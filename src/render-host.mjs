import { chmodSync, closeSync, constants, fchmodSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';

const MANIFEST = '.credential-custody-render.json';
const FILE_ID = /^[a-z0-9][a-z0-9.-]{0,95}$/u;

function serviceName(value) {
  if (typeof value !== 'string' || !value.trim() || value.length > 240 || /[\u0000-\u001f\u007f/\\]/u.test(value) || value === '.' || value === '..') {
    throw new TypeError('a rendered service must be a single nonempty filename component');
  }
  return value;
}

/**
 * A file credential's place in the runtime directory, where the code that reads it looks (keys/kalshi/<name>.pem,
 * fastmail/<account>.json): relative, at most six filename components, none hidden, never under files/ and never
 * a service's env file.
 */
export function placedPath(value) {
  const parts = typeof value === 'string' ? value.split('/') : [];
  const valid = parts.length > 0 && parts.length <= 6 && parts[0] !== 'files' && !(parts.length === 1 && value.endsWith('.env'))
    && parts.every((part) => { try { return serviceName(part) && !part.startsWith('.'); } catch { return false; } });
  if (!valid) throw new TypeError(`a placed credential path must be relative filename components, not ${JSON.stringify(value)}`);
  return value;
}

function managedPath(value) {
  if (typeof value !== 'string') throw new TypeError('invalid managed credential output');
  if (value.startsWith('files/') && FILE_ID.test(value.slice(6))) return value;
  if (value.endsWith('.env') && !value.includes('/') && serviceName(value.slice(0, -4))) return value;
  try { return placedPath(value); } catch { throw new TypeError('invalid managed credential output'); }
}

/** An output's parent directories, where they exist, are real directories: never a symlink out of the runtime directory. */
function realParents(dir, name) {
  const parts = name.split('/').slice(0, -1);
  for (let depth = 1; depth <= parts.length; depth += 1) {
    let info;
    try { info = lstatSync(join(dir, ...parts.slice(0, depth))); }
    catch (error) { if (error.code === 'ENOENT') return; throw error; }
    if (info.isSymbolicLink() || !info.isDirectory()) throw new Error('credential output directory must not be a symlink');
  }
}

/** Create each directory from the runtime directory down to a placed output, refusing symlinks on the way. */
function directories(dir, name) {
  const parts = name.split('/').slice(0, -1);
  for (let depth = 1; depth <= parts.length; depth += 1) directory(join(dir, ...parts.slice(0, depth)));
}

function regularFile(path) {
  let info;
  try { info = lstatSync(path); }
  catch (error) { if (error.code === 'ENOENT') return false; throw error; }
  if (!info.isFile()) throw new Error('credential output must be a regular file');
  return true;
}

function directory(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const info = lstatSync(path);
  if (info.isSymbolicLink() || !info.isDirectory()) throw new Error('credential output directory must not be a symlink');
  chmodSync(path, 0o700);
}

function writeAtomic(path, text) {
  regularFile(path);
  const temporary = `${path}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temporary, text, { mode: 0o600, flag: 'wx' });
    renameSync(temporary, path);
  } finally {
    try { unlinkSync(temporary); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

function acquireLock(path) {
  // flock locks the inherited open-file description, which this process retains.
  // Closing the descriptor (including on process death) releases the kernel lock.
  const fd = openSync(path, constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW, 0o600);
  try {
    if (!fstatSync(fd).isFile()) throw new Error('credential renderer lock must be a regular file');
    fchmodSync(fd, 0o600);
    const result = spawnSync('flock', ['--exclusive', '--nonblock', '--conflict-exit-code', '75', '3'], {
      stdio: ['ignore', 'pipe', 'pipe', fd], encoding: 'utf8',
    });
    if (result.error) throw new Error('credential rendering requires the util-linux flock command', { cause: result.error });
    if (result.status === 75) throw Object.assign(new Error('another credential render is active'), { code: 'RENDER_BUSY' });
    if (result.status !== 0) throw new Error('credential renderer could not acquire its kernel lock');
    return () => closeSync(fd);
  } catch (error) { closeSync(fd); throw error; }
}

/** Render one host's declared consumers and withdraw only this renderer's prior outputs. */
export async function renderHost(store, host, dir) {
  if (!host || !dir) throw new TypeError('host and runtime directory are required');
  // A file credential renders where its consumer reads it (`path`), or else to files/<id>.
  const services = new Map(), fileOutputs = new Map();
  for (const rec of store.records()) for (const consumer of rec.consumers ?? []) if (consumer.host === host) {
    const isFile = Boolean(consumer.file || consumer.path);
    let output;
    if (isFile) {
      if (!FILE_ID.test(rec.id)) throw new TypeError('invalid credential file id');
      output = consumer.path ? placedPath(consumer.path) : `files/${rec.id}`;
      if (fileOutputs.has(output) && fileOutputs.get(output) !== rec.id) throw new Error(`two credentials are placed at ${output}`);
      fileOutputs.set(output, rec.id);
    }
    if (consumer.variable) {
      const service = serviceName(consumer.service);
      const paths = services.get(service) ?? [];
      if (isFile) paths.push(`${consumer.variable}=${join(dir, output)}`);
      services.set(service, paths);
    }
  }
  const envOutputs = new Set([...services.keys()].map((service) => `${service}.env`));
  for (const output of fileOutputs.keys()) if (envOutputs.has(output)) throw new Error(`a credential is placed at a service's env file ${output}`);
  directory(dir);
  directory(join(dir, 'files'));
  const releaseLock = acquireLock(join(dir, '.credential-custody-render.lock'));
  try {
    const manifestPath = join(dir, MANIFEST);
    let previous = [];
    if (regularFile(manifestPath)) {
      const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
      if (manifest.version !== 1 || manifest.host !== host || !Array.isArray(manifest.outputs) || (manifest.state !== undefined && !['rendering', 'complete'].includes(manifest.state))) throw new Error('invalid credential output manifest');
      previous = manifest.outputs.map(managedPath);
    }
    const outputs = new Map();
    for (const [service, paths] of [...services].sort(([a], [b]) => a.localeCompare(b))) outputs.set(`${service}.env`, (await store.render(host, service)) + paths.sort().map(line => `${line}\n`).join(''));
    for (const [output, id] of [...fileOutputs].sort(([a], [b]) => a.localeCompare(b))) outputs.set(output, await store.get(id, host));
    // Validate every destination before making a partial update, including stale files.
    for (const name of new Set([...previous, ...outputs.keys()])) { realParents(dir, name); regularFile(join(dir, name)); }
    // Retain ownership of both generations before writing any new output. An interrupted
    // update can then be reconciled on retry, including outputs no longer requested.
    writeAtomic(manifestPath, `${JSON.stringify({ version: 1, host, state: 'rendering', outputs: [...new Set([...previous, ...outputs.keys()])].sort() }, null, 2)}\n`);
    for (const [name, text] of outputs) { directories(dir, name); writeAtomic(join(dir, name), text); }
    for (const name of previous) if (!outputs.has(name) && regularFile(join(dir, name))) unlinkSync(join(dir, name));
    writeAtomic(manifestPath, `${JSON.stringify({ version: 1, host, state: 'complete', outputs: [...outputs.keys()].sort() }, null, 2)}\n`);
    return { host, to: dir, services: [...services.keys()].sort(), files: [...fileOutputs.keys()].sort() };
  } finally { releaseLock(); }
}
