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

function managedPath(value) {
  if (typeof value !== 'string') throw new TypeError('invalid managed credential output');
  if (value.startsWith('files/') && FILE_ID.test(value.slice(6))) return value;
  if (value.endsWith('.env') && serviceName(value.slice(0, -4))) return value;
  throw new TypeError('invalid managed credential output');
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
  const services = new Map(), fileIds = new Set();
  for (const rec of store.records()) for (const consumer of rec.consumers ?? []) if (consumer.host === host) {
    if (consumer.file) {
      if (!FILE_ID.test(rec.id)) throw new TypeError('invalid credential file id');
      fileIds.add(rec.id);
    }
    if (consumer.variable) {
      const service = serviceName(consumer.service);
      const paths = services.get(service) ?? [];
      if (consumer.file) paths.push(`${consumer.variable}=${join(dir, 'files', rec.id)}`);
      services.set(service, paths);
    }
  }
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
    for (const id of [...fileIds].sort()) outputs.set(`files/${id}`, await store.get(id, host));
    // Validate every destination before making a partial update, including stale files.
    for (const name of new Set([...previous, ...outputs.keys()])) regularFile(join(dir, name));
    // Retain ownership of both generations before writing any new output. An interrupted
    // update can then be reconciled on retry, including outputs no longer requested.
    writeAtomic(manifestPath, `${JSON.stringify({ version: 1, host, state: 'rendering', outputs: [...new Set([...previous, ...outputs.keys()])].sort() }, null, 2)}\n`);
    for (const [name, text] of outputs) writeAtomic(join(dir, name), text);
    for (const name of previous) if (!outputs.has(name) && regularFile(join(dir, name))) unlinkSync(join(dir, name));
    writeAtomic(manifestPath, `${JSON.stringify({ version: 1, host, state: 'complete', outputs: [...outputs.keys()].sort() }, null, 2)}\n`);
    return { host, to: dir, services: [...services.keys()].sort(), files: [...fileIds].sort() };
  } finally { releaseLock(); }
}
