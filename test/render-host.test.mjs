import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, statSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { renderHost } from '../src/render-host.mjs';

const host = 'test-host';
const value = 'INERT_TEST_VALUE';
const env = (service = 'test-service') => ({ id: 'test-credential', holders: [host], consumers: [{ host, service, variable: 'TEST_VALUE' }] });
const file = () => ({ id: 'test-file', holders: [host], consumers: [{ host, service: 'test-service', file: '/ignored-source-location' }] });

function fixture(t, records = [env(), file()]) {
  const root = mkdtempSync(join(tmpdir(), 'render-host-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const state = { records, value, calls: 0 };
  const store = {
    records: () => state.records,
    render: async (selectedHost, service) => { assert.equal(selectedHost, host); state.calls++; return `TEST_VALUE=${state.value}\n`; },
    get: async (id, selectedHost) => { assert.equal(selectedHost, host); state.calls++; return state.value; },
  };
  return { root, dir: join(root, 'runtime'), state, store };
}

test('renders both consumer forms privately with value-free receipt and manifest', async t => {
  const f = fixture(t);
  const receipt = await renderHost(f.store, host, f.dir);
  assert.equal(readFileSync(join(f.dir, 'test-service.env'), 'utf8'), `TEST_VALUE=${value}\n`);
  assert.equal(readFileSync(join(f.dir, 'files/test-file'), 'utf8'), value);
  for (const name of ['', 'files']) assert.equal(statSync(join(f.dir, name)).mode & 0o777, 0o700);
  for (const name of ['test-service.env', 'files/test-file', '.credential-custody-render.json']) assert.equal(statSync(join(f.dir, name)).mode & 0o777, 0o600);
  assert.equal(JSON.stringify(receipt).includes(value), false);
  assert.equal(readFileSync(join(f.dir, '.credential-custody-render.json'), 'utf8').includes(value), false);
});

test('rejects escaping and invalid service names before reading values or creating output', async t => {
  const f = fixture(t);
  for (const service of ['../escaped', 'files/nested', '..\\escaped', '', '.', '..', 'bad\nname', null]) {
    f.state.records = [env(service)];
    await assert.rejects(renderHost(f.store, host, f.dir), /filename component/);
    assert.equal(f.state.calls, 0);
    assert.equal(existsSync(f.dir), false);
  }
});

test('rejects a malformed file credential id before touching output', async t => {
  const f = fixture(t, [{ ...file(), id: '../outside' }]);
  await assert.rejects(renderHost(f.store, host, f.dir), /invalid credential file id/);
  assert.equal(existsSync(f.dir), false);
});

test('rotation replaces managed bytes, then withdrawn consumers remove only managed outputs', async t => {
  const f = fixture(t);
  await renderHost(f.store, host, f.dir);
  f.state.value = 'INERT_ROTATED_VALUE';
  await renderHost(f.store, host, f.dir);
  assert.equal(readFileSync(join(f.dir, 'files/test-file'), 'utf8'), f.state.value);
  writeFileSync(join(f.dir, 'unrelated.env'), 'KEEP');
  writeFileSync(join(f.dir, 'files/unrelated'), 'KEEP');
  f.state.records = [];
  const receipt = await renderHost(f.store, host, f.dir);
  assert.equal(existsSync(join(f.dir, 'test-service.env')), false);
  assert.equal(existsSync(join(f.dir, 'files/test-file')), false);
  assert.equal(readFileSync(join(f.dir, 'unrelated.env'), 'utf8'), 'KEEP');
  assert.equal(readFileSync(join(f.dir, 'files/unrelated'), 'utf8'), 'KEEP');
  assert.deepEqual(receipt.services, []);
  assert.deepEqual(receipt.files, []);
});

test('refuses an invalid or foreign-host manifest without deleting unrelated files', async t => {
  const f = fixture(t);
  mkdirSync(f.dir, { recursive: true });
  writeFileSync(join(f.root, 'outside.env'), 'KEEP');
  for (const manifest of [{version:1,host,outputs:['../outside.env']},{version:1,host:'other-host',outputs:[]}]) {
    writeFileSync(join(f.dir, '.credential-custody-render.json'), JSON.stringify(manifest));
    await assert.rejects(renderHost(f.store, host, f.dir));
    assert.equal(readFileSync(join(f.root, 'outside.env'), 'utf8'), 'KEEP');
  }
});

test('refuses symlinked output directories and files instead of writing outside', async t => {
  const f = fixture(t);
  mkdirSync(f.dir, { recursive: true });
  const outside = join(f.root, 'outside');
  mkdirSync(outside);
  symlinkSync(outside, join(f.dir, 'files'));
  await assert.rejects(renderHost(f.store, host, f.dir), /symlink/);
  rmSync(join(f.dir, 'files'));
  writeFileSync(join(outside, 'victim'), 'KEEP');
  symlinkSync(join(outside, 'victim'), join(f.dir, 'test-service.env'));
  await assert.rejects(renderHost(f.store, host, f.dir), /regular file/);
  assert.equal(readFileSync(join(outside, 'victim'), 'utf8'), 'KEEP');
});

test('only one render may own a runtime directory at a time', async t => {
  const f = fixture(t);
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  f.store.render = async () => { await gate; return 'INERT'; };
  const first = renderHost(f.store, host, f.dir);
  await assert.rejects(renderHost(f.store, host, f.dir), { code: 'RENDER_BUSY' });
  release();
  await first;
  assert.equal(statSync(join(f.dir, '.credential-custody-render.lock')).mode & 0o777, 0o600);
  await renderHost(f.store, host, f.dir);
});

test('a killed renderer releases its kernel lock without manual lock-file removal', async t => {
  const f = fixture(t);
  const moduleUrl = new URL('../src/render-host.mjs', import.meta.url).href;
  const code = `import { renderHost } from ${JSON.stringify(moduleUrl)};
    const timer=setInterval(()=>{},1000);
    const store={records:()=>${JSON.stringify([env()])},render:async()=>{process.send('locked');await new Promise(()=>{});},get:async()=>''};
    await renderHost(store,${JSON.stringify(host)},${JSON.stringify(f.dir)});clearInterval(timer);`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', code], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  await once(child, 'message');
  await assert.rejects(renderHost(f.store, host, f.dir), { code: 'RENDER_BUSY' });
  const exited = once(child, 'exit');
  child.kill('SIGKILL');
  await exited;
  await renderHost(f.store, host, f.dir);
  assert.equal(readFileSync(join(f.dir, 'test-service.env'), 'utf8'), `TEST_VALUE=${value}\n`);
});

test('a failed value retrieval preserves the previous outputs and manifest', async t => {
  const f = fixture(t);
  await renderHost(f.store, host, f.dir);
  const paths = ['test-service.env', 'files/test-file', '.credential-custody-render.json'];
  const before = paths.map(path => readFileSync(join(f.dir, path), 'utf8'));
  f.state.value = 'INERT_NOT_COMMITTED';
  f.store.get = async () => { throw new Error('synthetic retrieval refusal'); };
  await assert.rejects(renderHost(f.store, host, f.dir), /synthetic retrieval refusal/);
  assert.deepEqual(paths.map(path => readFileSync(join(f.dir, path), 'utf8')), before);
  assert.equal(existsSync(join(f.dir, 'test-service.env.tmp')), false);
});

test('retry reconciles an interrupted generation without deleting unrelated outputs', async t => {
  const f = fixture(t, []);
  mkdirSync(join(f.dir, 'files'), { recursive: true });
  writeFileSync(join(f.dir, 'interrupted.env'), 'INERT_OLD_VALUE');
  writeFileSync(join(f.dir, 'unrelated.env'), 'KEEP');
  writeFileSync(join(f.dir, '.credential-custody-render.json'), JSON.stringify({ version: 1, host, state: 'rendering', outputs: ['interrupted.env', 'files/not-yet-written'] }));
  await renderHost(f.store, host, f.dir);
  assert.equal(existsSync(join(f.dir, 'interrupted.env')), false);
  assert.equal(readFileSync(join(f.dir, 'unrelated.env'), 'utf8'), 'KEEP');
  const manifest = JSON.parse(readFileSync(join(f.dir, '.credential-custody-render.json'), 'utf8'));
  assert.equal(manifest.state, 'complete');
  assert.deepEqual(manifest.outputs, []);
});

test('retains upstream file-variable bindings as paths, never file contents', async t => {
  const record = file(); record.consumers[0].variable = 'TEST_FILE';
  const f = fixture(t, [record]);
  f.store.render = async () => '';
  await renderHost(f.store, host, f.dir);
  assert.equal(readFileSync(join(f.dir, 'test-service.env'), 'utf8'), `TEST_FILE=${join(f.dir, 'files/test-file')}\n`);
  assert.equal(readFileSync(join(f.dir, 'files/test-file'), 'utf8'), value);
});

test('a mid-write I/O failure retains ownership so retry can withdraw new outputs', async t => {
  const f = fixture(t);
  const originalWrite = fs.writeFileSync;
  fs.writeFileSync = (path, ...args) => {
    if (typeof path === 'string' && path.startsWith(join(f.dir, 'files/test-file.')) && path.endsWith('.tmp')) throw Object.assign(new Error('synthetic I/O failure'), { code: 'EIO' });
    return originalWrite(path, ...args);
  };
  syncBuiltinESMExports();
  try { await assert.rejects(renderHost(f.store, host, f.dir), /synthetic I\/O failure/); }
  finally { fs.writeFileSync = originalWrite; syncBuiltinESMExports(); }
  assert.equal(existsSync(join(f.dir, 'test-service.env')), true);
  assert.equal(existsSync(join(f.dir, 'files/test-file')), false);
  const pending = JSON.parse(readFileSync(join(f.dir, '.credential-custody-render.json'), 'utf8'));
  assert.equal(pending.state, 'rendering');
  assert.deepEqual(pending.outputs, ['files/test-file', 'test-service.env']);
  writeFileSync(join(f.dir, 'unrelated.env'), 'KEEP');
  f.state.records = [];
  await renderHost(f.store, host, f.dir);
  assert.equal(existsSync(join(f.dir, 'test-service.env')), false);
  assert.equal(readFileSync(join(f.dir, 'unrelated.env'), 'utf8'), 'KEEP');
});
