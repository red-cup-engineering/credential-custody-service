import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { openStore } from '../src/store.mjs';

test('genuine age custody reaches both original entrypoints and file bindings without returning values', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-store-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const storePath = join(root, 'store'), runtime = join(root, 'runtime'), host = 'fixture-host';
  const store = openStore(storePath);
  // Ephemeral identities exist only in this temporary fixture, never a real host or account.
  await store.initHost(host);
  await store.put('fixture-value', 'INERT_VALUE', { holders: [host], consumers: [{ host, service: 'fixture-service', variable: 'TEST_VALUE' }] });
  await store.put('fixture-file', 'INERT_FILE_VALUE', { holders: [host], consumers: [{ host, service: 'fixture-service', file: '/unused-fixture-source' }] });
  assert.match(readFileSync(join(storePath, 'sealed/fixture-value.age'), 'utf8'), /^-----BEGIN AGE ENCRYPTED FILE-----/u);
  assert.equal(readFileSync(join(storePath, 'sealed/fixture-value.age'), 'utf8').includes('INERT_VALUE'), false);
  const cli = (...args) => spawnSync(process.execPath, [new URL('../scripts/credentials.mjs', import.meta.url).pathname, '--store', storePath, '--host', host, ...args], { encoding: 'utf8' });
  const binding = cli('bind-file', 'fixture-file', '--service', 'fixture-service', '--variable', 'TEST_FILE');
  assert.equal(binding.status, 0, binding.stderr);
  const rendered = cli('render-host', '--to', runtime);
  assert.equal(rendered.status, 0, rendered.stderr);
  assert.equal(rendered.stdout.includes('INERT_VALUE'), false);
  const environment = readFileSync(join(runtime, 'fixture-service.env'), 'utf8');
  assert.equal(environment, `TEST_VALUE=INERT_VALUE\nTEST_FILE=${join(runtime, 'files/fixture-file')}\n`);
  assert.equal(readFileSync(join(runtime, 'files/fixture-file'), 'utf8'), 'INERT_FILE_VALUE');
  await store.put('fixture-value', 'INERT_ROTATED_VALUE', { consumers: [] });
  await store.put('fixture-file', 'INERT_FILE_VALUE', { consumers: [] });
  const unit = spawnSync(process.execPath, [new URL('../scripts/render-host.mjs', import.meta.url).pathname], { encoding: 'utf8', env: { ...process.env, CREDENTIALS_STORE: storePath, CREDENTIALS_HOST: host, CREDENTIALS_RENDER_TO: runtime, CREDENTIALS_PULL: '0' } });
  assert.equal(unit.status, 0, unit.stderr);
  assert.equal(unit.stdout.includes('INERT'), false);
  assert.equal(existsSync(join(runtime, 'fixture-service.env')), false);
  assert.equal(existsSync(join(runtime, 'files/fixture-file')), false);
});

test('bind gives a held credential another service without reading it, as a variable or a placed file', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-bind-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const storePath = join(root, 'store'), runtime = join(root, 'runtime'), host = 'fixture-host';
  const store = openStore(storePath);
  await store.initHost(host);
  await store.put('fixture-id', 'INERT_ID', { holders: [host], consumers: [{ host, service: 'first-service', variable: 'FIXTURE_ID' }] });
  await store.put('fixture-key', 'INERT_KEY_FILE', { holders: [host], consumers: [{ host, service: 'first-service', path: 'keys/fixture/key.pem', variable: 'FIXTURE_KEY_PATH' }] });
  const cli = (...args) => spawnSync(process.execPath, [new URL('../scripts/credentials.mjs', import.meta.url).pathname, '--store', storePath, '--host', host, ...args], { encoding: 'utf8' });
  const variable = cli('bind', 'fixture-id', '--service', 'second-service', '--variable', 'SECOND_ID');
  assert.equal(variable.status, 0, variable.stderr);
  const file = cli('bind', 'fixture-key', '--service', 'second-service', '--variable', 'SECOND_KEY_PATH', '--path', 'keys/fixture/key.pem');
  assert.equal(file.status, 0, file.stderr);
  assert.equal(`${variable.stdout}${file.stdout}`.includes('INERT'), false, 'binding never returns a value');
  const rendered = cli('render-host', '--to', runtime);
  assert.equal(rendered.status, 0, rendered.stderr);
  assert.equal(readFileSync(join(runtime, 'second-service.env'), 'utf8'), `SECOND_ID=INERT_ID\nSECOND_KEY_PATH=${join(runtime, 'keys/fixture/key.pem')}\n`);
  assert.equal(readFileSync(join(runtime, 'first-service.env'), 'utf8'), `FIXTURE_ID=INERT_ID\nFIXTURE_KEY_PATH=${join(runtime, 'keys/fixture/key.pem')}\n`);
  // a host the value is not sealed to cannot be bound
  const elsewhere = spawnSync(process.execPath, [new URL('../scripts/credentials.mjs', import.meta.url).pathname, '--store', storePath, '--host', 'other-host', 'bind', 'fixture-id', '--service', 's', '--variable', 'X_ID'], { encoding: 'utf8' });
  assert.notEqual(elsewhere.status, 0);
  assert.match(elsewhere.stderr, /not sealed to other-host/u);
});

test('re-enrolling an existing host returns its original public recipient, not a Promise', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-host-reenrollment-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, 'store'), selectedHost = 'fixture-host';
  const opened = openStore(path);
  const enrolled = await opened.initHost(selectedHost);
  const identityBefore = readFileSync(join(path, 'hosts', selectedHost + '.identity'));
  const recipientsBefore = readFileSync(join(path, 'recipients.json'));
  const repeated = await opened.initHost(selectedHost);
  assert.equal(enrolled.created, true);
  assert.equal(repeated.created, false);
  assert.equal(typeof enrolled.recipient, 'string');
  assert.equal(typeof repeated.recipient, 'string', 'the repeat result must be serializable public data');
  assert.equal(repeated.recipient, enrolled.recipient);
  assert.deepEqual(readFileSync(join(path, 'hosts', selectedHost + '.identity')), identityBefore);
  assert.deepEqual(readFileSync(join(path, 'recipients.json')), recipientsBefore);
});


test('host render refuses injected environment assignment bytes before changing existing managed outputs', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-env-injection-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const storePath = join(root, 'store'), runtime = join(root, 'runtime'), host = 'fixture-host';
  const store = openStore(storePath);
  await store.initHost(host);
  await store.put('fixture-env', 'INERT_BASE', {
    holders: [host], consumers: [{ host, service: 'fixture-service', variable: 'FIXTURE' }],
  });
  const multilineFile = 'INERT_FILE_HEADER\nINERT_FILE_FOOTER\n';
  await store.put('fixture-multiline-file', multilineFile, {
    holders: [host], consumers: [{ host, service: 'fixture-service', file: '/unused-fixture-source' }],
  });
  const cli = () => spawnSync(process.execPath, [
    new URL('../scripts/credentials.mjs', import.meta.url).pathname,
    '--store', storePath, '--host', host, 'render-host', '--to', runtime,
  ], { encoding: 'utf8' });
  const initial = cli();
  assert.equal(initial.status, 0, initial.stderr);
  const envPath = join(runtime, 'fixture-service.env');
  const filePath = join(runtime, 'files/fixture-multiline-file');
  const manifestPath = join(runtime, '.credential-custody-render.json');
  const baselineEnv = readFileSync(envPath);
  const baselineFile = readFileSync(filePath);
  const baselineManifest = readFileSync(manifestPath);
  assert.equal(baselineFile.toString('utf8'), multilineFile,
    'multiline secrets remain valid when delivered as files');
  for (const injected of [
    'INERT_VALUE\nINJECTED_ROLE=admin',
    'INERT_VALUE\rINJECTED_ROLE=admin',
    'INERT_VALUE\u0000INJECTED_ROLE=admin',
  ]) {
    await store.put('fixture-env', injected);
    await assert.rejects(store.render(host, 'fixture-service'), /single-line|control character|environment/u,
      'direct environment rendering must also refuse unsafe content');
    const refused = cli();
    assert.notEqual(refused.status, 0, 'unsafe value must never produce a successful generation');
    assert.equal(refused.stdout, '', 'no partial/success output on refusal');
    assert.match(refused.stderr, /single-line|control character|environment/u);
    assert.equal(refused.stderr.includes('INJECTED_ROLE=admin'), false, 'never echo a secret');
    assert.deepEqual(readFileSync(envPath), baselineEnv, 'prior environment must survive refusal');
    assert.deepEqual(readFileSync(filePath), baselineFile, 'prior file credential must survive refusal');
    assert.deepEqual(readFileSync(manifestPath), baselineManifest, 'ownership must survive refusal');
  }
  await store.put('fixture-env', 'INERT_ROTATED');
  const final = cli();
  assert.equal(final.status, 0, final.stderr);
  assert.match(readFileSync(envPath, 'utf8'), /FIXTURE=INERT_ROTATED/u);
});
