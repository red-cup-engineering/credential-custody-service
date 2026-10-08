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
