import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { createStore, openStore } from '../src/store.mjs';

const cli = (dir, ...args) => spawnSync(process.execPath, [new URL('../scripts/credentials.mjs', import.meta.url).pathname, '--store', dir, ...args], { encoding: 'utf8' });

test('opening a path that holds no store refuses by name and creates nothing', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'credential-open-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const missing = join(root, 'retired', 'data', 'credentials');
  assert.throws(() => openStore(missing), /no credential store at .*retired.*registry/u);
  assert.equal(existsSync(missing), false, 'a read never makes the store it was pointed at');
  const render = spawnSync(process.execPath, [new URL('../scripts/render-host.mjs', import.meta.url).pathname], { encoding: 'utf8',
    env: { ...process.env, CREDENTIALS_STORE: missing, CREDENTIALS_HOST: 'fixture-host', CREDENTIALS_RENDER_TO: join(root, 'runtime'), CREDENTIALS_PULL: '0' } });
  assert.notEqual(render.status, 0, 'a render pointed at no store fails instead of succeeding with nothing');
  assert.match(render.stderr, /no credential store/u);
  assert.equal(existsSync(missing), false);
});

test('a store is created once, on purpose, and then opens', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'credential-create-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const dir = join(root, 'store');
  assert.notEqual(cli(dir, 'list').status, 0, 'list does not create a store');
  assert.equal(existsSync(dir), false);
  const made = cli(dir, 'init-store');
  assert.equal(made.status, 0, made.stderr);
  for (const sub of ['registry', 'sealed', 'hosts', '.gitignore']) assert.ok(existsSync(join(dir, sub)), sub);
  assert.deepEqual(openStore(dir).records(), []);
  assert.deepEqual(createStore(dir).records(), [], 'creating an existing store keeps it');
});
