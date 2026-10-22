import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { openStore } from '../src/store.mjs';

// Ephemeral identities and inert values exist only in these temporary fixtures.
async function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'credential-describe-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const dir = join(root, 'store'), store = openStore(dir);
  await store.initHost('holder-host');
  await store.put('fixture-value', 'INERT_VALUE', { holders: ['holder-host'], consumers: [{ host: 'holder-host', service: 'fixture-service', variable: 'API_KEY_FIXTURE' }], rotateEveryDays: 30 });
  await store.put('fixture-other', 'OTHER_INERT_VALUE', { holders: ['holder-host'] });
  return { root, dir, store };
}
const bytes = (dir, id) => readFileSync(join(dir, 'sealed', `${id}.age`));
const raw = (dir, id) => readFileSync(join(dir, 'registry', `${id}.json`), 'utf8');

test('describe sets provider, owner, purpose, account and plan, and leaves the sealed value and custody fields alone', async (t) => {
  const { dir, store } = await fixture(t);
  const before = store.record('fixture-value'), sealedBefore = bytes(dir, 'fixture-value'), otherBefore = raw(dir, 'fixture-other');
  const shown = store.describe('fixture-value', { provider: 'example-provider', owner: 'example-org', purpose: 'inference for fixture-service', account: 'example-account', plan: 'pro' });
  assert.deepEqual(shown, { id: 'fixture-value', provider: 'example-provider', owner: 'example-org', purpose: 'inference for fixture-service', account: 'example-account', plan: 'pro' });
  const after = store.record('fixture-value');
  assert.equal(after.account, 'example-account');
  assert.equal(after.plan, 'pro');
  assert.deepEqual(bytes(dir, 'fixture-value'), sealedBefore, 'the sealed file is byte-identical');
  for (const field of ['holders', 'consumers', 'rotatedAt', 'rotateEveryDays', 'kind', 'fingerprint', 'sealedTo', 'createdAt']) assert.deepEqual(after[field], before[field], field);
  assert.equal(raw(dir, 'fixture-other'), otherBefore, 'another record is untouched');
  assert.equal(await store.get('fixture-value', 'holder-host'), 'INERT_VALUE');
  assert.deepEqual(readdirSync(join(dir, 'registry')).sort(), ['fixture-other.json', 'fixture-value.json'], 'no temp file is left behind');
});

test('a second, different describe changes only the fields it names, and --clear empties one', async (t) => {
  const { dir, store } = await fixture(t);
  store.describe('fixture-value', { provider: 'example-provider', account: 'example-account', plan: 'pro' });
  const sealedBefore = bytes(dir, 'fixture-value');
  store.describe('fixture-value', { plan: 'team', purpose: 'second purpose' }, ['account']);
  const rec = store.record('fixture-value');
  assert.equal(rec.provider, 'example-provider');
  assert.equal(rec.plan, 'team');
  assert.equal(rec.purpose, 'second purpose');
  assert.equal(rec.account, null);
  assert.deepEqual(bytes(dir, 'fixture-value'), sealedBefore);
  assert.throws(() => store.describe('fixture-value', { plan: 'x' }, ['plan']), /both set and cleared/);
  assert.throws(() => store.describe('fixture-value', {}, ['holders']), /not a descriptive field/);
  assert.throws(() => store.describe('fixture-value', {}), /needs at least one/);
});

test('an unknown id is refused and nothing is created', async (t) => {
  const { dir, store } = await fixture(t);
  assert.throws(() => store.describe('no-such-credential', { provider: 'example-provider' }), /no credential no-such-credential/);
  assert.deepEqual(readdirSync(join(dir, 'registry')).sort(), ['fixture-other.json', 'fixture-value.json']);
});

test('a secret-shaped field value is refused and the record is unchanged', async (t) => {
  const { dir, store } = await fixture(t);
  const before = raw(dir, 'fixture-value');
  for (const text of ['API_KEY_FIXTURE=abc123', 'AGE-SECRET-KEY-1ABCDEF', '-----BEGIN PRIVATE KEY-----', 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8', 'INERT_VALUE'])
    assert.throws(() => store.describe('fixture-value', { purpose: text }), /secret|credential's value/, text);
  assert.throws(() => store.describe('fixture-value', { provider: 'two\nlines' }), /one line/);
  assert.throws(() => store.describe('fixture-value', { provider: '   ' }), /one line/);
  assert.equal(raw(dir, 'fixture-value'), before);
  // A variable name alone, and ordinary prose, are descriptions and not secrets.
  store.describe('fixture-value', { purpose: 'API_KEY_FIXTURE for fixture-service' });
  assert.equal(store.record('fixture-value').purpose, 'API_KEY_FIXTURE for fixture-service');
});

test('the CLI describes without a host, shows the new fields in list, and refuses with a sentence', async (t) => {
  const { dir } = await fixture(t);
  const cli = (...args) => spawnSync(process.execPath, [new URL('../scripts/credentials.mjs', import.meta.url).pathname, '--store', dir, ...args], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  const sealedBefore = bytes(dir, 'fixture-value');
  const ok = cli('describe', 'fixture-value', '--provider', 'example-provider', '--account', 'example-account', '--plan', 'pro');
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(JSON.parse(ok.stdout).plan, 'pro');
  const listed = JSON.parse(cli('list').stdout).find((r) => r.id === 'fixture-value');
  assert.equal(listed.account, 'example-account');
  assert.equal(listed.plan, 'pro');
  assert.equal(listed.provider, 'example-provider');
  const cleared = cli('describe', 'fixture-value', '--clear', 'plan', '--clear', 'account');
  assert.equal(cleared.status, 0, cleared.stderr);
  assert.equal(JSON.parse(cleared.stdout).plan, null);
  const unknown = cli('describe', 'nope', '--provider', 'x');
  assert.equal(unknown.status, 1);
  assert.match(unknown.stderr, /^credentials: no credential nope/);
  const secret = cli('describe', 'fixture-value', '--purpose', 'API_KEY_X=abc');
  assert.equal(secret.status, 1);
  assert.match(secret.stderr, /looks like a secret/);
  assert.deepEqual(bytes(dir, 'fixture-value'), sealedBefore);
});
