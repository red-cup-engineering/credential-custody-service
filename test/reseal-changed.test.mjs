import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createStore, openStore } from '../src/store.mjs';

// Ephemeral identities exist only in these temporary fixtures, never a real host or account.
async function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'credential-reseal-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const dir = join(root, 'store'), store = createStore(dir);
  await store.initHost('holder-host');
  await store.initHost('new-host');
  return { root, dir, store };
}
const grant = (dir, id, holder) => {
  const path = join(dir, 'registry', `${id}.json`), rec = JSON.parse(readFileSync(path, 'utf8'));
  writeFileSync(path, `${JSON.stringify({ ...rec, holders: [...rec.holders, holder] }, null, 2)}\n`);
};

test('a sealed value records the public recipients it was sealed to', async (t) => {
  const { store } = await fixture(t);
  const rec = await store.put('fixture-value', 'INERT_VALUE', { holders: ['holder-host'] });
  assert.deepEqual(rec.sealedTo, [store.recipients().hosts['holder-host']]);
});

test('a holder granted by editing the registry is resealed by a holder that can open it, once', async (t) => {
  const { dir, store } = await fixture(t);
  await store.put('fixture-value', 'INERT_VALUE', { holders: ['holder-host'] });
  grant(dir, 'fixture-value', 'new-host');
  await assert.rejects(store.get('fixture-value', 'new-host'));
  assert.deepEqual(await store.resealChanged('holder-host'), { resealed: ['fixture-value'], skipped: [] });
  assert.equal(await store.get('fixture-value', 'new-host'), 'INERT_VALUE');
  assert.deepEqual(store.record('fixture-value').sealedTo, [store.recipients().hosts['holder-host'], store.recipients().hosts['new-host']].sort());
  assert.deepEqual(await store.resealChanged('holder-host'), { resealed: [], skipped: [] });
});

test('untracked records and credentials this host does not hold are left alone', async (t) => {
  const { dir, store } = await fixture(t);
  await store.put('fixture-untracked', 'INERT_VALUE', { holders: ['holder-host'] });
  const path = join(dir, 'registry', 'fixture-untracked.json'), rec = JSON.parse(readFileSync(path, 'utf8'));
  delete rec.sealedTo; writeFileSync(path, `${JSON.stringify({ ...rec, holders: ['holder-host', 'new-host'] }, null, 2)}\n`);
  await store.put('fixture-other', 'INERT_VALUE', { holders: ['new-host'] });
  assert.deepEqual(await store.resealChanged('holder-host'), { resealed: [], skipped: [] });
});

test('the render-host unit reseals a pulled grant and pushes it', async (t) => {
  const { root, dir, store } = await fixture(t);
  const git = (cwd, ...args) => { const r = spawnSync('git', args, { cwd, encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr); return r.stdout; };
  const origin = join(root, 'origin.git');
  git(root, 'init', '-q', '--bare', origin);
  git(dir, 'init', '-q'); git(dir, 'remote', 'add', 'origin', origin);
  await store.put('fixture-value', 'INERT_VALUE', { holders: ['holder-host'], consumers: [{ host: 'new-host', service: 'fixture-service', variable: 'TEST_VALUE' }] });
  git(dir, 'add', '-A', '.'); git(dir, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '-m', 'seed'); git(dir, 'push', '-q', '-u', 'origin', 'HEAD');
  // The grant arrives as a reviewed edit on the origin; the holder's unit pulls it.
  const other = join(root, 'other'); git(root, 'clone', '-q', origin, other);
  grant(other, 'fixture-value', 'new-host');
  git(other, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '-am', 'grant'); git(other, 'push', '-q');
  const unit = spawnSync(process.execPath, [new URL('../scripts/render-host.mjs', import.meta.url).pathname], { encoding: 'utf8',
    env: { ...process.env, CREDENTIALS_STORE: dir, CREDENTIALS_HOST: 'holder-host', CREDENTIALS_RENDER_TO: join(root, 'runtime'), CREDENTIALS_PULL: '1' } });
  assert.equal(unit.status, 0, unit.stderr);
  assert.match(unit.stderr, /resealed fixture-value/);
  assert.equal(unit.stdout.includes('INERT'), false);
  git(other, 'pull', '-q');
  assert.equal(await openStore(other).get('fixture-value', 'new-host').catch(() => null), null, 'the clone has no new-host identity of its own');
  const resealedRecord = JSON.parse(readFileSync(join(other, 'registry', 'fixture-value.json'), 'utf8'));
  assert.equal(resealedRecord.sealedTo.length, 2);
  assert.equal(await store.get('fixture-value', 'new-host'), 'INERT_VALUE');
});
