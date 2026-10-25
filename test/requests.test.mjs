import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createStore, openStore } from '../src/store.mjs';

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'credential-requests-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const dir = join(root, 'store');
  return { dir, store: createStore(dir) };
}
const cli = (dir, ...args) => spawnSync(process.execPath, [new URL('../scripts/credentials.mjs', import.meta.url).pathname, '--store', dir, ...args], { encoding: 'utf8' });
const rows = (dir) => readFileSync(join(dir, 'requests.jsonl'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));

test('a request without a blocking condition is requested, as before', (t) => {
  const { dir, store } = fixture(t);
  const row = store.request('provider.free-key', { reason: 'zero-cash lane', by: 'host-a' });
  assert.equal(row.state, 'requested');
  assert.equal('blockedBy' in row, false);
  assert.deepEqual(rows(dir).map((r) => r.state), ['requested']);
});

test('a request blocked by a condition is tracked as deferred with that condition', (t) => {
  const { dir, store } = fixture(t);
  const row = store.request('provider.card-gated-key', { reason: 'free tier behind a card', by: 'host-a', blockedBy: 'requires a card' });
  assert.equal(row.state, 'deferred');
  assert.equal(row.blockedBy, 'requires a card');
  assert.deepEqual(rows(dir)[0], row);
});

test('requests lists only requested by default, deferred with --deferred, and both with --all', (t) => {
  const { dir, store } = fixture(t);
  store.request('a.now', { reason: 'r', by: 'h' });
  store.request('b.later', { reason: 'r', by: 'h', blockedBy: 'requires a card' });
  const ids = (...flags) => JSON.parse(cli(dir, 'requests', ...flags).stdout).map((r) => r.id);
  assert.deepEqual(ids(), ['a.now']);
  assert.deepEqual(ids('--deferred'), ['b.later']);
  assert.deepEqual(ids('--all'), ['a.now', 'b.later']);
  const audit = JSON.parse(cli(dir, 'audit').stdout);
  assert.deepEqual(audit.requests, ['a.now']);
  assert.deepEqual(audit.deferredRequests, ['b.later (requires a card)']);
});

test('the CLI writes a deferred request through --blocked-by', (t) => {
  const { dir } = fixture(t);
  const result = cli(dir, 'request', 'c.cli', '--reason', 'free tier', '--blocked-by', 'requires a card', '--by', 'host-a');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(rows(dir)[0].state, 'deferred');
});

test('a blocking condition that is empty, multi-line or secret-shaped is refused and nothing is written', (t) => {
  const { dir, store } = fixture(t);
  for (const blockedBy of ['  ', 'requires\na card', 'API_KEY_X=abcdefghijklmnop0123456789', 'Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7d']) {
    assert.throws(() => store.request('d.bad', { reason: 'r', by: 'h', blockedBy }), TypeError);
  }
  assert.deepEqual(store.requests(), []);
});
