import test from 'node:test';
import assert from 'node:assert/strict';
import { appendFileSync, existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createStore } from '../src/store.mjs';

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

test('an interrupted JSONL request never appears as a healthy empty backlog', (t) => {
  const { dir, store } = fixture(t), path = join(dir, 'requests.jsonl');
  assert.deepEqual(store.requests(), [], 'an actually absent ledger is legitimately empty');
  assert.equal(existsSync(path), false, 'reading an absent ledger creates nothing');
  store.request('provider.first', { reason: 'existing account', by: 'host-a' });
  store.request('provider.second', { reason: 'original customer need', by: 'host-b', blockedBy: 'requires reviewed provider' });
  const valid = readFileSync(path);
  appendFileSync(path, '{interrupted-last-line\n');
  const original = readFileSync(path);
  assert.throws(() => store.requests(), /credential requests.*line 3.*invalid JSON/iu,
    'a trailing partial write cannot erase earlier recorded requests');
  for (const action of [['requests', '--all'], ['requests'], ['audit']]) {
    const refused = cli(dir, ...action);
    assert.notEqual(refused.status, 0, 'a reader must refuse incomplete request custody');
    assert.equal(refused.stdout, '', 'never claim an empty backlog when source is invalid');
    assert.match(refused.stderr, /requests.*line 3.*invalid JSON/iu);
    assert.equal(refused.stderr.includes('original customer need'), false, 'diagnostics must not disclose request details');
  }
  assert.deepEqual(readFileSync(path), original, 'the failed reader preserves every original byte for explicit reconciliation');
  writeFileSync(path, valid);
  assert.deepEqual(store.requests().map(row => row.id), ['provider.first', 'provider.second'],
    'once original valid evidence returns, all requests become readable');
});

test('syntactically valid but unrecognized request states cannot disappear from audit', (t) => {
  const { dir, store } = fixture(t), path = join(dir, 'requests.jsonl');
  store.request('provider.first', { reason: 'original need', by: 'host-a' });
  const valid = readFileSync(path);
  for (const invalid of [{ id: 'foreign-state', state: 'completed' }, { state: 'requested' }, null, []]) {
    writeFileSync(path, valid);
    appendFileSync(path, JSON.stringify(invalid) + '\n');
    const before = readFileSync(path);
    assert.throws(() => store.requests(), /credential requests.*line 2.*invalid record/iu,
      'unrecognized or malformed records cannot be silently excluded from requested/deferred views');
    const audit = cli(dir, 'audit');
    assert.notEqual(audit.status, 0);
    assert.equal(audit.stdout, '');
    assert.deepEqual(readFileSync(path), before);
  }
  writeFileSync(path, valid);
  assert.deepEqual(store.requests().map(row => row.id), ['provider.first']);
});

test('a linked external request file is not an authorized original backlog', t => {
  const { dir, store } = fixture(t), path = join(dir, 'requests.jsonl');
  const external = join(dir, '..', 'other-organization-request-list.jsonl');
  const data = JSON.stringify({ at: '2026-10-24T20:45:00Z', id: 'foreign.need', state: 'requested',
    reason: 'INERT_OTHER_ORGANIZATION', by: 'foreign-host' }) + '\n';
  writeFileSync(external, data);
  symlinkSync(external, path);
  assert.throws(() => store.requests(), /credential requests.*(unavailable|symlink|source)/iu,
    'an external log must not be mistaken for the selected store\'s requests');
  const listed = cli(dir, 'requests', '--all');
  assert.notEqual(listed.status, 0);
  assert.equal(listed.stdout, '');
  assert.equal(listed.stderr.includes('INERT_OTHER_ORGANIZATION'), false);
  assert.equal(readFileSync(external, 'utf8'), data);
});

test('a linked external request file may not receive newly requested credential metadata', t => {
  const { dir, store } = fixture(t), path = join(dir, 'requests.jsonl');
  const external = join(dir, '..', 'unrelated-output-sentinel.jsonl');
  writeFileSync(external, 'INERT_OUTSIDE_CUSTODY_MUST_REMAIN_UNCHANGED\n');
  const before = readFileSync(external);
  symlinkSync(external, path);
  assert.throws(() => store.request('inert.need', { reason: 'fixture only', by: 'fixture-host' }),
    /credential requests.*(unavailable|symlink|source)/iu,
    'request append must not follow a link into unrelated storage');
  assert.deepEqual(readFileSync(external), before, 'no external file may be changed on refusal');
  assert.equal(existsSync(path), true, 'source evidence survives refusal without path replacement');
});

test('a corrupt existing request backlog refuses subsequent append without a false success receipt', t => {
  const { dir, store } = fixture(t), path = join(dir, 'requests.jsonl');
  store.request('prior.need', { reason: 'original need', by: 'host-a' });
  const valid = readFileSync(path);
  appendFileSync(path, '{incomplete-append\n');
  const corrupt = readFileSync(path);
  assert.throws(() => store.request('later.need', { reason: 'still-needed', by: 'host-b' }),
    /credential requests.*line 2.*invalid JSON/iu,
    'new requests cannot be reported accepted into unreadable custody');
  assert.deepEqual(readFileSync(path), corrupt, 'the new request must not silently append behind corrupted source');
  const attempted = cli(dir, 'request', 'later.need', '--reason', 'still-needed', '--by', 'host-b');
  assert.notEqual(attempted.status, 0);
  assert.equal(attempted.stdout, '', 'CLI must never acknowledge new Work on an unreadable ledger');
  assert.deepEqual(readFileSync(path), corrupt);
  writeFileSync(path, valid);
  const received = store.request('later.need', { reason: 'still-needed', by: 'host-b' });
  assert.equal(received.id, 'later.need');
  assert.deepEqual(store.requests().map(row => row.id), ['prior.need', 'later.need']);
});


test('an unterminated but parseable request row is incomplete custody, not permission to append', t => {
  const { dir, store } = fixture(t), path = join(dir, 'requests.jsonl');
  store.request('first.need', { reason: 'original accepted Work', by: 'host-a' });
  const valid = readFileSync(path, 'utf8');
  assert.equal(valid.endsWith('\n'), true, 'the original producer terminates each JSONL row');
  writeFileSync(path, valid.slice(0, -1));
  const interrupted = readFileSync(path);
  assert.throws(() => store.requests(), /credential requests.*(unterminated|newline|incomplete)/iu,
    'a complete JSON value without its append terminator may have been interrupted');
  for (const action of [['requests', '--all'], ['audit'], ['request', 'second.need', '--reason', 'still required', '--by', 'host-b']]) {
    const refused = cli(dir, ...action);
    assert.notEqual(refused.status, 0, 'the original backlog is not safe to receive Work');
    assert.equal(refused.stdout, '', 'do not fabricate a successful read or append receipt');
    assert.equal(refused.stderr.includes('original accepted Work'), false);
    assert.deepEqual(readFileSync(path), interrupted, 'no failed reader or producer may change custody');
  }
  assert.throws(() => store.request('second.need', { reason: 'still required', by: 'host-b' }),
    /credential requests.*(unterminated|newline|incomplete)/iu);
  assert.deepEqual(readFileSync(path), interrupted);
  writeFileSync(path, valid);
  assert.deepEqual(store.requests().map(row => row.id), ['first.need']);
  assert.equal(store.request('second.need', { reason: 'still required', by: 'host-b' }).id, 'second.need');
  assert.deepEqual(store.requests().map(row => row.id), ['first.need', 'second.need'],
    'complete source recovery admits both original and later demand without lost Work');
});
