import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openStore } from '../src/store.mjs';

const host = 'fixture-host';
const script = new URL('../scripts/render-host.mjs', import.meta.url).pathname;
const cli = new URL('../scripts/credentials.mjs', import.meta.url).pathname;
const fixture = t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-source-refusal-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return { root, store: join(root, 'source'), runtime: join(root, 'runtime') };
};
const runUnit = (store, runtime, selectedHost = host, pull = '0') =>
  spawnSync(process.execPath, [script], {
    encoding: 'utf8',
    env: { ...process.env, CREDENTIALS_STORE: store, CREDENTIALS_HOST: selectedHost, CREDENTIALS_RENDER_TO: runtime, CREDENTIALS_PULL: pull },
  });
const runCli = (store, runtime, selectedHost = host, command = 'render-host') =>
  spawnSync(process.execPath, [cli, '--store', store, '--host', selectedHost, command, ...(command === 'render-host' ? ['--to', runtime] : ['example-service'])], { encoding: 'utf8' });

function seedLiveOutput(runtime) {
  mkdirSync(runtime, { recursive: true });
  writeFileSync(join(runtime, 'kept.env'), 'PREVIOUSLY_RENDERED_INERT_VALUE\n', { mode: 0o600 });
  const manifest = JSON.stringify({ version: 1, host, state: 'complete', outputs: ['kept.env'] });
  writeFileSync(join(runtime, '.credential-custody-render.json'), manifest);
  return manifest;
}

function refuseWithoutPruning(result, store, runtime, manifest, expected) {
  assert.notEqual(result.status, 0, 'failed source admission must exit nonzero');
  assert.equal(result.stdout, '', 'do not report an empty render as successful');
  assert.ok(result.stderr.includes(store), 'diagnostic must identify the original selected store');
  assert.match(result.stderr, expected);
  assert.equal(readFileSync(join(runtime, 'kept.env'), 'utf8'), 'PREVIOUSLY_RENDERED_INERT_VALUE\n');
  assert.equal(readFileSync(join(runtime, '.credential-custody-render.json'), 'utf8'), manifest);
}

test('standalone host unit never creates a missing store or prunes a live render after failed pull', t => {
  const f = fixture(t), manifest = seedLiveOutput(f.runtime);
  for (const pull of ['0', '1']) {
    const run = runUnit(f.store, f.runtime, host, pull);
    refuseWithoutPruning(run, f.store, f.runtime, manifest, /unavailable/u);
    assert.equal(existsSync(f.store), false, 'rendering cannot fabricate a new empty store');
  }
});

test('both CLI rendering paths fail closed on absent source and do not fabricate it', t => {
  const f = fixture(t), manifest = seedLiveOutput(f.runtime);
  for (const command of ['render-host', 'render']) {
    refuseWithoutPruning(runCli(f.store, f.runtime, host, command), f.store, f.runtime, manifest, /unavailable/u);
    assert.equal(existsSync(f.store), false);
  }
});

test('direct store entrypoints do not demote missing source into a valid empty store', async t => {
  const f = fixture(t), manifest = seedLiveOutput(f.runtime);
  const opened = openStore(f.store, { create: false });
  await assert.rejects(opened.render(host, 'example-service'), /credential store.*unavailable/u);
  await assert.rejects(opened.renderHost(host, f.runtime), /credential store.*unavailable/u);
  assert.equal(existsSync(f.store), false);
  assert.equal(readFileSync(join(f.runtime, '.credential-custody-render.json'), 'utf8'), manifest);
});

test('missing sealed, registry, host identity and recipients never withdraw a previous render', async t => {
  const f = fixture(t), manifest = seedLiveOutput(f.runtime);
  const opened = openStore(f.store);
  await opened.initHost(host);
  const identityPath = join(f.store, 'hosts', host + '.identity');
  const identity = readFileSync(identityPath, 'utf8');
  const recipientsPath = join(f.store, 'recipients.json');
  const recipients = readFileSync(recipientsPath, 'utf8');
  const cases = [
    { path: join(f.store, 'sealed'), dir: true, expected: /sealed.*ENOENT/u },
    { path: join(f.store, 'registry'), dir: true, expected: /registry.*ENOENT/u },
    { path: identityPath, restore: identity, expected: /identity.*ENOENT/u },
    { path: recipientsPath, restore: recipients, expected: /recipients.*ENOENT/u },
  ];
  for (const entry of cases) {
    rmSync(entry.path, { recursive: Boolean(entry.dir), force: true });
    refuseWithoutPruning(runUnit(f.store, f.runtime), f.store, f.runtime, manifest, entry.expected);
    refuseWithoutPruning(runCli(f.store, f.runtime), f.store, f.runtime, manifest, entry.expected);
    if (entry.dir) {
      assert.equal(existsSync(entry.path), false, 'render command may not rebuild missing source directories');
      mkdirSync(entry.path);
    } else {
      assert.equal(existsSync(entry.path), false, 'render command may not recreate source identity');
      writeFileSync(entry.path, entry.restore, { mode: 0o600 });
    }
  }
  const wrongHost = runUnit(f.store, f.runtime, 'other-host');
  refuseWithoutPruning(wrongHost, f.store, f.runtime, manifest, /other-host.*identity.*ENOENT/u);
  writeFileSync(recipientsPath, '{malformed json');
  refuseWithoutPruning(runUnit(f.store, f.runtime), f.store, f.runtime, manifest, /cannot read recipients/u);
  writeFileSync(recipientsPath, recipients);
  // A different valid age recipient is not the selected host's public half.
  await opened.initHost('other-valid-holder');
  const mismatched = JSON.parse(readFileSync(recipientsPath, 'utf8'));
  mismatched.hosts[host] = mismatched.hosts['other-valid-holder'];
  writeFileSync(recipientsPath, JSON.stringify(mismatched));
  refuseWithoutPruning(runUnit(f.store, f.runtime), f.store, f.runtime, manifest, /identity and recipient mismatch/u);
  writeFileSync(recipientsPath, recipients);
  writeFileSync(identityPath, 'INVALID_HOST_IDENTITY\n', { mode: 0o600 });
  refuseWithoutPruning(runUnit(f.store, f.runtime), f.store, f.runtime, manifest, /invalid host identity/u);
  writeFileSync(identityPath, identity, { mode: 0o600 });
  const healthy = runUnit(f.store, join(f.root, 'empty-valid-runtime'));
  assert.equal(healthy.status, 0, healthy.stderr);
  assert.deepEqual(JSON.parse(healthy.stdout).services, [], 'an authenticated empty store is legitimately empty');
});

test('an enumerated registry entry that vanished is a source refusal, never permission to withdraw output', async t => {
  const f = fixture(t), manifest = seedLiveOutput(f.runtime);
  const opened = openStore(f.store);
  await opened.initHost(host);
  // A dangling link has a directory entry but its target vanished between
  // enumeration and read. The old records() silently filtered ENOENT to null,
  // mistakenly authorizing an empty render and deleting managed outputs.
  const missingRecord = join(f.store, 'registry', 'vanished.json');
  symlinkSync(join(f.root, 'not-there.json'), missingRecord);
  for (const result of [runUnit(f.store, f.runtime), runCli(f.store, f.runtime)]) {
    refuseWithoutPruning(result, f.store, f.runtime, manifest, /ENOENT.*vanished\.json/u);
  }
  await assert.rejects(opened.renderHost(host, f.runtime), /vanished\.json|ENOENT/u);
  assert.equal(readFileSync(join(f.runtime, 'kept.env'), 'utf8'), 'PREVIOUSLY_RENDERED_INERT_VALUE\n');
  assert.equal(readFileSync(join(f.runtime, '.credential-custody-render.json'), 'utf8'), manifest);
});

test('unreadable sealed source is not a valid empty store and must preserve earlier output', async t => {
  const f = fixture(t), manifest = seedLiveOutput(f.runtime);
  const opened = openStore(f.store);
  await opened.initHost(host);
  const sealed = join(f.store, 'sealed');
  chmodSync(sealed, 0o000);
  try {
    for (const result of [runUnit(f.store, f.runtime), runCli(f.store, f.runtime)]) {
      refuseWithoutPruning(result, f.store, f.runtime, manifest, /unavailable: .*sealed.*(unreadable|EACCES)/u);
    }
  } finally {
    chmodSync(sealed, 0o700);
  }
  const healthy = runUnit(f.store, join(f.root, 'verified-valid'));
  assert.equal(healthy.status, 0, healthy.stderr);
});

test('a registry filename/record-id mismatch cannot silently withdraw live credentials', async t => {
  const f = fixture(t), manifest = seedLiveOutput(f.runtime);
  const opened = openStore(f.store);
  await opened.initHost(host);
  // A partial rename or wrongly installed record can leave a valid JSON object
  // with an id from another filename. The old renderer accepted the empty
  // consumer list and reported successful pruning of the healthy generation.
  const path = join(f.store, 'registry', 'renamed-record.json');
  writeFileSync(path, JSON.stringify({
    id: 'original-record', holders: [host], consumers: [],
  }));
  for (const result of [runUnit(f.store, f.runtime), runCli(f.store, f.runtime)]) {
    refuseWithoutPruning(result, f.store, f.runtime, manifest, /registry.*renamed-record[.]json.*id.*mismatch/u);
  }
  await assert.rejects(opened.renderHost(host, f.runtime), /registry.*renamed-record[.]json.*id.*mismatch/u);
});

test('a partial registry record must never be interpreted as permission to erase a healthy generation', async t => {
  const f = fixture(t), manifest = seedLiveOutput(f.runtime);
  const opened = openStore(f.store);
  await opened.initHost(host);
  const path = join(f.store, 'registry', 'partial.json');
  const invalid = [
    ['absent consumers', { id: 'partial', holders: [host] }],
    ['null consumers', { id: 'partial', holders: [host], consumers: null }],
    ['string consumers', { id: 'partial', holders: [host], consumers: '' }],
    ['false consumer entry', { id: 'partial', holders: [host], consumers: [false] }],
    ['absent holders', { id: 'partial', consumers: [] }],
  ];
  for (const [label, record] of invalid) {
    writeFileSync(path, JSON.stringify(record) + '\n');
    for (const result of [runUnit(f.store, f.runtime), runCli(f.store, f.runtime)]) {
      refuseWithoutPruning(result, f.store, f.runtime, manifest, /registry.*partial[.]json.*(holders|consumers)/u);
    }
    await assert.rejects(opened.renderHost(host, f.runtime), /registry.*partial[.]json.*(holders|consumers)/u, label);
  }
  // The refusal must not incorrectly prohibit an intentionally empty but
  // complete source: an authorized retirement can still withdraw stale output.
  rmSync(path);
  await opened.put('partial', 'INERT_FIXTURE_VALUE', { holders: [host] });
  const healthy = runUnit(f.store, f.runtime);
  assert.equal(healthy.status, 0, healthy.stderr);
  assert.equal(existsSync(join(f.runtime, 'kept.env')), false, 'valid empty consumers retire stale output');
  const received = JSON.parse(readFileSync(join(f.runtime, '.credential-custody-render.json'), 'utf8'));
  assert.equal(received.state, 'complete');
  assert.deepEqual(received.outputs, []);
});
