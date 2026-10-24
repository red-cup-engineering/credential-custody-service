import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, readdirSync, existsSync, rmSync, symlinkSync } from 'node:fs';
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



test('host enrollment never overwrites a preexisting temporary symlink outside the custody store', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-temp-symlink-enrollment-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const storePath = join(root, 'store'), sentinel = join(root, 'unrelated-sentinel');
  const pristine = 'INERT_UNRELATED_CONTENT_MUST_SURVIVE';
  writeFileSync(sentinel, pristine, { mode: 0o600 });
  const store = openStore(storePath);
  // A stale or malicious staging path must never be opened for writing:
  // recipients.json.tmp is not the final declared source document.
  symlinkSync(sentinel, join(storePath, 'recipients.json.tmp'));
  const enrolled = await store.initHost('fixture-host');
  assert.equal(enrolled.created, true);
  assert.equal(readFileSync(sentinel, 'utf8'), pristine, 'identity enrollment must not overwrite unrelated files');
  assert.equal(store.recipients().hosts['fixture-host'], enrolled.recipient);
});

test('sealed credential update never overwrites a preexisting temporary symlink outside the custody store', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-temp-symlink-seal-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const storePath = join(root, 'store'), sentinel = join(root, 'unrelated-sentinel');
  const pristine = 'INERT_UNRELATED_CONTENT_MUST_SURVIVE';
  writeFileSync(sentinel, pristine, { mode: 0o600 });
  const store = openStore(storePath);
  await store.initHost('fixture-host');
  symlinkSync(sentinel, join(storePath, 'sealed', 'fixture.id.age.tmp'));
  await store.put('fixture.id', 'INERT_SEALED_VALUE', { holders: ['fixture-host'], consumers: [] });
  assert.equal(readFileSync(sentinel, 'utf8'), pristine, 'sealing must not overwrite unrelated files');
  assert.equal(await store.get('fixture.id', 'fixture-host'), 'INERT_SEALED_VALUE');
});

test('host enrollment refuses traversal and invalid host labels before changing identity or recipients', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-host-label-refusal-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, 'store'), opened = openStore(path);
  const escaped = join(root, 'escaped.identity');
  writeFileSync(escaped, 'ORIGINAL_INERT_SENTINEL');
  for (const unsafeHost of ['../../escaped', '../escaped', 'invalid/name', 'invalid\\\\name', 'bad\\nname', 'bad\\rname', '', '..', 'bad host', 'UPPERCASE']) {
    await assert.rejects(opened.initHost(unsafeHost), /host.*(name|label)|invalid host/u, unsafeHost);
    const run = spawnSync(process.execPath, [
      new URL('../scripts/credentials.mjs', import.meta.url).pathname,
      '--store', path, '--host', unsafeHost, 'init-host',
    ], { encoding: 'utf8' });
    assert.notEqual(run.status, 0, 'CLI must also refuse invalid host labels');
    assert.equal(run.stdout, '', 'CLI must not claim enrollment');
    assert.equal(readFileSync(escaped, 'utf8'), 'ORIGINAL_INERT_SENTINEL');
    assert.equal(existsSync(join(path, 'recipients.json')), false, 'invalid host must not register recipients');
    assert.deepEqual(readdirSync(join(path, 'hosts')), [], 'invalid host must not mint an identity');
  }
  const healthy = await opened.initHost('fixture-host');
  assert.equal(healthy.created, true);
  assert.match(healthy.recipient, /^age1[0-9a-z]+$/u);
});

test('host enrollment refuses interrupted or mismatched custody instead of silently granting new identity', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-host-custody-refusal-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, 'store'), selectedHost = 'fixture-host', opened = openStore(path);
  const created = await opened.initHost(selectedHost);
  const identityPath = join(path, 'hosts', selectedHost + '.identity');
  const recipientsPath = join(path, 'recipients.json');
  const identity = readFileSync(identityPath, 'utf8');
  const recipients = readFileSync(recipientsPath, 'utf8');

  rmSync(recipientsPath); // interruption between private identity and recipient registration
  await assert.rejects(opened.initHost(selectedHost), /recipient|custody|incomplete|mismatch/u);
  assert.equal(readFileSync(identityPath, 'utf8'), identity);
  assert.equal(existsSync(recipientsPath), false);

  writeFileSync(recipientsPath, JSON.stringify({ hosts: { [selectedHost]: 'age1forged' }, recovery: [] }));
  const mismatched = readFileSync(recipientsPath, 'utf8');
  await assert.rejects(opened.initHost(selectedHost), /recipient|custody|mismatch/u);
  assert.equal(readFileSync(identityPath, 'utf8'), identity);
  assert.equal(readFileSync(recipientsPath, 'utf8'), mismatched);

  writeFileSync(recipientsPath, recipients);
  rmSync(identityPath); // a pre-existing grant must not be overwritten with fresh private key
  await assert.rejects(opened.initHost(selectedHost), /recipient|custody|identity|mismatch/u);
  assert.equal(existsSync(identityPath), false);
  assert.equal(readFileSync(recipientsPath, 'utf8'), recipients);

  // The original, uncorrupted enrollment remains valid and idempotent.
  assert.match(created.recipient, /^age1[0-9a-z]+$/u);
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


test('systemd EnvironmentFile preserves quoted, escaped and whitespace-bearing credentials and file paths', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-systemd-escape-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const storePath = join(root, 'store');
  const runtime = join(root, 'runtime\\with spaces');
  const host = 'fixture-host';
  const store = openStore(storePath);
  await store.initHost(host);
  const original = '  INERT\\route "quoted" $marker  ';
  await store.put('fixture-env', original, {
    holders: [host], consumers: [{ host, service: 'fixture', variable: 'FIXTURE_SECRET' }],
  });
  await store.put('fixture-file', 'INERT_FILE', {
    holders: [host], consumers: [{ host, service: 'fixture', path: 'keys/fixture.pem', variable: 'FIXTURE_FILE' }],
  });
  const direct = await store.render(host, 'fixture');
  assert.equal(direct, 'FIXTURE_SECRET=' + JSON.stringify(original) + '\n',
    'direct render must preserve the value through systemd EnvironmentFile quoting');
  const delivered = await store.renderHost(host, runtime);
  assert.deepEqual(delivered.services, ['fixture']);
  const env = readFileSync(join(runtime, 'fixture.env'));
  assert.equal(env.toString('utf8'), 'FIXTURE_SECRET=' + JSON.stringify(original) +
    '\nFIXTURE_FILE=' + JSON.stringify(join(runtime, 'keys/fixture.pem')) + '\n',
    'file path and secret must both round-trip through quoted systemd assignments');
  assert.equal(readFileSync(join(runtime, 'keys/fixture.pem'), 'utf8'), 'INERT_FILE');
  const manifest = readFileSync(join(runtime, '.credential-custody-render.json'));
  await store.put('fixture-env', 'INERT_CONTROL\tVALUE');
  await assert.rejects(store.render(host, 'fixture'), /single-line|control character/u,
    'embedded controls should not be silently delivered into an EnvironmentFile');
  await assert.rejects(store.renderHost(host, runtime), /single-line|control character/u);
  assert.deepEqual(readFileSync(join(runtime, 'fixture.env')), env);
  assert.deepEqual(readFileSync(join(runtime, '.credential-custody-render.json')), manifest);
});


test('duplicate environment bindings must refuse without retiring a healthy generation', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-env-collision-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const storePath = join(root, 'store'), runtime = join(root, 'runtime'), host = 'fixture-host';
  const store = openStore(storePath);
  await store.initHost(host);
  await store.put('first', 'INERT_FIRST', {
    holders: [host], consumers: [{ host, service: 'fixture', variable: 'DUPLICATE' }],
  });
  await store.renderHost(host, runtime);
  const envFile = join(runtime, 'fixture.env');
  const manifestFile = join(runtime, '.credential-custody-render.json');
  const beforeEnv = readFileSync(envFile), beforeManifest = readFileSync(manifestFile);
  const cli = () => spawnSync(process.execPath, [
    new URL('../scripts/credentials.mjs', import.meta.url).pathname,
    '--store', storePath, '--host', host, 'render-host', '--to', runtime,
  ], { encoding: 'utf8' });

  // Even a syntactically valid source must not silently select the last
  // secret sharing the same systemd environment variable name.
  await store.put('second', 'INERT_SECOND', {
    holders: [host], consumers: [{ host, service: 'fixture', variable: 'DUPLICATE' }],
  });
  await assert.rejects(store.render(host, 'fixture'), /duplicate.*environment.*DUPLICATE|DUPLICATE.*already bound/u);
  let refused = cli();
  assert.notEqual(refused.status, 0);
  assert.equal(refused.stdout, '');
  assert.match(refused.stderr, /duplicate.*environment.*DUPLICATE|DUPLICATE.*already bound/u);
  assert.deepEqual(readFileSync(envFile), beforeEnv);
  assert.deepEqual(readFileSync(manifestFile), beforeManifest);
  assert.equal(refused.stderr.includes('INERT_SECOND'), false);

  // A path binding also claims the environment variable. It must not
  // overwrite a secret just because it is backed by a different file.
  await store.put('second', 'INERT_FILE', {
    holders: [host], consumers: [{ host, service: 'fixture', variable: 'DUPLICATE', path: 'keys/fixture.pem' }],
  });
  refused = cli();
  assert.notEqual(refused.status, 0);
  assert.equal(refused.stdout, '');
  assert.match(refused.stderr, /duplicate.*environment.*DUPLICATE|DUPLICATE.*already bound/u);
  assert.deepEqual(readFileSync(envFile), beforeEnv);
  assert.deepEqual(readFileSync(manifestFile), beforeManifest);

  // Distinct names remain permitted and can be received normally.
  await store.put('second', 'INERT_FILE', {
    holders: [host], consumers: [{ host, service: 'fixture', variable: 'SECOND_FILE', path: 'keys/fixture.pem' }],
  });
  const accepted = cli();
  assert.equal(accepted.status, 0, accepted.stderr);
  assert.match(readFileSync(envFile, 'utf8'), /DUPLICATE=INERT_FIRST/u);
  assert.match(readFileSync(envFile, 'utf8'), /SECOND_FILE=/u);
  assert.equal(readFileSync(join(runtime, 'keys/fixture.pem'), 'utf8'), 'INERT_FILE');
});
