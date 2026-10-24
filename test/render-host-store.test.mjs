import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, readdirSync, existsSync, rmSync, symlinkSync, lstatSync } from 'node:fs';
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

test('single-service CLI render must not follow a stale temporary symlink into an unrelated file', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-render-output-symlink-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const storePath = join(root, 'store'), host = 'fixture-host';
  const sentinel = join(root, 'unrelated-sentinel');
  const output = join(root, 'fixture-service.env');
  const pristine = 'INERT_UNRELATED_FILE_MUST_SURVIVE';
  writeFileSync(sentinel, pristine, { mode: 0o600 });
  const store = openStore(storePath);
  await store.initHost(host);
  await store.put('fixture', 'INERT_ENV_SECRET', {
    holders: [host],
    consumers: [{ host, service: 'fixture-service', variable: 'FIXTURE_VALUE' }],
  });
  // The former fixed <output>.tmp path can be left behind or redirected to
  // unrelated content. Its presence must never become permission to overwrite.
  symlinkSync(sentinel, output + '.tmp');
  const rendered = spawnSync(process.execPath, [
    new URL('../scripts/credentials.mjs', import.meta.url).pathname,
    '--store', storePath, '--host', host, 'render', 'fixture-service', '--out', output,
  ], { encoding: 'utf8' });
  assert.equal(rendered.status, 0, rendered.stderr);
  assert.equal(readFileSync(sentinel, 'utf8'), pristine, 'render must never clobber an unrelated destination');
  assert.equal(readFileSync(output, 'utf8'), 'FIXTURE_VALUE=INERT_ENV_SECRET\n');
  assert.equal(rendered.stdout.includes('INERT_ENV_SECRET'), false, 'a file receipt must never include plaintext');
});

test('renaming custody refuses an existing orphaned sealed target without losing either encrypted value', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-rename-orphan-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const storePath = join(root, 'store'), host = 'fixture-host';
  const store = openStore(storePath);
  await store.initHost(host);
  await store.put('source', 'INERT_LIVE_SECRET', {
    holders: [host],
    consumers: [{ host, service: 'fixture-service', variable: 'TEST_VALUE' }],
  });
  const sourceRecord = join(storePath, 'registry/source.json');
  const sourceCipher = join(storePath, 'sealed/source.age');
  const targetRecord = join(storePath, 'registry/orphan.json');
  const targetCipher = join(storePath, 'sealed/orphan.age');
  const beforeRecord = readFileSync(sourceRecord);
  const beforeCipher = readFileSync(sourceCipher);
  // Interrupted recovery may leave encrypted bytes with no corresponding
  // registry record. "Unclaimed ID" does not authorize destruction of bytes.
  const orphanedBytes = 'INERT_UNRECONCILED_CIPHERTEXT_NOT_AUTHORIZED_TO_DELETE';
  writeFileSync(targetCipher, orphanedBytes, { mode: 0o600 });
  assert.throws(() => store.rename('source', 'orphan'), /sealed|exists|occupied|custody/iu);
  assert.deepEqual(readFileSync(sourceRecord), beforeRecord);
  assert.deepEqual(readFileSync(sourceCipher), beforeCipher);
  assert.equal(readFileSync(targetCipher, 'utf8'), orphanedBytes);
  assert.equal(existsSync(targetRecord), false);

  // A free id continues to permit a normal rename with the same sealed value.
  const moved = store.rename('source', 'renamed');
  assert.deepEqual(moved, { from: 'source', to: 'renamed' });
  assert.equal(await store.get('renamed', host), 'INERT_LIVE_SECRET');
  assert.equal(existsSync(sourceRecord), false);
  assert.equal(existsSync(sourceCipher), false);
});

test('put refuses orphaned sealed payloads and dangling links instead of overwriting unresolved custody', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-put-orphan-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const storePath = join(root, 'store'), host = 'fixture-host';
  const store = openStore(storePath);
  await store.initHost(host);
  const orphan = join(storePath, 'sealed', 'unclaimed.age');
  const preserved = 'INERT_ORPHAN_CIPHERTEXT_MUST_NOT_BE_OVERWRITTEN';
  writeFileSync(orphan, preserved, { mode: 0o600 });
  await assert.rejects(
    store.put('unclaimed', 'INERT_NEW_VALUE', { holders: [host], consumers: [] }),
    /sealed|orphan|exists|custody/iu,
    'an absent registry record never authorizes overwriting existing encrypted evidence',
  );
  assert.equal(readFileSync(orphan, 'utf8'), preserved);
  assert.equal(existsSync(join(storePath, 'registry/unclaimed.json')), false);

  const missing = join(root, 'missing-ciphertext');
  const dangling = join(storePath, 'sealed', 'dangling.age');
  symlinkSync(missing, dangling);
  await assert.rejects(
    store.put('dangling', 'INERT_OTHER_VALUE', { holders: [host], consumers: [] }),
    /sealed|orphan|exists|custody/iu,
    'a dangling symlink also reserves the name for explicit custody reconciliation',
  );
  assert.equal(existsSync(missing), false, 'refusal must not create the symlink target');
  assert.equal(existsSync(join(storePath, 'registry/dangling.json')), false);
  const { lstatSync, readlinkSync } = await import('node:fs');
  assert.equal(lstatSync(dangling).isSymbolicLink(), true);
  assert.equal(readlinkSync(dangling), missing);

  await store.put('new-id', 'INERT_VALID_VALUE', { holders: [host], consumers: [] });
  assert.equal(await store.get('new-id', host), 'INERT_VALID_VALUE', 'fresh unoccupied custody remains supported');
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

test('host enrollment preserves dangling identity links instead of reassigning unresolved custody', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-host-dangling-identity-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const storePath = join(root, 'store'), host = 'fixture-host';
  const store = openStore(storePath);
  const identityPath = join(storePath, 'hosts', host + '.identity');
  const missingTarget = join(root, 'missing-earlier-private-identity');
  symlinkSync(missingTarget, identityPath);
  const { lstatSync, readlinkSync } = await import('node:fs');

  await assert.rejects(store.initHost(host), /identity|custody|symlink|exists|regular/u,
    'a broken link reserves a private identity name until custody is explicitly reconciled');
  assert.equal(lstatSync(identityPath).isSymbolicLink(), true, 'refusal must retain dangling evidence');
  assert.equal(readlinkSync(identityPath), missingTarget);
  assert.equal(existsSync(missingTarget), false, 'refusal must not follow or fabricate a target');
  assert.equal(existsSync(join(storePath, 'recipients.json')), false, 'refusal must not grant a replacement host recipient');

  const cli = spawnSync(process.execPath, [
    new URL('../scripts/credentials.mjs', import.meta.url).pathname,
    '--store', storePath, '--host', host, 'init-host',
  ], { encoding: 'utf8' });
  assert.notEqual(cli.status, 0, 'installed producer must refuse the same unresolved custody');
  assert.equal(cli.stdout, '', 'refused enrollment must not claim success');
  assert.equal(lstatSync(identityPath).isSymbolicLink(), true);
  assert.equal(existsSync(join(storePath, 'recipients.json')), false);

  rmSync(identityPath);
  const created = await store.initHost(host);
  assert.equal(created.created, true, 'an unoccupied identity can still be enrolled');
  assert.equal(lstatSync(identityPath).isFile(), true);
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
  // A source author can no longer introduce the collision. Tamper with an
  // existing valid sealed record to verify the receiving guard separately.
  await store.put('second', 'INERT_SECOND', { holders: [host], consumers: [] });
  const secondRecordPath = join(storePath, 'registry/second.json');
  const corruptSource = consumer => {
    const rec = JSON.parse(readFileSync(secondRecordPath, 'utf8'));
    writeFileSync(secondRecordPath, JSON.stringify({ ...rec, consumers: [consumer] }, null, 2) + '\n');
  };
  corruptSource({ host, service: 'fixture', variable: 'DUPLICATE' });
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
  corruptSource({ host, service: 'fixture', variable: 'DUPLICATE', path: 'keys/fixture.pem' });
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


test('credential producers reject colliding service-variable grants before source mutation', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-producer-collision-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const storePath = join(root, 'store'), runtime = join(root, 'runtime'), host = 'fixture-host';
  const store = openStore(storePath);
  await store.initHost(host);
  await store.put('first', 'INERT_FIRST', {
    holders: [host], consumers: [{ host, service: 'fixture', variable: 'ALREADY_USED' }],
  });
  await store.put('second', 'INERT_SECOND', { holders: [host], consumers: [] });
  await store.put('file', 'INERT_FILE', {
    holders: [host], consumers: [{ host, service: 'fixture', file: '/inert/fixture.pem' }],
  });
  const snapshot = id => readFileSync(join(storePath, 'registry', id + '.json'));
  const sealed = id => readFileSync(join(storePath, 'sealed', id + '.age'));
  const secondRecord = snapshot('second'), secondCipher = sealed('second');
  const fileRecord = snapshot('file');

  assert.throws(() => store.bind('second', { host, service: 'fixture', variable: 'ALREADY_USED' }),
    /duplicate environment binding ALREADY_USED/u, 'bind must not poison valid source');
  assert.deepEqual(snapshot('second'), secondRecord, 'refused bind retains the existing registry');
  await assert.rejects(store.put('second', 'INERT_ROTATED', {
    holders: [host], consumers: [{ host, service: 'fixture', variable: 'ALREADY_USED' }],
  }), /duplicate environment binding ALREADY_USED/u,
  'put must reject a collision before replacing the previous sealed value');
  assert.deepEqual(snapshot('second'), secondRecord, 'refused put retains the prior record');
  assert.deepEqual(sealed('second'), secondCipher, 'refused put retains the prior sealed credential');
  assert.throws(() => store.bindFile('file', { host, service: 'fixture', variable: 'ALREADY_USED' }),
    /duplicate environment binding ALREADY_USED/u, 'file-backed binding must not replace an env credential');
  assert.deepEqual(snapshot('file'), fileRecord, 'refused file bind retains the registry');

  store.bind('second', { host, service: 'fixture', variable: 'DISTINCT' });
  const accepted = await store.renderHost(host, runtime);
  assert.deepEqual(accepted.services, ['fixture']);
  const env = readFileSync(join(runtime, 'fixture.env'), 'utf8');
  assert.match(env, /ALREADY_USED=INERT_FIRST/u);
  assert.match(env, /DISTINCT=INERT_SECOND/u);
});


test('registered rotation preserves unresolved sealed entries rather than legitimizing damage', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-rotation-linked-seal-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const storePath = join(root, 'store'), host = 'fixture-host';
  const opened = openStore(storePath);
  await opened.initHost(host);
  await opened.put('first', 'INERT_FIRST', { holders: [host], consumers: [] });
  await opened.put('other', 'INERT_OTHER', { holders: [host], consumers: [] });
  const registry = join(storePath, 'registry/first.json');
  const seal = join(storePath, 'sealed/first.age');
  const foreign = join(storePath, 'sealed/other.age');
  const registryBefore = readFileSync(registry);
  const original = readFileSync(seal);
  const otherBefore = readFileSync(foreign);

  rmSync(seal);
  symlinkSync(foreign, seal);
  await assert.rejects(opened.put('first', 'INERT_NOT_AUTHORIZED_TO_REPLACE_LINK', {}),
    /sealed credential.*(source|custody|regular|unavailable|symlink)/iu,
    'an existing registry record is not permission to erase linked sealed evidence');
  assert.equal(lstatSync(seal).isSymbolicLink(), true, 'linked custody evidence survives refusal');
  assert.deepEqual(readFileSync(registry), registryBefore);
  assert.deepEqual(readFileSync(foreign), otherBefore);

  rmSync(seal);
  symlinkSync(join(root, 'not-recovered-yet.age'), seal);
  await assert.rejects(opened.put('first', 'INERT_NOT_AUTHORIZED_TO_REPAIR_LINK', {}),
    /sealed credential.*(source|custody|regular|unavailable|symlink)/iu,
    'dangling sealed custody must remain unresolved, not be replaced');
  assert.equal(lstatSync(seal).isSymbolicLink(), true);
  assert.deepEqual(readFileSync(registry), registryBefore);

  rmSync(seal);
  await assert.rejects(opened.put('first', 'INERT_NOT_AUTHORIZED_TO_FILL_MISSING', {}),
    /sealed credential.*(source|custody|regular|unavailable|missing)/iu,
    'missing original ciphertext requires explicit reconciliation, not silent rotation');
  assert.deepEqual(readFileSync(registry), registryBefore);
  assert.equal(existsSync(seal), false);

  writeFileSync(seal, original);
  const rotated = await opened.put('first', 'INERT_VALID_ROTATION', {});
  assert.equal(rotated.id, 'first');
  assert.equal(await opened.get('first', host), 'INERT_VALID_ROTATION');
});


test('direct credential reads reject substituted sealed source links without leaking another value', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-direct-read-source-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const storePath = join(root, 'store'), runtime = join(root, 'runtime'), host = 'fixture-host';
  const opened = openStore(storePath);
  await opened.initHost(host);
  await opened.put('first', 'INERT_FIRST_CONFIDENTIAL', {
    holders: [host], consumers: [{ host, service: 'fixture', variable: 'FIXTURE_KEY' }],
  });
  await opened.put('other', 'INERT_OTHER_CONFIDENTIAL', { holders: [host], consumers: [] });
  assert.equal(await opened.get('first', host), 'INERT_FIRST_CONFIDENTIAL',
    'healthy credential reads still work');
  await assert.rejects(opened.get('other', 'unheld-host'), /does not hold/u,
    'an unheld host never receives an unrelated credential');

  await opened.renderHost(host, runtime);
  const sealed = join(storePath, 'sealed/first.age');
  const other = join(storePath, 'sealed/other.age');
  const original = readFileSync(sealed), otherCipher = readFileSync(other);
  const priorEnv = readFileSync(join(runtime, 'fixture.env'));
  const manifest = readFileSync(join(runtime, '.credential-custody-render.json'));

  rmSync(sealed);
  symlinkSync(other, sealed);
  await assert.rejects(opened.get('first', host), /sealed credential source.*(symlink|regular|unavailable)/iu,
    'a registry grant for first must not decrypt substituted ciphertext belonging to other');
  await assert.rejects(opened.renderHost(host, runtime), /sealed.*(source|regular|unavailable)/iu,
    'a linked source is incomplete, not an authorized new render generation');
  assert.deepEqual(readFileSync(join(runtime, 'fixture.env')), priorEnv);
  assert.deepEqual(readFileSync(join(runtime, '.credential-custody-render.json')), manifest);
  assert.deepEqual(readFileSync(other), otherCipher);
  assert.equal(lstatSync(sealed).isSymbolicLink(), true);

  rmSync(sealed);
  symlinkSync(join(root, 'unresolved-sealed-source.age'), sealed);
  await assert.rejects(opened.get('first', host), /sealed credential source.*(symlink|regular|unavailable)/iu,
    'dangling source evidence must also fail closed, not be followed');
  assert.equal(lstatSync(sealed).isSymbolicLink(), true);
  assert.deepEqual(readFileSync(join(runtime, 'fixture.env')), priorEnv);

  rmSync(sealed);
  writeFileSync(sealed, original);
  assert.equal(await opened.get('first', host), 'INERT_FIRST_CONFIDENTIAL',
    'restored original custody remains decryptable');
});


test('host enrollment refuses malformed recipient registries before creating private identity', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-recipient-integrity-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const host = 'fixture-host';
  const malformed = [
    { record: { hosts: null, recovery: [] }, recovery: false },
    { record: { hosts: [], recovery: [] }, recovery: false },
    { record: { hosts: {}, recovery: 'not-a-list' }, recovery: true },
    { record: { hosts: {}, recovery: { broken: true } }, recovery: true },
  ];
  for (const [index, candidate] of malformed.entries()) {
    const storePath = join(root, 'bad-' + index);
    const opened = openStore(storePath);
    const recipientFile = join(storePath, 'recipients.json');
    const before = JSON.stringify(candidate.record, null, 2) + '\n';
    writeFileSync(recipientFile, before);
    await assert.rejects(opened.initHost(host, { recovery: candidate.recovery }),
      /recipients.*(invalid|malformed|custody|shape)/iu,
      'incomplete recipient metadata is not permission to leave an orphan private identity');
    assert.equal(existsSync(join(storePath, 'hosts', host + '.identity')), false,
      'invalid registration must be rejected before any private identity is published');
    assert.equal(readFileSync(recipientFile, 'utf8'), before,
      'invalid public registration evidence must not be rewritten or silently repaired');
  }
  const healthy = openStore(join(root, 'healthy'));
  const enrolled = await healthy.initHost(host, { recovery: true });
  assert.equal(enrolled.created, true, 'valid first recovery enrollment remains supported');
  assert.equal(healthy.recipients().recovery.includes(enrolled.recipient), true);
});

test('new credential cannot claim another credential\'s installed placed output', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-placed-new-collision-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const selected = 'fixture-host', path = join(root, 'source'), store = openStore(path);
  await store.initHost(selected);
  await store.put('first', 'INERT_FIRST', {
    holders: [selected], consumers: [{ host: selected, service: 'first-service', variable: 'FIRST_FILE', path: 'keys/shared.pem' }],
  });
  const firstCipher = readFileSync(join(path, 'sealed/first.age'));
  const firstRecord = readFileSync(join(path, 'registry/first.json'));
  await assert.rejects(store.put('second', 'INERT_SECOND', {
    holders: [selected], consumers: [{ host: selected, service: 'second-service', variable: 'SECOND_FILE', path: 'keys/shared.pem' }],
  }), /conflicting file placement/u, 'the second credential may not take the first credential\'s runtime filename');
  assert.equal(existsSync(join(path, 'registry/second.json')), false, 'refusal must precede record creation');
  assert.equal(existsSync(join(path, 'sealed/second.age')), false, 'refusal must precede encryption/publication');
  assert.deepEqual(readFileSync(join(path, 'sealed/first.age')), firstCipher);
  assert.deepEqual(readFileSync(join(path, 'registry/first.json')), firstRecord);
});

test('rotation cannot replace healthy ciphertext when its new placed path collides', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-placed-rotate-collision-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const selected = 'fixture-host', path = join(root, 'source'), runtime = join(root, 'runtime'), store = openStore(path);
  await store.initHost(selected);
  await store.put('first', 'INERT_FIRST', {
    holders: [selected], consumers: [{ host: selected, service: 'fixture', variable: 'FIRST_PATH', path: 'keys/first.pem' }],
  });
  await store.put('second', 'INERT_SECOND', {
    holders: [selected], consumers: [{ host: selected, service: 'fixture', variable: 'SECOND_PATH', path: 'keys/second.pem' }],
  });
  await store.renderHost(selected, runtime);
  const baseline = {
    second: readFileSync(join(path, 'sealed/second.age')),
    record: readFileSync(join(path, 'registry/second.json')),
    firstOutput: readFileSync(join(runtime, 'keys/first.pem')),
    secondOutput: readFileSync(join(runtime, 'keys/second.pem')),
    manifest: readFileSync(join(runtime, '.credential-custody-render.json')),
    placedManifest: readFileSync(join(runtime, '.credential-custody-render-placed.json')),
  };
  await assert.rejects(store.put('second', 'INERT_ROTATED_BUT_NOT_ALLOWED', {
    consumers: [{ host: selected, service: 'fixture', variable: 'SECOND_PATH', path: 'keys/first.pem' }],
  }), /conflicting file placement/u, 'a conflicting output must be refused before rotation replaces sealed bytes');
  assert.deepEqual(readFileSync(join(path, 'sealed/second.age')), baseline.second);
  assert.deepEqual(readFileSync(join(path, 'registry/second.json')), baseline.record);
  const good = await store.renderHost(selected, runtime);
  assert.deepEqual(good.services, ['fixture']);
  assert.deepEqual(readFileSync(join(runtime, 'keys/first.pem')), baseline.firstOutput);
  assert.deepEqual(readFileSync(join(runtime, 'keys/second.pem')), baseline.secondOutput);
  assert.deepEqual(readFileSync(join(runtime, '.credential-custody-render.json')), baseline.manifest);
  assert.deepEqual(readFileSync(join(runtime, '.credential-custody-render-placed.json')), baseline.placedManifest);
});

test('binding refuses a file placed beneath an existing file and preserves its source', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-placed-nested-collision-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const selected = 'fixture-host', path = join(root, 'source'), store = openStore(path);
  await store.initHost(selected);
  await store.put('first', 'INERT_FIRST', {
    holders: [selected], consumers: [{ host: selected, service: 'fixture', variable: 'FIRST_PATH', path: 'keys/fixture.pem' }],
  });
  await store.put('second', 'INERT_SECOND', { holders: [selected], consumers: [] });
  const original = readFileSync(join(path, 'registry/second.json'));
  assert.throws(() => store.bind('second', {
    host: selected, service: 'another', variable: 'SECOND_PATH', path: 'keys/fixture.pem/private.pem',
  }), /conflicting file placement/u, 'a file cannot simultaneously be an output and a parent directory');
  assert.deepEqual(readFileSync(join(path, 'registry/second.json')), original);
});

test('same credential multi-service placed output and other-host independent placements remain healthy', async t => {
  const root = mkdtempSync(join(tmpdir(), 'credential-placed-shared-valid-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, 'source'), store = openStore(path);
  await store.initHost('fixture-one');
  await store.initHost('fixture-two');
  await store.put('first', 'INERT_FIRST', {
    holders: ['fixture-one', 'fixture-two'],
    consumers: [{ host: 'fixture-one', service: 'one', variable: 'FIRST_PATH', path: 'keys/shared.pem' },
      { host: 'fixture-one', service: 'two', variable: 'ALSO_FIRST', path: 'keys/shared.pem' }],
  });
  await store.put('second', 'INERT_SECOND', {
    holders: ['fixture-two'],
    consumers: [{ host: 'fixture-two', service: 'two', variable: 'SECOND_PATH', path: 'keys/shared.pem' }],
  });
  assert.equal((await store.renderHost('fixture-one', join(root, 'one'))).files.length, 1);
  assert.equal((await store.renderHost('fixture-two', join(root, 'two'))).files.length, 1);
  assert.equal(readFileSync(join(root, 'one/keys/shared.pem'), 'utf8'), 'INERT_FIRST');
  assert.equal(readFileSync(join(root, 'two/keys/shared.pem'), 'utf8'), 'INERT_SECOND');
});
