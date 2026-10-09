import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { renderHost, placedPath } from '../src/render-host.mjs';
import { renderHost as renderBeforePlacement } from './fixtures/render-host-before-placement.mjs';

const host = 'synthetic-name-contract-host';
const controls = [...Array.from({ length: 32 }, (_, code) => code), 127];
const point = code => `U+${code.toString(16).toUpperCase().padStart(4, '0')}`;
const serviceRecord = service => ({ id: 'synthetic-env', consumers: [{ host, service, variable: 'SYNTHETIC_VALUE' }] });

function fixture(t, records = []) {
  const root = mkdtempSync(join(tmpdir(), 'render-name-contract-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const state = { records, value: 'SYNTHETIC_NONCREDENTIAL_VALUE', calls: 0 };
  const store = {
    records: () => state.records,
    render: async (selectedHost, service) => {
      assert.equal(selectedHost, host);
      assert.equal(typeof service, 'string');
      state.calls += 1;
      return `SYNTHETIC_VALUE=${state.value}\n`;
    },
    get: async (id, selectedHost) => {
      assert.equal(selectedHost, host);
      assert.equal(typeof id, 'string');
      state.calls += 1;
      return state.value;
    },
  };
  return { root, dir: join(root, 'runtime'), state, store };
}

test('all forbidden ASCII controls are refused before value reads or output creation', async t => {
  for (const code of controls) await t.test(point(code), async t => {
    const f = fixture(t, [serviceRecord(`synthetic${String.fromCodePoint(code)}service`)]);
    await assert.rejects(renderHost(f.store, host, f.dir), /filename component/);
    assert.equal(f.state.calls, 0);
    assert.equal(existsSync(f.dir), false);
  });
});

test('placed filename components share the same control refusal before effects', async t => {
  for (const code of controls) await t.test(point(code), async t => {
    const path = `synthetic/name${String.fromCodePoint(code)}part`;
    const f = fixture(t, [{ id: 'synthetic-file', consumers: [{ host, path }] }]);
    assert.throws(() => placedPath(path), /relative filename components/);
    await assert.rejects(renderHost(f.store, host, f.dir), /relative filename components/);
    assert.equal(f.state.calls, 0);
    assert.equal(existsSync(f.dir), false);
  });
});

test('valid printable characters remain accepted in names and placed components', async t => {
  // The accidental range excluded @, A-Z, [, ], ^ and _. Backslash stays forbidden.
  const names = [
    ...Array.from({ length: 32 }, (_, index) => index + 64).filter(code => code !== 92).map(code => `valid${String.fromCodePoint(code)}name`),
    'lowercase-0123.name', 'name with space', 'café', '.service',
  ];
  for (const service of names) await t.test(JSON.stringify(service), async t => {
    const f = fixture(t, [serviceRecord(service)]);
    await renderHost(f.store, host, f.dir);
    await renderHost(f.store, host, f.dir); // Read back the previous manifest with the same name.
    assert.equal(readFileSync(join(f.dir, `${service}.env`), 'utf8'), `SYNTHETIC_VALUE=${f.state.value}\n`);
    assert.equal(f.state.calls, 2);
    if (!service.startsWith('.')) assert.equal(placedPath(`synthetic/${service}`), `synthetic/${service}`);
  });
});

test('non-character name bounds and placed-path restrictions are unchanged', async t => {
  const f = fixture(t);
  for (const service of [undefined, null, 1, {}, '', '   ', '.', '..', 'a'.repeat(241), 'a/b', 'a\\b']) {
    f.state.records = [serviceRecord(service)];
    await assert.rejects(renderHost(f.store, host, f.dir), /filename component/);
    assert.equal(f.state.calls, 0);
    assert.equal(existsSync(f.dir), false);
  }
  assert.equal(placedPath('a'.repeat(240)), 'a'.repeat(240));
  assert.throws(() => placedPath('a'.repeat(241)), /relative filename components/);
  for (const path of ['files/name', '.hidden/name', 'service.env', '/absolute', 'trailing/', 'a/../b', 'a/b/c/d/e/f/g']) {
    assert.throws(() => placedPath(path), /relative filename components/);
  }
});

test('split manifests survive new-old-new-old-new rendering and final withdrawal', async t => {
  const f = fixture(t, [
    serviceRecord('synthetic-service'),
    { id: 'synthetic-conventional', consumers: [{ host, file: 'synthetic-unused-source' }] },
    { id: 'synthetic-placed', consumers: [{ host, service: 'synthetic-service', variable: 'SYNTHETIC_FILE', file: 'synthetic-unused-source', path: 'placed/synthetic.txt' }] },
  ]);
  const main = join(f.dir, '.credential-custody-render.json');
  const placed = join(f.dir, '.credential-custody-render-placed.json');
  let lastPlacedValue, placedManifest;
  for (const [index, renderer] of [renderHost, renderBeforePlacement, renderHost, renderBeforePlacement, renderHost].entries()) {
    const isCurrent = renderer === renderHost;
    f.state.value = `SYNTHETIC_NONCREDENTIAL_GENERATION_${index}`;
    const receipt = await renderer(f.store, host, f.dir);
    if (index === 0) writeFileSync(join(f.dir, 'unrelated.txt'), 'SYNTHETIC_KEEP');
    const mainText = readFileSync(main, 'utf8'), placedText = readFileSync(placed, 'utf8');
    assert.deepEqual(JSON.parse(mainText), {
      version: 1, host, state: 'complete',
      outputs: isCurrent ? ['files/synthetic-conventional', 'synthetic-service.env'] : ['files/synthetic-conventional', 'files/synthetic-placed', 'synthetic-service.env'],
    });
    assert.deepEqual(JSON.parse(placedText), { version: 1, host, state: 'complete', outputs: ['placed/synthetic.txt'] });
    for (const text of [JSON.stringify(receipt), mainText, placedText]) assert.equal(text.includes('SYNTHETIC_NONCREDENTIAL_'), false);
    for (const path of [main, placed]) assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.equal(readFileSync(join(f.dir, 'files/synthetic-conventional'), 'utf8'), f.state.value);
    const binding = isCurrent ? 'placed/synthetic.txt' : 'files/synthetic-placed';
    assert.equal(readFileSync(join(f.dir, 'synthetic-service.env'), 'utf8'), `SYNTHETIC_VALUE=${f.state.value}\nSYNTHETIC_FILE=${join(f.dir, binding)}\n`);
    if (isCurrent) {
      lastPlacedValue = f.state.value;
      placedManifest = placedText;
      assert.equal(existsSync(join(f.dir, 'files/synthetic-placed')), false);
    } else {
      assert.equal(placedText, placedManifest);
      assert.equal(readFileSync(join(f.dir, 'files/synthetic-placed'), 'utf8'), f.state.value);
    }
    assert.equal(readFileSync(join(f.dir, 'placed/synthetic.txt'), 'utf8'), lastPlacedValue);
    assert.equal(readFileSync(join(f.dir, 'unrelated.txt'), 'utf8'), 'SYNTHETIC_KEEP');
  }
  f.state.records = [];
  await renderHost(f.store, host, f.dir);
  for (const path of ['synthetic-service.env', 'files/synthetic-conventional', 'placed/synthetic.txt']) assert.equal(existsSync(join(f.dir, path)), false);
  for (const path of [main, placed]) assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')).outputs, []);
  assert.equal(readFileSync(join(f.dir, 'unrelated.txt'), 'utf8'), 'SYNTHETIC_KEEP');
});
