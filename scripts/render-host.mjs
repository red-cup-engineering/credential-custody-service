#!/usr/bin/env node
/**
 * Render this host's credentials, configured wholly by its environment so a service manager can run it as a unit:
 *
 *   CREDENTIALS_STORE      the store (a services section's data/credentials/, in that section's checkout)
 *   CREDENTIALS_HOST       this host
 *   CREDENTIALS_RENDER_TO  the runtime directory to render into (e.g. /run/user/<uid>/<holder>-credentials)
 *   CREDENTIALS_IDENTITIES this host's identity directory, in its own machine state (default <store>/hosts)
 *   CREDENTIALS_PULL       when "1", fast-forward the store's checkout first so new and rotated credentials arrive,
 *                          then reseal what this host holds whose holders changed (CREDENTIALS_RESEAL=0 skips it)
 */
import { execFileSync } from 'node:child_process';
import { openStore } from '../src/store.mjs';
import { assertRenderableStore } from '../src/render-source-admission.mjs';
import { commitAndPush } from '../src/keep.mjs';

process.on('uncaughtException', (error) => { process.stderr.write(`render-host: ${error.message}\n`); process.exit(1); });
const need = (name) => process.env[name] || (() => { throw new Error(`${name} is required`); })();
const store = need('CREDENTIALS_STORE'), host = need('CREDENTIALS_HOST'), to = need('CREDENTIALS_RENDER_TO');
const located = process.env.CREDENTIALS_IDENTITIES ? { identities: process.env.CREDENTIALS_IDENTITIES } : {};
// The services wait on this render: an unreachable origin renders what the checkout already holds.
if (process.env.CREDENTIALS_PULL === '1') {
  // Never run Git against a misselected checkout, even before output pruning.
  await assertRenderableStore(store, host, located);
  try { execFileSync('git', ['-C', store, 'pull', '-q', '--ff-only'], { stdio: ['ignore', 'inherit', 'inherit'], timeout: 60_000 }); }
  catch (error) { process.stderr.write(`render-host: pull failed, rendering the checkout as it stands: ${error.message.split('\n')[0]}\n`); }
}
await assertRenderableStore(store, host, located);
const opened = openStore(store, { create: false, ...located });
// A pulled grant reaches its new holder without anyone running reseal: this host reseals what it holds whose
// holders changed, and pushes so the new holder's next pull opens it. CREDENTIALS_RESEAL=0 turns it off.
if (process.env.CREDENTIALS_PULL === '1' && process.env.CREDENTIALS_RESEAL !== '0') {
  const { resealed, skipped } = await opened.resealChanged(host);
  for (const { id, reason } of skipped) process.stderr.write(`render-host: ${id} not resealed: ${reason}\n`);
  if (resealed.length) {
    const kept = commitAndPush(store, `Reseal ${resealed.length} credential(s) to their holders (${host})`);
    process.stderr.write(`render-host: resealed ${resealed.join(', ')}${kept.pushed ? '' : ` (not pushed: ${kept.reason ?? 'no commit'})`}\n`);
  }
}
process.stdout.write(`${JSON.stringify(await opened.renderHost(host, to))}\n`);
