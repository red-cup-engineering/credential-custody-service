#!/usr/bin/env node
/**
 * Render this host's credentials, configured wholly by its environment so a service manager can run it as a unit:
 *
 *   CREDENTIALS_STORE      the store (a services section's data/credentials/, in that section's checkout)
 *   CREDENTIALS_HOST       this host
 *   CREDENTIALS_RENDER_TO  the runtime directory to render into (e.g. /run/user/<uid>/<holder>-credentials)
 *   CREDENTIALS_PULL       when "1", fast-forward the store's checkout first so new and rotated credentials arrive
 */
import { execFileSync } from 'node:child_process';
import { openStore } from '../src/store.mjs';

process.on('uncaughtException', (error) => { process.stderr.write(`render-host: ${error.message}\n`); process.exit(1); });
const need = (name) => process.env[name] || (() => { throw new Error(`${name} is required`); })();
const store = need('CREDENTIALS_STORE'), host = need('CREDENTIALS_HOST'), to = need('CREDENTIALS_RENDER_TO');
if (process.env.CREDENTIALS_PULL === '1') execFileSync('git', ['-C', store, 'pull', '-q', '--ff-only'], { stdio: ['ignore', 'inherit', 'inherit'] });
process.stdout.write(`${JSON.stringify(await openStore(store).renderHost(host, to))}\n`);
