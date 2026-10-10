/**
 * Where code finds its credentials, and where it puts the ones it obtains.
 *
 * A process reads credentials only from its credentials directory, `CREDENTIALS_DIRECTORY` (systemd's name for the
 * same thing): this host's credentials rendered from its credential store into runtime memory (render-host), as
 * `<service>.env` files and file credentials at the relative paths their code reads (`keys/kalshi/<name>.pem`).
 * Code never defaults to a file in a home directory.
 *
 * A credential a process obtains (a key it generates, a token an OAuth grant returns, a key a person pastes) is
 * kept: sealed into the host's store, rendered at once so the process can read it back, and committed and pushed
 * so it reaches the store's other holders and its recovery recipients. Nothing writes a credential to a file of
 * its own.
 *
 *   CREDENTIALS_DIRECTORY  this host's rendered credentials (read)
 *   CREDENTIALS_STORE      the credential store, a services section's data/credentials/ in its checkout (keep)
 *   CREDENTIALS_HOST       this host (keep)
 */
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { openStore } from './store.mjs';
import { placedPath } from './render-host.mjs';

const need = (env, name, why) => env[name] || (() => { throw Object.assign(new Error(`${name} is not set: ${why}`), { code: 'CREDENTIALS_UNCONFIGURED' }); })();
const RENDERED = 'this process was not given its host\'s rendered credentials (credential-custody render-host)';
const slug = (s) => s.toLowerCase().replace(/[^a-z0-9.]+/gu, '-').replace(/^-|-$/gu, '');

/** This process's credentials directory. */
export const credentialsDirectory = (env = process.env) => need(env, 'CREDENTIALS_DIRECTORY', RENDERED);

/** Where a credential its code reads by relative path (`kalshi.env`, `fastmail/<account>.json`) is, for this process. */
export function credentialPath(relative, env = process.env) {
  const envFile = typeof relative === 'string' && /^[a-z0-9][a-z0-9._-]*\.env$/iu.test(relative);
  return join(credentialsDirectory(env), envFile ? relative : placedPath(relative));
}

export function commitAndPush(storeDir, message) {
  const git = (...args) => spawnSync('git', ['-C', storeDir, ...args], { encoding: 'utf8', timeout: 60_000 });
  const added = git('add', '-A', '.');
  if (added.status !== 0) return { committed: false, pushed: false, reason: added.stderr.trim() };
  const committed = git('-c', 'user.name=credential custody', '-c', 'user.email=credential-custody@users.noreply.github.com', 'commit', '-q', '-m', message);
  if (committed.status !== 0) return { committed: false, pushed: false, reason: (committed.stdout + committed.stderr).trim() };
  const pulled = git('pull', '-q', '--rebase');
  const pushed = pulled.status === 0 ? git('push', '-q') : pulled;
  return { committed: true, pushed: pushed.status === 0, ...(pushed.status === 0 ? {} : { reason: pushed.stderr.trim() }) };
}

/**
 * Keep a credential a process has just obtained. A file credential names the `path` its code reads it at (and, with
 * `variable`, the variable that names that path in `<service>.env`); an environment credential names only its
 * `variable`. A consumer already recorded for this host and service keeps its other fields. Returns where it can now
 * be read and whether the store's commit reached its origin (a push that fails leaves the commit for the next keep
 * or a person to push).
 */
export async function keepCredential({ id, value, service, path, variable, kind = 'other', provider = null, purpose = null }, env = process.env) {
  if (typeof value !== 'string' || !value) throw new TypeError('keepCredential: a value is required');
  if (!service || (!path && !variable)) throw new TypeError('keepCredential: a service and a path (a file credential) or a variable');
  const storeDir = need(env, 'CREDENTIALS_STORE', 'no credential store is configured for this process to keep credentials in');
  const host = need(env, 'CREDENTIALS_HOST', 'this process does not know which host it is');
  const dir = credentialsDirectory(env);
  const name = id ?? slug(`${service}.${variable ?? path}`);
  const consumer = path ? { host, service, path: placedPath(path), ...(variable ? { variable } : {}) } : { host, service, variable };
  const store = openStore(storeDir), old = store.record(name);
  const same = (c) => c.host === host && c.service === service && (path ? c.path === path : c.variable === variable && !c.path && !c.file);
  const prior = old?.consumers ?? [];
  const consumers = prior.some(same) ? prior.map((c) => (same(c) ? { ...c, ...consumer } : c)) : [...prior, consumer];
  await store.put(name, value, {
    ...(old ?? { kind, provider, purpose: purpose ?? `${variable ?? path} for ${service}` }),
    holders: [...new Set([...(old?.holders ?? []), host])], consumers,
  });
  await store.renderHost(host, dir);
  return { id: name, host, service, ...(path ? { path: join(dir, path) } : {}), ...(variable ? { variable } : {}), ...commitAndPush(storeDir, `Keep ${name} (${host}: ${service})`) };
}

/**
 * Forget a credential a process has revoked (a grant withdrawn, a key rotated out): it leaves the store, this host
 * re-renders (its output is withdrawn), and the store commits and pushes. Returns whether the store held it.
 */
export async function forgetCredential({ id }, env = process.env) {
  const storeDir = need(env, 'CREDENTIALS_STORE', 'no credential store is configured for this process to forget credentials in');
  const host = need(env, 'CREDENTIALS_HOST', 'this process does not know which host it is');
  const store = openStore(storeDir);
  if (!store.remove(id)) return { id, forgotten: false };
  await store.renderHost(host, credentialsDirectory(env));
  return { id, forgotten: true, ...commitAndPush(storeDir, `Forget ${id} (${host})`) };
}
