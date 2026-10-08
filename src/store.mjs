/**
 * A credential store: the registry of the credentials a holder (an organization) keeps, and their values sealed
 * to the hosts allowed to use them. The store is a directory, normally a services section's `data/credentials/`,
 * tracked in that section's repository: everything in it is safe to publish to the section's readers except
 * `hosts/`, which is git-ignored and holds each host's own identity.
 *
 *   recipients.json        { hosts: { <host>: "age1…" }, recovery: ["age1…"] }  public keys
 *   registry/<id>.json     one record per credential: what it is, whose it is, who holds and uses it; never the value
 *   sealed/<id>.age        the value, sealed to its holders and the recovery recipients
 *   requests.jsonl         credentials asked for and not yet held: the one list a person works through
 *   hosts/<host>.identity  this host's private identity (git-ignored, 0600)
 *
 * Vocabulary (561 Group note 2026-08-09, inventory of authentication and credential code): a credential carries
 * evidence or authority; custody controls its storage and use. This store is custody; it does not authenticate
 * or authorize anything.
 */
import { createHash } from 'node:crypto';
import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateIdentity, openWith, recipientOf, sealTo } from './recipient-seal.mjs';
import { placedPath, renderHost as renderHostCredentials } from './render-host.mjs';

export const KINDS = Object.freeze(['api-key', 'oauth-client-secret', 'oauth-refresh-token', 'token', 'password', 'passphrase', 'private-key', 'session-secret', 'other']);
const ID = /^[a-z0-9][a-z0-9.-]{0,95}$/u;

/** A short public fingerprint of a value: finds plaintext copies and duplicates without recording the value. */
export const fingerprint = (value) => createHash('sha256').update(value).digest('hex').slice(0, 16);

const readJson = (path, fallback) => { try { return JSON.parse(readFileSync(path, 'utf8')); } catch (error) { if (error.code === 'ENOENT') return fallback; throw error; } };
const writeAtomic = (path, text, mode = 0o644) => { writeFileSync(`${path}.tmp`, text, { mode }); chmodSync(`${path}.tmp`, mode); renameSync(`${path}.tmp`, path); };

export function openStore(dir) {
  if (!dir) throw new TypeError('a credential store directory is required (a services section data/credentials/)');
  for (const sub of ['registry', 'sealed', 'hosts']) mkdirSync(join(dir, sub), { recursive: true });
  const ignore = join(dir, '.gitignore');
  if (!existsSync(ignore)) writeFileSync(ignore, 'hosts/\n*.tmp\n');
  const recipientsPath = join(dir, 'recipients.json');
  const recipients = () => readJson(recipientsPath, { hosts: {}, recovery: [] });
  const recordPath = (id) => { if (!ID.test(id)) throw new TypeError(`credential id ${id} must be lowercase letters, digits, dots and dashes`); return join(dir, 'registry', `${id}.json`); };
  const identityPath = (host) => join(dir, 'hosts', `${host}.identity`);

  function identity(host) {
    const path = identityPath(host);
    if (!existsSync(path)) throw new Error(`host ${host} has no identity in ${join(dir, 'hosts')}; run: credentials init-host ${host}`);
    if ((statSync(path).mode & 0o077) !== 0) throw new Error(`${path} is readable by others; chmod 600 it`);
    return readFileSync(path, 'utf8').trim();
  }
  const record = (id) => readJson(recordPath(id), null);
  const records = () => readdirSync(join(dir, 'registry')).filter((f) => f.endsWith('.json')).map((f) => readJson(join(dir, 'registry', f), null)).filter(Boolean);
  const sealFor = (holders) => {
    const r = recipients(), keys = [...holders.map((h) => { if (!r.hosts[h]) throw new Error(`host ${h} has no recipient in recipients.json`); return r.hosts[h]; }), ...r.recovery];
    return [...new Set(keys)];
  };

  return {
    dir, recipients, record, records,

    /** Create this host's identity (once) and record its public recipient. */
    async initHost(host, { recovery = false } = {}) {
      const path = identityPath(host);
      if (existsSync(path)) return { host, recipient: recipientOf(identity(host)), created: false };
      const id = await generateIdentity(), recipient = await recipientOf(id);
      writeAtomic(path, `${id}\n`, 0o600);
      const r = recipients();
      if (recovery) r.recovery = [...new Set([...(r.recovery ?? []), recipient])]; else r.hosts[host] = recipient;
      writeAtomic(recipientsPath, `${JSON.stringify(r, null, 2)}\n`);
      return { host, recipient, created: true, recovery };
    },

    /** Register (or update) a credential and seal its value to its holders. */
    async put(id, value, fields = {}) {
      const now = new Date().toISOString(), old = record(id) ?? {};
      const next = { id, provider: null, kind: 'other', owner: null, purpose: null, holders: [], consumers: [], rotateEveryDays: null, createdAt: now, ...old, ...fields, fingerprint: fingerprint(value), rotatedAt: old.fingerprint && old.fingerprint !== fingerprint(value) ? now : (old.rotatedAt ?? now) };
      if (!KINDS.includes(next.kind)) throw new TypeError(`kind ${next.kind} is not one of ${KINDS.join(', ')}`);
      if (!next.holders.length) throw new TypeError(`credential ${id} needs at least one holder host`);
      writeAtomic(join(dir, 'sealed', `${id}.age`), await sealTo(value, sealFor(next.holders)));
      writeAtomic(recordPath(id), `${JSON.stringify(next, null, 2)}\n`);
      return next;
    },

    /** A credential's value, opened with this host's identity. */
    async get(id, host) {
      const rec = record(id);
      if (!rec) throw new Error(`no credential ${id} in this store; ask for it with: credentials request ${id} --reason "…"`);
      if (!rec.holders.includes(host)) throw new Error(`host ${host} does not hold ${id} (holders: ${rec.holders.join(', ')})`);
      return openWith(readFileSync(join(dir, 'sealed', `${id}.age`), 'utf8'), [identity(host)]);
    },

    /** Reseal every credential to its current holders (after a holder or recovery recipient changes). */
    async reseal(host) {
      const done = [];
      for (const rec of records()) { const value = await this.get(rec.id, host); await this.put(rec.id, value, rec); done.push(rec.id); }
      return done;
    },

    /** The environment a service runs with on a host: each consumer variable bound to its credential's value. */
    async render(host, service) {
      const lines = [];
      for (const rec of records()) for (const c of rec.consumers ?? []) if (c.host === host && c.service === service && c.variable && !c.file && !c.path) lines.push(`${c.variable}=${await this.get(rec.id, host)}`);
      return lines.sort().join('\n') + (lines.length ? '\n' : '');
    },

    /**
     * Place each of a host's file credentials where its code reads it inside the rendered directory: a consumer whose
     * recorded file lies under `root` (the directory the code used to read from, say ~/.config/<holder>) is placed at
     * its path relative to that root.
     */
    placeFiles(host, root) {
      const base = `${root.replace(/\/+$/u, '')}/`, placed = [];
      for (const rec of records()) {
        let changed = false;
        const consumers = (rec.consumers ?? []).map((c) => {
          if (c.host !== host || !c.file || c.path || !c.file.startsWith(base)) return c;
          changed = true; placed.push({ id: rec.id, service: c.service, path: placedPath(c.file.slice(base.length)) });
          return { ...c, path: c.file.slice(base.length) };
        });
        if (changed) writeAtomic(recordPath(rec.id), `${JSON.stringify({ ...rec, consumers }, null, 2)}\n`);
      }
      return placed;
    },

    /** Name the variable through which a service finds a file credential: render-host then binds it to the rendered file. */
    bindFile(id, { host, service, variable }) {
      const rec = record(id);
      if (!rec) throw new Error(`no credential ${id}`);
      const consumers = rec.consumers ?? [], hit = consumers.find((c) => c.host === host && c.service === service && (c.file || c.path));
      if (!hit) throw new Error(`${id} has no file consumer ${service} on ${host}`);
      hit.variable = variable;
      writeAtomic(recordPath(id), `${JSON.stringify({ ...rec, consumers }, null, 2)}\n`);
      return { id, host, service, variable };
    },

    /**
     * Everything a host's services use, rendered into a directory only this user can read (a runtime tmpfs): one
     * `<service>.env` per service (its secret variables, and each bound file credential's path) and one
     * `files/<id>` per file credential. Re-run on a timer so rotations reach the services.
     */
    async renderHost(host, to) {
      return renderHostCredentials(this, host, to);
    },

    /** Remove a credential that is revoked or retired: its record and sealed value leave the store (git keeps history). */
    remove(id) {
      if (!record(id)) return false;
      unlinkSync(recordPath(id));
      try { unlinkSync(join(dir, 'sealed', `${id}.age`)); } catch (error) { if (error.code !== 'ENOENT') throw error; }
      return true;
    },

    /** Rename a credential: its record, sealed value and requests move to the new id. */
    rename(from, to) {
      const rec = record(from);
      if (!rec) throw new Error(`no credential ${from}`);
      if (record(to)) throw new Error(`credential ${to} already exists`);
      writeAtomic(recordPath(to), `${JSON.stringify({ ...rec, id: to }, null, 2)}\n`);
      renameSync(join(dir, 'sealed', `${from}.age`), join(dir, 'sealed', `${to}.age`));
      unlinkSync(recordPath(from));
      return { from, to };
    },

    /** Ask for a credential this store does not hold; the person who can obtain it works this list. */
    request(id, { reason, by, consumers = [] }) {
      const row = { at: new Date().toISOString(), id, reason, by, consumers, state: 'requested' };
      appendFileSync(join(dir, 'requests.jsonl'), `${JSON.stringify(row)}\n`);
      return row;
    },
    requests: () => { try { return readFileSync(join(dir, 'requests.jsonl'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; } },
  };
}

/** Names that carry secrets in an env file; *_PATH, *_FILE, *_ROOT, *_DIR and *_URL name places, not secrets. */
export const SECRET_NAME = /(SECRET|TOKEN|PASSWORD|PASSPHRASE|API_KEY|PRIVATE_KEY|_KEY$|^KEY_|AUTHORIZATIONS)/u;
export const PLACE_NAME = /(_PATH|_FILE|_ROOT|_DIR|_URL|_ORIGIN|_ID)$/u;
export const isSecretName = (name) => SECRET_NAME.test(name) && !PLACE_NAME.test(name);

/** Parse an env file's assignments (values unquoted). */
export function parseEnv(text) {
  const out = [];
  for (const line of text.split('\n')) { const m = /^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)=(.*)$/u.exec(line); if (m) out.push([m[1], m[2].trim().replace(/^(["'])(.*)\1$/u, '$2')]); }
  return out;
}
