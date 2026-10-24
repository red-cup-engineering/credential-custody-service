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
import { assertRenderableStore } from './render-source-admission.mjs';

export const KINDS = Object.freeze(['api-key', 'oauth-client-secret', 'oauth-refresh-token', 'token', 'password', 'passphrase', 'private-key', 'session-secret', 'other']);
const ID = /^[a-z0-9][a-z0-9.-]{0,95}$/u;

/** The registry fields that only describe a credential; `describe` may rewrite these and nothing else. */
export const DESCRIPTIVE_FIELDS = Object.freeze(['provider', 'owner', 'purpose', 'account', 'plan']);
const DESCRIPTION_LIMIT = 200;

/** A short public fingerprint of a value: finds plaintext copies and duplicates without recording the value. */
export const fingerprint = (value) => createHash('sha256').update(value).digest('hex').slice(0, 16);

const readJson = (path, fallback) => { try { return JSON.parse(readFileSync(path, 'utf8')); } catch (error) { if (error.code === 'ENOENT') return fallback; throw error; } };
const writeAtomic = (path, text, mode = 0o644) => { writeFileSync(`${path}.tmp`, text, { mode }); chmodSync(`${path}.tmp`, mode); renameSync(`${path}.tmp`, path); };

export function openStore(dir, { create = true } = {}) {
  if (!dir) throw new TypeError('a credential store directory is required (a services section data/credentials/)');
  if (create) {
    for (const sub of ['registry', 'sealed', 'hosts']) mkdirSync(join(dir, sub), { recursive: true });
    const ignore = join(dir, '.gitignore');
    if (!existsSync(ignore)) writeFileSync(ignore, 'hosts/\n*.tmp\n');
  }
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
  // Once a registry entry has been enumerated it must be read successfully:
  // treating ENOENT as a missing optional record silently erases a credential
  // from the render plan, allowing a later manifest reconciliation to withdraw
  // its previously healthy output. Only record(id) may have an absent fallback.
  const records = () => readdirSync(join(dir, 'registry')).filter((f) => f.endsWith('.json')).map((f) => {
    const path = join(dir, 'registry', f);
    const value = JSON.parse(readFileSync(path, 'utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new TypeError(`credential registry entry ${path} must be a record object`);
    }
    return value;
  });
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
      const keys = sealFor(next.holders);
      writeAtomic(join(dir, 'sealed', `${id}.age`), await sealTo(value, keys));
      // The public recipients this value is sealed to, so a holder can see when the holders changed under it.
      next.sealedTo = [...keys].sort();
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

    /**
     * Reseal what this host holds whose holders' recipients no longer match the recipients it was sealed to: a
     * holder granted by a reviewed edit of the registry (or a recipient replaced) can then open it after the next
     * pull of any other holder. A record without `sealedTo` is untracked and left as it is.
     */
    async resealChanged(host) {
      const resealed = [], skipped = [];
      for (const rec of records()) {
        if (!Array.isArray(rec.sealedTo) || !rec.holders?.includes(host)) continue;
        let expected;
        try { expected = [...sealFor(rec.holders)].sort(); } catch (error) { skipped.push({ id: rec.id, reason: error.message }); continue; }
        if (expected.length === rec.sealedTo.length && expected.every((key, i) => key === rec.sealedTo[i])) continue;
        try { await this.put(rec.id, await this.get(rec.id, host), rec); resealed.push(rec.id); }
        catch (error) { skipped.push({ id: rec.id, reason: error.message }); }
      }
      return { resealed, skipped };
    },

    /** Reseal every credential to its current holders (after a holder or recovery recipient changes). */
    async reseal(host) {
      const done = [];
      for (const rec of records()) { const value = await this.get(rec.id, host); await this.put(rec.id, value, rec); done.push(rec.id); }
      return done;
    },

    /** The environment a service runs with on a host: each consumer variable bound to its credential's value. */
    async render(host, service) {
      await assertRenderableStore(dir, host);
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

    /**
     * Give a credential one more consumer on a host that already holds it, without reading its value: a service's
     * variable (`<service>.env` then carries the value), or, with `path`, a file credential placed at `path` whose
     * rendered location the variable names. A host the value is not sealed to cannot be bound; reseal it first.
     */
    bind(id, { host, service, variable, path }) {
      const rec = record(id);
      if (!rec) throw new Error(`no credential ${id}`);
      if (!(rec.holders ?? []).includes(host)) throw new Error(`${id} is not sealed to ${host}: add it as a holder and reseal before binding`);
      if (typeof service !== 'string' || !service || typeof variable !== 'string' || !/^[A-Z][A-Z0-9_]*$/u.test(variable)) throw new TypeError('bind needs a service and an UPPER_CASE variable');
      const consumer = { host, service, variable, ...(path === undefined ? {} : { path: placedPath(path) }) };
      const consumers = [...(rec.consumers ?? []).filter((c) => !(c.host === host && c.service === service && c.variable === variable)), consumer];
      writeAtomic(recordPath(id), `${JSON.stringify({ ...rec, consumers }, null, 2)}\n`);
      return { id, ...consumer };
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
      await assertRenderableStore(dir, host);
      return renderHostCredentials(this, host, to);
    },

    /**
     * Say what a credential is for, without touching its value: rewrite only the descriptive fields of its registry
     * record (provider, owner, purpose, account, plan). The sealed file is never read, opened or resealed; holders,
     * consumers, kind, fingerprint, sealedTo and rotatedAt are carried over untouched. An unknown id, a field that
     * looks like a secret, or a request that changes nothing is refused before anything is written.
     */
    describe(id, fields = {}, clear = []) {
      const rec = record(id);
      if (!rec) throw new Error(`no credential ${id} in this store`);
      const changes = {}, known = new Set(DESCRIPTIVE_FIELDS);
      for (const [field, value] of Object.entries(fields)) {
        if (value === undefined) continue;
        if (!known.has(field)) throw new TypeError(`${field} is not a descriptive field (${DESCRIPTIVE_FIELDS.join(', ')})`);
        const text = typeof value === 'string' ? value.trim() : '';
        if (!text || text.length > DESCRIPTION_LIMIT || /[\r\n]/u.test(text)) throw new TypeError(`${field} must be one line of 1 to ${DESCRIPTION_LIMIT} characters`);
        if (looksSecret(text)) throw new TypeError(`${field} looks like a secret and was not written; describe where a credential comes from, never its value`);
        if (records().some((r) => r.fingerprint && r.fingerprint === fingerprint(text))) throw new TypeError(`${field} equals a stored credential's value and was not written`);
        changes[field] = text;
      }
      for (const field of clear) {
        if (!known.has(field)) throw new TypeError(`cannot clear ${field}: not a descriptive field (${DESCRIPTIVE_FIELDS.join(', ')})`);
        if (field in changes) throw new TypeError(`${field} is both set and cleared`);
        changes[field] = null;
      }
      if (!Object.keys(changes).length) throw new TypeError(`describe ${id} needs at least one of ${DESCRIPTIVE_FIELDS.map((f) => `--${f}`).join(', ')} or --clear <field>`);
      const next = { ...rec, ...changes };
      writeAtomic(recordPath(id), `${JSON.stringify(next, null, 2)}\n`);
      return { id, ...Object.fromEntries(DESCRIPTIVE_FIELDS.map((f) => [f, next[f] ?? null])) };
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
    request(id, { reason, by, consumers = [], blockedBy } = {}) {
      // A request whose provider demands something the Group has not admitted yet (a payment card, say) is still
      // tracked, as deferred with the condition that blocks it, so the list of what to obtain is whole while the
      // person working it sees only what can be done now.
      if (blockedBy !== undefined) {
        const text = typeof blockedBy === 'string' ? blockedBy.trim() : '';
        if (!text || text.length > DESCRIPTION_LIMIT || /[\r\n]/u.test(text)) throw new TypeError(`blocked-by must be one line of 1 to ${DESCRIPTION_LIMIT} characters`);
        if (looksSecret(text)) throw new TypeError('blocked-by looks like a secret and was not written; name the condition, never a value');
        blockedBy = text;
      }
      const row = { at: new Date().toISOString(), id, reason, by, consumers, state: blockedBy === undefined ? 'requested' : 'deferred', ...(blockedBy === undefined ? {} : { blockedBy }) };
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

/**
 * Whether descriptive text is shaped like a secret: an env assignment to a secret-named variable (`API_KEY_X=…`), a
 * PEM or age secret key, or one long unbroken token of key characters. Names alone (`API_KEY_GROQ`) are not secrets.
 */
export const looksSecret = (text) => /AGE-SECRET-KEY-|-----BEGIN /u.test(text)
  || parseEnv(text).some(([name, value]) => value && isSecretName(name))
  || (/^[A-Za-z0-9_\-+/=.]{32,}$/u.test(text) && /[0-9]/u.test(text) && /[A-Za-z]/u.test(text));
