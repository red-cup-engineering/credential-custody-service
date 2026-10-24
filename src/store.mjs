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
import { createHash, randomUUID } from 'node:crypto';
import { appendFileSync, chmodSync, existsSync, linkSync, lstatSync, mkdirSync, readFileSync, readdirSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateIdentity, openWith, recipientOf, sealTo } from './recipient-seal.mjs';
import { placedPath, serviceName, environmentAssignment, renderHost as renderHostCredentials } from './render-host.mjs';
import { assertRenderableStore, assertCredentialHost } from './render-source-admission.mjs';

export const KINDS = Object.freeze(['api-key', 'oauth-client-secret', 'oauth-refresh-token', 'token', 'password', 'passphrase', 'private-key', 'session-secret', 'other']);
const ID = /^[a-z0-9][a-z0-9.-]{0,95}$/u;

/** The registry fields that only describe a credential; `describe` may rewrite these and nothing else. */
export const DESCRIPTIVE_FIELDS = Object.freeze(['provider', 'owner', 'purpose', 'account', 'plan']);
const DESCRIPTION_LIMIT = 200;

/** A short public fingerprint of a value: finds plaintext copies and duplicates without recording the value. */
export const fingerprint = (value) => createHash('sha256').update(value).digest('hex').slice(0, 16);

const readJson = (path, fallback) => { try { return JSON.parse(readFileSync(path, 'utf8')); } catch (error) { if (error.code === 'ENOENT') return fallback; throw error; } };
// Never reuse a predictable staging pathname: a stale .tmp symlink could
// overwrite a file outside credential custody before the atomic rename.
// Exclusive, unique staging also prevents overlapping writers from sharing
// an intermediate file (it does not by itself serialize registry updates).
const writeAtomic = (path, text, mode = 0o644, { exclusive = false } = {}) => {
  const temporary = `${path}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temporary, text, { mode, flag: 'wx' });
    chmodSync(temporary, mode);
    // New credential IDs must not replace orphaned sealed evidence: publish
    // through an exclusive hard link, which also rejects dangling symlinks.
    // Existing IDs may atomically replace their recorded ciphertext.
    if (exclusive) linkSync(temporary, path);
    else renameSync(temporary, path);
  } finally {
    try { unlinkSync(temporary); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
};

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
  const identityPath = (host) => join(dir, 'hosts', `${assertCredentialHost(host)}.identity`);

  function identity(host) {
    const path = identityPath(host);
    if (!existsSync(path)) throw new Error(`host ${host} has no identity in ${join(dir, 'hosts')}; run: credentials init-host ${host}`);
    if ((statSync(path).mode & 0o077) !== 0) throw new Error(`${path} is readable by others; chmod 600 it`);
    return readFileSync(path, 'utf8').trim();
  }
  // A listed record is part of the source's custody evidence. Missing or
  // malformed holder/consumer arrays cannot silently mean "no consumers":
  // doing so authorizes withdrawal of previously healthy runtime credentials.
  const requireRecord = (path, id, value) => {
    if (!value || typeof value !== 'object' || Array.isArray(value) || value.id !== id) {
      throw new TypeError(`credential registry entry ${path} id mismatch or invalid record`);
    }
    if (!Array.isArray(value.holders) || value.holders.length === 0 || value.holders.some((holder) => typeof holder !== 'string' || !holder)) {
      throw new TypeError(`credential registry entry ${path} holders must be a list of hosts`);
    }
    // A host label alone does not declare any renderable delivery. Earlier
    // versions silently interpreted such partial records as an empty service
    // roster, withdrawing credentials from an otherwise healthy generation.
    // An explicit placed/file consumer may omit a service variable; an env
    // consumer must supply both a service and a valid assignment name.
    const delivers = (consumer) => {
      if (!consumer || typeof consumer !== 'object' || Array.isArray(consumer)
        || typeof consumer.host !== 'string' || !consumer.host) return false;
      // A file consumer must not bypass the variable/service checks: the
      // renderer writes file bindings into env files, so a newline, assignment,
      // missing service, or unsafe service name is a source-integrity failure.
      for (const key of ['file', 'path']) {
        if (Object.hasOwn(consumer, key) && (typeof consumer[key] !== 'string' || !consumer[key].trim())) return false;
      }
      if (Object.hasOwn(consumer, 'path')) {
        try { placedPath(consumer.path); } catch { return false; }
      }
      const file = Object.hasOwn(consumer, 'file') || Object.hasOwn(consumer, 'path');
      const variable = Object.hasOwn(consumer, 'variable');
      if (Object.hasOwn(consumer, 'service') || variable) {
        try { serviceName(consumer.service); } catch { return false; }
      }
      if (variable && (typeof consumer.variable !== 'string' || !/^[A-Z][A-Z0-9_]*$/u.test(consumer.variable))) return false;
      return file || variable;
    };
    if (!Array.isArray(value.consumers) || value.consumers.some((consumer) => !delivers(consumer))) {
      throw new TypeError(`credential registry entry ${path} consumers must declare actual host-bound file or service-variable delivery`);
    }
    return value;
  };
  const record = (id) => {
    const path = recordPath(id), value = readJson(path, undefined);
    return value === undefined ? null : requireRecord(path, id, value);
  };
  // Once a registry entry has been enumerated it must be read successfully:
  // a vanished or malformed entry must never be mistaken for empty custody.
  const records = () => {
    const registryNames = readdirSync(join(dir, 'registry')).filter((f) => f.endsWith('.json'));
    // A sealed value left by interrupted registry maintenance is still custody
    // evidence. A missing corresponding record cannot mean "zero credentials":
    // that mistaken inference previously withdrew a healthy runtime generation.
    // Inspect the actual sealed directory entries, including dangling links,
    // before treating this store as complete or considering any pruning.
    const declaredSeals = new Set(registryNames.map((f) => `${f.slice(0, -'.json'.length)}.age`));
    for (const name of readdirSync(join(dir, 'sealed'))) {
      if (name.endsWith('.age') && !declaredSeals.has(name)) {
        const orphan = join(dir, 'sealed', name);
        throw new Error(`credential sealed source ${orphan} has no registry entry; incomplete custody requires reconciliation`);
      }
    }
    return registryNames.map((f) => {
      const path = join(dir, 'registry', f), filenameId = f.slice(0, -'.json'.length);
      const value = JSON.parse(readFileSync(path, 'utf8'));
      if (!ID.test(filenameId)) throw new TypeError(`credential registry entry ${path} has invalid filename id`);
      const admitted = requireRecord(path, filenameId, value);
      // A declared record without its sealed payload is incomplete custody,
      // not permission to retire previous host outputs. Check even records with
      // no consumers or with holders other than the currently rendered host.
      const sealedPath = join(dir, 'sealed', `${filenameId}.age`);
      let sealed;
      try { sealed = lstatSync(sealedPath); }
      catch (error) {
        throw new Error(`credential sealed source ${sealedPath} unavailable (${error.code ?? 'cannot inspect'})`, { cause: error });
      }
      if (!sealed.isFile() || sealed.size === 0 || !(sealed.mode & 0o444)) {
        throw new Error(`credential sealed source ${sealedPath} unavailable (not a readable nonempty regular file)`);
      }
      return admitted;
    });
  };
  // Refuse authoring a source that will later fail rendering. Compare the
  // exact host/service/variable claims of the candidate against all other
  // records, but allow a damaged record to be repaired by replacing its own
  // bindings. The original renderer still independently rejects external
  // registry edits and races at receiving time.
  const assertNoEnvironmentCollisions = (id, candidate) => {
    const claims = new Map();
    const claimKey = (consumer) => JSON.stringify([consumer.host, consumer.service, consumer.variable]);
    const error = (consumer) => new Error('duplicate environment binding ' + consumer.variable
      + ' for service ' + consumer.service + ' on host ' + consumer.host);
    for (const consumer of candidate.consumers ?? []) {
      if (!consumer.variable) continue;
      const key = claimKey(consumer);
      if (claims.has(key)) throw error(consumer);
      claims.set(key, consumer);
    }
    if (!claims.size) return;
    for (const existing of records()) {
      if (existing.id === id) continue;
      for (const consumer of existing.consumers ?? []) {
        if (consumer.variable && claims.has(claimKey(consumer))) throw error(consumer);
      }
    }
  };
  const sealFor = (holders) => {
    const r = recipients(), keys = [...holders.map((h) => { if (!r.hosts[h]) throw new Error(`host ${h} has no recipient in recipients.json`); return r.hosts[h]; }), ...r.recovery];
    return [...new Set(keys)];
  };

  return {
    dir, recipients, record, records,

    /** Create this host's identity (once) and record its public recipient. */
    async initHost(host, { recovery = false } = {}) {
      // identityPath already validates via the shared admission contract.
      const path = identityPath(host);
      const prior = recipients();
      // existsSync follows symlinks and reports a dangling identity link as
      // missing. That link may be evidence of interrupted or externally mounted
      // private custody; never silently replace it with a fresh identity.
      let priorIdentity;
      try { priorIdentity = lstatSync(path); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
      if (priorIdentity) {
        if (!priorIdentity.isFile() && !priorIdentity.isSymbolicLink()) {
          throw new Error(`host ${host} identity custody at ${path} is not a file; reconcile explicitly`);
        }
        const recipient = await recipientOf(identity(host));
        const acknowledged = recovery ? prior.recovery?.includes(recipient) : prior.hosts?.[host] === recipient;
        if (!acknowledged) throw new Error(`host ${host} identity/recipient custody mismatch; repair registration explicitly`);
        return { host, recipient, created: false };
      }
      if (Object.hasOwn(prior.hosts ?? {}, host)) {
        throw new Error(`host ${host} has a recipient but no local identity; repair custody explicitly`);
      }
      const id = await generateIdentity(), recipient = await recipientOf(id);
      // A concurrent writer can create the name after lstat. Publish only
      // into an unoccupied name, without replacing any prior custody evidence.
      try { writeAtomic(path, `${id}\n`, 0o600, { exclusive: true }); }
      catch (error) {
        if (error.code === 'EEXIST') throw new Error(`host ${host} identity custody at ${path} already exists; reconcile explicitly`, { cause: error });
        throw error;
      }
      const r = recipients();
      if (recovery) r.recovery = [...new Set([...(r.recovery ?? []), recipient])]; else r.hosts[host] = recipient;
      writeAtomic(recipientsPath, `${JSON.stringify(r, null, 2)}\n`);
      return { host, recipient, created: true, recovery };
    },

    /** Register (or update) a credential and seal its value to its holders. */
    async put(id, value, fields = {}) {
      const now = new Date().toISOString(), prior = record(id), old = prior ?? {};
      const next = { id, provider: null, kind: 'other', owner: null, purpose: null, holders: [], consumers: [], rotateEveryDays: null, createdAt: now, ...old, ...fields, fingerprint: fingerprint(value), rotatedAt: old.fingerprint && old.fingerprint !== fingerprint(value) ? now : (old.rotatedAt ?? now) };
      if (!KINDS.includes(next.kind)) throw new TypeError(`kind ${next.kind} is not one of ${KINDS.join(', ')}`);
      if (!Array.isArray(next.holders) || !next.holders.length) throw new TypeError(`credential ${id} needs at least one holder host`);
      // A writer must never mint source records that the renderer then refuses.
      // Admit the complete record BEFORE sealing/replacing a valid earlier value.
      requireRecord(recordPath(id), id, next);
      assertNoEnvironmentCollisions(id, next);
      const keys = sealFor(next.holders);
      const sealedPath = join(dir, 'sealed', `${id}.age`);
      try { writeAtomic(sealedPath, await sealTo(value, keys), 0o644, { exclusive: prior === null }); }
      catch (error) {
        if (prior === null && error.code === 'EEXIST') {
          throw new Error(`sealed credential destination ${sealedPath} already exists; reconcile orphaned custody before writing`, { cause: error });
        }
        throw error;
      }
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
      const lines = [], variables = new Set();
      for (const rec of records()) for (const c of rec.consumers ?? []) {
        if (c.host !== host || c.service !== service || !c.variable || c.file || c.path) continue;
        if (variables.has(c.variable)) {
          throw new Error(`duplicate environment binding ${c.variable} for service ${service}`);
        }
        variables.add(c.variable);
        const value = await this.get(rec.id, host);
        // These bytes become systemd EnvironmentFile assignments; preserve the exact value.
        // Newlines could inject another assignment; systemd control characters are
        // not portable values. Fail before touching outputs.
        // Multiline secrets remain supported by file consumers.
        if (typeof value !== 'string' || /[\u0000-\u001f\u007f\uFEFF]/u.test(value)) {
          throw new TypeError(`environment credential ${rec.id} must have a single-line value without control characters; deliver such values as files`);
        }
        lines.push(environmentAssignment(c.variable, value));
      }
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
      // A syntactically valid env variable cannot make an unsafe output filename safe.
      serviceName(service);
      const consumer = { host, service, variable, ...(path === undefined ? {} : { path: placedPath(path) }) };
      const consumers = [...(rec.consumers ?? []).filter((c) => !(c.host === host && c.service === service && c.variable === variable)), consumer];
      assertNoEnvironmentCollisions(id, { ...rec, consumers });
      writeAtomic(recordPath(id), `${JSON.stringify({ ...rec, consumers }, null, 2)}\n`);
      return { id, ...consumer };
    },

    /** Name the variable through which a service finds a file credential: render-host then binds it to the rendered file. */
    bindFile(id, { host, service, variable }) {
      const rec = record(id);
      if (!rec) throw new Error(`no credential ${id}`);
      // File-path binding is still a host-bound credential grant; refuse
      // forged env assignment names and unheld hosts before changing custody.
      if (!rec.holders.includes(host)) throw new Error(`${id} is not sealed to ${host}: add it as a holder and reseal before binding`);
      if (typeof variable !== 'string' || !/^[A-Z][A-Z0-9_]*$/u.test(variable)) throw new TypeError('bindFile needs an UPPER_CASE variable');
      serviceName(service);
      const consumers = rec.consumers ?? [], hit = consumers.find((c) => c.host === host && c.service === service && (c.file || c.path));
      if (!hit) throw new Error(`${id} has no file consumer ${service} on ${host}`);
      hit.variable = variable;
      assertNoEnvironmentCollisions(id, { ...rec, consumers });
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
      const source = join(dir, 'sealed', `${from}.age`), destination = join(dir, 'sealed', `${to}.age`);
      // A missing record is NOT evidence that the corresponding encrypted
      // bytes are disposable. A partial move or recovery may have left an
      // orphan payload. Never rename over it, even after an enrollment race.
      // Hardlinking to an unoccupied name is atomic and fails with EEXIST
      // for existing files *and* dangling symlinks. Keep the original pair
      // intact until the new registry entry has been durably written.
      let sourceInfo;
      try { sourceInfo = lstatSync(source); }
      catch (error) { throw new Error(`sealed credential source ${source} unavailable`, { cause: error }); }
      if (!sourceInfo.isFile() || !sourceInfo.size) {
        throw new Error(`sealed credential source ${source} is not a nonempty regular file`);
      }
      try { linkSync(source, destination); }
      catch (error) {
        if (error.code === 'EEXIST') throw new Error(`sealed credential destination ${destination} already exists; reconcile custody before renaming`, { cause: error });
        throw error;
      }
      try {
        writeAtomic(recordPath(to), `${JSON.stringify({ ...rec, id: to }, null, 2)}\n`);
      } catch (error) {
        // No new registry entry was committed: release our newly created
        // ciphertext link while retaining the entire original source.
        unlinkSync(destination);
        throw error;
      }
      // If either removal fails, the new credential remains decryptable;
      // repair leftover old registry/seal evidence explicitly on retry.
      unlinkSync(recordPath(from));
      unlinkSync(source);
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
