#!/usr/bin/env node
/**
 * The credentials command: one place an agent or a person asks for, stores, renders and audits credentials.
 *
 *   credentials --store <dir> --host <host> <command> …        (or CREDENTIALS_STORE, CREDENTIALS_HOST)
 *
 *   init-host [--recovery]           create this host's identity (or a recovery identity) and record its recipient
 *   list                             every credential: kind, provider, owner, holders, consumers, age
 *   get <id>                         print a credential's value (this host must hold it)
 *   put <id> --holders a,b [--kind --provider --owner --purpose --rotate-days N]   value read from stdin
 *   render <service> [--out <file>]  the env file a service runs with on this host (0600), from the registry
 *   import <env-file> --service <s> [--holders a,b] [--dry-run]
 *                                    take an existing env file's secrets into the store (duplicates by fingerprint
 *                                    become one credential with several consumers); non-secret settings stay put
 *   audit [--scan <dir>]…            credentials past rotation, requests outstanding, and plaintext copies of stored
 *                                    values (or unstored secrets) in env files under the scanned directories
 *   import-file <path> --service <s> --id <id>   take a credential that is a whole file (a key, a service account)
 *   render-files <service>           write a service's file credentials on this host (0600)
 *   render-host --to <dir>           every service's env file and every file credential this host uses (0700/0600)
 *   rename <from> <to>               give a credential a better id
 *   request <id> --reason "…"       ask for a credential the store does not hold
 *   requests                         the outstanding requests
 *   reseal                           reseal every credential this host can open to its current holders
 *
 * An agent that needs a credential runs `get`; when the store does not hold it, `request`. It never asks a
 * person to sign in for it.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync, chmodSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { fingerprint, isSecretName, openStore, parseEnv } from '../src/store.mjs';

// A refusal is a sentence for the person or agent reading it, not a stack trace.
process.on('uncaughtException', (error) => { process.stderr.write(`credentials: ${error.message}\n`); process.exit(1); });

const { values: o, positionals: [command, arg, arg2] } = parseArgs({ allowPositionals: true, options: {
  store: { type: 'string' }, host: { type: 'string' }, holders: { type: 'string' }, kind: { type: 'string' }, provider: { type: 'string' },
  owner: { type: 'string' }, purpose: { type: 'string' }, 'rotate-days': { type: 'string' }, service: { type: 'string' }, out: { type: 'string' },
  reason: { type: 'string' }, id: { type: 'string' }, to: { type: 'string' }, by: { type: 'string' }, scan: { type: 'string', multiple: true }, recovery: { type: 'boolean' }, 'dry-run': { type: 'boolean' },
} });
const storeDir = o.store ?? process.env.CREDENTIALS_STORE, host = o.host ?? process.env.CREDENTIALS_HOST;
const fail = (message) => { process.stderr.write(`${message}\n`); process.exit(2); };
if (!storeDir) fail('--store <services section data/credentials dir> (or CREDENTIALS_STORE) is required');
const store = openStore(storeDir);
const needHost = () => host ?? fail('--host <this host> (or CREDENTIALS_HOST) is required');
const list = (s) => (s ?? '').split(',').map((x) => x.trim()).filter(Boolean);
const readStdin = () => readFileSync(0, 'utf8').replace(/\r?\n$/u, '');
const out = (value) => process.stdout.write(`${typeof value === 'string' ? value : JSON.stringify(value, null, 2)}\n`);
const days = (iso) => Math.floor((Date.now() - Date.parse(iso)) / 86400000);
const slug = (s) => s.toLowerCase().replace(/[^a-z0-9.]+/gu, '-').replace(/^-|-$/gu, '');

if (command === 'init-host') out(await store.initHost(o.recovery ? (arg ?? 'recovery') : needHost(), { recovery: o.recovery }));
else if (command === 'list') out(store.records().map((r) => ({ id: r.id, kind: r.kind, provider: r.provider, owner: r.owner, holders: r.holders, consumers: (r.consumers ?? []).map((c) => `${c.host}:${c.service}:${c.variable}`), ageDays: days(r.rotatedAt) })));
else if (command === 'get') process.stdout.write(await store.get(arg ?? fail('get <id>'), needHost()));
else if (command === 'put') {
  if (!arg) fail('put <id> --holders a,b  (value on stdin)');
  const fields = { ...(o.holders ? { holders: list(o.holders) } : {}), ...(o.kind ? { kind: o.kind } : {}), ...(o.provider ? { provider: o.provider } : {}), ...(o.owner ? { owner: o.owner } : {}), ...(o.purpose ? { purpose: o.purpose } : {}), ...(o['rotate-days'] ? { rotateEveryDays: Number(o['rotate-days']) } : {}) };
  const rec = await store.put(arg, readStdin(), fields);
  out({ id: rec.id, holders: rec.holders, fingerprint: rec.fingerprint });
} else if (command === 'render') {
  const text = await store.render(needHost(), arg ?? fail('render <service>'));
  if (!o.out) process.stdout.write(text);
  else { writeFileSync(`${o.out}.tmp`, text, { mode: 0o600 }); chmodSync(`${o.out}.tmp`, 0o600); renameSync(`${o.out}.tmp`, o.out); out({ wrote: o.out, variables: text.split('\n').filter(Boolean).length }); }
} else if (command === 'import') {
  const file = arg ?? fail('import <env-file> --service <name>'), service = o.service ?? fail('--service <name> names who uses this env file'), me = needHost();
  const holders = o.holders ? list(o.holders) : [me];
  const byFingerprint = new Map(store.records().map((r) => [r.fingerprint, r]));
  const report = { file, service, imported: [], joined: [], settings: [] };
  for (const [variable, value] of parseEnv(readFileSync(file, 'utf8'))) {
    if (!isSecretName(variable) || !value) { report.settings.push(variable); continue; }
    const consumer = { host: me, service, variable }, existing = byFingerprint.get(fingerprint(value));
    if (existing) {
      const consumers = [...(existing.consumers ?? []).filter((c) => !(c.host === me && c.service === service && c.variable === variable)), consumer];
      if (!o['dry-run']) byFingerprint.set(existing.fingerprint, await store.put(existing.id, value, { ...existing, holders: [...new Set([...existing.holders, ...holders])], consumers }));
      report.joined.push(`${variable} -> ${existing.id}`);
    } else {
      // An id already holding a different value (the same variable on another host, say) is never overwritten.
      let id = slug(`${service}.${variable}`);
      if (store.record(id)) id = slug(`${service}.${variable}.${me}`);
      if (!o['dry-run']) byFingerprint.set(fingerprint(value), await store.put(id, value, { holders, consumers: [consumer], purpose: `${variable} for ${service}` }));
      report.imported.push(`${variable} -> ${id}`);
    }
  }
  out(report);
} else if (command === 'import-file') {
  const file = arg ?? fail('import-file <path> --service <s> --id <id> [--kind] [--provider]'), service = o.service ?? fail('--service is required'), me = needHost();
  const id = o.id ?? fail('--id names the credential (e.g. kalshi.api-private-key)');
  const value = readFileSync(file, 'utf8'), existing = store.record(id);
  if (existing && existing.fingerprint !== fingerprint(value)) fail(`credential ${id} already holds a different value`);
  const consumers = [...(existing?.consumers ?? []).filter((c) => !(c.host === me && c.file === file)), { host: me, service, file }];
  const rec = await store.put(id, value, { ...(existing ?? {}), holders: [...new Set([...(existing?.holders ?? []), me])], consumers, ...(o.kind ? { kind: o.kind } : {}), ...(o.provider ? { provider: o.provider } : {}), ...(existing ? {} : { purpose: `${file} for ${service}` }) });
  out({ id: rec.id, holders: rec.holders, file });
} else if (command === 'render-files') {
  const written = [];
  for (const { id, file, value } of await store.files(needHost(), arg ?? fail('render-files <service>'))) {
    writeFileSync(`${file}.tmp`, value, { mode: 0o600 }); chmodSync(`${file}.tmp`, 0o600); renameSync(`${file}.tmp`, file); written.push({ id, file });
  }
  out({ written });
} else if (command === 'render-host') {
  // Everything this host's services use, rendered where only this user can read it: one env file per service
  // (its secret variables) and one file per file credential. Re-run on a timer so rotations reach the services.
  const me = needHost(), dir = o.to ?? fail('render-host --to <runtime dir> (e.g. $XDG_RUNTIME_DIR/561-group-credentials)');
  mkdirSync(join(dir, 'files'), { recursive: true, mode: 0o700 }); chmodSync(dir, 0o700);
  const write = (path, text) => { writeFileSync(`${path}.tmp`, text, { mode: 0o600 }); chmodSync(`${path}.tmp`, 0o600); renameSync(`${path}.tmp`, path); };
  const services = new Set(), fileIds = new Set();
  for (const rec of store.records()) for (const c of rec.consumers ?? []) if (c.host === me) { if (c.variable) services.add(c.service); if (c.file) fileIds.add(rec.id); }
  for (const service of services) write(join(dir, `${service}.env`), await store.render(me, service));
  for (const id of fileIds) write(join(dir, 'files', id), await store.get(id, me));
  out({ host: me, to: dir, services: [...services].sort(), files: [...fileIds].sort() });
} else if (command === 'rename') {
  out(store.rename(arg ?? fail('rename <from> <to>'), arg2 ?? fail('rename <from> <to>')));
} else if (command === 'audit') {
  const records = store.records(), byFingerprint = new Map(records.map((r) => [r.fingerprint, r.id]));
  const report = { credentials: records.length, overdue: records.filter((r) => r.rotateEveryDays && days(r.rotatedAt) > r.rotateEveryDays).map((r) => r.id), requests: store.requests().filter((r) => r.state === 'requested').map((r) => r.id), plaintextCopies: [], unstoredSecrets: [] };
  const walk = (dir) => { let entries = []; try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return []; } return entries.flatMap((e) => (e.isDirectory() && !['node_modules', '.git'].includes(e.name) ? walk(join(dir, e.name)) : e.isFile() && /\.env(\.|$)|\.env\.[a-z0-9-]+$/u.test(e.name) ? [join(dir, e.name)] : [])); };
  for (const dir of o.scan ?? []) for (const file of walk(dir)) {
    let pairs; try { if (statSync(file).size > 1 << 20) continue; pairs = parseEnv(readFileSync(file, 'utf8')); } catch { continue; }
    for (const [variable, value] of pairs) if (isSecretName(variable) && value) {
      const id = byFingerprint.get(fingerprint(value));
      (id ? report.plaintextCopies : report.unstoredSecrets).push(id ? `${file}:${variable} = ${id}` : `${file}:${variable}`);
    }
  }
  out(report);
} else if (command === 'request') out(store.request(arg ?? fail('request <id> --reason "…"'), { reason: o.reason ?? fail('--reason is required'), by: o.by ?? host ?? null }));
else if (command === 'requests') out(store.requests().filter((r) => r.state === 'requested'));
else if (command === 'reseal') out({ resealed: await store.reseal(needHost()) });
else fail('usage: credentials --store <dir> --host <host> init-host|list|get|put|render|import|audit|request|requests|reseal');
