import { accessSync, constants, statSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { recipientOf } from './recipient-seal.mjs';

/** Refuse incomplete or misselected source custody before any runtime output or reseal. */
export async function assertRenderableStore(dir, host) {
  if (typeof dir !== 'string' || !dir) throw new TypeError('credential store directory is required for rendering');
  if (typeof host !== 'string' || !host || host === '.' || host === '..' || /[/\\\u0000-\u001f\u007f]/u.test(host)) {
    throw new TypeError(`invalid credential host for store ${JSON.stringify(dir)}`);
  }
  const context = `credential store ${JSON.stringify(dir)} for host ${JSON.stringify(host)}`;
  const requireKind = (path, kind) => {
    let info;
    try { info = statSync(path); }
    catch (error) { throw new Error(`${context} unavailable: ${path} (${error.code ?? 'unreadable'})`, { cause: error }); }
    if (kind === 'directory' ? !info.isDirectory() : !info.isFile()) {
      throw new Error(`${context} unavailable: ${path} is not a ${kind}`);
    }
    if (kind === 'directory') {
      // stat alone succeeds on an unreadable sealed directory. With an empty
      // registry, that mistake would authorize withdrawing prior credentials.
      // Check both POSIX mode bits (including root callers) and actual access.
      if (!(info.mode & 0o444) || !(info.mode & 0o111)) {
        throw new Error(`${context} unavailable: ${path} unreadable directory`);
      }
      try { accessSync(path, constants.R_OK | constants.X_OK); }
      catch (error) { throw new Error(`${context} unavailable: ${path} unreadable (${error.code ?? 'access denied'})`, { cause: error }); }
    }
    return info;
  };
  for (const path of [dir, join(dir, 'registry'), join(dir, 'sealed'), join(dir, 'hosts')]) requireKind(path, 'directory');
  const identityFile = join(dir, 'hosts', `${host}.identity`);
  const identityInfo = requireKind(identityFile, 'file');
  if (identityInfo.mode & 0o077) throw new Error(`${context} unavailable: ${identityFile} is readable by others`);
  let identity;
  try { identity = readFileSync(identityFile, 'utf8').trim(); }
  catch (error) { throw new Error(`${context} unavailable: cannot read host identity ${identityFile} (${error.code ?? 'unreadable'})`, { cause: error }); }
  if (!/^AGE-SECRET-KEY-1[A-Z0-9]+$/u.test(identity)) throw new Error(`${context} unavailable: invalid host identity at ${identityFile}`);
  const recipientsFile = join(dir, 'recipients.json');
  requireKind(recipientsFile, 'file');
  let recipients;
  try { recipients = JSON.parse(readFileSync(recipientsFile, 'utf8')); }
  catch (error) { throw new Error(`${context} unavailable: cannot read recipients at ${recipientsFile}`, { cause: error }); }
  if (typeof recipients?.hosts?.[host] !== 'string' || !/^age1[0-9a-z]+$/u.test(recipients.hosts[host])) {
    throw new Error(`${context} unavailable: no valid recipient for host in ${recipientsFile}`);
  }
  // A syntactically plausible but unrelated source can otherwise authorize a
  // zero-credential render and withdraw existing files under the wrong key.
  let derivedRecipient;
  try { derivedRecipient = await recipientOf(identity); }
  catch (error) { throw new Error(`${context} unavailable: invalid host identity at ${identityFile}`, { cause: error }); }
  if (derivedRecipient !== recipients.hosts[host]) {
    throw new Error(`${context} unavailable: host identity and recipient mismatch in ${recipientsFile}`);
  }
}
