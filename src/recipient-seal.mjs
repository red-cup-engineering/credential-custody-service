/**
 * Sealing to recipients: a value sealed so that only the holders of named identities can open it. The format is
 * age (https://age-encryption.org/v1) with X25519 recipients, written ASCII-armored so a sealed value is a plain
 * text file. seal.mjs seals with one shared symmetric key; this seals to each holder separately, so a holder opens
 * what was sealed to it and nothing else, and adding or removing a holder never shares a key.
 *
 * An identity is `AGE-SECRET-KEY-1…` (private: kept by its holder, never sealed alongside the values); its
 * recipient is `age1…` (public: safe to record).
 */
import { Decrypter, Encrypter, armor, generateX25519Identity, identityToRecipient } from 'age-encryption';

/** A new holder identity (private). */
export const generateIdentity = () => generateX25519Identity();

/** The public recipient of an identity. */
export const recipientOf = (identity) => identityToRecipient(identity);

/** Seal a text value to every recipient; the result is an armored age file. */
export async function sealTo(value, recipients) {
  if (typeof value !== 'string') throw new TypeError('a sealed value is text');
  if (!Array.isArray(recipients) || recipients.length === 0) throw new TypeError('sealing needs at least one recipient');
  const encrypter = new Encrypter();
  for (const recipient of recipients) encrypter.addRecipient(recipient);
  return armor.encode(await encrypter.encrypt(value));
}

/** Open an armored age file with any of the given identities. */
export async function openWith(sealed, identities) {
  const decrypter = new Decrypter();
  for (const identity of identities) decrypter.addIdentity(identity);
  return decrypter.decrypt(armor.decode(sealed), 'text');
}
