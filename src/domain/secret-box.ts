import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes,
} from 'node:crypto';

/**
 * Authenticated encryption of secrets at rest (spec §13.1: signing private
 * keys and MFA secrets): AES-256-GCM with a random 12-byte IV and a 16-byte
 * authentication tag, under a key derived from `KEY_ENCRYPTION_SECRET` with
 * HKDF-SHA256. Each purpose derives its own key (HKDF `info`), and every
 * ciphertext is bound to its record through the additional authenticated
 * data (e.g. the key id or user id), so a ciphertext copied to another row
 * does not decrypt.
 *
 * Encoded form: `v1.<iv>.<tag>.<ciphertext>` (base64url parts).
 *
 * @see https://www.rfc-editor.org/rfc/rfc5869 (HKDF)
 * @see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf (GCM, 96-bit IV)
 */
export const SECRET_BOX_VERSION = 'v1';

/** AES-256-GCM parameters. */
const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

/** Application salt of the HKDF extraction step (constant, public). */
const HKDF_SALT = Buffer.from('ais-its-auth/key-encryption', 'utf8');

/** Purposes with their own derived key (HKDF `info`). */
export type SecretPurpose = 'signing-key' | 'mfa-secret';

/** Thrown when a ciphertext is malformed, tampered with or bound to other data. */
export class SecretDecryptionError extends Error {
  override readonly name = 'SecretDecryptionError';
}

/** Derives the 256-bit key of a purpose from the master secret (HKDF-SHA256). */
export function deriveKey(
  masterSecret: string,
  purpose: SecretPurpose,
): Buffer {
  return Buffer.from(
    hkdfSync(
      'sha256',
      Buffer.from(masterSecret, 'utf8'),
      HKDF_SALT,
      Buffer.from(`aisits:${purpose}`, 'utf8'),
      KEY_LENGTH,
    ),
  );
}

/**
 * Encrypts `plaintext` bound to `associatedData`.
 *
 * @param iv only for tests (deterministic vectors); a fresh random IV otherwise.
 */
export function sealSecret(
  key: Buffer,
  plaintext: string,
  associatedData: string,
  iv: Buffer = randomBytes(IV_LENGTH),
): string {
  if (key.length !== KEY_LENGTH)
    throw new RangeError('AES-256 needs a 32-byte key');
  if (iv.length !== IV_LENGTH) throw new RangeError('GCM IV must be 12 bytes');
  const cipher = createCipheriv(ALGORITHM, key, iv, {
    authTagLength: TAG_LENGTH,
  });
  cipher.setAAD(Buffer.from(associatedData, 'utf8'));
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  return [
    SECRET_BOX_VERSION,
    iv.toString('base64url'),
    cipher.getAuthTag().toString('base64url'),
    ciphertext.toString('base64url'),
  ].join('.');
}

/**
 * Decrypts a value of {@link sealSecret}.
 *
 * @throws {SecretDecryptionError} when the value is malformed, was encrypted
 *   with another key, was modified, or is bound to other associated data.
 */
export function openSecret(
  key: Buffer,
  sealed: string,
  associatedData: string,
): string {
  const [version, ivPart, tagPart, ciphertextPart, ...rest] = sealed.split('.');
  if (
    version !== SECRET_BOX_VERSION ||
    ivPart === undefined ||
    tagPart === undefined ||
    ciphertextPart === undefined ||
    rest.length > 0
  ) {
    throw new SecretDecryptionError('Unsupported or malformed secret');
  }
  const iv = Buffer.from(ivPart, 'base64url');
  const tag = Buffer.from(tagPart, 'base64url');
  if (iv.length !== IV_LENGTH || tag.length !== TAG_LENGTH) {
    throw new SecretDecryptionError('Malformed secret');
  }
  try {
    const decipher = createDecipheriv(ALGORITHM, key, iv, {
      authTagLength: TAG_LENGTH,
    });
    decipher.setAAD(Buffer.from(associatedData, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([
      decipher.update(Buffer.from(ciphertextPart, 'base64url')),
      decipher.final(),
    ]).toString('utf8');
  } catch (error) {
    throw new SecretDecryptionError('The secret cannot be decrypted', {
      cause: error,
    });
  }
}
