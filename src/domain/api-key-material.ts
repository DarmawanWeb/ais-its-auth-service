import { randomInt } from 'node:crypto';

import {
  API_KEY_ID_LENGTH,
  API_KEY_SECRET_LENGTH,
  BASE62_ALPHABET,
  formatApiKey,
  hashApiKey,
  type ParsedApiKey,
  parseApiKey,
} from '@darmawanweb/ais-its-contracts/auth';

import { hexDigestsEqual } from './opaque-token.js';

/**
 * API key material (spec §8.1): `sk_<10-char id>_<32-char secret>` in
 * base62, formatted and parsed by the contracts helpers. The id part is the
 * public lookup prefix `sk_<id>` (`api_keys.prefix`, unique); the full key
 * is stored only as its SHA-256 (`api_keys.key_hash`, contracts `hashApiKey`:
 * the one definition producers and verifiers share) and shown once.
 *
 * Characters are drawn with `crypto.randomInt`, which samples uniformly
 * (rejection sampling, no modulo bias): 32 base62 characters carry
 * ≈ 190 bits of entropy.
 *
 * @see docs/PLATFORM_SPEC.md §8.1
 */
export interface GeneratedApiKey extends ParsedApiKey {
  /** The full key, shown to the caller exactly once. */
  readonly key: string;
  /** SHA-256 (hex) of the full key. */
  readonly hash: string;
}

/** `length` uniformly random base62 characters. */
export function randomBase62(length: number): string {
  let value = '';
  for (let index = 0; index < length; index += 1) {
    value += BASE62_ALPHABET.charAt(randomInt(BASE62_ALPHABET.length));
  }
  return value;
}

/**
 * A new API key with its lookup prefix and hash; with `id`, a new secret for
 * an existing key (rotation keeps the id and so the prefix `sk_<id>`).
 */
export async function generateApiKey(
  id: string = randomBase62(API_KEY_ID_LENGTH),
): Promise<GeneratedApiKey> {
  const secret = randomBase62(API_KEY_SECRET_LENGTH);
  const key = formatApiKey({ id, secret });
  const parsed = parseApiKey(key);
  if (parsed === null) throw new Error('Generated an invalid API key');
  return { ...parsed, key, hash: await hashApiKey(key) };
}

/** The hashes a key row accepts: its current one, and during a rotation's grace period the replaced one. */
export interface AcceptedKeyHashes {
  readonly keyHash: string;
  readonly previousKeyHash: string | null;
  readonly previousKeyExpiresAt: Date | null;
}

/**
 * Which secret of a key row `key` is, compared in constant time against
 * each accepted hash: `current`, `previous` (the replaced secret, until
 * `previousKeyExpiresAt`), or `null`. `key` must be well-formed (parse it
 * first): contracts `hashApiKey` throws `TypeError` for anything else.
 */
export async function matchApiKey(
  key: string,
  accepted: AcceptedKeyHashes,
  now: Date = new Date(),
): Promise<'current' | 'previous' | null> {
  const hash = await hashApiKey(key);
  const current = hexDigestsEqual(hash, accepted.keyHash);
  const previous =
    accepted.previousKeyHash !== null &&
    accepted.previousKeyExpiresAt !== null &&
    accepted.previousKeyExpiresAt.getTime() > now.getTime() &&
    hexDigestsEqual(hash, accepted.previousKeyHash);
  if (current) return 'current';
  return previous ? 'previous' : null;
}
