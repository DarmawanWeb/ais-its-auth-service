import { randomInt } from 'node:crypto';

import {
  API_KEY_ID_LENGTH,
  API_KEY_SECRET_LENGTH,
  BASE62_ALPHABET,
  formatApiKey,
  type ParsedApiKey,
  parseApiKey,
} from '@darmawanweb/ais-its-contracts/auth';

import { hexDigestsEqual, sha256Hex } from './opaque-token.js';

/**
 * API key material (spec §8.1): `sk_<10-char id>_<32-char secret>` in
 * base62, formatted and parsed by the contracts helpers. The id part is the
 * public lookup prefix `sk_<id>` (`api_keys.prefix`, unique); the full key
 * is stored only as its SHA-256 (`api_keys.key_hash`) and shown once.
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

/** A new API key with its lookup prefix and hash. */
export function generateApiKey(): GeneratedApiKey {
  const id = randomBase62(API_KEY_ID_LENGTH);
  const secret = randomBase62(API_KEY_SECRET_LENGTH);
  const key = formatApiKey({ id, secret });
  const parsed = parseApiKey(key);
  if (parsed === null) throw new Error('Generated an invalid API key');
  return { ...parsed, key, hash: hashApiKey(key) };
}

/** SHA-256 (hex) of a full API key, as stored in `api_keys.key_hash`. */
export function hashApiKey(key: string): string {
  return sha256Hex(key);
}

/** Constant-time check of a presented key against a stored hash. */
export function apiKeyMatches(key: string, storedHash: string): boolean {
  return hexDigestsEqual(hashApiKey(key), storedHash);
}
