import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Opaque bearer secrets (refresh tokens, password reset and invitation
 * tokens): 256 random bits, base64url encoded (43 characters), stored only
 * as their SHA-256 (spec §8.3). A database leak therefore never yields a
 * usable token, and a lookup by hash needs no constant-time comparison
 * (the hash is the index key, not a secret).
 *
 * @see docs/PLATFORM_SPEC.md §8.3
 */
export const OPAQUE_TOKEN_BYTES = 32;

/** Shape of a token produced by {@link generateOpaqueToken}. */
export const OPAQUE_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** A fresh random token. */
export function generateOpaqueToken(): string {
  return randomBytes(OPAQUE_TOKEN_BYTES).toString('base64url');
}

/** Lowercase hex SHA-256 of a token or key (64 characters). */
export function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/** `true` when `value` has the shape of an opaque token (cheap pre-check before a lookup). */
export function isOpaqueToken(value: string): boolean {
  return OPAQUE_TOKEN_PATTERN.test(value);
}

/** Constant-time comparison of two hex digests of equal length. */
export function hexDigestsEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'hex');
  const right = Buffer.from(b, 'hex');
  return (
    left.length === right.length &&
    left.length > 0 &&
    timingSafeEqual(left, right)
  );
}
