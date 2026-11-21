/**
 * Life cycle of the JWT signing keys (spec §8.2, §13.1):
 *
 * ```text
 * active ──rotate──► retiring ──(grace elapsed)──► retired
 * ```
 *
 * Exactly one key is `active` and signs new tokens. Rotation demotes it to
 * `retiring`: it no longer signs but stays in the JWKS, so tokens it signed
 * keep verifying until they expire. Once its successor is older than the
 * grace period (the access token lifetime plus the verifiers' clock
 * tolerance plus the time other auth replicas need to pick up the new active
 * key), no valid token can carry its `kid` and it becomes `retired`
 * (removed from the JWKS, kept for the record).
 *
 * @see docs/PLATFORM_SPEC.md §8.2, §13.1
 * @see https://www.rfc-editor.org/rfc/rfc7517#section-5 (JWK Set)
 */
export const KEY_CACHE_REFRESH_MS = 30_000;

/** Clock skew tolerated by every verifier (kit `ACCESS_TOKEN_CLOCK_TOLERANCE_SECONDS`). */
export const VERIFIER_CLOCK_TOLERANCE_SECONDS = 30;

/** Status of a signing key (`signing_keys.status`). */
export type SigningKeyStatus = 'active' | 'retiring' | 'retired';

/** How long a retiring key stays published after its successor was created, seconds. */
export function retirementGraceSeconds(accessTokenTtlSeconds: number): number {
  return (
    accessTokenTtlSeconds +
    VERIFIER_CLOCK_TOLERANCE_SECONDS +
    Math.ceil(KEY_CACHE_REFRESH_MS / 1000)
  );
}

/** `true` when a key of this status belongs in the published JWKS. */
export function isPublished(status: SigningKeyStatus): boolean {
  return status !== 'retired';
}
