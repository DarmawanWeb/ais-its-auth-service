/** State of an API key as introspection sees it. */
export type ApiKeyStatus = 'active' | 'expired' | 'revoked';

/** The states of {@link ApiKeyStatus}, for OpenAPI enums. */
export const API_KEY_STATUSES: readonly ApiKeyStatus[] = [
  'active',
  'expired',
  'revoked',
];

/** Default grace period of a rotation: the replaced secret keeps working for 24 h. */
export const DEFAULT_ROTATION_GRACE_MIN = 24 * 60;

/** Longest grace period of a rotation: 7 days. */
export const MAX_ROTATION_GRACE_MIN = 7 * 24 * 60;

/**
 * `revoked` once revoked, `expired` from `expiresAt` on, else `active`. An
 * inactive key is refused by introspection whichever secret it presents.
 */
export function apiKeyStatus(
  key: { readonly revokedAt: Date | null; readonly expiresAt: Date | null },
  now: Date = new Date(),
): ApiKeyStatus {
  if (key.revokedAt !== null) return 'revoked';
  if (key.expiresAt !== null && key.expiresAt.getTime() <= now.getTime())
    return 'expired';
  return 'active';
}

/**
 * End of a rotation's grace period: the replaced secret is accepted until
 * then; `null` for `0` (it stops working at once).
 *
 * @throws {RangeError} for anything but an integer of 0 …
 *   {@link MAX_ROTATION_GRACE_MIN} (the DTO's bounds): a value that slipped
 *   past validation — `null` compares `<= 0` — must fail the rotation, not
 *   silently end the replaced secret at once.
 */
export function rotationGraceEnd(
  now: Date,
  gracePeriodMin: number,
): Date | null {
  if (
    !Number.isInteger(gracePeriodMin) ||
    gracePeriodMin < 0 ||
    gracePeriodMin > MAX_ROTATION_GRACE_MIN
  ) {
    throw new RangeError(
      `Invalid rotation grace period: ${String(gracePeriodMin)} minutes`,
    );
  }
  return gracePeriodMin === 0
    ? null
    : new Date(now.getTime() + gracePeriodMin * 60_000);
}

/**
 * When the replaced secret of a key stops being accepted, while that is
 * still ahead (`null` when there is no grace period running).
 */
export function pendingGraceEnd(
  key: { readonly previousKeyExpiresAt: Date | null },
  now: Date = new Date(),
): Date | null {
  const end = key.previousKeyExpiresAt;
  return end !== null && end.getTime() > now.getTime() ? end : null;
}
