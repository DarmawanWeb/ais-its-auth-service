/**
 * Refresh token rotation state machine (spec §8.3). A session is a token
 * family: every refresh consumes the presented token (`used_at`) and issues
 * its successor in the same family. Presenting a consumed token means it
 * was copied — by an attacker or by the legitimate client after a theft —
 * so the whole family is revoked (reuse detection, OAuth 2.0 Security BCP
 * §4.14.2).
 *
 * ```text
 *  presented token ──► session revoked? ── yes ─► reject (session_revoked)
 *        │ no
 *        ▼
 *     already used? ── yes ─► revoke family (reuse_detected)
 *        │ no
 *        ▼
 *       expired? ── yes ─► reject (expired)
 *        │ no
 *        ▼
 *   account active? ── no ─► revoke family (account_inactive)
 *        │ yes
 *        ▼
 *  still a member of the session's org? ── no ─► revoke family (membership_removed)
 *        │ yes
 *        ▼
 *      rotate (mark used, issue successor)
 * ```
 *
 * @see docs/PLATFORM_SPEC.md §8.3
 * @see https://datatracker.ietf.org/doc/html/rfc9700#section-4.14.2 (refresh token rotation)
 */
export interface RefreshTokenState {
  /** When the presented token was consumed, `null` while unused. */
  readonly usedAt: Date | null;
  readonly expiresAt: Date;
  /** Revocation of the session (token family). */
  readonly sessionRevokedAt: Date | null;
  readonly userStatus: 'active' | 'invited' | 'disabled';
  /**
   * `false` when the session's active organization no longer grants the user
   * access (membership removed and not a platform admin); `true` otherwise,
   * including sessions without an organization.
   */
  readonly orgAccess: boolean;
}

/** Why a refresh was refused. */
export type RefreshRejection =
  | 'session_revoked'
  | 'reuse_detected'
  | 'expired'
  | 'account_inactive'
  | 'membership_removed';

/** Outcome of presenting a refresh token. */
export type RefreshDecision =
  | { readonly action: 'rotate' }
  | {
      readonly action: 'reject';
      readonly reason: Extract<RefreshRejection, 'session_revoked' | 'expired'>;
    }
  | {
      readonly action: 'revoke_family';
      readonly reason: Exclude<RefreshRejection, 'session_revoked' | 'expired'>;
    };

/** Decides what a presented (known) refresh token leads to at `now`. */
export function decideRefresh(
  state: RefreshTokenState,
  now: Date,
): RefreshDecision {
  if (state.sessionRevokedAt !== null)
    return { action: 'reject', reason: 'session_revoked' };
  if (state.usedAt !== null)
    return { action: 'revoke_family', reason: 'reuse_detected' };
  if (state.expiresAt.getTime() <= now.getTime())
    return { action: 'reject', reason: 'expired' };
  if (state.userStatus !== 'active')
    return { action: 'revoke_family', reason: 'account_inactive' };
  if (!state.orgAccess)
    return { action: 'revoke_family', reason: 'membership_removed' };
  return { action: 'rotate' };
}

/** Expiry of a token issued at `issuedAt` (sliding session lifetime). */
export function refreshTokenExpiry(issuedAt: Date, ttlDays: number): Date {
  return new Date(issuedAt.getTime() + ttlDays * 86_400_000);
}
