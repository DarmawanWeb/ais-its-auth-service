import { describe, expect, it } from 'vitest';

import { decideRefresh, type RefreshTokenState, refreshTokenExpiry } from './refresh-rotation.js';

const NOW = new Date('2026-11-21T10:00:00Z');

function state(overrides: Partial<RefreshTokenState> = {}): RefreshTokenState {
  return {
    usedAt: null,
    expiresAt: new Date('2026-12-21T10:00:00Z'),
    sessionRevokedAt: null,
    userStatus: 'active',
    orgAccess: true,
    ...overrides,
  };
}

describe('refresh token rotation state machine (spec §8.3)', () => {
  it('rotates an unused, unexpired token of an active session', () => {
    expect(decideRefresh(state(), NOW)).toEqual({ action: 'rotate' });
  });

  it('revokes the family when a consumed token is presented again (reuse detection)', () => {
    expect(decideRefresh(state({ usedAt: new Date('2026-11-21T09:59:00Z') }), NOW)).toEqual({
      action: 'revoke_family',
      reason: 'reuse_detected',
    });
  });

  it('rejects tokens of revoked sessions before anything else', () => {
    expect(
      decideRefresh(state({ sessionRevokedAt: new Date('2026-11-20T00:00:00Z'), usedAt: NOW }), NOW),
    ).toEqual({ action: 'reject', reason: 'session_revoked' });
  });

  it('rejects expired tokens at and after the expiry instant', () => {
    expect(decideRefresh(state({ expiresAt: NOW }), NOW)).toEqual({ action: 'reject', reason: 'expired' });
    expect(decideRefresh(state({ expiresAt: new Date(NOW.getTime() + 1) }), NOW)).toEqual({ action: 'rotate' });
  });

  it('revokes the family of disabled or invited accounts and of removed members', () => {
    expect(decideRefresh(state({ userStatus: 'disabled' }), NOW)).toEqual({
      action: 'revoke_family',
      reason: 'account_inactive',
    });
    expect(decideRefresh(state({ userStatus: 'invited' }), NOW)).toEqual({
      action: 'revoke_family',
      reason: 'account_inactive',
    });
    expect(decideRefresh(state({ orgAccess: false }), NOW)).toEqual({
      action: 'revoke_family',
      reason: 'membership_removed',
    });
  });

  it('gives each token a sliding lifetime of REFRESH_TOKEN_TTL_DAYS', () => {
    expect(refreshTokenExpiry(NOW, 30).toISOString()).toBe('2026-12-21T10:00:00.000Z');
  });
});
