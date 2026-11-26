import { describe, expect, it } from 'vitest';

import {
  apiKeyStatus,
  MAX_ROTATION_GRACE_MIN,
  pendingGraceEnd,
  rotationGraceEnd,
} from './api-key-lifecycle.js';

const NOW = new Date('2026-11-23T10:00:00Z');

describe('API key lifecycle', () => {
  it('derives the status from revocation and expiry', () => {
    expect(apiKeyStatus({ revokedAt: null, expiresAt: null }, NOW)).toBe(
      'active',
    );
    expect(
      apiKeyStatus(
        { revokedAt: null, expiresAt: new Date('2026-11-23T10:00:01Z') },
        NOW,
      ),
    ).toBe('active');
    expect(apiKeyStatus({ revokedAt: null, expiresAt: NOW }, NOW)).toBe(
      'expired',
    );
    expect(apiKeyStatus({ revokedAt: NOW, expiresAt: new Date(0) }, NOW)).toBe(
      'revoked',
    );
  });

  it('ends a grace period after the given minutes, or at once for 0', () => {
    expect(rotationGraceEnd(NOW, 90)?.toISOString()).toBe(
      '2026-11-23T11:30:00.000Z',
    );
    expect(rotationGraceEnd(NOW, 0)).toBeNull();
    expect(rotationGraceEnd(NOW, MAX_ROTATION_GRACE_MIN)?.toISOString()).toBe(
      '2026-11-30T10:00:00.000Z',
    );
  });

  it('refuses a grace period outside the DTO bounds instead of ending the old secret at once', () => {
    // `null <= 0` is true: a null that slipped past validation used to mean "no grace period".
    for (const invalid of [
      null,
      undefined,
      Number.NaN,
      -1,
      1.5,
      MAX_ROTATION_GRACE_MIN + 1,
      '5',
    ]) {
      expect(() => rotationGraceEnd(NOW, invalid as unknown as number)).toThrow(
        RangeError,
      );
    }
  });

  it('shows a grace end only while it is ahead', () => {
    const end = new Date('2026-11-23T11:00:00Z');
    expect(pendingGraceEnd({ previousKeyExpiresAt: end }, NOW)).toBe(end);
    expect(pendingGraceEnd({ previousKeyExpiresAt: NOW }, NOW)).toBeNull();
    expect(pendingGraceEnd({ previousKeyExpiresAt: null }, NOW)).toBeNull();
  });
});
