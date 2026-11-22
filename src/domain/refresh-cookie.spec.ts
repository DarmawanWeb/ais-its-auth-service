import { describe, expect, it } from 'vitest';

import {
  clearedRefreshCookieAttributes,
  REFRESH_COOKIE_NAME,
  refreshCookieAttributes,
  refreshFailureEndsSession,
} from './refresh-cookie.js';

/** An error carrying a problem code, like the kit's DomainError. */
function problem(code: string): Error {
  return Object.assign(new Error(code), { code });
}

describe('refresh cookie attributes (spec §8.3)', () => {
  it('is aisits_rt, HttpOnly, SameSite=Strict, scoped to /api/v2/auth, living the token TTL', () => {
    expect(REFRESH_COOKIE_NAME).toBe('aisits_rt');
    expect(refreshCookieAttributes(true, 30)).toEqual({
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: '/api/v2/auth',
      maxAge: 2_592_000,
    });
    expect(refreshCookieAttributes(false, 7)).toMatchObject({
      secure: false,
      maxAge: 604_800,
    });
  });

  it('is cleared with the same scope and Max-Age=0', () => {
    expect(clearedRefreshCookieAttributes(true)).toEqual({
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: '/api/v2/auth',
      maxAge: 0,
    });
  });

  it('is cleared only by refusals that end the session, not by transient failures', () => {
    expect(refreshFailureEndsSession(problem('INVALID_REFRESH_TOKEN'))).toBe(
      true,
    );
    expect(refreshFailureEndsSession(problem('REFRESH_TOKEN_REUSED'))).toBe(
      true,
    );
    expect(refreshFailureEndsSession(problem('ACCOUNT_DISABLED'))).toBe(true);
    expect(refreshFailureEndsSession(problem('SERVICE_UNAVAILABLE'))).toBe(
      false,
    );
    expect(refreshFailureEndsSession(problem('INTERNAL_ERROR'))).toBe(false);
    // A driver error (code = SQLSTATE) or a plain error keeps the cookie.
    expect(refreshFailureEndsSession(problem('57P01'))).toBe(false);
    expect(refreshFailureEndsSession(new Error('Connection terminated'))).toBe(
      false,
    );
    expect(refreshFailureEndsSession('INVALID_REFRESH_TOKEN')).toBe(false);
  });
});
