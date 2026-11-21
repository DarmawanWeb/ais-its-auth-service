import { describe, expect, it } from 'vitest';

import {
  clearedRefreshCookieAttributes,
  REFRESH_COOKIE_NAME,
  refreshCookieAttributes,
} from './refresh-cookie.js';

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
});
