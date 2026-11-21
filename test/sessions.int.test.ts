import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  startTestService,
  TEST_ADMIN,
  TEST_PASSWORD,
  type TestService,
  WEB_ORIGIN,
} from './support/test-service.js';

describe('login, refresh rotation, logout and throttling', () => {
  let service: TestService;

  beforeAll(async () => {
    service = await startTestService();
  });

  afterAll(async () => {
    await service.close();
  });

  const refresh = (cookie: string, origin: string = WEB_ORIGIN) =>
    service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/refresh',
      headers: { cookie, origin },
    });

  it('signs in and sets the refresh cookie with the spec flags', async () => {
    const org = await service.createOrganization();
    const user = await service.createUser({
      email: service.email('captain'),
      name: 'Captain Ahmad',
      memberships: [{ orgId: org.id, role: 'fleet_manager' }],
    });
    const session = await service.login(
      user.email.toUpperCase(),
      TEST_PASSWORD,
    );

    expect(session.body).toMatchObject({
      expiresIn: 900,
      activeOrgId: org.id,
      user: {
        id: user.id,
        email: user.email,
        name: 'Captain Ahmad',
        mfaEnabled: false,
      },
      memberships: [
        {
          orgId: org.id,
          orgName: org.name,
          orgSlug: org.slug,
          orgKind: 'shipping_company',
          role: 'fleet_manager',
        },
      ],
    });
    expect(session.setCookie).toMatch(/^aisits_rt=[A-Za-z0-9_-]{43};/);
    expect(session.setCookie).toContain('Max-Age=2592000');
    expect(session.setCookie).toContain('Path=/api/v2/auth');
    expect(session.setCookie).toContain('HttpOnly');
    expect(session.setCookie).toContain('SameSite=Strict');
    expect(session.setCookie).not.toContain('Secure'); // COOKIE_SECURE unset outside production

    const me = await service.app.inject({
      method: 'GET',
      url: '/api/v2/me',
      headers: session.headers,
    });
    expect(me.json()).toMatchObject({
      id: user.id,
      activeOrgId: org.id,
      roles: ['fleet_manager'],
    });
  });

  it('refuses wrong passwords and unknown e-mails with the same problem', async () => {
    const user = await service.createUser({
      email: service.email('wrongpass'),
    });
    const wrong = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/login',
      headers: { 'x-forwarded-for': '198.51.100.1' },
      payload: { email: user.email, password: 'NotThePassword1' },
    });
    const unknown = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/login',
      headers: { 'x-forwarded-for': '198.51.100.1' },
      payload: { email: service.email('nobody'), password: 'NotThePassword1' },
    });
    for (const response of [wrong, unknown]) {
      expect(response.statusCode).toBe(401);
      expect(response.headers['content-type']).toContain(
        'application/problem+json',
      );
      expect(response.json()).toMatchObject({
        code: 'INVALID_CREDENTIALS',
        detail: 'The e-mail or password is incorrect',
      });
    }
  });

  it('rotates the refresh token and revokes the family when a used token is presented again', async () => {
    const user = await service.createUser({ email: service.email('rotation') });
    const first = await service.login(user.email, TEST_PASSWORD);

    const rotated = await refresh(first.cookie);
    expect(rotated.statusCode).toBe(200);
    expect(rotated.json()).toMatchObject({ expiresIn: 900 });
    const second = String(rotated.headers['set-cookie']).split(';')[0] ?? '';
    expect(second).not.toBe(first.cookie);
    const me = await service.app.inject({
      method: 'GET',
      url: '/api/v2/me',
      headers: {
        authorization: `Bearer ${rotated.json<{ accessToken: string }>().accessToken}`,
      },
    });
    expect(me.statusCode).toBe(200);

    const reused = await refresh(first.cookie);
    expect(reused.statusCode).toBe(401);
    expect(reused.json()).toMatchObject({ code: 'REFRESH_TOKEN_REUSED' });
    expect(String(reused.headers['set-cookie'])).toContain('Max-Age=0');

    // The whole family is revoked: the legitimate successor no longer works either.
    const successor = await refresh(second);
    expect(successor.statusCode).toBe(401);
    expect(successor.json()).toMatchObject({ code: 'INVALID_REFRESH_TOKEN' });
  });

  it('refuses refreshes without a cookie or from a foreign origin', async () => {
    const missing = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/refresh',
    });
    expect(missing.statusCode).toBe(401);
    expect(missing.json()).toMatchObject({ code: 'INVALID_REFRESH_TOKEN' });

    const user = await service.createUser({ email: service.email('csrf') });
    const session = await service.login(user.email, TEST_PASSWORD);
    const foreign = await refresh(session.cookie, 'https://evil.example');
    expect(foreign.statusCode).toBe(403);
    expect(foreign.json()).toMatchObject({ code: 'ORIGIN_NOT_ALLOWED' });
    // Same-origin requests through the gateway (PUBLIC_BASE_URL) are allowed.
    expect(
      (await refresh(session.cookie, 'http://localhost:8000')).statusCode,
    ).toBe(200);
  });

  it('logs out: revokes the session and clears the cookie', async () => {
    const user = await service.createUser({ email: service.email('logout') });
    const session = await service.login(user.email, TEST_PASSWORD);
    const logout = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/logout',
      headers: { cookie: session.cookie, origin: WEB_ORIGIN },
    });
    expect(logout.statusCode).toBe(204);
    expect(String(logout.headers['set-cookie'])).toMatch(
      /^aisits_rt=;.*Max-Age=0/,
    );
    expect((await refresh(session.cookie)).statusCode).toBe(401);
    // Idempotent without a session.
    const again = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/logout',
    });
    expect(again.statusCode).toBe(204);
  });

  it('lists and revokes the own sessions', async () => {
    const user = await service.createUser({ email: service.email('devices') });
    const laptop = await service.login(user.email, TEST_PASSWORD);
    const phone = await service.login(user.email, TEST_PASSWORD);
    const list = await service.app.inject({
      method: 'GET',
      url: '/api/v2/auth/sessions',
      headers: laptop.headers,
    });
    expect(list.statusCode).toBe(200);
    const sessions = list.json<{
      data: { id: string; current: boolean }[];
      meta: { total: number };
    }>();
    expect(sessions.meta.total).toBe(2);
    const other = sessions.data.find((entry) => !entry.current);
    expect(other).toBeDefined();

    const revoke = await service.app.inject({
      method: 'DELETE',
      url: `/api/v2/auth/sessions/${other?.id ?? ''}`,
      headers: laptop.headers,
    });
    expect(revoke.statusCode).toBe(204);
    expect((await refresh(phone.cookie)).statusCode).toBe(401);
    expect((await refresh(laptop.cookie)).statusCode).toBe(200);

    const stranger = await service.createUser({
      email: service.email('stranger'),
    });
    const strangerSession = await service.login(stranger.email, TEST_PASSWORD);
    const foreign = await service.app.inject({
      method: 'DELETE',
      url: `/api/v2/auth/sessions/${other?.id ?? ''}`,
      headers: strangerSession.headers,
    });
    expect(foreign.statusCode).toBe(404);
  });

  it('switches the active organization of members only and keeps it across refreshes', async () => {
    const first = await service.createOrganization();
    const second = await service.createOrganization();
    const outsider = await service.createOrganization();
    const user = await service.createUser({
      email: service.email('multiorg'),
      memberships: [
        { orgId: first.id, role: 'viewer' },
        { orgId: second.id, role: 'org_admin' },
      ],
    });
    const session = await service.login(user.email, TEST_PASSWORD);
    expect(session.body.activeOrgId).toBe(first.id);

    const switched = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/switch-org',
      headers: session.headers,
      payload: { orgId: second.id },
    });
    expect(switched.statusCode).toBe(200);
    expect(switched.json()).toMatchObject({
      activeOrgId: second.id,
      expiresIn: 900,
    });
    const me = await service.app.inject({
      method: 'GET',
      url: '/api/v2/me',
      headers: {
        authorization: `Bearer ${switched.json<{ accessToken: string }>().accessToken}`,
      },
    });
    expect(me.json()).toMatchObject({
      activeOrgId: second.id,
      roles: ['org_admin'],
    });

    const refreshed = await refresh(session.cookie);
    const verify = await service.app.inject({
      method: 'GET',
      url: '/api/v2/auth/verify',
      headers: {
        authorization: `Bearer ${refreshed.json<{ accessToken: string }>().accessToken}`,
      },
    });
    expect(verify.headers['x-org-id']).toBe(second.id);

    const denied = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/switch-org',
      headers: session.headers,
      payload: { orgId: outsider.id },
    });
    expect(denied.statusCode).toBe(403);
    expect(denied.json()).toMatchObject({ code: 'NOT_A_MEMBER' });

    // Super admins may enter any organization.
    const admin = await service.loginAdmin();
    const entered = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/switch-org',
      headers: admin.headers,
      payload: { orgId: outsider.id },
    });
    expect(entered.statusCode).toBe(200);
  });

  it('throttles 5 failed logins per e-mail with 429 RATE_LIMITED and Retry-After', async () => {
    const user = await service.createUser({
      email: service.email('bruteforce'),
    });
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const failed = await service.app.inject({
        method: 'POST',
        url: '/api/v2/auth/login',
        headers: { 'x-forwarded-for': `192.0.2.${attempt + 1}` },
        payload: { email: user.email, password: `WrongGuess${attempt}` },
      });
      expect(failed.statusCode).toBe(401);
    }
    const blocked = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/login',
      headers: { 'x-forwarded-for': '192.0.2.99' },
      payload: { email: user.email, password: TEST_PASSWORD },
    });
    expect(blocked.statusCode).toBe(429);
    expect(blocked.json()).toMatchObject({ code: 'RATE_LIMITED' });
    expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0);
    expect(Number(blocked.headers['retry-after'])).toBeLessThanOrEqual(900);
  });

  it('throttles 20 failed logins per IP across e-mails', async () => {
    const ip = '192.0.2.200';
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const failed = await service.app.inject({
        method: 'POST',
        url: '/api/v2/auth/login',
        headers: { 'x-forwarded-for': ip },
        payload: {
          email: service.email(`spray${attempt}`),
          password: 'Password123',
        },
      });
      expect(failed.statusCode).toBe(401);
    }
    const blocked = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/login',
      headers: { 'x-forwarded-for': ip },
      payload: { email: TEST_ADMIN.email, password: TEST_ADMIN.password },
    });
    expect(blocked.statusCode).toBe(429);
    // Other clients are not affected.
    await expect(service.loginAdmin()).resolves.toBeDefined();
  });

  it('refuses disabled accounts and revokes their sessions', async () => {
    const user = await service.createUser({ email: service.email('disabled') });
    const session = await service.login(user.email, TEST_PASSWORD);
    const admin = await service.loginAdmin();
    const disabled = await service.app.inject({
      method: 'PATCH',
      url: `/api/v2/users/${user.id}`,
      headers: admin.headers,
      payload: { status: 'disabled' },
    });
    expect(disabled.statusCode).toBe(200);
    expect(disabled.json()).toMatchObject({ status: 'disabled' });
    expect((await refresh(session.cookie)).statusCode).toBe(401);
    const login = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/login',
      headers: { 'x-forwarded-for': '198.51.100.77' },
      payload: { email: user.email, password: TEST_PASSWORD },
    });
    expect(login.statusCode).toBe(403);
    expect(login.json()).toMatchObject({ code: 'ACCOUNT_DISABLED' });

    const self = await service.app.inject({
      method: 'PATCH',
      url: `/api/v2/users/${(admin.body.user as { id: string }).id}`,
      headers: admin.headers,
      payload: { status: 'disabled' },
    });
    expect(self.statusCode).toBe(409);
  });
});
