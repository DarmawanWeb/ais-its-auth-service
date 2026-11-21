import { setTimeout as sleep } from 'node:timers/promises';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  startTestService,
  TEST_PASSWORD,
  type TestService,
  tokenOfLink,
  WEB_ORIGIN,
} from './support/test-service.js';

describe('forgotten passwords, resets and password changes', () => {
  let service: TestService;

  beforeAll(async () => {
    service = await startTestService();
  });

  afterAll(async () => {
    await service.close();
  });

  const forgot = (email: string, ip = '203.0.113.80') =>
    service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/password/forgot',
      headers: { 'x-forwarded-for': ip },
      payload: { email, locale: 'en' },
    });

  it('e-mails a reset link through NOTIFY; the token works exactly once and revokes the sessions', async () => {
    const user = await service.createUser({
      email: service.email('forgetful'),
      name: 'Rina',
    });
    const session = await service.login(user.email, TEST_PASSWORD);
    const sequence = await service.lastEmailSequence();

    const accepted = await forgot(user.email);
    expect(accepted.statusCode).toBe(202);
    const email = await service.nextEmail(user.email, sequence);
    expect(email).toMatchObject({
      to: user.email,
      template: 'password_reset',
      locale: 'en',
      data: { name: 'Rina', expiresInMinutes: 30 },
    });
    const link = String(email.data.link);
    expect(link.startsWith('http://localhost:8000/reset-password#token=')).toBe(
      true,
    );
    const token = tokenOfLink(link);

    const weak = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/password/reset',
      payload: { token, password: 'short1' },
    });
    expect(weak.statusCode).toBe(400);
    expect(weak.json()).toMatchObject({
      code: 'VALIDATION_FAILED',
      errors: [{ field: 'password', code: 'password_too_short' }],
    });

    const reset = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/password/reset',
      payload: { token, password: 'BrandNewSecret7' },
    });
    expect(reset.statusCode).toBe(204);
    const reused = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/password/reset',
      payload: { token, password: 'AnotherSecret8' },
    });
    expect(reused.statusCode).toBe(400);
    expect(reused.json()).toMatchObject({ code: 'INVALID_TOKEN' });

    const refresh = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/refresh',
      headers: { cookie: session.cookie, origin: WEB_ORIGIN },
    });
    expect(refresh.statusCode).toBe(401);
    await expect(service.login(user.email, TEST_PASSWORD)).rejects.toThrow(
      /401/,
    );
    await expect(
      service.login(user.email, 'BrandNewSecret7'),
    ).resolves.toBeDefined();
  });

  it('answers 202 for unknown addresses without sending anything', async () => {
    const sequence = await service.lastEmailSequence();
    const unknown = service.email('ghost');
    const response = await forgot(unknown, '203.0.113.81');
    expect(response.statusCode).toBe(202);
    await sleep(500);
    expect(await service.lastEmailSequence()).toBe(sequence);
  });

  it('throttles forgot-password requests per IP', async () => {
    const ip = '203.0.113.82';
    for (let attempt = 0; attempt < 10; attempt += 1) {
      expect(
        (await forgot(service.email(`flood${attempt}`), ip)).statusCode,
      ).toBe(202);
    }
    const blocked = await forgot(service.email('flood-last'), ip);
    expect(blocked.statusCode).toBe(429);
    expect(blocked.headers['retry-after']).toBeDefined();
  });

  it('changes the password with the current one and revokes the other sessions', async () => {
    const user = await service.createUser({ email: service.email('changer') });
    const current = await service.login(user.email, TEST_PASSWORD);
    const other = await service.login(user.email, TEST_PASSWORD);

    const wrong = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/password/change',
      headers: current.headers,
      payload: {
        currentPassword: 'NotMyPassword1',
        newPassword: 'ChangedSecret9',
      },
    });
    expect(wrong.statusCode).toBe(400);
    expect(wrong.json()).toMatchObject({
      errors: [{ field: 'currentPassword' }],
    });

    const noDigit = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/password/change',
      headers: current.headers,
      payload: {
        currentPassword: TEST_PASSWORD,
        newPassword: 'OnlyLettersHere',
      },
    });
    expect(noDigit.statusCode).toBe(400);
    expect(noDigit.json()).toMatchObject({
      errors: [{ field: 'newPassword', code: 'password_missing_digit' }],
    });

    const changed = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/password/change',
      headers: current.headers,
      payload: {
        currentPassword: TEST_PASSWORD,
        newPassword: 'ChangedSecret9',
      },
    });
    expect(changed.statusCode).toBe(204);

    const refreshOther = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/refresh',
      headers: { cookie: other.cookie, origin: WEB_ORIGIN },
    });
    expect(refreshOther.statusCode).toBe(401);
    const refreshCurrent = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/refresh',
      headers: { cookie: current.cookie, origin: WEB_ORIGIN },
    });
    expect(refreshCurrent.statusCode).toBe(200);
    await expect(
      service.login(user.email, 'ChangedSecret9'),
    ).resolves.toBeDefined();
  });
});
