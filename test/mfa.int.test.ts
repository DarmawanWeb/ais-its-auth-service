import { setTimeout as sleep } from 'node:timers/promises';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { generateTotp, TOTP_PARAMETERS } from '../src/domain/totp.js';
import {
  startTestService,
  TEST_PASSWORD,
  type TestService,
} from './support/test-service.js';

const STEP_MS = TOTP_PARAMETERS.periodSeconds * 1000;

/** Waits until the current 30-second step has at least 20 s left, so the codes below stay in the window. */
async function freshStep(): Promise<number> {
  const intoStep = Date.now() % STEP_MS;
  if (intoStep > STEP_MS - 20_000) await sleep(STEP_MS - intoStep + 50);
  return Date.now();
}

describe('TOTP multi-factor authentication', () => {
  let service: TestService;

  beforeAll(async () => {
    service = await startTestService();
  });

  afterAll(async () => {
    await service.close();
  });

  it('sets up, enables, signs in with and disables MFA using real TOTP codes', async () => {
    const user = await service.createUser({ email: service.email('mfa') });
    const session = await service.login(user.email, TEST_PASSWORD);

    const setup = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/mfa/setup',
      headers: session.headers,
    });
    expect(setup.statusCode).toBe(200);
    const { secret, otpauthUrl } = setup.json<{
      secret: string;
      otpauthUrl: string;
    }>();
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(otpauthUrl).toContain('otpauth://totp/');
    expect(otpauthUrl).toContain(`secret=${secret}`);
    expect(otpauthUrl).toContain('issuer=AIS%20Maritime%20Intelligence');

    const now = await freshStep();
    const wrong = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/mfa/enable',
      headers: session.headers,
      payload: { code: generateTotp(secret, now + 5 * STEP_MS) },
    });
    expect(wrong.statusCode).toBe(401);
    expect(wrong.json()).toMatchObject({ code: 'INVALID_MFA_CODE' });

    const enable = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/mfa/enable',
      headers: session.headers,
      payload: { code: generateTotp(secret, now) },
    });
    expect(enable.statusCode).toBe(204);
    const me = await service.app.inject({
      method: 'GET',
      url: '/api/v2/me',
      headers: session.headers,
    });
    expect(me.json()).toMatchObject({ mfaEnabled: true });

    // The password alone now yields an MFA challenge, no session.
    const login = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/login',
      headers: { 'x-forwarded-for': '203.0.113.50' },
      payload: { email: user.email, password: TEST_PASSWORD },
    });
    expect(login.statusCode).toBe(200);
    expect(login.headers['set-cookie']).toBeUndefined();
    const challenge = login.json<{ mfaRequired: boolean; mfaToken: string }>();
    expect(challenge.mfaRequired).toBe(true);

    // The challenge is no access token.
    const misuse = await service.app.inject({
      method: 'GET',
      url: '/api/v2/me',
      headers: { authorization: `Bearer ${challenge.mfaToken}` },
    });
    expect(misuse.statusCode).toBe(401);

    // A code already used (enable) is refused: no replay.
    const replay = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/mfa/verify',
      payload: {
        mfaToken: challenge.mfaToken,
        code: generateTotp(secret, now),
      },
    });
    expect(replay.statusCode).toBe(401);
    expect(replay.json()).toMatchObject({ code: 'INVALID_MFA_CODE' });

    const verified = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/mfa/verify',
      payload: {
        mfaToken: challenge.mfaToken,
        code: generateTotp(secret, now + STEP_MS),
      },
    });
    expect(verified.statusCode).toBe(200);
    expect(verified.json()).toMatchObject({
      user: { id: user.id, mfaEnabled: true },
      expiresIn: 900,
    });
    expect(String(verified.headers['set-cookie'])).toMatch(/^aisits_rt=/);

    // The challenge is single use (refused before the code is checked, so no code is consumed).
    const again = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/mfa/verify',
      payload: {
        mfaToken: challenge.mfaToken,
        code: generateTotp(secret, now - STEP_MS),
      },
    });
    expect(again.statusCode).toBe(400);
    expect(again.json()).toMatchObject({ code: 'INVALID_TOKEN' });

    const disable = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/mfa/disable',
      headers: session.headers,
      payload: { code: generateTotp(secret, now - STEP_MS) },
    });
    expect(disable.statusCode).toBe(204);
    const plain = await service.login(user.email, TEST_PASSWORD);
    expect(plain.body).toMatchObject({ user: { mfaEnabled: false } });
  });

  it('refuses to enable without a setup and to disable when not enabled', async () => {
    const user = await service.createUser({ email: service.email('nomfa') });
    const session = await service.login(user.email, TEST_PASSWORD);
    const enable = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/mfa/enable',
      headers: session.headers,
      payload: { code: '123456' },
    });
    expect(enable.statusCode).toBe(409);
    expect(enable.json()).toMatchObject({ code: 'MFA_SETUP_REQUIRED' });
    const disable = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/mfa/disable',
      headers: session.headers,
      payload: { code: '123456' },
    });
    expect(disable.statusCode).toBe(409);
    expect(disable.json()).toMatchObject({ code: 'MFA_NOT_ENABLED' });
  });
});
