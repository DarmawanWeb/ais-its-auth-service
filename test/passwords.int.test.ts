import { setTimeout as sleep } from 'node:timers/promises';

import { PG_POOL, type Pool } from '@darmawanweb/ais-its-nest/db';
import { waitFor } from '@darmawanweb/ais-its-nest/testing';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it, vi } from 'vitest';

import { PasswordHasher } from '../src/modules/crypto/password-hasher.service.js';
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

  it('checks the link before hashing anything and throttles failed resets per IP', async () => {
    const hash = vi.spyOn(service.app.get(PasswordHasher), 'hash');
    const reset = (token: string) =>
      service.app.inject({
        method: 'POST',
        url: '/api/v2/auth/password/reset',
        headers: { 'x-forwarded-for': '203.0.113.90' },
        payload: { token, password: 'Garbage1Password9' },
      });
    try {
      // Malformed, then well-formed but unknown: 10 failures allowed per window.
      for (let attempt = 0; attempt < 10; attempt += 1) {
        const token =
          attempt % 2 === 0 ? 'x' : 'A'.repeat(42) + String(attempt);
        const response = await reset(token);
        expect(response.statusCode).toBe(400);
        expect(response.json()).toMatchObject({ code: 'INVALID_TOKEN' });
      }
      const blocked = await reset('x');
      expect(blocked.statusCode).toBe(429);
      expect(blocked.json()).toMatchObject({ code: 'RATE_LIMITED' });
      expect(blocked.headers['retry-after']).toBeDefined();
      expect(hash).not.toHaveBeenCalled();
    } finally {
      hash.mockRestore();
    }
    // Other clients are not affected.
    const elsewhere = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/password/reset',
      headers: { 'x-forwarded-for': '203.0.113.91' },
      payload: { token: 'x', password: 'Garbage1Password9' },
    });
    expect(elsewhere.statusCode).toBe(400);
  });

  it('never re-enables an account that is disabled while its reset runs', async () => {
    const user = await service.createUser({
      email: service.email('contained'),
    });
    const sequence = await service.lastEmailSequence();
    expect((await forgot(user.email, '203.0.113.92')).statusCode).toBe(202);
    const token = tokenOfLink(
      (await service.nextEmail(user.email, sequence)).data.link,
    );
    const pool = service.app.get<unknown, Pool>(PG_POOL);

    // A second connection runs the writes of PATCH /users/:id {status: 'disabled'}
    // and holds the row lock while the reset arrives.
    const blocker = new pg.Client({
      connectionString: inject('infra').databaseUrl,
    });
    await blocker.connect();
    let response;
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        "UPDATE auth.users SET status = 'disabled', updated_at = now() WHERE id = $1",
        [user.id],
      );
      await blocker.query(
        'UPDATE auth.sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL',
        [user.id],
      );
      const pending = service.app
        .inject({
          method: 'POST',
          url: '/api/v2/auth/password/reset',
          payload: { token, password: 'Takeover2026x' },
        })
        .then((reply) => reply);
      await waitFor(
        async () => {
          const waiting = await pool.query<{ n: number }>(
            "SELECT count(*)::int AS n FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query ILIKE '%for update%'",
          );
          return (waiting.rows[0]?.n ?? 0) > 0 ? true : undefined;
        },
        { timeoutMs: 10_000, message: 'the reset waiting for the user row' },
      );
      await blocker.query('COMMIT');
      response = await pending;
    } finally {
      await blocker.end();
    }
    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({ code: 'ACCOUNT_DISABLED' });
    const stored = await pool.query<{ status: string }>(
      'SELECT status FROM users WHERE id = $1',
      [user.id],
    );
    expect(stored.rows[0]?.status).toBe('disabled');
    await expect(service.login(user.email, 'Takeover2026x')).rejects.toThrow(
      /401/,
    );
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
