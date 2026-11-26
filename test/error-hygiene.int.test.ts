import { newId } from '@darmawanweb/ais-its-contracts/domain';
import { PG_POOL, type Pool } from '@darmawanweb/ais-its-nest/db';
import { waitFor } from '@darmawanweb/ais-its-nest/testing';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  type Session,
  startTestService,
  TEST_PASSWORD,
  type TestService,
} from './support/test-service.js';

/**
 * Database errors never leak the values a statement bound (0.2.0: the kit
 * sanitizes logs and problem details; the local `withoutQueryValues`
 * wrapper is gone). The service logs at debug level into `lines`.
 */
describe('database error hygiene (no secrets in responses or logs)', () => {
  const lines: string[] = [];
  let service: TestService;
  let admin: Session;
  let pool: Pool;

  beforeAll(async () => {
    service = await startTestService(
      { LOG_LEVEL: 'debug' },
      { logLines: lines },
    );
    admin = await service.loginAdmin();
    pool = service.app.get<unknown, Pool>(PG_POOL);
  });

  afterAll(async () => {
    await service.close();
  });

  it('answers a failed password write with 500 and logs it without the argon2id hash', async () => {
    const user = await service.createUser({
      email: service.email('hash-writer'),
    });
    const session = await service.login(user.email, TEST_PASSWORD);
    // Makes the UPDATE of this user's password fail (23514), as an outage would.
    await pool.query(
      `ALTER TABLE users ADD CONSTRAINT test_reject_password_write CHECK (password_hash IS NULL OR id <> '${user.id}'::uuid) NOT VALID`,
    );
    try {
      lines.length = 0;
      const response = await service.app.inject({
        method: 'POST',
        url: '/api/v2/auth/password/change',
        headers: session.headers,
        payload: {
          currentPassword: TEST_PASSWORD,
          newPassword: 'BrandNewPass2026',
        },
      });
      expect(response.statusCode).toBe(500);
      expect(response.json()).toMatchObject({ code: 'INTERNAL_ERROR' });
      expect(response.body).not.toContain('$argon2');
      const log = lines.join('\n');
      // The failure is logged (sanitized: the driver's message, no parameters) …
      expect(log).toContain('test_reject_password_write');
      // … and neither the stored hash nor the new password appears anywhere.
      expect(log).not.toContain('$argon2');
      expect(log).not.toContain('BrandNewPass2026');
    } finally {
      await pool.query(
        'ALTER TABLE users DROP CONSTRAINT test_reject_password_write',
      );
    }
  });

  it('answers a duplicate e-mail (unique violation) with 409 and logs no e-mail', async () => {
    const org = await service.createOrganization('research');
    const email = service.email('raced-address');
    const racer = await pool.connect();
    try {
      // An uncommitted account with the address: the invitation does not
      // see it, inserts its own and waits on the unique index …
      await racer.query('BEGIN');
      await racer.query(
        `INSERT INTO users (id, email, name, status) VALUES ($1, $2, 'Racer', 'invited')`,
        [newId(), email],
      );
      lines.length = 0;
      const pending = service.app.inject({
        method: 'POST',
        url: `/api/v2/organizations/${org.id}/members`,
        headers: admin.headers,
        payload: { email, name: 'Raced Invitee', role: 'viewer' },
      });
      await waitFor(
        async () =>
          (
            await pool.query<{ waiting: number }>(
              `SELECT count(*)::int AS waiting FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()`,
            )
          ).rows[0]?.waiting === 1,
        { timeoutMs: 10_000 },
      );
      // … until this commit turns its INSERT into a 23505 users_email_key.
      await racer.query('COMMIT');
      const response = await pending;
      expect(response.statusCode).toBe(409);
      expect(response.json()).toMatchObject({ code: 'INVITATION_CONFLICT' });
      expect(response.body).not.toContain(email);
      expect(lines.join('\n')).not.toContain(email);
    } finally {
      await racer.query('ROLLBACK').catch(() => undefined);
      racer.release();
    }
  });
});
