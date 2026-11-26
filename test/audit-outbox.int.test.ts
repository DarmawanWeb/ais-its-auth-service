import { EVENT_TYPES } from '@darmawanweb/ais-its-contracts/events';
import { PG_POOL, type Pool } from '@darmawanweb/ais-its-nest/db';
import { OutboxRelay } from '@darmawanweb/ais-its-nest/nats';
import { waitFor } from '@darmawanweb/ais-its-nest/testing';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { Transactions } from '../src/db/transactions.js';

import {
  type Session,
  startTestService,
  TEST_ADMIN,
  type TestService,
} from './support/test-service.js';

interface OutboxRow {
  readonly id: string;
  readonly published_at: Date | null;
  readonly actor_id: string | null;
}

/**
 * The service's own audit records go through the transactional outbox
 * (migration 0005, kit `AuditService.enqueue`): they commit or roll back
 * with the change they describe, and wait in the outbox until the relay can
 * publish them, so a NATS outage delays them instead of dropping them. The
 * relay is stopped after sign-in, as if NATS were unreachable, and the
 * tests relay by hand.
 */
describe('audit records in the transactional outbox', () => {
  let service: TestService;
  let admin: Session;
  let adminId: string;
  let pool: Pool;
  let relay: OutboxRelay;

  beforeAll(async () => {
    service = await startTestService();
    admin = await service.loginAdmin();
    pool = service.app.get<Pool>(PG_POOL);
    relay = service.app.get(OutboxRelay);
    await relay.beforeApplicationShutdown();
    const { rows } = await pool.query<{ id: string }>(
      'SELECT id FROM users WHERE email = $1',
      [TEST_ADMIN.email],
    );
    adminId = rows[0]?.id ?? '';
  });

  afterAll(async () => {
    await service.close();
  });

  async function queued(action: string): Promise<OutboxRow[]> {
    const { rows } = await pool.query<OutboxRow>(
      `SELECT id, published_at, data->>'actorId' AS actor_id FROM outbox
       WHERE type = $1 AND data->>'action' = $2 ORDER BY seq`,
      [EVENT_TYPES.AUDIT_RECORDED, action],
    );
    return rows;
  }

  async function stored(
    id: string,
  ): Promise<{ action: string; actor_id: string | null } | undefined> {
    const { rows } = await pool.query<{
      action: string;
      actor_id: string | null;
    }>('SELECT action, actor_id FROM audit_logs WHERE id = $1', [id]);
    return rows[0];
  }

  it('commits the record with its change and stores it once the relay publishes it', async () => {
    const response = await service.app.inject({
      method: 'PATCH',
      url: '/api/v2/me',
      headers: admin.headers,
      payload: { name: 'Outbox Admin' },
    });
    expect(response.statusCode).toBe(200);
    const [record] = await queued('user.update');
    expect(record).toMatchObject({ published_at: null, actor_id: adminId });
    if (record === undefined) return;
    // Not published yet (NATS "down"): nothing reached the audit log.
    expect(await stored(record.id)).toBeUndefined();

    const pass = await relay.relayOnce();
    expect(pass.published).toBeGreaterThanOrEqual(1);
    // The outbox row id is the envelope id, which keys audit_logs.
    await expect(
      waitFor(() => stored(record.id), { timeoutMs: 15_000 }),
    ).resolves.toEqual({ action: 'user.update', actor_id: adminId });
    const [published] = await queued('user.update');
    expect(published?.published_at).toBeInstanceOf(Date);
  });

  it('rolls the record back with a failed change', async () => {
    const transactions = service.app.get(Transactions);
    await expect(
      transactions.run(async ({ audit }) => {
        await audit({
          action: 'outbox_test.rollback',
          targetType: 'user',
          targetId: adminId,
          orgId: null,
        });
        throw new Error('the change failed');
      }),
    ).rejects.toThrow('the change failed');
    expect(await queued('outbox_test.rollback')).toEqual([]);
  });

  it('queues the record of a change committed elsewhere right after it (signing key rotation)', async () => {
    const response = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/keys/rotate',
      headers: admin.headers,
    });
    expect(response.statusCode).toBe(200);
    const records = await queued('auth.signing_key.rotate');
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ published_at: null, actor_id: adminId });
  });

  it('keeps failed sign-ins best effort (no outbox row per attempt)', async () => {
    const response = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/login',
      payload: { email: TEST_ADMIN.email, password: 'WrongPassword99' },
    });
    expect(response.statusCode).toBe(401);
    expect(await queued('auth.login.failed')).toEqual([]);
  });
});
