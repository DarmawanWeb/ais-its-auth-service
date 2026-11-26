import { newId } from '@darmawanweb/ais-its-contracts/domain';
import {
  EVENT_TYPES,
  makeEnvelope,
} from '@darmawanweb/ais-its-contracts/events';
import type { MetricsService } from '@darmawanweb/ais-its-nest/metrics';
import {
  type ConsumerEnvelope,
  DeadLetterError,
} from '@darmawanweb/ais-its-nest/nats';
import { DrizzleQueryError } from 'drizzle-orm/errors';
import { describe, expect, it, vi } from 'vitest';

import type {
  AuditLabels,
  AuditLogsRepository,
  NewAuditLog,
} from '../modules/audit-logs/audit-logs.repository.js';
import { AuditLogConsumer } from './audit-log.consumer.js';

const LABELS: AuditLabels = {
  actorName: 'Siti\u0000 Rahma',
  actorEmail: 'siti@example.com',
  orgName: 'PT Demo',
  targetLabel: null,
};

function envelope(
  targetId = 'row-7',
  source = 'fleet',
  meta: Record<string, unknown> = { fields: ['name'] },
): ConsumerEnvelope<'auth-audit'> {
  return makeEnvelope<typeof EVENT_TYPES.AUDIT_RECORDED>({
    type: EVENT_TYPES.AUDIT_RECORDED,
    source,
    data: {
      actorType: 'user',
      actorId: newId(),
      orgId: newId(),
      action: 'vessel.update',
      targetType: 'vessel',
      targetId,
      ip: '10.0.0.7',
      userAgent: 'test',
      meta,
      at: new Date().toISOString(),
    },
  });
}

/** Names an `auth` record captured when it was written (`meta.auditLabels`). */
const CAPTURED: AuditLabels = {
  actorName: 'Admin Lama',
  actorEmail: 'admin@example.com',
  orgName: 'Doomed Org D',
  targetLabel: 'Doomed Org D',
};

/** drizzle's error for a failed insert: the bound values in message and params. */
function insertError(code: string, message: string): DrizzleQueryError {
  return new DrizzleQueryError(
    'insert into "auth"."audit_logs" … values ($1, …)',
    ['secret-target-id'],
    Object.assign(new Error(message), { code, severity: 'ERROR' }),
  );
}

function consumerWith(insert: (entry: NewAuditLog) => Promise<boolean>) {
  const inc = vi.fn();
  const logs = {
    labelsFor: vi.fn(() => Promise.resolve(LABELS)),
    insert: vi.fn(insert),
  };
  const metrics = { counter: () => ({ inc }) } as unknown as MetricsService;
  return {
    consumer: new AuditLogConsumer(
      logs as unknown as AuditLogsRepository,
      metrics,
      { SERVICE_NAME: 'auth' },
    ),
    logs,
    inc,
  };
}

describe('AuditLogConsumer', () => {
  it('stores the record with the names captured now (made storable)', async () => {
    const { consumer, logs, inc } = consumerWith(() => Promise.resolve(true));
    const event = envelope();
    await consumer.onAuditRecorded(event);
    expect(logs.insert).toHaveBeenCalledWith(
      expect.objectContaining({
        id: event.id,
        source: 'fleet',
        action: 'vessel.update',
        actorName: 'Siti� Rahma',
        actorEmail: 'siti@example.com',
        orgName: 'PT Demo',
        targetLabel: null,
      }),
    );
    expect(inc).toHaveBeenCalledWith({ source: 'fleet', outcome: 'inserted' });
  });

  it('stores the names an own record captured when it was written, without reading them again', async () => {
    const { consumer, logs } = consumerWith(() => Promise.resolve(true));
    // The organization was deleted before the record arrived: only the
    // names captured in its transaction still say which one it was.
    const event = envelope(newId(), 'auth', {
      name: 'Doomed Org D',
      auditLabels: CAPTURED,
    });
    await consumer.onAuditRecorded(event);
    expect(logs.labelsFor).not.toHaveBeenCalled();
    expect(logs.insert).toHaveBeenCalledWith(
      expect.objectContaining({
        id: event.id,
        source: 'auth',
        ...CAPTURED,
        // The transport key is not stored: meta shows what the change did.
        meta: { name: 'Doomed Org D' },
      }),
    );
  });

  it('reads the names now for own records without (valid) captured names', async () => {
    for (const meta of [
      { fields: ['name'] },
      { fields: ['name'], auditLabels: { ...CAPTURED, orgName: 42 } },
      { fields: ['name'], auditLabels: 'Doomed Org D' },
    ]) {
      const { consumer, logs } = consumerWith(() => Promise.resolve(true));
      await consumer.onAuditRecorded(envelope('row-7', 'auth', meta));
      expect(logs.labelsFor).toHaveBeenCalledTimes(1);
      expect(logs.insert).toHaveBeenCalledWith(
        expect.objectContaining({ orgName: 'PT Demo', meta }),
      );
    }
  });

  it('ignores names other services put into meta.auditLabels', async () => {
    const { consumer, logs } = consumerWith(() => Promise.resolve(true));
    const meta = { auditLabels: { ...CAPTURED, orgName: 'Spoofed Org' } };
    await consumer.onAuditRecorded(envelope('row-7', 'fleet', meta));
    expect(logs.labelsFor).toHaveBeenCalledTimes(1);
    expect(logs.insert).toHaveBeenCalledWith(
      expect.objectContaining({ source: 'fleet', orgName: 'PT Demo', meta }),
    );
  });

  it('counts a redelivery as duplicate', async () => {
    const { consumer, inc } = consumerWith(() => Promise.resolve(false));
    await consumer.onAuditRecorded(envelope());
    expect(inc).toHaveBeenCalledWith({ source: 'fleet', outcome: 'duplicate' });
  });

  it.each([
    [
      '54000',
      'index row size 3016 exceeds btree version 4 maximum 2704 for index "x"',
    ],
    ['23514', 'new row violates check constraint "audit_logs_action_check"'],
    ['22P05', 'unsupported Unicode escape sequence'],
  ])(
    'dead-letters a record the database can never store (SQLSTATE %s)',
    async (code, message) => {
      const { consumer, inc } = consumerWith(() =>
        Promise.reject(insertError(code, message)),
      );
      const event = envelope();
      const error: unknown = await consumer.onAuditRecorded(event).then(
        () => undefined,
        (reason: unknown) => reason,
      );
      expect(error).toBeInstanceOf(DeadLetterError);
      expect((error as Error).message).toBe(
        `Audit record ${event.id} (vessel.update) can never be stored: ${message} (SQLSTATE ${code})`,
      );
      expect(JSON.stringify(error)).not.toContain('secret-target-id');
      expect(String((error as Error).cause)).not.toContain('secret-target-id');
      expect(inc).toHaveBeenCalledWith({
        source: 'fleet',
        outcome: 'dead_letter',
      });
    },
  );

  it.each([
    ['57014', 'canceling statement due to statement timeout'],
    ['40001', 'could not serialize access'],
  ])(
    'rethrows a transient failure (SQLSTATE %s) to be retried',
    async (code, message) => {
      const failure = insertError(code, message);
      const { consumer, inc } = consumerWith(() => Promise.reject(failure));
      await expect(consumer.onAuditRecorded(envelope())).rejects.toBe(failure);
      expect(inc).not.toHaveBeenCalled();
    },
  );
});
