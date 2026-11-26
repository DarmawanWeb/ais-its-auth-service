import type { AuditEntry, AuditService } from '@darmawanweb/ais-its-nest/audit';
import type { OutboxRelay } from '@darmawanweb/ais-its-nest/nats';
import type { Pool, PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';

import type { AuditLabels } from '../domain/audit-labels.js';
import { AuditLabelReader } from './audit-labels.js';
import { Transactions } from './transactions.js';

const ENTRY: AuditEntry = {
  action: 'user.update',
  targetType: 'user',
  targetId: '0192f3a4-5b6c-7d8e-9f01-23456789abcd',
  meta: { fields: ['name'] },
};

const LABELS: AuditLabels = {
  actorName: null,
  actorEmail: null,
  orgName: null,
  targetLabel: 'Siti Rahma <siti@example.com>',
};

/** {@link ENTRY} as it is queued: with the names read when it was written. */
const LABELLED: AuditEntry = {
  ...ENTRY,
  meta: { fields: ['name'], auditLabels: LABELS },
};

/** A pool whose one connection logs its statements, an audit service and a relay that log their calls. */
function setup() {
  const log: string[] = [];
  const client = {
    query: vi.fn((text: string) => {
      log.push(text.split(' ')[0] ?? text);
      return Promise.resolve({ rows: [], rowCount: 0 });
    }),
    release: vi.fn(),
  };
  const pool = { connect: vi.fn(() => Promise.resolve(client)) };
  const audits = {
    buildRecord: vi.fn((entry: AuditEntry) => ({
      actorType: 'system',
      actorId: null,
      orgId: entry.orgId ?? null,
      action: entry.action,
      targetType: entry.targetType ?? null,
      targetId: entry.targetId ?? null,
      ip: null,
      userAgent: null,
      meta: { ...(entry.meta ?? {}) },
      at: new Date().toISOString(),
    })),
    enqueue: vi.fn((target: unknown) => {
      log.push(target === client ? 'enqueue(client)' : 'enqueue(pool)');
      return Promise.resolve('envelope-id');
    }),
  };
  const relay = { notify: vi.fn(() => log.push('notify')) };
  const labels = new AuditLabelReader();
  const readLabels = vi.spyOn(labels, 'read').mockImplementation(() => {
    log.push('labels');
    return Promise.resolve(LABELS);
  });
  const transactions = new Transactions(
    pool as unknown as Pool,
    audits as unknown as AuditService,
    relay as unknown as OutboxRelay,
    labels,
  );
  return {
    log,
    client: client as unknown as PoolClient,
    pool,
    audits,
    relay,
    readLabels,
    transactions,
  };
}

describe('Transactions', () => {
  it('queues records on the connection of the transaction and wakes the relay after the commit', async () => {
    const { log, client, audits, readLabels, transactions } = setup();
    let transactionExecutor: unknown;
    const result = await transactions.run(async ({ tx, audit }) => {
      transactionExecutor = tx;
      await expect(audit(ENTRY)).resolves.toBe('envelope-id');
      return 42;
    });
    expect(result).toBe(42);
    expect(audits.enqueue).toHaveBeenCalledWith(
      client,
      LABELLED,
      undefined,
      undefined,
    );
    expect(log).toEqual([
      'BEGIN',
      'labels',
      'enqueue(client)',
      'COMMIT',
      'notify',
    ]);
    // The names are read in the transaction: they see its own changes.
    expect(readLabels).toHaveBeenCalledWith(
      transactionExecutor,
      expect.objectContaining({
        action: 'user.update',
        targetType: 'user',
        targetId: ENTRY.targetId,
      }),
    );
  });

  it('does not wake the relay for a transaction without records', async () => {
    const { log, relay, transactions } = setup();
    await transactions.run(() => Promise.resolve(undefined));
    expect(log).toEqual(['BEGIN', 'COMMIT']);
    expect(relay.notify).not.toHaveBeenCalled();
  });

  it('rolls the records back with a failed change and leaves the relay alone', async () => {
    const { log, relay, transactions } = setup();
    await expect(
      transactions.run(async ({ audit }) => {
        await audit(ENTRY);
        throw new Error('the change failed');
      }),
    ).rejects.toThrow('the change failed');
    expect(log).toEqual(['BEGIN', 'labels', 'enqueue(client)', 'ROLLBACK']);
    expect(relay.notify).not.toHaveBeenCalled();
  });

  it('queues a record outside a transaction on the pool (durable, not atomic)', async () => {
    const { log, pool, audits, transactions } = setup();
    await transactions.record(ENTRY);
    expect(audits.enqueue).toHaveBeenCalledWith(
      pool,
      LABELLED,
      undefined,
      undefined,
    );
    expect(log).toEqual(['labels', 'enqueue(pool)', 'notify']);
  });
});
