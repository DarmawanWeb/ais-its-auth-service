import {
  type AuditEntry,
  type AuditRequest,
  AuditService,
} from '@darmawanweb/ais-its-nest/audit';
import type { Principal } from '@darmawanweb/ais-its-nest/auth';
import { InjectPool, withTransaction } from '@darmawanweb/ais-its-nest/db';
import { OutboxRelay } from '@darmawanweb/ais-its-nest/nats';
import { Injectable } from '@nestjs/common';
import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';

import { withCapturedLabels } from '../domain/audit-labels.js';
import { AuditLabelReader } from './audit-labels.js';
import type { Executor } from './database.js';
import * as schema from './schema.js';

/** Queues the audit record of an entry; resolves to its envelope id. */
export type AuditRecorder = (
  entry: AuditEntry,
  principal?: Principal,
  request?: AuditRequest,
) => Promise<string>;

/** A transaction opened by {@link Transactions.run}. */
export interface AuditedTransaction {
  /** Drizzle on the transaction's connection: pass it to the repositories. */
  readonly tx: Executor;
  /**
   * Writes the `audit.recorded.v1` record of an entry to the outbox in this
   * transaction (kit `AuditService.enqueue`): it commits or rolls back with
   * the change it describes, and the `OutboxRelay` publishes it on
   * `audit.v1.auth` after the commit, also after a NATS outage. Unlike the
   * best-effort `AuditService.record` it throws (an invalid entry, a failed
   * insert), and the change fails with it.
   *
   * The record carries the names of its actor, organization and target as
   * this transaction sees them when `audit` is called (`meta.auditLabels`,
   * see `CAPTURED_LABELS_META_KEY`), so a later rename or deletion — even
   * one before the consumer stores it — does not change them. Call it
   * before deleting the row it names (e.g. `organization.delete`).
   */
  readonly audit: AuditRecorder;
}

/**
 * Transactions of the audited changes (CORE-10): the change and its audit
 * record commit together, so a security event is never lost to a NATS
 * outage and a rolled-back change is never recorded.
 *
 * Uses the kit's `withTransaction` on the service pool (drizzle's own
 * `db.transaction` does not expose the connection the outbox insert needs)
 * and wraps the connection in drizzle with the service schema, as the kit's
 * `DatabaseModule` does for the pool, so repositories run unchanged on it.
 * Repositories must not open transactions on the executor they get (a
 * nested `transaction()` would issue `BEGIN`/`COMMIT` on this connection).
 */
@Injectable()
export class Transactions {
  /** Drizzle on the pool, for the labels of {@link record}. */
  private readonly db: Executor;

  constructor(
    @InjectPool() private readonly pool: Pool,
    private readonly audits: AuditService,
    private readonly relay: OutboxRelay,
    private readonly labels: AuditLabelReader,
  ) {
    this.db = drizzle({ client: pool, schema });
  }

  /**
   * Runs `work` in one transaction (`READ COMMITTED`, no retries: callers
   * hold row locks and expect one attempt) and wakes the relay once a
   * transaction that queued records has committed, so they are published
   * at once rather than at its next poll.
   */
  async run<T>(
    work: (transaction: AuditedTransaction) => Promise<T>,
  ): Promise<T> {
    const queued = { records: 0 };
    const result = await withTransaction(this.pool, (client) => {
      const tx = drizzle({ client, schema });
      return work({
        tx,
        audit: async (entry, principal, request) => {
          queued.records += 1;
          const labelled = await this.labelled(tx, entry, principal, request);
          return this.audits.enqueue(client, labelled, principal, request);
        },
      });
    });
    if (queued.records > 0) this.relay.notify();
    return result;
  }

  /**
   * Queues a record that describes no database change of its own (e.g. a
   * signing key rotation, whose transaction belongs to the key store) on
   * its own connection, right after that change: durable like
   * {@link AuditedTransaction.audit} (names captured now, from committed
   * state), but not atomic with the change.
   */
  async record(
    entry: AuditEntry,
    principal?: Principal,
    request?: AuditRequest,
  ): Promise<string> {
    const labelled = await this.labelled(this.db, entry, principal, request);
    const id = await this.audits.enqueue(
      this.pool,
      labelled,
      principal,
      request,
    );
    this.relay.notify();
    return id;
  }

  /**
   * `entry` with the names of its actor, organization and target as
   * `executor` sees them now (`meta.auditLabels`), for the same actor and
   * organization the kit derives (`AuditService.buildRecord`).
   */
  private async labelled(
    executor: Executor,
    entry: AuditEntry,
    principal: Principal | undefined,
    request: AuditRequest | undefined,
  ): Promise<AuditEntry> {
    const record = this.audits.buildRecord(entry, principal, request);
    const labels = await this.labels.read(executor, record);
    return { ...entry, meta: withCapturedLabels(entry.meta, labels) };
  }
}
