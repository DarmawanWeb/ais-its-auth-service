import {
  OutboxModule,
  type OutboxModuleOptions,
} from '@darmawanweb/ais-its-nest/nats';
import { Global, Module } from '@nestjs/common';

import { AuditLabelReader } from './audit-labels.js';
import { Transactions } from './transactions.js';

/**
 * Relay of the audit outbox (`0005_audit_outbox.sql`): per-key mode (every
 * replica relays, rows are claimed with `SKIP LOCKED`), the kit's poll
 * interval, batch size and retry backoff. Published rows are kept one hour
 * (the kit default is 24 h): they only repeat what `audit_logs` stores.
 */
export const AUDIT_OUTBOX_OPTIONS: OutboxModuleOptions = {
  mode: 'per-key',
  retentionMs: 3_600_000,
};

/**
 * Audited transactions for every module ({@link Transactions}), with the
 * kit's `OutboxRelay` that publishes the queued audit records on `AUDIT`.
 */
@Global()
@Module({
  imports: [OutboxModule.forRoot(AUDIT_OUTBOX_OPTIONS)],
  providers: [Transactions, AuditLabelReader],
  exports: [Transactions, OutboxModule],
})
export class TransactionsModule {}
