import { InjectConfig } from '@darmawanweb/ais-its-nest';
import { sanitizeError, sqlStateOf } from '@darmawanweb/ais-its-nest/db';
import {
  type Counter,
  MetricsService,
} from '@darmawanweb/ais-its-nest/metrics';
import {
  type ConsumerEnvelope,
  DeadLetterError,
  EventHandler,
} from '@darmawanweb/ais-its-nest/nats';
import { Injectable } from '@nestjs/common';

import type { Config } from '../config.js';
import {
  capturedLabelsOf,
  isNeverStorable,
  withoutCapturedLabels,
} from '../domain/audit-labels.js';
import {
  storableNullableText,
  storableRecord,
  storableText,
} from '../domain/storable-text.js';
import {
  type AuditLabels,
  AuditLogsRepository,
  type NewAuditLog,
} from '../modules/audit-logs/audit-logs.repository.js';

/**
 * The central audit log (spec §7.3): durable consumer `auth-audit` on the
 * `AUDIT` stream, writing every service's `audit.recorded.v1` — this
 * service's own security events included — into the `audit_logs`
 * hypertable, with the names of its actor, organization and target: for
 * this service's own records the names captured when they were written
 * (`meta.auditLabels`, see `CAPTURED_LABELS_META_KEY`; the key is not
 * stored), for other services' records (and own records without captured
 * names) the names as they are when the record arrives
 * (`AuditLogsRepository.labelsFor`). Idempotent: the envelope id is part of
 * the primary key, so a redelivery inserts nothing.
 *
 * Invalid payloads are terminated by the kit. Text PostgreSQL refuses
 * (U+0000, lone surrogates, absurd nesting) is made storable, so such a
 * record is kept rather than lost. A record the database still rejects for
 * a reason inherent to it (`isNeverStorable`: data exceptions, constraint
 * violations, an index entry above the btree limit) is dead-lettered at
 * once with `DeadLetterError` (`dlq.AUDIT.auth-audit`, kept for an
 * operator) instead of being retried until `maxDeliver`; transient failures
 * are retried with backoff.
 */
@Injectable()
export class AuditLogConsumer {
  private readonly persisted: Counter<'source' | 'outcome'>;

  /** `SERVICE_NAME`: the `source` of the records whose captured names are trusted. */
  private readonly ownSource: string;

  constructor(
    private readonly logs: AuditLogsRepository,
    metrics: MetricsService,
    @InjectConfig() config: Pick<Config, 'SERVICE_NAME'>,
  ) {
    this.ownSource = config.SERVICE_NAME;
    this.persisted = metrics.counter({
      name: 'auth_audit_logs_persisted_total',
      help: 'audit.recorded.v1 events by outcome (inserted, duplicate, or dead_letter: never storable), by source service.',
      labelNames: ['source', 'outcome'],
    });
  }

  @EventHandler({
    consumer: 'auth-audit',
    concurrency: 4,
    orderBySubject: false,
  })
  async onAuditRecorded(event: ConsumerEnvelope<'auth-audit'>): Promise<void> {
    const { data } = event;
    const source = event.source.slice(0, 40);
    // Only this service writes names into its records (other producers
    // cannot read its tables, and must not name its users or tenants).
    const captured =
      event.source === this.ownSource ? capturedLabelsOf(data.meta) : undefined;
    const entry: NewAuditLog = {
      id: event.id,
      at: new Date(data.at),
      source: storableText(event.source),
      actorType: data.actorType,
      actorId: data.actorId,
      orgId: data.orgId,
      action: data.action,
      targetType: storableNullableText(data.targetType),
      targetId: storableNullableText(data.targetId),
      ip: storableNullableText(data.ip),
      userAgent: storableNullableText(data.userAgent),
      meta: storableRecord(
        captured === undefined ? data.meta : withoutCapturedLabels(data.meta),
      ),
    };
    const labels = storableLabels(
      captured ?? (await this.logs.labelsFor(entry)),
    );
    let inserted: boolean;
    try {
      inserted = await this.logs.insert({ ...entry, ...labels });
    } catch (error) {
      if (!isNeverStorable(error)) throw error;
      this.persisted.inc({ source, outcome: 'dead_letter' });
      // The driver's primary message only: never the bound values.
      const sanitized = sanitizeError(error);
      const reason =
        sanitized instanceof Error ? sanitized.message : 'database error';
      throw new DeadLetterError(
        `Audit record ${event.id} (${data.action}) can never be stored: ${reason} (SQLSTATE ${sqlStateOf(error) ?? 'unknown'})`,
        { cause: sanitized },
      );
    }
    this.persisted.inc({
      source,
      outcome: inserted ? 'inserted' : 'duplicate',
    });
  }
}

/** {@link storableNullableText} of every label (meta labels are producer text). */
function storableLabels(labels: AuditLabels): AuditLabels {
  return {
    actorName: storableNullableText(labels.actorName),
    actorEmail: storableNullableText(labels.actorEmail),
    orgName: storableNullableText(labels.orgName),
    targetLabel: storableNullableText(labels.targetLabel),
  };
}
