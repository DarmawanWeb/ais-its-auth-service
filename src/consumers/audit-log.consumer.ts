import { MetricsService } from '@darmawanweb/ais-its-nest/metrics';
import {
  type ConsumerEnvelope,
  EventHandler,
} from '@darmawanweb/ais-its-nest/nats';
import { Injectable } from '@nestjs/common';

import type { CounterMetric } from '../common/metrics.js';
import { AuditLogsRepository } from '../modules/audit-logs/audit-logs.repository.js';

/**
 * The central audit log (spec §7.3): durable consumer `auth-audit` on the
 * `AUDIT` stream, writing every service's `audit.recorded.v1` — this
 * service's own security events included — into the `audit_logs`
 * hypertable. Idempotent: the envelope id is part of the primary key, so a
 * redelivery inserts nothing. Invalid payloads are terminated by the kit.
 */
@Injectable()
export class AuditLogConsumer {
  private readonly persisted: CounterMetric;

  constructor(
    private readonly logs: AuditLogsRepository,
    metrics: MetricsService,
  ) {
    this.persisted = metrics.counter({
      name: 'auth_audit_logs_persisted_total',
      help: 'audit.recorded.v1 events written to audit_logs (outcome inserted or duplicate), by source service.',
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
    const inserted = await this.logs.insert({
      id: event.id,
      at: new Date(data.at),
      source: event.source,
      actorType: data.actorType,
      actorId: data.actorId,
      orgId: data.orgId,
      action: data.action,
      targetType: data.targetType,
      targetId: data.targetId,
      ip: data.ip,
      userAgent: data.userAgent,
      meta: data.meta,
    });
    this.persisted.inc({
      source: event.source.slice(0, 40),
      outcome: inserted ? 'inserted' : 'duplicate',
    });
  }
}
