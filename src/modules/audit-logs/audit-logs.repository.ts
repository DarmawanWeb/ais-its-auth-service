import type { AuditActorType } from '@darmawanweb/ais-its-contracts/domain';
import { type Database, InjectDb } from '@darmawanweb/ais-its-nest/db';
import { Injectable } from '@nestjs/common';
import { and, desc, eq, gte, lt, type SQL, sql } from 'drizzle-orm';

import type { AuditLogRow } from '../../db/database.js';
import * as schema from '../../db/schema.js';

const { auditLogs } = schema;

/** A record to persist (the envelope id deduplicates redeliveries). */
export interface NewAuditLog {
  readonly id: string;
  readonly at: Date;
  readonly source: string;
  readonly actorType: AuditActorType;
  readonly actorId: string | null;
  readonly orgId: string | null;
  readonly action: string;
  readonly targetType: string | null;
  readonly targetId: string | null;
  readonly ip: string | null;
  readonly userAgent: string | null;
  readonly meta: Record<string, unknown>;
}

/** Filters of `GET /audit-logs`. */
export interface AuditLogFilter {
  readonly actorId?: string | undefined;
  readonly action?: string | undefined;
  readonly targetType?: string | undefined;
  readonly targetId?: string | undefined;
  readonly from: Date;
  readonly to: Date;
}

/** Tenancy of a listing: one organization, or every record (super admins). */
export type AuditLogScope =
  { readonly kind: 'org'; readonly orgId: string } | { readonly kind: 'all' };

/** Position of the last row of a page (`at` DESC, `id` DESC). */
export interface AuditLogCursor {
  readonly at: string;
  readonly id: string;
}

/** Drizzle access to the `audit_logs` hypertable. */
@Injectable()
export class AuditLogsRepository {
  constructor(@InjectDb() private readonly db: Database<typeof schema>) {}

  /** Inserts a record once; `false` for a redelivered envelope (`ON CONFLICT DO NOTHING`). */
  async insert(entry: NewAuditLog): Promise<boolean> {
    const rows = await this.db
      .insert(auditLogs)
      .values(entry)
      .onConflictDoNothing({ target: [auditLogs.at, auditLogs.id] })
      .returning({ id: auditLogs.id });
    return rows.length > 0;
  }

  /** Newest first, `limit` rows after `cursor`. */
  async list(
    filter: AuditLogFilter,
    scope: AuditLogScope,
    cursor: AuditLogCursor | undefined,
    limit: number,
  ): Promise<AuditLogRow[]> {
    const conditions: (SQL | undefined)[] = [
      scope.kind === 'org' ? eq(auditLogs.orgId, scope.orgId) : undefined,
      gte(auditLogs.at, filter.from),
      lt(auditLogs.at, filter.to),
      filter.actorId === undefined
        ? undefined
        : eq(auditLogs.actorId, filter.actorId),
      filter.action === undefined
        ? undefined
        : eq(auditLogs.action, filter.action),
      filter.targetType === undefined
        ? undefined
        : eq(auditLogs.targetType, filter.targetType),
      filter.targetId === undefined
        ? undefined
        : eq(auditLogs.targetId, filter.targetId),
      cursor === undefined
        ? undefined
        : sql`(${auditLogs.at}, ${auditLogs.id}) < (${new Date(cursor.at)}::timestamptz, ${cursor.id}::uuid)`,
    ];
    return this.db
      .select()
      .from(auditLogs)
      .where(and(...conditions))
      .orderBy(desc(auditLogs.at), desc(auditLogs.id))
      .limit(limit);
  }
}
