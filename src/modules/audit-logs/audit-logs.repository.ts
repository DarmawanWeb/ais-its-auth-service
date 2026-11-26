import type { AuditActorType } from '@darmawanweb/ais-its-contracts/domain';
import { type Database, InjectDb } from '@darmawanweb/ais-its-nest/db';
import { Injectable } from '@nestjs/common';
import {
  and,
  asc,
  count,
  desc,
  eq,
  getTableColumns,
  gte,
  like,
  lt,
  max,
  type SQL,
  sql,
} from 'drizzle-orm';
import { alias } from 'drizzle-orm/pg-core';

import {
  escapeLikePattern,
  type AuditLogRow,
  type Executor,
} from '../../db/database.js';
import {
  type AuditLabelInput,
  readAuditLabels,
} from '../../db/audit-labels.js';
import * as schema from '../../db/schema.js';
import type { AuditLabels } from '../../domain/audit-labels.js';

export type { AuditLabelInput } from '../../db/audit-labels.js';
export type { AuditLabels } from '../../domain/audit-labels.js';

const { apiKeys, auditLogs, organizations, users } = schema;

/** A record to persist (the envelope id deduplicates redeliveries). */
export interface NewAuditLog extends Partial<AuditLabels> {
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

/** Filters of `GET /audit-logs` (and its CSV export). */
export interface AuditLogFilter {
  readonly actorId?: string | undefined;
  /** Actor e-mail (case-insensitive), as captured or, for older rows, current. */
  readonly actorEmail?: string | undefined;
  readonly action?: string | undefined;
  /** Prefix of the action, e.g. `membership.` */
  readonly actionPrefix?: string | undefined;
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

/** An action recorded in a scope and range, with its count and newest time. */
export interface AuditActionCount {
  readonly action: string;
  readonly count: number;
  readonly lastAt: Date;
}

/** Most distinct actions `GET /audit-logs/actions` returns. */
export const AUDIT_ACTIONS_MAX = 500;

/** Current names, for rows stored before labels were captured. */
const actorUsers = alias(users, 'actor_user');
const actorKeys = alias(apiKeys, 'actor_key');
const currentOrgs = alias(organizations, 'current_org');

/**
 * A row with its labels as the API shows them: the names captured when it
 * was stored, else (rows of 0.1.0) the current names of its actor and
 * organization.
 */
const effectiveColumns = {
  ...getTableColumns(auditLogs),
  actorName: sql<
    string | null
  >`coalesce(${auditLogs.actorName}, ${actorUsers.name}, ${actorKeys.name})`,
  actorEmail: sql<
    string | null
  >`coalesce(${auditLogs.actorEmail}, ${actorUsers.email})`,
  orgName: sql<
    string | null
  >`coalesce(${auditLogs.orgName}, ${currentOrgs.name})`,
};

/** Drizzle access to the `audit_logs` hypertable. */
@Injectable()
export class AuditLogsRepository {
  constructor(@InjectDb() private readonly db: Database<typeof schema>) {}

  /**
   * Inserts a record once; `false` for a redelivered envelope (`ON CONFLICT
   * DO NOTHING`). `executor` lets the demo seeder write its records in the
   * seed transaction.
   */
  async insert(
    entry: NewAuditLog,
    executor: Executor = this.db,
  ): Promise<boolean> {
    const rows = await executor
      .insert(auditLogs)
      .values(entry)
      .onConflictDoNothing({ target: [auditLogs.at, auditLogs.id] })
      .returning({ id: auditLogs.id });
    return rows.length > 0;
  }

  /**
   * The names to store with a record as they are now ({@link readAuditLabels}):
   * the consumer's names for the records of other services (and for own
   * records without captured labels); `executor` lets the demo seeder read
   * them in the seed transaction.
   */
  labelsFor(
    entry: AuditLabelInput,
    executor: Executor = this.db,
  ): Promise<AuditLabels> {
    return readAuditLabels(executor, entry);
  }

  /** Newest first, `limit` rows after `cursor`, with their effective labels. */
  async list(
    filter: AuditLogFilter,
    scope: AuditLogScope,
    cursor: AuditLogCursor | undefined,
    limit: number,
  ): Promise<AuditLogRow[]> {
    const conditions: (SQL | undefined)[] = [
      ...scopeAndRange(scope, filter),
      filter.actorId === undefined
        ? undefined
        : eq(auditLogs.actorId, filter.actorId),
      filter.actorEmail === undefined
        ? undefined
        : sql`lower(${effectiveColumns.actorEmail}) = ${filter.actorEmail.toLowerCase()}`,
      filter.action === undefined
        ? undefined
        : eq(auditLogs.action, filter.action),
      filter.actionPrefix === undefined
        ? undefined
        : like(auditLogs.action, `${escapeLikePattern(filter.actionPrefix)}%`),
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
      .select(effectiveColumns)
      .from(auditLogs)
      .leftJoin(
        actorUsers,
        and(
          eq(auditLogs.actorType, 'user'),
          eq(actorUsers.id, auditLogs.actorId),
        ),
      )
      .leftJoin(
        actorKeys,
        and(
          eq(auditLogs.actorType, 'api_key'),
          eq(actorKeys.id, auditLogs.actorId),
        ),
      )
      .leftJoin(currentOrgs, eq(currentOrgs.id, auditLogs.orgId))
      .where(and(...conditions))
      .orderBy(desc(auditLogs.at), desc(auditLogs.id))
      .limit(limit);
  }

  /**
   * The distinct actions recorded in a scope and range (optionally under a
   * prefix), by action, with their counts: at most {@link AUDIT_ACTIONS_MAX}.
   */
  async actions(
    scope: AuditLogScope,
    range: { readonly from: Date; readonly to: Date },
    actionPrefix: string | undefined,
  ): Promise<AuditActionCount[]> {
    const rows = await this.db
      .select({
        action: auditLogs.action,
        count: count(),
        lastAt: max(auditLogs.at),
      })
      .from(auditLogs)
      .where(
        and(
          ...scopeAndRange(scope, range),
          actionPrefix === undefined
            ? undefined
            : like(auditLogs.action, `${escapeLikePattern(actionPrefix)}%`),
        ),
      )
      .groupBy(auditLogs.action)
      .orderBy(asc(auditLogs.action))
      .limit(AUDIT_ACTIONS_MAX);
    return rows.flatMap((row) =>
      row.lastAt === null
        ? []
        : [{ action: row.action, count: row.count, lastAt: row.lastAt }],
    );
  }
}

/** Tenancy and time range conditions (`[from, to)`). */
function scopeAndRange(
  scope: AuditLogScope,
  range: { readonly from: Date; readonly to: Date },
): (SQL | undefined)[] {
  return [
    scope.kind === 'org' ? eq(auditLogs.orgId, scope.orgId) : undefined,
    gte(auditLogs.at, range.from),
    lt(auditLogs.at, range.to),
  ];
}
