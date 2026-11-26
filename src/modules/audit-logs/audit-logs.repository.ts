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
import * as schema from '../../db/schema.js';
import {
  metaTargetLabel,
  type OwnTargetType,
  ownTarget,
} from '../../domain/audit-labels.js';

const { apiKeys, auditLogs, membershipInvitations, organizations, users } =
  schema;

/** Names stored with a record (`0003_audit_log_labels.sql`). */
export interface AuditLabels {
  readonly actorName: string | null;
  readonly actorEmail: string | null;
  readonly orgName: string | null;
  readonly targetLabel: string | null;
}

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

/** What {@link AuditLogsRepository.labelsFor} names. */
export type AuditLabelInput = Pick<
  NewAuditLog,
  'actorType' | 'actorId' | 'orgId' | 'targetType' | 'targetId' | 'meta'
>;

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
   * The names to store with a record, read in one statement as they are
   * now: the actor's name and e-mail (users) or the API key's name, the
   * organization's name, and the target's label — from this service's
   * tables for its own target types (`ownTarget`), otherwise (or when the
   * row is gone) the producer's `meta.targetLabel` / `meta.name`. Ids are
   * bound as parameters and only UUIDs are looked up, so the statement
   * cannot fail on the record's values.
   */
  async labelsFor(
    entry: AuditLabelInput,
    executor: Executor = this.db,
  ): Promise<AuditLabels> {
    const actorUser = entry.actorType === 'user' ? entry.actorId : null;
    const actorKey = entry.actorType === 'api_key' ? entry.actorId : null;
    const target = ownTarget(entry.targetType, entry.targetId);
    const result = await executor.execute<{
      actor_user_name: string | null;
      actor_user_email: string | null;
      actor_key_name: string | null;
      org_name: string | null;
      target_label: string | null;
    }>(sql`
      SELECT
        (SELECT ${users.name} FROM ${users} WHERE ${users.id} = ${actorUser}::uuid) AS actor_user_name,
        (SELECT ${users.email} FROM ${users} WHERE ${users.id} = ${actorUser}::uuid) AS actor_user_email,
        (SELECT ${apiKeys.name} FROM ${apiKeys} WHERE ${apiKeys.id} = ${actorKey}::uuid) AS actor_key_name,
        (SELECT ${organizations.name} FROM ${organizations} WHERE ${organizations.id} = ${entry.orgId}::uuid) AS org_name,
        ${target === undefined ? sql`NULL::text` : targetLabelSql(target.type, target.id)} AS target_label`);
    const row = result.rows[0];
    return {
      actorName: row?.actor_user_name ?? row?.actor_key_name ?? null,
      actorEmail: row?.actor_user_email ?? null,
      orgName: row?.org_name ?? null,
      targetLabel: row?.target_label ?? metaTargetLabel(entry.meta),
    };
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

/** Scalar subquery of the label of one of this service's targets. */
function targetLabelSql(type: OwnTargetType, id: string): SQL {
  switch (type) {
    case 'user':
      return sql`(SELECT ${users.name} || ' <' || ${users.email} || '>' FROM ${users} WHERE ${users.id} = ${id}::uuid)`;
    case 'organization':
      return sql`(SELECT ${organizations.name} FROM ${organizations} WHERE ${organizations.id} = ${id}::uuid)`;
    case 'api_key':
      return sql`(SELECT ${apiKeys.name} || ' (' || ${apiKeys.prefix} || ')' FROM ${apiKeys} WHERE ${apiKeys.id} = ${id}::uuid)`;
    case 'membership_invitation':
      return sql`(SELECT ${users.email} FROM ${membershipInvitations} JOIN ${users} ON ${users.id} = ${membershipInvitations.userId} WHERE ${membershipInvitations.id} = ${id}::uuid)`;
    default: {
      const unknownType: never = type;
      throw new Error(`No label query for ${String(unknownType)}`);
    }
  }
}
