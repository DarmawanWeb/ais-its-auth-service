import type { AuditActorType } from '@darmawanweb/ais-its-contracts/domain';
import { Injectable } from '@nestjs/common';
import { type SQL, sql } from 'drizzle-orm';

import {
  type AuditLabels,
  metaTargetLabel,
  type OwnTargetType,
  ownTarget,
} from '../domain/audit-labels.js';
import type { Executor } from './database.js';
import * as schema from './schema.js';

const { apiKeys, membershipInvitations, organizations, users } = schema;

/** What {@link readAuditLabels} names: the record's actor, organization and target. */
export interface AuditLabelInput {
  readonly actorType: AuditActorType;
  readonly actorId: string | null;
  readonly orgId: string | null;
  readonly targetType: string | null;
  readonly targetId: string | null;
  readonly meta: Readonly<Record<string, unknown>>;
}

/**
 * The names of a record as `executor` sees them now, in one statement: the
 * actor's name and e-mail (users) or the API key's name, the organization's
 * name, and the target's label — from this service's tables for its own
 * target types (`ownTarget`), otherwise (or when the row is gone) the
 * producer's `meta.targetLabel` / `meta.name`. Ids are bound as parameters
 * and only UUIDs are looked up, so the statement cannot fail on the
 * record's values. On a transaction's executor it sees that transaction's
 * own changes (a row created or renamed in it; not one deleted before).
 */
export async function readAuditLabels(
  executor: Executor,
  entry: AuditLabelInput,
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

/**
 * {@link readAuditLabels} as a provider, for `Transactions`: this service
 * reads the labels of its own records when it writes them.
 */
@Injectable()
export class AuditLabelReader {
  read(executor: Executor, entry: AuditLabelInput): Promise<AuditLabels> {
    return readAuditLabels(executor, entry);
  }
}

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
