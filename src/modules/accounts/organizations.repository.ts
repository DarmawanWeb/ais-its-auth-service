import { type Database, InjectDb } from '@darmawanweb/ais-its-nest/db';
import { Injectable } from '@nestjs/common';
import { and, count, desc, eq, ilike, or, type SQL, sql } from 'drizzle-orm';

import {
  escapeLikePattern,
  type Executor,
  type OrganizationRow,
} from '../../db/database.js';
import * as schema from '../../db/schema.js';
import type { OrganizationKind } from '../../domain/access-rules.js';

const { apiKeys, memberships, organizations } = schema;

/** A row of `GET /organizations` with its counts. */
export interface OrganizationListRow {
  readonly organization: OrganizationRow;
  /** Members (memberships) of the organization. */
  readonly memberCount: number;
  /** API keys that pass introspection now (neither revoked nor expired). */
  readonly apiKeyCount: number;
}

/** Organizations per kind (`GET /organizations/stats`). */
export type OrganizationKindCounts = Record<OrganizationKind, number>;

/** An organization to insert. */
export interface NewOrganization {
  readonly id: string;
  readonly name: string;
  readonly slug: string;
  readonly kind: OrganizationKind;
}

/** Fields an update may change. */
export interface OrganizationChanges {
  readonly name?: string | undefined;
  readonly slug?: string | undefined;
  readonly kind?: OrganizationKind | undefined;
}

/** Filters of `GET /organizations`. */
export interface OrganizationFilter {
  readonly search?: string | undefined;
  readonly kind?: OrganizationKind | undefined;
}

/** Name of the unique constraint on `slug` (`0001_init.sql`). */
export const ORGANIZATION_SLUG_CONSTRAINT = 'organizations_slug_key';

/** Drizzle access to `organizations`. */
@Injectable()
export class OrganizationsRepository {
  constructor(@InjectDb() private readonly db: Database<typeof schema>) {}

  async findById(
    id: string,
    executor: Executor = this.db,
  ): Promise<OrganizationRow | undefined> {
    const [row] = await executor
      .select()
      .from(organizations)
      .where(eq(organizations.id, id))
      .limit(1);
    return row;
  }

  /** Locks the row for the rest of the transaction (`FOR UPDATE`). */
  async lockById(
    id: string,
    executor: Executor,
  ): Promise<OrganizationRow | undefined> {
    const [row] = await executor
      .select()
      .from(organizations)
      .where(eq(organizations.id, id))
      .for('update')
      .limit(1);
    return row;
  }

  /**
   * Reads the row with a share lock (`FOR SHARE`): membership writes that
   * depend on the organization's kind hold it, so a concurrent kind change
   * (`FOR UPDATE`) waits for them and sees their result.
   */
  async lockForShare(
    id: string,
    executor: Executor,
  ): Promise<OrganizationRow | undefined> {
    const [row] = await executor
      .select()
      .from(organizations)
      .where(eq(organizations.id, id))
      .for('share')
      .limit(1);
    return row;
  }

  async findBySlug(
    slug: string,
    executor: Executor = this.db,
  ): Promise<OrganizationRow | undefined> {
    const [row] = await executor
      .select()
      .from(organizations)
      .where(eq(organizations.slug, slug))
      .limit(1);
    return row;
  }

  /** Inserts an organization; a taken slug violates {@link ORGANIZATION_SLUG_CONSTRAINT}. */
  async insert(
    organization: NewOrganization,
    executor: Executor = this.db,
  ): Promise<OrganizationRow> {
    const [row] = await executor
      .insert(organizations)
      .values(organization)
      .returning();
    if (row === undefined)
      throw new Error('INSERT … RETURNING returned no row');
    return row;
  }

  /** Applies `changes`; `undefined` when no organization matched. */
  async update(
    id: string,
    changes: OrganizationChanges,
    executor: Executor = this.db,
  ): Promise<OrganizationRow | undefined> {
    const [row] = await executor
      .update(organizations)
      .set({
        ...(changes.name === undefined ? {} : { name: changes.name }),
        ...(changes.slug === undefined ? {} : { slug: changes.slug }),
        ...(changes.kind === undefined ? {} : { kind: changes.kind }),
        updatedAt: sql`now()`,
      })
      .where(eq(organizations.id, id))
      .returning();
    return row;
  }

  /** Deletes an organization (memberships and API keys cascade). */
  async delete(id: string, executor: Executor): Promise<boolean> {
    const rows = await executor
      .delete(organizations)
      .where(eq(organizations.id, id))
      .returning({ id: organizations.id });
    return rows.length > 0;
  }

  /** One page, by name, with the counts of each row, and the total. */
  async list(
    filter: OrganizationFilter,
    page: { readonly offset: number; readonly limit: number },
  ): Promise<{ rows: OrganizationListRow[]; total: number }> {
    const where = and(...filterConditions(filter));
    const [rows, totals] = await Promise.all([
      this.db
        .select({
          organization: organizations,
          // Explicit references: drizzle renders the columns of a one-table
          // select unqualified, and an unqualified "id" inside the subquery
          // would be the subquery's own column.
          memberCount: sql<number>`(SELECT count(*)::int FROM ${memberships} m WHERE m.org_id = ${organizations}.id)`,
          apiKeyCount: sql<number>`(SELECT count(*)::int FROM ${apiKeys} k WHERE k.org_id = ${organizations}.id AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > now()))`,
        })
        .from(organizations)
        .where(where)
        .orderBy(organizations.name, desc(organizations.id))
        .limit(page.limit)
        .offset(page.offset),
      this.db.select({ total: count() }).from(organizations).where(where),
    ]);
    return { rows, total: totals[0]?.total ?? 0 };
  }

  /** Organizations matching `filter.search`, per kind (every kind present, 0 included). */
  async countByKind(
    filter: Pick<OrganizationFilter, 'search'>,
  ): Promise<OrganizationKindCounts> {
    const rows = await this.db
      .select({ kind: organizations.kind, count: count() })
      .from(organizations)
      .where(and(...filterConditions({ search: filter.search })))
      .groupBy(organizations.kind);
    const counts: OrganizationKindCounts = {
      shipping_company: 0,
      authority: 0,
      platform: 0,
      research: 0,
    };
    for (const row of rows) counts[row.kind] = row.count;
    return counts;
  }
}

function filterConditions(filter: OrganizationFilter): (SQL | undefined)[] {
  const pattern =
    filter.search === undefined
      ? undefined
      : `%${escapeLikePattern(filter.search)}%`;
  return [
    pattern === undefined
      ? undefined
      : or(
          ilike(organizations.name, pattern),
          ilike(organizations.slug, pattern),
        ),
    filter.kind === undefined ? undefined : eq(organizations.kind, filter.kind),
  ];
}
