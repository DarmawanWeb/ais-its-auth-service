import type { OrgRole } from '@darmawanweb/ais-its-contracts/auth';
import { type Database, InjectDb } from '@darmawanweb/ais-its-nest/db';
import { Injectable } from '@nestjs/common';
import { and, asc, count, eq, inArray } from 'drizzle-orm';

import type {
  Executor,
  MembershipRow,
  OrganizationRow,
  UserRow,
} from '../../db/database.js';
import * as schema from '../../db/schema.js';

const { memberships, organizations, users } = schema;

/** A membership with its organization (login response, `/me`). */
export interface MembershipWithOrganization {
  readonly membership: MembershipRow;
  readonly organization: OrganizationRow;
}

/** A member of an organization with the account (`GET /organizations/:id/members`). */
export interface MemberRecord {
  readonly membership: MembershipRow;
  readonly user: UserRow;
}

/** Drizzle access to `memberships`. */
@Injectable()
export class MembershipsRepository {
  constructor(@InjectDb() private readonly db: Database<typeof schema>) {}

  async find(
    userId: string,
    orgId: string,
    executor: Executor = this.db,
  ): Promise<MembershipRow | undefined> {
    const [row] = await executor
      .select()
      .from(memberships)
      .where(and(eq(memberships.userId, userId), eq(memberships.orgId, orgId)))
      .limit(1);
    return row;
  }

  /** The user's memberships with their organizations, oldest first. */
  async listOfUser(userId: string): Promise<MembershipWithOrganization[]> {
    return this.db
      .select({ membership: memberships, organization: organizations })
      .from(memberships)
      .innerJoin(organizations, eq(organizations.id, memberships.orgId))
      .where(eq(memberships.userId, userId))
      .orderBy(asc(memberships.createdAt), asc(memberships.orgId));
  }

  /** Memberships of several users (directory listing). */
  async listOfUsers(userIds: readonly string[]): Promise<MembershipRow[]> {
    if (userIds.length === 0) return [];
    return this.db
      .select()
      .from(memberships)
      .where(inArray(memberships.userId, [...userIds]))
      .orderBy(asc(memberships.createdAt));
  }

  /** One page of an organization's members (by e-mail) and the total. */
  async listMembers(
    orgId: string,
    page: { readonly offset: number; readonly limit: number },
  ): Promise<{ rows: MemberRecord[]; total: number }> {
    const where = eq(memberships.orgId, orgId);
    const [rows, totals] = await Promise.all([
      this.db
        .select({ membership: memberships, user: users })
        .from(memberships)
        .innerJoin(users, eq(users.id, memberships.userId))
        .where(where)
        .orderBy(asc(users.email))
        .limit(page.limit)
        .offset(page.offset),
      this.db.select({ total: count() }).from(memberships).where(where),
    ]);
    return { rows, total: totals[0]?.total ?? 0 };
  }

  async insert(
    membership: {
      readonly userId: string;
      readonly orgId: string;
      readonly role: OrgRole;
    },
    executor: Executor = this.db,
  ): Promise<MembershipRow> {
    const [row] = await executor
      .insert(memberships)
      .values(membership)
      .returning();
    if (row === undefined)
      throw new Error('INSERT … RETURNING returned no row');
    return row;
  }

  /**
   * Creates a membership unless one exists (invitation acceptance stays
   * idempotent); `undefined` when the user already was a member.
   */
  async insertIfAbsent(
    membership: {
      readonly userId: string;
      readonly orgId: string;
      readonly role: OrgRole;
    },
    tx: Executor,
  ): Promise<MembershipRow | undefined> {
    const [row] = await tx
      .insert(memberships)
      .values(membership)
      .onConflictDoNothing({
        target: [memberships.userId, memberships.orgId],
      })
      .returning();
    return row;
  }

  async updateRole(
    userId: string,
    orgId: string,
    role: OrgRole,
    executor: Executor,
  ): Promise<MembershipRow | undefined> {
    const [row] = await executor
      .update(memberships)
      .set({ role })
      .where(and(eq(memberships.userId, userId), eq(memberships.orgId, orgId)))
      .returning();
    return row;
  }

  async delete(
    userId: string,
    orgId: string,
    executor: Executor,
  ): Promise<boolean> {
    const rows = await executor
      .delete(memberships)
      .where(and(eq(memberships.userId, userId), eq(memberships.orgId, orgId)))
      .returning({ userId: memberships.userId });
    return rows.length > 0;
  }

  /** The distinct roles held by the members of an organization. */
  async rolesInUse(orgId: string, executor: Executor): Promise<OrgRole[]> {
    const rows = await executor
      .selectDistinct({ role: memberships.role })
      .from(memberships)
      .where(eq(memberships.orgId, orgId));
    return rows.map((row) => row.role);
  }

  /**
   * The `org_admin`s of an organization, locked (`FOR UPDATE`) until the end
   * of the transaction, so concurrent demotions cannot both pass the
   * last-admin check.
   */
  async lockAdmins(orgId: string, executor: Executor): Promise<string[]> {
    const rows = await executor
      .select({ userId: memberships.userId })
      .from(memberships)
      .where(
        and(eq(memberships.orgId, orgId), eq(memberships.role, 'org_admin')),
      )
      .for('update');
    return rows.map((row) => row.userId);
  }
}
