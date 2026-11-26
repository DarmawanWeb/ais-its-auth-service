import type { OrgRole } from '@darmawanweb/ais-its-contracts/auth';
import { type Database, InjectDb } from '@darmawanweb/ais-its-nest/db';
import { Injectable } from '@nestjs/common';
import { and, count, desc, eq, gt, lt, sql } from 'drizzle-orm';
import { alias } from 'drizzle-orm/pg-core';

import type { Executor, MembershipInvitationRow } from '../../db/database.js';
import * as schema from '../../db/schema.js';

const { membershipInvitations, users } = schema;

/** The inviting admin (`invited_by`), for the name shown with an invitation. */
const inviters = alias(users, 'inviter');

/** An invitation as the organization sees it: what its admin typed, and the address. */
export interface InvitationRecord {
  readonly invitation: MembershipInvitationRow;
  /** The invited address (normalized, as the admin typed it). */
  readonly email: string;
  /** Current display name of the inviting admin (`null` once that account is deleted). */
  readonly invitedByName: string | null;
}

/** A renewed link of an invitation (`POST …/invitations/:invitationId/resend`). */
export interface InvitationRenewal {
  readonly tokenHash: string;
  readonly expiresAt: Date;
  readonly invitedBy: string;
}

/** A new or renewed invitation. */
export interface InvitationWrite {
  readonly id: string;
  readonly orgId: string;
  readonly userId: string;
  readonly role: OrgRole;
  readonly name: string;
  readonly invitedBy: string;
  readonly tokenHash: string;
  readonly expiresAt: Date;
}

/** Drizzle access to `membership_invitations` (token hashes only). */
@Injectable()
export class InvitationsRepository {
  constructor(@InjectDb() private readonly db: Database<typeof schema>) {}

  /**
   * Records the invitation of `userId` to `orgId`, or renews the pending
   * one (new token, role, name, inviter and expiry; `id` and `created_at`
   * stay), so sending an invitation again invalidates the previous link.
   */
  async upsert(
    invitation: InvitationWrite,
    tx: Executor,
  ): Promise<MembershipInvitationRow> {
    const [row] = await tx
      .insert(membershipInvitations)
      .values(invitation)
      .onConflictDoUpdate({
        target: [membershipInvitations.orgId, membershipInvitations.userId],
        set: {
          role: invitation.role,
          name: invitation.name,
          invitedBy: invitation.invitedBy,
          tokenHash: invitation.tokenHash,
          expiresAt: invitation.expiresAt,
          updatedAt: sql`now()`,
        },
      })
      .returning();
    if (row === undefined)
      throw new Error('INSERT … ON CONFLICT … RETURNING returned no row');
    return row;
  }

  /** An invitation of `orgId`, locked until the end of the transaction. */
  async lockInOrg(
    id: string,
    orgId: string,
    tx: Executor,
  ): Promise<MembershipInvitationRow | undefined> {
    const [row] = await tx
      .select()
      .from(membershipInvitations)
      .where(
        and(
          eq(membershipInvitations.id, id),
          eq(membershipInvitations.orgId, orgId),
        ),
      )
      .for('update')
      .limit(1);
    return row;
  }

  /**
   * Replaces the link of an invitation (new token and expiry; the previous
   * link stops working) and records who sent it; role, name and
   * `created_at` stay.
   */
  async renew(
    id: string,
    renewal: InvitationRenewal,
    tx: Executor,
  ): Promise<MembershipInvitationRow> {
    const [row] = await tx
      .update(membershipInvitations)
      .set({
        tokenHash: renewal.tokenHash,
        expiresAt: renewal.expiresAt,
        invitedBy: renewal.invitedBy,
        updatedAt: sql`now()`,
      })
      .where(eq(membershipInvitations.id, id))
      .returning();
    if (row === undefined)
      throw new Error('UPDATE … RETURNING returned no row');
    return row;
  }

  /** The unexpired invitation of a token hash (no lock: a cheap pre-check). */
  async findRedeemable(
    tokenHash: string,
    now: Date,
    executor: Executor = this.db,
  ): Promise<MembershipInvitationRow | undefined> {
    const [row] = await executor
      .select()
      .from(membershipInvitations)
      .where(
        and(
          eq(membershipInvitations.tokenHash, tokenHash),
          gt(membershipInvitations.expiresAt, now),
        ),
      )
      .limit(1);
    return row;
  }

  /** The invitation of a token hash, locked until the end of the transaction. */
  async lockByHash(
    tokenHash: string,
    tx: Executor,
  ): Promise<MembershipInvitationRow | undefined> {
    const [row] = await tx
      .select()
      .from(membershipInvitations)
      .where(eq(membershipInvitations.tokenHash, tokenHash))
      .for('update')
      .limit(1);
    return row;
  }

  /** One page of an organization's invitations, newest first, and the total. */
  async listOfOrg(
    orgId: string,
    page: { readonly offset: number; readonly limit: number },
  ): Promise<{ rows: InvitationRecord[]; total: number }> {
    const where = eq(membershipInvitations.orgId, orgId);
    const [rows, totals] = await Promise.all([
      this.db
        .select({
          invitation: membershipInvitations,
          email: users.email,
          invitedByName: inviters.name,
        })
        .from(membershipInvitations)
        .innerJoin(users, eq(users.id, membershipInvitations.userId))
        .leftJoin(inviters, eq(inviters.id, membershipInvitations.invitedBy))
        .where(where)
        .orderBy(
          desc(membershipInvitations.createdAt),
          desc(membershipInvitations.id),
        )
        .limit(page.limit)
        .offset(page.offset),
      this.db
        .select({ total: count() })
        .from(membershipInvitations)
        .where(where),
    ]);
    return { rows, total: totals[0]?.total ?? 0 };
  }

  /** The distinct roles of an organization's invitations (kind changes must not strand them). */
  async rolesInUse(orgId: string, tx: Executor): Promise<OrgRole[]> {
    const rows = await tx
      .selectDistinct({ role: membershipInvitations.role })
      .from(membershipInvitations)
      .where(eq(membershipInvitations.orgId, orgId));
    return rows.map((row) => row.role);
  }

  /** Deletes an invitation of `orgId`; `undefined` when there is none. */
  async deleteInOrg(
    id: string,
    orgId: string,
  ): Promise<MembershipInvitationRow | undefined> {
    const [row] = await this.db
      .delete(membershipInvitations)
      .where(
        and(
          eq(membershipInvitations.id, id),
          eq(membershipInvitations.orgId, orgId),
        ),
      )
      .returning();
    return row;
  }

  /** Deletes an accepted invitation inside the acceptance transaction. */
  async delete(id: string, tx: Executor): Promise<void> {
    await tx
      .delete(membershipInvitations)
      .where(eq(membershipInvitations.id, id));
  }

  /** Housekeeping: deletes invitations that expired before `before`. */
  async prune(before: Date): Promise<number> {
    const rows = await this.db
      .delete(membershipInvitations)
      .where(lt(membershipInvitations.expiresAt, before))
      .returning({ id: membershipInvitations.id });
    return rows.length;
  }
}
