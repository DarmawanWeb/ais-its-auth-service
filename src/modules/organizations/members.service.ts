import {
  type PageQuery,
  type Paginated,
  pageOffset,
  toPaginated,
} from '@darmawanweb/ais-its-contracts/api';
import type { OrgRole } from '@darmawanweb/ais-its-contracts/auth';
import { type Locale, newId } from '@darmawanweb/ais-its-contracts/domain';
import {
  type AuditRequest,
  AuditService,
} from '@darmawanweb/ais-its-nest/audit';
import type { Principal, UserPrincipal } from '@darmawanweb/ais-its-nest/auth';
import { type Database, InjectDb } from '@darmawanweb/ais-its-nest/db';
import { ForbiddenError } from '@darmawanweb/ais-its-nest';
import { Injectable } from '@nestjs/common';

import { AuthErrors } from '../../common/errors.js';
import { requireUser } from '../../common/principals.js';
import type { Executor, OrganizationRow } from '../../db/database.js';
import { isUniqueViolation } from '../../db/errors.js';
import type * as schema from '../../db/schema.js';
import {
  canManageMembers,
  isRoleGrantable,
  removesLastAdmin,
} from '../../domain/access-rules.js';
import { normalizeEmail } from '../../domain/identity.js';
import {
  type MemberRecord,
  MembershipsRepository,
} from '../accounts/memberships.repository.js';
import { OrganizationsRepository } from '../accounts/organizations.repository.js';
import { SessionsRepository } from '../accounts/sessions.repository.js';
import {
  USER_EMAIL_CONSTRAINT,
  UsersRepository,
} from '../accounts/users.repository.js';
import { InvitationService } from '../passwords/invitation.service.js';

/** `POST /organizations/:id/members`. */
export interface AddMemberInput {
  readonly email: string;
  readonly name: string;
  readonly role: OrgRole;
  readonly locale?: Locale | undefined;
}

/** A member added (or re-invited). */
export interface AddedMember {
  readonly record: MemberRecord;
  readonly invitationSent: boolean;
}

/** Name of the primary key of `memberships`. */
const MEMBERSHIP_PRIMARY_KEY = 'memberships_pkey';

/**
 * Members of organizations (spec §13.1, `user:manage`): `org_admin`s manage
 * their active organization, super admins every organization. Rules
 * (`domain/access-rules.ts`): roles must be grantable in the organization's
 * kind, the last `org_admin` can be neither demoted nor removed (checked
 * under row locks). Membership changes do not touch existing access tokens
 * (short TTL); a removed member's sessions in that organization are revoked.
 */
@Injectable()
export class MembersService {
  constructor(
    @InjectDb() private readonly db: Database<typeof schema>,
    private readonly organizations: OrganizationsRepository,
    private readonly memberships: MembershipsRepository,
    private readonly users: UsersRepository,
    private readonly sessions: SessionsRepository,
    private readonly invitations: InvitationService,
    private readonly audit: AuditService,
  ) {}

  /** One page of the organization's members. */
  async list(
    orgId: string,
    page: PageQuery,
    principal: Principal,
  ): Promise<Paginated<MemberRecord>> {
    await this.manageable(orgId, principal);
    const { rows, total } = await this.memberships.listMembers(orgId, {
      offset: pageOffset(page),
      limit: page.pageSize,
    });
    return toPaginated(rows, page, total);
  }

  /**
   * Adds a member. Unknown e-mails get an `invited` account; accounts that
   * have not accepted an invitation yet receive one (again, also when they
   * are already members: the way to resend an invitation).
   */
  async add(
    orgId: string,
    input: AddMemberInput,
    principal: Principal,
    request: AuditRequest,
  ): Promise<AddedMember> {
    const { actor, organization } = await this.manageable(orgId, principal);
    assertGrantable(organization, input.role);
    const email = normalizeEmail(input.email);
    const { record, created } = await this.conflictsAsProblems(orgId, () =>
      this.db.transaction(async (tx) => {
        const user =
          (await this.users.findByEmail(email, tx)) ??
          (await this.users.insert(
            {
              id: newId(),
              email,
              name: input.name,
              passwordHash: null,
              status: 'invited',
              isPlatformAdmin: false,
            },
            tx,
          ));
        const existing = await this.memberships.find(user.id, orgId, tx);
        if (existing !== undefined) {
          if (user.status !== 'invited')
            throw AuthErrors.memberExists(orgId, user.id);
          return { record: { membership: existing, user }, created: false };
        }
        const membership = await this.memberships.insert(
          { userId: user.id, orgId, role: input.role },
          tx,
        );
        return { record: { membership, user }, created: true };
      }),
    );
    const invitationSent =
      record.user.status === 'invited' &&
      (await this.invitations.send({
        user: record.user,
        organization,
        role: record.membership.role,
        invitedBy: actor.name,
        locale: input.locale,
      }));
    await this.audit.record(
      {
        action: created ? 'membership.create' : 'membership.invite',
        targetType: 'user',
        targetId: record.user.id,
        orgId,
        meta: {
          role: record.membership.role,
          invited: record.user.status === 'invited',
          invitationSent,
        },
      },
      actor,
      request,
    );
    return { record, invitationSent };
  }

  /** Changes a member's role (never demoting the last `org_admin`). */
  async changeRole(
    orgId: string,
    userId: string,
    role: OrgRole,
    principal: Principal,
    request: AuditRequest,
  ): Promise<MemberRecord> {
    const { actor, organization } = await this.manageable(orgId, principal);
    assertGrantable(organization, role);
    const change = await this.db.transaction(async (tx) => {
      const { membership, user } = await this.lockedMember(
        orgId,
        userId,
        role,
        tx,
      );
      if (membership.role === role)
        return { record: { membership, user }, from: role };
      const updated = await this.memberships.updateRole(
        userId,
        orgId,
        role,
        tx,
      );
      if (updated === undefined) throw AuthErrors.memberNotFound(orgId, userId);
      return { record: { membership: updated, user }, from: membership.role };
    });
    if (change.from !== role) {
      await this.audit.record(
        {
          action: 'membership.update',
          targetType: 'user',
          targetId: userId,
          orgId,
          meta: { from: change.from, to: role },
        },
        actor,
        request,
      );
    }
    return change.record;
  }

  /** Removes a member (never the last `org_admin`) and revokes their sessions in the organization. */
  async remove(
    orgId: string,
    userId: string,
    principal: Principal,
    request: AuditRequest,
  ): Promise<void> {
    const { actor } = await this.manageable(orgId, principal);
    const removed = await this.db.transaction(async (tx) => {
      const { membership } = await this.lockedMember(orgId, userId, null, tx);
      await this.memberships.delete(userId, orgId, tx);
      const revokedSessions = await this.sessions.revokeOfUser(
        userId,
        { orgId },
        tx,
      );
      return { role: membership.role, revokedSessions };
    });
    await this.audit.record(
      {
        action: 'membership.delete',
        targetType: 'user',
        targetId: userId,
        orgId,
        meta: removed,
      },
      actor,
      request,
    );
  }

  /** The organization when the principal may manage its members. */
  private async manageable(
    orgId: string,
    principal: Principal,
  ): Promise<{ actor: UserPrincipal; organization: OrganizationRow }> {
    const actor = requireUser(principal);
    if (!canManageMembers(actor, orgId)) {
      throw new ForbiddenError(
        'You can only manage the members of your active organization',
        {
          extra: { orgId },
        },
      );
    }
    const organization = await this.organizations.findById(orgId);
    if (organization === undefined)
      throw AuthErrors.organizationNotFound(orgId);
    return { actor, organization };
  }

  /**
   * Loads a membership after locking the organization's admins, and refuses
   * a change to `nextRole` (`null` = removal) that would leave no admin.
   */
  private async lockedMember(
    orgId: string,
    userId: string,
    nextRole: OrgRole | null,
    tx: Executor,
  ): Promise<MemberRecord> {
    const admins = await this.memberships.lockAdmins(orgId, tx);
    const membership = await this.memberships.find(userId, orgId, tx);
    const user =
      membership === undefined
        ? undefined
        : await this.users.findById(userId, tx);
    if (membership === undefined || user === undefined)
      throw AuthErrors.memberNotFound(orgId, userId);
    if (removesLastAdmin(admins, userId, nextRole))
      throw AuthErrors.lastOrgAdmin(orgId);
    return { membership, user };
  }

  /** Maps concurrent duplicate inserts (same e-mail, same membership) to `409`. */
  private async conflictsAsProblems<T>(
    orgId: string,
    write: () => Promise<T>,
  ): Promise<T> {
    try {
      return await write();
    } catch (error) {
      if (isUniqueViolation(error, USER_EMAIL_CONSTRAINT))
        throw AuthErrors.emailTaken();
      if (isUniqueViolation(error, MEMBERSHIP_PRIMARY_KEY))
        throw AuthErrors.memberExists(orgId);
      throw error;
    }
  }
}

/** Refuses roles the organization's kind cannot grant (`authority` outside authority organizations). */
function assertGrantable(organization: OrganizationRow, role: OrgRole): void {
  if (!isRoleGrantable(organization.kind, role))
    throw AuthErrors.roleNotGrantable(role, organization.kind);
}
