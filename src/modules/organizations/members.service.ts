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
import {
  type Database,
  InjectDb,
  isUniqueViolation,
} from '@darmawanweb/ais-its-nest/db';
import { ForbiddenError } from '@darmawanweb/ais-its-nest';
import { Injectable } from '@nestjs/common';

import { AuthErrors } from '../../common/errors.js';
import { requireUser } from '../../common/principals.js';
import type { Executor, OrganizationRow } from '../../db/database.js';
import type * as schema from '../../db/schema.js';
import {
  canManageMembers,
  isRoleGrantable,
  removesLastAdmin,
} from '../../domain/access-rules.js';
import { normalizeEmail } from '../../domain/identity.js';
import {
  type InvitationRecord,
  InvitationsRepository,
} from '../accounts/invitations.repository.js';
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
import { AuthThrottle } from '../throttling/auth-throttle.service.js';

/** `POST /organizations/:id/members`. */
export interface InviteMemberInput {
  readonly email: string;
  readonly name: string;
  readonly role: OrgRole;
  readonly locale?: Locale | undefined;
}

/** An invitation sent (or sent again). */
export interface SentInvitation {
  readonly record: InvitationRecord;
  /** The e-mail request was published (`false`: NATS failed; send it again). */
  readonly invitationSent: boolean;
}

/**
 * Members and invitations of organizations (spec §13.1, `user:manage`):
 * `org_admin`s manage their active organization, super admins every
 * organization. Rules (`domain/access-rules.ts`): roles must be grantable in
 * the organization's kind, the last `org_admin` can be neither demoted nor
 * removed (checked under row locks), and accounts join only by accepting an
 * invitation. Membership changes do not touch existing access tokens (short
 * TTL); a removed member's sessions in that organization are revoked.
 */
@Injectable()
export class MembersService {
  constructor(
    @InjectDb() private readonly db: Database<typeof schema>,
    private readonly organizations: OrganizationsRepository,
    private readonly memberships: MembershipsRepository,
    private readonly users: UsersRepository,
    private readonly sessions: SessionsRepository,
    private readonly invitationRows: InvitationsRepository,
    private readonly invitations: InvitationService,
    private readonly audit: AuditService,
    private readonly throttle: AuthThrottle,
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
   * Invites an address to the organization. Nobody is attached without
   * consent: the membership is written when the invitee accepts the
   * e-mailed link. Unknown addresses get an `invited` account (spec
   * §13.1); existing accounts — of any tenant — only receive the e-mail.
   * The answer, the invitation list and the audit record are the same in
   * both cases and show only what the admin typed, so an admin learns
   * nothing about accounts outside the organization. Inviting a pending
   * address again renews the link (the way to resend an invitation).
   *
   * @throws {ConflictError} `409 MEMBER_ALREADY_EXISTS` for a member of the organization.
   * @throws {DomainError} `422 ROLE_NOT_GRANTABLE` for roles the organization's kind cannot grant.
   */
  async invite(
    orgId: string,
    input: InviteMemberInput,
    principal: Principal,
    request: AuditRequest,
  ): Promise<SentInvitation> {
    const { actor, organization } = await this.manageable(orgId, principal);
    const email = normalizeEmail(input.email);
    const token = this.invitations.newToken();
    const { invitation, user } = await this.conflictsAsProblems(orgId, () =>
      this.db.transaction(async (tx) => {
        await this.assertGrantableLocked(orgId, input.role, tx);
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
        // A member that never activated the account may be invited again.
        if (existing !== undefined && user.status !== 'invited')
          throw AuthErrors.memberExists(orgId);
        const invitation = await this.invitationRows.upsert(
          {
            id: newId(),
            orgId,
            userId: user.id,
            role: input.role,
            name: input.name,
            invitedBy: actor.id,
            tokenHash: token.tokenHash,
            expiresAt: token.expiresAt,
          },
          tx,
        );
        return { invitation, user };
      }),
    );
    const invitationSent = await this.invitations.send({
      to: user.email,
      recipientName: user.name,
      organization,
      role: invitation.role,
      invitedBy: actor.name,
      token,
      locale: input.locale,
    });
    // The invitation, not the account, is the target: the organization's
    // audit log must not reveal the id of an account outside it.
    await this.audit.record(
      {
        action: 'membership.invite',
        targetType: 'membership_invitation',
        targetId: invitation.id,
        orgId,
        meta: { role: invitation.role, invitationSent },
      },
      actor,
      request,
    );
    return {
      record: { invitation, email: user.email, invitedByName: actor.name },
      invitationSent,
    };
  }

  /**
   * Sends a pending (or expired) invitation again: a new link valid
   * `INVITE_TTL_HOURS` replaces the previous one, which stops working; role
   * and name stay, the sender becomes the inviter. The role is checked
   * again against the organization's kind (under its share lock, then the
   * invitation's row lock: the lock order of every organization change).
   * At most 3 resends per invitation and hour.
   *
   * @throws {NotFoundError} `404 INVITATION_NOT_FOUND` (also once accepted or withdrawn).
   * @throws {DomainError} `422 ROLE_NOT_GRANTABLE` when the kind changed since.
   * @throws {RateLimitedError} `429 RATE_LIMITED` beyond the resend limit.
   */
  async resendInvitation(
    orgId: string,
    invitationId: string,
    locale: Locale | undefined,
    principal: Principal,
    request: AuditRequest,
  ): Promise<SentInvitation> {
    const { actor } = await this.manageable(orgId, principal);
    await this.throttle.consumeInvitationResend(invitationId);
    const token = this.invitations.newToken();
    const { invitation, user, organization } = await this.db.transaction(
      async (tx) => {
        const organization = await this.organizations.lockForShare(orgId, tx);
        if (organization === undefined)
          throw AuthErrors.organizationNotFound(orgId);
        const pending = await this.invitationRows.lockInOrg(
          invitationId,
          orgId,
          tx,
        );
        if (pending === undefined)
          throw AuthErrors.invitationNotFound(orgId, invitationId);
        if (!isRoleGrantable(organization.kind, pending.role))
          throw AuthErrors.roleNotGrantable(pending.role, organization.kind);
        const user = await this.users.findById(pending.userId, tx);
        if (user === undefined)
          throw AuthErrors.invitationNotFound(orgId, invitationId);
        const invitation = await this.invitationRows.renew(
          invitationId,
          {
            tokenHash: token.tokenHash,
            expiresAt: token.expiresAt,
            invitedBy: actor.id,
          },
          tx,
        );
        return { invitation, user, organization };
      },
    );
    const invitationSent = await this.invitations.send({
      to: user.email,
      recipientName: user.name,
      organization,
      role: invitation.role,
      invitedBy: actor.name,
      token,
      locale,
    });
    await this.audit.record(
      {
        action: 'membership.invite.resend',
        targetType: 'membership_invitation',
        targetId: invitation.id,
        orgId,
        meta: { role: invitation.role, invitationSent },
      },
      actor,
      request,
    );
    return {
      record: { invitation, email: user.email, invitedByName: actor.name },
      invitationSent,
    };
  }

  /** One page of the organization's pending (and expired) invitations. */
  async listInvitations(
    orgId: string,
    page: PageQuery,
    principal: Principal,
  ): Promise<Paginated<InvitationRecord>> {
    await this.manageable(orgId, principal);
    const { rows, total } = await this.invitationRows.listOfOrg(orgId, {
      offset: pageOffset(page),
      limit: page.pageSize,
    });
    return toPaginated(rows, page, total);
  }

  /** Withdraws an invitation: its link stops working. */
  async cancelInvitation(
    orgId: string,
    invitationId: string,
    principal: Principal,
    request: AuditRequest,
  ): Promise<void> {
    const { actor } = await this.manageable(orgId, principal);
    const deleted = await this.invitationRows.deleteInOrg(invitationId, orgId);
    if (deleted === undefined)
      throw AuthErrors.invitationNotFound(orgId, invitationId);
    await this.audit.record(
      {
        action: 'membership.invite.cancel',
        targetType: 'membership_invitation',
        targetId: invitationId,
        orgId,
        meta: { role: deleted.role },
      },
      actor,
      request,
    );
  }

  /** Changes a member's role (never demoting the last `org_admin`). */
  async changeRole(
    orgId: string,
    userId: string,
    role: OrgRole,
    principal: Principal,
    request: AuditRequest,
  ): Promise<MemberRecord> {
    const { actor } = await this.manageable(orgId, principal);
    const change = await this.db.transaction(async (tx) => {
      await this.assertGrantableLocked(orgId, role, tx);
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

  /**
   * Refuses roles the organization's kind cannot grant (`authority` outside
   * authority organizations), reading the kind under a share lock so a
   * concurrent kind change cannot slip in before the write commits.
   */
  private async assertGrantableLocked(
    orgId: string,
    role: OrgRole,
    tx: Executor,
  ): Promise<void> {
    const organization = await this.organizations.lockForShare(orgId, tx);
    if (organization === undefined)
      throw AuthErrors.organizationNotFound(orgId);
    if (!isRoleGrantable(organization.kind, role))
      throw AuthErrors.roleNotGrantable(role, organization.kind);
  }

  /**
   * Two concurrent invitations of the same new address both try to create
   * its account; the loser answers `409 INVITATION_CONFLICT` (repeating the
   * request renews the invitation) — never a hint that the address exists.
   */
  private async conflictsAsProblems<T>(
    orgId: string,
    write: () => Promise<T>,
  ): Promise<T> {
    try {
      return await write();
    } catch (error) {
      if (isUniqueViolation(error, USER_EMAIL_CONSTRAINT))
        throw AuthErrors.invitationConflict(orgId);
      throw error;
    }
  }
}
