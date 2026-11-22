import type { OrgRole } from '@darmawanweb/ais-its-contracts/auth';
import type { Locale } from '@darmawanweb/ais-its-contracts/domain';
import { InjectConfig } from '@darmawanweb/ais-its-nest';
import { Injectable } from '@nestjs/common';

import { AuthErrors } from '../../common/errors.js';
import type { Config } from '../../config.js';
import type {
  Executor,
  MembershipInvitationRow,
  OrganizationRow,
} from '../../db/database.js';
import { isRoleGrantable } from '../../domain/access-rules.js';
import { tokenLink } from '../../domain/identity.js';
import {
  generateOpaqueToken,
  isOpaqueToken,
  sha256Hex,
} from '../../domain/opaque-token.js';
import { InvitationsRepository } from '../accounts/invitations.repository.js';
import { MembershipsRepository } from '../accounts/memberships.repository.js';
import { OrganizationsRepository } from '../accounts/organizations.repository.js';
import { EmailRequester } from '../notifications/email-requester.service.js';

/** Route of the web app that accepts invitations (`#token=…`). */
export const ACCEPT_INVITE_PATH = '/accept-invite';

/** The link token of an invitation: the secret for the e-mail, its hash for the database. */
export interface InvitationToken {
  readonly token: string;
  readonly tokenHash: string;
  readonly expiresAt: Date;
}

/** The invitation e-mail. */
export interface InvitationMail {
  readonly to: string;
  /** Name of the account owner (the e-mail goes to them, never to the inviter). */
  readonly recipientName: string;
  readonly organization: OrganizationRow;
  readonly role: OrgRole;
  /** Display name of the inviting admin. */
  readonly invitedBy: string;
  readonly token: InvitationToken;
  readonly locale?: Locale | undefined;
}

/** An invitation being accepted, with its organization (both locked). */
export interface LockedInvitation {
  readonly invitation: MembershipInvitationRow;
  readonly organization: OrganizationRow;
}

/**
 * Invitations to join an organization (spec §13.1): a one-time link token
 * valid `INVITE_TTL_HOURS`, stored as SHA-256 in `membership_invitations`
 * and e-mailed with the `account_invite` template. The invitee accepts with
 * `POST /auth/password/reset` (choosing a password, which also activates a
 * new account); only then is the membership written — nobody is added to
 * an organization without consent.
 */
@Injectable()
export class InvitationService {
  constructor(
    @InjectConfig() private readonly config: Config,
    private readonly invitations: InvitationsRepository,
    private readonly organizations: OrganizationsRepository,
    private readonly memberships: MembershipsRepository,
    private readonly emails: EmailRequester,
  ) {}

  /** A fresh link token expiring after `INVITE_TTL_HOURS`. */
  newToken(now: Date = new Date()): InvitationToken {
    const token = generateOpaqueToken();
    return {
      token,
      tokenHash: sha256Hex(token),
      expiresAt: new Date(
        now.getTime() + this.config.INVITE_TTL_HOURS * 3_600_000,
      ),
    };
  }

  /** Requests the e-mail; `false` when it could not be requested. */
  async send(mail: InvitationMail): Promise<boolean> {
    return this.emails.request({
      to: mail.to,
      template: 'account_invite',
      locale: mail.locale ?? this.config.EMAIL_DEFAULT_LOCALE,
      data: {
        name: mail.recipientName,
        link: tokenLink(
          this.config.PUBLIC_BASE_URL,
          ACCEPT_INVITE_PATH,
          mail.token.token,
        ),
        organizationName: mail.organization.name,
        role: mail.role,
        invitedBy: mail.invitedBy,
        expiresInHours: this.config.INVITE_TTL_HOURS,
      },
    });
  }

  /** `true` when `presented` is the token of an unexpired invitation (no lock, no write). */
  async isRedeemable(
    presented: string,
    now: Date = new Date(),
  ): Promise<boolean> {
    if (!isOpaqueToken(presented)) return false;
    return (
      (await this.invitations.findRedeemable(sha256Hex(presented), now)) !==
      undefined
    );
  }

  /**
   * The unexpired invitation of `presented` and its organization, locked
   * until the end of the caller's transaction; `undefined` when there is
   * none. Lock order of every organization change — the organization first
   * (`FOR SHARE`), then its rows — so an acceptance never deadlocks with an
   * organization deletion or a kind change.
   */
  async lock(
    presented: string,
    tx: Executor,
    now: Date = new Date(),
  ): Promise<LockedInvitation | undefined> {
    if (!isOpaqueToken(presented)) return undefined;
    const tokenHash = sha256Hex(presented);
    const pending = await this.invitations.findRedeemable(tokenHash, now, tx);
    if (pending === undefined) return undefined;
    const organization = await this.organizations.lockForShare(
      pending.orgId,
      tx,
    );
    if (organization === undefined) return undefined;
    const invitation = await this.invitations.lockByHash(tokenHash, tx);
    if (
      invitation?.orgId !== organization.id ||
      invitation.expiresAt.getTime() <= now.getTime()
    )
      return undefined;
    return { invitation, organization };
  }

  /**
   * Writes the membership of an accepted invitation and deletes the
   * invitation, inside the acceptance transaction. The role is checked
   * again against the organization's kind (read under the share lock of
   * {@link lock}), which may have changed since the invitation was sent.
   *
   * @returns `false` when the invitee already was a member (acceptance is idempotent).
   * @throws {DomainError} `422 ROLE_NOT_GRANTABLE` (the transaction rolls back; the invitation stays).
   */
  async grant(
    { invitation, organization }: LockedInvitation,
    tx: Executor,
  ): Promise<boolean> {
    if (!isRoleGrantable(organization.kind, invitation.role))
      throw AuthErrors.roleNotGrantable(invitation.role, organization.kind);
    const membership = await this.memberships.insertIfAbsent(
      {
        userId: invitation.userId,
        orgId: invitation.orgId,
        role: invitation.role,
      },
      tx,
    );
    await this.invitations.delete(invitation.id, tx);
    return membership !== undefined;
  }
}
