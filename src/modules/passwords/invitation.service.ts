import type { OrgRole } from '@darmawanweb/ais-its-contracts/auth';
import type { Locale } from '@darmawanweb/ais-its-contracts/domain';
import { InjectConfig } from '@darmawanweb/ais-its-nest';
import { Injectable } from '@nestjs/common';

import type { Config } from '../../config.js';
import type { OrganizationRow, UserRow } from '../../db/database.js';
import { tokenLink } from '../../domain/identity.js';
import { EmailRequester } from '../notifications/email-requester.service.js';
import { OneTimeTokens } from './one-time-tokens.service.js';

/** Route of the web app that accepts invitations (`#token=…`). */
export const ACCEPT_INVITE_PATH = '/accept-invite';

/** Who is invited where. */
export interface Invitation {
  readonly user: UserRow;
  readonly organization: OrganizationRow;
  readonly role: OrgRole;
  /** Display name of the inviting admin. */
  readonly invitedBy: string;
  readonly locale?: Locale | undefined;
}

/**
 * Invitation links (spec §13.1): a one-time `invite` token valid
 * `INVITE_TTL_HOURS`, e-mailed with the `account_invite` template. The link
 * is accepted with `POST /auth/password/reset` (the invitee chooses a
 * password, which activates the account).
 */
@Injectable()
export class InvitationService {
  constructor(
    @InjectConfig() private readonly config: Config,
    private readonly tokens: OneTimeTokens,
    private readonly emails: EmailRequester,
  ) {}

  /** Issues the token and requests the e-mail; `false` when the e-mail could not be requested. */
  async send(invitation: Invitation): Promise<boolean> {
    const hours = this.config.INVITE_TTL_HOURS;
    const { token } = await this.tokens.issue(
      invitation.user.id,
      'invite',
      hours * 3_600_000,
    );
    return this.emails.request({
      to: invitation.user.email,
      template: 'account_invite',
      locale: invitation.locale ?? this.config.EMAIL_DEFAULT_LOCALE,
      data: {
        name: invitation.user.name,
        link: tokenLink(this.config.PUBLIC_BASE_URL, ACCEPT_INVITE_PATH, token),
        organizationName: invitation.organization.name,
        role: invitation.role,
        invitedBy: invitation.invitedBy,
        expiresInHours: hours,
      },
    });
  }
}
