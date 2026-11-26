import {
  type PageQuery,
  type Paginated,
  pageOffset,
  toPaginated,
} from '@darmawanweb/ais-its-contracts/api';
import type { AuditRequest } from '@darmawanweb/ais-its-nest/audit';
import type { Principal } from '@darmawanweb/ais-its-nest/auth';
import { Injectable } from '@nestjs/common';

import { AuthErrors } from '../../common/errors.js';
import { requireUser } from '../../common/principals.js';
import type { SessionRow } from '../../db/database.js';
import { Transactions } from '../../db/transactions.js';
import { accessRoles } from '../../domain/access-rules.js';
import { MembershipsRepository } from '../accounts/memberships.repository.js';
import { OrganizationsRepository } from '../accounts/organizations.repository.js';
import { SessionsRepository } from '../accounts/sessions.repository.js';
import { UsersRepository } from '../accounts/users.repository.js';
import {
  type IssuedAccessToken,
  TokenService,
} from '../tokens/token.service.js';

/** A session of the signed-in user, flagged when it is the calling one. */
export interface SessionView {
  readonly session: SessionRow;
  readonly current: boolean;
}

/** Result of `POST /auth/switch-org`. */
export interface SwitchedOrganization {
  readonly access: IssuedAccessToken;
  readonly activeOrgId: string;
}

/**
 * Self-service session management of the signed-in user: list and revoke
 * own sessions, switch the active organization of the current session.
 */
@Injectable()
export class AccountSessionsService {
  constructor(
    private readonly sessions: SessionsRepository,
    private readonly users: UsersRepository,
    private readonly organizations: OrganizationsRepository,
    private readonly memberships: MembershipsRepository,
    private readonly tokens: TokenService,
    private readonly transactions: Transactions,
  ) {}

  /** The user's active sessions, most recently used first. */
  async list(
    principal: Principal,
    page: PageQuery,
  ): Promise<Paginated<SessionView>> {
    const user = requireUser(principal);
    const { rows, total } = await this.sessions.listActiveOfUser(user.id, {
      offset: pageOffset(page),
      limit: page.pageSize,
    });
    return toPaginated(
      rows.map((session) => ({
        session,
        current: session.id === user.sessionId,
      })),
      page,
      total,
    );
  }

  /** Revokes one of the user's own sessions (sign out a device). */
  async revoke(
    principal: Principal,
    sessionId: string,
    request: AuditRequest,
  ): Promise<void> {
    const user = requireUser(principal);
    await this.transactions.run(async ({ tx, audit }) => {
      if (!(await this.sessions.revokeOwn(user.id, sessionId, tx)))
        throw AuthErrors.sessionNotFound(sessionId);
      await audit(
        {
          action: 'auth.session.revoke',
          targetType: 'session',
          targetId: sessionId,
        },
        user,
        request,
      );
    });
  }

  /**
   * Makes `orgId` the active organization of the current session and issues
   * an access token with the roles of that membership (spec §13.1: members
   * only, or super admins). Recorded as `auth.session.switch_org`.
   */
  async switchOrganization(
    principal: Principal,
    orgId: string,
    request: AuditRequest,
  ): Promise<SwitchedOrganization> {
    const actor = requireUser(principal);
    const user = await this.users.findById(actor.id);
    if (user === undefined) throw AuthErrors.userNotFound(actor.id);
    if (user.status !== 'active') throw AuthErrors.accountDisabled();
    const membership = await this.memberships.find(user.id, orgId);
    if (membership === undefined) {
      if (!user.isPlatformAdmin) throw AuthErrors.notAMember(orgId);
      if ((await this.organizations.findById(orgId)) === undefined) {
        throw AuthErrors.organizationNotFound(orgId);
      }
    }
    const roles = accessRoles(membership?.role ?? null, user.isPlatformAdmin);
    // Signed inside the transaction: when signing fails (no key loaded) the
    // session keeps its organization and no switch is recorded.
    const access = await this.transactions.run(async ({ tx, audit }) => {
      if (!(await this.sessions.setOrg(actor.sessionId, orgId, tx))) {
        throw AuthErrors.invalidRefreshToken(
          'The session was revoked; sign in again',
        );
      }
      const token = await this.tokens.issueAccessToken({
        userId: user.id,
        sessionId: actor.sessionId,
        orgId,
        roles,
        email: user.email,
        name: user.name,
      });
      if (actor.orgId !== orgId) {
        await audit(
          {
            action: 'auth.session.switch_org',
            targetType: 'session',
            targetId: actor.sessionId,
            orgId,
            meta: { fromOrgId: actor.orgId, roles },
          },
          actor,
          request,
        );
      }
      return token;
    });
    return { access, activeOrgId: orgId };
  }
}
