import type { Locale } from '@darmawanweb/ais-its-contracts/domain';
import { InjectConfig, ValidationFailedError } from '@darmawanweb/ais-its-nest';
import {
  type AuditRequest,
  AuditService,
} from '@darmawanweb/ais-its-nest/audit';
import type { Principal } from '@darmawanweb/ais-its-nest/auth';
import { type Database, InjectDb } from '@darmawanweb/ais-its-nest/db';
import {
  type BeforeApplicationShutdown,
  Injectable,
  Logger,
} from '@nestjs/common';

import { BackgroundWork } from '../../common/background-work.js';
import { AuthErrors } from '../../common/errors.js';
import { clientInfo, requireUser } from '../../common/principals.js';
import type { Config } from '../../config.js';
import type {
  Executor,
  MembershipInvitationRow,
  UserRow,
} from '../../db/database.js';
import type * as schema from '../../db/schema.js';
import { normalizeEmail, tokenLink } from '../../domain/identity.js';
import { checkPasswordPolicy } from '../../domain/password-policy.js';
import { SessionsRepository } from '../accounts/sessions.repository.js';
import { UsersRepository } from '../accounts/users.repository.js';
import { PasswordHasher } from '../crypto/password-hasher.service.js';
import { EmailRequester } from '../notifications/email-requester.service.js';
import { actorOf } from '../sessions/audit-actor.js';
import { AuthThrottle } from '../throttling/auth-throttle.service.js';
import { InvitationService } from './invitation.service.js';
import { OneTimeTokens } from './one-time-tokens.service.js';

/** Route of the web app that consumes reset links (`#token=…`). */
export const RESET_PASSWORD_PATH = '/reset-password';

/** Request facts used for throttling and the audit trail. */
export type ClientRequest = AuditRequest & { readonly ip?: string | undefined };

/** Result of redeeming a reset or invitation link (inside the transaction). */
type RedeemOutcome =
  | { readonly kind: 'invalid' }
  | { readonly kind: 'disabled' }
  | {
      readonly kind: 'reset';
      readonly user: UserRow;
      readonly revokedSessions: number;
    }
  | {
      readonly kind: 'accepted';
      readonly user: UserRow;
      readonly invitation: MembershipInvitationRow;
      readonly membershipCreated: boolean;
      readonly revokedSessions: number;
    };

/**
 * Password life cycle (spec §13.1): forgotten passwords (always `202`, the
 * link travels by e-mail), resets and invitation acceptance with a one-time
 * link (revokes every session), and changes by the signed-in user (revokes
 * the other sessions).
 */
@Injectable()
export class PasswordService implements BeforeApplicationShutdown {
  /** Forgot-password lookups and e-mails, finished after the `202`. */
  private readonly background = new BackgroundWork(new Logger('Passwords'));

  constructor(
    @InjectDb() private readonly db: Database<typeof schema>,
    @InjectConfig() private readonly config: Config,
    private readonly users: UsersRepository,
    private readonly sessions: SessionsRepository,
    private readonly hasher: PasswordHasher,
    private readonly tokens: OneTimeTokens,
    private readonly invitations: InvitationService,
    private readonly emails: EmailRequester,
    private readonly throttle: AuthThrottle,
    private readonly audit: AuditService,
  ) {}

  /**
   * Accepts a forgot-password request. The answer never depends on whether
   * the address exists: the lookup, the token and the e-mail run after the
   * response, so neither the status nor the timing reveals accounts.
   *
   * @throws {RateLimitedError} when the client IP sent too many requests.
   */
  async forgot(
    email: string,
    locale: Locale | undefined,
    request: ClientRequest,
  ): Promise<void> {
    await this.throttle.consumeForgotPassword(clientInfo(request).ip);
    const address = normalizeEmail(email);
    const context = { ip: request.ip, headers: request.headers };
    this.background.run('Password reset request', () =>
      this.sendResetLink(
        address,
        locale ?? this.config.EMAIL_DEFAULT_LOCALE,
        context,
      ),
    );
  }

  /** Lets started reset e-mails finish before NATS drains and the pool closes. */
  async beforeApplicationShutdown(): Promise<void> {
    await this.background.drain();
  }

  /**
   * Sets a new password with a reset link, or accepts an invitation (spec
   * §13.1: "also used to accept invites"), and revokes every session of the
   * user.
   *
   * The link is checked first — its format, then an indexed lookup — and
   * the argon2id hash is computed only for a link that can be redeemed, so
   * anonymous garbage costs no hashing on the shared libuv pool; failed
   * attempts are throttled per client IP. The writes run with the token row
   * and the user row locked (`FOR UPDATE`) and the password write is
   * conditional (`status <> 'disabled'`), so a disable committing at the
   * same moment is never undone.
   *
   * - reset link: consumes the user's open reset links;
   * - invitation: activates an invited account, writes the membership and
   *   deletes the invitation.
   *
   * @throws {DomainError} `400 INVALID_TOKEN`, `400 VALIDATION_FAILED`
   *   (policy), `403 ACCOUNT_DISABLED`, `422 ROLE_NOT_GRANTABLE`, `429 RATE_LIMITED`.
   */
  async reset(
    token: string,
    password: string,
    request: ClientRequest,
  ): Promise<void> {
    assertPasswordPolicy('password', password);
    const outcome = await this.throttle.guardReset(
      clientInfo(request).ip,
      async () => {
        const kind = await this.redeemableKind(token);
        if (kind === undefined) throw AuthErrors.invalidToken();
        const passwordHash = await this.hasher.hash(password);
        const result = await this.db.transaction((tx) =>
          kind === 'reset'
            ? this.resetLocked(token, passwordHash, tx)
            : this.acceptLocked(token, passwordHash, tx),
        );
        if (result.kind === 'invalid') throw AuthErrors.invalidToken();
        if (result.kind === 'disabled') throw AuthErrors.accountDisabled();
        return result;
      },
    );
    const actor = actorOf(outcome.user, { id: outcome.user.id, orgId: null });
    if (outcome.kind === 'reset') {
      await this.audit.record(
        {
          action: 'auth.password.reset',
          targetType: 'user',
          targetId: outcome.user.id,
          orgId: null,
          meta: { revokedSessions: outcome.revokedSessions },
        },
        actor,
        request,
      );
      return;
    }
    await this.audit.record(
      {
        action: 'auth.invite.accept',
        targetType: 'user',
        targetId: outcome.user.id,
        orgId: outcome.invitation.orgId,
        meta: {
          invitationId: outcome.invitation.id,
          role: outcome.invitation.role,
          accountActivated: outcome.user.status === 'invited',
          membershipCreated: outcome.membershipCreated,
          revokedSessions: outcome.revokedSessions,
        },
      },
      actor,
      request,
    );
  }

  /**
   * Changes the signed-in user's password after checking the current one
   * (throttled per account) and revokes their other sessions.
   */
  async change(
    principal: Principal,
    currentPassword: string,
    newPassword: string,
    request: ClientRequest,
  ): Promise<void> {
    const actor = requireUser(principal);
    const user = await this.users.findById(actor.id);
    if (user === undefined) throw AuthErrors.userNotFound(actor.id);
    const storedHash = user.passwordHash;
    if (storedHash === null) throw AuthErrors.accountDisabled();
    await this.throttle.guardPasswordChange(user.id, async () => {
      if (!(await this.hasher.verify(storedHash, currentPassword))) {
        throw new ValidationFailedError([
          {
            field: 'currentPassword',
            message: 'The current password is incorrect',
            code: 'password_mismatch',
          },
        ]);
      }
    });
    assertPasswordPolicy('newPassword', newPassword);
    const passwordHash = await this.hasher.hash(newPassword);
    const revoked = await this.db.transaction(async (tx) => {
      // Conditional write: an account disabled meanwhile keeps its password.
      if (!(await this.users.setPassword(user.id, passwordHash, undefined, tx)))
        return undefined;
      return this.sessions.revokeOfUser(
        user.id,
        { exceptSessionId: actor.sessionId },
        tx,
      );
    });
    if (revoked === undefined) throw AuthErrors.accountDisabled();
    await this.audit.record(
      {
        action: 'auth.password.change',
        targetType: 'user',
        targetId: user.id,
        meta: { revokedSessions: revoked },
      },
      actor,
      request,
    );
  }

  /** Which kind of link `token` is, when it can be redeemed now (no lock, no write). */
  private async redeemableKind(
    token: string,
  ): Promise<'reset' | 'invitation' | undefined> {
    if (await this.tokens.isRedeemable(token)) return 'reset';
    if (await this.invitations.isRedeemable(token)) return 'invitation';
    return undefined;
  }

  /** Reset link: consume, then set the password of the locked user. */
  private async resetLocked(
    token: string,
    passwordHash: string,
    tx: Executor,
  ): Promise<RedeemOutcome> {
    const row = await this.tokens.consume(token, tx);
    if (row === undefined) return { kind: 'invalid' };
    const user = await this.users.lockById(row.userId, tx);
    if (user === undefined) return { kind: 'invalid' };
    if (!(await this.setPasswordUnlessDisabled(user, passwordHash, tx)))
      return { kind: 'disabled' };
    const revokedSessions = await this.sessions.revokeOfUser(user.id, {}, tx);
    return { kind: 'reset', user, revokedSessions };
  }

  /** Invitation: lock it, set the password of the locked user, write the membership. */
  private async acceptLocked(
    token: string,
    passwordHash: string,
    tx: Executor,
  ): Promise<RedeemOutcome> {
    const locked = await this.invitations.lock(token, tx);
    if (locked === undefined) return { kind: 'invalid' };
    const user = await this.users.lockById(locked.invitation.userId, tx);
    if (user === undefined) return { kind: 'invalid' };
    if (!(await this.setPasswordUnlessDisabled(user, passwordHash, tx)))
      return { kind: 'disabled' };
    const membershipCreated = await this.invitations.grant(locked, tx);
    const revokedSessions = await this.sessions.revokeOfUser(user.id, {}, tx);
    return {
      kind: 'accepted',
      user,
      invitation: locked.invitation,
      membershipCreated,
      revokedSessions,
    };
  }

  /**
   * Sets the password and activates the account of a locked user row; the
   * `UPDATE` itself also refuses disabled accounts.
   */
  private async setPasswordUnlessDisabled(
    user: UserRow,
    passwordHash: string,
    tx: Executor,
  ): Promise<boolean> {
    if (user.status === 'disabled') return false;
    return this.users.setPassword(user.id, passwordHash, 'active', tx);
  }

  /** Issues a reset token and requests the e-mail (background part of {@link forgot}). */
  private async sendResetLink(
    email: string,
    locale: Locale,
    request: ClientRequest,
  ): Promise<void> {
    const user = await this.users.findByEmail(email);
    // Disabled accounts get no link; invited ones have no password yet and
    // are activated by their invitation link instead.
    if (user?.status !== 'active') return;
    if (!(await this.throttle.allowResetEmail(email))) return;
    const ttlMinutes = this.config.PASSWORD_RESET_TTL_MIN;
    const { token } = await this.tokens.issue(
      user.id,
      'reset',
      ttlMinutes * 60_000,
    );
    const sent = await this.emails.request({
      to: user.email,
      template: 'password_reset',
      locale,
      data: {
        name: user.name,
        link: tokenLink(
          this.config.PUBLIC_BASE_URL,
          RESET_PASSWORD_PATH,
          token,
        ),
        expiresInMinutes: ttlMinutes,
      },
    });
    await this.recordResetRequest(user, sent, request);
  }

  private async recordResetRequest(
    user: UserRow,
    sent: boolean,
    request: ClientRequest,
  ): Promise<void> {
    await this.audit.record(
      {
        action: 'auth.password.reset_request',
        targetType: 'user',
        targetId: user.id,
        orgId: null,
        meta: { emailRequested: sent },
      },
      undefined,
      request,
    );
  }
}

/** Throws `400 VALIDATION_FAILED` when `password` violates the policy. */
export function assertPasswordPolicy(field: string, password: string): void {
  const violations = checkPasswordPolicy(password);
  if (violations.length > 0) throw AuthErrors.weakPassword(field, violations);
}
