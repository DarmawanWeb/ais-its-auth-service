import type { Locale } from '@darmawanweb/ais-its-contracts/domain';
import { InjectConfig, ValidationFailedError } from '@darmawanweb/ais-its-nest';
import {
  type AuditRequest,
  AuditService,
} from '@darmawanweb/ais-its-nest/audit';
import type { Principal } from '@darmawanweb/ais-its-nest/auth';
import { type Database, InjectDb } from '@darmawanweb/ais-its-nest/db';
import { Injectable, Logger } from '@nestjs/common';

import { AuthErrors } from '../../common/errors.js';
import { requireUser } from '../../common/principals.js';
import type { Config } from '../../config.js';
import type { UserRow } from '../../db/database.js';
import type * as schema from '../../db/schema.js';
import { normalizeEmail, tokenLink } from '../../domain/identity.js';
import { checkPasswordPolicy } from '../../domain/password-policy.js';
import { SessionsRepository } from '../accounts/sessions.repository.js';
import { UsersRepository } from '../accounts/users.repository.js';
import { PasswordHasher } from '../crypto/password-hasher.service.js';
import { EmailRequester } from '../notifications/email-requester.service.js';
import { actorOf } from '../sessions/audit-actor.js';
import { AuthThrottle } from '../throttling/auth-throttle.service.js';
import { OneTimeTokens } from './one-time-tokens.service.js';

/** Route of the web app that consumes reset links (`#token=…`). */
export const RESET_PASSWORD_PATH = '/reset-password';

/** Request facts used for throttling and the audit trail. */
export type ClientRequest = AuditRequest & { readonly ip?: string | undefined };

/**
 * Password life cycle (spec §13.1): forgotten passwords (always `202`, the
 * link travels by e-mail), resets and invitation acceptance with a one-time
 * token (revokes every session), and changes by the signed-in user (revokes
 * the other sessions).
 */
@Injectable()
export class PasswordService {
  private readonly logger = new Logger('Passwords');

  constructor(
    @InjectDb() private readonly db: Database<typeof schema>,
    @InjectConfig() private readonly config: Config,
    private readonly users: UsersRepository,
    private readonly sessions: SessionsRepository,
    private readonly hasher: PasswordHasher,
    private readonly tokens: OneTimeTokens,
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
    await this.throttle.consumeForgotPassword(request.ip ?? null);
    const address = normalizeEmail(email);
    const context = { ip: request.ip, headers: request.headers };
    void this.sendResetLink(
      address,
      locale ?? this.config.EMAIL_DEFAULT_LOCALE,
      context,
    ).catch((error: unknown) => {
      this.logger.error(
        `Password reset request failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    });
  }

  /**
   * Sets a new password with a reset or invitation token: activates invited
   * accounts, consumes the token and revokes every session of the user.
   *
   * @throws {DomainError} `400 INVALID_TOKEN`, `400 VALIDATION_FAILED` (policy), `403 ACCOUNT_DISABLED`.
   */
  async reset(
    token: string,
    password: string,
    request: ClientRequest,
  ): Promise<void> {
    assertPasswordPolicy('password', password);
    const passwordHash = await this.hasher.hash(password);
    const outcome = await this.db.transaction(async (tx) => {
      const row = await this.tokens.consume(token, tx);
      if (row === undefined) return undefined;
      const user = await this.users.findById(row.userId, tx);
      if (user === undefined) return undefined;
      if (user.status === 'disabled')
        return { user, disabled: true as const, purpose: row.purpose };
      await this.users.setPassword(user.id, passwordHash, 'active', tx);
      await this.sessions.revokeOfUser(user.id, {}, tx);
      return { user, disabled: false as const, purpose: row.purpose };
    });
    if (outcome === undefined) throw AuthErrors.invalidToken();
    if (outcome.disabled) throw AuthErrors.accountDisabled();
    const accepted =
      outcome.purpose === 'invite' || outcome.user.status === 'invited';
    await this.audit.record(
      {
        action: accepted ? 'auth.invite.accept' : 'auth.password.reset',
        targetType: 'user',
        targetId: outcome.user.id,
        orgId: null,
        meta: { purpose: outcome.purpose },
      },
      actorOf(outcome.user, { id: outcome.user.id, orgId: null }),
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
      await this.users.setPassword(user.id, passwordHash, undefined, tx);
      return this.sessions.revokeOfUser(
        user.id,
        { exceptSessionId: actor.sessionId },
        tx,
      );
    });
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

  /** Issues a reset token and requests the e-mail (background part of {@link forgot}). */
  private async sendResetLink(
    email: string,
    locale: Locale,
    request: ClientRequest,
  ): Promise<void> {
    const user = await this.users.findByEmail(email);
    if (user === undefined || user.status === 'disabled') return;
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
