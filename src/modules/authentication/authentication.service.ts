import {
  type AuditRequest,
  AuditService,
} from '@darmawanweb/ais-its-nest/audit';
import { DomainError } from '@darmawanweb/ais-its-nest';
import {
  type Counter,
  MetricsService,
} from '@darmawanweb/ais-its-nest/metrics';
import { InjectRedis, type Redis } from '@darmawanweb/ais-its-nest/redis';
import { Injectable } from '@nestjs/common';

import { AuthErrors } from '../../common/errors.js';
import { type ClientInfo, clientInfo } from '../../common/principals.js';
import type { UserRow } from '../../db/database.js';
import { Transactions } from '../../db/transactions.js';
import { accessRoles } from '../../domain/access-rules.js';
import { normalizeEmail } from '../../domain/identity.js';
import {
  type MembershipWithOrganization,
  MembershipsRepository,
} from '../accounts/memberships.repository.js';
import { UsersRepository } from '../accounts/users.repository.js';
import { PasswordHasher } from '../crypto/password-hasher.service.js';
import { MfaService } from '../mfa/mfa.service.js';
import { actorOf } from '../sessions/audit-actor.js';
import {
  type OpenedSession,
  SessionService,
} from '../sessions/session.service.js';
import { AuthThrottle } from '../throttling/auth-throttle.service.js';
import { TokenService } from '../tokens/token.service.js';

/** A completed sign-in. */
export interface SignedIn {
  readonly kind: 'signed_in';
  readonly user: UserRow;
  readonly memberships: MembershipWithOrganization[];
  readonly activeOrgId: string | null;
  readonly opened: OpenedSession;
}

/** A password sign-in that still needs the TOTP code. */
export interface MfaPending {
  readonly kind: 'mfa_required';
  readonly mfaToken: string;
}

/** The request facts of a sign-in. */
export type SignInRequest = AuditRequest & {
  readonly ip?: string | undefined;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
};

/**
 * Sign-in (spec §13.1): password login with constant-time behaviour for
 * unknown accounts, per-e-mail and per-IP failure throttling, an optional
 * TOTP second step through a 5-minute single-use MFA token, and the session
 * with its first refresh token. Every outcome is audited (`auth.login.*`).
 */
@Injectable()
export class AuthenticationService {
  private readonly logins: Counter<'outcome'>;

  constructor(
    private readonly users: UsersRepository,
    private readonly memberships: MembershipsRepository,
    private readonly hasher: PasswordHasher,
    private readonly throttle: AuthThrottle,
    private readonly sessions: SessionService,
    private readonly tokens: TokenService,
    private readonly mfa: MfaService,
    private readonly audit: AuditService,
    private readonly transactions: Transactions,
    @InjectRedis() private readonly redis: Redis,
    metrics: MetricsService,
  ) {
    this.logins = metrics.counter({
      name: 'auth_logins_total',
      help: 'Sign-in attempts by outcome (success, mfa_required, invalid_credentials, …).',
      labelNames: ['outcome'],
    });
  }

  /**
   * Verifies e-mail and password.
   *
   * @throws {UnauthorizedError} `INVALID_CREDENTIALS` for unknown e-mails and wrong passwords alike.
   * @throws {ForbiddenError} `ACCOUNT_DISABLED` (only after a correct password).
   * @throws {RateLimitedError} `RATE_LIMITED` with `Retry-After` when throttled.
   */
  async login(
    email: string,
    password: string,
    request: SignInRequest,
  ): Promise<SignedIn | MfaPending> {
    const address = normalizeEmail(email);
    const client = clientInfo(request);
    const user = await this.observeFailure(address, 'password', request, () =>
      this.throttle.guardLogin(address, client.ip, () =>
        this.checkPassword(address, password),
      ),
    );
    if (
      user.passwordHash !== null &&
      this.hasher.needsRehash(user.passwordHash)
    ) {
      // Compare-and-set: a password change committed meanwhile wins.
      await this.users.rehashPassword(
        user.id,
        user.passwordHash,
        await this.hasher.hash(password),
      );
    }
    if (user.mfaEnabled) {
      this.logins.inc({ outcome: 'mfa_required' });
      return {
        kind: 'mfa_required',
        mfaToken: await this.tokens.issueMfaChallenge(user.id),
      };
    }
    return this.signIn(user, client, request, false);
  }

  /**
   * Completes an MFA sign-in with the challenge token and a TOTP code; the
   * challenge is single use.
   */
  async verifyMfa(
    mfaToken: string,
    code: string,
    request: SignInRequest,
  ): Promise<SignedIn> {
    const challenge = await this.tokens.verifyMfaChallenge(mfaToken);
    const usedKey = `mfa:challenge:${challenge.challengeId}`;
    // A consumed challenge is refused before the code is checked, so it never burns a code.
    if ((await this.redis.exists(usedKey)) > 0) throw challengeUsed();
    const user = await this.users.findById(challenge.userId);
    if (user?.mfaEnabled !== true) throw AuthErrors.invalidCredentials();
    if (user.status !== 'active') throw AuthErrors.accountDisabled();
    const client = clientInfo(request);
    await this.observeFailure(user.email, 'mfa', request, () =>
      this.throttle.guardMfa(user.id, client.ip, () =>
        this.mfa.checkCode(user, code),
      ),
    );
    const ttlSeconds = Math.max(
      1,
      Math.ceil((challenge.expiresAt.getTime() - Date.now()) / 1000),
    );
    const unused = await this.redis.set(usedKey, '1', 'EX', ttlSeconds, 'NX');
    if (unused !== 'OK') throw challengeUsed();
    return this.signIn(user, client, request, true);
  }

  /** The account of valid credentials; same work and error for unknown e-mails. */
  private async checkPassword(
    email: string,
    password: string,
  ): Promise<UserRow> {
    const user = await this.users.findByEmail(email);
    if (user === undefined || user.passwordHash === null) {
      await this.hasher.verifyDummy(password);
      throw AuthErrors.invalidCredentials();
    }
    if (!(await this.hasher.verify(user.passwordHash, password)))
      throw AuthErrors.invalidCredentials();
    if (user.status === 'disabled') throw AuthErrors.accountDisabled();
    if (user.status !== 'active') throw AuthErrors.invalidCredentials();
    return user;
  }

  /** Opens the session in the user's first organization and records the sign-in. */
  private async signIn(
    user: UserRow,
    client: ClientInfo,
    request: AuditRequest,
    mfa: boolean,
  ): Promise<SignedIn> {
    const memberships = await this.memberships.listOfUser(user.id);
    const first = memberships[0];
    const activeOrgId = first?.organization.id ?? null;
    // The session, the sign-in time and the audit record commit together.
    const opened = await this.transactions.run(async ({ tx, audit }) => {
      const session = await this.sessions.open(user, activeOrgId, client, tx);
      await this.users.recordLogin(user.id, tx);
      await audit(
        {
          action: 'auth.login.succeeded',
          targetType: 'session',
          targetId: session.session.id,
          orgId: activeOrgId,
          meta: { mfa },
        },
        actorOf(
          user,
          session.session,
          accessRoles(first?.membership.role ?? null, user.isPlatformAdmin),
        ),
        request,
      );
      return session;
    });
    this.logins.inc({ outcome: 'success' });
    return { kind: 'signed_in', user, memberships, activeOrgId, opened };
  }

  /**
   * Counts and audits a failed attempt (throttled attempts are only counted),
   * then rethrows. The only best-effort record of the service
   * (`AuditService.record`, not the outbox): a failed attempt changes
   * nothing to commit with, and writing a row per attempt would turn a
   * credential-stuffing run into database write load; during a NATS outage
   * such records are dropped and counted (`aisits_audit_failures_total`),
   * while `aisits_auth_logins_total{outcome}` still counts every attempt.
   */
  private async observeFailure<T>(
    email: string,
    stage: 'password' | 'mfa',
    request: AuditRequest,
    attempt: () => Promise<T>,
  ): Promise<T> {
    try {
      return await attempt();
    } catch (error) {
      const reason =
        error instanceof DomainError ? error.code.toLowerCase() : 'error';
      this.logins.inc({ outcome: reason });
      if (error instanceof DomainError && error.code !== 'RATE_LIMITED') {
        await this.audit.record(
          {
            action: 'auth.login.failed',
            orgId: null,
            meta: { email, stage, reason },
          },
          undefined,
          request,
        );
      }
      throw error;
    }
  }
}

function challengeUsed(): DomainError {
  return new DomainError('INVALID_TOKEN', {
    detail: 'The MFA token was already used; sign in again',
  });
}
