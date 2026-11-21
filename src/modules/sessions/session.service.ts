import { newId } from '@darmawanweb/ais-its-contracts/domain';
import { InjectConfig } from '@darmawanweb/ais-its-nest';
import {
  type AuditRequest,
  AuditService,
} from '@darmawanweb/ais-its-nest/audit';
import { type Database, InjectDb } from '@darmawanweb/ais-its-nest/db';
import { MetricsService } from '@darmawanweb/ais-its-nest/metrics';
import { Injectable, Logger } from '@nestjs/common';

import { AuthErrors } from '../../common/errors.js';
import type { CounterMetric } from '../../common/metrics.js';
import type { ClientInfo } from '../../common/principals.js';
import type { Config } from '../../config.js';
import type {
  Executor,
  MembershipRow,
  SessionRow,
  UserRow,
} from '../../db/database.js';
import type * as schema from '../../db/schema.js';
import { accessRoles } from '../../domain/access-rules.js';
import {
  generateOpaqueToken,
  isOpaqueToken,
  sha256Hex,
} from '../../domain/opaque-token.js';
import {
  decideRefresh,
  type RefreshRejection,
  refreshTokenExpiry,
} from '../../domain/refresh-rotation.js';
import { MembershipsRepository } from '../accounts/memberships.repository.js';
import { SessionsRepository } from '../accounts/sessions.repository.js';
import {
  type IssuedAccessToken,
  TokenService,
} from '../tokens/token.service.js';
import { actorOf } from './audit-actor.js';

/** A new refresh token for the cookie. */
export interface RefreshCookie {
  readonly token: string;
  readonly expiresAt: Date;
}

/** A session opened by a sign-in. */
export interface OpenedSession {
  readonly session: SessionRow;
  readonly access: IssuedAccessToken;
  readonly refresh: RefreshCookie;
}

/** A successful refresh. */
export interface RefreshedSession {
  readonly access: IssuedAccessToken;
  readonly refresh: RefreshCookie;
}

type RefreshOutcome =
  | {
      readonly kind: 'rotated';
      readonly user: UserRow;
      readonly session: SessionRow;
      readonly role: MembershipRow | undefined;
      readonly refresh: RefreshCookie;
    }
  | { readonly kind: 'unknown' }
  | {
      readonly kind: 'refused';
      readonly reason: RefreshRejection;
      readonly revoked: boolean;
      readonly user: UserRow;
      readonly session: SessionRow;
    };

/**
 * Sessions and rotating refresh tokens (spec §8.3): a session is a token
 * family; every refresh consumes the presented token and issues its
 * successor; presenting a consumed token revokes the family
 * (`domain/refresh-rotation.ts`). Roles are recomputed from the memberships
 * at every refresh, so membership changes reach access tokens within
 * `ACCESS_TOKEN_TTL`.
 */
@Injectable()
export class SessionService {
  private readonly logger = new Logger('Sessions');
  private readonly refreshes: CounterMetric;

  constructor(
    @InjectDb() private readonly db: Database<typeof schema>,
    @InjectConfig() private readonly config: Config,
    private readonly sessions: SessionsRepository,
    private readonly memberships: MembershipsRepository,
    private readonly tokens: TokenService,
    private readonly audit: AuditService,
    metrics: MetricsService,
  ) {
    this.refreshes = metrics.counter({
      name: 'auth_token_refreshes_total',
      help: 'Refresh token presentations by outcome (rotated, unknown, expired, reuse_detected, …).',
      labelNames: ['outcome'],
    });
  }

  /** Opens a session for a user whose credentials were verified. */
  async open(
    user: UserRow,
    orgId: string | null,
    client: ClientInfo,
  ): Promise<OpenedSession> {
    const role =
      orgId === null ? undefined : await this.memberships.find(user.id, orgId);
    const refresh = this.newRefreshToken();
    const session = await this.sessions.create(
      {
        id: newId(),
        userId: user.id,
        orgId,
        ip: client.ip,
        userAgent: client.userAgent,
      },
      {
        id: newId(),
        tokenHash: sha256Hex(refresh.token),
        expiresAt: refresh.expiresAt,
      },
    );
    const access = await this.tokens.issueAccessToken({
      userId: user.id,
      sessionId: session.id,
      orgId,
      roles: accessRoles(role?.role ?? null, user.isPlatformAdmin),
      email: user.email,
      name: user.name,
    });
    return { session, access, refresh };
  }

  /**
   * Rotates a refresh token.
   *
   * @throws {UnauthorizedError} `INVALID_REFRESH_TOKEN` (unknown, expired,
   *   revoked) or `REFRESH_TOKEN_REUSED` (family revoked).
   * @throws {ForbiddenError} `ACCOUNT_DISABLED`.
   */
  async refresh(
    presented: string | undefined,
    request: AuditRequest,
  ): Promise<RefreshedSession> {
    if (presented === undefined || !isOpaqueToken(presented)) {
      this.refreshes.inc({ outcome: 'missing' });
      throw AuthErrors.invalidRefreshToken();
    }
    const outcome = await this.db.transaction((tx) =>
      this.rotateLocked(sha256Hex(presented), tx),
    );
    if (outcome.kind === 'unknown') {
      this.refreshes.inc({ outcome: 'unknown' });
      throw AuthErrors.invalidRefreshToken();
    }
    if (outcome.kind === 'refused') {
      this.refreshes.inc({ outcome: outcome.reason });
      return this.refuse(outcome, request);
    }
    this.refreshes.inc({ outcome: 'rotated' });
    const access = await this.tokens.issueAccessToken({
      userId: outcome.user.id,
      sessionId: outcome.session.id,
      orgId: outcome.session.orgId,
      roles: accessRoles(
        outcome.role?.role ?? null,
        outcome.user.isPlatformAdmin,
      ),
      email: outcome.user.email,
      name: outcome.user.name,
    });
    return { access, refresh: outcome.refresh };
  }

  /**
   * Revokes the session of a refresh token (logout). Unknown tokens are
   * ignored: logging out is idempotent.
   */
  async logout(
    presented: string | undefined,
    request: AuditRequest,
  ): Promise<void> {
    if (presented === undefined || !isOpaqueToken(presented)) return;
    const found = await this.sessions.findByToken(sha256Hex(presented));
    if (found === undefined || !(await this.sessions.revoke(found.session.id)))
      return;
    const { session, user } = found;
    await this.audit.record(
      {
        action: 'auth.logout',
        targetType: 'session',
        targetId: session.id,
        orgId: session.orgId,
      },
      actorOf(user, session),
      request,
    );
  }

  /** Housekeeping: drops tokens and sessions that ended before `before`. */
  prune(before: Date): Promise<{ tokens: number; sessions: number }> {
    return this.sessions.prune(before);
  }

  private newRefreshToken(now: Date = new Date()): RefreshCookie {
    return {
      token: generateOpaqueToken(),
      expiresAt: refreshTokenExpiry(now, this.config.REFRESH_TOKEN_TTL_DAYS),
    };
  }

  /** The rotation decision and its writes, inside the transaction. */
  private async rotateLocked(
    tokenHash: string,
    tx: Executor,
  ): Promise<RefreshOutcome> {
    const context = await this.sessions.lockToken(tokenHash, tx);
    if (context === undefined) return { kind: 'unknown' };
    const { token, session, user } = context;
    const membership =
      session.orgId === null
        ? undefined
        : await this.memberships.find(user.id, session.orgId, tx);
    const decision = decideRefresh(
      {
        usedAt: token.usedAt,
        expiresAt: token.expiresAt,
        sessionRevokedAt: session.revokedAt,
        userStatus: user.status,
        orgAccess:
          session.orgId === null ||
          user.isPlatformAdmin ||
          membership !== undefined,
      },
      new Date(),
    );
    switch (decision.action) {
      case 'rotate': {
        const refresh = this.newRefreshToken();
        await this.sessions.rotate(
          token.id,
          {
            id: newId(),
            sessionId: session.id,
            tokenHash: sha256Hex(refresh.token),
            expiresAt: refresh.expiresAt,
          },
          tx,
        );
        return { kind: 'rotated', user, session, role: membership, refresh };
      }
      case 'revoke_family':
        await this.sessions.revoke(session.id, tx);
        return {
          kind: 'refused',
          reason: decision.reason,
          revoked: true,
          user,
          session,
        };
      case 'reject':
        return {
          kind: 'refused',
          reason: decision.reason,
          revoked: false,
          user,
          session,
        };
    }
  }

  /** Records and reports a refused refresh (after the revocation committed). */
  private async refuse(
    outcome: Extract<RefreshOutcome, { kind: 'refused' }>,
    request: AuditRequest,
  ): Promise<never> {
    const { user, session, reason } = outcome;
    if (reason === 'reuse_detected') {
      this.logger.warn(
        `Refresh token reuse detected: session ${session.id} of user ${user.id} revoked`,
      );
      await this.audit.record(
        {
          action: 'auth.refresh.reuse_detected',
          targetType: 'session',
          targetId: session.id,
          orgId: session.orgId,
          meta: { userId: user.id },
        },
        undefined,
        request,
      );
      throw AuthErrors.refreshTokenReused();
    }
    if (reason === 'account_inactive' && user.status === 'disabled')
      throw AuthErrors.accountDisabled();
    throw AuthErrors.invalidRefreshToken();
  }
}
