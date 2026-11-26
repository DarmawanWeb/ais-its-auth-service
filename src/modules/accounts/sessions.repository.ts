import { type Database, InjectDb } from '@darmawanweb/ais-its-nest/db';
import { Injectable } from '@nestjs/common';
import {
  and,
  count,
  desc,
  eq,
  isNotNull,
  isNull,
  lt,
  ne,
  or,
  sql,
} from 'drizzle-orm';

import type {
  Executor,
  RefreshTokenRow,
  SessionRow,
  UserRow,
} from '../../db/database.js';
import * as schema from '../../db/schema.js';

const { refreshTokens, sessions, users } = schema;

/** A session to open. */
export interface NewSession {
  readonly id: string;
  readonly userId: string;
  readonly orgId: string | null;
  readonly ip: string | null;
  readonly userAgent: string | null;
}

/** A refresh token to store (hash only). */
export interface NewRefreshToken {
  readonly id: string;
  readonly sessionId: string;
  readonly tokenHash: string;
  readonly expiresAt: Date;
}

/** A presented refresh token with its session and account, locked for the transaction. */
export interface RefreshTokenContext {
  readonly token: RefreshTokenRow;
  readonly session: SessionRow;
  readonly user: UserRow;
}

/** Which of a user's sessions to revoke. */
export interface RevokeScope {
  /** Keep this session (password change revokes the *other* sessions). */
  readonly exceptSessionId?: string | undefined;
  /** Only sessions whose active organization is this one (member removal). */
  readonly orgId?: string | undefined;
}

/** Drizzle access to `sessions` and `refresh_tokens` (spec §8.3). */
@Injectable()
export class SessionsRepository {
  constructor(@InjectDb() private readonly db: Database<typeof schema>) {}

  /** Opens a session with its first refresh token. */
  async create(
    session: NewSession,
    token: Omit<NewRefreshToken, 'sessionId'>,
    executor: Executor = this.db,
  ): Promise<SessionRow> {
    const [row] = await executor.insert(sessions).values(session).returning();
    if (row === undefined)
      throw new Error('INSERT … RETURNING returned no row');
    await executor
      .insert(refreshTokens)
      .values({ ...token, sessionId: row.id });
    return row;
  }

  /**
   * Finds a refresh token by hash and locks its row (`FOR UPDATE`), so two
   * concurrent refreshes with the same token are serialized: the second one
   * sees `used_at` and triggers reuse detection. Only the token row is
   * locked (drizzle renders `FOR UPDATE OF` schema-qualified, which
   * PostgreSQL rejects, so the session and account are read separately).
   */
  async lockToken(
    tokenHash: string,
    executor: Executor,
  ): Promise<RefreshTokenContext | undefined> {
    const [token] = await executor
      .select()
      .from(refreshTokens)
      .where(eq(refreshTokens.tokenHash, tokenHash))
      .for('update')
      .limit(1);
    if (token === undefined) return undefined;
    const [owner] = await executor
      .select({ session: sessions, user: users })
      .from(sessions)
      .innerJoin(users, eq(users.id, sessions.userId))
      .where(eq(sessions.id, token.sessionId))
      .limit(1);
    return owner === undefined ? undefined : { token, ...owner };
  }

  /** Session and account of a refresh token (no lock; logout). */
  async findByToken(
    tokenHash: string,
  ): Promise<{ session: SessionRow; user: UserRow } | undefined> {
    const [row] = await this.db
      .select({ session: sessions, user: users })
      .from(refreshTokens)
      .innerJoin(sessions, eq(sessions.id, refreshTokens.sessionId))
      .innerJoin(users, eq(users.id, sessions.userId))
      .where(eq(refreshTokens.tokenHash, tokenHash))
      .limit(1);
    return row;
  }

  /** Consumes a token and stores its successor; bumps `last_used_at`. */
  async rotate(
    usedTokenId: string,
    successor: NewRefreshToken,
    executor: Executor,
  ): Promise<void> {
    await executor
      .update(refreshTokens)
      .set({ usedAt: sql`now()` })
      .where(eq(refreshTokens.id, usedTokenId));
    await executor.insert(refreshTokens).values(successor);
    await executor
      .update(sessions)
      .set({ lastUsedAt: sql`now()` })
      .where(eq(sessions.id, successor.sessionId));
  }

  /** A session that is not revoked. */
  async findActive(
    id: string,
    executor: Executor = this.db,
  ): Promise<SessionRow | undefined> {
    const [row] = await executor
      .select()
      .from(sessions)
      .where(and(eq(sessions.id, id), isNull(sessions.revokedAt)))
      .limit(1);
    return row;
  }

  /** Changes the active organization of a session. */
  async setOrg(
    id: string,
    orgId: string | null,
    executor: Executor = this.db,
  ): Promise<boolean> {
    const rows = await executor
      .update(sessions)
      .set({ orgId, lastUsedAt: sql`now()` })
      .where(and(eq(sessions.id, id), isNull(sessions.revokedAt)))
      .returning({ id: sessions.id });
    return rows.length > 0;
  }

  /** Revokes one session (token family); `false` when it was not active. */
  async revoke(id: string, executor: Executor = this.db): Promise<boolean> {
    const rows = await executor
      .update(sessions)
      .set({ revokedAt: sql`now()` })
      .where(and(eq(sessions.id, id), isNull(sessions.revokedAt)))
      .returning({ id: sessions.id });
    return rows.length > 0;
  }

  /** Revokes one of the user's own sessions; `false` when it is not theirs or not active. */
  async revokeOwn(
    userId: string,
    id: string,
    executor: Executor = this.db,
  ): Promise<boolean> {
    const rows = await executor
      .update(sessions)
      .set({ revokedAt: sql`now()` })
      .where(
        and(
          eq(sessions.id, id),
          eq(sessions.userId, userId),
          isNull(sessions.revokedAt),
        ),
      )
      .returning({ id: sessions.id });
    return rows.length > 0;
  }

  /** Revokes a user's active sessions within `scope`; returns how many. */
  async revokeOfUser(
    userId: string,
    scope: RevokeScope = {},
    executor: Executor = this.db,
  ): Promise<number> {
    const rows = await executor
      .update(sessions)
      .set({ revokedAt: sql`now()` })
      .where(
        and(
          eq(sessions.userId, userId),
          isNull(sessions.revokedAt),
          scope.exceptSessionId === undefined
            ? undefined
            : ne(sessions.id, scope.exceptSessionId),
          scope.orgId === undefined
            ? undefined
            : eq(sessions.orgId, scope.orgId),
        ),
      )
      .returning({ id: sessions.id });
    return rows.length;
  }

  /** Revokes every active session whose active organization is `orgId`. */
  async revokeOfOrg(orgId: string, executor: Executor): Promise<number> {
    const rows = await executor
      .update(sessions)
      .set({ revokedAt: sql`now()` })
      .where(and(eq(sessions.orgId, orgId), isNull(sessions.revokedAt)))
      .returning({ id: sessions.id });
    return rows.length;
  }

  /** One page of a user's active sessions, most recently used first. */
  async listActiveOfUser(
    userId: string,
    page: { readonly offset: number; readonly limit: number },
  ): Promise<{ rows: SessionRow[]; total: number }> {
    const where = and(eq(sessions.userId, userId), isNull(sessions.revokedAt));
    const [rows, totals] = await Promise.all([
      this.db
        .select()
        .from(sessions)
        .where(where)
        .orderBy(desc(sessions.lastUsedAt), desc(sessions.id))
        .limit(page.limit)
        .offset(page.offset),
      this.db.select({ total: count() }).from(sessions).where(where),
    ]);
    return { rows, total: totals[0]?.total ?? 0 };
  }

  /**
   * Housekeeping: deletes refresh tokens that expired before `before` and
   * sessions revoked before `before`, or whose tokens are all gone.
   */
  async prune(before: Date): Promise<{ tokens: number; sessions: number }> {
    const deletedTokens = await this.db
      .delete(refreshTokens)
      .where(lt(refreshTokens.expiresAt, before))
      .returning({ id: refreshTokens.id });
    const deletedSessions = await this.db
      .delete(sessions)
      .where(
        or(
          and(isNotNull(sessions.revokedAt), lt(sessions.revokedAt, before)),
          and(
            lt(sessions.lastUsedAt, before),
            sql`NOT EXISTS (SELECT 1 FROM ${refreshTokens} WHERE ${refreshTokens.sessionId} = ${sessions.id})`,
          ),
        ),
      )
      .returning({ id: sessions.id });
    return { tokens: deletedTokens.length, sessions: deletedSessions.length };
  }
}
