import { type Database, InjectDb } from '@darmawanweb/ais-its-nest/db';
import { Injectable } from '@nestjs/common';
import {
  and,
  count,
  desc,
  eq,
  isNull,
  lt,
  or,
  type SQL,
  sql,
} from 'drizzle-orm';

import type { ApiKeyRow, Executor } from '../../db/database.js';
import * as schema from '../../db/schema.js';

const { apiKeys } = schema;

/** An API key to store (hash only). */
export interface NewApiKey {
  readonly id: string;
  readonly orgId: string;
  readonly name: string;
  readonly prefix: string;
  readonly keyHash: string;
  readonly scopes: readonly string[];
  readonly createdBy: string | null;
  /** Inactive from this time on; `null`/absent = no expiry. */
  readonly expiresAt?: Date | null | undefined;
}

/** A new secret for a key (`POST /api-keys/:id/rotate`). */
export interface KeyRotation {
  readonly keyHash: string;
  /** Hash of the replaced secret, accepted until {@link previousKeyExpiresAt}; `null` for no grace period. */
  readonly previousKeyHash: string | null;
  readonly previousKeyExpiresAt: Date | null;
}

/** Which keys a listing may see. */
export type ApiKeyScopeFilter =
  { readonly kind: 'org'; readonly orgId: string } | { readonly kind: 'all' };

/** How often `last_used_at` is written at most, seconds (spec §13.1: once per minute). */
export const LAST_USED_RESOLUTION_SECONDS = 60;

/** Drizzle access to `api_keys`. */
@Injectable()
export class ApiKeysRepository {
  constructor(@InjectDb() private readonly db: Database<typeof schema>) {}

  async insert(
    key: NewApiKey,
    executor: Executor = this.db,
  ): Promise<ApiKeyRow> {
    const [row] = await executor
      .insert(apiKeys)
      .values({ ...key, scopes: [...key.scopes] })
      .returning();
    if (row === undefined)
      throw new Error('INSERT … RETURNING returned no row');
    return row;
  }

  async findById(id: string): Promise<ApiKeyRow | undefined> {
    const [row] = await this.db
      .select()
      .from(apiKeys)
      .where(eq(apiKeys.id, id))
      .limit(1);
    return row;
  }

  /** The key, locked until the end of the transaction (rotations serialize). */
  async lockById(id: string, tx: Executor): Promise<ApiKeyRow | undefined> {
    const [row] = await tx
      .select()
      .from(apiKeys)
      .where(eq(apiKeys.id, id))
      .for('update')
      .limit(1);
    return row;
  }

  /**
   * Replaces the secret of a key: the new hash, the replaced one with the
   * end of its grace period (or none), and the rotation time. The id and
   * the prefix stay.
   */
  async rotate(
    id: string,
    rotation: KeyRotation,
    tx: Executor,
  ): Promise<ApiKeyRow> {
    const [row] = await tx
      .update(apiKeys)
      .set({
        keyHash: rotation.keyHash,
        previousKeyHash: rotation.previousKeyHash,
        previousKeyExpiresAt: rotation.previousKeyExpiresAt,
        rotatedAt: sql`now()`,
      })
      .where(eq(apiKeys.id, id))
      .returning();
    if (row === undefined)
      throw new Error('UPDATE … RETURNING returned no row');
    return row;
  }

  /** Housekeeping: forgets replaced secrets whose grace period ended before `before`. */
  async pruneReplacedSecrets(before: Date): Promise<number> {
    const rows = await this.db
      .update(apiKeys)
      .set({ previousKeyHash: null, previousKeyExpiresAt: null })
      .where(lt(apiKeys.previousKeyExpiresAt, before))
      .returning({ id: apiKeys.id });
    return rows.length;
  }

  /** The active key of an organization with this name (seeding is idempotent by name). */
  async findActiveByName(
    orgId: string,
    name: string,
    executor: Executor = this.db,
  ): Promise<ApiKeyRow | undefined> {
    const [row] = await executor
      .select()
      .from(apiKeys)
      .where(
        and(
          eq(apiKeys.orgId, orgId),
          eq(apiKeys.name, name),
          isNull(apiKeys.revokedAt),
        ),
      )
      .limit(1);
    return row;
  }

  /** The key with this public prefix (`sk_<id>`). */
  async findByPrefix(prefix: string): Promise<ApiKeyRow | undefined> {
    const [row] = await this.db
      .select()
      .from(apiKeys)
      .where(eq(apiKeys.prefix, prefix))
      .limit(1);
    return row;
  }

  /** Active (optionally also revoked) keys of a scope, newest first, and the total. */
  async list(
    scope: ApiKeyScopeFilter,
    includeRevoked: boolean,
    page: { readonly offset: number; readonly limit: number },
  ): Promise<{ rows: ApiKeyRow[]; total: number }> {
    const conditions: (SQL | undefined)[] = [
      scope.kind === 'org' ? eq(apiKeys.orgId, scope.orgId) : undefined,
      includeRevoked ? undefined : isNull(apiKeys.revokedAt),
    ];
    const where = and(...conditions);
    const [rows, totals] = await Promise.all([
      this.db
        .select()
        .from(apiKeys)
        .where(where)
        .orderBy(desc(apiKeys.createdAt), desc(apiKeys.id))
        .limit(page.limit)
        .offset(page.offset),
      this.db.select({ total: count() }).from(apiKeys).where(where),
    ]);
    return { rows, total: totals[0]?.total ?? 0 };
  }

  /** Revokes a key; returns it, also when it was already revoked. */
  async revoke(
    id: string,
    executor: Executor = this.db,
  ): Promise<ApiKeyRow | undefined> {
    const [row] = await executor
      .update(apiKeys)
      .set({ revokedAt: sql`coalesce(${apiKeys.revokedAt}, now())` })
      .where(eq(apiKeys.id, id))
      .returning();
    return row;
  }

  /** Records a use, at most once per {@link LAST_USED_RESOLUTION_SECONDS}. */
  async touch(id: string): Promise<void> {
    await this.db
      .update(apiKeys)
      .set({ lastUsedAt: sql`now()` })
      .where(
        and(
          eq(apiKeys.id, id),
          or(
            isNull(apiKeys.lastUsedAt),
            lt(
              apiKeys.lastUsedAt,
              sql`now() - make_interval(secs => ${LAST_USED_RESOLUTION_SECONDS})`,
            ),
          ),
        ),
      );
  }
}
