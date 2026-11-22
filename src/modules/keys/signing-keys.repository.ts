import { type Database, InjectDb } from '@darmawanweb/ais-its-nest/db';
import { Injectable } from '@nestjs/common';
import { desc, eq, inArray, sql } from 'drizzle-orm';

import type { Executor, SigningKeyRow } from '../../db/database.js';
import * as schema from '../../db/schema.js';
import type { PublicSigningJwk } from '../../db/schema.js';

const { signingKeys } = schema;

/** A key to store as the new active key. */
export interface NewSigningKey {
  readonly kid: string;
  readonly publicJwk: PublicSigningJwk;
  readonly privateKeyEnc: string;
}

/** Drizzle access to `signing_keys`. */
@Injectable()
export class SigningKeysRepository {
  constructor(@InjectDb() private readonly db: Database<typeof schema>) {}

  /** Runs `work` in a transaction serialized with every other key change (advisory lock). */
  withKeyLock<T>(work: (executor: Executor) => Promise<T>): Promise<T> {
    return this.db.transaction(async (tx) => {
      await tx.execute(
        sql`SELECT pg_advisory_xact_lock(hashtext('aisits.auth.signing_keys'))`,
      );
      return work(tx);
    });
  }

  /** Every key's sealed private key, locked for a re-seal (`pnpm rotate:key-secret`). */
  async lockAllSealed(
    tx: Executor,
  ): Promise<{ kid: string; privateKeyEnc: string }[]> {
    return tx
      .select({
        kid: signingKeys.kid,
        privateKeyEnc: signingKeys.privateKeyEnc,
      })
      .from(signingKeys)
      .orderBy(signingKeys.kid)
      .for('update');
  }

  /** Stores a re-sealed private key. */
  async replaceSealed(
    kid: string,
    privateKeyEnc: string,
    tx: Executor,
  ): Promise<void> {
    await tx
      .update(signingKeys)
      .set({ privateKeyEnc })
      .where(eq(signingKeys.kid, kid));
  }

  /** Active and retiring keys (the JWKS), newest first. */
  async findPublished(): Promise<SigningKeyRow[]> {
    return this.db
      .select()
      .from(signingKeys)
      .where(inArray(signingKeys.status, ['active', 'retiring']))
      .orderBy(desc(signingKeys.createdAt));
  }

  async findActive(
    executor: Executor = this.db,
  ): Promise<SigningKeyRow | undefined> {
    const [row] = await executor
      .select()
      .from(signingKeys)
      .where(eq(signingKeys.status, 'active'))
      .limit(1);
    return row;
  }

  async insertActive(
    key: NewSigningKey,
    executor: Executor,
  ): Promise<SigningKeyRow> {
    const [row] = await executor
      .insert(signingKeys)
      .values({ ...key, status: 'active' })
      .returning();
    if (row === undefined)
      throw new Error('INSERT … RETURNING returned no row');
    return row;
  }

  /** Demotes the active key to `retiring`; returns its kid. */
  async retireActive(executor: Executor): Promise<string | undefined> {
    const [row] = await executor
      .update(signingKeys)
      .set({ status: 'retiring' })
      .where(eq(signingKeys.status, 'active'))
      .returning({ kid: signingKeys.kid });
    return row?.kid;
  }

  /**
   * Retires every `retiring` key whose successor (a key created after it)
   * is older than `graceSeconds`; returns their kids.
   */
  async retireExpired(graceSeconds: number): Promise<string[]> {
    const rows = await this.db
      .update(signingKeys)
      .set({ status: 'retired', retiredAt: sql`now()` })
      .where(
        sql`${signingKeys.status} = 'retiring' AND EXISTS (
          SELECT 1 FROM ${signingKeys} AS successor
          WHERE successor.created_at > ${signingKeys.createdAt}
            AND successor.created_at <= now() - make_interval(secs => ${graceSeconds})
        )`,
      )
      .returning({ kid: signingKeys.kid });
    return rows.map((row) => row.kid);
  }
}
