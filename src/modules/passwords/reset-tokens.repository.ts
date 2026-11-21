import { type Database, InjectDb } from '@darmawanweb/ais-its-nest/db';
import { Injectable } from '@nestjs/common';
import { and, eq, isNull, lt, sql } from 'drizzle-orm';

import type { Executor, PasswordResetTokenRow } from '../../db/database.js';
import * as schema from '../../db/schema.js';

const { passwordResetTokens } = schema;

/** Purpose of a one-time token. */
export type ResetTokenPurpose = PasswordResetTokenRow['purpose'];

/** Drizzle access to `password_reset_tokens` (hashes only). */
@Injectable()
export class ResetTokensRepository {
  constructor(@InjectDb() private readonly db: Database<typeof schema>) {}

  async insert(
    token: {
      readonly id: string;
      readonly userId: string;
      readonly tokenHash: string;
      readonly purpose: ResetTokenPurpose;
      readonly expiresAt: Date;
    },
    executor: Executor = this.db,
  ): Promise<void> {
    await executor.insert(passwordResetTokens).values(token);
  }

  /** Invalidates the user's unused tokens (a new link replaces the old ones). */
  async invalidateOpen(
    userId: string,
    executor: Executor = this.db,
  ): Promise<void> {
    await executor
      .update(passwordResetTokens)
      .set({ usedAt: sql`now()` })
      .where(
        and(
          eq(passwordResetTokens.userId, userId),
          isNull(passwordResetTokens.usedAt),
        ),
      );
  }

  /** Finds a token by hash and locks it until the end of the transaction. */
  async lockByHash(
    tokenHash: string,
    executor: Executor,
  ): Promise<PasswordResetTokenRow | undefined> {
    const [row] = await executor
      .select()
      .from(passwordResetTokens)
      .where(eq(passwordResetTokens.tokenHash, tokenHash))
      .for('update')
      .limit(1);
    return row;
  }

  /** Housekeeping: deletes tokens that expired before `before`. */
  async prune(before: Date): Promise<number> {
    const rows = await this.db
      .delete(passwordResetTokens)
      .where(lt(passwordResetTokens.expiresAt, before))
      .returning({ id: passwordResetTokens.id });
    return rows.length;
  }
}
