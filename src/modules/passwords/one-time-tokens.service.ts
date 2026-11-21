import { newId } from '@darmawanweb/ais-its-contracts/domain';
import { type Database, InjectDb } from '@darmawanweb/ais-its-nest/db';
import { Injectable } from '@nestjs/common';

import type { Executor, PasswordResetTokenRow } from '../../db/database.js';
import type * as schema from '../../db/schema.js';
import {
  generateOpaqueToken,
  isOpaqueToken,
  sha256Hex,
} from '../../domain/opaque-token.js';
import {
  type ResetTokenPurpose,
  ResetTokensRepository,
} from './reset-tokens.repository.js';

/** A token handed out in an e-mail link. */
export interface IssuedOneTimeToken {
  readonly token: string;
  readonly expiresAt: Date;
}

/**
 * One-time tokens of password reset and invitation links (spec §13.1): 256
 * random bits, stored as SHA-256, valid once and until `expires_at`. A new
 * token invalidates the user's previous unused ones.
 */
@Injectable()
export class OneTimeTokens {
  constructor(
    @InjectDb() private readonly db: Database<typeof schema>,
    private readonly repository: ResetTokensRepository,
  ) {}

  /** Issues a token for `userId`, replacing the open ones. */
  async issue(
    userId: string,
    purpose: ResetTokenPurpose,
    ttlMs: number,
    now: Date = new Date(),
  ): Promise<IssuedOneTimeToken> {
    const token = generateOpaqueToken();
    const expiresAt = new Date(now.getTime() + ttlMs);
    await this.db.transaction(async (tx) => {
      await this.repository.invalidateOpen(userId, tx);
      await this.repository.insert(
        {
          id: newId(),
          userId,
          tokenHash: sha256Hex(token),
          purpose,
          expiresAt,
        },
        tx,
      );
    });
    return { token, expiresAt };
  }

  /**
   * Consumes a presented token inside the caller's transaction: returns the
   * locked row when it is unused and unexpired (and marks it used together
   * with the user's other open tokens), else `undefined`.
   */
  async consume(
    presented: string,
    executor: Executor,
    now: Date = new Date(),
  ): Promise<PasswordResetTokenRow | undefined> {
    if (!isOpaqueToken(presented)) return undefined;
    const row = await this.repository.lockByHash(
      sha256Hex(presented),
      executor,
    );
    if (row?.usedAt !== null || row.expiresAt.getTime() <= now.getTime()) {
      return undefined;
    }
    await this.repository.invalidateOpen(row.userId, executor);
    return row;
  }
}
