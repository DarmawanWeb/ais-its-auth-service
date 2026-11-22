import { type Database, InjectDb } from '@darmawanweb/ais-its-nest/db';
import { Injectable } from '@nestjs/common';
import {
  and,
  asc,
  count,
  desc,
  eq,
  ilike,
  isNotNull,
  ne,
  or,
  type SQL,
  sql,
} from 'drizzle-orm';

import {
  escapeLikePattern,
  type Executor,
  type UserRow,
} from '../../db/database.js';
import { withoutQueryValues } from '../../db/errors.js';
import * as schema from '../../db/schema.js';

const { users } = schema;

/** Status of an account. */
export type UserStatus = UserRow['status'];

/** A user to insert (the database fills the timestamps). */
export interface NewUser {
  readonly id: string;
  readonly email: string;
  readonly name: string;
  readonly passwordHash: string | null;
  readonly status: UserStatus;
  readonly isPlatformAdmin: boolean;
}

/** Filters of the user directory (`GET /users`). */
export interface UserFilter {
  /** Case-insensitive substring of the e-mail or name. */
  readonly search?: string | undefined;
  readonly status?: UserStatus | undefined;
}

/** Name of the unique index on `lower(email)` (`0001_init.sql`). */
export const USER_EMAIL_CONSTRAINT = 'users_email_key';

/**
 * Drizzle access to `users`. E-mails are stored normalized (lowercase).
 * Every write goes through `withoutQueryValues`: a failed query must not
 * put the argon2id hash or the sealed MFA secret it binds (or a row the
 * driver echoes in its `detail`) into logs or error responses.
 */
@Injectable()
export class UsersRepository {
  constructor(@InjectDb() private readonly db: Database<typeof schema>) {}

  async findById(
    id: string,
    executor: Executor = this.db,
  ): Promise<UserRow | undefined> {
    const [row] = await executor
      .select()
      .from(users)
      .where(eq(users.id, id))
      .limit(1);
    return row;
  }

  /**
   * Reads a user and locks the row until the end of the transaction
   * (`FOR UPDATE`): status checks followed by writes (reset, invitation
   * acceptance, enabling/disabling) serialize instead of losing updates.
   */
  async lockById(id: string, tx: Executor): Promise<UserRow | undefined> {
    const [row] = await tx
      .select()
      .from(users)
      .where(eq(users.id, id))
      .for('update')
      .limit(1);
    return row;
  }

  /** The user with this (normalized) e-mail. */
  async findByEmail(
    email: string,
    executor: Executor = this.db,
  ): Promise<UserRow | undefined> {
    const [row] = await executor
      .select()
      .from(users)
      .where(sql`lower(${users.email}) = lower(${email})`)
      .limit(1);
    return row;
  }

  /** Inserts a user; a taken e-mail violates {@link USER_EMAIL_CONSTRAINT}. */
  async insert(user: NewUser, executor: Executor = this.db): Promise<UserRow> {
    const [row] = await withoutQueryValues('Creating the user', () =>
      executor.insert(users).values(user).returning(),
    );
    if (row === undefined)
      throw new Error('INSERT … RETURNING returned no row');
    return row;
  }

  /** `true` when no account exists yet (bootstrap). */
  async isEmpty(executor: Executor = this.db): Promise<boolean> {
    const [row] = await executor.select({ id: users.id }).from(users).limit(1);
    return row === undefined;
  }

  /** One page of the directory, newest first, and the total. */
  async list(
    filter: UserFilter,
    page: { readonly offset: number; readonly limit: number },
  ): Promise<{ rows: UserRow[]; total: number }> {
    const where = and(...filterConditions(filter));
    const [rows, totals] = await Promise.all([
      this.db
        .select()
        .from(users)
        .where(where)
        .orderBy(desc(users.createdAt), desc(users.id))
        .limit(page.limit)
        .offset(page.offset),
      this.db.select({ total: count() }).from(users).where(where),
    ]);
    return { rows, total: totals[0]?.total ?? 0 };
  }

  /**
   * Sets the password (and optionally the status, e.g. invited → active) of
   * an account that is not disabled. The condition is part of the `UPDATE`,
   * so a disable that commits first is never overwritten.
   *
   * @returns `false` when no such account (or it is disabled).
   */
  async setPassword(
    id: string,
    passwordHash: string,
    status: UserStatus | undefined,
    executor: Executor = this.db,
  ): Promise<boolean> {
    const rows = await withoutQueryValues('Storing the password', () =>
      executor
        .update(users)
        .set({
          passwordHash,
          ...(status === undefined ? {} : { status }),
          updatedAt: sql`now()`,
        })
        .where(and(eq(users.id, id), ne(users.status, 'disabled')))
        .returning({ id: users.id }),
    );
    return rows.length > 0;
  }

  /**
   * Replaces a hash with a stronger one of the same password (argon2
   * parameters changed), only if it is still `expectedHash`: a concurrent
   * password change wins over the rehash of a sign-in with the old password.
   */
  async rehashPassword(
    id: string,
    expectedHash: string,
    passwordHash: string,
  ): Promise<boolean> {
    const rows = await withoutQueryValues('Rehashing the password', () =>
      this.db
        .update(users)
        .set({ passwordHash, updatedAt: sql`now()` })
        .where(and(eq(users.id, id), eq(users.passwordHash, expectedHash)))
        .returning({ id: users.id }),
    );
    return rows.length > 0;
  }

  /** Changes the status; `undefined` when no user matched. */
  async setStatus(
    id: string,
    status: UserStatus,
    executor: Executor = this.db,
  ): Promise<UserRow | undefined> {
    const [row] = await withoutQueryValues('Changing the status', () =>
      executor
        .update(users)
        .set({ status, updatedAt: sql`now()` })
        .where(eq(users.id, id))
        .returning(),
    );
    return row;
  }

  /** Changes the display name; `undefined` when no user matched. */
  async setName(id: string, name: string): Promise<UserRow | undefined> {
    const [row] = await withoutQueryValues('Renaming the user', () =>
      this.db
        .update(users)
        .set({ name, updatedAt: sql`now()` })
        .where(eq(users.id, id))
        .returning(),
    );
    return row;
  }

  /** Records a successful sign-in. */
  async recordLogin(id: string): Promise<void> {
    await withoutQueryValues('Recording the sign-in', () =>
      this.db
        .update(users)
        .set({ lastLoginAt: sql`now()` })
        .where(eq(users.id, id)),
    );
  }

  /**
   * Stores a sealed MFA secret: pending (`enabled = false`, after setup) or
   * active (`enabled = true`, after the first valid code); `null` clears it.
   */
  async setMfa(
    id: string,
    mfa: { readonly secretEnc: string | null; readonly enabled: boolean },
  ): Promise<void> {
    await withoutQueryValues('Storing the MFA secret', () =>
      this.db
        .update(users)
        .set({
          mfaSecretEnc: mfa.secretEnc,
          mfaEnabled: mfa.enabled,
          updatedAt: sql`now()`,
        })
        .where(eq(users.id, id)),
    );
  }

  /** Every sealed MFA secret (pending or enabled), locked for a re-seal (`pnpm rotate:key-secret`). */
  async lockSealedMfaSecrets(
    tx: Executor,
  ): Promise<{ id: string; mfaSecretEnc: string }[]> {
    const rows = await tx
      .select({ id: users.id, mfaSecretEnc: users.mfaSecretEnc })
      .from(users)
      .where(isNotNull(users.mfaSecretEnc))
      .orderBy(asc(users.id))
      .for('update');
    return rows.flatMap((row) =>
      row.mfaSecretEnc === null
        ? []
        : [{ id: row.id, mfaSecretEnc: row.mfaSecretEnc }],
    );
  }

  /** Stores a re-sealed MFA secret (the enabled flag is untouched). */
  async replaceMfaSecret(
    id: string,
    mfaSecretEnc: string,
    tx: Executor,
  ): Promise<void> {
    await withoutQueryValues('Storing the MFA secret', () =>
      tx
        .update(users)
        .set({ mfaSecretEnc, updatedAt: sql`now()` })
        .where(eq(users.id, id)),
    );
  }
}

function filterConditions(filter: UserFilter): (SQL | undefined)[] {
  const pattern =
    filter.search === undefined
      ? undefined
      : `%${escapeLikePattern(filter.search)}%`;
  return [
    pattern === undefined
      ? undefined
      : or(ilike(users.email, pattern), ilike(users.name, pattern)),
    filter.status === undefined ? undefined : eq(users.status, filter.status),
  ];
}
