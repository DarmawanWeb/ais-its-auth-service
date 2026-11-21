import { type Database, InjectDb } from '@darmawanweb/ais-its-nest/db';
import { Injectable } from '@nestjs/common';
import {
  and,
  count,
  desc,
  eq,
  ilike,
  inArray,
  or,
  type SQL,
  sql,
} from 'drizzle-orm';

import {
  escapeLikePattern,
  type Executor,
  type UserRow,
} from '../../db/database.js';
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

/** Drizzle access to `users`. E-mails are stored normalized (lowercase). */
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

  /** Several users by id (unknown ids are skipped). */
  async findByIds(ids: readonly string[]): Promise<UserRow[]> {
    if (ids.length === 0) return [];
    return this.db
      .select()
      .from(users)
      .where(inArray(users.id, [...ids]));
  }

  /** Inserts a user; a taken e-mail violates {@link USER_EMAIL_CONSTRAINT}. */
  async insert(user: NewUser, executor: Executor = this.db): Promise<UserRow> {
    const [row] = await executor.insert(users).values(user).returning();
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

  /** Sets the password (and optionally the status, e.g. invited → active). */
  async setPassword(
    id: string,
    passwordHash: string,
    status: UserStatus | undefined,
    executor: Executor = this.db,
  ): Promise<void> {
    await executor
      .update(users)
      .set({
        passwordHash,
        ...(status === undefined ? {} : { status }),
        updatedAt: sql`now()`,
      })
      .where(eq(users.id, id));
  }

  /** Changes the status; `undefined` when no user matched. */
  async setStatus(
    id: string,
    status: UserStatus,
    executor: Executor = this.db,
  ): Promise<UserRow | undefined> {
    const [row] = await executor
      .update(users)
      .set({ status, updatedAt: sql`now()` })
      .where(eq(users.id, id))
      .returning();
    return row;
  }

  /** Changes the display name; `undefined` when no user matched. */
  async setName(id: string, name: string): Promise<UserRow | undefined> {
    const [row] = await this.db
      .update(users)
      .set({ name, updatedAt: sql`now()` })
      .where(eq(users.id, id))
      .returning();
    return row;
  }

  /** Records a successful sign-in. */
  async recordLogin(id: string): Promise<void> {
    await this.db
      .update(users)
      .set({ lastLoginAt: sql`now()` })
      .where(eq(users.id, id));
  }

  /**
   * Stores a sealed MFA secret: pending (`enabled = false`, after setup) or
   * active (`enabled = true`, after the first valid code); `null` clears it.
   */
  async setMfa(
    id: string,
    mfa: { readonly secretEnc: string | null; readonly enabled: boolean },
  ): Promise<void> {
    await this.db
      .update(users)
      .set({
        mfaSecretEnc: mfa.secretEnc,
        mfaEnabled: mfa.enabled,
        updatedAt: sql`now()`,
      })
      .where(eq(users.id, id));
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
