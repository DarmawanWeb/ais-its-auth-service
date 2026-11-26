import {
  type Database,
  databaseErrorInfo,
  sanitizeError,
  sqlStateOf,
} from '@darmawanweb/ais-its-nest/db';
import { DrizzleQueryError } from 'drizzle-orm/errors';
import { describe, expect, it } from 'vitest';

import type * as schema from '../../db/schema.js';
import { UsersRepository } from './users.repository.js';

const HASH =
  '$argon2id$v=19$m=19456,t=2,p=1$61Cilzezl7XPnBuVRfsD+A$pWYyBgS0m3c4XrPq1y9Zt0Q8v7L2k5N6w4E3r2T1y0U';

/**
 * A drizzle database whose every query fails the way a statement timeout
 * does: `DrizzleQueryError` with the bound parameters in its message.
 */
function failingDatabase(): Database<typeof schema> {
  const fail = (): Promise<never> =>
    Promise.reject(
      new DrizzleQueryError(
        'update "auth"."users" set "password_hash" = $1 …',
        [HASH],
        Object.assign(
          new Error('canceling statement due to statement timeout'),
          { code: '57014' },
        ),
      ),
    );
  const chain: Record<string, unknown> = {};
  for (const method of ['update', 'insert', 'set', 'values', 'where']) {
    chain[method] = () => chain;
  }
  chain.returning = fail;
  chain.then = (
    resolve: (value: unknown) => unknown,
    reject: (reason: unknown) => unknown,
  ) => fail().then(resolve, reject);
  return chain as unknown as Database<typeof schema>;
}

/**
 * The repository no longer wraps its writes (0.2.0): drizzle's error reaches
 * the kit, whose `sanitizeError` is what its problem-details filter, logger
 * and DLQ headers use. These cases pin that the secrets a write binds never
 * survive it.
 */
describe('UsersRepository writes (no password hash in sanitized errors)', () => {
  const repository = new UsersRepository(failingDatabase());

  it.each([
    ['setPassword', () => repository.setPassword('id', HASH, 'active')],
    ['rehashPassword', () => repository.rehashPassword('id', 'old', HASH)],
    [
      'insert',
      () =>
        repository.insert({
          id: 'id',
          email: 'a@example.com',
          name: 'A',
          passwordHash: HASH,
          status: 'active',
          isPlatformAdmin: false,
        }),
    ],
    [
      'setMfa',
      () => repository.setMfa('id', { secretEnc: HASH, enabled: true }),
    ],
  ])('%s: the kit sanitizes the failure', async (_name, write) => {
    const error: unknown = await write().then(
      () => undefined,
      (reason: unknown) => reason,
    );
    // The raw error carries the hash (the reason the kit sanitizes) …
    expect(error).toBeInstanceOf(DrizzleQueryError);
    expect(JSON.stringify((error as DrizzleQueryError).params)).toContain(
      'argon2',
    );
    // … what is logged and answered does not, and keeps the SQLSTATE.
    const sanitized = sanitizeError(error) as Error;
    expect(sanitized.message).toBe(
      'canceling statement due to statement timeout',
    );
    expect(sqlStateOf(sanitized)).toBe('57014');
    expect(JSON.stringify(databaseErrorInfo(error))).not.toContain('argon2');
    expect(`${sanitized.message}${sanitized.stack ?? ''}`).not.toContain(
      'argon2',
    );
    expect(JSON.stringify(sanitized)).not.toContain('argon2');
  });
});
