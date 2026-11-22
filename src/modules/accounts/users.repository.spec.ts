import type { Database } from '@darmawanweb/ais-its-nest/db';
import { DrizzleQueryError } from 'drizzle-orm/errors';
import { describe, expect, it } from 'vitest';

import { SanitizedDatabaseError } from '../../db/errors.js';
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

describe('UsersRepository writes (no password hash in errors)', () => {
  const repository = new UsersRepository(failingDatabase());

  it.each([
    [
      'setPassword',
      () => repository.setPassword('id', HASH, 'active'),
      'Storing the password failed',
    ],
    [
      'rehashPassword',
      () => repository.rehashPassword('id', 'old', HASH),
      'Rehashing the password failed',
    ],
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
      'Creating the user failed',
    ],
    [
      'setMfa',
      () => repository.setMfa('id', { secretEnc: 'v1.x.y.z', enabled: true }),
      'Storing the MFA secret failed',
    ],
  ])('%s rethrows a sanitized error', async (_name, write, message) => {
    const error: unknown = await write().then(
      () => undefined,
      (reason: unknown) => reason,
    );
    expect(error).toBeInstanceOf(SanitizedDatabaseError);
    expect((error as Error).message).toContain(message);
    expect(JSON.stringify(error)).not.toContain('argon2');
    expect((error as Error).message).not.toContain('argon2');
  });
});
