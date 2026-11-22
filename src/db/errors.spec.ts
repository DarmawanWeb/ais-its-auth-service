import { DrizzleQueryError } from 'drizzle-orm/errors';
import { describe, expect, it } from 'vitest';

import {
  isUniqueViolation,
  PG_UNIQUE_VIOLATION,
  SanitizedDatabaseError,
  withoutQueryValues,
} from './errors.js';

/** An argon2id PHC string like the ones `users.password_hash` holds. */
const HASH =
  '$argon2id$v=19$m=19456,t=2,p=1$61Cilzezl7XPnBuVRfsD+A$pWYyBgS0m3c4XrPq1y9Zt0Q8v7L2k5N6w4E3r2T1y0U';

/** What drizzle throws when `UPDATE users SET password_hash = $1 …` fails. */
function failedPasswordWrite(driver: Error): DrizzleQueryError {
  return new DrizzleQueryError(
    'update "auth"."users" set "password_hash" = $1, "updated_at" = now() where "auth"."users"."id" = $2',
    [HASH, '01a1f000-0000-7000-8000-000000000001'],
    driver,
  );
}

/** Everything a logger or a JSON response could show of an error. */
function exposedText(error: Error): string {
  return [
    error.message,
    String(error.stack),
    JSON.stringify(error),
    JSON.stringify(Object.getOwnPropertyDescriptors(error)),
    String(error.cause),
  ].join('\n');
}

/** A driver error as `pg` throws it. */
function driverError(code: string, constraint?: string): Error {
  return Object.assign(new Error('duplicate key value'), { code, constraint });
}

describe('isUniqueViolation', () => {
  it('recognizes a unique violation of the driver', () => {
    expect(isUniqueViolation(driverError(PG_UNIQUE_VIOLATION, 'x_key'))).toBe(
      true,
    );
  });

  it('looks through wrapping errors (drizzle DrizzleQueryError)', () => {
    const wrapped = new Error('Failed query', {
      cause: driverError(PG_UNIQUE_VIOLATION, 'notes_org_mmsi_title_key'),
    });
    expect(isUniqueViolation(wrapped, 'notes_org_mmsi_title_key')).toBe(true);
  });

  it('checks the constraint name when given', () => {
    expect(
      isUniqueViolation(driverError(PG_UNIQUE_VIOLATION, 'a_key'), 'b_key'),
    ).toBe(false);
  });

  it('ignores other errors and non-errors', () => {
    expect(isUniqueViolation(driverError('23503', 'fk'))).toBe(false);
    expect(isUniqueViolation(new Error('boom'))).toBe(false);
    expect(isUniqueViolation({ code: PG_UNIQUE_VIOLATION })).toBe(false);
    expect(isUniqueViolation(undefined)).toBe(false);
  });
});

describe('SanitizedDatabaseError (no secrets in logs, spec §10)', () => {
  it('drops the bound parameters, the SQL and the driver detail', () => {
    const driver = Object.assign(
      new Error('canceling statement due to statement timeout'),
      {
        code: '57014',
        detail: `Failing row contains (…, ${HASH}, active, …)`,
        table: 'users',
      },
    );
    const raw = failedPasswordWrite(driver);
    expect(exposedText(raw)).toContain(HASH);

    const sanitized = new SanitizedDatabaseError('Storing the password', raw);
    expect(sanitized.message).toBe(
      'Storing the password failed: canceling statement due to statement timeout (SQLSTATE 57014)',
    );
    expect(sanitized.code).toBe('57014');
    expect(sanitized.table).toBe('users');
    expect(sanitized.cause).toBeUndefined();
    const text = exposedText(sanitized);
    expect(text).not.toContain('argon2');
    expect(text).not.toContain('pWYyBg');
    expect(text).not.toContain('Failing row');
    expect(text).not.toContain('update "auth"');
  });

  it('keeps code and constraint so unique violations are still recognized', () => {
    const sanitized = new SanitizedDatabaseError(
      'Creating the user',
      failedPasswordWrite(driverError(PG_UNIQUE_VIOLATION, 'users_email_key')),
    );
    expect(isUniqueViolation(sanitized, 'users_email_key')).toBe(true);
    expect(isUniqueViolation(sanitized, 'other_key')).toBe(false);
  });

  it('scrubs PHC strings a driver message might echo and handles plain errors', () => {
    expect(
      new SanitizedDatabaseError(
        'Storing the password',
        new Error(`value ${HASH} is odd`),
      ).message,
    ).toBe('Storing the password failed: value [REDACTED] is odd');
    expect(new SanitizedDatabaseError('Op', 'not an error').message).toBe(
      'Op failed: unknown database error',
    );
  });

  it('wraps failed writes and passes results through', async () => {
    await expect(
      withoutQueryValues('Op', () => Promise.resolve(42)),
    ).resolves.toBe(42);
    const failure = withoutQueryValues('Storing the password', () =>
      Promise.reject(failedPasswordWrite(new Error('Connection terminated'))),
    );
    await expect(failure).rejects.toBeInstanceOf(SanitizedDatabaseError);
    await expect(failure).rejects.toThrow(
      'Storing the password failed: Connection terminated',
    );
  });
});
