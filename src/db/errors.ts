import { DrizzleQueryError } from 'drizzle-orm/errors';

/** SQLSTATE of a unique constraint violation. */
export const PG_UNIQUE_VIOLATION = '23505';

/**
 * `true` when `error` (or one of its causes — drizzle wraps driver errors in
 * `DrizzleQueryError`) is a PostgreSQL unique violation, optionally of the
 * named constraint.
 *
 * @example
 * catch (error) {
 *   if (isUniqueViolation(error, 'notes_org_mmsi_title_key')) throw new ConflictError(…);
 *   throw error;
 * }
 */
export function isUniqueViolation(
  error: unknown,
  constraint?: string,
): boolean {
  let current: unknown = error;
  for (let depth = 0; current instanceof Error && depth < 8; depth += 1) {
    if ('code' in current && current.code === PG_UNIQUE_VIOLATION) {
      return (
        constraint === undefined ||
        ('constraint' in current && current.constraint === constraint)
      );
    }
    current = current.cause;
  }
  return false;
}

/** argon2 PHC strings (`$argon2id$v=19$m=…$<salt>$<digest>`), scrubbed from driver messages. */
const PHC_STRING = /\$argon2[a-z]*\$[A-Za-z0-9+/=$,.-]*[A-Za-z0-9+/=]/g;

/** Text written in place of a scrubbed value. */
const SCRUBBED = '[REDACTED]';

/** A property of `error` when it is a string. */
function stringProperty(error: unknown, key: string): string | undefined {
  if (typeof error !== 'object' || error === null || !(key in error))
    return undefined;
  const value: unknown = (error as Record<string, unknown>)[key];
  return typeof value === 'string' ? value : undefined;
}

/**
 * A database error stripped of everything that can echo the values a query
 * wrote. drizzle's `DrizzleQueryError` carries every bound parameter in its
 * message (`Failed query: … params: …`) and in `params`, and the driver
 * error's `detail` repeats keys or whole rows (`Failing row contains (…)`);
 * the kit's problem-details filter logs the complete exception (and shows
 * its message outside production). Writes of secrets — argon2id password
 * hashes, sealed MFA secrets — rethrow this error instead.
 *
 * Kept: the operation, the driver's primary message (argon2 PHC strings
 * scrubbed as a safety net), the SQLSTATE `code`, `constraint` and `table`,
 * so {@link isUniqueViolation} and operators still see what failed. Dropped:
 * the SQL text, `params`, `detail`, `where` and the original cause chain.
 */
export class SanitizedDatabaseError extends Error {
  override readonly name = 'SanitizedDatabaseError';
  /** SQLSTATE of the driver error, when there was one. */
  readonly code: string | undefined;
  /** Violated constraint, when there was one. */
  readonly constraint: string | undefined;
  /** Table of the driver error, when known. */
  readonly table: string | undefined;

  constructor(operation: string, error: unknown) {
    const driver = error instanceof DrizzleQueryError ? error.cause : error;
    const reason = (
      driver instanceof Error ? driver.message : 'unknown database error'
    ).replace(PHC_STRING, SCRUBBED);
    const code = stringProperty(driver, 'code');
    super(
      `${operation} failed: ${reason}${code === undefined ? '' : ` (SQLSTATE ${code})`}`,
    );
    this.code = code;
    this.constraint = stringProperty(driver, 'constraint');
    this.table = stringProperty(driver, 'table');
  }
}

/**
 * Runs a write that binds secrets and rethrows any failure as a
 * {@link SanitizedDatabaseError}.
 *
 * @param operation what was attempted, e.g. `"Storing the password"`.
 */
export async function withoutQueryValues<T>(
  operation: string,
  write: () => Promise<T>,
): Promise<T> {
  try {
    return await write();
  } catch (error) {
    throw new SanitizedDatabaseError(operation, error);
  }
}
