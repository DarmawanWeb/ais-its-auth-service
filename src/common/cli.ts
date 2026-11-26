import { sanitizeError } from '@darmawanweb/ais-its-nest/db';

/** The part of the kit's `createLogger()` logger a CLI entry point uses. */
export interface CliLogger {
  error(details: { readonly err: unknown }, message: string): void;
}

/**
 * Runs the work of a CLI entry point (`pnpm rotate:key-secret`,
 * `pnpm seed:demo`). A failure is logged as `failureMessage` with the error
 * sanitized (kit `sanitizeError`: a database error keeps the driver's
 * message, SQLSTATE, constraint and table, never the values its statement
 * bound — sealed MFA secrets, argon2id hashes — in its message, stack or
 * fields; the kit's redaction only covers `err.params` and `err.detail`),
 * and the process exits with 1 instead of Node printing the raw rejection.
 *
 * @returns `true` when the work succeeded.
 */
export async function runCliTask(
  logger: CliLogger,
  failureMessage: string,
  work: () => Promise<void>,
  exit: { exitCode?: number | string | null | undefined } = process,
): Promise<boolean> {
  try {
    await work();
    return true;
  } catch (error) {
    logger.error({ err: sanitizeError(error) }, failureMessage);
    exit.exitCode = 1;
    return false;
  }
}

/** The pool error handler of a CLI entry point (connection errors, sanitized like {@link runCliTask}). */
export function logPoolError(logger: CliLogger): (error: Error) => void {
  return (error) => {
    logger.error({ err: sanitizeError(error) }, 'Database pool error');
  };
}
