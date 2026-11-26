import { createLogger } from '@darmawanweb/ais-its-nest';
import { DrizzleQueryError } from 'drizzle-orm/errors';
import { describe, expect, it } from 'vitest';

import { logPoolError, runCliTask } from './cli.js';

const SEALED_SECRET =
  'v1.bDwLvyFTlIxWJsBm.2ojiNYdCBEJFzGCRr7Leuw.HBePlboxnQeevHhwgh7Lru2n-o4_H7_vA5QSIaePP5c';
const PASSWORD_HASH =
  '$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA';

/** The kit's JSON logger writing into `lines` (what the CLI really prints). */
function capturedLogger() {
  const lines: string[] = [];
  const logger = createLogger(
    { service: 'auth', level: 'info', pretty: false },
    { write: (line: string) => lines.push(line) },
  );
  return { logger, lines };
}

/** drizzle's error for a failed write: every bound value in message and params. */
function failedWrite(params: unknown[]): DrizzleQueryError {
  return new DrizzleQueryError(
    'update "auth"."users" set "mfa_secret_enc" = $1 where "users"."id" = $2',
    params,
    Object.assign(new Error('review: forced failure'), {
      code: 'P0001',
      severity: 'ERROR',
      detail: `Failing row contains (${String(params[0])})`,
    }),
  );
}

describe('runCliTask', () => {
  it('logs a database failure without the values its statement bound and exits with 1', async () => {
    const { logger, lines } = capturedLogger();
    const exit: { exitCode?: number } = {};
    const userId = 'a1fe4287-7014-4688-89e3-f5cba83a33e8';

    const succeeded = await runCliTask(
      logger,
      'Rotating KEY_ENCRYPTION_SECRET failed',
      () => Promise.reject(failedWrite([SEALED_SECRET, userId])),
      exit,
    );

    expect(succeeded).toBe(false);
    expect(exit.exitCode).toBe(1);
    expect(lines).toHaveLength(1);
    const output = lines.join('');
    expect(output).not.toContain(SEALED_SECRET);
    expect(output).not.toContain(userId);
    const logged = JSON.parse(output) as {
      msg: string;
      err: { type: string; message: string; code: string; stack: string };
    };
    expect(logged.msg).toBe('Rotating KEY_ENCRYPTION_SECRET failed');
    expect(logged.err).toMatchObject({
      type: 'SanitizedDatabaseError',
      message: 'review: forced failure',
      code: 'P0001',
    });
    expect(logged.err.stack).not.toContain('params:');
  });

  it('keeps a failure wrapping a database error free of its values too', async () => {
    const { logger, lines } = capturedLogger();
    const exit: { exitCode?: number } = {};
    const wrapped = new Error('Seeding the users failed', {
      cause: failedWrite(['demo@example.com', PASSWORD_HASH]),
    });

    await runCliTask(
      logger,
      'Seeding the demo data failed',
      () => Promise.reject(wrapped),
      exit,
    );

    expect(exit.exitCode).toBe(1);
    const output = lines.join('');
    expect(output).toContain('Seeding the users failed');
    expect(output).not.toContain(PASSWORD_HASH);
    expect(output).not.toContain('$argon2id$');
    expect(output).not.toContain('demo@example.com');
  });

  it('leaves the exit code alone when the work succeeds', async () => {
    const { logger, lines } = capturedLogger();
    const exit: { exitCode?: number } = {};
    expect(
      await runCliTask(logger, 'never', () => Promise.resolve(), exit),
    ).toBe(true);
    expect(exit.exitCode).toBeUndefined();
    expect(lines).toHaveLength(0);
  });

  it('logs pool errors sanitized', () => {
    const { logger, lines } = capturedLogger();
    logPoolError(logger)(failedWrite([SEALED_SECRET, 'x']));
    expect(lines.join('')).not.toContain(SEALED_SECRET);
    expect(JSON.parse(lines.join(''))).toMatchObject({
      msg: 'Database pool error',
    });
  });
});
