import { sanitizeError } from '@darmawanweb/ais-its-nest/db';
import type { Logger } from '@nestjs/common';

/**
 * The message of a failure as it may be logged: for a database error the
 * driver's primary message (drizzle's own message lists every bound value,
 * e.g. the e-mail address of a forgot-password lookup), else the message.
 */
export function failureMessage(error: unknown): string {
  const sanitized = sanitizeError(error);
  return sanitized instanceof Error ? sanitized.message : String(sanitized);
}

/**
 * Work a request starts but does not wait for — the forgot-password lookup
 * and e-mail, whose duration must not show in the response time (user
 * enumeration). Failures are logged instead of rejecting anything, and
 * {@link drain} waits for the tasks in flight, so a graceful shutdown
 * (`beforeApplicationShutdown`, before NATS drains and the pool closes in
 * `onApplicationShutdown`) never cuts a started e-mail request off.
 */
export class BackgroundWork {
  private readonly pending = new Set<Promise<void>>();

  constructor(private readonly logger: Logger) {}

  /** Number of tasks in flight. */
  get size(): number {
    return this.pending.size;
  }

  /** Starts `work` without awaiting it; `description` names it in the failure log. */
  run(description: string, work: () => Promise<void>): void {
    const task: Promise<void> = Promise.resolve()
      .then(work)
      .catch((error: unknown) => {
        this.logger.error(
          { err: sanitizeError(error) },
          `${description} failed: ${failureMessage(error)}`,
        );
      })
      .finally(() => {
        this.pending.delete(task);
      });
    this.pending.add(task);
  }

  /** Resolves once every task — including tasks started while draining — has settled. */
  async drain(): Promise<void> {
    while (this.pending.size > 0) await Promise.allSettled([...this.pending]);
  }
}
