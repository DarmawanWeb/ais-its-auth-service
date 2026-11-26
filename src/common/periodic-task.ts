import { sanitizeError } from '@darmawanweb/ais-its-nest/db';
import type { Logger } from '@nestjs/common';

import { failureMessage } from './background-work.js';

/**
 * A background job run every `intervalMs` (key retirement, housekeeping):
 * runs never overlap, failures are logged (sanitized: a database error never
 * shows the values its statement bound) and retried at the next tick, and
 * the timer never keeps the process alive. Start it in
 * `onApplicationBootstrap` and stop it in `beforeApplicationShutdown`.
 */
export class PeriodicTask {
  private timer: NodeJS.Timeout | undefined;
  private running: Promise<void> | undefined;

  constructor(
    private readonly name: string,
    private readonly intervalMs: number,
    private readonly work: () => Promise<void>,
    private readonly logger: Logger,
  ) {}

  /** Schedules the job (idempotent). */
  start(): void {
    if (this.timer !== undefined) return;
    this.timer = setInterval(() => {
      void this.runOnce();
    }, this.intervalMs);
    this.timer.unref();
  }

  /** Cancels the schedule and waits for a run in progress. */
  async stop(): Promise<void> {
    clearInterval(this.timer);
    this.timer = undefined;
    await this.running;
  }

  /** Runs the job now unless a run is in progress. */
  runOnce(): Promise<void> {
    this.running ??= this.work()
      .catch((error: unknown) => {
        this.logger.warn(
          { err: sanitizeError(error) },
          `${this.name} failed: ${failureMessage(error)}`,
        );
      })
      .finally(() => {
        this.running = undefined;
      });
    return this.running;
  }
}
