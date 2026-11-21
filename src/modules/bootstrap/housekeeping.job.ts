import {
  type BeforeApplicationShutdown,
  Injectable,
  Logger,
  type OnApplicationBootstrap,
} from '@nestjs/common';

import { PeriodicTask } from '../../common/periodic-task.js';
import { SessionsRepository } from '../accounts/sessions.repository.js';
import { ResetTokensRepository } from '../passwords/reset-tokens.repository.js';

/** How often the job runs, ms. */
export const HOUSEKEEPING_INTERVAL_MS = 60 * 60_000;

/** How long ended sessions and expired tokens are kept for investigations, ms. */
export const ENDED_RECORDS_RETENTION_MS = 30 * 86_400_000;

/**
 * Hourly cleanup: refresh tokens and sessions that ended, and reset or
 * invitation tokens that expired, more than {@link ENDED_RECORDS_RETENTION_MS}
 * ago (the audit log keeps the history).
 */
@Injectable()
export class HousekeepingJob
  implements OnApplicationBootstrap, BeforeApplicationShutdown
{
  private readonly logger = new Logger('Housekeeping');
  private readonly task: PeriodicTask;

  constructor(
    private readonly sessions: SessionsRepository,
    private readonly resetTokens: ResetTokensRepository,
  ) {
    this.task = new PeriodicTask(
      'Housekeeping',
      HOUSEKEEPING_INTERVAL_MS,
      () => this.run(),
      this.logger,
    );
  }

  onApplicationBootstrap(): void {
    this.task.start();
  }

  async beforeApplicationShutdown(): Promise<void> {
    await this.task.stop();
  }

  /** One cleanup pass. */
  async run(now: Date = new Date()): Promise<void> {
    const before = new Date(now.getTime() - ENDED_RECORDS_RETENTION_MS);
    const { tokens, sessions } = await this.sessions.prune(before);
    const resetTokens = await this.resetTokens.prune(before);
    if (tokens + sessions + resetTokens > 0) {
      this.logger.log(
        `Removed ${tokens} refresh tokens, ${sessions} sessions and ${resetTokens} reset tokens ended before ${before.toISOString()}`,
      );
    }
  }
}
