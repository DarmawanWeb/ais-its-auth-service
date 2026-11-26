import {
  type BeforeApplicationShutdown,
  Injectable,
  Logger,
  type OnApplicationBootstrap,
} from '@nestjs/common';

import { PeriodicTask } from '../../common/periodic-task.js';
import { InvitationsRepository } from '../accounts/invitations.repository.js';
import { SessionsRepository } from '../accounts/sessions.repository.js';
import { ApiKeysRepository } from '../api-keys/api-keys.repository.js';
import { ResetTokensRepository } from '../passwords/reset-tokens.repository.js';

/** How often the job runs, ms. */
export const HOUSEKEEPING_INTERVAL_MS = 60 * 60_000;

/** How long ended sessions and expired tokens are kept for investigations, ms. */
export const ENDED_RECORDS_RETENTION_MS = 30 * 86_400_000;

/**
 * Hourly cleanup: refresh tokens and sessions that ended, and reset tokens
 * and invitations that expired, more than {@link ENDED_RECORDS_RETENTION_MS}
 * ago (the audit log keeps the history); and the hashes of rotated API key
 * secrets whose grace period is over (introspection ignores them already).
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
    private readonly invitations: InvitationsRepository,
    private readonly apiKeys: ApiKeysRepository,
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
    const invitations = await this.invitations.prune(before);
    if (tokens + sessions + resetTokens + invitations > 0) {
      this.logger.log(
        `Removed ${tokens} refresh tokens, ${sessions} sessions, ${resetTokens} reset tokens and ${invitations} invitations ended before ${before.toISOString()}`,
      );
    }
    const replaced = await this.apiKeys.pruneReplacedSecrets(now);
    if (replaced > 0) {
      this.logger.log(
        `Forgot the replaced secrets of ${replaced} rotated API keys (grace period over)`,
      );
    }
  }
}
