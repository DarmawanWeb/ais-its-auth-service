import { InjectConfig } from '@darmawanweb/ais-its-nest';
import {
  type BeforeApplicationShutdown,
  Injectable,
  Logger,
  type OnApplicationBootstrap,
} from '@nestjs/common';

import { PeriodicTask } from '../../common/periodic-task.js';
import type { Config } from '../../config.js';
import { retirementGraceSeconds } from '../../domain/signing-key-rules.js';
import { SigningKeyStore } from './signing-key.store.js';

/** How often retiring keys are checked, ms. */
export const KEY_RETIREMENT_INTERVAL_MS = 60_000;

/**
 * Retires keys that were rotated out more than `ACCESS_TOKEN_TTL` (plus the
 * verifiers' clock tolerance and the key cache refresh) ago, removing them
 * from the JWKS (spec §13.1). Every replica runs it; the update is
 * idempotent.
 */
@Injectable()
export class KeyRetirementJob
  implements OnApplicationBootstrap, BeforeApplicationShutdown
{
  private readonly task: PeriodicTask;

  constructor(
    private readonly keys: SigningKeyStore,
    @InjectConfig() config: Config,
  ) {
    const graceSeconds = retirementGraceSeconds(config.ACCESS_TOKEN_TTL);
    this.task = new PeriodicTask(
      'Signing key retirement',
      KEY_RETIREMENT_INTERVAL_MS,
      async () => {
        await this.keys.retireExpired(graceSeconds);
      },
      new Logger('KeyRetirement'),
    );
  }

  onApplicationBootstrap(): void {
    this.task.start();
  }

  async beforeApplicationShutdown(): Promise<void> {
    await this.task.stop();
  }

  /** Runs one retirement pass now (operations, tests). */
  runOnce(): Promise<void> {
    return this.task.runOnce();
  }
}
