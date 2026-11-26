import { Module } from '@nestjs/common';

import { AccountsModule } from '../accounts/accounts.module.js';
import { ApiKeysModule } from '../api-keys/api-keys.module.js';
import { CryptoModule } from '../crypto/crypto.module.js';
import { PasswordsModule } from '../passwords/passwords.module.js';
import { HousekeepingJob } from './housekeeping.job.js';
import { PlatformBootstrap } from './platform-bootstrap.service.js';

/** First-boot bootstrap and periodic housekeeping. */
@Module({
  imports: [AccountsModule, ApiKeysModule, CryptoModule, PasswordsModule],
  providers: [PlatformBootstrap, HousekeepingJob],
})
export class BootstrapModule {}
