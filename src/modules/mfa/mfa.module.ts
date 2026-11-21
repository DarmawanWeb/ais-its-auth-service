import { Module } from '@nestjs/common';

import { AccountsModule } from '../accounts/accounts.module.js';
import { CryptoModule } from '../crypto/crypto.module.js';
import { ThrottlingModule } from '../throttling/throttling.module.js';
import { MfaService } from './mfa.service.js';

/** TOTP multi-factor authentication (endpoints in `AuthenticationModule`). */
@Module({
  imports: [AccountsModule, CryptoModule, ThrottlingModule],
  providers: [MfaService],
  exports: [MfaService],
})
export class MfaModule {}
