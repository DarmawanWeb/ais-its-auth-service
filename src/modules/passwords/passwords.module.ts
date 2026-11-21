import { Module } from '@nestjs/common';

import { AccountsModule } from '../accounts/accounts.module.js';
import { CryptoModule } from '../crypto/crypto.module.js';
import { NotificationsModule } from '../notifications/notifications.module.js';
import { ThrottlingModule } from '../throttling/throttling.module.js';
import { InvitationService } from './invitation.service.js';
import { OneTimeTokens } from './one-time-tokens.service.js';
import { PasswordService } from './password.service.js';
import { PasswordsController } from './passwords.controller.js';
import { ResetTokensRepository } from './reset-tokens.repository.js';

/** Password reset, invitations and password changes. */
@Module({
  imports: [
    AccountsModule,
    CryptoModule,
    NotificationsModule,
    ThrottlingModule,
  ],
  controllers: [PasswordsController],
  providers: [
    ResetTokensRepository,
    OneTimeTokens,
    PasswordService,
    InvitationService,
  ],
  exports: [InvitationService, ResetTokensRepository],
})
export class PasswordsModule {}
