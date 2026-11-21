import { Module } from '@nestjs/common';

import { AccountsModule } from '../accounts/accounts.module.js';
import { TokensModule } from '../tokens/tokens.module.js';
import { AccountSessionsService } from './account-sessions.service.js';
import { SessionService } from './session.service.js';

/** Sessions, rotating refresh tokens and the user's own session management. */
@Module({
  imports: [AccountsModule, TokensModule],
  providers: [SessionService, AccountSessionsService],
  exports: [SessionService, AccountSessionsService],
})
export class SessionsModule {}
