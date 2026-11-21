import { Module } from '@nestjs/common';

import { AccountsModule } from '../accounts/accounts.module.js';
import { CryptoModule } from '../crypto/crypto.module.js';
import { MfaModule } from '../mfa/mfa.module.js';
import { SessionsModule } from '../sessions/sessions.module.js';
import { ThrottlingModule } from '../throttling/throttling.module.js';
import { TokensModule } from '../tokens/tokens.module.js';
import {
  AuthController,
  MfaController,
  SessionsController,
  VerifyController,
} from './auth.controller.js';
import { AuthenticationService } from './authentication.service.js';
import { CookieOriginGuard } from './cookie-origin.guard.js';
import { ForwardAuthService } from './forward-auth.service.js';
import { RefreshCookieJar } from './refresh-cookie.js';

/** Sign-in, MFA, refresh/logout, sessions, switch-org and the gateway verify endpoint. */
@Module({
  imports: [
    AccountsModule,
    CryptoModule,
    MfaModule,
    SessionsModule,
    ThrottlingModule,
    TokensModule,
  ],
  controllers: [
    AuthController,
    VerifyController,
    SessionsController,
    MfaController,
  ],
  providers: [
    AuthenticationService,
    ForwardAuthService,
    RefreshCookieJar,
    CookieOriginGuard,
  ],
})
export class AuthenticationModule {}
