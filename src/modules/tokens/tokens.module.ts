import { Module } from '@nestjs/common';

import { KeysModule } from '../keys/keys.module.js';
import { TokenService } from './token.service.js';

/** Access token and MFA challenge signing. */
@Module({
  imports: [KeysModule],
  providers: [TokenService],
  exports: [TokenService],
})
export class TokensModule {}
