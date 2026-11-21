import { Module } from '@nestjs/common';

import { AuthThrottle } from './auth-throttle.service.js';

/** Login, MFA and password throttles (Valkey). */
@Module({
  providers: [AuthThrottle],
  exports: [AuthThrottle],
})
export class ThrottlingModule {}
