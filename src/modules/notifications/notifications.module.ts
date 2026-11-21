import { Module } from '@nestjs/common';

import { EmailRequester } from './email-requester.service.js';

/** Transactional e-mail requests (`NOTIFY` stream). */
@Module({
  providers: [EmailRequester],
  exports: [EmailRequester],
})
export class NotificationsModule {}
