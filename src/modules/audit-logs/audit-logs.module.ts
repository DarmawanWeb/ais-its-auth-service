import { Module } from '@nestjs/common';

import { AuditLogConsumer } from '../../consumers/audit-log.consumer.js';
import { AuditLogsController } from './audit-logs.controller.js';
import { AuditLogsRepository } from './audit-logs.repository.js';
import { AuditLogsService } from './audit-logs.service.js';

/** The central audit log: consumer `auth-audit` and `GET /audit-logs`. */
@Module({
  controllers: [AuditLogsController],
  providers: [AuditLogsRepository, AuditLogsService, AuditLogConsumer],
})
export class AuditLogsModule {}
