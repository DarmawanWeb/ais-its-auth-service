import { Module } from '@nestjs/common';

import { AuditLogConsumer } from '../../consumers/audit-log.consumer.js';
import {
  AuditLogsController,
  AuditLogsExportController,
} from './audit-logs.controller.js';
import { AuditLogsRepository } from './audit-logs.repository.js';
import { AuditLogsService } from './audit-logs.service.js';

/** The central audit log: consumer `auth-audit`, `GET /audit-logs` (+ `/actions`) and `GET /audit-logs.csv`. */
@Module({
  controllers: [AuditLogsController, AuditLogsExportController],
  providers: [AuditLogsRepository, AuditLogsService, AuditLogConsumer],
})
export class AuditLogsModule {}
