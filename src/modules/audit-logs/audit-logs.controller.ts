import type { CursorPage } from '@darmawanweb/ais-its-contracts/api';
import {
  CurrentPrincipal,
  type Principal,
  RequirePermissions,
} from '@darmawanweb/ais-its-nest/auth';
import { ApiCursorResponse } from '@darmawanweb/ais-its-nest/http';
import { Controller, Get, Query } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';

import { AuditLogsService } from './audit-logs.service.js';
import { AuditLogDto, ListAuditLogsQuery } from './dto/audit-log.dto.js';

/** The central audit log: `/api/v2/audit-logs` (`audit:read`). */
@ApiTags('audit-logs')
@Controller('audit-logs')
export class AuditLogsController {
  constructor(private readonly logs: AuditLogsService) {}

  @Get()
  @RequirePermissions('audit:read')
  @ApiOperation({
    summary:
      'Audit records of the active organization (super admins: all), newest first',
  })
  @ApiCursorResponse(AuditLogDto)
  async list(
    @Query() query: ListAuditLogsQuery,
    @CurrentPrincipal() principal: Principal,
  ): Promise<CursorPage<AuditLogDto>> {
    const page = await this.logs.list(principal, query);
    return {
      data: page.data.map((row) => new AuditLogDto(row)),
      page: page.page,
    };
  }
}
