import { Readable } from 'node:stream';

import type { CursorPage } from '@darmawanweb/ais-its-contracts/api';
import {
  CurrentPrincipal,
  type Principal,
  RequirePermissions,
} from '@darmawanweb/ais-its-nest/auth';
import { ApiCursorResponse } from '@darmawanweb/ais-its-nest/http';
import { Controller, Get, Header, Query, StreamableFile } from '@nestjs/common';
import {
  ApiOkResponse,
  ApiOperation,
  ApiProduces,
  ApiTags,
} from '@nestjs/swagger';

import {
  AUDIT_LOG_CSV_HEADER,
  AUDIT_LOG_CSV_MEDIA_TYPE,
  auditLogCsv,
  auditLogCsvFilename,
} from './audit-log-csv.js';
import { AuditLogsService } from './audit-logs.service.js';
import {
  AuditActionsDto,
  AuditLogDto,
  AuditLogFiltersQuery,
  ListAuditActionsQuery,
  ListAuditLogsQuery,
} from './dto/audit-log.dto.js';

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
    description:
      'Filters: actorId, actorEmail (case-insensitive), action (exact) or actionPrefix (e.g. membership.), targetType, ' +
      'targetId, from/to (default: the last 30 days). Records carry the names of their actor, organization and target as ' +
      'they were when the record was stored.',
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

  @Get('actions')
  @RequirePermissions('audit:read')
  @ApiOperation({
    summary:
      'The distinct actions recorded in the scope and range, with their counts (filter suggestions)',
    description:
      'Same scope as GET /audit-logs (active organization; super admins all or ?orgId). Range from/to: default the last ' +
      '30 days, at most 366 days (400 VALIDATION_FAILED beyond). Ordered by action, at most 500.',
  })
  @ApiOkResponse({ type: AuditActionsDto })
  async actions(
    @Query() query: ListAuditActionsQuery,
    @CurrentPrincipal() principal: Principal,
  ): Promise<AuditActionsDto> {
    return new AuditActionsDto(await this.logs.actions(principal, query));
  }
}

/** CSV export of the audit log: `/api/v2/audit-logs.csv` (`audit:read`). */
@ApiTags('audit-logs')
@Controller('audit-logs.csv')
export class AuditLogsExportController {
  constructor(private readonly logs: AuditLogsService) {}

  @Get()
  @RequirePermissions('audit:read')
  @Header('Cache-Control', 'no-store')
  @ApiOperation({
    summary: 'Export the audit records as CSV (compliance requests)',
    description:
      'The records of GET /audit-logs with the same filters, scope and default range (newest first) as one streamed ' +
      `RFC 4180 file (\`Content-Disposition: attachment\`): the header line \`${AUDIT_LOG_CSV_HEADER.trimEnd()}\`, CRLF ` +
      'line ends, the values of the JSON records (empty for null, meta as JSON). Text cells that start with =, +, -, @, ' +
      'tab or CR get a leading apostrophe, so spreadsheet programs never run them as formulas (OWASP CSV injection). Errors ' +
      'before the first byte are problem details; a failure during the transfer aborts the connection, so a cut file never ' +
      'looks complete.',
  })
  @ApiProduces('text/csv')
  @ApiOkResponse({
    description: `CSV file with a header line (\`Content-Type: ${AUDIT_LOG_CSV_MEDIA_TYPE}\`)`,
    content: {
      'text/csv': {
        schema: { type: 'string' },
        example: `${AUDIT_LOG_CSV_HEADER}0192f3a4-5b6c-7d8e-9f01-23456789abcd,2026-11-21T10:15:00.000Z,auth,user,0192f3a4-5b6c-7d8e-9f01-23456789abce,Siti Rahma,siti@example.com,0192f3a4-5b6c-7d8e-9f01-23456789abcf,PT Pelayaran Nusantara,membership.invite,membership_invitation,0192f3a4-5b6c-7d8e-9f01-23456789abd0,officer@example.com,203.0.113.5,Mozilla/5.0,"{""role"":""viewer""}"\r\n`,
      },
    },
  })
  async exportCsv(
    @Query() query: AuditLogFiltersQuery,
    @CurrentPrincipal() principal: Principal,
  ): Promise<StreamableFile> {
    const exported = await this.logs.export(principal, query);
    const filename = auditLogCsvFilename(
      exported.orgId,
      exported.from,
      exported.to,
    );
    return new StreamableFile(
      Readable.from(auditLogCsv(exported.batches), { objectMode: false }),
      {
        type: AUDIT_LOG_CSV_MEDIA_TYPE,
        disposition: `attachment; filename="${filename}"`,
      },
    );
  }
}
