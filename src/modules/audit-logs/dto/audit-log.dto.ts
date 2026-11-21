import {
  AUDIT_ACTION_PATTERN,
  AUDIT_ACTOR_TYPES,
} from '@darmawanweb/ais-its-contracts/domain';
import {
  CursorQueryDto,
  TimeRangeQueryDto,
} from '@darmawanweb/ais-its-nest/http';
import {
  ApiProperty,
  ApiPropertyOptional,
  IntersectionType,
} from '@nestjs/swagger';
import { IsOptional, IsString, IsUUID, Length, Matches } from 'class-validator';

import type { AuditLogRow } from '../../../db/database.js';

/** An audit record on the wire. */
export class AuditLogDto {
  @ApiProperty({
    format: 'uuid',
    description: 'Id of the audit.recorded.v1 event',
  })
  readonly id: string;

  @ApiProperty({ format: 'date-time' })
  readonly at: string;

  @ApiProperty({ example: 'fleet', description: 'Producing service' })
  readonly source: string;

  @ApiProperty({ enum: AUDIT_ACTOR_TYPES })
  readonly actorType: string;

  @ApiProperty({ type: String, format: 'uuid', nullable: true })
  readonly actorId: string | null;

  @ApiProperty({ type: String, format: 'uuid', nullable: true })
  readonly orgId: string | null;

  @ApiProperty({ example: 'vessel.update' })
  readonly action: string;

  @ApiProperty({ type: String, nullable: true, example: 'vessel' })
  readonly targetType: string | null;

  @ApiProperty({ type: String, nullable: true })
  readonly targetId: string | null;

  @ApiProperty({ type: String, nullable: true })
  readonly ip: string | null;

  @ApiProperty({ type: String, nullable: true })
  readonly userAgent: string | null;

  @ApiProperty({ type: 'object', additionalProperties: true })
  readonly meta: Record<string, unknown>;

  constructor(row: AuditLogRow) {
    this.id = row.id;
    this.at = row.at.toISOString();
    this.source = row.source;
    this.actorType = row.actorType;
    this.actorId = row.actorId;
    this.orgId = row.orgId;
    this.action = row.action;
    this.targetType = row.targetType;
    this.targetId = row.targetId;
    this.ip = row.ip;
    this.userAgent = row.userAgent;
    this.meta = row.meta;
  }
}

/** Query of `GET /audit-logs` (cursor-based, newest first; default range: the last 30 days). */
export class ListAuditLogsQuery extends IntersectionType(
  CursorQueryDto,
  TimeRangeQueryDto,
) {
  @ApiPropertyOptional({ format: 'uuid' })
  @IsOptional()
  @IsUUID()
  readonly actorId?: string;

  @ApiPropertyOptional({ example: 'auth.login.failed' })
  @IsOptional()
  @Matches(AUDIT_ACTION_PATTERN)
  @Length(3, 128)
  readonly action?: string;

  @ApiPropertyOptional({ example: 'user' })
  @IsOptional()
  @IsString()
  @Length(1, 64)
  readonly targetType?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @Length(1, 128)
  readonly targetId?: string;

  @ApiPropertyOptional({
    format: 'uuid',
    description:
      'Organization (super admins; others read their active organization)',
  })
  @IsOptional()
  @IsUUID()
  readonly orgId?: string;
}
