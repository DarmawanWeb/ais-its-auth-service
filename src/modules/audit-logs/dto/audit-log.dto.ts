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
import {
  IsEmail,
  IsOptional,
  IsString,
  IsUUID,
  Length,
  Matches,
  MaxLength,
} from 'class-validator';

import { EmailInput } from '../../../common/dto.js';
import type { AuditLogRow } from '../../../db/database.js';
import type { AuditActionCount } from '../audit-logs.repository.js';

/** `actionPrefix`: the start of an action, e.g. `membership.` or `auth.login`. */
export const AUDIT_ACTION_PREFIX_PATTERN = /^[a-z][a-z0-9_]*(\.[a-z0-9_]*)*$/;

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

  @ApiProperty({
    type: String,
    nullable: true,
    example: 'Siti Rahma',
    description:
      'Name of the user, or of the API key, that acted, captured when the record was stored (records stored before 0.2.0: the current name); null for system actors and unknown ids',
  })
  readonly actorName: string | null;

  @ApiProperty({
    type: String,
    nullable: true,
    example: 'siti@example.com',
    description:
      'E-mail of the acting user, captured when the record was stored (older records: the current one); null for API keys and system actors',
  })
  readonly actorEmail: string | null;

  @ApiProperty({ type: String, format: 'uuid', nullable: true })
  readonly orgId: string | null;

  @ApiProperty({
    type: String,
    nullable: true,
    example: 'PT Pelayaran Nusantara',
    description:
      'Name of the organization, captured when the record was stored (older records: the current name)',
  })
  readonly orgName: string | null;

  @ApiProperty({ example: 'vessel.update' })
  readonly action: string;

  @ApiProperty({ type: String, nullable: true, example: 'vessel' })
  readonly targetType: string | null;

  @ApiProperty({ type: String, nullable: true })
  readonly targetId: string | null;

  @ApiProperty({
    type: String,
    nullable: true,
    example: 'Siti Rahma <siti@example.com>',
    description:
      "Label of the target when the record was stored: users 'Name <e-mail>', organizations and API keys by name, invitations by address; " +
      "other services' targets by the producer's meta.targetLabel or meta.name; else null",
  })
  readonly targetLabel: string | null;

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
    this.actorName = row.actorName;
    this.actorEmail = row.actorEmail;
    this.orgId = row.orgId;
    this.orgName = row.orgName;
    this.action = row.action;
    this.targetType = row.targetType;
    this.targetId = row.targetId;
    this.targetLabel = row.targetLabel;
    this.ip = row.ip;
    this.userAgent = row.userAgent;
    this.meta = row.meta;
  }
}

/** Filters of `GET /audit-logs` and `GET /audit-logs.csv` (default range: the last 30 days). */
export class AuditLogFiltersQuery extends TimeRangeQueryDto {
  @ApiPropertyOptional({ format: 'uuid' })
  @IsOptional()
  @IsUUID()
  readonly actorId?: string;

  @ApiPropertyOptional({
    example: 'siti@example.com',
    description:
      'Records of the user with this e-mail (case-insensitive; as captured with the record, or the current one for older records)',
  })
  @IsOptional()
  @EmailInput()
  @IsEmail()
  @MaxLength(320)
  readonly actorEmail?: string;

  @ApiPropertyOptional({
    example: 'auth.login.failed',
    description: 'Exact action',
  })
  @IsOptional()
  @Matches(AUDIT_ACTION_PATTERN)
  @Length(3, 128)
  readonly action?: string;

  @ApiPropertyOptional({
    example: 'membership.',
    description:
      'Actions starting with this text, e.g. membership. for every membership action',
  })
  @IsOptional()
  @Matches(AUDIT_ACTION_PREFIX_PATTERN)
  @Length(1, 128)
  readonly actionPrefix?: string;

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

/** Query of `GET /audit-logs` (cursor-based, newest first; default range: the last 30 days). */
export class ListAuditLogsQuery extends IntersectionType(
  CursorQueryDto,
  AuditLogFiltersQuery,
) {}

/** Query of `GET /audit-logs/actions` (default range: the last 30 days, at most 366 days). */
export class ListAuditActionsQuery extends TimeRangeQueryDto {
  @ApiPropertyOptional({
    example: 'membership.',
    description: 'Only actions starting with this text',
  })
  @IsOptional()
  @Matches(AUDIT_ACTION_PREFIX_PATTERN)
  @Length(1, 128)
  readonly actionPrefix?: string;

  @ApiPropertyOptional({
    format: 'uuid',
    description:
      'Organization (super admins; others read their active organization)',
  })
  @IsOptional()
  @IsUUID()
  readonly orgId?: string;
}

/** An action recorded in the range, with its count. */
export class AuditActionDto {
  @ApiProperty({ example: 'membership.invite' })
  readonly action: string;

  @ApiProperty({
    example: 12,
    description: 'Records of the action in the range',
  })
  readonly count: number;

  @ApiProperty({
    format: 'date-time',
    description: 'Newest record of the action in the range',
  })
  readonly lastAt: string;

  constructor(entry: AuditActionCount) {
    this.action = entry.action;
    this.count = entry.count;
    this.lastAt = entry.lastAt.toISOString();
  }
}

/** Result of `GET /audit-logs/actions`: the distinct actions, by action (at most 500). */
export class AuditActionsDto {
  @ApiProperty({ type: AuditActionDto, isArray: true })
  readonly data: AuditActionDto[];

  constructor(entries: readonly AuditActionCount[]) {
    this.data = entries.map((entry) => new AuditActionDto(entry));
  }
}
