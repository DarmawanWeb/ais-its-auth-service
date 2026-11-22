import {
  API_KEY_SCOPES,
  type ApiKeyScope,
} from '@darmawanweb/ais-its-contracts/auth';
import { PageQueryDto } from '@darmawanweb/ais-its-nest/http';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import {
  ArrayMaxSize,
  ArrayMinSize,
  ArrayUnique,
  IsArray,
  IsBoolean,
  IsIn,
  IsOptional,
  IsString,
  IsUUID,
  Length,
} from 'class-validator';

import { TrimmedInput } from '../../../common/dto.js';
import type { ApiKeyRow } from '../../../db/database.js';

/** An API key on the wire (never its secret or hash). */
export class ApiKeyDto {
  @ApiProperty({ format: 'uuid' })
  readonly id: string;

  @ApiProperty({ format: 'uuid' })
  readonly orgId: string;

  @ApiProperty({ example: 'AIS pusher Batam' })
  readonly name: string;

  @ApiProperty({
    example: 'sk_7Hq2LmZx9a',
    description: 'Public part of the key (sk_<id>)',
  })
  readonly prefix: string;

  @ApiProperty({ enum: API_KEY_SCOPES, isArray: true })
  readonly scopes: string[];

  @ApiProperty({ type: String, format: 'uuid', nullable: true })
  readonly createdBy: string | null;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  readonly lastUsedAt: string | null;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  readonly revokedAt: string | null;

  @ApiProperty({ format: 'date-time' })
  readonly createdAt: string;

  constructor(row: ApiKeyRow) {
    this.id = row.id;
    this.orgId = row.orgId;
    this.name = row.name;
    this.prefix = row.prefix;
    this.scopes = [...row.scopes];
    this.createdBy = row.createdBy;
    this.lastUsedAt = row.lastUsedAt?.toISOString() ?? null;
    this.revokedAt = row.revokedAt?.toISOString() ?? null;
    this.createdAt = row.createdAt.toISOString();
  }
}

/** A new key with its secret. */
export class ApiKeyWithSecretDto extends ApiKeyDto {
  @ApiProperty({
    example: 'sk_7Hq2LmZx9a_9vQ4hD2kP0sWmX7cBnR5tY1uE3oL8aZ6',
    description: 'The full key: shown once, store it now',
  })
  readonly key: string;

  constructor(row: ApiKeyRow, key: string) {
    super(row);
    this.key = key;
  }
}

/** Result of `POST /api-keys` (spec §13.1: `{ apiKey: { …, key } }`). */
export class CreatedApiKeyDto {
  @ApiProperty({ type: ApiKeyWithSecretDto })
  readonly apiKey: ApiKeyWithSecretDto;

  constructor(row: ApiKeyRow, key: string) {
    this.apiKey = new ApiKeyWithSecretDto(row, key);
  }
}

/** `POST /api-keys`. */
export class CreateApiKeyDto {
  @ApiProperty({ minLength: 1, maxLength: 100, example: 'AIS pusher Batam' })
  @TrimmedInput()
  @IsString()
  @Length(1, 100)
  readonly name!: string;

  @ApiProperty({
    enum: API_KEY_SCOPES,
    isArray: true,
    minItems: 1,
    uniqueItems: true,
    description:
      'ais:ingest (writes the AIS feed shared by every tenant) is granted by super admins only (403 SCOPE_NOT_GRANTABLE otherwise); org_admins grant telemetry:ingest and ais:read',
  })
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(API_KEY_SCOPES.length)
  @ArrayUnique()
  @IsIn(API_KEY_SCOPES, { each: true })
  readonly scopes!: ApiKeyScope[];

  @ApiPropertyOptional({
    format: 'uuid',
    description:
      'Owning organization (super admins); others create keys in their active organization',
  })
  @IsOptional()
  @IsUUID()
  readonly orgId?: string;
}

/** Query of `GET /api-keys`. */
export class ListApiKeysQuery extends PageQueryDto {
  @ApiPropertyOptional({
    format: 'uuid',
    description: 'Organization (super admins; others see their active one)',
  })
  @IsOptional()
  @IsUUID()
  readonly orgId?: string;

  @ApiPropertyOptional({ default: false, description: 'Include revoked keys' })
  @IsOptional()
  @Transform(({ value }: { value: unknown }) =>
    value === 'true' ? true : value === 'false' ? false : value,
  )
  @IsBoolean()
  readonly includeRevoked: boolean = false;
}

/** `POST /internal/api-keys/introspect`. */
export class IntrospectApiKeyDto {
  @ApiProperty({ description: 'The presented X-API-Key value' })
  @IsString()
  @Length(1, 256)
  readonly key!: string;
}

/** Introspection result: `{ active: true, keyId, orgId, scopes, name }` or `{ active: false }`. */
export class ApiKeyIntrospectionDto {
  @ApiProperty()
  readonly active!: boolean;

  @ApiPropertyOptional({ format: 'uuid' })
  readonly keyId?: string;

  @ApiPropertyOptional({ format: 'uuid' })
  readonly orgId?: string;

  @ApiPropertyOptional({ enum: API_KEY_SCOPES, isArray: true })
  readonly scopes?: string[];

  @ApiPropertyOptional()
  readonly name?: string;
}
