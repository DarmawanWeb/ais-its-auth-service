import { PageQueryDto } from '@darmawanweb/ais-its-nest/http';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsIn,
  IsOptional,
  IsString,
  IsUUID,
  Length,
} from 'class-validator';

import { TrimmedInput } from '../../../common/dto.js';

/** Most ids of one `GET /users?ids=` lookup (one page of 100). */
export const USER_IDS_MAX = 100;

/** `PATCH /me`. */
export class UpdateMeDto {
  @ApiProperty({ minLength: 1, maxLength: 200, example: 'Siti Rahma' })
  @TrimmedInput()
  @IsString()
  @Length(1, 200)
  readonly name!: string;
}

/** Statuses an administrator may set. */
export const SETTABLE_USER_STATUSES = ['active', 'disabled'] as const;

/** `PATCH /users/:id`. */
export class UpdateUserStatusDto {
  @ApiProperty({
    enum: SETTABLE_USER_STATUSES,
    description:
      'disabled revokes every session; active re-enables a disabled account',
  })
  @IsIn(SETTABLE_USER_STATUSES)
  readonly status!: (typeof SETTABLE_USER_STATUSES)[number];
}

/** Query of `GET /users`. */
export class ListUsersQuery extends PageQueryDto {
  @ApiPropertyOptional({
    description: 'Case-insensitive substring of the e-mail or name',
  })
  @IsOptional()
  @TrimmedInput()
  @IsString()
  @Length(1, 200)
  readonly search?: string;

  @ApiPropertyOptional({ enum: ['active', 'invited', 'disabled'] })
  @IsOptional()
  @IsIn(['active', 'invited', 'disabled'])
  readonly status?: 'active' | 'invited' | 'disabled';

  @ApiPropertyOptional({
    type: String,
    example:
      '0192f3a4-5b6c-7d8e-9f01-23456789abcd,0192f3a4-5b6c-7d8e-9f01-23456789abce',
    description: `Only these users: comma-separated ids, at most ${USER_IDS_MAX} (with pageSize=100 one page holds them all); unknown ids are skipped`,
  })
  @IsOptional()
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string'
      ? value
          .split(',')
          .map((id) => id.trim())
          .filter((id) => id !== '')
      : value,
  )
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(USER_IDS_MAX)
  @IsUUID('all', { each: true })
  readonly ids?: string[];

  @ApiPropertyOptional({
    format: 'uuid',
    description: 'Only members of this organization',
  })
  @IsOptional()
  @IsUUID()
  readonly orgId?: string;
}
