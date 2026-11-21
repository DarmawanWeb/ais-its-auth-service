import { PageQueryDto } from '@darmawanweb/ais-its-nest/http';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional, IsString, Length } from 'class-validator';

import { TrimmedInput } from '../../../common/dto.js';

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
}
