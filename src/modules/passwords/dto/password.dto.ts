import { LOCALES, type Locale } from '@darmawanweb/ais-its-contracts/domain';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEmail,
  IsIn,
  IsOptional,
  IsString,
  Length,
  MaxLength,
} from 'class-validator';

import { EmailInput } from '../../../common/dto.js';
import {
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
} from '../../../domain/password-policy.js';

const PASSWORD_DESCRIPTION = `At least ${PASSWORD_MIN_LENGTH} characters with letters and digits (at most ${PASSWORD_MAX_LENGTH})`;

/** `POST /auth/password/forgot`. */
export class ForgotPasswordDto {
  @ApiProperty({ example: 'captain@example.com', maxLength: 320 })
  @EmailInput()
  @IsEmail()
  @MaxLength(320)
  readonly email!: string;

  @ApiPropertyOptional({ enum: LOCALES, description: 'Language of the e-mail' })
  @IsOptional()
  @IsIn(LOCALES)
  readonly locale?: Locale;
}

/** `POST /auth/password/reset` (also accepts invitations). */
export class ResetPasswordDto {
  @ApiProperty({
    description: 'Token of the e-mailed link (`#token=…`)',
    minLength: 1,
    maxLength: 128,
  })
  @IsString()
  @Length(1, 128)
  readonly token!: string;

  @ApiProperty({
    description: PASSWORD_DESCRIPTION,
    format: 'password',
    maxLength: 1024,
  })
  @IsString()
  @MaxLength(1024)
  readonly password!: string;
}

/** `POST /auth/password/change`. */
export class ChangePasswordDto {
  @ApiProperty({ format: 'password', maxLength: 1024 })
  @IsString()
  @MaxLength(1024)
  readonly currentPassword!: string;

  @ApiProperty({
    description: PASSWORD_DESCRIPTION,
    format: 'password',
    maxLength: 1024,
  })
  @IsString()
  @MaxLength(1024)
  readonly newPassword!: string;
}
