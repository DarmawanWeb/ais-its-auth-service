import { ROLES } from '@darmawanweb/ais-its-contracts/auth';
import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsString,
  IsUUID,
  Length,
  Matches,
  MaxLength,
} from 'class-validator';

import { EmailInput } from '../../../common/dto.js';
import { MembershipDto, UserDto } from '../../users/dto/user.dto.js';
import type { SignedIn } from '../authentication.service.js';

/** `POST /auth/login`. */
export class LoginDto {
  @ApiProperty({ example: 'admin@ais-its.local', maxLength: 320 })
  @EmailInput()
  @IsEmail()
  @MaxLength(320)
  readonly email!: string;

  @ApiProperty({ format: 'password', maxLength: 1024 })
  @IsString()
  @Length(1, 1024)
  readonly password!: string;
}

/** `POST /auth/mfa/verify`. */
export class MfaVerifyDto {
  @ApiProperty({
    description: 'mfaToken of the login response (5 minutes, single use)',
  })
  @IsString()
  @Length(1, 4096)
  readonly mfaToken!: string;

  @ApiProperty({
    example: '123456',
    description: '6-digit code of the authenticator app',
  })
  @IsString()
  @Matches(/^\d{3}[ -]?\d{3}$/)
  readonly code!: string;
}

/** `POST /auth/mfa/enable` and `/auth/mfa/disable`. */
export class MfaCodeDto {
  @ApiProperty({
    example: '123456',
    description: '6-digit code of the authenticator app',
  })
  @IsString()
  @Matches(/^\d{3}[ -]?\d{3}$/)
  readonly code!: string;
}

/** `POST /auth/switch-org`. */
export class SwitchOrganizationDto {
  @ApiProperty({ format: 'uuid' })
  @IsUUID()
  readonly orgId!: string;
}

/** A new access token. */
export class AccessTokenDto {
  @ApiProperty({ description: 'EdDSA JWT (spec §8.2)' })
  readonly accessToken: string;

  @ApiProperty({ example: 900, description: 'Lifetime in seconds' })
  readonly expiresIn: number;

  constructor(access: {
    readonly accessToken: string;
    readonly expiresIn: number;
  }) {
    this.accessToken = access.accessToken;
    this.expiresIn = access.expiresIn;
  }
}

/** Successful sign-in (the refresh token is set as the `aisits_rt` cookie). */
export class LoginResponseDto extends AccessTokenDto {
  @ApiProperty({ type: UserDto })
  readonly user: UserDto;

  @ApiProperty({ type: [MembershipDto] })
  readonly memberships: MembershipDto[];

  @ApiProperty({ type: String, format: 'uuid', nullable: true })
  readonly activeOrgId: string | null;

  constructor(signedIn: SignedIn) {
    super(signedIn.opened.access);
    this.user = new UserDto(signedIn.user);
    this.memberships = signedIn.memberships.map(
      (membership) => new MembershipDto(membership),
    );
    this.activeOrgId = signedIn.activeOrgId;
  }
}

/** Password accepted, the TOTP code is still required (`POST /auth/mfa/verify`). */
export class MfaChallengeDto {
  @ApiProperty({ enum: [true] })
  readonly mfaRequired = true as const;

  @ApiProperty({ description: '5-minute single-use challenge token' })
  readonly mfaToken: string;

  constructor(mfaToken: string) {
    this.mfaToken = mfaToken;
  }
}

/** Result of `POST /auth/switch-org`. */
export class SwitchOrganizationResponseDto extends AccessTokenDto {
  @ApiProperty({ format: 'uuid' })
  readonly activeOrgId: string;

  constructor(result: {
    readonly access: {
      readonly accessToken: string;
      readonly expiresIn: number;
    };
    readonly activeOrgId: string;
  }) {
    super(result.access);
    this.activeOrgId = result.activeOrgId;
  }
}

/** `POST /auth/mfa/setup`. */
export class MfaSetupDto {
  @ApiProperty({ description: 'Base32 secret for manual entry' })
  readonly secret: string;

  @ApiProperty({ description: 'otpauth://totp/… URI for the QR code' })
  readonly otpauthUrl: string;

  constructor(enrollment: {
    readonly secret: string;
    readonly otpauthUrl: string;
  }) {
    this.secret = enrollment.secret;
    this.otpauthUrl = enrollment.otpauthUrl;
  }
}

/** A session of the signed-in user. */
export class SessionDto {
  @ApiProperty({ format: 'uuid' })
  readonly id: string;

  @ApiProperty({
    type: String,
    format: 'uuid',
    nullable: true,
    description: 'Active organization',
  })
  readonly orgId: string | null;

  @ApiProperty({ format: 'date-time' })
  readonly createdAt: string;

  @ApiProperty({ format: 'date-time' })
  readonly lastUsedAt: string;

  @ApiProperty({ type: String, nullable: true })
  readonly ip: string | null;

  @ApiProperty({ type: String, nullable: true })
  readonly userAgent: string | null;

  @ApiProperty({ description: 'The session of the calling access token' })
  readonly current: boolean;

  constructor(view: {
    readonly session: {
      readonly id: string;
      readonly orgId: string | null;
      readonly createdAt: Date;
      readonly lastUsedAt: Date;
      readonly ip: string | null;
      readonly userAgent: string | null;
    };
    readonly current: boolean;
  }) {
    this.id = view.session.id;
    this.orgId = view.session.orgId;
    this.createdAt = view.session.createdAt.toISOString();
    this.lastUsedAt = view.session.lastUsedAt.toISOString();
    this.ip = view.session.ip;
    this.userAgent = view.session.userAgent;
    this.current = view.current;
  }
}

/** `GET /auth/verify` (the same facts are sent as `X-User-Id`, `X-Org-Id`, `X-Roles`). */
export class VerifiedTokenDto {
  @ApiProperty({ format: 'uuid' })
  readonly userId: string;

  @ApiProperty({ type: String, format: 'uuid', nullable: true })
  readonly orgId: string | null;

  @ApiProperty({ enum: ROLES, isArray: true })
  readonly roles: string[];

  constructor(principal: {
    readonly id: string;
    readonly orgId: string | null;
    readonly roles: readonly string[];
  }) {
    this.userId = principal.id;
    this.orgId = principal.orgId;
    this.roles = [...principal.roles];
  }
}
