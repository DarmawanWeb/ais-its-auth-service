import { ORG_ROLES, type OrgRole } from '@darmawanweb/ais-its-contracts/auth';
import { LOCALES, type Locale } from '@darmawanweb/ais-its-contracts/domain';
import { PageQueryDto } from '@darmawanweb/ais-its-nest/http';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEmail,
  IsIn,
  IsOptional,
  IsString,
  Length,
  Matches,
  MaxLength,
} from 'class-validator';

import { EmailInput, TrimmedInput } from '../../../common/dto.js';
import type { OrganizationRow } from '../../../db/database.js';
import {
  ORGANIZATION_KINDS,
  type OrganizationKind,
} from '../../../domain/access-rules.js';
import { SLUG_MAX_LENGTH, SLUG_PATTERN } from '../../../domain/identity.js';
import type { InvitationRecord } from '../../accounts/invitations.repository.js';
import type { MemberRecord } from '../../accounts/memberships.repository.js';

/** Kinds that can be created through the API (the platform organization comes from the bootstrap). */
export const CREATABLE_ORGANIZATION_KINDS = ORGANIZATION_KINDS.filter(
  (kind): kind is Exclude<OrganizationKind, 'platform'> => kind !== 'platform',
);

/** An organization on the wire. */
export class OrganizationDto {
  @ApiProperty({ format: 'uuid' })
  readonly id: string;

  @ApiProperty({ example: 'PT Pelayaran Nusantara' })
  readonly name: string;

  @ApiProperty({ example: 'pelayaran-nusantara' })
  readonly slug: string;

  @ApiProperty({ enum: ORGANIZATION_KINDS })
  readonly kind: string;

  @ApiProperty({ format: 'date-time' })
  readonly createdAt: string;

  @ApiProperty({ format: 'date-time' })
  readonly updatedAt: string;

  constructor(organization: OrganizationRow) {
    this.id = organization.id;
    this.name = organization.name;
    this.slug = organization.slug;
    this.kind = organization.kind;
    this.createdAt = organization.createdAt.toISOString();
    this.updatedAt = organization.updatedAt.toISOString();
  }
}

/** `POST /organizations`. */
export class CreateOrganizationDto {
  @ApiProperty({
    minLength: 1,
    maxLength: 200,
    example: 'PT Pelayaran Nusantara',
  })
  @TrimmedInput()
  @IsString()
  @Length(1, 200)
  readonly name!: string;

  @ApiPropertyOptional({
    maxLength: SLUG_MAX_LENGTH,
    description: `Unique handle matching ${SLUG_PATTERN.source}; derived from the name when omitted`,
    example: 'pelayaran-nusantara',
  })
  @IsOptional()
  @Matches(SLUG_PATTERN)
  @MaxLength(SLUG_MAX_LENGTH)
  readonly slug?: string;

  @ApiProperty({ enum: CREATABLE_ORGANIZATION_KINDS })
  @IsIn(CREATABLE_ORGANIZATION_KINDS)
  readonly kind!: Exclude<OrganizationKind, 'platform'>;
}

/** `PATCH /organizations/:id`. */
export class UpdateOrganizationDto {
  @ApiPropertyOptional({ minLength: 1, maxLength: 200 })
  @IsOptional()
  @TrimmedInput()
  @IsString()
  @Length(1, 200)
  readonly name?: string;

  @ApiPropertyOptional({ maxLength: SLUG_MAX_LENGTH })
  @IsOptional()
  @Matches(SLUG_PATTERN)
  @MaxLength(SLUG_MAX_LENGTH)
  readonly slug?: string;

  @ApiPropertyOptional({ enum: CREATABLE_ORGANIZATION_KINDS })
  @IsOptional()
  @IsIn(CREATABLE_ORGANIZATION_KINDS)
  readonly kind?: Exclude<OrganizationKind, 'platform'>;
}

/** Query of `GET /organizations`. */
export class ListOrganizationsQuery extends PageQueryDto {
  @ApiPropertyOptional({
    description: 'Case-insensitive substring of the name or slug',
  })
  @IsOptional()
  @TrimmedInput()
  @IsString()
  @Length(1, 200)
  readonly search?: string;

  @ApiPropertyOptional({ enum: ORGANIZATION_KINDS })
  @IsOptional()
  @IsIn(ORGANIZATION_KINDS)
  readonly kind?: OrganizationKind;
}

/** A member of an organization. */
export class MemberDto {
  @ApiProperty({ format: 'uuid' })
  readonly userId: string;

  @ApiProperty()
  readonly email: string;

  @ApiProperty()
  readonly name: string;

  @ApiProperty({ enum: ['active', 'invited', 'disabled'] })
  readonly status: string;

  @ApiProperty({ enum: ORG_ROLES })
  readonly role: string;

  @ApiProperty()
  readonly mfaEnabled: boolean;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  readonly lastLoginAt: string | null;

  @ApiProperty({ format: 'date-time' })
  readonly joinedAt: string;

  constructor({ membership, user }: MemberRecord) {
    this.userId = user.id;
    this.email = user.email;
    this.name = user.name;
    this.status = user.status;
    this.role = membership.role;
    this.mfaEnabled = user.mfaEnabled;
    this.lastLoginAt = user.lastLoginAt?.toISOString() ?? null;
    this.joinedAt = membership.createdAt.toISOString();
  }
}

/**
 * A pending invitation as the organization sees it: only what its admin
 * typed. Whether the address already has an account (and anything about
 * that account) stays hidden until the invitee accepts.
 */
export class InvitationDto {
  @ApiProperty({ format: 'uuid' })
  readonly id: string;

  @ApiProperty({ description: 'The invited address (normalized)' })
  readonly email: string;

  @ApiProperty({ description: 'Display name entered by the inviting admin' })
  readonly name: string;

  @ApiProperty({ enum: ORG_ROLES })
  readonly role: string;

  @ApiProperty({
    type: String,
    format: 'uuid',
    nullable: true,
    description: 'User id of the inviting admin',
  })
  readonly invitedBy: string | null;

  @ApiProperty({ format: 'date-time' })
  readonly createdAt: string;

  @ApiProperty({
    format: 'date-time',
    description: 'The link stops working at this time (send it again to renew)',
  })
  readonly expiresAt: string;

  @ApiProperty({ description: 'The link has expired' })
  readonly expired: boolean;

  constructor({ invitation, email }: InvitationRecord, now: Date = new Date()) {
    this.id = invitation.id;
    this.email = email;
    this.name = invitation.name;
    this.role = invitation.role;
    this.invitedBy = invitation.invitedBy;
    this.createdAt = invitation.createdAt.toISOString();
    this.expiresAt = invitation.expiresAt.toISOString();
    this.expired = invitation.expiresAt.getTime() <= now.getTime();
  }
}

/**
 * Result of `POST /organizations/:id/members`: the invitation, identical
 * for new addresses and existing accounts.
 */
export class SentInvitationDto extends InvitationDto {
  @ApiProperty({
    description:
      'The invitation e-mail was requested (false: the message bus failed; send the invitation again)',
  })
  readonly invitationSent: boolean;

  constructor(record: InvitationRecord, invitationSent: boolean) {
    super(record);
    this.invitationSent = invitationSent;
  }
}

/** `POST /organizations/:id/members`. */
export class InviteMemberDto {
  @ApiProperty({ example: 'officer@example.com', maxLength: 320 })
  @EmailInput()
  @IsEmail()
  @MaxLength(320)
  readonly email!: string;

  @ApiProperty({
    minLength: 1,
    maxLength: 200,
    description:
      'Display name shown to the organization until the invitee accepts (and of a new account)',
  })
  @TrimmedInput()
  @IsString()
  @Length(1, 200)
  readonly name!: string;

  @ApiProperty({ enum: ORG_ROLES })
  @IsIn(ORG_ROLES)
  readonly role!: OrgRole;

  @ApiPropertyOptional({
    enum: LOCALES,
    description: 'Language of the invitation e-mail',
  })
  @IsOptional()
  @IsIn(LOCALES)
  readonly locale?: Locale;
}

/** `PATCH /organizations/:id/members/:userId`. */
export class UpdateMemberDto {
  @ApiProperty({ enum: ORG_ROLES })
  @IsIn(ORG_ROLES)
  readonly role!: OrgRole;
}
