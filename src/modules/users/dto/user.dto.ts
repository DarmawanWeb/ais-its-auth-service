import {
  ORG_ROLES,
  PERMISSIONS,
  ROLES,
} from '@darmawanweb/ais-its-contracts/auth';
import { ApiProperty } from '@nestjs/swagger';

import type { MembershipRow, UserRow } from '../../../db/database.js';
import { ORGANIZATION_KINDS } from '../../../domain/access-rules.js';
import type { MembershipWithOrganization } from '../../accounts/memberships.repository.js';

/** An account on the wire (never the password hash or the MFA secret). */
export class UserDto {
  @ApiProperty({ format: 'uuid' })
  readonly id: string;

  @ApiProperty({ example: 'captain@example.com' })
  readonly email: string;

  @ApiProperty({ example: 'Siti Rahma' })
  readonly name: string;

  @ApiProperty({ enum: ['active', 'invited', 'disabled'] })
  readonly status: string;

  @ApiProperty()
  readonly mfaEnabled: boolean;

  @ApiProperty({ description: 'Holds the platform role super_admin' })
  readonly isPlatformAdmin: boolean;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  readonly lastLoginAt: string | null;

  @ApiProperty({ format: 'date-time' })
  readonly createdAt: string;

  @ApiProperty({ format: 'date-time' })
  readonly updatedAt: string;

  constructor(user: UserRow) {
    this.id = user.id;
    this.email = user.email;
    this.name = user.name;
    this.status = user.status;
    this.mfaEnabled = user.mfaEnabled;
    this.isPlatformAdmin = user.isPlatformAdmin;
    this.lastLoginAt = user.lastLoginAt?.toISOString() ?? null;
    this.createdAt = user.createdAt.toISOString();
    this.updatedAt = user.updatedAt.toISOString();
  }
}

/** A membership with its organization (login response, `/me`). */
export class MembershipDto {
  @ApiProperty({ format: 'uuid' })
  readonly orgId: string;

  @ApiProperty({ example: 'PT Pelayaran Nusantara' })
  readonly orgName: string;

  @ApiProperty({ example: 'pelayaran-nusantara' })
  readonly orgSlug: string;

  @ApiProperty({ enum: ORGANIZATION_KINDS })
  readonly orgKind: string;

  @ApiProperty({ enum: ORG_ROLES })
  readonly role: string;

  @ApiProperty({ format: 'date-time' })
  readonly joinedAt: string;

  constructor({ membership, organization }: MembershipWithOrganization) {
    this.orgId = organization.id;
    this.orgName = organization.name;
    this.orgSlug = organization.slug;
    this.orgKind = organization.kind;
    this.role = membership.role;
    this.joinedAt = membership.createdAt.toISOString();
  }
}

/** `GET /me`: the account, its memberships and the access of the current token. */
export class MeDto extends UserDto {
  @ApiProperty({ type: [MembershipDto] })
  readonly memberships: MembershipDto[];

  @ApiProperty({
    type: String,
    format: 'uuid',
    nullable: true,
    description: 'Active organization of the token',
  })
  readonly activeOrgId: string | null;

  @ApiProperty({
    enum: ROLES,
    isArray: true,
    description: 'Roles of the token',
  })
  readonly roles: string[];

  @ApiProperty({
    enum: PERMISSIONS,
    isArray: true,
    description: 'Permissions of those roles',
  })
  readonly permissions: string[];

  constructor(
    user: UserRow,
    memberships: readonly MembershipWithOrganization[],
    access: {
      readonly activeOrgId: string | null;
      readonly roles: readonly string[];
      readonly permissions: Iterable<string>;
    },
  ) {
    super(user);
    this.memberships = memberships.map(
      (membership) => new MembershipDto(membership),
    );
    this.activeOrgId = access.activeOrgId;
    this.roles = [...access.roles];
    this.permissions = [...access.permissions].sort();
  }
}

/** A membership in the user directory. */
export class UserMembershipDto {
  @ApiProperty({ format: 'uuid' })
  readonly orgId: string;

  @ApiProperty({ enum: ORG_ROLES })
  readonly role: string;

  constructor(membership: MembershipRow) {
    this.orgId = membership.orgId;
    this.role = membership.role;
  }
}

/** A user of the platform directory (`GET /users`). */
export class DirectoryUserDto extends UserDto {
  @ApiProperty({ type: [UserMembershipDto] })
  readonly memberships: UserMembershipDto[];

  constructor(user: UserRow, memberships: readonly MembershipRow[]) {
    super(user);
    this.memberships = memberships.map(
      (membership) => new UserMembershipDto(membership),
    );
  }
}
