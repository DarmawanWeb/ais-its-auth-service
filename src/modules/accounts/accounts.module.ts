import { Module } from '@nestjs/common';

import { InvitationsRepository } from './invitations.repository.js';
import { MembershipsRepository } from './memberships.repository.js';
import { OrganizationsRepository } from './organizations.repository.js';
import { SessionsRepository } from './sessions.repository.js';
import { UsersRepository } from './users.repository.js';

/**
 * Data access of the identity aggregate (users, organizations, memberships,
 * invitations, sessions and refresh tokens), shared by the feature modules so none of
 * them depends on another feature's internals.
 */
@Module({
  providers: [
    UsersRepository,
    OrganizationsRepository,
    MembershipsRepository,
    InvitationsRepository,
    SessionsRepository,
  ],
  exports: [
    UsersRepository,
    OrganizationsRepository,
    MembershipsRepository,
    InvitationsRepository,
    SessionsRepository,
  ],
})
export class AccountsModule {}
