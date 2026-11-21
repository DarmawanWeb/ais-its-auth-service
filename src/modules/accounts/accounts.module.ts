import { Module } from '@nestjs/common';

import { MembershipsRepository } from './memberships.repository.js';
import { OrganizationsRepository } from './organizations.repository.js';
import { SessionsRepository } from './sessions.repository.js';
import { UsersRepository } from './users.repository.js';

/**
 * Data access of the identity aggregate (users, organizations, memberships,
 * sessions and refresh tokens), shared by the feature modules so none of
 * them depends on another feature's internals.
 */
@Module({
  providers: [
    UsersRepository,
    OrganizationsRepository,
    MembershipsRepository,
    SessionsRepository,
  ],
  exports: [
    UsersRepository,
    OrganizationsRepository,
    MembershipsRepository,
    SessionsRepository,
  ],
})
export class AccountsModule {}
