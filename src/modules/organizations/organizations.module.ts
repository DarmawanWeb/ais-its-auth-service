import { Module } from '@nestjs/common';

import { AccountsModule } from '../accounts/accounts.module.js';
import { PasswordsModule } from '../passwords/passwords.module.js';
import { MembersService } from './members.service.js';
import {
  InvitationsController,
  MembersController,
  OrganizationsController,
} from './organizations.controller.js';
import { OrganizationsService } from './organizations.service.js';

/** Organizations, their members and invitations. */
@Module({
  imports: [AccountsModule, PasswordsModule],
  controllers: [
    OrganizationsController,
    MembersController,
    InvitationsController,
  ],
  providers: [OrganizationsService, MembersService],
})
export class OrganizationsModule {}
