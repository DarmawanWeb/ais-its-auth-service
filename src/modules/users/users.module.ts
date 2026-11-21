import { Module } from '@nestjs/common';

import { AccountsModule } from '../accounts/accounts.module.js';
import { MeController, UsersController } from './users.controller.js';
import { UsersService } from './users.service.js';

/** `/me` and the user directory `/users`. */
@Module({
  imports: [AccountsModule],
  controllers: [MeController, UsersController],
  providers: [UsersService],
})
export class UsersModule {}
