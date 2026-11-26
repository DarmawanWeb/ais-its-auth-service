import { Module } from '@nestjs/common';

import { AccountsModule } from '../accounts/accounts.module.js';
import {
  ApiKeysController,
  InternalApiKeysController,
} from './api-keys.controller.js';
import { ApiKeysRepository } from './api-keys.repository.js';
import { ApiKeysService } from './api-keys.service.js';

/** API keys and their introspection for the other services. */
@Module({
  imports: [AccountsModule],
  controllers: [ApiKeysController, InternalApiKeysController],
  providers: [ApiKeysRepository, ApiKeysService],
  exports: [ApiKeysRepository],
})
export class ApiKeysModule {}
