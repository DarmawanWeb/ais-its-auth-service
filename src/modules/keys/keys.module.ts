import { Module } from '@nestjs/common';

import { CryptoModule } from '../crypto/crypto.module.js';
import { JwksController, KeysController } from './keys.controller.js';
import { KeyRetirementJob } from './key-retirement.job.js';
import { KeysService } from './keys.service.js';
import { SigningKeyStore } from './signing-key.store.js';
import { SigningKeysRepository } from './signing-keys.repository.js';

/**
 * JWT signing keys and the JWKS (spec §8.2, §13.1). Also imported by the kit
 * `AuthModule` (see `app.module.ts`), whose verifier resolves keys through
 * {@link SigningKeyStore.keyResolver}.
 */
@Module({
  imports: [CryptoModule],
  controllers: [JwksController, KeysController],
  providers: [
    SigningKeysRepository,
    SigningKeyStore,
    KeysService,
    KeyRetirementJob,
  ],
  exports: [SigningKeyStore],
})
export class KeysModule {}
