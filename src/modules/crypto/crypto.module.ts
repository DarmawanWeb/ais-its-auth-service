import { Module } from '@nestjs/common';

import { KeyEncryption } from './key-encryption.service.js';
import { PasswordHasher } from './password-hasher.service.js';

/** Password hashing and encryption of secrets at rest. */
@Module({
  providers: [KeyEncryption, PasswordHasher],
  exports: [KeyEncryption, PasswordHasher],
})
export class CryptoModule {}
