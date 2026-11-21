import { InjectConfig } from '@darmawanweb/ais-its-nest';
import { Injectable } from '@nestjs/common';

import type { Config } from '../../config.js';
import {
  deriveKey,
  openSecret,
  sealSecret,
  type SecretPurpose,
} from '../../domain/secret-box.js';

/**
 * Encrypts secrets at rest (signing private keys, MFA secrets) with keys
 * derived from `KEY_ENCRYPTION_SECRET` (see `domain/secret-box.ts`). Keys
 * are derived once at construction: pure computation, no I/O.
 */
@Injectable()
export class KeyEncryption {
  private readonly keys: Readonly<Record<SecretPurpose, Buffer>>;

  constructor(@InjectConfig() config: Config) {
    this.keys = {
      'signing-key': deriveKey(config.KEY_ENCRYPTION_SECRET, 'signing-key'),
      'mfa-secret': deriveKey(config.KEY_ENCRYPTION_SECRET, 'mfa-secret'),
    };
  }

  /** Seals `plaintext`, bound to `associatedData` (the owning record's id). */
  seal(
    purpose: SecretPurpose,
    plaintext: string,
    associatedData: string,
  ): string {
    return sealSecret(this.keys[purpose], plaintext, associatedData);
  }

  /**
   * Opens a sealed value.
   *
   * @throws {SecretDecryptionError} when it was sealed with another secret,
   *   modified, or belongs to another record.
   */
  open(purpose: SecretPurpose, sealed: string, associatedData: string): string {
    return openSecret(this.keys[purpose], sealed, associatedData);
  }
}
