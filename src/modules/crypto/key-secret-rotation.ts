import type { Database } from '@darmawanweb/ais-its-nest/db';

import type * as schema from '../../db/schema.js';
import { SecretDecryptionError } from '../../domain/secret-box.js';
import type { UsersRepository } from '../accounts/users.repository.js';
import type { SigningKeysRepository } from '../keys/signing-keys.repository.js';
import type { KeyEncryption } from './key-encryption.service.js';

/** Counts of one re-seal pass. */
export interface KeySecretRotationResult {
  /** Signing private keys re-sealed with the current secret. */
  readonly signingKeys: number;
  /** MFA secrets re-sealed with the current secret. */
  readonly mfaSecrets: number;
  /** Values that already were sealed with the current secret. */
  readonly alreadyCurrent: number;
}

/** A stored value neither secret opens: the rotation rolls back. */
export class KeySecretRotationError extends Error {
  override readonly name = 'KeySecretRotationError';
}

/**
 * Rotation of `KEY_ENCRYPTION_SECRET` (`pnpm rotate:key-secret`): re-seals
 * every signing private key and MFA secret sealed with
 * `KEY_ENCRYPTION_SECRET_PREVIOUS` under the current secret, in one
 * transaction with the rows locked. Idempotent (current values are left
 * alone); if any value opens with neither secret nothing is changed.
 *
 * Procedure: deploy every replica with the new `KEY_ENCRYPTION_SECRET` and
 * the old one as `KEY_ENCRYPTION_SECRET_PREVIOUS` (both open, the new one
 * seals), run this, then remove `KEY_ENCRYPTION_SECRET_PREVIOUS`.
 */
export class KeySecretRotation {
  constructor(
    private readonly db: Database<typeof schema>,
    private readonly encryption: KeyEncryption,
    private readonly signingKeys: SigningKeysRepository,
    private readonly users: UsersRepository,
  ) {}

  /**
   * @throws {KeySecretRotationError} when no previous secret is configured
   *   or a stored value opens with neither secret (nothing is written).
   */
  async run(): Promise<KeySecretRotationResult> {
    if (!this.encryption.rotating) {
      throw new KeySecretRotationError(
        'Set KEY_ENCRYPTION_SECRET_PREVIOUS to the old secret (and KEY_ENCRYPTION_SECRET to the new one)',
      );
    }
    return this.db.transaction(async (tx) => {
      let signingKeys = 0;
      let mfaSecrets = 0;
      let alreadyCurrent = 0;
      for (const key of await this.signingKeys.lockAllSealed(tx)) {
        const resealed = this.resealed(
          'signing-key',
          key.privateKeyEnc,
          key.kid,
          `signing key ${key.kid}`,
        );
        if (resealed === undefined) alreadyCurrent += 1;
        else {
          await this.signingKeys.replaceSealed(key.kid, resealed, tx);
          signingKeys += 1;
        }
      }
      for (const user of await this.users.lockSealedMfaSecrets(tx)) {
        const resealed = this.resealed(
          'mfa-secret',
          user.mfaSecretEnc,
          user.id,
          `MFA secret of user ${user.id}`,
        );
        if (resealed === undefined) alreadyCurrent += 1;
        else {
          await this.users.replaceMfaSecret(user.id, resealed, tx);
          mfaSecrets += 1;
        }
      }
      return { signingKeys, mfaSecrets, alreadyCurrent };
    });
  }

  private resealed(
    purpose: 'signing-key' | 'mfa-secret',
    sealed: string,
    associatedData: string,
    label: string,
  ): string | undefined {
    try {
      return this.encryption.reseal(purpose, sealed, associatedData);
    } catch (error) {
      if (error instanceof SecretDecryptionError) {
        throw new KeySecretRotationError(
          `The ${label} opens with neither KEY_ENCRYPTION_SECRET nor KEY_ENCRYPTION_SECRET_PREVIOUS; nothing was changed`,
        );
      }
      throw error;
    }
  }
}
