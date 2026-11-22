import { InjectConfig } from '@darmawanweb/ais-its-nest';
import { Injectable } from '@nestjs/common';

import type { Config } from '../../config.js';
import {
  deriveKey,
  openSecret,
  resealSecret,
  SecretDecryptionError,
  sealSecret,
  type SecretPurpose,
} from '../../domain/secret-box.js';

/** The secrets {@link KeyEncryption} derives its keys from. */
export type KeyEncryptionSecrets = Pick<
  Config,
  'KEY_ENCRYPTION_SECRET' | 'KEY_ENCRYPTION_SECRET_PREVIOUS'
>;

type PurposeKeys = Readonly<Record<SecretPurpose, Buffer>>;

function keysOf(masterSecret: string): PurposeKeys {
  return {
    'signing-key': deriveKey(masterSecret, 'signing-key'),
    'mfa-secret': deriveKey(masterSecret, 'mfa-secret'),
  };
}

/**
 * Encrypts secrets at rest (signing private keys, MFA secrets) with keys
 * derived from `KEY_ENCRYPTION_SECRET` (see `domain/secret-box.ts`). Keys
 * are derived once at construction: pure computation, no I/O.
 *
 * While `KEY_ENCRYPTION_SECRET` is being rotated,
 * `KEY_ENCRYPTION_SECRET_PREVIOUS` holds the old secret: values it sealed
 * still open, new values are sealed with the current secret, and
 * `pnpm rotate:key-secret` re-seals the stored ones ({@link reseal}).
 */
@Injectable()
export class KeyEncryption {
  private readonly keys: PurposeKeys;
  private readonly previousKeys: PurposeKeys | undefined;

  constructor(@InjectConfig() config: KeyEncryptionSecrets) {
    this.keys = keysOf(config.KEY_ENCRYPTION_SECRET);
    this.previousKeys =
      config.KEY_ENCRYPTION_SECRET_PREVIOUS === undefined
        ? undefined
        : keysOf(config.KEY_ENCRYPTION_SECRET_PREVIOUS);
  }

  /** `true` while a previous secret is configured (a rotation is in progress). */
  get rotating(): boolean {
    return this.previousKeys !== undefined;
  }

  /** Seals `plaintext` with the current secret, bound to `associatedData` (the owning record's id). */
  seal(
    purpose: SecretPurpose,
    plaintext: string,
    associatedData: string,
  ): string {
    return sealSecret(this.keys[purpose], plaintext, associatedData);
  }

  /**
   * Opens a sealed value with the current secret, or the previous one
   * during a rotation.
   *
   * @throws {SecretDecryptionError} when it was sealed with another secret,
   *   modified, or belongs to another record.
   */
  open(purpose: SecretPurpose, sealed: string, associatedData: string): string {
    try {
      return openSecret(this.keys[purpose], sealed, associatedData);
    } catch (error) {
      if (
        this.previousKeys === undefined ||
        !(error instanceof SecretDecryptionError)
      )
        throw error;
      return openSecret(this.previousKeys[purpose], sealed, associatedData);
    }
  }

  /**
   * The value sealed with the current secret when the previous one sealed
   * it; `undefined` when it already is current (rotation is idempotent).
   *
   * @throws {SecretDecryptionError} when neither secret opens it, or no
   *   previous secret is configured for a value the current one cannot open.
   */
  reseal(
    purpose: SecretPurpose,
    sealed: string,
    associatedData: string,
  ): string | undefined {
    if (this.previousKeys === undefined) {
      openSecret(this.keys[purpose], sealed, associatedData);
      return undefined;
    }
    return resealSecret(
      this.keys[purpose],
      this.previousKeys[purpose],
      sealed,
      associatedData,
    );
  }
}
