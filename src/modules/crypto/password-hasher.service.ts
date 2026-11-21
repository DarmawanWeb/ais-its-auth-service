import { randomBytes } from 'node:crypto';

import { hash, parseOptions, verify } from '@node-rs/argon2';
import { Injectable } from '@nestjs/common';

import {
  ARGON2_PARAMETERS,
  needsRehash,
} from '../../domain/password-hashing.js';

/**
 * argon2id password hashing (spec §13.1, `domain/password-hashing.ts`).
 * Hashing runs on the libuv thread pool (`@node-rs/argon2`), so it never
 * blocks the event loop.
 */
@Injectable()
export class PasswordHasher {
  private dummyHash: Promise<string> | undefined;

  /** PHC string of `password` with a fresh random salt. */
  hash(password: string): Promise<string> {
    // `@node-rs/argon2` defaults to argon2id; the parameters are explicit.
    return hash(password, { ...ARGON2_PARAMETERS });
  }

  /** `true` when `password` matches `storedHash`; a malformed hash never matches. */
  async verify(storedHash: string, password: string): Promise<boolean> {
    try {
      return await verify(storedHash, password);
    } catch {
      return false;
    }
  }

  /**
   * Spends the time of one verification and returns `false`: used for
   * unknown e-mails and accounts without a password, so response times do
   * not reveal which accounts exist (user enumeration).
   */
  async verifyDummy(password: string): Promise<false> {
    this.dummyHash ??= this.hash(randomBytes(32).toString('base64url'));
    await this.verify(await this.dummyHash, password);
    return false;
  }

  /** `true` when `storedHash` was made with other parameters than the current policy. */
  needsRehash(storedHash: string): boolean {
    try {
      return needsRehash(parseOptions(storedHash));
    } catch {
      return true;
    }
  }
}
