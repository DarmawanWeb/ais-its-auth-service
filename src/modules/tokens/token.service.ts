import { randomUUID } from 'node:crypto';

import {
  ACCESS_TOKEN_ALGORITHM,
  ACCESS_TOKEN_TYPE,
  MFA_TOKEN_TTL_SECONDS,
  type Role,
} from '@darmawanweb/ais-its-contracts/auth';
import { InjectConfig, UnauthorizedError } from '@darmawanweb/ais-its-nest';
import { Injectable } from '@nestjs/common';
import { jwtVerify, SignJWT } from 'jose';
import * as z from 'zod';

import type { Config } from '../../config.js';
import { SigningKeyStore } from '../keys/signing-key.store.js';

/** Who an access token is issued to (spec §8.2 claims). */
export interface AccessTokenSubject {
  readonly userId: string;
  readonly sessionId: string;
  /** Active organization, `null` for platform admins without one. */
  readonly orgId: string | null;
  readonly roles: readonly Role[];
  readonly email: string;
  readonly name: string;
}

/** A signed access token. */
export interface IssuedAccessToken {
  readonly accessToken: string;
  /** Lifetime in seconds (`ACCESS_TOKEN_TTL`). */
  readonly expiresIn: number;
  readonly expiresAt: Date;
}

/** Claims of an MFA challenge token. */
export interface MfaChallenge {
  readonly userId: string;
  /** Unique id of the challenge (single use). */
  readonly challengeId: string;
  readonly expiresAt: Date;
}

/** `typ` of MFA challenge tokens: never accepted as an access token. */
export const MFA_TOKEN_TYPE = 'mfa';

const MfaClaimsSchema = z.object({
  sub: z.uuid(),
  jti: z.uuid(),
  typ: z.literal(MFA_TOKEN_TYPE),
  exp: z.int().positive(),
});

/**
 * Signs the platform's JWTs with the active Ed25519 key (spec §8.2):
 *
 * - access tokens: `iss`, `aud`, `sub`, `sid`, `org`, `roles`, `email`,
 *   `name`, `typ="access"`, `iat`, `exp` (`ACCESS_TOKEN_TTL`), header `kid`;
 * - MFA challenge tokens returned by a password login when MFA is enabled:
 *   5 minutes, `typ="mfa"` and the audience `<AUTH_AUDIENCE>:mfa`, so no
 *   service accepts them as access tokens; single use is enforced by the
 *   caller through `jti`.
 */
@Injectable()
export class TokenService {
  constructor(
    private readonly keys: SigningKeyStore,
    @InjectConfig() private readonly config: Config,
  ) {}

  /** Audience of MFA challenge tokens. */
  get mfaAudience(): string {
    return `${this.config.AUTH_AUDIENCE}:mfa`;
  }

  /** Signs an access token for `subject`. */
  async issueAccessToken(
    subject: AccessTokenSubject,
    now: Date = new Date(),
  ): Promise<IssuedAccessToken> {
    const { kid, key } = await this.keys.signingKey();
    const issuedAt = Math.floor(now.getTime() / 1000);
    const expiresAt = issuedAt + this.config.ACCESS_TOKEN_TTL;
    const accessToken = await new SignJWT({
      sid: subject.sessionId,
      org: subject.orgId,
      roles: [...subject.roles],
      email: subject.email,
      name: subject.name,
      typ: ACCESS_TOKEN_TYPE,
    })
      .setProtectedHeader({ alg: ACCESS_TOKEN_ALGORITHM, kid, typ: 'JWT' })
      .setIssuer(this.config.AUTH_ISSUER)
      .setAudience(this.config.AUTH_AUDIENCE)
      .setSubject(subject.userId)
      .setIssuedAt(issuedAt)
      .setExpirationTime(expiresAt)
      .sign(key);
    return {
      accessToken,
      expiresIn: this.config.ACCESS_TOKEN_TTL,
      expiresAt: new Date(expiresAt * 1000),
    };
  }

  /** Signs a 5-minute MFA challenge for a user whose password was verified. */
  async issueMfaChallenge(
    userId: string,
    now: Date = new Date(),
  ): Promise<string> {
    const { kid, key } = await this.keys.signingKey();
    const issuedAt = Math.floor(now.getTime() / 1000);
    return new SignJWT({ typ: MFA_TOKEN_TYPE })
      .setProtectedHeader({ alg: ACCESS_TOKEN_ALGORITHM, kid, typ: 'JWT' })
      .setIssuer(this.config.AUTH_ISSUER)
      .setAudience(this.mfaAudience)
      .setSubject(userId)
      .setJti(randomUUID())
      .setIssuedAt(issuedAt)
      .setExpirationTime(issuedAt + MFA_TOKEN_TTL_SECONDS)
      .sign(key);
  }

  /**
   * Verifies an MFA challenge token.
   *
   * @throws {UnauthorizedError} `401 INVALID_TOKEN`-style `UNAUTHORIZED` when it is invalid or expired.
   */
  async verifyMfaChallenge(token: string): Promise<MfaChallenge> {
    try {
      const { payload } = await jwtVerify(token, this.keys.keyResolver, {
        issuer: this.config.AUTH_ISSUER,
        audience: this.mfaAudience,
        algorithms: [ACCESS_TOKEN_ALGORITHM],
      });
      const claims = MfaClaimsSchema.parse(payload);
      return {
        userId: claims.sub,
        challengeId: claims.jti,
        expiresAt: new Date(claims.exp * 1000),
      };
    } catch (error) {
      throw new UnauthorizedError('The MFA token is invalid or expired', {
        challenge: 'Bearer error="invalid_token"',
        cause: error,
      });
    }
  }
}
