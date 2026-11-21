import { parseBearerToken } from '@darmawanweb/ais-its-contracts/auth';
import { UnauthorizedError } from '@darmawanweb/ais-its-nest';
import {
  AccessTokenVerifier,
  type UserPrincipal,
} from '@darmawanweb/ais-its-nest/auth';
import { Injectable } from '@nestjs/common';

/**
 * Traefik `forwardAuth` (spec §12, `GET /auth/verify`): validates the
 * bearer token of the original request with the local signing keys, so the
 * gateway can protect upstreams that do not verify tokens themselves
 * (legacy `/api/v1`, map tiles).
 */
@Injectable()
export class ForwardAuthService {
  constructor(private readonly verifier: AccessTokenVerifier) {}

  /**
   * The principal of an `Authorization` header.
   *
   * @throws {UnauthorizedError} `401` without, or with an invalid or expired, token.
   */
  async verify(authorization: string | undefined): Promise<UserPrincipal> {
    const token = parseBearerToken(authorization);
    if (token === null) {
      throw new UnauthorizedError('Authentication required', {
        challenge: 'Bearer',
      });
    }
    return this.verifier.verify(token);
  }
}
