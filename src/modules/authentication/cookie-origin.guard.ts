import { InjectConfig } from '@darmawanweb/ais-its-nest';
import {
  type CanActivate,
  type ExecutionContext,
  Injectable,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';

import { AuthErrors } from '../../common/errors.js';
import type { Config } from '../../config.js';
import { allowedOrigins, isAllowedOrigin } from '../../domain/origin-policy.js';

/**
 * CSRF defence of the cookie endpoints (`/auth/refresh`, `/auth/logout`): a
 * request with an `Origin` header must come from `CORS_ORIGINS` or the
 * origin of `PUBLIC_BASE_URL` (`domain/origin-policy.ts`), else
 * `403 ORIGIN_NOT_ALLOWED`.
 */
@Injectable()
export class CookieOriginGuard implements CanActivate {
  private readonly allowed: ReadonlySet<string>;

  constructor(@InjectConfig() config: Config) {
    this.allowed = allowedOrigins([
      ...config.CORS_ORIGINS,
      config.PUBLIC_BASE_URL,
    ]);
  }

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<FastifyRequest>();
    const origin = request.headers.origin;
    if (!isAllowedOrigin(origin, this.allowed))
      throw AuthErrors.originNotAllowed(origin ?? 'null');
    return true;
  }
}
