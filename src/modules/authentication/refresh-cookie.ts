import { InjectConfig } from '@darmawanweb/ais-its-nest';
import type { CookieSerializeOptions } from '@fastify/cookie';
import { Injectable } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';

import { type Config, cookieSecure } from '../../config.js';
import {
  clearedRefreshCookieAttributes,
  REFRESH_COOKIE_NAME,
  refreshCookieAttributes,
} from '../../domain/refresh-cookie.js';

/** Reads, sets and clears the refresh token cookie (`@fastify/cookie`, registered by the bootstrap). */
@Injectable()
export class RefreshCookieJar {
  private readonly secure: boolean;

  constructor(@InjectConfig() private readonly config: Config) {
    this.secure = cookieSecure(config);
  }

  /** The presented refresh token, if any. */
  read(request: FastifyRequest): string | undefined {
    const value = request.cookies[REFRESH_COOKIE_NAME];
    return value === '' ? undefined : value;
  }

  /** Sets (or replaces) the cookie. */
  set(reply: FastifyReply, token: string): void {
    const options: CookieSerializeOptions = {
      ...refreshCookieAttributes(
        this.secure,
        this.config.REFRESH_TOKEN_TTL_DAYS,
      ),
    };
    reply.setCookie(REFRESH_COOKIE_NAME, token, options);
  }

  /** Deletes the cookie. */
  clear(reply: FastifyReply): void {
    const options: CookieSerializeOptions = {
      ...clearedRefreshCookieAttributes(this.secure),
    };
    reply.setCookie(REFRESH_COOKIE_NAME, '', options);
  }
}
