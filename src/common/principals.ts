import { ForbiddenError } from '@darmawanweb/ais-its-nest';
import type { Principal, UserPrincipal } from '@darmawanweb/ais-its-nest/auth';

import { normalizeClientIp } from '../domain/client-ip.js';

/**
 * The user behind a request. The auth service accepts no API keys on its
 * routes (`AuthModule.forRoot({ apiKeys: false })`), so this only guards the
 * type; a key principal would be refused with `403`.
 */
export function requireUser(principal: Principal): UserPrincipal {
  if (principal.kind !== 'user') {
    throw new ForbiddenError('This operation needs a signed-in user');
  }
  return principal;
}

/** Throws `403 FORBIDDEN` unless the principal is a super admin (spec §13.1 `[super_admin]`). */
export function assertPlatformAdmin(principal: Principal): UserPrincipal {
  const user = requireUser(principal);
  if (!user.isPlatformAdmin) {
    throw new ForbiddenError('Only platform administrators may do this', {
      extra: { requiredRole: 'super_admin' },
    });
  }
  return user;
}

/** Client facts of a request recorded with sessions. */
export interface ClientInfo {
  /** A valid IPv4/IPv6 address (`sessions.ip` is `inet`), else `null`. */
  readonly ip: string | null;
  readonly userAgent: string | null;
}

/** The request facts {@link clientInfo} reads. */
export interface ClientRequestFacts {
  readonly ip?: string | undefined;
  readonly headers?:
    Readonly<Record<string, string | string[] | undefined>> | undefined;
}

/** Longest stored user agent (`sessions.user_agent`). */
const USER_AGENT_MAX_LENGTH = 512;

/**
 * The client IP (`X-Forwarded-For` from trusted proxies only, see
 * `TRUSTED_PROXIES`), normalized by {@link normalizeClientIp} (`null` for a
 * malformed value), and the user agent. Sessions and every throttle key use
 * this value.
 */
export function clientInfo(request: ClientRequestFacts): ClientInfo {
  const agent = request.headers?.['user-agent'];
  const userAgent =
    typeof agent === 'string' && agent !== ''
      ? agent.slice(0, USER_AGENT_MAX_LENGTH)
      : null;
  return { ip: normalizeClientIp(request.ip), userAgent };
}
