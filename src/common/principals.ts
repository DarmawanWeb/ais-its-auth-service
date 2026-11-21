import { ForbiddenError } from '@darmawanweb/ais-its-nest';
import type { Principal, UserPrincipal } from '@darmawanweb/ais-its-nest/auth';

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
  readonly ip: string | null;
  readonly userAgent: string | null;
}

/** Longest stored user agent (`sessions.user_agent`). */
const USER_AGENT_MAX_LENGTH = 512;

/** The client IP (from trusted proxies only, see `TRUSTED_PROXIES`) and user agent. */
export function clientInfo(request: {
  readonly ip?: string | undefined;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
}): ClientInfo {
  const agent = request.headers['user-agent'];
  const userAgent =
    typeof agent === 'string' && agent !== ''
      ? agent.slice(0, USER_AGENT_MAX_LENGTH)
      : null;
  return { ip: request.ip ?? null, userAgent };
}
