import type { Role } from '@darmawanweb/ais-its-contracts/auth';
import { UserPrincipal } from '@darmawanweb/ais-its-nest/auth';

import type { UserRow } from '../../db/database.js';

/**
 * The principal of a user who has no access token yet (sign-in, refresh,
 * logout by cookie), so the audit record names them as the actor.
 */
export function actorOf(
  user: Pick<UserRow, 'id' | 'email' | 'name'>,
  session: { readonly id: string; readonly orgId: string | null },
  roles: readonly Role[] = [],
): UserPrincipal {
  return new UserPrincipal({
    id: user.id,
    sessionId: session.id,
    orgId: session.orgId,
    roles,
    email: user.email,
    name: user.name,
  });
}
