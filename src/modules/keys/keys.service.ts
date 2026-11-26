import type { AuditRequest } from '@darmawanweb/ais-its-nest/audit';
import type { Principal } from '@darmawanweb/ais-its-nest/auth';
import { Injectable } from '@nestjs/common';

import { requireUser } from '../../common/principals.js';
import { Transactions } from '../../db/transactions.js';
import { type KeyRotation, SigningKeyStore } from './signing-key.store.js';

/** Signing key administration (spec §13.1 `POST /auth/keys/rotate`). */
@Injectable()
export class KeysService {
  constructor(
    private readonly keys: SigningKeyStore,
    private readonly transactions: Transactions,
  ) {}

  /**
   * Rotates the signing key; super admins only (`@RequirePlatformAdmin()` on
   * the route: `403 PLATFORM_ADMIN_REQUIRED`). The rotation commits in the
   * key store's own transaction (advisory lock, cache reload); its record is
   * queued in the outbox right after (durable, not atomic with it).
   */
  async rotate(
    principal: Principal,
    request?: AuditRequest,
  ): Promise<KeyRotation> {
    const admin = requireUser(principal);
    const rotation = await this.keys.rotate();
    await this.transactions.record(
      {
        action: 'auth.signing_key.rotate',
        targetType: 'signing_key',
        targetId: rotation.kid,
        orgId: null,
        meta: { previousKid: rotation.previousKid },
      },
      admin,
      request,
    );
    return rotation;
  }
}
