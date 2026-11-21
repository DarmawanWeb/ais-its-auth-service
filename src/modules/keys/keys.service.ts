import {
  type AuditRequest,
  AuditService,
} from '@darmawanweb/ais-its-nest/audit';
import type { Principal } from '@darmawanweb/ais-its-nest/auth';
import { Injectable } from '@nestjs/common';

import { assertPlatformAdmin } from '../../common/principals.js';
import { type KeyRotation, SigningKeyStore } from './signing-key.store.js';

/** Signing key administration (spec §13.1 `POST /auth/keys/rotate`). */
@Injectable()
export class KeysService {
  constructor(
    private readonly keys: SigningKeyStore,
    private readonly audit: AuditService,
  ) {}

  /** Rotates the signing key; super admins only. */
  async rotate(
    principal: Principal,
    request?: AuditRequest,
  ): Promise<KeyRotation> {
    const admin = assertPlatformAdmin(principal);
    const rotation = await this.keys.rotate();
    await this.audit.record(
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
