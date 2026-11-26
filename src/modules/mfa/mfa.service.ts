import type { AuditRequest } from '@darmawanweb/ais-its-nest/audit';
import type { Principal } from '@darmawanweb/ais-its-nest/auth';
import { InjectRedis, type Redis } from '@darmawanweb/ais-its-nest/redis';
import { Injectable } from '@nestjs/common';

import { AuthErrors } from '../../common/errors.js';
import { clientInfo, requireUser } from '../../common/principals.js';
import type { UserRow } from '../../db/database.js';
import { Transactions } from '../../db/transactions.js';
import {
  generateTotpSecret,
  TOTP_PARAMETERS,
  totpProvisioningUri,
  verifyTotp,
} from '../../domain/totp.js';
import { UsersRepository } from '../accounts/users.repository.js';
import { KeyEncryption } from '../crypto/key-encryption.service.js';
import { AuthThrottle } from '../throttling/auth-throttle.service.js';

/** What an authenticator app needs (`POST /auth/mfa/setup`). */
export interface MfaEnrollment {
  /** Base32 secret for manual entry. */
  readonly secret: string;
  /** `otpauth://totp/…` URI for the QR code. */
  readonly otpauthUrl: string;
}

/** How long a used time step is remembered, seconds (covers the ±1 step window twice). */
const USED_STEP_TTL_SECONDS =
  TOTP_PARAMETERS.periodSeconds * (2 * TOTP_PARAMETERS.window + 2);

/**
 * TOTP multi-factor authentication (spec §13.1): setup stores a pending
 * secret (sealed with AES-256-GCM, bound to the user id), the first valid
 * code enables it, a valid code disables it. Every accepted code is
 * single-use: its time step is recorded in Valkey (`SET NX`), so a code seen
 * by a shoulder surfer or a phishing proxy cannot be replayed.
 */
@Injectable()
export class MfaService {
  constructor(
    private readonly users: UsersRepository,
    private readonly encryption: KeyEncryption,
    private readonly throttle: AuthThrottle,
    private readonly transactions: Transactions,
    @InjectRedis() private readonly redis: Redis,
  ) {}

  /** Starts (or restarts) the enrollment with a new pending secret. */
  async setup(principal: Principal): Promise<MfaEnrollment> {
    const user = await this.currentUser(principal);
    if (user.mfaEnabled) throw AuthErrors.mfaAlreadyEnabled();
    const secret = generateTotpSecret();
    await this.users.setMfa(user.id, {
      secretEnc: this.encryption.seal('mfa-secret', secret, user.id),
      enabled: false,
    });
    return { secret, otpauthUrl: totpProvisioningUri(secret, user.email) };
  }

  /** Enables MFA with the first code of the pending secret. */
  async enable(
    principal: Principal,
    code: string,
    request: AuditRequest & { ip?: string | undefined },
  ): Promise<void> {
    const user = await this.currentUser(principal);
    if (user.mfaEnabled) throw AuthErrors.mfaAlreadyEnabled();
    if (user.mfaSecretEnc === null) throw AuthErrors.mfaSetupRequired();
    await this.throttle.guardMfa(user.id, clientInfo(request).ip, () =>
      this.checkCode(user, code),
    );
    const secretEnc = user.mfaSecretEnc;
    await this.transactions.run(async ({ tx, audit }) => {
      await this.users.setMfa(user.id, { secretEnc, enabled: true }, tx);
      await audit(
        { action: 'auth.mfa.enable', targetType: 'user', targetId: user.id },
        principal,
        request,
      );
    });
  }

  /** Disables MFA after a valid code. */
  async disable(
    principal: Principal,
    code: string,
    request: AuditRequest & { ip?: string | undefined },
  ): Promise<void> {
    const user = await this.currentUser(principal);
    if (!user.mfaEnabled) throw AuthErrors.mfaNotEnabled();
    await this.throttle.guardMfa(user.id, clientInfo(request).ip, () =>
      this.checkCode(user, code),
    );
    await this.transactions.run(async ({ tx, audit }) => {
      await this.users.setMfa(user.id, { secretEnc: null, enabled: false }, tx);
      await audit(
        { action: 'auth.mfa.disable', targetType: 'user', targetId: user.id },
        principal,
        request,
      );
    });
  }

  /**
   * Verifies a code of the user's secret and consumes its time step.
   *
   * @throws {UnauthorizedError} `INVALID_MFA_CODE` when it is wrong, outside the window or replayed.
   */
  async checkCode(
    user: UserRow,
    code: string,
    now: Date = new Date(),
  ): Promise<void> {
    if (user.mfaSecretEnc === null) throw AuthErrors.invalidMfaCode();
    const secret = this.encryption.open(
      'mfa-secret',
      user.mfaSecretEnc,
      user.id,
    );
    const step = verifyTotp(secret, code, now.getTime());
    if (step === null) throw AuthErrors.invalidMfaCode();
    const fresh = await this.redis.set(
      `mfa:used:${user.id}:${step}`,
      '1',
      'EX',
      USED_STEP_TTL_SECONDS,
      'NX',
    );
    if (fresh !== 'OK') throw AuthErrors.invalidMfaCode();
  }

  private async currentUser(principal: Principal): Promise<UserRow> {
    const actor = requireUser(principal);
    const user = await this.users.findById(actor.id);
    if (user === undefined) throw AuthErrors.userNotFound(actor.id);
    return user;
  }
}
