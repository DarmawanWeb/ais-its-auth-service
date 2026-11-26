import { newId } from '@darmawanweb/ais-its-contracts/domain';
import { InjectConfig } from '@darmawanweb/ais-its-nest';
import {
  Injectable,
  Logger,
  type OnApplicationBootstrap,
} from '@nestjs/common';
import { sql } from 'drizzle-orm';

import { type Config, DEV_BOOTSTRAP_ADMIN_PASSWORD } from '../../config.js';
import { Transactions } from '../../db/transactions.js';
import { normalizeEmail } from '../../domain/identity.js';
import { checkPasswordPolicy } from '../../domain/password-policy.js';
import { MembershipsRepository } from '../accounts/memberships.repository.js';
import { OrganizationsRepository } from '../accounts/organizations.repository.js';
import { UsersRepository } from '../accounts/users.repository.js';
import { PasswordHasher } from '../crypto/password-hasher.service.js';

/** The platform organization created on an empty database (spec §13.1). */
export const PLATFORM_ORGANIZATION = Object.freeze({
  name: 'AIS Maritime Intelligence',
  slug: 'ais-maritime-intelligence',
  kind: 'platform',
} as const);

/** Display name of the bootstrap super admin. */
export const BOOTSTRAP_ADMIN_NAME = 'Platform Administrator';

/** Thrown when the bootstrap configuration is unusable. */
export class BootstrapConfigurationError extends Error {
  override readonly name = 'BootstrapConfigurationError';
}

/**
 * Bootstrap of an empty database (spec §13.1): the platform organization
 * `AIS Maritime Intelligence` (kind `platform`) and a super admin from
 * `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD`, who is also the
 * platform organization's `org_admin`. Runs once, under an advisory lock, so
 * concurrently starting replicas create one admin. In production the
 * documented default password is refused.
 */
@Injectable()
export class PlatformBootstrap implements OnApplicationBootstrap {
  private readonly logger = new Logger('Bootstrap');

  constructor(
    private readonly transactions: Transactions,
    @InjectConfig() private readonly config: Config,
    private readonly users: UsersRepository,
    private readonly organizations: OrganizationsRepository,
    private readonly memberships: MembershipsRepository,
    private readonly hasher: PasswordHasher,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    if (!(await this.users.isEmpty())) return;
    const password = this.config.BOOTSTRAP_ADMIN_PASSWORD;
    this.assertUsablePassword(password);
    const passwordHash = await this.hasher.hash(password);
    const email = normalizeEmail(this.config.BOOTSTRAP_ADMIN_EMAIL);
    const created = await this.transactions.run(async ({ tx, audit }) => {
      await tx.execute(
        sql`SELECT pg_advisory_xact_lock(hashtext('aisits.auth.bootstrap'))`,
      );
      if (!(await this.users.isEmpty(tx))) return undefined;
      const organization =
        (await this.organizations.findBySlug(PLATFORM_ORGANIZATION.slug, tx)) ??
        (await this.organizations.insert(
          { id: newId(), ...PLATFORM_ORGANIZATION },
          tx,
        ));
      const admin = await this.users.insert(
        {
          id: newId(),
          email,
          name: BOOTSTRAP_ADMIN_NAME,
          passwordHash,
          status: 'active',
          isPlatformAdmin: true,
        },
        tx,
      );
      await this.memberships.insert(
        { userId: admin.id, orgId: organization.id, role: 'org_admin' },
        tx,
      );
      await audit({
        action: 'platform.bootstrap',
        targetType: 'user',
        targetId: admin.id,
        orgId: organization.id,
        meta: { email, organizationId: organization.id },
      });
      return { organization, admin };
    });
    if (created === undefined) return;
    this.logger.warn(
      `Bootstrapped the platform organization and the super admin ${email}: change the bootstrap password now`,
    );
  }

  private assertUsablePassword(password: string): void {
    if (
      this.config.NODE_ENV === 'production' &&
      password === DEV_BOOTSTRAP_ADMIN_PASSWORD
    ) {
      throw new BootstrapConfigurationError(
        'BOOTSTRAP_ADMIN_PASSWORD must be set to a secret of its own to bootstrap a production database',
      );
    }
    if (checkPasswordPolicy(password).length > 0) {
      throw new BootstrapConfigurationError(
        'BOOTSTRAP_ADMIN_PASSWORD does not satisfy the password policy (10+ characters with letters and digits)',
      );
    }
  }
}
