import type { ApiKeyScope, OrgRole } from '@darmawanweb/ais-its-contracts/auth';
import { newId } from '@darmawanweb/ais-its-contracts/domain';
import type { Database } from '@darmawanweb/ais-its-nest/db';

import type { Executor, OrganizationRow, UserRow } from '../../db/database.js';
import type * as schema from '../../db/schema.js';
import type { OrganizationKind } from '../../domain/access-rules.js';
import { generateApiKey } from '../../domain/api-key-material.js';
import { checkPasswordPolicy } from '../../domain/password-policy.js';
import type { MembershipsRepository } from '../accounts/memberships.repository.js';
import type { OrganizationsRepository } from '../accounts/organizations.repository.js';
import type { UsersRepository } from '../accounts/users.repository.js';
import type { ApiKeysRepository } from '../api-keys/api-keys.repository.js';
import type { PasswordHasher } from '../crypto/password-hasher.service.js';

/** Demo organizations (spec §13.1 `pnpm seed:demo`). */
export const DEMO_ORGANIZATIONS = {
  shipping: {
    name: 'PT Demo Pelayaran Nusantara',
    slug: 'demo-shipping',
    kind: 'shipping_company',
  },
  authority: {
    name: 'Demo Otoritas Maritim',
    slug: 'demo-authority',
    kind: 'authority',
  },
} as const satisfies Record<
  string,
  { name: string; slug: string; kind: OrganizationKind }
>;

type DemoOrganization = keyof typeof DEMO_ORGANIZATIONS;

/** One demo user per role. */
export const DEMO_USERS: readonly {
  readonly email: string;
  readonly name: string;
  readonly role: OrgRole | 'super_admin';
  readonly organization: DemoOrganization | null;
}[] = [
  {
    email: 'superadmin@demo.ais-its.local',
    name: 'Demo Super Admin',
    role: 'super_admin',
    organization: null,
  },
  {
    email: 'orgadmin@demo.ais-its.local',
    name: 'Demo Org Admin',
    role: 'org_admin',
    organization: 'shipping',
  },
  {
    email: 'fleet@demo.ais-its.local',
    name: 'Demo Fleet Manager',
    role: 'fleet_manager',
    organization: 'shipping',
  },
  {
    email: 'authority@demo.ais-its.local',
    name: 'Demo Authority Officer',
    role: 'authority',
    organization: 'authority',
  },
  {
    email: 'viewer@demo.ais-its.local',
    name: 'Demo Viewer',
    role: 'viewer',
    organization: 'shipping',
  },
];

/** Demo API keys of the shipping company. */
export const DEMO_API_KEYS: readonly {
  readonly name: string;
  readonly scopes: readonly ApiKeyScope[];
}[] = [
  { name: 'Demo AIS pusher', scopes: ['ais:ingest'] },
  { name: 'Demo fuel meter', scopes: ['telemetry:ingest'] },
];

/** What the seed created or found. */
export interface DemoSeedResult {
  readonly organizations: readonly {
    readonly slug: string;
    readonly id: string;
    readonly created: boolean;
  }[];
  readonly users: readonly {
    readonly email: string;
    readonly role: string;
    readonly created: boolean;
  }[];
  /** `key` is `null` for keys that already existed (secrets are shown only once). */
  readonly apiKeys: readonly {
    readonly name: string;
    readonly scopes: readonly string[];
    readonly key: string | null;
  }[];
  readonly password: string;
}

/**
 * Idempotent demo data: a shipping company and an authority, one user per
 * role (all with the same demo password) and two API keys. Existing
 * organizations (by slug), users (by e-mail, password untouched) and keys
 * (by organization and name) are kept, so it can run against a used
 * database.
 */
export class DemoSeeder {
  constructor(
    private readonly db: Database<typeof schema>,
    private readonly organizations: OrganizationsRepository,
    private readonly users: UsersRepository,
    private readonly memberships: MembershipsRepository,
    private readonly apiKeys: ApiKeysRepository,
    private readonly hasher: PasswordHasher,
  ) {}

  async run(password: string): Promise<DemoSeedResult> {
    if (checkPasswordPolicy(password).length > 0) {
      throw new RangeError(
        'SEED_DEMO_PASSWORD must have 10+ characters with letters and digits',
      );
    }
    const passwordHash = await this.hasher.hash(password);
    return this.db.transaction(async (tx) => {
      const organizations = new Map<
        DemoOrganization,
        { row: OrganizationRow; created: boolean }
      >();
      for (const key of Object.keys(DEMO_ORGANIZATIONS) as DemoOrganization[]) {
        organizations.set(key, await this.organization(key, tx));
      }
      const users: { email: string; role: string; created: boolean }[] = [];
      for (const demo of DEMO_USERS) {
        const { row, created } = await this.user(demo, passwordHash, tx);
        const organization =
          demo.organization === null
            ? undefined
            : organizations.get(demo.organization);
        if (organization !== undefined && demo.role !== 'super_admin') {
          if (
            (await this.memberships.find(row.id, organization.row.id, tx)) ===
            undefined
          ) {
            await this.memberships.insert(
              { userId: row.id, orgId: organization.row.id, role: demo.role },
              tx,
            );
          }
        }
        users.push({ email: row.email, role: demo.role, created });
      }
      const shipping = organizations.get('shipping');
      if (shipping === undefined)
        throw new Error('The demo shipping company is missing');
      const apiKeys: {
        name: string;
        scopes: readonly string[];
        key: string | null;
      }[] = [];
      for (const demo of DEMO_API_KEYS) {
        apiKeys.push(await this.apiKey(shipping.row.id, demo, tx));
      }
      return {
        organizations: [...organizations.values()].map(({ row, created }) => ({
          slug: row.slug,
          id: row.id,
          created,
        })),
        users,
        apiKeys,
        password,
      };
    });
  }

  private async organization(
    key: DemoOrganization,
    tx: Executor,
  ): Promise<{ row: OrganizationRow; created: boolean }> {
    const demo = DEMO_ORGANIZATIONS[key];
    const existing = await this.organizations.findBySlug(demo.slug, tx);
    if (existing !== undefined) return { row: existing, created: false };
    return {
      row: await this.organizations.insert({ id: newId(), ...demo }, tx),
      created: true,
    };
  }

  private async user(
    demo: (typeof DEMO_USERS)[number],
    passwordHash: string,
    tx: Executor,
  ): Promise<{ row: UserRow; created: boolean }> {
    const existing = await this.users.findByEmail(demo.email, tx);
    if (existing !== undefined) return { row: existing, created: false };
    const row = await this.users.insert(
      {
        id: newId(),
        email: demo.email,
        name: demo.name,
        passwordHash,
        status: 'active',
        isPlatformAdmin: demo.role === 'super_admin',
      },
      tx,
    );
    return { row, created: true };
  }

  private async apiKey(
    orgId: string,
    demo: (typeof DEMO_API_KEYS)[number],
    tx: Executor,
  ): Promise<{ name: string; scopes: readonly string[]; key: string | null }> {
    if (
      (await this.apiKeys.findActiveByName(orgId, demo.name, tx)) !== undefined
    ) {
      return { name: demo.name, scopes: demo.scopes, key: null };
    }
    const material = generateApiKey();
    await this.apiKeys.insert(
      {
        id: newId(),
        orgId,
        name: demo.name,
        prefix: material.prefix,
        keyHash: material.hash,
        scopes: demo.scopes,
        createdBy: null,
      },
      tx,
    );
    return { name: demo.name, scopes: demo.scopes, key: material.key };
  }
}

/** The seed report printed by `pnpm seed:demo`. */
export function formatDemoSeed(result: DemoSeedResult): string {
  const lines = [
    '',
    'AIS Maritime Intelligence — demo data',
    '',
    'Organizations:',
  ];
  for (const organization of result.organizations) {
    lines.push(
      `  ${organization.slug.padEnd(16)} ${organization.id}${organization.created ? '' : ' (existing)'}`,
    );
  }
  lines.push('', `Users (password for new users: ${result.password}):`);
  for (const user of result.users) {
    lines.push(
      `  ${user.role.padEnd(14)} ${user.email}${user.created ? '' : ' (existing, password unchanged)'}`,
    );
  }
  lines.push('', 'API keys (shown once, store them now):');
  for (const key of result.apiKeys) {
    lines.push(
      `  ${key.name.padEnd(16)} [${key.scopes.join(', ')}] ${key.key ?? '(existing, not shown again)'}`,
    );
  }
  lines.push('');
  return lines.join('\n');
}
