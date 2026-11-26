import type { EmailRequestedV1 } from '@darmawanweb/ais-its-contracts/events';
import {
  NOTIFY_EMAIL_SUBJECT,
  parseEnvelope,
} from '@darmawanweb/ais-its-contracts/events';
import type { OrgRole } from '@darmawanweb/ais-its-contracts/auth';
import { newId } from '@darmawanweb/ais-its-contracts/domain';
import { NatsClient } from '@darmawanweb/ais-its-nest/nats';
import { createRedisClient } from '@darmawanweb/ais-its-nest/redis';
import {
  buildTestApp,
  createTestConfig,
  uniqueName,
  waitFor,
} from '@darmawanweb/ais-its-nest/testing';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import pg from 'pg';
import { inject } from 'vitest';

import { AppModule } from '../../src/app.module.js';
import { type Config, configSchema } from '../../src/config.js';
import type { OrganizationRow, UserRow } from '../../src/db/database.js';
import type { OrganizationKind } from '../../src/domain/access-rules.js';
import { MembershipsRepository } from '../../src/modules/accounts/memberships.repository.js';
import { OrganizationsRepository } from '../../src/modules/accounts/organizations.repository.js';
import { UsersRepository } from '../../src/modules/accounts/users.repository.js';
import { PasswordHasher } from '../../src/modules/crypto/password-hasher.service.js';
import { OPENAPI } from '../../src/openapi.options.js';
import { EXPOSED_HEADERS, SERVICE } from '../../src/service.js';

/** Credentials of the bootstrap super admin in every test application. */
export const TEST_ADMIN = Object.freeze({
  email: 'admin@ais-its.test',
  password: 'AdminPass2026',
});

/** Default password of the users created by {@link TestService.createUser}. */
export const TEST_PASSWORD = 'CorrectHorse42';

/** Origin of the web app in tests (in `CORS_ORIGINS`). */
export const WEB_ORIGIN = 'http://localhost:5173';

/** The tables of the service, emptied before every test file. */
const TABLES = [
  'outbox',
  'audit_logs',
  'api_keys',
  'password_reset_tokens',
  'membership_invitations',
  'refresh_tokens',
  'sessions',
  'memberships',
  'users',
  'organizations',
  'signing_keys',
];

/** A signed-in client: the access token and the refresh cookie. */
export interface Session {
  readonly accessToken: string;
  /** `aisits_rt=<token>` (for the `Cookie` header). */
  readonly cookie: string;
  /** Raw `Set-Cookie` header of the login. */
  readonly setCookie: string;
  readonly body: Record<string, unknown>;
  /** `{ authorization: 'Bearer …' }`. */
  readonly headers: { authorization: string };
}

/** The real application on the shared containers, started from an empty database. */
export interface TestService {
  readonly app: NestFastifyApplication;
  readonly config: Config;
  /** Signs in through `POST /auth/login` (fails the test unless it returns 200 with a token). */
  login(email: string, password: string, ip?: string): Promise<Session>;
  /** Signs in as the bootstrap super admin. */
  loginAdmin(): Promise<Session>;
  /** Creates an active user directly in the database (test arrangement). */
  createUser(options: {
    readonly email?: string;
    readonly name?: string;
    readonly password?: string;
    readonly platformAdmin?: boolean;
    readonly memberships?: readonly {
      readonly orgId: string;
      readonly role: OrgRole;
    }[];
  }): Promise<UserRow>;
  /** Creates an organization directly in the database. */
  createOrganization(
    kind?: OrganizationKind,
    name?: string,
  ): Promise<OrganizationRow>;
  /** Sequence of the newest `NOTIFY` message (0 when the stream is empty). */
  lastEmailSequence(): Promise<number>;
  /** Waits for an e-mail request to `to` published after `afterSequence`. */
  nextEmail(to: string, afterSequence: number): Promise<EmailRequestedV1>;
  /** A unique e-mail address for this test file. */
  email(local: string): string;
  close(): Promise<void>;
}

/** Empties the service tables (when the migrations already ran) and Valkey. */
async function resetState(
  databaseUrl: string,
  redisUrl: string,
): Promise<void> {
  const client = new pg.Client({ connectionString: databaseUrl });
  await client.connect();
  try {
    const existing = await client.query<{ name: string }>(
      `SELECT table_name AS name FROM information_schema.tables WHERE table_schema = $1 AND table_name = ANY($2)`,
      [SERVICE.schema, TABLES],
    );
    if (existing.rows.length > 0) {
      await client.query(
        `TRUNCATE ${existing.rows.map((row) => `${SERVICE.schema}.${row.name}`).join(', ')} CASCADE`,
      );
    }
  } finally {
    await client.end();
  }
  const redis = createRedisClient({
    REDIS_URL: redisUrl,
    SERVICE_NAME: 'auth-test',
  });
  await redis.connect();
  try {
    await redis.flushdb();
  } finally {
    await redis.quit();
  }
}

/**
 * Builds and initializes the AppModule as `bootstrapService()` does (hooks
 * run: migrations apply, the signing key and the bootstrap admin are
 * created, consumers start) without listening; use `app.inject()` and
 * close it with `close()`.
 */
export async function startTestService(
  env: Readonly<Record<string, string>> = {},
  options: {
    /** Receives the service's JSON log lines (set `LOG_LEVEL` in `env`). */
    readonly logLines?: string[];
  } = {},
): Promise<TestService> {
  const infra = inject('infra');
  await resetState(infra.databaseUrl, infra.redisUrl);
  const suffix = uniqueName('t');
  const config = createTestConfig(configSchema, {
    SERVICE_NAME: SERVICE.name,
    DATABASE_URL: infra.databaseUrl,
    DATABASE_SCHEMA: SERVICE.schema,
    DB_MIGRATE_ON_BOOT: 'true',
    NATS_URL: infra.natsUrl,
    NATS_DURABLE_PREFIX: suffix,
    REDIS_URL: infra.redisUrl,
    BOOTSTRAP_ADMIN_EMAIL: TEST_ADMIN.email,
    BOOTSTRAP_ADMIN_PASSWORD: TEST_ADMIN.password,
    INTERNAL_TOKEN: 'test-internal-token-0123456789',
    CORS_ORIGINS: `${WEB_ORIGIN},http://localhost:8000`,
    PUBLIC_BASE_URL: 'http://localhost:8000',
    // TEST_LOG_LEVEL=debug pnpm test:int shows the service logs.
    ...(process.env.TEST_LOG_LEVEL === undefined
      ? {}
      : { LOG_LEVEL: process.env.TEST_LOG_LEVEL }),
    ...env,
  });
  const app = await buildTestApp(AppModule, {
    config,
    openapi: OPENAPI,
    cookies: true,
    cors: { exposedHeaders: EXPOSED_HEADERS },
    logging:
      options.logLines === undefined
        ? undefined
        : {
            destination: {
              write: (line: string) => {
                options.logLines?.push(line);
              },
            },
          },
  });
  const hasher = new PasswordHasher();

  const login = async (
    email: string,
    password: string,
    ip = '203.0.113.10',
  ): Promise<Session> => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/v2/auth/login',
      headers: { 'x-forwarded-for': ip },
      payload: { email, password },
    });
    if (response.statusCode !== 200) {
      throw new Error(
        `Login of ${email} failed: ${response.statusCode} ${response.body}`,
      );
    }
    const body = response.json<Record<string, unknown>>();
    const setCookie = String(response.headers['set-cookie']);
    const accessToken = String(body.accessToken);
    return {
      accessToken,
      cookie: setCookie.split(';')[0] ?? '',
      setCookie,
      body,
      headers: { authorization: `Bearer ${accessToken}` },
    };
  };

  const lastEmailSequence = async (): Promise<number> => {
    const { manager } = app.get(NatsClient);
    const info = await manager.streams.info('NOTIFY');
    return info.state.last_seq;
  };

  return {
    app,
    config,
    login,
    loginAdmin: () => login(TEST_ADMIN.email, TEST_ADMIN.password),
    async createUser(options) {
      const users = app.get(UsersRepository);
      const user = await users.insert({
        id: newId(),
        email: (
          options.email ?? `${uniqueName('user')}@example.com`
        ).toLowerCase(),
        name: options.name ?? 'Test User',
        passwordHash: await hasher.hash(options.password ?? TEST_PASSWORD),
        status: 'active',
        isPlatformAdmin: options.platformAdmin ?? false,
      });
      for (const membership of options.memberships ?? []) {
        await app
          .get(MembershipsRepository)
          .insert({ userId: user.id, ...membership });
      }
      return user;
    },
    createOrganization(kind = 'shipping_company', name = 'Test Organization') {
      return app.get(OrganizationsRepository).insert({
        id: newId(),
        name,
        slug: uniqueName('org').replaceAll('_', '-'),
        kind,
      });
    },
    lastEmailSequence,
    async nextEmail(to, afterSequence) {
      const { manager } = app.get(NatsClient);
      // Scans every request published after `afterSequence` (several
      // e-mails may follow each other); nothing consumes NOTIFY in tests.
      return waitFor(
        async () => {
          const last = await lastEmailSequence();
          for (let seq = afterSequence + 1; seq <= last; seq += 1) {
            const stored = await manager.streams.getMessage('NOTIFY', { seq });
            if (stored?.subject !== NOTIFY_EMAIL_SUBJECT) continue;
            const parsed = parseEnvelope(stored.data);
            if (!parsed.success) continue;
            const data = parsed.envelope.data as EmailRequestedV1;
            if (data.to === to) return data;
          }
          return undefined;
        },
        { timeoutMs: 10_000, message: `e-mail to ${to}` },
      );
    },
    email: (local) => `${local}.${suffix.replaceAll('_', '-')}@example.com`,
    close: () => app.close(),
  };
}

/** The token of an e-mailed link (`…#token=<token>`). */
export function tokenOfLink(link: unknown): string {
  const match = /#token=([^&]+)$/.exec(String(link));
  if (match?.[1] === undefined) throw new Error(`No token in ${String(link)}`);
  return decodeURIComponent(match[1]);
}
