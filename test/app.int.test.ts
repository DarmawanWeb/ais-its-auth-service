import { HTTP_HEADERS } from '@darmawanweb/ais-its-contracts/auth';
import { PG_POOL, type Pool } from '@darmawanweb/ais-its-nest/db';
import { createTestJwtIssuer } from '@darmawanweb/ais-its-nest/testing';
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { KeyRetirementJob } from '../src/modules/keys/key-retirement.job.js';
import { SERVICE } from '../src/service.js';
import {
  startTestService,
  TEST_ADMIN,
  type TestService,
} from './support/test-service.js';

const METHODOLOGY_URL = `/api/v2/${SERVICE.name}/methodology`;

describe(`${SERVICE.packageName} platform behaviour, bootstrap and signing keys`, () => {
  let service: TestService;

  beforeAll(async () => {
    service = await startTestService();
  });

  afterAll(async () => {
    await service.close();
  });

  it('is live and ready with the database, NATS and Valkey up', async () => {
    const live = await service.app.inject({
      method: 'GET',
      url: '/health/live',
    });
    expect(live.statusCode).toBe(200);

    const ready = await service.app.inject({
      method: 'GET',
      url: '/health/ready',
    });
    expect(ready.statusCode).toBe(200);
    expect(ready.json()).toMatchObject({
      status: 'ok',
      details: {
        database: { status: 'up' },
        nats: { status: 'up' },
        redis: { status: 'up' },
      },
    });
  });

  it('applied the migrations, with audit_logs as a compressed hypertable', async () => {
    const pool = service.app.get<unknown, Pool>(PG_POOL);
    const migrations = await pool.query<{ name: string }>(
      'SELECT name FROM schema_migrations ORDER BY version',
    );
    expect(migrations.rows.map((row) => row.name)).toContain('init');
    const hypertable = await pool.query<{ compression_enabled: boolean }>(
      `SELECT compression_enabled FROM timescaledb_information.hypertables
       WHERE hypertable_schema = 'auth' AND hypertable_name = 'audit_logs'`,
    );
    expect(hypertable.rows).toEqual([{ compression_enabled: true }]);
    const jobs = await pool.query<{ proc_name: string }>(
      `SELECT proc_name FROM timescaledb_information.jobs
       WHERE hypertable_schema = 'auth' AND hypertable_name = 'audit_logs' ORDER BY proc_name`,
    );
    expect(jobs.rows.map((row) => row.proc_name)).toEqual([
      'policy_compression',
      'policy_retention',
    ]);
  });

  it('bootstrapped the platform organization and its super admin', async () => {
    const admin = await service.loginAdmin();
    expect(admin.body).toMatchObject({
      user: {
        email: TEST_ADMIN.email,
        isPlatformAdmin: true,
        status: 'active',
      },
      memberships: [
        {
          orgName: 'AIS Maritime Intelligence',
          orgKind: 'platform',
          role: 'org_admin',
        },
      ],
    });
    const me = await service.app.inject({
      method: 'GET',
      url: '/api/v2/me',
      headers: admin.headers,
    });
    expect(me.json()).toMatchObject({ roles: ['org_admin', 'super_admin'] });
    expect(me.json<{ permissions: string[] }>().permissions).toContain(
      'org:manage',
    );
  });

  it('denies anonymous requests and tokens of foreign keys with 401 problem details', async () => {
    const anonymous = await service.app.inject({
      method: 'GET',
      url: METHODOLOGY_URL,
    });
    expect(anonymous.statusCode).toBe(401);
    expect(anonymous.headers['content-type']).toContain(
      'application/problem+json',
    );
    expect(anonymous.headers['www-authenticate']).toBeDefined();

    const foreign = await createTestJwtIssuer();
    const forged = await service.app.inject({
      method: 'GET',
      url: '/api/v2/me',
      headers: {
        authorization: `Bearer ${await foreign.sign({ roles: ['super_admin'], orgId: null })}`,
      },
    });
    expect(forged.statusCode).toBe(401);
  });

  it('serves the methodology (no catalog method) to a signed-in user', async () => {
    const admin = await service.loginAdmin();
    const response = await service.app.inject({
      method: 'GET',
      url: METHODOLOGY_URL,
      headers: admin.headers,
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ service: SERVICE.name, methods: [] });
  });

  it('issues access tokens that verify against the served JWKS', async () => {
    const admin = await service.loginAdmin();
    const jwks = await service.app.inject({
      method: 'GET',
      url: '/.well-known/jwks.json',
    });
    expect(jwks.statusCode).toBe(200);
    expect(jwks.headers['cache-control']).toContain('max-age');
    const keySet = jwks.json<{
      keys: {
        kid: string;
        kty: string;
        crv: string;
        alg: string;
        d?: string;
      }[];
    }>();
    expect(keySet.keys).toHaveLength(1);
    expect(keySet.keys[0]).toMatchObject({
      kty: 'OKP',
      crv: 'Ed25519',
      alg: 'EdDSA',
      use: 'sig',
    });
    expect(keySet.keys[0]?.d).toBeUndefined();

    const { payload, protectedHeader } = await jwtVerify(
      admin.accessToken,
      createLocalJWKSet(keySet),
      {
        issuer: 'ais-its-auth',
        audience: 'ais-its-api',
      },
    );
    expect(protectedHeader).toMatchObject({
      alg: 'EdDSA',
      kid: keySet.keys[0]?.kid,
    });
    expect(payload).toMatchObject({
      typ: 'access',
      email: TEST_ADMIN.email,
      roles: ['org_admin', 'super_admin'],
    });
    expect(Number(payload.exp) - Number(payload.iat)).toBe(900);
  });

  it('rotates the signing key: old tokens keep verifying, new ones use the new kid', async () => {
    const admin = await service.loginAdmin();
    const before = decodeProtectedHeader(admin.accessToken).kid;
    const rotation = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/keys/rotate',
      headers: admin.headers,
    });
    expect(rotation.statusCode).toBe(200);
    expect(rotation.json()).toMatchObject({ previousKid: before });
    const newKid = rotation.json<{ kid: string }>().kid;

    const jwks = await service.app.inject({
      method: 'GET',
      url: '/.well-known/jwks.json',
    });
    expect(
      jwks
        .json<{ keys: { kid: string }[] }>()
        .keys.map((key) => key.kid)
        .sort(),
    ).toEqual([before, newKid].sort());
    const old = await service.app.inject({
      method: 'GET',
      url: '/api/v2/me',
      headers: admin.headers,
    });
    expect(old.statusCode).toBe(200);
    const fresh = await service.loginAdmin();
    expect(decodeProtectedHeader(fresh.accessToken).kid).toBe(newKid);

    // A retiring key stays published until its grace period elapsed.
    await service.app.get(KeyRetirementJob).runOnce();
    const still = await service.app.inject({
      method: 'GET',
      url: '/.well-known/jwks.json',
    });
    expect(still.json<{ keys: unknown[] }>().keys).toHaveLength(2);

    // Only super admins rotate.
    const viewer = await service.createUser({ memberships: [] });
    const session = await service.login(viewer.email, 'CorrectHorse42');
    const denied = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/keys/rotate',
      headers: session.headers,
    });
    expect(denied.statusCode).toBe(403);
    // The kit guard (`@RequirePlatformAdmin()`), before the handler runs.
    expect(denied.json<{ code: string }>().code).toBe(
      'PLATFORM_ADMIN_REQUIRED',
    );
  });

  it('retires a rotated key once its successor is older than the grace period', async () => {
    const pool = service.app.get<unknown, Pool>(PG_POOL);
    const admin = await service.loginAdmin();
    const oldKid = decodeProtectedHeader(admin.accessToken).kid;
    const rotation = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/keys/rotate',
      headers: admin.headers,
    });
    expect(rotation.statusCode).toBe(200);
    const newKid = rotation.json<{ kid: string }>().kid;

    // Pretend every key, in order, was created ACCESS_TOKEN_TTL + tolerances (960 s) earlier.
    await pool.query(
      `UPDATE signing_keys SET created_at = created_at - interval '961 seconds'`,
    );
    await service.app.get(KeyRetirementJob).runOnce();

    const statuses = await pool.query<{
      kid: string;
      status: string;
      retired: boolean;
    }>(
      `SELECT kid, status, retired_at IS NOT NULL AS retired FROM signing_keys WHERE kid = ANY($1)`,
      [[oldKid, newKid]],
    );
    expect(
      Object.fromEntries(statuses.rows.map((row) => [row.kid, row])),
    ).toEqual({
      [String(oldKid)]: { kid: oldKid, status: 'retired', retired: true },
      [newKid]: { kid: newKid, status: 'active', retired: false },
    });
    const jwks = await service.app.inject({
      method: 'GET',
      url: '/.well-known/jwks.json',
    });
    expect(
      jwks.json<{ keys: { kid: string }[] }>().keys.map((key) => key.kid),
    ).not.toContain(oldKid);
    // A token of the retired key is no longer accepted.
    const stale = await service.app.inject({
      method: 'GET',
      url: '/api/v2/me',
      headers: admin.headers,
    });
    expect(stale.statusCode).toBe(401);
    const fresh = await service.loginAdmin();
    expect(decodeProtectedHeader(fresh.accessToken).kid).toBe(newKid);
  });

  it('answers the gateway forwardAuth with identity headers, or 401', async () => {
    const admin = await service.loginAdmin();
    const verified = await service.app.inject({
      method: 'GET',
      url: '/api/v2/auth/verify',
      headers: admin.headers,
    });
    expect(verified.statusCode).toBe(200);
    expect(verified.headers[HTTP_HEADERS.USER_ID.toLowerCase()]).toBe(
      (admin.body.user as { id: string }).id,
    );
    expect(verified.headers[HTTP_HEADERS.ORG_ID.toLowerCase()]).toBe(
      String(admin.body.activeOrgId),
    );
    expect(verified.headers[HTTP_HEADERS.ROLES.toLowerCase()]).toBe(
      'org_admin,super_admin',
    );
    expect(verified.headers['cache-control']).toBe('no-store');

    const missing = await service.app.inject({
      method: 'GET',
      url: '/api/v2/auth/verify',
    });
    expect(missing.statusCode).toBe(401);
    const invalid = await service.app.inject({
      method: 'GET',
      url: '/api/v2/auth/verify',
      headers: { authorization: 'Bearer not-a-token' },
    });
    expect(invalid.statusCode).toBe(401);
  });

  it('documents its routes in /openapi.json and exposes metrics', async () => {
    const response = await service.app.inject({
      method: 'GET',
      url: '/openapi.json',
    });
    expect(response.statusCode).toBe(200);
    const document = response.json<{
      paths: Record<
        string,
        Record<string, { security?: Record<string, unknown>[] }>
      >;
      security?: Record<string, unknown>[];
      components: { securitySchemes: Record<string, unknown> };
    }>();
    expect(Object.keys(document.paths)).toEqual(
      expect.arrayContaining([
        '/api/v2/auth/login',
        '/.well-known/jwks.json',
        '/internal/api-keys/introspect',
        '/api/v2/organizations/{id}/invitations',
      ]),
    );
    // OpenAPI 3: every security requirement names a declared scheme.
    const used = new Set(
      [
        ...(document.security ?? []),
        ...Object.values(document.paths).flatMap((operations) =>
          Object.values(operations).flatMap(
            (operation) => operation.security ?? [],
          ),
        ),
      ].flatMap((requirement) => Object.keys(requirement)),
    );
    const declared = Object.keys(document.components.securitySchemes);
    expect([...used].filter((name) => !declared.includes(name))).toEqual([]);
    // The refresh cookie is a declared scheme (0.2.0), used by refresh and logout.
    expect(document.components.securitySchemes.refreshCookie).toMatchObject({
      type: 'apiKey',
      in: 'cookie',
      name: 'aisits_rt',
    });
    // (`{}`: the routes are public, the cookie is their only credential.)
    for (const path of ['/api/v2/auth/refresh', '/api/v2/auth/logout']) {
      expect(document.paths[path]?.post?.security).toContainEqual({
        refreshCookie: [],
      });
    }
    // Platform-wide operations document their role (`@RequirePlatformAdmin()`).
    const rotate = document.paths['/api/v2/auth/keys/rotate']
      ?.post as unknown as Record<string, unknown> | undefined;
    expect(rotate?.['x-required-roles']).toEqual(['super_admin']);
    // Page-based lists document the page maximum of spec §5.
    const listUsers = document.paths['/api/v2/users']?.get as unknown as {
      parameters: { name: string; schema: { maximum?: number } }[];
    };
    expect(
      listUsers.parameters.find((parameter) => parameter.name === 'page')
        ?.schema.maximum,
    ).toBe(1_000_000);
    // Bodies that may be omitted are not `required` (generated clients
    // would force one), and integer fields say so.
    for (const path of [
      '/api/v2/api-keys/{id}/rotate',
      '/api/v2/organizations/{id}/invitations/{invitationId}/resend',
    ]) {
      const operation = document.paths[path]?.post as unknown as
        { requestBody?: { required?: boolean; content?: unknown } } | undefined;
      expect(operation?.requestBody?.content, path).toBeDefined();
      expect(operation?.requestBody?.required, path).toBe(false);
    }
    const schemas = (
      document.components as unknown as {
        schemas: Record<
          string,
          { properties: Record<string, Record<string, unknown>> }
        >;
      }
    ).schemas;
    expect(schemas.RotateApiKeyDto?.properties.gracePeriodMin).toMatchObject({
      type: 'integer',
      minimum: 0,
      maximum: 10_080,
      default: 1440,
    });
    expect(schemas.CreateApiKeyDto?.properties.expiresAt).toMatchObject({
      type: 'string',
      format: 'date-time',
    });
    const metrics = await service.app.inject({
      method: 'GET',
      url: '/metrics',
    });
    expect(metrics.body).toContain('aisits_http_requests_total');
    expect(metrics.body).toContain('aisits_auth_logins_total');
  });
});
