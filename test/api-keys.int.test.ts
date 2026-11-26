import { PG_POOL, type Pool } from '@darmawanweb/ais-its-nest/db';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { HousekeepingJob } from '../src/modules/bootstrap/housekeeping.job.js';
import {
  type Session,
  startTestService,
  TEST_PASSWORD,
  type TestService,
} from './support/test-service.js';

interface KeyBody {
  id: string;
  key: string;
  prefix: string;
  status: string;
  expiresAt: string | null;
  rotatedAt: string | null;
  previousKeyExpiresAt: string | null;
}

const INTERNAL_TOKEN = 'test-internal-token-0123456789';

describe('API keys and internal introspection', () => {
  let service: TestService;

  beforeAll(async () => {
    service = await startTestService();
  });

  afterAll(async () => {
    await service.close();
  });

  const introspect = (key: string, token: string | null = INTERNAL_TOKEN) =>
    service.app.inject({
      method: 'POST',
      url: '/internal/api-keys/introspect',
      headers: token === null ? {} : { 'x-internal-token': token },
      payload: { key },
    });

  it('creates a key shown once, introspects it for services and revokes it', async () => {
    const org = await service.createOrganization();
    const orgAdmin = await service.createUser({
      memberships: [{ orgId: org.id, role: 'org_admin' }],
    });
    const session = await service.login(orgAdmin.email, TEST_PASSWORD);

    const created = await service.app.inject({
      method: 'POST',
      url: '/api/v2/api-keys',
      headers: session.headers,
      payload: { name: 'Fuel meter Batam', scopes: ['telemetry:ingest'] },
    });
    expect(created.statusCode).toBe(201);
    const { apiKey } = created.json<{
      apiKey: { id: string; key: string; prefix: string; orgId: string };
    }>();
    expect(apiKey.key).toMatch(/^sk_[0-9A-Za-z]{10}_[0-9A-Za-z]{32}$/);
    expect(apiKey.key.startsWith(`${apiKey.prefix}_`)).toBe(true);
    expect(apiKey.orgId).toBe(org.id);

    const listed = await service.app.inject({
      method: 'GET',
      url: '/api/v2/api-keys',
      headers: session.headers,
    });
    expect(listed.json()).toMatchObject({
      data: [{ id: apiKey.id, lastUsedAt: null }],
      meta: { total: 1 },
    });
    expect(listed.body).not.toContain(apiKey.key);

    expect((await introspect(apiKey.key, null)).statusCode).toBe(401);
    expect(
      (await introspect(apiKey.key, 'wrong-token-of-sufficient-length'))
        .statusCode,
    ).toBe(401);
    const active = await introspect(apiKey.key);
    expect(active.statusCode).toBe(200);
    expect(active.json()).toEqual({
      active: true,
      keyId: apiKey.id,
      orgId: org.id,
      scopes: ['telemetry:ingest'],
      name: 'Fuel meter Batam',
    });

    // last_used_at is written at most once per minute.
    const pool = service.app.get<unknown, Pool>(PG_POOL);
    const firstUse = await pool.query<{ last_used_at: Date }>(
      'SELECT last_used_at FROM api_keys WHERE id = $1',
      [apiKey.id],
    );
    expect(firstUse.rows[0]?.last_used_at).toBeInstanceOf(Date);
    await introspect(apiKey.key);
    const secondUse = await pool.query<{ last_used_at: Date }>(
      'SELECT last_used_at FROM api_keys WHERE id = $1',
      [apiKey.id],
    );
    expect(secondUse.rows[0]?.last_used_at.getTime()).toBe(
      firstUse.rows[0]?.last_used_at.getTime(),
    );

    const tampered = `${apiKey.key.slice(0, -1)}${apiKey.key.endsWith('a') ? 'b' : 'a'}`;
    expect((await introspect(tampered)).json()).toEqual({ active: false });
    expect((await introspect('not-a-key')).json()).toEqual({ active: false });

    const revoked = await service.app.inject({
      method: 'DELETE',
      url: `/api/v2/api-keys/${apiKey.id}`,
      headers: session.headers,
    });
    expect(revoked.statusCode).toBe(204);
    expect((await introspect(apiKey.key)).json()).toEqual({ active: false });
    const withRevoked = await service.app.inject({
      method: 'GET',
      url: '/api/v2/api-keys?includeRevoked=true',
      headers: session.headers,
    });
    expect(
      withRevoked.json<{ data: { revokedAt: string | null }[] }>().data[0]
        ?.revokedAt,
    ).not.toBeNull();
  });

  it('grants the shared-feed scope ais:ingest to super admins only', async () => {
    const org = await service.createOrganization();
    const orgAdmin = await service.createUser({
      memberships: [{ orgId: org.id, role: 'org_admin' }],
    });
    const session = await service.login(orgAdmin.email, TEST_PASSWORD);
    const refused = await service.app.inject({
      method: 'POST',
      url: '/api/v2/api-keys',
      headers: session.headers,
      payload: {
        name: 'Tenant pusher',
        scopes: ['telemetry:ingest', 'ais:ingest'],
      },
    });
    expect(refused.statusCode).toBe(403);
    expect(refused.json()).toMatchObject({
      code: 'SCOPE_NOT_GRANTABLE',
      scopes: ['ais:ingest'],
    });
    const pool = service.app.get<unknown, Pool>(PG_POOL);
    const stored = await pool.query(
      'SELECT id FROM api_keys WHERE org_id = $1',
      [org.id],
    );
    expect(stored.rowCount).toBe(0);

    const tenantSafe = await service.app.inject({
      method: 'POST',
      url: '/api/v2/api-keys',
      headers: session.headers,
      payload: { name: 'Partner reader', scopes: ['ais:read'] },
    });
    expect(tenantSafe.statusCode).toBe(201);

    const admin = await service.loginAdmin();
    const granted = await service.app.inject({
      method: 'POST',
      url: '/api/v2/api-keys',
      headers: admin.headers,
      payload: {
        name: 'AIS pusher Batam',
        scopes: ['ais:ingest'],
        orgId: org.id,
      },
    });
    expect(granted.statusCode).toBe(201);
    const { apiKey } = granted.json<{ apiKey: { key: string } }>();
    expect((await introspect(apiKey.key)).json()).toMatchObject({
      active: true,
      orgId: org.id,
      scopes: ['ais:ingest'],
    });
  });

  it('keeps keys tenant-private and closed to other roles', async () => {
    const mine = await service.createOrganization();
    const theirs = await service.createOrganization();
    const owner = await service.createUser({
      memberships: [{ orgId: theirs.id, role: 'org_admin' }],
    });
    const ownerSession = await service.login(owner.email, TEST_PASSWORD);
    const created = await service.app.inject({
      method: 'POST',
      url: '/api/v2/api-keys',
      headers: ownerSession.headers,
      payload: { name: 'Fuel meter', scopes: ['telemetry:ingest'] },
    });
    const keyId = created.json<{ apiKey: { id: string } }>().apiKey.id;

    const intruder = await service.createUser({
      memberships: [{ orgId: mine.id, role: 'org_admin' }],
    });
    const intruderSession = await service.login(intruder.email, TEST_PASSWORD);
    const revoke = await service.app.inject({
      method: 'DELETE',
      url: `/api/v2/api-keys/${keyId}`,
      headers: intruderSession.headers,
    });
    expect(revoke.statusCode).toBe(404);
    const list = await service.app.inject({
      method: 'GET',
      url: `/api/v2/api-keys?orgId=${theirs.id}`,
      headers: intruderSession.headers,
    });
    expect(list.statusCode).toBe(403);
    const createForeign = await service.app.inject({
      method: 'POST',
      url: '/api/v2/api-keys',
      headers: intruderSession.headers,
      payload: { name: 'Sneaky', scopes: ['ais:read'], orgId: theirs.id },
    });
    expect(createForeign.statusCode).toBe(403);

    const viewer = await service.createUser({
      memberships: [{ orgId: theirs.id, role: 'viewer' }],
    });
    const viewerSession = await service.login(viewer.email, TEST_PASSWORD);
    const viewerList = await service.app.inject({
      method: 'GET',
      url: '/api/v2/api-keys',
      headers: viewerSession.headers,
    });
    expect(viewerList.statusCode).toBe(403);

    // Super admins manage keys of any organization.
    const admin = await service.loginAdmin();
    const adminList = await service.app.inject({
      method: 'GET',
      url: `/api/v2/api-keys?orgId=${theirs.id}`,
      headers: admin.headers,
    });
    expect(adminList.json()).toMatchObject({ data: [{ id: keyId }] });
    const adminCreate = await service.app.inject({
      method: 'POST',
      url: '/api/v2/api-keys',
      headers: admin.headers,
      payload: { name: 'Partner feed', scopes: ['ais:read'], orgId: mine.id },
    });
    expect(adminCreate.statusCode).toBe(201);
    const invalidScope = await service.app.inject({
      method: 'POST',
      url: '/api/v2/api-keys',
      headers: admin.headers,
      payload: { name: 'Bad', scopes: ['vessel:write'], orgId: mine.id },
    });
    expect(invalidScope.statusCode).toBe(400);
  });
  const createKey = async (
    session: Session,
    payload: Record<string, unknown>,
  ): Promise<KeyBody> => {
    const response = await service.app.inject({
      method: 'POST',
      url: '/api/v2/api-keys',
      headers: session.headers,
      payload,
    });
    expect(response.statusCode).toBe(201);
    return response.json<{ apiKey: KeyBody }>().apiKey;
  };

  const rotate = (
    session: Session,
    id: string,
    payload?: Record<string, unknown>,
  ) =>
    service.app.inject({
      method: 'POST',
      url: `/api/v2/api-keys/${id}/rotate`,
      headers: { ...session.headers, 'content-type': 'application/json' },
      ...(payload === undefined ? {} : { payload }),
    });

  const isActive = async (key: string): Promise<boolean> =>
    (await introspect(key)).json<{ active: boolean }>().active;

  const listed = async (session: Session, id: string): Promise<KeyBody> => {
    const response = await service.app.inject({
      method: 'GET',
      url: '/api/v2/api-keys?includeRevoked=true',
      headers: session.headers,
    });
    const found = response
      .json<{ data: KeyBody[] }>()
      .data.find((entry) => entry.id === id);
    if (found === undefined) throw new Error(`Key ${id} not listed`);
    return found;
  };

  it('expires keys at expiresAt (introspection inactive, status expired)', async () => {
    const org = await service.createOrganization();
    const orgAdmin = await service.createUser({
      memberships: [{ orgId: org.id, role: 'org_admin' }],
    });
    const session = await service.login(orgAdmin.email, TEST_PASSWORD);
    const past = await service.app.inject({
      method: 'POST',
      url: '/api/v2/api-keys',
      headers: session.headers,
      payload: {
        name: 'Too late',
        scopes: ['telemetry:ingest'],
        expiresAt: new Date(Date.now() - 1000).toISOString(),
      },
    });
    expect(past.statusCode).toBe(400);
    expect(past.json()).toMatchObject({
      code: 'VALIDATION_FAILED',
      errors: [expect.objectContaining({ field: 'expiresAt' })],
    });

    const expiresAt = new Date(Date.now() + 1500).toISOString();
    const key = await createKey(session, {
      name: 'Short lived',
      scopes: ['telemetry:ingest'],
      expiresAt,
    });
    expect(key).toMatchObject({ status: 'active', expiresAt });
    expect(await isActive(key.key)).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 1700));
    expect(await isActive(key.key)).toBe(false);
    expect(await listed(session, key.id)).toMatchObject({
      status: 'expired',
      expiresAt,
    });
    const rotated = await rotate(session, key.id);
    expect(rotated.statusCode).toBe(409);
    expect(rotated.json()).toMatchObject({
      code: 'API_KEY_INACTIVE',
      reason: 'expired',
    });
  });

  it('accepts only ISO-8601 UTC timestamps as expiresAt (400, never a 500 or a misread date)', async () => {
    const org = await service.createOrganization();
    const orgAdmin = await service.createUser({
      memberships: [{ orgId: org.id, role: 'org_admin' }],
    });
    const session = await service.login(orgAdmin.email, TEST_PASSWORD);
    for (const expiresAt of [
      '2027-W05', // week date: Date cannot read it (was a 500)
      '2027-123', // ordinal date (was a 500)
      '20270101', // basic format (was a 500)
      '-2027-01-01', // negative year (was stored as 2027-01-01)
      '2027-01-01T10:00', // no zone (was read in the server's time zone)
      '2027-01-01T10:00:00',
      '2027-01-01T10:00:00+07:00', // not UTC (spec §2: UTC on the wire)
      '2027-02-30T00:00:00Z', // no such day
      '2027-01-01',
      null, // "must be in the future" before
      1_798_761_600_000,
    ]) {
      const response = await service.app.inject({
        method: 'POST',
        url: '/api/v2/api-keys',
        headers: session.headers,
        payload: { name: 'Odd date', scopes: ['ais:read'], expiresAt },
      });
      expect(response.statusCode, JSON.stringify(expiresAt)).toBe(400);
      expect(response.json()).toMatchObject({
        code: 'VALIDATION_FAILED',
        errors: [
          expect.objectContaining({
            field: 'expiresAt',
            code: 'isUtcDateTime',
          }),
        ],
      });
    }
    const listedKeys = await service.app.inject({
      method: 'GET',
      url: '/api/v2/api-keys',
      headers: session.headers,
    });
    expect(listedKeys.json()).toMatchObject({ meta: { total: 0 } });

    const key = await createKey(session, {
      name: 'Until 2030',
      scopes: ['ais:read'],
      expiresAt: '2030-01-01T00:00:00Z',
    });
    expect(key).toMatchObject({
      status: 'active',
      expiresAt: '2030-01-01T00:00:00.000Z',
    });
  });

  it('refuses a null grace period (400) instead of ending the replaced secret at once', async () => {
    const org = await service.createOrganization();
    const orgAdmin = await service.createUser({
      memberships: [{ orgId: org.id, role: 'org_admin' }],
    });
    const session = await service.login(orgAdmin.email, TEST_PASSWORD);
    const original = await createKey(session, {
      name: 'Gauge null grace',
      scopes: ['telemetry:ingest'],
    });
    // null used to replace the 24 h default and stop the old secret at once.
    for (const gracePeriodMin of [null, '5', 1.5, -1]) {
      const refused = await rotate(session, original.id, { gracePeriodMin });
      expect(refused.statusCode, JSON.stringify(gracePeriodMin)).toBe(400);
      const problem = refused.json<{
        code: string;
        errors: { field: string }[];
      }>();
      expect(problem.code).toBe('VALIDATION_FAILED');
      expect(new Set(problem.errors.map((error) => error.field))).toEqual(
        new Set(['gracePeriodMin']),
      );
    }
    // Nothing was rotated: the device's secret still works.
    expect(await isActive(original.key)).toBe(true);
    expect(await listed(session, original.id)).toMatchObject({
      rotatedAt: null,
      previousKeyExpiresAt: null,
    });
  });

  it('rotates the secret, keeping id and prefix, with a grace period for the old one', async () => {
    const org = await service.createOrganization();
    const orgAdmin = await service.createUser({
      memberships: [{ orgId: org.id, role: 'org_admin' }],
    });
    const session = await service.login(orgAdmin.email, TEST_PASSWORD);
    const original = await createKey(session, {
      name: 'Fuel meter rotating',
      scopes: ['telemetry:ingest'],
    });

    const first = await rotate(session, original.id, { gracePeriodMin: 60 });
    expect(first.statusCode).toBe(200);
    const second = first.json<{ apiKey: KeyBody }>().apiKey;
    expect(second).toMatchObject({
      id: original.id,
      prefix: original.prefix,
      status: 'active',
    });
    expect(second.key).not.toBe(original.key);
    expect(second.key.startsWith(`${original.prefix}_`)).toBe(true);
    expect(second.rotatedAt).not.toBeNull();
    const graceEnd = Date.parse(second.previousKeyExpiresAt ?? '');
    expect(graceEnd - Date.now()).toBeGreaterThan(59 * 60_000);
    expect(graceEnd - Date.now()).toBeLessThanOrEqual(60 * 60_000);
    // Both secrets resolve to the same key id during the grace period.
    for (const secret of [original.key, second.key]) {
      expect((await introspect(secret)).json()).toMatchObject({
        active: true,
        keyId: original.id,
        orgId: org.id,
      });
    }

    // Without a body: the default grace period (24 h); the oldest secret stops at once.
    const bodiless = await rotate(session, original.id);
    expect(bodiless.statusCode).toBe(200);
    const third = bodiless.json<{ apiKey: KeyBody }>().apiKey;
    expect(
      Date.parse(third.previousKeyExpiresAt ?? '') - Date.now(),
    ).toBeGreaterThan(23 * 3_600_000);
    expect(await isActive(original.key)).toBe(false);
    expect(await isActive(second.key)).toBe(true);
    expect(await isActive(third.key)).toBe(true);

    // gracePeriodMin 0: only the new secret works.
    const immediate = await rotate(session, original.id, { gracePeriodMin: 0 });
    const fourth = immediate.json<{ apiKey: KeyBody }>().apiKey;
    expect(fourth.previousKeyExpiresAt).toBeNull();
    expect(await isActive(third.key)).toBe(false);
    expect(await isActive(fourth.key)).toBe(true);
    expect(
      (await rotate(session, original.id, { gracePeriodMin: 10_081 }))
        .statusCode,
    ).toBe(400);

    // Housekeeping forgets replaced secrets once their grace period is over.
    const pool = service.app.get<unknown, Pool>(PG_POOL);
    await rotate(session, original.id, { gracePeriodMin: 5 });
    await pool.query(
      `UPDATE api_keys SET previous_key_expires_at = now() - interval '1 second' WHERE id = $1`,
      [original.id],
    );
    await service.app.get(HousekeepingJob).run();
    const { rows } = await pool.query<{ previous_key_hash: string | null }>(
      'SELECT previous_key_hash FROM api_keys WHERE id = $1',
      [original.id],
    );
    expect(rows[0]?.previous_key_hash).toBeNull();
  });

  it('rotates only manageable, active keys whose scopes the caller may grant', async () => {
    const admin = await service.loginAdmin();
    const org = await service.createOrganization();
    const other = await service.createOrganization();
    const orgAdmin = await service.createUser({
      memberships: [{ orgId: org.id, role: 'org_admin' }],
    });
    const session = await service.login(orgAdmin.email, TEST_PASSWORD);
    const feed = await createKey(admin, {
      name: 'AIS pusher',
      scopes: ['ais:ingest'],
      orgId: org.id,
    });
    const refused = await rotate(session, feed.id);
    expect(refused.statusCode).toBe(403);
    expect(refused.json()).toMatchObject({ code: 'SCOPE_NOT_GRANTABLE' });
    expect(await isActive(feed.key)).toBe(true);
    expect((await rotate(admin, feed.id)).statusCode).toBe(200);

    const foreign = await createKey(admin, {
      name: 'Foreign',
      scopes: ['ais:read'],
      orgId: other.id,
    });
    expect((await rotate(session, foreign.id)).statusCode).toBe(404);

    const revoked = await createKey(session, {
      name: 'Revoked',
      scopes: ['ais:read'],
    });
    await service.app.inject({
      method: 'DELETE',
      url: `/api/v2/api-keys/${revoked.id}`,
      headers: session.headers,
    });
    const inactive = await rotate(session, revoked.id);
    expect(inactive.statusCode).toBe(409);
    expect(inactive.json()).toMatchObject({
      code: 'API_KEY_INACTIVE',
      reason: 'revoked',
    });
    expect(await listed(session, revoked.id)).toMatchObject({
      status: 'revoked',
    });

    const viewer = await service.createUser({
      memberships: [{ orgId: org.id, role: 'viewer' }],
    });
    const viewerSession = await service.login(viewer.email, TEST_PASSWORD);
    expect((await rotate(viewerSession, revoked.id)).statusCode).toBe(403);
  });

  it('answers malformed path ids with 400 VALIDATION_FAILED naming the parameter', async () => {
    const admin = await service.loginAdmin();
    for (const [method, url] of [
      ['DELETE', '/api/v2/api-keys/not-a-uuid'],
      ['POST', '/api/v2/api-keys/not-a-uuid/rotate'],
    ] as const) {
      const response = await service.app.inject({
        method,
        url,
        headers: { ...admin.headers, 'content-type': 'application/json' },
      });
      expect(response.statusCode).toBe(400);
      expect(response.json()).toMatchObject({
        code: 'VALIDATION_FAILED',
        errors: [expect.objectContaining({ field: 'id' })],
      });
    }
  });
});
