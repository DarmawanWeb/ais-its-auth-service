import { PG_POOL, type Pool } from '@darmawanweb/ais-its-nest/db';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  startTestService,
  TEST_PASSWORD,
  type TestService,
} from './support/test-service.js';

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
      payload: { name: 'AIS pusher Batam', scopes: ['ais:ingest'] },
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
      scopes: ['ais:ingest'],
      name: 'AIS pusher Batam',
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
});
