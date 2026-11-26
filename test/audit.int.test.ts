import { randomBytes } from 'node:crypto';

import {
  type AuditRecordedV1,
  encodeEnvelope,
  EVENT_TYPES,
  makeEnvelope,
  subjectForEvent,
} from '@darmawanweb/ais-its-contracts/events';
import { newId } from '@darmawanweb/ais-its-contracts/domain';
import {
  type Database,
  DRIZZLE_DB,
  PG_POOL,
  type Pool,
} from '@darmawanweb/ais-its-nest/db';
import { DLQ_HEADERS, NatsClient } from '@darmawanweb/ais-its-nest/nats';
import { waitFor } from '@darmawanweb/ais-its-nest/testing';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import type * as schema from '../src/db/schema.js';
import { MembershipsRepository } from '../src/modules/accounts/memberships.repository.js';
import { OrganizationsRepository } from '../src/modules/accounts/organizations.repository.js';
import { UsersRepository } from '../src/modules/accounts/users.repository.js';
import { ApiKeysRepository } from '../src/modules/api-keys/api-keys.repository.js';
import { AuditLogsRepository } from '../src/modules/audit-logs/audit-logs.repository.js';
import {
  DEMO_USERS,
  DemoSeeder,
} from '../src/modules/bootstrap/demo-seeder.js';
import { BOOTSTRAP_ADMIN_NAME } from '../src/modules/bootstrap/platform-bootstrap.service.js';
import { PasswordHasher } from '../src/modules/crypto/password-hasher.service.js';

import {
  type Session,
  startTestService,
  TEST_ADMIN,
  TEST_PASSWORD,
  type TestService,
  WEB_ORIGIN,
} from './support/test-service.js';

interface AuditRecordBody {
  id: string;
  action: string;
  source: string;
  orgId: string | null;
  orgName: string | null;
  actorId: string | null;
  actorName: string | null;
  actorEmail: string | null;
  targetLabel: string | null;
  meta: Record<string, unknown>;
}

interface AuditPage {
  data: AuditRecordBody[];
  page: { nextCursor: string | null; limit: number };
}

describe('central audit log (consumer auth-audit, GET /audit-logs)', () => {
  let service: TestService;
  let admin: Session;

  beforeAll(async () => {
    service = await startTestService();
    admin = await service.loginAdmin();
  });

  afterAll(async () => {
    await service.close();
  });

  /** Publishes an audit record as another service would (source `fleet`). */
  const publishForeign = async (
    orgId: string | null,
    action: string,
    msgId?: string,
  ) => {
    const envelope = makeEnvelope({
      type: EVENT_TYPES.AUDIT_RECORDED,
      source: 'fleet',
      data: {
        actorType: 'user',
        actorId: newId(),
        orgId,
        action,
        targetType: 'vessel',
        targetId: '525005223',
        ip: '10.0.0.7',
        userAgent: 'fleet-test',
        meta: { fields: ['name'] },
        at: new Date().toISOString(),
      },
    });
    await app()
      .get(NatsClient)
      .jetstream.publish(subjectForEvent(envelope), encodeEnvelope(envelope), {
        msgID: msgId ?? envelope.id,
      });
    return envelope;
  };
  const app = () => service.app;

  /** Publishes an `audit.recorded.v1` of service `fleet` with these fields. */
  const publishRecord = async (data: Partial<AuditRecordedV1>) => {
    const envelope = makeEnvelope({
      type: EVENT_TYPES.AUDIT_RECORDED,
      source: 'fleet',
      data: {
        actorType: 'system',
        actorId: null,
        orgId: null,
        action: 'vessel.update',
        targetType: 'vessel',
        targetId: '525005223',
        ip: null,
        userAgent: null,
        meta: {},
        at: new Date().toISOString(),
        ...data,
      },
    });
    await app()
      .get(NatsClient)
      .jetstream.publish(subjectForEvent(envelope), encodeEnvelope(envelope), {
        msgID: envelope.id,
      });
    return envelope;
  };

  /** The record with this envelope id, once the consumer stored it. */
  const stored = (session: Session, id: string, query: string) =>
    waitFor(async () => {
      const { body } = await auditLogs(session, query);
      return body.data.find((entry) => entry.id === id);
    });

  const auditLogs = async (
    session: Session,
    query = '',
  ): Promise<{ status: number; body: AuditPage }> => {
    const response = await service.app.inject({
      method: 'GET',
      url: `/api/v2/audit-logs${query}`,
      headers: session.headers,
    });
    return { status: response.statusCode, body: response.json<AuditPage>() };
  };

  it('persists the records of other services once, even when redelivered', async () => {
    const org = await service.createOrganization();
    const envelope = await publishForeign(org.id, 'vessel.update');
    // The same envelope again under another Nats-Msg-Id: stored twice in the stream, persisted once.
    await service.app
      .get(NatsClient)
      .jetstream.publish(subjectForEvent(envelope), encodeEnvelope(envelope), {
        msgID: newId(),
      });

    const found = await waitFor(async () => {
      const { body } = await auditLogs(
        admin,
        `?orgId=${org.id}&action=vessel.update`,
      );
      return body.data.length > 0 ? body : undefined;
    });
    expect(found.data).toEqual([
      expect.objectContaining({
        id: envelope.id,
        source: 'fleet',
        orgId: org.id,
        action: 'vessel.update',
        meta: { fields: ['name'] },
      }),
    ]);
    await new Promise((resolve) => setTimeout(resolve, 500));
    expect((await auditLogs(admin, `?orgId=${org.id}`)).body.data).toHaveLength(
      1,
    );
  });

  it('stores records whose text PostgreSQL would refuse (NUL, lone surrogates) instead of retrying them', async () => {
    const org = await service.createOrganization();
    const envelope = makeEnvelope({
      type: EVENT_TYPES.AUDIT_RECORDED,
      source: 'fleet',
      data: {
        actorType: 'system',
        actorId: null,
        orgId: org.id,
        action: 'vessel.import',
        targetType: 'vessel',
        targetId: 'row\u0000 7',
        ip: null,
        userAgent: 'importer\u0000',
        meta: { 'file\u0000name': 'kapal\u0000.csv', bad: '\uD800', n: 3 },
        at: new Date().toISOString(),
      },
    });
    await app()
      .get(NatsClient)
      .jetstream.publish(subjectForEvent(envelope), encodeEnvelope(envelope), {
        msgID: envelope.id,
      });
    const found = await waitFor(async () => {
      const { body } = await auditLogs(
        admin,
        `?orgId=${org.id}&action=vessel.import`,
      );
      return body.data.length > 0 ? body : undefined;
    });
    expect(found.data[0]).toMatchObject({
      id: envelope.id,
      meta: { 'file\uFFFDname': 'kapal\uFFFD.csv', bad: '\uFFFD', n: 3 },
    });
  });

  it('audits everything pnpm seed:demo creates, in the seed transaction', async () => {
    const db = service.app.get<unknown, Database<typeof schema>>(DRIZZLE_DB);
    const seeder = new DemoSeeder(
      db,
      new OrganizationsRepository(db),
      new UsersRepository(db),
      new MembershipsRepository(db),
      new ApiKeysRepository(db),
      new PasswordHasher(),
      { repository: new AuditLogsRepository(db), source: 'auth' },
    );
    const result = await seeder.run('SeedSecret2026');
    expect(result.apiKeys.every((key) => key.key !== null)).toBe(true);
    const seeded = await auditLogs(admin, '?limit=200');
    const actions = seeded.body.data
      .filter((record) => record.meta.seed === 'demo')
      .map((record) => record.action);
    expect(actions.filter((action) => action === 'user.create')).toHaveLength(
      DEMO_USERS.length,
    );
    expect(
      actions.filter((action) => action === 'organization.create'),
    ).toHaveLength(2);
    expect(
      actions.filter((action) => action === 'api_key.create'),
    ).toHaveLength(2);
    expect(
      actions.filter((action) => action === 'membership.create'),
    ).toHaveLength(DEMO_USERS.length - 1);
    // A second run creates nothing and audits nothing more.
    await seeder.run('SeedSecret2026');
    const again = await auditLogs(admin, '?limit=200');
    expect(
      again.body.data.filter((record) => record.meta.seed === 'demo'),
    ).toHaveLength(actions.length);
  });

  it('records this service’s own security events through the same pipeline', async () => {
    const user = await service.createUser({ email: service.email('audited') });
    await service.login(user.email, TEST_PASSWORD);
    await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/login',
      headers: { 'x-forwarded-for': '198.51.100.9' },
      payload: { email: user.email, password: 'WrongPassword1' },
    });
    const succeeded = await waitFor(async () => {
      const { body } = await auditLogs(
        admin,
        `?actorId=${user.id}&action=auth.login.succeeded`,
      );
      return body.data[0];
    });
    expect(succeeded).toMatchObject({
      source: 'auth',
      actorId: user.id,
      meta: { mfa: false },
    });
    const failed = await waitFor(async () => {
      const { body } = await auditLogs(admin, '?action=auth.login.failed');
      return body.data.find((entry) => entry.meta.email === user.email);
    });
    expect(failed).toMatchObject({
      source: 'auth',
      actorId: null,
      meta: { reason: 'invalid_credentials', stage: 'password' },
    });

    const first = await service.createOrganization();
    const second = await service.createOrganization();
    const member = await service.createUser({
      email: service.email('switcher'),
      memberships: [
        { orgId: first.id, role: 'viewer' },
        { orgId: second.id, role: 'fleet_manager' },
      ],
    });
    const session = await service.login(member.email, TEST_PASSWORD);
    const fromOrgId = String(session.body.activeOrgId);
    const target = fromOrgId === first.id ? second.id : first.id;
    const switched = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/switch-org',
      headers: session.headers,
      payload: { orgId: target },
    });
    expect(switched.statusCode).toBe(200);
    const switchRecord = await waitFor(async () => {
      const { body } = await auditLogs(
        admin,
        `?actorId=${member.id}&action=auth.session.switch_org`,
      );
      return body.data[0];
    });
    expect(switchRecord).toMatchObject({
      source: 'auth',
      orgId: target,
      meta: { fromOrgId },
    });
  });

  it('keeps audit logs tenant-private and pages through them with a cursor', async () => {
    const mine = await service.createOrganization();
    const theirs = await service.createOrganization();
    for (let index = 0; index < 3; index += 1)
      await publishForeign(mine.id, 'vessel.update');
    await publishForeign(theirs.id, 'vessel.delete');
    await waitFor(
      async () =>
        (await auditLogs(admin, `?orgId=${mine.id}`)).body.data.length === 3,
    );
    await waitFor(
      async () =>
        (await auditLogs(admin, `?orgId=${theirs.id}`)).body.data.length === 1,
    );

    const orgAdmin = await service.createUser({
      memberships: [{ orgId: mine.id, role: 'org_admin' }],
    });
    const session = await service.login(orgAdmin.email, TEST_PASSWORD);
    const own = await auditLogs(session);
    expect(own.status).toBe(200);
    expect(own.body.data.every((entry) => entry.orgId === mine.id)).toBe(true);
    expect(
      own.body.data.filter((entry) => entry.source === 'fleet'),
    ).toHaveLength(3);
    expect((await auditLogs(session, `?orgId=${theirs.id}`)).status).toBe(403);

    const first = await auditLogs(admin, `?orgId=${mine.id}&limit=2`);
    expect(first.body.data).toHaveLength(2);
    expect(first.body.page.nextCursor).not.toBeNull();
    const second = await auditLogs(
      admin,
      `?orgId=${mine.id}&limit=2&cursor=${first.body.page.nextCursor ?? ''}`,
    );
    expect(second.body.data.length).toBeGreaterThanOrEqual(1);
    const ids = [...first.body.data, ...second.body.data].map(
      (entry) => entry.id,
    );
    expect(new Set(ids).size).toBe(ids.length);

    const viewer = await service.createUser({
      memberships: [{ orgId: mine.id, role: 'viewer' }],
    });
    const viewerSession = await service.login(viewer.email, TEST_PASSWORD);
    expect((await auditLogs(viewerSession)).status).toBe(403);
  });
  it('stores the names of actor, organization and target with each record', async () => {
    const org = await service.createOrganization('research', 'PT Label Uji');
    const orgAdmin = await service.createUser({
      email: service.email('label-admin'),
      name: 'Label Admin',
      memberships: [{ orgId: org.id, role: 'org_admin' }],
    });
    const session = await service.login(orgAdmin.email, TEST_PASSWORD);
    const invitee = service.email('label-invitee');
    const invited = await service.app.inject({
      method: 'POST',
      url: `/api/v2/organizations/${org.id}/members`,
      headers: session.headers,
      payload: { email: invitee, name: 'Invitee', role: 'viewer' },
    });
    expect(invited.statusCode).toBe(201);
    const own = await waitFor(async () => {
      const { body } = await auditLogs(session, '?action=membership.invite');
      return body.data[0];
    });
    expect(own).toMatchObject({
      source: 'auth',
      actorId: orgAdmin.id,
      actorName: 'Label Admin',
      actorEmail: orgAdmin.email,
      orgName: 'PT Label Uji',
      targetLabel: invitee,
    });

    const created = await service.app.inject({
      method: 'POST',
      url: '/api/v2/api-keys',
      headers: admin.headers,
      payload: { name: 'Pusher Label', scopes: ['ais:read'], orgId: org.id },
    });
    expect(created.statusCode).toBe(201);
    const keyId = created.json<{ apiKey: { id: string } }>().apiKey.id;
    // A foreign record by a user, named by the producer's meta.name …
    const byUser = await publishRecord({
      actorType: 'user',
      actorId: orgAdmin.id,
      orgId: org.id,
      action: 'engine.create',
      targetType: 'engine',
      targetId: newId(),
      meta: { name: 'Main engine', kind: 'main' },
    });
    // … one by an API key, about a vessel without a label …
    const byKey = await publishRecord({
      actorType: 'api_key',
      actorId: keyId,
      orgId: org.id,
      action: 'vessel.update',
      meta: { fields: ['name'] },
    });
    // … and one by the system about this service's user, with a producer label.
    const bySystem = await publishRecord({
      orgId: org.id,
      action: 'user.export',
      targetType: 'user',
      targetId: orgAdmin.id,
      meta: { targetLabel: 'ignored: own targets come from the tables' },
    });
    expect(
      await stored(admin, byUser.id, `?orgId=${org.id}&action=engine.create`),
    ).toMatchObject({
      actorName: 'Label Admin',
      actorEmail: orgAdmin.email,
      orgName: 'PT Label Uji',
      targetLabel: 'Main engine',
    });
    expect(
      await stored(admin, byKey.id, `?orgId=${org.id}&action=vessel.update`),
    ).toMatchObject({
      actorName: 'Pusher Label',
      actorEmail: null,
      targetLabel: null,
    });
    expect(
      await stored(admin, bySystem.id, `?orgId=${org.id}&action=user.export`),
    ).toMatchObject({
      actorName: null,
      actorEmail: null,
      targetLabel: `Label Admin <${orgAdmin.email}>`,
    });

    // Names captured with a record stay when the organization is renamed.
    const renamed = await service.app.inject({
      method: 'PATCH',
      url: `/api/v2/organizations/${org.id}`,
      headers: admin.headers,
      payload: { name: 'PT Label Baru' },
    });
    expect(renamed.statusCode).toBe(200);
    const after = await auditLogs(
      admin,
      `?orgId=${org.id}&action=engine.create`,
    );
    expect(after.body.data[0]?.orgName).toBe('PT Label Uji');
  });

  it('keeps the names of the write time when the organization changes before its records are stored', async () => {
    // Created, renamed and deleted at once: the records reach the consumer
    // after the changes (as during a NATS outage or consumer lag), so names
    // read on arrival would be the new name or none at all.
    const created = await service.app.inject({
      method: 'POST',
      url: '/api/v2/organizations',
      headers: admin.headers,
      payload: { name: 'PT Sekejap', kind: 'research' },
    });
    expect(created.statusCode).toBe(201);
    const orgId = created.json<{ id: string }>().id;
    const invitee = service.email('fleeting-invitee');
    const invited = await service.app.inject({
      method: 'POST',
      url: `/api/v2/organizations/${orgId}/members`,
      headers: admin.headers,
      payload: { email: invitee, name: 'Fleeting', role: 'viewer' },
    });
    expect(invited.statusCode).toBe(201);
    const cancelled = await service.app.inject({
      method: 'DELETE',
      url: `/api/v2/organizations/${orgId}/invitations/${invited.json<{ id: string }>().id}`,
      headers: admin.headers,
    });
    expect(cancelled.statusCode).toBe(204);
    const renamed = await service.app.inject({
      method: 'PATCH',
      url: `/api/v2/organizations/${orgId}`,
      headers: admin.headers,
      payload: { name: 'PT Sekejap Baru' },
    });
    expect(renamed.statusCode).toBe(200);
    const deleted = await service.app.inject({
      method: 'DELETE',
      url: `/api/v2/organizations/${orgId}`,
      headers: admin.headers,
    });
    expect(deleted.statusCode).toBe(204);

    const records = await waitFor(async () => {
      const { body } = await auditLogs(admin, `?orgId=${orgId}`);
      return body.data.length >= 5 ? body.data : undefined;
    });
    const byAction = Object.fromEntries(
      records.map((record) => [record.action, record]),
    );
    expect(byAction['organization.create']).toMatchObject({
      orgName: 'PT Sekejap',
      targetLabel: 'PT Sekejap',
    });
    expect(byAction['membership.invite.cancel']).toMatchObject({
      orgName: 'PT Sekejap',
      targetLabel: invitee,
    });
    expect(byAction['organization.update']).toMatchObject({
      orgName: 'PT Sekejap Baru',
      targetLabel: 'PT Sekejap Baru',
    });
    // Captured before the delete, in its transaction.
    expect(byAction['organization.delete']).toMatchObject({
      actorName: BOOTSTRAP_ADMIN_NAME,
      actorEmail: TEST_ADMIN.email,
      orgName: 'PT Sekejap Baru',
      targetLabel: 'PT Sekejap Baru',
    });
    // The names travel in meta.auditLabels, which is not stored.
    for (const record of records)
      expect(record.meta).not.toHaveProperty('auditLabels');
  });

  it('shows the current names for records stored without names (before 0.2.0)', async () => {
    const org = await service.createOrganization('research', 'PT Lama');
    const user = await service.createUser({
      email: service.email('old-record'),
      name: 'Old Actor',
    });
    const id = newId();
    await service.app.get(AuditLogsRepository).insert({
      id,
      at: new Date(),
      source: 'fleet',
      actorType: 'user',
      actorId: user.id,
      orgId: org.id,
      action: 'vessel.update',
      targetType: 'vessel',
      targetId: '525005223',
      ip: null,
      userAgent: null,
      meta: {},
    });
    const { body } = await auditLogs(admin, `?orgId=${org.id}`);
    expect(body.data.find((entry) => entry.id === id)).toMatchObject({
      actorName: 'Old Actor',
      actorEmail: user.email,
      orgName: 'PT Lama',
      targetLabel: null,
    });
    const filtered = await auditLogs(
      admin,
      `?orgId=${org.id}&actorEmail=${encodeURIComponent(user.email.toUpperCase())}`,
    );
    expect(filtered.body.data.map((entry) => entry.id)).toEqual([id]);
  });

  it('filters by action prefix and actor e-mail and lists the recorded actions', async () => {
    const org = await service.createOrganization('research');
    const other = await service.createOrganization('research');
    const actor = await service.createUser({
      email: service.email('prefix-actor'),
      memberships: [{ orgId: org.id, role: 'org_admin' }],
    });
    const records = [
      await publishRecord({ orgId: org.id, action: 'vessel.update' }),
      await publishRecord({
        orgId: org.id,
        action: 'vessel.update',
        actorType: 'user',
        actorId: actor.id,
      }),
      await publishRecord({ orgId: org.id, action: 'vessel.delete' }),
      await publishRecord({ orgId: org.id, action: 'engine.create' }),
      await publishRecord({ orgId: other.id, action: 'vessel_type.update' }),
    ];
    await waitFor(
      async () =>
        (await auditLogs(admin, `?orgId=${org.id}`)).body.data.length === 4,
    );
    await stored(admin, records[4]?.id ?? '', `?orgId=${other.id}`);

    const vessels = await auditLogs(
      admin,
      `?orgId=${org.id}&actionPrefix=vessel.`,
    );
    expect(vessels.body.data.map((entry) => entry.action).sort()).toEqual([
      'vessel.delete',
      'vessel.update',
      'vessel.update',
    ]);
    // `_` is literal in a prefix (vessel_type.update does not match vessel.).
    expect(
      (await auditLogs(admin, '?actionPrefix=vessel.')).body.data.some(
        (entry) => entry.action === 'vessel_type.update',
      ),
    ).toBe(false);
    const byActor = await auditLogs(
      admin,
      `?orgId=${org.id}&actorEmail=${encodeURIComponent(actor.email.toUpperCase())}`,
    );
    expect(byActor.body.data.map((entry) => entry.id)).toEqual([
      records[1]?.id,
    ]);
    const badPrefix = await auditLogs(admin, '?actionPrefix=Vessel');
    expect(badPrefix.status).toBe(400);

    const session = await service.login(actor.email, TEST_PASSWORD);
    const actions = await service.app.inject({
      method: 'GET',
      url: '/api/v2/audit-logs/actions',
      headers: session.headers,
    });
    expect(actions.statusCode).toBe(200);
    // The org admin's own sign-in (auth.login.succeeded) is in the scope too.
    const facet = actions.json<{
      data: { action: string; count: number; lastAt: string }[];
    }>().data;
    expect(facet.map((entry) => entry.action)).toEqual(
      [...facet.map((entry) => entry.action)].sort(),
    );
    expect(facet).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ action: 'engine.create', count: 1 }),
        expect.objectContaining({ action: 'vessel.delete', count: 1 }),
        expect.objectContaining({ action: 'vessel.update', count: 2 }),
      ]),
    );
    expect(facet.some((entry) => entry.action === 'vessel_type.update')).toBe(
      false,
    );
    const prefixed = await service.app.inject({
      method: 'GET',
      url: `/api/v2/audit-logs/actions?orgId=${org.id}&actionPrefix=vessel.u`,
      headers: admin.headers,
    });
    expect(
      prefixed.json<{ data: { action: string }[] }>().data.map((a) => a.action),
    ).toEqual(['vessel.update']);
    const foreign = await service.app.inject({
      method: 'GET',
      url: `/api/v2/audit-logs/actions?orgId=${other.id}`,
      headers: session.headers,
    });
    expect(foreign.statusCode).toBe(403);
    const tooLong = await service.app.inject({
      method: 'GET',
      url: '/api/v2/audit-logs/actions?from=2024-01-01T00:00:00Z&to=2026-01-01T00:00:00Z',
      headers: admin.headers,
    });
    expect(tooLong.statusCode).toBe(400);
    expect(tooLong.json()).toMatchObject({ code: 'VALIDATION_FAILED' });
  });

  it('exports the filtered records as a streamed CSV file (several batches)', async () => {
    const org = await service.createOrganization('research', 'PT Ekspor');
    const other = await service.createOrganization('research');
    const pool = service.app.get<unknown, Pool>(PG_POOL);
    // 1205 records: two full batches of 1000 and a short one.
    await pool.query(
      `INSERT INTO audit_logs (id, at, source, actor_type, org_id, action, target_type, target_id, user_agent, meta)
       SELECT gen_random_uuid(), now() - make_interval(secs => i), 'fleet', 'system', $1::uuid, 'vessel.update',
              'vessel', i::text, CASE WHEN i = 1 THEN '=cmd|calc' ELSE 'importer' END, '{"n": 1}'::jsonb
       FROM generate_series(1, 1205) AS i`,
      [org.id],
    );
    const response = await service.app.inject({
      method: 'GET',
      url: `/api/v2/audit-logs.csv?orgId=${org.id}`,
      headers: { ...admin.headers, origin: WEB_ORIGIN },
    });
    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toBe(
      'text/csv; charset=utf-8; header=present',
    );
    expect(String(response.headers['content-disposition'])).toMatch(
      new RegExp(
        `^attachment; filename="audit-logs-${org.id}-\\d{8}T\\d{6}Z_\\d{8}T\\d{6}Z\\.csv"$`,
      ),
    );
    expect(response.headers['cache-control']).toBe('no-store');
    expect(
      String(response.headers['access-control-expose-headers']).toLowerCase(),
    ).toContain('content-disposition');
    const lines = response.body.split('\r\n').filter((line) => line !== '');
    expect(lines[0]).toBe(
      'id,at,source,actorType,actorId,actorName,actorEmail,orgId,orgName,action,targetType,targetId,targetLabel,ip,userAgent,meta',
    );
    expect(lines).toHaveLength(1206);
    expect(new Set(lines.map((line) => line.split(',')[0])).size).toBe(1206);
    expect(lines[1]).toContain(
      ",PT Ekspor,vessel.update,vessel,1,,,'=cmd|calc,",
    );
    expect(lines[1]).toContain('"{""n"":1}"');

    const empty = await service.app.inject({
      method: 'GET',
      url: `/api/v2/audit-logs.csv?orgId=${org.id}&actionPrefix=nothing.`,
      headers: admin.headers,
    });
    expect(empty.body.split('\r\n').filter((line) => line !== '')).toHaveLength(
      1,
    );

    const orgAdmin = await service.createUser({
      memberships: [{ orgId: other.id, role: 'org_admin' }],
    });
    const otherSession = await service.login(orgAdmin.email, TEST_PASSWORD);
    const foreign = await service.app.inject({
      method: 'GET',
      url: `/api/v2/audit-logs.csv?orgId=${org.id}`,
      headers: otherSession.headers,
    });
    expect(foreign.statusCode).toBe(403);
    expect(foreign.headers['content-type']).toContain(
      'application/problem+json',
    );
    const viewer = await service.createUser({
      memberships: [{ orgId: org.id, role: 'viewer' }],
    });
    const viewerSession = await service.login(viewer.email, TEST_PASSWORD);
    const denied = await service.app.inject({
      method: 'GET',
      url: '/api/v2/audit-logs.csv',
      headers: viewerSession.headers,
    });
    expect(denied.statusCode).toBe(403);
  });

  it('dead-letters a record the database can never store at its first delivery', async () => {
    const org = await service.createOrganization('research');
    // Incompressible and far above the btree limit of 2704 bytes (54000).
    const targetId = randomBytes(3000).toString('base64');
    const envelope = await publishRecord({ orgId: org.id, targetId });
    const durable = `${service.config.NATS_DURABLE_PREFIX}auth-audit`;
    const dead = await waitFor(
      async () => {
        const message = await service.app
          .get(NatsClient)
          .manager.streams.getMessage('DLQ', {
            last_by_subj: `dlq.AUDIT.${durable}`,
          })
          .catch(() => undefined);
        return message?.json<{ id: string }>().id === envelope.id
          ? message
          : undefined;
      },
      { timeoutMs: 20_000 },
    );
    expect(dead.header.get(DLQ_HEADERS.ERROR_NAME)).toBe('DeadLetterError');
    expect(dead.header.get(DLQ_HEADERS.DELIVERY_COUNT)).toBe('1');
    const error = dead.header.get(DLQ_HEADERS.ERROR);
    expect(error).toContain(`Audit record ${envelope.id} (vessel.update)`);
    expect(error).toContain('SQLSTATE 54000');
    expect(error).not.toContain(targetId.slice(0, 40));
    expect((await auditLogs(admin, `?orgId=${org.id}`)).body.data).toEqual([]);
  });
});
