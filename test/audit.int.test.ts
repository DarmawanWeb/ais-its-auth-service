import {
  encodeEnvelope,
  EVENT_TYPES,
  makeEnvelope,
  subjectForEvent,
} from '@darmawanweb/ais-its-contracts/events';
import { newId } from '@darmawanweb/ais-its-contracts/domain';
import { type Database, DRIZZLE_DB } from '@darmawanweb/ais-its-nest/db';
import { NatsClient } from '@darmawanweb/ais-its-nest/nats';
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
import { PasswordHasher } from '../src/modules/crypto/password-hasher.service.js';

import {
  type Session,
  startTestService,
  TEST_PASSWORD,
  type TestService,
} from './support/test-service.js';

interface AuditPage {
  data: {
    id: string;
    action: string;
    source: string;
    orgId: string | null;
    actorId: string | null;
    meta: Record<string, unknown>;
  }[];
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
});
