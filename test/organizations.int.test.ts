import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  type Session,
  startTestService,
  TEST_PASSWORD,
  type TestService,
  tokenOfLink,
  WEB_ORIGIN,
} from './support/test-service.js';

interface MemberBody {
  userId: string;
  email: string;
  role: string;
  status: string;
  invitationSent: boolean;
}

describe('organizations, invitations and members', () => {
  let service: TestService;
  let admin: Session;

  beforeAll(async () => {
    service = await startTestService();
    admin = await service.loginAdmin();
  });

  afterAll(async () => {
    await service.close();
  });

  const createOrganization = async (name: string, kind: string) => {
    const response = await service.app.inject({
      method: 'POST',
      url: '/api/v2/organizations',
      headers: admin.headers,
      payload: { name, kind },
    });
    expect(response.statusCode).toBe(201);
    return response.json<{ id: string; slug: string; kind: string }>();
  };

  const invite = (
    session: Session,
    orgId: string,
    payload: Record<string, unknown>,
  ) =>
    service.app.inject({
      method: 'POST',
      url: `/api/v2/organizations/${orgId}/members`,
      headers: session.headers,
      payload,
    });

  it('creates organizations with derived slugs and refuses taken slugs', async () => {
    const org = await createOrganization(
      'PT Pelayaran Sejahtera Abadi',
      'shipping_company',
    );
    expect(org).toMatchObject({
      slug: 'pt-pelayaran-sejahtera-abadi',
      kind: 'shipping_company',
    });
    const duplicate = await service.app.inject({
      method: 'POST',
      url: '/api/v2/organizations',
      headers: admin.headers,
      payload: { name: 'Other', slug: org.slug, kind: 'research' },
    });
    expect(duplicate.statusCode).toBe(409);
    expect(duplicate.json()).toMatchObject({ code: 'ORGANIZATION_SLUG_TAKEN' });
    const platform = await service.app.inject({
      method: 'POST',
      url: '/api/v2/organizations',
      headers: admin.headers,
      payload: { name: 'Second platform', kind: 'platform' },
    });
    expect(platform.statusCode).toBe(400);

    const list = await service.app.inject({
      method: 'GET',
      url: '/api/v2/organizations?search=sejahtera',
      headers: admin.headers,
    });
    expect(list.json()).toMatchObject({
      data: [{ id: org.id }],
      meta: { page: 1, pageSize: 20, total: 1 },
    });
  });

  it('invites a new member by e-mail; the invitation link activates the account', async () => {
    const org = await createOrganization(
      'PT Invitasi Bahari',
      'shipping_company',
    );
    const email = service.email('invitee');
    const sequence = await service.lastEmailSequence();
    const added = await invite(admin, org.id, {
      email,
      name: 'Dewi Lestari',
      role: 'org_admin',
      locale: 'en',
    });
    expect(added.statusCode).toBe(201);
    expect(added.json<MemberBody>()).toMatchObject({
      email,
      role: 'org_admin',
      status: 'invited',
      invitationSent: true,
    });

    const message = await service.nextEmail(email, sequence);
    expect(message).toMatchObject({
      template: 'account_invite',
      locale: 'en',
      data: {
        name: 'Dewi Lestari',
        organizationName: 'PT Invitasi Bahari',
        role: 'org_admin',
      },
    });
    expect(String(message.data.link)).toMatch(
      /^http:\/\/localhost:8000\/accept-invite#token=/,
    );

    // Not active yet: no login.
    await expect(service.login(email, 'InvitedSecret1')).rejects.toThrow(/401/);
    const accept = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/password/reset',
      payload: {
        token: tokenOfLink(message.data.link),
        password: 'InvitedSecret1',
      },
    });
    expect(accept.statusCode).toBe(204);
    const session = await service.login(email, 'InvitedSecret1');
    expect(session.body).toMatchObject({
      activeOrgId: org.id,
      user: { status: 'active' },
    });

    // Members read their own organization; others do not see it.
    const own = await service.app.inject({
      method: 'GET',
      url: `/api/v2/organizations/${org.id}`,
      headers: session.headers,
    });
    expect(own.statusCode).toBe(200);
    const elsewhere = await createOrganization('PT Lain', 'shipping_company');
    const hidden = await service.app.inject({
      method: 'GET',
      url: `/api/v2/organizations/${elsewhere.id}`,
      headers: session.headers,
    });
    expect(hidden.statusCode).toBe(404);
    const directory = await service.app.inject({
      method: 'GET',
      url: '/api/v2/organizations',
      headers: session.headers,
    });
    expect(directory.statusCode).toBe(403);
  });

  it('lets org_admins manage only their organization and keeps the last org_admin', async () => {
    const org = await createOrganization(
      'PT Admin Terakhir',
      'shipping_company',
    );
    const other = await createOrganization('PT Tetangga', 'shipping_company');
    const orgAdmin = await service.createUser({
      email: service.email('lastadmin'),
      memberships: [{ orgId: org.id, role: 'org_admin' }],
    });
    const session = await service.login(orgAdmin.email, TEST_PASSWORD);

    const foreign = await invite(session, other.id, {
      email: service.email('x'),
      name: 'X',
      role: 'viewer',
    });
    expect(foreign.statusCode).toBe(403);
    const foreignList = await service.app.inject({
      method: 'GET',
      url: `/api/v2/organizations/${other.id}/members`,
      headers: session.headers,
    });
    expect(foreignList.statusCode).toBe(403);

    const authorityRole = await invite(session, org.id, {
      email: service.email('auth'),
      name: 'A',
      role: 'authority',
    });
    expect(authorityRole.statusCode).toBe(422);
    expect(authorityRole.json()).toMatchObject({ code: 'ROLE_NOT_GRANTABLE' });

    const demote = await service.app.inject({
      method: 'PATCH',
      url: `/api/v2/organizations/${org.id}/members/${orgAdmin.id}`,
      headers: session.headers,
      payload: { role: 'viewer' },
    });
    expect(demote.statusCode).toBe(409);
    expect(demote.json()).toMatchObject({ code: 'LAST_ORG_ADMIN' });
    const leave = await service.app.inject({
      method: 'DELETE',
      url: `/api/v2/organizations/${org.id}/members/${orgAdmin.id}`,
      headers: session.headers,
    });
    expect(leave.statusCode).toBe(409);

    // With a second admin, the first may step down.
    const second = await service.createUser({
      email: service.email('secondadmin'),
    });
    const added = await invite(session, org.id, {
      email: second.email,
      name: 'ignored',
      role: 'org_admin',
    });
    expect(added.statusCode).toBe(201);
    expect(added.json<MemberBody>()).toMatchObject({
      userId: second.id,
      status: 'active',
      invitationSent: false,
    });
    const again = await invite(session, org.id, {
      email: second.email,
      name: 'ignored',
      role: 'viewer',
    });
    expect(again.statusCode).toBe(409);
    expect(again.json()).toMatchObject({ code: 'MEMBER_ALREADY_EXISTS' });

    const stepDown = await service.app.inject({
      method: 'PATCH',
      url: `/api/v2/organizations/${org.id}/members/${orgAdmin.id}`,
      headers: session.headers,
      payload: { role: 'fleet_manager' },
    });
    expect(stepDown.statusCode).toBe(200);
    expect(stepDown.json()).toMatchObject({ role: 'fleet_manager' });

    const members = await service.app.inject({
      method: 'GET',
      url: `/api/v2/organizations/${org.id}/members`,
      headers: admin.headers,
    });
    expect(
      members
        .json<{ data: MemberBody[] }>()
        .data.map((member) => member.role)
        .sort(),
    ).toEqual(['fleet_manager', 'org_admin']);
  });

  it('removing a member revokes their refresh sessions in that organization', async () => {
    const org = await createOrganization('PT Keluar', 'shipping_company');
    const member = await service.createUser({
      email: service.email('leaver'),
      memberships: [{ orgId: org.id, role: 'viewer' }],
    });
    const session = await service.login(member.email, TEST_PASSWORD);
    const removed = await service.app.inject({
      method: 'DELETE',
      url: `/api/v2/organizations/${org.id}/members/${member.id}`,
      headers: admin.headers,
    });
    expect(removed.statusCode).toBe(204);
    // The access token stays valid until it expires (short TTL) …
    const me = await service.app.inject({
      method: 'GET',
      url: '/api/v2/me',
      headers: session.headers,
    });
    expect(me.statusCode).toBe(200);
    // … but the session cannot be refreshed any more.
    const refresh = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/refresh',
      headers: { cookie: session.cookie, origin: WEB_ORIGIN },
    });
    expect(refresh.statusCode).toBe(401);
    const missing = await service.app.inject({
      method: 'DELETE',
      url: `/api/v2/organizations/${org.id}/members/${member.id}`,
      headers: admin.headers,
    });
    expect(missing.statusCode).toBe(404);
  });

  it('grants authority only in authority organizations and protects the platform organization', async () => {
    const authorities = await createOrganization(
      'Demo Syahbandar',
      'authority',
    );
    const officer = await invite(admin, authorities.id, {
      email: service.email('officer'),
      name: 'Officer Budi',
      role: 'authority',
    });
    expect(officer.statusCode).toBe(201);

    // The authority role cannot be stranded by turning the organization into a shipping company.
    const rekind = await service.app.inject({
      method: 'PATCH',
      url: `/api/v2/organizations/${authorities.id}`,
      headers: admin.headers,
      payload: { kind: 'shipping_company' },
    });
    expect(rekind.statusCode).toBe(409);
    expect(rekind.json()).toMatchObject({
      code: 'ORGANIZATION_KIND_CONFLICT',
      roles: ['authority'],
    });
    const renamed = await service.app.inject({
      method: 'PATCH',
      url: `/api/v2/organizations/${authorities.id}`,
      headers: admin.headers,
      payload: { name: 'Demo Syahbandar Utama', kind: 'authority' },
    });
    expect(renamed.statusCode).toBe(200);
    expect(renamed.json()).toMatchObject({
      name: 'Demo Syahbandar Utama',
      kind: 'authority',
    });

    const platformId = String(admin.body.activeOrgId);
    const deletePlatform = await service.app.inject({
      method: 'DELETE',
      url: `/api/v2/organizations/${platformId}`,
      headers: admin.headers,
    });
    expect(deletePlatform.statusCode).toBe(409);
    expect(deletePlatform.json()).toMatchObject({
      code: 'ORGANIZATION_PROTECTED',
    });

    const doomed = await createOrganization('PT Bubar', 'research');
    const member = await service.createUser({
      email: service.email('doomed'),
      memberships: [{ orgId: doomed.id, role: 'viewer' }],
    });
    const session = await service.login(member.email, TEST_PASSWORD);
    const deleted = await service.app.inject({
      method: 'DELETE',
      url: `/api/v2/organizations/${doomed.id}`,
      headers: admin.headers,
    });
    expect(deleted.statusCode).toBe(204);
    const refresh = await service.app.inject({
      method: 'POST',
      url: '/api/v2/auth/refresh',
      headers: { cookie: session.cookie, origin: WEB_ORIGIN },
    });
    expect(refresh.statusCode).toBe(401);
  });

  it('searches the user directory (super admins only)', async () => {
    const user = await service.createUser({
      email: service.email('findme'),
      name: 'Findable Person',
    });
    const found = await service.app.inject({
      method: 'GET',
      url: '/api/v2/users?search=findable',
      headers: admin.headers,
    });
    expect(found.json()).toMatchObject({
      data: [{ id: user.id, memberships: [] }],
      meta: { total: 1 },
    });
    const session = await service.login(user.email, TEST_PASSWORD);
    const denied = await service.app.inject({
      method: 'GET',
      url: '/api/v2/users',
      headers: session.headers,
    });
    expect(denied.statusCode).toBe(403);
  });
});
