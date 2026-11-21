import { type Permission, permissionsForRoles, type Role } from '@darmawanweb/ais-its-contracts/auth';
import { describe, expect, it } from 'vitest';

import {
  accessRoles,
  type Actor,
  canManageApiKeys,
  canManageMembers,
  canReadAuditLogs,
  canViewOrganization,
  grantableRoles,
  isRoleGrantable,
  removesLastAdmin,
} from './access-rules.js';

const ORG = '01a1f000-0000-7000-8000-000000000001';
const OTHER = '01a1f000-0000-7000-8000-000000000002';

/** An actor with the permissions of `roles` (contracts ROLE_PERMISSIONS). */
function actor(roles: readonly Role[], orgId: string | null = ORG): Actor {
  const permissions = permissionsForRoles(roles);
  return {
    isPlatformAdmin: roles.includes('super_admin'),
    orgId,
    can: (permission: Permission) => permissions.has(permission),
  };
}

describe('access rules (spec §8.4, §8.5, §13.1)', () => {
  it('lets org_admins manage members of their active organization only, super admins all', () => {
    expect(canManageMembers(actor(['org_admin']), ORG)).toBe(true);
    expect(canManageMembers(actor(['org_admin']), OTHER)).toBe(false);
    expect(canManageMembers(actor(['fleet_manager']), ORG)).toBe(false);
    expect(canManageMembers(actor(['viewer']), ORG)).toBe(false);
    expect(canManageMembers(actor(['super_admin'], null), OTHER)).toBe(true);
  });

  it('shows an organization to its members and to org:manage holders', () => {
    expect(canViewOrganization(actor(['viewer']), true)).toBe(true);
    expect(canViewOrganization(actor(['org_admin']), false)).toBe(false);
    expect(canViewOrganization(actor(['super_admin'], null), false)).toBe(true);
  });

  it('lets only the key organization’s org_admins and super admins manage API keys', () => {
    expect(canManageApiKeys(actor(['org_admin']), ORG)).toBe(true);
    expect(canManageApiKeys(actor(['org_admin']), OTHER)).toBe(false);
    expect(canManageApiKeys(actor(['fleet_manager']), ORG)).toBe(false);
    expect(canManageApiKeys(actor(['authority']), ORG)).toBe(false);
    expect(canManageApiKeys(actor(['super_admin'], null), OTHER)).toBe(true);
  });

  it('restricts the audit log to the own organization (super admins: all, incl. platform records)', () => {
    expect(canReadAuditLogs(actor(['org_admin']), ORG)).toBe(true);
    expect(canReadAuditLogs(actor(['org_admin']), OTHER)).toBe(false);
    expect(canReadAuditLogs(actor(['org_admin']), null)).toBe(false);
    expect(canReadAuditLogs(actor(['viewer']), ORG)).toBe(false);
    expect(canReadAuditLogs(actor(['super_admin'], null), null)).toBe(true);
  });

  it('reserves the authority role for authority organizations', () => {
    expect(grantableRoles('authority')).toContain('authority');
    expect(isRoleGrantable('shipping_company', 'authority')).toBe(false);
    expect(isRoleGrantable('platform', 'authority')).toBe(false);
    expect(isRoleGrantable('research', 'viewer')).toBe(true);
    expect(isRoleGrantable('shipping_company', 'org_admin')).toBe(true);
  });

  it('never removes or demotes the last org_admin', () => {
    expect(removesLastAdmin(['a'], 'a', null)).toBe(true);
    expect(removesLastAdmin(['a'], 'a', 'viewer')).toBe(true);
    expect(removesLastAdmin(['a'], 'a', 'org_admin')).toBe(false);
    expect(removesLastAdmin(['a', 'b'], 'a', null)).toBe(false);
    expect(removesLastAdmin(['a'], 'b', null)).toBe(false);
    expect(removesLastAdmin([], 'b', 'viewer')).toBe(false);
  });

  it('builds token roles from the membership plus the platform role', () => {
    expect(accessRoles('fleet_manager', false)).toEqual(['fleet_manager']);
    expect(accessRoles('org_admin', true)).toEqual(['org_admin', 'super_admin']);
    expect(accessRoles(null, true)).toEqual(['super_admin']);
    expect(accessRoles(null, false)).toEqual([]);
  });
});
