import type {
  OrgRole,
  Permission,
  Role,
} from '@darmawanweb/ais-its-contracts/auth';

/**
 * Authorization rules of the identity resources (spec §8.4, §8.5, §13.1).
 * The route guard checks permissions; these functions add the tenant rules
 * the guard cannot know (which organization a resource belongs to), so they
 * are applied in the services on data loaded from the database — never on
 * organization ids sent by the client.
 *
 * @see docs/PLATFORM_SPEC.md §8.4 (role matrix), §8.5 (tenancy), §13.1 (members)
 */
export interface Actor {
  /** Holds the platform role `super_admin`. */
  readonly isPlatformAdmin: boolean;
  /** Active organization of the access token. */
  readonly orgId: string | null;
  can(permission: Permission): boolean;
}

/** Kinds of organizations (`organizations.kind`). */
export const ORGANIZATION_KINDS = [
  'shipping_company',
  'authority',
  'platform',
  'research',
] as const;

/** An organization kind. */
export type OrganizationKind = (typeof ORGANIZATION_KINDS)[number];

/** `true` when the actor acts within `orgId`: its active organization, or any for super admins. */
function actsWithin(actor: Actor, orgId: string): boolean {
  return actor.isPlatformAdmin || actor.orgId === orgId;
}

/**
 * Members of an organization are managed by its `org_admin`s (permission
 * `user:manage`, active organization) and by super admins.
 */
export function canManageMembers(actor: Actor, orgId: string): boolean {
  return actor.can('user:manage') && actsWithin(actor, orgId);
}

/**
 * An organization is visible to `org:manage` holders (super admins) and to
 * its own members (any role, whatever their active organization).
 */
export function canViewOrganization(actor: Actor, isMember: boolean): boolean {
  return actor.can('org:manage') || isMember;
}

/** API keys are managed by `org_admin`s of the key's organization and by super admins. */
export function canManageApiKeys(actor: Actor, keyOrgId: string): boolean {
  return actor.can('api_key:manage') && actsWithin(actor, keyOrgId);
}

/**
 * The audit log is readable per organization by `audit:read` holders of that
 * organization; super admins read every organization and platform records
 * (`orgId = null`).
 */
export function canReadAuditLogs(actor: Actor, orgId: string | null): boolean {
  if (!actor.can('audit:read')) return false;
  if (actor.isPlatformAdmin) return true;
  return orgId !== null && actor.orgId === orgId;
}

/**
 * Roles an organization of `kind` may grant. `authority` carries
 * cross-tenant read access to safety and surveillance data (§8.5), so it is
 * reserved for organizations of kind `authority`: an `org_admin` of a
 * shipping company cannot hand it out.
 */
export function grantableRoles(kind: OrganizationKind): readonly OrgRole[] {
  return kind === 'authority'
    ? ['org_admin', 'fleet_manager', 'authority', 'viewer']
    : ['org_admin', 'fleet_manager', 'viewer'];
}

/** `true` when `role` may be granted in an organization of `kind`. */
export function isRoleGrantable(
  kind: OrganizationKind,
  role: OrgRole,
): boolean {
  return grantableRoles(kind).includes(role);
}

/**
 * Roles held in an organization that it could no longer grant as `kind`
 * (e.g. `authority` members when an authority becomes a shipping company).
 * Such a kind change is refused until those members get another role, so
 * every membership keeps satisfying {@link grantableRoles}.
 *
 * @param rolesInUse the roles of the organization's current members.
 * @returns the stranded roles, deduplicated and sorted; empty when the change is safe.
 */
export function rolesStrandedByKind(
  kind: OrganizationKind,
  rolesInUse: readonly OrgRole[],
): OrgRole[] {
  return [...new Set(rolesInUse)]
    .filter((role) => !isRoleGrantable(kind, role))
    .sort();
}

/**
 * Last-admin protection: `true` when changing `userId`'s membership to
 * `nextRole` (`null` = removal) would leave the organization without an
 * `org_admin`.
 *
 * @param adminUserIds the current `org_admin`s of the organization (read under a lock).
 */
export function removesLastAdmin(
  adminUserIds: readonly string[],
  userId: string,
  nextRole: OrgRole | null,
): boolean {
  if (nextRole === 'org_admin') return false;
  if (!adminUserIds.includes(userId)) return false;
  return adminUserIds.length <= 1;
}

/**
 * Roles of an access token (spec §8.2): the membership role in the active
 * organization plus the platform role `super_admin` of platform admins.
 */
export function accessRoles(
  membershipRole: OrgRole | null,
  isPlatformAdmin: boolean,
): Role[] {
  const roles: Role[] = [];
  if (membershipRole !== null) roles.push(membershipRole);
  if (isPlatformAdmin) roles.push('super_admin');
  return roles;
}
