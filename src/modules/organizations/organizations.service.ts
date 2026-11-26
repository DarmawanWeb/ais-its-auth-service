import {
  type PageQuery,
  type Paginated,
  pageOffset,
  toPaginated,
} from '@darmawanweb/ais-its-contracts/api';
import { newId } from '@darmawanweb/ais-its-contracts/domain';
import type { AuditRequest } from '@darmawanweb/ais-its-nest/audit';
import type { Principal } from '@darmawanweb/ais-its-nest/auth';
import { isUniqueViolation } from '@darmawanweb/ais-its-nest/db';
import { Injectable } from '@nestjs/common';

import { AuthErrors } from '../../common/errors.js';
import { requireUser } from '../../common/principals.js';
import type { OrganizationRow } from '../../db/database.js';
import { Transactions } from '../../db/transactions.js';
import {
  canViewOrganization,
  type OrganizationKind,
  rolesStrandedByKind,
} from '../../domain/access-rules.js';
import { slugify } from '../../domain/identity.js';
import { InvitationsRepository } from '../accounts/invitations.repository.js';
import { MembershipsRepository } from '../accounts/memberships.repository.js';
import {
  ORGANIZATION_SLUG_CONSTRAINT,
  type OrganizationChanges,
  type OrganizationFilter,
  type OrganizationKindCounts,
  type OrganizationListRow,
  OrganizationsRepository,
} from '../accounts/organizations.repository.js';
import { SessionsRepository } from '../accounts/sessions.repository.js';

/** Fields of a new organization. */
export interface CreateOrganizationInput {
  readonly name: string;
  readonly slug?: string | undefined;
  readonly kind: Exclude<OrganizationKind, 'platform'>;
}

/**
 * Organizations (tenants, spec §13.1): managed by `org:manage` holders
 * (super admins); members may read their own organizations. The platform
 * organization cannot be deleted or change its kind.
 */
@Injectable()
export class OrganizationsService {
  constructor(
    private readonly transactions: Transactions,
    private readonly organizations: OrganizationsRepository,
    private readonly memberships: MembershipsRepository,
    private readonly invitations: InvitationsRepository,
    private readonly sessions: SessionsRepository,
  ) {}

  /** One page of organizations, by name, with their member and API key counts. */
  async list(
    filter: OrganizationFilter,
    page: PageQuery,
  ): Promise<Paginated<OrganizationListRow>> {
    const { rows, total } = await this.organizations.list(filter, {
      offset: pageOffset(page),
      limit: page.pageSize,
    });
    return toPaginated(rows, page, total);
  }

  /** Organizations per kind over every page (optionally those matching `search`). */
  async stats(filter: {
    readonly search?: string | undefined;
  }): Promise<{ total: number; byKind: OrganizationKindCounts }> {
    const byKind = await this.organizations.countByKind(filter);
    const total = Object.values(byKind).reduce((sum, value) => sum + value, 0);
    return { total, byKind };
  }

  /**
   * An organization visible to the principal (`org:manage`, or a member);
   * others get `404`, so the existence of other tenants is not revealed.
   */
  async get(id: string, principal: Principal): Promise<OrganizationRow> {
    const actor = requireUser(principal);
    const organization = await this.organizations.findById(id);
    if (organization === undefined) throw AuthErrors.organizationNotFound(id);
    const isMember = (await this.memberships.find(actor.id, id)) !== undefined;
    if (!canViewOrganization(actor, isMember))
      throw AuthErrors.organizationNotFound(id);
    return organization;
  }

  /** Creates an organization; the slug is derived from the name when omitted. */
  async create(
    input: CreateOrganizationInput,
    principal: Principal,
    request: AuditRequest,
  ): Promise<OrganizationRow> {
    const slug = input.slug ?? slugify(input.name);
    if (slug === null) throw AuthErrors.slugRequired();
    return uniqueSlug(slug, () =>
      this.transactions.run(async ({ tx, audit }) => {
        const organization = await this.organizations.insert(
          { id: newId(), name: input.name, slug, kind: input.kind },
          tx,
        );
        await audit(
          {
            action: 'organization.create',
            targetType: 'organization',
            targetId: organization.id,
            orgId: organization.id,
            meta: { name: organization.name, slug, kind: organization.kind },
          },
          principal,
          request,
        );
        return organization;
      }),
    );
  }

  /**
   * Changes name, slug or kind. The platform organization keeps its kind,
   * and a kind change that would strand members' roles (e.g. `authority`
   * members of an organization becoming a shipping company) is refused
   * with `409 ORGANIZATION_KIND_CONFLICT`; the row lock serializes it with
   * membership writes (they share-lock the organization).
   */
  async update(
    id: string,
    changes: OrganizationChanges,
    principal: Principal,
    request: AuditRequest,
  ): Promise<OrganizationRow> {
    const fields = (['name', 'slug', 'kind'] as const).filter(
      (field) => changes[field] !== undefined,
    );
    return uniqueSlug(changes.slug, () =>
      this.transactions.run(async ({ tx, audit }) => {
        const current = await this.organizations.lockById(id, tx);
        if (current === undefined) throw AuthErrors.organizationNotFound(id);
        const kind = changes.kind;
        if (
          current.kind === 'platform' &&
          kind !== undefined &&
          kind !== 'platform'
        ) {
          throw AuthErrors.organizationProtected(
            'The platform organization cannot change its kind',
          );
        }
        if (fields.length === 0) return current;
        if (kind !== undefined && kind !== current.kind) {
          // Pending invitations count: every invitation stays acceptable.
          const stranded = rolesStrandedByKind(kind, [
            ...(await this.memberships.rolesInUse(id, tx)),
            ...(await this.invitations.rolesInUse(id, tx)),
          ]);
          if (stranded.length > 0)
            throw AuthErrors.kindStrandsRoles(kind, stranded);
        }
        const row = await this.organizations.update(id, changes, tx);
        if (row === undefined) throw AuthErrors.organizationNotFound(id);
        await audit(
          {
            action: 'organization.update',
            targetType: 'organization',
            targetId: id,
            orgId: id,
            meta: { fields },
          },
          principal,
          request,
        );
        return row;
      }),
    );
  }

  /**
   * Deletes an organization with its memberships and API keys, and revokes
   * the sessions working in it. The platform organization is protected.
   */
  async remove(
    id: string,
    principal: Principal,
    request: AuditRequest,
  ): Promise<void> {
    await this.transactions.run(async ({ tx, audit }) => {
      const organization = await this.organizations.lockById(id, tx);
      if (organization === undefined) throw AuthErrors.organizationNotFound(id);
      if (organization.kind === 'platform') {
        throw AuthErrors.organizationProtected(
          'The platform organization cannot be deleted',
        );
      }
      const revokedSessions = await this.sessions.revokeOfOrg(id, tx);
      // Before the delete: the record captures the organization's name as
      // `orgName` and `targetLabel` (it commits or rolls back with it).
      await audit(
        {
          action: 'organization.delete',
          targetType: 'organization',
          targetId: id,
          orgId: id,
          meta: {
            name: organization.name,
            slug: organization.slug,
            revokedSessions,
          },
        },
        principal,
        request,
      );
      await this.organizations.delete(id, tx);
    });
  }
}

/**
 * Runs a write and maps a taken slug to `409 ORGANIZATION_SLUG_TAKEN`
 * (`slug` is the slug the write sets; `undefined` keeps the current one).
 */
async function uniqueSlug<T>(
  slug: string | undefined,
  write: () => Promise<T>,
): Promise<T> {
  try {
    return await write();
  } catch (error) {
    if (
      slug !== undefined &&
      isUniqueViolation(error, ORGANIZATION_SLUG_CONSTRAINT)
    )
      throw AuthErrors.slugTaken(slug);
    throw error;
  }
}
