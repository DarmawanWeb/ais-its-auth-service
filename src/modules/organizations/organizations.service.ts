import {
  type PageQuery,
  type Paginated,
  pageOffset,
  toPaginated,
} from '@darmawanweb/ais-its-contracts/api';
import { newId } from '@darmawanweb/ais-its-contracts/domain';
import {
  type AuditRequest,
  AuditService,
} from '@darmawanweb/ais-its-nest/audit';
import type { Principal } from '@darmawanweb/ais-its-nest/auth';
import { type Database, InjectDb } from '@darmawanweb/ais-its-nest/db';
import { Injectable } from '@nestjs/common';

import { AuthErrors } from '../../common/errors.js';
import { requireUser } from '../../common/principals.js';
import type { OrganizationRow } from '../../db/database.js';
import { isUniqueViolation } from '../../db/errors.js';
import type * as schema from '../../db/schema.js';
import {
  canViewOrganization,
  type OrganizationKind,
} from '../../domain/access-rules.js';
import { slugify } from '../../domain/identity.js';
import { MembershipsRepository } from '../accounts/memberships.repository.js';
import {
  ORGANIZATION_SLUG_CONSTRAINT,
  type OrganizationChanges,
  type OrganizationFilter,
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
    @InjectDb() private readonly db: Database<typeof schema>,
    private readonly organizations: OrganizationsRepository,
    private readonly memberships: MembershipsRepository,
    private readonly sessions: SessionsRepository,
    private readonly audit: AuditService,
  ) {}

  /** One page of organizations, by name. */
  async list(
    filter: OrganizationFilter,
    page: PageQuery,
  ): Promise<Paginated<OrganizationRow>> {
    const { rows, total } = await this.organizations.list(filter, {
      offset: pageOffset(page),
      limit: page.pageSize,
    });
    return toPaginated(rows, page, total);
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
    const organization = await uniqueSlug(slug, () =>
      this.organizations.insert({
        id: newId(),
        name: input.name,
        slug,
        kind: input.kind,
      }),
    );
    await this.audit.record(
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
  }

  /** Changes name, slug or kind (the platform organization keeps its kind). */
  async update(
    id: string,
    changes: OrganizationChanges,
    principal: Principal,
    request: AuditRequest,
  ): Promise<OrganizationRow> {
    const current = await this.organizations.findById(id);
    if (current === undefined) throw AuthErrors.organizationNotFound(id);
    if (
      current.kind === 'platform' &&
      changes.kind !== undefined &&
      changes.kind !== 'platform'
    ) {
      throw AuthErrors.organizationProtected(
        'The platform organization cannot change its kind',
      );
    }
    const fields = (['name', 'slug', 'kind'] as const).filter(
      (field) => changes[field] !== undefined,
    );
    if (fields.length === 0) return current;
    const updated = await uniqueSlug(changes.slug ?? current.slug, () =>
      this.organizations.update(id, changes),
    );
    if (updated === undefined) throw AuthErrors.organizationNotFound(id);
    await this.audit.record(
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
    return updated;
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
    const deleted = await this.db.transaction(async (tx) => {
      const organization = await this.organizations.lockById(id, tx);
      if (organization === undefined) throw AuthErrors.organizationNotFound(id);
      if (organization.kind === 'platform') {
        throw AuthErrors.organizationProtected(
          'The platform organization cannot be deleted',
        );
      }
      const revokedSessions = await this.sessions.revokeOfOrg(id, tx);
      await this.organizations.delete(id, tx);
      return { organization, revokedSessions };
    });
    await this.audit.record(
      {
        action: 'organization.delete',
        targetType: 'organization',
        targetId: id,
        orgId: id,
        meta: {
          name: deleted.organization.name,
          slug: deleted.organization.slug,
          revokedSessions: deleted.revokedSessions,
        },
      },
      principal,
      request,
    );
  }
}

/** Runs a write and maps a taken slug to `409 ORGANIZATION_SLUG_TAKEN`. */
async function uniqueSlug<T>(
  slug: string,
  write: () => Promise<T>,
): Promise<T> {
  try {
    return await write();
  } catch (error) {
    if (isUniqueViolation(error, ORGANIZATION_SLUG_CONSTRAINT))
      throw AuthErrors.slugTaken(slug);
    throw error;
  }
}
