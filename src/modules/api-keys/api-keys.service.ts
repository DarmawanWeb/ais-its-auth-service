import {
  type PageQuery,
  type Paginated,
  pageOffset,
  toPaginated,
} from '@darmawanweb/ais-its-contracts/api';
import {
  type ApiKeyIntrospectionResult,
  type ApiKeyScope,
  parseApiKey,
  parseScopes,
} from '@darmawanweb/ais-its-contracts/auth';
import { newId } from '@darmawanweb/ais-its-contracts/domain';
import { ForbiddenError } from '@darmawanweb/ais-its-nest';
import {
  type AuditRequest,
  AuditService,
} from '@darmawanweb/ais-its-nest/audit';
import type { Principal } from '@darmawanweb/ais-its-nest/auth';
import { MetricsService } from '@darmawanweb/ais-its-nest/metrics';
import { Injectable } from '@nestjs/common';

import { AuthErrors } from '../../common/errors.js';
import type { CounterMetric } from '../../common/metrics.js';
import { requireUser } from '../../common/principals.js';
import type { ApiKeyRow } from '../../db/database.js';
import { canManageApiKeys } from '../../domain/access-rules.js';
import {
  apiKeyMatches,
  generateApiKey,
} from '../../domain/api-key-material.js';
import { OrganizationsRepository } from '../accounts/organizations.repository.js';
import {
  type ApiKeyScopeFilter,
  ApiKeysRepository,
} from './api-keys.repository.js';

/** Fields of a new key. */
export interface CreateApiKeyInput {
  readonly name: string;
  readonly scopes: readonly ApiKeyScope[];
  /** Super admins only; others create keys in their active organization. */
  readonly orgId?: string | undefined;
}

/** A created key with its secret (shown once). */
export interface CreatedApiKey {
  readonly row: ApiKeyRow;
  readonly key: string;
}

/**
 * API keys of machine clients (spec §8.1, §13.1): managed by `org_admin`s
 * of the key's organization and by super admins (`api_key:manage`);
 * stored as SHA-256 with a unique lookup prefix; introspected by the other
 * services (`/internal/api-keys/introspect`).
 */
@Injectable()
export class ApiKeysService {
  private readonly introspections: CounterMetric;

  constructor(
    private readonly keys: ApiKeysRepository,
    private readonly organizations: OrganizationsRepository,
    private readonly audit: AuditService,
    metrics: MetricsService,
  ) {
    this.introspections = metrics.counter({
      name: 'auth_api_key_introspections_total',
      help: 'API key introspections by outcome (active, inactive).',
      labelNames: ['outcome'],
    });
  }

  /** Keys visible to the principal: its active organization, or any (filtered) for super admins. */
  async list(
    principal: Principal,
    filter: {
      readonly orgId?: string | undefined;
      readonly includeRevoked: boolean;
    },
    page: PageQuery,
  ): Promise<Paginated<ApiKeyRow>> {
    const scope = this.scopeOf(principal, filter.orgId);
    const { rows, total } = await this.keys.list(scope, filter.includeRevoked, {
      offset: pageOffset(page),
      limit: page.pageSize,
    });
    return toPaginated(rows, page, total);
  }

  /** Creates a key; the secret is returned once and never stored. */
  async create(
    principal: Principal,
    input: CreateApiKeyInput,
    request: AuditRequest,
  ): Promise<CreatedApiKey> {
    const actor = requireUser(principal);
    const orgId = this.targetOrg(principal, input.orgId);
    if ((await this.organizations.findById(orgId)) === undefined)
      throw AuthErrors.organizationNotFound(orgId);
    const material = generateApiKey();
    const row = await this.keys.insert({
      id: newId(),
      orgId,
      name: input.name,
      prefix: material.prefix,
      keyHash: material.hash,
      scopes: [...new Set(input.scopes)],
      createdBy: actor.id,
    });
    await this.audit.record(
      {
        action: 'api_key.create',
        targetType: 'api_key',
        targetId: row.id,
        orgId,
        meta: { name: row.name, prefix: row.prefix, scopes: row.scopes },
      },
      actor,
      request,
    );
    return { row, key: material.key };
  }

  /** Revokes a key (idempotent); keys of other organizations are not found. */
  async revoke(
    principal: Principal,
    id: string,
    request: AuditRequest,
  ): Promise<void> {
    const actor = requireUser(principal);
    const key = await this.keys.findById(id);
    if (key === undefined || !canManageApiKeys(actor, key.orgId))
      throw AuthErrors.apiKeyNotFound(id);
    if (key.revokedAt !== null) return;
    await this.keys.revoke(id);
    await this.audit.record(
      {
        action: 'api_key.revoke',
        targetType: 'api_key',
        targetId: id,
        orgId: key.orgId,
        meta: { name: key.name, prefix: key.prefix },
      },
      actor,
      request,
    );
  }

  /**
   * Introspection for the other services: format check, lookup by prefix,
   * constant-time hash comparison, revocation; records the use at most once
   * per minute.
   */
  async introspect(key: string): Promise<ApiKeyIntrospectionResult> {
    const parsed = parseApiKey(key);
    const row =
      parsed === null ? undefined : await this.keys.findByPrefix(parsed.prefix);
    if (row?.revokedAt !== null || !apiKeyMatches(key, row.keyHash)) {
      this.introspections.inc({ outcome: 'inactive' });
      return { active: false };
    }
    await this.keys.touch(row.id);
    this.introspections.inc({ outcome: 'active' });
    return {
      active: true,
      keyId: row.id,
      orgId: row.orgId,
      scopes: parseScopes(row.scopes),
      name: row.name,
    };
  }

  private scopeOf(
    principal: Principal,
    orgId: string | undefined,
  ): ApiKeyScopeFilter {
    if (principal.isPlatformAdmin)
      return orgId === undefined ? { kind: 'all' } : { kind: 'org', orgId };
    return { kind: 'org', orgId: this.targetOrg(principal, orgId) };
  }

  /** The organization a non-admin acts in (its active organization, never a client-chosen one). */
  private targetOrg(
    principal: Principal,
    requested: string | undefined,
  ): string {
    const active = principal.orgId;
    if (principal.isPlatformAdmin) {
      const orgId = requested ?? active;
      if (orgId === null) throw AuthErrors.organizationRequired();
      return orgId;
    }
    if (active === null) throw AuthErrors.organizationRequired();
    if (requested !== undefined && requested !== active) {
      throw new ForbiddenError(
        'API keys can only be managed in your active organization',
        {
          extra: { orgId: requested },
        },
      );
    }
    return active;
  }
}
