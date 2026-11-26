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
import type { AuditRequest } from '@darmawanweb/ais-its-nest/audit';
import type { Principal } from '@darmawanweb/ais-its-nest/auth';
import {
  type Counter,
  MetricsService,
} from '@darmawanweb/ais-its-nest/metrics';
import { Injectable } from '@nestjs/common';

import { AuthErrors } from '../../common/errors.js';
import { requireUser } from '../../common/principals.js';
import type { ApiKeyRow } from '../../db/database.js';
import { Transactions } from '../../db/transactions.js';
import {
  canManageApiKeys,
  ungrantableScopes,
} from '../../domain/access-rules.js';
import {
  apiKeyStatus,
  rotationGraceEnd,
} from '../../domain/api-key-lifecycle.js';
import { generateApiKey, matchApiKey } from '../../domain/api-key-material.js';
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
  /** Inactive from then on (must lie in the future); absent = no expiry. */
  readonly expiresAt?: Date | undefined;
}

/** `POST /api-keys/:id/rotate`. */
export interface RotateApiKeyInput {
  /** Minutes the replaced secret keeps working (0 = stops at once). */
  readonly gracePeriodMin: number;
}

/** A created key with its secret (shown once). */
export interface CreatedApiKey {
  readonly row: ApiKeyRow;
  readonly key: string;
}

/**
 * API keys of machine clients (spec §8.1, §13.1): managed by `org_admin`s
 * of the key's organization and by super admins (`api_key:manage`); the
 * platform-wide write scope `ais:ingest` is granted by super admins only;
 * stored as SHA-256 with a unique lookup prefix; introspected by the other
 * services (`/internal/api-keys/introspect`). Keys may expire
 * (`expiresAt`) and get a new secret (rotation) that keeps their id and
 * prefix, with a grace period for the replaced one.
 */
@Injectable()
export class ApiKeysService {
  private readonly introspections: Counter<'outcome'>;

  constructor(
    private readonly transactions: Transactions,
    private readonly keys: ApiKeysRepository,
    private readonly organizations: OrganizationsRepository,
    metrics: MetricsService,
  ) {
    this.introspections = metrics.counter({
      name: 'auth_api_key_introspections_total',
      help: 'API key introspections by outcome (active, active_previous: the replaced secret of a rotation during its grace period, inactive).',
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

  /**
   * Creates a key; the secret is returned once and never stored.
   *
   * @throws {ForbiddenError} `403 SCOPE_NOT_GRANTABLE` for scopes the caller
   *   may not grant (`ais:ingest` outside super admins, see `grantableScopes`).
   * @throws {ValidationFailedError} `400 VALIDATION_FAILED` (field
   *   `expiresAt`) for an invalid date or one that is not in the future.
   */
  async create(
    principal: Principal,
    input: CreateApiKeyInput,
    request: AuditRequest,
  ): Promise<CreatedApiKey> {
    const actor = requireUser(principal);
    const refused = ungrantableScopes(actor, input.scopes);
    if (refused.length > 0) throw AuthErrors.scopeNotGrantable(refused);
    if (input.expiresAt !== undefined) {
      // An Invalid Date compares false with everything: it would pass the
      // future check and fail the insert with a RangeError (500).
      if (Number.isNaN(input.expiresAt.getTime()))
        throw AuthErrors.invalidExpiry();
      if (input.expiresAt.getTime() <= Date.now())
        throw AuthErrors.expiryInPast();
    }
    const orgId = this.targetOrg(principal, input.orgId);
    if ((await this.organizations.findById(orgId)) === undefined)
      throw AuthErrors.organizationNotFound(orgId);
    const material = await generateApiKey();
    const row = await this.transactions.run(async ({ tx, audit }) => {
      const inserted = await this.keys.insert(
        {
          id: newId(),
          orgId,
          name: input.name,
          prefix: material.prefix,
          keyHash: material.hash,
          scopes: [...new Set(input.scopes)],
          createdBy: actor.id,
          expiresAt: input.expiresAt ?? null,
        },
        tx,
      );
      await audit(
        {
          action: 'api_key.create',
          targetType: 'api_key',
          targetId: inserted.id,
          orgId,
          meta: {
            name: inserted.name,
            prefix: inserted.prefix,
            scopes: inserted.scopes,
            expiresAt: inserted.expiresAt?.toISOString() ?? null,
          },
        },
        actor,
        request,
      );
      return inserted;
    });
    return { row, key: material.key };
  }

  /**
   * Gives a key a new secret, returned once. The id and the prefix `sk_<id>`
   * stay (other services bind to the key id, e.g. telemetry devices), so a
   * device only swaps the secret. The replaced secret keeps working for
   * `gracePeriodMin` minutes (0: stops at once); rotating again during a
   * grace period ends the older one at once (one replaced secret at most).
   * Under a row lock, so concurrent rotations serialize.
   *
   * @throws {NotFoundError} `404 API_KEY_NOT_FOUND` for keys the caller may not manage.
   * @throws {ForbiddenError} `403 SCOPE_NOT_GRANTABLE` when the key carries a scope
   *   the caller could not grant (a new secret is a new credential).
   * @throws {ConflictError} `409 API_KEY_INACTIVE` for revoked or expired keys.
   */
  async rotate(
    principal: Principal,
    id: string,
    input: RotateApiKeyInput,
    request: AuditRequest,
  ): Promise<CreatedApiKey> {
    const actor = requireUser(principal);
    const now = new Date();
    return this.transactions.run(async ({ tx, audit }) => {
      const current = await this.keys.lockById(id, tx);
      if (current === undefined || !canManageApiKeys(actor, current.orgId))
        throw AuthErrors.apiKeyNotFound(id);
      const refused = ungrantableScopes(actor, parseScopes(current.scopes));
      if (refused.length > 0) throw AuthErrors.scopeNotGrantable(refused);
      const status = apiKeyStatus(current, now);
      if (status !== 'active') throw AuthErrors.apiKeyInactive(id, status);
      const material = await generateApiKey(current.prefix.slice('sk_'.length));
      if (material.prefix !== current.prefix)
        throw new Error(`Rotation changed the prefix of API key ${id}`);
      const graceEnd = rotationGraceEnd(now, input.gracePeriodMin);
      const row = await this.keys.rotate(
        id,
        {
          keyHash: material.hash,
          previousKeyHash: graceEnd === null ? null : current.keyHash,
          previousKeyExpiresAt: graceEnd,
        },
        tx,
      );
      await audit(
        {
          action: 'api_key.rotate',
          targetType: 'api_key',
          targetId: id,
          orgId: row.orgId,
          meta: {
            name: row.name,
            prefix: row.prefix,
            gracePeriodMin: input.gracePeriodMin,
            previousKeyExpiresAt:
              row.previousKeyExpiresAt?.toISOString() ?? null,
          },
        },
        actor,
        request,
      );
      return { row, key: material.key };
    });
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
    await this.transactions.run(async ({ tx, audit }) => {
      await this.keys.revoke(id, tx);
      await audit(
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
    });
  }

  /**
   * Introspection for the other services: format check, lookup by prefix,
   * revocation and expiry, constant-time comparison with the current secret
   * (and with the replaced one during a rotation's grace period); records
   * the use at most once per minute. The kit caches an active answer for
   * 60 s per consuming replica, so a revocation, an expiry or the end of a
   * grace period takes effect there within that time.
   */
  async introspect(key: string): Promise<ApiKeyIntrospectionResult> {
    const parsed = parseApiKey(key);
    const row =
      parsed === null ? undefined : await this.keys.findByPrefix(parsed.prefix);
    const now = new Date();
    const match =
      row === undefined || apiKeyStatus(row, now) !== 'active'
        ? null
        : await matchApiKey(key, row, now);
    if (row === undefined || match === null) {
      this.introspections.inc({ outcome: 'inactive' });
      return { active: false };
    }
    await this.keys.touch(row.id);
    this.introspections.inc({
      outcome: match === 'previous' ? 'active_previous' : 'active',
    });
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
