import type { CursorPage } from '@darmawanweb/ais-its-contracts/api';
import { ForbiddenError } from '@darmawanweb/ais-its-nest';
import type { Principal } from '@darmawanweb/ais-its-nest/auth';
import { sanitizeError } from '@darmawanweb/ais-its-nest/db';
import {
  cursorPage,
  decodeQueryCursor,
  resolveQueryTimeRange,
} from '@darmawanweb/ais-its-nest/http';
import { Injectable, Logger } from '@nestjs/common';
import * as z from 'zod';

import { AuthErrors } from '../../common/errors.js';
import { requireUser } from '../../common/principals.js';
import type { AuditLogRow } from '../../db/database.js';
import { canReadAuditLogs } from '../../domain/access-rules.js';
import {
  type AuditActionCount,
  type AuditLogCursor,
  type AuditLogFilter,
  type AuditLogScope,
  AuditLogsRepository,
} from './audit-logs.repository.js';
import type {
  AuditLogFiltersQuery,
  ListAuditActionsQuery,
  ListAuditLogsQuery,
} from './dto/audit-log.dto.js';

/** Default range of a listing, an export or the actions without `from`: 30 days. */
export const AUDIT_LOG_DEFAULT_RANGE_MS = 30 * 86_400_000;

/** Longest range of `GET /audit-logs/actions` (it counts every record of the range): 366 days. */
export const AUDIT_ACTIONS_MAX_RANGE_MS = 366 * 86_400_000;

/** Records per query of a CSV export (keyset batches, never one long statement). */
export const AUDIT_LOG_EXPORT_BATCH_SIZE = 1000;

const CursorSchema = z.object({ at: z.iso.datetime(), id: z.uuid() });

/** A CSV export: validated, its first batch read, the rest read as it streams. */
export interface AuditLogExport {
  /** The organization exported, `null` for every record (super admins). */
  readonly orgId: string | null;
  readonly from: Date;
  readonly to: Date;
  readonly batches: AsyncIterable<readonly AuditLogRow[]>;
}

/**
 * Reads the central audit log (spec §13.1 `GET /audit-logs`, `audit:read`):
 * `org_admin`s read their active organization, super admins every record
 * (optionally one organization). The listing, the CSV export and the
 * action facet share the filters and the tenancy rule.
 */
@Injectable()
export class AuditLogsService {
  private readonly logger = new Logger('AuditLogs');

  constructor(private readonly logs: AuditLogsRepository) {}

  async list(
    principal: Principal,
    query: ListAuditLogsQuery,
  ): Promise<CursorPage<AuditLogRow>> {
    const scope = this.scopeOf(principal, query.orgId);
    const rows = await this.logs.list(
      filterOf(query),
      scope,
      decodeQueryCursor(query, CursorSchema),
      query.limit + 1,
    );
    return cursorPage(rows, query.limit, cursorOf);
  }

  /**
   * The distinct actions recorded in the principal's scope and the range
   * (default 30 days, at most 366), with their counts: the server's
   * suggestions for the action filters.
   */
  async actions(
    principal: Principal,
    query: ListAuditActionsQuery,
  ): Promise<AuditActionCount[]> {
    const scope = this.scopeOf(principal, query.orgId);
    const range = resolveQueryTimeRange(query, {
      defaultDurationMs: AUDIT_LOG_DEFAULT_RANGE_MS,
      maxDurationMs: AUDIT_ACTIONS_MAX_RANGE_MS,
    });
    return this.logs.actions(scope, range, query.actionPrefix);
  }

  /**
   * Validates an export (tenancy, filters, range) and reads its first
   * batch, so every error of the request surfaces before the first byte;
   * the further batches are read as the client consumes them (keyset by
   * `(at, id)`, newest first like the listing).
   */
  async export(
    principal: Principal,
    query: AuditLogFiltersQuery,
  ): Promise<AuditLogExport> {
    const scope = this.scopeOf(principal, query.orgId);
    const filter = filterOf(query);
    const batch = (after: AuditLogCursor | undefined) =>
      this.logs.list(filter, scope, after, AUDIT_LOG_EXPORT_BATCH_SIZE);
    const first = await batch(undefined);
    return {
      orgId: scope.kind === 'org' ? scope.orgId : null,
      from: filter.from,
      to: filter.to,
      batches: this.exportBatches(first, batch),
    };
  }

  /**
   * The batches of an export: `first`, then one query after the last row of
   * each full batch, until a batch comes back short. A failure while the
   * response streams can no longer become a problem response: it is logged
   * without bound values and ends the stream (the connection is aborted, so
   * a cut file never looks complete).
   */
  private async *exportBatches(
    first: readonly AuditLogRow[],
    next: (after: AuditLogCursor) => Promise<readonly AuditLogRow[]>,
  ): AsyncGenerator<readonly AuditLogRow[]> {
    let batch = first;
    try {
      for (;;) {
        if (batch.length > 0) yield batch;
        const last = batch.at(-1);
        if (batch.length < AUDIT_LOG_EXPORT_BATCH_SIZE || last === undefined)
          return;
        batch = await next(cursorOf(last));
      }
    } catch (error) {
      const sanitized = sanitizeError(error);
      this.logger.warn(
        { err: sanitized },
        'Audit log export failed while streaming; the download is aborted',
      );
      throw sanitized;
    }
  }

  private scopeOf(
    principal: Principal,
    orgId: string | undefined,
  ): AuditLogScope {
    const actor = requireUser(principal);
    if (actor.isPlatformAdmin)
      return orgId === undefined ? { kind: 'all' } : { kind: 'org', orgId };
    const target = orgId ?? actor.orgId;
    if (target === null) throw AuthErrors.organizationRequired();
    if (!canReadAuditLogs(actor, target)) {
      throw new ForbiddenError(
        'You can only read the audit log of your active organization',
        {
          extra: { orgId: target },
        },
      );
    }
    return { kind: 'org', orgId: target };
  }
}

/** The filter parameters of a validated query (listing or export). */
type AuditLogFilterParams = Pick<
  AuditLogFiltersQuery,
  | 'actorId'
  | 'actorEmail'
  | 'action'
  | 'actionPrefix'
  | 'targetType'
  | 'targetId'
  | 'from'
  | 'to'
>;

/** The repository filter of validated filter parameters (default range: 30 days). */
function filterOf(query: AuditLogFilterParams): AuditLogFilter {
  const { from, to } = resolveQueryTimeRange(query, {
    defaultDurationMs: AUDIT_LOG_DEFAULT_RANGE_MS,
  });
  return {
    actorId: query.actorId,
    actorEmail: query.actorEmail,
    action: query.action,
    actionPrefix: query.actionPrefix,
    targetType: query.targetType,
    targetId: query.targetId,
    from,
    to,
  };
}

/** Keyset position of a row (`at` DESC, `id` DESC). */
function cursorOf(row: AuditLogRow): AuditLogCursor {
  return { at: row.at.toISOString(), id: row.id };
}
