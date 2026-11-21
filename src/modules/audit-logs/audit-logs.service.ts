import type { CursorPage } from '@darmawanweb/ais-its-contracts/api';
import { ForbiddenError } from '@darmawanweb/ais-its-nest';
import type { Principal } from '@darmawanweb/ais-its-nest/auth';
import {
  cursorPage,
  decodeQueryCursor,
  resolveQueryTimeRange,
} from '@darmawanweb/ais-its-nest/http';
import { Injectable } from '@nestjs/common';
import * as z from 'zod';

import { AuthErrors } from '../../common/errors.js';
import { requireUser } from '../../common/principals.js';
import type { AuditLogRow } from '../../db/database.js';
import { canReadAuditLogs } from '../../domain/access-rules.js';
import {
  type AuditLogScope,
  AuditLogsRepository,
} from './audit-logs.repository.js';
import type { ListAuditLogsQuery } from './dto/audit-log.dto.js';

/** Default range of a listing without `from`: 30 days. */
export const AUDIT_LOG_DEFAULT_RANGE_MS = 30 * 86_400_000;

const CursorSchema = z.object({ at: z.iso.datetime(), id: z.uuid() });

/**
 * Reads the central audit log (spec §13.1 `GET /audit-logs`, `audit:read`):
 * `org_admin`s read their active organization, super admins every record
 * (optionally one organization).
 */
@Injectable()
export class AuditLogsService {
  constructor(private readonly logs: AuditLogsRepository) {}

  async list(
    principal: Principal,
    query: ListAuditLogsQuery,
  ): Promise<CursorPage<AuditLogRow>> {
    const scope = this.scopeOf(principal, query.orgId);
    const { from, to } = resolveQueryTimeRange(query, {
      defaultDurationMs: AUDIT_LOG_DEFAULT_RANGE_MS,
    });
    const rows = await this.logs.list(
      {
        actorId: query.actorId,
        action: query.action,
        targetType: query.targetType,
        targetId: query.targetId,
        from,
        to,
      },
      scope,
      decodeQueryCursor(query, CursorSchema),
      query.limit + 1,
    );
    return cursorPage(rows, query.limit, (row) => ({
      at: row.at.toISOString(),
      id: row.id,
    }));
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
