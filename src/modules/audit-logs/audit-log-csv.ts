import type { AuditLogRow } from '../../db/database.js';
import { AuditLogDto } from './dto/audit-log.dto.js';

/** Columns of `GET /audit-logs.csv`: the fields of {@link AuditLogDto}, `meta` as JSON. */
export const AUDIT_LOG_CSV_COLUMNS = [
  'id',
  'at',
  'source',
  'actorType',
  'actorId',
  'actorName',
  'actorEmail',
  'orgId',
  'orgName',
  'action',
  'targetType',
  'targetId',
  'targetLabel',
  'ip',
  'userAgent',
  'meta',
] as const satisfies readonly (keyof AuditLogDto)[];

/** Media type of the export: RFC 4180 CSV with a header line, UTF-8. */
export const AUDIT_LOG_CSV_MEDIA_TYPE =
  'text/csv; charset=utf-8; header=present';

/** Line break of RFC 4180. */
const CRLF = '\r\n';

/** The header line of the export. */
export const AUDIT_LOG_CSV_HEADER = AUDIT_LOG_CSV_COLUMNS.join(',') + CRLF;

/**
 * First characters that make spreadsheet programs evaluate a cell as a
 * formula (OWASP "CSV Injection"): `=`, `+`, `-`, `@`, tab and carriage
 * return.
 */
const FORMULA_START = /^[=+\-@\t\r]/;

/**
 * One CSV cell (RFC 4180): empty for `null`; text that a spreadsheet would
 * run as a formula gets a leading apostrophe (names, user agents and meta
 * come from users and other services); quoted, quotes doubled, when it
 * holds a comma, a quote or a line break.
 *
 * @see https://owasp.org/www-community/attacks/CSV_Injection
 */
export function csvCell(value: string | null): string {
  if (value === null) return '';
  const text = FORMULA_START.test(value) ? `'${value}` : value;
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

/** The lines of a batch of records, with the values of the JSON API. */
export function auditLogCsvLines(rows: readonly AuditLogRow[]): string {
  let lines = '';
  for (const row of rows) {
    const dto = new AuditLogDto(row);
    lines +=
      AUDIT_LOG_CSV_COLUMNS.map((column) =>
        csvCell(column === 'meta' ? JSON.stringify(dto.meta) : dto[column]),
      ).join(',') + CRLF;
  }
  return lines;
}

/** The export as text chunks: the header line, then one chunk per batch. */
export async function* auditLogCsv(
  batches: AsyncIterable<readonly AuditLogRow[]>,
): AsyncGenerator<string> {
  yield AUDIT_LOG_CSV_HEADER;
  for await (const batch of batches) yield auditLogCsvLines(batch);
}

/**
 * File name of an export, `audit-logs-<orgId|all>-<from>_<to>.csv` with
 * compact UTC times to the second (`20261121T100000Z`).
 */
export function auditLogCsvFilename(
  orgId: string | null,
  from: Date,
  to: Date,
): string {
  return `audit-logs-${orgId ?? 'all'}-${compactUtc(from)}_${compactUtc(to)}.csv`;
}

function compactUtc(time: Date): string {
  return time
    .toISOString()
    .replace(/\.\d{3}Z$/, 'Z')
    .replaceAll('-', '')
    .replaceAll(':', '');
}
