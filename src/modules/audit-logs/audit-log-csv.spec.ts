import { describe, expect, it } from 'vitest';

import type { AuditLogRow } from '../../db/database.js';
import {
  AUDIT_LOG_CSV_HEADER,
  auditLogCsv,
  auditLogCsvFilename,
  auditLogCsvLines,
  csvCell,
} from './audit-log-csv.js';

const ROW: AuditLogRow = {
  id: '0192f3a4-5b6c-7d8e-9f01-23456789abcd',
  at: new Date('2026-11-21T10:15:00.000Z'),
  source: 'auth',
  actorType: 'user',
  actorId: '0192f3a4-5b6c-7d8e-9f01-23456789abce',
  orgId: '0192f3a4-5b6c-7d8e-9f01-23456789abcf',
  action: 'membership.invite',
  targetType: 'membership_invitation',
  targetId: '0192f3a4-5b6c-7d8e-9f01-23456789abd0',
  ip: '203.0.113.5',
  userAgent: '=HYPERLINK("http://x")',
  meta: { role: 'viewer', note: 'a, "b"' },
  recordedAt: new Date('2026-11-21T10:15:01.000Z'),
  actorName: 'Siti Rahma',
  actorEmail: 'siti@example.com',
  orgName: 'PT Demo, Tbk',
  targetLabel: null,
};

/** The items of `items` as an async iterable (batches as the repository yields them). */
function toAsync<T>(items: readonly T[]): AsyncIterable<T> {
  return {
    [Symbol.asyncIterator]: () => {
      let index = 0;
      return {
        next: () =>
          Promise.resolve(
            index < items.length
              ? { done: false, value: items[index++] as T }
              : { done: true, value: undefined },
          ),
      };
    },
  };
}

describe('audit log CSV export', () => {
  it('quotes cells with commas, quotes and line breaks (RFC 4180)', () => {
    expect(csvCell(null)).toBe('');
    expect(csvCell('plain')).toBe('plain');
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell('two\r\nlines')).toBe('"two\r\nlines"');
  });

  it('neutralizes cells a spreadsheet would run as formulas (OWASP)', () => {
    expect(csvCell('=1+2')).toBe("'=1+2");
    expect(csvCell('+31 20')).toBe("'+31 20");
    expect(csvCell('-2')).toBe("'-2");
    expect(csvCell('@SUM(A1)')).toBe("'@SUM(A1)");
    expect(csvCell('\tx')).toBe("'\tx");
    expect(csvCell('=A1,B1')).toBe(`"'=A1,B1"`);
    expect(csvCell('2026-11-21T10:15:00.000Z')).toBe(
      '2026-11-21T10:15:00.000Z',
    );
  });

  it('writes one line per record with the JSON values, meta as JSON', async () => {
    expect(auditLogCsvLines([ROW])).toBe(
      '0192f3a4-5b6c-7d8e-9f01-23456789abcd,2026-11-21T10:15:00.000Z,auth,user,' +
        '0192f3a4-5b6c-7d8e-9f01-23456789abce,Siti Rahma,siti@example.com,' +
        '0192f3a4-5b6c-7d8e-9f01-23456789abcf,"PT Demo, Tbk",membership.invite,membership_invitation,' +
        '0192f3a4-5b6c-7d8e-9f01-23456789abd0,,203.0.113.5,"\'=HYPERLINK(""http://x"")",' +
        '"{""role"":""viewer"",""note"":""a, \\""b\\""""}"\r\n',
    );
    const batches: readonly (readonly AuditLogRow[])[] = [[ROW], [], [ROW]];
    let file = '';
    for await (const chunk of auditLogCsv(toAsync(batches))) file += chunk;
    expect(file.startsWith(AUDIT_LOG_CSV_HEADER)).toBe(true);
    expect(AUDIT_LOG_CSV_HEADER).toBe(
      'id,at,source,actorType,actorId,actorName,actorEmail,orgId,orgName,action,targetType,targetId,targetLabel,ip,userAgent,meta\r\n',
    );
    expect(file.split('\r\n').filter((line) => line !== '')).toHaveLength(3);
  });

  it('names the file after the scope and the range', () => {
    expect(
      auditLogCsvFilename(
        null,
        new Date('2026-10-22T10:00:00.123Z'),
        new Date('2026-11-21T10:00:00Z'),
      ),
    ).toBe('audit-logs-all-20261022T100000Z_20261121T100000Z.csv');
    expect(
      auditLogCsvFilename(
        ROW.orgId,
        new Date('2026-11-01T00:00:00Z'),
        new Date('2026-11-02T00:00:00Z'),
      ),
    ).toBe(`audit-logs-${ROW.orgId}-20261101T000000Z_20261102T000000Z.csv`);
  });
});
