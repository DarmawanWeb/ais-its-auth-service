import { describe, expect, it } from 'vitest';

import {
  type AuditLabels,
  CAPTURED_LABELS_META_KEY,
  capturedLabelsOf,
  isNeverStorable,
  isUuid,
  META_LABEL_MAX_LENGTH,
  metaTargetLabel,
  ownTarget,
  withCapturedLabels,
  withoutCapturedLabels,
} from './audit-labels.js';

const ID = '0192f3a4-5b6c-7d8e-9f01-23456789abcd';

/** A driver error with a SQLSTATE, wrapped like drizzle wraps it. */
function databaseError(code: string): Error {
  return new Error('Failed query: insert … params: secret', {
    cause: Object.assign(new Error('rejected'), { code, severity: 'ERROR' }),
  });
}

describe('audit record labels', () => {
  it('carries the names captured at write time in meta and takes them out again', () => {
    const labels: AuditLabels = {
      actorName: 'Admin',
      actorEmail: 'admin@example.com',
      orgName: 'PT Lama',
      targetLabel: null,
    };
    const meta = withCapturedLabels({ name: 'PT Lama' }, labels);
    expect(CAPTURED_LABELS_META_KEY).toBe('auditLabels');
    expect(meta).toEqual({ name: 'PT Lama', auditLabels: labels });
    // A JSON round trip (outbox, NATS) keeps them.
    const relayed = JSON.parse(JSON.stringify(meta)) as Record<string, unknown>;
    expect(capturedLabelsOf(relayed)).toEqual(labels);
    expect(withoutCapturedLabels(relayed)).toEqual({ name: 'PT Lama' });
    expect(withCapturedLabels(undefined, labels)).toEqual({
      auditLabels: labels,
    });
  });

  it('accepts captured names only in their shape', () => {
    const valid = {
      actorName: null,
      actorEmail: null,
      orgName: 'PT Lama',
      targetLabel: null,
    };
    expect(capturedLabelsOf({})).toBeUndefined();
    expect(capturedLabelsOf({ auditLabels: null })).toBeUndefined();
    expect(capturedLabelsOf({ auditLabels: 'PT Lama' })).toBeUndefined();
    expect(capturedLabelsOf({ auditLabels: [valid] })).toBeUndefined();
    expect(
      capturedLabelsOf({ auditLabels: { ...valid, orgName: 42 } }),
    ).toBeUndefined();
    const { targetLabel: _missing, ...incomplete } = valid;
    expect(capturedLabelsOf({ auditLabels: incomplete })).toBeUndefined();
    // Extra fields are not taken over.
    expect(capturedLabelsOf({ auditLabels: { ...valid, ip: 'x' } })).toEqual(
      valid,
    );
  });

  it('names only this service’s target types with UUID ids', () => {
    expect(ownTarget('user', ID)).toEqual({ type: 'user', id: ID });
    expect(ownTarget('membership_invitation', ID)?.type).toBe(
      'membership_invitation',
    );
    expect(ownTarget('vessel', ID)).toBeUndefined();
    expect(ownTarget('signing_key', ID)).toBeUndefined();
    expect(ownTarget('user', '525005223')).toBeUndefined();
    expect(ownTarget(null, null)).toBeUndefined();
    expect(isUuid(ID.toUpperCase())).toBe(true);
    expect(isUuid(`${ID}x`)).toBe(false);
  });

  it('takes a producer label from meta.targetLabel, else meta.name', () => {
    expect(metaTargetLabel({ targetLabel: ' KM Sinar ', name: 'x' })).toBe(
      'KM Sinar',
    );
    expect(metaTargetLabel({ name: 'Main engine' })).toBe('Main engine');
    expect(metaTargetLabel({ targetLabel: '  ', name: 'Fallback' })).toBe(
      'Fallback',
    );
    expect(metaTargetLabel({ name: 42, fields: ['name'] })).toBeNull();
    expect(metaTargetLabel({})).toBeNull();
    const long = metaTargetLabel({ name: '😀'.repeat(300) }) ?? '';
    expect(Array.from(long)).toHaveLength(META_LABEL_MAX_LENGTH);
    expect(long.endsWith('😀')).toBe(true);
  });
});

describe('isNeverStorable (dead-letter instead of retrying)', () => {
  it.each(['22P05', '22001', '23514', '23502', '54000'])(
    'is true for SQLSTATE %s',
    (code) => {
      expect(isNeverStorable(databaseError(code))).toBe(true);
    },
  );

  it.each(['57014', '40001', '40P01', '53100', '08006', 'XX000'])(
    'is false for the transient SQLSTATE %s',
    (code) => {
      expect(isNeverStorable(databaseError(code))).toBe(false);
    },
  );

  it('is false for errors without a SQLSTATE', () => {
    expect(
      isNeverStorable(
        Object.assign(new Error('connect ECONNREFUSED'), {
          code: 'ECONNREFUSED',
        }),
      ),
    ).toBe(false);
    expect(isNeverStorable(new Error('boom'))).toBe(false);
    expect(isNeverStorable(undefined)).toBe(false);
  });
});
