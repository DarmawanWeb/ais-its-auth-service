import { describe, expect, it } from 'vitest';

import {
  isNeverStorable,
  isUuid,
  META_LABEL_MAX_LENGTH,
  metaTargetLabel,
  ownTarget,
} from './audit-labels.js';

const ID = '0192f3a4-5b6c-7d8e-9f01-23456789abcd';

/** A driver error with a SQLSTATE, wrapped like drizzle wraps it. */
function databaseError(code: string): Error {
  return new Error('Failed query: insert … params: secret', {
    cause: Object.assign(new Error('rejected'), { code, severity: 'ERROR' }),
  });
}

describe('audit record labels', () => {
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
