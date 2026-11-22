import { describe, expect, it } from 'vitest';

import {
  MAX_JSON_DEPTH,
  REPLACEMENT_CHARACTER as R,
  storableJson,
  storableNullableText,
  storableText,
  TRUNCATED_JSON,
} from './storable-text.js';

describe('storable text (audit_logs never refuses a valid event)', () => {
  it('replaces NUL characters and lone surrogates, keeps everything else', () => {
    expect(storableText('a\u0000b')).toBe(`a${R}b`);
    expect(storableText('x\uD800y')).toBe(`x${R}y`);
    expect(storableText('x\uDC00')).toBe(`x${R}`);
    expect(storableText('kapal 🚢 Batam, ümlaut')).toBe(
      'kapal 🚢 Batam, ümlaut',
    );
    expect(storableNullableText(null)).toBeNull();
    expect(storableNullableText('\u0000')).toBe(R);
  });

  it('cleans keys and values at every level of a JSON value', () => {
    expect(
      storableJson({
        'k\u0000': ['v\u0000', 1, true, null, { deep: '\uD83D' }],
        n: 42,
      }),
    ).toEqual({ [`k${R}`]: [`v${R}`, 1, true, null, { deep: R }], n: 42 });
    // The result serializes into JSON PostgreSQL accepts.
    expect(JSON.stringify(storableJson({ a: '\u0000\uD800' }))).toBe(
      JSON.stringify({ a: `${R}${R}` }),
    );
  });

  it('truncates subtrees nested too deeply to serialize safely', () => {
    let nested: unknown = 'leaf';
    for (let level = 0; level < MAX_JSON_DEPTH + 5; level += 1)
      nested = { level: nested };
    let cursor = storableJson(nested);
    let depth = 0;
    while (typeof cursor === 'object' && cursor !== null) {
      cursor = (cursor as { level: unknown }).level;
      depth += 1;
    }
    expect(depth).toBe(MAX_JSON_DEPTH);
    expect(cursor).toBe(TRUNCATED_JSON);
  });
});
