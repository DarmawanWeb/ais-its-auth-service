import { createHash } from 'node:crypto';

import { API_KEY_PATTERN, isApiKey, maskApiKey, parseApiKey } from '@darmawanweb/ais-its-contracts/auth';
import { describe, expect, it } from 'vitest';

import { apiKeyMatches, generateApiKey, hashApiKey, randomBase62 } from './api-key-material.js';

describe('API key material (spec §8.1: sk_<10 id>_<32 secret>, SHA-256 at rest)', () => {
  it('generates keys in the contracts format with their prefix and hash', () => {
    const generated = generateApiKey();
    expect(generated.key).toMatch(API_KEY_PATTERN);
    expect(isApiKey(generated.key)).toBe(true);
    expect(parseApiKey(generated.key)).toEqual({
      id: generated.id,
      secret: generated.secret,
      prefix: generated.prefix,
    });
    expect(generated.prefix).toBe(`sk_${generated.id}`);
    expect(generated.hash).toBe(createHash('sha256').update(generated.key).digest('hex'));
    expect(maskApiKey(generated.key)).toBe(`${generated.prefix}_…`);
  });

  it('never repeats keys and uses the whole base62 alphabet', () => {
    const keys = new Set(Array.from({ length: 200 }, () => generateApiKey().key));
    expect(keys.size).toBe(200);
    const sample = randomBase62(20_000);
    expect(new Set(sample).size).toBe(62);
    expect(sample).toMatch(/^[0-9A-Za-z]+$/);
  });

  it('matches a key against its stored hash only, in constant time', () => {
    const { key, hash } = generateApiKey();
    expect(hashApiKey(key)).toBe(hash);
    expect(apiKeyMatches(key, hash)).toBe(true);
    expect(apiKeyMatches(`${key.slice(0, -1)}${key.endsWith('a') ? 'b' : 'a'}`, hash)).toBe(false);
    expect(apiKeyMatches(key, generateApiKey().hash)).toBe(false);
    expect(apiKeyMatches(key, '')).toBe(false);
    expect(apiKeyMatches(key, 'abc')).toBe(false);
  });

  it('parses only well-formed keys (contracts helpers)', () => {
    expect(parseApiKey('sk_short_secret')).toBeNull();
    expect(parseApiKey(`sk_${'a'.repeat(10)}_${'b'.repeat(31)}`)).toBeNull();
    expect(parseApiKey(`sk_${'a'.repeat(10)}_${'b'.repeat(32)}`)).toMatchObject({ prefix: `sk_${'a'.repeat(10)}` });
  });
});
