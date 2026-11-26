import { createHash } from 'node:crypto';

import {
  API_KEY_PATTERN,
  hashApiKey,
  isApiKey,
  maskApiKey,
  parseApiKey,
} from '@darmawanweb/ais-its-contracts/auth';
import { describe, expect, it } from 'vitest';

import {
  generateApiKey,
  matchApiKey,
  randomBase62,
} from './api-key-material.js';

describe('API key material (spec §8.1: sk_<10 id>_<32 secret>, SHA-256 at rest)', () => {
  it('generates keys in the contracts format with their prefix and hash', async () => {
    const generated = await generateApiKey();
    expect(generated.key).toMatch(API_KEY_PATTERN);
    expect(isApiKey(generated.key)).toBe(true);
    expect(parseApiKey(generated.key)).toEqual({
      id: generated.id,
      secret: generated.secret,
      prefix: generated.prefix,
    });
    expect(generated.prefix).toBe(`sk_${generated.id}`);
    expect(generated.hash).toBe(
      createHash('sha256').update(generated.key).digest('hex'),
    );
    expect(maskApiKey(generated.key)).toBe(`${generated.prefix}_…`);
  });

  it('never repeats keys and uses the whole base62 alphabet', async () => {
    const generated = await Promise.all(
      Array.from({ length: 200 }, () => generateApiKey()),
    );
    const keys = new Set(generated.map((entry) => entry.key));
    expect(keys.size).toBe(200);
    const sample = randomBase62(20_000);
    expect(new Set(sample).size).toBe(62);
    expect(sample).toMatch(/^[0-9A-Za-z]+$/);
  });

  it('hashes with the contracts definition (SHA-256 hex of the full key)', async () => {
    const { key, hash } = await generateApiKey();
    expect(await hashApiKey(key)).toBe(hash);
    expect(hash).toBe(createHash('sha256').update(key).digest('hex'));
  });

  it('keeps the id (and prefix) when a secret is generated for an existing key', async () => {
    const original = await generateApiKey();
    const rotated = await generateApiKey(original.id);
    expect(rotated.prefix).toBe(original.prefix);
    expect(rotated.secret).not.toBe(original.secret);
    expect(rotated.hash).not.toBe(original.hash);
  });

  it('matches the current secret, and the replaced one only during its grace period', async () => {
    const replaced = await generateApiKey();
    const current = await generateApiKey(replaced.id);
    const now = new Date('2026-11-23T10:00:00Z');
    const accepted = {
      keyHash: current.hash,
      previousKeyHash: replaced.hash,
      previousKeyExpiresAt: new Date('2026-11-23T11:00:00Z'),
    };
    expect(await matchApiKey(current.key, accepted, now)).toBe('current');
    expect(await matchApiKey(replaced.key, accepted, now)).toBe('previous');
    expect(
      await matchApiKey(
        replaced.key,
        accepted,
        new Date('2026-11-23T11:00:00Z'),
      ),
    ).toBeNull();
    const other = await generateApiKey(replaced.id);
    expect(await matchApiKey(other.key, accepted, now)).toBeNull();
    expect(
      await matchApiKey(replaced.key, {
        keyHash: current.hash,
        previousKeyHash: null,
        previousKeyExpiresAt: null,
      }),
    ).toBeNull();
    expect(
      await matchApiKey(current.key, {
        keyHash: '',
        previousKeyHash: null,
        previousKeyExpiresAt: null,
      }),
    ).toBeNull();
  });

  it('parses only well-formed keys (contracts helpers)', () => {
    expect(parseApiKey('sk_short_secret')).toBeNull();
    expect(parseApiKey(`sk_${'a'.repeat(10)}_${'b'.repeat(31)}`)).toBeNull();
    expect(parseApiKey(`sk_${'a'.repeat(10)}_${'b'.repeat(32)}`)).toMatchObject(
      { prefix: `sk_${'a'.repeat(10)}` },
    );
  });
});
