import { describe, expect, it } from 'vitest';

import { needsRehash } from './password-hashing.js';
import { isPublished, retirementGraceSeconds } from './signing-key-rules.js';

describe('signing key life cycle', () => {
  it('keeps a retiring key published for the token lifetime plus tolerances', () => {
    expect(retirementGraceSeconds(900)).toBe(960);
    expect(isPublished('active')).toBe(true);
    expect(isPublished('retiring')).toBe(true);
    expect(isPublished('retired')).toBe(false);
  });
});

describe('needsRehash (argon2id m=19456, t=2, p=1)', () => {
  const current = { algorithm: 2, memoryCost: 19_456, timeCost: 2, parallelism: 1, outputLen: 32 };

  it('keeps hashes made with the current parameters', () => {
    expect(needsRehash(current)).toBe(false);
  });

  it('upgrades other algorithms and parameters', () => {
    expect(needsRehash({ ...current, algorithm: 1 })).toBe(true);
    expect(needsRehash({ ...current, memoryCost: 4096 })).toBe(true);
    expect(needsRehash({ ...current, timeCost: 3 })).toBe(true);
    expect(needsRehash({ ...current, parallelism: 2 })).toBe(true);
    expect(needsRehash({ ...current, outputLen: 16 })).toBe(true);
  });
});
