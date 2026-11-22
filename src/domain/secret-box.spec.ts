import { describe, expect, it } from 'vitest';

import {
  deriveKey,
  openSecret,
  resealSecret,
  SecretDecryptionError,
  sealSecret,
} from './secret-box.js';

const SECRET = 'a-key-encryption-secret-of-32-chars!!';

describe('secret box (AES-256-GCM, HKDF-SHA256 keys)', () => {
  const key = deriveKey(SECRET, 'signing-key');

  it('derives a distinct 32-byte key per purpose and secret, deterministically', () => {
    expect(key).toHaveLength(32);
    expect(deriveKey(SECRET, 'signing-key').equals(key)).toBe(true);
    expect(deriveKey(SECRET, 'mfa-secret').equals(key)).toBe(false);
    expect(deriveKey(`${SECRET}x`, 'signing-key').equals(key)).toBe(false);
  });

  it('round-trips and never repeats a ciphertext (random 12-byte IV)', () => {
    const sealed = sealSecret(key, '{"d":"private"}', 'kid-1');
    expect(sealed).toMatch(
      /^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]+$/,
    );
    expect(sealed).not.toContain('private');
    expect(openSecret(key, sealed, 'kid-1')).toBe('{"d":"private"}');
    expect(sealSecret(key, '{"d":"private"}', 'kid-1')).not.toBe(sealed);
  });

  it('is deterministic for a given IV (test vector stability)', () => {
    const iv = Buffer.alloc(12, 7);
    expect(sealSecret(key, 'secret', 'aad', iv)).toBe(
      sealSecret(key, 'secret', 'aad', iv),
    );
  });

  it('refuses another key, other associated data, tampering and malformed input', () => {
    const sealed = sealSecret(key, 'JBSWY3DPEHPK3PXP', 'user-1');
    expect(() =>
      openSecret(deriveKey(SECRET, 'mfa-secret'), sealed, 'user-1'),
    ).toThrow(SecretDecryptionError);
    expect(() => openSecret(key, sealed, 'user-2')).toThrow(
      SecretDecryptionError,
    );
    const [version, iv, tag, ciphertext] = sealed.split('.');
    const flipped = `${ciphertext?.startsWith('A') === true ? 'B' : 'A'}${ciphertext?.slice(1) ?? ''}`;
    expect(() =>
      openSecret(key, [version, iv, tag, flipped].join('.'), 'user-1'),
    ).toThrow(SecretDecryptionError);
    expect(() => openSecret(key, 'v2.a.b.c', 'user-1')).toThrow(
      SecretDecryptionError,
    );
    expect(() => openSecret(key, 'garbage', 'user-1')).toThrow(
      SecretDecryptionError,
    );
    expect(() => openSecret(key, `${sealed}.extra`, 'user-1')).toThrow(
      SecretDecryptionError,
    );
  });

  it('validates key and IV sizes', () => {
    expect(() => sealSecret(Buffer.alloc(16), 'x', 'y')).toThrow(RangeError);
    expect(() => sealSecret(key, 'x', 'y', Buffer.alloc(16))).toThrow(
      RangeError,
    );
  });
});

describe('resealSecret (rotation of KEY_ENCRYPTION_SECRET)', () => {
  const previous = deriveKey(SECRET, 'mfa-secret');
  const current = deriveKey(`${SECRET}-rotated`, 'mfa-secret');

  it('re-seals a value of the previous key under the current key, keeping its binding', () => {
    const old = sealSecret(previous, 'JBSWY3DPEHPK3PXP', 'user-1');
    const resealed = resealSecret(current, previous, old, 'user-1');
    expect(resealed).toBeDefined();
    expect(openSecret(current, String(resealed), 'user-1')).toBe(
      'JBSWY3DPEHPK3PXP',
    );
    expect(() => openSecret(previous, String(resealed), 'user-1')).toThrow(
      SecretDecryptionError,
    );
    expect(() => openSecret(current, String(resealed), 'user-2')).toThrow(
      SecretDecryptionError,
    );
  });

  it('is idempotent and refuses values neither key opens', () => {
    const fresh = sealSecret(current, 'secret', 'user-1');
    expect(resealSecret(current, previous, fresh, 'user-1')).toBeUndefined();
    const foreign = sealSecret(
      deriveKey('another-secret-of-at-least-32-chars', 'mfa-secret'),
      'secret',
      'user-1',
    );
    expect(() => resealSecret(current, previous, foreign, 'user-1')).toThrow(
      SecretDecryptionError,
    );
    const wrongRecord = sealSecret(previous, 'secret', 'user-1');
    expect(() =>
      resealSecret(current, previous, wrongRecord, 'user-2'),
    ).toThrow(SecretDecryptionError);
  });
});
