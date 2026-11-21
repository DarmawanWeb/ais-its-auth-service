import { describe, expect, it } from 'vitest';

import {
  deriveKey,
  openSecret,
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
    expect(sealed).toMatch(/^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]+$/);
    expect(sealed).not.toContain('private');
    expect(openSecret(key, sealed, 'kid-1')).toBe('{"d":"private"}');
    expect(sealSecret(key, '{"d":"private"}', 'kid-1')).not.toBe(sealed);
  });

  it('is deterministic for a given IV (test vector stability)', () => {
    const iv = Buffer.alloc(12, 7);
    expect(sealSecret(key, 'secret', 'aad', iv)).toBe(sealSecret(key, 'secret', 'aad', iv));
  });

  it('refuses another key, other associated data, tampering and malformed input', () => {
    const sealed = sealSecret(key, 'JBSWY3DPEHPK3PXP', 'user-1');
    expect(() => openSecret(deriveKey(SECRET, 'mfa-secret'), sealed, 'user-1')).toThrow(SecretDecryptionError);
    expect(() => openSecret(key, sealed, 'user-2')).toThrow(SecretDecryptionError);
    const [version, iv, tag, ciphertext] = sealed.split('.');
    const flipped = `${ciphertext?.startsWith('A') === true ? 'B' : 'A'}${ciphertext?.slice(1) ?? ''}`;
    expect(() => openSecret(key, [version, iv, tag, flipped].join('.'), 'user-1')).toThrow(SecretDecryptionError);
    expect(() => openSecret(key, 'v2.a.b.c', 'user-1')).toThrow(SecretDecryptionError);
    expect(() => openSecret(key, 'garbage', 'user-1')).toThrow(SecretDecryptionError);
    expect(() => openSecret(key, `${sealed}.extra`, 'user-1')).toThrow(SecretDecryptionError);
  });

  it('validates key and IV sizes', () => {
    expect(() => sealSecret(Buffer.alloc(16), 'x', 'y')).toThrow(RangeError);
    expect(() => sealSecret(key, 'x', 'y', Buffer.alloc(16))).toThrow(RangeError);
  });
});
