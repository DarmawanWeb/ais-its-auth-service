import { describe, expect, it } from 'vitest';

import { SecretDecryptionError } from '../../domain/secret-box.js';
import { KeyEncryption } from './key-encryption.service.js';

const OLD = 'old-key-encryption-secret-0123456789abcdef';
const NEW = 'new-key-encryption-secret-0123456789abcdef';

describe('KeyEncryption during a KEY_ENCRYPTION_SECRET rotation', () => {
  const before = new KeyEncryption({
    KEY_ENCRYPTION_SECRET: OLD,
    KEY_ENCRYPTION_SECRET_PREVIOUS: undefined,
  });
  const during = new KeyEncryption({
    KEY_ENCRYPTION_SECRET: NEW,
    KEY_ENCRYPTION_SECRET_PREVIOUS: OLD,
  });
  const after = new KeyEncryption({
    KEY_ENCRYPTION_SECRET: NEW,
    KEY_ENCRYPTION_SECRET_PREVIOUS: undefined,
  });

  it('opens values of both secrets and seals with the new one while rotating', () => {
    const old = before.seal('signing-key', '{"d":"x"}', 'kid-1');
    expect(during.rotating).toBe(true);
    expect(during.open('signing-key', old, 'kid-1')).toBe('{"d":"x"}');
    const fresh = during.seal('signing-key', '{"d":"y"}', 'kid-2');
    expect(after.open('signing-key', fresh, 'kid-2')).toBe('{"d":"y"}');
    expect(() => after.open('signing-key', old, 'kid-1')).toThrow(
      SecretDecryptionError,
    );
  });

  it('re-seals old values once, leaves current ones alone', () => {
    const old = before.seal('mfa-secret', 'JBSWY3DPEHPK3PXP', 'user-1');
    const resealed = during.reseal('mfa-secret', old, 'user-1');
    expect(after.open('mfa-secret', String(resealed), 'user-1')).toBe(
      'JBSWY3DPEHPK3PXP',
    );
    expect(
      during.reseal('mfa-secret', String(resealed), 'user-1'),
    ).toBeUndefined();
    // Without a previous secret, only current values pass.
    expect(after.reseal('mfa-secret', String(resealed), 'user-1')).toBe(
      undefined,
    );
    expect(() => after.reseal('mfa-secret', old, 'user-1')).toThrow(
      SecretDecryptionError,
    );
    expect(after.rotating).toBe(false);
  });
});
