import { describe, expect, it } from 'vitest';

import {
  generateTotp,
  generateTotpSecret,
  normalizeTotpCode,
  totpProvisioningUri,
  verifyTotp,
} from './totp.js';

// RFC 6238 appendix B: ASCII secret "12345678901234567890" (SHA-1), base32 encoded.
const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

describe('TOTP (RFC 6238: SHA-1, 6 digits, 30 s, window ±1)', () => {
  it('matches the RFC 6238 test vectors (last 6 of the 8 published digits)', () => {
    expect(generateTotp(RFC_SECRET, 59_000)).toBe('287082');
    expect(generateTotp(RFC_SECRET, 1_111_111_109_000)).toBe('081804');
    expect(generateTotp(RFC_SECRET, 1_234_567_890_000)).toBe('005924');
    expect(generateTotp(RFC_SECRET, 2_000_000_000_000)).toBe('279037');
  });

  it('accepts the current, previous and next step and returns the matched counter', () => {
    const now = 1_234_567_890_000;
    const counter = Math.floor(now / 30_000);
    expect(verifyTotp(RFC_SECRET, generateTotp(RFC_SECRET, now), now)).toBe(counter);
    expect(verifyTotp(RFC_SECRET, generateTotp(RFC_SECRET, now - 30_000), now)).toBe(counter - 1);
    expect(verifyTotp(RFC_SECRET, generateTotp(RFC_SECRET, now + 30_000), now)).toBe(counter + 1);
    expect(verifyTotp(RFC_SECRET, generateTotp(RFC_SECRET, now + 60_000), now)).toBeNull();
    expect(verifyTotp(RFC_SECRET, generateTotp(RFC_SECRET, now - 60_000), now)).toBeNull();
  });

  it('tolerates spaces and dashes and refuses malformed codes', () => {
    const now = 59_000;
    expect(normalizeTotpCode('287 082')).toBe('287082');
    expect(verifyTotp(RFC_SECRET, '287-082', now)).not.toBeNull();
    expect(verifyTotp(RFC_SECRET, '28708', now)).toBeNull();
    expect(verifyTotp(RFC_SECRET, 'abcdef', now)).toBeNull();
  });

  it('generates 160-bit secrets and otpauth URIs for authenticator apps', () => {
    const secret = generateTotpSecret();
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(generateTotpSecret()).not.toBe(secret);
    const uri = totpProvisioningUri(secret, 'captain@example.com');
    expect(uri).toMatch(/^otpauth:\/\/totp\/AIS%20Maritime%20Intelligence:captain%40example\.com\?/);
    expect(uri).toContain(`secret=${secret}`);
    expect(uri).toContain('algorithm=SHA1');
    expect(uri).toContain('digits=6');
    expect(uri).toContain('period=30');
  });
});
