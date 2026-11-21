import { Secret, TOTP } from 'otpauth';

/**
 * Time-based one-time passwords for MFA (RFC 6238) with the parameters every
 * authenticator app supports: HMAC-SHA1, 6 digits, 30-second steps, and a
 * verification window of ±1 step (clock drift and typing time). Secrets are
 * 160 random bits (RFC 4226 §4 recommends at least 128, 160 is the HMAC-SHA1
 * block-size choice of most issuers), exchanged as base32 in an
 * `otpauth://` URI.
 *
 * A code is accepted once: verification returns the matched time-step
 * counter, which the caller records so a replayed code is refused.
 *
 * @see https://www.rfc-editor.org/rfc/rfc6238 (TOTP)
 * @see https://www.rfc-editor.org/rfc/rfc4226#section-4 (secret length)
 * @see https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 */
export const TOTP_PARAMETERS = Object.freeze({
  algorithm: 'SHA1',
  digits: 6,
  periodSeconds: 30,
  /** Steps accepted before and after the current one. */
  window: 1,
  secretBytes: 20,
});

/** Issuer shown by authenticator apps. */
export const TOTP_ISSUER = 'AIS Maritime Intelligence';

const CODE_PATTERN = /^\d{6}$/;

function totp(secretBase32: string, label = 'account'): TOTP {
  return new TOTP({
    issuer: TOTP_ISSUER,
    label,
    algorithm: TOTP_PARAMETERS.algorithm,
    digits: TOTP_PARAMETERS.digits,
    period: TOTP_PARAMETERS.periodSeconds,
    secret: Secret.fromBase32(secretBase32),
  });
}

/** A new random secret, base32 encoded. */
export function generateTotpSecret(): string {
  return new Secret({ size: TOTP_PARAMETERS.secretBytes }).base32;
}

/** `otpauth://totp/…` provisioning URI (QR code content) for `accountName` (the e-mail). */
export function totpProvisioningUri(
  secretBase32: string,
  accountName: string,
): string {
  return totp(secretBase32, accountName).toString();
}

/** Removes the spaces and dashes users type between digit groups. */
export function normalizeTotpCode(code: string): string {
  return code.replace(/[\s-]/g, '');
}

/**
 * Verifies a code at `timestampMs`.
 *
 * @returns the time-step counter the code belongs to, or `null` when the
 *   code is malformed or outside the window.
 */
export function verifyTotp(
  secretBase32: string,
  code: string,
  timestampMs: number,
): number | null {
  const token = normalizeTotpCode(code);
  if (!CODE_PATTERN.test(token)) return null;
  const generator = totp(secretBase32);
  const delta = generator.validate({
    token,
    timestamp: timestampMs,
    window: TOTP_PARAMETERS.window,
  });
  if (delta === null) return null;
  return generator.counter({ timestamp: timestampMs }) + delta;
}

/** The code of `secretBase32` at `timestampMs` (tests, demo tooling). */
export function generateTotp(
  secretBase32: string,
  timestampMs: number,
): string {
  return totp(secretBase32).generate({ timestamp: timestampMs });
}
