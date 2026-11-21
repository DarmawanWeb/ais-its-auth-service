/**
 * Password policy of spec §13.1: at least {@link PASSWORD_MIN_LENGTH}
 * characters with at least one letter and one digit. The upper bound
 * {@link PASSWORD_MAX_LENGTH} caps the hashing cost of a single request.
 *
 * Length is counted in Unicode code points, letters are any Unicode letter
 * (`\p{L}`) and digits any decimal digit (`\p{Nd}`), so passphrases in
 * Bahasa Indonesia or other scripts are accepted.
 *
 * @see docs/PLATFORM_SPEC.md §13.1 (Rules)
 * @see https://pages.nist.gov/800-63-4/sp800-63b.html (NIST SP 800-63B: length over composition, no truncation)
 */
export const PASSWORD_MIN_LENGTH = 10;

/** Longest accepted password, in code points (bounds argon2 input per request). */
export const PASSWORD_MAX_LENGTH = 128;

/** Why a password does not satisfy the policy. */
export type PasswordPolicyViolation =
  'too_short' | 'too_long' | 'missing_letter' | 'missing_digit';

const LETTER = /\p{L}/u;
const DIGIT = /\p{Nd}/u;

/**
 * Checks a candidate password against the policy.
 *
 * @returns every violated rule, in a stable order; empty when the password is acceptable.
 */
export function checkPasswordPolicy(
  password: string,
): PasswordPolicyViolation[] {
  const violations: PasswordPolicyViolation[] = [];
  const length = codePointLength(password);
  if (length < PASSWORD_MIN_LENGTH) violations.push('too_short');
  if (length > PASSWORD_MAX_LENGTH) violations.push('too_long');
  if (!LETTER.test(password)) violations.push('missing_letter');
  if (!DIGIT.test(password)) violations.push('missing_digit');
  return violations;
}

const VIOLATION_MESSAGES: Readonly<Record<PasswordPolicyViolation, string>> = {
  too_short: `must be at least ${PASSWORD_MIN_LENGTH} characters long`,
  too_long: `must be at most ${PASSWORD_MAX_LENGTH} characters long`,
  missing_letter: 'must contain at least one letter',
  missing_digit: 'must contain at least one digit',
};

/** Human-readable message of a violation (problem details `errors[].message`). */
export function passwordViolationMessage(
  violation: PasswordPolicyViolation,
): string {
  return VIOLATION_MESSAGES[violation];
}

/** Length in Unicode code points (what users count as characters, unlike UTF-16 units). */
function codePointLength(value: string): number {
  let length = 0;
  for (const _codePoint of value) length += 1;
  return length;
}
