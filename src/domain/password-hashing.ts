/**
 * Password hashing parameters (spec §13.1): argon2id with m = 19 456 KiB,
 * t = 2, p = 1 — the first OWASP-recommended configuration — producing PHC
 * strings `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>` (16-byte random
 * salt, 32-byte output). Hashes created with other parameters are upgraded
 * transparently after a successful login ({@link needsRehash}).
 *
 * @see docs/PLATFORM_SPEC.md §13.1 (Rules)
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
 * @see https://www.rfc-editor.org/rfc/rfc9106 (Argon2)
 */
export const ARGON2_PARAMETERS = Object.freeze({
  /** Memory cost, KiB. */
  memoryCost: 19_456,
  /** Passes. */
  timeCost: 2,
  /** Lanes. */
  parallelism: 1,
  /** Raw hash length, bytes. */
  outputLen: 32,
});

/** Parameters encoded in a stored hash (`@node-rs/argon2` `parseOptions`). */
export interface StoredHashParameters {
  /** `0` argon2d, `1` argon2i, `2` argon2id. */
  readonly algorithm: number;
  readonly memoryCost: number;
  readonly timeCost: number;
  readonly parallelism: number;
  readonly outputLen: number;
}

/** Numeric id of argon2id in `@node-rs/argon2` (its `Algorithm.Argon2id`). */
export const ARGON2ID = 2;

/** `true` when a stored hash was made with other parameters than {@link ARGON2_PARAMETERS}. */
export function needsRehash(stored: StoredHashParameters): boolean {
  return (
    stored.algorithm !== ARGON2ID ||
    stored.memoryCost !== ARGON2_PARAMETERS.memoryCost ||
    stored.timeCost !== ARGON2_PARAMETERS.timeCost ||
    stored.parallelism !== ARGON2_PARAMETERS.parallelism ||
    stored.outputLen !== ARGON2_PARAMETERS.outputLen
  );
}
