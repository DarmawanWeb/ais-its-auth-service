/**
 * Ids of the methodology catalog methods this service implements
 * (docs/references/methods.json, docs/PLATFORM_SPEC.md §17). The auth
 * service implements no maritime method: its security rules (password
 * policy, throttling, argon2id, TOTP, token rotation) cite their standards
 * in TSDoc instead (see the README, "Methodology & references").
 */
export const IMPLEMENTED_METHOD_IDS: readonly string[] = [];
