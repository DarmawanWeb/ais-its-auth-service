import { Transform, type TransformFnParams } from 'class-transformer';

/** Trims string input before validation (other values pass unchanged). */
export function trimString(params: TransformFnParams): unknown {
  const input: unknown = params.value;
  return typeof input === 'string' ? input.trim() : input;
}

/** Trims and lowercases e-mail input before validation. */
export function normalizeEmailInput(params: TransformFnParams): unknown {
  const input: unknown = params.value;
  return typeof input === 'string' ? input.trim().toLowerCase() : input;
}

/** `@Transform` of e-mail fields. */
export const EmailInput = (): PropertyDecorator =>
  Transform(normalizeEmailInput);

/** `@Transform` of trimmed text fields. */
export const TrimmedInput = (): PropertyDecorator => Transform(trimString);
