/** U+FFFD, written in place of characters PostgreSQL cannot store. */
export const REPLACEMENT_CHARACTER = '�';

/** Deepest nesting of a JSON value kept by {@link storableJson}. */
export const MAX_JSON_DEPTH = 32;

/** Written in place of a JSON subtree nested deeper than {@link MAX_JSON_DEPTH}. */
export const TRUNCATED_JSON = '[truncated: nested too deeply]';

/** U+0000, refused by `text` and `jsonb`. */
const NUL = '\u0000';

/** A UTF-16 surrogate without its partner, refused by `jsonb` (`"\ud800"`). */
const LONE_SURROGATE =
  /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

/**
 * Text PostgreSQL can store. Valid JSON (and therefore a valid event) may
 * carry characters the database refuses: U+0000 in `text` and `jsonb`
 * ("invalid byte sequence for encoding UTF8: 0x00", "unsupported Unicode
 * escape sequence") and lone surrogates in `jsonb`. Retrying such an insert
 * can never succeed, so the characters are replaced with U+FFFD.
 */
export function storableText(value: string): string {
  return value
    .replaceAll(NUL, REPLACEMENT_CHARACTER)
    .replace(LONE_SURROGATE, REPLACEMENT_CHARACTER);
}

/** {@link storableText} for an optional value. */
export function storableNullableText(value: string | null): string | null {
  return value === null ? null : storableText(value);
}

/**
 * A JSON value PostgreSQL `jsonb` can store: {@link storableText} applied to
 * every string (object keys included), and subtrees nested deeper than
 * {@link MAX_JSON_DEPTH} replaced by {@link TRUNCATED_JSON} (serializing
 * them would overflow the stack).
 */
export function storableJson(value: unknown, depth = 0): unknown {
  if (typeof value === 'string') return storableText(value);
  if (value === null || typeof value !== 'object') return value;
  if (depth >= MAX_JSON_DEPTH) return TRUNCATED_JSON;
  if (Array.isArray(value))
    return value.map((item) => storableJson(item, depth + 1));
  return storableRecord(value as Record<string, unknown>, depth);
}

/** {@link storableJson} of an object (the `meta` of an audit record). */
export function storableRecord(
  value: Readonly<Record<string, unknown>>,
  depth = 0,
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      storableText(key),
      storableJson(item, depth + 1),
    ]),
  );
}
