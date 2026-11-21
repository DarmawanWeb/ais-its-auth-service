/**
 * Normalization of identity input. E-mail addresses are compared
 * case-insensitively (`users_email_key` is a unique index on
 * `lower(email)`, spec §13.1) and stored trimmed and lowercased; slugs are
 * URL-safe organization handles.
 *
 * @see docs/PLATFORM_SPEC.md §13.1 (users, organizations)
 */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/** Longest slug (a DNS label, so slugs can become subdomains). */
export const SLUG_MAX_LENGTH = 63;

/** Lowercase ASCII words separated by single dashes. */
export const SLUG_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

/**
 * URL-safe slug of an organization name: accents are stripped, other
 * characters become dashes, and the result is cut at a dash boundary to
 * {@link SLUG_MAX_LENGTH}. Returns `null` when nothing usable remains
 * (e.g. a name in a non-Latin script), so the caller asks for an explicit slug.
 */
export function slugify(name: string): string | null {
  const ascii = name.normalize('NFKD').replace(/\p{M}/gu, '').toLowerCase();
  let slug = ascii.replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  if (slug.length > SLUG_MAX_LENGTH) {
    slug = slug.slice(0, SLUG_MAX_LENGTH).replace(/-+[^-]*$/, '');
    if (slug === '')
      slug = ascii.replace(/[^a-z0-9]/g, '').slice(0, SLUG_MAX_LENGTH);
  }
  return SLUG_PATTERN.test(slug) ? slug : null;
}

/**
 * Link of an e-mail that carries a one-time token. The token travels in
 * the URL fragment (`#token=…`), which browsers never send to servers, so
 * it never reaches access logs or `Referer` headers (spec §13.1).
 */
export function tokenLink(
  baseUrl: string,
  path: string,
  token: string,
): string {
  const base = baseUrl.replace(/\/+$/, '');
  const route = path.startsWith('/') ? path : `/${path}`;
  return `${base}${route}#token=${encodeURIComponent(token)}`;
}
