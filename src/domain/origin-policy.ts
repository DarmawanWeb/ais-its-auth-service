/**
 * CSRF defence of the cookie endpoints (`POST /auth/refresh`,
 * `POST /auth/logout`): besides `SameSite=Strict`, a request that carries an
 * `Origin` header must come from an allowed web origin — the `CORS_ORIGINS`
 * list or the origin of `PUBLIC_BASE_URL`. Requests without `Origin`
 * (same-origin navigations of old browsers, server-side clients) pass;
 * `Origin: null` (sandboxed frames, opaque origins) is refused.
 *
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#verifying-origin-with-standard-headers
 * @see https://www.rfc-editor.org/rfc/rfc6454 (origin serialization)
 */
export function normalizeOrigin(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    return url.origin;
  } catch {
    return null;
  }
}

/** The allowed origins (normalized, deduplicated) of the configured URLs. */
export function allowedOrigins(urls: Iterable<string>): ReadonlySet<string> {
  const origins = new Set<string>();
  for (const url of urls) {
    const origin = normalizeOrigin(url);
    if (origin !== null) origins.add(origin);
  }
  return origins;
}

/**
 * `true` when a request with this `Origin` header value may use the
 * refresh cookie.
 */
export function isAllowedOrigin(
  origin: string | undefined,
  allowed: ReadonlySet<string>,
): boolean {
  if (origin === undefined) return true;
  const normalized = normalizeOrigin(origin);
  return normalized !== null && allowed.has(normalized);
}
