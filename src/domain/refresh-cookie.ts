import {
  REFRESH_TOKEN_COOKIE,
  REFRESH_TOKEN_COOKIE_PATH,
} from '@darmawanweb/ais-its-contracts/auth';

/**
 * The refresh token cookie of spec §8.3: `aisits_rt`, `HttpOnly` (no script
 * access), `Secure` (configurable off for plain-HTTP development),
 * `SameSite=Strict` (never sent on cross-site requests), `Path=/api/v2/auth`
 * (only the refresh and logout endpoints receive it) and a `Max-Age` equal to
 * the refresh token lifetime.
 *
 * @see docs/PLATFORM_SPEC.md §8.3
 * @see https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html (SameSite, cookie attributes)
 */
export interface RefreshCookieAttributes {
  readonly httpOnly: true;
  readonly secure: boolean;
  readonly sameSite: 'strict';
  readonly path: string;
  /** Seconds; `0` deletes the cookie. */
  readonly maxAge: number;
}

/** Name of the cookie. */
export const REFRESH_COOKIE_NAME = REFRESH_TOKEN_COOKIE;

/** Attributes of a refresh cookie living `ttlDays`. */
export function refreshCookieAttributes(
  secure: boolean,
  ttlDays: number,
): RefreshCookieAttributes {
  return {
    httpOnly: true,
    secure,
    sameSite: 'strict',
    path: REFRESH_TOKEN_COOKIE_PATH,
    maxAge: ttlDays * 86_400,
  };
}

/** Attributes that delete the cookie (same scope, `Max-Age=0`). */
export function clearedRefreshCookieAttributes(
  secure: boolean,
): RefreshCookieAttributes {
  return { ...refreshCookieAttributes(secure, 0), maxAge: 0 };
}

/**
 * Problem codes of a refresh that ends the session for good: the browser
 * must drop its cookie. Every other failure (database outage, no signing
 * key loaded, a timeout) is transient — the session is still valid on the
 * server — so the cookie is kept and the client can retry.
 */
export const SESSION_ENDING_REFRESH_CODES: ReadonlySet<string> = new Set([
  'INVALID_REFRESH_TOKEN',
  'REFRESH_TOKEN_REUSED',
  'ACCOUNT_DISABLED',
]);

/** `true` when a failed refresh must clear the cookie (see {@link SESSION_ENDING_REFRESH_CODES}). */
export function refreshFailureEndsSession(error: unknown): boolean {
  return (
    error instanceof Error &&
    'code' in error &&
    typeof error.code === 'string' &&
    SESSION_ENDING_REFRESH_CODES.has(error.code)
  );
}
