import { isIP } from 'node:net';

/** Longest accepted raw value (an IPv6 address with brackets, zone and port stays below it). */
const MAX_RAW_LENGTH = 100;

/** `[<address>]` or `[<address>]:<port>`. */
const BRACKETED = /^\[([^\]]+)\](?::\d{1,5})?$/;

/** `<IPv4>:<port>`, as some L7 balancers append the port to `X-Forwarded-For`. */
const IPV4_WITH_PORT = /^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/;

/**
 * The client address of a request in a form PostgreSQL `inet` accepts, or
 * `null` when there is none.
 *
 * Behind trusted proxies (`TRUSTED_PROXIES`) Fastify takes the left-most
 * untrusted `X-Forwarded-For` token as it was sent, and that token need
 * not be an address: `foo`, `1.2.3.4:5678`, `[2001:db8::1]`,
 * `[2001:db8::1]:443`. Brackets and ports are stripped, an IPv6 zone id
 * (`fe80::1%eth0`, which `inet` refuses) is dropped, and anything that is
 * still not an IPv4/IPv6 address yields `null` — a malformed header must
 * never turn a correct sign-in into a database error.
 *
 * @param value `request.ip` (or a socket address); `undefined`/`null` for none.
 * @returns the bare address, e.g. `203.0.113.5` or `2001:db8::1`, or `null`.
 */
export function normalizeClientIp(
  value: string | null | undefined,
): string | null {
  if (value === undefined || value === null) return null;
  let candidate = value.trim();
  if (candidate === '' || candidate.length > MAX_RAW_LENGTH) return null;
  const bracketed = BRACKETED.exec(candidate);
  const withPort = IPV4_WITH_PORT.exec(candidate);
  if (bracketed?.[1] !== undefined) candidate = bracketed[1];
  else if (withPort?.[1] !== undefined) candidate = withPort[1];
  const zone = candidate.indexOf('%');
  if (zone !== -1) candidate = candidate.slice(0, zone);
  return isIP(candidate) === 0 ? null : candidate;
}
