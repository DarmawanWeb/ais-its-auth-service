import { describe, expect, it } from 'vitest';

import { clientInfo } from './principals.js';

/** `clientInfo` of a request whose `request.ip` (proxy-addr) is `ip`. */
const ipOf = (ip: string | undefined): string | null =>
  clientInfo({ ip, headers: {} }).ip;

/**
 * Client addresses of sessions (`sessions.ip` is `inet`) and throttle keys:
 * the case table of the former local `normalizeClientIp`, now served by the
 * kit's `clientIp`, so stored ips are unchanged by the 0.2.0 upgrade.
 */
describe('clientInfo (session and throttle ips)', () => {
  it('keeps plain IPv4 and IPv6 addresses', () => {
    expect(ipOf('203.0.113.5')).toBe('203.0.113.5');
    expect(ipOf('::1')).toBe('::1');
    expect(ipOf('2001:db8::1')).toBe('2001:db8::1');
    expect(ipOf('::ffff:198.51.100.7')).toBe('::ffff:198.51.100.7');
    expect(ipOf(' 203.0.113.5 ')).toBe('203.0.113.5');
  });

  it('strips ports, brackets and IPv6 zone ids', () => {
    expect(ipOf('1.2.3.4:5678')).toBe('1.2.3.4');
    expect(ipOf('[2001:db8::1]')).toBe('2001:db8::1');
    expect(ipOf('[2001:db8::1]:443')).toBe('2001:db8::1');
    expect(ipOf('fe80::1%eth0')).toBe('fe80::1');
  });

  it('turns everything that is not an address into null', () => {
    for (const value of [
      'foo',
      'bar',
      '',
      '   ',
      'unknown',
      '1.2.3.256',
      '01.2.3.4',
      '1.2.3.4:99999999',
      '[foo]',
      '203.0.113.5, bar',
      'a'.repeat(200),
      undefined,
    ]) {
      expect(ipOf(value)).toBeNull();
    }
  });

  it('keeps the user agent up to 512 characters', () => {
    expect(clientInfo({ headers: { 'user-agent': 'x'.repeat(600) } })).toEqual({
      ip: null,
      userAgent: 'x'.repeat(512),
    });
    expect(clientInfo({ headers: { 'user-agent': '' } }).userAgent).toBeNull();
    expect(clientInfo({}).userAgent).toBeNull();
  });
});
