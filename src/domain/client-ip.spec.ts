import { describe, expect, it } from 'vitest';

import { normalizeClientIp } from './client-ip.js';

describe('normalizeClientIp (sessions.ip is inet)', () => {
  it('keeps plain IPv4 and IPv6 addresses', () => {
    expect(normalizeClientIp('203.0.113.5')).toBe('203.0.113.5');
    expect(normalizeClientIp('::1')).toBe('::1');
    expect(normalizeClientIp('2001:db8::1')).toBe('2001:db8::1');
    expect(normalizeClientIp('::ffff:198.51.100.7')).toBe(
      '::ffff:198.51.100.7',
    );
    expect(normalizeClientIp(' 203.0.113.5 ')).toBe('203.0.113.5');
  });

  it('strips ports, brackets and IPv6 zone ids', () => {
    expect(normalizeClientIp('1.2.3.4:5678')).toBe('1.2.3.4');
    expect(normalizeClientIp('[2001:db8::1]')).toBe('2001:db8::1');
    expect(normalizeClientIp('[2001:db8::1]:443')).toBe('2001:db8::1');
    expect(normalizeClientIp('fe80::1%eth0')).toBe('fe80::1');
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
      null,
    ]) {
      expect(normalizeClientIp(value)).toBeNull();
    }
  });
});
