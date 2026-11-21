import { describe, expect, it } from 'vitest';

import { allowedOrigins, isAllowedOrigin, normalizeOrigin } from './origin-policy.js';

describe('origin policy of the cookie endpoints (CSRF)', () => {
  const allowed = allowedOrigins(['http://localhost:5173', 'http://localhost:8000/', 'https://ais.example.id/app']);

  it('normalizes configured URLs to origins', () => {
    expect([...allowed].sort()).toEqual(['http://localhost:5173', 'http://localhost:8000', 'https://ais.example.id']);
    expect(normalizeOrigin('HTTPS://AIS.EXAMPLE.ID:443')).toBe('https://ais.example.id');
    expect(normalizeOrigin('ftp://files.example')).toBeNull();
    expect(normalizeOrigin('not a url')).toBeNull();
  });

  it('accepts requests without Origin and from allowed origins only', () => {
    expect(isAllowedOrigin(undefined, allowed)).toBe(true);
    expect(isAllowedOrigin('http://localhost:5173', allowed)).toBe(true);
    expect(isAllowedOrigin('https://ais.example.id', allowed)).toBe(true);
    expect(isAllowedOrigin('https://evil.example', allowed)).toBe(false);
    expect(isAllowedOrigin('http://localhost:5174', allowed)).toBe(false);
    expect(isAllowedOrigin('https://ais.example.id.evil.example', allowed)).toBe(false);
    expect(isAllowedOrigin('null', allowed)).toBe(false);
  });
});
