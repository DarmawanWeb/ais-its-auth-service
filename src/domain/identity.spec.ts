import { describe, expect, it } from 'vitest';

import { normalizeEmail, SLUG_MAX_LENGTH, slugify, tokenLink } from './identity.js';

describe('identity helpers', () => {
  it('normalizes e-mails for case-insensitive identity', () => {
    expect(normalizeEmail('  Captain.Ahmad@Example.COM ')).toBe('captain.ahmad@example.com');
  });

  it('derives URL-safe slugs from organization names', () => {
    expect(slugify('PT Pelayaran Nusantara')).toBe('pt-pelayaran-nusantara');
    expect(slugify('Dinas Perhubungan — Kota Batam')).toBe('dinas-perhubungan-kota-batam');
    expect(slugify('Société Générale Maritime')).toBe('societe-generale-maritime');
    expect(slugify('  --Ocean   & Co.--  ')).toBe('ocean-co');
    expect(slugify('海事局')).toBeNull();
    const long = slugify('word '.repeat(30));
    expect(long?.length).toBeLessThanOrEqual(SLUG_MAX_LENGTH);
    expect(long?.endsWith('-')).toBe(false);
  });

  it('puts one-time tokens into the URL fragment', () => {
    expect(tokenLink('http://localhost:8000/', '/reset-password', 'abc_DEF-123')).toBe(
      'http://localhost:8000/reset-password#token=abc_DEF-123',
    );
    expect(tokenLink('https://ais.example.id/app', 'accept-invite', 'x')).toBe(
      'https://ais.example.id/app/accept-invite#token=x',
    );
  });
});
