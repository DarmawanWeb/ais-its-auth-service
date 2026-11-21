import { describe, expect, it } from 'vitest';

import {
  generateSigningKey,
  importPrivateKey,
  importPublicKey,
  jwkThumbprint,
  parsePrivateJwk,
  publishedJwk,
} from './key-material.js';

describe('signing key material (Ed25519, RFC 7638 kid)', () => {
  it('derives the kid as the RFC 7638 thumbprint (RFC 8037 appendix A.3 vector)', async () => {
    await expect(
      jwkThumbprint({
        kty: 'OKP',
        crv: 'Ed25519',
        x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
      }),
    ).resolves.toBe('kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k');
  });

  it('generates distinct Ed25519 key pairs whose kid is their own thumbprint', async () => {
    const first = await generateSigningKey();
    const second = await generateSigningKey();

    expect(first.kid).not.toBe(second.kid);
    expect(first.kid).toMatch(/^[A-Za-z0-9_-]{43}$/);
    await expect(jwkThumbprint(first.publicJwk)).resolves.toBe(first.kid);
    expect(first.publicJwk).toEqual({
      kty: 'OKP',
      crv: 'Ed25519',
      x: first.privateJwk.x,
    });
    await expect(importPublicKey(first.publicJwk)).resolves.toBeDefined();
    await expect(
      importPrivateKey(parsePrivateJwk(JSON.stringify(first.privateJwk))),
    ).resolves.toBeDefined();
  });

  it('publishes only public members with kid, alg and use', async () => {
    const material = await generateSigningKey();
    const jwk = publishedJwk(material.kid, material.publicJwk);

    expect(jwk).toEqual({
      kty: 'OKP',
      crv: 'Ed25519',
      x: material.publicJwk.x,
      kid: material.kid,
      alg: 'EdDSA',
      use: 'sig',
    });
    expect(jwk).not.toHaveProperty('d');
  });

  it('refuses decrypted material that is not a private Ed25519 JWK', () => {
    expect(() =>
      parsePrivateJwk(JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x: 'x' })),
    ).toThrow();
    expect(() =>
      parsePrivateJwk(
        JSON.stringify({ kty: 'EC', crv: 'P-256', x: 'x', d: 'd' }),
      ),
    ).toThrow();
  });
});
