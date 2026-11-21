import { ACCESS_TOKEN_ALGORITHM } from '@darmawanweb/ais-its-contracts/auth';
import {
  calculateJwkThumbprint,
  type CryptoKey,
  exportJWK,
  generateKeyPair,
  importJWK,
  type JWK,
} from 'jose';
import * as z from 'zod';

import type { PublicSigningJwk } from '../../db/schema.js';

/**
 * Ed25519 key material of the access token signer (spec §8.2): the key id
 * is the RFC 7638 JWK thumbprint (SHA-256, base64url) of the public key, so
 * it is derived from the key itself and identical on every instance.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7638 (JWK thumbprint)
 * @see https://www.rfc-editor.org/rfc/rfc8037 (OKP / Ed25519 JWKs)
 */
export interface SigningKeyMaterial {
  readonly kid: string;
  readonly publicJwk: PublicSigningJwk;
  /** Private JWK (`d` included): only ever stored sealed. */
  readonly privateJwk: PrivateSigningJwk;
}

/** Private Ed25519 JWK. */
export interface PrivateSigningJwk extends PublicSigningJwk {
  readonly d: string;
}

const PrivateJwkSchema = z.object({
  kty: z.literal('OKP'),
  crv: z.literal('Ed25519'),
  x: z.string().min(1),
  d: z.string().min(1),
});

const PublicJwkSchema = PrivateJwkSchema.omit({ d: true });

/** A fresh Ed25519 key pair with its thumbprint kid. */
export async function generateSigningKey(): Promise<SigningKeyMaterial> {
  const { publicKey, privateKey } = await generateKeyPair(
    ACCESS_TOKEN_ALGORITHM,
    {
      crv: 'Ed25519',
      extractable: true,
    },
  );
  const publicJwk = PublicJwkSchema.parse(await exportJWK(publicKey));
  const privateJwk = PrivateJwkSchema.parse(await exportJWK(privateKey));
  return { kid: await jwkThumbprint(publicJwk), publicJwk, privateJwk };
}

/** RFC 7638 thumbprint (SHA-256, base64url) of a public JWK. */
export function jwkThumbprint(publicJwk: PublicSigningJwk): Promise<string> {
  return calculateJwkThumbprint(
    { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x },
    'sha256',
  );
}

/** Parses a decrypted private JWK. */
export function parsePrivateJwk(json: string): PrivateSigningJwk {
  return PrivateJwkSchema.parse(JSON.parse(json));
}

/** The signing key (private) of a JWK. */
export function importPrivateKey(jwk: PrivateSigningJwk): Promise<CryptoKey> {
  return importJWK({ ...jwk }, ACCESS_TOKEN_ALGORITHM);
}

/** The verification key (public) of a JWK. */
export function importPublicKey(jwk: PublicSigningJwk): Promise<CryptoKey> {
  return importJWK(
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
    ACCESS_TOKEN_ALGORITHM,
  );
}

/** JWKS member of a published key (RFC 7517 §4: `kid`, `alg`, `use`). */
export function publishedJwk(kid: string, publicJwk: PublicSigningJwk): JWK {
  return {
    kty: publicJwk.kty,
    crv: publicJwk.crv,
    x: publicJwk.x,
    kid,
    alg: ACCESS_TOKEN_ALGORITHM,
    use: 'sig',
  };
}
