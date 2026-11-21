import { ApiProperty } from '@nestjs/swagger';

import type { JsonWebKeySet, KeyRotation } from '../signing-key.store.js';

/** A published Ed25519 public key (RFC 7517 / RFC 8037). */
export class JwkDto {
  @ApiProperty({ enum: ['OKP'] })
  readonly kty: string;

  @ApiProperty({ enum: ['Ed25519'] })
  readonly crv: string;

  @ApiProperty({ description: 'Public key, base64url' })
  readonly x: string;

  @ApiProperty({
    description: 'Key id: RFC 7638 thumbprint (SHA-256, base64url)',
  })
  readonly kid: string;

  @ApiProperty({ enum: ['EdDSA'] })
  readonly alg: string;

  @ApiProperty({ enum: ['sig'] })
  readonly use: string;

  constructor(jwk: JsonWebKeySet['keys'][number]) {
    this.kty = jwk.kty ?? 'OKP';
    this.crv = jwk.crv ?? 'Ed25519';
    this.x = jwk.x ?? '';
    this.kid = jwk.kid ?? '';
    this.alg = jwk.alg ?? 'EdDSA';
    this.use = jwk.use ?? 'sig';
  }
}

/** JWK Set of the access token signer (active and retiring keys). */
export class JwksDto {
  @ApiProperty({ type: [JwkDto] })
  readonly keys: JwkDto[];

  constructor(jwks: JsonWebKeySet) {
    this.keys = jwks.keys.map((jwk) => new JwkDto(jwk));
  }
}

/** Result of `POST /auth/keys/rotate`. */
export class KeyRotationDto {
  @ApiProperty({ description: 'Kid of the new active key' })
  readonly kid: string;

  @ApiProperty({
    type: String,
    nullable: true,
    description:
      'Kid of the key that is now retiring (still published until it retires)',
  })
  readonly previousKid: string | null;

  @ApiProperty({ format: 'date-time' })
  readonly createdAt: string;

  constructor(rotation: KeyRotation) {
    this.kid = rotation.kid;
    this.previousKid = rotation.previousKid;
    this.createdAt = rotation.createdAt.toISOString();
  }
}
