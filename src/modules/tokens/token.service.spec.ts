import { ROLE_PERMISSIONS } from '@darmawanweb/ais-its-contracts/auth';
import {
  loadConfig,
  ServiceUnavailableError,
  UnauthorizedError,
} from '@darmawanweb/ais-its-nest';
import { verifyAccessToken } from '@darmawanweb/ais-its-nest/auth';
import {
  calculateJwkThumbprint,
  createLocalJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  jwtVerify,
} from 'jose';
import { Logger } from '@nestjs/common';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { type Config, configSchema } from '../../config.js';
import type { Executor, SigningKeyRow } from '../../db/database.js';
import { KeyEncryption } from '../crypto/key-encryption.service.js';
import { SigningKeyStore } from '../keys/signing-key.store.js';
import {
  type NewSigningKey,
  SigningKeysRepository,
} from '../keys/signing-keys.repository.js';
import { type AccessTokenSubject, TokenService } from './token.service.js';

/** `signing_keys` in memory: the repository methods the key store uses, without a database. */
class InMemorySigningKeys extends SigningKeysRepository {
  readonly rows: SigningKeyRow[] = [];

  constructor() {
    // Never touches drizzle: every method the store calls is overridden below.
    super(undefined as never);
  }

  override withKeyLock<T>(
    work: (executor: Executor) => Promise<T>,
  ): Promise<T> {
    return work(undefined as never);
  }

  override findPublished(): Promise<SigningKeyRow[]> {
    return Promise.resolve(
      this.rows
        .filter((row) => row.status !== 'retired')
        .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime()),
    );
  }

  override findActive(): Promise<SigningKeyRow | undefined> {
    return Promise.resolve(this.rows.find((row) => row.status === 'active'));
  }

  override insertActive(key: NewSigningKey): Promise<SigningKeyRow> {
    const row: SigningKeyRow = {
      ...key,
      algorithm: 'EdDSA',
      status: 'active',
      // Strictly increasing creation times keep "newest first" deterministic.
      createdAt: new Date(Date.now() + this.rows.length),
      retiredAt: null,
    };
    this.rows.push(row);
    return Promise.resolve(row);
  }

  override retireActive(): Promise<string | undefined> {
    const active = this.rows.find((row) => row.status === 'active');
    if (active !== undefined) active.status = 'retiring';
    return Promise.resolve(active?.kid);
  }
}

const SUBJECT: AccessTokenSubject = {
  userId: '0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b',
  sessionId: '0193a1b2-c3d4-7e5f-8a9b-1c1d2e3f4a5b',
  orgId: '0193a1b2-c3d4-7e5f-8a9b-2c1d2e3f4a5b',
  roles: ['fleet_manager'],
  email: 'fleet@example.com',
  name: 'Fleet Manager',
};

function testConfig(): Config {
  return loadConfig(configSchema, {
    env: { LOG_LEVEL: 'silent', ACCESS_TOKEN_TTL: '600' },
    envFile: false,
    output: null,
  });
}

describe('TokenService (spec §8.2 access tokens, 5-minute MFA challenges)', () => {
  let config: Config;
  let repository: InMemorySigningKeys;
  let keys: SigningKeyStore;
  let tokens: TokenService;

  beforeAll(() => {
    Logger.overrideLogger(false);
  });

  beforeEach(async () => {
    config = testConfig();
    repository = new InMemorySigningKeys();
    keys = new SigningKeyStore(repository, new KeyEncryption(config));
    await keys.onApplicationBootstrap();
    tokens = new TokenService(keys, config);
  });

  it('signs EdDSA access tokens with the spec claims and the active kid', async () => {
    const now = new Date();
    const issued = await tokens.issueAccessToken(SUBJECT, now);

    const header = decodeProtectedHeader(issued.accessToken);
    const [active] = repository.rows;
    expect(header).toEqual({ alg: 'EdDSA', kid: active?.kid, typ: 'JWT' });
    const claims = decodeJwt(issued.accessToken);
    expect(claims).toEqual({
      iss: 'ais-its-auth',
      aud: 'ais-its-api',
      sub: SUBJECT.userId,
      sid: SUBJECT.sessionId,
      org: SUBJECT.orgId,
      roles: ['fleet_manager'],
      email: SUBJECT.email,
      name: SUBJECT.name,
      typ: 'access',
      iat: Math.floor(now.getTime() / 1000),
      exp: Math.floor(now.getTime() / 1000) + 600,
    });
    expect(issued.expiresIn).toBe(600);
    expect(issued.expiresAt.getTime()).toBe(Number(claims.exp) * 1000);
  });

  it('issues tokens every service verifies with the kit verifier and the published JWKS', async () => {
    const { accessToken } = await tokens.issueAccessToken(SUBJECT);

    const principal = await verifyAccessToken(accessToken, {
      issuer: config.AUTH_ISSUER,
      audience: config.AUTH_AUDIENCE,
      keyResolver: createLocalJWKSet({ keys: [...(await keys.jwks()).keys] }),
    });
    expect(principal).toMatchObject({
      id: SUBJECT.userId,
      sessionId: SUBJECT.sessionId,
      orgId: SUBJECT.orgId,
      roles: ['fleet_manager'],
      isPlatformAdmin: false,
    });
    expect([...principal.permissions].sort()).toEqual(
      [...ROLE_PERMISSIONS.fleet_manager].sort(),
    );
    // The local resolver plugged into the kit AuthModule accepts it too.
    await expect(
      verifyAccessToken(accessToken, {
        issuer: config.AUTH_ISSUER,
        audience: config.AUTH_AUDIENCE,
        keyResolver: keys.keyResolver,
      }),
    ).resolves.toMatchObject({ id: SUBJECT.userId });
  });

  it('publishes public keys only, with the RFC 7638 thumbprint as kid, and seals the private key', async () => {
    const { keys: published } = await keys.jwks();
    expect(published).toHaveLength(1);
    const [jwk] = published;
    expect(typeof jwk?.x).toBe('string');
    expect(jwk).toEqual({
      kty: 'OKP',
      crv: 'Ed25519',
      x: jwk?.x,
      kid: await calculateJwkThumbprint(
        { kty: 'OKP', crv: 'Ed25519', x: String(jwk?.x) },
        'sha256',
      ),
      alg: 'EdDSA',
      use: 'sig',
    });
    const [row] = repository.rows;
    expect(row?.privateKeyEnc).toMatch(/^v1\.[\w-]+\.[\w-]+\.[\w-]+$/);
    expect(row?.privateKeyEnc).not.toContain(String(jwk?.x));
  });

  it('signs with the new key after a rotation while tokens of the retiring key keep verifying', async () => {
    const before = await tokens.issueAccessToken(SUBJECT);
    const rotation = await keys.rotate();
    const after = await tokens.issueAccessToken(SUBJECT);

    expect(rotation.previousKid).toBe(
      decodeProtectedHeader(before.accessToken).kid,
    );
    expect(decodeProtectedHeader(after.accessToken).kid).toBe(rotation.kid);
    const jwks = createLocalJWKSet({ keys: [...(await keys.jwks()).keys] });
    for (const token of [before.accessToken, after.accessToken]) {
      await expect(
        jwtVerify(token, jwks, {
          issuer: config.AUTH_ISSUER,
          audience: config.AUTH_AUDIENCE,
        }),
      ).resolves.toBeDefined();
    }
  });

  it('round-trips single-use MFA challenges valid for 5 minutes', async () => {
    const now = new Date();
    const token = await tokens.issueMfaChallenge(SUBJECT.userId, now);

    const challenge = await tokens.verifyMfaChallenge(token);
    expect(challenge.userId).toBe(SUBJECT.userId);
    expect(challenge.challengeId).toMatch(/^[0-9a-f-]{36}$/);
    expect(challenge.expiresAt.getTime()).toBe(
      (Math.floor(now.getTime() / 1000) + 300) * 1000,
    );
    const second = await tokens.verifyMfaChallenge(
      await tokens.issueMfaChallenge(SUBJECT.userId, now),
    );
    expect(second.challengeId).not.toBe(challenge.challengeId);
  });

  it('never accepts an MFA challenge as an access token, nor the reverse', async () => {
    const challenge = await tokens.issueMfaChallenge(SUBJECT.userId);
    await expect(
      verifyAccessToken(challenge, {
        issuer: config.AUTH_ISSUER,
        audience: config.AUTH_AUDIENCE,
        keyResolver: keys.keyResolver,
      }),
    ).rejects.toBeInstanceOf(UnauthorizedError);

    const { accessToken } = await tokens.issueAccessToken(SUBJECT);
    await expect(tokens.verifyMfaChallenge(accessToken)).rejects.toBeInstanceOf(
      UnauthorizedError,
    );
  });

  it('refuses expired and tampered MFA challenges', async () => {
    const expired = await tokens.issueMfaChallenge(
      SUBJECT.userId,
      new Date(Date.now() - 301_000),
    );
    await expect(tokens.verifyMfaChallenge(expired)).rejects.toBeInstanceOf(
      UnauthorizedError,
    );

    const valid = await tokens.issueMfaChallenge(SUBJECT.userId);
    const [header, payload, signature] = valid.split('.');
    const forged = Buffer.from(
      JSON.stringify({
        ...decodeJwt(valid),
        sub: '0193a1b2-c3d4-7e5f-8a9b-9c1d2e3f4a5b',
      }),
    ).toString('base64url');
    expect(forged).not.toBe(payload);
    await expect(
      tokens.verifyMfaChallenge(`${header}.${forged}.${signature}`),
    ).rejects.toBeInstanceOf(UnauthorizedError);
  });

  it('answers 503 instead of signing when no key could ever be loaded', async () => {
    const broken = new SigningKeyStore(
      new (class extends InMemorySigningKeys {
        override findPublished(): Promise<SigningKeyRow[]> {
          return Promise.reject(new Error('database down'));
        }
      })(),
      new KeyEncryption(config),
    );
    await expect(
      new TokenService(broken, config).issueAccessToken(SUBJECT),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});
