import { ServiceUnavailableError } from '@darmawanweb/ais-its-nest';
import type { AccessTokenKeyResolver } from '@darmawanweb/ais-its-nest/auth';
import { sanitizeError } from '@darmawanweb/ais-its-nest/db';
import {
  Injectable,
  Logger,
  type OnApplicationBootstrap,
} from '@nestjs/common';
import { type CryptoKey, errors as joseErrors, type JWK } from 'jose';

import { failureMessage } from '../../common/background-work.js';
import type { SigningKeyRow } from '../../db/database.js';
import { KEY_CACHE_REFRESH_MS } from '../../domain/signing-key-rules.js';
import { KeyEncryption } from '../crypto/key-encryption.service.js';
import {
  generateSigningKey,
  importPrivateKey,
  importPublicKey,
  parsePrivateJwk,
  publishedJwk,
  type SigningKeyMaterial,
} from './key-material.js';
import {
  type NewSigningKey,
  SigningKeysRepository,
} from './signing-keys.repository.js';

/** The key new access tokens are signed with. */
export interface ActiveSigningKey {
  readonly kid: string;
  readonly key: CryptoKey;
}

/** A JWK Set (RFC 7517 §5). */
export interface JsonWebKeySet {
  readonly keys: readonly JWK[];
}

/** Outcome of a rotation. */
export interface KeyRotation {
  readonly kid: string;
  readonly previousKid: string | null;
  readonly createdAt: Date;
}

interface LoadedKeys {
  readonly active: ActiveSigningKey | undefined;
  readonly verification: ReadonlyMap<string, CryptoKey>;
  readonly jwks: JsonWebKeySet;
  readonly loadedAt: number;
}

/** Minimum time between two reloads triggered by an unknown `kid`, ms. */
const UNKNOWN_KID_RELOAD_COOLDOWN_MS = 5_000;

/**
 * The service's JWT signing keys (spec §8.2, §13.1), cached in memory and
 * reloaded from `signing_keys` every {@link KEY_CACHE_REFRESH_MS} so every
 * replica follows rotations made by another one:
 *
 * - on bootstrap an Ed25519 key is generated when none is active (under an
 *   advisory lock, so concurrent first boots create one key);
 * - {@link signingKey} is the active key, {@link jwks} the published
 *   (active + retiring) keys, {@link keyResolver} verifies this service's
 *   own tokens locally (plugged into the kit `AuthModule`, no HTTP call to
 *   itself);
 * - private keys are stored sealed (AES-256-GCM, bound to the kid).
 *
 * When the database is briefly unreachable the cached keys keep working
 * (stale-if-error); without any cached key requests fail with `503`.
 */
@Injectable()
export class SigningKeyStore implements OnApplicationBootstrap {
  private readonly logger = new Logger('SigningKeys');
  private state: LoadedKeys | undefined;
  private loading: Promise<LoadedKeys> | undefined;
  private lastUnknownKidReload = 0;

  constructor(
    private readonly repository: SigningKeysRepository,
    private readonly encryption: KeyEncryption,
  ) {}

  /** Generates the first key on an empty database, then loads the keys. */
  async onApplicationBootstrap(): Promise<void> {
    await this.ensureActiveKey();
    await this.reload();
  }

  /**
   * Key resolver of the kit's access token verifier: the published key with
   * the token's `kid`. An unknown kid triggers one reload (rate limited), so a
   * key created by another replica is found; retired keys stay unknown (401).
   */
  readonly keyResolver: AccessTokenKeyResolver = async (header) => {
    const kid = header.kid;
    if (kid === undefined)
      throw new joseErrors.JWKSNoMatchingKey('The token has no kid');
    let keys = await this.current();
    let key = keys.verification.get(kid);
    if (
      key === undefined &&
      Date.now() - this.lastUnknownKidReload > UNKNOWN_KID_RELOAD_COOLDOWN_MS
    ) {
      this.lastUnknownKidReload = Date.now();
      keys = await this.reload();
      key = keys.verification.get(kid);
    }
    if (key === undefined) throw new joseErrors.JWKSNoMatchingKey();
    return key;
  };

  /** The active signing key. */
  async signingKey(): Promise<ActiveSigningKey> {
    const keys = await this.current();
    if (keys.active === undefined) {
      throw new ServiceUnavailableError('No active signing key is available');
    }
    return keys.active;
  }

  /** The published JWK Set (`GET /.well-known/jwks.json`). */
  async jwks(): Promise<JsonWebKeySet> {
    return (await this.current()).jwks;
  }

  /**
   * Rotates the signing key: the active key becomes `retiring` (still
   * published) and a new key becomes active, in one transaction.
   */
  async rotate(): Promise<KeyRotation> {
    const material = await generateSigningKey();
    const result = await this.repository.withKeyLock(async (executor) => {
      const previousKid = await this.repository.retireActive(executor);
      const row = await this.repository.insertActive(
        this.sealed(material),
        executor,
      );
      return {
        kid: row.kid,
        previousKid: previousKid ?? null,
        createdAt: row.createdAt,
      };
    });
    await this.reload();
    this.logger.log(
      `Rotated the signing key: ${result.previousKid ?? 'none'} → ${result.kid}`,
    );
    return result;
  }

  /** Retires the retiring keys whose grace period elapsed; returns their kids. */
  async retireExpired(graceSeconds: number): Promise<string[]> {
    const retired = await this.repository.retireExpired(graceSeconds);
    if (retired.length > 0) {
      this.logger.log(`Retired signing keys ${retired.join(', ')}`);
      await this.reload();
    }
    return retired;
  }

  /** Creates the first active key when there is none. */
  private async ensureActiveKey(): Promise<void> {
    if ((await this.repository.findActive()) !== undefined) return;
    const material = await generateSigningKey();
    const created = await this.repository.withKeyLock(async (executor) => {
      if ((await this.repository.findActive(executor)) !== undefined)
        return false;
      await this.repository.insertActive(this.sealed(material), executor);
      return true;
    });
    if (created)
      this.logger.log(`Generated the first signing key ${material.kid}`);
  }

  /** The row of new key material, its private JWK sealed and bound to the kid. */
  private sealed(material: SigningKeyMaterial): NewSigningKey {
    return {
      kid: material.kid,
      publicJwk: material.publicJwk,
      privateKeyEnc: this.encryption.seal(
        'signing-key',
        JSON.stringify(material.privateJwk),
        material.kid,
      ),
    };
  }

  /** The cached keys, reloaded when older than the refresh interval. */
  private async current(): Promise<LoadedKeys> {
    const state = this.state;
    if (
      state !== undefined &&
      Date.now() - state.loadedAt < KEY_CACHE_REFRESH_MS
    ) {
      return state;
    }
    try {
      return await this.reload();
    } catch (error) {
      if (state === undefined) {
        throw new ServiceUnavailableError('The signing keys cannot be loaded', {
          cause: error,
        });
      }
      this.logger.warn(
        { err: sanitizeError(error) },
        `Reloading the signing keys failed, using the cached keys: ${failureMessage(error)}`,
      );
      return state;
    }
  }

  /** Loads the published keys (single flight). */
  private reload(): Promise<LoadedKeys> {
    this.loading ??= this.load().then(
      (state) => {
        this.state = state;
        this.loading = undefined;
        return state;
      },
      (error: unknown) => {
        this.loading = undefined;
        throw error;
      },
    );
    return this.loading;
  }

  private async load(): Promise<LoadedKeys> {
    const rows = await this.repository.findPublished();
    const verification = new Map<string, CryptoKey>();
    for (const row of rows)
      verification.set(row.kid, await importPublicKey(row.publicJwk));
    const activeRow = rows.find((row) => row.status === 'active');
    return {
      active:
        activeRow === undefined ? undefined : await this.activeKey(activeRow),
      verification,
      jwks: { keys: rows.map((row) => publishedJwk(row.kid, row.publicJwk)) },
      loadedAt: Date.now(),
    };
  }

  private async activeKey(row: SigningKeyRow): Promise<ActiveSigningKey> {
    const json = this.encryption.open(
      'signing-key',
      row.privateKeyEnc,
      row.kid,
    );
    return { kid: row.kid, key: await importPrivateKey(parsePrivateJwk(json)) };
  }
}
