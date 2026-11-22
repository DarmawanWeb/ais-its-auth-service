import {
  type Database,
  DRIZZLE_DB,
  PG_POOL,
  type Pool,
} from '@darmawanweb/ais-its-nest/db';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import type * as schema from '../src/db/schema.js';
import { UsersRepository } from '../src/modules/accounts/users.repository.js';
import {
  KeyEncryption,
  type KeyEncryptionSecrets,
} from '../src/modules/crypto/key-encryption.service.js';
import {
  KeySecretRotation,
  KeySecretRotationError,
} from '../src/modules/crypto/key-secret-rotation.js';
import { SigningKeysRepository } from '../src/modules/keys/signing-keys.repository.js';
import { startTestService, type TestService } from './support/test-service.js';

const NEW_SECRET = 'rotated-key-encryption-secret-0123456789';

describe('rotating KEY_ENCRYPTION_SECRET (pnpm rotate:key-secret)', () => {
  let service: TestService;

  beforeAll(async () => {
    service = await startTestService();
  });

  afterAll(async () => {
    await service.close();
  });

  const rotation = (secrets: KeyEncryptionSecrets) => {
    const db = service.app.get<unknown, Database<typeof schema>>(DRIZZLE_DB);
    return new KeySecretRotation(
      db,
      new KeyEncryption(secrets),
      new SigningKeysRepository(db),
      new UsersRepository(db),
    );
  };

  it('re-seals signing keys and MFA secrets under the new secret, atomically and idempotently', async () => {
    const user = await service.createUser({
      email: service.email('mfa-rotation'),
    });
    const users = service.app.get(UsersRepository);
    await users.setMfa(user.id, {
      secretEnc: service.app
        .get(KeyEncryption)
        .seal('mfa-secret', 'JBSWY3DPEHPK3PXP', user.id),
      enabled: true,
    });
    const oldSecret = service.config.KEY_ENCRYPTION_SECRET;
    const pool = service.app.get<unknown, Pool>(PG_POOL);
    const stored = async () => ({
      keys: (
        await pool.query<{ kid: string; private_key_enc: string }>(
          'SELECT kid, private_key_enc FROM signing_keys ORDER BY kid',
        )
      ).rows,
      mfa: (
        await pool.query<{ mfa_secret_enc: string }>(
          'SELECT mfa_secret_enc FROM users WHERE id = $1',
          [user.id],
        )
      ).rows[0]?.mfa_secret_enc,
    });
    const before = await stored();
    expect(before.keys).toHaveLength(1);

    await expect(
      rotation({
        KEY_ENCRYPTION_SECRET: NEW_SECRET,
        KEY_ENCRYPTION_SECRET_PREVIOUS: undefined,
      }).run(),
    ).rejects.toThrow(KeySecretRotationError);
    // A wrong previous secret changes nothing (one transaction).
    await expect(
      rotation({
        KEY_ENCRYPTION_SECRET: NEW_SECRET,
        KEY_ENCRYPTION_SECRET_PREVIOUS:
          'wrong-previous-secret-0123456789abcdef',
      }).run(),
    ).rejects.toThrow(/opens with neither/);
    expect(await stored()).toEqual(before);

    const during = {
      KEY_ENCRYPTION_SECRET: NEW_SECRET,
      KEY_ENCRYPTION_SECRET_PREVIOUS: oldSecret,
    };
    expect(await rotation(during).run()).toEqual({
      signingKeys: 1,
      mfaSecrets: 1,
      alreadyCurrent: 0,
    });
    expect(await rotation(during).run()).toEqual({
      signingKeys: 0,
      mfaSecrets: 0,
      alreadyCurrent: 2,
    });

    // Everything opens with the new secret alone.
    const after = new KeyEncryption({
      KEY_ENCRYPTION_SECRET: NEW_SECRET,
      KEY_ENCRYPTION_SECRET_PREVIOUS: undefined,
    });
    const rotated = await stored();
    for (const key of rotated.keys) {
      expect(
        JSON.parse(after.open('signing-key', key.private_key_enc, key.kid)),
      ).toMatchObject({ kty: 'OKP', crv: 'Ed25519' });
    }
    expect(after.open('mfa-secret', String(rotated.mfa), user.id)).toBe(
      'JBSWY3DPEHPK3PXP',
    );
  });
});
