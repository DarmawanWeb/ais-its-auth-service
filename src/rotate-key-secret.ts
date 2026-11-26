import 'reflect-metadata';

import { createLogger, loadConfig } from '@darmawanweb/ais-its-nest';
import {
  createDatabasePool,
  databasePoolSettings,
} from '@darmawanweb/ais-its-nest/db';
import { drizzle } from 'drizzle-orm/node-postgres';

import { logPoolError, runCliTask } from './common/cli.js';
import { configSchema } from './config.js';
import * as schema from './db/schema.js';
import { UsersRepository } from './modules/accounts/users.repository.js';
import { KeyEncryption } from './modules/crypto/key-encryption.service.js';
import { KeySecretRotation } from './modules/crypto/key-secret-rotation.js';
import { SigningKeysRepository } from './modules/keys/signing-keys.repository.js';

// `pnpm rotate:key-secret`: re-seals the signing private keys and MFA secrets
// sealed with KEY_ENCRYPTION_SECRET_PREVIOUS under KEY_ENCRYPTION_SECRET
// (one transaction; idempotent). See KeySecretRotation for the procedure.
const config = loadConfig(configSchema);
const logger = createLogger({
  service: config.SERVICE_NAME,
  level: config.LOG_LEVEL,
  pretty: config.LOG_PRETTY,
});
const pool = createDatabasePool(
  databasePoolSettings(config),
  logPoolError(logger),
);
try {
  // A failed write must not log the new sealed MFA secret it bound.
  await runCliTask(
    logger,
    'Rotating KEY_ENCRYPTION_SECRET failed',
    async () => {
      const db = drizzle(pool, { schema });
      const result = await new KeySecretRotation(
        db,
        new KeyEncryption(config),
        new SigningKeysRepository(db),
        new UsersRepository(db),
      ).run();
      logger.info(
        result,
        `Re-sealed ${result.signingKeys} signing keys and ${result.mfaSecrets} MFA secrets (${result.alreadyCurrent} already current); remove KEY_ENCRYPTION_SECRET_PREVIOUS now`,
      );
    },
  );
} finally {
  await pool.end();
}
