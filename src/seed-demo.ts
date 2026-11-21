import 'reflect-metadata';

import { createLogger, loadConfig } from '@darmawanweb/ais-its-nest';
import {
  createDatabasePool,
  databasePoolSettings,
  runMigrations,
} from '@darmawanweb/ais-its-nest/db';
import { drizzle } from 'drizzle-orm/node-postgres';

import { configSchema } from './config.js';
import * as schema from './db/schema.js';
import { MembershipsRepository } from './modules/accounts/memberships.repository.js';
import { OrganizationsRepository } from './modules/accounts/organizations.repository.js';
import { UsersRepository } from './modules/accounts/users.repository.js';
import { ApiKeysRepository } from './modules/api-keys/api-keys.repository.js';
import { DemoSeeder, formatDemoSeed } from './modules/bootstrap/demo-seeder.js';
import { PasswordHasher } from './modules/crypto/password-hasher.service.js';

// `pnpm seed:demo` (spec §13.1): applies the migrations, then creates the demo
// organizations, one user per role and two API keys, and prints them.
const config = loadConfig(configSchema);
const logger = createLogger({
  service: config.SERVICE_NAME,
  level: config.LOG_LEVEL,
  pretty: config.LOG_PRETTY,
});
const pool = createDatabasePool(databasePoolSettings(config), (error) => {
  logger.error({ err: error }, 'Database pool error');
});
try {
  await runMigrations({
    pool,
    schema: config.DATABASE_SCHEMA,
    dir: new URL('../migrations', import.meta.url).pathname,
    logger: {
      info: (message) => {
        logger.info(message);
      },
      warn: (message) => {
        logger.warn(message);
      },
    },
  });
  const db = drizzle(pool, { schema });
  const seeder = new DemoSeeder(
    db,
    new OrganizationsRepository(db),
    new UsersRepository(db),
    new MembershipsRepository(db),
    new ApiKeysRepository(db),
    new PasswordHasher(),
  );
  process.stdout.write(
    formatDemoSeed(await seeder.run(config.SEED_DEMO_PASSWORD)),
  );
} finally {
  await pool.end();
}
