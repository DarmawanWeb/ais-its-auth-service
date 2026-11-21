import { AuditModule } from '@darmawanweb/ais-its-nest/audit';
import { AuthModule } from '@darmawanweb/ais-its-nest/auth';
import { DatabaseModule } from '@darmawanweb/ais-its-nest/db';
import { NatsModule } from '@darmawanweb/ais-its-nest/nats';
import { RedisModule } from '@darmawanweb/ais-its-nest/redis';
import { Module } from '@nestjs/common';

import * as schema from './db/schema.js';
import { ApiKeysModule } from './modules/api-keys/api-keys.module.js';
import { AuditLogsModule } from './modules/audit-logs/audit-logs.module.js';
import { AuthenticationModule } from './modules/authentication/authentication.module.js';
import { BootstrapModule } from './modules/bootstrap/bootstrap.module.js';
import { KeysModule } from './modules/keys/keys.module.js';
import { SigningKeyStore } from './modules/keys/signing-key.store.js';
import { MethodologyModule } from './modules/methodology/methodology.module.js';
import { OrganizationsModule } from './modules/organizations/organizations.module.js';
import { PasswordsModule } from './modules/passwords/passwords.module.js';
import { UsersModule } from './modules/users/users.module.js';

/**
 * Root module. `bootstrapService()` wraps it in the kit's platform root module
 * (configuration, logging, metrics, health, validation, problem details).
 * Nothing connects at construction time: connections, migrations and streams
 * are set up in lifecycle hooks before the HTTP port opens; the signing key
 * and the bootstrap admin are created in `onApplicationBootstrap`, after the
 * migrations.
 */
@Module({
  imports: [
    // pg pool + drizzle (search_path=auth,public); migrations on boot.
    DatabaseModule.forRoot({ schema }),
    // Produced streams: NOTIFY (e-mail requests) and AUDIT (own security events);
    // AUDIT is also consumed (durable consumer auth-audit, the central audit log).
    NatsModule.forRoot({ streams: ['NOTIFY', 'AUDIT'] }),
    // Login throttling, MFA code replay protection.
    RedisModule.forRoot({ keyPrefix: 'auth:' }),
    // Global default-deny guard. Tokens are verified with this service's own
    // keys (no HTTP call to itself); no auth route accepts API keys.
    AuthModule.forRoot({
      apiKeys: false,
      imports: [KeysModule],
      keyResolver: {
        useFactory: (keys: SigningKeyStore) => keys.keyResolver,
        inject: [SigningKeyStore],
      },
    }),
    AuditModule,
    KeysModule,
    AuthenticationModule,
    PasswordsModule,
    UsersModule,
    OrganizationsModule,
    ApiKeysModule,
    AuditLogsModule,
    BootstrapModule,
    MethodologyModule,
  ],
})
export class AppModule {}
