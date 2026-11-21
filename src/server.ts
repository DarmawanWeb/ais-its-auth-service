import 'reflect-metadata';

import { bootstrapService, loadConfig } from '@darmawanweb/ais-its-nest';

import { AppModule } from './app.module.js';
import { configSchema } from './config.js';
import { OPENAPI } from './openapi.options.js';

// Connect, migrate and ensure streams (onModuleInit) → signing key, bootstrap
// admin, consumers (onApplicationBootstrap) → listen on HOST:PORT. SIGTERM
// turns readiness to 503, drains consumers and NATS, then closes the pool.
// Cookies: the refresh token cookie aisits_rt (spec §8.3).
await bootstrapService({
  appModule: AppModule,
  config: loadConfig(configSchema),
  openapi: OPENAPI,
  cookies: true,
});
