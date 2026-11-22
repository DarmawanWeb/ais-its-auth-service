import { ConfigValidationError, loadConfig } from '@darmawanweb/ais-its-nest';
import { describe, expect, it } from 'vitest';

import { configSchema } from './config.js';
import { SERVICE } from './service.js';

/** Loads the configuration from `env` only (no .env file, no process.env). */
function load(env: Record<string, string> = {}) {
  return loadConfig(configSchema, {
    env: { LOG_LEVEL: 'silent', ...env },
    envFile: false,
    output: null,
  });
}

describe('configSchema', () => {
  it('applies the service defaults (spec §3, §4, §6)', () => {
    const config = load();

    expect(config).toMatchObject({
      NODE_ENV: 'development',
      SERVICE_NAME: SERVICE.name,
      SERVICE_VERSION: SERVICE.version,
      PORT: SERVICE.port,
      DATABASE_SCHEMA: SERVICE.schema,
      DATABASE_URL: `postgres://${SERVICE.schema}_svc:${SERVICE.schema}_svc@localhost:5432/aisits`,
      NATS_URL: ['nats://localhost:4222'],
    });
  });

  it('reads overrides from the environment', () => {
    expect(
      load({ PORT: '4000', NATS_URL: 'nats://a:4222,nats://b:4222' }),
    ).toMatchObject({
      PORT: 4000,
      NATS_URL: ['nats://a:4222', 'nats://b:4222'],
    });
  });

  it('refuses invalid values', () => {
    expect(() => load({ PORT: 'eighty' })).toThrow(ConfigValidationError);
  });

  it('refuses the development secrets in production', () => {
    expect(() =>
      load({
        NODE_ENV: 'production',
        DATABASE_URL: 'postgres://u:p@db:5432/aisits',
      }),
    ).toThrow(ConfigValidationError);
  });

  it('accepts a previous key secret for rotations, but not the current one again', () => {
    const current = 'current-key-encryption-secret-0123456789';
    expect(
      load({
        KEY_ENCRYPTION_SECRET: current,
        KEY_ENCRYPTION_SECRET_PREVIOUS: 'previous-key-encryption-secret-012345',
      }),
    ).toMatchObject({
      KEY_ENCRYPTION_SECRET_PREVIOUS: 'previous-key-encryption-secret-012345',
    });
    expect(load().KEY_ENCRYPTION_SECRET_PREVIOUS).toBeUndefined();
    expect(() =>
      load({
        KEY_ENCRYPTION_SECRET: current,
        KEY_ENCRYPTION_SECRET_PREVIOUS: current,
      }),
    ).toThrow(ConfigValidationError);
  });

  it('keeps the demo seed out of production unless explicitly allowed', () => {
    expect(load().SEED_DEMO_ALLOW_PRODUCTION).toBe(false);
    expect(
      load({ SEED_DEMO_ALLOW_PRODUCTION: 'true' }).SEED_DEMO_ALLOW_PRODUCTION,
    ).toBe(true);
  });
});
