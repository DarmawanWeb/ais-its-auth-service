import {
  type AppConfig,
  defineConfig,
  envBoolean,
  envInteger,
  ServiceNameSchema,
  SqlIdentifierSchema,
} from '@darmawanweb/ais-its-nest';
import * as z from 'zod';

import { SERVICE } from './service.js';

/**
 * Development default of `KEY_ENCRYPTION_SECRET`; refused in production like
 * the kit refuses the development `INTERNAL_TOKEN`.
 */
export const DEV_KEY_ENCRYPTION_SECRET =
  'dev-key-encryption-secret-change-me-0123456789';

/** Development default of `BOOTSTRAP_ADMIN_PASSWORD` (spec §13.1). */
export const DEV_BOOTSTRAP_ADMIN_PASSWORD = 'ChangeMe123!';

/** Development default of `SEED_DEMO_PASSWORD`; `pnpm seed:demo` refuses it in production. */
export const DEV_SEED_DEMO_PASSWORD = 'DemoPass2026';

/** Minimum length of `KEY_ENCRYPTION_SECRET` (spec §13.1: 32+ characters). */
export const MIN_KEY_ENCRYPTION_SECRET_LENGTH = 32;

/**
 * Environment of the service: the platform base variables (spec §4) with this
 * service's defaults, plus the auth variables of spec §13.1. Add a variable
 * here and to `.env.example`; `loadConfig()` refuses to start on invalid
 * values and prints every problem.
 */
export const configSchema = defineConfig({
  SERVICE_NAME: ServiceNameSchema.default(SERVICE.name),
  SERVICE_VERSION: z.string().min(1).default(SERVICE.version),
  PORT: envInteger(0, 65_535).default(SERVICE.port),
  DATABASE_SCHEMA: SqlIdentifierSchema.default(SERVICE.schema),
  /** Secret the AES-256-GCM keys of signing keys and MFA secrets are derived from (HKDF-SHA256). */
  KEY_ENCRYPTION_SECRET: z
    .string()
    .min(MIN_KEY_ENCRYPTION_SECRET_LENGTH)
    .default(DEV_KEY_ENCRYPTION_SECRET),
  /**
   * The previous `KEY_ENCRYPTION_SECRET` while rotating it: values it sealed
   * still open, and `pnpm rotate:key-secret` re-seals them with the current
   * secret. Unset it once the rotation ran.
   */
  KEY_ENCRYPTION_SECRET_PREVIOUS: z
    .string()
    .min(MIN_KEY_ENCRYPTION_SECRET_LENGTH)
    .optional(),
  /** Access token lifetime, seconds (spec §8.2: 15 min). */
  ACCESS_TOKEN_TTL: envInteger(60, 3_600).default(900),
  /** Refresh token (session inactivity) lifetime, days (spec §8.3: 30 d). */
  REFRESH_TOKEN_TTL_DAYS: envInteger(1, 365).default(30),
  /**
   * `Secure` attribute of the refresh cookie. Unset: `true` in production,
   * `false` otherwise (plain-HTTP development, spec §8.3).
   */
  COOKIE_SECURE: envBoolean().optional(),
  /** Super admin created on an empty database (spec §13.1). */
  BOOTSTRAP_ADMIN_EMAIL: z.email().default('admin@ais-its.local'),
  BOOTSTRAP_ADMIN_PASSWORD: z
    .string()
    .min(1)
    .default(DEV_BOOTSTRAP_ADMIN_PASSWORD),
  /** Validity of password reset links, minutes (spec §13.1: 30 min). */
  PASSWORD_RESET_TTL_MIN: envInteger(5, 1_440).default(30),
  /** Validity of invitation links, hours. */
  INVITE_TTL_HOURS: envInteger(1, 720).default(168),
  /** Locale of transactional e-mails when the request names none. */
  EMAIL_DEFAULT_LOCALE: z.enum(['id', 'en']).default('id'),
  /** Password of the users created by `pnpm seed:demo`. */
  SEED_DEMO_PASSWORD: z.string().min(10).default(DEV_SEED_DEMO_PASSWORD),
  /**
   * `pnpm seed:demo` refuses to run with `NODE_ENV=production` unless this
   * is `true` and `SEED_DEMO_PASSWORD` is not the documented default.
   */
  SEED_DEMO_ALLOW_PRODUCTION: envBoolean().default(false),
}).superRefine((config, context) => {
  if (
    config.NODE_ENV === 'production' &&
    config.KEY_ENCRYPTION_SECRET === DEV_KEY_ENCRYPTION_SECRET
  ) {
    context.addIssue({
      code: 'custom',
      path: ['KEY_ENCRYPTION_SECRET'],
      message:
        'Must be a secret of its own in production (not the development default)',
    });
  }
  if (config.KEY_ENCRYPTION_SECRET_PREVIOUS === config.KEY_ENCRYPTION_SECRET) {
    context.addIssue({
      code: 'custom',
      path: ['KEY_ENCRYPTION_SECRET_PREVIOUS'],
      message: 'Must differ from KEY_ENCRYPTION_SECRET (it is the old secret)',
    });
  }
});

/** Validated configuration; inject it with `@InjectConfig() config: Config`. */
export type Config = AppConfig<typeof configSchema>;

/** The `Secure` flag of the refresh cookie (see `COOKIE_SECURE`). */
export function cookieSecure(
  config: Pick<Config, 'COOKIE_SECURE' | 'NODE_ENV'>,
): boolean {
  return config.COOKIE_SECURE ?? config.NODE_ENV === 'production';
}
