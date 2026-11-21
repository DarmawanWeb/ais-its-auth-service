// Drizzle definitions of the "auth" schema (docs/PLATFORM_SPEC.md §6, §13.1).
// The SQL files in migrations/ create the tables; these definitions MUST
// mirror them and only type the queries.
import { sql } from 'drizzle-orm';
import * as pg from 'drizzle-orm/pg-core';

/** The service's PostgreSQL schema, owned by the role `auth_svc`. */
export const serviceSchema = pg.pgSchema('auth');

const createdAt = () =>
  pg.timestamp('created_at', { withTimezone: true }).notNull().defaultNow();
const updatedAt = () =>
  pg.timestamp('updated_at', { withTimezone: true }).notNull().defaultNow();
const timestamp = (name: string) => pg.timestamp(name, { withTimezone: true });

/** Tenants (`0001_init.sql`). */
export const organizations = serviceSchema.table(
  'organizations',
  {
    id: pg.uuid('id').primaryKey(),
    name: pg.text('name').notNull(),
    slug: pg.text('slug').notNull(),
    kind: pg
      .text('kind', {
        enum: ['shipping_company', 'authority', 'platform', 'research'],
      })
      .notNull(),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (table) => [pg.unique('organizations_slug_key').on(table.slug)],
);

/** Accounts; `email` is unique on `lower(email)`. */
export const users = serviceSchema.table(
  'users',
  {
    id: pg.uuid('id').primaryKey(),
    email: pg.text('email').notNull(),
    name: pg.text('name').notNull(),
    passwordHash: pg.text('password_hash'),
    status: pg
      .text('status', { enum: ['active', 'invited', 'disabled'] })
      .notNull()
      .default('invited'),
    mfaEnabled: pg.boolean('mfa_enabled').notNull().default(false),
    mfaSecretEnc: pg.text('mfa_secret_enc'),
    lastLoginAt: timestamp('last_login_at'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
    isPlatformAdmin: pg.boolean('is_platform_admin').notNull().default(false),
  },
  (table) => [
    pg.uniqueIndex('users_email_key').on(sql`lower(${table.email})`),
    pg.index('users_created_idx').on(table.createdAt.desc(), table.id.desc()),
  ],
);

/** Organization roles of users. */
export const memberships = serviceSchema.table(
  'memberships',
  {
    userId: pg
      .uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    orgId: pg
      .uuid('org_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    role: pg
      .text('role', {
        enum: ['org_admin', 'fleet_manager', 'authority', 'viewer'],
      })
      .notNull(),
    createdAt: createdAt(),
  },
  (table) => [
    pg.primaryKey({ columns: [table.userId, table.orgId] }),
    pg.index('memberships_org_role_idx').on(table.orgId, table.role),
  ],
);

/** Sessions (refresh token families); `orgId` is the active organization. */
export const sessions = serviceSchema.table(
  'sessions',
  {
    id: pg.uuid('id').primaryKey(),
    userId: pg
      .uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    orgId: pg
      .uuid('org_id')
      .references(() => organizations.id, { onDelete: 'set null' }),
    createdAt: createdAt(),
    lastUsedAt: timestamp('last_used_at').notNull().defaultNow(),
    revokedAt: timestamp('revoked_at'),
    ip: pg.inet('ip'),
    userAgent: pg.text('user_agent'),
  },
  (table) => [
    pg
      .index('sessions_user_active_idx')
      .on(table.userId, table.lastUsedAt.desc())
      .where(sql`${table.revokedAt} IS NULL`),
    pg
      .index('sessions_org_active_idx')
      .on(table.orgId)
      .where(sql`${table.revokedAt} IS NULL`),
  ],
);

/** Rotating refresh tokens (SHA-256 hex of the opaque token). */
export const refreshTokens = serviceSchema.table(
  'refresh_tokens',
  {
    id: pg.uuid('id').primaryKey(),
    sessionId: pg
      .uuid('session_id')
      .notNull()
      .references(() => sessions.id, { onDelete: 'cascade' }),
    tokenHash: pg.text('token_hash').notNull(),
    expiresAt: timestamp('expires_at').notNull(),
    usedAt: timestamp('used_at'),
    createdAt: createdAt(),
  },
  (table) => [
    pg.unique('refresh_tokens_token_hash_key').on(table.tokenHash),
    pg.index('refresh_tokens_session_idx').on(table.sessionId),
    pg.index('refresh_tokens_expires_idx').on(table.expiresAt),
  ],
);

/** One-time password reset and invitation tokens. */
export const passwordResetTokens = serviceSchema.table(
  'password_reset_tokens',
  {
    id: pg.uuid('id').primaryKey(),
    userId: pg
      .uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    tokenHash: pg.text('token_hash').notNull(),
    purpose: pg.text('purpose', { enum: ['reset', 'invite'] }).notNull(),
    expiresAt: timestamp('expires_at').notNull(),
    usedAt: timestamp('used_at'),
  },
  (table) => [
    pg.unique('password_reset_tokens_token_hash_key').on(table.tokenHash),
    pg
      .index('password_reset_tokens_user_open_idx')
      .on(table.userId)
      .where(sql`${table.usedAt} IS NULL`),
    pg.index('password_reset_tokens_expires_idx').on(table.expiresAt),
  ],
);

/** API keys of machine clients (prefix `sk_<id>`, SHA-256 hex of the key). */
export const apiKeys = serviceSchema.table(
  'api_keys',
  {
    id: pg.uuid('id').primaryKey(),
    orgId: pg
      .uuid('org_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    name: pg.text('name').notNull(),
    prefix: pg.text('prefix').notNull(),
    keyHash: pg.text('key_hash').notNull(),
    scopes: pg.text('scopes').array().notNull(),
    createdBy: pg
      .uuid('created_by')
      .references(() => users.id, { onDelete: 'set null' }),
    lastUsedAt: timestamp('last_used_at'),
    revokedAt: timestamp('revoked_at'),
    createdAt: createdAt(),
  },
  (table) => [
    pg.unique('api_keys_prefix_key').on(table.prefix),
    pg
      .index('api_keys_org_created_idx')
      .on(table.orgId, table.createdAt.desc(), table.id.desc()),
  ],
);

/** Public JWK of a signing key (Ed25519, no private member). */
export interface PublicSigningJwk {
  readonly kty: 'OKP';
  readonly crv: 'Ed25519';
  readonly x: string;
}

/** JWT signing keys; the private JWK is sealed with AES-256-GCM. */
export const signingKeys = serviceSchema.table(
  'signing_keys',
  {
    kid: pg.text('kid').primaryKey(),
    algorithm: pg
      .text('algorithm', { enum: ['EdDSA'] })
      .notNull()
      .default('EdDSA'),
    publicJwk: pg.jsonb('public_jwk').$type<PublicSigningJwk>().notNull(),
    privateKeyEnc: pg.text('private_key_enc').notNull(),
    status: pg
      .text('status', { enum: ['active', 'retiring', 'retired'] })
      .notNull(),
    createdAt: createdAt(),
    retiredAt: timestamp('retired_at'),
  },
  (table) => [
    pg
      .uniqueIndex('signing_keys_one_active_idx')
      .on(table.status)
      .where(sql`${table.status} = 'active'`),
    pg.index('signing_keys_created_idx').on(table.createdAt.desc()),
  ],
);

/** Central audit log (hypertable on `at`, compressed after 7 d, kept 2 years). */
export const auditLogs = serviceSchema.table(
  'audit_logs',
  {
    id: pg.uuid('id').notNull(),
    at: timestamp('at').notNull(),
    source: pg.text('source').notNull(),
    actorType: pg
      .text('actor_type', { enum: ['user', 'api_key', 'system'] })
      .notNull(),
    actorId: pg.uuid('actor_id'),
    orgId: pg.uuid('org_id'),
    action: pg.text('action').notNull(),
    targetType: pg.text('target_type'),
    targetId: pg.text('target_id'),
    ip: pg.text('ip'),
    userAgent: pg.text('user_agent'),
    meta: pg
      .jsonb('meta')
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
    recordedAt: timestamp('recorded_at').notNull().defaultNow(),
  },
  (table) => [
    pg.primaryKey({ columns: [table.at, table.id] }),
    pg
      .index('audit_logs_org_at_idx')
      .on(table.orgId, table.at.desc(), table.id.desc()),
    pg
      .index('audit_logs_actor_at_idx')
      .on(table.actorId, table.at.desc())
      .where(sql`${table.actorId} IS NOT NULL`),
    pg
      .index('audit_logs_target_at_idx')
      .on(table.targetType, table.targetId, table.at.desc())
      .where(sql`${table.targetId} IS NOT NULL`),
    pg.index('audit_logs_action_at_idx').on(table.action, table.at.desc()),
  ],
);
