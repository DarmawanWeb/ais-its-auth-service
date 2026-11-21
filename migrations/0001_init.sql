-- 0001_init — initial schema of ais-its-auth-service (docs/PLATFORM_SPEC.md §6, §13.1).
--
-- Runs inside schema "auth" (search_path=auth,public) as the
-- role auth_svc, in one transaction. The infrastructure creates the extensions
-- (timescaledb, postgis, pgcrypto) in "public"; services never CREATE EXTENSION.
-- Migrations are forward-only: once applied anywhere, never edit this file
-- (its checksum is verified at startup) — add 0002_<change>.sql instead.

COMMENT ON SCHEMA auth IS 'auth service — identities, sessions, signing keys, API keys, audit log; owned by auth_svc';

-- Tenants. The platform organization (kind 'platform') is created by the bootstrap.
CREATE TABLE organizations (
  id         uuid PRIMARY KEY,
  name       text NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 200),
  slug       text NOT NULL CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' AND char_length(slug) <= 63),
  kind       text NOT NULL CHECK (kind IN ('shipping_company', 'authority', 'platform', 'research')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT organizations_slug_key UNIQUE (slug)
);

-- Accounts. Invited users have no password until they accept the invitation.
CREATE TABLE users (
  id                uuid PRIMARY KEY,
  email             text NOT NULL CHECK (char_length(email) BETWEEN 3 AND 320 AND email = lower(btrim(email))),
  name              text NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 200),
  password_hash     text CHECK (password_hash LIKE '$argon2%'),
  status            text NOT NULL DEFAULT 'invited' CHECK (status IN ('active', 'invited', 'disabled')),
  mfa_enabled       boolean NOT NULL DEFAULT false,
  -- AES-256-GCM sealed TOTP secret (v1.<iv>.<tag>.<ciphertext>); set while pending or enabled.
  mfa_secret_enc    text,
  last_login_at     timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  is_platform_admin boolean NOT NULL DEFAULT false,
  CONSTRAINT users_active_password_check CHECK (status <> 'active' OR password_hash IS NOT NULL),
  CONSTRAINT users_mfa_secret_check CHECK (NOT mfa_enabled OR mfa_secret_enc IS NOT NULL)
);

CREATE UNIQUE INDEX users_email_key ON users (lower(email));
CREATE INDEX users_created_idx ON users (created_at DESC, id DESC);

-- Organization roles of users ('super_admin' is the platform flag users.is_platform_admin).
CREATE TABLE memberships (
  user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  role       text NOT NULL CHECK (role IN ('org_admin', 'fleet_manager', 'authority', 'viewer')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, org_id)
);

CREATE INDEX memberships_org_role_idx ON memberships (org_id, role);

-- Sessions = refresh token families (spec §8.3); org_id is the active organization.
CREATE TABLE sessions (
  id           uuid PRIMARY KEY,
  user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  org_id       uuid REFERENCES organizations (id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz NOT NULL DEFAULT now(),
  revoked_at   timestamptz,
  ip           inet,
  user_agent   text CHECK (char_length(user_agent) <= 512)
);

CREATE INDEX sessions_user_active_idx ON sessions (user_id, last_used_at DESC) WHERE revoked_at IS NULL;
CREATE INDEX sessions_org_active_idx ON sessions (org_id) WHERE revoked_at IS NULL;

-- Rotating refresh tokens, stored as SHA-256 (hex) of the opaque token.
CREATE TABLE refresh_tokens (
  id         uuid PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
  token_hash text NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  expires_at timestamptz NOT NULL,
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT refresh_tokens_token_hash_key UNIQUE (token_hash),
  CONSTRAINT refresh_tokens_expiry_check CHECK (expires_at > created_at)
);

CREATE INDEX refresh_tokens_session_idx ON refresh_tokens (session_id);
CREATE INDEX refresh_tokens_expires_idx ON refresh_tokens (expires_at);

-- One-time password reset and invitation tokens (SHA-256 hex).
CREATE TABLE password_reset_tokens (
  id         uuid PRIMARY KEY,
  user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  token_hash text NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  purpose    text NOT NULL CHECK (purpose IN ('reset', 'invite')),
  expires_at timestamptz NOT NULL,
  used_at    timestamptz,
  CONSTRAINT password_reset_tokens_token_hash_key UNIQUE (token_hash)
);

CREATE INDEX password_reset_tokens_user_open_idx ON password_reset_tokens (user_id) WHERE used_at IS NULL;
CREATE INDEX password_reset_tokens_expires_idx ON password_reset_tokens (expires_at);

-- Machine clients (spec §8.1): sk_<id>_<secret>; prefix = sk_<id>, key_hash = SHA-256 (hex) of the key.
CREATE TABLE api_keys (
  id           uuid PRIMARY KEY,
  org_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  name         text NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 100),
  prefix       text NOT NULL CHECK (prefix ~ '^sk_[0-9A-Za-z]{10}$'),
  key_hash     text NOT NULL CHECK (key_hash ~ '^[0-9a-f]{64}$'),
  scopes       text[] NOT NULL CHECK (
    cardinality(scopes) BETWEEN 1 AND 16
    AND scopes <@ ARRAY['ais:ingest', 'telemetry:ingest', 'ais:read']::text[]
  ),
  created_by   uuid REFERENCES users (id) ON DELETE SET NULL,
  last_used_at timestamptz,
  revoked_at   timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT api_keys_prefix_key UNIQUE (prefix)
);

CREATE INDEX api_keys_org_created_idx ON api_keys (org_id, created_at DESC, id DESC);

-- JWT signing keys (Ed25519). The private JWK is sealed with AES-256-GCM (v1.<iv>.<tag>.<ciphertext>);
-- kid is the RFC 7638 thumbprint of the public JWK.
CREATE TABLE signing_keys (
  kid             text PRIMARY KEY CHECK (kid ~ '^[A-Za-z0-9_-]{43}$'),
  algorithm       text NOT NULL DEFAULT 'EdDSA' CHECK (algorithm = 'EdDSA'),
  public_jwk      jsonb NOT NULL CHECK (public_jwk ->> 'kty' = 'OKP' AND public_jwk ->> 'crv' = 'Ed25519' AND NOT public_jwk ? 'd'),
  private_key_enc text NOT NULL CHECK (private_key_enc LIKE 'v1.%'),
  status          text NOT NULL CHECK (status IN ('active', 'retiring', 'retired')),
  created_at      timestamptz NOT NULL DEFAULT now(),
  retired_at      timestamptz,
  CONSTRAINT signing_keys_retired_check CHECK ((status = 'retired') = (retired_at IS NOT NULL))
);

-- At most one active key, even with concurrent first boots of several instances.
CREATE UNIQUE INDEX signing_keys_one_active_idx ON signing_keys (status) WHERE status = 'active';
CREATE INDEX signing_keys_created_idx ON signing_keys (created_at DESC);

-- Central audit log: audit.recorded.v1 of every service (consumer auth-audit), id = envelope id.
CREATE TABLE audit_logs (
  id          uuid NOT NULL,
  at          timestamptz NOT NULL,
  source      text NOT NULL,
  actor_type  text NOT NULL CHECK (actor_type IN ('user', 'api_key', 'system')),
  actor_id    uuid,
  org_id      uuid,
  action      text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
  target_type text,
  target_id   text,
  ip          text,
  user_agent  text,
  meta        jsonb NOT NULL DEFAULT '{}'::jsonb,
  recorded_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (at, id)
);

SELECT create_hypertable('audit_logs', by_range('at', INTERVAL '7 days'));

CREATE INDEX audit_logs_org_at_idx ON audit_logs (org_id, at DESC, id DESC);
CREATE INDEX audit_logs_actor_at_idx ON audit_logs (actor_id, at DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX audit_logs_target_at_idx ON audit_logs (target_type, target_id, at DESC) WHERE target_id IS NOT NULL;
CREATE INDEX audit_logs_action_at_idx ON audit_logs (action, at DESC);

-- Rows are immutable: compress chunks older than 7 days (segmented by tenant), keep 2 years.
ALTER TABLE audit_logs SET (
  timescaledb.compress,
  timescaledb.compress_segmentby = 'org_id',
  timescaledb.compress_orderby = 'at DESC, id DESC'
);
SELECT add_compression_policy('audit_logs', INTERVAL '7 days');
SELECT add_retention_policy('audit_logs', INTERVAL '2 years');
