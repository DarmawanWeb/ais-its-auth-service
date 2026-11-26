-- 0004_api_key_expiry_rotation — optional expiry and secret rotation of API keys (0.2.0).
--
-- expires_at: set on creation (POST /api-keys { expiresAt }); introspection
-- treats the key as inactive from then on, like a revoked one.
--
-- Rotation (POST /api-keys/:id/rotate) keeps the key's id and public prefix
-- sk_<id> (telemetry binds devices to the key id) and replaces the secret:
-- key_hash becomes the hash of the new key, and the hash of the replaced key
-- stays valid until previous_key_expires_at (the grace period), so devices
-- can switch without downtime. Rotating again during a grace period replaces
-- the previous hash: only the most recent former secret stays valid.

ALTER TABLE api_keys ADD COLUMN expires_at timestamptz;
ALTER TABLE api_keys ADD COLUMN rotated_at timestamptz;
ALTER TABLE api_keys ADD COLUMN previous_key_hash text;
ALTER TABLE api_keys ADD COLUMN previous_key_expires_at timestamptz;

ALTER TABLE api_keys ADD CONSTRAINT api_keys_previous_key_check
  CHECK ((previous_key_hash IS NULL) = (previous_key_expires_at IS NULL));
