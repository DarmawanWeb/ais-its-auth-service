-- 0002_membership_invitations — invitations to join an organization (docs/PLATFORM_SPEC.md §13.1).
--
-- POST /organizations/:id/members no longer attaches an account to the
-- organization: it records an invitation that the invitee accepts with the
-- e-mailed link (POST /auth/password/reset). An org_admin can therefore
-- neither add accounts of other tenants without their consent nor learn
-- whether an address has an account: until the invitee accepts, the
-- organization only sees what its admin typed (address, name, role).
-- The membership row is written when the invitation is accepted.

CREATE TABLE membership_invitations (
  id         uuid PRIMARY KEY,
  org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  -- The invited account: an existing one, or a new 'invited' account created with the invitation.
  user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  role       text NOT NULL CHECK (role IN ('org_admin', 'fleet_manager', 'authority', 'viewer')),
  -- Display name typed by the inviter; shown to the organization instead of the account's own data.
  name       text NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 200),
  invited_by uuid REFERENCES users (id) ON DELETE SET NULL,
  -- SHA-256 (hex) of the opaque link token; replaced when the invitation is sent again.
  token_hash text NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT membership_invitations_token_hash_key UNIQUE (token_hash),
  CONSTRAINT membership_invitations_org_user_key UNIQUE (org_id, user_id),
  CONSTRAINT membership_invitations_expiry_check CHECK (expires_at > created_at)
);

CREATE INDEX membership_invitations_org_created_idx ON membership_invitations (org_id, created_at DESC, id DESC);
CREATE INDEX membership_invitations_user_idx ON membership_invitations (user_id);
CREATE INDEX membership_invitations_expires_idx ON membership_invitations (expires_at);
