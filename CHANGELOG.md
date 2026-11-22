# Changelog

All notable changes to `ais-its-auth-service` are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the service adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- `ais:ingest` API keys (the AIS feed shared by every tenant) can only be granted by super admins;
  `org_admin`s get `403 SCOPE_NOT_GRANTABLE` and grant `telemetry:ingest` and `ais:read` only.
- `POST /organizations/:id/members` no longer attaches existing accounts of any tenant: it records
  an invitation (new table `membership_invitations`, migration `0002`) and e-mails the link; the
  membership is written when the invitee accepts it with `POST /auth/password/reset`. The answer,
  the new `GET /organizations/:id/invitations` and the audit record (target
  `membership_invitation`) are identical for new and existing addresses and show only what the
  admin typed. New `DELETE /organizations/:id/invitations/:invitationId`; kind changes also check
  the roles of pending invitations.
- Password resets and invitation acceptances lock the user row and write the password only
  `WHERE status <> 'disabled'`; disabling an account locks the row too, so a reset racing a
  disable can no longer re-enable the account. Password changes refuse disabled accounts the same
  way, and the login rehash is a compare-and-set on the old hash.
- Reset and invitation links are checked before the argon2id hash is computed, and failed
  attempts are throttled (10 / 15 min per IP), so anonymous garbage no longer slows down sign-in.
- Failed writes of `users` rethrow a `SanitizedDatabaseError` without SQL parameters or driver
  `detail`: password hashes and sealed MFA secrets no longer reach error logs or responses.
- `pnpm seed:demo` refuses `NODE_ENV=production` unless `SEED_DEMO_ALLOW_PRODUCTION=true` and a
  non-default `SEED_DEMO_PASSWORD` are set, and audits everything it creates.

### Fixed

- A malformed client address from a trusted proxy (`X-Forwarded-For: foo`, `1.2.3.4:5678`,
  `[2001:db8::1]`) no longer makes login and MFA verification fail with `500`: client IPs are
  normalized (ports, brackets, zone ids stripped; anything else `null`) for sessions and
  throttle keys.
- `POST /auth/refresh` clears the cookie only for refusals that end the session
  (`INVALID_REFRESH_TOKEN`, `REFRESH_TOKEN_REUSED`, `ACCOUNT_DISABLED`), and the access token is
  signed before the rotation commits, so a transient failure (database outage, no signing key)
  neither logs the user out nor turns the retry into a reuse detection.
- The audit consumer stores events with characters PostgreSQL refuses (U+0000, lone surrogates)
  or absurdly nested `meta` instead of retrying them until they reach the DLQ.
- `openapi.json` no longer references the undeclared security scheme `aisits_rt`; the cookie is
  described on the refresh and logout operations.

- The Docker image no longer installs the kit's test-only optional peers (`testcontainers`,
  `@nestjs/testing` and their tree: dockerode, ssh2, archiver, …): `.pnpmfile.cjs` keeps them out
  of the production graph (`node_modules` 233 → 200 MB, image 521 → 481 MB).

### Added

- Rotation of `KEY_ENCRYPTION_SECRET`: `KEY_ENCRYPTION_SECRET_PREVIOUS` (values it sealed still
  open) and `pnpm rotate:key-secret` (re-seals signing keys and MFA secrets in one transaction).

## [0.1.0] - 2026-11-21

### Added

- Identity model of spec §13.1 (schema `auth`): `organizations`, `users` (unique on
  `lower(email)`), `memberships`, `sessions`, `refresh_tokens`, `password_reset_tokens`,
  `api_keys`, `signing_keys` and the `audit_logs` hypertable (compressed after 7 days, kept 2 years).
- Sign-in with argon2id passwords (m = 19 456 KiB, t = 2, p = 1, transparent rehash), constant-time
  answers for unknown accounts, `INVALID_CREDENTIALS` for every credential failure, and Valkey
  throttles (5 failures / 15 min per e-mail, 20 / 15 min per IP, `429 RATE_LIMITED` with
  `Retry-After`).
- Sessions with rotating opaque refresh tokens in the `aisits_rt` cookie (`HttpOnly`, `Secure`
  configurable, `SameSite=Strict`, `Path=/api/v2/auth`, 30 days), reuse detection revoking the
  whole family, Origin checks against CSRF on refresh and logout, session list/revocation and
  `POST /auth/switch-org`.
- EdDSA (Ed25519) access tokens (spec §8.2) signed with keys generated on first boot, sealed with
  AES-256-GCM under an HKDF-SHA256 key from `KEY_ENCRYPTION_SECRET`, kid = RFC 7638 thumbprint;
  `GET /.well-known/jwks.json` (active + retiring keys), `POST /auth/keys/rotate` (super admins) and
  a retirement job; the service verifies its own tokens with a local key resolver.
- TOTP MFA (setup, enable, disable, login second step with a 5-minute single-use MFA token),
  secrets sealed at rest, single-use codes.
- Password reset (`202` always, link in the URL fragment, 30 minutes, single use, revokes every
  session), password change (revokes the other sessions) and invitations, requested from the
  notification service through `notify.email.requested.v1` on the `NOTIFY` work queue.
- Organizations and members administration with tenancy (`org_admin` within the active
  organization, super admins everywhere), last-admin protection, `authority` grantable only in
  authority organizations (also enforced on kind changes), removal revoking the member's
  sessions; `/me`; user directory and account status for super admins.
- API keys (`sk_<id>_<secret>`, SHA-256 at rest, shown once) per organization and
  `POST /internal/api-keys/introspect` (`X-Internal-Token`, `last_used_at` at most once a minute).
- Traefik `forwardAuth` endpoint `GET /auth/verify` (`X-User-Id`, `X-Org-Id`, `X-Roles`).
- Central audit log: durable consumer `auth-audit` persisting `audit.recorded.v1` of every service
  idempotently; own security events recorded through the kit `AuditService`;
  `GET /audit-logs` with cursor pagination and tenancy.
- Bootstrap of the platform organization and super admin on an empty database, hourly
  housekeeping of ended sessions and tokens, and `pnpm seed:demo` (demo shipping company and
  authority, one user per role, two API keys).
- Metrics `aisits_auth_logins_total`, `aisits_auth_token_refreshes_total`,
  `aisits_auth_emails_requested_total`, `aisits_auth_api_key_introspections_total`,
  `aisits_auth_audit_logs_persisted_total`; unit and integration tests; OpenAPI document; Docker
  image.

[Unreleased]: https://github.com/DarmawanWeb/ais-its-auth-service/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DarmawanWeb/ais-its-auth-service/releases/tag/v0.1.0
