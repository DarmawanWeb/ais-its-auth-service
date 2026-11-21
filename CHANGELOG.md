# Changelog

All notable changes to `ais-its-auth-service` are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the service adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
