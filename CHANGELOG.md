# Changelog

All notable changes to `ais-its-auth-service` are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the service adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-23

Upgrade to `@darmawanweb/ais-its-contracts` 0.4.0 and `@darmawanweb/ais-its-nest` 0.3.0 (the
local workarounds for the platform issues this service reported are gone), the backend gaps the
web app reported for the admin pages, and the security hardening made after 0.1.0. Migrations
`0003` and `0004` only add nullable columns and a `CHECK`; 0.1.0 and 0.2.0 replicas can run side
by side during a rolling update, but only 0.2.0 serves the new routes, captures audit names and
enforces API key expiry and rotation grace periods (see the README, Operations).

### Added

- Audit records carry `actorName`, `actorEmail`, `orgName` and `targetLabel`, stored by the
  `auth-audit` consumer as they are when the record arrives (migration `0003`): the actor's name
  and e-mail or the API key's name, the organization's name, and this service's targets from its
  tables (users `Name <e-mail>`, organizations, API keys `Name (sk_<id>)`, invitations by address)
  or other services' targets from the producer's `meta.targetLabel` / `meta.name`. Renames and
  deletions no longer change history; rows of 0.1.0 show the current names. `pnpm seed:demo`
  stores the names too.
- `GET /api/v2/audit-logs` filters `actorEmail` (case-insensitive) and `actionPrefix` (e.g.
  `membership.`, matched literally).
- `GET /api/v2/audit-logs/actions?actionPrefix&orgId&from&to` (`audit:read`, same scope): the
  distinct actions of the range with `count` and `lastAt` (default 30 days, at most 366, at most
  500 actions), for the filter suggestions.
- `GET /api/v2/audit-logs.csv` (`audit:read`): the records of the listing's filters as one streamed
  RFC 4180 file (`Content-Disposition: attachment; filename="audit-logs-<orgId|all>-<from>_<to>.csv"`,
  exposed cross-origin; `Cache-Control: no-store`), read in keyset batches of 1 000; cells that a
  spreadsheet would run as formulas get a leading apostrophe (OWASP CSV injection); errors before
  the first byte are problem details, a failure mid-transfer aborts the connection.
- `POST /api/v2/organizations/:id/invitations/:invitationId/resend` (`user:manage`, optional body
  `{ locale }`) → `200 SentInvitationDto`: a new link replaces the old one (which stops working),
  role and name stay, the role is checked again against the organization's kind; at most 3 resends
  per invitation and hour (`429 RATE_LIMITED`). Audited as `membership.invite.resend`.
- `InvitationDto.invitedByName` (current name of the inviting admin).
- `GET /api/v2/organizations` rows carry `memberCount` and `apiKeyCount` (keys that work now), and
  `GET /api/v2/organizations/stats?search` (`org:manage`) answers
  `{ total, byKind: { shipping_company, authority, platform, research } }` over every page.
- `GET /api/v2/users` accepts `ids=a,b,c` (batch lookup of up to 100 ids) and `orgId` (members of
  an organization).
- API keys may expire: `POST /api/v2/api-keys { expiresAt }` (in the future, else
  `400 VALIDATION_FAILED`); introspection treats the key as inactive from then on. `ApiKeyDto`
  gains `expiresAt`, `status` (`active` | `expired` | `revoked`), `rotatedAt` and
  `previousKeyExpiresAt` (migration `0004`).
- `POST /api/v2/api-keys/:id/rotate { gracePeriodMin? }` (`api_key:manage`): a new secret,
  returned once, for the same key id and prefix (telemetry binds devices to the key id); the
  replaced secret keeps working for the grace period (default 24 h, at most 7 days, 0 = at once).
  An `org_admin` cannot rotate a key whose scopes it could not grant (`403 SCOPE_NOT_GRANTABLE`,
  e.g. `ais:ingest`); revoked or expired keys answer `409 API_KEY_INACTIVE`. Audited as
  `api_key.rotate`; `aisits_auth_api_key_introspections_total{outcome="active_previous"}` counts
  uses of a replaced secret. Housekeeping forgets replaced secrets after their grace period.
- Rotation of `KEY_ENCRYPTION_SECRET`: `KEY_ENCRYPTION_SECRET_PREVIOUS` (values it sealed still
  open) and `pnpm rotate:key-secret` (re-seals signing keys and MFA secrets in one transaction).

### Changed

- `@darmawanweb/ais-its-contracts` ^0.4.0 and `@darmawanweb/ais-its-nest` ^0.3.0. Metric fields
  use the kit's `Counter` type (`src/common/metrics.ts` removed); API key hashes come from contracts
  `hashApiKey` (same SHA-256 hex, now asynchronous).
- `openapi.json` declares the refresh cookie as the security scheme `refreshCookie`
  (`apiKey` in the cookie `aisits_rt`, kit `REFRESH_COOKIE_SECURITY_SCHEME`) on refresh and
  logout, the page maximum of 1 000 000, `uuid` path parameters and the new routes.
- Malformed path ids answer `400 VALIDATION_FAILED` with the parameter as `field` (kit
  `@UuidParam()` instead of `ParseUUIDPipe`).
- `PATCH /api/v2/organizations/:id` refuses `null` for `name`, `slug` and `kind`
  (`400 VALIDATION_FAILED`) instead of failing on the `NOT NULL` column.
- The `auth-audit` consumer dead-letters a record the database can never store (SQLSTATE classes
  `22`, `23`, `54`, e.g. a target id above the btree index limit) at its first delivery with
  `DeadLetterError` (`dlq.AUDIT.auth-audit`) instead of retrying it until `maxDeliver`;
  `aisits_auth_audit_logs_persisted_total` gains `outcome="dead_letter"`.
- Migrations are resolved from the package (`MIGRATIONS_DIR`) for the service, `pnpm migrate` and
  `pnpm seed:demo`, whatever the working directory.
- `TRUSTED_PROXIES`: production guidance (the gateway only) in `.env.example` and the README; the
  kit warns at boot while production runs with the default.

### Removed

- Local workarounds now provided by the kit: `src/db/errors.ts` (`SanitizedDatabaseError`,
  `withoutQueryValues` around every `users` write, the local `isUniqueViolation`; the kit sanitizes
  logs, problem details and DLQ headers and provides `isUniqueViolation`), `src/domain/client-ip.ts`
  (`normalizeClientIp`; the kit's `clientIp` has the same case table), the `REFRESH_COOKIE_DESCRIPTION`
  prose in place of a security scheme, and the `@darmawanweb/ais-its-nest` entry of `.pnpmfile.cjs`
  (the kit no longer declares test peers; the hook now strips `@nestjs/terminus`' optional gRPC
  peers, as the template does).

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
- Failed database writes no longer put password hashes, sealed MFA secrets or e-mail addresses
  into logs or responses (the kit's sanitization; regression tests for a failed password write
  and a duplicate e-mail). Failures the service logs itself — background work (the
  forgot-password lookup), the periodic jobs (housekeeping, key retirement) and the signing key
  reload — used drizzle's message, which lists every bound value (e.g. the looked-up e-mail
  address); they are logged with `sanitizeError` now.
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
- `openapi.json` no longer references an undeclared security scheme (`aisits_rt`).
- The Docker image no longer installs test-only packages (`testcontainers`, `@nestjs/testing`
  and their tree: dockerode, ssh2, archiver, …) nor terminus' optional gRPC peers.

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
