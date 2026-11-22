# ais-its-auth-service

Identity, organizations, memberships and roles, sessions, JWT signing keys and JWKS, API keys, MFA
and the central audit log of **AIS Maritime Intelligence** v2.

Service `auth` (port **3001**, PostgreSQL schema `auth`): NestJS 12 + Fastify 5 on the platform kit
[`@darmawanweb/ais-its-nest`](https://github.com/DarmawanWeb/ais-its-contracts/tree/main/packages/nest)
and the contracts [`@darmawanweb/ais-its-contracts`](https://github.com/DarmawanWeb/ais-its-contracts/tree/main/packages/contracts),
TimescaleDB, NATS JetStream and Valkey. The normative engineering spec is
[`docs/PLATFORM_SPEC.md`](../../docs/PLATFORM_SPEC.md) (§5, §8, §13.1) of the central repository
[`ais-its-platform`](https://github.com/DarmawanWeb/ais-its-platform).

## Purpose and responsibilities

The auth service is the platform's identity provider and its security record keeper:

- **Accounts and tenants** — users (`active`, `invited`, `disabled`), organizations (tenants of kind
  `shipping_company`, `authority`, `platform`, `research`), memberships with one role per
  organization (`org_admin`, `fleet_manager`, `authority`, `viewer`) and the platform role
  `super_admin` (`users.is_platform_admin`). Accounts join an organization only by accepting an
  invitation, so no admin can attach — or learn anything about — accounts of other tenants.
- **Sign-in** — e-mail + password (argon2id), optional TOTP second factor, login throttling, and
  constant-time behaviour for unknown accounts.
- **Sessions** — rotating opaque refresh tokens in the `aisits_rt` cookie with reuse detection
  (a replayed token revokes its whole family), self-service session list/revocation, switching the
  active organization.
- **Tokens** — EdDSA (Ed25519) access tokens of spec §8.2, signing keys generated on first boot,
  sealed at rest, rotated on demand and retired automatically; the JWKS for every other service;
  the Traefik `forwardAuth` endpoint for upstreams that do not verify tokens themselves.
- **Machine clients** — API keys (`sk_<id>_<secret>`) per organization and their introspection by
  the other services (`/internal/api-keys/introspect`); the shared-feed scope `ais:ingest` is
  granted by super admins only.
- **Password flows** — forgot/reset and invitations through `notify.email.requested.v1` on the
  `NOTIFY` work queue (the notification service sends the e-mails).
- **Central audit log** — the durable consumer `auth-audit` persists the `audit.recorded.v1`
  events of every service into the `audit_logs` hypertable; its own security events take the
  same path through the kit `AuditService`. `GET /audit-logs` reads it per tenant.
- **Bootstrap** — the platform organization `AIS Maritime Intelligence` and a super admin on an
  empty database; `pnpm seed:demo` for demo data.

It does **not** send e-mails (notification service), rate-limit anonymous traffic in general (the
gateway does) or store other services' data (it only keeps their audit records).

## Architecture

```mermaid
flowchart LR
  web["Web app / API clients"] -->|"/api/v2/auth, /me, /organizations,<br/>/users, /api-keys, /audit-logs"| gw["Traefik gateway :8000"]
  gw --> auth
  gw -.->|"forwardAuth GET /api/v2/auth/verify<br/>(/api/v1, /tiles)"| auth
  services["Other services"] -->|"GET /.well-known/jwks.json<br/>(cached, verify locally)"| auth
  services -->|"POST /internal/api-keys/introspect<br/>X-Internal-Token"| auth
  subgraph auth["auth :3001"]
    direction TB
    ctl["controllers<br/>(global default-deny guard,<br/>local key resolver)"] --> svc["services<br/>(rules from src/domain)"] --> repo["drizzle repositories"]
    keys["SigningKeyStore<br/>(Ed25519, AES-256-GCM sealed)"]
    consumer["AuditLogConsumer<br/>(durable auth-audit)"]
  end
  repo --> pg[("PostgreSQL schema auth<br/>+ audit_logs hypertable")]
  keys --> pg
  svc --> valkey[("Valkey<br/>throttles, used MFA codes")]
  svc -->|"notify.email.requested.v1"| notify[["NOTIFY (work queue)"]]
  svc -->|"audit.recorded.v1 → audit.v1.auth"| audit[["AUDIT"]]
  services -->|"audit.v1.<service>"| audit
  audit --> consumer --> pg
  notify --> notification["notification service<br/>(consumer notification-email)"]
```

Layers: `controller → service → repository` per feature in `src/modules/<feature>/`; the rules
(password policy, rotation state machine, access rules, key life cycle, TOTP, secret box, origin
policy) are pure functions in `src/domain/` with unit tests. Tenancy is enforced in the services
on data loaded from the database (`src/domain/access-rules.ts`), never on organization ids sent by
the client. Multi-write operations (rotation, reset, member changes, organization deletion) run in
one transaction; the last-admin rule is checked under row locks.

The service verifies its own access tokens with its local signing keys: `AuthModule.forRoot({
keyResolver })` gets `SigningKeyStore.keyResolver` (no HTTP call to itself), and `apiKeys: false`
(no auth route accepts API keys).

Startup follows the kit's lifecycle rule: connect, migrate, ensure the `NOTIFY` and `AUDIT` streams
(`onModuleInit`) → generate the first signing key when none is active, bootstrap an empty database,
start the `auth-audit` consumer and the jobs (`onApplicationBootstrap`) → the port opens. On
`SIGTERM` readiness turns `503`, the consumer and background e-mail requests drain, NATS drains,
the pool closes.

| Path                            | What                                                                                                                                                                                                |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/main.ts` / `src/server.ts` | tracing, then `bootstrapService()` with cookies                                                                                                                                                     |
| `src/app.module.ts`             | database, NATS (`NOTIFY`, `AUDIT`), Valkey, kit auth with the local key resolver, features                                                                                                          |
| `src/config.ts`                 | zod environment schema (base variables + auth variables)                                                                                                                                            |
| `src/domain/`                   | pure rules: password policy/hashing, refresh rotation, access rules (incl. grantable scopes), TOTP, secret box, key life cycle, API key material, origin policy, identity, client IP, storable text |
| `src/modules/authentication/`   | login, MFA verify, refresh, logout, sessions, switch-org, MFA enrollment, `verify`                                                                                                                  |
| `src/modules/keys/`             | signing keys, JWKS, rotation, retirement job                                                                                                                                                        |
| `src/modules/passwords/`        | forgot/reset/change, invitations, one-time tokens                                                                                                                                                   |
| `src/modules/organizations/`    | organizations, members and invitations                                                                                                                                                              |
| `src/modules/users/`            | `/me` and the user directory                                                                                                                                                                        |
| `src/modules/api-keys/`         | API keys and internal introspection                                                                                                                                                                 |
| `src/modules/audit-logs/`       | `GET /audit-logs`; `src/consumers/audit-log.consumer.ts` writes the log                                                                                                                             |
| `src/modules/bootstrap/`        | first-boot bootstrap, demo seeder, hourly housekeeping                                                                                                                                              |
| `migrations/`                   | forward-only SQL (`0001_init.sql`, `0002_membership_invitations.sql`)                                                                                                                               |
| `test/`                         | integration tests against TimescaleDB, NATS and Valkey containers                                                                                                                                   |

## Data model

Schema `auth`, owned by `auth_svc`; [`migrations/0001_init.sql`](migrations/0001_init.sql) and
[`migrations/0002_membership_invitations.sql`](migrations/0002_membership_invitations.sql) are
mirrored by [`src/db/schema.ts`](src/db/schema.ts). Ids are UUID v7 generated by the application.

```mermaid
erDiagram
  organizations ||--o{ memberships : has
  users ||--o{ memberships : has
  users ||--o{ sessions : opens
  organizations |o--o{ sessions : "active org"
  sessions ||--o{ refresh_tokens : "token family"
  users ||--o{ password_reset_tokens : receives
  organizations ||--o{ membership_invitations : invites
  users ||--o{ membership_invitations : "is invited"
  organizations ||--o{ api_keys : owns
  users |o--o{ api_keys : created
```

| Table                    | Columns (essentials)                                                                                                                                           | Constraints and indexes                                                                                                       |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `organizations`          | `id`, `name`, `slug`, `kind`, `created_at`, `updated_at`                                                                                                       | `slug` unique (DNS label pattern), `kind` ∈ shipping_company/authority/platform/research                                      |
| `users`                  | `id`, `email`, `name`, `password_hash` (PHC argon2id), `status`, `mfa_enabled`, `mfa_secret_enc`, `last_login_at`, `is_platform_admin`, timestamps             | unique index on `lower(email)`; active ⇒ password; MFA enabled ⇒ secret                                                       |
| `memberships`            | `user_id`, `org_id`, `role`, `created_at`                                                                                                                      | PK `(user_id, org_id)`, role ∈ org_admin/fleet_manager/authority/viewer, index `(org_id, role)`                               |
| `sessions`               | `id` (= refresh token family), `user_id`, `org_id` (active org), `created_at`, `last_used_at`, `revoked_at`, `ip` (`inet`), `user_agent`                       | partial indexes on active sessions per user and per org                                                                       |
| `refresh_tokens`         | `id`, `session_id`, `token_hash` (SHA-256 hex), `expires_at`, `used_at`, `created_at`                                                                          | `token_hash` unique, cascade with the session                                                                                 |
| `password_reset_tokens`  | `id`, `user_id`, `token_hash`, `purpose` (`reset` \| `invite`; only `reset` is issued, see invitations), `expires_at`, `used_at`                               | `token_hash` unique, partial index of open tokens                                                                             |
| `membership_invitations` | `id`, `org_id`, `user_id`, `role`, `name` (typed by the inviter), `invited_by`, `token_hash` (SHA-256 hex), `expires_at`, timestamps                           | `token_hash` unique, one invitation per `(org_id, user_id)`; the membership is written on acceptance                          |
| `api_keys`               | `id`, `org_id`, `name`, `prefix` (`sk_<id>`), `key_hash` (SHA-256 hex), `scopes text[]`, `created_by`, `last_used_at`, `revoked_at`, `created_at`              | `prefix` unique, scopes ⊆ `ais:ingest`/`telemetry:ingest`/`ais:read`                                                          |
| `signing_keys`           | `kid` (RFC 7638 thumbprint), `algorithm` (`EdDSA`), `public_jwk jsonb`, `private_key_enc` (`v1.<iv>.<tag>.<ciphertext>`), `status`, `created_at`, `retired_at` | at most one `active` key (partial unique index), public JWK without `d`                                                       |
| `audit_logs`             | `id` (envelope id), `at`, `source`, `actor_type`, `actor_id`, `org_id`, `action`, `target_type`, `target_id`, `ip`, `user_agent`, `meta jsonb`, `recorded_at`  | **hypertable** on `at` (7-day chunks), PK `(at, id)`, compressed after **7 days** (`segmentby org_id`), retention **2 years** |

Valkey (prefix `auth:`): rate limiter windows `ratelimit:<limiter>:<key>` (e-mail keys are
SHA-256-truncated, never in clear) and single-use markers `mfa:used:<userId>:<step>`,
`mfa:challenge:<jti>`. Housekeeping deletes ended sessions, expired refresh tokens, expired reset
tokens and expired invitations 30 days after they ended (hourly).

## API

Public routes live under `/api/v2` (Swagger UI `/docs`, JSON `/openapi.json`, committed as
[`openapi.json`](openapi.json)); errors are RFC 9457 problem details. Lists are page-based
(`page`, `pageSize` ≤ 100) except the audit log (cursor, `limit` ≤ 500).

| Method   | Path                                                                               | Permission                                         | What                                                                                                                                                                                             |
| -------- | ---------------------------------------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `POST`   | `/api/v2/auth/login`                                                               | public, throttled                                  | `{ accessToken, expiresIn, user, memberships, activeOrgId }` + cookie, or `{ mfaRequired: true, mfaToken }`                                                                                      |
| `POST`   | `/api/v2/auth/mfa/verify`                                                          | public, throttled                                  | `{ mfaToken, code }` → login response + cookie                                                                                                                                                   |
| `POST`   | `/api/v2/auth/refresh`                                                             | public, `aisits_rt` cookie, Origin check           | `{ accessToken, expiresIn }` + rotated cookie                                                                                                                                                    |
| `POST`   | `/api/v2/auth/logout`                                                              | public, cookie, Origin check                       | `204`, revokes the session, clears the cookie                                                                                                                                                    |
| `POST`   | `/api/v2/auth/switch-org`                                                          | signed-in user (member, or super_admin)            | `{ orgId }` → `{ accessToken, expiresIn, activeOrgId }`                                                                                                                                          |
| `POST`   | `/api/v2/auth/password/forgot`                                                     | public, throttled                                  | `{ email, locale? }` → always `202`; e-mails a reset link (30 min)                                                                                                                               |
| `POST`   | `/api/v2/auth/password/reset`                                                      | public, throttled per IP (failures)                | `{ token, password }` → `204`; also accepts invitations (writes the membership); revokes every session                                                                                           |
| `POST`   | `/api/v2/auth/password/change`                                                     | signed-in user                                     | `{ currentPassword, newPassword }` → `204`; revokes the other sessions                                                                                                                           |
| `POST`   | `/api/v2/auth/mfa/setup`                                                           | signed-in user                                     | `{ secret, otpauthUrl }` (pending until enabled)                                                                                                                                                 |
| `POST`   | `/api/v2/auth/mfa/enable` / `.../mfa/disable`                                      | signed-in user                                     | `{ code }` → `204`                                                                                                                                                                               |
| `GET`    | `/api/v2/auth/sessions`                                                            | signed-in user                                     | own active sessions (`current` flag)                                                                                                                                                             |
| `DELETE` | `/api/v2/auth/sessions/:id`                                                        | signed-in user                                     | revoke one own session                                                                                                                                                                           |
| `POST`   | `/api/v2/auth/keys/rotate`                                                         | `super_admin`                                      | `{ kid, previousKid, createdAt }`                                                                                                                                                                |
| `GET`    | `/api/v2/auth/verify`                                                              | public route, validates the bearer token           | `200` with `X-User-Id`, `X-Org-Id`, `X-Roles` (Traefik `forwardAuth`), else `401`                                                                                                                |
| `GET`    | `/api/v2/auth/methodology`                                                         | signed-in user                                     | catalog methods implemented here (none, see below)                                                                                                                                               |
| `GET`    | `/.well-known/jwks.json`                                                           | public                                             | active + retiring public keys (`Cache-Control: max-age=60`)                                                                                                                                      |
| `GET`    | `/api/v2/me`                                                                       | signed-in user                                     | profile, memberships, active org, roles, permissions                                                                                                                                             |
| `PATCH`  | `/api/v2/me`                                                                       | signed-in user                                     | `{ name }`                                                                                                                                                                                       |
| `GET`    | `/api/v2/organizations?search&kind`                                                | `org:manage`                                       | all organizations                                                                                                                                                                                |
| `POST`   | `/api/v2/organizations`                                                            | `org:manage`                                       | `{ name, slug?, kind }` (slug derived from the name when omitted)                                                                                                                                |
| `GET`    | `/api/v2/organizations/:id`                                                        | `org:manage`, or a member of the organization      | others get `404`                                                                                                                                                                                 |
| `PATCH`  | `/api/v2/organizations/:id`                                                        | `org:manage`                                       | `{ name?, slug?, kind? }`; the platform org keeps its kind, no kind change may strand roles of members or pending invitations (`409`)                                                            |
| `DELETE` | `/api/v2/organizations/:id`                                                        | `org:manage`                                       | deletes memberships and API keys, revokes sessions; platform org protected                                                                                                                       |
| `GET`    | `/api/v2/organizations/:id/members`                                                | `user:manage` (own active org; super_admin any)    | members with their role and status                                                                                                                                                               |
| `POST`   | `/api/v2/organizations/:id/members`                                                | `user:manage`                                      | `{ email, name, role, locale? }` → `201` invitation (same answer for new and existing addresses); unknown e-mails become `invited` accounts; the address joins when it accepts the e-mailed link |
| `GET`    | `/api/v2/organizations/:id/invitations`                                            | `user:manage`                                      | pending (and expired) invitations, newest first — only what the admin typed                                                                                                                      |
| `DELETE` | `/api/v2/organizations/:id/invitations/:invitationId`                              | `user:manage`                                      | withdraw an invitation (`204`; its link stops working)                                                                                                                                           |
| `PATCH`  | `/api/v2/organizations/:id/members/:userId`                                        | `user:manage`                                      | `{ role }`; the last `org_admin` cannot be demoted                                                                                                                                               |
| `DELETE` | `/api/v2/organizations/:id/members/:userId`                                        | `user:manage`                                      | not the last `org_admin`; revokes the member's sessions in that org                                                                                                                              |
| `GET`    | `/api/v2/users?search&status`                                                      | `org:manage`                                       | user directory with memberships                                                                                                                                                                  |
| `PATCH`  | `/api/v2/users/:id`                                                                | `org:manage`                                       | `{ status: active \| disabled }`; disabling revokes every session                                                                                                                                |
| `GET`    | `/api/v2/api-keys?orgId&includeRevoked`                                            | `api_key:manage` (own active org; super_admin any) | keys without secrets                                                                                                                                                                             |
| `POST`   | `/api/v2/api-keys`                                                                 | `api_key:manage`; `ais:ingest` only `super_admin`  | `{ name, scopes, orgId? }` → `{ apiKey: { …, key } }` (key shown once); `403 SCOPE_NOT_GRANTABLE`                                                                                                |
| `DELETE` | `/api/v2/api-keys/:id`                                                             | `api_key:manage`                                   | revoke (`404` for keys of other organizations)                                                                                                                                                   |
| `GET`    | `/api/v2/audit-logs?actorId&action&targetType&targetId&orgId&from&to&cursor&limit` | `audit:read` (own active org; super_admin all)     | newest first, default range 30 days                                                                                                                                                              |
| `POST`   | `/internal/api-keys/introspect`                                                    | `X-Internal-Token` (not routed by the gateway)     | `{ key }` → `{ active: true, keyId, orgId, scopes, name }` \| `{ active: false }`                                                                                                                |
| `GET`    | `/health/live`, `/health/ready`, `/metrics`                                        | public, not routed by the gateway                  | liveness, readiness (database, NATS, Valkey), Prometheus                                                                                                                                         |

**Rules** (spec §8, §13.1):

- Passwords: argon2id m = 19 456 KiB, t = 2, p = 1; ≥ 10 characters with a letter and a digit
  (≤ 128); hashes with other parameters are upgraded at the next login. Unknown e-mails hash a
  dummy password and answer the same `401 INVALID_CREDENTIALS` as wrong passwords.
- Throttles (Valkey, reserved before the check, refunded on success): **5 failed logins / 15 min
  per e-mail**, **20 / 15 min per IP** (also counts MFA codes), 5 failed MFA codes / 15 min per
  account, 5 wrong current passwords / 15 min per account, 10 forgot-password requests / 15 min per
  IP (`429`), 3 reset e-mails / hour per address (silently skipped), 10 failed resets or invitation
  acceptances (bad links, disabled accounts) / 15 min per IP. Exhausted limits answer
  `429 RATE_LIMITED` with `Retry-After`. The client IP is `request.ip` (from `TRUSTED_PROXIES`)
  normalized by [`client-ip.ts`](src/domain/client-ip.ts): ports, brackets and IPv6 zone ids are
  stripped, anything that is not an address becomes `null` (session `ip` null, throttle key
  `unknown`) — a malformed `X-Forwarded-For` never breaks a sign-in.
- Reset links and invitations are checked (format, then an indexed lookup) **before** the
  argon2id hash is computed, so anonymous garbage costs no hashing on the libuv pool that login
  shares. The password write runs with the token and the user row locked (`FOR UPDATE`) and only
  `WHERE status <> 'disabled'`; disabling an account locks the row too, so a reset or acceptance
  racing a disable can never re-enable it. The login rehash is a compare-and-set on the old hash.
- Refresh cookie `aisits_rt`: `HttpOnly; Secure` (`COOKIE_SECURE`); `SameSite=Strict;
Path=/api/v2/auth; Max-Age=30d`; the token is 256 random bits stored as SHA-256. Every refresh
  consumes the token and issues its successor; presenting a consumed token revokes the family
  (`401 REFRESH_TOKEN_REUSED`). Refresh and logout refuse an `Origin` outside `CORS_ORIGINS` /
  `PUBLIC_BASE_URL` (`403 ORIGIN_NOT_ALLOWED`). A failed refresh clears the cookie only when it
  ends the session (`INVALID_REFRESH_TOKEN`, `REFRESH_TOKEN_REUSED`, `ACCOUNT_DISABLED`); on a
  transient failure (database down, no signing key) the cookie is kept, and since the new access
  token is signed before the rotation commits, the retry with the same cookie succeeds.
- Access tokens: EdDSA, `kid` header, 15 min, claims `iss, aud, sub, sid, org, roles, email, name,
typ="access", iat, exp`; roles are recomputed from the memberships at every refresh and switch.
  Membership changes do not invalidate issued access tokens (short TTL) but removal revokes the
  member's refresh sessions in that organization.
- Signing keys: Ed25519, generated on first boot when none is active (advisory lock), private JWK
  sealed with AES-256-GCM (key from `KEY_ENCRYPTION_SECRET` via HKDF-SHA256, random 12-byte IV,
  tag stored, bound to the kid). Rotation demotes the active key to `retiring` (still in the
  JWKS); a job (every minute) retires keys whose successor is older than `ACCESS_TOKEN_TTL` + 30 s
  clock tolerance + 30 s key cache refresh. Replicas reload keys every 30 s.
- MFA: TOTP SHA-1, 6 digits, 30 s, ±1 step; the secret is sealed like the signing keys (bound to
  the user id); every accepted code is single use; the 5-minute MFA token is a JWT with audience
  `<AUTH_AUDIENCE>:mfa` and `typ="mfa"` (never accepted as an access token), single use.
- Members: `org_admin`s manage their active organization only, super admins every organization;
  `authority` can only be granted in organizations of kind `authority`; an organization always keeps
  one `org_admin`. Nobody is attached without consent: `POST …/members` records an invitation (and
  an `invited` account for unknown addresses) and e-mails the link; the membership is written when
  the invitee accepts it with `POST /auth/password/reset` (an existing account chooses its password
  again, like a reset — the mailbox owner proves control the same way). Until then the
  organization sees only what its admin typed — the answer, `GET …/invitations` and the audit
  record (target `membership_invitation`) are identical for new and existing addresses, so an
  admin cannot enumerate accounts, names, MFA or sign-in facts of other tenants.
- API keys: managed by `org_admin`s of the key's organization or super admins; **`ais:ingest` is
  granted by super admins only** (`403 SCOPE_NOT_GRANTABLE`): the ingestor accepts any key with the
  scope whatever its organization, and the AIS feed is shared by every tenant (§8.5), so a tenant
  key could fake positions that raise other tenants' alerts and feed their CII. `org_admin`s grant
  `telemetry:ingest` (checked against the key's organization by the telemetry service) and
  `ais:read`. Introspection updates `last_used_at` at most once per minute.

**Error codes** (besides the shared `VALIDATION_FAILED`, `UNAUTHORIZED`, `FORBIDDEN`,
`RATE_LIMITED`, `SERVICE_UNAVAILABLE`, `INTERNAL_ERROR`): `INVALID_CREDENTIALS`,
`ACCOUNT_DISABLED`, `INVALID_MFA_CODE`, `INVALID_REFRESH_TOKEN`, `REFRESH_TOKEN_REUSED`,
`ORIGIN_NOT_ALLOWED`, `INVALID_TOKEN`, `USER_NOT_FOUND`, `ORGANIZATION_NOT_FOUND`,
`MEMBER_NOT_FOUND`, `SESSION_NOT_FOUND`, `API_KEY_NOT_FOUND`, `SCOPE_NOT_GRANTABLE` (403),
`MEMBER_ALREADY_EXISTS`, `INVITATION_NOT_FOUND`, `INVITATION_CONFLICT` (409, retry),
`LAST_ORG_ADMIN`, `ORGANIZATION_SLUG_TAKEN`, `ORGANIZATION_PROTECTED`, `ORGANIZATION_KIND_CONFLICT`,
`ROLE_NOT_GRANTABLE` (422), `NOT_A_MEMBER`, `CANNOT_CHANGE_OWN_STATUS`,
`INVALID_STATUS_TRANSITION`, `MFA_ALREADY_ENABLED`, `MFA_NOT_ENABLED`, `MFA_SETUP_REQUIRED`,
`ORGANIZATION_REQUIRED` (see [`src/common/errors.ts`](src/common/errors.ts)).

## Events

| Direction | Stream (role)                  | Subject           | Type                        | Consumer / notes                                                                                                          |
| --------- | ------------------------------ | ----------------- | --------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| produces  | `NOTIFY` (work queue, ensured) | `notify.email.v1` | `notify.email.requested.v1` | consumed by `notification-email`; templates `password_reset`, `account_invite`; links carry the token in the URL fragment |
| produces  | `AUDIT` (ensured)              | `audit.v1.auth`   | `audit.recorded.v1`         | own security events through the kit `AuditService` (best effort)                                                          |
| consumes  | `AUDIT`                        | `audit.v1.>`      | `audit.recorded.v1`         | durable **`auth-audit`** → `audit_logs` (idempotent: `ON CONFLICT (at, id) DO NOTHING`, concurrency 4)                    |

Audited actions of this service: `auth.login.succeeded`, `auth.login.failed`, `auth.logout`,
`auth.refresh.reuse_detected`, `auth.session.revoke`, `auth.session.switch_org`,
`auth.password.change`, `auth.password.reset`, `auth.password.reset_request`,
`auth.invite.accept` (with the joined `orgId`), `auth.mfa.enable`, `auth.mfa.disable`,
`auth.signing_key.rotate`, `membership.invite` and `membership.invite.cancel` (target
`membership_invitation`, never the invited account), `membership.update`, `membership.delete`,
`api_key.create`, `api_key.revoke`, `organization.create`, `organization.update`,
`organization.delete`, `user.update`, `user.status.update`, `platform.bootstrap`.
`pnpm seed:demo` audits what it creates (`organization.create`, `user.create`,
`membership.create`, `api_key.create`, actor `system`, `meta.seed = "demo"`) by writing the
records into `audit_logs` in the seed transaction — the CLI runs without NATS. E-mail payloads,
tokens and password hashes are never logged: writes of the `users` table rethrow a sanitized error
(no SQL parameters, no driver `detail`) when they fail.

The audit consumer stores every valid event: characters PostgreSQL refuses (U+0000 in `text` and
`jsonb`, lone UTF-16 surrogates in `jsonb`) are replaced with U+FFFD and `meta` nested deeper than
32 levels is truncated, so such records are no longer retried until they reach the DLQ.

## Configuration

Every variable is listed with its development default in [`.env.example`](.env.example); the
service refuses to start on invalid values and prints every problem (names and reasons, never
values).

| Variable                                              | Default                                              | Notes                                                                                                                                                                                |
| ----------------------------------------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `NODE_ENV`                                            | `development`                                        | `development` \| `test` \| `production`                                                                                                                                              |
| `SERVICE_NAME` / `SERVICE_VERSION`                    | `auth` / `package.json` version                      | logs, metrics, event `source`, `audit.v1.auth`                                                                                                                                       |
| `HOST` / `PORT`                                       | `0.0.0.0` / `3001`                                   |                                                                                                                                                                                      |
| `LOG_LEVEL` / `LOG_PRETTY`                            | `info` / `true` in development                       | pino; secrets, cookies and tokens are redacted                                                                                                                                       |
| `SHUTDOWN_TIMEOUT_MS`                                 | `30000`                                              | graceful shutdown deadline                                                                                                                                                           |
| `DATABASE_URL`                                        | `postgres://auth_svc:auth_svc@localhost:5432/aisits` | required in production                                                                                                                                                               |
| `DATABASE_SCHEMA`                                     | `auth`                                               | `search_path=auth,public`                                                                                                                                                            |
| `DATABASE_POOL_MAX` / `DATABASE_STATEMENT_TIMEOUT_MS` | `10` / `30000`                                       |                                                                                                                                                                                      |
| `DB_MIGRATE_ON_BOOT`                                  | `true`                                               | also `pnpm migrate`                                                                                                                                                                  |
| `NATS_URL`                                            | `nats://localhost:4222`                              | comma separated list allowed                                                                                                                                                         |
| `NATS_DURABLE_PREFIX`                                 | empty                                                | prefix of durable names (test suites)                                                                                                                                                |
| `REDIS_URL`                                           | `redis://localhost:6379`                             | throttles and single-use MFA markers                                                                                                                                                 |
| `AUTH_ISSUER` / `AUTH_AUDIENCE`                       | `ais-its-auth` / `ais-its-api`                       | `iss` / `aud` of issued tokens (MFA tokens: `<aud>:mfa`)                                                                                                                             |
| `AUTH_JWKS_URL` / `AUTH_INTERNAL_URL`                 | `http://localhost:3001/…`                            | read by the kit for other services; unused here (local key resolver, no API-key routes)                                                                                              |
| `INTERNAL_TOKEN`                                      | `dev-internal-token-change-me`                       | `X-Internal-Token` of `/internal/*`; ≥ 16 characters and not the default in production                                                                                               |
| `CORS_ORIGINS`                                        | `http://localhost:5173,http://localhost:8000`        | CORS and the Origin allow-list of refresh/logout                                                                                                                                     |
| `PUBLIC_BASE_URL`                                     | `http://localhost:8000`                              | base of e-mail links (`/reset-password#token=…`, `/accept-invite#token=…`); its origin is allowed too                                                                                |
| `TRUSTED_PROXIES`                                     | `loopback,linklocal,uniquelocal`                     | whose `X-Forwarded-For` sets the client IP (per-IP throttles, sessions, audit); set it to the gateway's address in production, or any client on a private network chooses its own IP |
| `OTEL_EXPORTER_OTLP_ENDPOINT`                         | unset                                                | OTLP/HTTP tracing when set                                                                                                                                                           |
| `KEY_ENCRYPTION_SECRET`                               | development value                                    | **32+ characters**; master secret sealing signing keys and MFA secrets; refused default in production                                                                                |
| `KEY_ENCRYPTION_SECRET_PREVIOUS`                      | unset                                                | the old secret while rotating it (values it sealed still open; `pnpm rotate:key-secret` re-seals them)                                                                               |
| `ACCESS_TOKEN_TTL`                                    | `900`                                                | seconds (60..3600); also the retirement grace of rotated keys                                                                                                                        |
| `REFRESH_TOKEN_TTL_DAYS`                              | `30`                                                 | days (1..365); cookie `Max-Age` and sliding token expiry                                                                                                                             |
| `COOKIE_SECURE`                                       | `true` in production, else `false`                   | `Secure` attribute of `aisits_rt`                                                                                                                                                    |
| `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD`  | `admin@ais-its.local` / `ChangeMe123!`               | super admin of an empty database; the default password is refused in production                                                                                                      |
| `PASSWORD_RESET_TTL_MIN`                              | `30`                                                 | reset link validity, minutes                                                                                                                                                         |
| `INVITE_TTL_HOURS`                                    | `168`                                                | invitation link validity, hours                                                                                                                                                      |
| `EMAIL_DEFAULT_LOCALE`                                | `id`                                                 | `id` \| `en`, when a request names none                                                                                                                                              |
| `SEED_DEMO_PASSWORD`                                  | `DemoPass2026`                                       | password of the users created by `pnpm seed:demo`                                                                                                                                    |
| `SEED_DEMO_ALLOW_PRODUCTION`                          | `false`                                              | `pnpm seed:demo` refuses `NODE_ENV=production` unless `true` **and** `SEED_DEMO_PASSWORD` is not the default                                                                         |

## Local development

Requirements: Node.js 24 (`.nvmrc`), pnpm 10 (`corepack enable`), Docker. `@darmawanweb/*`
packages come from GitHub Packages: map the scope once in `~/.npmrc` (never in this repository).

```bash
pnpm install
cp .env.example .env
pnpm --dir ../.. infra:up      # postgres, nats, valkey, mailpit … (central repository)
pnpm dev                       # watch mode; first boot creates the signing key and the super admin
pnpm build && pnpm seed:demo   # optional: demo organizations, one user per role, two API keys

curl -s localhost:3001/health/ready
curl -s -c jar -H 'content-type: application/json' \
  -d '{"email":"admin@ais-its.local","password":"ChangeMe123!"}' localhost:3001/api/v2/auth/login
curl -s -b jar -X POST localhost:3001/api/v2/auth/refresh       # rotates the cookie in "jar"
open http://localhost:3001/docs                                  # Swagger UI
```

| Script                                          | What                                                                                                                                                                            |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm dev`                                      | watch mode (`nest start --watch --builder swc`)                                                                                                                                 |
| `pnpm build` / `pnpm start` / `pnpm start:prod` | compile with `tsc` to `dist/` / run it / run with `NODE_ENV=production`                                                                                                         |
| `pnpm migrate`                                  | apply `migrations/` (also on boot when `DB_MIGRATE_ON_BOOT=true`)                                                                                                               |
| `pnpm seed:demo`                                | (after `pnpm build`) idempotent, audited demo data, prints the users and the API keys once; refused in production without `SEED_DEMO_ALLOW_PRODUCTION=true` and an own password |
| `pnpm rotate:key-secret`                        | (after `pnpm build`) re-seals signing keys and MFA secrets from `KEY_ENCRYPTION_SECRET_PREVIOUS` to `KEY_ENCRYPTION_SECRET`                                                     |
| `pnpm openapi` / `pnpm openapi:check`           | write / verify `openapi.json` without any infrastructure                                                                                                                        |
| `pnpm test` / `pnpm test:int` / `pnpm test:all` | unit / integration (Docker) / both                                                                                                                                              |
| `pnpm lint` / `pnpm typecheck` / `pnpm format`  | ESLint, `tsc --noEmit`, Prettier                                                                                                                                                |

## Testing

- **Unit** (`src/**/*.spec.ts`, no Docker): password policy and hashing parameters, refresh
  rotation state machine, access rules (permissions, tenancy, last admin, grantable roles and API
  key scopes), secret box (AES-256-GCM/HKDF, tampering, binding, re-sealing) and the rotation
  fallback, API key generation/parsing/hashing, TOTP (RFC 6238 vectors), origin policy, cookie
  attributes and which refresh failures clear the cookie, client IP normalization, storable audit
  text, sanitized database errors (no password hash in messages), signing key life cycle, key
  material (RFC 8037 thumbprint vector), token service (claims, JWKS verification, rotation, MFA
  challenges), the demo seed guard, configuration.
- **Integration** (`test/*.int.test.ts`): the real `AppModule` against `timescale/timescaledb-ha:pg17`,
  `nats:2.11-alpine` and `valkey/valkey:8-alpine` started once by
  [`test/support/global-setup.ts`](test/support/global-setup.ts); each file starts from emptied
  tables. Covered: health/migrations/hypertable policies, bootstrap, JWKS verification with `jose`,
  rotation and post-grace retirement, forwardAuth headers, login cookie flags, refresh rotation and
  reuse detection, transient refresh failures keeping the cookie, logout, sessions, switch-org,
  sign-in with a malformed `X-Forwarded-For`, throttling (per e-mail and per IP), disabled
  accounts, MFA with real TOTP codes, forgot/reset (asserting the `NOTIFY` event, single use, no
  hashing for bad links, per-IP throttle, a reset racing a disable held by a second connection),
  password change, invitations (identical answers for new and existing addresses, nothing attached
  or revealed before acceptance, withdrawal), members and last-admin protection, API keys via
  `/internal` with `X-Internal-Token` (`ais:ingest` refused to `org_admin`s), the audit consumer
  (idempotent on redelivery, NUL characters), the audited demo seed, `GET /audit-logs` tenancy,
  `KEY_ENCRYPTION_SECRET` rotation, and an OpenAPI document whose security names are all declared.

```bash
pnpm test
TESTCONTAINERS_RYUK_DISABLED=true pnpm test:int          # TEST_LOG_LEVEL=debug shows service logs
```

## Operations

- **Image** `ghcr.io/darmawanweb/ais-its-auth-service` (multi-stage `node:24-alpine`, non-root,
  production dependencies only, `HEALTHCHECK` on `/health/live`; about 480 MB, of which ~180 MB is
  the Node.js base and ~200 MB `node_modules`). [`.pnpmfile.cjs`](.pnpmfile.cjs) keeps optional
  peers that pnpm would otherwise link to dev dependencies out of the production install:
  `typescript` (`@nestjs/swagger`) and the kit's test-only `testcontainers` and `@nestjs/testing`.
  The largest remaining packages come from the framework and the kit (`es-toolkit` and
  `swagger-ui-dist` via `@nestjs/swagger`, OTLP gRPC exporters via `@opentelemetry/sdk-node`).
  Build with BuildKit secrets only:

  ```bash
  DOCKER_BUILDKIT=1 docker build --secret id=npmrc,src=$HOME/.npmrc -t ais-its-auth-service .
  # behind a TLS-intercepting proxy add the optional CA bundle (spec §11):
  DOCKER_BUILDKIT=1 docker build --network host --secret id=npmrc,src=$HOME/.npmrc \
    --secret id=ca,src=/path/to/ca-bundle.crt -t ais-its-auth-service .
  ```

- **Health**: `/health/live` (process), `/health/ready` (`database`, `nats` incl. the `auth-audit`
  consumer, `redis`); readiness is `503` while shutting down.
- **Metrics** (`/metrics`, prefix `aisits_`): HTTP RED and event metrics of the kit
  (`aisits_events_consumed_total{stream="AUDIT",consumer="auth-audit",outcome}`, …) plus
  `aisits_auth_logins_total{outcome}`, `aisits_auth_token_refreshes_total{outcome}` (watch
  `reuse_detected`), `aisits_auth_emails_requested_total{template,outcome}`,
  `aisits_auth_api_key_introspections_total{outcome}`,
  `aisits_auth_audit_logs_persisted_total{source,outcome}`, `aisits_audit_failures_total`.
- **Key rotation**: `POST /api/v2/auth/keys/rotate` as a super admin; other services pick up the
  new key on their next JWKS refresh or at the first unknown `kid`; the old key leaves the JWKS
  ~16 minutes later.
- **Troubleshooting**
  - _Rotating `KEY_ENCRYPTION_SECRET`_ (suspected leak, scheduled rotation): (1) deploy every
    replica with the new secret as `KEY_ENCRYPTION_SECRET` and the old one as
    `KEY_ENCRYPTION_SECRET_PREVIOUS` — both open, the new one seals; (2) run
    `pnpm rotate:key-secret` (one transaction with the rows locked; idempotent; refuses and changes
    nothing when a value opens with neither secret); (3) remove `KEY_ENCRYPTION_SECRET_PREVIOUS` and
    redeploy. After a leak, also rotate the signing key (`POST /auth/keys/rotate`).
  - _Boot fails with `SecretDecryptionError`_: `KEY_ENCRYPTION_SECRET` differs from the one that
    sealed the stored keys. Restore it (or set the old one as `KEY_ENCRYPTION_SECRET_PREVIOUS` and
    rotate); if it is lost, retire the keys
    (`UPDATE auth.signing_keys SET status = 'retired', retired_at = now() WHERE status <> 'retired'`)
    so a new key is generated at boot (issued access tokens become invalid, users refresh), and
    reset MFA of affected users (`mfa_enabled = false, mfa_secret_enc = NULL`).
  - _`pnpm seed:demo` exits with "Refusing to seed demo accounts"_: `NODE_ENV=production`. Demo
    accounts include a super admin; set `SEED_DEMO_ALLOW_PRODUCTION=true` and a
    `SEED_DEMO_PASSWORD` of your own only for a deliberate demo installation.
  - _Sessions show no IP / per-IP throttles share one bucket_: the forwarded client address was not
    an IP (`X-Forwarded-For: foo`, an appended port is stripped) — fix the proxy, and set
    `TRUSTED_PROXIES` to the gateway only.
  - _A failed write logs `SanitizedDatabaseError: Storing the password failed: … (SQLSTATE …)`_:
    deliberately without SQL parameters (the password hash); the SQLSTATE names the cause
    (`57014` statement timeout, `40P01` deadlock, …).
  - _Boot fails with `BootstrapConfigurationError`_: an empty production database needs a
    `BOOTSTRAP_ADMIN_PASSWORD` of its own that satisfies the password policy.
  - _`429 RATE_LIMITED` on login_: wait for `Retry-After`; an operator can clear a window with
    `DEL auth:ratelimit:login-email:<key>` / `auth:ratelimit:login-ip:<ip>`. Behind a proxy, set
    `TRUSTED_PROXIES` or every user shares the proxy's IP budget.
  - _Refresh answers `403 ORIGIN_NOT_ALLOWED`_: add the web origin to `CORS_ORIGINS`.
  - _Cookie not stored in development_: `COOKIE_SECURE=true` over plain HTTP; set it to `false`.
  - _No reset/invite e-mails_: check `aisits_auth_emails_requested_total{outcome="failed"}` and
    the `notification-email` consumer of the notification service (the `NOTIFY` stream keeps
    requests 7 days). E-mail requests are published after the write commits and not retried (no
    outbox): a user repeats forgot-password, an admin invites the address again
    (`invitationSent: false` in the answer tells them to).
  - _Audit records missing_: check the consumer lag of `auth-audit` and `dlq.AUDIT.auth-audit`
    in the `DLQ` stream.

## Spec notes and deviations

- **Who grants `ais:ingest`** — spec §8.1/§8.4 list the scope but do not say who may grant it.
  The ingestor accepts any key holding it, whatever the key's organization, and the AIS feed is
  shared by every tenant (§8.5), so this service reserves it to super admins
  (`403 SCOPE_NOT_GRANTABLE`); the spec should state the rule.
- **Invitations** — spec §13.1 lists no invitations table and lets `POST …/members` attach
  existing accounts. To keep tenants from attaching (and probing) each other's accounts, the
  service adds `membership_invitations` (migration `0002`), `GET` and `DELETE
/organizations/:id/invitations[/:invitationId]`, and answers `POST …/members` with the
  invitation. Invitation links are accepted with `POST /auth/password/reset` as the spec says, so
  an existing account accepting an invitation chooses its password again (and its other
  sessions end) — the same proof of mailbox control as a reset. `password_reset_tokens.purpose`
  keeps `invite` in its `CHECK` (spec), but only `reset` tokens are issued.
- **Extra variables** — `KEY_ENCRYPTION_SECRET_PREVIOUS` (rotation of the master secret, with
  `pnpm rotate:key-secret`) and `SEED_DEMO_ALLOW_PRODUCTION` (production guard of the seed) are not
  in spec §13.1.
- **Seed audit** — `pnpm seed:demo` writes its audit records straight into `audit_logs` (the
  table this service owns) instead of publishing them through `AUDIT`: the CLI runs without NATS
  and the records commit with the seeded data.

## Legacy parity notes

The MVP (`/home/user/seemp-ref/be-legacy`) had no working authentication: its routes did not wire
an auth controller; only `src/validation/auth.validation.ts` (register/login rules) and
`src/utils/jwt.ts` (HS256 access/refresh JWTs from `JWT_SECRET` / `REFRESH_TOKEN_SECRET`) and the
Postman collection `2. Auth` (`register`, `login`, `logout {userId}`) exist. v2 replaces it
entirely (spec §15.6 "authentication everywhere"):

| Legacy                                                       | v2                                                                                                                |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| self-registration `POST /auth/register`                      | invitation by an org admin (`POST /organizations/:id/members`); bootstrap/seed for the first accounts             |
| password ≥ 6, ASCII letters and digits (`express-validator`) | ≥ 10 characters with a letter and a digit, any script, ≤ 128 (spec §13.1)                                         |
| bcryptjs dependency                                          | argon2id (m = 19 456 KiB, t = 2, p = 1)                                                                           |
| HS256 JWTs with shared secrets, refresh token as a JWT       | EdDSA access tokens with a public JWKS; opaque rotating refresh tokens with reuse detection in an HttpOnly cookie |
| `logout { userId }` (any caller)                             | `POST /auth/logout` revokes the session of the presented cookie                                                   |
| no roles or tenants                                          | organizations, memberships, roles and permissions of spec §8.4, tenancy of §8.5                                   |

## Methodology & references

The auth service implements **no method of the methodology catalog**
([`docs/references/methods.json`](../../docs/references/methods.json), described in
[`docs/METHODOLOGY.md`](../../docs/METHODOLOGY.md)): the catalog covers maritime analytics (AIS,
geo, safety, surveillance, emission, SEEMP, telemetry) and has no security domain, so
`GET /api/v2/auth/methodology` lists no method and no source carries a `@method` tag. The
security rules and thresholds of this service are traceable to their standards instead (TSDoc
`@see` on each domain function):

| Rule (file)                                                                                                                            | Value                                                             | Sources                                                                                                                                                                                                                                                                 |
| -------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Password hashing ([`password-hashing.ts`](src/domain/password-hashing.ts))                                                             | argon2id m = 19 456 KiB, t = 2, p = 1, 16-byte salt, 32-byte hash | [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id), [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106)                                                                                     |
| Password policy ([`password-policy.ts`](src/domain/password-policy.ts))                                                                | ≥ 10 code points, a letter and a digit, ≤ 128                     | spec §13.1, [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html)                                                                                                                                                                                           |
| Login throttling ([`auth-throttle.service.ts`](src/modules/throttling/auth-throttle.service.ts))                                       | 5 / 15 min per e-mail, 20 / 15 min per IP                         | spec §13.1, [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#protect-against-automated-attacks)                                                                                                        |
| Refresh rotation and reuse detection ([`refresh-rotation.ts`](src/domain/refresh-rotation.ts))                                         | revoke the family on reuse                                        | spec §8.3, [RFC 9700 §4.14.2](https://datatracker.ietf.org/doc/html/rfc9700#section-4.14.2)                                                                                                                                                                             |
| Refresh cookie ([`refresh-cookie.ts`](src/domain/refresh-cookie.ts)), Origin check ([`origin-policy.ts`](src/domain/origin-policy.ts)) | HttpOnly, Secure, SameSite=Strict, Path=/api/v2/auth              | spec §8.3, [RFC 6265bis](https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html), [OWASP CSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#verifying-origin-with-standard-headers) |
| Secret encryption ([`secret-box.ts`](src/domain/secret-box.ts))                                                                        | AES-256-GCM, 96-bit IV, HKDF-SHA256 per purpose                   | [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf), [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)                                                                                                                    |
| Signing keys ([`key-material.ts`](src/modules/keys/key-material.ts), [`signing-key-rules.ts`](src/domain/signing-key-rules.ts))        | Ed25519, kid = JWK thumbprint, grace = TTL + 60 s                 | spec §8.2, [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037), [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638), [RFC 7517 §5](https://www.rfc-editor.org/rfc/rfc7517#section-5)                                                                                      |
| TOTP ([`totp.ts`](src/domain/totp.ts))                                                                                                 | SHA-1, 6 digits, 30 s, ±1 step, 160-bit secret                    | [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238), [RFC 4226 §4](https://www.rfc-editor.org/rfc/rfc4226#section-4), [Key URI format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)                                                               |
| API keys ([`api-key-material.ts`](src/domain/api-key-material.ts))                                                                     | `sk_<10>_<32>` base62, SHA-256 at rest                            | spec §8.1                                                                                                                                                                                                                                                               |

Proposed catalog ids, should the platform add a `security` domain to the catalog:
`security.password_hashing`, `security.password_policy`, `security.login_throttle`,
`security.refresh_rotation`, `security.secret_encryption`, `security.signing_key_lifecycle`,
`security.totp`, `security.api_key_scope_grant` (`ais:ingest` for super admins only,
[`access-rules.ts`](src/domain/access-rules.ts)), `security.invitation_consent` (memberships only
by accepted invitation) and `security.client_ip` ([`client-ip.ts`](src/domain/client-ip.ts)).

## Contributing

Conventional commits (commitlint), lint-staged on commit (Husky). CI runs format, lint, typecheck,
unit and integration tests, build, the `openapi.json` freshness check and the image build. Release:
move the `Unreleased` entries of [CHANGELOG.md](CHANGELOG.md) under the new version, bump
`package.json`, tag `v<version>`.
