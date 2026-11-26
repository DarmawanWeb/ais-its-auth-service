import {
  ConflictError,
  DomainError,
  ForbiddenError,
  NotFoundError,
  UnauthorizedError,
  ValidationFailedError,
} from '@darmawanweb/ais-its-nest';

import {
  type PasswordPolicyViolation,
  passwordViolationMessage,
} from '../domain/password-policy.js';

/**
 * Problems of the auth service (RFC 9457, spec §5). Codes are stable
 * UPPER_SNAKE_CASE; shared codes come from contracts `ERROR_DEFINITIONS`,
 * the others are specific to this service and listed in the README.
 */
export const AuthErrors = {
  /** Wrong e-mail or password, deliberately not saying which (no user enumeration). */
  invalidCredentials: (): UnauthorizedError =>
    new UnauthorizedError('The e-mail or password is incorrect', {
      code: 'INVALID_CREDENTIALS',
      challenge: 'Bearer',
    }),

  accountDisabled: (): ForbiddenError =>
    new ForbiddenError('The account is disabled', { code: 'ACCOUNT_DISABLED' }),

  invalidMfaCode: (): UnauthorizedError =>
    new UnauthorizedError(
      'The authentication code is invalid or was already used',
      {
        code: 'INVALID_MFA_CODE',
        challenge: 'Bearer',
      },
    ),

  /** Missing, unknown, expired or revoked refresh token (the cookie is cleared). */
  invalidRefreshToken: (
    detail = 'The session expired or was revoked; sign in again',
  ): UnauthorizedError =>
    new UnauthorizedError(detail, {
      code: 'INVALID_REFRESH_TOKEN',
      title: 'Invalid refresh token',
      challenge: 'Bearer error="invalid_token"',
    }),

  /** A consumed refresh token was presented again: the session was revoked. */
  refreshTokenReused: (): UnauthorizedError =>
    new UnauthorizedError(
      'This refresh token was already used; the session was revoked for safety, sign in again',
      {
        code: 'REFRESH_TOKEN_REUSED',
        title: 'Refresh token reused',
        challenge: 'Bearer error="invalid_token"',
      },
    ),

  /** Cookie endpoint called from a foreign web origin (CSRF defence). */
  originNotAllowed: (origin: string): ForbiddenError =>
    new ForbiddenError(
      `Requests from the origin ${origin} may not use the session cookie`,
      {
        code: 'ORIGIN_NOT_ALLOWED',
        title: 'Origin not allowed',
      },
    ),

  /** Unknown, expired or already used reset/invitation token. */
  invalidToken: (): DomainError =>
    new DomainError('INVALID_TOKEN', {
      detail:
        'The link is invalid, expired or was already used; request a new one',
    }),

  /** The password violates the policy of spec §13.1. */
  weakPassword: (
    field: string,
    violations: readonly PasswordPolicyViolation[],
  ): ValidationFailedError =>
    new ValidationFailedError(
      violations.map((violation) => ({
        field,
        message: `The password ${passwordViolationMessage(violation)}`,
        code: `password_${violation}`,
      })),
    ),

  userNotFound: (id: string): NotFoundError =>
    new NotFoundError(`No user with id ${id}`, {
      code: 'USER_NOT_FOUND',
      extra: { id },
    }),

  organizationNotFound: (id: string): NotFoundError =>
    new NotFoundError(`No organization with id ${id}`, {
      code: 'ORGANIZATION_NOT_FOUND',
      extra: { id },
    }),

  memberNotFound: (orgId: string, userId: string): NotFoundError =>
    new NotFoundError(
      `User ${userId} is not a member of organization ${orgId}`,
      {
        code: 'MEMBER_NOT_FOUND',
        title: 'Member not found',
        extra: { orgId, userId },
      },
    ),

  sessionNotFound: (id: string): NotFoundError =>
    new NotFoundError(`No active session with id ${id}`, {
      code: 'SESSION_NOT_FOUND',
      title: 'Session not found',
      extra: { id },
    }),

  apiKeyNotFound: (id: string): NotFoundError =>
    new NotFoundError(`No API key with id ${id}`, {
      code: 'API_KEY_NOT_FOUND',
      extra: { id },
    }),

  /** A revoked or expired key cannot get a new secret (`POST /api-keys/:id/rotate`). */
  apiKeyInactive: (id: string, reason: 'revoked' | 'expired'): ConflictError =>
    new ConflictError(
      `The API key ${id} is ${reason}; create a new key instead of rotating it`,
      {
        code: 'API_KEY_INACTIVE',
        title: 'API key inactive',
        extra: { id, reason },
      },
    ),

  /** `expiresAt` of a new key must lie in the future. */
  expiryInPast: (): ValidationFailedError =>
    new ValidationFailedError([
      {
        field: 'expiresAt',
        message: 'expiresAt must be in the future',
        code: 'futureDate',
      },
    ]),

  /** The caller may not grant these API-key scopes (`ais:ingest` is for super admins). */
  scopeNotGrantable: (scopes: readonly string[]): ForbiddenError =>
    new ForbiddenError(
      `You may not grant the API-key scope(s) ${scopes.join(', ')}; only platform administrators can`,
      {
        code: 'SCOPE_NOT_GRANTABLE',
        title: 'Scope not grantable',
        extra: { scopes },
      },
    ),

  memberExists: (orgId: string): ConflictError =>
    new ConflictError('The address belongs to a member of the organization', {
      code: 'MEMBER_ALREADY_EXISTS',
      title: 'Member already exists',
      extra: { orgId },
    }),

  invitationNotFound: (orgId: string, id: string): NotFoundError =>
    new NotFoundError(`No invitation with id ${id} in organization ${orgId}`, {
      code: 'INVITATION_NOT_FOUND',
      title: 'Invitation not found',
      extra: { orgId, id },
    }),

  /** The same address was invited concurrently; repeating the request renews the invitation. */
  invitationConflict: (orgId: string): ConflictError =>
    new ConflictError(
      'The address was invited at the same moment by another request; try again',
      {
        code: 'INVITATION_CONFLICT',
        title: 'Invitation conflict',
        extra: { orgId },
      },
    ),

  lastOrgAdmin: (orgId: string): ConflictError =>
    new ConflictError('An organization must keep at least one org_admin', {
      code: 'LAST_ORG_ADMIN',
      title: 'Last organization admin',
      extra: { orgId },
    }),

  slugTaken: (slug: string): ConflictError =>
    new ConflictError(
      `The slug "${slug}" is already used by another organization`,
      {
        code: 'ORGANIZATION_SLUG_TAKEN',
        title: 'Organization slug taken',
        extra: { slug },
      },
    ),

  slugRequired: (): ValidationFailedError =>
    new ValidationFailedError([
      {
        field: 'slug',
        message: 'No slug can be derived from the name; send one',
        code: 'slug_required',
      },
    ]),

  organizationProtected: (detail: string): ConflictError =>
    new ConflictError(detail, {
      code: 'ORGANIZATION_PROTECTED',
      title: 'Organization protected',
    }),

  /** A kind change would leave members with roles the new kind cannot grant. */
  kindStrandsRoles: (kind: string, roles: readonly string[]): ConflictError =>
    new ConflictError(
      `Members or pending invitations hold roles an organization of kind ${kind} cannot grant (${roles.join(', ')}); change those roles (or withdraw the invitations) first`,
      {
        code: 'ORGANIZATION_KIND_CONFLICT',
        title: 'Organization kind conflict',
        extra: { kind, roles },
      },
    ),

  roleNotGrantable: (role: string, kind: string): DomainError =>
    new DomainError('ROLE_NOT_GRANTABLE', {
      status: 422,
      title: 'Role not grantable',
      detail: `The role ${role} cannot be granted in an organization of kind ${kind}`,
      extra: { role, kind },
    }),

  notAMember: (orgId: string): ForbiddenError =>
    new ForbiddenError('You are not a member of this organization', {
      code: 'NOT_A_MEMBER',
      title: 'Not a member',
      extra: { orgId },
    }),

  ownStatus: (): ConflictError =>
    new ConflictError('You cannot change the status of your own account', {
      code: 'CANNOT_CHANGE_OWN_STATUS',
      title: 'Cannot change own status',
    }),

  statusTransition: (from: string, to: string): ConflictError =>
    new ConflictError(`An account cannot go from ${from} to ${to}`, {
      code: 'INVALID_STATUS_TRANSITION',
      title: 'Invalid status transition',
      extra: { from, to },
    }),

  mfaAlreadyEnabled: (): ConflictError =>
    new ConflictError('Multi-factor authentication is already enabled', {
      code: 'MFA_ALREADY_ENABLED',
      title: 'MFA already enabled',
    }),

  mfaNotEnabled: (): ConflictError =>
    new ConflictError('Multi-factor authentication is not enabled', {
      code: 'MFA_NOT_ENABLED',
      title: 'MFA not enabled',
    }),

  mfaSetupRequired: (): ConflictError =>
    new ConflictError(
      'Start the setup (POST /auth/mfa/setup) before enabling MFA',
      {
        code: 'MFA_SETUP_REQUIRED',
        title: 'MFA setup required',
      },
    ),

  organizationRequired: (): ForbiddenError =>
    new ForbiddenError('Select an organization first (POST /auth/switch-org)', {
      code: 'ORGANIZATION_REQUIRED',
      title: 'Organization required',
    }),
} as const;
