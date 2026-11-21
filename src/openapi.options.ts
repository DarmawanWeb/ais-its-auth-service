import type { OpenApiOptions } from '@darmawanweb/ais-its-nest';

import { SERVICE } from './service.js';

/** OpenAPI document of the service (`/docs`, `/openapi.json`, `pnpm openapi`). */
export const OPENAPI: OpenApiOptions = {
  title: `AIS Maritime Intelligence — ${SERVICE.title}`,
  version: SERVICE.version,
  description: SERVICE.description,
  tags: [
    {
      name: 'auth',
      description: 'Sign-in, MFA, sessions, refresh tokens and password flows',
    },
    { name: 'me', description: 'The signed-in user' },
    {
      name: 'organizations',
      description: 'Organizations (tenants) and their members',
    },
    { name: 'users', description: 'Platform user directory (super admins)' },
    { name: 'api-keys', description: 'API keys of machine clients' },
    { name: 'audit-logs', description: 'Central audit log of every service' },
    { name: 'keys', description: 'JWT signing keys and the JWKS' },
    {
      name: 'internal',
      description: 'Service-to-service endpoints (X-Internal-Token)',
    },
    {
      name: 'methodology',
      description: 'Methods of the methodology catalog implemented here',
    },
  ],
};
