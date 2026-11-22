import type { NodePgQueryResultHKT } from 'drizzle-orm/node-postgres';
import type { PgDatabase } from 'drizzle-orm/pg-core';

import type * as schema from './schema.js';

/**
 * Query executor of the repositories: the injected drizzle database or a
 * transaction opened on it (`db.transaction(async (tx) => …)`), so one
 * repository method can run alone or inside a multi-write transaction.
 */
export type Executor = PgDatabase<NodePgQueryResultHKT, typeof schema>;

/** Rows of the service tables. */
export type UserRow = typeof schema.users.$inferSelect;
export type OrganizationRow = typeof schema.organizations.$inferSelect;
export type MembershipRow = typeof schema.memberships.$inferSelect;
export type SessionRow = typeof schema.sessions.$inferSelect;
export type RefreshTokenRow = typeof schema.refreshTokens.$inferSelect;
export type PasswordResetTokenRow =
  typeof schema.passwordResetTokens.$inferSelect;
export type MembershipInvitationRow =
  typeof schema.membershipInvitations.$inferSelect;
export type ApiKeyRow = typeof schema.apiKeys.$inferSelect;
export type SigningKeyRow = typeof schema.signingKeys.$inferSelect;
export type AuditLogRow = typeof schema.auditLogs.$inferSelect;

/** Escapes `%`, `_` and `\` so user input matches literally in LIKE patterns. */
export function escapeLikePattern(value: string): string {
  return value.replace(/[\\%_]/g, (character) => `\\${character}`);
}
