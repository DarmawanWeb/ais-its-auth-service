import { sqlStateOf } from '@darmawanweb/ais-its-nest/db';

/** Longest label taken from a producer's `meta` (characters). */
export const META_LABEL_MAX_LENGTH = 200;

/** Names stored with a record (`0003_audit_log_labels.sql`). */
export interface AuditLabels {
  readonly actorName: string | null;
  readonly actorEmail: string | null;
  readonly orgName: string | null;
  readonly targetLabel: string | null;
}

const LABEL_FIELDS = [
  'actorName',
  'actorEmail',
  'orgName',
  'targetLabel',
] as const satisfies readonly (keyof AuditLabels)[];

/**
 * Key of `meta` under which this service's own records carry the names of
 * their actor, organization and target, read when the record is written
 * (`Transactions`, in the transaction of the change it describes): the
 * `auth-audit` consumer stores these instead of reading the names when the
 * record arrives — which may be after a rename or a deletion (relay
 * backlog, NATS outage, consumer lag) — and drops the key from the stored
 * `meta`. Honoured only for records whose `source` is this service;
 * `audit.recorded.v1` has no label fields.
 */
export const CAPTURED_LABELS_META_KEY = 'auditLabels';

/** `meta` with the names captured for its record ({@link CAPTURED_LABELS_META_KEY}). */
export function withCapturedLabels(
  meta: Readonly<Record<string, unknown>> | undefined,
  labels: AuditLabels,
): Record<string, unknown> {
  const captured: Record<string, string | null> = {};
  for (const field of LABEL_FIELDS) captured[field] = labels[field];
  return { ...(meta ?? {}), [CAPTURED_LABELS_META_KEY]: captured };
}

/**
 * The names captured with a record ({@link withCapturedLabels}), or
 * `undefined` when `meta` carries none or not in that shape (every field a
 * string or `null`).
 */
export function capturedLabelsOf(
  meta: Readonly<Record<string, unknown>>,
): AuditLabels | undefined {
  const value = meta[CAPTURED_LABELS_META_KEY];
  if (typeof value !== 'object' || value === null || Array.isArray(value))
    return undefined;
  const fields = value as Record<string, unknown>;
  const labels: Record<string, string | null> = {};
  for (const field of LABEL_FIELDS) {
    const label = fields[field];
    if (label !== null && typeof label !== 'string') return undefined;
    labels[field] = label;
  }
  return labels as unknown as AuditLabels;
}

/** `meta` without {@link CAPTURED_LABELS_META_KEY} (what is stored and shown). */
export function withoutCapturedLabels(
  meta: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  const { [CAPTURED_LABELS_META_KEY]: _captured, ...rest } = meta;
  return rest;
}

/**
 * Target types this service owns, whose labels it resolves from its own
 * tables when the record is stored: `user` → `Name <e-mail>`,
 * `organization` → its name, `api_key` → `Name (sk_<id>)`,
 * `membership_invitation` → the invited address.
 */
export const OWN_TARGET_TYPES = [
  'user',
  'organization',
  'api_key',
  'membership_invitation',
] as const;

/** A target type of {@link OWN_TARGET_TYPES}. */
export type OwnTargetType = (typeof OWN_TARGET_TYPES)[number];

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** `true` for a canonical UUID string (target ids are free text). */
export function isUuid(value: string | null): value is string {
  return value !== null && UUID_PATTERN.test(value);
}

/**
 * The target of a record when this service can name it from its tables:
 * an {@link OwnTargetType} with a UUID id; `undefined` otherwise (targets of
 * other services, non-UUID ids such as signing key ids).
 */
export function ownTarget(
  targetType: string | null,
  targetId: string | null,
): { readonly type: OwnTargetType; readonly id: string } | undefined {
  const type = OWN_TARGET_TYPES.find((own) => own === targetType);
  return type !== undefined && isUuid(targetId)
    ? { type, id: targetId }
    : undefined;
}

/**
 * The label a producer gave its target in `meta`: `meta.targetLabel`, else
 * `meta.name` (the convention of most producers, e.g. `engine.create`),
 * when it is a non-blank string; trimmed and cut to
 * {@link META_LABEL_MAX_LENGTH} characters. `audit.recorded.v1` has no label
 * field, so this is how other services' targets get a name.
 */
export function metaTargetLabel(
  meta: Readonly<Record<string, unknown>>,
): string | null {
  for (const key of ['targetLabel', 'name']) {
    const value = meta[key];
    if (typeof value !== 'string') continue;
    const label = value.trim();
    // By code point, so a surrogate pair is never cut in half.
    if (label !== '')
      return Array.from(label).slice(0, META_LABEL_MAX_LENGTH).join('');
  }
  return null;
}

/**
 * SQLSTATE classes of failures a retry cannot fix for the same row:
 * `22` data exceptions (a value the column type refuses), `23` integrity
 * constraint violations (a `CHECK` the contracts do not mirror) and `54`
 * program limits (e.g. `54000`: an index entry above the btree maximum of
 * 2704 bytes, from a very long incompressible target id).
 */
export const NEVER_STORABLE_SQLSTATE_CLASSES = ['22', '23', '54'] as const;

/**
 * `true` when storing an audit record failed for a reason inherent to the
 * record (see {@link NEVER_STORABLE_SQLSTATE_CLASSES}), so the consumer
 * dead-letters it instead of retrying; `false` for transient failures
 * (connection loss, timeouts, serialization failures, a full disk), which
 * are retried.
 */
export function isNeverStorable(error: unknown): boolean {
  const state = sqlStateOf(error);
  return (
    state !== undefined &&
    NEVER_STORABLE_SQLSTATE_CLASSES.some((prefix) => state.startsWith(prefix))
  );
}
