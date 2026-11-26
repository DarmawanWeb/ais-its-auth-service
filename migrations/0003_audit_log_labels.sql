-- 0003_audit_log_labels — names captured with each audit record (0.2.0).
--
-- GET /audit-logs showed ids only, so the web app had to join members and the
-- (super-admin only) user directory and could not name API-key actors, system
-- actors or targets of other services. The auth-audit consumer now stores the
-- names as they were when the record arrived: the actor's name and e-mail
-- (users) or the API key's name, the organization's name, and a label of the
-- target (resolved from auth's own tables, or the producer's meta.targetLabel /
-- meta.name). They stay readable after the user, key or organization is renamed
-- or deleted. Rows stored before 0.2.0 keep NULL here; the API falls back to the
-- current names for them.
--
-- Nullable columns without a default: TimescaleDB adds them to a compressed
-- hypertable without rewriting or decompressing any chunk.

ALTER TABLE audit_logs ADD COLUMN actor_name text;
ALTER TABLE audit_logs ADD COLUMN actor_email text;
ALTER TABLE audit_logs ADD COLUMN org_name text;
ALTER TABLE audit_logs ADD COLUMN target_label text;
