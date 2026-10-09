-- 2026-10-09-001: the instants a credential's key is judged by are UTC, whatever the writer's session.
--
-- _issuer_key_facts (polaris_web/app.py) and the doctor's polaris-key-register-check.sql compare a
-- signature's TokenSignature.signed_at, and its credential's ISSUED TokenLifecycleEvent.event_timestamp,
-- with its authority's key register (AuthorityKeyEvent). Each is a TIMESTAMP whose default was
-- CURRENT_TIMESTAMP, which converts to the SESSION's timezone. The database runs UTC (2026-09-24-005),
-- but a session may SET timezone: as polaris_app at 'Etc/GMT+12', issuance, recovery, migration and bulk
-- issuance wrote a signature's instant twelve hours behind UTC, and a signature made after its key was
-- retired or declared compromised read as made before it. Each now defaults to the UTC wall clock.
--
-- phase: expand. Column defaults only; no row changes. The canonical copy lives in 01_schema.sql.
-- REVERSIBLE: the .down.sql restores CURRENT_TIMESTAMP.
ALTER TABLE TokenSignature ALTER COLUMN signed_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE TokenLifecycleEvent ALTER COLUMN event_timestamp SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE AuthorityKeyEvent ALTER COLUMN effective_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE AuthorityKeyEvent ALTER COLUMN recorded_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
