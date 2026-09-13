-- ============================================================================
-- POLARIS — IDENTITY TOKEN SYSTEM
-- 00_migrations_table.sql : Schema migration registry (v8.95)
-- ============================================================================
--
-- Position C of a recorded decision selected by
-- VANTA in-chat 2026-05-14 ("C"). The migration framework Polaris ships is
-- custom polaris-native, matching the existing operator-script style:
--
--   - Migrations live in polaris_sql/migrations/ as plain SQL files
--   - Each change has TWO files: <name>.up.sql + <name>.down.sql
--   - Bidirectional — a down file is required even for
--     irreversible changes (the file documents that no revert is possible)
--   - Applied in lexicographic order via scripts/polaris-migrate.sh
--   - SHA-256-of-file recorded for tamper-detection at revert time
--
-- This file creates the `schema_version` table that polaris-migrate.sh
-- writes to. It is THE 13TH AUDIT-OF-RECORD INSTANCE in the schema
-- (after TokenLifecycleEvent, VerificationEvent, EnrollmentStatusEvent,
-- AnchorBatch, RecoveryRequest, TokenSignature, AgencyTrustAttestation,
-- TokenStateEpoch, DuressEvent, LifecycleArchiveCheckpoint, plus the
-- 3 filesystem AoR instances).
--
-- Append-only invariant: never DELETE/UPDATE; revert
-- appends a NEW row (event_type='reverted'); the original apply-row
-- stays untouched as the historical record.
--
-- Load order: this file runs FIRST in 00_load_all.sql (before
-- 01_schema.sql) so that even the schema-creation step itself can be
-- migration-tracked if Phase 2 ever backfills the v0 baseline.
-- ============================================================================

-- v9.02 idempotency: DROP+CREATE (was: CREATE IF NOT EXISTS).
-- Pre-v9.02 the registry persisted across 00_load_all.sql re-runs,
-- but 01_schema.sql DROPS+recreates baseline tables AND drops
-- migration-created tables (OperatorWebauthnCredential,
-- idx_checkpoint_purged_at_desc), so the registry claiming
-- "all applied" diverged from the actual schema state.
--
-- 00_load_all.sql IS the factory-reset surface. Within a single DB
-- lifetime the registry is append-only via the trigger below; across
-- 00_load_all.sql re-runs the lifetime resets and polaris-migrate.sh
-- --up re-applies migrations from scratch. Operators in production
-- should never re-run 00_load_all.sql after the initial deploy
-- (polaris-migrate.sh --up is the production-incremental path).
DROP TABLE IF EXISTS schema_version CASCADE;
CREATE TABLE schema_version (
    event_id         BIGSERIAL PRIMARY KEY,
    name             VARCHAR(200)  NOT NULL,
    event_type       VARCHAR(20)   NOT NULL,
    occurred_at      TIMESTAMPTZ   NOT NULL DEFAULT now(),
    actor_user_id    INTEGER,
    file_sha256      VARCHAR(64)   NOT NULL,

    CONSTRAINT schema_version_event_type_enum
        CHECK (event_type IN ('applied', 'reverted')),
    CONSTRAINT schema_version_name_format
        CHECK (name ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{3}-[a-z][a-z0-9_-]*$'),
    CONSTRAINT schema_version_sha256_hex
        CHECK (file_sha256 ~ '^[0-9a-fA-F]{64}$')
);

CREATE INDEX idx_schema_version_name_time
    ON schema_version (name, occurred_at DESC);

CREATE INDEX idx_schema_version_recent
    ON schema_version (occurred_at DESC);

COMMENT ON TABLE schema_version IS
    'Schema migration registry (v8.95 / Position C). Append-only per '
    'Append-only. Each row records a single event (applied or reverted) '
    'with SHA-256 of the file that ran. 13th audit-of-record instance.';

-- Append-only trigger.
-- Uses the same `reject_audit_modification()` function declared in
-- 06_triggers.sql — that function gained the GUC-keyed DELETE
-- carve-out in v8.87, but schema_version does NOT participate in
-- the archive-purge cycle, so the carve-out is operationally
-- irrelevant here.
--
-- We use a dedicated function to be explicit that schema_version is
-- strictly append-only at full strictness (no carve-out at all),
-- same shape as v8.87's reject_checkpoint_modification.
CREATE OR REPLACE FUNCTION reject_schema_version_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- No carve-out. Migration audit trail must be complete.
    RAISE EXCEPTION
        '% on schema_version is forbidden: '
        'this table is the audit-of-record for schema migrations '
        '(v8.95); rows accumulate forever, revert events '
        'append rather than mutate.',
        TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS trg_schema_version_append_only ON schema_version;
CREATE TRIGGER trg_schema_version_append_only
    BEFORE UPDATE OR DELETE ON schema_version
    FOR EACH ROW
    EXECUTE FUNCTION reject_schema_version_modification();

COMMENT ON FUNCTION reject_schema_version_modification IS
    'Strict append-only enforcement for schema_version. G32 (v8.95): '
    'the migration audit-of-record cannot lose entries. No carve-out.';
