-- ============================================================================
-- POLARIS — IDENTITY TOKEN SYSTEM
-- 09_grants.sql : Application-role privileges
--
-- Creates the polaris_app database role used by the Flask web app and the
-- polaris-cli tool, with the minimum privilege set needed:
--   - CONNECT on the database
--   - USAGE on the public schema
--   - SELECT, INSERT, UPDATE, DELETE on tables
--   - USAGE, SELECT on sequences (for SERIAL/IDENTITY columns)
--   - EXECUTE on functions (for the UC stored procedures)
--
-- Notably absent: any DDL privileges (CREATE/DROP/ALTER). This is intentional
-- defense-in-depth for the SQL console: even if the application-layer
-- whitelist were bypassed, DROP TABLE would still be rejected by Postgres.
--
-- Default privileges are also configured so future objects added to the public
-- schema (e.g. by future migrations) inherit the same grant pattern.
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        CREATE ROLE polaris_app WITH LOGIN PASSWORD 'polaris_dev_password';
    END IF;
END$$;

-- Grant CONNECT on the CURRENT database, not a hardcoded name. This file loads
-- into whatever DB it runs against: 'polaris_test' in dev/CI, 'polaris' in the
-- prod compose. Hardcoding 'polaris_test' made prod init ERROR ("database
-- polaris_test does not exist") under ON_ERROR_STOP, aborting docker-init.sh
-- before it enabled TLS — so the prod stack never came up (found v9.140). Use
-- current_database() dynamically, the same pattern this file already uses for
-- the ALTER DATABASE GUC settings below.
DO $$
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO polaris_app', current_database());
END$$;
GRANT USAGE ON SCHEMA public TO polaris_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO polaris_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO polaris_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO polaris_app;

-- Default privileges for any future objects in the public schema.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO polaris_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO polaris_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT EXECUTE ON FUNCTIONS TO polaris_app;

-- ----------------------------------------------------------------------------
-- v9.85 / C1 append-only as a privilege boundary, not only a trigger.
--
-- The append-only audit-of-record tables are guarded by the
-- reject_audit_modification() trigger, which has a GUC carve-out: it permits
-- UPDATE/DELETE when polaris.purge_in_progress = 'TRUE'. That GUC is a custom
-- setting any role can SET — including polaris_app — so the trigger alone did
-- NOT stop the application role from deleting an audit row:
--
--     SET LOCAL polaris.purge_in_progress = 'TRUE';
--     DELETE FROM TokenLifecycleEvent WHERE event_id = ...;   -- succeeded
--
-- C1 is the thesis (audit-of-record, enforced at the database level), so the
-- trigger must not be the only thing standing between the app role and a
-- forged audit history. The grant model now backs it: polaris_app keeps
-- SELECT + INSERT (append-only IS insert-allowed) but loses UPDATE/DELETE on
-- every append-only table. The sole legitimate DELETE path, uc_archive_purge,
-- is SECURITY DEFINER (owned by a privileged role) and runs the deletes with
-- the owner's rights, inside the admin-gated, checkpoint-writing transaction.
-- Now even a role that sets the GUC is refused at the ACL layer before the
-- trigger ever fires.
--
-- to_regclass guards each name so this block is robust to load order:
-- AuditAccessLog is created by a later migration, which carries its own
-- matching REVOKE (2026-05-15-003-audit-access-log.up.sql); the loop simply
-- skips any table not yet present.
DO $$
DECLARE
    v_tbl TEXT;
    -- Lowercased on purpose: these tables were created with unquoted
    -- identifiers, so Postgres folded their names to lower case. %I would
    -- quote a MixedCase literal into a case-sensitive name that matches
    -- nothing, so to_regclass would return NULL and every REVOKE would be
    -- silently skipped.
    v_append_only_tables TEXT[] := ARRAY[
        'tokenlifecycleevent',
        'verificationevent',
        'enrollmentstatusevent',
        'anchorbatch',
        'tokenstateepochleaf',
        'duressevent',
        'authauditlog',
        'auditaccesslog',
        -- v9.89: a consumed ZK anti-replay nonce must never be un-consumed
        -- (deleting it re-opens the replay window). polaris_app INSERTs to
        -- consume; it must not UPDATE/DELETE.
        'zkverificationnonce',
        -- v9.125: the right-to-erasure log. polaris_app INSERTs an erasure
        -- record (via uc_pseudonymize_individual) but must not edit or remove
        -- one, or the erasure log could be made to lie about what happened.
        'individualerasureevent',
        -- P1.11: the retention policy. Appending a policy is INSERT and stays
        -- available; superseding one is an UPDATE and belongs to
        -- uc_apply_retention_template, which is SECURITY DEFINER and
        -- admin-gated. A role that could UPDATE this table directly could
        -- retire a retention decision without recording who did it.
        'retentionpolicy',
        -- P8.2c: the exchange-receipt transparency log. polaris_app appends a
        -- receipt's hash at mint time; a role that could UPDATE/DELETE could
        -- rewrite the log, which the trigger also forbids.
        'exchangereceiptlog',
        -- P8.2d: the exchange gateway's replay register. polaris_app consumes a
        -- nonce (INSERT); un-consuming one (UPDATE/DELETE) would re-open replay.
        'exchangenonce',
        -- P8.4: the auth broker's consumed-code register (code hashes only).
        'authcodeconsumed'
    ];
BEGIN
    FOREACH v_tbl IN ARRAY v_append_only_tables LOOP
        IF to_regclass(format('public.%I', v_tbl)) IS NOT NULL THEN
            EXECUTE format('REVOKE UPDATE, DELETE ON %I FROM polaris_app', v_tbl);
        END IF;
    END LOOP;
END$$;

-- ----------------------------------------------------------------------------
-- v8.15 / R11-6 / M2-11 — System-default GUCs for the issuer-discretion
-- bound enforced by uc8_revoke_token.
--
-- polaris.default_max_revoke_percent — N (percent of agency's outstanding
--                                       tokens) above which a co-signer is
--                                       required.
-- polaris.default_window_days         — W (rolling window) over which
--                                       revocations are counted.
--
-- Per-agency overrides live in IssuerDiscretionPolicy; absence of a row
-- there inherits these defaults. The procedure reads them via
-- current_setting('polaris.default_*', true) and COALESCEs against a
-- hardcoded numeric fallback so a missing GUC degrades to defaults rather
-- than erroring.
--
-- ALTER DATABASE binds the setting to whichever database this file loads
-- into. format(%I) is the safe-identifier path; current_database() picks
-- the live DB name so this works for polaris, polaris_test, or any other
-- deployment target.
-- ----------------------------------------------------------------------------
DO $$
BEGIN
    EXECUTE format(
        'ALTER DATABASE %I SET polaris.default_max_revoke_percent = 5.00',
        current_database());
    EXECUTE format(
        'ALTER DATABASE %I SET polaris.default_window_days = 30',
        current_database());
END$$;

-- ============================================================================
-- END OF 09_grants.sql
-- ============================================================================
