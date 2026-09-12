-- ============================================================================
-- 2026-09-12-005-quota-enforcement-reads-the-live-row.up.sql
--
-- v9.424 turned AgencyQuota from a setting into a decision that survives being
-- changed: a superseded row keeps `superseded_at`, and exactly one row per agency
-- is in force. Its migration, 2026-09-11-001-agency-quota-history, says so in its
-- own header --
--
--     CHANGES (4): enforce_agency_quota() reads the LIVE row. A superseded cap must
--
-- -- and never redefines the function. The canonical 06_triggers.sql was corrected;
-- the migration chain was not, and 2026-09-01-002-agency-quota still carries the
-- pre-history body with a bare `WHERE agency_id = v_agency_id`.
--
-- WHAT THAT DOES. On a database built by loading the SQL files and then applying
-- migrations in order, the older migration reinstalls the older function, and
-- `SELECT ... INTO v_cap` over a table that now holds several rows per agency takes
-- an arbitrary one. Measured on such a database: an agency whose cap was LOWERED from
-- 999999 to 5 had 999999 enforced, because the superseded row came back first. The
-- lowering needs a 20-character justification at the database (v9.190) and then does
-- not take effect.
--
-- A deployment re-runs `polaris-migrate.sh --sync-objects` after migrating, which
-- re-applies 06_triggers.sql and puts the correct body back, so a deployed stack was
-- never exposed. Anything that migrates WITHOUT that step was.
--
-- 2026-09-01-002 and 2026-09-11-001 are history and stay as they are. This supersedes
-- them by running after them, and carries the body rather than describing it.
--
-- phase: expand. Replaces a function body; no table, column or constraint changes.
-- REVERSIBLE: the .down.sql restores the pre-history body, which reintroduces the bug
-- on purpose, because that is what reversing this means.
-- ============================================================================

CREATE OR REPLACE FUNCTION enforce_agency_quota()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    v_kind      TEXT := TG_ARGV[0];      -- 'issue' | 'revoke' | 'verify'
    v_agency_id INTEGER;
    v_cap       INTEGER;
    v_window    INTERVAL;
    v_count     INTEGER;
BEGIN
    IF v_kind = 'verify' THEN
        v_agency_id := NEW.requesting_agency_id;
    ELSE
        v_agency_id := NEW.issuing_agency_id;
    END IF;

    -- Only a NEW transition into REVOKED is a revocation. Nested on purpose:
    -- PL/pgSQL compiles the whole condition, and VerificationEvent rows have
    -- no status column, so a flat `v_kind = 'revoke' AND NEW.status ...`
    -- raised "record new has no field status" on every verification.
    IF v_kind = 'revoke' THEN
        IF NEW.status <> 'REVOKED' OR OLD.status = 'REVOKED' THEN
            RETURN NEW;
        END IF;
    END IF;

    -- Cheap exit: no quota row, or no cap of this kind.
    SELECT CASE v_kind
               WHEN 'issue'  THEN issue_per_day
               WHEN 'revoke' THEN revoke_per_day
               ELSE               verify_per_hour
           END
      INTO v_cap
      FROM AgencyQuota
     WHERE agency_id = v_agency_id
       AND superseded_at IS NULL;   -- v9.424: a superseded cap does not bind
    IF v_cap IS NULL THEN
        RETURN NEW;
    END IF;

    v_window := CASE v_kind WHEN 'verify' THEN INTERVAL '1 hour' ELSE INTERVAL '1 day' END;

    -- C9: serialize the count-then-write per (kind, agency).
    PERFORM pg_advisory_xact_lock(
        hashtext('polaris.quota.' || v_kind || '.' || v_agency_id::TEXT));

    IF v_kind = 'issue' THEN
        SELECT count(*) INTO v_count
          FROM IdentityToken
         WHERE issuing_agency_id = v_agency_id
           AND issued_date > CURRENT_TIMESTAMP - v_window;
    ELSIF v_kind = 'revoke' THEN
        SELECT count(*) INTO v_count
          FROM TokenLifecycleEvent e
          JOIN IdentityToken t ON t.token_id = e.token_id
         WHERE t.issuing_agency_id = v_agency_id
           AND e.event_type = 'REVOKED'
           AND e.event_timestamp > CURRENT_TIMESTAMP - v_window;
    ELSE
        SELECT count(*) INTO v_count
          FROM VerificationEvent
         WHERE requesting_agency_id = v_agency_id
           AND event_timestamp > CURRENT_TIMESTAMP - v_window;
    END IF;

    IF v_count + 1 > v_cap THEN
        RAISE EXCEPTION
            'quota exceeded: agency % has reached its % quota of % per % (AgencyQuota)',
            v_agency_id, v_kind, v_cap,
            CASE v_kind WHEN 'verify' THEN 'hour' ELSE 'day' END
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END$$;
