-- ============================================================================
-- 2026-09-12-005-quota-enforcement-reads-the-live-row.down.sql
--
-- Reverses v9.449 by restoring the pre-history body, which reads EVERY AgencyQuota
-- row for an agency rather than the one in force. That is not a tidy-up: on a table
-- that keeps superseded rows it means the enforced cap is whichever row comes back
-- first, so a quota that was lowered can stop being the one enforced.
--
-- Reversing this migration reintroduces that, deliberately, because that is what
-- reversing it means.
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
     WHERE agency_id = v_agency_id;   -- v9.424: a superseded cap does not bind
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
