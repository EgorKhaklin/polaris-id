-- ============================================================================
-- 2026-09-11-001-agency-quota-history.down.sql
--
-- Reverses the v9.424 quota-history migration: back to one row per agency,
-- keyed on agency_id, editable in place.
--
-- LOSSY, and deliberately loud about it. The old shape holds exactly one row
-- per agency, so the superseded rows -- the record of who set which cap, when,
-- and why -- cannot survive the reversal. This keeps the LIVE row for each
-- agency and drops the rest. Running it discards audit history.
-- ============================================================================

DROP TRIGGER IF EXISTS trg_agency_quota_immutable ON AgencyQuota;
DROP FUNCTION IF EXISTS enforce_agency_quota_immutability();

-- The live row survives; the history does not fit the old shape.
DELETE FROM AgencyQuota WHERE superseded_at IS NOT NULL;

DROP INDEX IF EXISTS uq_effective_agency_quota;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_name = 'agencyquota' AND column_name = 'quota_id') THEN
        ALTER TABLE AgencyQuota DROP CONSTRAINT agencyquota_pkey;
        ALTER TABLE AgencyQuota DROP COLUMN quota_id;
        ALTER TABLE AgencyQuota ADD PRIMARY KEY (agency_id);
    END IF;
END $$;

ALTER TABLE AgencyQuota DROP COLUMN IF EXISTS superseded_at;

-- The enforcement lookup goes back to expecting one row per agency. This has to be
-- done here and correctly: the v9.424 body reads superseded_at, which the column drop
-- above has just removed, so leaving it in place would fail every capped issuance,
-- revocation and verification with "column superseded_at does not exist". A reversal
-- that leaves the write paths broken is not a reversal. The body below is the pre-v9.424
-- lookup, byte for byte apart from the filter; the rest of the function is untouched
-- because ALTER-ing one statement of a plpgsql body is not a thing SQL offers, so the
-- surrounding lines are reproduced from 06_triggers.sql as of that version.
DO $$
BEGIN
    EXECUTE replace(
        pg_get_functiondef('enforce_agency_quota()'::regprocedure),
        'WHERE agency_id = v_agency_id' || chr(10) ||
        '       AND superseded_at IS NULL;',
        'WHERE agency_id = v_agency_id;');
END $$;

DO $$
BEGIN
    IF pg_get_functiondef('enforce_agency_quota()'::regprocedure) LIKE '%superseded_at%' THEN
        RAISE EXCEPTION 'enforce_agency_quota still reads superseded_at, which this '
                        'migration has just dropped: reinstall it from 06_triggers.sql '
                        'as of v9.423 before letting writes through';
    END IF;
END $$;
