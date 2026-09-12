-- ============================================================================
-- 2026-09-12-001-discretion-policy-history.down.sql
--
-- Reverses v9.426: IssuerDiscretionPolicy goes back to one editable row per agency.
--
-- LOSSY, and loud about it. The old shape holds exactly one row per agency, so the
-- superseded bounds -- the record of who raised an agency's revocation ceiling, from
-- what, when, and why -- cannot survive. This keeps the bound IN FORCE for each
-- agency and drops the rest. Running it discards audit history and makes the
-- "any loosening is auditable" claim false again.
--
-- It also restores uc8_revoke_token's lookup, because the v9.426 body reads
-- superseded_at and the column drop below would otherwise make every sanctioned
-- revocation fail with "column superseded_at does not exist". A reversal that leaves
-- the revocation path broken is not a reversal.
-- ============================================================================

DROP TRIGGER IF EXISTS trg_discretion_policy_immutable ON IssuerDiscretionPolicy;
DROP FUNCTION IF EXISTS enforce_discretion_policy_immutability();

-- The bound in force survives; the history does not fit the old shape.
DELETE FROM IssuerDiscretionPolicy WHERE superseded_at IS NOT NULL;

DROP INDEX IF EXISTS uq_effective_discretion_policy;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_name = 'issuerdiscretionpolicy' AND column_name = 'policy_id') THEN
        ALTER TABLE IssuerDiscretionPolicy DROP CONSTRAINT issuerdiscretionpolicy_pkey;
        ALTER TABLE IssuerDiscretionPolicy DROP COLUMN policy_id;
        ALTER TABLE IssuerDiscretionPolicy ADD PRIMARY KEY (agency_id);
    END IF;
END $$;

ALTER TABLE IssuerDiscretionPolicy DROP COLUMN IF EXISTS superseded_at;

-- The enforcement lookup goes back to expecting one row per agency.
DO $$
BEGIN
    EXECUTE replace(
        pg_get_functiondef('uc8_revoke_token(integer,integer,character varying,character varying,integer)'::regprocedure),
        'WHERE agency_id = v_issuing_agency_id' || chr(10) ||
        '      AND superseded_at IS NULL;',
        'WHERE agency_id = v_issuing_agency_id;');
EXCEPTION WHEN undefined_function THEN
    RAISE EXCEPTION 'uc8_revoke_token was not found under its expected signature; reinstall '
                    '05_procedures.sql as of v9.425 before letting revocations through';
END $$;

DO $$
BEGIN
    IF pg_get_functiondef('uc8_revoke_token(integer,integer,character varying,character varying,integer)'::regprocedure)
       LIKE '%superseded_at%' THEN
        RAISE EXCEPTION 'uc8_revoke_token still reads superseded_at, which this migration has '
                        'just dropped: reinstall 05_procedures.sql as of v9.425';
    END IF;
END $$;
