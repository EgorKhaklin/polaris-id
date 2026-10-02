-- 2026-10-01-005: exact population counts that cost the same at any population (lab/strategy/008).
--
-- ADD:
--   PopulationCount, PopulationCountDelta: credentials by authority and status, and live
--     signatures on active credentials by authority and algorithm. The Overview read these with
--     full counts of IdentityToken and of TokenSignature joined to it, recomputed on every view:
--     10.4 seconds at two million people, and in proportion to the population beyond.
--   population_count_tokens(), population_count_signatures(), population_count_truncated():
--     statement triggers that append each statement's net change. Writers only append, so no
--     writer waits on another's counter row and none can deadlock over one.
--   uc_fold_population_counts(): moves changes into the totals; the application role may call it.
--   uc_rebuild_population_counts(): recounts under a SHARE lock; owner-only.
--   Row-level security on both tables, by authority, like IdentityToken's.
--
-- EXPAND: the previous release neither reads nor writes these tables; its writes to IdentityToken
-- and TokenSignature fire the triggers like any other, so the counts stay exact during a roll.
-- LOCK: the closing recount SHARE-locks IdentityToken and TokenSignature until this migration
-- commits, so writers wait for it: on a large population, apply it in a maintenance window.
-- REVERSIBLE: yes (the .down.sql drops every object here).

CREATE TABLE IF NOT EXISTS PopulationCount (
    facet       VARCHAR(20) NOT NULL
        CHECK (facet IN ('credential_status', 'live_signature')),
    agency_id   INTEGER     NOT NULL REFERENCES Agency(agency_id),
    -- credential_status: a status; live_signature: an algorithm id, as text.
    item        VARCHAR(40) NOT NULL,
    n           BIGINT      NOT NULL CHECK (n >= 0),
    PRIMARY KEY (facet, agency_id, item)
);

CREATE TABLE IF NOT EXISTS PopulationCountDelta (
    delta_id    BIGSERIAL   PRIMARY KEY,
    facet       VARCHAR(20) NOT NULL
        CHECK (facet IN ('credential_status', 'live_signature')),
    agency_id   INTEGER     NOT NULL REFERENCES Agency(agency_id),
    item        VARCHAR(40) NOT NULL,
    n           BIGINT      NOT NULL CHECK (n <> 0)
);

COMMENT ON TABLE PopulationCount IS
  'Exact population counts by authority (lab/strategy/008): credentials by status and live '
  'signatures on active credentials by algorithm. Folded from PopulationCountDelta by '
  'uc_fold_population_counts(); a reader sums both. Written only by the owner''s routines.';
COMMENT ON TABLE PopulationCountDelta IS
  'Signed changes to PopulationCount not yet folded in, appended by the statement triggers on '
  'IdentityToken and TokenSignature. Append-only for writers, so counting never serialises them.';

ALTER TABLE PopulationCount ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS population_count_authority_isolation ON PopulationCount;
CREATE POLICY population_count_authority_isolation ON PopulationCount
    USING (
        agency_id = coalesce(
            NULLIF(current_setting('polaris.operator_agency_id', true), '')::INTEGER,
            agency_id)
    );
ALTER TABLE PopulationCountDelta ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS population_count_delta_authority_isolation ON PopulationCountDelta;
CREATE POLICY population_count_delta_authority_isolation ON PopulationCountDelta
    USING (
        agency_id = coalesce(
            NULLIF(current_setting('polaris.operator_agency_id', true), '')::INTEGER,
            agency_id)
    );

CREATE OR REPLACE FUNCTION uc_fold_population_counts()
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_folded BIGINT := 0;
BEGIN
    IF NOT pg_try_advisory_xact_lock(hashtext('polaris.population.fold')) THEN
        RETURN 0;
    END IF;
    -- An existing total is updated and a new one inserted, in two statements of one: INSERT ...
    -- ON CONFLICT DO UPDATE checks the proposed row's CHECK (n >= 0) before it finds the
    -- conflict, so a decrement of an existing total would be refused as a negative new row.
    -- One fold runs at a time (the lock above), so the two never race for a new key.
    WITH moved AS (
        DELETE FROM PopulationCountDelta
        RETURNING facet, agency_id, item, n
    ), summed AS (
        SELECT facet, agency_id, item, sum(n) AS n, count(*) AS deltas
          FROM moved
         GROUP BY facet, agency_id, item
    ), updated AS (
        UPDATE PopulationCount c SET n = c.n + s.n
          FROM summed s
         WHERE c.facet = s.facet AND c.agency_id = s.agency_id AND c.item = s.item AND s.n <> 0
        RETURNING 1
    ), inserted AS (
        INSERT INTO PopulationCount (facet, agency_id, item, n)
        SELECT s.facet, s.agency_id, s.item, s.n
          FROM summed s
         WHERE s.n <> 0
           AND NOT EXISTS (SELECT 1 FROM PopulationCount c
                            WHERE c.facet = s.facet AND c.agency_id = s.agency_id AND c.item = s.item)
        RETURNING 1
    )
    SELECT COALESCE(sum(deltas), 0) INTO v_folded FROM summed;
    RETURN v_folded;
END$$;

COMMENT ON FUNCTION uc_fold_population_counts() IS
  'Folds PopulationCountDelta into PopulationCount (lab/strategy/008). Idempotent and '
  'non-blocking: one fold at a time, and a caller that finds one running returns 0.';

-- Recount from the tables themselves: the load scripts call it after the seed, the bench after a
-- bulk load with triggers off, and an operator to reconcile. It SHARE-locks IdentityToken and
-- TokenSignature, so every writer waits until it commits and the recount is exact in any
-- isolation level; on a large population that is a maintenance window, so the application role
-- may not run it (09_grants.sql).
CREATE OR REPLACE FUNCTION uc_rebuild_population_counts()
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('polaris.population.fold'));
    LOCK TABLE IdentityToken, TokenSignature IN SHARE MODE;
    DELETE FROM PopulationCountDelta;
    DELETE FROM PopulationCount;
    INSERT INTO PopulationCount (facet, agency_id, item, n)
    SELECT 'credential_status', issuing_agency_id, status, count(*)
      FROM IdentityToken
     GROUP BY issuing_agency_id, status;
    INSERT INTO PopulationCount (facet, agency_id, item, n)
    SELECT 'live_signature', t.issuing_agency_id, s.algorithm_id::TEXT, count(*)
      FROM TokenSignature s
      JOIN IdentityToken t ON t.token_id = s.token_id
     WHERE s.deprecation_date IS NULL AND t.status = 'ACTIVE'
     GROUP BY t.issuing_agency_id, s.algorithm_id;
END$$;

COMMENT ON FUNCTION uc_rebuild_population_counts() IS
  'Recounts PopulationCount from IdentityToken and TokenSignature under a SHARE lock '
  '(lab/strategy/008). Owner-only: a full count of the population is a maintenance act.';

CREATE OR REPLACE FUNCTION population_count_tokens()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    -- Each branch names only the transition tables its event has.
    IF TG_OP = 'INSERT' THEN
        INSERT INTO PopulationCountDelta (facet, agency_id, item, n)
        SELECT 'credential_status', issuing_agency_id, status, count(*)
          FROM new_rows GROUP BY issuing_agency_id, status;
        -- A credential has no signature when it is inserted: the signature's insert counts it.
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO PopulationCountDelta (facet, agency_id, item, n)
        SELECT 'credential_status', issuing_agency_id, status, -count(*)
          FROM old_rows GROUP BY issuing_agency_id, status;
        INSERT INTO PopulationCountDelta (facet, agency_id, item, n)
        SELECT 'live_signature', o.issuing_agency_id, s.algorithm_id::TEXT, -count(*)
          FROM old_rows o
          JOIN TokenSignature s ON s.token_id = o.token_id AND s.deprecation_date IS NULL
         WHERE o.status = 'ACTIVE'
         GROUP BY o.issuing_agency_id, s.algorithm_id;
    ELSE
        INSERT INTO PopulationCountDelta (facet, agency_id, item, n)
        SELECT 'credential_status', agency_id, status, sum(d)
          FROM (SELECT issuing_agency_id AS agency_id, status, -1 AS d FROM old_rows
                UNION ALL
                SELECT issuing_agency_id, status, 1 FROM new_rows) c
         GROUP BY agency_id, status
        HAVING sum(d) <> 0;
        INSERT INTO PopulationCountDelta (facet, agency_id, item, n)
        SELECT 'live_signature', agency_id, algorithm_id::TEXT, sum(d)
          FROM (SELECT o.issuing_agency_id AS agency_id, s.algorithm_id, -1 AS d
                  FROM old_rows o
                  JOIN TokenSignature s ON s.token_id = o.token_id AND s.deprecation_date IS NULL
                 WHERE o.status = 'ACTIVE'
                UNION ALL
                SELECT n.issuing_agency_id, s.algorithm_id, 1
                  FROM new_rows n
                  JOIN TokenSignature s ON s.token_id = n.token_id AND s.deprecation_date IS NULL
                 WHERE n.status = 'ACTIVE') c
         GROUP BY agency_id, algorithm_id
        HAVING sum(d) <> 0;
    END IF;
    -- Now and then fold, so the changes stay few when nobody reads. A count must never stop a
    -- credential write: should the fold fail, the changes stay unfolded (a reader still sums
    -- them) and the write goes on.
    IF random() < 0.002 THEN
        BEGIN
            PERFORM uc_fold_population_counts();
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'population counts not folded: %', SQLERRM;
        END;
    END IF;
    RETURN NULL;
END$$;

CREATE OR REPLACE FUNCTION population_count_signatures()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    -- A live signature (no deprecation date) on an ACTIVE credential, by the credential's
    -- authority and the signature's algorithm.
    IF TG_OP = 'INSERT' THEN
        INSERT INTO PopulationCountDelta (facet, agency_id, item, n)
        SELECT 'live_signature', t.issuing_agency_id, n.algorithm_id::TEXT, count(*)
          FROM new_rows n JOIN IdentityToken t ON t.token_id = n.token_id
         WHERE n.deprecation_date IS NULL AND t.status = 'ACTIVE'
         GROUP BY t.issuing_agency_id, n.algorithm_id;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO PopulationCountDelta (facet, agency_id, item, n)
        SELECT 'live_signature', t.issuing_agency_id, o.algorithm_id::TEXT, -count(*)
          FROM old_rows o JOIN IdentityToken t ON t.token_id = o.token_id
         WHERE o.deprecation_date IS NULL AND t.status = 'ACTIVE'
         GROUP BY t.issuing_agency_id, o.algorithm_id;
    ELSE
        INSERT INTO PopulationCountDelta (facet, agency_id, item, n)
        SELECT 'live_signature', agency_id, algorithm_id::TEXT, sum(d)
          FROM (SELECT t.issuing_agency_id AS agency_id, o.algorithm_id, -1 AS d
                  FROM old_rows o JOIN IdentityToken t ON t.token_id = o.token_id
                 WHERE o.deprecation_date IS NULL AND t.status = 'ACTIVE'
                UNION ALL
                SELECT t.issuing_agency_id, n.algorithm_id, 1
                  FROM new_rows n JOIN IdentityToken t ON t.token_id = n.token_id
                 WHERE n.deprecation_date IS NULL AND t.status = 'ACTIVE') c
         GROUP BY agency_id, algorithm_id
        HAVING sum(d) <> 0;
    END IF;
    -- Now and then fold, so the changes stay few when nobody reads. A count must never stop a
    -- credential write: should the fold fail, the changes stay unfolded (a reader still sums
    -- them) and the write goes on.
    IF random() < 0.002 THEN
        BEGIN
            PERFORM uc_fold_population_counts();
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'population counts not folded: %', SQLERRM;
        END;
    END IF;
    RETURN NULL;
END$$;

-- TRUNCATE fires no row or statement-row events, so it clears what it invalidates: every count
-- for IdentityToken (both facets read it), the live-signature counts for TokenSignature.
CREATE OR REPLACE FUNCTION population_count_truncated()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF TG_TABLE_NAME = 'identitytoken' THEN
        DELETE FROM PopulationCountDelta;
        DELETE FROM PopulationCount;
    ELSE
        DELETE FROM PopulationCountDelta WHERE facet = 'live_signature';
        DELETE FROM PopulationCount WHERE facet = 'live_signature';
    END IF;
    RETURN NULL;
END$$;

DROP TRIGGER IF EXISTS trg_population_count_token_insert ON IdentityToken;
CREATE TRIGGER trg_population_count_token_insert
    AFTER INSERT ON IdentityToken REFERENCING NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION population_count_tokens();
DROP TRIGGER IF EXISTS trg_population_count_token_update ON IdentityToken;
CREATE TRIGGER trg_population_count_token_update
    AFTER UPDATE ON IdentityToken REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION population_count_tokens();
DROP TRIGGER IF EXISTS trg_population_count_token_delete ON IdentityToken;
CREATE TRIGGER trg_population_count_token_delete
    AFTER DELETE ON IdentityToken REFERENCING OLD TABLE AS old_rows
    FOR EACH STATEMENT EXECUTE FUNCTION population_count_tokens();
DROP TRIGGER IF EXISTS trg_population_count_token_truncate ON IdentityToken;
CREATE TRIGGER trg_population_count_token_truncate
    AFTER TRUNCATE ON IdentityToken
    FOR EACH STATEMENT EXECUTE FUNCTION population_count_truncated();

DROP TRIGGER IF EXISTS trg_population_count_signature_insert ON TokenSignature;
CREATE TRIGGER trg_population_count_signature_insert
    AFTER INSERT ON TokenSignature REFERENCING NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION population_count_signatures();
DROP TRIGGER IF EXISTS trg_population_count_signature_update ON TokenSignature;
CREATE TRIGGER trg_population_count_signature_update
    AFTER UPDATE ON TokenSignature REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION population_count_signatures();
DROP TRIGGER IF EXISTS trg_population_count_signature_delete ON TokenSignature;
CREATE TRIGGER trg_population_count_signature_delete
    AFTER DELETE ON TokenSignature REFERENCING OLD TABLE AS old_rows
    FOR EACH STATEMENT EXECUTE FUNCTION population_count_signatures();
DROP TRIGGER IF EXISTS trg_population_count_signature_truncate ON TokenSignature;
CREATE TRIGGER trg_population_count_signature_truncate
    AFTER TRUNCATE ON TokenSignature
    FOR EACH STATEMENT EXECUTE FUNCTION population_count_truncated();

-- Definer routines are the owner's rights, lent: nobody's but the application role's
-- (09_grants.sql), and the recount not even its.
DO $$
DECLARE
    v_sig TEXT;
BEGIN
    FOR v_sig IN
        SELECT p.oid::regprocedure::text
          FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'public'
           AND p.proname IN ('uc_fold_population_counts', 'uc_rebuild_population_counts',
                             'population_count_tokens', 'population_count_signatures',
                             'population_count_truncated')
    LOOP
        EXECUTE format('REVOKE EXECUTE ON ROUTINE %s FROM PUBLIC', v_sig);
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
            EXECUTE format('GRANT EXECUTE ON ROUTINE %s TO polaris_app', v_sig);
        END IF;
    END LOOP;
END$$;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT SELECT ON PopulationCount, PopulationCountDelta TO polaris_app;
    END IF;
END$$;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        REVOKE INSERT, UPDATE, DELETE ON PopulationCount, PopulationCountDelta FROM polaris_app;
    END IF;
END$$;
DO $$
DECLARE
    v_sig TEXT;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        FOR v_sig IN
            SELECT p.oid::regprocedure::text
              FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'public' AND p.proname = 'uc_rebuild_population_counts'
        LOOP
            EXECUTE format('REVOKE EXECUTE ON ROUTINE %s FROM polaris_app', v_sig);
        END LOOP;
    END IF;
END$$;

-- Count what is already there.
SELECT uc_rebuild_population_counts();
