-- 2026-10-02-001: enrolment counts that cost the same at any population (lab/strategy/008, step 4).
--
-- ADD:
--   EnrollmentCurrent: each person's latest enrolment status beside their jurisdiction, the row
--     IndividualCurrentEnrollment derives from every event. The enrolment summary grouped that
--     view, finding every person's latest event on each call: 6.4 seconds at two million people.
--   EnrollmentCount, EnrollmentCountDelta: people by jurisdiction and status, kept the way
--     PopulationCount is (signed changes appended, folded in now and then; a reader sums both).
--   enrollment_current_follow_event(), enrollment_current_follow_jurisdiction(),
--     enrollment_count_follow_current(), enrollment_count_truncated(): the triggers that keep them.
--   uc_fold_enrollment_counts(): the application role may call it.
--   uc_rebuild_enrollment_counts(): rebuilds both from the tables under a SHARE lock; owner-only.
-- CHANGE:
--   civic_enrollment_summary(VARCHAR) reads the counts and returns n_individuals as BIGINT
--     (it was INTEGER, which overflows in a jurisdiction past 2^31 people). Same name, argument
--     and columns; the answer is the same as before at any population.
--
-- EXPAND: the previous release neither reads nor writes the new tables, and its writes to
-- Individual and EnrollmentStatusEvent fire the triggers like any other. Its call of
-- civic_enrollment_summary reads an int from the BIGINT column like any other.
-- LOCK: the closing rebuild SHARE-locks Individual and EnrollmentStatusEvent until this migration
-- commits, so writers wait for it: on a large population, apply it in a maintenance window.
-- REVERSIBLE: yes (the .down.sql drops every object here and restores the previous summary).

CREATE TABLE IF NOT EXISTS EnrollmentCurrent (
    individual_id   INTEGER     PRIMARY KEY REFERENCES Individual(individual_id),
    jurisdiction    VARCHAR(10) NOT NULL,
    status          VARCHAR(20) NOT NULL
        CHECK (status IN ('NOT_ENROLLED', 'PENDING_ENROLLMENT', 'ENROLLED', 'EXEMPT', 'LAPSED')),
    event_timestamp TIMESTAMP   NOT NULL,
    event_id        BIGINT      NOT NULL
);

CREATE TABLE IF NOT EXISTS EnrollmentCount (
    jurisdiction VARCHAR(10) NOT NULL,
    status       VARCHAR(20) NOT NULL,
    n            BIGINT      NOT NULL CHECK (n >= 0),
    PRIMARY KEY (jurisdiction, status)
);

CREATE TABLE IF NOT EXISTS EnrollmentCountDelta (
    delta_id     BIGSERIAL   PRIMARY KEY,
    jurisdiction VARCHAR(10) NOT NULL,
    status       VARCHAR(20) NOT NULL,
    n            BIGINT      NOT NULL CHECK (n <> 0)
);

COMMENT ON TABLE EnrollmentCurrent IS
  'Each person''s latest enrolment status and jurisdiction (lab/strategy/008): the row '
  'IndividualCurrentEnrollment derives from every event, kept by triggers on EnrollmentStatusEvent '
  'and Individual. Written only by the owner''s triggers and routines; the application role '
  'cannot read it (the summary needs only the totals).';
COMMENT ON TABLE EnrollmentCount IS
  'People by jurisdiction and enrolment status, exact at any population. Folded from '
  'EnrollmentCountDelta by uc_fold_enrollment_counts(); a reader sums both.';
COMMENT ON TABLE EnrollmentCountDelta IS
  'Signed changes to EnrollmentCount not yet folded in, appended by the triggers on '
  'EnrollmentCurrent. Append-only for writers.';

-- Move every visible change into the totals; one fold at a time, and a caller that finds one
-- running returns at once. The triggers call it now and then, so the changes stay few; a reader
-- sums the totals and the changes, so it need not.
CREATE OR REPLACE FUNCTION uc_fold_enrollment_counts()
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_folded BIGINT := 0;
BEGIN
    IF NOT pg_try_advisory_xact_lock(hashtext('polaris.enrollment.fold')) THEN
        RETURN 0;
    END IF;
    -- Update, then insert, as uc_fold_population_counts does: an upsert would check a decrement
    -- of an existing total against CHECK (n >= 0) as if it were a new row.
    WITH moved AS (
        DELETE FROM EnrollmentCountDelta
        RETURNING jurisdiction, status, n
    ), summed AS (
        SELECT jurisdiction, status, sum(n) AS n, count(*) AS deltas
          FROM moved
         GROUP BY jurisdiction, status
    ), updated AS (
        UPDATE EnrollmentCount c SET n = c.n + s.n
          FROM summed s
         WHERE c.jurisdiction = s.jurisdiction AND c.status = s.status AND s.n <> 0
        RETURNING 1
    ), inserted AS (
        INSERT INTO EnrollmentCount (jurisdiction, status, n)
        SELECT s.jurisdiction, s.status, s.n
          FROM summed s
         WHERE s.n <> 0
           AND NOT EXISTS (SELECT 1 FROM EnrollmentCount c
                            WHERE c.jurisdiction = s.jurisdiction AND c.status = s.status)
        RETURNING 1
    )
    SELECT COALESCE(sum(deltas), 0) INTO v_folded FROM summed;
    RETURN v_folded;
END$$;

COMMENT ON FUNCTION uc_fold_enrollment_counts() IS
  'Folds EnrollmentCountDelta into EnrollmentCount (lab/strategy/008). Idempotent and '
  'non-blocking: one fold at a time, and a caller that finds one running returns 0.';

-- Rebuild every person's latest status and the totals from Individual and EnrollmentStatusEvent:
-- the load scripts call it after the seed, the migration that adds the tables to fill them, and an
-- operator to reconcile. It SHARE-locks both tables, so writers wait until it commits; on a large
-- population that is a maintenance window, so the application role may not run it (09_grants.sql).
-- The per-row count trigger is off while EnrollmentCurrent is refilled, since the totals are
-- recounted from it in one pass; the ALTER TABLE is transactional, so a failed rebuild leaves the
-- trigger as it was.
CREATE OR REPLACE FUNCTION uc_rebuild_enrollment_counts()
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('polaris.enrollment.fold'));
    LOCK TABLE Individual, EnrollmentStatusEvent IN SHARE MODE;
    ALTER TABLE EnrollmentCurrent DISABLE TRIGGER trg_enrollment_count_follow_current;
    DELETE FROM EnrollmentCurrent;
    INSERT INTO EnrollmentCurrent (individual_id, jurisdiction, status, event_timestamp, event_id)
    SELECT i.individual_id, i.jurisdiction,
           COALESCE(l.status, 'NOT_ENROLLED'),
           COALESCE(l.event_timestamp, '-infinity'::TIMESTAMP),
           COALESCE(l.event_id, 0)
      FROM Individual i
      LEFT JOIN (SELECT DISTINCT ON (individual_id) individual_id, status, event_timestamp, event_id
                   FROM EnrollmentStatusEvent
                  ORDER BY individual_id, event_timestamp DESC, event_id DESC) l
             USING (individual_id);
    ALTER TABLE EnrollmentCurrent ENABLE TRIGGER trg_enrollment_count_follow_current;
    DELETE FROM EnrollmentCountDelta;
    DELETE FROM EnrollmentCount;
    INSERT INTO EnrollmentCount (jurisdiction, status, n)
    SELECT jurisdiction, status, count(*)
      FROM EnrollmentCurrent
     GROUP BY jurisdiction, status;
END$$;

COMMENT ON FUNCTION uc_rebuild_enrollment_counts() IS
  'Rebuilds EnrollmentCurrent and EnrollmentCount from Individual and EnrollmentStatusEvent under '
  'a SHARE lock (lab/strategy/008). Owner-only: a full pass over the population is a maintenance act.';

CREATE OR REPLACE FUNCTION enrollment_current_follow_event()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    -- The latest event wins, in the view's order: a late arrival with an earlier stamp is history,
    -- not the person's status. The jurisdiction is read only for a person's first row; after that
    -- the jurisdiction trigger keeps it.
    INSERT INTO EnrollmentCurrent AS c (individual_id, jurisdiction, status, event_timestamp, event_id)
    SELECT NEW.individual_id, i.jurisdiction, NEW.status, NEW.event_timestamp, NEW.event_id
      FROM Individual i WHERE i.individual_id = NEW.individual_id
    ON CONFLICT (individual_id) DO UPDATE
       SET status = EXCLUDED.status,
           event_timestamp = EXCLUDED.event_timestamp,
           event_id = EXCLUDED.event_id
     WHERE (c.event_timestamp, c.event_id) < (EXCLUDED.event_timestamp, EXCLUDED.event_id);
    RETURN NULL;
END$$;

DROP TRIGGER IF EXISTS trg_enrollment_current_follow_event ON EnrollmentStatusEvent;
CREATE TRIGGER trg_enrollment_current_follow_event
    AFTER INSERT ON EnrollmentStatusEvent
    FOR EACH ROW EXECUTE FUNCTION enrollment_current_follow_event();

CREATE OR REPLACE FUNCTION enrollment_current_follow_jurisdiction()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    UPDATE EnrollmentCurrent SET jurisdiction = NEW.jurisdiction
     WHERE individual_id = NEW.individual_id;
    RETURN NULL;
END$$;

DROP TRIGGER IF EXISTS trg_enrollment_current_follow_jurisdiction ON Individual;
CREATE TRIGGER trg_enrollment_current_follow_jurisdiction
    AFTER UPDATE OF jurisdiction ON Individual
    FOR EACH ROW WHEN (OLD.jurisdiction IS DISTINCT FROM NEW.jurisdiction)
    EXECUTE FUNCTION enrollment_current_follow_jurisdiction();

-- Each change to a person's (jurisdiction, status) as a signed change to the totals. A person is
-- never deleted (their first event refers to them), so a row leaves EnrollmentCurrent only by the
-- owner's hand; the rebuild does it with this trigger off, and any other delete is counted here.
CREATE OR REPLACE FUNCTION enrollment_count_follow_current()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO EnrollmentCountDelta (jurisdiction, status, n)
        VALUES (NEW.jurisdiction, NEW.status, 1);
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO EnrollmentCountDelta (jurisdiction, status, n)
        VALUES (OLD.jurisdiction, OLD.status, -1);
    ELSIF (OLD.jurisdiction, OLD.status) IS DISTINCT FROM (NEW.jurisdiction, NEW.status) THEN
        INSERT INTO EnrollmentCountDelta (jurisdiction, status, n)
        VALUES (OLD.jurisdiction, OLD.status, -1), (NEW.jurisdiction, NEW.status, 1);
    END IF;
    -- Now and then fold, so the changes stay few when nobody reads. A count must never stop a
    -- person's write: should the fold fail, the changes stay unfolded and the write goes on.
    IF random() < 0.002 THEN
        BEGIN
            PERFORM uc_fold_enrollment_counts();
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'enrolment counts not folded: %', SQLERRM;
        END;
    END IF;
    RETURN NULL;
END$$;

DROP TRIGGER IF EXISTS trg_enrollment_count_follow_current ON EnrollmentCurrent;
CREATE TRIGGER trg_enrollment_count_follow_current
    AFTER INSERT OR UPDATE OR DELETE ON EnrollmentCurrent
    FOR EACH ROW EXECUTE FUNCTION enrollment_count_follow_current();

-- TRUNCATE fires no row events, so it clears the totals it invalidates.
CREATE OR REPLACE FUNCTION enrollment_count_truncated()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    DELETE FROM EnrollmentCountDelta;
    DELETE FROM EnrollmentCount;
    RETURN NULL;
END$$;

DROP TRIGGER IF EXISTS trg_enrollment_count_truncate ON EnrollmentCurrent;
CREATE TRIGGER trg_enrollment_count_truncate
    AFTER TRUNCATE ON EnrollmentCurrent
    FOR EACH STATEMENT EXECUTE FUNCTION enrollment_count_truncated();

DROP FUNCTION IF EXISTS civic_enrollment_summary(VARCHAR);
CREATE FUNCTION civic_enrollment_summary(
    p_jurisdiction VARCHAR(10) DEFAULT NULL  -- NULL = all jurisdictions
)
RETURNS TABLE (
    jurisdiction  VARCHAR(10),
    status        VARCHAR(20),
    n_individuals BIGINT
)
LANGUAGE sql STABLE AS $$
    SELECT c.jurisdiction, c.status, sum(c.n)::BIGINT
      FROM (SELECT jurisdiction, status, n FROM EnrollmentCount
            UNION ALL
            SELECT jurisdiction, status, n FROM EnrollmentCountDelta) c
     WHERE p_jurisdiction IS NULL OR c.jurisdiction = p_jurisdiction
     GROUP BY c.jurisdiction, c.status
    HAVING sum(c.n) <> 0
     ORDER BY c.jurisdiction, c.status;
$$;

COMMENT ON FUNCTION civic_enrollment_summary IS
  'Per-jurisdiction counts of individuals in each enrollment status '
  '(R11-4 / M2-9), from the maintained EnrollmentCount (lab/strategy/008). Counts only: '
  'per-individual enumeration is not a first-class query. Implements PDF §9 '
  'population-coverage civic-query requirement.';

REVOKE SELECT, INSERT, UPDATE, DELETE ON EnrollmentCurrent FROM polaris_app;
REVOKE INSERT, UPDATE, DELETE ON EnrollmentCount, EnrollmentCountDelta FROM polaris_app;
DO $$
DECLARE
    v_sig TEXT;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        FOR v_sig IN
            SELECT p.oid::regprocedure::text
              FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'public' AND p.proname = 'uc_rebuild_enrollment_counts'
        LOOP
            EXECUTE format('REVOKE EXECUTE ON ROUTINE %s FROM polaris_app', v_sig);
        END LOOP;
    END IF;
END$$;

SELECT uc_rebuild_enrollment_counts();
