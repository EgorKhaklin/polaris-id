-- 2026-09-24-002: three id spaces that ran out inside the planning horizon, widened to 64 bits.
--
-- polaris_web/capacity.py sizes every sequence against the roadmap's national targets
-- (350M persons, an enrollment surge of 200,000 a day) over a 25-year horizon, and
-- check_capacity_model fails a push on any that runs out. It read `CREATE TABLE IF NOT EXISTS X`
-- as a table named IF, and it skipped any table without a growth driver without a word:
-- thirty-one of forty sequences were never sized. Sized now, three 32-bit SERIALs run out:
--   EnrollmentStatusEvent.event_id  9.8 years (a NOT_ENROLLED row seeded per person, then
--                                              PENDING and ENROLLED)
--   EnrollmentEvidence.evidence_id  9.8 years (up to three evidence pieces per proofing)
--   HolderKeyEvent.event_id        14.7 years (a binding and a rotation per credential)
-- Nothing is slow when a sequence is exhausted: every insert on the path fails, and here the
-- path is enrollment.
--
-- Idempotent: a database created from 01_schema.sql after this change already has BIGINT.
-- widens: EnrollmentStatusEvent.event_id INTEGER -> BIGINT
-- widens: EnrollmentEvidence.evidence_id INTEGER -> BIGINT
-- widens: HolderKeyEvent.event_id INTEGER -> BIGINT
-- IndividualCurrentEnrollment and HolderKeyCurrent read these columns, and PostgreSQL will
-- not change a column type under a view, so both are dropped and recreated verbatim from
-- 03_view.sql and 01_schema.sql, and their grants restored.
DROP VIEW IF EXISTS IndividualCurrentEnrollment;
ALTER TABLE EnrollmentStatusEvent ALTER COLUMN event_id TYPE BIGINT;
ALTER TABLE EnrollmentEvidence    ALTER COLUMN evidence_id TYPE BIGINT;
DROP VIEW IF EXISTS HolderKeyCurrent;
ALTER TABLE HolderKeyEvent        ALTER COLUMN event_id TYPE BIGINT;
DO $$
DECLARE s TEXT;
BEGIN
    FOREACH s IN ARRAY ARRAY[
        pg_get_serial_sequence('enrollmentstatusevent', 'event_id'),
        pg_get_serial_sequence('enrollmentevidence', 'evidence_id'),
        pg_get_serial_sequence('holderkeyevent', 'event_id')]
    LOOP
        IF s IS NOT NULL THEN
            EXECUTE format('ALTER SEQUENCE %s AS BIGINT', s);
        END IF;
    END LOOP;
END$$;

CREATE OR REPLACE VIEW IndividualCurrentEnrollment AS
WITH latest AS (
    SELECT DISTINCT ON (individual_id)
           individual_id,
           status,
           transition_reason,
           recorded_by_agency_id,
           event_timestamp
    FROM   EnrollmentStatusEvent
    ORDER BY individual_id, event_timestamp DESC, event_id DESC
)
SELECT  i.individual_id,
        i.legal_name,
        i.jurisdiction,
        COALESCE(l.status, 'NOT_ENROLLED')             AS current_status,
        COALESCE(l.event_timestamp, i.enrollment_date) AS last_status_change,
        l.transition_reason                            AS last_transition_reason,
        l.recorded_by_agency_id                        AS last_recording_agency
FROM    Individual i
LEFT JOIN latest l USING (individual_id);

COMMENT ON VIEW IndividualCurrentEnrollment IS
  'Per-individual current enrollment status (R11-4). The latest '
  'EnrollmentStatusEvent row wins; individuals with no events default to '
  'NOT_ENROLLED via COALESCE — the absence is itself the default, not a '
  'positive flag. Implements PDF §9 population-coverage civic visibility.';
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON IndividualCurrentEnrollment TO polaris_app;
    END IF;
END$$;

CREATE OR REPLACE VIEW HolderKeyCurrent AS
SELECT DISTINCT ON (hke.token_id)
       hke.token_id,
       hke.public_key_hex,
       hke.algorithm,
       hke.event,
       hke.effective_at
  FROM HolderKeyEvent hke
 WHERE hke.effective_at <= CURRENT_TIMESTAMP
 ORDER BY hke.token_id, hke.effective_at DESC, hke.event_id DESC;

COMMENT ON VIEW HolderKeyCurrent IS
  'P9.1: the holder key in force for each credential right now. event = ''revoked'' means the '
  'holder has no usable key until a new one is bound.';
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT SELECT ON HolderKeyCurrent TO polaris_app;
    END IF;
END$$;
