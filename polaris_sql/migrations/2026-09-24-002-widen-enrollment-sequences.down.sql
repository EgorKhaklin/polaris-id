-- Reverts 2026-09-24-002. Refuses once any of the three has issued an id past 32 bits,
-- because narrowing would then fail halfway or truncate the record.
DO $$
BEGIN
    IF (SELECT coalesce(max(event_id), 0) FROM EnrollmentStatusEvent) > 2147483647
       OR (SELECT coalesce(max(evidence_id), 0) FROM EnrollmentEvidence) > 2147483647
       OR (SELECT coalesce(max(event_id), 0) FROM HolderKeyEvent) > 2147483647 THEN
        RAISE EXCEPTION 'an id past 2147483647 has been issued; these columns cannot be narrowed';
    END IF;
END$$;
DO $$
DECLARE s TEXT;
BEGIN
    FOREACH s IN ARRAY ARRAY[
        pg_get_serial_sequence('enrollmentstatusevent', 'event_id'),
        pg_get_serial_sequence('enrollmentevidence', 'evidence_id'),
        pg_get_serial_sequence('holderkeyevent', 'event_id')]
    LOOP
        IF s IS NOT NULL THEN
            EXECUTE format('ALTER SEQUENCE %s AS INTEGER', s);
        END IF;
    END LOOP;
END$$;
DROP VIEW IF EXISTS IndividualCurrentEnrollment;
ALTER TABLE EnrollmentStatusEvent ALTER COLUMN event_id TYPE INTEGER;
ALTER TABLE EnrollmentEvidence    ALTER COLUMN evidence_id TYPE INTEGER;
DROP VIEW IF EXISTS HolderKeyCurrent;
ALTER TABLE HolderKeyEvent        ALTER COLUMN event_id TYPE INTEGER;

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
