-- 2026-10-02-001 down: drop the enrolment counts, their triggers and routines, and restore the
-- summary that grouped IndividualCurrentEnrollment on every call.
DROP TRIGGER IF EXISTS trg_enrollment_count_truncate ON EnrollmentCurrent;
DROP TRIGGER IF EXISTS trg_enrollment_count_follow_current ON EnrollmentCurrent;
DROP TRIGGER IF EXISTS trg_enrollment_current_follow_jurisdiction ON Individual;
DROP TRIGGER IF EXISTS trg_enrollment_current_follow_event ON EnrollmentStatusEvent;
DROP FUNCTION IF EXISTS enrollment_count_truncated();
DROP FUNCTION IF EXISTS enrollment_count_follow_current();
DROP FUNCTION IF EXISTS enrollment_current_follow_jurisdiction();
DROP FUNCTION IF EXISTS enrollment_current_follow_event();
DROP FUNCTION IF EXISTS uc_rebuild_enrollment_counts();
DROP FUNCTION IF EXISTS uc_fold_enrollment_counts();

DROP FUNCTION IF EXISTS civic_enrollment_summary(VARCHAR);
CREATE FUNCTION civic_enrollment_summary(
    p_jurisdiction VARCHAR(10) DEFAULT NULL
)
RETURNS TABLE (
    jurisdiction  VARCHAR(10),
    status        VARCHAR(20),
    n_individuals INTEGER
)
LANGUAGE plpgsql AS $$
BEGIN
    RETURN QUERY
    SELECT  ice.jurisdiction,
            ice.current_status,
            count(*)::INTEGER
    FROM    IndividualCurrentEnrollment ice
    WHERE   (p_jurisdiction IS NULL OR ice.jurisdiction = p_jurisdiction)
    GROUP BY ice.jurisdiction, ice.current_status
    ORDER BY ice.jurisdiction, ice.current_status;
END$$;
COMMENT ON FUNCTION civic_enrollment_summary IS
  'Per-jurisdiction counts of individuals in each enrollment status '
  '(R11-4 / M2-9). Counts only: per-individual enumeration is not a '
  'first-class query. Implements PDF §9 population-coverage civic-query '
  'requirement.';

DROP TABLE IF EXISTS EnrollmentCountDelta;
DROP TABLE IF EXISTS EnrollmentCount;
DROP TABLE IF EXISTS EnrollmentCurrent;
