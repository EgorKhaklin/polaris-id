-- Reverts 2026-09-24-012.

DROP TRIGGER IF EXISTS trg_enrollment_event_by_recorder ON EnrollmentStatusEvent;
DROP FUNCTION IF EXISTS enforce_enrollment_status_written_by_its_recorder();
