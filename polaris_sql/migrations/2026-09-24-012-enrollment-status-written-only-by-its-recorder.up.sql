-- 2026-09-24-012: a person's enrollment status is written only by its recorder or the owner.
--
-- The same block closes 06_triggers.sql for a fresh install; the reasoning is there.
CREATE OR REPLACE FUNCTION enforce_enrollment_status_written_by_its_recorder()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF pg_trigger_depth() < 2
       AND session_user::name <> (SELECT pg_get_userbyid(relowner) FROM pg_class
                                   WHERE oid = 'EnrollmentStatusEvent'::regclass) THEN
        RAISE EXCEPTION 'EnrollmentStatusEvent is written only by the trigger that records an '
                        'enrollment, or by the owner; a direct INSERT would set a person''s '
                        'enrollment status that nothing established'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_enrollment_event_by_recorder ON EnrollmentStatusEvent;
CREATE TRIGGER trg_enrollment_event_by_recorder
    BEFORE INSERT ON EnrollmentStatusEvent
    FOR EACH ROW EXECUTE FUNCTION enforce_enrollment_status_written_by_its_recorder();
