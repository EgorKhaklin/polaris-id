-- 2026-09-24-011: the change records accept only what their recorders write.
--
-- The same block closes 06_triggers.sql for a fresh install; the reasoning is there.
CREATE OR REPLACE FUNCTION enforce_event_written_by_its_recorder()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF pg_trigger_depth() < 2 THEN
        RAISE EXCEPTION '% is written only by the trigger that records the change; a direct '
                        'INSERT would put an event in the record that nothing did', TG_TABLE_NAME
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    NEW.db_role := session_user;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_agency_event_by_recorder ON AgencyEvent;
CREATE TRIGGER trg_agency_event_by_recorder
    BEFORE INSERT ON AgencyEvent
    FOR EACH ROW EXECUTE FUNCTION enforce_event_written_by_its_recorder();
DROP TRIGGER IF EXISTS trg_app_user_event_by_recorder ON AppUserEvent;
CREATE TRIGGER trg_app_user_event_by_recorder
    BEFORE INSERT ON AppUserEvent
    FOR EACH ROW EXECUTE FUNCTION enforce_event_written_by_its_recorder();
DROP TRIGGER IF EXISTS trg_relying_party_event_by_recorder ON RelyingPartyEvent;
CREATE TRIGGER trg_relying_party_event_by_recorder
    BEFORE INSERT ON RelyingPartyEvent
    FOR EACH ROW EXECUTE FUNCTION enforce_event_written_by_its_recorder();
