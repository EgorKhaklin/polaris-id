-- Reverts 2026-09-24-011.

DROP TRIGGER IF EXISTS trg_agency_event_by_recorder ON AgencyEvent;
DROP TRIGGER IF EXISTS trg_app_user_event_by_recorder ON AppUserEvent;
DROP TRIGGER IF EXISTS trg_relying_party_event_by_recorder ON RelyingPartyEvent;
DROP FUNCTION IF EXISTS enforce_event_written_by_its_recorder();
