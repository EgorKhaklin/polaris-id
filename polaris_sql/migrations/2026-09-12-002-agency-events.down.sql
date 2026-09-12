-- ============================================================================
-- 2026-09-12-002-agency-events.down.sql
--
-- Reverses v9.440: the root of the hierarchy goes back to having no trigger on it.
--
-- LOSSY, and loud about it. Dropping AgencyEvent discards the record of who created
-- each issuing authority, who raised the level it operates at, who moved the
-- jurisdiction it operates in, and the reasons they gave. There is nowhere else that
-- information lives, because before v9.440 it was not written down at all: every audit
-- table in the schema was byte-identical after creating an authority.
--
-- Running this also removes three rules. Creating an authority stops requiring a stated
-- reason. Rescoping one from a county to a nation stops requiring one. And DELETE on
-- Agency is permitted again, so an authority that issued credentials can be made never
-- to have existed while thirty-five tables still point at its id.
-- ============================================================================

DROP TRIGGER IF EXISTS trg_agency_audited ON Agency;
DROP TRIGGER IF EXISTS trg_agency_event_append_only ON AgencyEvent;
DROP FUNCTION IF EXISTS record_agency_change();

-- The append-only guard is gone, so the table can be dropped. This is the loss.
DROP TABLE IF EXISTS AgencyEvent;
