-- ============================================================================
-- 2026-09-12-006-agency-event-index-matches-the-filter.down.sql
--
-- Restores `WHERE widened`, the partial index that holds only the rows the database
-- could rank. After this the index no longer covers the filter the operator tool runs,
-- so `agency-history --widened-only` falls back to a sequential scan.
-- ============================================================================

DROP INDEX IF EXISTS idx_agency_event_widened;
CREATE INDEX IF NOT EXISTS idx_agency_event_widened ON AgencyEvent (recorded_at DESC)
    WHERE widened;
