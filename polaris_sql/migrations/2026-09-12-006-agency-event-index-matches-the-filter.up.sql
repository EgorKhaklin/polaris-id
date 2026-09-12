-- ============================================================================
-- 2026-09-12-006-agency-event-index-matches-the-filter.up.sql
--
-- The same shape as -005, found by extending that check from functions to indexes.
--
-- v9.440 made AgencyEvent.widened three-valued: NULL means the change moved an
-- authority's SCOPE and the database will not rank it. The assessor's filter became
-- `widened IS NOT FALSE`, and v9.443 corrected the partial index in 01_schema.sql to
-- match. Migration 2026-09-12-002-agency-events still carries `WHERE widened`, which
-- holds only the TRUE rows, so a database built by loading the SQL files and then
-- applying migrations has an index that cannot serve the query it exists for.
--
-- Not a correctness bug: `agency-history --widened-only` returns the right rows either
-- way, because PostgreSQL falls back to a sequential scan when the partial predicate
-- does not imply the query's. It is a divergence between what the schema says and what
-- a migrated database has, which is the thing -005's check exists to refuse.
--
-- 2026-09-12-002 is history and stays as it is; this supersedes it by running after.
--
-- phase: expand. Replaces an index; no table, column or constraint changes.
-- REVERSIBLE: the .down.sql restores `WHERE widened`.
-- ============================================================================

DROP INDEX IF EXISTS idx_agency_event_widened;
CREATE INDEX IF NOT EXISTS idx_agency_event_widened ON AgencyEvent (recorded_at DESC)
    WHERE widened IS NOT FALSE;
