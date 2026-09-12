-- ============================================================================
-- 2026-09-12-004-relying-party-weakened-three-valued.down.sql
--
-- Reverses v9.448. LOSSY: `weakened` cannot be NOT NULL while rows say NULL, so
-- every "the database could not rank this" is rewritten to FALSE -- which is the
-- exact claim the migration existed to stop the record making. After this, a
-- relying party swapped from one enrollment population to another, or from one
-- context to another, reads as a change that granted nothing.
--
-- Reload 06_triggers.sql afterwards to restore the boolean predicate and the gate
-- that goes with it; leaving the three-valued function against a NOT NULL column
-- makes every unrankable change raise instead of recording.
-- ============================================================================

UPDATE RelyingPartyEvent SET weakened = FALSE WHERE weakened IS NULL;
ALTER TABLE RelyingPartyEvent ALTER COLUMN weakened SET NOT NULL;

DROP INDEX IF EXISTS idx_rp_event_weakened;
CREATE INDEX IF NOT EXISTS idx_rp_event_weakened ON RelyingPartyEvent (recorded_at DESC)
    WHERE weakened;
