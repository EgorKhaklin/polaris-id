-- ============================================================================
-- 2026-09-11-016-trusted-referee.down.sql
--
-- Revert: drop RefereeVouching and its indexes.
--
-- This destroys the record of which credentials rest on a named person's word.
-- After a deployment has enrolled anybody through a referee, that record is the
-- only way to answer "which enrollments did this referee touch?" when one is
-- found to have vouched falsely. Reverting then is not a rollback; it is an
-- erasure of the accountability the table exists to hold, and the credentials
-- outlive it.
--
-- Intended for pre-deployment rollback only.
-- ============================================================================

BEGIN;

DROP INDEX IF EXISTS idx_vouching_by_proofing;
DROP INDEX IF EXISTS idx_vouching_by_referee;
DROP TABLE IF EXISTS RefereeVouching;

COMMIT;
