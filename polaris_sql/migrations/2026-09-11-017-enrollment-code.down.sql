-- ============================================================================
-- 2026-09-11-017-enrollment-code.down.sql
--
-- Revert: drop EnrollmentCode and its indexes.
--
-- Outstanding codes become unredeemable, which is the correct failure: a code
-- whose record is gone cannot be checked for expiry, single use or its attempt
-- count, and honouring one on the strength of the applicant presenting it would
-- be accepting a secret with no lifecycle behind it.
--
-- Intended for pre-deployment rollback.
-- ============================================================================

BEGIN;

DROP INDEX IF EXISTS idx_enrollment_code_individual;
DROP INDEX IF EXISTS idx_enrollment_code_hash;
DROP TABLE IF EXISTS EnrollmentCode;

COMMIT;
