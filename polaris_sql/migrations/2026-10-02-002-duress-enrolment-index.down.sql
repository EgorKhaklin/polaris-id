-- 2026-10-02-002 down: drop the duress enrolment index.
DROP INDEX IF EXISTS idx_identitytoken_duress_enrolled;
