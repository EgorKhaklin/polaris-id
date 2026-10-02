-- 2026-10-02-003 down: drop the SUCCESS rules trigger and its function. The verification form keeps
-- its own checks; the database stops refusing the rows a direct INSERT could write.
DROP TRIGGER IF EXISTS trg_verification_success_rules ON VerificationEvent;
DROP FUNCTION IF EXISTS enforce_verification_success_rules();
