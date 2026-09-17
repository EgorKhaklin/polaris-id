-- Revert 2026-09-17-001. The failure counter goes back to decaying only on a successful
-- login, which means failures accumulate toward a lockout with no time bound. Fail-closed,
-- so a revert is safe for availability of the control rather than for its accuracy.
ALTER TABLE AppUser DROP COLUMN IF EXISTS last_failed_login_at;
