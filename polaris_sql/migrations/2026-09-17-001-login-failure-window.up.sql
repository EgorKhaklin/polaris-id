-- 2026-09-17-001: the login-failure window, which was documented and never measured.
--
-- `LOGIN_FAILURE_WINDOW_MIN` has been in polaris_web/security.py since the lockout was
-- written, and docs/operator/SECURITY-CONTROLS.md states the control as "5 failures WITHIN
-- 10 MINUTES locks the account for 15 minutes". Nothing compared it. The counter decayed
-- only on a SUCCESSFUL login, so failures a fortnight apart accumulated toward one lockout
-- and the window in the document described behaviour the system did not have.
--
-- The direction it was wrong in was fail-closed, which is why nobody noticed: the account
-- locked MORE readily than advertised, never less. A control stricter than its own
-- documentation is still one nobody can reason about, and it sat on the same state machine
-- as two defects that were not fail-closed (an account could be locked exactly once ever,
-- and the lock's deadline was compared against a different machine's clock).
--
-- One nullable column, no default needed: a NULL reads as "no failure recorded yet", which
-- is exactly what every existing row means.
ALTER TABLE AppUser ADD COLUMN IF NOT EXISTS last_failed_login_at TIMESTAMP;

COMMENT ON COLUMN AppUser.last_failed_login_at IS
    'When the most recent failed login was recorded. The failure counter restarts rather '
    'than incrementing when a new failure arrives more than LOGIN_FAILURE_WINDOW_MIN after '
    'this instant. Written by the same statement that moves failed_login_count, so the two '
    'cannot disagree. Cleared by a successful login alongside the counter.';
