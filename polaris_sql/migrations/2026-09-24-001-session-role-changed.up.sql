-- 2026-09-24-001: a session ended by a role change can be recorded as ended.
--
-- On 2026-09-17 (940af89) validate_session learned to end a live session whose account's
-- role changed while it was live, writing revoke_reason 'role_changed'. The constraint on
-- OperatorSession.revoke_reason was never widened to admit it. Measured: after a role change
-- every request from the old session raised CheckViolation in the before_request hook. The
-- UPDATE rolled back, so the session was never revoked and SESSION_REVOKED was never audited;
-- the request failed with a server error instead of ending the session and redirecting. No
-- test changed a role during a live session: a held-out mutation that deleted the role-change
-- branch survived every suite, and the test written for it is what found this.
ALTER TABLE OperatorSession DROP CONSTRAINT IF EXISTS chk_opsession_revoke_reason;
ALTER TABLE OperatorSession ADD CONSTRAINT chk_opsession_revoke_reason
    CHECK (revoke_reason IS NULL OR revoke_reason IN
           ('logout', 'evicted', 'idle', 'deactivated',
            'network_policy', 'password_changed', 'operator', 'role_changed'));
