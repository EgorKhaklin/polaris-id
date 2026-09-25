-- 2026-09-25-004: a session ended by a change of its account's authority binding can be recorded.
--
-- validate_session now ends a live session whose account was bound to another authority (or
-- bound, or unbound) while it was live, as it has ended one whose role changed since 2026-09-17,
-- writing revoke_reason 'agency_changed'. 2026-09-24-001 is the reason this migration exists: the
-- role change was taught to the code before the constraint, and every request from such a
-- session raised a CheckViolation instead of ending it.
ALTER TABLE OperatorSession DROP CONSTRAINT IF EXISTS chk_opsession_revoke_reason;
ALTER TABLE OperatorSession ADD CONSTRAINT chk_opsession_revoke_reason
    CHECK (revoke_reason IS NULL OR revoke_reason IN
           ('logout', 'evicted', 'idle', 'deactivated',
            'network_policy', 'password_changed', 'operator', 'role_changed', 'agency_changed'));
