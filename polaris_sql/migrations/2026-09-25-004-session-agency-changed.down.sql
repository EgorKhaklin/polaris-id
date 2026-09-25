-- Reverts 2026-09-25-004. A session already ended for an authority change would violate the
-- narrower constraint, so those reasons are rewritten to 'operator' first.
UPDATE OperatorSession SET revoke_reason = 'operator' WHERE revoke_reason = 'agency_changed';
ALTER TABLE OperatorSession DROP CONSTRAINT IF EXISTS chk_opsession_revoke_reason;
ALTER TABLE OperatorSession ADD CONSTRAINT chk_opsession_revoke_reason
    CHECK (revoke_reason IS NULL OR revoke_reason IN
           ('logout', 'evicted', 'idle', 'deactivated',
            'network_policy', 'password_changed', 'operator', 'role_changed'));
