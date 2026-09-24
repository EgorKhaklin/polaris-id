-- Reverts 2026-09-24-001. Refuses while any session was ended by a role change, because
-- dropping the value would make those recorded rows violate the constraint.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM OperatorSession WHERE revoke_reason = 'role_changed') THEN
        RAISE EXCEPTION 'OperatorSession holds sessions ended by a role change; cannot narrow '
                        'chk_opsession_revoke_reason back';
    END IF;
END$$;
ALTER TABLE OperatorSession DROP CONSTRAINT IF EXISTS chk_opsession_revoke_reason;
ALTER TABLE OperatorSession ADD CONSTRAINT chk_opsession_revoke_reason
    CHECK (revoke_reason IS NULL OR revoke_reason IN
           ('logout', 'evicted', 'idle', 'deactivated',
            'network_policy', 'password_changed', 'operator'));
