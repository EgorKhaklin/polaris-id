-- 008 (P9.7, v9.347): RecoveryRequest becomes a fully schema-enforced audit of record.
-- ----------------------------------------------------------------------------
-- enforce_recovery_request_immutability (BEFORE trigger), P9.7 (v9.347):
-- RecoveryRequest is the 14th audit-of-record and was the ONE instance that
-- rested on procedure discipline rather than on the schema. uc9_complete_recovery
-- was the only sanctioned writer, but a raw UPDATE from a database session was
-- not refused, so the strongest statement the project could make about the
-- recovery ceremony was weaker than the one it makes about every other audit of
-- record. This closes it, in the shape of enforce_attestation_immutability.
--
-- Bounded mutation, all of it one way:
--   - identity and request fields never change;
--   - status leaves PENDING exactly once, to a terminal value, and a terminal
--     value never moves again;
--   - the four decision fields are written once, never rewritten, never un-set;
--   - the three out-of-band channels may be recorded while the request is
--     PENDING, and biometric_verified never goes back to FALSE;
--   - DELETE is refused outright.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_recovery_request_immutability()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'DELETE on RecoveryRequest is forbidden (audit-of-record for the recovery ceremony)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Identity and request fields are immutable.
    IF NEW.recovery_id            <> OLD.recovery_id
       OR NEW.claimed_individual_id <> OLD.claimed_individual_id
       OR NEW.requested_at          <> OLD.requested_at
       OR NEW.requesting_agency_id  <> OLD.requesting_agency_id
       OR NEW.requesting_user_id    <> OLD.requesting_user_id
       OR NEW.cooldown_expires_at   <> OLD.cooldown_expires_at THEN
        RAISE EXCEPTION
            'RecoveryRequest is append-only except for the out-of-band channels and the decision'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Status is one way out of PENDING, and terminal is terminal.
    IF NEW.status <> OLD.status THEN
        IF OLD.status <> 'PENDING' THEN
            RAISE EXCEPTION
                'RecoveryRequest.status is terminal at % and cannot be changed', OLD.status
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        IF NEW.status NOT IN ('APPROVED','REJECTED','EXPIRED') THEN
            RAISE EXCEPTION
                'RecoveryRequest.status may leave PENDING only for APPROVED, REJECTED or EXPIRED'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    END IF;

    -- The out-of-band channels are recorded before a decision, never after it,
    -- and a verified biometric channel never becomes unverified.
    IF OLD.status <> 'PENDING' THEN
        IF NEW.biometric_verified      IS DISTINCT FROM OLD.biometric_verified
           OR NEW.sworn_statement_hash    IS DISTINCT FROM OLD.sworn_statement_hash
           OR NEW.witness_agency_id       IS DISTINCT FROM OLD.witness_agency_id
           OR NEW.witness_co_sign_user_id IS DISTINCT FROM OLD.witness_co_sign_user_id THEN
            RAISE EXCEPTION
                'the out-of-band channels cannot be rewritten after a decision is recorded'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    END IF;
    IF OLD.biometric_verified AND NOT NEW.biometric_verified THEN
        RAISE EXCEPTION
            'biometric_verified cannot be un-set once recorded'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- The decision is written once. Never rewritten, never withdrawn.
    IF OLD.decided_at IS NOT NULL THEN
        IF NEW.decided_at          IS DISTINCT FROM OLD.decided_at
           OR NEW.decided_by_user_id IS DISTINCT FROM OLD.decided_by_user_id
           OR NEW.decision_reason    IS DISTINCT FROM OLD.decision_reason
           OR NEW.resulting_token_id IS DISTINCT FROM OLD.resulting_token_id THEN
            RAISE EXCEPTION
                'a recorded recovery decision cannot be rewritten or withdrawn'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    END IF;

    RETURN NEW;
END$$;

DROP TRIGGER IF EXISTS trg_recovery_request_immutable ON RecoveryRequest;
CREATE TRIGGER trg_recovery_request_immutable
    BEFORE UPDATE OR DELETE ON RecoveryRequest
    FOR EACH ROW EXECUTE FUNCTION enforce_recovery_request_immutability();
