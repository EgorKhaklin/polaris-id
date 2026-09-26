-- 2026-09-26-001: the recovery ceremony's three channels get a path in the product.
-- Since rc.54 only the schema owner could record them, so no recovery could be approved through
-- the application. Adds the attribution columns and uc9_record_recovery_channel.

ALTER TABLE RecoveryRequest ADD COLUMN IF NOT EXISTS biometric_recorded_by INTEGER REFERENCES AppUser(user_id);
ALTER TABLE RecoveryRequest ADD COLUMN IF NOT EXISTS sworn_recorded_by     INTEGER REFERENCES AppUser(user_id);

-- ----------------------------------------------------------------------------
-- uc9_record_recovery_channel, 1.0.0-rc.60. Records one of the recovery ceremony's three
-- out-of-band channels on a PENDING request, attributed to the user who records it.
-- Since rc.54 the application role cannot UPDATE RecoveryRequest, which closed the door through
-- which one role could set all three channels at once; it also left no path in the product to
-- record them, so no recovery could reach APPROVED without the schema owner at a psql prompt.
-- This is that path, gated per channel:
--   BIOMETRIC  an active operator or admin, not the requester, attests the biometric check;
--   SWORN      an active operator or admin, not the requester, records the statement's SHA-256;
--   WITNESS    the witness co-signs as themselves: an active operator or admin bound to an
--              authority other than the requesting one (the independent institution).
-- Each channel is recorded once. uc9_complete_recovery still requires all three, the cool-down,
-- and an admin approver who is neither the requester nor the witness.
-- SECURITY DEFINER because the application role holds no UPDATE on RecoveryRequest; the actor is
-- authenticated by parameter, never by current_user, and search_path is pinned.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE uc9_record_recovery_channel(
    p_recovery_id    INTEGER,
    p_recording_user INTEGER,
    p_channel        VARCHAR,
    p_sworn_hash     VARCHAR DEFAULT NULL
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_req      RecoveryRequest%ROWTYPE;
    v_role     VARCHAR(20);
    v_active   BOOLEAN;
    v_agency   INTEGER;
BEGIN
    SELECT role, is_active, agency_id INTO v_role, v_active, v_agency
      FROM AppUser WHERE user_id = p_recording_user;
    IF NOT FOUND OR v_active IS NOT TRUE OR v_role NOT IN ('admin', 'operator') THEN
        RAISE EXCEPTION 'Recording a recovery channel requires an active operator or admin (user %)',
            p_recording_user USING ERRCODE = 'insufficient_privilege';
    END IF;

    SELECT * INTO v_req FROM RecoveryRequest WHERE recovery_id = p_recovery_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Recovery request % does not exist', p_recovery_id;
    END IF;
    IF v_req.status <> 'PENDING' THEN
        RAISE EXCEPTION 'Recovery request % is % (channels are recorded only while PENDING)',
            p_recovery_id, v_req.status USING ERRCODE = 'check_violation';
    END IF;
    IF p_recording_user = v_req.requesting_user_id THEN
        RAISE EXCEPTION 'The requester (user %) cannot record a channel of their own request',
            p_recording_user USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF p_channel = 'BIOMETRIC' THEN
        IF v_req.biometric_verified THEN
            RAISE EXCEPTION 'The biometric channel of request % is already recorded', p_recovery_id
                USING ERRCODE = 'check_violation';
        END IF;
        UPDATE RecoveryRequest
           SET biometric_verified = TRUE, biometric_recorded_by = p_recording_user
         WHERE recovery_id = p_recovery_id;
    ELSIF p_channel = 'SWORN' THEN
        IF v_req.sworn_statement_hash IS NOT NULL THEN
            RAISE EXCEPTION 'The sworn-statement channel of request % is already recorded', p_recovery_id
                USING ERRCODE = 'check_violation';
        END IF;
        IF p_sworn_hash IS NULL OR p_sworn_hash !~ '^[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'A sworn statement is recorded as the SHA-256 of the document, 64 lowercase hex characters'
                USING ERRCODE = 'check_violation';
        END IF;
        UPDATE RecoveryRequest
           SET sworn_statement_hash = p_sworn_hash, sworn_recorded_by = p_recording_user
         WHERE recovery_id = p_recovery_id;
    ELSIF p_channel = 'WITNESS' THEN
        IF v_req.witness_agency_id IS NOT NULL THEN
            RAISE EXCEPTION 'The witness channel of request % is already recorded', p_recovery_id
                USING ERRCODE = 'check_violation';
        END IF;
        IF v_agency IS NULL OR v_agency = v_req.requesting_agency_id THEN
            RAISE EXCEPTION 'A witness co-signs for an authority other than the requesting one (user % is bound to %)',
                p_recording_user, COALESCE(v_agency::TEXT, 'no authority')
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        UPDATE RecoveryRequest
           SET witness_agency_id = v_agency, witness_co_sign_user_id = p_recording_user
         WHERE recovery_id = p_recovery_id;
    ELSE
        RAISE EXCEPTION 'Channel must be BIOMETRIC, SWORN or WITNESS, got %', p_channel;
    END IF;
END;
$$;
