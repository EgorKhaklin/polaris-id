-- 2026-10-05-001: a recovery requested by an authority with no standing over the person is witnessed by
-- the person's original issuer (THREAT-MODEL).
--
-- uc9_initiate_recovery ties the requesting authority to nothing about the person, and the WITNESS
-- channel required only an authority other than the requester. So two authorities, B requesting and any
-- third C witnessing, could recover, and since 2026-10-02-006 sign, a credential for a person neither
-- ever issued to. One authority alone still could not.
--
-- REPLACE: uc9_record_recovery_channel's WITNESS branch. Standing is the issuer of the person's most
-- recent credential, or a non-PRIVATE authority whose jurisdiction is the person's or the person's
-- country (ISO 3166-2, enforced by CHECK on both tables). A requester without standing needs a witness
-- bound to that original issuer; a person with no credential at all can be recovered only by an
-- authority with jurisdictional standing. Same signature, so the grant stands. The body is
-- 05_procedures.sql's.
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
    v_original INTEGER;
    v_standing BOOLEAN;
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
        SELECT t.issuing_agency_id INTO v_original
          FROM IdentityToken t
         WHERE t.individual_id = v_req.claimed_individual_id
         ORDER BY t.issued_date DESC, t.token_id DESC
         LIMIT 1;
        SELECT v_req.requesting_agency_id = v_original
               OR (a.agency_type <> 'PRIVATE'
                   AND (a.jurisdiction = i.jurisdiction
                        OR a.jurisdiction = split_part(i.jurisdiction, '-', 1)))
          INTO v_standing
          FROM Agency a, Individual i
         WHERE a.agency_id = v_req.requesting_agency_id
           AND i.individual_id = v_req.claimed_individual_id;
        IF v_standing IS NOT TRUE AND v_agency IS DISTINCT FROM v_original THEN
            RAISE EXCEPTION 'Authority % has no standing over individual %, so the witness must be bound to the original issuer (%), not %',
                v_req.requesting_agency_id, v_req.claimed_individual_id,
                COALESCE(v_original::TEXT, 'none: no credential was ever issued'), v_agency
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
