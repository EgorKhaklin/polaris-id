-- 2026-10-02-006: a recovered credential is signed by the signing module (CORE-BUG).
--
-- uc9_complete_recovery wrote 'UC9_RECOVERY_PLACEHOLDER_<recovery>_TOKEN_<token>' as the new
-- credential's signature: bytes no algorithm made, under the algorithm the operator named, so the
-- credential an approved recovery handed back verified under nothing (GET /api/tokens/<id>/verify:
-- signature_valid false), with real signing or without it.
--
-- REPLACE: the procedure takes p_signature_bytes and p_signing_public_key_hex from its caller,
-- which signs the new token value through pqc_signing.credential_signature with the requesting
-- authority's key, and refuses an APPROVED decision without a signature. The body is
-- 05_procedures.sql's, so a database built by load-then-migrate runs the same procedure.
-- DROP: the ten-parameter signature, first: left beside the new one, a call without the two
-- trailing arguments would match both.
-- GRANT: EXECUTE for the application role alone, as 09_grants.sql does for every definer routine.
--
-- EXPAND: no. A caller of the old signature fails until it is updated; the route and the CLI in
-- this release pass the signature. A previous release still serving during a rolling deploy cannot
-- approve a recovery until it is replaced: it refuses, rather than issuing a credential that does
-- not verify.
-- REVERSIBLE: yes; the down file restores the ten-parameter procedure from 2026-09-25-007.
DROP PROCEDURE IF EXISTS uc9_complete_recovery(INTEGER, INTEGER, VARCHAR, TEXT, VARCHAR, VARCHAR, INTEGER, VARCHAR, VARCHAR, VARCHAR);

CREATE OR REPLACE PROCEDURE uc9_complete_recovery(
    p_recovery_id        INTEGER,
    p_deciding_user      INTEGER,
    p_decision           VARCHAR,   -- 'APPROVED' or 'REJECTED'
    p_reason             TEXT,
    p_new_token_value    VARCHAR DEFAULT NULL,
    p_new_serial         VARCHAR DEFAULT NULL,
    p_algorithm_id       INTEGER DEFAULT NULL,
    p_biometric_binding  VARCHAR DEFAULT NULL,
    p_liveness_check     VARCHAR DEFAULT NULL,
    p_published_location VARCHAR DEFAULT NULL,
    p_signature_bytes    BYTEA DEFAULT NULL,
    p_signing_public_key_hex VARCHAR DEFAULT NULL
)
LANGUAGE plpgsql
-- SECURITY DEFINER (1.0.0-rc.19): this procedure moves a token into REVOKED, and
-- trg_enforce_revocation_velocity admits that transition only when the current role owns
-- the revocation procedures. Before rc.19 the trigger admitted it whenever the session had
-- set polaris.revoke_check_done, which any session holding polaris_app could set for itself
-- and then revoke with a plain UPDATE, skipping the rate bound and the co-signer rule. The
-- actor is authenticated by parameter, never by current_user, so running as the owner does
-- not weaken any gate; search_path is pinned so the elevated body cannot be redirected.
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_individual_id     INTEGER;
    v_requesting_agency INTEGER;
    v_requesting_user   INTEGER;
    v_status            VARCHAR(20);
    v_cooldown_at       TIMESTAMP;
    v_biometric         BOOLEAN;
    v_sworn             VARCHAR(128);
    v_witness_agency    INTEGER;
    v_witness_user      INTEGER;
    v_role              VARCHAR(20);
    v_active_flag       BOOLEAN;
    v_lost_token        RECORD;
    v_new_token_id      INTEGER;
BEGIN
    -- C9: serialize concurrent completions of the same recovery (and any
    -- other recoveries for the same individual). Two threads racing this
    -- procedure for the same recovery_id would each pass the cool-down +
    -- three-channel CHECKs and both attempt the UPDATE+INSERT chain; the
    -- per-individual advisory lock makes them wait for each other so the
    -- second sees the post-commit APPROVED state and aborts cleanly.
    PERFORM pg_advisory_xact_lock(
        hashtext('polaris.recovery.' ||
            (SELECT claimed_individual_id::TEXT
             FROM RecoveryRequest WHERE recovery_id = p_recovery_id)));

    -- Belt-and-suspenders: deciding user must hold admin role.
    SELECT role, is_active INTO v_role, v_active_flag
    FROM AppUser WHERE user_id = p_deciding_user;
    IF NOT FOUND OR v_role <> 'admin' OR v_active_flag <> TRUE THEN
        RAISE EXCEPTION
            'Recovery decision requires admin role (user % has role=%)',
            p_deciding_user, COALESCE(v_role, 'NONE')
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- SECOND of two sufficient mechanisms, and measured as such on 2026-09-14:
    -- dropping this clause leaves all 866 tests green, dropping the advisory lock
    -- above leaves all 866 green, dropping BOTH turns the suite red. The advisory
    -- lock on claimed_individual_id already serializes every caller that could
    -- collide here, because uq_one_pending_recovery_per_individual allows one
    -- PENDING recovery per individual. Keep both: a green suite after removing
    -- either one says the other covered it, not that the clause was dead.
    -- Load the recovery request with FOR UPDATE so we observe the
    -- post-lock state if another thread already mutated it.
    SELECT claimed_individual_id, requesting_agency_id, requesting_user_id,
           status, cooldown_expires_at, biometric_verified,
           sworn_statement_hash, witness_agency_id, witness_co_sign_user_id
      INTO v_individual_id, v_requesting_agency, v_requesting_user,
           v_status, v_cooldown_at, v_biometric,
           v_sworn, v_witness_agency, v_witness_user
    FROM RecoveryRequest
    WHERE recovery_id = p_recovery_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Recovery request % does not exist', p_recovery_id;
    END IF;
    IF v_status <> 'PENDING' THEN
        RAISE EXCEPTION
            'Recovery request % is already in status % (not PENDING)',
            p_recovery_id, v_status;
    END IF;

    -- Approver ≠ requester (also CHECK on the table, but procedure errors
    -- earlier with a clearer message).
    IF p_deciding_user = v_requesting_user THEN
        RAISE EXCEPTION
            'Approver (user %) must differ from requester (user %)',
            p_deciding_user, v_requesting_user;
    END IF;

    -- Validate decision argument.
    IF p_decision NOT IN ('APPROVED', 'REJECTED') THEN
        RAISE EXCEPTION 'Decision must be APPROVED or REJECTED, got %',
            p_decision;
    END IF;

    IF p_decision = 'APPROVED' THEN
        -- Cool-down check (also enforced by approved_after_cooldown CHECK).
        IF CURRENT_TIMESTAMP < v_cooldown_at THEN
            RAISE EXCEPTION
                'Cool-down has not expired (until %); cannot approve yet',
                v_cooldown_at
                USING ERRCODE = 'check_violation';
        END IF;

        -- Three-channel check (also enforced by approved_requires_three_channels CHECK).
        IF v_biometric IS NOT TRUE OR v_sworn IS NULL
           OR v_witness_agency IS NULL OR v_witness_user IS NULL THEN
            RAISE EXCEPTION
                'APPROVED requires all three OOB channels (biometric, sworn statement, witness agency co-sign)'
                USING ERRCODE = 'check_violation';
        END IF;

        -- Separation of duties: the witness co-signer is the third independent
        -- channel, so it cannot be the approver or the requester. Without this,
        -- one compromised admin can self-witness AND self-approve, collapsing
        -- the "three independent channels" multiplicative cost to a single
        -- actor. uc8_revoke_token enforces the same co-signer-must-differ rule
        -- on the exit (revocation) leg; this is the entry leg. Also backed by
        -- the witness_differs_from_parties CHECK on RecoveryRequest.
        IF v_witness_user = p_deciding_user OR v_witness_user = v_requesting_user THEN
            RAISE EXCEPTION
                'Witness co-signer (user %) must differ from both the approver (%) and the requester (%)',
                v_witness_user, p_deciding_user, v_requesting_user
                USING ERRCODE = 'check_violation';
        END IF;

        -- Validate the new-token parameters.
        IF p_new_token_value IS NULL OR p_new_serial IS NULL
           OR p_algorithm_id IS NULL OR p_biometric_binding IS NULL
           OR p_liveness_check IS NULL OR p_published_location IS NULL THEN
            RAISE EXCEPTION
                'APPROVED recovery requires new token parameters '
                '(p_new_token_value, p_new_serial, p_algorithm_id, '
                'p_biometric_binding, p_liveness_check, p_published_location)';
        END IF;
        -- The recovered credential is signed like any other: by the signing module, over its
        -- token value, by the requesting authority's key. Until 2026-10-02 this procedure wrote
        -- 'UC9_RECOVERY_PLACEHOLDER_...' as the signature, bytes no algorithm made, so the
        -- credential a recovery handed back verified under nothing.
        IF p_signature_bytes IS NULL THEN
            RAISE EXCEPTION
                'APPROVED recovery requires the new credential''s signature (p_signature_bytes), '
                'made by the signing module over p_new_token_value'
                USING ERRCODE = 'check_violation';
        END IF;

        -- Step 1: invalidate all of the holder's existing non-terminal tokens
        -- and publish each to RevocationList. ACTIVE tokens go to LOST (lost by
        -- recovery); RESERVE tokens go to REVOKED — the ONLY legal terminal edge
        -- from RESERVE (RESERVE->LOST is not a legal transition, so the prior
        -- blanket ->LOST aborted the whole recovery for any holder whose only
        -- surviving token was a reserve, which is exactly the catastrophic-loss
        -- case UC-9 exists to serve). DORMANT is not produced by any procedure,
        -- so it is out of scope. The RESERVE->REVOKED edge trips
        -- enforce_revocation_velocity_bound unless this sanctioned path opts out
        -- the way uc4/uc8 do.
        PERFORM set_config('polaris.actor_agency_id', v_requesting_agency::TEXT, true);
        PERFORM set_config('polaris.reason_code',
            'LOST_BY_RECOVERY [RECOVERY:' || p_recovery_id::TEXT || ']', true);

        FOR v_lost_token IN
            SELECT token_id, status FROM IdentityToken
            WHERE individual_id = v_individual_id
              AND status IN ('ACTIVE','RESERVE')
        LOOP
            IF v_lost_token.status = 'RESERVE' THEN
                PERFORM set_config('polaris.revoke_check_done', '1', true);
                UPDATE IdentityToken
                   SET status = 'REVOKED'
                 WHERE token_id = v_lost_token.token_id;

                INSERT INTO RevocationList
                    (token_id, revoked_by_agency_id, effective_date,
                     reason_code, published_location)
                VALUES
                    (v_lost_token.token_id, v_requesting_agency, polaris_utc_date(),
                     'SUPERSEDED', p_published_location);
            ELSE
                UPDATE IdentityToken
                   SET status = 'LOST'
                 WHERE token_id = v_lost_token.token_id;

                INSERT INTO RevocationList
                    (token_id, revoked_by_agency_id, effective_date,
                     reason_code, published_location)
                VALUES
                    (v_lost_token.token_id, v_requesting_agency, polaris_utc_date(),
                     'LOST', p_published_location);
            END IF;
        END LOOP;

        -- Step 2: insert the new IdentityToken. predecessor_token_id is
        -- NULL because the prior chain was lost (distinct from UC-4's
        -- reserve activation, which DOES set predecessor). The auto-audit
        -- trigger will emit a lifecycle row with the recovery tag once
        -- we set reason_code below and UPDATE the new token's status.
        INSERT INTO IdentityToken
            (token_value, physical_serial, hardware_model,
             biometric_binding_type, individual_id, issuing_agency_id,
             algorithm_id, status, issued_date, expiration_date,
             liveness_check_type)
        VALUES
            (p_new_token_value, p_new_serial, 'TitanQ-3',
             p_biometric_binding, v_individual_id, v_requesting_agency,
             p_algorithm_id, 'RESERVE', CURRENT_TIMESTAMP,
             (polaris_utc_date() + INTERVAL '10 years')::DATE,
             p_liveness_check)
        RETURNING token_id INTO v_new_token_id;

        -- R11-1 / M2-6: the new credential's TokenSignature row, as issuance stores one: the
        -- caller's signature and the key it was made by (NULL for the placeholder, which has
        -- none). The lifecycle row this procedure writes below tags the recovery.
        INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes, signing_public_key_hex)
        VALUES (v_new_token_id, p_algorithm_id, p_signature_bytes, p_signing_public_key_hex);

        -- Step 3: promote the new token to ACTIVE with the recovery tag.
        PERFORM set_config('polaris.reason_code',
            'RECOVERY_ISSUED [RECOVERY:' || p_recovery_id::TEXT || ']', true);
        UPDATE IdentityToken
           SET status = 'ACTIVE',
               activated_date = CURRENT_TIMESTAMP,
               biometric_enrolled_date = CURRENT_TIMESTAMP,
               enrollment_witness_agency_id = v_witness_agency
         WHERE token_id = v_new_token_id;

        -- Step 4: close out the RecoveryRequest.
        UPDATE RecoveryRequest
           SET status = 'APPROVED',
               decided_at = CURRENT_TIMESTAMP,
               decided_by_user_id = p_deciding_user,
               decision_reason = p_reason,
               resulting_token_id = v_new_token_id
         WHERE recovery_id = p_recovery_id;

        RAISE NOTICE 'Recovery #% APPROVED; new ACTIVE token #%',
            p_recovery_id, v_new_token_id;

    ELSE  -- REJECTED
        UPDATE RecoveryRequest
           SET status = 'REJECTED',
               decided_at = CURRENT_TIMESTAMP,
               decided_by_user_id = p_deciding_user,
               decision_reason = p_reason
         WHERE recovery_id = p_recovery_id;

        RAISE NOTICE 'Recovery #% REJECTED', p_recovery_id;
    END IF;
END$$;

COMMENT ON PROCEDURE uc9_complete_recovery(INTEGER, INTEGER, VARCHAR, TEXT,
    VARCHAR, VARCHAR, INTEGER, VARCHAR, VARCHAR, VARCHAR, BYTEA, VARCHAR) IS
  'UC-9 phase 2: transition a PENDING RecoveryRequest to APPROVED or '
  'REJECTED. APPROVED requires admin role, expired cool-down, three OOB '
  'channels, full new-token parameters and the new credential''s signature, '
  'made by the signing module. Old non-terminal tokens '
  'transition to LOST and publish to RevocationList (UC-4 pattern). '
  'Serializes per-individual via pg_advisory_xact_lock (C9 correctness).';

DO $grant$
BEGIN
    REVOKE EXECUTE ON PROCEDURE uc9_complete_recovery(INTEGER, INTEGER, VARCHAR, TEXT, VARCHAR, VARCHAR, INTEGER, VARCHAR, VARCHAR, VARCHAR, BYTEA, VARCHAR) FROM PUBLIC;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT EXECUTE ON PROCEDURE uc9_complete_recovery(INTEGER, INTEGER, VARCHAR, TEXT, VARCHAR, VARCHAR, INTEGER, VARCHAR, VARCHAR, VARCHAR, BYTEA, VARCHAR) TO polaris_app;
    END IF;
END$grant$;
