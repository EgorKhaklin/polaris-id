-- 2026-09-24-004: the revocation gate is a role, not a setting the caller can set.
--
-- trg_enforce_revocation_velocity made uc8_revoke_token the only way into REVOKED by admitting
-- the transition when the session had set polaris.revoke_check_done. Any session can set a
-- setting: a polaris_app session set it and revoked with a plain UPDATE, skipping the rate
-- bound and the co-signer rule. The three procedures that set it (uc4_activate_reserve,
-- uc8_revoke_token, uc9_complete_recovery) now run SECURITY DEFINER with a pinned
-- search_path, and the trigger honours the setting only when the current role owns
-- uc8_revoke_token. uc8 also reads the default bound from the DATABASE's setting through
-- polaris_database_setting(), so a session can no longer loosen the bound it is about to be
-- held to. Bodies are copied from 05_procedures.sql and 06_triggers.sql, which carry the same
-- change for a fresh install.


CREATE OR REPLACE FUNCTION polaris_database_setting(p_name TEXT)
RETURNS TEXT
LANGUAGE sql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT o.option_value
      FROM pg_db_role_setting s
      JOIN pg_database d ON d.oid = s.setdatabase
     CROSS JOIN LATERAL pg_options_to_table(s.setconfig) o
     WHERE d.datname = current_database()
       AND s.setrole = 0
       AND o.option_name = p_name
$$;

CREATE OR REPLACE FUNCTION uc4_activate_reserve(
    p_lost_token_id      INTEGER,
    p_actor_agency_id    INTEGER,
    p_reason_code        VARCHAR(40),
    p_reserve_token_id   INTEGER,
    p_published_location VARCHAR(300)
) RETURNS INTEGER
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
    v_lost_individual_id     INTEGER;
    v_reserve_individual_id  INTEGER;
    v_lost_status            VARCHAR(20);
    v_reserve_status         VARCHAR(20);
    v_terminal_status        VARCHAR(20);
    v_lifecycle_event_type   VARCHAR(20);
BEGIN
    -- Validate: lost token is currently ACTIVE.
    SELECT individual_id, status INTO v_lost_individual_id, v_lost_status
    FROM IdentityToken WHERE token_id = p_lost_token_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Lost token % does not exist', p_lost_token_id
            USING ERRCODE = 'no_data_found';
    END IF;
    IF v_lost_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'Token % is not ACTIVE (current status: %)',
            p_lost_token_id, v_lost_status
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Validate: reserve token is currently RESERVE and belongs to same individual.
    SELECT individual_id, status INTO v_reserve_individual_id, v_reserve_status
    FROM IdentityToken WHERE token_id = p_reserve_token_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Reserve token % does not exist', p_reserve_token_id
            USING ERRCODE = 'no_data_found';
    END IF;
    IF v_reserve_status <> 'RESERVE' THEN
        RAISE EXCEPTION 'Token % is not in RESERVE state (current status: %)',
            p_reserve_token_id, v_reserve_status
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF v_reserve_individual_id <> v_lost_individual_id THEN
        RAISE EXCEPTION 'Reserve token % belongs to a different individual than lost token %',
            p_reserve_token_id, p_lost_token_id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    -- Map reason_code to terminal status and lifecycle event_type.
    v_terminal_status := CASE p_reason_code
        WHEN 'LOST'         THEN 'LOST'
        WHEN 'STOLEN'       THEN 'LOST'
        WHEN 'COMPROMISED'  THEN 'REVOKED'
        WHEN 'SUPERSEDED'   THEN 'REVOKED'
        WHEN 'ADMINISTRATIVE' THEN 'REVOKED'
        ELSE 'REVOKED'
    END;
    v_lifecycle_event_type := CASE v_terminal_status
        WHEN 'LOST'    THEN 'LOST'
        WHEN 'REVOKED' THEN 'REVOKED'
    END;

    -- Concurrency hardening: serialize all UC-4 activations for the same
    -- holder by acquiring a row lock on the Individual record. Two operators
    -- running this procedure simultaneously for the same holder will queue;
    -- the second one observes the post-T1 state and either succeeds or fails
    -- cleanly with a domain error rather than producing inconsistent data.
    PERFORM 1
       FROM Individual
      WHERE individual_id = v_lost_individual_id
      FOR UPDATE;

    -- Re-validate the token statuses UNDER the lock, with the token rows
    -- themselves locked. The status reads at the top of this procedure happened
    -- BEFORE the lock above, so a concurrent UC-4 for the same holder could have
    -- transitioned these tokens in between; acting on the stale pre-lock snapshot
    -- let a second caller re-revoke the already-LOST token and write a duplicate
    -- RevocationList row. Re-reading the now-locked rows makes a stale second
    -- caller fail cleanly here with a domain error instead.
    SELECT status INTO v_lost_status FROM IdentityToken
        WHERE token_id = p_lost_token_id FOR UPDATE;
    IF v_lost_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'Token % is not ACTIVE (current status: %)',
            p_lost_token_id, v_lost_status
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT status INTO v_reserve_status FROM IdentityToken
        WHERE token_id = p_reserve_token_id FOR UPDATE;
    IF v_reserve_status <> 'RESERVE' THEN
        RAISE EXCEPTION 'Token % is not in RESERVE state (current status: %)',
            p_reserve_token_id, v_reserve_status
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Compute the next activation sequence atomically inside the locked
    -- region. The previous code hardcoded `activation_sequence = 2`, which
    -- was wrong for any holder past their second active token AND raced
    -- if two procedures read the table at the same time. Now we read the
    -- max under the row lock above, eliminating both bugs.
    DECLARE v_next_seq INTEGER; BEGIN
    SELECT COALESCE(MAX(activation_sequence), 0) + 1
      INTO v_next_seq
      FROM IdentityToken
     WHERE individual_id = v_lost_individual_id;

    -- Step 1: transition the lost token to its terminal status FIRST.
    -- This releases the partial unique index on status='ACTIVE' for this individual.
    -- Set audit-trigger GUCs so the AFTER UPDATE trigger writes a properly-
    -- attributed lifecycle event automatically.
    PERFORM set_config('polaris.actor_agency_id', p_actor_agency_id::TEXT, true);
    PERFORM set_config('polaris.reason_code',     'HOLDER_REPORTED_' || p_reason_code, true);

    -- uc4 is a sanctioned 1-for-1 reserve swap, not a mass revocation. The
    -- COMPROMISED / SUPERSEDED / ADMINISTRATIVE reason codes map the lost token
    -- to terminal status REVOKED (see the CASE above), which trips
    -- enforce_revocation_velocity_bound() unless this GUC is set. The bound
    -- exists to refuse raw out-of-procedure UPDATEs, not the sanctioned swap
    -- this procedure performs, so opt out the same way uc8_revoke_token does.
    -- Without this the procedure aborts and three of its five reason codes are
    -- unusable.
    IF v_terminal_status = 'REVOKED' THEN
        PERFORM set_config('polaris.revoke_check_done', '1', true);
    END IF;

    UPDATE IdentityToken
       SET status = v_terminal_status
     WHERE token_id = p_lost_token_id;

    -- Step 2: publish to revocation list.
    INSERT INTO RevocationList
        (token_id, revoked_by_agency_id, effective_date, reason_code, published_location)
    VALUES
        (p_lost_token_id, p_actor_agency_id, CURRENT_DATE,
         p_reason_code, p_published_location);

    -- Step 3: promote the reserve to ACTIVE with predecessor pointer.
    -- Update the GUC reason for this transition; agency stays the same.
    PERFORM set_config('polaris.reason_code', 'RESERVE_PROMOTION', true);

    UPDATE IdentityToken
       SET status                 = 'ACTIVE',
           predecessor_token_id   = p_lost_token_id,
           activation_sequence    = v_next_seq,
           activated_date         = CURRENT_TIMESTAMP
     WHERE token_id = p_reserve_token_id;

    RETURN p_reserve_token_id;
    END;
END;
$$;

CREATE OR REPLACE PROCEDURE uc8_revoke_token(
    p_token_id            INTEGER,
    p_actor_agency_id     INTEGER,
    p_reason_code         VARCHAR(40),
    p_published_location  VARCHAR(300),
    p_cosigner_agency_id  INTEGER DEFAULT NULL
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
    v_issuing_agency_id INTEGER;
    v_current_status    VARCHAR(20);
    v_outstanding       INTEGER;
    v_recent_revokes    INTEGER;
    v_max_percent       NUMERIC(5,2);
    v_window_days       INTEGER;
    v_observed_percent  NUMERIC(8,4);
    v_cosigner_auth     VARCHAR(20);
BEGIN
    -- C9: serialize concurrent revocations by the SAME agency so the
    -- read-then-write rate check is atomic. Two threads racing the
    -- (N+1)th call against the same agency block each other on this
    -- lock; the loser sees the winner's row when its rate read runs.
    -- Transaction-scoped — released at COMMIT/ROLLBACK automatically.
    PERFORM pg_advisory_xact_lock(
        hashtext('polaris.revoke.' ||
            (SELECT issuing_agency_id::TEXT
             FROM IdentityToken WHERE token_id = p_token_id)));

    -- Resolve token state. The bound applies to the *issuing* agency
    -- (not necessarily the actor). Reject already-terminal tokens so
    -- a token cannot be double-revoked or revoked-after-LOST.
    SELECT issuing_agency_id, status
      INTO v_issuing_agency_id, v_current_status
    FROM IdentityToken WHERE token_id = p_token_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Token % does not exist', p_token_id;
    END IF;
    IF v_current_status IN ('REVOKED','LOST','EXPIRED') THEN
        RAISE EXCEPTION 'Token % is already terminal (%); cannot revoke',
            p_token_id, v_current_status;
    END IF;

    -- Resolve effective policy (per-agency override or system default).
    -- current_setting(..., true) returns NULL for missing GUCs; COALESCE
    -- to hardcoded 5.00 / 30 so a missing GUC degrades to defaults.
    SELECT max_revoke_percent, window_days
      INTO v_max_percent, v_window_days
    FROM IssuerDiscretionPolicy
    WHERE agency_id = v_issuing_agency_id
      AND superseded_at IS NULL;   -- v9.426: a superseded bound does not bind
    IF NOT FOUND THEN
        -- The DATABASE's setting, not the session's (1.0.0-rc.19). ALTER DATABASE sets the
        -- default, and any session can override a setting for itself, so reading
        -- current_setting() let the caller choose the bound it was about to be held to.
        v_max_percent := COALESCE(
            NULLIF(polaris_database_setting('polaris.default_max_revoke_percent'), '')::NUMERIC,
            5.00);
        v_window_days := COALESCE(
            NULLIF(polaris_database_setting('polaris.default_window_days'), '')::INTEGER,
            30);
    END IF;

    -- Outstanding = ever-issued by this agency (lifetime denominator).
    SELECT count(*) INTO v_outstanding
    FROM IdentityToken
    WHERE issuing_agency_id = v_issuing_agency_id;

    -- Numerator = revocations in window, INCLUDING this one.
    SELECT count(*) + 1 INTO v_recent_revokes
    FROM TokenLifecycleEvent e
    JOIN IdentityToken t ON t.token_id = e.token_id
    WHERE t.issuing_agency_id = v_issuing_agency_id
      AND e.event_type = 'REVOKED'
      AND e.event_timestamp > CURRENT_TIMESTAMP - (v_window_days || ' days')::INTERVAL;

    v_observed_percent := CASE
        WHEN v_outstanding = 0 THEN 100  -- empty agency: any revocation trips bound
        ELSE (v_recent_revokes::NUMERIC / v_outstanding) * 100
    END;

    IF v_observed_percent > v_max_percent THEN
        IF p_cosigner_agency_id IS NULL THEN
            RAISE EXCEPTION
                'Revocation rate for agency % would reach % percent in % day window (bound: % percent); co-signer required',
                v_issuing_agency_id, v_observed_percent,
                v_window_days, v_max_percent
                USING ERRCODE = 'check_violation';
        END IF;

        -- Co-signer must be a *different* agency.
        IF p_cosigner_agency_id = p_actor_agency_id THEN
            RAISE EXCEPTION 'Co-signer must differ from actor';
        END IF;

        -- Co-signer must hold BOTH on the token's algorithm.
        SELECT aa.authorization_type INTO v_cosigner_auth
        FROM AgencyAlgorithmAuth aa
        JOIN IdentityToken      t ON t.algorithm_id = aa.algorithm_id
        WHERE aa.agency_id = p_cosigner_agency_id
          AND t.token_id    = p_token_id;
        IF NOT FOUND OR v_cosigner_auth <> 'BOTH' THEN
            RAISE EXCEPTION
                'Co-signer agency % lacks BOTH authorization on the relevant algorithm',
                p_cosigner_agency_id;
        END IF;
    END IF;

    -- Step 1: transition the token to REVOKED. Set audit-trigger GUCs
    -- so the AFTER UPDATE trigger writes a properly-attributed lifecycle
    -- event automatically (same pattern as UC-4). The co-signer tag
    -- lives in the lifecycle event reason_code (VARCHAR(60), not domain-
    -- checked), keeping the verifier-facing RevocationList row in the
    -- canonical reason-code vocabulary.
    PERFORM set_config('polaris.actor_agency_id', p_actor_agency_id::TEXT, true);
    PERFORM set_config('polaris.reason_code',
        CASE WHEN p_cosigner_agency_id IS NULL
             THEN p_reason_code
             ELSE p_reason_code || ' [COSIGN:' || p_cosigner_agency_id::TEXT || ']'
        END,
        true);
    -- Signal to the belt-and-suspenders trigger that the bound has
    -- been checked under this transaction (see 06_triggers.sql).
    PERFORM set_config('polaris.revoke_check_done', '1', true);

    UPDATE IdentityToken
       SET status = 'REVOKED'
     WHERE token_id = p_token_id;

    -- Step 2: publish to the verifier-facing revocation list (UC-4
    -- pattern). Without this, the token state would diverge from
    -- the published CRL.
    INSERT INTO RevocationList
        (token_id, revoked_by_agency_id, effective_date,
         reason_code, published_location)
    VALUES
        (p_token_id, p_actor_agency_id, CURRENT_DATE,
         p_reason_code, p_published_location);
END$$;

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
    p_published_location VARCHAR DEFAULT NULL
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
                    (v_lost_token.token_id, v_requesting_agency, CURRENT_DATE,
                     'SUPERSEDED', p_published_location);
            ELSE
                UPDATE IdentityToken
                   SET status = 'LOST'
                 WHERE token_id = v_lost_token.token_id;

                INSERT INTO RevocationList
                    (token_id, revoked_by_agency_id, effective_date,
                     reason_code, published_location)
                VALUES
                    (v_lost_token.token_id, v_requesting_agency, CURRENT_DATE,
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
             (CURRENT_DATE + INTERVAL '10 years')::DATE,
             p_liveness_check)
        RETURNING token_id INTO v_new_token_id;

        -- R11-1 / M2-6: issue a TokenSignature row alongside the new
        -- IdentityToken so the M:N invariant is satisfied. Tagged with
        -- the recovery context in the placeholder so audit replay can
        -- identify recovery-issued signatures.
        INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes)
        VALUES (v_new_token_id, p_algorithm_id,
                ('UC9_RECOVERY_PLACEHOLDER_' || p_recovery_id::TEXT
                 || '_TOKEN_' || v_new_token_id::TEXT)::BYTEA);

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

CREATE OR REPLACE FUNCTION enforce_revocation_velocity_bound()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    -- Only fire on NEW transitions INTO 'REVOKED'.
    IF NEW.status <> 'REVOKED' OR OLD.status = 'REVOKED' THEN
        RETURN NEW;
    END IF;

    -- Procedure path sets this GUC. If absent, the UPDATE bypassed
    -- uc8_revoke_token and the bound has not been checked.
    --
    -- 1.0.0-rc.19: the GUC alone is not a gate, because any session can set it; a
    -- polaris_app session did, and revoked with a plain UPDATE. It is honoured only
    -- when the CURRENT ROLE owns the revocation procedure, which is true inside the
    -- SECURITY DEFINER procedures and for the schema owner (who could drop this
    -- trigger anyway), and never for the application role.
    IF current_setting('polaris.revoke_check_done', true) = '1'
       AND current_user = (SELECT pg_get_userbyid(p.proowner) FROM pg_proc p
                            WHERE p.proname = 'uc8_revoke_token' LIMIT 1) THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'Direct UPDATE to status=REVOKED is not allowed. Use uc8_revoke_token().'
        USING ERRCODE = 'insufficient_privilege';
END$$;
