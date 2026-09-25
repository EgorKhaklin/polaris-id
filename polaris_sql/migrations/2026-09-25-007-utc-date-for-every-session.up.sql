-- 2026-09-25-007: every date decision reads the UTC date, whatever timezone the session set.
--
-- 1.0.0-rc.28 set the database's timezone to UTC so that CURRENT_DATE would be the UTC date the
-- application, the signed status assertion and the standalone verifiers judge expiry by. That is
-- a default: a client's PGTZ, a pooler or SET timezone overrides it for the session, and every
-- decision written with CURRENT_DATE then answered in the client's zone (with PGTZ at UTC+14 an
-- expired credential signed in). This adds polaris_utc_date() and re-creates the fourteen
-- objects that used CURRENT_DATE with it. Bodies copied from 05_procedures.sql, 06_triggers.sql,
-- 14_foresight_helpers.sql and 16_athena.sql; the only change in each is that substitution.

CREATE OR REPLACE FUNCTION polaris_utc_date()
RETURNS DATE
LANGUAGE sql STABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT (now() AT TIME ZONE 'UTC')::date
$$;

CREATE OR REPLACE FUNCTION uc1_issue_and_activate(
    p_legal_name              VARCHAR(200),
    p_dob                     DATE,
    p_jurisdiction            VARCHAR(10),
    p_issuing_agency_id       INTEGER,
    p_algorithm_id            INTEGER,
    p_biometric_binding_type  VARCHAR(20),
    p_witness_agency_id       INTEGER,
    p_liveness_check_type     VARCHAR(20),
    p_token_value             VARCHAR(128),
    p_physical_serial         VARCHAR(64),
    p_hardware_model          VARCHAR(50),
    p_permitted_contexts      INTEGER[],
    p_signature_bytes         BYTEA   DEFAULT NULL,
    p_signing_public_key_hex  TEXT    DEFAULT NULL
) RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_individual_id  INTEGER;
    v_token_id       INTEGER;
    v_auth_type      VARCHAR(20);
    v_context_id     INTEGER;
BEGIN
    -- Step 1: validate the issuing agency's authorization (UC-1 step 1).
    SELECT authorization_type INTO v_auth_type
    FROM AgencyAlgorithmAuth
    WHERE agency_id    = p_issuing_agency_id
      AND algorithm_id = p_algorithm_id;
    IF NOT FOUND OR v_auth_type NOT IN ('ISSUE','BOTH') THEN
        RAISE EXCEPTION 'Agency % is not authorized to issue under algorithm %',
            p_issuing_agency_id, p_algorithm_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Step 1b: refuse issuance under a deprecated algorithm. uc6_migrate_algorithm
    -- already refuses to migrate a token TO a deprecated algorithm; uc1 must not
    -- mint a brand-new ACTIVE token under one either (it would be a live token
    -- signed with an algorithm the system already considers retired/weakened —
    -- exactly what the algorithm-as-data, post-quantum-migration design prevents).
    PERFORM 1 FROM CryptographicAlgorithm
     WHERE algorithm_id = p_algorithm_id
       AND (deprecation_date IS NULL OR deprecation_date > CURRENT_TIMESTAMP);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Algorithm % is deprecated; cannot issue a new token under it',
            p_algorithm_id
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Step 2: insert Individual if no existing record (UC-1 step 2).
    --   The application normally checks for an existing individual first;
    --   this procedure simplifies by always inserting a new individual,
    --   matching the UC-1 sample transaction in the report.
    INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
    VALUES (p_legal_name, p_dob, p_jurisdiction)
    RETURNING individual_id INTO v_individual_id;

    -- Step 3-4: insert IdentityToken in RESERVE + lifecycle ISSUED (UC-1 steps 3-4).
    INSERT INTO IdentityToken
        (token_value, physical_serial, hardware_model,
         biometric_binding_type, individual_id, issuing_agency_id, algorithm_id,
         status, issued_date, expiration_date)
    VALUES
        (p_token_value, p_physical_serial, p_hardware_model,
         p_biometric_binding_type, v_individual_id, p_issuing_agency_id, p_algorithm_id,
         'RESERVE', CURRENT_TIMESTAMP, (polaris_utc_date() + INTERVAL '10 years')::date)
    RETURNING token_id INTO v_token_id;

    -- R11-1 / M2-6: issue a TokenSignature row alongside the IdentityToken
    -- so the M:N invariant (every token has >= 1 active signature) is
    -- satisfied from the moment the token exists. v9.58: the signature bytes
    -- now come from the app's signing module (polaris_web/pqc_signing.py) via
    -- p_signature_bytes — a real ML-DSA-65 signature when POLARIS_USE_REAL_PQC=1
    -- and liboqs are present, a deterministic SHA3-256 binding of token_value
    -- otherwise. Direct SQL callers that pass NULL fall back to the legacy
    -- deterministic string, so existing tooling and tests are unaffected.
    -- v9.117: store the issuer public key (hex) alongside the signature so
    -- verify-at-use is self-contained. NULL for the placeholder path (no key).
    INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes, signing_public_key_hex)
    VALUES (v_token_id, p_algorithm_id,
            COALESCE(p_signature_bytes,
                     ('UC1_ISSUE_PLACEHOLDER_' || v_token_id::TEXT)::BYTEA),
            p_signing_public_key_hex);

    INSERT INTO TokenLifecycleEvent
        (token_id, actor_agency_id, event_type, reason_code)
    VALUES
        (v_token_id, p_issuing_agency_id, 'ISSUED', 'INITIAL_ENROLLMENT');

    -- Step 5: hardware-binding ceremony (UC-1 step 5).
    --   Update biometric metadata fields and witness reference.
    UPDATE IdentityToken
       SET biometric_enrolled_date      = CURRENT_TIMESTAMP,
           enrollment_witness_agency_id = p_witness_agency_id,
           liveness_check_type          = p_liveness_check_type
     WHERE token_id = v_token_id;

    -- Step 6-7: activate (UC-1 steps 6-7). Set the audit-trigger context GUCs
    -- so the AFTER UPDATE trigger writes a properly-attributed lifecycle event.
    -- This replaces the explicit INSERT INTO TokenLifecycleEvent that used to
    -- live here — the database now guarantees the audit row.
    PERFORM set_config('polaris.actor_agency_id', p_issuing_agency_id::TEXT, true);
    PERFORM set_config('polaris.reason_code',     'POST_BIOMETRIC_ENROLLMENT', true);

    UPDATE IdentityToken
       SET status         = 'ACTIVE',
           activated_date = CURRENT_TIMESTAMP
     WHERE token_id = v_token_id;

    -- Step 8: insert default permissions (UC-1 step 8).
    FOREACH v_context_id IN ARRAY p_permitted_contexts LOOP
        INSERT INTO TokenPermission (token_id, context_id, permission_level)
        VALUES (v_token_id, v_context_id, 'VERIFY');
    END LOOP;

    RETURN v_token_id;
END;
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
        (p_lost_token_id, p_actor_agency_id, polaris_utc_date(),
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

CREATE OR REPLACE FUNCTION uc5_bind_device(
    p_token_id           INTEGER,
    p_device_type        VARCHAR(20),
    p_device_fingerprint VARCHAR(128),
    p_binding_method     VARCHAR(40),
    p_validity_months    INTEGER DEFAULT 12
) RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_token_status VARCHAR(20);
    v_expiration   DATE;
    v_binding_id   INTEGER;
BEGIN
    -- Validate: token is ACTIVE.
    SELECT status, expiration_date INTO v_token_status, v_expiration
    FROM IdentityToken WHERE token_id = p_token_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Token % does not exist', p_token_id
            USING ERRCODE = 'no_data_found';
    END IF;
    IF v_token_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'Token % is not ACTIVE (current status: %); cannot bind device',
            p_token_id, v_token_status
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- 1.0.0-rc.36: nor past its expiration date. Nothing moves ACTIVE to EXPIRED when the
    -- date passes, so the status above still reads ACTIVE for a credential that has run out;
    -- the relying-party holder-key binding refused one since rc.24, this path did not.
    -- polaris_utc_date(), not CURRENT_DATE: rc.28 made UTC the default, which a session can override.
    IF v_expiration IS NOT NULL AND v_expiration < polaris_utc_date() THEN
        RAISE EXCEPTION 'Token % expired on %; cannot bind device', p_token_id, v_expiration
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    INSERT INTO DeviceBinding
        (token_id, device_type, device_fingerprint, binding_method,
         authorized_date, expires_date, status)
    VALUES
        (p_token_id, p_device_type, p_device_fingerprint, p_binding_method,
         CURRENT_TIMESTAMP,
         CURRENT_TIMESTAMP + (p_validity_months || ' months')::INTERVAL,
         'ACTIVE')
    RETURNING binding_id INTO v_binding_id;

    INSERT INTO TokenLifecycleEvent
        (token_id, actor_agency_id, event_type, reason_code)
    VALUES
        (p_token_id, NULL, 'DEVICE_BOUND',
         'DEVICE_TYPE_' || p_device_type);

    RETURN v_binding_id;
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
        (p_token_id, p_actor_agency_id, polaris_utc_date(),
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

CREATE OR REPLACE PROCEDURE uc10_attest_trust(
    p_attesting_id  INTEGER,
    p_attested_id   INTEGER,
    p_context_id    INTEGER,
    p_valid_until   DATE,
    p_signed_by     INTEGER
)
LANGUAGE plpgsql AS $$
DECLARE
    v_user_role TEXT;
BEGIN
    -- C9: per-attesting-agency advisory lock. The 5th catalog entry.
    -- Cross-attesting-agency operations run in parallel; same-attesting-
    -- agency operations serialize.
    PERFORM pg_advisory_xact_lock(
        hashtext('polaris.federation.attest.' || p_attesting_id::TEXT));

    -- Validate admin role on signer.
    SELECT role INTO v_user_role FROM AppUser WHERE user_id = p_signed_by;
    IF v_user_role IS NULL THEN
        RAISE EXCEPTION 'AppUser % not found', p_signed_by
            USING ERRCODE = 'no_data_found';
    END IF;
    IF v_user_role <> 'admin' THEN
        RAISE EXCEPTION
            'Federation attestation requires admin role (signer % has role %)',
            p_signed_by, v_user_role
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- 2026-09-24: an admin whose account is DEACTIVATED held this authority as fully as a
    -- live one. uc9_complete_recovery and uc_pseudonymize_individual refused a deactivated
    -- actor; the five procedures below checked the role alone.
    IF NOT (SELECT is_active FROM AppUser WHERE user_id = p_signed_by) THEN
        RAISE EXCEPTION 'uc10_attest_trust: user % is not an active account', p_signed_by
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Validate valid_until is in the future.
    IF p_valid_until <= polaris_utc_date() THEN
        RAISE EXCEPTION
            'valid_until must be strictly in the future; got %', p_valid_until;
    END IF;

    -- Insert. The schema's three CHECK constraints and the partial unique
    -- index handle the rest:
    --   - attestation_no_self_attestation (CHECK)  → if A==A
    --   - attestation_validity_floor (CHECK)       → if validity is zero/neg
    --   - attestation_revocation_consistency (CHECK) → not triggered on INSERT
    --   - uq_active_attestation (partial unique)   → if duplicate active row
    BEGIN
        INSERT INTO AgencyTrustAttestation
            (attesting_agency_id, attested_agency_id, context_id,
             valid_until, signed_by)
        VALUES
            (p_attesting_id, p_attested_id, p_context_id,
             p_valid_until, p_signed_by);
    EXCEPTION
        WHEN unique_violation THEN
            RAISE EXCEPTION
                'An active attestation already exists for (attesting=%, attested=%, context=%); revoke it before re-attesting',
                p_attesting_id, p_attested_id, p_context_id
                USING ERRCODE = 'unique_violation';
    END;

    RAISE NOTICE 'uc10_attest_trust: %→% for context % until %',
        p_attesting_id, p_attested_id, p_context_id, p_valid_until;
END$$;

CREATE OR REPLACE PROCEDURE uc_bulk_issue(p_batch_id INTEGER, INOUT p_rows_issued INTEGER DEFAULT NULL)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_agency INTEGER; v_algo INTEGER; v_auth VARCHAR(20); v_n INTEGER;
BEGIN
    SELECT issuing_agency_id, algorithm_id INTO v_agency, v_algo
      FROM BulkEnrollmentBatch WHERE batch_id = p_batch_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'uc_bulk_issue: batch % does not exist', p_batch_id; END IF;
    IF EXISTS (SELECT 1 FROM BulkEnrollmentBatch WHERE batch_id = p_batch_id AND issued_at IS NOT NULL) THEN
        RAISE EXCEPTION 'uc_bulk_issue: batch % was already issued', p_batch_id USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- the same authorization uc1 checks, once for the batch (one agency, one algorithm)
    SELECT authorization_type INTO v_auth FROM AgencyAlgorithmAuth
     WHERE agency_id = v_agency AND algorithm_id = v_algo;
    IF NOT FOUND OR v_auth NOT IN ('ISSUE','BOTH') THEN
        RAISE EXCEPTION 'uc_bulk_issue: agency % is not authorized to issue under algorithm %', v_agency, v_algo
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    PERFORM 1 FROM CryptographicAlgorithm WHERE algorithm_id = v_algo
       AND (deprecation_date IS NULL OR deprecation_date > CURRENT_TIMESTAMP);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'uc_bulk_issue: algorithm % is deprecated; cannot issue under it', v_algo
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    SELECT count(*) INTO v_n FROM BulkEnrollmentStaging WHERE batch_id = p_batch_id;
    IF v_n = 0 THEN RAISE EXCEPTION 'uc_bulk_issue: batch % has no staged rows', p_batch_id; END IF;

    -- Pre-assign the primary keys so the multi-table inserts correlate set-based.
    -- A staged individual_id LEFT NULL is a new person (first enrollment): it gets
    -- a fresh id and a new Individual row. A staged individual_id SET correlates the
    -- row to an existing person (a re-card of someone whose prior token is no longer
    -- active): it keeps its id and inserts no duplicate Individual. C3
    -- (uq_one_active_per_person) is what enforces "no longer active" -- a re-card of
    -- someone who still holds an active token fails at activation and rolls the batch
    -- back, exactly as two staged rows for one person do.
    UPDATE BulkEnrollmentStaging
       SET individual_id = COALESCE(individual_id, nextval(pg_get_serial_sequence('individual','individual_id')))
     WHERE batch_id = p_batch_id;
    INSERT INTO Individual (individual_id, legal_name, date_of_birth, jurisdiction)
      SELECT individual_id, legal_name, date_of_birth, jurisdiction FROM BulkEnrollmentStaging s
       WHERE batch_id = p_batch_id
         AND NOT EXISTS (SELECT 1 FROM Individual i WHERE i.individual_id = s.individual_id);
    -- (the AFTER-INSERT trigger seeds a NOT_ENROLLED EnrollmentStatusEvent per NEW row;
    --  correlated rows keep the existing person's enrollment history untouched)

    UPDATE BulkEnrollmentStaging SET token_id = nextval(pg_get_serial_sequence('identitytoken','token_id'))
     WHERE batch_id = p_batch_id;
    INSERT INTO IdentityToken (token_id, token_value, physical_serial, hardware_model, biometric_binding_type,
                               individual_id, issuing_agency_id, algorithm_id, status, issued_date, expiration_date,
                               biometric_enrolled_date, enrollment_witness_agency_id, liveness_check_type)
      SELECT token_id, token_value, physical_serial, hardware_model, biometric_binding_type,
             individual_id, v_agency, v_algo, 'RESERVE', CURRENT_TIMESTAMP, (polaris_utc_date() + INTERVAL '10 years')::date,
             CURRENT_TIMESTAMP, witness_agency_id, liveness_check_type
        FROM BulkEnrollmentStaging WHERE batch_id = p_batch_id;
    -- (FKs, CHECKs, and the token_value/physical_serial UNIQUE constraints hold per row)

    -- v9.257: bulk issuance stores the REAL signature the caller staged (signed
    -- through the pqc_signing module, exactly like single issuance). It no longer
    -- fabricates a placeholder literal keyed on the token id: an unsigned staged
    -- row is REFUSED, so a mass-issued token can never claim a signature it does
    -- not have. (The deterministic-placeholder mode still stages a verifiable
    -- sha3-256 of token_value with a NULL key; only real ML-DSA-65 carries a key.)
    IF EXISTS (SELECT 1 FROM BulkEnrollmentStaging
               WHERE batch_id = p_batch_id AND signature_bytes IS NULL) THEN
        RAISE EXCEPTION 'bulk issuance requires a signature for every staged token: a row has '
                        'signature_bytes NULL. Sign each token_value through the signing module '
                        'before staging (pqc_signing.signature_with_key_for_token).'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes, signing_public_key_hex)
      SELECT token_id, v_algo, signature_bytes, signing_public_key_hex
        FROM BulkEnrollmentStaging WHERE batch_id = p_batch_id;
    -- (enforce_token_has_active_signature is satisfied: every token gets a signature)

    INSERT INTO TokenLifecycleEvent (token_id, actor_agency_id, event_type, reason_code)
      SELECT token_id, v_agency, 'ISSUED', 'BULK_ENROLLMENT' FROM BulkEnrollmentStaging WHERE batch_id = p_batch_id;

    -- Activate. The audit trigger writes an ACTIVATED lifecycle row per token from
    -- the batch's agency (one agency per batch), and the state-machine trigger
    -- validates RESERVE -> ACTIVE per row.
    PERFORM set_config('polaris.actor_agency_id', v_agency::TEXT, true);
    PERFORM set_config('polaris.reason_code', 'BULK_POST_ENROLLMENT', true);
    UPDATE IdentityToken t SET status = 'ACTIVE', activated_date = CURRENT_TIMESTAMP
      FROM BulkEnrollmentStaging s WHERE t.token_id = s.token_id AND s.batch_id = p_batch_id;
    -- (uq_one_active_per_person, C3, holds across the batch: two active tokens for
    --  one person fail here and roll back every row)

    INSERT INTO TokenPermission (token_id, context_id, permission_level)
      SELECT token_id, unnest(permitted_contexts), 'VERIFY' FROM BulkEnrollmentStaging WHERE batch_id = p_batch_id;

    UPDATE BulkEnrollmentBatch SET issued_at = CURRENT_TIMESTAMP, rows_issued = v_n WHERE batch_id = p_batch_id;
    p_rows_issued := v_n;
END $$;

CREATE OR REPLACE FUNCTION enforce_token_state_machine()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- No status change: nothing to validate.
    IF OLD.status = NEW.status THEN
        RETURN NEW;
    END IF;

    -- Validate the (OLD.status, NEW.status) transition pair against the legal set.
    IF NOT (
           (OLD.status = 'RESERVE' AND NEW.status = 'ACTIVE')
        OR (OLD.status = 'RESERVE' AND NEW.status = 'REVOKED')
        OR (OLD.status = 'ACTIVE'  AND NEW.status = 'DORMANT')
        OR (OLD.status = 'ACTIVE'  AND NEW.status = 'REVOKED')
        OR (OLD.status = 'ACTIVE'  AND NEW.status = 'LOST')
        OR (OLD.status = 'ACTIVE'  AND NEW.status = 'EXPIRED')
    ) THEN
        RAISE EXCEPTION 'Illegal token state transition: % → %. Legal transitions are listed in Appendix A.',
            OLD.status, NEW.status
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Activation invariant: ACTIVE tokens must have an activated_date.
    IF NEW.status = 'ACTIVE' AND NEW.activated_date IS NULL THEN
        RAISE EXCEPTION 'Cannot transition to ACTIVE without setting activated_date'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- 1.0.0-rc.37: nothing becomes ACTIVE past its expiration_date. Nothing moves ACTIVE to
    -- EXPIRED when the date passes, so a credential activated already expired would read
    -- ACTIVE in the table while every verifier refuses it; uc4_activate_reserve did exactly
    -- that. Asked here, the one door into ACTIVE, so no route or procedure has to remember.
    IF NEW.status = 'ACTIVE' AND NEW.expiration_date < polaris_utc_date() THEN
        RAISE EXCEPTION 'Cannot activate token %: it expired on %', NEW.token_id, NEW.expiration_date
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION foresight_audit_volume_trend(p_weeks INTEGER DEFAULT 12)
RETURNS TABLE (
    week_start                DATE,
    lifecycle_event_count     BIGINT,
    verification_event_count  BIGINT,
    total_audit_volume        BIGINT
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    IF p_weeks < 1 OR p_weeks > 520 THEN
        RAISE EXCEPTION 'p_weeks must be between 1 and 520 (got %)', p_weeks
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    RETURN QUERY
    WITH weeks AS (
        SELECT (DATE_TRUNC('week', polaris_utc_date()) - (n || ' weeks')::INTERVAL)::DATE AS week_start
          FROM generate_series(0, p_weeks - 1) n
    ),
    lifecycle_per_week AS (
        SELECT DATE_TRUNC('week', event_timestamp)::DATE AS w,
               COUNT(*) AS c
          FROM TokenLifecycleEvent
         WHERE event_timestamp >= polaris_utc_date() - (p_weeks * 7 || ' days')::INTERVAL
         GROUP BY 1
    ),
    verification_per_week AS (
        SELECT DATE_TRUNC('week', event_timestamp)::DATE AS w,
               COUNT(*) AS c
          FROM VerificationEvent
         WHERE event_timestamp >= polaris_utc_date() - (p_weeks * 7 || ' days')::INTERVAL
         GROUP BY 1
    )
    SELECT
        w.week_start,
        COALESCE(l.c, 0)::BIGINT  AS lifecycle_event_count,
        COALESCE(v.c, 0)::BIGINT  AS verification_event_count,
        (COALESCE(l.c, 0) + COALESCE(v.c, 0))::BIGINT AS total_audit_volume
      FROM weeks w
 LEFT JOIN lifecycle_per_week l    ON l.w = w.week_start
 LEFT JOIN verification_per_week v ON v.w = w.week_start
  ORDER BY w.week_start ASC;
END;
$$;

CREATE OR REPLACE VIEW v_athena_algorithm WITH (security_invoker = true) AS
SELECT alg.algorithm_id, alg.name, alg.family, alg.quantum_resistant,
       alg.nist_standard, alg.security_level_bits,
       alg.public_key_size, alg.signature_size, alg.deprecation_date,
       (alg.deprecation_date IS NOT NULL AND alg.deprecation_date <= polaris_utc_date()) AS is_deprecated,
       'CryptographicAlgorithm'::text AS source
  FROM CryptographicAlgorithm alg;

CREATE OR REPLACE VIEW v_athena_credential_class WITH (security_invoker = true) AS
SELECT alg.algorithm_id AS class_id, alg.name AS class_name, alg.family,
       alg.quantum_resistant, alg.security_level_bits,
       (alg.deprecation_date IS NOT NULL AND alg.deprecation_date <= polaris_utc_date()) AS is_deprecated,
       COUNT(*) FILTER (WHERE aaa.authorization_type IN ('ISSUE','BOTH')) AS authorized_issuer_count,
       'CryptographicAlgorithm + AgencyAlgorithmAuth'::text AS source
  FROM CryptographicAlgorithm alg
  LEFT JOIN AgencyAlgorithmAuth aaa ON aaa.algorithm_id = alg.algorithm_id
 GROUP BY alg.algorithm_id, alg.name, alg.family, alg.quantum_resistant,
          alg.security_level_bits, alg.deprecation_date;

CREATE OR REPLACE VIEW v_athena_trust_agreement WITH (security_invoker = true) AS
SELECT ata.attestation_id,
       ata.attesting_agency_id, aa.name AS attesting_agency_name,
       ata.attested_agency_id,  ab.name AS attested_agency_name,
       ata.context_id, vc.context_type,
       ata.attested_date, ata.valid_until,
       'AgencyTrustAttestation'::text AS source
  FROM AgencyTrustAttestation ata
  JOIN Agency aa ON ata.attesting_agency_id = aa.agency_id
  JOIN Agency ab ON ata.attested_agency_id  = ab.agency_id
  JOIN VerificationContext vc ON ata.context_id = vc.context_id
 WHERE ata.revocation_date IS NULL
   AND ata.valid_until >= polaris_utc_date();

CREATE OR REPLACE VIEW v_athena_relies_on WITH (security_invoker = true) AS
SELECT ata.attesting_agency_id AS from_agency_id, aa.name AS from_agency_name,
       ata.attested_agency_id  AS to_agency_id,   ab.name AS to_agency_name,
       ata.context_id, vc.context_type, ata.valid_until,
       'AgencyTrustAttestation'::text AS source
  FROM AgencyTrustAttestation ata
  JOIN Agency aa ON ata.attesting_agency_id = aa.agency_id
  JOIN Agency ab ON ata.attested_agency_id  = ab.agency_id
  JOIN VerificationContext vc ON ata.context_id = vc.context_id
 WHERE ata.revocation_date IS NULL
   AND ata.valid_until >= polaris_utc_date();

CREATE OR REPLACE FUNCTION athena_authority_chain(p_agency_id INTEGER, p_algorithm_id INTEGER)
RETURNS TABLE (step INTEGER, relation TEXT, detail TEXT, source TEXT)
LANGUAGE sql STABLE AS $athena_chain$
    SELECT 1, 'agency',
           a.name || ' (' || a.agency_type || ', ' || a.jurisdiction || ')', 'Agency'
      FROM Agency a WHERE a.agency_id = p_agency_id
    UNION ALL
    SELECT 2, 'algorithm',
           alg.name || ' (' || alg.family || ', L' || alg.security_level_bits ||
           CASE WHEN alg.deprecation_date IS NOT NULL AND alg.deprecation_date <= polaris_utc_date()
                THEN ', DEPRECATED' ELSE '' END || ')',
           'CryptographicAlgorithm'
      FROM CryptographicAlgorithm alg WHERE alg.algorithm_id = p_algorithm_id
    UNION ALL
    SELECT 3, 'may_issue',
           'authorization_type=' || aaa.authorization_type ||
           ', granted ' || to_char(aaa.authorized_date,'YYYY-MM-DD'),
           'AgencyAlgorithmAuth'
      FROM AgencyAlgorithmAuth aaa
     WHERE aaa.agency_id = p_agency_id AND aaa.algorithm_id = p_algorithm_id
       AND aaa.authorization_type IN ('ISSUE','BOTH')
    ORDER BY 1
    LIMIT 100;
$athena_chain$;
