-- Reverts 2026-09-24-013: the routines as they were, the INSERT grant back, and the partitions'
-- blanket grant restored (which is the hole this migration closes).

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
         'RESERVE', CURRENT_TIMESTAMP, (CURRENT_DATE + INTERVAL '10 years')::date)
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

CREATE OR REPLACE FUNCTION uc5_bind_device(
    p_token_id           INTEGER,
    p_device_type        VARCHAR(20),
    p_device_fingerprint VARCHAR(128),
    p_binding_method     VARCHAR(40),
    p_validity_months    INTEGER DEFAULT 12
) RETURNS INTEGER
LANGUAGE plpgsql
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
    -- The database runs on UTC since rc.28, so CURRENT_DATE is the UTC date.
    IF v_expiration IS NOT NULL AND v_expiration < CURRENT_DATE THEN
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

CREATE OR REPLACE PROCEDURE uc_bulk_issue(p_batch_id INTEGER, INOUT p_rows_issued INTEGER DEFAULT NULL)
LANGUAGE plpgsql AS $$
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
             individual_id, v_agency, v_algo, 'RESERVE', CURRENT_TIMESTAMP, (CURRENT_DATE + INTERVAL '10 years')::date,
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

CREATE OR REPLACE FUNCTION audit_token_state_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_event_type    VARCHAR(40);
    v_actor         INTEGER;
    v_reason        VARCHAR(60);
    v_lat           DOUBLE PRECISION;
    v_lon           DOUBLE PRECISION;
BEGIN
    -- No status change: nothing to audit.
    IF OLD.status = NEW.status THEN
        RETURN NEW;
    END IF;

    -- Map (OLD,NEW) to the event_type column on TokenLifecycleEvent.
    v_event_type := CASE NEW.status
        WHEN 'ACTIVE'  THEN 'ACTIVATED'
        WHEN 'DORMANT' THEN 'DEACTIVATED'
        WHEN 'REVOKED' THEN 'REVOKED'
        WHEN 'LOST'    THEN 'LOST'
        WHEN 'EXPIRED' THEN 'EXPIRED'
        ELSE 'STATUS_CHANGED'
    END;

    -- Optional session-level actor, reason, and location. current_setting
    -- returns '' when the GUC is unset (with missing_ok = true).
    v_actor  := NULLIF(current_setting('polaris.actor_agency_id', true), '')::INTEGER;
    v_reason := NULLIF(current_setting('polaris.reason_code',     true), '');
    v_lat    := NULLIF(current_setting('polaris.event_lat',       true), '')::DOUBLE PRECISION;
    v_lon    := NULLIF(current_setting('polaris.event_lon',       true), '')::DOUBLE PRECISION;

    -- If the application has ALREADY inserted a matching event in this
    -- transaction (the legacy pattern from before this trigger existed,
    -- still used by some stored procedures during the migration window),
    -- skip duplicating. We detect this by looking for a matching event
    -- created within the last 100ms.
    IF EXISTS (
        SELECT 1 FROM TokenLifecycleEvent
        WHERE token_id = NEW.token_id
          AND event_type = v_event_type
          AND event_timestamp >= CURRENT_TIMESTAMP - INTERVAL '100 milliseconds'
    ) THEN
        RETURN NEW;
    END IF;

    -- Append the audit row. The append-only trigger will not block this
    -- because it only fires on UPDATE or DELETE.
    INSERT INTO TokenLifecycleEvent (
        token_id, actor_agency_id, event_type, reason_code, event_timestamp,
        latitude, longitude
    )
    VALUES (
        NEW.token_id, v_actor, v_event_type,
        COALESCE(v_reason, 'AUTO_AUDIT_TRIGGER'),
        CURRENT_TIMESTAMP,
        v_lat, v_lon
    );

    RETURN NEW;
END;
$$;

CREATE OR REPLACE PROCEDURE uc_ensure_event_partitions(p_months_ahead integer DEFAULT 3)
LANGUAGE plpgsql AS $$
DECLARE
    v_tables text[] := ARRAY['tokenlifecycleevent','verificationevent','enrollmentstatusevent','authauditlog'];
    v_tbl text; v_from date; v_to date; v_part text; i integer;
BEGIN
    IF p_months_ahead < 0 OR p_months_ahead > 60 THEN
        RAISE EXCEPTION 'uc_ensure_event_partitions: p_months_ahead must be between 0 and 60 (got %)', p_months_ahead;
    END IF;
    FOREACH v_tbl IN ARRAY v_tables LOOP
        FOR i IN 0..p_months_ahead LOOP
            v_from := (date_trunc('month', now()) + make_interval(months => i))::date;
            v_to   := (v_from + interval '1 month')::date;
            v_part := format('%s_%s', v_tbl, to_char(v_from, 'YYYY_MM'));
            CONTINUE WHEN to_regclass(v_part) IS NOT NULL;
            BEGIN
                EXECUTE format('CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)', v_part, v_tbl, v_from, v_to);
            EXCEPTION WHEN others THEN
                -- The DEFAULT partition already holds rows for this month (the
                -- manager fell behind, or the seed spans it): leave them there,
                -- purged by retention. A missing monthly partition is a
                -- monitored condition, never silent data loss.
                RAISE WARNING 'uc_ensure_event_partitions: could not create % (%); rows for that month stay in %_default',
                    v_part, SQLERRM, v_tbl;
            END;
        END LOOP;
    END LOOP;
END $$;

DROP FUNCTION IF EXISTS polaris_lock_event_partitions();
GRANT INSERT ON TokenLifecycleEvent TO polaris_app;
DO $$
DECLARE v_part TEXT;
BEGIN
    FOR v_part IN
        SELECT c.relname FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_class p ON p.oid = i.inhparent
         WHERE p.relname IN ('tokenlifecycleevent', 'verificationevent', 'enrollmentstatusevent', 'authauditlog')
    LOOP
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO polaris_app', v_part);
    END LOOP;
END$$;
