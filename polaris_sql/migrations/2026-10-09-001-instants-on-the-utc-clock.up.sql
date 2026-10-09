-- 2026-10-09-001: every instant the database records or compares is on the UTC clock, whatever
-- TimeZone the session set.
--
-- THREAT-MODEL. The instant columns are TIMESTAMP without a zone. A bare CURRENT_TIMESTAMP stored
-- into one, or compared with one, is read in the SESSION's TimeZone, and any role may SET it: the
-- database default (09_grants.sql) and the application's PGTZ=UTC hold only for a session that does
-- not ask. Measured as polaris_app, changing nothing but SET timezone = 'Etc/GMT-14': uc1 recorded a
-- credential's signed_at, issued_date and ISSUED / ACTIVATED events fourteen hours ahead; a status
-- UPDATE made audit_token_state_change write its audit-of-record row fourteen hours ahead; uc8 dated
-- a published revocation fourteen hours ahead; uc_record_holder_key_event and uc10_attest_trust,
-- which read no clock, stamped effective_at and attested_date through their column defaults; and
-- uc9_complete_recovery approved a recovery an hour before its cool-down ended in UTC (up to
-- fourteen hours early), writing a decided_at that satisfied approved_after_cooldown. The
-- application role holds no direct write on any of these and none of the routines takes a
-- timestamp argument, so the capability was the timezone's alone.
--
-- What this does:
--   1. every routine that reads the clock runs with SET timezone = 'UTC'. Ten FUNCTIONs are
--      re-created with the canonical text, because check_migrations_do_not_revert_canonical_objects
--      holds the last migration copy of a function to its canonical file; the eleven procedures and
--      the two foresight functions (no migration copy) take ALTER ... SET;
--   2. the 43 TIMESTAMP column defaults read (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'); the parent's
--      default reaches every partition, and a partition made later copies it;
--   3. HolderKeyCurrent and v_ontology_token compare with the UTC clock.
-- The TIMESTAMPTZ defaults (now()) hold instants, which no zone moves, and are left as they are.
--
-- phase: expand. No table, column or type changes; a default, a routine setting and two view
-- bodies do. The canonical copies live in 01_schema.sql, 05_procedures.sql, 06_triggers.sql,
-- 14_foresight_helpers.sql and 15_ontology.sql. REVERSIBLE: the .down.sql resets each routine's
-- timezone and puts back the session-clock defaults and views. Idempotent.

-- ---------------------------------------------------------------------------------------------
-- 1. Routines. The ten functions, as the canonical files define them.
-- ---------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION polaris_utc_date()
RETURNS DATE
LANGUAGE sql STABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
SET timezone = 'UTC'
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
SET timezone = 'UTC'
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
    -- signed with an algorithm the system already considers retired/weakened:
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
    -- p_signature_bytes: a real ML-DSA-65 signature when POLARIS_USE_REAL_PQC=1
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
    -- live here: the database now guarantees the audit row.
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
SET timezone = 'UTC'
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
SET timezone = 'UTC'
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

CREATE OR REPLACE FUNCTION retention_cutoff(
    p_table_class  VARCHAR(24),
    p_jurisdiction VARCHAR(10) DEFAULT NULL
)
RETURNS TIMESTAMPTZ
LANGUAGE sql STABLE
SET timezone = 'UTC'
AS $$
    SELECT now() - make_interval(days => retention_days_for(p_table_class, p_jurisdiction));
$$;

CREATE OR REPLACE FUNCTION uc_issue_credential_copy(
    p_token_value  VARCHAR(128),
    p_agency_id    INTEGER,
    p_valid_for    INTERVAL DEFAULT INTERVAL '30 days'
) RETURNS TABLE (copy_id BIGINT, list_day DATE, list_no INTEGER, status_index INTEGER,
                 expires_at TIMESTAMP, legal_name VARCHAR(200), date_of_birth DATE,
                 jurisdiction VARCHAR(10))
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
SET timezone = 'UTC'
AS $$
DECLARE
    v_token_id    INTEGER;
    v_status      VARCHAR(20);
    v_agency      INTEGER;
    v_individual  INTEGER;
    v_expiration  DATE;
    -- The UTC wall clock, not the session's: list_day, issued_at and expires_at are all
    -- read from this, and a session's timezone must move none of them (2026-09-28).
    v_now         TIMESTAMP := (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
    v_exp         TIMESTAMP;
    v_copy        BIGINT;
    v_list_no     INTEGER;
    v_index       INTEGER;
    v_tries       INTEGER := 0;
BEGIN
    IF p_valid_for IS NULL OR p_valid_for <= INTERVAL '0' OR p_valid_for > INTERVAL '30 days' THEN
        RAISE EXCEPTION 'a wallet copy lives more than nothing and at most thirty days, not %', p_valid_for
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- FOR SHARE: a revocation in flight waits for this record, or this waits for it, so a copy
    -- is never recorded against a credential whose revocation has already committed.
    SELECT t.token_id, t.status, t.issuing_agency_id, t.individual_id, t.expiration_date
      INTO v_token_id, v_status, v_agency, v_individual, v_expiration
      FROM IdentityToken t
     WHERE t.token_value = p_token_value
       FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no credential has that value' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'a wallet copy is issued only for an ACTIVE credential; this one is %', v_status
            USING ERRCODE = 'check_violation';
    END IF;
    IF v_agency <> p_agency_id THEN
        RAISE EXCEPTION 'the credential was issued by agency %, not %', v_agency, p_agency_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    v_exp := date_trunc('second', v_now + p_valid_for);
    IF v_expiration IS NOT NULL AND v_expiration::TIMESTAMP < v_exp THEN
        v_exp := v_expiration::TIMESTAMP;
    END IF;
    IF v_exp <= v_now THEN
        RAISE EXCEPTION 'the credential expires before a copy could be valid'
            USING ERRCODE = 'check_violation';
    END IF;

    v_copy := nextval(pg_get_serial_sequence('credentialcopy', 'copy_id'));
    v_list_no := (v_copy / 524288)::INTEGER;
    LOOP
        v_tries := v_tries + 1;
        v_index := (('x' || substr(replace(gen_random_uuid()::TEXT, '-', ''), 1, 8))::BIT(32)::INTEGER
                    & 1048575);
        BEGIN
            INSERT INTO CredentialCopy (copy_id, token_id, agency_id, list_day, list_no,
                                        status_index, format, issued_at, expires_at)
            VALUES (v_copy, v_token_id, p_agency_id, v_now::DATE, v_list_no,
                    v_index, 'dc+sd-jwt', v_now, v_exp);
            EXIT;
        EXCEPTION WHEN unique_violation THEN
            IF v_tries >= 64 THEN
                RAISE EXCEPTION 'no free status index after 64 draws in a list at most half full'
                    USING ERRCODE = 'program_limit_exceeded';
            END IF;
        END;
    END LOOP;

    RETURN QUERY
        SELECT v_copy, v_now::DATE, v_list_no, v_index, v_exp,
               i.legal_name, i.date_of_birth, i.jurisdiction
          FROM Individual i
         WHERE i.individual_id = v_individual;
END $$;

CREATE OR REPLACE FUNCTION credential_copy_valid_indexes(p_agency_id INTEGER, p_list_day DATE,
                                                         p_list_no INTEGER)
RETURNS TABLE (status_index INTEGER)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
SET timezone = 'UTC'
AS $$
    SELECT c.status_index
      FROM CredentialCopy c
      JOIN IdentityToken t ON t.token_id = c.token_id
     WHERE c.agency_id = p_agency_id
       AND c.list_day = p_list_day
       AND c.list_no = p_list_no
       AND t.status = 'ACTIVE'
       AND c.expires_at > (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
$$;

CREATE OR REPLACE FUNCTION audit_token_state_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
SET timezone = 'UTC'
AS $$
DECLARE
    v_event_type    VARCHAR(40);
    v_actor         INTEGER;
    v_reason        VARCHAR(60);
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

    -- Optional session-level actor and reason. current_setting returns '' when the GUC is
    -- unset (with missing_ok = true). The row carries no location: the polaris.event_lat and
    -- event_lon settings it once read were set by nothing, and since lab/strategy/009 step 4c
    -- nothing shows a coordinate, so a session can no longer start a location trail here.
    v_actor  := NULLIF(current_setting('polaris.actor_agency_id', true), '')::INTEGER;
    v_reason := NULLIF(current_setting('polaris.reason_code',     true), '');

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
        token_id, actor_agency_id, event_type, reason_code, event_timestamp
    )
    VALUES (
        NEW.token_id, v_actor, v_event_type,
        COALESCE(v_reason, 'AUTO_AUDIT_TRIGGER'),
        CURRENT_TIMESTAMP
    );

    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION enforce_agency_quota()
RETURNS TRIGGER LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
SET timezone = 'UTC'
AS $$
DECLARE
    v_kind      TEXT := TG_ARGV[0];      -- 'issue' | 'revoke' | 'verify'
    v_agency_id INTEGER;
    v_cap       INTEGER;
    v_window    INTERVAL;
    v_count     INTEGER;
BEGIN
    IF v_kind = 'verify' THEN
        v_agency_id := NEW.requesting_agency_id;
    ELSE
        v_agency_id := NEW.issuing_agency_id;
    END IF;

    -- Only a NEW transition into REVOKED is a revocation. Nested on purpose:
    -- PL/pgSQL compiles the whole condition, and VerificationEvent rows have
    -- no status column, so a flat `v_kind = 'revoke' AND NEW.status ...`
    -- raised "record new has no field status" on every verification.
    IF v_kind = 'revoke' THEN
        IF NEW.status <> 'REVOKED' OR OLD.status = 'REVOKED' THEN
            RETURN NEW;
        END IF;
    END IF;

    -- Cheap exit: no quota row, or no cap of this kind.
    SELECT CASE v_kind
               WHEN 'issue'  THEN issue_per_day
               WHEN 'revoke' THEN revoke_per_day
               ELSE               verify_per_hour
           END
      INTO v_cap
      FROM AgencyQuota
     WHERE agency_id = v_agency_id
       AND superseded_at IS NULL;   -- v9.424: a superseded cap does not bind
    IF v_cap IS NULL THEN
        RETURN NEW;
    END IF;

    v_window := CASE v_kind WHEN 'verify' THEN INTERVAL '1 hour' ELSE INTERVAL '1 day' END;

    -- C9: serialize the count-then-write per (kind, agency).
    PERFORM pg_advisory_xact_lock(
        hashtext('polaris.quota.' || v_kind || '.' || v_agency_id::TEXT));

    IF v_kind = 'issue' THEN
        SELECT count(*) INTO v_count
          FROM IdentityToken
         WHERE issuing_agency_id = v_agency_id
           AND issued_date > CURRENT_TIMESTAMP - v_window;
    ELSIF v_kind = 'revoke' THEN
        SELECT count(*) INTO v_count
          FROM TokenLifecycleEvent e
          JOIN IdentityToken t ON t.token_id = e.token_id
         WHERE t.issuing_agency_id = v_agency_id
           AND e.event_type = 'REVOKED'
           AND e.event_timestamp > CURRENT_TIMESTAMP - v_window;
    ELSE
        SELECT count(*) INTO v_count
          FROM VerificationEvent
         WHERE requesting_agency_id = v_agency_id
           AND event_timestamp > CURRENT_TIMESTAMP - v_window;
    END IF;

    IF v_count + 1 > v_cap THEN
        RAISE EXCEPTION
            'quota exceeded: agency % has reached its % quota of % per % (AgencyQuota)',
            v_agency_id, v_kind, v_cap,
            CASE v_kind WHEN 'verify' THEN 'hour' ELSE 'day' END
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END$$;

CREATE OR REPLACE FUNCTION enforce_vouching_rules()
RETURNS TRIGGER
LANGUAGE plpgsql
SET timezone = 'UTC'
AS $$
DECLARE
    v_referee_level  VARCHAR(6);
    v_cosigner_level VARCHAR(6);
    v_seen           INTEGER;
BEGIN
    SELECT derived_ial INTO v_referee_level
      FROM EnrollmentProofing
     WHERE individual_id = NEW.referee_individual_id
     ORDER BY recorded_at DESC, proofing_id DESC
     LIMIT 1;
    IF v_referee_level IS NULL THEN
        RAISE EXCEPTION 'referee % has no proofing record; a referee lends an assurance they must hold',
            NEW.referee_individual_id
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.referee_ial IS DISTINCT FROM v_referee_level THEN
        RAISE EXCEPTION 'referee_ial is %, but referee % is proofed at %; the level is derived, never chosen',
            NEW.referee_ial, NEW.referee_individual_id, v_referee_level
            USING ERRCODE = 'check_violation';
    END IF;

    IF NEW.co_signer_individual_id IS NOT NULL THEN
        SELECT derived_ial INTO v_cosigner_level
          FROM EnrollmentProofing
         WHERE individual_id = NEW.co_signer_individual_id
         ORDER BY recorded_at DESC, proofing_id DESC
         LIMIT 1;
        IF v_cosigner_level IS NULL OR v_cosigner_level < 'IAL2' THEN
            RAISE EXCEPTION 'co-signer % is not proofed at IAL2 or above; a co-signer is a second proofed person',
                NEW.co_signer_individual_id
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext('polaris.referee_vouching'), NEW.referee_individual_id);
    SELECT count(*) INTO v_seen
      FROM RefereeVouching
     WHERE referee_individual_id = NEW.referee_individual_id
       AND vouched_at >= CURRENT_TIMESTAMP - interval '30 days';
    IF v_seen >= 25 AND NEW.co_signer_individual_id IS NULL THEN
        RAISE EXCEPTION 'referee % has vouched % time(s) in the last 30 days, at or past the bound of 25; this vouching needs a co-signer',
            NEW.referee_individual_id, v_seen
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END;
$$;

-- The procedures and the two foresight functions keep their bodies; only the setting changes.
ALTER PROCEDURE uc8_revoke_token(INTEGER, INTEGER, VARCHAR, VARCHAR, INTEGER) SET timezone = 'UTC';
ALTER PROCEDURE uc9_initiate_recovery(INTEGER, INTEGER, INTEGER, INTEGER) SET timezone = 'UTC';
ALTER PROCEDURE uc9_complete_recovery(INTEGER, INTEGER, VARCHAR, TEXT, VARCHAR, VARCHAR, INTEGER, VARCHAR, VARCHAR, VARCHAR, BYTEA, VARCHAR) SET timezone = 'UTC';
ALTER PROCEDURE uc6_migrate_algorithm(INTEGER, INTEGER, BYTEA, BOOLEAN, TEXT) SET timezone = 'UTC';
ALTER PROCEDURE close_anchor_batch(INTEGER, VARCHAR, JSONB) SET timezone = 'UTC';
ALTER PROCEDURE uc10_revoke_attestation(INTEGER, VARCHAR, INTEGER) SET timezone = 'UTC';
ALTER PROCEDURE uc_archive_purge(TIMESTAMPTZ, VARCHAR, VARCHAR, INTEGER, VARCHAR, TIMESTAMPTZ[], BIGINT) SET timezone = 'UTC';
ALTER PROCEDURE uc_apply_retention_template(VARCHAR, VARCHAR, INTEGER) SET timezone = 'UTC';
ALTER PROCEDURE uc_set_retention_policy(VARCHAR, VARCHAR, INTEGER, TEXT, INTEGER, INTEGER, INTEGER) SET timezone = 'UTC';
ALTER PROCEDURE uc_bulk_issue(INTEGER, INTEGER) SET timezone = 'UTC';
ALTER PROCEDURE uc_ensure_event_partitions(INTEGER) SET timezone = 'UTC';
ALTER FUNCTION foresight_token_age_distribution() SET timezone = 'UTC';
ALTER FUNCTION foresight_verification_dormancy(INTEGER) SET timezone = 'UTC';

-- ---------------------------------------------------------------------------------------------
-- 2. Column defaults: the UTC wall clock, whoever inserts the row and from whatever zone.
-- ---------------------------------------------------------------------------------------------
ALTER TABLE Individual ALTER COLUMN enrollment_date SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE AppUser ALTER COLUMN created_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE RelyingParty ALTER COLUMN created_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE AgencyEvent ALTER COLUMN recorded_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE AppUserEvent ALTER COLUMN recorded_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE RelyingPartyEvent ALTER COLUMN recorded_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE ExchangeReceiptLog ALTER COLUMN minted_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE TimestampLog ALTER COLUMN anchored_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE ChainAnchor ALTER COLUMN recorded_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE BackupEvent ALTER COLUMN completed_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE RestoreRecord ALTER COLUMN recorded_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE ExchangeNonce ALTER COLUMN consumed_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE AuthCodeConsumed ALTER COLUMN consumed_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE AuthorityKeyEvent
    ALTER COLUMN effective_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'),
    ALTER COLUMN recorded_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE AuthAuditLog ALTER COLUMN event_timestamp SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE IdentityToken ALTER COLUMN issued_date SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE TokenLifecycleEvent ALTER COLUMN event_timestamp SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE VerificationEvent ALTER COLUMN event_timestamp SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE DeviceBinding ALTER COLUMN authorized_date SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE BlockchainAnchor ALTER COLUMN anchored_date SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE RevocationList ALTER COLUMN revocation_timestamp SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE AgencyAlgorithmAuth ALTER COLUMN authorized_date SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE TokenPermission ALTER COLUMN granted_date SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE IssuerDiscretionPolicy ALTER COLUMN set_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE AgencyQuota ALTER COLUMN set_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE EnrollmentStatusEvent ALTER COLUMN event_timestamp SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE IndividualErasureEvent ALTER COLUMN event_timestamp SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE RecoveryRequest ALTER COLUMN requested_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE TokenSignature ALTER COLUMN signed_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE AnchorBatch ALTER COLUMN created_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE HolderKeyEvent
    ALTER COLUMN effective_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'),
    ALTER COLUMN recorded_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE CredentialCopy ALTER COLUMN issued_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE AgencyTrustAttestation ALTER COLUMN attested_date SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE TokenStateEpoch
    ALTER COLUMN valid_from SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'),
    ALTER COLUMN closed_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE DuressEvent ALTER COLUMN event_timestamp SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE EnrollmentProofing ALTER COLUMN recorded_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE RefereeVouching ALTER COLUMN vouched_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE EnrollmentCode ALTER COLUMN issued_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE CardPersonalization ALTER COLUMN personalized_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
ALTER TABLE BulkEnrollmentBatch ALTER COLUMN created_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');

-- ---------------------------------------------------------------------------------------------
-- 3. Views.
-- ---------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW HolderKeyCurrent WITH (security_invoker = true) AS
SELECT DISTINCT ON (hke.token_id)
       hke.token_id,
       hke.public_key_hex,
       hke.algorithm,
       hke.event,
       hke.effective_at
  FROM HolderKeyEvent hke
 WHERE hke.effective_at <= (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
 ORDER BY hke.token_id, hke.effective_at DESC, hke.event_id DESC;

CREATE OR REPLACE VIEW v_ontology_token WITH (security_invoker = true) AS
SELECT
    t.token_id,
    t.token_value,
    t.physical_serial,
    t.individual_id,
    t.issuing_agency_id,
    t.algorithm_id,
    t.predecessor_token_id,
    t.activation_sequence,
    t.status,
    t.issued_date,
    t.activated_date,
    t.expiration_date,
    -- Anti-coercion property: does this token have a duress code enrolled?
    (t.duress_code_hash IS NOT NULL) AS has_duress_code,
    -- Computed: age in days
    EXTRACT(EPOCH FROM ((NOW() AT TIME ZONE 'UTC') - t.issued_date)) / 86400.0
        AS age_days,
    -- Computed: lifetime event counts
    (SELECT COUNT(*) FROM TokenLifecycleEvent l
      WHERE l.token_id = t.token_id) AS lifecycle_event_count,
    (SELECT COUNT(*) FROM VerificationEvent v
      WHERE v.token_id = t.token_id) AS verification_event_count,
    (SELECT COUNT(*) FROM TokenSignature s
      WHERE s.token_id = t.token_id) AS signature_count,
    -- Linked objects (resolved labels for ontology consumers)
    i.legal_name AS individual_legal_name,
    ag.name      AS issuing_agency_name,
    alg.name     AS algorithm_name,
    alg.quantum_resistant
FROM IdentityToken t
JOIN Individual            i   ON t.individual_id     = i.individual_id
JOIN Agency                ag  ON t.issuing_agency_id = ag.agency_id
JOIN CryptographicAlgorithm alg ON t.algorithm_id     = alg.algorithm_id;
