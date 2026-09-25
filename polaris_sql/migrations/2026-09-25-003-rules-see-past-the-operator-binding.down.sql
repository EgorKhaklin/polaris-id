-- Reverts 2026-09-25-003: the seven routines as they were, running as their caller.

CREATE OR REPLACE PROCEDURE uc6_migrate_algorithm(
    p_token_id        INTEGER,
    p_new_algorithm   INTEGER,
    p_new_signature   BYTEA,
    p_deprecate_old   BOOLEAN DEFAULT FALSE,
    p_signing_public_key_hex TEXT DEFAULT NULL
)
LANGUAGE plpgsql AS $$
DECLARE
    v_token_exists  INTEGER;
    v_alg_exists    INTEGER;
    v_new_sig_id    INTEGER;
    v_old_count     INTEGER;
BEGIN
    -- C9: per-token serialization. Two threads racing on the same token
    -- block each other on this lock; the loser sees the winner's row
    -- when its checks re-run.
    PERFORM pg_advisory_xact_lock(
        hashtext('polaris.migrate.' || p_token_id::TEXT));

    -- Validate the token exists.
    SELECT count(*) INTO v_token_exists
    FROM IdentityToken WHERE token_id = p_token_id;
    IF v_token_exists = 0 THEN
        RAISE EXCEPTION 'Token % does not exist', p_token_id;
    END IF;

    -- Validate the new algorithm exists and is not deprecated.
    SELECT count(*) INTO v_alg_exists
    FROM CryptographicAlgorithm
    WHERE algorithm_id = p_new_algorithm
      AND (deprecation_date IS NULL OR deprecation_date > CURRENT_TIMESTAMP);
    IF v_alg_exists = 0 THEN
        RAISE EXCEPTION
            'Algorithm % does not exist or is itself deprecated',
            p_new_algorithm;
    END IF;

    -- Insert the new TokenSignature row. The UNIQUE constraint
    -- (token_id, algorithm_id) rejects duplicate-algorithm migrations.
    -- v9.119: store the issuer public key with the migration signature, like
    -- uc1, so verify-at-use is self-contained. NULL for the placeholder path.
    INSERT INTO TokenSignature
        (token_id, algorithm_id, signature_bytes, signing_public_key_hex)
    VALUES
        (p_token_id, p_new_algorithm, p_new_signature, p_signing_public_key_hex)
    RETURNING signature_id INTO v_new_sig_id;

    -- Optionally deprecate the OLD signatures (every active sig other
    -- than the one just inserted). Setting deprecation_date is the
    -- one-way operation enforced by enforce_token_signature_immutability.
    IF p_deprecate_old THEN
        UPDATE TokenSignature
           SET deprecation_date = CURRENT_TIMESTAMP + INTERVAL '1 second'
         WHERE token_id = p_token_id
           AND signature_id <> v_new_sig_id
           AND deprecation_date IS NULL;
        -- The +1 second is required to satisfy the deprecation_after_signed
        -- CHECK; an instantaneous "deprecated at creation" doesn't make
        -- sense and the constraint refuses it.
    END IF;

    -- The enforce_token_has_active_signature trigger fired on the INSERT
    -- and the optional UPDATE; if either left the token with zero active
    -- signatures, the procedure would have already aborted. We're safe.

    RAISE NOTICE 'UC-6 migrated token %: new signature_id=% under algorithm %',
        p_token_id, v_new_sig_id, p_new_algorithm;
END$$;

CREATE OR REPLACE PROCEDURE uc9_initiate_recovery(
    p_individual_id      INTEGER,
    p_requesting_agency  INTEGER,
    p_requesting_user    INTEGER,
    p_cooldown_hours     INTEGER DEFAULT 48
)
LANGUAGE plpgsql AS $$
DECLARE
    v_active_count   INTEGER;
    v_pending_count  INTEGER;
    v_new_id         INTEGER;
BEGIN
    -- Reject if an ACTIVE token already exists — UC-4 is the right path.
    SELECT count(*) INTO v_active_count
    FROM IdentityToken
    WHERE individual_id = p_individual_id AND status = 'ACTIVE';
    IF v_active_count > 0 THEN
        RAISE EXCEPTION
            'Individual % has an ACTIVE token; use UC-4 reserve activation, not UC-9 recovery',
            p_individual_id
            USING ERRCODE = 'check_violation';
    END IF;

    -- Reject if a PENDING recovery already exists for this individual.
    SELECT count(*) INTO v_pending_count
    FROM RecoveryRequest
    WHERE claimed_individual_id = p_individual_id AND status = 'PENDING';
    IF v_pending_count > 0 THEN
        RAISE EXCEPTION
            'A PENDING recovery already exists for individual %',
            p_individual_id
            USING ERRCODE = 'unique_violation';
    END IF;

    INSERT INTO RecoveryRequest
        (claimed_individual_id, requesting_agency_id, requesting_user_id,
         cooldown_expires_at)
    VALUES
        (p_individual_id, p_requesting_agency, p_requesting_user,
         CURRENT_TIMESTAMP + (p_cooldown_hours || ' hours')::INTERVAL)
    RETURNING recovery_id INTO v_new_id;

    -- Surface the new id via NOTICE so callers without RETURNING can see it.
    RAISE NOTICE 'Created RecoveryRequest #%', v_new_id;
END$$;

CREATE OR REPLACE PROCEDURE uc12_record_duress(
    p_token_id              INTEGER,
    p_context_id            INTEGER,
    p_requesting_agency_id  INTEGER,
    p_oob_channel           VARCHAR(40) DEFAULT 'AUDIT_TABLE'
)
LANGUAGE plpgsql AS $$
BEGIN
    -- Validate that the token actually has a duress_code_hash enrolled.
    -- If the caller invoked this procedure for a token that hasn't enrolled
    -- duress, that's a programming error — fail loudly rather than write a
    -- nonsensical row.
    IF NOT EXISTS (
        SELECT 1 FROM IdentityToken
         WHERE token_id = p_token_id
           AND duress_code_hash IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'Token % has no duress code enrolled; cannot record duress event',
            p_token_id
            USING ERRCODE = 'no_data_found';
    END IF;

    INSERT INTO DuressEvent
        (token_id, context_id, requesting_agency_id, oob_channel)
    VALUES
        (p_token_id, p_context_id, p_requesting_agency_id, p_oob_channel);

    -- Server-side log (the operator's stderr is one of the v1 OOB channels;
    -- production would wire SMS/Slack/SIEM via oob_channel dispatching).
    RAISE NOTICE 'DURESS DETECTED: token_id=%, context_id=%, requesting_agency=%, channel=%',
        p_token_id, p_context_id, p_requesting_agency_id, p_oob_channel;
END$$;

CREATE OR REPLACE PROCEDURE close_anchor_batch(
    p_algorithm_id  INTEGER,
    p_merkle_root   VARCHAR(128),
    -- proofs is a JSON object: { "<anchor_id>": <proof_json>, ... }
    -- pre-computed by anchoring.py in the same call.
    p_proofs        JSONB
)
LANGUAGE plpgsql AS $$
DECLARE
    v_pending_count   INTEGER;
    v_new_batch_id    INTEGER;
    v_alg_exists      INTEGER;
BEGIN
    -- C9: per-algorithm advisory lock. See docs/design/concurrency.md
    -- ("Per-algorithm advisory-lock") for the rationale.
    PERFORM pg_advisory_xact_lock(
        hashtext('polaris.anchor.close-batch.' || p_algorithm_id::TEXT));

    -- Validate algorithm exists and is not deprecated.
    SELECT count(*) INTO v_alg_exists
    FROM CryptographicAlgorithm
    WHERE algorithm_id = p_algorithm_id
      AND (deprecation_date IS NULL OR deprecation_date > CURRENT_TIMESTAMP);
    IF v_alg_exists = 0 THEN
        RAISE EXCEPTION
            'Algorithm % does not exist or is deprecated; cannot close batch',
            p_algorithm_id;
    END IF;

    -- Count pending anchors for this algorithm. The leaf set is the
    -- BlockchainAnchor rows whose underlying token was signed under
    -- algorithm p_algorithm_id (via IdentityToken.algorithm_id) AND
    -- which are not yet batched.
    SELECT count(*) INTO v_pending_count
    FROM BlockchainAnchor a
    JOIN IdentityToken    t ON a.token_id = t.token_id
    WHERE a.batch_id IS NULL
      AND t.algorithm_id = p_algorithm_id;

    IF v_pending_count = 0 THEN
        RAISE EXCEPTION
            'No pending BlockchainAnchor rows for algorithm %; nothing to batch',
            p_algorithm_id
            USING ERRCODE = 'no_data_found';
    END IF;

    -- Hard cap per the proposal: 10,000 leaves per batch.
    IF v_pending_count > 10000 THEN
        RAISE EXCEPTION
            'Pending anchors (%) exceeds batch-size cap of 10000; close in multiple batches',
            v_pending_count;
    END IF;

    -- Create the AnchorBatch row. The append-only trigger on AnchorBatch
    -- will prevent any future UPDATE to merkle_root or DELETE.
    INSERT INTO AnchorBatch (merkle_root, algorithm_id, batch_size)
    VALUES (p_merkle_root, p_algorithm_id, v_pending_count)
    RETURNING batch_id INTO v_new_batch_id;

    -- Assign batch_id + per-leaf merkle_proof to every pending anchor of
    -- this algorithm. Deterministic leaf order (sort by anchor_id) defeats
    -- the publish-then-fork attack; the Python helper uses the same order
    -- when computing the proofs.
    UPDATE BlockchainAnchor a
       SET batch_id = v_new_batch_id,
           merkle_proof = (p_proofs ->> a.anchor_id::TEXT)::JSONB
      FROM IdentityToken t
     WHERE a.token_id = t.token_id
       AND a.batch_id IS NULL
       AND t.algorithm_id = p_algorithm_id;

    RAISE NOTICE 'close_anchor_batch: created batch_id=%, % leaves under algorithm %',
        v_new_batch_id, v_pending_count, p_algorithm_id;
END$$;

CREATE OR REPLACE FUNCTION enforce_revocation_status()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_status VARCHAR(20);
BEGIN
    SELECT status INTO v_status FROM IdentityToken WHERE token_id = NEW.token_id;
    IF v_status NOT IN ('REVOKED', 'LOST', 'EXPIRED') THEN
        RAISE EXCEPTION
            'Cannot add token % to RevocationList: status is % (must be REVOKED, LOST, or EXPIRED)',
            NEW.token_id, COALESCE(v_status, 'NULL')
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION enforce_predecessor_same_individual()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_predecessor_individual INTEGER;
BEGIN
    IF NEW.predecessor_token_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT individual_id INTO v_predecessor_individual
    FROM IdentityToken WHERE token_id = NEW.predecessor_token_id;
    IF v_predecessor_individual IS NULL THEN
        RAISE EXCEPTION 'predecessor_token_id % does not exist', NEW.predecessor_token_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    IF v_predecessor_individual != NEW.individual_id THEN
        RAISE EXCEPTION
            'predecessor_token_id % belongs to individual % but new token is for individual %; '
            'succession must be per-holder',
            NEW.predecessor_token_id, v_predecessor_individual, NEW.individual_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION enforce_agency_quota()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
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
