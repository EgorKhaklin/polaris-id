-- 2026-09-24-003: a deactivated admin authorizes nothing.
--
-- Five admin-gated procedures checked AppUser.role and not AppUser.is_active, so a DEACTIVATED
-- admin's user id still authorized a federation attestation, its revocation, an epoch closure,
-- a retention template and an archive purge (the one DELETE path into the append-only audit).
-- uc9_complete_recovery and uc_pseudonymize_individual already refused a deactivated actor.
-- The web routes could not reach these with a deactivated account, whose sessions end; the CLI
-- and the operator scripts pass a user id straight in. Each now refuses, with
-- insufficient_privilege, after its role check. Bodies are copied from 05_procedures.sql, which
-- carries the same change for a fresh install.

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
    IF p_valid_until <= CURRENT_DATE THEN
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


CREATE OR REPLACE PROCEDURE uc10_revoke_attestation(
    p_attestation_id    INTEGER,
    p_revocation_reason VARCHAR(80),
    p_signed_by         INTEGER
)
LANGUAGE plpgsql AS $$
DECLARE
    v_attesting_id  INTEGER;
    v_already_rev   TIMESTAMP;
    v_user_role     TEXT;
BEGIN
    -- Read the attesting agency for the lock key + existence check. Existence is
    -- stable (attestations are not deleted); the mutable revocation_date is
    -- re-read under the lock below, NOT here.
    SELECT attesting_agency_id
      INTO v_attesting_id
      FROM AgencyTrustAttestation
     WHERE attestation_id = p_attestation_id;

    IF v_attesting_id IS NULL THEN
        RAISE EXCEPTION
            'Attestation % does not exist', p_attestation_id
            USING ERRCODE = 'no_data_found';
    END IF;

    -- C9: per-attesting-agency advisory lock FIRST (same key as
    -- uc10_attest_trust, so attest+revoke on the same agency serialize). The
    -- already-revoked guard MUST be checked after the lock: if it ran before,
    -- two concurrent revokes would both pass a pre-lock read and the second
    -- would silently overwrite the first's reason and timestamp.
    -- uc8_revoke_token uses the same lock-first ordering.
    PERFORM pg_advisory_xact_lock(
        hashtext('polaris.federation.attest.' || v_attesting_id::TEXT));

    -- Re-read the revocation state under the lock (row-locked) and reject a
    -- double-revoke. A second caller that waited on the lock now sees the
    -- first's committed revocation_date and fails cleanly.
    --
    -- FOR UPDATE here is the SECOND of two sufficient mechanisms, measured on
    -- 2026-09-14: dropping it leaves all 866 tests green, dropping the advisory
    -- lock above leaves all 866 green, dropping BOTH turns the suite red. The
    -- advisory lock on the attesting agency already serializes every caller that
    -- could collide on this row. Keep both: a green suite after removing either
    -- one says the other covered it, not that the clause was dead.
    SELECT revocation_date INTO v_already_rev
      FROM AgencyTrustAttestation
     WHERE attestation_id = p_attestation_id
       FOR UPDATE;
    IF v_already_rev IS NOT NULL THEN
        RAISE EXCEPTION
            'Attestation % is already revoked at %', p_attestation_id, v_already_rev;
    END IF;

    -- Validate admin role on signer.
    SELECT role INTO v_user_role FROM AppUser WHERE user_id = p_signed_by;
    IF v_user_role IS NULL THEN
        RAISE EXCEPTION 'AppUser % not found', p_signed_by
            USING ERRCODE = 'no_data_found';
    END IF;
    IF v_user_role <> 'admin' THEN
        RAISE EXCEPTION
            'Federation revocation requires admin role (signer % has role %)',
            p_signed_by, v_user_role
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- 2026-09-24: an admin whose account is DEACTIVATED held this authority as fully as a
    -- live one. uc9_complete_recovery and uc_pseudonymize_individual refused a deactivated
    -- actor; the five procedures below checked the role alone.
    IF NOT (SELECT is_active FROM AppUser WHERE user_id = p_signed_by) THEN
        RAISE EXCEPTION 'uc10_revoke_attestation: user % is not an active account', p_signed_by
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- The schema's revocation_consistency CHECK enforces the 8-char
    -- reason floor; we let the constraint surface the readable error.
    UPDATE AgencyTrustAttestation
       SET revocation_date   = CURRENT_TIMESTAMP,
           revocation_reason = p_revocation_reason
     WHERE attestation_id = p_attestation_id;

    RAISE NOTICE 'uc10_revoke_attestation: revoked attestation %', p_attestation_id;
END$$;


CREATE OR REPLACE PROCEDURE uc11_close_epoch(
    p_merkle_root      VARCHAR(128),
    p_valid_until      TIMESTAMP,
    p_closed_by        INTEGER,
    -- token_leaves: JSON array of objects [{"token_id": int, "leaf_hash": hex, "proof_path": [...]}, ...]
    p_token_leaves     JSONB
)
LANGUAGE plpgsql AS $$
DECLARE
    v_new_epoch_id  INTEGER;
    v_count         INTEGER;
    v_user_role     TEXT;
    v_leaf          JSONB;
BEGIN
    -- C9: per-procedure advisory lock — serializes epoch closures (otherwise
    -- two concurrent calls would race on the INSERT).
    PERFORM pg_advisory_xact_lock(
        hashtext('polaris.zk.close-epoch'));

    -- Validate admin role.
    SELECT role INTO v_user_role FROM AppUser WHERE user_id = p_closed_by;
    IF v_user_role IS NULL THEN
        RAISE EXCEPTION 'AppUser % not found', p_closed_by
            USING ERRCODE = 'no_data_found';
    END IF;
    IF v_user_role <> 'admin' THEN
        RAISE EXCEPTION
            'Epoch closure requires admin role (signer % has role %)',
            p_closed_by, v_user_role
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- 2026-09-24: an admin whose account is DEACTIVATED held this authority as fully as a
    -- live one. uc9_complete_recovery and uc_pseudonymize_individual refused a deactivated
    -- actor; the five procedures below checked the role alone.
    IF NOT (SELECT is_active FROM AppUser WHERE user_id = p_closed_by) THEN
        RAISE EXCEPTION 'uc11_close_epoch: user % is not an active account', p_closed_by
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Count leaves.
    SELECT jsonb_array_length(p_token_leaves) INTO v_count;
    IF v_count IS NULL OR v_count = 0 THEN
        RAISE EXCEPTION
            'Cannot close an empty epoch (zero valid tokens to commit)'
            USING ERRCODE = 'no_data_found';
    END IF;
    IF v_count > 10000 THEN
        RAISE EXCEPTION
            'Epoch size (%) exceeds cap of 10000; split into multiple epochs', v_count;
    END IF;

    -- Create the epoch row. The CHECK constraints enforce hex format,
    -- valid_until > valid_from, count cap.
    INSERT INTO TokenStateEpoch
        (merkle_root, valid_until, committed_count, closed_by_user_id)
    VALUES (p_merkle_root, p_valid_until, v_count, p_closed_by)
    RETURNING epoch_id INTO v_new_epoch_id;

    -- Write per-leaf rows. Iterate over the JSON array.
    FOR v_leaf IN SELECT * FROM jsonb_array_elements(p_token_leaves)
    LOOP
        INSERT INTO TokenStateEpochLeaf
            (epoch_id, token_id, leaf_hash, proof_path)
        VALUES (
            v_new_epoch_id,
            (v_leaf ->> 'token_id')::INTEGER,
            v_leaf ->> 'leaf_hash',
            v_leaf -> 'proof_path'
        );
    END LOOP;

    RAISE NOTICE 'uc11_close_epoch: created epoch_id=%, % leaves, valid_until=%',
        v_new_epoch_id, v_count, p_valid_until;
END$$;


CREATE OR REPLACE PROCEDURE uc_archive_purge(
    p_cutoff_timestamp  TIMESTAMPTZ,
    p_archive_uri       VARCHAR(512),
    p_archive_sha256    VARCHAR(64),
    p_actor_user_id     INTEGER,
    p_jurisdiction      VARCHAR(10) DEFAULT NULL,
    p_class_cutoffs     TIMESTAMPTZ[] DEFAULT NULL,
    INOUT  checkpoint_id_out  BIGINT DEFAULT NULL
)
LANGUAGE plpgsql
-- SECURITY DEFINER (v9.85): this is the ONLY legitimate DELETE path against the
-- append-only audit tables, and polaris_app no longer holds UPDATE/DELETE on
-- them (09_grants.sql). The deletes must therefore run with the procedure
-- owner's rights, not the caller's. Safe to elevate because the actor is
-- authenticated by the p_actor_user_id PARAMETER checked against AppUser.role
-- below — never via current_user/session_user — so running as the owner does
-- not weaken the admin gate. search_path is pinned so the elevated body cannot
-- be redirected to attacker-controlled objects.
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_actor_role         VARCHAR(64);
    v_lifecycle_purged   INTEGER := 0;
    v_verification_purged INTEGER := 0;
    v_enrollment_purged  INTEGER := 0;
    v_authaudit_purged   INTEGER := 0;
    v_anchorbatch_purged INTEGER := 0;
    v_attestation_purged INTEGER := 0;
    v_duress_purged      INTEGER := 0;
    v_total_purged       INTEGER := 0;
    v_class              VARCHAR(24);
    v_class_cutoff       TIMESTAMPTZ;
    -- The cutoff that actually applies to each class. In flag mode all four
    -- equal p_cutoff_timestamp; in policy mode each is the class's own
    -- retention cutoff, bounded by the archive's coverage.
    v_cut_lifecycle      TIMESTAMPTZ;
    v_cut_verification   TIMESTAMPTZ;
    v_cut_enrollment     TIMESTAMPTZ;
    v_cut_authaudit      TIMESTAMPTZ;
    v_cutoff_source      VARCHAR(6);
BEGIN
    -- 1. Validate cutoff is in the past.
    IF p_cutoff_timestamp > now() THEN
        RAISE EXCEPTION 'uc_archive_purge: cutoff_timestamp (%) is in the future; refusing.',
            p_cutoff_timestamp
            USING ERRCODE = 'check_violation';
    END IF;

    -- 1b. Reconcile the requested cutoff with the retention policy (P1.11).
    --
    -- FLAG MODE (p_class_cutoffs IS NULL, the default): one cutoff for every
    -- class. Each class this procedure deletes from has an effective
    -- retention, and a cutoff younger than any of them would delete rows still
    -- inside their window, so the procedure refuses. It refuses rather than
    -- narrowing: a purge that silently deleted less than the operator asked
    -- for is the worse failure. Absent any configured policy the resolver
    -- returns the 365-day schema floor, so this refuses a recent-history purge
    -- even on a deployment that has recorded no decision.
    --
    -- POLICY MODE (v9.235): the caller supplies one cutoff per class, in the
    -- order TOKEN_LIFECYCLE, VERIFICATION, ENROLLMENT, AUTH_AUDIT. That is
    -- what a per-class retention schedule actually means: under MINIMIZED,
    -- verification history older than two years is purgeable while the token
    -- lifecycle is held for five, and one cutoff can express only one of
    -- those. The supplied cutoffs come from the archive's manifest, so they
    -- describe rows the archive demonstrably holds, and each is still checked
    -- against the class's own retention: a cutoff inside a window is refused
    -- here exactly as in flag mode. The procedure does NOT resolve the cutoffs
    -- itself, because retention_cutoff() advances with now() and would drift
    -- past the archive between the archive run and the purge.
    --
    -- The reconciliation runs BEFORE the carve-out opens.
    IF p_class_cutoffs IS NULL THEN
        v_cutoff_source := 'FLAG';
        FOR v_class, v_class_cutoff IN
            SELECT c, retention_cutoff(c, p_jurisdiction)
              FROM unnest(ARRAY['TOKEN_LIFECYCLE','VERIFICATION',
                                'ENROLLMENT','AUTH_AUDIT']::VARCHAR(24)[]) AS c
        LOOP
            IF p_cutoff_timestamp > v_class_cutoff THEN
                RAISE EXCEPTION
                    'uc_archive_purge: cutoff % is inside the retention window for % '
                    '(% days, purgeable only before %). Set a shorter retention with '
                    'uc_apply_retention_template, purge at an older cutoff, or purge '
                    'from an archive taken with --from-policy.',
                    p_cutoff_timestamp, v_class,
                    retention_days_for(v_class, p_jurisdiction), v_class_cutoff
                    USING ERRCODE = 'check_violation';
            END IF;
        END LOOP;
        v_cut_lifecycle    := p_cutoff_timestamp;
        v_cut_verification := p_cutoff_timestamp;
        v_cut_enrollment   := p_cutoff_timestamp;
        v_cut_authaudit    := p_cutoff_timestamp;
    ELSE
        v_cutoff_source := 'POLICY';
        IF array_length(p_class_cutoffs, 1) IS DISTINCT FROM 4
           OR array_position(p_class_cutoffs, NULL) IS NOT NULL THEN
            RAISE EXCEPTION
                'uc_archive_purge: p_class_cutoffs must hold exactly four non-null '
                'timestamps, ordered TOKEN_LIFECYCLE, VERIFICATION, ENROLLMENT, '
                'AUTH_AUDIT; got %.', p_class_cutoffs
                USING ERRCODE = 'check_violation';
        END IF;

        v_cut_lifecycle    := p_class_cutoffs[1];
        v_cut_verification := p_class_cutoffs[2];
        v_cut_enrollment   := p_class_cutoffs[3];
        v_cut_authaudit    := p_class_cutoffs[4];

        FOR v_class, v_class_cutoff IN
            SELECT c.class, c.cut FROM (VALUES
                ('TOKEN_LIFECYCLE'::VARCHAR(24), v_cut_lifecycle),
                ('VERIFICATION',                 v_cut_verification),
                ('ENROLLMENT',                   v_cut_enrollment),
                ('AUTH_AUDIT',                   v_cut_authaudit)
            ) AS c(class, cut)
        LOOP
            IF v_class_cutoff > now() THEN
                RAISE EXCEPTION
                    'uc_archive_purge: the cutoff for % (%) is in the future; refusing.',
                    v_class, v_class_cutoff
                    USING ERRCODE = 'check_violation';
            END IF;
            IF v_class_cutoff > retention_cutoff(v_class, p_jurisdiction) THEN
                RAISE EXCEPTION
                    'uc_archive_purge: the cutoff for % (%) is inside its retention '
                    'window (% days, purgeable only before %). The archive was taken '
                    'against a longer-lived policy than the one in force; re-archive '
                    'and purge from that.',
                    v_class, v_class_cutoff,
                    retention_days_for(v_class, p_jurisdiction),
                    retention_cutoff(v_class, p_jurisdiction)
                    USING ERRCODE = 'check_violation';
            END IF;
            IF p_cutoff_timestamp > v_class_cutoff THEN
                RAISE EXCEPTION
                    'uc_archive_purge: the scalar cutoff % is newer than the cutoff for '
                    '% (%). The manifest scalar must be the oldest of the per-class '
                    'cutoffs, so that a reader ignoring them cannot over-delete.',
                    p_cutoff_timestamp, v_class, v_class_cutoff
                    USING ERRCODE = 'check_violation';
            END IF;
        END LOOP;
    END IF;

    -- 2. Validate SHA-256 format.
    IF p_archive_sha256 IS NULL OR length(p_archive_sha256) <> 64
       OR p_archive_sha256 !~ '^[0-9a-fA-F]{64}$' THEN
        RAISE EXCEPTION 'uc_archive_purge: archive_sha256 must be 64 hex chars; got %',
            p_archive_sha256
            USING ERRCODE = 'check_violation';
    END IF;

    -- 3. Validate actor is admin (the procedure is admin-only).
    SELECT role INTO v_actor_role FROM AppUser WHERE user_id = p_actor_user_id;
    IF v_actor_role IS NULL THEN
        RAISE EXCEPTION 'uc_archive_purge: actor_user_id (%) does not exist.',
            p_actor_user_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    IF v_actor_role <> 'admin' THEN
        RAISE EXCEPTION 'uc_archive_purge: actor_user_id (%) has role %, must be admin.',
            p_actor_user_id, v_actor_role
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- 2026-09-24: an admin whose account is DEACTIVATED held this authority as fully as a
    -- live one. uc9_complete_recovery and uc_pseudonymize_individual refused a deactivated
    -- actor; the five procedures below checked the role alone.
    IF NOT (SELECT is_active FROM AppUser WHERE user_id = p_actor_user_id) THEN
        RAISE EXCEPTION 'uc_archive_purge: user % is not an active account', p_actor_user_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- 4. Open the carve-out. SET LOCAL is transaction-scoped; it
    --    cannot leak past COMMIT/ROLLBACK.
    SET LOCAL polaris.purge_in_progress = 'TRUE';

    -- 5. Issue the deletes. ORDER MATTERS for referential integrity:
    --    delete leaves before epochs (if Phase 2.5 ever extends purge
    --    to TokenStateEpoch); delete event tables in any order since
    --    they reference IdentityToken which is not purged.

    DELETE FROM TokenLifecycleEvent
        WHERE event_timestamp < v_cut_lifecycle;
    GET DIAGNOSTICS v_lifecycle_purged = ROW_COUNT;

    DELETE FROM VerificationEvent
        WHERE event_timestamp < v_cut_verification;
    GET DIAGNOSTICS v_verification_purged = ROW_COUNT;

    DELETE FROM EnrollmentStatusEvent
        WHERE event_timestamp < v_cut_enrollment;
    GET DIAGNOSTICS v_enrollment_purged = ROW_COUNT;

    DELETE FROM AuthAuditLog
        WHERE event_timestamp < v_cut_authaudit;
    GET DIAGNOSTICS v_authaudit_purged = ROW_COUNT;

    -- AnchorBatch is intentionally excluded from v8.87 Phase 2b
    -- because BlockchainAnchor.batch_id holds an FK reference;
    -- cleanly handling the cascade requires either NULLing the
    -- per-token anchor's batch_id (preserving the row but
    -- disconnecting the batch reference) or purging both together.
    -- Phase 2c will resolve this. AnchorBatch is low-volume (one
    -- row per algorithm-batch, not per token) so the storage
    -- pressure that motivated Phase 2b doesn't accrue here in any
    -- case. The checkpoint column is preserved for forward-compat.
    v_anchorbatch_purged := 0;

    -- AgencyTrustAttestation has its own enforce_attestation_immutability
    -- trigger (separate from reject_audit_modification); DuressEvent has
    -- its own enforce_duress_event_immutability. Both are deliberately
    -- strict and the v8.87 GUC carve-out does NOT apply to them. They
    -- stay out of Phase 2b's purge surface; Phase 2c can extend the
    -- carve-out pattern to their triggers if/when needed. For now,
    -- federation attestations and duress events stay in hot forever
    -- (operationally fine — both are low-volume audit-class).
    v_attestation_purged := 0;
    v_duress_purged := 0;

    v_total_purged := v_lifecycle_purged + v_verification_purged
                    + v_enrollment_purged + v_authaudit_purged
                    + v_anchorbatch_purged + v_attestation_purged
                    + v_duress_purged;

    -- 6. Write the checkpoint row. SAME transaction, so atomic
    --    with the deletes.
    INSERT INTO LifecycleArchiveCheckpoint (
        cutoff_timestamp,
        archive_uri,
        archive_sha256,
        actor_user_id,
        rows_purged_lifecycle,
        rows_purged_verification,
        rows_purged_enrollment,
        rows_purged_authaudit,
        rows_purged_anchorbatch,
        rows_purged_attestation,
        rows_purged_duress,
        rows_purged_total,
        cutoff_source,
        jurisdiction,
        cutoff_lifecycle,
        cutoff_verification,
        cutoff_enrollment,
        cutoff_authaudit
    ) VALUES (
        p_cutoff_timestamp,
        p_archive_uri,
        lower(p_archive_sha256),
        p_actor_user_id,
        v_lifecycle_purged,
        v_verification_purged,
        v_enrollment_purged,
        v_authaudit_purged,
        v_anchorbatch_purged,
        v_attestation_purged,
        v_duress_purged,
        v_total_purged,
        v_cutoff_source,
        p_jurisdiction,
        v_cut_lifecycle,
        v_cut_verification,
        v_cut_enrollment,
        v_cut_authaudit
    )
    RETURNING checkpoint_id INTO checkpoint_id_out;

    -- The GUC evaporates at transaction end; no explicit reset needed.
END;
$$;


CREATE OR REPLACE PROCEDURE uc_apply_retention_template(
    p_template       VARCHAR(24),
    p_jurisdiction   VARCHAR(10),
    p_actor_user_id  INTEGER
)
LANGUAGE plpgsql
-- SECURITY DEFINER for the same reason uc_archive_purge is: superseding a
-- policy is an UPDATE on an append-only table, and polaris_app is revoked
-- UPDATE there (09_grants.sql). The admin gate is the p_actor_user_id
-- parameter checked against AppUser.role below, never current_user, so
-- running as the owner does not weaken it. search_path is pinned so the
-- elevated body cannot be redirected.
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_role      VARCHAR(20);
    v_class     VARCHAR(24);
    v_days      INTEGER;
    v_reason    TEXT;
    v_applied   INTEGER := 0;
BEGIN
    IF p_template NOT IN ('STANDARD-5Y', 'MINIMIZED') THEN
        RAISE EXCEPTION 'uc_apply_retention_template: unknown template %; expected STANDARD-5Y or MINIMIZED',
            p_template USING ERRCODE = 'invalid_parameter_value';
    END IF;

    SELECT role INTO v_role FROM AppUser WHERE user_id = p_actor_user_id;
    IF v_role IS NULL THEN
        RAISE EXCEPTION 'uc_apply_retention_template: actor_user_id (%) does not exist.',
            p_actor_user_id USING ERRCODE = 'foreign_key_violation';
    END IF;
    IF v_role <> 'admin' THEN
        RAISE EXCEPTION 'uc_apply_retention_template: actor_user_id (%) has role %, must be admin.',
            p_actor_user_id, v_role USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- 2026-09-24: an admin whose account is DEACTIVATED held this authority as fully as a
    -- live one. uc9_complete_recovery and uc_pseudonymize_individual refused a deactivated
    -- actor; the five procedures below checked the role alone.
    IF NOT (SELECT is_active FROM AppUser WHERE user_id = p_actor_user_id) THEN
        RAISE EXCEPTION 'uc_apply_retention_template: user % is not an active account', p_actor_user_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Supersede whatever is effective for this jurisdiction, then append.
    FOR v_class, v_days, v_reason IN
        SELECT t.class, t.days, t.reason
          FROM (VALUES
            ('TOKEN_LIFECYCLE', CASE WHEN p_template = 'MINIMIZED' THEN 1825 ELSE 1825 END,
             'Template ' || p_template || ': the token''s own history is the civic record and is kept five years.'),
            ('ENROLLMENT',      CASE WHEN p_template = 'MINIMIZED' THEN 1825 ELSE 1825 END,
             'Template ' || p_template || ': enrolment status is the civic record and is kept five years.'),
            ('VERIFICATION',    CASE WHEN p_template = 'MINIMIZED' THEN 730  ELSE 1825 END,
             'Template ' || p_template || ': verification events are the most privacy-sensitive class; this is an engineering default, not a legal determination.'),
            ('AUTH_AUDIT',      CASE WHEN p_template = 'MINIMIZED' THEN 730  ELSE 1825 END,
             'Template ' || p_template || ': operator authentication events; this is an engineering default, not a legal determination.')
          ) AS t(class, days, reason)
    LOOP
        UPDATE RetentionPolicy
           SET superseded_at = now()
         WHERE table_class = v_class
           AND jurisdiction IS NOT DISTINCT FROM p_jurisdiction
           AND superseded_at IS NULL;

        INSERT INTO RetentionPolicy
            (table_class, jurisdiction, retention_days, justification, set_by_user_id)
        VALUES
            (v_class, p_jurisdiction, v_days, v_reason, p_actor_user_id);

        v_applied := v_applied + 1;
    END LOOP;

    RAISE NOTICE 'uc_apply_retention_template: % applied to % class(es) for jurisdiction %',
        p_template, v_applied, COALESCE(p_jurisdiction, '(deployment default)');
END;
$$;

