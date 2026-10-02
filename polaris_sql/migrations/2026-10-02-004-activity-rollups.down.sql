-- 2026-10-02-004 down: drop the activity rollups, their triggers and routines, and restore the
-- purge without its rollup step. Nothing of the release that added them reads the rollups yet;
-- a later release's Atlas does, so roll that back first.
DROP TRIGGER IF EXISTS trg_activity_rollup_lifecycle_truncate ON TokenLifecycleEvent;
DROP TRIGGER IF EXISTS trg_activity_rollup_lifecycle_insert ON TokenLifecycleEvent;
DROP TRIGGER IF EXISTS trg_activity_rollup_verification_truncate ON VerificationEvent;
DROP TRIGGER IF EXISTS trg_activity_rollup_verification_insert ON VerificationEvent;
DROP FUNCTION IF EXISTS activity_rollup_truncated();
DROP FUNCTION IF EXISTS activity_rollup_lifecycles();
DROP FUNCTION IF EXISTS activity_rollup_verifications();

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

DROP FUNCTION IF EXISTS uc_rebuild_activity_rollups();
DROP FUNCTION IF EXISTS uc_fold_activity_rollups();
DROP TABLE IF EXISTS LifecycleRollupDelta;
DROP TABLE IF EXISTS LifecycleRollupDaily;
DROP TABLE IF EXISTS LifecycleRollup;
DROP TABLE IF EXISTS VerificationRollupDelta;
DROP TABLE IF EXISTS VerificationRollupDaily;
DROP TABLE IF EXISTS VerificationRollup;
