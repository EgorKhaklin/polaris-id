-- 2026-10-02-004: activity rollups that cost the same at any population (lab/strategy/009, step 4).
--
-- ADD:
--   VerificationRollup, VerificationRollupDaily, VerificationRollupDelta: verifications by hour
--     (and by day), requesting authority, context, outcome, disclosure level and the verified
--     credential's algorithm. LifecycleRollup, LifecycleRollupDaily, LifecycleRollupDelta:
--     lifecycle events by hour (and by day), acting authority and type. No column names a
--     person, a credential or a place, and none holds a coordinate. Row-level security by
--     authority, as on the event tables they count.
--   activity_rollup_verifications(), activity_rollup_lifecycles(), activity_rollup_truncated():
--     statement triggers that append each statement's counts. Writers only append.
--   uc_fold_activity_rollups(): moves the counts into the hourly and daily totals; the
--     application role may call it.
--   uc_rebuild_activity_rollups(): recounts from the event tables under a SHARE lock, keeping the
--     hours and days a recorded purge cut through; owner-only.
-- CHANGE:
--   uc_archive_purge folds the rollups and deletes the hourly rows of the hours wholly before its
--     cutoffs; the daily rows stay. Same signature, refusals and checkpoint.
--
-- EXPAND: the previous release neither reads nor writes the new tables, and its inserts into the
-- event tables fire the triggers like any other. Its purge is this one's less the rollup step.
-- LOCK: the closing recount SHARE-locks VerificationEvent and TokenLifecycleEvent until this
-- migration commits, so writers wait for it: on a large deployment, apply it in a maintenance
-- window.
-- REVERSIBLE: yes (the .down.sql drops every object here and restores the previous purge).

CREATE TABLE IF NOT EXISTS VerificationRollup (
    bucket               TIMESTAMP   NOT NULL,
    requesting_agency_id INTEGER     NOT NULL REFERENCES Agency(agency_id),
    context_id           INTEGER     NOT NULL REFERENCES VerificationContext(context_id),
    outcome              VARCHAR(20) NOT NULL,
    disclosure_level     VARCHAR(20) NOT NULL,
    algorithm_id         INTEGER     NOT NULL CHECK (algorithm_id >= 0),
    n                    BIGINT      NOT NULL CHECK (n > 0),
    PRIMARY KEY (bucket, requesting_agency_id, context_id, outcome, disclosure_level, algorithm_id)
);

CREATE TABLE IF NOT EXISTS VerificationRollupDaily (
    bucket               TIMESTAMP   NOT NULL,
    requesting_agency_id INTEGER     NOT NULL REFERENCES Agency(agency_id),
    context_id           INTEGER     NOT NULL REFERENCES VerificationContext(context_id),
    outcome              VARCHAR(20) NOT NULL,
    disclosure_level     VARCHAR(20) NOT NULL,
    algorithm_id         INTEGER     NOT NULL CHECK (algorithm_id >= 0),
    n                    BIGINT      NOT NULL CHECK (n > 0),
    PRIMARY KEY (bucket, requesting_agency_id, context_id, outcome, disclosure_level, algorithm_id)
);

CREATE TABLE IF NOT EXISTS VerificationRollupDelta (
    delta_id             BIGSERIAL   PRIMARY KEY,
    bucket               TIMESTAMP   NOT NULL,
    requesting_agency_id INTEGER     NOT NULL,
    context_id           INTEGER     NOT NULL,
    outcome              VARCHAR(20) NOT NULL,
    disclosure_level     VARCHAR(20) NOT NULL,
    algorithm_id         INTEGER     NOT NULL CHECK (algorithm_id >= 0),
    n                    BIGINT      NOT NULL CHECK (n > 0)
);

CREATE TABLE IF NOT EXISTS LifecycleRollup (
    bucket          TIMESTAMP   NOT NULL,
    actor_agency_id INTEGER     NOT NULL CHECK (actor_agency_id >= 0),
    event_type      VARCHAR(20) NOT NULL,
    n               BIGINT      NOT NULL CHECK (n > 0),
    PRIMARY KEY (bucket, actor_agency_id, event_type)
);

CREATE TABLE IF NOT EXISTS LifecycleRollupDaily (
    bucket          TIMESTAMP   NOT NULL,
    actor_agency_id INTEGER     NOT NULL CHECK (actor_agency_id >= 0),
    event_type      VARCHAR(20) NOT NULL,
    n               BIGINT      NOT NULL CHECK (n > 0),
    PRIMARY KEY (bucket, actor_agency_id, event_type)
);

CREATE TABLE IF NOT EXISTS LifecycleRollupDelta (
    delta_id        BIGSERIAL   PRIMARY KEY,
    bucket          TIMESTAMP   NOT NULL,
    actor_agency_id INTEGER     NOT NULL,
    event_type      VARCHAR(20) NOT NULL,
    n               BIGINT      NOT NULL CHECK (n > 0)
);

COMMENT ON TABLE VerificationRollup IS
  'Verifications by hour, requesting authority, context, outcome, disclosure level and the '
  'verified credential''s algorithm (lab/strategy/009, step 4). No person, credential or place. '
  'Folded from VerificationRollupDelta; a reader sums both. Hours wholly before a purge''s cutoff '
  'go with the purge.';
COMMENT ON TABLE VerificationRollupDaily IS
  'VerificationRollup by day, for windows longer than a week. Kept after a purge, as statistics.';
COMMENT ON TABLE VerificationRollupDelta IS
  'Verification counts not yet folded in, one row per statement and cell, appended by the '
  'statement trigger on VerificationEvent. Append-only for writers.';
COMMENT ON TABLE LifecycleRollup IS
  'Lifecycle events by hour, acting authority (0: none acted) and type (lab/strategy/009, '
  'step 4). Folded from LifecycleRollupDelta; a reader sums both. Hours wholly before a purge''s '
  'cutoff go with the purge.';
COMMENT ON TABLE LifecycleRollupDaily IS
  'LifecycleRollup by day, for windows longer than a week. Kept after a purge, as statistics.';
COMMENT ON TABLE LifecycleRollupDelta IS
  'Lifecycle counts not yet folded in, one row per statement and cell, appended by the '
  'statement trigger on TokenLifecycleEvent. Append-only for writers.';

ALTER TABLE VerificationRollup ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS verificationrollup_authority_isolation ON VerificationRollup;
CREATE POLICY verificationrollup_authority_isolation ON VerificationRollup
    USING (
        requesting_agency_id = coalesce(
            NULLIF(current_setting('polaris.operator_agency_id', true), '')::INTEGER,
            requesting_agency_id)
    );
ALTER TABLE VerificationRollupDaily ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS verificationrollupdaily_authority_isolation ON VerificationRollupDaily;
CREATE POLICY verificationrollupdaily_authority_isolation ON VerificationRollupDaily
    USING (
        requesting_agency_id = coalesce(
            NULLIF(current_setting('polaris.operator_agency_id', true), '')::INTEGER,
            requesting_agency_id)
    );
ALTER TABLE VerificationRollupDelta ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS verificationrollupdelta_authority_isolation ON VerificationRollupDelta;
CREATE POLICY verificationrollupdelta_authority_isolation ON VerificationRollupDelta
    USING (
        requesting_agency_id = coalesce(
            NULLIF(current_setting('polaris.operator_agency_id', true), '')::INTEGER,
            requesting_agency_id)
    );
ALTER TABLE LifecycleRollup ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS lifecyclerollup_authority_isolation ON LifecycleRollup;
CREATE POLICY lifecyclerollup_authority_isolation ON LifecycleRollup
    USING (
        actor_agency_id = 0
        OR actor_agency_id = coalesce(
            NULLIF(current_setting('polaris.operator_agency_id', true), '')::INTEGER,
            actor_agency_id)
    );
ALTER TABLE LifecycleRollupDaily ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS lifecyclerollupdaily_authority_isolation ON LifecycleRollupDaily;
CREATE POLICY lifecyclerollupdaily_authority_isolation ON LifecycleRollupDaily
    USING (
        actor_agency_id = 0
        OR actor_agency_id = coalesce(
            NULLIF(current_setting('polaris.operator_agency_id', true), '')::INTEGER,
            actor_agency_id)
    );
ALTER TABLE LifecycleRollupDelta ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS lifecyclerollupdelta_authority_isolation ON LifecycleRollupDelta;
CREATE POLICY lifecyclerollupdelta_authority_isolation ON LifecycleRollupDelta
    USING (
        actor_agency_id = 0
        OR actor_agency_id = coalesce(
            NULLIF(current_setting('polaris.operator_agency_id', true), '')::INTEGER,
            actor_agency_id)
    );

CREATE OR REPLACE FUNCTION uc_fold_activity_rollups()
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_verifications BIGINT := 0;
    v_lifecycles    BIGINT := 0;
BEGIN
    IF NOT pg_try_advisory_xact_lock(hashtext('polaris.activity.fold')) THEN
        RETURN 0;
    END IF;
    -- Additions only, so an upsert is safe here: the proposed row's CHECK (n > 0) holds for every
    -- change, unlike the population fold's decrements. One fold runs at a time (the lock above).
    WITH moved AS (
        DELETE FROM VerificationRollupDelta
        RETURNING bucket, requesting_agency_id, context_id, outcome, disclosure_level, algorithm_id, n
    ), hourly AS (
        INSERT INTO VerificationRollup AS r
               (bucket, requesting_agency_id, context_id, outcome, disclosure_level, algorithm_id, n)
        SELECT bucket, requesting_agency_id, context_id, outcome, disclosure_level, algorithm_id, sum(n)
          FROM moved
         GROUP BY bucket, requesting_agency_id, context_id, outcome, disclosure_level, algorithm_id
        ON CONFLICT (bucket, requesting_agency_id, context_id, outcome, disclosure_level, algorithm_id)
        DO UPDATE SET n = r.n + EXCLUDED.n
        RETURNING 1
    ), daily AS (
        INSERT INTO VerificationRollupDaily AS r
               (bucket, requesting_agency_id, context_id, outcome, disclosure_level, algorithm_id, n)
        SELECT date_trunc('day', bucket), requesting_agency_id, context_id, outcome, disclosure_level,
               algorithm_id, sum(n)
          FROM moved
         GROUP BY date_trunc('day', bucket), requesting_agency_id, context_id, outcome,
                  disclosure_level, algorithm_id
        ON CONFLICT (bucket, requesting_agency_id, context_id, outcome, disclosure_level, algorithm_id)
        DO UPDATE SET n = r.n + EXCLUDED.n
        RETURNING 1
    )
    SELECT count(*) INTO v_verifications FROM moved;

    WITH moved AS (
        DELETE FROM LifecycleRollupDelta
        RETURNING bucket, actor_agency_id, event_type, n
    ), hourly AS (
        INSERT INTO LifecycleRollup AS r (bucket, actor_agency_id, event_type, n)
        SELECT bucket, actor_agency_id, event_type, sum(n)
          FROM moved
         GROUP BY bucket, actor_agency_id, event_type
        ON CONFLICT (bucket, actor_agency_id, event_type) DO UPDATE SET n = r.n + EXCLUDED.n
        RETURNING 1
    ), daily AS (
        INSERT INTO LifecycleRollupDaily AS r (bucket, actor_agency_id, event_type, n)
        SELECT date_trunc('day', bucket), actor_agency_id, event_type, sum(n)
          FROM moved
         GROUP BY date_trunc('day', bucket), actor_agency_id, event_type
        ON CONFLICT (bucket, actor_agency_id, event_type) DO UPDATE SET n = r.n + EXCLUDED.n
        RETURNING 1
    )
    SELECT count(*) INTO v_lifecycles FROM moved;
    RETURN v_verifications + v_lifecycles;
END$$;

COMMENT ON FUNCTION uc_fold_activity_rollups() IS
  'Folds the activity rollup deltas into the hourly and daily totals (lab/strategy/009, step 4). '
  'Idempotent and non-blocking: one fold at a time, and a caller that finds one running returns 0.';

CREATE OR REPLACE FUNCTION uc_rebuild_activity_rollups()
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_cut_verification TIMESTAMPTZ;
    v_cut_lifecycle    TIMESTAMPTZ;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('polaris.activity.fold'));
    LOCK TABLE VerificationEvent, TokenLifecycleEvent IN SHARE MODE;
    PERFORM uc_fold_activity_rollups();
    SELECT max(COALESCE(cutoff_verification, cutoff_timestamp)),
           max(COALESCE(cutoff_lifecycle, cutoff_timestamp))
      INTO v_cut_verification, v_cut_lifecycle
      FROM LifecycleArchiveCheckpoint;

    DELETE FROM VerificationRollup
     WHERE v_cut_verification IS NULL
        OR bucket >= date_trunc('hour', v_cut_verification) + INTERVAL '1 hour';
    INSERT INTO VerificationRollup
           (bucket, requesting_agency_id, context_id, outcome, disclosure_level, algorithm_id, n)
    SELECT date_trunc('hour', ve.event_timestamp), ve.requesting_agency_id, ve.context_id,
           ve.outcome, ve.disclosure_level, COALESCE(t.algorithm_id, 0), count(*)
      FROM VerificationEvent ve
      LEFT JOIN IdentityToken t ON t.token_id = ve.token_id
     WHERE v_cut_verification IS NULL
        OR ve.event_timestamp >= date_trunc('hour', v_cut_verification) + INTERVAL '1 hour'
     GROUP BY date_trunc('hour', ve.event_timestamp), ve.requesting_agency_id, ve.context_id,
              ve.outcome, ve.disclosure_level, COALESCE(t.algorithm_id, 0);
    DELETE FROM VerificationRollupDaily
     WHERE v_cut_verification IS NULL
        OR bucket >= date_trunc('day', v_cut_verification) + INTERVAL '1 day';
    INSERT INTO VerificationRollupDaily
           (bucket, requesting_agency_id, context_id, outcome, disclosure_level, algorithm_id, n)
    SELECT date_trunc('day', bucket), requesting_agency_id, context_id, outcome, disclosure_level,
           algorithm_id, sum(n)
      FROM VerificationRollup
     WHERE v_cut_verification IS NULL
        OR bucket >= date_trunc('day', v_cut_verification) + INTERVAL '1 day'
     GROUP BY date_trunc('day', bucket), requesting_agency_id, context_id, outcome,
              disclosure_level, algorithm_id;

    DELETE FROM LifecycleRollup
     WHERE v_cut_lifecycle IS NULL
        OR bucket >= date_trunc('hour', v_cut_lifecycle) + INTERVAL '1 hour';
    INSERT INTO LifecycleRollup (bucket, actor_agency_id, event_type, n)
    SELECT date_trunc('hour', event_timestamp), COALESCE(actor_agency_id, 0), event_type, count(*)
      FROM TokenLifecycleEvent
     WHERE v_cut_lifecycle IS NULL
        OR event_timestamp >= date_trunc('hour', v_cut_lifecycle) + INTERVAL '1 hour'
     GROUP BY date_trunc('hour', event_timestamp), COALESCE(actor_agency_id, 0), event_type;
    DELETE FROM LifecycleRollupDaily
     WHERE v_cut_lifecycle IS NULL
        OR bucket >= date_trunc('day', v_cut_lifecycle) + INTERVAL '1 day';
    INSERT INTO LifecycleRollupDaily (bucket, actor_agency_id, event_type, n)
    SELECT date_trunc('day', bucket), actor_agency_id, event_type, sum(n)
      FROM LifecycleRollup
     WHERE v_cut_lifecycle IS NULL
        OR bucket >= date_trunc('day', v_cut_lifecycle) + INTERVAL '1 day'
     GROUP BY date_trunc('day', bucket), actor_agency_id, event_type;
END$$;

COMMENT ON FUNCTION uc_rebuild_activity_rollups() IS
  'Recounts the activity rollups from VerificationEvent and TokenLifecycleEvent under a SHARE lock '
  '(lab/strategy/009, step 4), keeping the hours and days a recorded purge cut through. '
  'Owner-only: a full pass over the events is a maintenance act.';

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

    -- The hourly activity rollups go with the hours they count (lab/strategy/009, step 4): what
    -- is pending is folded first, then the hours wholly before each cutoff are deleted. The daily
    -- rollups stay: they are the system's statistics, and say nothing finer than a day.
    PERFORM pg_advisory_xact_lock(hashtext('polaris.activity.fold'));
    PERFORM uc_fold_activity_rollups();
    DELETE FROM VerificationRollup WHERE bucket < date_trunc('hour', v_cut_verification);
    DELETE FROM LifecycleRollup    WHERE bucket < date_trunc('hour', v_cut_lifecycle);

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

CREATE OR REPLACE FUNCTION activity_rollup_verifications()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    -- The credential's algorithm as the verification is recorded; one that named no credential
    -- (zero-knowledge) counts under 0. No other property of the credential is read.
    INSERT INTO VerificationRollupDelta
           (bucket, requesting_agency_id, context_id, outcome, disclosure_level, algorithm_id, n)
    SELECT date_trunc('hour', e.event_timestamp), e.requesting_agency_id, e.context_id,
           e.outcome, e.disclosure_level, COALESCE(t.algorithm_id, 0), count(*)
      FROM new_rows e
      LEFT JOIN IdentityToken t ON t.token_id = e.token_id
     GROUP BY date_trunc('hour', e.event_timestamp), e.requesting_agency_id, e.context_id,
              e.outcome, e.disclosure_level, COALESCE(t.algorithm_id, 0);
    -- Now and then fold, so the changes stay few when nobody reads. A count must never stop a
    -- verification from being recorded: should the fold fail, the changes stay unfolded (a
    -- reader still sums them) and the insert goes on.
    IF random() < 0.002 THEN
        BEGIN
            PERFORM uc_fold_activity_rollups();
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'activity rollups not folded: %', SQLERRM;
        END;
    END IF;
    RETURN NULL;
END$$;

CREATE OR REPLACE FUNCTION activity_rollup_lifecycles()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    -- A transition no authority made (NULL actor: the system's, or the holder's device) counts
    -- under 0, which no authority is.
    INSERT INTO LifecycleRollupDelta (bucket, actor_agency_id, event_type, n)
    SELECT date_trunc('hour', e.event_timestamp), COALESCE(e.actor_agency_id, 0), e.event_type,
           count(*)
      FROM new_rows e
     GROUP BY date_trunc('hour', e.event_timestamp), COALESCE(e.actor_agency_id, 0), e.event_type;
    IF random() < 0.002 THEN
        BEGIN
            PERFORM uc_fold_activity_rollups();
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'activity rollups not folded: %', SQLERRM;
        END;
    END IF;
    RETURN NULL;
END$$;

-- TRUNCATE fires no row events, so it clears the rollups of the table it empties.
CREATE OR REPLACE FUNCTION activity_rollup_truncated()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF TG_TABLE_NAME = 'verificationevent' THEN
        DELETE FROM VerificationRollupDelta;
        DELETE FROM VerificationRollup;
        DELETE FROM VerificationRollupDaily;
    ELSE
        DELETE FROM LifecycleRollupDelta;
        DELETE FROM LifecycleRollup;
        DELETE FROM LifecycleRollupDaily;
    END IF;
    RETURN NULL;
END$$;

DROP TRIGGER IF EXISTS trg_activity_rollup_verification_insert ON VerificationEvent;
CREATE TRIGGER trg_activity_rollup_verification_insert
    AFTER INSERT ON VerificationEvent REFERENCING NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION activity_rollup_verifications();
DROP TRIGGER IF EXISTS trg_activity_rollup_verification_truncate ON VerificationEvent;
CREATE TRIGGER trg_activity_rollup_verification_truncate
    AFTER TRUNCATE ON VerificationEvent
    FOR EACH STATEMENT EXECUTE FUNCTION activity_rollup_truncated();
DROP TRIGGER IF EXISTS trg_activity_rollup_lifecycle_insert ON TokenLifecycleEvent;
CREATE TRIGGER trg_activity_rollup_lifecycle_insert
    AFTER INSERT ON TokenLifecycleEvent REFERENCING NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION activity_rollup_lifecycles();
DROP TRIGGER IF EXISTS trg_activity_rollup_lifecycle_truncate ON TokenLifecycleEvent;
CREATE TRIGGER trg_activity_rollup_lifecycle_truncate
    AFTER TRUNCATE ON TokenLifecycleEvent
    FOR EACH STATEMENT EXECUTE FUNCTION activity_rollup_truncated();

-- Definer routines are the owner's rights, lent: nobody's but the application role's
-- (09_grants.sql), and the recount not even its.
DO $$
DECLARE
    v_sig TEXT;
BEGIN
    FOR v_sig IN
        SELECT p.oid::regprocedure::text
          FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'public'
           AND p.proname IN ('uc_fold_activity_rollups', 'uc_rebuild_activity_rollups',
                             'activity_rollup_verifications', 'activity_rollup_lifecycles',
                             'activity_rollup_truncated')
    LOOP
        EXECUTE format('REVOKE EXECUTE ON ROUTINE %s FROM PUBLIC', v_sig);
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
            EXECUTE format('GRANT EXECUTE ON ROUTINE %s TO polaris_app', v_sig);
        END IF;
    END LOOP;
END$$;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT SELECT ON VerificationRollup, VerificationRollupDaily, VerificationRollupDelta,
            LifecycleRollup, LifecycleRollupDaily, LifecycleRollupDelta TO polaris_app;
        REVOKE INSERT, UPDATE, DELETE ON VerificationRollup, VerificationRollupDaily,
            VerificationRollupDelta, LifecycleRollup, LifecycleRollupDaily, LifecycleRollupDelta
            FROM polaris_app;
    END IF;
END$$;
DO $$
DECLARE
    v_sig TEXT;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        FOR v_sig IN
            SELECT p.oid::regprocedure::text
              FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'public' AND p.proname = 'uc_rebuild_activity_rollups'
        LOOP
            EXECUTE format('REVOKE EXECUTE ON ROUTINE %s FROM polaris_app', v_sig);
        END LOOP;
    END IF;
END$$;

-- Count what is already there.
SELECT uc_rebuild_activity_rollups();
