-- AI-context: append-only enforcement, audit trigger, lifecycle event auto-emission. Audit trigger reads polaris.{actor_agency_id, reason_code, event_lat, event_lon} GUCs. See docs/design/concurrency.md.
-- ============================================================================
-- POLARIS — IDENTITY TOKEN SYSTEM
-- 06_triggers.sql : State-machine enforcement triggers
--
-- Implements the legal-transition set from Appendix A's state machine as a
-- BEFORE UPDATE trigger on IdentityToken. This is the "database triggers"
-- enforcement option from the report's "Production Enforcement of the State
-- Machine" subsection — the strongest option because it guarantees
-- enforcement regardless of which client connects to the database.
--
-- Also implements the append-only invariant on TokenLifecycleEvent and
-- VerificationEvent: UPDATE and DELETE on these tables are rejected,
-- realizing NFR-4 ("the lifecycle table is append-only by convention and
-- tooling, not by storage engine") at the tooling layer.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- State-machine enforcement on IdentityToken.status
-- Legal transitions (from Figure 3, Appendix A):
--    *      → RESERVE   (issuance — INSERT, not handled by this trigger)
--    RESERVE → ACTIVE   (activation)
--    ACTIVE  → DORMANT  (deactivation through reserve promotion)
--    ACTIVE  → REVOKED  (terminal, dashed in figure)
--    ACTIVE  → LOST     (terminal)
--    ACTIVE  → EXPIRED  (terminal)
--    RESERVE → REVOKED  (administrative, NOT shown in figure but legal —
--                        this is the David case in the sample data, where
--                        a paperwork error voids a never-activated token)
-- All other transitions are illegal.
-- ----------------------------------------------------------------------------

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

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_token_state_machine ON IdentityToken;
CREATE TRIGGER trg_token_state_machine
    BEFORE UPDATE OF status ON IdentityToken
    FOR EACH ROW
    EXECUTE FUNCTION enforce_token_state_machine();

COMMENT ON FUNCTION enforce_token_state_machine IS
  'Enforces the legal-transition set from Appendix A. Rejects (OLD.status, '
  'NEW.status) pairs not in the legal set; also requires activated_date '
  'whenever a token transitions to ACTIVE.';

-- ----------------------------------------------------------------------------
-- Append-only enforcement on TokenLifecycleEvent.
-- The audit trail is the schema's repudiation defense (STRIDE Repudiation
-- mitigation in Appendix D); allowing UPDATE or DELETE would break the
-- non-repudiation property.
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION reject_audit_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_purge_in_progress TEXT;
BEGIN
    -- Arc B Phase 2b (v8.87) constitutional carve-out (Position B,
    -- DECIDED in a recorded decision):
    -- the uc_archive_purge() procedure sets a transaction-scoped GUC
    -- before issuing DELETE; this function honors that single carve-out.
    --
    -- Carve-out semantics:
    --   - Applies ONLY to DELETE (TG_OP = 'DELETE'). UPDATE still rejects.
    --   - The GUC is `polaris.purge_in_progress`. SET LOCAL means it
    --     evaporates at the transaction boundary; it cannot leak out of
    --     the procedure.
    --   - The procedure also writes a LifecycleArchiveCheckpoint row in
    --     the same transaction. If the row is missing for a DELETE that
    --     was committed, the audit chain is broken — but with the
    --     append-only checkpoint trigger + the v8.87 deferred-constraint
    --     setup, this is observable.
    --
    -- Outside the procedure, DELETE and UPDATE both fail with
    -- insufficient_privilege. The append-only contract still holds at
    -- the table-as-such level; the procedure is the only legitimate
    -- path through.
    IF TG_OP = 'DELETE' THEN
        v_purge_in_progress := current_setting('polaris.purge_in_progress', true);
        IF v_purge_in_progress = 'TRUE' THEN
            -- The carve-out is open. Allow the DELETE.
            RETURN OLD;
        END IF;
    END IF;

    RAISE EXCEPTION
        '% on % is forbidden: this table is append-only (audit invariant). '
        'For Phase 2b archive-then-delete, route through uc_archive_purge().',
        TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS trg_lifecycle_append_only ON TokenLifecycleEvent;
CREATE TRIGGER trg_lifecycle_append_only
    BEFORE UPDATE OR DELETE ON TokenLifecycleEvent
    FOR EACH ROW
    EXECUTE FUNCTION reject_audit_modification();

DROP TRIGGER IF EXISTS trg_verification_append_only ON VerificationEvent;
CREATE TRIGGER trg_verification_append_only
    BEFORE UPDATE OR DELETE ON VerificationEvent
    FOR EACH ROW
    EXECUTE FUNCTION reject_audit_modification();

-- v8.16 / R11-4 / M2-9 — extend the append-only invariant to
-- EnrollmentStatusEvent. The enrollment-state log is policy audit; once
-- written, it cannot be retroactively edited or removed.
DROP TRIGGER IF EXISTS trg_enrollment_event_append_only ON EnrollmentStatusEvent;
CREATE TRIGGER trg_enrollment_event_append_only
    BEFORE UPDATE OR DELETE ON EnrollmentStatusEvent
    FOR EACH ROW
    EXECUTE FUNCTION reject_audit_modification();

-- v9.125 — extend the append-only invariant to IndividualErasureEvent. The
-- record that a holder's name was pseudonymized is itself audit-of-record: if
-- an erasure row could be edited or removed, the erasure log could be made to
-- lie about whether (and by whom) an erasure happened. Once written, it stands.
DROP TRIGGER IF EXISTS trg_erasure_append_only ON IndividualErasureEvent;
CREATE TRIGGER trg_erasure_append_only
    BEFORE UPDATE OR DELETE ON IndividualErasureEvent
    FOR EACH ROW
    EXECUTE FUNCTION reject_audit_modification();

-- v8.21 / R10-2 / M2-2 — extend the append-only invariant to AnchorBatch.
-- The Merkle-log commitment is by definition immutable: rewriting the
-- merkle_root would break every inclusion proof issued against it.
-- AnchorBatch joins the four-table append-only set as the audit-of-record
-- for batch-time cryptographic commitments.
--
-- Note: committed_to_chain / external_chain / external_chain_tx are
-- legitimately mutable (operator sets them when the batch is pushed to
-- an external chain). Future hardening could split this into a narrower
-- trigger (immutable on merkle_root / algorithm_id / batch_size, mutable
-- on the chain-commit fields) — analogous to the
-- enforce_token_signature_immutability shape. For v1, the full append-only
-- trigger applies, and operators record external-chain commits via a
-- dedicated procedure (close_anchor_batch_chain — deferred per the
-- proposal's "What this is NOT").
DROP TRIGGER IF EXISTS trg_anchor_batch_append_only ON AnchorBatch;
CREATE TRIGGER trg_anchor_batch_append_only
    BEFORE UPDATE OR DELETE ON AnchorBatch
    FOR EACH ROW
    EXECUTE FUNCTION reject_audit_modification();

-- v8.87 / Arc B Phase 2b — LifecycleArchiveCheckpoint is the audit-of-record
-- for archive-then-delete purges. It must itself be append-only at full
-- strictness (the carve-out in reject_audit_modification only applies
-- when the procedure-set GUC is TRUE; checkpoint rows are written
-- INSIDE that procedure, so deletes against checkpoints would fall
-- through the same carve-out — but a separate, strict trigger ensures
-- the checkpoint chain is never broken even by a misconfigured procedure).
CREATE OR REPLACE FUNCTION reject_checkpoint_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- No carve-out. Checkpoints are the audit-of-record for the carve-out
    -- itself; if checkpoints could be deleted, the chain would not be
    -- self-consistent. G30 (v8.87) enforces this structurally.
    RAISE EXCEPTION
        '% on LifecycleArchiveCheckpoint is forbidden: '
        'the checkpoint chain is the audit-of-record for archive purges and must remain whole.',
        TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS trg_checkpoint_append_only ON LifecycleArchiveCheckpoint;
CREATE TRIGGER trg_checkpoint_append_only
    BEFORE UPDATE OR DELETE ON LifecycleArchiveCheckpoint
    FOR EACH ROW
    EXECUTE FUNCTION reject_checkpoint_modification();

COMMENT ON FUNCTION reject_checkpoint_modification IS
    'Strict append-only enforcement for LifecycleArchiveCheckpoint. '
    'No GUC carve-out (G30 / v8.87): the checkpoint chain must remain '
    'whole even when uc_archive_purge() has its purge-in-progress GUC '
    'set, because the checkpoint chain IS the audit-of-record for the '
    'carve-out itself.';

-- P8.2c (v9.322): the exchange-receipt transparency log is strictly append-only.
-- No GUC carve-out: a transparency log that can be rewritten is not a
-- transparency log. The monitor and witnesses would detect a rewrite; the
-- trigger makes it impossible from inside the database as well.
CREATE OR REPLACE FUNCTION reject_receipt_log_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        '% on ExchangeReceiptLog is forbidden: '
        'the receipt log is an append-only transparency log and must never be rewritten.',
        TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS trg_receipt_log_append_only ON ExchangeReceiptLog;
CREATE TRIGGER trg_receipt_log_append_only
    BEFORE UPDATE OR DELETE ON ExchangeReceiptLog
    FOR EACH ROW
    EXECUTE FUNCTION reject_receipt_log_modification();

COMMENT ON FUNCTION reject_receipt_log_modification IS
    'Strict append-only enforcement for ExchangeReceiptLog (P8.2c). No carve-out: '
    'the receipt log is published as an RFC-6962 transparency log and a rewrite '
    'would be a fork the monitor and witnesses alert on; the trigger forbids it at '
    'the database as well.';

-- P8.2d (v9.324): a consumed exchange nonce must never be un-consumed (deleting one
-- re-opens the replay window), so the replay register is strictly append-only.
CREATE OR REPLACE FUNCTION reject_exchange_nonce_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        '% on ExchangeNonce is forbidden: a consumed nonce must never be un-consumed.',
        TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS trg_exchange_nonce_append_only ON ExchangeNonce;
CREATE TRIGGER trg_exchange_nonce_append_only
    BEFORE UPDATE OR DELETE ON ExchangeNonce
    FOR EACH ROW
    EXECUTE FUNCTION reject_exchange_nonce_modification();

-- P8.4 (v9.326): a consumed authorization code must never be un-consumed.
CREATE OR REPLACE FUNCTION reject_auth_code_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        '% on AuthCodeConsumed is forbidden: a consumed authorization code must never be un-consumed.',
        TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS trg_auth_code_append_only ON AuthCodeConsumed;
CREATE TRIGGER trg_auth_code_append_only
    BEFORE UPDATE OR DELETE ON AuthCodeConsumed
    FOR EACH ROW
    EXECUTE FUNCTION reject_auth_code_modification();

COMMENT ON FUNCTION reject_audit_modification IS
  'Blocks UPDATE and DELETE on append-only audit tables (TokenLifecycleEvent, '
  'VerificationEvent, EnrollmentStatusEvent, AnchorBatch). Realizes NFR-4 at '
  'the tooling layer. AnchorBatch joined the set in v8.21 / R10-2 as the '
  'fifth audit-of-record instance — see docs/design/audit-of-record.md.';

-- ----------------------------------------------------------------------------
-- AUTOMATIC LIFECYCLE AUDIT on IdentityToken status changes.
--
-- Architectural improvement: rather than rely on the application layer to
-- INSERT a TokenLifecycleEvent after every UPDATE on IdentityToken.status
-- (which the report calls out as the operational responsibility for NFR-4),
-- this AFTER UPDATE trigger writes the audit row automatically. This
-- eliminates the class of bugs where a status change commits but the audit
-- row is missing (e.g., the application crashes between the two statements,
-- or a future developer forgets the second statement).
--
-- The trigger reads two optional session settings:
--   polaris.actor_agency_id  — the agency performing the change (NULL ok)
--   polaris.reason_code      — a free-text reason for the audit row
-- These are set via SET LOCAL polaris.actor_agency_id = '...' inside the
-- transaction. Stored procedures (UC-1, UC-4, UC-5) set these explicitly;
-- direct UPDATEs from the web layer set them via the helper in app.py.
--
-- The trigger maps status transitions to event_type values per Appendix A.
-- ----------------------------------------------------------------------------

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

DROP TRIGGER IF EXISTS trg_token_audit_state_change ON IdentityToken;
CREATE TRIGGER trg_token_audit_state_change
    AFTER UPDATE OF status ON IdentityToken
    FOR EACH ROW
    EXECUTE FUNCTION audit_token_state_change();

COMMENT ON FUNCTION audit_token_state_change IS
  'Automatically writes a TokenLifecycleEvent row whenever IdentityToken.status '
  'changes. Reads polaris.actor_agency_id and polaris.reason_code session GUCs '
  'for context. Eliminates the application-discipline dependency for NFR-4 '
  '(audit completeness): the database guarantees an event row exists for every '
  'state change, regardless of which client connects.';

-- ----------------------------------------------------------------------------
-- v8.15 / R11-6 / M2-11 — Belt-and-suspenders trigger for the bounded
-- revocation path. The procedure uc8_revoke_token is the *only* sanctioned
-- way to revoke a token; this trigger refuses raw UPDATEs that try to flip
-- status to 'REVOKED' without going through it.
--
-- Mechanism: the procedure sets polaris.revoke_check_done='1' for the
-- duration of the transaction. The trigger reads that GUC and only allows
-- the transition if it is set. A direct UPDATE from psql, the SQL console,
-- or app code that bypassed uc8_revoke_token will not have set the GUC
-- and will be rejected.
--
-- This does NOT re-do the rate math — the procedure already did it within
-- the same transaction. The trigger's job is to ensure the procedure is
-- the only entry point.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_revocation_velocity_bound()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    -- Only fire on NEW transitions INTO 'REVOKED'.
    IF NEW.status <> 'REVOKED' OR OLD.status = 'REVOKED' THEN
        RETURN NEW;
    END IF;

    -- Procedure path sets this GUC. If absent, the UPDATE bypassed
    -- uc8_revoke_token and the bound has not been checked.
    IF current_setting('polaris.revoke_check_done', true) = '1' THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'Direct UPDATE to status=REVOKED is not allowed. Use uc8_revoke_token().'
        USING ERRCODE = 'insufficient_privilege';
END$$;

DROP TRIGGER IF EXISTS trg_enforce_revocation_velocity ON IdentityToken;
CREATE TRIGGER trg_enforce_revocation_velocity
    BEFORE UPDATE OF status ON IdentityToken
    FOR EACH ROW
    EXECUTE FUNCTION enforce_revocation_velocity_bound();

COMMENT ON FUNCTION enforce_revocation_velocity_bound IS
  'Belt-and-suspenders trigger for R11-6 / M2-11. Refuses raw UPDATEs to '
  'IdentityToken.status=REVOKED that bypass the uc8_revoke_token procedure. '
  'The procedure sets the polaris.revoke_check_done session GUC for the '
  'duration of the transaction; absence of the GUC at the moment of the '
  'UPDATE means the rate-limit bound has not been checked, so the trigger '
  'refuses the transition.';

-- ----------------------------------------------------------------------------
-- v8.16 / R11-4 / M2-9 — Seed default enrollment status.
--
-- Every new Individual row gets an explicit NOT_ENROLLED event at the
-- moment of insertion, so the absence is materialized rather than inferred.
-- This makes the "person exists, no enrollment recorded" state distinct
-- from the "person doesn't exist" state in the EnrollmentStatusEvent log.
--
-- The trigger runs AFTER INSERT so individual_id is populated (it's a
-- SERIAL column; BEFORE INSERT would see NULL).
--
-- recorded_by_agency_id is NULL because this is a SYSTEM event, not an
-- agency-driven transition. transition_reason 'INDIVIDUAL_ROW_CREATED'
-- documents the provenance.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION seed_default_enrollment_status()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO EnrollmentStatusEvent
        (individual_id, status, transition_reason, recorded_by_agency_id)
    VALUES
        (NEW.individual_id, 'NOT_ENROLLED', 'INDIVIDUAL_ROW_CREATED', NULL);
    RETURN NEW;
END$$;

DROP TRIGGER IF EXISTS trg_seed_default_enrollment_status ON Individual;
CREATE TRIGGER trg_seed_default_enrollment_status
    AFTER INSERT ON Individual
    FOR EACH ROW
    EXECUTE FUNCTION seed_default_enrollment_status();

COMMENT ON FUNCTION seed_default_enrollment_status IS
  'R11-4 / M2-9. Emits a NOT_ENROLLED EnrollmentStatusEvent for every new '
  'Individual row so the default state is materialized rather than inferred. '
  'recorded_by_agency_id is NULL to indicate this is a SYSTEM event.';

-- ----------------------------------------------------------------------------
-- v8.18 / R11-1 / M2-6 — TokenSignature invariant triggers.
--
-- enforce_token_has_active_signature (AFTER trigger):
--   Every token must have ≥ 1 non-deprecated signature at all times.
--   Fires after every TokenSignature INSERT/UPDATE/DELETE and re-checks
--   the count for the affected token. If zero active, RAISE.
--
-- enforce_token_signature_immutability (BEFORE trigger):
--   TokenSignature is the audit-of-record for migrations. The row is
--   write-once and deprecation_date is one-way:
--     - DELETE forbidden outright.
--     - UPDATE confined to deprecation_date only.
--     - deprecation_date can transition NULL → timestamp (allowed once).
--     - deprecation_date can NOT transition timestamp → NULL (un-set
--       forbidden — would erase a deprecation record).
--     - deprecation_date can NOT move earlier than its existing value
--       (backdating forbidden).
--
-- Together these enforce: signatures are immutable except for their
-- deprecation_date marker, and tokens never end up signature-less.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_token_has_active_signature()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    v_token_id INTEGER;
    n_active   INTEGER;
BEGIN
    v_token_id := COALESCE(NEW.token_id, OLD.token_id);

    SELECT count(*) INTO n_active
    FROM TokenSignature
    WHERE token_id = v_token_id
      AND deprecation_date IS NULL;

    IF n_active = 0 THEN
        RAISE EXCEPTION 'Token % has zero active signatures', v_token_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN COALESCE(NEW, OLD);
END$$;

DROP TRIGGER IF EXISTS trg_token_must_have_active_signature ON TokenSignature;
CREATE TRIGGER trg_token_must_have_active_signature
    AFTER INSERT OR UPDATE OR DELETE ON TokenSignature
    FOR EACH ROW EXECUTE FUNCTION enforce_token_has_active_signature();

COMMENT ON FUNCTION enforce_token_has_active_signature IS
  'R11-1 / M2-6. Re-checks after every TokenSignature mutation: every '
  'token must have ≥ 1 non-deprecated signature. Mirrors the partial '
  'unique index pattern used for one-ACTIVE-per-individual (C3).';

CREATE OR REPLACE FUNCTION enforce_token_signature_immutability()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    -- DELETE is forbidden outright — would erase the migration record.
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'DELETE on TokenSignature is forbidden (audit-of-record for migrations)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- UPDATE: only deprecation_date may change. signing_public_key_hex (v9.117)
    -- is nullable, so it is compared with IS DISTINCT FROM (a plain <> with NULL
    -- would yield NULL, not TRUE, and silently let a change through).
    IF NEW.signature_id      <> OLD.signature_id
       OR NEW.token_id        <> OLD.token_id
       OR NEW.algorithm_id    <> OLD.algorithm_id
       OR NEW.signature_bytes <> OLD.signature_bytes
       OR NEW.signing_public_key_hex IS DISTINCT FROM OLD.signing_public_key_hex
       OR NEW.signed_at       <> OLD.signed_at THEN
        RAISE EXCEPTION
            'TokenSignature is append-only except for deprecation_date'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- deprecation_date is one-way.
    IF OLD.deprecation_date IS NOT NULL THEN
        IF NEW.deprecation_date IS NULL THEN
            RAISE EXCEPTION
                'deprecation_date cannot be un-set once recorded'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        IF NEW.deprecation_date < OLD.deprecation_date THEN
            RAISE EXCEPTION
                'deprecation_date cannot be moved earlier once recorded'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    END IF;

    RETURN NEW;
END$$;

DROP TRIGGER IF EXISTS trg_token_signature_immutable ON TokenSignature;
CREATE TRIGGER trg_token_signature_immutable
    BEFORE UPDATE OR DELETE ON TokenSignature
    FOR EACH ROW EXECUTE FUNCTION enforce_token_signature_immutability();

COMMENT ON FUNCTION enforce_token_signature_immutability IS
  'R11-1 / M2-6. TokenSignature is the audit-of-record for migrations. '
  'Rejects DELETE outright; rejects UPDATEs to any column other than '
  'deprecation_date; rejects deprecation_date un-setting or backdating. '
  'Narrower than reject_audit_modification because deprecation_date is '
  'legitimately mutable-once.';

-- ----------------------------------------------------------------------------
-- enforce_attestation_immutability (BEFORE trigger):
-- AgencyTrustAttestation is the 6th audit-of-record. Append-only with
-- bounded mutation: only (revocation_date, revocation_reason) may change,
-- and that pair moves together one-way (NULL → values; never back).
-- Mirrors enforce_token_signature_immutability shape. R11-3 / M2-8.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_attestation_immutability()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'DELETE on AgencyTrustAttestation is forbidden (audit-of-record for federation)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Identity + content fields are immutable.
    IF NEW.attestation_id        <> OLD.attestation_id
       OR NEW.attesting_agency_id <> OLD.attesting_agency_id
       OR NEW.attested_agency_id  <> OLD.attested_agency_id
       OR NEW.context_id          <> OLD.context_id
       OR NEW.attested_date       <> OLD.attested_date
       OR NEW.valid_until         <> OLD.valid_until
       OR NEW.signed_by           <> OLD.signed_by THEN
        RAISE EXCEPTION
            'AgencyTrustAttestation is append-only except for (revocation_date, revocation_reason)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Revocation is one-way: once set, cannot un-set or move earlier.
    IF OLD.revocation_date IS NOT NULL THEN
        IF NEW.revocation_date IS NULL THEN
            RAISE EXCEPTION
                'revocation_date cannot be un-set once recorded'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        IF NEW.revocation_date < OLD.revocation_date THEN
            RAISE EXCEPTION
                'revocation_date cannot be moved earlier once recorded'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    END IF;

    RETURN NEW;
END$$;

DROP TRIGGER IF EXISTS trg_attestation_immutable ON AgencyTrustAttestation;
CREATE TRIGGER trg_attestation_immutable
    BEFORE UPDATE OR DELETE ON AgencyTrustAttestation
    FOR EACH ROW EXECUTE FUNCTION enforce_attestation_immutability();

COMMENT ON FUNCTION enforce_attestation_immutability IS
  'R11-3 / M2-8. AgencyTrustAttestation is the 6th audit-of-record (federation '
  'trust graph). Rejects DELETE outright; rejects UPDATE to any column other '
  'than (revocation_date, revocation_reason); enforces one-way revocation '
  '(cannot un-set or backdate once recorded).';

-- ----------------------------------------------------------------------------
-- enforce_epoch_immutability (BEFORE trigger):
-- TokenStateEpoch is the 7th audit-of-record. Fully append-only — once
-- the epoch is closed, the merkle_root is the cryptographic commitment
-- against which proofs are generated. Mutating the root would invalidate
-- every proof issued against it. Mutating committed_count or valid_until
-- would change the verifier's behavior toward existing proofs.
-- R10-1 / M2-1.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_epoch_immutability()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'DELETE on TokenStateEpoch is forbidden (audit-of-record for ZK epoch)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- All fields immutable after closure.
    RAISE EXCEPTION
        'TokenStateEpoch is fully append-only after closure (audit-of-record for SNARK)'
        USING ERRCODE = 'insufficient_privilege';
END$$;

DROP TRIGGER IF EXISTS trg_epoch_immutable ON TokenStateEpoch;
CREATE TRIGGER trg_epoch_immutable
    BEFORE UPDATE OR DELETE ON TokenStateEpoch
    FOR EACH ROW EXECUTE FUNCTION enforce_epoch_immutability();

COMMENT ON FUNCTION enforce_epoch_immutability IS
  'R10-1 / M2-1. TokenStateEpoch is the 7th audit-of-record (ZK-SNARK epoch '
  'commitment). Fully append-only after closure — every proof generated '
  'against the merkle_root depends on its immutability. Rejects all UPDATE '
  'and DELETE operations.';

-- ----------------------------------------------------------------------------
-- TokenStateEpochLeaf is also append-only. We extend reject_audit_modification
-- to cover it (the 5th protected table — joining TokenLifecycleEvent,
-- VerificationEvent, EnrollmentStatusEvent, and AnchorBatch).
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS trg_epoch_leaf_append_only ON TokenStateEpochLeaf;
CREATE TRIGGER trg_epoch_leaf_append_only
    BEFORE UPDATE OR DELETE ON TokenStateEpochLeaf
    FOR EACH ROW EXECUTE FUNCTION reject_audit_modification();

-- ----------------------------------------------------------------------------
-- DuressEvent append-only trigger (R11-5 / M2-10 / v8.24).
-- DuressEvent is the 8th audit-of-record instance. The compulsion-resistance
-- signal is meaningful only if its history is immutable — an attacker who
-- could modify or delete duress events would defeat the whole mechanism.
-- Reuses reject_audit_modification.
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS trg_duress_event_append_only ON DuressEvent;
CREATE TRIGGER trg_duress_event_append_only
    BEFORE UPDATE OR DELETE ON DuressEvent
    FOR EACH ROW EXECUTE FUNCTION reject_audit_modification();

-- ----------------------------------------------------------------------------
-- AuthAuditLog append-only trigger. The table was promoted to 01_schema.sql
-- in v8.24-fix (so RecoveryRequest etc. can FK to AppUser on fresh load),
-- but reject_audit_modification is defined here, so the trigger creation
-- belongs in this file.
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS trg_authaudit_append_only ON AuthAuditLog;
CREATE TRIGGER trg_authaudit_append_only
    BEFORE UPDATE OR DELETE ON AuthAuditLog
    FOR EACH ROW EXECUTE FUNCTION reject_audit_modification();

-- ----------------------------------------------------------------------------
-- v9.190 / roadmap P1.8 — per-agency quotas. One function, three triggers:
--
--   trg_quota_issue   BEFORE INSERT ON IdentityToken       (issuing_agency_id, 1 day)
--   trg_quota_revoke  BEFORE UPDATE OF status ON IdentityToken, into REVOKED
--                                                          (issuing_agency_id, 1 day)
--   trg_quota_verify  BEFORE INSERT ON VerificationEvent   (requesting_agency_id, 1 hour)
--
-- The cap comes from AgencyQuota (NULL / no row = unlimited, and the function
-- returns before taking any lock or counting anything, so an uncapped agency
-- pays one primary-key lookup per write). A capped write takes a per-(kind,
-- agency) transaction-scoped advisory lock, counts the window from the
-- audit-of-record tables, and refuses the (cap + 1)th with a message the app
-- maps to HTTP 429 and a polaris_quota_refusals_total increment. The lock is
-- what makes the cap exact under concurrent writers (C9): the loser of the
-- race sees the winner's committed row when its count runs.
--
-- Unlike enforce_revocation_velocity_bound there is NO opt-out GUC: a quota
-- is a bound on what an agency may do, and a sanctioned procedure is still
-- the agency doing it. The count-based cap and the percentage bound compose;
-- whichever trips first refuses.
-- ----------------------------------------------------------------------------
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
     WHERE agency_id = v_agency_id;
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

DROP TRIGGER IF EXISTS trg_quota_issue ON IdentityToken;
CREATE TRIGGER trg_quota_issue
    BEFORE INSERT ON IdentityToken
    FOR EACH ROW
    EXECUTE FUNCTION enforce_agency_quota('issue');

DROP TRIGGER IF EXISTS trg_quota_revoke ON IdentityToken;
CREATE TRIGGER trg_quota_revoke
    BEFORE UPDATE OF status ON IdentityToken
    FOR EACH ROW
    EXECUTE FUNCTION enforce_agency_quota('revoke');

DROP TRIGGER IF EXISTS trg_quota_verify ON VerificationEvent;
CREATE TRIGGER trg_quota_verify
    BEFORE INSERT ON VerificationEvent
    FOR EACH ROW
    EXECUTE FUNCTION enforce_agency_quota('verify');

COMMENT ON FUNCTION enforce_agency_quota IS
  'v9.190 / P1.8 per-agency quota enforcement. Reads AgencyQuota (NULL or no '
  'row = unlimited, returned before any lock), serializes per (kind, agency) '
  'with a transaction-scoped advisory lock, counts the rolling window from '
  'the audit-of-record tables, and refuses the (cap + 1)th write with '
  '"quota exceeded: ..." (check_violation), which the app maps to HTTP 429.';

-- ============================================================================
-- END OF 06_triggers.sql
-- 17 triggers, 10 trigger functions:
--   1.  enforce_token_state_machine            (BEFORE UPDATE) — rejects illegal transitions
--   2.  audit_token_state_change               (AFTER UPDATE)  — auto-writes audit row
--   3.  reject_audit_modification              (BEFORE UPDATE/DELETE on TokenLifecycleEvent)
--   4.  reject_audit_modification              (BEFORE UPDATE/DELETE on VerificationEvent)
--   5.  reject_audit_modification              (BEFORE UPDATE/DELETE on EnrollmentStatusEvent)
--   6.  enforce_revocation_velocity_bound      (BEFORE UPDATE) — refuses raw REVOKED UPDATEs
--   7.  seed_default_enrollment_status         (AFTER INSERT on Individual) — emits NOT_ENROLLED
--   8.  enforce_token_has_active_signature     (AFTER on TokenSignature) — ≥ 1 active sig per token
--   9.  enforce_token_signature_immutability   (BEFORE on TokenSignature) — write-once + one-way deprecation
--   10. reject_audit_modification              (BEFORE UPDATE/DELETE on AnchorBatch — v8.21 / R10-2)
--   11. enforce_attestation_immutability       (BEFORE on AgencyTrustAttestation — v8.22 / R11-3)
--   12. enforce_epoch_immutability             (BEFORE on TokenStateEpoch — v8.23 / R10-1)
--   13. reject_audit_modification              (BEFORE on TokenStateEpochLeaf — v8.23 / R10-1)
--   14. reject_audit_modification              (BEFORE on DuressEvent — v8.24 / R11-5)
--   15. enforce_agency_quota('issue')          (BEFORE INSERT on IdentityToken — v9.190 / P1.8)
--   16. enforce_agency_quota('revoke')         (BEFORE UPDATE OF status on IdentityToken — v9.190 / P1.8)
--   17. enforce_agency_quota('verify')         (BEFORE INSERT on VerificationEvent — v9.190 / P1.8)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- enforce_retention_policy_immutability (roadmap P1.11)
--
-- RetentionPolicy is an audit of record: it holds what an operator decided
-- about how long audit history is kept, and when. Editing that decision in
-- place would erase the thing it exists to prove.
--
--   DELETE forbidden outright.
--   UPDATE confined to superseded_at.
--   superseded_at moves NULL -> timestamp once. It cannot return to NULL (that
--   would resurrect a superseded policy silently) and it cannot move earlier
--   (that would backdate when a decision stopped applying).
--
-- Changing a retention decision therefore appends a row, which is what
-- uc_apply_retention_template does.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_retention_policy_immutability()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'RetentionPolicy is append-only: DELETE is refused. A retention '
            'decision is an audit of record; supersede it instead.'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF NEW.policy_id      IS DISTINCT FROM OLD.policy_id
       OR NEW.table_class    IS DISTINCT FROM OLD.table_class
       OR NEW.jurisdiction   IS DISTINCT FROM OLD.jurisdiction
       OR NEW.retention_days IS DISTINCT FROM OLD.retention_days
       OR NEW.justification  IS DISTINCT FROM OLD.justification
       OR NEW.set_by_user_id IS DISTINCT FROM OLD.set_by_user_id
       OR NEW.effective_from IS DISTINCT FROM OLD.effective_from THEN
        RAISE EXCEPTION
            'RetentionPolicy is append-only: only superseded_at may change. '
            'Append a new policy row instead of editing this one.'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF OLD.superseded_at IS NOT NULL THEN
        IF NEW.superseded_at IS NULL THEN
            RAISE EXCEPTION
                'RetentionPolicy: superseded_at cannot be un-set; a superseded '
                'policy stays superseded.'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        IF NEW.superseded_at < OLD.superseded_at THEN
            RAISE EXCEPTION
                'RetentionPolicy: superseded_at cannot move earlier (% -> %); '
                'backdating when a decision stopped applying is refused.',
                OLD.superseded_at, NEW.superseded_at
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_retention_policy_immutable ON RetentionPolicy;
CREATE TRIGGER trg_retention_policy_immutable
    BEFORE UPDATE OR DELETE ON RetentionPolicy
    FOR EACH ROW EXECUTE FUNCTION enforce_retention_policy_immutability();

COMMENT ON FUNCTION enforce_retention_policy_immutability IS
    'RetentionPolicy is append-only with one-way supersession (P1.11): no '
    'DELETE, no UPDATE except superseded_at, and superseded_at moves NULL to a '
    'timestamp once, never back and never earlier.';
