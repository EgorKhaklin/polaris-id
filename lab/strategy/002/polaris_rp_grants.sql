-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Egor Khaklin and the Polaris contributors
-- lab/strategy/002/polaris_rp_grants.sql
--
-- LAB ONLY. The relying-party compartment's database login, as measured against the scratch
-- database polaris_rpcomp (lab/strategy/002-relying-party-api-compartment.md, section 9).
-- Nothing in polaris_sql/ loads this file.
--
-- Derived by reading polaris_web/rp_api.py and every helper it calls into (app.query, app.get_db,
-- app._issuer_key_facts, app._check_and_record_duress, app._record_duress_async,
-- app._zk_verify_and_consume, app._db_now, the app.py before/after-request hooks, security.*,
-- pqc_signing, custody, anchoring, mdoc, vc, rp_auth), then corrected by running the relying-party
-- test classes with the application connected as polaris_rp (run_rp_as_polaris_rp.py) and every
-- statement on the path as polaris_rp (probe_rp_statements.py). Where a measurement changed a
-- right, the comment says so.
--
-- Idempotent: run as the schema owner, any number of times, including after test_app's
-- reload_sample_data (which re-runs 04_data, 06_triggers, 09_grants, 10_auth).
--
--   psql -h localhost -U vanta -d polaris_rpcomp -v ON_ERROR_STOP=1 -f lab/strategy/002/polaris_rp_grants.sql

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_rp') THEN
        CREATE ROLE polaris_rp WITH LOGIN NOINHERIT PASSWORD 'polaris_rp_lab';
    END IF;
END$$;
ALTER ROLE polaris_rp WITH LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- Start from nothing, so a re-run after an edit cannot leave a stale right behind.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM polaris_rp;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM polaris_rp;
DO $$
DECLARE v_sig TEXT;
BEGIN
    FOR v_sig IN SELECT p.oid::regprocedure::text FROM pg_proc p
                   JOIN pg_namespace n ON n.oid = p.pronamespace
                  WHERE n.nspname = 'public' AND p.prosecdef
                    AND has_function_privilege('polaris_rp', p.oid, 'EXECUTE') LOOP
        EXECUTE format('REVOKE EXECUTE ON ROUTINE %s FROM polaris_rp', v_sig);
    END LOOP;
END$$;

-- Every route: the login itself.
DO $$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO polaris_rp', current_database()); END$$;
GRANT USAGE ON SCHEMA public TO polaris_rp;

-- ============================================================================================
-- READS
-- ============================================================================================

-- POST /api/v1/oauth/token, /api/v1/auth/token (_rp_authenticate_client: rp_id, client_secret_hash,
-- enabled, scope by client_id); POST /api/v1/verify (rate_limit_per_min, enabled by rp_id);
-- POST /api/v1/auth/authorize (the registered policy: require_zk, required_enrollment,
-- required_context_id); GET /api/v1/registry/<id> (org_name, scope of enabled parties).
-- Column-level: created_at and last_used_at are not read.
GRANT SELECT (rp_id, client_id, client_secret_hash, org_name, scope, enabled,
              rate_limit_per_min, require_zk, required_enrollment, required_context_id)
    ON RelyingParty TO polaris_rp;

-- POST /api/v1/verify and every possession-authenticated route (_possession_authenticated:
-- holder-key, holder-binding, status-assertion, mdoc, verifiable-credential, sign/<id>/holder,
-- auth/authorize): token_id, individual_id, token_value, status, issuing_agency_id,
-- expiration_date. /api/v1/mdoc and /verifiable-credential join it by token_value.
-- /api/v1/revocation-feed/<id> (and the LTV evidence in sign/<id>/holder) reads token_value of
-- revoked tokens. /api/v1/auth/authorize with presented_code: _check_and_record_duress reads
-- duress_code_hash. Column-level: the hardware, biometric and succession columns are not read.
-- The row-level policy token_authority_isolation (TO PUBLIC) applies and is permissive when
-- polaris.operator_agency_id is unset, which it always is on this surface.
GRANT SELECT (token_id, token_value, individual_id, issuing_agency_id, status,
              expiration_date, duress_code_hash)
    ON IdentityToken TO polaris_rp;

-- POST /api/v1/verify and _possession_authenticated: the stored issuance signature and key.
GRANT SELECT ON TokenSignature TO polaris_rp;

-- Nearly every route: the authority's name and signing key (verify's join, epoch leaves,
-- federation-manifest, epoch-checkpoint, revocation-feed, status-bundle, exchange-receipt/signed,
-- timestamp, registry, exchange requester lookup, sign/holder, auth/token, trust-list, mdoc).
GRANT SELECT ON Agency TO polaris_rp;

-- GET /api/v1/epoch/<id>/leaves, federation-manifest, epoch-checkpoint, revocation-feed;
-- auth/authorize with a ZK step-up (_zk_verify_and_consume).
GRANT SELECT ON TokenStateEpoch TO polaris_rp;
-- GET /api/v1/epoch/<id>/leaves.
GRANT SELECT ON TokenStateEpochLeaf TO polaris_rp;

-- POST /api/v1/holder-key, /holder-binding, /status-assertion (_holder_binding_for):
-- HolderKeyCurrent is a security_invoker view over HolderKeyEvent, so both are needed.
GRANT SELECT ON HolderKeyCurrent, HolderKeyEvent TO polaris_rp;

-- POST /api/v1/mdoc and /api/v1/auth/authorize: the holder's enrollment status, through
-- IndividualCurrentEnrollment, a security_invoker view over Individual and EnrollmentStatusEvent.
-- The view's own select list carries Individual.legal_name and jurisdiction, and PostgreSQL
-- checks the invoker's column rights on every column the view references, not only the one the
-- route reads: with (individual_id, enrollment_date) alone, `SELECT current_status FROM
-- IndividualCurrentEnrollment` is refused (measured). So as the code stands the public surface
-- must be able to read every holder's legal name. Finding B-2 in RESULTS.md; date_of_birth is
-- still withheld.
GRANT SELECT ON IndividualCurrentEnrollment TO polaris_rp;
GRANT SELECT ON EnrollmentStatusEvent TO polaris_rp;
GRANT SELECT (individual_id, legal_name, jurisdiction, enrollment_date) ON Individual TO polaris_rp;

-- POST /api/v1/mdoc and /api/v1/verifiable-credential: the credential's first context type;
-- POST /api/v1/auth/authorize: whether it is permitted in the context the ID token names.
GRANT SELECT ON VerificationContext, TokenPermission TO polaris_rp;

-- POST /api/v1/verify (_issuer_key_facts), GET /api/v1/federation-manifest/<id> and
-- /api/v1/trust-list/<id> (_authority_keys, _key_status): AuthorityKeyCurrent is a
-- security_invoker view over AuthorityKeyEvent.
GRANT SELECT ON AuthorityKeyCurrent, AuthorityKeyEvent TO polaris_rp;

-- POST /api/v1/verify (_issuer_key_facts): the protected ISSUED instant. Partitioned; the parent
-- grant covers reads through the parent. Row-level policy lifecycle_authority_isolation applies,
-- permissive when unscoped.
GRANT SELECT ON TokenLifecycleEvent TO polaris_rp;

-- GET /api/v1/federation-manifest/<id> (and sign LTV evidence), POST exchange-receipt/signed
-- (_exchange_attestation).
GRANT SELECT ON AgencyTrustAttestation TO polaris_rp;

-- GET /api/v1/revocation-feed/<id>, federation-status-bundle, sign/<id>/holder LTV evidence.
GRANT SELECT ON RevocationList TO polaris_rp;

-- GET /api/v1/registry/<id>: four security_invoker Athena views and their base tables
-- (v_athena_agency over Agency; v_athena_proof_policy over VerificationContext;
-- v_athena_trust_agreement over Agency, AgencyTrustAttestation, VerificationContext;
-- v_athena_disclosure_policy reads no table).
GRANT SELECT ON v_athena_agency, v_athena_proof_policy, v_athena_disclosure_policy,
                v_athena_trust_agreement TO polaris_rp;

-- GET /api/v1/transparency/* (the anchor log), /transparency/receipts/*,
-- /transparency/timestamps/*, exchange-receipt/inclusion, timestamp/inclusion, and the
-- log-index lookups after each append.
GRANT SELECT ON AnchorBatch, ExchangeReceiptLog, TimestampLog TO polaris_rp;

-- ============================================================================================
-- WRITES
-- ============================================================================================

-- POST /api/v1/oauth/token: the coarse last-used stamp. One column, nothing else.
GRANT UPDATE (last_used_at) ON RelyingParty TO polaris_rp;

-- POST /api/v1/holder-key: bind / rotate / revoke the holder key (append-only register).
GRANT INSERT ON HolderKeyEvent TO polaris_rp;
GRANT USAGE ON SEQUENCE holderkeyevent_event_id_seq TO polaris_rp;

-- POST /api/v1/exchange/<id>: the gateway's replay register.
GRANT INSERT ON ExchangeNonce TO polaris_rp;

-- POST /api/v1/auth/token: the consumed-code register.
GRANT INSERT ON AuthCodeConsumed TO polaris_rp;

-- POST /api/v1/exchange-receipt/<id>/signed (and the operator path at exchange-receipt/<id>):
-- the receipt transparency log.
GRANT INSERT ON ExchangeReceiptLog TO polaris_rp;
GRANT USAGE ON SEQUENCE exchangereceiptlog_seq_seq TO polaris_rp;

-- POST /api/v1/timestamp/<id> with anchor=true, and sign/<id>/holder with anchor_timestamp=true:
-- the timestamp transparency log.
GRANT INSERT ON TimestampLog TO polaris_rp;
GRANT USAGE ON SEQUENCE timestamplog_seq_seq TO polaris_rp;

-- POST /api/v1/auth/authorize with a ZK step-up (_zk_verify_and_consume): the single-use nonce.
-- Not in the section-1 table. INSERT ... ON CONFLICT ON CONSTRAINT pk_zk_verification_nonce DO
-- NOTHING RETURNING consumed_at: RETURNING needs SELECT on consumed_at, and the ON CONFLICT
-- arbiter needs SELECT on the key columns (epoch_id, context_id, nonce). Found by
-- probe_rp_statements.py: with SELECT (consumed_at) alone the statement is refused, and no test
-- class reaches it (no test drives a step-up with a proof that verifies). Every column, so the
-- table-level grant; the rows hold no token identifier (C2).
GRANT INSERT, SELECT ON ZkVerificationNonce TO polaris_rp;

-- ============================================================================================
-- PROCEDURES
-- ============================================================================================

-- POST /api/v1/auth/authorize with presented_code matching an enrolled duress code:
-- _check_and_record_duress -> _record_duress_async -> CALL uc12_record_duress. SECURITY DEFINER;
-- it writes DuressEvent as the owner. Not in the section-1 table. See RESULTS.md, finding B-1.
GRANT EXECUTE ON PROCEDURE uc12_record_duress(INTEGER, INTEGER, INTEGER, VARCHAR) TO polaris_rp;

-- Non-definer functions the path calls (polaris_database_setting in _zk_verify_and_consume,
-- _rp_weakens in the RelyingParty trigger) are executable by PUBLIC and need no grant.
