-- Reverts 2026-10-09-001: the routines, the column defaults and the two views read the session's
-- clock again. The ten re-created functions keep their bodies, which are the ones the migrations
-- before this one left; only the setting goes.

ALTER FUNCTION polaris_utc_date() RESET timezone;
ALTER FUNCTION uc1_issue_and_activate(VARCHAR, DATE, VARCHAR, INTEGER, INTEGER, VARCHAR, INTEGER, VARCHAR, VARCHAR, VARCHAR, VARCHAR, INTEGER[], BYTEA, TEXT) RESET timezone;
ALTER FUNCTION uc4_activate_reserve(INTEGER, INTEGER, VARCHAR, INTEGER, VARCHAR) RESET timezone;
ALTER FUNCTION uc5_bind_device(INTEGER, VARCHAR, VARCHAR, VARCHAR, INTEGER) RESET timezone;
ALTER FUNCTION retention_cutoff(VARCHAR, VARCHAR) RESET timezone;
ALTER FUNCTION uc_issue_credential_copy(VARCHAR, INTEGER, INTERVAL) RESET timezone;
ALTER FUNCTION credential_copy_valid_indexes(INTEGER, DATE, INTEGER) RESET timezone;
ALTER FUNCTION audit_token_state_change() RESET timezone;
ALTER FUNCTION enforce_agency_quota() RESET timezone;
ALTER FUNCTION enforce_vouching_rules() RESET timezone;
ALTER PROCEDURE uc8_revoke_token(INTEGER, INTEGER, VARCHAR, VARCHAR, INTEGER) RESET timezone;
ALTER PROCEDURE uc9_initiate_recovery(INTEGER, INTEGER, INTEGER, INTEGER) RESET timezone;
ALTER PROCEDURE uc9_complete_recovery(INTEGER, INTEGER, VARCHAR, TEXT, VARCHAR, VARCHAR, INTEGER, VARCHAR, VARCHAR, VARCHAR, BYTEA, VARCHAR) RESET timezone;
ALTER PROCEDURE uc6_migrate_algorithm(INTEGER, INTEGER, BYTEA, BOOLEAN, TEXT) RESET timezone;
ALTER PROCEDURE close_anchor_batch(INTEGER, VARCHAR, JSONB) RESET timezone;
ALTER PROCEDURE uc10_revoke_attestation(INTEGER, VARCHAR, INTEGER) RESET timezone;
ALTER PROCEDURE uc_archive_purge(TIMESTAMPTZ, VARCHAR, VARCHAR, INTEGER, VARCHAR, TIMESTAMPTZ[], BIGINT) RESET timezone;
ALTER PROCEDURE uc_apply_retention_template(VARCHAR, VARCHAR, INTEGER) RESET timezone;
ALTER PROCEDURE uc_set_retention_policy(VARCHAR, VARCHAR, INTEGER, TEXT, INTEGER, INTEGER, INTEGER) RESET timezone;
ALTER PROCEDURE uc_bulk_issue(INTEGER, INTEGER) RESET timezone;
ALTER PROCEDURE uc_ensure_event_partitions(INTEGER) RESET timezone;
ALTER FUNCTION foresight_token_age_distribution() RESET timezone;
ALTER FUNCTION foresight_verification_dormancy(INTEGER) RESET timezone;

ALTER TABLE Individual ALTER COLUMN enrollment_date SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE AppUser ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE RelyingParty ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE AgencyEvent ALTER COLUMN recorded_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE AppUserEvent ALTER COLUMN recorded_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE RelyingPartyEvent ALTER COLUMN recorded_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE ExchangeReceiptLog ALTER COLUMN minted_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE TimestampLog ALTER COLUMN anchored_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE ChainAnchor ALTER COLUMN recorded_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE BackupEvent ALTER COLUMN completed_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE RestoreRecord ALTER COLUMN recorded_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE ExchangeNonce ALTER COLUMN consumed_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE AuthCodeConsumed ALTER COLUMN consumed_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE AuthorityKeyEvent
    ALTER COLUMN effective_at SET DEFAULT CURRENT_TIMESTAMP,
    ALTER COLUMN recorded_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE AuthAuditLog ALTER COLUMN event_timestamp SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE IdentityToken ALTER COLUMN issued_date SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE TokenLifecycleEvent ALTER COLUMN event_timestamp SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE VerificationEvent ALTER COLUMN event_timestamp SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE DeviceBinding ALTER COLUMN authorized_date SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE BlockchainAnchor ALTER COLUMN anchored_date SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE RevocationList ALTER COLUMN revocation_timestamp SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE AgencyAlgorithmAuth ALTER COLUMN authorized_date SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE TokenPermission ALTER COLUMN granted_date SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE IssuerDiscretionPolicy ALTER COLUMN set_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE AgencyQuota ALTER COLUMN set_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE EnrollmentStatusEvent ALTER COLUMN event_timestamp SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE IndividualErasureEvent ALTER COLUMN event_timestamp SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE RecoveryRequest ALTER COLUMN requested_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE TokenSignature ALTER COLUMN signed_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE AnchorBatch ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE HolderKeyEvent
    ALTER COLUMN effective_at SET DEFAULT CURRENT_TIMESTAMP,
    ALTER COLUMN recorded_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE CredentialCopy ALTER COLUMN issued_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE AgencyTrustAttestation ALTER COLUMN attested_date SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE TokenStateEpoch
    ALTER COLUMN valid_from SET DEFAULT CURRENT_TIMESTAMP,
    ALTER COLUMN closed_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE DuressEvent ALTER COLUMN event_timestamp SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE EnrollmentProofing ALTER COLUMN recorded_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE RefereeVouching ALTER COLUMN vouched_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE EnrollmentCode ALTER COLUMN issued_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE CardPersonalization ALTER COLUMN personalized_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE BulkEnrollmentBatch ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;

CREATE OR REPLACE VIEW HolderKeyCurrent WITH (security_invoker = true) AS
SELECT DISTINCT ON (hke.token_id)
       hke.token_id,
       hke.public_key_hex,
       hke.algorithm,
       hke.event,
       hke.effective_at
  FROM HolderKeyEvent hke
 WHERE hke.effective_at <= CURRENT_TIMESTAMP
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
    EXTRACT(EPOCH FROM (NOW() - t.issued_date)) / 86400.0
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
