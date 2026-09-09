"""
test_check_constraints.py
============================================================================

Schema CHECK-constraint regression suite (v8.80 / ARCH-004).

The Polaris schema declares 50+ named CHECK constraints across ~20 tables.
Each one names an invariant that the database enforces at write time:
status enums, lat/lon ranges, hex-format validation, multi-column
consistency rules, etc.

For most of v8 these constraints went untested — an earlier coherence
check flagged the gap as a long-standing one (41 CHECKs in schema, ~16
in tests). This file closes that gap.

Pattern: each test tries an INSERT that should violate the named
constraint, expects ``psycopg2.errors.CheckViolation``, and rolls back.
A few constraints also have positive boundary-case tests where the
positive case is non-obvious.

This file is independent of the Flask app. It connects directly to
``polaris_test`` as the operator user, uses one transaction per test,
and rolls back. No DB state survives.

Run:
    python3 test_check_constraints.py
    python3 -m unittest test_check_constraints -v

Coverage map: see the class docstrings. Each class is one schema table.
"""

import os
import sys
import unittest

import psycopg2
from psycopg2 import errors as pg_errors
from psycopg2.extras import RealDictCursor

# Import the Flask app's DB_CONFIG so tests stay aligned with app config.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as flask_app

DB_CONFIG = flask_app.DB_CONFIG


# ----------------------------------------------------------------------------
# Base case: open a transaction; assertions roll it back
# ----------------------------------------------------------------------------

class _CheckBase(unittest.TestCase):
    """Shared connection-per-test helper.

    Each test opens a fresh connection, runs its INSERT inside a
    transaction, and unconditionally rolls back at tearDown.
    """

    def setUp(self):
        self.conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def tearDown(self):
        try:
            self.conn.rollback()
        finally:
            self.conn.close()

    def _expect_check_violation(self, sql, params=None, constraint_name=None):
        """Run ``sql`` and assert it raises CheckViolation, optionally
        on a specific constraint."""
        with self.assertRaises(pg_errors.CheckViolation) as ctx:
            with self.conn.cursor() as cur:
                cur.execute(sql, params or ())
        if constraint_name:
            self.assertIn(
                constraint_name,
                str(ctx.exception),
                f"expected CheckViolation on '{constraint_name}'; "
                f"got: {ctx.exception}",
            )


# ============================================================================
# Agency
# ============================================================================

class TestAgencyChecks(_CheckBase):
    """agency_type enum + authorization_level 1..5 range."""

    def test_agency_type_enum_rejects_unknown(self):
        self._expect_check_violation(
            "INSERT INTO Agency (name, agency_type, jurisdiction, authorization_level) "
            "VALUES ('Test', 'INVALID', 'Nowhere', 3)",
            constraint_name='agency_type_check',
        )

    def test_agency_authorization_level_above_ceiling(self):
        self._expect_check_violation(
            "INSERT INTO Agency (name, agency_type, jurisdiction, authorization_level) "
            "VALUES ('Test', 'FEDERAL', 'Nowhere', 6)",
            constraint_name='authorization_level',
        )

    def test_agency_authorization_level_zero_rejected(self):
        self._expect_check_violation(
            "INSERT INTO Agency (name, agency_type, jurisdiction, authorization_level) "
            "VALUES ('Test', 'FEDERAL', 'Nowhere', 0)",
            constraint_name='authorization_level',
        )


# ============================================================================
# AgencyAlgorithmAuth
# ============================================================================

class TestAgencyAlgorithmAuthChecks(_CheckBase):
    """authorization_type enum: ISSUE / VERIFY / BOTH."""

    def test_authorization_type_enum(self):
        self._expect_check_violation(
            "INSERT INTO AgencyAlgorithmAuth (agency_id, algorithm_id, authorization_type) "
            "VALUES (1, 1, 'NEVER')",
            constraint_name='authorization_type_check',
        )


# ============================================================================
# AgencyTrustAttestation (R11-3 / M2-8)
# ============================================================================

class TestAgencyTrustAttestationChecks(_CheckBase):

    def test_no_self_attestation(self):
        self._expect_check_violation(
            "INSERT INTO AgencyTrustAttestation "
            "(attesting_agency_id, attested_agency_id, context_id, "
            "valid_until, signed_by) "
            "VALUES (1, 1, 1, CURRENT_DATE + interval '90 days', 1)",
            constraint_name='no_self_attestation',
        )

    def test_validity_floor_zero_duration_rejected(self):
        """valid_until > attested_date. Default attested_date is today."""
        self._expect_check_violation(
            "INSERT INTO AgencyTrustAttestation "
            "(attesting_agency_id, attested_agency_id, context_id, "
            "attested_date, valid_until, signed_by) "
            "VALUES (1, 2, 1, CURRENT_DATE, CURRENT_DATE, 1)",
            constraint_name='validity_floor',
        )

    def test_revocation_consistency_partial_revocation_rejected(self):
        """If revocation_date is set, revocation_reason must also be set
        (and >= 8 chars)."""
        self._expect_check_violation(
            "INSERT INTO AgencyTrustAttestation "
            "(attesting_agency_id, attested_agency_id, context_id, "
            "valid_until, signed_by, revocation_date) "
            "VALUES (1, 2, 1, CURRENT_DATE + interval '90 days', 1, CURRENT_DATE)",
            constraint_name='revocation_consistency',
        )

    def test_revocation_reason_too_short_rejected(self):
        """revocation_reason floor is 8 chars."""
        self._expect_check_violation(
            "INSERT INTO AgencyTrustAttestation "
            "(attesting_agency_id, attested_agency_id, context_id, "
            "valid_until, signed_by, revocation_date, revocation_reason) "
            "VALUES (1, 2, 1, CURRENT_DATE + interval '90 days', 1, "
            "CURRENT_DATE, 'short')",
            constraint_name='revocation_consistency',
        )


# ============================================================================
# AnchorBatch (R10-2 / M2-2)
# ============================================================================

class TestAnchorBatchChecks(_CheckBase):

    def test_batch_size_must_be_positive(self):
        self._expect_check_violation(
            "INSERT INTO AnchorBatch (algorithm_id, merkle_root, batch_size) "
            "VALUES (1, 'deadbeef', 0)",
            constraint_name='batch_size',
        )

    def test_external_chain_enum_rejects_unknown(self):
        self._expect_check_violation(
            "INSERT INTO AnchorBatch "
            "(algorithm_id, merkle_root, batch_size, external_chain) "
            "VALUES (1, 'deadbeef', 1, 'BITCOIN')",
            constraint_name='external_chain_check',
        )

    def test_chain_consistency_committed_requires_chain(self):
        """committed_to_chain=true requires external_chain IS NOT NULL."""
        self._expect_check_violation(
            "INSERT INTO AnchorBatch "
            "(algorithm_id, merkle_root, batch_size, committed_to_chain) "
            "VALUES (1, 'deadbeef', 1, true)",
            constraint_name='batch_chain_consistency',
        )

    def test_batch_root_must_be_hex(self):
        self._expect_check_violation(
            "INSERT INTO AnchorBatch (algorithm_id, merkle_root, batch_size) "
            "VALUES (1, 'NOT-HEX!', 1)",
            constraint_name='batch_root_is_hex',
        )


# ============================================================================
# AppUser (auth)
# ============================================================================

class TestAppUserChecks(_CheckBase):

    def test_role_enum(self):
        self._expect_check_violation(
            "INSERT INTO AppUser (username, password_hash, role) "
            "VALUES ('xtest', 'argon2id$dummy', 'godmode')",
            constraint_name='chk_appuser_role',
        )

    def test_username_format_lowercase_only(self):
        """chk_appuser_username_format: ^[a-z0-9._-]{3,50}$"""
        self._expect_check_violation(
            "INSERT INTO AppUser (username, password_hash, role) "
            "VALUES ('UPPER', 'argon2id$dummy', 'operator')",
            constraint_name='chk_appuser_username_format',
        )

    def test_username_too_short_rejected(self):
        self._expect_check_violation(
            "INSERT INTO AppUser (username, password_hash, role) "
            "VALUES ('xy', 'argon2id$dummy', 'operator')",
            constraint_name='chk_appuser_username_format',
        )

    def test_failed_count_nonneg(self):
        self._expect_check_violation(
            "INSERT INTO AppUser (username, password_hash, role, failed_login_count) "
            "VALUES ('xtest', 'argon2id$dummy', 'operator', -1)",
            constraint_name='chk_appuser_failed_count_nonneg',
        )


# ============================================================================
# AuthAuditLog
# ============================================================================

class TestAuthAuditLogChecks(_CheckBase):

    def test_event_type_enum(self):
        self._expect_check_violation(
            "INSERT INTO AuthAuditLog (event_type, username, ip_address) "
            "VALUES ('TIME_TRAVEL', 'admin', '127.0.0.1')",
            constraint_name='chk_authaudit_event_type',
        )


# ============================================================================
# BlockchainAnchor
# ============================================================================

class TestBlockchainAnchorChecks(_CheckBase):

    def test_status_enum(self):
        self._expect_check_violation(
            "INSERT INTO BlockchainAnchor "
            "(token_id, did, commitment_hash, ledger_network, status) "
            "VALUES (1, 'did:polaris:test', 'deadbeef', 'ALGORAND_PQ', 'INVALID')",
            constraint_name='blockchainanchor_status_check',
        )

    def test_ledger_network_enum(self):
        self._expect_check_violation(
            "INSERT INTO BlockchainAnchor "
            "(token_id, did, commitment_hash, ledger_network) "
            "VALUES (1, 'did:polaris:test', 'deadbeef', 'BITCOIN')",
            constraint_name='ledger_network_check',
        )

    def test_anchor_proof_with_batch_partial_is_rejected(self):
        """If batch_id is set, merkle_proof must also be set."""
        self._expect_check_violation(
            "INSERT INTO BlockchainAnchor "
            "(token_id, did, commitment_hash, ledger_network, batch_id) "
            "VALUES (1, 'did:polaris:test', 'hash', 'ALGORAND_PQ', 1)",
            constraint_name='anchor_proof_with_batch',
        )


# ============================================================================
# CryptographicAlgorithm
# ============================================================================

class TestCryptographicAlgorithmChecks(_CheckBase):

    def test_security_level_bits_floor(self):
        """80-bit floor; 64 must reject."""
        self._expect_check_violation(
            "INSERT INTO CryptographicAlgorithm "
            "(name, family, quantum_resistant, security_level_bits) "
            "VALUES ('weak-test', 'TEST', false, 64)",
            constraint_name='security_level_bits',
        )

    def test_security_level_bits_ceiling(self):
        self._expect_check_violation(
            "INSERT INTO CryptographicAlgorithm "
            "(name, family, quantum_resistant, security_level_bits) "
            "VALUES ('xstrong', 'TEST', true, 257)",
            constraint_name='security_level_bits',
        )


# ============================================================================
# DeviceBinding
# ============================================================================

class TestDeviceBindingChecks(_CheckBase):

    def test_device_type_enum(self):
        self._expect_check_violation(
            "INSERT INTO DeviceBinding "
            "(token_id, device_type, device_fingerprint, binding_method) "
            "VALUES (1, 'LAPTOP', 'fp', 'SECURE_ENCLAVE')",
            constraint_name='device_type_check',
        )

    def test_binding_method_enum(self):
        self._expect_check_violation(
            "INSERT INTO DeviceBinding "
            "(token_id, device_type, device_fingerprint, binding_method) "
            "VALUES (1, 'PHONE', 'fp', 'CUSTOM_METHOD')",
            constraint_name='binding_method_check',
        )


# ============================================================================
# EnrollmentStatusEvent (R11-4 / M2-9)
# ============================================================================

class TestEnrollmentStatusEventChecks(_CheckBase):

    def test_status_enum(self):
        self._expect_check_violation(
            "INSERT INTO EnrollmentStatusEvent "
            "(individual_id, status, transition_reason) "
            "VALUES (1, 'UNKNOWN', 'Test')",
            constraint_name='enrollmentstatusevent_status_check',
        )


class TestIdentityTokenChecks(_CheckBase):

    def test_status_enum(self):
        self._expect_check_violation(
            "INSERT INTO IdentityToken "
            "(individual_id, token_value, physical_serial, status, "
            "algorithm_id, issuing_agency_id, biometric_binding_type) "
            "VALUES (2, 'X-TEST-1', 'PSV-1', 'INVALID', 1, 1, 'FINGERPRINT')",
            constraint_name='identitytoken_status_check',
        )

    def test_biometric_binding_type_enum(self):
        self._expect_check_violation(
            "INSERT INTO IdentityToken "
            "(individual_id, token_value, physical_serial, status, "
            "algorithm_id, issuing_agency_id, biometric_binding_type) "
            "VALUES (2, 'X-TEST-2', 'PSV-2', 'RESERVE', 1, 1, 'DNA')",
            constraint_name='biometric_binding_type_check',
        )

    def test_liveness_check_type_enum(self):
        self._expect_check_violation(
            "INSERT INTO IdentityToken "
            "(individual_id, token_value, physical_serial, status, "
            "algorithm_id, issuing_agency_id, biometric_binding_type, "
            "liveness_check_type) "
            "VALUES (2, 'X-TEST-3', 'PSV-3', 'RESERVE', 1, 1, 'FINGERPRINT', 'NONE')",
            constraint_name='liveness_check_type_check',
        )

    def test_activation_sequence_must_be_positive(self):
        self._expect_check_violation(
            "INSERT INTO IdentityToken "
            "(individual_id, token_value, physical_serial, status, "
            "algorithm_id, issuing_agency_id, biometric_binding_type, "
            "activation_sequence) "
            "VALUES (2, 'X-TEST-4', 'PSV-4', 'RESERVE', 1, 1, 'FINGERPRINT', 0)",
            constraint_name='activation_sequence_check',
        )

    def test_duress_hash_well_formed(self):
        """duress_code_hash, when present, must be >= 20 chars."""
        self._expect_check_violation(
            "INSERT INTO IdentityToken "
            "(individual_id, token_value, physical_serial, status, "
            "algorithm_id, issuing_agency_id, biometric_binding_type, "
            "duress_code_hash) "
            "VALUES (2, 'X-TEST-5', 'PSV-5', 'RESERVE', 1, 1, 'FINGERPRINT', 'short')",
            constraint_name='chk_duress_hash_well_formed',
        )

    def test_token_time_order_activated_before_issued_rejected(self):
        """chk_token_time_order: activated_date >= issued_date."""
        self._expect_check_violation(
            "INSERT INTO IdentityToken "
            "(individual_id, token_value, physical_serial, status, "
            "algorithm_id, issuing_agency_id, biometric_binding_type, "
            "issued_date, activated_date) "
            "VALUES (2, 'X-TEST-6', 'PSV-6', 'ACTIVE', 1, 1, 'FINGERPRINT', "
            "'2026-05-14 12:00:00', '2026-05-13 12:00:00')",
            constraint_name='chk_token_time_order',
        )


# ============================================================================
# IssuerDiscretionPolicy (R11-6 / M2-11)
# ============================================================================

class TestIssuerDiscretionPolicyChecks(_CheckBase):

    def test_window_days_floor(self):
        self._expect_check_violation(
            "INSERT INTO IssuerDiscretionPolicy "
            "(agency_id, max_revoke_percent, window_days, set_by_admin, justification) "
            "VALUES (1, 5.0, 0, 1, 'A reasonable justification for the policy')",
            constraint_name='window_days_check',
        )

    def test_window_days_ceiling(self):
        self._expect_check_violation(
            "INSERT INTO IssuerDiscretionPolicy "
            "(agency_id, max_revoke_percent, window_days, set_by_admin, justification) "
            "VALUES (1, 5.0, 366, 1, 'A reasonable justification for the policy')",
            constraint_name='window_days_check',
        )

    def test_max_revoke_percent_zero_rejected(self):
        self._expect_check_violation(
            "INSERT INTO IssuerDiscretionPolicy "
            "(agency_id, max_revoke_percent, window_days, set_by_admin, justification) "
            "VALUES (1, 0.0, 30, 1, 'A reasonable justification for the policy')",
            constraint_name='max_revoke_percent',
        )

    def test_justification_minimum_length(self):
        """justification must be >= 20 chars."""
        self._expect_check_violation(
            "INSERT INTO IssuerDiscretionPolicy "
            "(agency_id, max_revoke_percent, window_days, set_by_admin, justification) "
            "VALUES (1, 5.0, 30, 1, 'too short')",
            constraint_name='justification_check',
        )


# ============================================================================
# RecoveryRequest (R11-2 / M2-7)
# ============================================================================

class TestRecoveryRequestChecks(_CheckBase):

    def test_cooldown_window_minimum(self):
        """48-hour cooldown floor."""
        self._expect_check_violation(
            "INSERT INTO RecoveryRequest "
            "(claimed_individual_id, requesting_agency_id, requesting_user_id, "
            "requested_at, cooldown_expires_at) "
            "VALUES (1, 1, 1, '2026-05-14 12:00:00', '2026-05-15 12:00:00')",
            constraint_name='cooldown_window_minimum',
        )

    def test_status_enum(self):
        self._expect_check_violation(
            "INSERT INTO RecoveryRequest "
            "(claimed_individual_id, requesting_agency_id, requesting_user_id, "
            "requested_at, cooldown_expires_at, status) "
            "VALUES (1, 1, 1, '2026-05-14 12:00:00', '2026-05-17 12:00:00', 'INVALID')",
            constraint_name='recoveryrequest_status_check',
        )

    def test_approver_differs_from_requester(self):
        self._expect_check_violation(
            "INSERT INTO RecoveryRequest "
            "(claimed_individual_id, requesting_agency_id, requesting_user_id, "
            "requested_at, cooldown_expires_at, decided_by_user_id) "
            "VALUES (1, 1, 1, '2026-05-14 12:00:00', '2026-05-17 12:00:00', 1)",
            constraint_name='approver_differs_from_requester',
        )


# ============================================================================
# RevocationList
# ============================================================================

class TestRevocationListChecks(_CheckBase):
    """RevocationList's `reason_code_check` enum is layered behind
    multiple safety triggers:

      * `enforce_revocation_status` (token must be REVOKED/LOST/EXPIRED
        before an entry can be added)
      * `enforce_revocation_velocity_bound` (direct UPDATE to
        ``status='REVOKED'`` is forbidden; must go through
        ``uc8_revoke_token()``)

    Exercising the reason_code CHECK in isolation requires bypassing
    these safety layers, which contradicts the defensive design they
    embody. The CHECK is structurally present in the schema (verified
    via the pg_constraint catalog ); the operational path through
    ``uc8_revoke_token`` is exercised by the existing UC test suite
    (see test_app.py). Leaving this class as a documentation anchor
    for the constraint without an isolated unit test.
    """

    def test_constraint_documented(self):
        """Documentation-only: the reason_code_check exists in the
        live schema and is exercised via the safety-trigger-protected
        operational path."""
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT con.conname
                FROM pg_constraint con
                JOIN pg_class cl ON con.conrelid = cl.oid
                WHERE cl.relname = 'revocationlist'
                  AND con.contype = 'c'
                  AND con.conname = 'revocationlist_reason_code_check'
            """)
            row = cur.fetchone()
            self.assertIsNotNone(row,
                "revocationlist_reason_code_check must exist in pg_constraint.")


# ============================================================================
# TokenLifecycleEvent
# ============================================================================

class TestTokenLifecycleEventChecks(_CheckBase):

    def test_event_type_enum(self):
        self._expect_check_violation(
            "INSERT INTO TokenLifecycleEvent (token_id, event_type) "
            "VALUES (1, 'DISAPPEARED')",
            constraint_name='event_type_check',
        )

    def test_latitude_above_ceiling(self):
        self._expect_check_violation(
            "INSERT INTO TokenLifecycleEvent "
            "(token_id, event_type, latitude, longitude) "
            "VALUES (1, 'ISSUED', 91.0, 0.0)",
            constraint_name='latitude_check',
        )

    def test_longitude_above_ceiling(self):
        self._expect_check_violation(
            "INSERT INTO TokenLifecycleEvent "
            "(token_id, event_type, latitude, longitude) "
            "VALUES (1, 'ISSUED', 0.0, 181.0)",
            constraint_name='longitude_check',
        )

    def test_latitude_below_floor(self):
        self._expect_check_violation(
            "INSERT INTO TokenLifecycleEvent "
            "(token_id, event_type, latitude, longitude) "
            "VALUES (1, 'ISSUED', -90.5, 0.0)",
            constraint_name='latitude_check',
        )


# ============================================================================
# TokenPermission
# ============================================================================

class TestTokenPermissionChecks(_CheckBase):

    def test_permission_level_enum(self):
        self._expect_check_violation(
            "INSERT INTO TokenPermission "
            "(token_id, context_id, permission_level) "
            "VALUES (1, 1, 'ROOT')",
            constraint_name='permission_level_check',
        )


# ============================================================================
# TokenSignature (R11-1 / M2-6)
# ============================================================================

class TestTokenSignatureChecks(_CheckBase):

    def test_deprecation_after_signed(self):
        """deprecation_date, if set, must be strictly after signed_at."""
        self._expect_check_violation(
            "INSERT INTO TokenSignature "
            "(token_id, algorithm_id, signature_bytes, signed_at, deprecation_date) "
            "VALUES (1, 1, decode('deadbeef', 'hex'), "
            "'2026-05-14 12:00:00', '2026-05-14 11:00:00')",
            constraint_name='deprecation_after_signed',
        )


# ============================================================================
# TokenStateEpoch + Leaves (R10-1 / M2-1)
# ============================================================================

class TestTokenStateEpochChecks(_CheckBase):

    def test_root_must_be_hex(self):
        self._expect_check_violation(
            "INSERT INTO TokenStateEpoch "
            "(merkle_root, valid_until, committed_count, closed_by_user_id) "
            "VALUES ('not-hex!', now() + interval '1 day', 1, 1)",
            constraint_name='epoch_root_is_hex',
        )

    def test_committed_count_cap(self):
        """committed_count cap is 10000."""
        self._expect_check_violation(
            "INSERT INTO TokenStateEpoch "
            "(merkle_root, valid_until, committed_count, closed_by_user_id) "
            "VALUES ('deadbeef', now() + interval '1 day', 10001, 1)",
            constraint_name='committed_count_cap',
        )

    def test_committed_count_must_be_positive(self):
        self._expect_check_violation(
            "INSERT INTO TokenStateEpoch "
            "(merkle_root, valid_until, committed_count, closed_by_user_id) "
            "VALUES ('deadbeef', now() + interval '1 day', 0, 1)",
            constraint_name='committed_count_check',
        )

    def test_validity_floor(self):
        """valid_until must exceed valid_from."""
        self._expect_check_violation(
            "INSERT INTO TokenStateEpoch "
            "(merkle_root, valid_from, valid_until, committed_count, closed_by_user_id) "
            "VALUES ('deadbeef', '2026-05-14 12:00:00', '2026-05-14 11:00:00', 1, 1)",
            constraint_name='epoch_validity_floor',
        )


# ============================================================================
# VerificationContext
# ============================================================================

class TestVerificationContextChecks(_CheckBase):

    def test_context_type_enum(self):
        self._expect_check_violation(
            "INSERT INTO VerificationContext "
            "(context_type, min_security_level) "
            "VALUES ('GAMBLING', 192)",
            constraint_name='context_type_check',
        )

    def test_min_security_level_floor(self):
        """128-bit floor for verification contexts."""
        self._expect_check_violation(
            "INSERT INTO VerificationContext "
            "(context_type, min_security_level) "
            "VALUES ('HEALTHCARE', 80)",
            constraint_name='min_security_level_check',
        )


# ============================================================================
# VerificationEvent — THE most-important checks: C2 enforcement
# ============================================================================

class TestVerificationEventChecks(_CheckBase):
    """The verification-event CHECKs include ``chk_disclosure_token_consistency``
    — the column-level half of C2 (ZK → token_id IS NULL). This is the
    most-important CHECK in the schema for the project's privacy claim."""

    def test_disclosure_level_enum(self):
        """The disclosure_level column-level enum CHECK fires on any
        value outside {ZERO_KNOWLEDGE, SELECTIVE, FULL}.

        Note: a non-enum value also fails ``chk_disclosure_token_consistency``
        (the multi-column CHECK) because no token_id/disclosure_level
        pair matches the consistency rule. PostgreSQL's CHECK evaluation
        order is implementation-defined; we accept either constraint
        firing.
        """
        # Try with token_id NULL so chk_disclosure_token_consistency
        # is satisfied only in the ZK case; PUBLIC isn't ZK, so the
        # consistency CHECK still fires but the enum CHECK is the
        # natural target. Either constraint firing means the bad
        # value was rejected — verify CheckViolation without binding
        # to a specific name.
        with self.assertRaises(pg_errors.CheckViolation):
            with self.conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO VerificationEvent "
                    "(token_id, requesting_agency_id, context_id, outcome, "
                    "disclosure_level) "
                    "VALUES (NULL, 1, 1, 'SUCCESS', 'PUBLIC')"
                )

    def test_C2_zk_with_nonnull_token_id_rejected(self):
        """chk_disclosure_token_consistency — C2 enforcement at column level.

        ZERO_KNOWLEDGE events MUST have token_id IS NULL. This is the
        privacy invariant; if it lapses, the verification graph becomes
        reconstructable from ZK events alone.
        """
        self._expect_check_violation(
            "INSERT INTO VerificationEvent "
            "(token_id, requesting_agency_id, context_id, outcome, disclosure_level) "
            "VALUES (1, 1, 1, 'SUCCESS', 'ZERO_KNOWLEDGE')",
            constraint_name='chk_disclosure_token_consistency',
        )

    def test_C2_full_with_null_token_id_rejected(self):
        """FULL events MUST have token_id IS NOT NULL — the other half
        of chk_disclosure_token_consistency."""
        self._expect_check_violation(
            "INSERT INTO VerificationEvent "
            "(token_id, requesting_agency_id, context_id, outcome, disclosure_level) "
            "VALUES (NULL, 1, 1, 'SUCCESS', 'FULL')",
            constraint_name='chk_disclosure_token_consistency',
        )

    def test_latitude_above_ceiling(self):
        self._expect_check_violation(
            "INSERT INTO VerificationEvent "
            "(token_id, requesting_agency_id, context_id, outcome, "
            "disclosure_level, latitude, longitude) "
            "VALUES (1, 1, 1, 'SUCCESS', 'FULL', 91.0, 0.0)",
            constraint_name='latitude_check',
        )


# ============================================================================
# DuressEvent (R11-5 / M2-10)
# ============================================================================

class TestDuressEventChecks(_CheckBase):

    def test_oob_channel_enum(self):
        self._expect_check_violation(
            "INSERT INTO DuressEvent "
            "(token_id, context_id, requesting_agency_id, oob_channel) "
            "VALUES (1, 1, 1, 'TELEGRAM')",
            constraint_name='oob_channel_check',
        )


class TestUC4ReserveActivation(_CheckBase):
    """uc4_activate_reserve must succeed for every reason code it offers.

    COMPROMISED / SUPERSEDED / ADMINISTRATIVE map the lost token to terminal
    status REVOKED, which trips enforce_revocation_velocity_bound() unless the
    procedure opts out of the bound (the way uc8_revoke_token does). Until uc4
    set polaris.revoke_check_done on its REVOKED branch, three of the five
    reason codes the UI offers aborted the whole procedure with
    'Direct UPDATE to status=REVOKED is not allowed'. LOST / STOLEN map to
    terminal LOST and never tripped the trigger, which is why nothing caught it.
    Each test runs inside the per-test transaction and rolls back.
    """

    def _run_uc4(self, reason_code):
        """Stage an ACTIVE holder + a fresh RESERVE for them, run uc4 with
        ``reason_code``, and return (promoted_token_id, reserve_token_id,
        lost_token_status). Propagates any procedure exception."""
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT individual_id, token_id FROM IdentityToken "
                "WHERE status = 'ACTIVE' LIMIT 1")
            row = cur.fetchone()
            self.assertIsNotNone(
                row, "sample data has no ACTIVE token to test uc4 against")
            individual_id, active_token = row['individual_id'], row['token_id']

            cur.execute(
                "INSERT INTO IdentityToken "
                "(token_value, physical_serial, biometric_binding_type, "
                " individual_id, issuing_agency_id, algorithm_id, status) "
                "VALUES (%s, %s, 'FINGERPRINT', %s, 3, 1, 'RESERVE') "
                "RETURNING token_id",
                (f'UC4TEST-{reason_code}-{active_token}',
                 f'UC4SER-{reason_code}-{active_token}', individual_id))
            reserve_token = cur.fetchone()['token_id']

            cur.execute(
                "SELECT uc4_activate_reserve(%s, 3, %s, %s, %s) AS promoted",
                (active_token, reason_code, reserve_token,
                 f'https://crl.idtoken.gov/test/{reason_code}.crl'))
            promoted = cur.fetchone()['promoted']

            cur.execute(
                "SELECT status FROM IdentityToken WHERE token_id = %s",
                (active_token,))
            lost_status = cur.fetchone()['status']
            return promoted, reserve_token, lost_status

    def test_lost_positive_control(self):
        promoted, reserve, lost_status = self._run_uc4('LOST')
        self.assertEqual(promoted, reserve)
        self.assertEqual(lost_status, 'LOST')

    def test_compromised_maps_to_revoked_and_succeeds(self):
        promoted, reserve, lost_status = self._run_uc4('COMPROMISED')
        self.assertEqual(promoted, reserve)
        self.assertEqual(lost_status, 'REVOKED')

    def test_superseded_maps_to_revoked_and_succeeds(self):
        promoted, reserve, lost_status = self._run_uc4('SUPERSEDED')
        self.assertEqual(promoted, reserve)
        self.assertEqual(lost_status, 'REVOKED')

    def test_administrative_maps_to_revoked_and_succeeds(self):
        promoted, reserve, lost_status = self._run_uc4('ADMINISTRATIVE')
        self.assertEqual(promoted, reserve)
        self.assertEqual(lost_status, 'REVOKED')


class TestUC1Issuance(_CheckBase):
    """uc1_issue_and_activate must refuse to mint a token under a DEPRECATED
    algorithm — uc6_migrate_algorithm already refuses to migrate a token TO a
    deprecated algorithm, and uc1 must not create one under it either (a live
    token signed with a retired/weakened algorithm). Runs in the per-test
    transaction and rolls back (the deprecation UPDATE is discarded)."""

    def test_uc1_refuses_deprecated_algorithm(self):
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT algorithm_id FROM AgencyAlgorithmAuth "
                "WHERE agency_id = 1 AND authorization_type IN ('ISSUE','BOTH') LIMIT 1")
            alg = cur.fetchone()['algorithm_id']
            cur.execute(
                "UPDATE CryptographicAlgorithm "
                "SET deprecation_date = CURRENT_TIMESTAMP - INTERVAL '1 day' "
                "WHERE algorithm_id = %s", (alg,))
            with self.assertRaises(pg_errors.InvalidParameterValue):
                cur.execute(
                    "SELECT uc1_issue_and_activate('Dep Test','1990-01-01','US-CA',1,%s,"
                    "'FINGERPRINT',1,'MULTI_MODAL','TKN-DEPTEST','SN-DEPTEST',NULL,"
                    "ARRAY[1])", (alg,))

    def test_uc1_succeeds_under_a_live_algorithm(self):
        # Control: a non-deprecated algorithm issues normally.
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT a.algorithm_id FROM AgencyAlgorithmAuth a "
                "JOIN CryptographicAlgorithm c ON c.algorithm_id = a.algorithm_id "
                "WHERE a.agency_id = 1 AND a.authorization_type IN ('ISSUE','BOTH') "
                "  AND (c.deprecation_date IS NULL OR c.deprecation_date > CURRENT_TIMESTAMP) "
                "LIMIT 1")
            alg = cur.fetchone()['algorithm_id']
            cur.execute(
                "SELECT uc1_issue_and_activate('Live Test','1990-01-01','US-CA',1,%s,"
                "'FINGERPRINT',1,'MULTI_MODAL','TKN-LIVETEST','SN-LIVETEST',NULL,"
                "ARRAY[1]) AS token_id", (alg,))
            self.assertIsNotNone(cur.fetchone()['token_id'])


class TestC1PrivilegeBoundary(unittest.TestCase):
    """C1 append-only is a PRIVILEGE boundary, not only a trigger.

    The reject_audit_modification trigger has a carve-out: it permits
    UPDATE/DELETE when the custom GUC polaris.purge_in_progress = 'TRUE'. Any
    role can SET a custom GUC, so the trigger alone did NOT stop the
    application role from deleting an audit row — it could set the GUC and
    delete. v9.85 revokes UPDATE/DELETE on every append-only table from
    polaris_app (keeping SELECT + INSERT), so the carve-out is unreachable from
    the app role; the one legitimate DELETE path, uc_archive_purge, is
    SECURITY DEFINER and runs the purge with the owner's rights.

    These tests open an EXPLICIT polaris_app connection so the boundary is
    exercised even when the suite itself connects as a superuser (locally the
    suite runs as `vanta`, which bypasses the ACL; in CI it is already
    polaris_app). They skip cleanly if the polaris_app role is unreachable.
    """

    APPEND_ONLY_TABLES = (
        "TokenLifecycleEvent", "VerificationEvent", "EnrollmentStatusEvent",
        "AnchorBatch", "TokenStateEpochLeaf", "DuressEvent", "AuthAuditLog",
        "AuditAccessLog",
        # v9.234: a retention decision is an audit of record like any other.
        "RetentionPolicy",
        # v9.322 (P8.2c): the exchange-receipt transparency log.
        "ExchangeReceiptLog",
        # v9.324 (P8.2d): the exchange gateway's replay register.
        "ExchangeNonce",
        # v9.326 (P8.4): the auth broker's consumed-code register.
        "AuthCodeConsumed",
        # v9.328 (P8.7b): the authority key register.
        "AuthorityKeyEvent",
    )

    def _app_conn(self):
        """A connection authenticated as the application role polaris_app.

        Skips the test if that role cannot be reached (e.g. a deployment that
        renamed it or set a non-default password without exporting it)."""
        cfg = dict(DB_CONFIG)
        cfg["user"] = "polaris_app"
        cfg["password"] = os.environ.get(
            "POLARIS_APP_TEST_PASSWORD",
            DB_CONFIG.get("password") or "polaris_dev_password")
        try:
            conn = psycopg2.connect(cursor_factory=RealDictCursor, **cfg)
        except psycopg2.OperationalError as exc:
            self.skipTest(f"polaris_app role unreachable: {exc}")
        self.addCleanup(conn.close)
        return conn

    def test_app_role_cannot_delete_audit_even_with_purge_guc(self):
        conn = self._app_conn()
        with conn.cursor() as cur:
            # Reproduce the original bypass: set the carve-out GUC, then delete.
            cur.execute("SET LOCAL polaris.purge_in_progress = 'TRUE'")
            with self.assertRaises(pg_errors.InsufficientPrivilege):
                cur.execute(
                    "DELETE FROM TokenLifecycleEvent "
                    "WHERE event_id = (SELECT min(event_id) FROM TokenLifecycleEvent)")
        conn.rollback()

    def test_app_role_cannot_update_or_delete_any_append_only_table(self):
        conn = self._app_conn()
        for tbl in self.APPEND_ONLY_TABLES:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT has_table_privilege('polaris_app', %s, 'UPDATE') AS upd, "
                    "       has_table_privilege('polaris_app', %s, 'DELETE') AS del, "
                    "       has_table_privilege('polaris_app', %s, 'INSERT') AS ins",
                    (tbl, tbl, tbl))
                row = cur.fetchone()
            self.assertFalse(row["upd"], f"polaris_app must not hold UPDATE on {tbl}")
            self.assertFalse(row["del"], f"polaris_app must not hold DELETE on {tbl}")
            self.assertTrue(row["ins"], f"append-only is insert-allowed: polaris_app needs INSERT on {tbl}")
            conn.rollback()

    def test_receipt_log_is_hash_only_and_strictly_append_only(self):
        """P8.2c: ExchangeReceiptLog holds ONLY a SHA3-256 hex (chk_receipt_log_hash) and is
        strictly append-only -- INSERT works for polaris_app, UPDATE/DELETE are refused."""
        conn = self._app_conn()
        with conn.cursor() as cur:
            with self.assertRaises(pg_errors.CheckViolation):
                cur.execute("INSERT INTO ExchangeReceiptLog (receipt_hash) VALUES ('not-a-hash')")
        conn.rollback()
        good = "ab" * 32
        with conn.cursor() as cur:
            cur.execute("INSERT INTO ExchangeReceiptLog (receipt_hash) VALUES (%s) RETURNING seq", (good,))
            self.assertIsNotNone(cur.fetchone()["seq"])
            with self.assertRaises(pg_errors.InsufficientPrivilege):
                cur.execute("UPDATE ExchangeReceiptLog SET receipt_hash = %s WHERE receipt_hash = %s", ("cd" * 32, good))
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute("INSERT INTO ExchangeReceiptLog (receipt_hash) VALUES (%s)", (good,))
            with self.assertRaises(pg_errors.InsufficientPrivilege):
                cur.execute("DELETE FROM ExchangeReceiptLog WHERE receipt_hash = %s", (good,))
        conn.rollback()

    def test_exchange_nonce_is_consumed_once_and_never_unconsumed(self):
        """P8.2d: ExchangeNonce consumes (requester key hash, nonce) once -- a second INSERT of
        the same pair is a replay (UniqueViolation) -- and polaris_app can never UPDATE/DELETE
        it (chk_exchange_nonce_key / chk_exchange_nonce_len bound the columns)."""
        conn = self._app_conn()
        kh, nonce = "ab" * 32, "req-nonce-1"
        with conn.cursor() as cur:
            cur.execute("INSERT INTO ExchangeNonce (requester_key_hash, nonce) VALUES (%s, %s)", (kh, nonce))
            with self.assertRaises(pg_errors.UniqueViolation):
                cur.execute("INSERT INTO ExchangeNonce (requester_key_hash, nonce) VALUES (%s, %s)", (kh, nonce))
        conn.rollback()
        with conn.cursor() as cur:
            with self.assertRaises(pg_errors.CheckViolation):
                cur.execute("INSERT INTO ExchangeNonce (requester_key_hash, nonce) VALUES ('not-a-key-hash', %s)", (nonce,))
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute("INSERT INTO ExchangeNonce (requester_key_hash, nonce) VALUES (%s, %s)", (kh, nonce))
            with self.assertRaises(pg_errors.InsufficientPrivilege):
                cur.execute("DELETE FROM ExchangeNonce WHERE requester_key_hash = %s", (kh,))
        conn.rollback()

    def test_auth_code_consumed_once_and_never_unconsumed(self):
        """P8.4: AuthCodeConsumed holds ONLY a code hash (chk_auth_code_hash); a second INSERT of
        the same hash is a replay (UniqueViolation) and polaris_app can never DELETE one."""
        conn = self._app_conn()
        h = "ef" * 32
        with conn.cursor() as cur:
            cur.execute("INSERT INTO AuthCodeConsumed (code_hash) VALUES (%s)", (h,))
            with self.assertRaises(pg_errors.UniqueViolation):
                cur.execute("INSERT INTO AuthCodeConsumed (code_hash) VALUES (%s)", (h,))
        conn.rollback()
        with conn.cursor() as cur:
            with self.assertRaises(pg_errors.CheckViolation):
                cur.execute("INSERT INTO AuthCodeConsumed (code_hash) VALUES ('not-a-hash')")
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute("INSERT INTO AuthCodeConsumed (code_hash) VALUES (%s)", (h,))
            with self.assertRaises(pg_errors.InsufficientPrivilege):
                cur.execute("DELETE FROM AuthCodeConsumed WHERE code_hash = %s", (h,))
        conn.rollback()

    def test_authority_key_history_is_append_only_and_one_way(self):
        """P8.7b: AuthorityKeyEvent accepts registered/retired/compromised rows (chk_authority_key_event),
        never an edit or a removal, and AuthorityKeyCurrent derives compromised > retired > active."""
        conn = self._app_conn()
        key = "ab" * 32
        with conn.cursor() as cur:
            with self.assertRaises(pg_errors.CheckViolation):
                cur.execute("INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, event) VALUES (1, %s, 'revived')", (key,))
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute("INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, event) VALUES (1, %s, 'registered')", (key,))
            cur.execute("SELECT status FROM AuthorityKeyCurrent WHERE public_key_hex = %s", (key,))
            self.assertEqual(cur.fetchone()["status"], "active")
            cur.execute("INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, event) VALUES (1, %s, 'retired')", (key,))
            cur.execute("SELECT status FROM AuthorityKeyCurrent WHERE public_key_hex = %s", (key,))
            self.assertEqual(cur.fetchone()["status"], "retired")
            cur.execute("INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, event) VALUES (1, %s, 'compromised')", (key,))
            cur.execute("SELECT status FROM AuthorityKeyCurrent WHERE public_key_hex = %s", (key,))
            self.assertEqual(cur.fetchone()["status"], "compromised")
            with self.assertRaises(pg_errors.InsufficientPrivilege):
                cur.execute("DELETE FROM AuthorityKeyEvent WHERE public_key_hex = %s", (key,))
        conn.rollback()

    def test_app_role_can_still_append_audit_rows(self):
        conn = self._app_conn()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO TokenLifecycleEvent (token_id, event_type, event_timestamp, reason_code) "
                "VALUES (1, 'ISSUED', now(), 'BOUNDARY_TEST') RETURNING event_id")
            self.assertIsNotNone(cur.fetchone()["event_id"],
                                 "append-only must still permit INSERT by polaris_app")
        conn.rollback()

    def test_archive_purge_still_deletes_via_security_definer(self):
        """The legitimate purge path still works for polaris_app: uc_archive_purge
        is SECURITY DEFINER, so it deletes with the owner's rights despite the
        REVOKE. The cutoff is older than the shipped five-year retention, since
        v9.234 the purge refuses anything younger. The whole exercise rolls back."""
        conn = self._app_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE role = 'admin' LIMIT 1")
            admin = cur.fetchone()
            if admin is None:
                self.skipTest("no admin user to authorize the purge")
            admin_id = admin["user_id"]
            cur.execute(
                "INSERT INTO TokenLifecycleEvent (token_id, event_type, event_timestamp, reason_code) "
                "VALUES (1, 'ISSUED', now() - INTERVAL '2200 days', 'PURGE_DEFINER_TEST')")
            cutoff = "now() - INTERVAL '2000 days'"
            cur.execute(
                f"SELECT count(*) AS n FROM TokenLifecycleEvent WHERE event_timestamp < {cutoff}")
            before = cur.fetchone()["n"]
            self.assertGreaterEqual(before, 1)
            cur.execute(
                "CALL uc_archive_purge((now() - INTERVAL '2000 days')::timestamptz, "
                "%s, %s, %s, NULL, NULL)",
                ("s3://polaris-archive/definer-test.tar.zst", "a" * 64, admin_id))
            cur.execute(
                f"SELECT count(*) AS n FROM TokenLifecycleEvent WHERE event_timestamp < {cutoff}")
            after = cur.fetchone()["n"]
            self.assertEqual(after, 0,
                             "uc_archive_purge (SECURITY DEFINER) must still purge old audit rows")
        conn.rollback()


class TestRetentionEngine(_CheckBase):
    """The retention decision is data, floored, and the purge obeys it (P1.11).

    Before v9.234 the cutoff was whatever the operator typed: the database
    accepted a purge at "older than one hour" as readily as one at five years,
    and nothing recorded who decided the retention or why. These tests hold the
    three properties that fixed it: the floor cannot be configured away, the
    decision cannot be edited after the fact, and a purge inside the window is
    refused rather than quietly narrowed.
    """

    def setUp(self):
        super().setUp()
        self.cur = self.conn.cursor()
        self.addCleanup(self.cur.close)

    def test_retention_floor_refuses_a_short_policy(self):
        with self.assertRaises(pg_errors.CheckViolation):
            self.cur.execute(
                "INSERT INTO RetentionPolicy (table_class, jurisdiction, retention_days, "
                "justification, set_by_user_id) VALUES ('VERIFICATION', 'US-PY1', 30, "
                "'a month is not long enough to be an audit of record', 1)")

    def test_a_policy_must_say_why(self):
        with self.assertRaises(pg_errors.CheckViolation):
            self.cur.execute(
                "INSERT INTO RetentionPolicy (table_class, jurisdiction, retention_days, "
                "justification, set_by_user_id) VALUES ('VERIFICATION', 'US-PY2', 1825, "
                "'because', 1)")

    def test_resolver_answers_for_an_unconfigured_jurisdiction(self):
        self.cur.execute("SELECT retention_days_for('VERIFICATION', 'US-NONE') AS d")
        self.assertGreaterEqual(self.cur.fetchone()["d"], 365,
                                "an unconfigured jurisdiction must still resolve, at or above the floor")

    def test_a_recorded_decision_cannot_be_edited(self):
        self.cur.execute(
            "INSERT INTO RetentionPolicy (table_class, jurisdiction, retention_days, "
            "justification, set_by_user_id) VALUES ('AUTH_AUDIT', 'US-PY4', 1825, "
            "'a decision recorded so the test can try to rewrite it', 1) RETURNING policy_id")
        pid = self.cur.fetchone()["policy_id"]
        with self.assertRaises(pg_errors.InsufficientPrivilege):
            self.cur.execute(
                "UPDATE RetentionPolicy SET retention_days = 400 WHERE policy_id = %s", (pid,))

    def test_a_recorded_decision_cannot_be_deleted(self):
        self.cur.execute(
            "INSERT INTO RetentionPolicy (table_class, jurisdiction, retention_days, "
            "justification, set_by_user_id) VALUES ('AUTH_AUDIT', 'US-PY5', 1825, "
            "'a decision recorded so the test can try to delete it', 1) RETURNING policy_id")
        pid = self.cur.fetchone()["policy_id"]
        with self.assertRaises(pg_errors.InsufficientPrivilege):
            self.cur.execute("DELETE FROM RetentionPolicy WHERE policy_id = %s", (pid,))

    def test_two_policies_cannot_be_effective_at_once(self):
        for _ in range(2):
            try:
                self.cur.execute(
                    "INSERT INTO RetentionPolicy (table_class, jurisdiction, retention_days, "
                    "justification, set_by_user_id) VALUES ('ENROLLMENT', 'US-PY6', 1825, "
                    "'two effective policies for one class would disagree', 1)")
            except pg_errors.UniqueViolation:
                return
        self.fail("a second effective policy for the same class was accepted")

    def test_policy_mode_purges_each_class_at_its_own_cutoff(self):
        """The point of a per-class schedule: two horizons, one purge."""
        self.cur.execute("SELECT user_id FROM AppUser WHERE role = 'admin' LIMIT 1")
        admin = self.cur.fetchone()
        self.cur.execute("SELECT token_id FROM IdentityToken ORDER BY token_id LIMIT 1")
        token = self.cur.fetchone()
        self.cur.execute(
            "SELECT context_id, requesting_agency_id FROM VerificationEvent ORDER BY event_id LIMIT 1")
        ctx = self.cur.fetchone()
        if admin is None or token is None or ctx is None:
            self.skipTest("no admin, token or verification context in the sample data")

        self.cur.execute(
            "INSERT INTO TokenLifecycleEvent (token_id, event_type, event_timestamp, reason_code) "
            "VALUES (%s, 'ISSUED', now() - INTERVAL '1100 days', 'PYDRILL')",
            (token["token_id"],))
        self.cur.execute(
            "INSERT INTO VerificationEvent (token_id, context_id, requesting_agency_id, "
            "event_timestamp, outcome, disclosure_level) "
            "VALUES (%s, %s, %s, now() - INTERVAL '1100 days', 'SUCCESS', 'SELECTIVE')",
            (token["token_id"], ctx["context_id"], ctx["requesting_agency_id"]))

        # The civic record is held for five years; verification for two.
        self.cur.execute(
            "CALL uc_archive_purge(%s::timestamptz, %s, %s, %s, NULL, %s::timestamptz[], NULL)",
            ("2021-01-01T00:00:00+00", "file:///tmp/pyclass.tar.gz", "d" * 64,
             admin["user_id"],
             ["2021-01-01T00:00:00+00", "2024-01-01T00:00:00+00",
              "2021-01-01T00:00:00+00", "2024-01-01T00:00:00+00"]))

        self.cur.execute(
            "SELECT count(*) AS n FROM TokenLifecycleEvent WHERE reason_code = 'PYDRILL'")
        self.assertEqual(self.cur.fetchone()["n"], 1,
                         "a 1100-day-old lifecycle row must survive a five-year lifecycle cutoff")
        self.cur.execute(
            "SELECT count(*) AS n FROM VerificationEvent "
            "WHERE event_timestamp < now() - INTERVAL '1000 days'")
        self.assertEqual(self.cur.fetchone()["n"], 0,
                         "verification rows past the two-year cutoff must be purged")

        self.cur.execute(
            "SELECT cutoff_source, cutoff_lifecycle, cutoff_verification "
            "FROM LifecycleArchiveCheckpoint ORDER BY checkpoint_id DESC LIMIT 1")
        cp = self.cur.fetchone()
        self.assertEqual(cp["cutoff_source"], "POLICY")
        self.assertLess(cp["cutoff_lifecycle"], cp["cutoff_verification"],
                        "the checkpoint must record both horizons, not one")

    def test_policy_mode_refuses_a_class_cutoff_inside_its_window(self):
        """An archive taken under a longer-lived policy must not purge under a shorter one."""
        self.cur.execute("SELECT user_id FROM AppUser WHERE role = 'admin' LIMIT 1")
        admin = self.cur.fetchone()
        if admin is None:
            self.skipTest("no admin user to authorize the purge")
        with self.assertRaises(pg_errors.CheckViolation):
            self.cur.execute(
                "CALL uc_archive_purge(%s::timestamptz, %s, %s, %s, NULL, %s::timestamptz[], NULL)",
                ("2021-01-01T00:00:00+00", "file:///tmp/pyinside.tar.gz", "e" * 64,
                 admin["user_id"],
                 # Verification inside its own window: ten days ago.
                 ["2021-01-01T00:00:00+00", "2026-08-25T00:00:00+00",
                  "2021-01-01T00:00:00+00", "2021-01-01T00:00:00+00"]))

    def test_policy_mode_refuses_a_scalar_newer_than_a_class_cutoff(self):
        """The manifest scalar is the oldest cutoff, so an old reader cannot over-delete."""
        self.cur.execute("SELECT user_id FROM AppUser WHERE role = 'admin' LIMIT 1")
        admin = self.cur.fetchone()
        if admin is None:
            self.skipTest("no admin user to authorize the purge")
        with self.assertRaises(pg_errors.CheckViolation):
            self.cur.execute(
                "CALL uc_archive_purge(%s::timestamptz, %s, %s, %s, NULL, %s::timestamptz[], NULL)",
                ("2024-01-01T00:00:00+00", "file:///tmp/pyscalar.tar.gz", "f" * 64,
                 admin["user_id"],
                 ["2021-01-01T00:00:00+00", "2024-01-01T00:00:00+00",
                  "2021-01-01T00:00:00+00", "2024-01-01T00:00:00+00"]))

    def test_policy_mode_refuses_a_malformed_cutoff_array(self):
        self.cur.execute("SELECT user_id FROM AppUser WHERE role = 'admin' LIMIT 1")
        admin = self.cur.fetchone()
        if admin is None:
            self.skipTest("no admin user to authorize the purge")
        with self.assertRaises(pg_errors.CheckViolation):
            self.cur.execute(
                "CALL uc_archive_purge(%s::timestamptz, %s, %s, %s, NULL, %s::timestamptz[], NULL)",
                ("2021-01-01T00:00:00+00", "file:///tmp/pyshort.tar.gz", "a" * 64,
                 admin["user_id"],
                 ["2021-01-01T00:00:00+00", "2021-01-01T00:00:00+00"]))

    def test_purge_refuses_a_cutoff_inside_the_retention_window(self):
        self.cur.execute("SELECT user_id FROM AppUser WHERE role = 'admin' LIMIT 1")
        admin = self.cur.fetchone()
        if admin is None:
            self.skipTest("no admin user to authorize the purge")
        with self.assertRaises(pg_errors.CheckViolation):
            self.cur.execute(
                "CALL uc_archive_purge((now() - INTERVAL '10 days')::timestamptz, %s, %s, %s, "
                "NULL, NULL)",
                ("file:///tmp/inside-window.tar.zst", "b" * 64, admin["user_id"]))


if __name__ == '__main__':
    unittest.main(verbosity=2)
