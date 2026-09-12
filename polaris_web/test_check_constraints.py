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
    """agency_type enum + authorization_level 1..5 range.

    Each insert declares a reason first. Since v9.440 `trg_agency_audited` is a BEFORE
    trigger, so it runs ahead of the table's CHECK constraints and a request with no
    stated reason is refused before the value is ever examined. Declaring one puts the
    CHECK back in the position of being the thing that refuses, which is what these
    tests are about. `TestAuthorityChangesAreRecorded` covers the other refusal.
    """

    #: Long enough to clear the 20-character floor the trigger enforces.
    REASON = "constraint test, not a real authority"

    def _expect_check_violation_with_reason(self, sql, constraint_name):
        self._expect_check_violation(
            "SELECT set_config('polaris.justification', %s, true); " + sql,
            params=(self.REASON,),
            constraint_name=constraint_name,
        )

    def test_agency_type_enum_rejects_unknown(self):
        self._expect_check_violation_with_reason(
            "INSERT INTO Agency (name, agency_type, jurisdiction, authorization_level) "
            "VALUES ('Test', 'INVALID', 'Nowhere', 3)",
            constraint_name='agency_type_check',
        )

    def test_agency_authorization_level_above_ceiling(self):
        self._expect_check_violation_with_reason(
            "INSERT INTO Agency (name, agency_type, jurisdiction, authorization_level) "
            "VALUES ('Test', 'FEDERAL', 'Nowhere', 6)",
            constraint_name='authorization_level',
        )

    def test_agency_authorization_level_zero_rejected(self):
        self._expect_check_violation_with_reason(
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
    """The account table's CHECK constraints.

    Each insert declares a reason first. Since v9.443 `trg_app_user_audited` is a BEFORE
    trigger, so it runs ahead of these CHECKs and an account with no stated reason is
    refused before the value is ever examined. Declaring one puts the CHECK back in the
    position of being the thing that refuses, which is what these tests are about.
    `TestAppUserChangesAreRecorded` covers the other refusal.
    """

    #: Long enough to clear the 20-character floor the trigger enforces.
    REASON = "constraint test, not a real operator account"

    def _expect_check_violation_with_reason(self, sql, constraint_name):
        self._expect_check_violation(
            "SELECT set_config('polaris.justification', %s, true); " + sql,
            params=(self.REASON,),
            constraint_name=constraint_name,
        )

    def test_role_enum(self):
        self._expect_check_violation_with_reason(
            "INSERT INTO AppUser (username, password_hash, role) "
            "VALUES ('xtest', 'argon2id$dummy', 'godmode')",
            constraint_name='chk_appuser_role',
        )

    def test_username_format_lowercase_only(self):
        """chk_appuser_username_format: ^[a-z0-9._-]{3,50}$"""
        self._expect_check_violation_with_reason(
            "INSERT INTO AppUser (username, password_hash, role) "
            "VALUES ('UPPER', 'argon2id$dummy', 'operator')",
            constraint_name='chk_appuser_username_format',
        )

    def test_username_too_short_rejected(self):
        self._expect_check_violation_with_reason(
            "INSERT INTO AppUser (username, password_hash, role) "
            "VALUES ('xy', 'argon2id$dummy', 'operator')",
            constraint_name='chk_appuser_username_format',
        )

    def test_failed_count_nonneg(self):
        self._expect_check_violation_with_reason(
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

    # P9.7 (v9.347): RecoveryRequest is an audit of record enforced at the SCHEMA, not by
    # the discipline of whoever holds a session. uc9_complete_recovery writes within the
    # envelope below; a raw UPDATE outside it is refused, and so is any DELETE.
    def _open_request(self, cur, _unused=None):
        """Open a PENDING request for an individual that has none. A partial unique index
        allows one open request per person, and these rows can no longer be deleted."""
        cur.execute(
            "INSERT INTO RecoveryRequest "
            "(claimed_individual_id, requesting_agency_id, requesting_user_id, cooldown_expires_at) "
            "SELECT i.individual_id, 1, (SELECT MIN(user_id) FROM AppUser), "
            "       CURRENT_TIMESTAMP + INTERVAL '49 hours' "
            "  FROM Individual i "
            " WHERE NOT EXISTS (SELECT 1 FROM RecoveryRequest r "
            "                    WHERE r.claimed_individual_id = i.individual_id AND r.status = 'PENDING') "
            " ORDER BY i.individual_id LIMIT 1 "
            "RETURNING recovery_id")
        row = cur.fetchone()
        self.assertIsNotNone(row, "no individual without an open recovery request")
        return row["recovery_id"]

    def _expect_refusal(self, sql, params, fragment):
        with self.assertRaises(psycopg2.Error) as ctx:
            with self.conn.cursor() as cur:
                cur.execute(sql, params)
        self.assertIn(fragment, str(ctx.exception))
        self.conn.rollback()

    def test_identity_fields_are_immutable(self):
        with self.conn.cursor() as cur:
            rid = self._open_request(cur, 1)
        self._expect_refusal("UPDATE RecoveryRequest SET claimed_individual_id = 2 WHERE recovery_id = %s",
                             (rid,), "append-only except for")

    def test_delete_is_refused(self):
        with self.conn.cursor() as cur:
            rid = self._open_request(cur, 1)
        self._expect_refusal("DELETE FROM RecoveryRequest WHERE recovery_id = %s", (rid,),
                             "DELETE on RecoveryRequest is forbidden")

    def test_verified_biometric_cannot_be_unset(self):
        with self.conn.cursor() as cur:
            rid = self._open_request(cur, 1)
            cur.execute("UPDATE RecoveryRequest SET biometric_verified = TRUE WHERE recovery_id = %s", (rid,))
        self._expect_refusal("UPDATE RecoveryRequest SET biometric_verified = FALSE WHERE recovery_id = %s",
                             (rid,), "cannot be un-set once recorded")

    def test_a_recorded_decision_cannot_be_rewritten(self):
        with self.conn.cursor() as cur:
            rid = self._open_request(cur, 1)
            cur.execute(
                "UPDATE RecoveryRequest SET status='REJECTED', decided_at=CURRENT_TIMESTAMP, "
                "decided_by_user_id=(SELECT MAX(user_id) FROM AppUser), decision_reason='under test' "
                "WHERE recovery_id = %s", (rid,))
        self._expect_refusal("UPDATE RecoveryRequest SET decision_reason = 'rewritten' WHERE recovery_id = %s",
                             (rid,), "cannot be rewritten or withdrawn")

    def test_a_terminal_status_cannot_move(self):
        with self.conn.cursor() as cur:
            rid = self._open_request(cur, 1)
            cur.execute(
                "UPDATE RecoveryRequest SET status='REJECTED', decided_at=CURRENT_TIMESTAMP, "
                "decided_by_user_id=(SELECT MAX(user_id) FROM AppUser), decision_reason='under test' "
                "WHERE recovery_id = %s", (rid,))
        self._expect_refusal("UPDATE RecoveryRequest SET status = 'EXPIRED' WHERE recovery_id = %s",
                             (rid,), "is terminal at REJECTED")

    def test_the_sanctioned_envelope_still_writes(self):
        """The paths uc9_complete_recovery uses are exactly the ones the trigger permits."""
        with self.conn.cursor() as cur:
            rid = self._open_request(cur, 1)
            cur.execute("UPDATE RecoveryRequest SET biometric_verified = TRUE, sworn_statement_hash = 'h' "
                        "WHERE recovery_id = %s", (rid,))
            cur.execute(
                "UPDATE RecoveryRequest SET status='REJECTED', decided_at=CURRENT_TIMESTAMP, "
                "decided_by_user_id=(SELECT MAX(user_id) FROM AppUser), decision_reason='under test' "
                "WHERE recovery_id = %s", (rid,))
            cur.execute("SELECT status, decision_reason FROM RecoveryRequest WHERE recovery_id = %s", (rid,))
            row = cur.fetchone()
        self.assertEqual(row["status"], "REJECTED")
        self.assertEqual(row["decision_reason"], "under test")


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
        # v9.349 (P9.1): the holder key register. A binding that could be updated would let
        # an operator replace the holder's key, which is the thing the register prevents.
        "HolderKeyEvent",
        # v9.341 (P8.5b): the timestamp transparency log.
        "TimestampLog",
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


    # ------------------------------------------------------------------
    # v9.437: the refusals uc_archive_purge makes.
    #
    # v9.434 deleted each of these and the whole suite stayed green. This procedure
    # is the ONLY sanctioned DELETE path against the append-only audit tables, and it
    # runs SECURITY DEFINER with the owner's rights precisely because nothing else
    # may. Everything standing between that power and an audit trail is a RAISE in
    # its preamble: the cutoff must be in the past, every per-class cutoff must be,
    # the archive digest must be a real digest, and the actor must be an admin who
    # exists. A trigger cannot check any of it -- the deletes have not happened yet.
    # ------------------------------------------------------------------

    def _admin_id(self):
        self.cur.execute("SELECT user_id FROM AppUser WHERE role = 'admin' LIMIT 1")
        return self.cur.fetchone()["user_id"]

    def _purge(self, cutoff="(now() - INTERVAL '2000 days')::timestamptz",
               digest="a" * 64, actor=None, class_cutoffs="NULL"):
        actor = self._admin_id() if actor is None else actor
        self.cur.execute(
            "CALL uc_archive_purge(%s, %%s, %%s, %%s, NULL, %s)" % (cutoff, class_cutoffs),
            ("s3://polaris-archive/v9437.tar.zst", digest, actor))

    def test_a_cutoff_in_the_future_is_refused(self):
        """A future cutoff deletes everything, including what has not happened yet."""
        with self.assertRaises(pg_errors.Error) as c:
            self._purge(cutoff="(now() + INTERVAL '1 day')::timestamptz")
        self.assertIn("is in the future", str(c.exception))

    def test_a_per_class_cutoff_in_the_future_is_refused(self):
        """The per-class array is the same power at finer grain, and was checked
        separately, so it needs its own case: a purge whose overall cutoff is sane can
        still carry a class cutoff that is not."""
        # Four, ordered TOKEN_LIFECYCLE, VERIFICATION, ENROLLMENT, AUTH_AUDIT: the
        # arity is checked separately and already covered, so this case has to satisfy
        # it in order to reach the one under test.
        past = "(now() - INTERVAL '2000 days')::timestamptz"
        future = "(now() + INTERVAL '1 day')::timestamptz"
        for i in range(4):
            with self.subTest(class_index=i):
                arr = ", ".join(future if j == i else past for j in range(4))
                self.cur.execute("SAVEPOINT classcut")
                with self.assertRaises(pg_errors.Error) as c:
                    self._purge(class_cutoffs="ARRAY[%s]" % arr)
                self.assertIn("is in the future", str(c.exception))
                self.cur.execute("ROLLBACK TO SAVEPOINT classcut")

    def test_the_archive_digest_must_be_a_digest(self):
        """The rows are gone after this runs; the digest is what proves the archive
        holding them is the one that was made. A short or non-hex string is not a
        commitment to anything."""
        for bad in ("", "deadbeef", "z" * 64, "A" * 63):
            with self.subTest(digest=bad or "(empty)"):
                self.cur.execute("SAVEPOINT digest")
                with self.assertRaises(pg_errors.Error) as c:
                    self._purge(digest=bad)
                self.assertIn("64 hex chars", str(c.exception))
                self.cur.execute("ROLLBACK TO SAVEPOINT digest")

    def test_an_actor_that_does_not_exist_is_refused(self):
        with self.assertRaises(pg_errors.Error) as c:
            self._purge(actor=9_000_004)
        self.assertIn("does not exist", str(c.exception))

    def test_a_non_admin_actor_is_refused(self):
        """SECURITY DEFINER means the procedure's own rights are the owner's, so the
        role check inside it is the entire access control on this path."""
        self.cur.execute("SELECT user_id, role FROM AppUser WHERE role <> 'admin' LIMIT 1")
        row = self.cur.fetchone()
        if row is None:
            self.skipTest("no non-admin account in the sample data")
        with self.assertRaises(pg_errors.Error) as c:
            self._purge(actor=row["user_id"])
        self.assertIn("must be admin", str(c.exception))

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


# ============================================================================
# Append-only, exhaustively (v9.412)
#
# C1 says the audit of record cannot be edited. The mechanism is a trigger, one
# per table, and v9.411 measured how many of them anything actually tested: of
# 37 top-level triggers, 14 could be dropped from the schema with all 757
# database tests still green. Twelve of those were append-only guards.
#
# The shape below is table-driven ON PURPOSE, and the last test in the class is
# the reason: it reads the append-only triggers out of the CATALOG and requires
# the fixture table to name every one. A new audit-of-record table therefore
# cannot be added without either covering it here or failing this suite, which
# is the property a hand-written list of tests does not have.
# ============================================================================

#: The guard functions that mean "this table is append-only". Read from pg_proc
#: rather than listed by trigger name, because a trigger can be renamed and the
#: guarantee is carried by what it calls.
APPEND_ONLY_GUARDS = (
    'reject_audit_modification',
    'reject_auth_code_modification',
    'reject_authority_key_event_modification',
    'reject_checkpoint_modification',
    'reject_exchange_nonce_modification',
    'reject_receipt_log_modification',
    'reject_schema_version_modification',
    'reject_timestamp_log_modification',
)

#: Phrases that identify a refusal as THE append-only guarantee rather than, say,
#: a missing GRANT, which raises the same SQLSTATE and would otherwise read as C1
#: being enforced when it is only being unreachable.
APPEND_ONLY_REFUSALS = ('append-only', 'un-consumed', 'immutable', 'single use',
                        'audit-of-record', 'append rather than mutate', 'never be')

#: table -> (primary key column, SQL that creates one row and returns that key).
#: The row is only a subject to attack; it does not have to be meaningful, only
#: legal. Where a table's row depends on another (evidence and vouching both
#: hang off a proofing record), the statement builds the chain.
_PROOFING = ("INSERT INTO EnrollmentProofing (individual_id, recorded_by_agency_id, presence, "
             "derived_ial) VALUES (1, 1, 'IN_PERSON', 'IAL2') RETURNING proofing_id")
_HEX64 = "repeat('a', 64)"

APPEND_ONLY_FIXTURES = {
    # v9.440: AgencyEvent has no INSERT of its own -- trg_agency_audited is the only
    # writer -- so the fixture creates the AUTHORITY and lets the trigger write the row.
    'appuserevent': ('event_id',
        "INSERT INTO AppUserEvent (user_id, username, event_type, field) "
        "VALUES (1, 'admin', 'RENAMED', 'username') RETURNING event_id"),
    'agencyevent': ('event_id',
        "SELECT set_config('polaris.justification', "
        "'append-only fixture: an authority created to attack its event row', true); "
        "INSERT INTO Agency (name, agency_type, jurisdiction, authorization_level) "
        "VALUES ('Append Only Authority Probe', 'COUNTY', 'US-ZZ', 1); "
        "SELECT max(event_id) AS event_id FROM AgencyEvent"),
    # v9.425: RelyingPartyEvent has no INSERT of its own -- trg_relying_party_audited
    # is the only writer. So the fixture makes the DECISION and lets the trigger write
    # the row, which is also the only way a caller could ever produce one.
    'relyingpartyevent': ('event_id',
        "SELECT set_config('polaris.justification', "
        "'append-only fixture: a party registered to attack its event row', true); "
        "INSERT INTO RelyingParty (client_id, client_secret_hash, org_name) "
        "VALUES ('rp_append_only_probe_01', repeat('c', 64), 'Append Only Probe'); "
        "SELECT max(event_id) AS event_id FROM RelyingPartyEvent"),
    'anchorbatch': ('batch_id', None),
    'auditaccesslog': ('access_id',
        "INSERT INTO AuditAccessLog (accessed_table) VALUES ('VerificationEvent') RETURNING access_id"),
    'authauditlog': ('audit_id',
        "INSERT INTO AuthAuditLog (event_type) VALUES ('LOGIN_SUCCESS') RETURNING audit_id"),
    'authcodeconsumed': ('code_hash',
        "INSERT INTO AuthCodeConsumed (code_hash) VALUES (repeat('b', 64)) RETURNING code_hash"),
    'authoritykeyevent': ('event_id',
        f"INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, event) "
        f"VALUES (1, {_HEX64}, 'registered') RETURNING event_id"),
    'cardpersonalization': ('personalization_id',
        "INSERT INTO CardPersonalization (token_id, issuing_agency_id, credential_ref, "
        "profile_version, normal_public_key, duress_public_key, card_object_sha3_256) "
        "VALUES (1, 1, decode(repeat('00',32),'hex'), 1, decode(repeat('11',32),'hex'), "
        "decode(repeat('22',32),'hex'), decode(repeat('33',32),'hex')) RETURNING personalization_id"),
    'duressevent': ('event_id',
        "INSERT INTO DuressEvent (token_id, context_id, requesting_agency_id) "
        "VALUES (1, 1, 1) RETURNING event_id"),
    'enrollmentevidence': ('evidence_id',
        # A chained fixture needs a CTE: INSERT ... RETURNING is not a scalar subquery.
        f"WITH p AS ({_PROOFING}) "
        "INSERT INTO EnrollmentEvidence (proofing_id, evidence_type, strength, validation_method, "
        "verification_method, validated, verified) "
        "SELECT p.proofing_id, 'PASSPORT', 'STRONG', 'VISUAL_INSPECTION', 'BIOMETRIC_COMPARISON', "
        "true, true FROM p RETURNING evidence_id"),
    'enrollmentproofing': ('proofing_id', _PROOFING),
    'enrollmentstatusevent': ('event_id', None),
    'exchangenonce': ('nonce',
        "INSERT INTO ExchangeNonce (requester_key_hash, nonce) "
        "VALUES (repeat('c', 64), 'append-only-fixture-nonce') RETURNING nonce"),
    'exchangereceiptlog': ('seq',
        "INSERT INTO ExchangeReceiptLog (receipt_hash) VALUES (repeat('d', 64)) RETURNING seq"),
    'holderkeyevent': ('event_id',
        f"INSERT INTO HolderKeyEvent (token_id, public_key_hex, event) "
        f"VALUES (1, {_HEX64}, 'bound') RETURNING event_id"),
    'individualerasureevent': ('erasure_id',
        "INSERT INTO IndividualErasureEvent (individual_id, pseudonym_assigned, erased_by_user_id, "
        "reason) VALUES (1, 'PSEUDO-APPEND-ONLY-TEST', 1, 'append-only fixture') RETURNING erasure_id"),
    'lifecyclearchivecheckpoint': ('checkpoint_id', None),
    'refereevouching': ('vouching_id',
        f"WITH p AS ({_PROOFING}) "
        "INSERT INTO RefereeVouching (proofing_id, referee_individual_id, applicant_individual_id, "
        "referee_ial, relationship, vouched_ial) "
        "SELECT p.proofing_id, 2, 1, 'IAL2', 'EMPLOYER', 'IAL2' FROM p RETURNING vouching_id"),
    'schema_version': ('event_id',
        "INSERT INTO schema_version (name, event_type, file_sha256) "
        "VALUES ('2026-09-11-999-append-only-fixture', 'applied', repeat('a', 64)) RETURNING event_id"),
    'timestamplog': ('seq',
        "INSERT INTO TimestampLog (timestamp_hash) VALUES (repeat('e', 64)) RETURNING seq"),
    'tokenlifecycleevent': ('event_id', None),
    'tokenstateepochleaf': ('leaf_id', None),
    'verificationevent': ('event_id', None),
}


class TestEveryAppendOnlyTableRefusesEdits(_CheckBase):
    """C1, once per table that claims it, rather than once for the tables
    somebody happened to write a test for."""

    def _a_row_in(self, cur, table, pk, make):
        """The key of an existing row, or of one created for the purpose.

        Deliberately NOT a skip. A table with no row and no way to make one
        cannot demonstrate append-only, and a suite that reports OK for that has
        reported a guarantee it did not test (v9.411)."""
        cur.execute(f"SELECT {pk} FROM {table} ORDER BY 1 LIMIT 1")
        row = cur.fetchone()
        if row is not None:
            return row[pk]
        self.assertIsNotNone(
            make,
            f"{table} is empty and no fixture statement is declared for it, so its "
            f"append-only trigger cannot be exercised. Add the INSERT rather than "
            f"letting the guarantee go untested.")
        cur.execute(make)
        return cur.fetchone()[pk]

    def _refuses(self, statement, verb):
        for table, (pk, make) in sorted(APPEND_ONLY_FIXTURES.items()):
            with self.subTest(table=table):
                try:
                    with self.conn.cursor() as cur:
                        key = self._a_row_in(cur, table, pk, make)
                        # The guards RAISE with insufficient_privilege, which is the
                        # right code: this is not a row failing a rule, it is an
                        # operation the table does not offer.
                        with self.assertRaises(
                                pg_errors.InsufficientPrivilege,
                                msg=f"{table} accepted a {verb}; C1 is not enforced there"
                        ) as caught:
                            cur.execute(statement(table, pk), (key,))
                        # And refused for the RIGHT reason. A privilege error from a
                        # missing GRANT would otherwise read as C1 being enforced.
                        message = str(caught.exception).lower()
                        self.assertTrue(
                            any(phrase in message for phrase in APPEND_ONLY_REFUSALS),
                            f"{table} refused the {verb}, but not as an append-only table: "
                            f"{caught.exception}")
                finally:
                    # The refusal aborts the transaction, and the fixture row must
                    # not survive into the next table's turn either way.
                    self.conn.rollback()

    def test_every_append_only_table_refuses_update(self):
        self._refuses(lambda t, pk: f"UPDATE {t} SET {pk} = {pk} WHERE {pk} = %s", "UPDATE")

    def test_every_append_only_table_refuses_delete(self):
        self._refuses(lambda t, pk: f"DELETE FROM {t} WHERE {pk} = %s", "DELETE")

    def test_the_fixture_table_covers_every_append_only_trigger_in_the_catalog(self):
        """The anti-vacuity anchor: the two tests above prove nothing about a
        table nobody listed, so the list is checked against the database."""
        with self.conn.cursor() as cur:
            cur.execute("""
            SELECT DISTINCT c.relname
              FROM pg_trigger t
              JOIN pg_class c ON c.oid = t.tgrelid
              JOIN pg_proc  p ON p.oid = t.tgfoid
             WHERE c.relnamespace = 'public'::regnamespace
               AND NOT t.tgisinternal
               AND NOT c.relispartition
               AND p.proname = ANY(%s)
            """, (list(APPEND_ONLY_GUARDS),))
            live = {r['relname'] for r in cur.fetchall()}
        listed = set(APPEND_ONLY_FIXTURES)
        self.assertEqual(
            live - listed, set(),
            "table(s) carry an append-only trigger but are not in APPEND_ONLY_FIXTURES, so "
            "nothing above tested them")
        self.assertEqual(
            listed - live, set(),
            "table(s) are listed as append-only but carry no append-only trigger in the "
            "database, so the tests above are asserting against a guarantee that is gone")
        self.assertGreaterEqual(
            len(live), 20,
            f"only {len(live)} append-only triggers were found in the catalog; the query has "
            "broken and these tests are passing by finding nothing")


# ============================================================================
# The three guards that are not append-only (v9.412)
#
# v9.411's trigger sweep left 14 triggers covered by nothing. Twelve were
# append-only and are covered by the class above. These are the other two, plus
# the enrollment code's one-way door, which is append-only in one direction only
# and so does not belong in the table-driven class.
# ============================================================================

class TestRelyingPartyDecisionsAreRecorded(_CheckBase):
    """A decision about an outside relying party is recorded, and a weakening says why.

    A relying party is an organisation with standing to ask this system about people.
    Before v9.425, registering one, turning off the zero-knowledge step-up its holders
    had to satisfy, and disabling or re-enabling it all wrote nothing anywhere: verified
    by running them against a loaded database and watching every audit table stay at the
    same row count.

    The writer is trg_relying_party_audited, not the CLI, so these tests attack the
    database directly. That is the point of the shape: a change made in psql is recorded
    on the same terms as one made through the tool.
    """

    WHY = 'a stated reason long enough to satisfy the floor'

    def setUp(self):
        super().setUp()
        self.cur = self.conn.cursor()
        self.addCleanup(self.cur.close)

    def _reason(self, why=None):
        self.cur.execute("SELECT set_config('polaris.justification', %s, true)",
                         (why if why is not None else self.WHY,))

    def _actor(self, who='probe-operator'):
        self.cur.execute("SELECT set_config('polaris.actor', %s, true)", (who,))

    def _register(self, cid='rp_recorded_probe_00001', **kw):
        cols = dict(require_zk=True, required_enrollment='ENROLLED', enabled=True,
                    rate_limit_per_min=120, scope='verify')
        cols.update(kw)
        names = ", ".join(cols)
        self.cur.execute(
            f"INSERT INTO RelyingParty (client_id, client_secret_hash, org_name, {names}) "
            f"VALUES (%s, repeat('a', 64), 'Recorded Probe', "
            + ", ".join(["%s"] * len(cols)) + ") RETURNING rp_id",
            (cid,) + tuple(cols.values()))
        return self.cur.fetchone()["rp_id"]

    def _events(self, rp_id):
        self.cur.execute("SELECT event_type, field, old_value, new_value, weakened, actor, "
                         "db_role, justification FROM RelyingPartyEvent "
                         " WHERE rp_id = %s ORDER BY event_id", (rp_id,))
        return self.cur.fetchall()

    # -- what the rule can and cannot rank (v9.448) ------------------------

    def test_gaining_a_capability_is_a_widening_even_when_the_string_is_shorter(self):
        """The miss that prompted this. Until v9.448 scope was ranked by STRING LENGTH,
        so 'authenticate' -> 'verify' gave the party the verify capability it did not
        hold, the length went DOWN, and the record said it granted nothing."""
        self._reason(); self._actor()
        rp = self._register(cid='rp_scope_gain_probe_0001', scope='authenticate')
        self._reason("the party is taking over the verification desk this quarter")
        self.cur.execute("UPDATE RelyingParty SET scope = 'verify' WHERE rp_id = %s", (rp,))
        e = [x for x in self._events(rp) if x["field"] == "scope"][-1]
        self.assertTrue(e["weakened"],
                        "gaining a capability the party did not hold is a widening, and the "
                        "old string-length rule called it harmless")

    def test_losing_a_capability_grants_nothing(self):
        self._reason(); self._actor()
        rp = self._register(cid='rp_scope_drop_probe_0001', scope='verify authenticate')
        self._reason("")
        self.cur.execute("UPDATE RelyingParty SET scope = 'verify' WHERE rp_id = %s", (rp,))
        e = [x for x in self._events(rp) if x["field"] == "scope"][-1]
        self.assertFalse(e["weakened"], "dropping a capability grants nothing")

    def test_a_swap_the_database_cannot_rank_is_recorded_as_such(self):
        """NULL, not FALSE. /api/v1/auth/authorize compares `enrollment != required`
        EXACTLY, so each value names one mutually exclusive population and no ordering
        puts one above another; contexts are likewise unordered."""
        self._reason(); self._actor()
        rp = self._register(cid='rp_swap_probe_00000001',
                            required_enrollment='ENROLLED', required_context_id=1)
        self._reason("moved to the exempt population for the pilot cohort")
        self.cur.execute("UPDATE RelyingParty SET required_enrollment = 'EXEMPT', "
                         " required_context_id = 2 WHERE rp_id = %s", (rp,))
        by_field = {x["field"]: x for x in self._events(rp) if x["field"]}
        for field in ("required_enrollment", "required_context_id"):
            with self.subTest(field=field):
                self.assertIsNone(by_field[field]["weakened"],
                                  "a swap between two values neither of which is above the "
                                  "other claims a direction the database cannot rank")

    def test_a_swap_still_needs_a_stated_reason(self):
        """The gate asks IS NOT FALSE. `NULL AND TRUE` is NULL, so a bare truth test would
        let every unrankable change through unexplained."""
        self._reason(); self._actor()
        rp = self._register(cid='rp_swap_reason_probe01', required_enrollment='ENROLLED')
        self.cur.execute("SAVEPOINT made")
        self._reason("")
        with self.assertRaises(pg_errors.InsufficientPrivilege):
            self.cur.execute("UPDATE RelyingParty SET required_enrollment = 'EXEMPT' "
                             " WHERE rp_id = %s", (rp,))
        self.cur.execute("ROLLBACK TO SAVEPOINT made")

    def test_removing_a_filter_entirely_is_a_weakening(self):
        """The one direction the original rule did get right, kept under test."""
        self._reason(); self._actor()
        rp = self._register(cid='rp_filter_drop_probe01', required_enrollment='ENROLLED')
        self._reason("the party now serves every holder regardless of enrollment")
        self.cur.execute("UPDATE RelyingParty SET required_enrollment = NULL WHERE rp_id = %s",
                         (rp,))
        e = [x for x in self._events(rp) if x["field"] == "required_enrollment"][-1]
        self.assertTrue(e["weakened"], "dropping the filter lets every holder through")

    def test_the_assessors_filter_returns_every_change_that_may_have_granted_reach(self):
        self._reason(); self._actor()
        rp = self._register(cid='rp_filter_view_probe01', required_enrollment='ENROLLED')
        self._reason("moved to the exempt population for the pilot cohort")
        self.cur.execute("UPDATE RelyingParty SET required_enrollment = 'EXEMPT' WHERE rp_id = %s",
                         (rp,))
        self._reason("")
        self.cur.execute("UPDATE RelyingParty SET org_name = 'Renamed Probe' WHERE rp_id = %s",
                         (rp,))
        self.cur.execute("SELECT field FROM RelyingPartyEvent WHERE rp_id = %s "
                         "   AND weakened IS NOT FALSE AND field IS NOT NULL "
                         " ORDER BY event_id", (rp,))
        got = [r["field"] for r in self.cur.fetchall()]
        self.assertEqual(got, ["required_enrollment"],
                         "the assessor's filter is not the set of changes that may have "
                         "granted reach")

    # -- registration ------------------------------------------------------

    def test_registering_a_party_is_recorded(self):
        self._reason(); self._actor()
        rp_id = self._register()
        events = self._events(rp_id)
        self.assertEqual(len(events), 1, "registration wrote no event")
        e = events[0]
        self.assertEqual(e["event_type"], "REGISTERED")
        self.assertTrue(e["weakened"], "granting standing where there was none is a weakening")
        self.assertEqual(e["actor"], "probe-operator")
        self.assertIn(self.WHY, e["justification"])
        self.assertIn("require_zk=t", e["new_value"],
                      "the event must record the policy the party was granted")

    def test_registering_a_party_with_no_reason_is_refused(self):
        """The rule is in the database, so there is no door past it."""
        with self.assertRaises(pg_errors.InsufficientPrivilege):
            self._register(cid='rp_no_reason_probe_0001')

    def test_a_reason_too_short_to_be_one_is_refused(self):
        self._reason('too short')
        with self.assertRaises(pg_errors.InsufficientPrivilege):
            self._register(cid='rp_short_reason_probe01')

    # -- weakening ---------------------------------------------------------

    def test_turning_off_the_step_up_is_recorded_as_a_weakening(self):
        """require_zk TRUE -> FALSE drops the holder from ACR zk to ACR possession."""
        self._reason(); self._actor()
        rp_id = self._register()
        self._reason('the integration window slipped so the step-up comes later')
        self.cur.execute("UPDATE RelyingParty SET require_zk = FALSE WHERE rp_id = %s", (rp_id,))
        e = self._events(rp_id)[-1]
        self.assertEqual((e["event_type"], e["field"]), ("POLICY_CHANGED", "require_zk"))
        self.assertEqual((e["old_value"], e["new_value"]), ("true", "false"))
        self.assertTrue(e["weakened"])
        self.assertIn('integration window', e["justification"])

    def test_every_weakening_is_refused_without_a_reason(self):
        """One subtest per field the predicate calls a weakening, so a field added to
        _rp_weakens without a matching refusal shows up here rather than in a review."""
        self._reason(); self._actor()
        rp_id = self._register(required_context_id=1)
        self.cur.execute("SAVEPOINT registered")
        for sql in ("require_zk = FALSE",
                    "required_enrollment = NULL",
                    "required_context_id = NULL",
                    "scope = 'verify authenticate'",
                    "rate_limit_per_min = 5000"):
            with self.subTest(change=sql):
                self._reason('')
                with self.assertRaises(pg_errors.InsufficientPrivilege,
                                       msg=f"{sql} was accepted with no stated reason"):
                    self.cur.execute(f"UPDATE RelyingParty SET {sql} WHERE rp_id = %s", (rp_id,))
                self.cur.execute("ROLLBACK TO SAVEPOINT registered")

    def test_re_enabling_a_disabled_party_needs_a_reason(self):
        """Disabling is a restriction and needs none; re-enabling grants standing back."""
        self._reason(); self._actor()
        rp_id = self._register()
        self._reason('')
        self.cur.execute("UPDATE RelyingParty SET enabled = FALSE WHERE rp_id = %s", (rp_id,))
        self.assertEqual(self._events(rp_id)[-1]["event_type"], "DISABLED")
        self.assertFalse(self._events(rp_id)[-1]["weakened"])
        with self.assertRaises(pg_errors.InsufficientPrivilege):
            self.cur.execute("UPDATE RelyingParty SET enabled = TRUE WHERE rp_id = %s", (rp_id,))

    def test_strengthening_needs_no_reason(self):
        """The rule bounds one direction. Demanding a reason to tighten a policy would
        make the safe change the expensive one."""
        self._reason(); self._actor()
        rp_id = self._register(require_zk=False, required_enrollment=None)
        self._reason('')
        self.cur.execute("UPDATE RelyingParty SET require_zk = TRUE, "
                         "required_enrollment = 'ENROLLED' WHERE rp_id = %s", (rp_id,))
        weakened = [e["weakened"] for e in self._events(rp_id)[1:]]
        self.assertTrue(weakened and not any(weakened),
                        "a tightening was recorded as a weakening")

    def test_one_statement_marks_only_the_field_that_weakened(self):
        """A mixed change must not tar its tightening half."""
        self._reason(); self._actor()
        rp_id = self._register()
        self._reason('the step-up comes later; the rate comes down to compensate')
        self.cur.execute("UPDATE RelyingParty SET require_zk = FALSE, rate_limit_per_min = 10 "
                         " WHERE rp_id = %s", (rp_id,))
        by_field = {e["field"]: e["weakened"] for e in self._events(rp_id) if e["field"]}
        self.assertEqual(by_field.get("require_zk"), True)
        self.assertEqual(by_field.get("rate_limit_per_min"), False)

    # -- the record itself -------------------------------------------------

    def test_a_change_made_outside_the_cli_is_recorded_the_same(self):
        """The trigger is the writer, so there is no unrecorded path. This whole class
        is that test; this one names it."""
        self._reason(); self._actor(who='')
        rp_id = self._register()
        e = self._events(rp_id)[0]
        self.assertIsNone(e["actor"], "an undeclared actor must be absent, not invented")
        self.assertTrue(e["db_role"], "db_role must always name the role that acted")

    def test_the_record_cannot_be_edited_or_deleted(self):
        self._reason(); self._actor()
        rp_id = self._register()
        self.cur.execute("SAVEPOINT recorded")
        for sql in ("UPDATE RelyingPartyEvent SET weakened = FALSE WHERE rp_id = %s",
                    "UPDATE RelyingPartyEvent SET justification = 'rewritten' WHERE rp_id = %s",
                    "DELETE FROM RelyingPartyEvent WHERE rp_id = %s"):
            with self.subTest(sql=sql.split()[0] + ' ' + sql.split()[3]):
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    self.cur.execute(sql, (rp_id,))
                self.cur.execute("ROLLBACK TO SAVEPOINT recorded")

    def test_the_record_outlives_the_party(self):
        """A contract ends and the party row goes; what was decided about it stays.
        A restrictive foreign key would forbid the delete and a cascading one would
        erase the record, so RelyingPartyEvent deliberately has neither."""
        self._reason(); self._actor()
        rp_id = self._register()
        self.cur.execute("DELETE FROM RelyingParty WHERE rp_id = %s", (rp_id,))
        self.assertEqual(len(self._events(rp_id)), 1,
                         "the record went with the party it was about")

    def test_the_client_id_cannot_be_repointed(self):
        """Editing client_id would silently re-attribute every event row above it."""
        self._reason(); self._actor()
        rp_id = self._register()
        with self.assertRaises(pg_errors.InsufficientPrivilege):
            self.cur.execute("UPDATE RelyingParty SET client_id = 'rp_repointed_probe_001' "
                             " WHERE rp_id = %s", (rp_id,))

    def test_last_used_at_is_not_recorded(self):
        """The app writes it on every API call. Recording it would bury the five rows a
        year that are decisions under a million that are traffic."""
        self._reason(); self._actor()
        rp_id = self._register()
        before = len(self._events(rp_id))
        self.cur.execute("UPDATE RelyingParty SET last_used_at = now() WHERE rp_id = %s", (rp_id,))
        self.assertEqual(len(self._events(rp_id)), before)

    def test_a_secret_rotation_is_recorded_without_the_secret(self):
        self._reason(); self._actor()
        rp_id = self._register()
        self.cur.execute("UPDATE RelyingParty SET client_secret_hash = repeat('b', 64) "
                         " WHERE rp_id = %s", (rp_id,))
        e = self._events(rp_id)[-1]
        self.assertEqual(e["event_type"], "SECRET_ROTATED")
        self.assertFalse(e["weakened"])
        self.assertEqual((e["old_value"], e["new_value"]), ("(redacted)", "(redacted)"))
        self.assertNotIn('a' * 64, str(e), "the old hash reached the record")

    def test_the_predicate_classifies_every_policy_column(self):
        """_rp_weakens returns NULL for a field it does not know, and a NULL would make
        the justification gate pass silently. Every column that is not plainly
        bookkeeping must therefore get a TRUE or FALSE answer from it."""
        self.cur.execute("""
            SELECT column_name FROM information_schema.columns
             WHERE table_name = 'relyingparty'
               AND column_name NOT IN ('rp_id', 'client_id', 'created_at', 'last_used_at')
        """)
        columns = [r["column_name"] for r in self.cur.fetchall()]
        self.assertGreaterEqual(len(columns), 7, "the column query found almost nothing")
        # v9.448: register the row this needs rather than skipping when the sample data
        # has none. It did skip -- eight subtests, silently, on a freshly loaded database
        # -- which is the shape check_property_no_skip refuses for the C1-C3 properties:
        # a fixture that cannot supply the row must fail loudly, not report green having
        # asked nothing.
        self._reason(); self._actor()
        self._register(cid='rp_classify_probe_00001')
        for column in columns:
            with self.subTest(column=column):
                self.cur.execute(
                    "SELECT _rp_weakens(%s, r, r) IS NOT NULL AS classified "
                    "  FROM RelyingParty r LIMIT 1", (column,))
                row = self.cur.fetchone()
                self.assertIsNotNone(row, "no relying party to ask about even after "
                                          "registering one; the fixture is broken")
                self.assertTrue(row["classified"],
                                f"_rp_weakens has no rule for {column}, so a change to it "
                                f"returns NULL and the justification gate lets it through")


class TestDiscretionPolicyIsAppendOnly(_CheckBase):
    """A revocation bound is a decision that is kept, not edited (v9.426).

    IssuerDiscretionPolicy bounds the share of its own tokens one issuing agency may
    revoke in a rolling window: it is what stands between one authority and mass
    revocation of the credentials it issued. agency_id was the primary key, so raising
    an agency's bound from 5% to 80% overwrote the baseline, who set it, when, and the
    reason given, while docs/operator/SECURITY-CONTROLS.md said the justification
    existed "so any loosening is auditable". Verified against a loaded database before
    the change: one row, 80%, a new name and a new reason, and no audit row anywhere.
    """

    def setUp(self):
        super().setUp()
        self.cur = self.conn.cursor()
        self.addCleanup(self.cur.close)

    AGENCY = 2      # a sample agency with no shipped override of its own

    def _record(self, percent=5.00, why='a bound recorded so the test can try to rewrite it'):
        self.cur.execute("UPDATE IssuerDiscretionPolicy SET superseded_at = now() "
                         " WHERE agency_id = %s AND superseded_at IS NULL", (self.AGENCY,))
        self.cur.execute(
            "INSERT INTO IssuerDiscretionPolicy (agency_id, max_revoke_percent, window_days, "
            "set_by_admin, justification) VALUES (%s, %s, 30, 'test', %s) RETURNING policy_id",
            (self.AGENCY, percent, why))
        return self.cur.fetchone()["policy_id"]

    def test_loosening_a_bound_keeps_the_one_it_replaced(self):
        """The claim SECURITY-CONTROLS.md makes, as a test."""
        self._record(5.00, 'the contracted baseline for this agency, stated')
        self._record(80.00, 'a mass reissue is planned and needs the headroom')
        self.cur.execute("SELECT max_revoke_percent, justification, superseded_at "
                         "FROM IssuerDiscretionPolicy WHERE agency_id = %s ORDER BY policy_id",
                         (self.AGENCY,))
        rows = self.cur.fetchall()
        self.assertGreaterEqual(len(rows), 2, "the bound it replaced was overwritten")
        live = [r for r in rows if r["superseded_at"] is None]
        self.assertEqual(len(live), 1, "exactly one bound may be in force per agency")
        self.assertEqual(float(live[0]["max_revoke_percent"]), 80.00)
        self.assertIn('the contracted baseline for this agency, stated',
                      [r["justification"] for r in rows],
                      "the reason given for the bound that was raised is gone")

    def _revocable_token(self, label):
        """A fresh Individual with one ACTIVE token issued by self.AGENCY.

        uq_one_active_per_person means each call needs its own person. RESERVE then
        ACTIVE, because the state-machine trigger allows no other way in.
        """
        self.cur.execute("INSERT INTO Individual (legal_name, date_of_birth, jurisdiction) "
                         "VALUES (%s, '1990-01-01', 'US-PA') RETURNING individual_id",
                         ('Discretion Bound Test ' + label,))
        iid = self.cur.fetchone()["individual_id"]
        self.cur.execute("SELECT algorithm_id FROM AgencyAlgorithmAuth "
                         " WHERE agency_id = %s LIMIT 1", (self.AGENCY,))
        row = self.cur.fetchone()
        if row is None:
            self.skipTest("agency %d is authorized for no algorithm, so it cannot issue"
                          % self.AGENCY)
        self.cur.execute(
            "INSERT INTO IdentityToken (token_value, physical_serial, hardware_model, "
            "biometric_binding_type, individual_id, issuing_agency_id, algorithm_id, status, "
            "issued_date, expiration_date) VALUES (%s, %s, 'TitanQ-3', 'IRIS', %s, %s, %s, "
            "'RESERVE', CURRENT_TIMESTAMP, (CURRENT_DATE + INTERVAL '10 years')::date) "
            "RETURNING token_id",
            ('TKN-DISC-' + label, 'SN-DISC-' + label, iid, self.AGENCY, row["algorithm_id"]))
        tid = self.cur.fetchone()["token_id"]
        self.cur.execute("SELECT set_config('polaris.actor_agency_id', %s, true)",
                         (str(self.AGENCY),))
        self.cur.execute("SELECT set_config('polaris.reason_code', 'INITIAL_ISSUE', true)")
        # The state machine requires activated_date on the way in.
        self.cur.execute("UPDATE IdentityToken SET status = 'ACTIVE', "
                         " activated_date = CURRENT_TIMESTAMP WHERE token_id = %s", (tid,))
        return tid

    def _revocation_allowed(self, label):
        """Does uc8_revoke_token let this agency revoke one more of its own tokens?"""
        tid = self._revocable_token(label)
        self.cur.execute("SAVEPOINT attempt")
        try:
            self.cur.execute(
                "CALL uc8_revoke_token(p_token_id => %s, p_actor_agency_id => %s, "
                "p_reason_code => 'ADMINISTRATIVE', "
                "p_published_location => 'https://crl.example/disc', "
                "p_cosigner_agency_id => NULL)", (tid, self.AGENCY))
        except pg_errors.Error:
            self.cur.execute("ROLLBACK TO SAVEPOINT attempt")
            return False
        return True

    def test_a_superseded_bound_does_not_bind(self):
        """uc8_revoke_token reads the bound IN FORCE, asked of the procedure itself.

        Two cases, deliberately, because one is not enough. Without the
        `superseded_at IS NULL` filter the procedure's `SELECT ... INTO` matches every
        bound the agency has ever had and takes one of them, so a single case can pass
        by luck: the row it happens to reach may be the right one. Whichever row an
        unfiltered lookup favours, it favours the same relative row in both cases below,
        so at least one of them must come out wrong. The first draft of this test
        queried the table with its own `superseded_at IS NULL` filter and asserted on
        the answer, which proved the filter worked in the test and nothing about the
        procedure: dropping the filter from 05_procedures.sql left it green.
        """
        with self.subTest(case='live bound is tight, superseded one is loose'):
            self.cur.execute("SAVEPOINT tight")
            self._record(100.00, 'the loose bound this test will supersede, stated fully')
            self._record(0.01, 'the tight bound in force, which must be the one that binds')
            self.assertFalse(self._revocation_allowed('TIGHT'),
                             "a revocation was allowed under a 0.01% bound in force, so the "
                             "procedure read the superseded 100% one")
            self.cur.execute("ROLLBACK TO SAVEPOINT tight")
        with self.subTest(case='live bound is loose, superseded one is tight'):
            self.cur.execute("SAVEPOINT loose")
            self._record(0.01, 'the tight bound this test will supersede, stated fully')
            self._record(100.00, 'the loose bound in force, which must be the one that binds')
            self.assertTrue(self._revocation_allowed('LOOSE'),
                            "a revocation was refused under a 100% bound in force, so the "
                            "procedure read the superseded 0.01% one")
            self.cur.execute("ROLLBACK TO SAVEPOINT loose")

    def test_two_bounds_cannot_be_in_force_for_one_agency(self):
        """uq_effective_discretion_policy, not application care, decides this."""
        self._record()
        with self.assertRaises(pg_errors.UniqueViolation):
            self.cur.execute(
                "INSERT INTO IssuerDiscretionPolicy (agency_id, max_revoke_percent, "
                "window_days, set_by_admin, justification) VALUES (%s, 50, 30, 'test', "
                "'a second bound in force for one agency, refused')", (self.AGENCY,))

    def test_a_recorded_bound_cannot_be_edited(self):
        for column, value in (('max_revoke_percent', 99), ('window_days', 365),
                              ('set_by_admin', 'someone_else'), ('agency_id', 4),
                              ('justification', 'a different reason, twenty plus characters'),
                              ('set_at', 'epoch')):
            with self.subTest(column=column):
                pid = self._record()
                self.cur.execute("SAVEPOINT recorded")
                with self.assertRaises(pg_errors.InsufficientPrivilege,
                                       msg=f"{column} was editable"):
                    self.cur.execute(
                        f"UPDATE IssuerDiscretionPolicy SET {column} = %s WHERE policy_id = %s",
                        (value, pid))
                self.cur.execute("ROLLBACK TO SAVEPOINT recorded")

    def test_a_recorded_bound_cannot_be_deleted(self):
        pid = self._record(why='a bound recorded so the test can try to delete it')
        with self.assertRaises(pg_errors.InsufficientPrivilege):
            self.cur.execute("DELETE FROM IssuerDiscretionPolicy WHERE policy_id = %s", (pid,))

    def test_superseding_is_one_way(self):
        """Un-superseding would put a replaced bound back in force with no trace that it
        had ever been replaced, which is the edit the history exists to stop."""
        pid = self._record()
        self.cur.execute("UPDATE IssuerDiscretionPolicy SET superseded_at = now() "
                         " WHERE policy_id = %s", (pid,))
        for attempt in ("superseded_at = NULL", "superseded_at = now() - interval '9 days'"):
            with self.subTest(attempt=attempt):
                self.cur.execute("SAVEPOINT one_way")
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    self.cur.execute(f"UPDATE IssuerDiscretionPolicy SET {attempt} "
                                     f" WHERE policy_id = %s", (pid,))
                self.cur.execute("ROLLBACK TO SAVEPOINT one_way")

    def test_the_justification_floor_still_binds_every_row(self):
        """The floor is what makes the kept history worth reading."""
        with self.assertRaises(pg_errors.CheckViolation):
            self.cur.execute(
                "INSERT INTO IssuerDiscretionPolicy (agency_id, max_revoke_percent, "
                "window_days, set_by_admin, justification) VALUES (%s, 9, 30, 'test', 'short')",
                (self.AGENCY,))


class TestAuthorityChangesAreRecorded(_CheckBase):
    """An authority cannot be created, widened or erased without a record (v9.440).

    An Agency issues credentials, holds signing keys, receives quotas and revocation
    bounds, and vouches for other authorities; thirty-five foreign keys point at it.
    Creating one wrote nothing: verified against a loaded database with every audit
    table unchanged and zero triggers on the table. It could also be renamed, have its
    authorization_level raised from 3 to 5, and be deleted, all silently.

    The writer is trg_agency_audited, not the console, so these attack the database
    directly: a change made in psql is recorded on the same terms.
    """

    WHY = 'a stated reason long enough to satisfy the floor'

    def setUp(self):
        super().setUp()
        self.cur = self.conn.cursor()
        self.addCleanup(self.cur.close)

    def _reason(self, why=None):
        self.cur.execute("SELECT set_config('polaris.justification', %s, true)",
                         (self.WHY if why is None else why,))

    def _actor(self, who='probe-operator'):
        self.cur.execute("SELECT set_config('polaris.actor', %s, true)", (who,))

    def _create(self, name='Recorded Authority Probe', level=2):
        self.cur.execute(
            "INSERT INTO Agency (name, agency_type, jurisdiction, authorization_level) "
            "VALUES (%s, 'COUNTY', 'US-ZZ', %s) RETURNING agency_id", (name, level))
        return self.cur.fetchone()["agency_id"]

    def _events(self, agency_id):
        self.cur.execute("SELECT event_type, field, old_value, new_value, widened, actor, "
                         "db_role, justification FROM AgencyEvent WHERE agency_id = %s "
                         " ORDER BY event_id", (agency_id,))
        return self.cur.fetchall()

    def test_creating_an_authority_is_recorded(self):
        self._reason(); self._actor()
        aid = self._create()
        events = self._events(aid)
        self.assertEqual(len(events), 1, "creating an authority wrote no event")
        e = events[0]
        self.assertEqual(e["event_type"], "CREATED")
        self.assertTrue(e["widened"], "an authority where there was none is a widening")
        self.assertEqual(e["actor"], "probe-operator")
        self.assertIn(self.WHY, e["justification"])
        self.assertIn("authorization_level=2", e["new_value"])

    def test_creating_an_authority_without_a_reason_is_refused(self):
        with self.assertRaises(pg_errors.InsufficientPrivilege):
            self._create(name='Unexplained Authority Probe')

    def test_raising_the_level_needs_a_reason_and_is_marked(self):
        """Level 5 is a federal issuer. Going up is the change that grants something."""
        self._reason(); self._actor()
        aid = self._create(level=2)
        self.cur.execute("SAVEPOINT created")
        self._reason('')
        with self.assertRaises(pg_errors.InsufficientPrivilege):
            self.cur.execute("UPDATE Agency SET authorization_level = 5 WHERE agency_id = %s",
                             (aid,))
        self.cur.execute("ROLLBACK TO SAVEPOINT created")
        self._reason('the authority is taking on federal issuance for the pilot')
        self.cur.execute("UPDATE Agency SET authorization_level = 5 WHERE agency_id = %s",
                         (aid,))
        e = self._events(aid)[-1]
        self.assertEqual((e["event_type"], e["old_value"], e["new_value"]),
                         ("LEVEL_CHANGED", "2", "5"))
        self.assertTrue(e["widened"])

    def test_lowering_the_level_is_recorded_but_needs_no_reason(self):
        """The rule bounds one direction: making an authority weaker is not a grant."""
        self._reason(); self._actor()
        aid = self._create(level=4)
        self._reason('')
        self.cur.execute("UPDATE Agency SET authorization_level = 1 WHERE agency_id = %s",
                         (aid,))
        e = self._events(aid)[-1]
        self.assertEqual(e["event_type"], "LEVEL_CHANGED")
        self.assertFalse(e["widened"], "a reduction was recorded as a widening")

    def test_a_rename_is_recorded_and_needs_no_reason(self):
        self._reason(); self._actor()
        aid = self._create()
        self._reason('')
        self.cur.execute("UPDATE Agency SET name = 'Renamed Authority Probe' "
                         " WHERE agency_id = %s", (aid,))
        e = self._events(aid)[-1]
        self.assertEqual((e["event_type"], e["field"]), ("RENAMED", "name"))
        self.assertFalse(e["widened"])

    def test_an_authority_cannot_be_deleted(self):
        """An authority that existed is part of the record even if it issued nothing."""
        self._reason(); self._actor()
        aid = self._create()
        with self.assertRaises(pg_errors.InsufficientPrivilege) as c:
            self.cur.execute("DELETE FROM Agency WHERE agency_id = %s", (aid,))
        self.assertIn("append-only", str(c.exception))

    def test_the_agency_id_cannot_be_repointed(self):
        """Thirty-five tables reference it; changing it would re-point all of them."""
        self._reason(); self._actor()
        aid = self._create()
        with self.assertRaises(pg_errors.InsufficientPrivilege):
            self.cur.execute("UPDATE Agency SET agency_id = agency_id + 5000 "
                             " WHERE agency_id = %s", (aid,))

    def test_the_record_cannot_be_edited_or_deleted(self):
        self._reason(); self._actor()
        aid = self._create()
        self.cur.execute("SAVEPOINT recorded")
        for sql in ("UPDATE AgencyEvent SET widened = FALSE WHERE agency_id = %s",
                    "UPDATE AgencyEvent SET justification = 'rewritten' WHERE agency_id = %s",
                    "DELETE FROM AgencyEvent WHERE agency_id = %s"):
            with self.subTest(sql=sql.split()[0]):
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    self.cur.execute(sql, (aid,))
                self.cur.execute("ROLLBACK TO SAVEPOINT recorded")

    def test_a_rescope_needs_a_reason(self):
        """The hole the first cut of this left open.

        `authorization_level` has an ordering, so the database can say a rise in it is a
        widening. `jurisdiction` is free text: 'US' is not greater than 'US-ZZ' by any
        comparison SQL has. So a county office could be made a national issuer in one
        UPDATE, with no reason given, and the record would carry `widened = FALSE`.
        """
        self._reason(); self._actor()
        aid = self._create()
        self.cur.execute("SAVEPOINT scoped")
        for column, value in (("jurisdiction", "US"), ("agency_type", "FEDERAL")):
            with self.subTest(column=column):
                self._reason("")            # the reason does not carry across
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    self.cur.execute("UPDATE Agency SET %s = %%s WHERE agency_id = %%s"
                                     % column, (value, aid))
                self.cur.execute("ROLLBACK TO SAVEPOINT scoped")

    def test_a_rescope_is_recorded_as_a_direction_the_database_cannot_decide(self):
        """NULL, not FALSE. FALSE would be a claim that nothing was granted, which is
        exactly what a county-to-nation move disproves, and it would drop the row out of
        the assessor's `--widened-only` list."""
        self._reason(); self._actor()
        aid = self._create()
        self._reason("promoted to a national issuer under the pilot charter")
        self.cur.execute("UPDATE Agency SET jurisdiction = 'US', agency_type = 'FEDERAL' "
                         " WHERE agency_id = %s", (aid,))
        by_type = {e["event_type"]: e for e in self._events(aid)}
        for event_type in ("JURISDICTION_CHANGED", "TYPE_CHANGED"):
            with self.subTest(event_type=event_type):
                self.assertIn(event_type, by_type, "a rescope wrote no event")
                self.assertIsNone(by_type[event_type]["widened"],
                                  "a rescope claims a direction the database cannot rank")

    def test_the_assessors_filter_returns_every_change_that_may_have_granted_reach(self):
        """`widened IS NOT FALSE` is the filter, and this is why: a rename must not appear
        in it, and a rescope must."""
        self._reason(); self._actor()
        aid = self._create()
        self._reason("promoted to a national issuer under the pilot charter")
        self.cur.execute("UPDATE Agency SET jurisdiction = 'US' WHERE agency_id = %s", (aid,))
        self.cur.execute("UPDATE Agency SET name = 'Renamed Authority Probe' "
                         " WHERE agency_id = %s", (aid,))
        self.cur.execute("SELECT event_type FROM AgencyEvent WHERE agency_id = %s "
                         "   AND widened IS NOT FALSE ORDER BY event_id", (aid,))
        got = [r["event_type"] for r in self.cur.fetchall()]
        self.assertEqual(got, ["CREATED", "JURISDICTION_CHANGED"],
                         "the assessor's filter is not the set of changes that may have "
                         "granted reach")

    def test_every_seeded_authority_carries_a_creation_event(self):
        """The load order installs the trigger after the sample data, so those rows are
        backfilled. A database showing authorities and no record of them reads as a
        broken recorder."""
        self.cur.execute("SELECT count(*) AS n FROM Agency a WHERE NOT EXISTS ("
                         " SELECT 1 FROM AgencyEvent e WHERE e.agency_id = a.agency_id "
                         "   AND e.event_type = 'CREATED')")
        self.assertEqual(self.cur.fetchone()["n"], 0,
                         "an authority exists with no record of having been created")


class TestAppUserChangesAreRecorded(_CheckBase):
    """An operator account cannot be created, promoted or relaxed without a record (v9.443).

    AppUser decides who may sign in, what role they hold, which authority they belong to,
    and the date by which they must carry a hardware key. It had no trigger: verified
    against a loaded database with pg_trigger returning zero non-internal rows. AuthAuditLog
    made it look recorded, but every row there is written by the APPLICATION and only when
    the application chooses to, so an UPDATE in psql wrote nothing at all.

    The writer is trg_app_user_audited, not the console, so these attack the database
    directly.
    """

    WHY = 'a stated reason long enough to satisfy the floor'

    def setUp(self):
        super().setUp()
        self.cur = self.conn.cursor()
        self.addCleanup(self.cur.close)

    def _reason(self, why=None):
        self.cur.execute("SELECT set_config('polaris.justification', %s, true)",
                         (self.WHY if why is None else why,))

    def _actor(self, who='probe-operator'):
        self.cur.execute("SELECT set_config('polaris.actor', %s, true)", (who,))

    def _create(self, username='probe.recorded', role='auditor', **kw):
        cols = ['username', 'password_hash', 'role'] + list(kw)
        vals = [username, 'scrypt$notahash', role] + list(kw.values())
        self.cur.execute(
            "INSERT INTO AppUser (%s) VALUES (%s) RETURNING user_id"
            % (', '.join(cols), ', '.join(['%s'] * len(vals))), tuple(vals))
        return self.cur.fetchone()["user_id"]

    def _events(self, user_id):
        self.cur.execute("SELECT event_type, field, old_value, new_value, widened, actor, "
                         "db_role, justification FROM AppUserEvent WHERE user_id = %s "
                         " ORDER BY event_id", (user_id,))
        return self.cur.fetchall()

    def test_creating_an_account_is_recorded(self):
        self._reason(); self._actor()
        uid = self._create()
        events = self._events(uid)
        self.assertEqual(len(events), 1, "creating an account wrote no event")
        e = events[0]
        self.assertEqual(e["event_type"], "CREATED")
        self.assertTrue(e["widened"], "an account where there was none is a grant of access")
        self.assertEqual(e["actor"], "probe-operator")
        self.assertIn(self.WHY, e["justification"])
        self.assertIsNotNone(e["db_role"], "no event may be anonymous")

    def test_creating_an_account_without_a_reason_is_refused(self):
        with self.assertRaises(pg_errors.InsufficientPrivilege):
            self._create(username='probe.unexplained')

    def test_promotion_needs_a_reason_and_is_marked(self):
        """auditor reads, operator acts, admin decides who may do either."""
        self._reason(); self._actor()
        uid = self._create(role='auditor')
        self.cur.execute("SAVEPOINT created")
        self._reason("")
        with self.assertRaises(pg_errors.InsufficientPrivilege):
            self.cur.execute("UPDATE AppUser SET role = 'admin' WHERE user_id = %s", (uid,))
        self.cur.execute("ROLLBACK TO SAVEPOINT created")
        self._reason("promoted to admin for the quarterly access review")
        self.cur.execute("UPDATE AppUser SET role = 'admin' WHERE user_id = %s", (uid,))
        e = [x for x in self._events(uid) if x["event_type"] == "ROLE_CHANGED"][0]
        self.assertTrue(e["widened"], "a rise in role is a widening")
        self.assertEqual((e["old_value"], e["new_value"]), ("auditor", "admin"))

    def test_demotion_is_recorded_but_needs_no_reason(self):
        """The rule bounds one direction: making an account weaker grants nothing."""
        self._reason(); self._actor()
        uid = self._create(role='admin')
        self._reason("")
        self.cur.execute("UPDATE AppUser SET role = 'auditor' WHERE user_id = %s", (uid,))
        e = [x for x in self._events(uid) if x["event_type"] == "ROLE_CHANGED"][0]
        self.assertFalse(e["widened"], "a fall in role grants nothing")

    def test_reactivation_needs_a_reason_and_deactivation_does_not(self):
        self._reason(); self._actor()
        uid = self._create(is_active=True)
        self._reason("")
        self.cur.execute("UPDATE AppUser SET is_active = FALSE WHERE user_id = %s", (uid,))
        self.assertEqual([x["event_type"] for x in self._events(uid)][-1], "DEACTIVATED")
        self.cur.execute("SAVEPOINT off")
        with self.assertRaises(pg_errors.InsufficientPrivilege):
            self.cur.execute("UPDATE AppUser SET is_active = TRUE WHERE user_id = %s", (uid,))
        self.cur.execute("ROLLBACK TO SAVEPOINT off")

    def test_a_deadline_pushed_further_away_is_a_widening(self):
        """The direction that matters: longer without a hardware key, not shorter."""
        self._reason(); self._actor()
        uid = self._create()
        self._reason("")
        self.cur.execute("UPDATE AppUser SET webauthn_required_after = NOW() + INTERVAL '7 days' "
                         " WHERE user_id = %s", (uid,))
        e = [x for x in self._events(uid) if x["event_type"] == "WEBAUTHN_DEADLINE_CHANGED"][-1]
        self.assertFalse(e["widened"], "imposing a requirement grants nothing")
        self.cur.execute("SAVEPOINT tight")
        for sql in ("UPDATE AppUser SET webauthn_required_after = NOW() + INTERVAL '400 days' "
                    " WHERE user_id = %s",
                    "UPDATE AppUser SET webauthn_required_after = NULL WHERE user_id = %s"):
            with self.subTest(sql=sql.split('=')[1][:18]):
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    self.cur.execute(sql, (uid,))
                self.cur.execute("ROLLBACK TO SAVEPOINT tight")

    def test_moving_between_authorities_is_recorded_as_undecidable(self):
        """NULL, not FALSE. P3.9 makes the agency boundary what an operator can see, and
        no ordering puts one authority above another."""
        self._reason(); self._actor()
        uid = self._create(agency_id=1)
        self.cur.execute("SAVEPOINT made")
        self._reason("")
        with self.assertRaises(pg_errors.InsufficientPrivilege):
            self.cur.execute("UPDATE AppUser SET agency_id = 2 WHERE user_id = %s", (uid,))
        self.cur.execute("ROLLBACK TO SAVEPOINT made")
        self._reason("seconded to the state bureau for the enrollment pilot")
        self.cur.execute("UPDATE AppUser SET agency_id = 2 WHERE user_id = %s", (uid,))
        e = [x for x in self._events(uid) if x["event_type"] == "AGENCY_CHANGED"][0]
        self.assertIsNone(e["widened"], "a move between authorities claims a direction "
                                        "the database cannot rank")

    def test_the_record_holds_no_secret(self):
        """A password change is the FACT, never the value. Held by a CHECK, so a caller
        writing a row directly cannot put a hash here either."""
        self._reason(); self._actor()
        uid = self._create()
        self._reason("")
        self.cur.execute("UPDATE AppUser SET password_hash = 'scrypt$rotated' "
                         " WHERE user_id = %s", (uid,))
        e = [x for x in self._events(uid) if x["event_type"] == "PASSWORD_CHANGED"][0]
        self.assertIsNone(e["old_value"], "the old password hash reached the record")
        self.assertIsNone(e["new_value"], "the new password hash reached the record")
        self.cur.execute("SAVEPOINT nosecret")
        with self.assertRaises(pg_errors.CheckViolation):
            self.cur.execute(
                "INSERT INTO AppUserEvent (user_id, username, event_type, field, new_value) "
                "VALUES (%s, 'x', 'PASSWORD_CHANGED', 'password_hash', 'scrypt$leaked')", (uid,))
        self.cur.execute("ROLLBACK TO SAVEPOINT nosecret")

    def test_a_sign_in_writes_nothing(self):
        """last_login_at, failed_login_count and locked_until are live state. Recording
        them would put a row per request here and bury the decisions."""
        self._reason(); self._actor()
        uid = self._create()
        before = len(self._events(uid))
        self._reason("")
        self.cur.execute("UPDATE AppUser SET failed_login_count = 3, "
                         " locked_until = NOW() + INTERVAL '15 minutes', last_login_at = NOW() "
                         " WHERE user_id = %s", (uid,))
        self.assertEqual(len(self._events(uid)), before,
                         "a sign-in attempt wrote a decision event")

    def test_deleting_an_account_is_recorded_rather_than_refused(self):
        """The deliberate difference from Agency (v9.440). An account created by mistake
        before it ever acted can go; one that acted is already held by the foreign keys."""
        self._reason(); self._actor()
        uid = self._create()
        self._reason("")
        self.cur.execute("DELETE FROM AppUser WHERE user_id = %s", (uid,))
        e = self._events(uid)[-1]
        self.assertEqual(e["event_type"], "DELETED")
        self.assertFalse(e["widened"], "removing access grants nothing")

    def test_the_user_id_cannot_be_repointed(self):
        self._reason(); self._actor()
        uid = self._create()
        with self.assertRaises(pg_errors.InsufficientPrivilege):
            self.cur.execute("UPDATE AppUser SET user_id = user_id + 5000 WHERE user_id = %s",
                             (uid,))

    def test_the_record_cannot_be_edited_or_deleted(self):
        self._reason(); self._actor()
        uid = self._create()
        self.cur.execute("SAVEPOINT recorded")
        for sql in ("UPDATE AppUserEvent SET widened = FALSE WHERE user_id = %s",
                    "UPDATE AppUserEvent SET justification = 'rewritten' WHERE user_id = %s",
                    "DELETE FROM AppUserEvent WHERE user_id = %s"):
            with self.subTest(sql=sql.split()[0]):
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    self.cur.execute(sql, (uid,))
                self.cur.execute("ROLLBACK TO SAVEPOINT recorded")

    def test_every_seeded_account_carries_a_creation_event(self):
        """The load order installs the trigger after the accounts, so those rows are
        backfilled. A database showing operators and no record of them reads as a broken
        recorder."""
        self.cur.execute("SELECT count(*) AS n FROM AppUser u WHERE NOT EXISTS ("
                         " SELECT 1 FROM AppUserEvent e WHERE e.user_id = u.user_id "
                         "   AND e.event_type = 'CREATED')")
        self.assertEqual(self.cur.fetchone()["n"], 0,
                         "an operator account exists with no record of having been created")


class TestAgencyQuotaIsAppendOnly(_CheckBase):
    """A quota decision is kept, not edited (v9.424).

    AgencyQuota bounds how much of the population one agency may touch. It used to
    be one editable row per agency, so raising a cap destroyed the previous cap, who
    set it, when, and the reason given, while the table's own COMMENT said a cap was
    auditable from the row alone. It is now the RetentionPolicy shape, and the tests
    live here rather than in the application suite for the same reason that one's do:
    the subject is the trigger and the partial index, so the fast mutation drill can
    reach them directly instead of taking a declaration on trust.
    """

    def setUp(self):
        super().setUp()
        self.cur = self.conn.cursor()
        self.addCleanup(self.cur.close)

    def _record(self, issue=400, why='a decision recorded so the test can try to rewrite it'):
        self.cur.execute(
            "UPDATE AgencyQuota SET superseded_at = now() "
            " WHERE agency_id = 1 AND superseded_at IS NULL")
        self.cur.execute(
            "INSERT INTO AgencyQuota (agency_id, issue_per_day, set_by_admin, justification) "
            "VALUES (1, %s, 'test', %s) RETURNING quota_id", (issue, why))
        return self.cur.fetchone()["quota_id"]

    def test_a_recorded_cap_cannot_be_edited(self):
        """Every field of a decision is frozen except the act of superseding it."""
        for column, value in (('issue_per_day', 9999), ('set_by_admin', 'someone_else'),
                              ('justification', 'a different reason, twenty plus characters'),
                              ('agency_id', 2), ('set_at', 'epoch')):
            with self.subTest(column=column):
                qid = self._record()
                with self.assertRaises(pg_errors.InsufficientPrivilege,
                                       msg=f"{column} was editable"):
                    self.cur.execute(
                        f"UPDATE AgencyQuota SET {column} = %s WHERE quota_id = %s",
                        (value, qid))
                self.conn.rollback()

    def test_a_recorded_cap_cannot_be_deleted(self):
        qid = self._record(why='a decision recorded so the test can try to delete it')
        with self.assertRaises(pg_errors.InsufficientPrivilege):
            self.cur.execute("DELETE FROM AgencyQuota WHERE quota_id = %s", (qid,))

    def test_superseding_is_one_way(self):
        """Un-superseding would put a replaced cap back in force and leave no trace
        that it had ever been replaced, which is the edit the history exists to stop."""
        qid = self._record(why='a decision recorded so the test can try to un-supersede it')
        self.cur.execute("UPDATE AgencyQuota SET superseded_at = now() WHERE quota_id = %s",
                         (qid,))
        # Savepoints rather than a rollback: the refusal aborts the transaction, and a
        # full rollback would also undo the row under test, so the second attempt would
        # touch nothing and pass without the trigger being involved at all.
        for attempt in ("superseded_at = NULL",
                        "superseded_at = now() - interval '9 days'"):
            with self.subTest(attempt=attempt):
                self.cur.execute("SAVEPOINT one_way")
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    self.cur.execute(f"UPDATE AgencyQuota SET {attempt} WHERE quota_id = %s",
                                     (qid,))
                self.cur.execute("ROLLBACK TO SAVEPOINT one_way")

    def test_two_caps_cannot_be_in_force_for_one_agency(self):
        """uq_effective_agency_quota, not application care, decides this: the
        enforcement lookup reads one row, so which row it is cannot depend on
        insertion order."""
        self._record(why='the cap in force for this agency, twenty plus chars')
        with self.assertRaises(pg_errors.UniqueViolation):
            self.cur.execute(
                "INSERT INTO AgencyQuota (agency_id, issue_per_day, set_by_admin, justification) "
                "VALUES (1, 900, 'test', 'a second live cap for one agency, refused')")


class TestRevocationListStatusGuard(_CheckBase):
    """A token can only be listed as revoked if it IS revoked."""

    def test_a_live_token_cannot_be_added_to_the_revocation_list(self):
        with self.conn.cursor() as cur:
            cur.execute("SELECT token_id FROM IdentityToken WHERE status = 'ACTIVE' "
                        "ORDER BY token_id LIMIT 1")
            live = cur.fetchone()
            self.assertIsNotNone(live, "no ACTIVE token in the sample data; broken fixture")
            with self.assertRaises(pg_errors.CheckViolation) as caught:
                cur.execute(
                    "INSERT INTO RevocationList (token_id, revoked_by_agency_id, effective_date, "
                    "reason_code) VALUES (%s, 1, CURRENT_DATE, 'COMPROMISED')", (live['token_id'],))
            self.assertIn('RevocationList', str(caught.exception))

    def test_a_revoked_token_can_be_added(self):
        """The positive half. Without it the test above would also pass against a
        trigger that refused every insert."""
        with self.conn.cursor() as cur:
            cur.execute("SELECT token_id FROM IdentityToken WHERE status IN "
                        "('REVOKED', 'LOST', 'EXPIRED') ORDER BY token_id LIMIT 1")
            dead = cur.fetchone()
            self.assertIsNotNone(dead, "no REVOKED/LOST/EXPIRED token in the sample data")
            cur.execute(
                "INSERT INTO RevocationList (token_id, revoked_by_agency_id, effective_date, "
                "reason_code) VALUES (%s, 1, CURRENT_DATE, 'COMPROMISED') RETURNING revocation_id",
                (dead['token_id'],))
            self.assertIsNotNone(cur.fetchone()['revocation_id'])


class TestPredecessorBelongsToTheSameIndividual(_CheckBase):
    """A replacement token cannot inherit from somebody else's token. Without
    this, a replacement chain is a way to move a credential between people."""

    _NEW = ("INSERT INTO IdentityToken (token_value, physical_serial, biometric_binding_type, "
            "individual_id, issuing_agency_id, algorithm_id, predecessor_token_id) "
            "VALUES (%s, %s, 'NONE', %s, 1, 1, %s) RETURNING token_id")

    def test_a_predecessor_belonging_to_another_individual_is_refused(self):
        with self.conn.cursor() as cur:
            cur.execute("SELECT token_id, individual_id FROM IdentityToken ORDER BY token_id LIMIT 2")
            rows = cur.fetchall()
            self.assertEqual(len(rows), 2, "fewer than two tokens in the sample data")
            other, mine = rows[0], rows[1]
            self.assertNotEqual(other['individual_id'], mine['individual_id'],
                                "the first two sample tokens share a holder; this test needs two")
            with self.assertRaises(pg_errors.CheckViolation) as caught:
                cur.execute(self._NEW, ('TKN-PRED-XIND', 'SER-PRED-XIND',
                                        mine['individual_id'], other['token_id']))
            self.assertIn('predecessor', str(caught.exception).lower())

    def test_a_predecessor_belonging_to_the_same_individual_is_accepted(self):
        with self.conn.cursor() as cur:
            cur.execute("SELECT token_id, individual_id FROM IdentityToken ORDER BY token_id LIMIT 1")
            mine = cur.fetchone()
            cur.execute(self._NEW, ('TKN-PRED-SAME', 'SER-PRED-SAME',
                                    mine['individual_id'], mine['token_id']))
            self.assertIsNotNone(cur.fetchone()['token_id'])


class TestEnrollmentCodeOneWayDoor(_CheckBase):
    """A code is fixed once issued, redeemed at most once, and its attempt
    counter only climbs. Append-only in one direction, which is why it is not in
    the table-driven class above."""

    _ISSUE = ("INSERT INTO EnrollmentCode (individual_id, issued_by_agency_id, code_hash, "
              "channel, expires_at) VALUES (1, 1, repeat('f', 64), 'POSTAL', "
              "CURRENT_TIMESTAMP + INTERVAL '1 day') RETURNING code_id")

    def test_the_code_hash_cannot_be_changed(self):
        with self.conn.cursor() as cur:
            cur.execute(self._ISSUE)
            code_id = cur.fetchone()['code_id']
            with self.assertRaises(pg_errors.CheckViolation) as caught:
                cur.execute("UPDATE EnrollmentCode SET code_hash = repeat('0', 64) "
                            "WHERE code_id = %s", (code_id,))
            self.assertIn('fixed once issued', str(caught.exception))

    def test_a_redeemed_code_cannot_be_un_redeemed(self):
        with self.conn.cursor() as cur:
            cur.execute(self._ISSUE)
            code_id = cur.fetchone()['code_id']
            # A redeemed code must name the proofing it produced, so the redemption
            # has to be a real one to get the door shut behind it.
            cur.execute(_PROOFING)
            proofing_id = cur.fetchone()['proofing_id']
            cur.execute("UPDATE EnrollmentCode SET redeemed_at = CURRENT_TIMESTAMP, "
                        "proofing_id = %s WHERE code_id = %s", (proofing_id, code_id))
            with self.assertRaises(pg_errors.CheckViolation) as caught:
                cur.execute("UPDATE EnrollmentCode SET redeemed_at = NULL WHERE code_id = %s",
                            (code_id,))
            self.assertIn('single use', str(caught.exception))

    def test_the_attempt_counter_cannot_be_reset(self):
        """Resetting the counter is how a brute-force bound stops being one."""
        with self.conn.cursor() as cur:
            cur.execute(self._ISSUE)
            code_id = cur.fetchone()['code_id']
            cur.execute("UPDATE EnrollmentCode SET attempts = attempts + 2 WHERE code_id = %s",
                        (code_id,))
            with self.assertRaises(pg_errors.CheckViolation):
                cur.execute("UPDATE EnrollmentCode SET attempts = 0 WHERE code_id = %s", (code_id,))


# ============================================================================
# Uniqueness, exhaustively (v9.415)
#
# The third mechanism MISSION names, after the trigger and the CHECK, is the
# unique index. Measured the same way as the other two: drop each one and see
# whether anything goes red. Twelve of the seventeen non-primary-key unique
# indexes were covered by nothing, including identitytoken_token_value_key and
# two PARTIAL indexes that encode real rules rather than key uniqueness (one
# active attestation per pair, one pending recovery per person).
#
# The duplicate is built by COPYING an existing row rather than by writing one,
# which is what makes this cover twelve rules in one small table: a copy of a
# valid row satisfies every NOT NULL, CHECK and foreign key by construction, so
# the only thing it can violate is uniqueness. Where a table carries more than
# one unique index the copy must be perturbed, or the wrong one fires first and
# the test would pass while proving something else.
# ============================================================================

#: index -> (seed statement for an empty table or None, {column: expression} to
#: perturb so a DIFFERENT unique index on the same table does not fire first).
UNIQUE_RULE_FIXTURES = {
    # One unique index on the table: a plain copy names it.
    'uq_active_attestation': (None, {}),
    'uq_effective_retention_policy': (None, {}),
    'uq_effective_discretion_policy': (None, {}),
    'uq_effective_agency_quota': (
        "INSERT INTO AgencyQuota (agency_id, issue_per_day, set_by_admin, justification) "
        "VALUES (1, 100, 'fixture', 'uniqueness probe: the cap in force for agency 1')", {}),
    'uq_one_pending_recovery_per_individual': (None, {}),
    'blockchainanchor_did_key': (None, {}),
    'cryptographicalgorithm_name_key': (None, {}),
    'devicebinding_device_fingerprint_key': (None, {}),
    'uq_one_leaf_per_token_per_epoch': (None, {}),
    'verificationcontext_context_type_key': (None, {}),
    'appuser_username_key': (None, {}),
    'timestamplog_timestamp_hash_key': (
        "INSERT INTO TimestampLog (timestamp_hash) VALUES (repeat('9', 64))", {}),
    'exchangereceiptlog_receipt_hash_key': (
        "INSERT INTO ExchangeReceiptLog (receipt_hash) VALUES (repeat('8', 64))", {}),
    'relyingparty_client_id_key': (
        # v9.425: registering a party is a weakening and the database wants a reason.
        "SELECT set_config('polaris.justification', "
        "'test fixture: the uniqueness probe party', true); "
        "INSERT INTO RelyingParty (client_id, client_secret_hash, org_name) "
        "VALUES ('rp_uniqueness_probe_0001', repeat('7', 64), 'Uniqueness Probe')", {}),
    'idx_card_personalization_one_per_token': (
        "INSERT INTO CardPersonalization (token_id, issuing_agency_id, credential_ref, "
        "profile_version, normal_public_key, duress_public_key, card_object_sha3_256) "
        "VALUES (1, 1, decode(repeat('00',32),'hex'), 1, decode(repeat('11',32),'hex'), "
        "decode(repeat('22',32),'hex'), decode(repeat('33',32),'hex'))", {}),
    # IdentityToken carries three. Each needs the other two stepped out of the way.
    'identitytoken_token_value_key': (None, {
        'physical_serial': "'SER-UNIQ-PROBE-A'"}),
    'identitytoken_physical_serial_key': (None, {
        'token_value': "'TKN-UNIQ-PROBE-B'"}),
    'one_signature_per_algorithm_per_token': (None, {}),
    'uq_one_active_per_person': (None, {
        'token_value': "'TKN-UNIQ-PROBE-C'", 'physical_serial': "'SER-UNIQ-PROBE-C'"}),
}


class TestEveryUniqueRuleRefusesADuplicate(_CheckBase):
    """Every uniqueness rule the schema states, exercised once."""

    def _copy_statement(self, cur, index_name, perturb):
        """INSERT a copy of one existing row, minus the primary key.

        Copying is the point. A row written by hand has to satisfy every other
        constraint on the table before it can reach the unique index; a copy of a
        row already in the table satisfies all of them by construction.
        """
        cur.execute("""
            SELECT i.indrelid::regclass::text AS tbl, i.indpred IS NOT NULL AS partial
              FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
             WHERE c.relnamespace = 'public'::regnamespace AND c.relname = %s
        """, (index_name,))
        row = cur.fetchone()
        self.assertIsNotNone(row, f"{index_name} is not an index in this database")
        table = row['tbl']
        cur.execute("""
            SELECT a.attname FROM pg_attribute a
             WHERE a.attrelid = %s::regclass AND a.attnum > 0 AND NOT a.attisdropped
               AND a.attidentity = ''
               AND NOT EXISTS (SELECT 1 FROM pg_index i
                                WHERE i.indrelid = a.attrelid AND i.indisprimary
                                  AND a.attnum = ANY(i.indkey))
             ORDER BY a.attnum
        """, (table,))
        cols = [r['attname'] for r in cur.fetchall()]
        select = ", ".join(perturb.get(c, f'"{c}"') for c in cols)
        target = ", ".join(f'"{c}"' for c in cols)
        # A partial index only fires on the rows it covers, so copy one of those.
        where = ""
        if row['partial']:
            cur.execute("SELECT pg_get_expr(indpred, indrelid) AS pred FROM pg_index i "
                        "JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = %s",
                        (index_name,))
            where = " WHERE " + cur.fetchone()['pred']
        return table, f"INSERT INTO {table} ({target}) SELECT {select} FROM {table}{where} LIMIT 1"

    def test_every_unique_rule_refuses_a_duplicate(self):
        for index_name, (seed, perturb) in sorted(UNIQUE_RULE_FIXTURES.items()):
            with self.subTest(index=index_name):
                try:
                    with self.conn.cursor() as cur:
                        # Some tables carry a BEFORE trigger that refuses an unexplained
                        # INSERT (Agency since v9.440, AppUser since v9.443). It fires
                        # ahead of the unique index, so without a reason this sweep would
                        # be measuring that refusal instead of the rule it names. Ignored
                        # by every table that has no such trigger.
                        cur.execute(
                            "SELECT set_config('polaris.actor', 'unique-rule-sweep', true), "
                            "       set_config('polaris.justification', "
                            "                  'uniqueness sweep copying a row to prove the "
                            "rule refuses a duplicate', true)")
                        table, statement = self._copy_statement(cur, index_name, perturb)
                        cur.execute(f"SELECT count(*) AS n FROM {table}")
                        if cur.fetchone()['n'] == 0:
                            self.assertIsNotNone(
                                seed,
                                f"{table} is empty and no seed is declared for {index_name}, so "
                                f"the rule cannot be exercised. Add the INSERT rather than "
                                f"letting the guarantee go untested.")
                            cur.execute(seed)
                        with self.assertRaises(
                                pg_errors.UniqueViolation,
                                msg=f"a duplicate row was accepted; {index_name} is not "
                                    f"enforced") as caught:
                            cur.execute(statement)
                        # And it must be THIS rule that refused. On a table with several
                        # unique indexes the wrong one firing would pass while proving
                        # something else.
                        self.assertIn(
                            index_name, str(caught.exception),
                            f"the duplicate was refused, but by a different rule than "
                            f"{index_name}: {caught.exception}")
                finally:
                    self.conn.rollback()

    def test_the_fixture_table_covers_every_unique_index_in_the_catalog(self):
        """The anti-vacuity anchor, as for the append-only tables: the test above
        proves nothing about an index nobody listed."""
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT c.relname
                  FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
                 WHERE c.relnamespace = 'public'::regnamespace
                   AND i.indisunique AND NOT i.indisprimary
                   AND NOT EXISTS (SELECT 1 FROM pg_class p JOIN pg_inherits h
                                          ON h.inhrelid = i.indrelid WHERE p.oid = h.inhparent)
            """)
            live = {r['relname'] for r in cur.fetchall()}
        listed = set(UNIQUE_RULE_FIXTURES)
        self.assertEqual(
            live - listed, set(),
            "unique index(es) exist that UNIQUE_RULE_FIXTURES does not list, so nothing above "
            "tested them")
        self.assertEqual(
            listed - live, set(),
            "index(es) are listed that the database does not define, so the test above is "
            "asserting against a rule that is gone")
        self.assertGreaterEqual(
            len(live), 15,
            f"only {len(live)} unique indexes were found; the query has broken and these tests "
            "are passing by finding nothing")


if __name__ == '__main__':
    unittest.main(verbosity=2)
