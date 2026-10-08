# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
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

import contextlib
import hashlib
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


@contextlib.contextmanager
def _folds_held(*keys):
    """Hold each fold's lock from a session of its own, as a running fold would hold it.

    The triggers fold pending changes by themselves now and then (random() < 0.002 per
    statement), and a fold inside a test's own transaction moves the changes the test is about to
    read out of the delta table. A test that reads a delta table it has just written holds the lock,
    so that fold returns at once. Without it two TestC1PrivilegeBoundary tests failed whenever the
    fold landed inside them, and the trigger refusal drill, which runs their module once per
    refusal, reported caught refusals as untested (four CI runs, 2026-10-08)."""
    holder = psycopg2.connect(**DB_CONFIG)
    holder.autocommit = True
    try:
        with holder.cursor() as cur:
            for key in keys:
                cur.execute("SELECT pg_advisory_lock(hashtext(%s))", (key,))
        yield
    finally:
        holder.close()        # a session's advisory locks end with it


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
            "VALUES (1, 1, 1, polaris_utc_date() + interval '90 days', 1)",
            constraint_name='no_self_attestation',
        )

    def test_validity_floor_zero_duration_rejected(self):
        """valid_until > attested_date. Default attested_date is today."""
        self._expect_check_violation(
            "INSERT INTO AgencyTrustAttestation "
            "(attesting_agency_id, attested_agency_id, context_id, "
            "attested_date, valid_until, signed_by) "
            "VALUES (1, 2, 1, polaris_utc_date(), polaris_utc_date(), 1)",
            constraint_name='validity_floor',
        )

    def test_revocation_consistency_partial_revocation_rejected(self):
        """If revocation_date is set, revocation_reason must also be set
        (and >= 8 chars)."""
        self._expect_check_violation(
            "INSERT INTO AgencyTrustAttestation "
            "(attesting_agency_id, attested_agency_id, context_id, "
            "valid_until, signed_by, revocation_date) "
            "VALUES (1, 2, 1, polaris_utc_date() + interval '90 days', 1, polaris_utc_date())",
            constraint_name='revocation_consistency',
        )

    def test_revocation_reason_too_short_rejected(self):
        """revocation_reason floor is 8 chars."""
        self._expect_check_violation(
            "INSERT INTO AgencyTrustAttestation "
            "(attesting_agency_id, attested_agency_id, context_id, "
            "valid_until, signed_by, revocation_date, revocation_reason) "
            "VALUES (1, 2, 1, polaris_utc_date() + interval '90 days', 1, "
            "polaris_utc_date(), 'short')",
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

    def test_token_value_is_a_serial(self):
        """chk_token_value_is_a_serial (2026-09-27, WIRE-SPEC 3.7): a token value that could be
        a signed JSON statement is refused by the register itself. Runs as the table's owner,
        asserted below, so it is the constraint that refuses and not a missing grant; a
        genuine serial in the same INSERT is the positive control."""
        with self.conn.cursor() as cur:
            cur.execute("SELECT pg_get_userbyid(relowner) = current_user AS is_owner "
                        "FROM pg_class WHERE oid = 'identitytoken'::regclass")
            if not cur.fetchone()['is_owner']:
                self.skipTest("needs the owner of IdentityToken (POLARIS_DB_USER), so a grant cannot refuse first")
        insert = ("INSERT INTO IdentityToken "
                  "(individual_id, token_value, physical_serial, status, "
                  "algorithm_id, issuing_agency_id, biometric_binding_type) "
                  "VALUES (2, %s, %s, 'RESERVE', 1, 1, 'FINGERPRINT')")
        with self.conn.cursor() as cur:
            cur.execute("SAVEPOINT serial_control")
            cur.execute(insert, ('X-TEST-SERIAL-OK', 'PSV-SERIAL-OK'))
            cur.execute("ROLLBACK TO SAVEPOINT serial_control")
        for i, (label, value) in enumerate((
                ("a signed JSON statement", '{"format":"polaris-trust-list/1","keys":[]}'),
                ("empty", ''),
                ("a control character", 'X-TEST-\x01'),
                ("a C1 control character", 'X-TEST-\u0085'),
                ("more than 128 bytes of UTF-8", 'é' * 100))):
            with self.subTest(label):
                with self.conn.cursor() as cur:
                    cur.execute("SAVEPOINT serial_case")
                try:
                    self._expect_check_violation(insert, (value, 'PSV-SERIAL-BAD-%d' % i),
                                                 constraint_name='chk_token_value_is_a_serial')
                finally:
                    with self.conn.cursor() as cur:
                        cur.execute("ROLLBACK TO SAVEPOINT serial_case")


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
        # Always a different person: a constant can equal the person the fixture picked, and an
        # UPDATE that changes nothing is not a rewrite.
        self._expect_refusal("UPDATE RecoveryRequest SET claimed_individual_id = claimed_individual_id + 1 "
                             "WHERE recovery_id = %s", (rid,), "append-only except for")

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


class TestUseCaseFunctionRefusals(_CheckBase):
    """The refusals the use-case FUNCTIONS make, each driven and each named by its message.

    uc1_issue_and_activate, uc4_activate_reserve and uc5_bind_device are declared FUNCTION
    because they return the id they create, and the procedure mutation drill selected
    prokind = 'p' only, so their refusals sat outside every mutation drill. Measured on
    2026-09-23 once the drill was extended: of the nine it could measure, seven could be
    deleted with every test still green, and uc5 had no test at all.

    Two of the uc4 refusals are sharper than they look. With 'Reserve token % does not
    exist' deleted, a missing reserve id leaves v_reserve_status NULL, and NULL <> 'RESERVE'
    is NULL rather than true, so every later check passes too: the function would mark the
    holder's lost token LOST and activate nothing, leaving them with no credential. The same
    NULL trap sits behind 'Lost token % does not exist'. Each test below asserts the
    refusal's own message, so a different error firing instead does not read as a pass.
    Each runs in the per-test transaction and rolls back."""

    def _active(self, cur):
        cur.execute("SELECT individual_id, token_id FROM IdentityToken "
                    "WHERE status = 'ACTIVE' ORDER BY token_id LIMIT 1")
        row = cur.fetchone()
        self.assertIsNotNone(row, "sample data has no ACTIVE token")
        return row['individual_id'], row['token_id']

    def _reserve_for(self, cur, individual_id, tag):
        cur.execute(
            "INSERT INTO IdentityToken (token_value, physical_serial, biometric_binding_type, "
            " individual_id, issuing_agency_id, algorithm_id, status) "
            "VALUES (%s, %s, 'FINGERPRINT', %s, 3, 1, 'RESERVE') RETURNING token_id",
            ('UCFN-%s-%s' % (tag, individual_id), 'UCFNSER-%s-%s' % (tag, individual_id), individual_id))
        return cur.fetchone()['token_id']

    def _refused(self, cur, sql, args, message, errtype):
        with self.assertRaises(errtype) as ctx:
            cur.execute(sql, args)
        self.assertIn(message, str(ctx.exception),
                      "refused, but by a different rule than the one under test")

    UC4 = "SELECT uc4_activate_reserve(%s, 3, 'LOST', %s, 'https://crl.idtoken.gov/test/ucfn.crl')"

    def test_uc4_refuses_a_lost_token_that_does_not_exist(self):
        with self.conn.cursor() as cur:
            ind, _ = self._active(cur)
            reserve = self._reserve_for(cur, ind, 'NOLOST')
            self._refused(cur, self.UC4, (2147483000, reserve), "Lost token 2147483000 does not exist",
                          pg_errors.NoDataFound)

    def test_uc4_refuses_a_reserve_that_does_not_exist(self):
        with self.conn.cursor() as cur:
            _, lost = self._active(cur)
            self._refused(cur, self.UC4, (lost, 2147483000), "Reserve token 2147483000 does not exist",
                          pg_errors.NoDataFound)

    def test_uc4_refuses_a_reserve_that_belongs_to_someone_else(self):
        with self.conn.cursor() as cur:
            ind, lost = self._active(cur)
            cur.execute("SELECT individual_id FROM Individual WHERE individual_id <> %s "
                        "ORDER BY individual_id LIMIT 1", (ind,))
            other = cur.fetchone()['individual_id']
            reserve = self._reserve_for(cur, other, 'OTHER')
            self._refused(cur, self.UC4, (lost, reserve),
                          "belongs to a different individual than lost token",
                          pg_errors.IntegrityConstraintViolation)

    def test_uc4_positive_control(self):
        with self.conn.cursor() as cur:
            ind, lost = self._active(cur)
            reserve = self._reserve_for(cur, ind, 'OK')
            cur.execute(self.UC4 + " AS promoted", (lost, reserve))
            self.assertEqual(cur.fetchone()['promoted'], reserve)

    UC1 = ("SELECT uc1_issue_and_activate('Auth Test','1990-01-01','US-CA',1,%s,"
           "'FINGERPRINT',1,'MULTI_MODAL','TKN-AUTHTEST','SN-AUTHTEST',NULL,ARRAY[1])")

    def test_uc1_refuses_an_agency_not_authorized_for_the_algorithm(self):
        with self.conn.cursor() as cur:
            cur.execute("SELECT algorithm_id FROM CryptographicAlgorithm WHERE algorithm_id NOT IN "
                        "(SELECT algorithm_id FROM AgencyAlgorithmAuth WHERE agency_id = 1 "
                        " AND authorization_type IN ('ISSUE','BOTH')) ORDER BY algorithm_id LIMIT 1")
            row = cur.fetchone()
            self.assertIsNotNone(row, "every algorithm is authorized for agency 1; the fixture needs one that is not")
            self._refused(cur, self.UC1, (row['algorithm_id'],),
                          "is not authorized to issue under algorithm", pg_errors.InsufficientPrivilege)

    UC5 = "SELECT uc5_bind_device(%s, 'PHONE', %s, 'SECURE_ENCLAVE', 12)"

    def test_uc5_refuses_a_token_that_does_not_exist(self):
        with self.conn.cursor() as cur:
            self._refused(cur, self.UC5, (2147483000, 'fp-none'), "Token 2147483000 does not exist",
                          pg_errors.NoDataFound)

    def test_uc5_refuses_a_token_that_is_not_active(self):
        with self.conn.cursor() as cur:
            ind, _ = self._active(cur)
            reserve = self._reserve_for(cur, ind, 'UC5')
            self._refused(cur, self.UC5, (reserve, 'fp-reserve'), "is not ACTIVE", pg_errors.InvalidParameterValue)

    def test_uc5_positive_control(self):
        with self.conn.cursor() as cur:
            _, token = self._active(cur)
            cur.execute(self.UC5 + " AS binding_id", (token, 'fp-control'))
            self.assertIsNotNone(cur.fetchone()['binding_id'])



class TestBulkIssueRefusals(unittest.TestCase):
    """uc_bulk_issue's six refusals, each driven directly (2026-09-24). The procedure mutation
    drill first examined this procedure when rc.40 made it SECURITY DEFINER, and all six could
    be deleted with every suite it runs still green: bulk issuance was exercised only through
    the CLI's tests. One connection as the owner, a savepoint per case, all rolled back."""

    def setUp(self):
        self.conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        self.cur = self.conn.cursor()
        self.n = 0

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def _batch(self, agency=1, algorithm=1, rows=1, signed=True, issued=False):
        self.cur.execute("INSERT INTO BulkEnrollmentBatch (issuing_agency_id, algorithm_id, note, "
                         "issued_at) VALUES (%s, %s, 'refusal probe', %s) RETURNING batch_id",
                         (agency, algorithm, "2026-01-01" if issued else None))
        bid = self.cur.fetchone()["batch_id"]
        for _ in range(rows):
            self.n += 1
            tv = "BULK-REFUSAL-%d-%d" % (bid, self.n)
            self.cur.execute(
                "INSERT INTO BulkEnrollmentStaging (batch_id, legal_name, date_of_birth, "
                "jurisdiction, biometric_binding_type, token_value, physical_serial, "
                "signature_bytes) VALUES (%s, 'Bulk Probe', DATE '1990-01-01', 'US-PA', 'IRIS', "
                "%s, %s, %s)", (bid, tv, "SN-" + tv, psycopg2.Binary(b"sig") if signed else None))
        return bid

    def _refused(self, bid, phrase):
        self.cur.execute("SAVEPOINT probe")
        with self.assertRaises(psycopg2.Error) as ctx:
            self.cur.execute("CALL uc_bulk_issue(%s)", (bid,))
        self.cur.execute("ROLLBACK TO SAVEPOINT probe")
        self.assertIn(phrase, str(ctx.exception))

    def test_a_good_batch_issues(self):
        bid = self._batch(rows=2)
        self.cur.execute("CALL uc_bulk_issue(%s)", (bid,))
        self.assertEqual(self.cur.fetchone()["p_rows_issued"], 2, "control: a good batch issues")
        self.cur.execute("SELECT count(*) AS n FROM TokenLifecycleEvent e JOIN BulkEnrollmentStaging s "
                         "ON s.token_id = e.token_id WHERE s.batch_id = %s AND e.event_type = 'ISSUED'",
                         (bid,))
        self.assertEqual(self.cur.fetchone()["n"], 2)

    def test_each_refusal(self):
        self._refused(987654321, "does not exist")
        self._refused(self._batch(issued=True), "already issued")
        self._refused(self._batch(agency=4), "not authorized to issue")
        self.cur.execute("UPDATE CryptographicAlgorithm SET deprecation_date = now() - INTERVAL '1 day' "
                         "WHERE algorithm_id = 3")
        self._refused(self._batch(algorithm=3), "deprecated")
        self._refused(self._batch(rows=0), "no staged rows")
        self._refused(self._batch(signed=False), "requires a signature")



class TestRetentionDecisionProcedure(unittest.TestCase):
    """uc_set_retention_policy (2026-09-25): the CLI's single-decision path, moved into a
    procedure because the application role is refused UPDATE on RetentionPolicy and the CLI
    connects as it. Its three actor refusals and its supersede, as the owner, rolled back."""

    def setUp(self):
        self.conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        self.cur = self.conn.cursor()
        self.cur.execute("SELECT user_id FROM AppUser WHERE role = 'admin' AND is_active LIMIT 1")
        self.admin = self.cur.fetchone()["user_id"]
        self.cur.execute("SELECT user_id FROM AppUser WHERE role <> 'admin' LIMIT 1")
        self.other = self.cur.fetchone()["user_id"]

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def _set(self, actor, days=2000, jurisdiction="US-ZZ"):
        self.cur.execute("CALL uc_set_retention_policy('VERIFICATION', %s, %s, "
                         "'retention probe: a decision recorded by the test', %s, NULL, NULL)",
                         (jurisdiction, days, actor))
        return self.cur.fetchone()

    def test_a_decision_supersedes_the_last(self):
        first = self._set(self.admin)
        self.assertEqual(first["p_superseded"], 0)
        second = self._set(self.admin, days=2100)
        self.assertEqual(second["p_superseded"], 1, "the earlier decision is superseded, not edited")
        self.cur.execute("SELECT retention_days, superseded_at IS NULL AS live FROM RetentionPolicy "
                         "WHERE policy_id IN (%s, %s) ORDER BY policy_id",
                         (first["p_policy_id"], second["p_policy_id"]))
        self.assertEqual([(r["retention_days"], r["live"]) for r in self.cur.fetchall()],
                         [(2000, False), (2100, True)])

    def test_only_an_active_admin_records_one(self):
        for actor, phrase in ((987654, "does not exist"), (self.other, "must be admin")):
            self.cur.execute("SAVEPOINT s")
            with self.assertRaises(psycopg2.Error, msg=phrase) as ctx:
                self._set(actor)
            self.cur.execute("ROLLBACK TO SAVEPOINT s")
            self.assertIn(phrase, str(ctx.exception))
        self.cur.execute("SELECT set_config('polaris.justification', 'probe: deactivate', true)")
        self.cur.execute("UPDATE AppUser SET is_active = FALSE WHERE user_id = %s", (self.admin,))
        with self.assertRaises(psycopg2.Error) as ctx:
            self._set(self.admin)
        self.assertIn("not an active account", str(ctx.exception))


class TestEachTriggerRefusalIsNoticed(_CheckBase):
    """2026-09-26. The trigger drill deletes whole triggers; nothing deleted one refusal INSIDE a
    trigger function. A one-off drill that did (each RAISE in each trigger function with more
    than one) found these refusals no test noticed: deleting any of them left every suite green.
    The others it reported are masked by a later check in the same function, a CHECK, or a
    foreign key, and the forbidden change is still refused. Each test here asserts the specific
    refusal's message, so a neighbouring check cannot stand in for it. Runs as the owner: the
    point is the trigger, not the grant."""

    def _refused(self, sql, params, message):
        with self.assertRaisesRegex(psycopg2.Error, message):
            with self.conn.cursor() as cur:
                cur.execute(sql, params)
        self.conn.rollback()

    def _ids(self, sql, n):
        """The first n ids a query returns, looked up rather than assumed: other suites in the
        same shard create and remove rows, so a fixed id is a guess about test order."""
        with self.conn.cursor() as cur:
            cur.execute(sql)
            ids = [list(r.values())[0] for r in cur.fetchall()][:n]
        self.assertEqual(len(ids), n, "fixture needs %d rows from: %s" % (n, sql))
        return ids

    def _token(self, status, **extra):
        """A fresh person and one credential in the given status, created here: the seed's
        tokens are consumed by the suites that run before this one (the weekly sweep runs the
        application suite many times on the same database first)."""
        (alg,) = self._ids("SELECT algorithm_id FROM CryptographicAlgorithm ORDER BY algorithm_id", 1)
        (agency,) = self._ids("SELECT agency_id FROM Agency ORDER BY agency_id", 1)
        with self.conn.cursor() as cur:
            cur.execute("INSERT INTO Individual (legal_name, date_of_birth, jurisdiction) "
                        "VALUES ('Trigger Refusal Fixture', DATE '1990-01-01', 'US-PA') "
                        "RETURNING individual_id")
            person = cur.fetchone()["individual_id"]
            cols = {"individual_id": person, "token_value": "TRF-%d-%s" % (person, status),
                    "physical_serial": "TRF-PS-%d-%s" % (person, status), "status": status,
                    "algorithm_id": alg, "issuing_agency_id": agency,
                    "biometric_binding_type": "FINGERPRINT"}
            cols.update(extra)
            cur.execute("INSERT INTO IdentityToken (%s) VALUES (%s) RETURNING token_id"
                        % (", ".join(cols), ", ".join(["%s"] * len(cols))), list(cols.values()))
            tok = cur.fetchone()["token_id"]
            cur.execute("INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes, signed_at) "
                        "VALUES (%s, %s, '\\x01'::bytea, CURRENT_TIMESTAMP - interval '3 days') "
                        "RETURNING signature_id", (tok, alg))
            self._sig = cur.fetchone()["signature_id"]
        return tok

    def _superseded_policy(self):
        (user,) = self._ids("SELECT user_id FROM AppUser ORDER BY user_id", 1)
        with self.conn.cursor() as cur:
            # Inserted already superseded: uq_effective_retention_policy admits one current
            # policy per class, and the seed's is current.
            cur.execute("INSERT INTO RetentionPolicy (table_class, retention_days, justification, "
                        "set_by_user_id, effective_from, superseded_at) VALUES ('AUTH_AUDIT', 400, "
                        "'a fixture for the refusals drill', %s, now() - interval '2 days', "
                        "now() - interval '1 day') RETURNING policy_id", (user,))
            return cur.fetchone()["policy_id"]

    def _attestation(self, **extra):
        a, b, self._third = self._ids("SELECT agency_id FROM Agency ORDER BY agency_id", 3)
        (ctx,) = self._ids("SELECT context_id FROM VerificationContext ORDER BY context_id", 1)
        (user,) = self._ids("SELECT user_id FROM AppUser ORDER BY user_id", 1)
        cols = {"attesting_agency_id": a, "attested_agency_id": b, "context_id": ctx,
                "signed_by": user}
        cols.update(extra)
        with self.conn.cursor() as cur:
            cur.execute("INSERT INTO AgencyTrustAttestation (%s, valid_until) VALUES (%s, "
                        "polaris_utc_date() + 90) RETURNING attestation_id"
                        % (", ".join(cols), ", ".join(["%s"] * len(cols))), list(cols.values()))
            return cur.fetchone()["attestation_id"]

    def test_an_attestation_cannot_be_pointed_at_another_authority(self):
        att = self._attestation()
        self._refused("UPDATE AgencyTrustAttestation SET attested_agency_id = %s "
                      "WHERE attestation_id = %s", (self._third, att), "append-only except for")

    def test_an_attestation_signature_cannot_be_replaced(self):
        att = self._attestation(attestation_format="polaris-attestation/1",
                                attestation_signature_hex="aa", attestation_public_key_hex="bb")
        self._refused("UPDATE AgencyTrustAttestation SET attestation_signature_hex = 'cc' "
                      "WHERE attestation_id = %s", (att,), "signature cannot be replaced")

    def test_a_recorded_revocation_cannot_be_withdrawn_or_backdated(self):
        # The owner is the only role uc10's own guard admits to the revocation columns, so these
        # two refusals are what stands between the owner and a quietly un-revoked trust edge.
        for sql, message in (
                ("UPDATE AgencyTrustAttestation SET revocation_date = NULL, revocation_reason = NULL "
                 "WHERE attestation_id = %s", "cannot be un-set"),
                ("UPDATE AgencyTrustAttestation SET revocation_date = revocation_date - interval '1 day' "
                 "WHERE attestation_id = %s", "cannot be moved earlier")):
            with self.subTest(message):
                att = self._attestation(revocation_date=None)
                with self.conn.cursor() as cur:
                    cur.execute("UPDATE AgencyTrustAttestation SET revocation_date = "
                                "polaris_utc_date(), revocation_reason = 'compromised signer key' "
                                "WHERE attestation_id = %s", (att,))
                self._refused(sql, (att,), message)

    def test_a_superseded_retention_policy_cannot_be_backdated(self):
        self._refused("UPDATE RetentionPolicy SET superseded_at = superseded_at - interval '1 hour' "
                      "WHERE policy_id = %s", (self._superseded_policy(),), "cannot move earlier")

    def test_a_deprecated_signature_cannot_be_undeprecated_or_backdated(self):
        # The application role writes TokenSignature (the migration path), so without these a
        # signature under a retired algorithm could be made current again.
        for sql, message in (
                ("UPDATE TokenSignature SET deprecation_date = NULL WHERE signature_id = %s",
                 "cannot be un-set"),
                ("UPDATE TokenSignature SET deprecation_date = deprecation_date - interval '1 day' "
                 "WHERE signature_id = %s", "cannot be moved earlier")):
            with self.subTest(message):
                self._token("RESERVE")
                with self.conn.cursor() as cur:
                    # A second signature on the token, so deprecating it leaves one active
                    # (trg_token_must_have_active_signature refuses a token with none).
                    cur.execute("INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes, "
                                "signed_at) SELECT s.token_id, a.algorithm_id, s.signature_bytes, "
                                "CURRENT_TIMESTAMP - interval '2 days' FROM TokenSignature s "
                                "JOIN CryptographicAlgorithm a ON NOT EXISTS (SELECT 1 FROM "
                                "TokenSignature t WHERE t.token_id = s.token_id AND t.algorithm_id "
                                "= a.algorithm_id) LIMIT 1 RETURNING signature_id")
                    sig = cur.fetchone()["signature_id"]
                    cur.execute("UPDATE TokenSignature SET deprecation_date = CURRENT_TIMESTAMP "
                                "WHERE signature_id = %s", (sig,))
                self._refused(sql, (sig,), message)

    def test_a_decided_recovery_keeps_its_channels(self):
        (person,) = self._ids("SELECT individual_id FROM Individual ORDER BY individual_id", 1)
        (agency,) = self._ids("SELECT agency_id FROM Agency ORDER BY agency_id", 1)
        asker, decider = self._ids("SELECT user_id FROM AppUser ORDER BY user_id", 2)
        with self.conn.cursor() as cur:
            cur.execute("INSERT INTO RecoveryRequest (claimed_individual_id, requesting_agency_id, "
                        "requesting_user_id, cooldown_expires_at, status, decided_at, "
                        "decided_by_user_id, decision_reason) VALUES (%s, %s, %s, "
                        "CURRENT_TIMESTAMP + interval '49 hours', 'REJECTED', CURRENT_TIMESTAMP, "
                        "%s, 'a test decision recorded') RETURNING recovery_id",
                        (person, agency, asker, decider))
            rid = cur.fetchone()["recovery_id"]
        self._refused("UPDATE RecoveryRequest SET sworn_statement_hash = repeat('e', 64) "
                      "WHERE recovery_id = %s", (rid,), "cannot be rewritten after")

    def test_a_superseded_retention_policy_stays_superseded(self):
        self._refused("UPDATE RetentionPolicy SET superseded_at = NULL WHERE policy_id = %s",
                      (self._superseded_policy(),), "cannot be un-set")

    def test_a_signature_cannot_be_rewritten(self):
        self._token("RESERVE")
        self._refused("UPDATE TokenSignature SET signature_bytes = '\\x00'::bytea "
                      "WHERE signature_id = %s", (self._sig,), "append-only except for deprecation_date")

    def test_a_token_keeps_one_active_signature(self):
        tok = self._token("RESERVE")
        self._refused("UPDATE TokenSignature SET deprecation_date = CURRENT_TIMESTAMP "
                      "WHERE token_id = %s", (tok,), "zero active signatures")

    def test_a_revoked_token_does_not_return(self):
        tok = self._token("REVOKED")
        self._refused("UPDATE IdentityToken SET status = 'ACTIVE' WHERE token_id = %s", (tok,),
                      "Illegal token state transition")

    def test_a_reserve_becomes_active_only_dated_and_unexpired(self):
        for sets, message in (
                ("activated_date = NULL", "without setting activated_date"),
                ("activated_date = CURRENT_TIMESTAMP, expiration_date = polaris_utc_date() - 1",
                 "it expired on")):
            with self.subTest(message):
                tok = self._token("RESERVE")
                self._refused("UPDATE IdentityToken SET status = 'ACTIVE', " + sets +
                              " WHERE token_id = %s", (tok,), message)


class TestVouchingRulesHeldByTheDatabase(_CheckBase):
    """2026-09-26. docs/design/trusted-referee.md: "Every limit is a database constraint, not
    only a module check." The referee's level was the writer's claim, the co-signer bound lived
    only in referee.py, and a co-signer was never checked for being proofed. As polaris_app, 26
    vouchings by an unproofed referee with no co-signer were recorded. trg_vouching_rules holds
    each rule for every writer; each test asserts that rule's own message."""

    def _person(self, name):
        with self.conn.cursor() as cur:
            cur.execute("INSERT INTO Individual (legal_name, date_of_birth, jurisdiction) "
                        "VALUES (%s, DATE '1985-01-01', 'US-PA') RETURNING individual_id", (name,))
            return cur.fetchone()["individual_id"]

    def _proof(self, person, level):
        with self.conn.cursor() as cur:
            cur.execute("SELECT min(agency_id) AS a FROM Agency")
            agency = cur.fetchone()["a"]
            cur.execute("INSERT INTO EnrollmentProofing (individual_id, recorded_by_agency_id, "
                        "presence, derived_ial) VALUES (%s, %s, 'IN_PERSON', %s) "
                        "RETURNING proofing_id", (person, agency, level))
            return cur.fetchone()["proofing_id"]

    def _setup(self, referee_level="IAL2"):
        self.referee = self._person("Referee Fixture")
        if referee_level:
            self._proof(self.referee, referee_level)
        self.applicant = self._person("Applicant Fixture")
        self.proofing = self._proof(self.applicant, "IAL1")

    def _vouch(self, referee_ial="IAL2", co_signer=None):
        with self.conn.cursor() as cur:
            cur.execute("INSERT INTO RefereeVouching (proofing_id, referee_individual_id, "
                        "applicant_individual_id, referee_ial, relationship, vouched_ial, "
                        "co_signer_individual_id) VALUES (%s, %s, %s, %s, 'SOCIAL_WORKER', 'IAL1', %s) "
                        "RETURNING vouching_id",
                        (self.proofing, self.referee, self.applicant, referee_ial, co_signer))
            return cur.fetchone()["vouching_id"]

    def _refused(self, message, **kw):
        with self.assertRaisesRegex(psycopg2.Error, message):
            self._vouch(**kw)
        self.conn.rollback()

    def test_a_proofed_referee_vouches(self):
        self._setup()
        self.assertIsNotNone(self._vouch())

    def test_an_unproofed_referee_cannot_vouch(self):
        self._setup(referee_level=None)
        self._refused("has no proofing record")

    def test_the_referee_level_is_derived_not_claimed(self):
        self._setup(referee_level="IAL1")
        self._refused("the level is derived, never chosen", referee_ial="IAL2")

    def test_past_the_bound_a_proofed_cosigner_is_required(self):
        self._setup()
        for _ in range(25):
            self._vouch()
        self._refused("needs a co-signer")
        # The same referee's 25 are gone with the rollback; rebuild them and co-sign the 26th.
        self._setup()
        for _ in range(25):
            self._vouch()
        cosigner = self._person("Co-signer Fixture")
        self._proof(cosigner, "IAL2")
        self.assertIsNotNone(self._vouch(co_signer=cosigner))

    def test_an_unproofed_cosigner_does_not_count(self):
        self._setup()
        cosigner = self._person("Unproofed Co-signer")
        self._refused("is not proofed at IAL2 or above", co_signer=cosigner)


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
        # 2026-09-28: the wallet copy record (docs/design/oid4vci-issuer.md). Editing a row
        # would move a copy's status index onto another copy.
        "CredentialCopy",
        # 013 (2026-10-04): the logs' public-chain anchors, written only by the schema owner.
        "ChainAnchor",
        # Lab record 017 (2026-10-07): the backup record, written only by the backup scripts.
        "BackupEvent",
        # Lab record 017 (2026-10-07): the record of reconciliations after a restore, written
        # only by scripts/polaris-reconcile-restore.py.
        "RestoreRecord",
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
            # 2026-09-24: CI gave this role the superuser's password, the connection failed,
            # and every test here SKIPPED, so the C1 privilege boundary was never exercised in
            # CI (rc.38's guards could be dropped with nothing going red). A skip is a pass
            # nobody reads. In CI it is a failure; elsewhere it still skips, with the reason.
            if os.environ.get("CI"):
                self.fail(f"polaris_app role unreachable in CI, so the privilege-boundary tests "
                          f"cannot run: {exc}. Set POLARIS_APP_TEST_PASSWORD.")
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
            # Since rc.40 the lifecycle log, and since 2026-09-25 the epoch leaves and the anchor
            # batches, are written only by SECURITY DEFINER routines; since 2026-09-27 the key
            # register, card personalization and retention policy only by the owner; since
            # 2026-09-28 the wallet copy record only by uc_issue_credential_copy; since the contract
            # migration 2026-10-01-003, the holder key register only by uc_record_holder_key_event;
            # since 2026-10-04 the chain anchors only by the schema owner; and since 2026-10-07 the
            # backup record only by the backup scripts and the record of reconciliations after a
            # restore only by its script, as the schema owner.
            self.assertEqual(bool(row["ins"]),
                             tbl.lower() not in ("tokenlifecycleevent", "tokenstateepochleaf",
                                                 "anchorbatch", "duressevent", "authoritykeyevent",
                                                 "cardpersonalization", "retentionpolicy",
                                                 "credentialcopy", "holderkeyevent", "chainanchor",
                                                 "backupevent", "restorerecord"),
                             f"append-only is insert-allowed except the lifecycle log, the epoch "
                             f"leaves, the anchor batches and the owner's registers: {tbl}")
            conn.rollback()

    def test_app_role_records_and_revokes_trust_only_through_uc10(self):
        """2026-09-25. With INSERT on AgencyTrustAttestation the application role could record a
        trust edge no admin signed, and the signing pass would sign it with the attesting
        authority's key; with UPDATE it could revoke one without the admin gate. Direct writes
        are refused; the two procedures still work for the role, in a transaction rolled back."""
        conn = self._app_conn()
        with conn.cursor() as cur:
            with self.assertRaises(pg_errors.InsufficientPrivilege):
                cur.execute("INSERT INTO AgencyTrustAttestation (attesting_agency_id, attested_agency_id, "
                            "context_id, attested_date, valid_until, signed_by) VALUES "
                            "(6, 1, 1, now() - interval '400 days', now()::date + 3650, "
                            "(SELECT user_id FROM AppUser WHERE username = 'admin'))")
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute("SELECT attestation_id FROM AgencyTrustAttestation "
                        "WHERE revocation_date IS NULL ORDER BY attestation_id LIMIT 1")
            aid = cur.fetchone()["attestation_id"]
            with self.assertRaises(pg_errors.InsufficientPrivilege) as ctx:
                cur.execute("UPDATE AgencyTrustAttestation SET revocation_date = now(), "
                            "revocation_reason = 'revoked around the gate' WHERE attestation_id = %s", (aid,))
            self.assertIn("uc10_revoke_attestation", str(ctx.exception))
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE username = 'admin'")
            admin = cur.fetchone()["user_id"]
            cur.execute("CALL uc10_revoke_attestation(%s, %s, %s)", (aid, "rolled back by the test", admin))
            cur.execute("SELECT revocation_date IS NOT NULL AS revoked FROM AgencyTrustAttestation "
                        "WHERE attestation_id = %s", (aid,))
            self.assertTrue(cur.fetchone()["revoked"], "the procedure still revokes for the role")
            cur.execute("CALL uc10_attest_trust(6, 1, 1, (now()::date + 30), %s)", (admin,))
        conn.rollback()

    def test_app_role_cannot_write_the_anchoring_layer(self):
        """2026-09-25. BlockchainAnchor has no trigger, and the application role held UPDATE on it:
        after a batch closed, an anchor could be moved into another batch and its Merkle proof
        rewritten. With INSERT on AnchorBatch it could record a batch whose size no leaves bear
        out. The application writes neither table; close_anchor_batch does, as the owner."""
        conn = self._app_conn()
        attempts = (
            ("move an anchor into another batch",
             "UPDATE BlockchainAnchor SET batch_id = batch_id, merkle_proof = '[]'::jsonb "
             "WHERE anchor_id = (SELECT min(anchor_id) FROM BlockchainAnchor)"),
            ("add an anchor", "INSERT INTO BlockchainAnchor (token_id, did, commitment_hash, ledger_network) "
                              "VALUES (1, 'did:x', 'ab', 'X')"),
            ("delete an anchor", "DELETE FROM BlockchainAnchor WHERE anchor_id = 0"),
            ("record a batch", "INSERT INTO AnchorBatch (merkle_root, algorithm_id, batch_size) "
                               "VALUES ('ab', 1, 5000)"),
        )
        for label, sql in attempts:
            with self.subTest(label), conn.cursor() as cur:
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute(sql)
            conn.rollback()

    def test_app_role_cannot_fabricate_a_permanent_record(self):
        """2026-09-25. DuressEvent, LifecycleArchiveCheckpoint and IndividualErasureEvent are
        append-only, and the application role held INSERT on all three though it writes none: it
        could record a duress alarm for a holder with no duress code, a checkpoint for a purge that
        never ran, or an erasure that never happened, and none could be corrected. Each is refused;
        the procedures that write them still work for the role."""
        conn = self._app_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE username = 'admin'")
            admin = cur.fetchone()["user_id"]
        conn.rollback()
        attempts = (
            ("a duress alarm", "INSERT INTO DuressEvent (token_id, context_id, requesting_agency_id, "
                               "oob_channel) VALUES (1, 1, 1, 'AUDIT_TABLE')", ()),
            ("an archive checkpoint", "INSERT INTO LifecycleArchiveCheckpoint DEFAULT VALUES", ()),
            ("an erasure", "INSERT INTO IndividualErasureEvent (individual_id, pseudonym_assigned, "
                           "erased_by_user_id, reason) VALUES (1, 'PSEUDONYMIZED-1', %s, 'never happened')",
             (admin,)),
        )
        for label, sql, args in attempts:
            with self.subTest(label), conn.cursor() as cur:
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute(sql, args)
            conn.rollback()
        with conn.cursor() as cur:
            cur.execute("SELECT individual_id FROM Individual WHERE individual_id NOT IN "
                        "(SELECT individual_id FROM IndividualErasureEvent) ORDER BY 1 LIMIT 1")
            ind = cur.fetchone()["individual_id"]
            cur.execute("CALL uc_pseudonymize_individual(%s, %s, %s)", (ind, admin, "rolled back by the test"))
            cur.execute("SELECT count(*) AS n FROM IndividualErasureEvent WHERE individual_id = %s", (ind,))
            self.assertEqual(cur.fetchone()["n"], 1, "the procedure still records the erasure for the role")
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute("SELECT token_id FROM IdentityToken WHERE duress_code_hash IS NULL ORDER BY 1 LIMIT 1")
            plain = cur.fetchone()["token_id"]
            with self.assertRaises(psycopg2.Error) as ctx:
                cur.execute("CALL uc12_record_duress(%s, 1, 1)", (plain,))
            self.assertIn("no duress code enrolled", str(ctx.exception),
                          "the procedure is reachable and refuses on its own terms")
        conn.rollback()

    def test_app_role_cannot_create_a_credential_around_issuance(self):
        """2026-09-25. Issuance is uc1_issue_and_activate (or uc_bulk_issue): two-witness signing,
        the algorithm authorization, the enrolment evidence. With INSERT on IdentityToken the
        application role could create an ACTIVE credential that passed none of it, and with INSERT
        on the other four tables grant it permissions, list a token as revoked, bind a device or
        open a recovery around their procedures. Each direct insert is refused."""
        conn = self._app_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT individual_id FROM Individual ORDER BY 1 LIMIT 1")
            ind = cur.fetchone()["individual_id"]
            cur.execute("SELECT token_id FROM IdentityToken ORDER BY 1 LIMIT 1")
            tid = cur.fetchone()["token_id"]
        conn.rollback()
        attempts = (
            ("a credential", "INSERT INTO IdentityToken (token_value, physical_serial, "
                             "biometric_binding_type, individual_id, issuing_agency_id, algorithm_id, "
                             "status) VALUES ('AROUND-ISSUANCE', 'AROUND-SN', 'FINGERPRINT', %s, 1, 1, "
                             "'RESERVE')", (ind,)),
            ("a permission", "INSERT INTO TokenPermission (token_id, context_id, permission_level) "
                             "VALUES (%s, 1, 'VERIFY')", (tid,)),
            ("a revocation-list entry", "INSERT INTO RevocationList (token_id, revoked_by_agency_id, "
                                        "effective_date, reason_code) VALUES (%s, 1, polaris_utc_date(), "
                                        "'COMPROMISED')", (tid,)),
            ("a device binding", "INSERT INTO DeviceBinding (token_id) VALUES (%s)", (tid,)),
            ("a recovery request", "INSERT INTO RecoveryRequest (claimed_individual_id) VALUES (%s)", (ind,)),
        )
        for label, sql, args in attempts:
            with self.subTest(label), conn.cursor() as cur:
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute(sql, args)
            conn.rollback()

    def test_app_role_cannot_record_the_recovery_channels_or_reopen_a_batch(self):
        """2026-09-25. uc9_complete_recovery approves only when the request shows all three
        out-of-band channels; with UPDATE the application role could record all three itself, so
        three independent verifications were one role's word. A bulk-issuance batch could have its
        issued_at reset, re-opening uc_bulk_issue's refusal to issue a batch twice. Both refused."""
        conn = self._app_conn()
        attempts = (
            ("the three recovery channels",
             "UPDATE RecoveryRequest SET biometric_verified = TRUE, sworn_statement_hash = %s "
             "WHERE recovery_id = (SELECT min(recovery_id) FROM RecoveryRequest)", ("ab" * 32,)),
            ("an issued batch re-opened",
             "UPDATE BulkEnrollmentBatch SET issued_at = NULL, rows_issued = NULL "
             "WHERE batch_id = (SELECT min(batch_id) FROM BulkEnrollmentBatch)", ()),
            ("a staged row rewritten", "UPDATE BulkEnrollmentStaging SET token_id = NULL WHERE false", ()),
        )
        for label, sql, args in attempts:
            with self.subTest(label), conn.cursor() as cur:
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute(sql, args)
            conn.rollback()

    def test_app_role_cannot_widen_revive_or_unrevoke_a_credential(self):
        """2026-09-25. TokenPermission and DeviceBinding carry no trigger, and the application role
        held UPDATE and DELETE on them and on RevocationList without using either: it could widen
        the contexts a credential is valid in, revive or extend a device binding, and delete or
        re-date a revocation so the verifiers' feeds stop listing a revoked token. All refused."""
        conn = self._app_conn()
        attempts = (
            ("widen a permission", "UPDATE TokenPermission SET context_id = context_id WHERE false"),
            ("drop a permission", "DELETE FROM TokenPermission WHERE false"),
            ("revive a device binding", "UPDATE DeviceBinding SET expires_date = expires_date WHERE false"),
            ("delete a device binding", "DELETE FROM DeviceBinding WHERE false"),
            ("re-date a revocation", "UPDATE RevocationList SET effective_date = effective_date WHERE false"),
            ("un-revoke a token", "DELETE FROM RevocationList WHERE false"),
        )
        for label, sql in attempts:
            with self.subTest(label), conn.cursor() as cur:
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute(sql)
            conn.rollback()

    def test_app_role_cannot_move_extend_or_rewrite_a_credential(self):
        """1.0.0-rc.56. The state machine guards status and nothing else, and the application
        role holds UPDATE on IdentityToken for its status changes. With it, one UPDATE moved an
        ACTIVE credential to another person, another extended it to 2099, and others rewrote its
        value, its issuer and its duress code. All refused now; a legal status change is not."""
        conn = self._app_conn()
        with conn.cursor() as cur:
            # An ACTIVE credential when there is one: the suites that run first on the same
            # database (the weekly sweeps) can leave only a RESERVE, and the control below needs a
            # transition that is legal from whatever status the fixture holds.
            cur.execute("SELECT token_id, status FROM IdentityToken WHERE status IN ('ACTIVE', 'RESERVE') "
                        "ORDER BY (status = 'ACTIVE') DESC, token_id LIMIT 1")
            row = cur.fetchone()
            tid, status = row["token_id"], row["status"]
            cur.execute("SELECT min(individual_id) AS other FROM Individual WHERE individual_id <> "
                        "(SELECT individual_id FROM IdentityToken WHERE token_id = %s)", (tid,))
            other = cur.fetchone()["other"]
        conn.rollback()
        attempts = (
            ("move it to another person", "UPDATE IdentityToken SET individual_id = %s WHERE token_id = %s", (other, tid)),
            ("extend it", "UPDATE IdentityToken SET expiration_date = DATE '2099-01-01' WHERE token_id = %s", (tid,)),
            ("rewrite its value", "UPDATE IdentityToken SET token_value = token_value || 'x' WHERE token_id = %s", (tid,)),
            ("change its issuer", "UPDATE IdentityToken SET issuing_agency_id = issuing_agency_id + 1 WHERE token_id = %s", (tid,)),
            # Whichever way round, so the write changes the row whatever the fixture holds.
            ("set or clear its duress code", "UPDATE IdentityToken SET duress_code_hash = CASE WHEN "
                                             "duress_code_hash IS NULL THEN 'x' ELSE NULL END WHERE token_id = %s", (tid,)),
            # COALESCE: a RESERVE has no activated_date, and NULL + 1 hour changes nothing.
            ("re-date its activation", "UPDATE IdentityToken SET activated_date = "
                                        "COALESCE(activated_date, CURRENT_TIMESTAMP) + interval '1 hour' "
                                        "WHERE token_id = %s", (tid,)),
        )
        for label, sql, args in attempts:
            with self.subTest(label), conn.cursor() as cur:
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute(sql, args)
            conn.rollback()
        # The application's own write still goes through: a legal transition, status alone
        # (with its activation date, the one column that may move with it).
        control = ("UPDATE IdentityToken SET status = 'LOST' WHERE token_id = %s" if status == "ACTIVE"
                   else "UPDATE IdentityToken SET status = 'ACTIVE', activated_date = CURRENT_TIMESTAMP "
                        "WHERE token_id = %s")
        with conn.cursor() as cur:
            cur.execute(control, (tid,))
            self.assertEqual(cur.rowcount, 1)
        conn.rollback()

    def test_app_role_sets_an_authority_key_only_from_the_register(self):
        """1.0.0-rc.57. Agency.signing_public_key_hex is the key the trust list serves as active and
        the key the exchange gateway authenticates an institution by. As polaris_app a plain
        UPDATE replaced it with a key the register had never seen. Refused now, as is a key the
        register holds as compromised; `polaris key-register` (log the key, then set it) works."""
        conn = self._app_conn()
        fresh, burnt = os.urandom(32).hex(), os.urandom(32).hex()
        with self.subTest("a key the register has never seen"), conn.cursor() as cur:
            with self.assertRaises(pg_errors.InsufficientPrivilege):
                cur.execute("UPDATE Agency SET signing_public_key_hex = %s WHERE agency_id = 1", (fresh,))
        conn.rollback()
        # Since 2026-09-27 the register is the owner's to append to, so the owner writes the
        # events and the UPDATE under test runs as polaris_app in the same transaction.
        owner = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        self.addCleanup(owner.close)
        with self.subTest("a key the register holds as compromised"), owner.cursor() as cur:
            for event in ("registered", "compromised"):
                cur.execute("INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, event) "
                            "VALUES (1, %s, %s)", (burnt, event))
            cur.execute("SET LOCAL ROLE polaris_app")
            with self.assertRaises(pg_errors.InsufficientPrivilege):
                cur.execute("UPDATE Agency SET signing_public_key_hex = %s WHERE agency_id = 1", (burnt,))
        owner.rollback()
        with self.subTest("the register's own path"), owner.cursor() as cur:
            cur.execute("INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, event) "
                        "VALUES (1, %s, 'registered')", (fresh,))
            cur.execute("SET LOCAL ROLE polaris_app")
            cur.execute("UPDATE Agency SET signing_public_key_hex = %s WHERE agency_id = 1", (fresh,))
            self.assertEqual(cur.rowcount, 1)
        owner.rollback()

    def test_app_role_cannot_revive_an_algorithm_or_grant_itself_one(self):
        """1.0.0-rc.58. Nothing the application runs writes the algorithm registry or the
        authorizations uc1, uc8 and uc_bulk_issue read. As polaris_app a plain UPDATE
        un-deprecated ECDSA-P256 and relabelled it quantum_resistant, and a row in
        AgencyAlgorithmAuth grants an authority the right to issue or co-sign. All refused."""
        conn = self._app_conn()
        attempts = (
            ("un-deprecate an algorithm", "UPDATE CryptographicAlgorithm SET deprecation_date = NULL WHERE false"),
            ("relabel an algorithm", "UPDATE CryptographicAlgorithm SET quantum_resistant = TRUE WHERE false"),
            ("add an algorithm", "INSERT INTO CryptographicAlgorithm (name) SELECT 'x' WHERE false"),
            ("grant an authorization", "INSERT INTO AgencyAlgorithmAuth (agency_id, algorithm_id, authorization_type) "
                                       "SELECT 1, 1, 'BOTH' WHERE false"),
            ("widen an authorization", "UPDATE AgencyAlgorithmAuth SET authorization_type = 'BOTH' WHERE false"),
            ("drop an authorization", "DELETE FROM AgencyAlgorithmAuth WHERE false"),
        )
        for label, sql in attempts:
            with self.subTest(label), conn.cursor() as cur:
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute(sql)
            conn.rollback()

    def test_app_role_cannot_lower_a_proof_policy(self):
        """1.0.0-rc.59. VerificationContext carries the proof policy an authority signs into its
        registry. Nothing the application runs writes it; as polaris_app a plain UPDATE lowered
        a context's requirements. All writes refused."""
        conn = self._app_conn()
        attempts = (
            ("drop the biometric requirement", "UPDATE VerificationContext SET requires_biometric = FALSE WHERE false"),
            ("lower the security level", "UPDATE VerificationContext SET min_security_level = 1 WHERE false"),
            ("add a context", "INSERT INTO VerificationContext (context_type) SELECT 'x' WHERE false"),
            ("delete a context", "DELETE FROM VerificationContext WHERE false"),
        )
        for label, sql in attempts:
            with self.subTest(label), conn.cursor() as cur:
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute(sql)
            conn.rollback()

    def test_a_recovery_completes_through_the_product_alone(self):
        """1.0.0-rc.60. Since rc.54 the application role cannot UPDATE RecoveryRequest, and no path
        in the product recorded the three out-of-band channels, so no recovery could reach
        APPROVED without the schema owner. uc9_record_recovery_channel is that path. Here the
        whole ceremony after initiation runs as polaris_app: the three channels, then the
        approval. The fixture (an aged PENDING request, a witness bound to another authority) is
        written as the owner."""
        import secrets
        owner = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        tag = secrets.token_hex(4)
        try:
            with owner, owner.cursor() as cur:
                cur.execute("SELECT user_id FROM AppUser WHERE username = 'admin'")
                admin = cur.fetchone()["user_id"]
                cur.execute("SELECT user_id FROM AppUser WHERE username = 'operator'")
                operator = cur.fetchone()["user_id"]
                cur.execute("SELECT set_config('polaris.justification', "
                            "'rc.60 fixture: a witness and a same-authority operator', true)")
                cur.execute("INSERT INTO AppUser (username, password_hash, role, agency_id) "
                            "VALUES (%s, 'x', 'operator', 2) RETURNING user_id", ("witness-" + tag,))
                witness = cur.fetchone()["user_id"]
                cur.execute("INSERT INTO AppUser (username, password_hash, role, agency_id) "
                            "VALUES (%s, 'x', 'operator', 1) RETURNING user_id", ("samewit-" + tag,))
                same_agency = cur.fetchone()["user_id"]
                cur.execute("INSERT INTO Individual (legal_name, date_of_birth, jurisdiction) "
                            "VALUES (%s, '1990-01-01', 'US-PA') RETURNING individual_id", ("RC60 " + tag,))
                ind = cur.fetchone()["individual_id"]
                cur.execute("INSERT INTO RecoveryRequest (claimed_individual_id, requested_at, "
                            "requesting_agency_id, requesting_user_id, cooldown_expires_at) VALUES "
                            "(%s, now() - interval '50 hours', 1, %s, now() - interval '2 hours') "
                            "RETURNING recovery_id", (ind, operator))
                rid = cur.fetchone()["recovery_id"]
        finally:
            owner.close()

        app = self._app_conn()
        rec = "CALL uc9_record_recovery_channel(%s, %s, %s, %s)"
        refusals = (
            ("the requester records a channel", (rid, operator, "BIOMETRIC", None), pg_errors.InsufficientPrivilege),
            ("an auditor records a channel", (rid, 3, "BIOMETRIC", None), pg_errors.InsufficientPrivilege),
            ("a witness from the requesting authority", (rid, same_agency, "WITNESS", None), pg_errors.InsufficientPrivilege),
            ("a sworn statement that is not a SHA-256", (rid, admin, "SWORN", "not-a-hash"), pg_errors.CheckViolation),
        )
        for label, args, err in refusals:
            with self.subTest(label), app.cursor() as cur:
                with self.assertRaises(err):
                    cur.execute(rec, args)
            app.rollback()

        with app.cursor() as cur:
            cur.execute(rec, (rid, admin, "BIOMETRIC", None))
            cur.execute(rec, (rid, admin, "SWORN", "ab" * 32))
            cur.execute(rec, (rid, witness, "WITNESS", None))
        app.commit()
        with self.subTest("a channel is recorded once"), app.cursor() as cur:
            with self.assertRaises(pg_errors.CheckViolation):
                cur.execute(rec, (rid, admin, "BIOMETRIC", None))
        app.rollback()

        with app.cursor() as cur:
            import pqc_signing
            signature = pqc_signing.credential_signature("TKN-RC60-" + tag, agency_id=1)
            cur.execute("CALL uc9_complete_recovery(%s, %s, 'APPROVED', 'rc.60 product path', %s, %s, 1, "
                        "'IRIS', 'MULTI_MODAL', %s, %s, %s)",
                        (rid, admin, "TKN-RC60-" + tag, "SN-RC60-" + tag, "https://crl.example/" + tag,
                         psycopg2.Binary(signature.signature_bytes), signature.public_key_hex))
            cur.execute("SELECT status, biometric_recorded_by, sworn_recorded_by, witness_agency_id, "
                        "witness_co_sign_user_id FROM RecoveryRequest WHERE recovery_id = %s", (rid,))
            row = cur.fetchone()
        app.commit()
        self.assertEqual(row["status"], "APPROVED", "the ceremony must complete through the product alone")
        self.assertEqual((row["biometric_recorded_by"], row["sworn_recorded_by"]), (admin, admin))
        self.assertEqual((row["witness_agency_id"], row["witness_co_sign_user_id"]), (2, witness))

        with self.subTest("nothing is recorded after the decision"), app.cursor() as cur:
            with self.assertRaises(pg_errors.CheckViolation):
                cur.execute(rec, (rid, admin, "SWORN", "cd" * 32))
        app.rollback()
        app.close()

    def test_a_recovery_without_standing_is_witnessed_by_the_original_issuer(self):
        """2026-10-05, THREAT-MODEL. The requesting authority was tied to nothing about the person
        and the witness only had to be another authority, so two authorities could recover a
        credential for a person neither ever issued to. Now a requester without standing (not
        the original issuer, not a public authority of the person's jurisdiction or country)
        needs a witness bound to the original issuer. Runs as polaris_app; fixtures as the owner."""
        import secrets
        owner = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        tag = secrets.token_hex(4)
        try:
            with owner, owner.cursor() as cur:
                cur.execute("SELECT user_id FROM AppUser WHERE username = 'operator'")
                operator = cur.fetchone()["user_id"]
                # A person with credentials, no pending recovery, and an original issuer that is
                # not the bank (agency 5, PRIVATE: never standing by jurisdiction).
                cur.execute("""
                    SELECT i.individual_id, (SELECT t.issuing_agency_id FROM IdentityToken t
                                              WHERE t.individual_id = i.individual_id
                                              ORDER BY t.issued_date DESC, t.token_id DESC LIMIT 1) AS original
                      FROM Individual i
                     WHERE EXISTS (SELECT 1 FROM IdentityToken t WHERE t.individual_id = i.individual_id)
                       AND NOT EXISTS (SELECT 1 FROM RecoveryRequest r
                                        WHERE r.claimed_individual_id = i.individual_id
                                          AND r.status = 'PENDING')
                     ORDER BY i.individual_id LIMIT 50""")
                person = next(r for r in cur.fetchall() if r["original"] != 5)
                original = person["original"]
                stranger_agency = next(a for a in (1, 2, 3, 4, 6) if a != original)
                cur.execute("SELECT set_config('polaris.justification', "
                            "'UC-9 standing fixture: witnesses bound to named authorities', true)")
                witnesses = {}
                for agency in {original, stranger_agency, 2, 3, 6}:
                    cur.execute("INSERT INTO AppUser (username, password_hash, role, agency_id) "
                                "VALUES (%s, 'x', 'operator', %s) RETURNING user_id",
                                ("std%d-%s" % (agency, tag), agency))
                    witnesses[agency] = cur.fetchone()["user_id"]
                cur.execute("INSERT INTO Individual (legal_name, date_of_birth, jurisdiction) "
                            "VALUES (%s, '1990-01-01', 'US-PA') RETURNING individual_id", ("STD " + tag,))
                tokenless = cur.fetchone()["individual_id"]

                def request(individual, agency):
                    cur.execute("INSERT INTO RecoveryRequest (claimed_individual_id, requested_at, "
                                "requesting_agency_id, requesting_user_id, cooldown_expires_at) VALUES "
                                "(%s, now() - interval '50 hours', %s, %s, now() - interval '2 hours') "
                                "RETURNING recovery_id", (individual, agency, operator))
                    return cur.fetchone()["recovery_id"]
                by_bank = request(person["individual_id"], 5)
                by_california = request(tokenless, 3)
        finally:
            owner.close()

        app = self._app_conn()
        rec = "CALL uc9_record_recovery_channel(%s, %s, %s, %s)"
        refusals = (
            ("no standing, a third authority witnesses", (by_bank, witnesses[stranger_agency]), "original issuer"),
            ("no standing, no credential ever issued", (by_california, witnesses[6]), "no credential was ever issued"),
        )
        for label, (rid, witness), words in refusals:
            with self.subTest(label), app.cursor() as cur:
                with self.assertRaises(pg_errors.InsufficientPrivilege) as c:
                    cur.execute(rec, (rid, witness, "WITNESS", None))
                self.assertIn(words, str(c.exception))
            app.rollback()

        with app.cursor() as cur:
            cur.execute(rec, (by_bank, witnesses[original], "WITNESS", None))
            cur.execute("SELECT witness_agency_id FROM RecoveryRequest WHERE recovery_id = %s", (by_bank,))
            self.assertEqual(cur.fetchone()["witness_agency_id"], original,
                             "the original issuer witnesses a request made without standing")
        app.commit()

        # Standing by jurisdiction: Pennsylvania requests for a Pennsylvanian, California witnesses.
        owner = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        try:
            with owner, owner.cursor() as cur:
                cur.execute("SELECT set_config('polaris.justification', 'UC-9 standing fixture', true)")
                cur.execute("UPDATE RecoveryRequest SET status = 'REJECTED', decided_at = now(), "
                            "decided_by_user_id = (SELECT user_id FROM AppUser WHERE username = 'admin'), "
                            "decision_reason = 'fixture' WHERE recovery_id = %s", (by_california,))
                cur.execute("INSERT INTO RecoveryRequest (claimed_individual_id, requested_at, "
                            "requesting_agency_id, requesting_user_id, cooldown_expires_at) VALUES "
                            "(%s, now() - interval '50 hours', 2, %s, now() - interval '2 hours') "
                            "RETURNING recovery_id", (tokenless, operator))
                by_pennsylvania = cur.fetchone()["recovery_id"]
        finally:
            owner.close()
        with app.cursor() as cur:
            cur.execute(rec, (by_pennsylvania, witnesses[3], "WITNESS", None))
        app.commit()
        app.close()

    def test_each_recovery_channel_refusal_is_its_own(self):
        """1.0.0-rc.60, written after the procedure mutation drill found five refusals that could be
        deleted with the ceremony test still green. Each case here reaches exactly one refusal:
        a request that does not exist, a request already decided (with no channel recorded, so
        no once-only refusal answers first), a second sworn statement and a second witness (an
        overwritten statement hash before the decision would be a silent substitution), and an
        unknown channel. With any one of those refusals deleted, the call returns silently."""
        import secrets
        owner = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        tag = secrets.token_hex(4)
        try:
            with owner, owner.cursor() as cur:
                cur.execute("SELECT user_id FROM AppUser WHERE username = 'admin'")
                admin = cur.fetchone()["user_id"]
                cur.execute("SELECT user_id FROM AppUser WHERE username = 'operator'")
                operator = cur.fetchone()["user_id"]
                cur.execute("SELECT set_config('polaris.justification', "
                            "'rc.60 fixture: witnesses bound to another authority', true)")
                cur.execute("INSERT INTO AppUser (username, password_hash, role, agency_id) "
                            "VALUES (%s, 'x', 'operator', 2) RETURNING user_id", ("wit1-" + tag,))
                witness = cur.fetchone()["user_id"]
                cur.execute("INSERT INTO AppUser (username, password_hash, role, agency_id) "
                            "VALUES (%s, 'x', 'operator', 3) RETURNING user_id", ("wit2-" + tag,))
                witness2 = cur.fetchone()["user_id"]
                rids = []
                for k in range(2):
                    cur.execute("INSERT INTO Individual (legal_name, date_of_birth, jurisdiction) "
                                "VALUES (%s, '1990-01-01', 'US-PA') RETURNING individual_id",
                                ("RC60b %s %d" % (tag, k),))
                    ind = cur.fetchone()["individual_id"]
                    cur.execute("INSERT INTO RecoveryRequest (claimed_individual_id, requested_at, "
                                "requesting_agency_id, requesting_user_id, cooldown_expires_at) VALUES "
                                "(%s, now() - interval '50 hours', 1, %s, now() - interval '2 hours') "
                                "RETURNING recovery_id", (ind, operator))
                    rids.append(cur.fetchone()["recovery_id"])
                open_rid, decided_rid = rids
                cur.execute("UPDATE RecoveryRequest SET status = 'REJECTED', decided_at = now(), "
                            "decided_by_user_id = %s, decision_reason = 'fixture' WHERE recovery_id = %s",
                            (admin, decided_rid))
        finally:
            owner.close()

        app = self._app_conn()
        rec = "CALL uc9_record_recovery_channel(%s, %s, %s, %s)"
        with app.cursor() as cur:
            cur.execute(rec, (open_rid, admin, "SWORN", "ab" * 32))
            cur.execute(rec, (open_rid, witness, "WITNESS", None))
        app.commit()
        cases = (
            ("a request that does not exist", (2 ** 31 - 1, admin, "BIOMETRIC", None), pg_errors.RaiseException),
            ("a request already decided", (decided_rid, admin, "BIOMETRIC", None), pg_errors.CheckViolation),
            ("a second sworn statement", (open_rid, admin, "SWORN", "cd" * 32), pg_errors.CheckViolation),
            ("a second witness", (open_rid, witness2, "WITNESS", None), pg_errors.CheckViolation),
            ("an unknown channel", (open_rid, admin, "FINGERPRINT", None), pg_errors.RaiseException),
        )
        for label, args, err in cases:
            with self.subTest(label), app.cursor() as cur:
                with self.assertRaises(err):
                    cur.execute(rec, args)
            app.rollback()
        with app.cursor() as cur:
            cur.execute("SELECT sworn_statement_hash, witness_co_sign_user_id FROM RecoveryRequest "
                        "WHERE recovery_id = %s", (open_rid,))
            row = cur.fetchone()
        app.rollback(); app.close()
        self.assertEqual((row["sworn_statement_hash"], row["witness_co_sign_user_id"]), ("ab" * 32, witness),
                         "a recorded channel was overwritten")

    def test_app_role_cannot_rewrite_the_constitution_athena_shows(self):
        """1.0.0-rc.61. The /athena console shows each of C1-C10, the mechanism that enforces it,
        and the key custody, from three tables 16_athena.sql writes as the owner. It loads after
        09_grants.sql, so the default privileges gave polaris_app write access, and one UPDATE made
        the console say C2 is enforced by "nothing". All writes refused; the console still reads."""
        conn = self._app_conn()
        attempts = (
            ("unenforce a rule", "UPDATE athena_rule_enforcement SET mechanism_name = 'nothing' "
                                 "WHERE rule_code = 'C2'"),
            ("drop an enforcement", "DELETE FROM athena_rule_enforcement WHERE rule_code = 'C2'"),
            ("rewrite a rule", "UPDATE athena_constitutional_rule SET statement = 'x' WHERE rule_code = 'C2'"),
            ("add a rule", "INSERT INTO athena_constitutional_rule (rule_code, title, statement, kind, "
                           "source_ref) VALUES ('C11', 'x', 'x', 'CONSTRAINT', 'x')"),
            ("delete a rule", "DELETE FROM athena_constitutional_rule WHERE rule_code = 'C10'"),
            ("relabel custody", "UPDATE athena_key_custody SET is_hardware = TRUE"),
            ("add custody", "INSERT INTO athena_key_custody (driver, label, is_hardware, source_ref) "
                            "VALUES ('x', 'x', TRUE, 'x')"),
            ("delete custody", "DELETE FROM athena_key_custody"),
        )
        for label, sql in attempts:
            with self.subTest(label), conn.cursor() as cur:
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute(sql)
            conn.rollback()
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM athena_rule_enforcement WHERE rule_code = 'C2' "
                        "AND mechanism_name <> 'nothing'")
            self.assertGreater(list(cur.fetchone().values())[0], 0, "the console still reads the map")
        conn.rollback()

    def test_app_role_revokes_only_through_uc8(self):
        """2026-09-26. The refusals drill: without trg_enforce_revocation_velocity's refusal, the
        application role could set status = 'REVOKED' directly, around uc8_revoke_token's rate
        bound and co-signer rule; nothing in the fast suites noticed."""
        conn = self._app_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT token_id FROM IdentityToken WHERE status IN ('ACTIVE', 'RESERVE') "
                        "ORDER BY token_id LIMIT 1")
            tok = cur.fetchone()["token_id"]
            with self.assertRaisesRegex(psycopg2.Error, "Use uc8_revoke_token"):
                cur.execute("UPDATE IdentityToken SET status = 'REVOKED' WHERE token_id = %s", (tok,))
        conn.rollback()

    def test_app_role_cannot_grant_itself_an_account(self):
        """2026-09-27 (owner-directed). With table-wide INSERT and UPDATE on AppUser the
        application role could create an admin, raise its own account to admin, or reset the
        admin's password. It keeps only the lockout columns the web application maintains."""
        conn = self._app_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('polaris.justification', %s, true)",
                        ("a justification of the required length, for this test",))
        for label, sql in (
                ("create an admin", "INSERT INTO AppUser (username, password_hash, role) "
                                    "VALUES ('forged_admin', 'x', 'admin')"),
                ("raise a role", "UPDATE AppUser SET role = 'admin' WHERE username = 'operator'"),
                ("reset a password", "UPDATE AppUser SET password_hash = 'x' WHERE username = 'admin'"),
                ("reactivate", "UPDATE AppUser SET is_active = TRUE WHERE false"),
                ("delete", "DELETE FROM AppUser WHERE false")):
            with self.subTest(label), conn.cursor() as cur:
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute(sql)
            conn.rollback()
        # The web application's own write still goes through.
        with conn.cursor() as cur:
            cur.execute("UPDATE AppUser SET failed_login_count = failed_login_count "
                        "WHERE username = 'admin'")
            self.assertEqual(cur.rowcount, 1)
        conn.rollback()

    def test_app_role_cannot_write_keys_cards_or_retention(self):
        """2026-09-27. As polaris_app: a registered key for an attacker, then made authority 1's
        signing key; an attacker's keys bound to an ACTIVE credential's card record; a retention
        policy attributed to an operator, around uc_set_retention_policy's admin check."""
        conn = self._app_conn()
        key = "ab" * 976
        for label, sql, params in (
                ("register a key", "INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, event) "
                                   "VALUES (1, %s, 'registered')", (key,)),
                ("bind card keys", "INSERT INTO CardPersonalization (token_id, issuing_agency_id, "
                                   "credential_ref, profile_version, normal_public_key, "
                                   "duress_public_key, card_object_sha3_256) SELECT token_id, "
                                   "issuing_agency_id, %s, 1, %s, %s, %s FROM IdentityToken "
                                   "WHERE status = 'ACTIVE' LIMIT 1",
                 (psycopg2.Binary(b"\xdd" * 32), psycopg2.Binary(b"\xaa" * 65),
                  psycopg2.Binary(b"\xbb" * 65), psycopg2.Binary(b"\xcc" * 32))),
                ("write a retention policy", "INSERT INTO RetentionPolicy (table_class, jurisdiction, "
                                             "retention_days, justification, set_by_user_id) "
                                             "SELECT 'VERIFICATION', 'APP-ROLE', 365, "
                                             "'written around the admin-only procedure', user_id "
                                             "FROM AppUser WHERE role <> 'admin' LIMIT 1", None)):
            with self.subTest(label), conn.cursor() as cur:
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute(sql, params)
            conn.rollback()
        # The rc.57 guard still refuses a key the register does not hold, so the circle is closed.
        with conn.cursor() as cur:
            with self.assertRaises(psycopg2.Error):
                cur.execute("UPDATE Agency SET signing_public_key_hex = %s WHERE agency_id = 1", (key,))
        conn.rollback()

    def test_app_role_cannot_run_the_retention_routines(self):
        """2026-10-01 (review F2). The definer grant loop lends every routine to polaris_app, and
        the retention routines take the acting admin as a parameter, which the role can name at
        will: as polaris_app, uc_set_retention_policy recorded a policy under an admin it was not.
        No route calls them; the CLI and scripts/polaris-purge.sh run them as the schema owner."""
        owner = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        self.addCleanup(owner.close)
        with owner.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE role = 'admin' ORDER BY user_id LIMIT 1")
            admin = cur.fetchone()["user_id"]
        conn = self._app_conn()
        for label, sql, params in (
                ("set a retention policy",
                 "CALL uc_set_retention_policy(%s, %s, %s, %s, %s, NULL, NULL)",
                 ("VERIFICATION", "APP-ROLE", 4000, "an admin the application named, not one who acted", admin)),
                ("apply a retention template",
                 "CALL uc_apply_retention_template(%s, %s, %s)", ("MINIMIZED", "APP-ROLE", admin)),
                ("purge the audit of record",
                 "CALL uc_archive_purge(p_cutoff_timestamp := %s::timestamptz, p_archive_uri := %s, "
                 "p_archive_sha256 := %s, p_actor_user_id := %s)",
                 ("1900-01-01T00:00:00Z", "file:///dev/null", "0" * 64, admin))):
            with self.subTest(label), conn.cursor() as cur:
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute(sql, params)
            conn.rollback()

    def test_the_app_role_writes_holder_key_events_only_through_the_routine(self):
        """2026-10-01, contract migration 2026-10-01-003: a direct INSERT is refused."""
        owner = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        self.addCleanup(owner.close)
        with owner.cursor() as cur:
            cur.execute("SELECT token_id FROM IdentityToken WHERE status = 'ACTIVE' ORDER BY token_id LIMIT 1")
            tid = cur.fetchone()["token_id"]
        conn = self._app_conn()
        try:
            with conn.cursor() as cur:
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute("INSERT INTO HolderKeyEvent (token_id, public_key_hex, event) "
                                "VALUES (%s, %s, 'bound')", (tid, "c3" * 40))
        finally:
            conn.rollback()

    def test_the_holder_key_routine_keeps_events_in_order(self):
        """2026-10-01 (review S2). The holder key route records events through
        uc_record_holder_key_event, run here as polaris_app: it sets the instant and holds bound /
        rotated / revoked in order for a live credential."""
        owner = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        self.addCleanup(owner.close)
        with owner.cursor() as cur:
            cur.execute("SELECT token_id FROM IdentityToken t WHERE status = 'ACTIVE' AND NOT EXISTS "
                        "(SELECT 1 FROM HolderKeyEvent h WHERE h.token_id = t.token_id) ORDER BY token_id LIMIT 1")
            tid = cur.fetchone()["token_id"]
            cur.execute("SELECT token_id FROM IdentityToken WHERE status <> 'ACTIVE' ORDER BY token_id LIMIT 1")
            dead = cur.fetchone()["token_id"]
        k1, k2 = "a1" * 40, "b2" * 40
        conn = self._app_conn()
        try:
            with conn.cursor() as cur:
                for label, args in (("rotate a key never bound", (tid, k2, 'ML-DSA-65', 'rotated')),
                                    ("revoke a key never bound", (tid, k1, 'ML-DSA-65', 'revoked')),
                                    ("bind to a credential that is not live", (dead, k1, 'ML-DSA-65', 'bound')),
                                    ("an event the register does not know", (tid, k1, 'ML-DSA-65', 'transferred'))):
                    with self.subTest(label):
                        cur.execute("SAVEPOINT s")
                        with self.assertRaises(pg_errors.CheckViolation):
                            cur.execute("SELECT uc_record_holder_key_event(%s, %s, %s, %s)", args)
                        cur.execute("ROLLBACK TO SAVEPOINT s")
                cur.execute("SELECT uc_record_holder_key_event(%s, %s, 'ML-DSA-65', 'bound')", (tid, k1))
                cur.execute("SELECT effective_at <= CURRENT_TIMESTAMP AS now FROM HolderKeyEvent "
                            "WHERE token_id = %s AND public_key_hex = %s", (tid, k1))
                self.assertTrue(cur.fetchone()["now"], "the routine records the first binding, in force now")
                # 2026-10-02 (review S1): pass the signer so each case reaches the guard it means to test
                # (bind-over hits the already-bound guard; revoke-not-live, signed by the live k1, hits the
                # names-the-live-key guard) rather than the new signer-under-lock guard.
                for label, args in (("bind over the live key", (tid, k2, 'ML-DSA-65', 'bound', None)),
                                    ("revoke a key that is not the live one", (tid, k2, 'ML-DSA-65', 'revoked', k1))):
                    with self.subTest(label):
                        cur.execute("SAVEPOINT s")
                        with self.assertRaises(pg_errors.CheckViolation):
                            cur.execute("SELECT uc_record_holder_key_event(%s, %s, %s, %s, %s)", args)
                        cur.execute("ROLLBACK TO SAVEPOINT s")
                # The signer is the key live at each step: k1 signs the rotation to k2, then k2 (now live)
                # signs its own revocation (review S1).
                cur.execute("SELECT uc_record_holder_key_event(%s, %s, 'ML-DSA-65', 'rotated', %s)", (tid, k2, k1))
                cur.execute("SELECT uc_record_holder_key_event(%s, %s, 'ML-DSA-65', 'revoked', %s)", (tid, k2, k2))
                cur.execute("SELECT event FROM HolderKeyCurrent WHERE token_id = %s", (tid,))
                self.assertEqual(cur.fetchone()["event"], "revoked", "rotate then revoke, in order")
        finally:
            conn.rollback()

    def test_a_rotation_signed_by_a_superseded_key_is_refused(self):
        """2026-10-02 (review S1, High): the read-before-lock rotation race. The route verifies
        change_proof against the live key it read, then uc_record_holder_key_event confirms, under the
        per-token lock, that that signer is still the live key. A rotation signed by a key a concurrent
        rotation has already replaced (a stolen-but-still-live key racing the holder's own) is refused,
        so it cannot append a second change over a stale key. On the pre-fix procedure, which checked
        only that some key was live, this rotation succeeded."""
        owner = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        self.addCleanup(owner.close)
        with owner.cursor() as cur:
            cur.execute("SELECT token_id FROM IdentityToken t WHERE status = 'ACTIVE' AND NOT EXISTS "
                        "(SELECT 1 FROM HolderKeyEvent h WHERE h.token_id = t.token_id) ORDER BY token_id LIMIT 1")
            tid = cur.fetchone()["token_id"]
        k1, k2, k3 = "a1" * 40, "b2" * 40, "c3" * 40
        conn = self._app_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT uc_record_holder_key_event(%s, %s, 'ML-DSA-65', 'bound', NULL)", (tid, k1))
                # The holder rotates k1 -> k2, signed by the live key k1. k2 is now the live key.
                cur.execute("SELECT uc_record_holder_key_event(%s, %s, 'ML-DSA-65', 'rotated', %s)", (tid, k2, k1))
                # A second rotation still signed by k1, now superseded, must be refused under the lock.
                cur.execute("SAVEPOINT s")
                with self.assertRaises(pg_errors.CheckViolation):
                    cur.execute("SELECT uc_record_holder_key_event(%s, %s, 'ML-DSA-65', 'rotated', %s)", (tid, k3, k1))
                cur.execute("ROLLBACK TO SAVEPOINT s")
                # The live key is the holder's k2, not the stale-signed k3.
                cur.execute("SELECT public_key_hex FROM HolderKeyCurrent WHERE token_id = %s", (tid,))
                self.assertEqual(cur.fetchone()["public_key_hex"], k2,
                                 "a rotation signed by a superseded key leaves the live key unchanged")
        finally:
            conn.rollback()

    def test_app_role_cannot_rewrite_a_relying_party(self):
        """2026-09-27. As polaris_app, writing its own justification, a zero-knowledge-only
        relying party was made full-disclosure and its client secret replaced with one the
        attacker knew. Registration and policy are the owner's; last_used_at stays writable."""
        owner = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        self.addCleanup(owner.close)
        with owner.cursor() as cur:
            cur.execute("SELECT set_config('polaris.justification', %s, true)",
                        ("a zero-knowledge-only relying party for this test",))
            cur.execute("INSERT INTO RelyingParty (client_id, client_secret_hash, org_name, scope, "
                        "require_zk) VALUES ('rp_' || md5(random()::text), 'owner-hash', 'ZK only', "
                        "'verify authenticate', TRUE) RETURNING client_id")
            cid = cur.fetchone()["client_id"]
            cur.execute("SET LOCAL ROLE polaris_app")
            cur.execute("SELECT set_config('polaris.justification', %s, true)",
                        ("the application writing its own justification text",))
            for label, sql in (
                    ("drop the zero-knowledge requirement",
                     "UPDATE RelyingParty SET require_zk = FALSE WHERE client_id = %s"),
                    ("replace the client secret",
                     "UPDATE RelyingParty SET client_secret_hash = 'attacker' WHERE client_id = %s"),
                    ("widen the scope",
                     "UPDATE RelyingParty SET scope = 'verify authenticate', enabled = TRUE WHERE client_id = %s"),
                    ("register a party",
                     "INSERT INTO RelyingParty (client_id, client_secret_hash, org_name) "
                     "SELECT %s || 'x', 'x', 'Forged'"),
                    ("remove a party", "DELETE FROM RelyingParty WHERE client_id = %s")):
                with self.subTest(label):
                    cur.execute("SAVEPOINT s")
                    with self.assertRaises(pg_errors.InsufficientPrivilege):
                        cur.execute(sql, (cid,))
                    cur.execute("ROLLBACK TO SAVEPOINT s")
            # The web application's own write still goes through.
            cur.execute("UPDATE RelyingParty SET last_used_at = now() WHERE client_id = %s", (cid,))
            self.assertEqual(cur.rowcount, 1)
        owner.rollback()

    def test_app_role_cannot_choose_its_own_bounds(self):
        """2026-09-26. As polaris_app, authority 1's revocation bound was superseded and reset to
        100% a day, under which uc8 never asks for a co-signer. All writes to both bounds refused."""
        conn = self._app_conn()
        for label, sql in (
                ("supersede the revocation bound", "UPDATE IssuerDiscretionPolicy SET superseded_at = now() WHERE false"),
                ("set a new one", "INSERT INTO IssuerDiscretionPolicy (agency_id, max_revoke_percent, window_days, "
                                  "set_by_admin, justification) SELECT 1, 100, 1, 'x', repeat('x', 20) WHERE false"),
                ("supersede a quota", "UPDATE AgencyQuota SET superseded_at = now() WHERE false"),
                ("set a new quota", "INSERT INTO AgencyQuota (agency_id, set_by_admin, justification) "
                                    "SELECT 1, 'x', repeat('x', 20) WHERE false"),
                ("delete", "DELETE FROM IssuerDiscretionPolicy WHERE false")):
            with self.subTest(label), conn.cursor() as cur:
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute(sql)
            conn.rollback()

    def test_app_role_cannot_assert_a_proofing_level(self):
        """2026-09-26. "The level is derived, never asserted." Nothing the application runs writes
        the proofing records; as polaris_app an IAL2 proofing resting on no evidence was recorded.
        All writes refused, to both tables."""
        conn = self._app_conn()
        for label, sql in (
                ("proofing", "INSERT INTO EnrollmentProofing (individual_id, recorded_by_agency_id, "
                             "presence, derived_ial) SELECT 1, 1, 'REMOTE_UNSUPERVISED', 'IAL2' WHERE false"),
                ("evidence", "INSERT INTO EnrollmentEvidence (proofing_id, evidence_type, strength, "
                             "validation_method, verification_method) SELECT 1, 'PASSPORT', 'STRONG', "
                             "'NONE', 'NONE' WHERE false"),
                ("update", "UPDATE EnrollmentProofing SET derived_ial = 'IAL2' WHERE false"),
                ("delete", "DELETE FROM EnrollmentEvidence WHERE false")):
            with self.subTest(label), conn.cursor() as cur:
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute(sql)
            conn.rollback()

    def test_app_role_cannot_record_a_vouching(self):
        """2026-09-26. Nothing the application runs writes RefereeVouching; with INSERT the
        application role recorded 26 vouchings by an unproofed referee. All writes refused."""
        conn = self._app_conn()
        for label, sql in (
                ("insert", "INSERT INTO RefereeVouching (proofing_id, referee_individual_id, "
                           "applicant_individual_id, referee_ial, relationship, vouched_ial) "
                           "SELECT 1, 1, 2, 'IAL2', 'NOTARY', 'IAL1' WHERE false"),
                ("update", "UPDATE RefereeVouching SET vouched_ial = 'IAL1' WHERE false"),
                ("delete", "DELETE FROM RefereeVouching WHERE false")):
            with self.subTest(label), conn.cursor() as cur:
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute(sql)
            conn.rollback()

    def test_app_role_cannot_mark_a_migration_applied(self):
        """1.0.0-rc.62. polaris-migrate.sh decides a migration is applied by the last event in
        schema_version, and polaris_app held INSERT on it: one row naming a pending migration, with
        the file's public SHA-256, and the next upgrade skips it. Only the migrator (the owner)
        writes the registry; the application may still read it."""
        conn = self._app_conn()
        attempts = (
            ("forge an apply", "INSERT INTO schema_version (name, event_type, actor_user_id, file_sha256) "
                               "VALUES ('2099-12-31-001-a-pending-fix', 'applied', NULL, repeat('a', 64))"),
            ("forge a revert", "INSERT INTO schema_version (name, event_type, actor_user_id, file_sha256) "
                               "SELECT name, 'reverted', NULL, file_sha256 FROM schema_version LIMIT 1"),
            ("rewrite", "UPDATE schema_version SET event_type = 'applied' WHERE false"),
            ("delete", "DELETE FROM schema_version WHERE false"),
        )
        for label, sql in attempts:
            with self.subTest(label), conn.cursor() as cur:
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute(sql)
            conn.rollback()
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM schema_version")
            self.assertIsNotNone(cur.fetchone(), "the application still reads the registry")
        conn.rollback()

    def test_app_role_writes_an_epoch_only_through_uc11(self):
        """2026-09-25. With INSERT on TokenStateEpoch the application role could write an epoch
        uc11_close_epoch refuses: one member, below the anonymity floor, or a committed_count
        (what the verifier reads as the anonymity set) its leaves do not bear out. The direct
        write is refused; the procedure is still callable and still refuses on its own terms."""
        conn = self._app_conn()
        with conn.cursor() as cur:
            with self.assertRaises(pg_errors.InsufficientPrivilege):
                cur.execute("INSERT INTO TokenStateEpoch (merkle_root, valid_from, valid_until, "
                            "committed_count, closed_at, closed_by_user_id) VALUES "
                            "(%s, now(), now() + interval '1 day', 20, now(), "
                            "(SELECT user_id FROM AppUser WHERE username = 'admin'))", ("ab" * 32,))
        conn.rollback()
        with conn.cursor() as cur:
            with self.assertRaises(pg_errors.InsufficientPrivilege):
                cur.execute("INSERT INTO TokenStateEpochLeaf (epoch_id, token_id, leaf_hash, proof_path) "
                            "VALUES (1, 1, %s, '[]'::jsonb)", ("cd" * 32,))
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE username = 'admin'")
            admin = cur.fetchone()["user_id"]
            with self.assertRaises(psycopg2.Error) as ctx:
                cur.execute("CALL uc11_close_epoch(%s, now()::timestamp + interval '1 day', %s, '[]'::jsonb)",
                            ("ef" * 32, admin))
            self.assertNotIsInstance(ctx.exception, pg_errors.InsufficientPrivilege,
                                     "the application role must still be able to call uc11_close_epoch")
            self.assertIn("empty epoch", str(ctx.exception))
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
        never an edit or a removal, and AuthorityKeyCurrent derives compromised > retired > active.
        The owner appends (the application role cannot, since 2026-09-27)."""
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        self.addCleanup(conn.close)
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
            cur.execute("SET LOCAL ROLE polaris_app")
            with self.assertRaises(pg_errors.InsufficientPrivilege):
                cur.execute("DELETE FROM AuthorityKeyEvent WHERE public_key_hex = %s", (key,))
        conn.rollback()

    def test_authority_key_register_accepts_only_the_ml_dsa_sets(self):
        """chk_authority_key_algorithm (2026-09-24): the registry publishes this value for
        relying parties to verify under, and until then only the CLI's choices kept a classical
        one out. As the owner, the register's only writer since 2026-09-27."""
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        self.addCleanup(conn.close)
        key = "cd" * 32
        with conn.cursor() as cur:
            with self.assertRaises(pg_errors.CheckViolation):
                cur.execute("INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, algorithm, event) "
                            "VALUES (1, %s, 'Ed25519', 'registered')", (key,))
        conn.rollback()
        with conn.cursor() as cur:
            for alg in ('ML-DSA-65', 'ML-DSA-87'):
                cur.execute("INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, algorithm, event) "
                            "VALUES (1, %s, %s, 'registered')", (key, alg))
        conn.rollback()

    def test_enrollment_evidence_values_carry_no_document_number(self):
        """chk_evidence_type_shape and chk_evidence_issuer_not_a_number (2026-09-24). As the owner:
        since 2026-09-26 the application role cannot write evidence at all, and the owner is the
        writer these CHECKs still bind."""
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        self.addCleanup(conn.close)
        ins = ("WITH p AS (%s) INSERT INTO EnrollmentEvidence (proofing_id, evidence_type, strength, "
               "validation_method, verification_method, issuing_authority_name, validated, verified) "
               "SELECT p.proofing_id, %%s, 'STRONG', 'VISUAL_INSPECTION', 'BIOMETRIC_COMPARISON', %%s, "
               "true, true FROM p" % _PROOFING)
        for kind, issuer in (("PASSPORT 123456789", None), ("PASSPORT", "Office 123456789")):
            with conn.cursor() as cur:
                with self.assertRaises(pg_errors.CheckViolation, msg=(kind, issuer)):
                    cur.execute(ins, (kind, issuer))
            conn.rollback()
        with conn.cursor() as cur:
            cur.execute(ins, ("DRIVING_LICENCE", "Department of State, 3rd Bureau"))
        conn.rollback()

    def test_the_change_records_accept_only_what_their_recorders_write(self):
        """1.0.0-rc.38. polaris_app holds INSERT on the three change records because the
        recorders run as the caller, and until then that let it append an event nothing did,
        attributed to any db_role it named. Measured: a rename of authority 1 'by' postgres."""
        conn = self._app_conn()
        forged = [
            "INSERT INTO AgencyEvent (agency_id, name, event_type, field, old_value, new_value, "
            "actor, db_role, justification) VALUES (1, 'x', 'RENAMED', 'name', 'A', 'B', "
            "'admin', 'postgres', 'forged')",
            "INSERT INTO AppUserEvent (user_id, username, event_type, field, db_role) "
            "VALUES (1, 'admin', 'RENAMED', 'username', 'postgres')",
            "INSERT INTO RelyingPartyEvent (rp_id, client_id, event_type, db_role, justification) "
            "VALUES (1, 'rp_forged', 'REGISTERED', 'postgres', 'forged')",
        ]
        for sql in forged:
            with conn.cursor() as cur:
                with self.assertRaises(pg_errors.InsufficientPrivilege, msg=sql[:30]) as ctx:
                    cur.execute(sql)
                self.assertIn("written only by the trigger", str(ctx.exception))
            conn.rollback()
        # The recorder still writes, and the attribution is the session's, not the writer's.
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('polaris.justification', 'rc.38 attribution probe', true)")
            cur.execute("UPDATE Agency SET name = name || ' (probe)' WHERE agency_id = 1")
            cur.execute("SELECT db_role FROM AgencyEvent WHERE agency_id = 1 "
                        "ORDER BY event_id DESC LIMIT 1")
            self.assertEqual(cur.fetchone()["db_role"], "polaris_app")
        conn.rollback()

    def test_the_application_cannot_set_a_persons_enrollment_status(self):
        """1.0.0-rc.39. Enrollment status is the latest EnrollmentStatusEvent, and a relying
        party's required_enrollment is decided on it at sign-in. Measured on rc.38: as
        polaris_app, one INSERT made a LAPSED person ENROLLED."""
        conn = self._app_conn()
        with conn.cursor() as cur:
            with self.assertRaises(pg_errors.InsufficientPrivilege) as ctx:
                cur.execute("INSERT INTO EnrollmentStatusEvent (individual_id, status, "
                            "transition_reason, recorded_by_agency_id) "
                            "VALUES (5, 'ENROLLED', 'forged', 1)")
            self.assertIn("written only by the trigger", str(ctx.exception))
        conn.rollback()
        # The recorder still writes: a person created by the application is seeded NOT_ENROLLED.
        with conn.cursor() as cur:
            cur.execute("INSERT INTO Individual (legal_name, date_of_birth, jurisdiction) "
                        "VALUES ('Enrollment Guard Probe', DATE '1990-01-01', 'US-PA') "
                        "RETURNING individual_id")
            iid = cur.fetchone()["individual_id"]
            cur.execute("SELECT current_status FROM IndividualCurrentEnrollment "
                        "WHERE individual_id = %s", (iid,))
            self.assertEqual(cur.fetchone()["current_status"], "NOT_ENROLLED")
        conn.rollback()

    def test_app_role_can_still_append_audit_rows(self):
        """The application records verifications itself, through the partitioned parent.
        (Until rc.40 this appended to TokenLifecycleEvent, which the application no longer
        writes directly; see the test below.)"""
        conn = self._app_conn()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO VerificationEvent (token_id, requesting_agency_id, context_id, outcome, "
                "disclosure_level) VALUES (NULL, 1, 1, 'SUCCESS', 'ZERO_KNOWLEDGE') RETURNING event_id")
            self.assertIsNotNone(cur.fetchone()["event_id"],
                                 "append-only must still permit INSERT through the parent")
        conn.rollback()

    def test_no_partition_of_an_audit_table_can_be_emptied(self):
        """1.0.0-rc.40. The UPDATE/DELETE revoke named the partitioned parents, and every
        partition kept the blanket grant. With the purge carve-out's setting, which any role
        can set, the trigger let a DELETE on a partition through. Measured on rc.39 as
        polaris_app: every row of all four event tables deleted."""
        conn = self._app_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid "
                        "JOIN pg_class p ON p.oid = i.inhparent WHERE p.relname IN "
                        "('tokenlifecycleevent', 'verificationevent', 'enrollmentstatusevent', "
                        "'authauditlog') ORDER BY 1")
            parts = [r["relname"] for r in cur.fetchall()]
        conn.rollback()
        self.assertGreaterEqual(len(parts), 8, "the partitions must exist for this to mean anything")
        for part in parts:
            for stmt in ("DELETE FROM %s" % part, "TRUNCATE %s" % part):
                with conn.cursor() as cur:
                    cur.execute("SELECT set_config('polaris.purge_in_progress', 'TRUE', true)")
                    with self.assertRaises(pg_errors.InsufficientPrivilege, msg=stmt):
                        cur.execute(stmt)
                conn.rollback()

    def test_the_application_cannot_append_a_lifecycle_event(self):
        """1.0.0-rc.40. TokenLifecycleEvent is written by uc1_issue_and_activate,
        uc5_bind_device, uc_bulk_issue and the audit_token_state_change trigger, all SECURITY
        DEFINER; polaris_app keeps SELECT only. The trigger still records a status change the
        application makes."""
        conn = self._app_conn()
        with conn.cursor() as cur:
            with self.assertRaises(pg_errors.InsufficientPrivilege):
                cur.execute("INSERT INTO TokenLifecycleEvent (token_id, event_type, event_timestamp, "
                            "reason_code) VALUES (1, 'REVOKED', now(), 'forged')")
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM TokenLifecycleEvent WHERE token_id = 1")
            before = cur.fetchone()["n"]
            cur.execute("UPDATE IdentityToken SET status = 'ACTIVE', activated_date = now() "
                        "WHERE token_id = 1 AND status = 'RESERVE'")
            self.assertEqual(cur.rowcount, 1, "fixture: token 1 is the sample RESERVE")
            cur.execute("SELECT count(*) AS n FROM TokenLifecycleEvent WHERE token_id = 1")
            self.assertEqual(cur.fetchone()["n"], before + 1, "the recorder must still write")
        conn.rollback()

    def test_the_purge_carve_out_is_not_opened_by_the_setting_alone(self):
        """2026-09-24 (after rc.40). The setting is settable by any role, so the trigger was
        only as strong as the grants beside it. A role that holds DELETE by mistake still
        cannot delete: the carve-out needs the purge's owner. Driven with a throwaway role
        granted DELETE, so the grant cannot be what refuses; all of it rolls back."""
        owner = psycopg2.connect(**DB_CONFIG)
        try:
            with owner.cursor() as cur:
                cur.execute("CREATE ROLE polaris_carveout_probe NOLOGIN")
                cur.execute("GRANT SELECT, DELETE ON AnchorBatch TO polaris_carveout_probe")
                cur.execute("SET LOCAL ROLE polaris_carveout_probe")
                cur.execute("SELECT set_config('polaris.purge_in_progress', 'TRUE', true)")
                with self.assertRaises(pg_errors.InsufficientPrivilege) as ctx:
                    cur.execute("DELETE FROM AnchorBatch")
                self.assertIn("append-only", str(ctx.exception))
        finally:
            owner.rollback()
            owner.close()

    def test_the_partition_manager_refuses_an_absurd_horizon(self):
        """p_months_ahead is bounded 0..60 (the full procedure drill found the bound untested,
        2026-09-24). A negative horizon or a century of empty partitions is refused."""
        owner = psycopg2.connect(**DB_CONFIG)
        try:
            for months in (-1, 61):
                with owner.cursor() as cur:
                    with self.assertRaises(psycopg2.Error, msg=months) as ctx:
                        cur.execute("CALL uc_ensure_event_partitions(%s)", (months,))
                    self.assertIn("between 0 and 60", str(ctx.exception))
                owner.rollback()
        finally:
            owner.rollback()
            owner.close()

    def test_a_definer_routine_is_the_applications_alone_to_call(self):
        """2026-09-25. PostgreSQL grants EXECUTE to PUBLIC, and a SECURITY DEFINER routine runs as
        its owner and authenticates its actor by parameter, so any role that could connect ran
        uc8_revoke_token as the owner. Measured with a role holding no grant at all: it entered
        the body and was stopped only by the business rules. Now it is refused at the door, and
        the application role keeps its EXECUTE, except on the retention routines, which take
        the acting admin as a parameter and are the owner's alone (2026-10-01, review F2), the
        population recount, which SHARE-locks the credential tables (lab/strategy/008), the
        enrolment rebuild, which SHARE-locks Individual and its enrolment events (step 4), and the
        activity recount, which SHARE-locks both event tables (lab/strategy/009, step 4)."""
        owner = psycopg2.connect(**DB_CONFIG)
        try:
            with owner.cursor() as cur:
                cur.execute("SELECT p.oid::regprocedure::text FROM pg_proc p "
                            "WHERE p.prosecdef AND p.pronamespace = 'public'::regnamespace")
                routines = [r[0] for r in cur.fetchall()]
                self.assertGreaterEqual(len(routines), 9)
                owner_only = {"uc_archive_purge", "uc_set_retention_policy", "uc_apply_retention_template",
                              "uc_rebuild_population_counts", "uc_rebuild_enrollment_counts",
                              "uc_rebuild_activity_rollups"}
                self.assertEqual({sig.split("(")[0] for sig in routines} & owner_only, owner_only,
                                 "the owner-only routines must exist for this to mean anything")
                for sig in routines:
                    cur.execute("SELECT has_function_privilege('polaris_app', %s, 'EXECUTE'), "
                                "       has_function_privilege('public', %s, 'EXECUTE')", (sig, sig))
                    app, public = cur.fetchone()
                    if sig.split("(")[0] in owner_only:
                        self.assertFalse(app, "the application role can call " + sig + ", the owner's alone")
                    else:
                        self.assertTrue(app, "the application must still call " + sig)
                    self.assertFalse(public, "PUBLIC can call " + sig + " as its owner")
                cur.execute("CREATE ROLE polaris_nobody_probe NOLOGIN")
                cur.execute("SET LOCAL ROLE polaris_nobody_probe")
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute("CALL uc8_revoke_token(3, 1, 'COMPROMISED', 'https://crl.example/x', NULL)")
        finally:
            owner.rollback()
            owner.close()

    def test_a_view_shows_a_bound_operator_no_more_than_the_tables_do(self):
        """2026-09-25. Operator isolation is row-level security, and a view ran as its owner, so
        RLS beneath it applied to the owner. Measured as polaris_app bound to agency 1: token 2
        (agency 3) invisible in IdentityToken, visible with its timeline in v_ontology_token,
        which /investigate/token/<id> reads. Every view now runs as its caller."""
        conn = self._app_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT set_config('polaris.operator_agency_id', '1', false)")
                pairs = [
                    ("SELECT count(*) AS n FROM IdentityToken WHERE token_id = 2",
                     "SELECT count(*) AS n FROM v_ontology_token WHERE token_id = 2"),
                    ("SELECT count(*) AS n FROM IdentityToken WHERE status = 'ACTIVE'",
                     "SELECT count(*) AS n FROM ActiveTokens"),
                    ("SELECT count(*) AS n FROM VerificationEvent",
                     "SELECT count(*) AS n FROM v_ontology_verification"),
                    ("SELECT count(*) AS n FROM (SELECT token_id FROM TokenLifecycleEvent WHERE token_id = 2 "
                     "UNION ALL SELECT token_id FROM VerificationEvent WHERE token_id = 2) t",
                     "SELECT count(*) AS n FROM v_ontology_token_timeline WHERE token_id = 2"),
                ]
                for table_sql, view_sql in pairs:
                    cur.execute(table_sql)
                    through_table = cur.fetchone()["n"]
                    cur.execute(view_sql)
                    self.assertLessEqual(cur.fetchone()["n"], through_table, view_sql)
                cur.execute("SELECT count(*) AS n FROM IdentityToken WHERE token_id = 2")
                self.assertEqual(cur.fetchone()["n"], 0, "fixture: token 2 is another authority's")
                cur.execute("SELECT c.relname FROM pg_class c WHERE c.relkind = 'v' "
                            "AND c.relnamespace = 'public'::regnamespace AND NOT coalesce("
                            "'security_invoker=true' = ANY(c.reloptions), false)")
                self.assertEqual([r["relname"] for r in cur.fetchall()], [],
                                 "a view that runs as its owner")
        finally:
            conn.rollback()
            conn.close()

    def test_a_bound_operator_sees_only_its_authoritys_events(self):
        """2026-09-26. Row-level security isolates three tables by authority. Weakening the
        IdentityToken policy to USING (true) turned tests red; weakening the ones on
        VerificationEvent (which carries where a credential was checked) and TokenLifecycleEvent
        turned nothing red, in the fast suites or in the application suite's bound-operator
        classes. As polaris_app bound to one authority, none of another's events is visible;
        unbound, they exist, so the zero is the policy's and not an empty fixture's."""
        conn = self._app_conn()
        queries = (
            ("verification events", "SELECT count(*) AS n FROM VerificationEvent "
                                    "WHERE requesting_agency_id <> %s"),
            ("lifecycle events", "SELECT count(*) AS n FROM TokenLifecycleEvent "
                                 "WHERE actor_agency_id IS NOT NULL AND actor_agency_id <> %s"),
        )
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT min(agency_id) AS a FROM Agency")
                agency = cur.fetchone()["a"]
                for label, sql in queries:
                    cur.execute("SELECT set_config('polaris.operator_agency_id', '', false)")
                    cur.execute(sql, (agency,))
                    self.assertGreater(cur.fetchone()["n"], 0,
                                       "fixture: another authority's %s exist" % label)
                    cur.execute("SELECT set_config('polaris.operator_agency_id', %s, false)", (str(agency),))
                    cur.execute(sql, (agency,))
                    self.assertEqual(cur.fetchone()["n"], 0,
                                     "a bound operator sees another authority's %s" % label)
        finally:
            conn.rollback()
            conn.close()

    def test_a_bound_operator_sees_only_its_authoritys_population_counts(self):
        """2026-10-02. The population counts (lab/strategy/008) are isolated by authority like the
        credentials they count. The constraint mutation drill weakened both policies to USING
        (true) and every suite stayed green. As polaris_app bound to one authority, no other
        authority's figure is visible, folded or pending; unbound, they exist, so the zero is
        the policy's. A status change on another authority's credential, rolled back with the
        rest, makes the pending figure: a folded table has none."""
        conn = self._app_conn()
        try:
            with _folds_held("polaris.population.fold"), conn.cursor() as cur:
                cur.execute("SELECT min(agency_id) AS a FROM Agency")
                agency = cur.fetchone()["a"]
                cur.execute("SELECT token_id FROM IdentityToken WHERE status = 'ACTIVE' "
                            "AND issuing_agency_id <> %s ORDER BY token_id LIMIT 1", (agency,))
                tok = cur.fetchone()
                self.assertIsNotNone(tok, "fixture: another authority's ACTIVE credential")
                cur.execute("SELECT set_config('polaris.justification', 'population isolation probe', true)")
                cur.execute("UPDATE IdentityToken SET status = 'DORMANT' WHERE token_id = %s",
                            (tok["token_id"],))
                for table in ("PopulationCount", "PopulationCountDelta"):
                    sql = "SELECT count(*) AS n FROM %s WHERE agency_id <> %%s" % table
                    cur.execute("SELECT set_config('polaris.operator_agency_id', '', false)")
                    cur.execute(sql, (agency,))
                    self.assertGreater(cur.fetchone()["n"], 0,
                                       "fixture: another authority's rows in %s" % table)
                    cur.execute("SELECT set_config('polaris.operator_agency_id', %s, false)", (str(agency),))
                    cur.execute(sql, (agency,))
                    self.assertEqual(cur.fetchone()["n"], 0,
                                     "a bound operator reads another authority's %s" % table)
                cur.execute("SELECT count(*) AS n FROM PopulationCount WHERE agency_id = %s", (agency,))
                self.assertGreater(cur.fetchone()["n"], 0,
                                   "the binding hides other authorities, not the operator's own")
        finally:
            conn.rollback()
            conn.close()

    def test_a_bound_operator_sees_only_its_authoritys_activity(self):
        """The activity rollups (lab/strategy/009) are isolated by authority like the events they
        count. The test lived in TestActivityRollups, where the constraint mutation drill, which
        runs this class, never looked: all six policies weakened to USING (true) left this class
        green and main's product suite red. As polaris_app bound to one authority, no other
        authority's row is visible in any rollup, totals, days or pending; unbound, they exist,
        so the zero is the policy's. A transition no authority made (actor 0) stays visible, as
        its NULL is on the event table."""
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        try:
            with _folds_held("polaris.activity.fold"), conn.cursor() as cur:
                a1, a2, ctx, tok = TestActivityRollups._fixture(cur)
                TestActivityRollups._record_events(cur, a1, a2, ctx, tok)
                cur.execute("SET LOCAL ROLE polaris_app")
                tables = (("VerificationRollup", "requesting_agency_id <> %s"),
                          ("VerificationRollupDaily", "requesting_agency_id <> %s"),
                          ("VerificationRollupDelta", "requesting_agency_id <> %s"),
                          ("LifecycleRollup", "actor_agency_id NOT IN (0, %s)"),
                          ("LifecycleRollupDaily", "actor_agency_id NOT IN (0, %s)"),
                          ("LifecycleRollupDelta", "actor_agency_id NOT IN (0, %s)"))
                for table, other in tables:
                    sql = "SELECT count(*) AS n FROM %s WHERE %s" % (table, other)
                    cur.execute("SELECT set_config('polaris.operator_agency_id', '', true)")
                    cur.execute(sql, (a1,))
                    self.assertGreater(cur.fetchone()["n"], 0,
                                       "fixture: another authority's rows in " + table)
                    cur.execute("SELECT set_config('polaris.operator_agency_id', %s, true)", (str(a1),))
                    cur.execute(sql, (a1,))
                    self.assertEqual(cur.fetchone()["n"], 0,
                                     "a bound operator reads another authority's " + table)
                cur.execute("SELECT count(*) AS n FROM LifecycleRollupDelta WHERE actor_agency_id = 0")
                self.assertGreater(cur.fetchone()["n"], 0, "a transition no authority made stays visible")
                cur.execute("SELECT count(*) AS n FROM VerificationRollupDelta")
                self.assertGreater(cur.fetchone()["n"], 0,
                                   "the binding hides other authorities, not the operator's own")
        finally:
            conn.rollback()
            conn.close()

    def test_the_database_refuses_a_success_the_verification_rules_forbid(self):
        """2026-10-02 (THREAT-MODEL). A SUCCESS naming a credential says the credential was live,
        permitted in the context, and trusted by the verifying authority. The verification form
        refuses each otherwise, but polaris_app holds INSERT on VerificationEvent: measured
        before the trigger, a SUCCESS for a REVOKED credential and one in a context the credential
        is not permitted in were both accepted from this role, and C1 keeps such a row for good.
        Each rule is refused here with its own reason, and the control (a SUCCESS that keeps all
        three) is accepted, so each refusal is that rule's and not a blanket one."""
        conn = self._app_conn()
        insert = ("INSERT INTO VerificationEvent (token_id, requesting_agency_id, context_id, "
                  "outcome, disclosure_level) VALUES (%s, %s, %s, 'SUCCESS', 'FULL')")
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT set_config('polaris.operator_agency_id', '', false)")
                # A live credential with a context it is permitted in, one it is not, and an
                # authority with no live attestation toward its issuer for the permitted context.
                cur.execute("""
                    SELECT t.token_id, t.issuing_agency_id, min(p.context_id) AS permitted,
                           (SELECT min(c.context_id) FROM VerificationContext c
                             WHERE NOT EXISTS (SELECT 1 FROM TokenPermission q
                                                WHERE q.token_id = t.token_id
                                                  AND q.context_id = c.context_id)) AS unpermitted
                      FROM IdentityToken t JOIN TokenPermission p ON p.token_id = t.token_id
                     WHERE t.status = 'ACTIVE'
                       AND (t.expiration_date IS NULL OR t.expiration_date >= polaris_utc_date())
                     GROUP BY t.token_id, t.issuing_agency_id
                    HAVING (SELECT min(c.context_id) FROM VerificationContext c
                             WHERE NOT EXISTS (SELECT 1 FROM TokenPermission q
                                                WHERE q.token_id = t.token_id
                                                  AND q.context_id = c.context_id)) IS NOT NULL
                     ORDER BY t.token_id LIMIT 1""")
                live = cur.fetchone()
                self.assertIsNotNone(live, "fixture: a live credential with an unpermitted context")
                cur.execute("""
                    SELECT a.agency_id FROM Agency a
                     WHERE a.agency_id <> %(issuer)s
                       AND NOT EXISTS (SELECT 1 FROM AgencyTrustAttestation x
                                        WHERE x.attesting_agency_id = a.agency_id
                                          AND x.attested_agency_id = %(issuer)s
                                          AND x.context_id = %(ctx)s
                                          AND x.revocation_date IS NULL
                                          AND x.valid_until >= polaris_utc_date())
                     ORDER BY a.agency_id LIMIT 1""",
                            {"issuer": live["issuing_agency_id"], "ctx": live["permitted"]})
                stranger = cur.fetchone()
                self.assertIsNotNone(stranger, "fixture: an authority that does not trust the issuer")
                cur.execute("SELECT token_id, issuing_agency_id FROM IdentityToken "
                            "WHERE status IN ('REVOKED', 'LOST') ORDER BY token_id LIMIT 1")
                dead = cur.fetchone()
                self.assertIsNotNone(dead, "fixture: a revoked or lost credential")
            conn.rollback()
            cases = (
                ("a credential that is no longer live", "cannot have succeeded, it is",
                 (dead["token_id"], dead["issuing_agency_id"], live["permitted"])),
                ("a context the credential is not permitted in", "not permitted in context",
                 (live["token_id"], live["issuing_agency_id"], live["unpermitted"])),
                ("an authority with no attestation toward the issuer", "holds no live attestation",
                 (live["token_id"], stranger["agency_id"], live["permitted"])),
            )
            for label, reason, args in cases:
                with self.subTest(case=label):
                    try:
                        with conn.cursor() as cur:
                            with self.assertRaisesRegex(psycopg2.Error, reason):
                                cur.execute(insert, args)
                    finally:
                        conn.rollback()   # an accepted row must not reach the control's count
            # The control: the same credential, its own issuer, a permitted context.
            with conn.cursor() as cur:
                cur.execute(insert, (live["token_id"], live["issuing_agency_id"], live["permitted"]))
                cur.execute("SELECT count(*) AS n FROM VerificationEvent WHERE token_id = %s "
                            "AND outcome = 'SUCCESS' AND event_timestamp >= now()", (live["token_id"],))
                self.assertEqual(cur.fetchone()["n"], 1, "a SUCCESS that keeps every rule must be recorded")
        finally:
            conn.rollback()
            conn.close()

    def test_a_rule_the_database_enforces_holds_for_a_bound_operator(self):
        """1.0.0-rc.42. Row-level security hides another authority's credentials from an
        operator bound to one, and routines that enforce a rule by READING those credentials
        ran as the caller, so under the binding the rule saw nothing to refuse. Measured on
        rc.41: a recovery opened for a holder with an ACTIVE credential elsewhere, and another
        authority's ACTIVE token put on the revocation list. Each case is refused unbound (the
        control) and must be refused bound."""
        conn = self._app_conn()
        try:
            with conn.cursor() as cur:
                # Any ACTIVE credential of an authority other than the one the operator is bound
                # to (1). It named token 2, which a test elsewhere in the same shard database can
                # have moved to LOST (found 2026-09-25 when the shards were packed differently).
                cur.execute("SELECT token_id, individual_id, issuing_agency_id FROM IdentityToken "
                            "WHERE status = 'ACTIVE' AND issuing_agency_id <> 1 "
                            "ORDER BY token_id LIMIT 1")
                tok = cur.fetchone()
                self.assertIsNotNone(tok, "fixture: another authority's ACTIVE credential")
                cur.execute("SELECT user_id FROM AppUser WHERE role = 'admin' LIMIT 1")
                admin = cur.fetchone()["user_id"]
            conn.rollback()
            attempts = [
                ("recovery for a holder with an ACTIVE credential",
                 "CALL uc9_initiate_recovery(%s, 1, %s, 48)", (tok["individual_id"], admin)),
                ("an ACTIVE token on the revocation list",
                 "INSERT INTO RevocationList (token_id, revoked_by_agency_id, effective_date, "
                 "reason_code) VALUES (%s, 1, polaris_utc_date(), 'COMPROMISED')", (tok["token_id"],)),
            ]
            for binding in ("", "1"):
                for label, sql, args in attempts:
                    with self.subTest(binding=binding or "none", case=label):
                        with conn.cursor() as cur:
                            cur.execute("SELECT set_config('polaris.operator_agency_id', %s, false)",
                                        (binding,))
                            with self.assertRaises(psycopg2.Error):
                                cur.execute(sql, args)
                        conn.rollback()
        finally:
            conn.rollback()
            conn.close()

    def test_a_partition_made_later_is_locked_too(self):
        """The partition manager takes the blanket grant back from each partition it creates."""
        # In ONE transaction, rolled back: the partitions this makes (and the triggers each
        # clones from its parent) must not outlive the test. An autocommitted first version
        # left 30 triggers behind, which the trigger mutation drill caught as a catalog that
        # did not come back.
        owner = psycopg2.connect(**DB_CONFIG)
        try:
            with owner.cursor() as cur:
                cur.execute("SELECT count(*) FROM pg_inherits")
                before = cur.fetchone()[0]
                cur.execute("CALL uc_ensure_event_partitions(8)")
                cur.execute("SELECT count(*) FROM pg_inherits")
                self.assertGreater(cur.fetchone()[0], before, "fixture: no partition was made")
                cur.execute("SELECT count(*) FROM information_schema.role_table_grants "
                            "WHERE grantee = 'polaris_app' AND privilege_type <> 'SELECT' "
                            "AND table_name ~ '^(tokenlifecycleevent|verificationevent|"
                            "enrollmentstatusevent|authauditlog)_'")
                self.assertEqual(cur.fetchone()[0], 0)
        finally:
            owner.rollback()
            owner.close()

    def _seed_old_lifecycle_row(self):
        owner = psycopg2.connect(**DB_CONFIG)
        owner.autocommit = True
        with owner.cursor() as cur:
            cur.execute("INSERT INTO TokenLifecycleEvent (token_id, event_type, event_timestamp, "
                        "reason_code) VALUES (1, 'ISSUED', now() - INTERVAL '2200 days', "
                        "'PURGE_DEFINER_TEST')")
        owner.close()
        self.addCleanup(self._drop_old_lifecycle_row)

    def _drop_old_lifecycle_row(self):
        owner = psycopg2.connect(**DB_CONFIG)
        with owner.cursor() as cur:
            cur.execute("SELECT set_config('polaris.purge_in_progress', 'TRUE', true)")
            cur.execute("DELETE FROM TokenLifecycleEvent WHERE reason_code = 'PURGE_DEFINER_TEST'")
        owner.commit()
        owner.close()

    def test_archive_purge_still_deletes_via_security_definer(self):
        """The purge still deletes old audit rows through uc_archive_purge, now for its only caller,
        the schema owner (scripts/polaris-purge.sh). Until 2026-10-01 this test ran it as
        polaris_app, which is the door review F2 closed: the routine takes the acting admin as a
        parameter, so the application role is refused it. The cutoff is older than the shipped
        five-year retention, since v9.234 the purge refuses anything younger. Rolls back."""
        call = ("CALL uc_archive_purge((now() - INTERVAL '2000 days')::timestamptz, "
                "%s, %s, %s, NULL, NULL)")
        app = self._app_conn()
        with app.cursor() as cur:
            with self.assertRaises(pg_errors.InsufficientPrivilege):
                cur.execute(call, ("s3://polaris-archive/definer-test.tar.zst", "a" * 64, 1))
        app.rollback()
        owner = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        try:
            with owner.cursor() as cur:
                cur.execute("SELECT user_id FROM AppUser WHERE role = 'admin' LIMIT 1")
                admin = cur.fetchone()
                if admin is None:
                    self.skipTest("no admin user to authorize the purge")
                # The owner seeds the old row (committed); the cleanup removes it if the purge did not.
                self._seed_old_lifecycle_row()
                cutoff = "now() - INTERVAL '2000 days'"
                cur.execute(f"SELECT count(*) AS n FROM TokenLifecycleEvent WHERE event_timestamp < {cutoff}")
                self.assertGreaterEqual(cur.fetchone()["n"], 1)
                cur.execute(call, ("s3://polaris-archive/definer-test.tar.zst", "a" * 64, admin["user_id"]))
                cur.execute(f"SELECT count(*) AS n FROM TokenLifecycleEvent WHERE event_timestamp < {cutoff}")
                self.assertEqual(cur.fetchone()["n"], 0,
                                 "uc_archive_purge (SECURITY DEFINER) must still purge old audit rows")
        finally:
            owner.rollback()
            owner.close()


class TestChainAnchorRecord(unittest.TestCase):
    """013: the record of each checkpoint committed to a public chain (ChainAnchor).

    The row is not the evidence: polaris-verify rereads the proof against block headers it reads
    itself. What the database holds to is that the record is the operator's and says one thing:
    the digest is derived from the checkpoint bytes rather than asserted beside them, a checkpoint
    is recorded once, the chain and method are the one the verifier reads, and the application
    role, which publishes the record, cannot write it."""

    CHECKPOINT = b'{"format":"polaris-chain-checkpoint/1","heads":["test"]}'

    def _owner(self):
        return TestCredentialCopyRecord._owner(self)

    def _insert(self, cur, checkpoint=None, digest=None, chain="BITCOIN", header="0" * 160):
        checkpoint = self.CHECKPOINT if checkpoint is None else checkpoint
        cur.execute(
            "INSERT INTO ChainAnchor (checkpoint, checkpoint_sha256, chain, method, proof, block_height, "
            "block_header_hex, recorded_by) VALUES (%s, %s, %s, 'OPENTIMESTAMPS', %s, 969876, %s, 'test') "
            "RETURNING anchor_id",
            (checkpoint, digest or hashlib.sha256(checkpoint).hexdigest(), chain, b"\x00", header))
        return cur.fetchone()["anchor_id"]

    def test_the_owner_records_an_anchor_whose_digest_is_its_checkpoint_s(self):
        conn = self._owner()
        with conn.cursor() as cur:
            self.assertIsNotNone(self._insert(cur))

    def test_a_digest_that_is_not_the_checkpoint_s_is_refused(self):
        conn = self._owner()
        with conn.cursor() as cur:
            with self.assertRaises(pg_errors.CheckViolation) as caught:
                self._insert(cur, digest="0" * 64)
            self.assertIn("chk_chain_anchor_digest", str(caught.exception))

    def test_a_chain_or_header_the_verifier_does_not_read_is_refused(self):
        for kw, rule in (({"chain": "ETHEREUM"}, "chk_chain_anchor_chain"),
                         ({"header": "Z" * 160}, "chk_chain_anchor_header"),
                         ({"header": "0" * 158}, "chk_chain_anchor_header")):
            with self.subTest(rule=rule, kw=kw):
                conn = self._owner()
                with conn.cursor() as cur:
                    with self.assertRaises(pg_errors.CheckViolation) as caught:
                        self._insert(cur, **kw)
                    self.assertIn(rule, str(caught.exception))

    def test_the_application_role_reads_the_record_and_cannot_write_it(self):
        conn = TestC1PrivilegeBoundary._app_conn(self)
        self.addCleanup(conn.rollback)
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM ChainAnchor")
            self.assertGreaterEqual(cur.fetchone()["n"], 0)
            with self.assertRaises(pg_errors.InsufficientPrivilege):
                self._insert(cur)


class TestCredentialCopyRecord(unittest.TestCase):
    """The wallet copy record obeys the credential record (docs/design/oid4vci-issuer.md).

    lab/strategy/005/STEP3.md showed the rule holding in the lab issuer's code and named that
    as its limit. Here it is the database's: uc_issue_credential_copy, the only writer of
    CredentialCopy, refuses a credential that is not ACTIVE, and credential_copy_valid_indexes,
    which the status list is computed from, drops a copy the moment its credential leaves
    ACTIVE. Every test runs as polaris_app, in one transaction that is rolled back: the
    credentials are issued through uc1_issue_and_activate and revoked through uc8_revoke_token,
    so no rule is stepped around to set a test up.
    """

    def _app(self):
        conn = TestC1PrivilegeBoundary._app_conn(self)
        self.addCleanup(conn.rollback)
        return conn

    def _owner(self):
        """The schema owner, for the one state polaris_app cannot make: an ACTIVE credential
        past its expiration_date (enforce_token_binding_owner_only lets the application
        change only a credential's status). The refusal under test is the definer function's,
        so which role calls it does not change what it decides."""
        cfg = dict(DB_CONFIG)
        cfg["user"] = os.environ.get("POLARIS_TEST_RELOAD_USER") or DB_CONFIG.get("user")
        password = os.environ.get("POLARIS_TEST_RELOAD_PASSWORD")
        if password is not None:
            cfg["password"] = password
        try:
            conn = psycopg2.connect(cursor_factory=RealDictCursor, **cfg)
        except psycopg2.OperationalError as exc:
            if os.environ.get("CI"):
                self.fail("the schema owner is unreachable in CI: %s" % exc)
            self.skipTest("the schema owner is unreachable: %s" % exc)
        self.addCleanup(conn.close)
        self.addCleanup(conn.rollback)
        return conn

    def _issue(self, cur, label):
        value = "TKN-COPY-TEST-%s-%d" % (label, os.getpid())
        cur.execute("SELECT uc1_issue_and_activate(%s, DATE '1990-05-06', 'PA', 2, 1, 'NONE', 2, "
                    "NULL, %s, %s, 'test', ARRAY[1]) AS token_id",
                    ("Copy Test %s" % label, value, "PHY-" + value))
        return value, cur.fetchone()["token_id"]

    def _copy(self, cur, value, agency=2, valid_for=None):
        if valid_for is None:
            cur.execute("SELECT * FROM uc_issue_credential_copy(%s, %s)", (value, agency))
        else:
            cur.execute("SELECT * FROM uc_issue_credential_copy(%s, %s, %s::INTERVAL)",
                        (value, agency, valid_for))
        return cur.fetchone()

    def _valid(self, cur, row):
        cur.execute("SELECT status_index FROM credential_copy_valid_indexes(2, %s, %s)",
                    (row["list_day"], row["list_no"]))
        return {r["status_index"] for r in cur.fetchall()}

    def test_an_active_credential_gets_a_copy_in_a_valid_position(self):
        conn = self._app()
        with conn.cursor() as cur:
            value, _ = self._issue(cur, "A")
            row = self._copy(cur, value)
            self.assertTrue(0 <= row["status_index"] < 1048576)
            self.assertEqual(row["list_no"], row["copy_id"] // 524288)
            self.assertEqual(row["legal_name"], "Copy Test A")
            self.assertIn(row["status_index"], self._valid(cur, row))

    def test_no_copy_for_a_credential_that_is_not_active(self):
        conn = self._app()
        with conn.cursor() as cur:
            value, token_id = self._issue(cur, "R")
            cur.execute("CALL uc8_revoke_token(%s, 2, 'COMPROMISED', 'copy test', 1)", (token_id,))
            with self.assertRaisesRegex(pg_errors.CheckViolation, "only for an ACTIVE credential"):
                self._copy(cur, value)

    def test_no_copy_for_another_agencys_credential(self):
        conn = self._app()
        with conn.cursor() as cur:
            value, _ = self._issue(cur, "G")
            with self.assertRaisesRegex(pg_errors.InsufficientPrivilege, "issued by agency 2, not 1"):
                self._copy(cur, value, agency=1)

    def test_no_copy_for_a_credential_that_does_not_exist(self):
        """Without this refusal the insert still fails, on a null token_id, with a different
        error; the procedure mutation drill showed no test told the two apart (2026-09-28)."""
        conn = self._app()
        with conn.cursor() as cur:
            with self.assertRaisesRegex(pg_errors.NoDataFound, "no credential has that value"):
                self._copy(cur, "TKN-NO-SUCH-CREDENTIAL-%d" % os.getpid())

    def test_no_copy_for_a_credential_past_its_expiration(self):
        """An ACTIVE credential whose expiration_date has passed (the expiry job has not run
        yet) gets no copy: its copy would be born expired."""
        conn = self._owner()
        with conn.cursor() as cur:
            value, token_id = self._issue(cur, "X")
            # The whole timeline moves back, because chk_token_time_order holds an expiration
            # to on or after the issue date: issued ten days ago, activated then, expired
            # yesterday, and still ACTIVE because no expiry job has run.
            cur.execute("UPDATE IdentityToken SET issued_date = CURRENT_TIMESTAMP - INTERVAL '10 days', "
                        "activated_date = CURRENT_TIMESTAMP - INTERVAL '10 days', "
                        "expiration_date = CURRENT_DATE - 1 WHERE token_id = %s", (token_id,))
            with self.assertRaisesRegex(pg_errors.CheckViolation, "expires before a copy could be valid"):
                self._copy(cur, value)

    def test_a_copy_does_not_outlive_its_credential(self):
        conn = self._owner()
        with conn.cursor() as cur:
            value, token_id = self._issue(cur, "E")
            cur.execute("UPDATE IdentityToken SET expiration_date = CURRENT_DATE + 3 "
                        "WHERE token_id = %s RETURNING expiration_date", (token_id,))
            expires = cur.fetchone()["expiration_date"]
            row = self._copy(cur, value)
            self.assertEqual(row["expires_at"].date(), expires,
                             "a copy lives thirty days, or until its credential expires if sooner")

    def test_a_copy_lives_at_most_thirty_days(self):
        conn = self._app()
        with conn.cursor() as cur:
            value, _ = self._issue(cur, "T")
            with self.assertRaisesRegex(pg_errors.InvalidParameterValue, "at most thirty days"):
                self._copy(cur, value, valid_for="31 days")

    def test_revocation_takes_the_copy_off_the_valid_list(self):
        """The effect the status list rests on, measured the way a verifier sees it."""
        conn = self._app()
        with conn.cursor() as cur:
            value, token_id = self._issue(cur, "V")
            row = self._copy(cur, value)
            self.assertIn(row["status_index"], self._valid(cur, row), "a live copy reads VALID")
            cur.execute("CALL uc8_revoke_token(%s, 2, 'COMPROMISED', 'copy test', 1)", (token_id,))
            self.assertNotIn(row["status_index"], self._valid(cur, row),
                             "a copy of a revoked credential must not read VALID")

    # 2026-09-28: the record read the SESSION's wall clock (CURRENT_TIMESTAMP::TIMESTAMP), so a
    # session's timezone moved list_day and every expiry comparison. A transaction's clock
    # stands still, so these tests move the zone instead of waiting: UTC-12 and UTC+14 between
    # them shift the date at any hour of the day.

    def test_the_list_day_is_the_utc_date_in_any_session_zone(self):
        conn = self._app()
        with conn.cursor() as cur:
            value, _ = self._issue(cur, "Z")
            for zone in ("Etc/GMT+12", "Etc/GMT-14"):
                cur.execute("SET LOCAL timezone = %s", (zone,))
                row = self._copy(cur, value)
                cur.execute("SELECT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::DATE AS utc")
                self.assertEqual(row["list_day"], cur.fetchone()["utc"],
                                 "a copy issued from a session at %s is filed under that "
                                 "session's date, not the UTC date" % zone)

    def test_a_live_copy_reads_valid_to_a_session_ahead_of_utc(self):
        conn = self._app()
        with conn.cursor() as cur:
            value, _ = self._issue(cur, "Y")
            cur.execute("SET LOCAL timezone = 'UTC'")
            row = self._copy(cur, value, valid_for="1 hour")
            cur.execute("SET LOCAL timezone = 'Etc/GMT-14'")
            self.assertIn(row["status_index"], self._valid(cur, row),
                          "a copy with an hour left reads revoked to a session at UTC+14")

    def test_an_expired_copy_reads_expired_to_a_session_behind_utc(self):
        """No procedure makes an expired copy, and a transaction cannot wait for one, so the
        schema owner writes the row the procedure would have written an hour ago."""
        conn = self._owner()
        with conn.cursor() as cur:
            value, token_id = self._issue(cur, "X")
            cur.execute(
                "WITH n AS (SELECT nextval(pg_get_serial_sequence('credentialcopy', 'copy_id')) AS id), "
                "t AS (SELECT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC') - INTERVAL '2 hours' AS at) "
                "INSERT INTO CredentialCopy (copy_id, token_id, agency_id, list_day, list_no, "
                "status_index, format, issued_at, expires_at) "
                "SELECT n.id, %s, 2, t.at::DATE, (n.id / 524288)::INTEGER, 4242, 'dc+sd-jwt', "
                "t.at, t.at + INTERVAL '1 hour' FROM n, t "
                "RETURNING list_day, list_no, status_index", (token_id,))
            row = cur.fetchone()
            cur.execute("SET LOCAL timezone = 'UTC'")
            self.assertNotIn(4242, self._valid(cur, row), "control: expired an hour ago in UTC")
            cur.execute("SET LOCAL timezone = 'Etc/GMT+12'")
            self.assertNotIn(4242, self._valid(cur, row),
                             "a copy that expired an hour ago reads VALID to a session at UTC-12")

    def test_indexes_are_unique_within_a_list(self):
        conn = self._app()
        with conn.cursor() as cur:
            value, _ = self._issue(cur, "U")
            rows = [self._copy(cur, value) for _ in range(25)]
            positions = {(r["list_day"], r["list_no"], r["status_index"]) for r in rows}
            self.assertEqual(len(positions), 25, "two copies share a status-list position")

    def test_the_application_cannot_write_or_edit_the_record(self):
        conn = self._app()
        with conn.cursor() as cur:
            value, _ = self._issue(cur, "W")
            row = self._copy(cur, value)
            for sql in ("UPDATE CredentialCopy SET status_index = 0 WHERE copy_id = %s",
                        "DELETE FROM CredentialCopy WHERE copy_id = %s"):
                with self.subTest(sql=sql.split()[0]):
                    cur.execute("SAVEPOINT s")
                    with self.assertRaises(pg_errors.InsufficientPrivilege):
                        cur.execute(sql, (row["copy_id"],))
                    cur.execute("ROLLBACK TO SAVEPOINT s")


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
    # 1.0.0-rc.38: a direct INSERT is refused, so the fixture writes its row with triggers
    # off for that one statement (the test role is the owner) and turns them back on before
    # the UPDATE or DELETE under test runs.
    'appuserevent': ('event_id',
        "SET LOCAL session_replication_role = replica; "
        "INSERT INTO AppUserEvent (user_id, username, event_type, field) "
        "VALUES (1, 'admin', 'RENAMED', 'username'); "
        "SET LOCAL session_replication_role = origin; "
        "SELECT max(event_id) AS event_id FROM AppUserEvent"),
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
    # 013 (2026-10-04): the logs' public-chain anchors. Written in production only by the schema
    # owner after the proof verifies; the fixture is the owner, and its checkpoint is any bytes
    # whose SHA-256 the database can derive.
    # Lab record 017 (2026-10-07): the backup record, written by the backup scripts as the
    # schema owner; the fixture is the owner.
    'backupevent': ('event_id',
        "INSERT INTO BackupEvent (kind, location) VALUES ('dump', '/var/backups/polaris/fixture.tar.gz') "
        "RETURNING event_id"),
    'chainanchor': ('anchor_id',
        "WITH c AS (SELECT convert_to('{\"format\":\"polaris-chain-checkpoint/1\",\"heads\":[]}', 'UTF8') AS b) "
        "INSERT INTO ChainAnchor (checkpoint, checkpoint_sha256, chain, method, proof, block_height, "
        "block_header_hex, recorded_by) SELECT c.b, encode(sha256(c.b), 'hex'), 'BITCOIN', "
        "'OPENTIMESTAMPS', decode('00', 'hex'), 0, repeat('0', 160), 'fixture' FROM c RETURNING anchor_id"),
    # 2026-09-28: the wallet copy record. Written in production only by
    # uc_issue_credential_copy; the fixture is the owner, so it writes a legal row directly
    # (a copy id drawn first, because the list number is derived from it).
    'credentialcopy': ('copy_id',
        "WITH n AS (SELECT nextval(pg_get_serial_sequence('credentialcopy', 'copy_id')) AS id) "
        "INSERT INTO CredentialCopy (copy_id, token_id, agency_id, list_day, list_no, status_index, "
        "format, issued_at, expires_at) SELECT n.id, 1, 1, CURRENT_DATE, (n.id / 524288)::INTEGER, "
        "4242, 'dc+sd-jwt', CURRENT_TIMESTAMP::TIMESTAMP, CURRENT_TIMESTAMP::TIMESTAMP + INTERVAL '1 day' "
        "FROM n RETURNING copy_id"),
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
    # The referee must be proofed (trg_vouching_rules derives the level from the record), and
    # in its own statement: a CTE's insert is not visible to the trigger's read of the same one.
    'refereevouching': ('vouching_id',
        "INSERT INTO EnrollmentProofing (individual_id, recorded_by_agency_id, presence, "
        "derived_ial) VALUES (2, 1, 'IN_PERSON', 'IAL2'); "
        f"WITH p AS ({_PROOFING}) "
        "INSERT INTO RefereeVouching (proofing_id, referee_individual_id, applicant_individual_id, "
        "referee_ial, relationship, vouched_ial) "
        "SELECT p.proofing_id, 2, 1, 'IAL2', 'EMPLOYER', 'IAL2' FROM p RETURNING vouching_id"),
    # Lab record 017 (2026-10-07): the record of reconciliations after a restore, written by
    # scripts/polaris-reconcile-restore.py as the schema owner; the fixture is the owner.
    'restorerecord': ('restore_id',
        "INSERT INTO RestoreRecord (target_time, archive_end, operator, outcome, report) "
        "VALUES (now() - interval '2 hours', now() - interval '1 hour', 'fixture', 'reconciled', '{}') "
        "RETURNING restore_id"),
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
            "'RESERVE', CURRENT_TIMESTAMP, (polaris_utc_date() + INTERVAL '10 years')::date) "
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
        # Since rc.38 a direct INSERT is refused before the CHECK is reached, so the CHECK is
        # driven with triggers off for the one statement, which only the owner can do.
        self.cur.execute("SAVEPOINT nosecret")
        self.cur.execute("SET LOCAL session_replication_role = replica")
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
                    "reason_code) VALUES (%s, 1, polaris_utc_date(), 'COMPROMISED')", (live['token_id'],))
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
                "reason_code) VALUES (%s, 1, polaris_utc_date(), 'COMPROMISED') RETURNING revocation_id",
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
    # 013 (2026-10-04): one checkpoint is recorded once. A second row for the same checkpoint
    # bytes is a copy the database refuses, whatever block it names.
    'chainanchor_checkpoint_sha256_key': (
        "WITH c AS (SELECT convert_to('{\"format\":\"polaris-chain-checkpoint/1\",\"heads\":[1]}', 'UTF8') AS b) "
        "INSERT INTO ChainAnchor (checkpoint, checkpoint_sha256, chain, method, proof, block_height, "
        "block_header_hex, recorded_by) SELECT c.b, encode(sha256(c.b), 'hex'), 'BITCOIN', "
        "'OPENTIMESTAMPS', decode('00', 'hex'), 0, repeat('0', 160), 'fixture' FROM c", {}),
    # 2026-09-28: a wallet copy's place in a status list is unique per agency, day and list.
    # The copy of this seeded row keeps its list number because its new copy_id falls in the
    # same list (copy_id / 2^19), so the only rule it can break is this one.
    'uq_credential_copy_status_index': (
        "WITH n AS (SELECT nextval(pg_get_serial_sequence('credentialcopy', 'copy_id')) AS id) "
        "INSERT INTO CredentialCopy (copy_id, token_id, agency_id, list_day, list_no, status_index, "
        "format, issued_at, expires_at) SELECT n.id, 1, 1, CURRENT_DATE, (n.id / 524288)::INTEGER, "
        "777, 'dc+sd-jwt', CURRENT_TIMESTAMP::TIMESTAMP, CURRENT_TIMESTAMP::TIMESTAMP + INTERVAL '1 day' "
        "FROM n", {}),
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



# ============================================================================
# Activity rollups (lab/strategy/009, step 4)
# ============================================================================

class TestEventsCarryNoLocation(_CheckBase):
    """lab/strategy/009, step 4c. No query filters or sorts a verification or a transition by its
    coordinates since the Atlas moved to the activity rollups, so no index on either event table
    covers one (each cost every located insert an update and served no query), and nothing in
    the database writes one. The index check reads the catalogue, so an index rebuilt by hand, or
    by a later load file, fails here as well as one in 02_indexes.sql. A column generated from a
    coordinate counts as one: the `geo` column the optional 13_postgis.sql added, and indexed
    with GiST, until step 4c. No test database has PostGIS, so polaris_checks reads the load
    files for that path as well."""

    #: Every index on the named tables or their partitions over a coordinate, or over a column
    #: generated from one. A GiST index on `geo` names no latitude; the column's expression does.
    LOCATED_INDEXES = r"""
        WITH ev AS (
            SELECT c.oid, c.relname AS tbl FROM pg_class c
             WHERE c.relname = ANY(%(tables)s) AND c.relkind IN ('r', 'p')
            UNION ALL
            SELECT i.inhrelid, p.relname FROM pg_inherits i JOIN pg_class p ON p.oid = i.inhparent
             WHERE p.relname = ANY(%(tables)s)
        ), located AS (
            SELECT a.attrelid, a.attname
              FROM pg_attribute a
              JOIN ev ON ev.oid = a.attrelid
              LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
             WHERE a.attnum > 0 AND NOT a.attisdropped
               AND (a.attname IN ('latitude', 'longitude')
                    OR (a.attgenerated <> ''
                        AND pg_get_expr(d.adbin, d.adrelid) ~* '\m(latitude|longitude)\M'))
        )
        SELECT ev.tbl, ix.relname AS idx
          FROM pg_index x
          JOIN ev ON ev.oid = x.indrelid
          JOIN pg_class ix ON ix.oid = x.indexrelid
         WHERE EXISTS (SELECT 1 FROM located l
                        WHERE l.attrelid = x.indrelid
                          AND pg_get_indexdef(x.indexrelid) ~* ('\m' || l.attname || '\M'))"""

    def _located_indexes(self, cur, tables):
        cur.execute(self.LOCATED_INDEXES, {'tables': list(tables)})
        return sorted((r['tbl'], r['idx']) for r in cur.fetchall())

    def test_no_index_on_an_event_table_covers_a_coordinate(self):
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT count(*) AS n FROM pg_index x JOIN pg_class c ON c.oid = x.indrelid
                 WHERE c.relname IN ('verificationevent', 'tokenlifecycleevent')""")
            self.assertGreaterEqual(cur.fetchone()['n'], 4,
                                    'the event tables keep their time and key indexes')
            self.assertEqual(
                self._located_indexes(cur, ('verificationevent', 'tokenlifecycleevent')), [])

    def test_the_index_check_sees_a_column_generated_from_a_coordinate(self):
        """The shape 13_postgis.sql built before step 4c, on a temporary table. Without it the
        generated-column half of the query above would never run, since no test has PostGIS."""
        with self.conn.cursor() as cur:
            cur.execute("CREATE TEMP TABLE located_probe (n INTEGER, latitude DOUBLE PRECISION, "
                        "  longitude DOUBLE PRECISION, "
                        "  geo DOUBLE PRECISION GENERATED ALWAYS AS (latitude + longitude) STORED)")
            cur.execute("CREATE INDEX located_probe_n ON located_probe (n)")
            cur.execute("CREATE INDEX located_probe_geo ON located_probe (geo) "
                        " WHERE geo IS NOT NULL")
            self.assertEqual(self._located_indexes(cur, ('located_probe',)),
                             [('located_probe', 'located_probe_geo')])

    def test_a_status_change_writes_no_coordinate_whatever_the_session_sets(self):
        """The audit trigger copied polaris.event_lat and event_lon into each lifecycle row it
        appended. Nothing set them, so every row carried NULL, and a session that did set them
        could start a location trail with no change to the schema. Step 4c removed the read."""
        with self.conn.cursor() as cur:
            cur.execute("SET LOCAL polaris.event_lat = '40.5'")
            cur.execute("SET LOCAL polaris.event_lon = '-80.1'")
            cur.execute("SELECT min(token_id) AS t FROM IdentityToken WHERE status = 'ACTIVE'")
            tok = cur.fetchone()['t']
            cur.execute("UPDATE IdentityToken SET status = 'LOST' WHERE token_id = %s", (tok,))
            cur.execute("SELECT latitude, longitude FROM TokenLifecycleEvent "
                        " WHERE token_id = %s AND reason_code = 'AUTO_AUDIT_TRIGGER' "
                        " ORDER BY event_id DESC LIMIT 1", (tok,))
            row = cur.fetchone()
        self.assertIsNotNone(row, 'the status change was audited by the trigger')
        self.assertEqual((row['latitude'], row['longitude']), (None, None))


class TestActivityRollups(_CheckBase):
    """The counts the Atlas reads, kept by statement triggers on the two event tables. Every test
    writes inside its own transaction and rolls it back, and every comparison is against a
    recount of the event tables themselves, in hours no fixture event occupies."""

    _HOURS = ("2025-12-31 03:00", "2025-12-31 04:00")
    _V_KEY = ("bucket", "requesting_agency_id", "context_id", "outcome", "disclosure_level",
              "algorithm_id")
    _L_KEY = ("bucket", "actor_agency_id", "event_type")

    @staticmethod
    def _fixture(cur):
        cur.execute("SELECT agency_id FROM Agency ORDER BY agency_id LIMIT 2")
        a1, a2 = [r["agency_id"] for r in cur.fetchall()]
        cur.execute("SELECT min(context_id) AS c FROM VerificationContext")
        ctx = cur.fetchone()["c"]
        cur.execute("SELECT token_id, algorithm_id FROM IdentityToken ORDER BY token_id LIMIT 1")
        tok = cur.fetchone()
        return a1, a2, ctx, tok

    @staticmethod
    def _record_events(cur, a1, a2, ctx, tok):
        """One statement into each event table: two hours, two authorities, a zero-knowledge
        verification, and a transition no authority made."""
        cur.execute(
            "INSERT INTO VerificationEvent (token_id, requesting_agency_id, context_id, "
            "event_timestamp, outcome, disclosure_level) VALUES "
            "(%(t)s, %(a1)s, %(c)s, '2025-12-31 03:15', 'FAILURE', 'FULL'), "
            "(%(t)s, %(a1)s, %(c)s, '2025-12-31 03:40', 'FAILURE', 'FULL'), "
            "(NULL, %(a2)s, %(c)s, '2025-12-31 03:50', 'FAILURE', 'ZERO_KNOWLEDGE'), "
            "(%(t)s, %(a2)s, %(c)s, '2025-12-31 04:05', 'UNAUTHORIZED', 'SELECTIVE')",
            {"t": tok["token_id"], "a1": a1, "a2": a2, "c": ctx})
        cur.execute(
            "INSERT INTO TokenLifecycleEvent (token_id, actor_agency_id, event_type, "
            "event_timestamp, reason_code) VALUES "
            "(%(t)s, %(a2)s, 'DEVICE_BOUND', '2025-12-31 03:20', 'rollup probe'), "
            "(%(t)s, NULL, 'DEVICE_BOUND', '2025-12-31 03:25', 'rollup probe'), "
            "(%(t)s, %(a2)s, 'DEVICE_REVOKED', '2025-12-31 04:10', 'rollup probe')",
            {"t": tok["token_id"], "a2": a2})

    def _cells(self, cur, sql, key):
        cur.execute(sql, (list(self._HOURS),))
        return {tuple(r[k] for k in key): r["n"] for r in cur.fetchall()}

    def _verification_cells(self, cur):
        """The rollup as a reader sums it (totals and pending changes), and a recount."""
        rolled = self._cells(cur, """
            SELECT bucket, requesting_agency_id, context_id, outcome, disclosure_level,
                   algorithm_id, sum(n) AS n
              FROM (SELECT bucket, requesting_agency_id, context_id, outcome, disclosure_level,
                           algorithm_id, n FROM VerificationRollup
                    UNION ALL
                    SELECT bucket, requesting_agency_id, context_id, outcome, disclosure_level,
                           algorithm_id, n FROM VerificationRollupDelta) r
             WHERE bucket = ANY(%s::timestamp[])
             GROUP BY 1, 2, 3, 4, 5, 6""", self._V_KEY)
        recounted = self._cells(cur, """
            SELECT date_trunc('hour', ve.event_timestamp) AS bucket, ve.requesting_agency_id,
                   ve.context_id, ve.outcome, ve.disclosure_level,
                   COALESCE(t.algorithm_id, 0) AS algorithm_id, count(*) AS n
              FROM VerificationEvent ve LEFT JOIN IdentityToken t ON t.token_id = ve.token_id
             WHERE date_trunc('hour', ve.event_timestamp) = ANY(%s::timestamp[])
             GROUP BY 1, 2, 3, 4, 5, 6""", self._V_KEY)
        return rolled, recounted

    def _lifecycle_cells(self, cur):
        rolled = self._cells(cur, """
            SELECT bucket, actor_agency_id, event_type, sum(n) AS n
              FROM (SELECT bucket, actor_agency_id, event_type, n FROM LifecycleRollup
                    UNION ALL
                    SELECT bucket, actor_agency_id, event_type, n FROM LifecycleRollupDelta) r
             WHERE bucket = ANY(%s::timestamp[])
             GROUP BY 1, 2, 3""", self._L_KEY)
        recounted = self._cells(cur, """
            SELECT date_trunc('hour', event_timestamp) AS bucket,
                   COALESCE(actor_agency_id, 0) AS actor_agency_id, event_type, count(*) AS n
              FROM TokenLifecycleEvent
             WHERE date_trunc('hour', event_timestamp) = ANY(%s::timestamp[])
             GROUP BY 1, 2, 3""", self._L_KEY)
        return rolled, recounted

    def test_every_recorded_event_is_counted_in_its_hour(self):
        """Each hour's cells equal a recount of the events, pending and then folded, and the
        fold leaves nothing pending and the day's totals equal to its hours'."""
        with self.conn.cursor() as cur:
            a1, a2, ctx, tok = self._fixture(cur)
            self._record_events(cur, a1, a2, ctx, tok)
            for stage in ("pending", "folded"):
                rolled, recounted = self._verification_cells(cur)
                self.assertEqual(sum(recounted.values()), 4, "fixture: the four verifications")
                self.assertEqual(rolled, recounted, "verifications, " + stage)
                rolled, recounted = self._lifecycle_cells(cur)
                self.assertEqual(sum(recounted.values()), 3, "fixture: the three transitions")
                self.assertEqual(rolled, recounted, "lifecycle events, " + stage)
                if stage == "pending":
                    # A trigger folds by itself now and then (random() < 0.002 per statement), so
                    # some or all of the fixture's changes may be folded already: the fold moves
                    # exactly what is still pending, never assumed positive.
                    cur.execute("SELECT (SELECT count(*) FROM VerificationRollupDelta) "
                                "     + (SELECT count(*) FROM LifecycleRollupDelta) AS n")
                    pending = cur.fetchone()["n"]
                    cur.execute("SELECT uc_fold_activity_rollups() AS folded")
                    self.assertEqual(cur.fetchone()["folded"], pending)
            cur.execute("SELECT (SELECT count(*) FROM VerificationRollupDelta) "
                        "     + (SELECT count(*) FROM LifecycleRollupDelta) AS n")
            self.assertEqual(cur.fetchone()["n"], 0, "a fold leaves nothing pending")
            # The credential's algorithm as recorded, and 0 for the verification that named none.
            algorithms = {key[5] for key in self._verification_cells(cur)[0]}
            self.assertEqual(algorithms, {tok["algorithm_id"], 0})
            cur.execute("SELECT (SELECT sum(n) FROM VerificationRollupDaily "
                        "         WHERE bucket = '2025-12-31') AS daily, "
                        "       (SELECT sum(n) FROM VerificationRollup "
                        "         WHERE bucket >= '2025-12-31' AND bucket < '2026-01-01') AS hourly")
            row = cur.fetchone()
            self.assertEqual(row["daily"], row["hourly"], "the day's total is its hours' sum")

    def test_a_truncate_empties_the_rollups_of_its_table_alone(self):
        with self.conn.cursor() as cur:
            a1, a2, ctx, tok = self._fixture(cur)
            self._record_events(cur, a1, a2, ctx, tok)
            counts = ("SELECT (SELECT count(*) FROM VerificationRollup) "
                      "     + (SELECT count(*) FROM VerificationRollupDaily) "
                      "     + (SELECT count(*) FROM VerificationRollupDelta) AS v, "
                      "       (SELECT count(*) FROM LifecycleRollup) "
                      "     + (SELECT count(*) FROM LifecycleRollupDaily) "
                      "     + (SELECT count(*) FROM LifecycleRollupDelta) AS l")
            cur.execute(counts)
            before = cur.fetchone()
            self.assertGreater(before["v"], 0, "fixture")
            self.assertGreater(before["l"], 0, "fixture")
            cur.execute("TRUNCATE VerificationEvent")
            cur.execute(counts)
            self.assertEqual(dict(cur.fetchone()), {"v": 0, "l": before["l"]})
            cur.execute("TRUNCATE TokenLifecycleEvent")
            cur.execute(counts)
            self.assertEqual(dict(cur.fetchone()), {"v": 0, "l": 0})

    def test_the_application_role_writes_no_rollup(self):
        """A count the application role could write is a count a compromised application could
        forge; it records events, and the triggers count them."""
        for table in ("VerificationRollup", "VerificationRollupDaily", "VerificationRollupDelta"):
            with self.subTest(table=table), self.conn.cursor() as cur:
                cur.execute("SAVEPOINT w")
                cur.execute("SET LOCAL ROLE polaris_app")
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute("INSERT INTO %s (bucket, requesting_agency_id, context_id, outcome, "
                                "disclosure_level, algorithm_id, n) SELECT date_trunc('hour', now()), "
                                "min(agency_id), 1, 'SUCCESS', 'FULL', 0, 1 FROM Agency" % table)
                cur.execute("ROLLBACK TO SAVEPOINT w")
        for table in ("LifecycleRollup", "LifecycleRollupDaily", "LifecycleRollupDelta"):
            with self.subTest(table=table), self.conn.cursor() as cur:
                cur.execute("SAVEPOINT w")
                cur.execute("SET LOCAL ROLE polaris_app")
                with self.assertRaises(pg_errors.InsufficientPrivilege):
                    cur.execute("UPDATE %s SET n = n + 1" % table)
                cur.execute("ROLLBACK TO SAVEPOINT w")

    def _purge(self, cur):
        """A policy-mode purge of verifications older than a thousand days, as 08_tests S.9."""
        cur.execute("SELECT user_id FROM AppUser WHERE role = 'admin' AND is_active "
                    "ORDER BY user_id LIMIT 1")
        admin = cur.fetchone()["user_id"]
        cur.execute("CALL uc_apply_retention_template('MINIMIZED', NULL, %s)", (admin,))
        cur.execute(
            "CALL uc_archive_purge(p_cutoff_timestamp := now() - interval '1825 days', "
            "p_archive_uri := 'file:///tmp/rollup-probe.tar.gz', p_archive_sha256 := repeat('d', 64), "
            "p_actor_user_id := %s, p_jurisdiction := NULL, p_class_cutoffs := ARRAY["
            "now() - interval '1825 days', now() - interval '1000 days', "
            "now() - interval '1825 days', now() - interval '1000 days']::timestamptz[], "
            "checkpoint_id_out := NULL)", (admin,))

    def _old_verification(self, cur, a1, ctx):
        cur.execute("INSERT INTO VerificationEvent (token_id, requesting_agency_id, context_id, "
                    "event_timestamp, outcome, disclosure_level) VALUES "
                    "(NULL, %s, %s, now() - interval '1100 days', 'FAILURE', 'SELECTIVE') "
                    "RETURNING date_trunc('hour', event_timestamp) AS hour, "
                    "date_trunc('day', event_timestamp) AS day", (a1, ctx))
        return cur.fetchone()

    def test_a_purge_takes_the_hours_it_empties_and_keeps_the_days(self):
        """Hourly cells live no longer than the events they count; the day stays, as statistics
        that say nothing finer than a day."""
        with self.conn.cursor() as cur:
            a1, a2, ctx, tok = self._fixture(cur)
            old = self._old_verification(cur, a1, ctx)
            self._purge(cur)
            cur.execute("SELECT count(*) AS n FROM VerificationEvent WHERE event_timestamp < now() - interval '1000 days'")
            self.assertEqual(cur.fetchone()["n"], 0, "fixture: the purge deleted the old verification")
            cur.execute("SELECT (SELECT count(*) FROM VerificationRollup WHERE bucket = %(h)s) "
                        "     + (SELECT count(*) FROM VerificationRollupDelta WHERE bucket = %(h)s) AS hourly, "
                        "       (SELECT count(*) FROM VerificationRollup "
                        "         WHERE bucket < date_trunc('hour', now() - interval '1000 days')) AS before_cut, "
                        "       (SELECT sum(n) FROM VerificationRollupDaily WHERE bucket = %(d)s "
                        "           AND requesting_agency_id = %(a)s AND outcome = 'FAILURE') AS daily",
                        {"h": old["hour"], "d": old["day"], "a": a1})
            row = cur.fetchone()
            self.assertEqual(row["hourly"], 0, "the purged hour's cells went with its events")
            self.assertEqual(row["before_cut"], 0, "no hour wholly before the cutoff is left")
            self.assertGreaterEqual(row["daily"], 1, "the day keeps the count")

    def test_a_rebuild_recounts_what_a_purge_did_not_cut(self):
        """A recount after a purge restores every hour after the cut from the events, and leaves
        the days the purge cut through as the fold left them: a recount would undercount them."""
        with self.conn.cursor() as cur:
            a1, a2, ctx, tok = self._fixture(cur)
            old = self._old_verification(cur, a1, ctx)
            self._purge(cur)
            self._record_events(cur, a1, a2, ctx, tok)
            cur.execute("SELECT uc_fold_activity_rollups()")
            cur.execute("UPDATE VerificationRollup SET n = n + 5 WHERE bucket = %s", (self._HOURS[0],))
            self.assertGreater(cur.rowcount, 0, "fixture: a counted hour to spoil")
            cur.execute("SELECT uc_rebuild_activity_rollups()")
            rolled, recounted = self._verification_cells(cur)
            self.assertEqual(rolled, recounted, "the spoiled hour is recounted")
            cur.execute("SELECT sum(n) AS n FROM VerificationRollupDaily WHERE bucket = %s "
                        "AND requesting_agency_id = %s AND outcome = 'FAILURE'", (old["day"], a1))
            self.assertGreaterEqual(cur.fetchone()["n"], 1, "the purged day keeps its count")


# 2026-09-25: a skipped security test is a pass nobody reads. TestC1PrivilegeBoundary skipped in
# CI for its whole life (the application role's password was never exported), and the privilege
# boundary it exists to prove was tested only on a laptop until the trigger mutation drill
# reported guards "untested" that had tests. In CI every test in this module that would skip
# FAILS instead, naming the reason; outside CI a skip still skips. check_security_suite_refuses_
# skips_in_ci holds this block, and refuses a skip decorator here, which would bypass it.
if os.environ.get("CI"):
    def _no_skip_in_ci(self, reason):
        self.fail("a security test would have skipped in CI: %s. Make it runnable here, "
                  "or it proves nothing." % reason)

    for _cls in list(globals().values()):
        if isinstance(_cls, type) and issubclass(_cls, unittest.TestCase):
            _cls.skipTest = _no_skip_in_ci


if __name__ == '__main__':
    unittest.main(verbosity=2)
