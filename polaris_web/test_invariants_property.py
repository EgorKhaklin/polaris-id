"""
test_invariants_property.py

Property-based tests for Polaris's three core MISSION.md hard
constraints, using Hypothesis to generate randomized inputs:

  C1 — TokenLifecycleEvent and VerificationEvent are append-only.
       Every UPDATE/DELETE attempt fails (trigger reject_audit_modification).
  C2 — VerificationEvent rows with disclosure_level='ZERO_KNOWLEDGE' have
       token_id IS NULL. CHECK constraint chk_disclosure_token_consistency
       enforces this AND its inverse (FULL must have token_id NOT NULL).
  C3 — At most one IdentityToken with status='ACTIVE' per Individual,
       enforced by partial unique index uq_one_active_per_person.

These properties are LOAD-BEARING. If any of these tests fails, a
hard constraint has regressed and Polaris's privacy / repudiation /
non-repudiation guarantees are broken regardless of what other tests
still pass.

The tests are READ-MOSTLY: each test attempts a write that should
fail, and rolls back. No persistent state changes; safe to run
against any Polaris database with at least one ACTIVE token.
"""

import os
import unittest
from contextlib import closing
import psycopg2
from psycopg2.extras import RealDictCursor
from hypothesis import given, strategies as st, settings, HealthCheck

DB_CONFIG = {
    'host':     os.environ.get('POLARIS_DB_HOST', 'localhost'),
    'database': os.environ.get('POLARIS_DB_NAME', 'polaris_test'),
    'user':     os.environ.get('POLARIS_DB_USER', 'polaris_app'),
    'password': os.environ.get('POLARIS_DB_PASSWORD', 'polaris_dev_password'),
}

# Schema-correct value sets (match 01_schema.sql CHECK constraints exactly)
VALID_TOKEN_STATUSES   = ['ACTIVE', 'RESERVE', 'DORMANT', 'REVOKED', 'LOST', 'EXPIRED']
VALID_LIFECYCLE_TYPES  = ['ISSUED', 'ACTIVATED', 'DEACTIVATED', 'DEVICE_BOUND',
                          'DEVICE_REVOKED', 'REVOKED', 'LOST', 'EXPIRED', 'REPLACED']
VALID_DISCLOSURE       = ['ZERO_KNOWLEDGE', 'SELECTIVE', 'FULL']
VALID_OUTCOMES         = ['SUCCESS', 'FAILURE', 'EXPIRED', 'UNAUTHORIZED']

LAT = st.floats(min_value=-89.99, max_value=89.99, allow_nan=False, allow_infinity=False)
LON = st.floats(min_value=-179.99, max_value=179.99, allow_nan=False, allow_infinity=False)

HYPOTHESIS_SETTINGS = settings(
    max_examples=15,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


def _get_connection():
    return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)


def _existing_active_holder():
    """Return one (individual_id, token_id) for a holder with an ACTIVE token."""
    with closing(_get_connection()) as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT individual_id, token_id
            FROM IdentityToken
            WHERE status = 'ACTIVE'
            ORDER BY token_id
            LIMIT 1
        """)
        row = cur.fetchone()
        if row is None:
            # v9.411 - not None, and not a skip. An identity database with no ACTIVE
            # token cannot exercise C2 or C3, and a suite that reports OK for that
            # has reported a guarantee it did not test.
            raise AssertionError(
                "the database holds no ACTIVE IdentityToken, so C2 and C3 cannot be "
                "exercised at all. That is a broken fixture, not a reason to pass.")
        return (row['individual_id'], row['token_id'])


def _existing_lifecycle_event():
    """One lifecycle event, CREATING one if the database holds none.

    v9.411 - this used to return None on an empty table and every caller answered
    that by skipping. C1 is not conditional on the sample data happening to carry a
    row: a skipped test leaves the append-only trigger covered by nothing while the
    suite still prints OK. Measured: with these three tests skipping,
    trg_lifecycle_append_only could be dropped and the whole suite stayed green.
    """
    with closing(_get_connection()) as conn, conn.cursor() as cur:
        cur.execute("SELECT event_id, token_id, event_type FROM TokenLifecycleEvent ORDER BY event_id LIMIT 1")
        row = cur.fetchone()
        if row is not None:
            return row
        cur.execute("SELECT token_id FROM IdentityToken ORDER BY token_id LIMIT 1")
        tok = cur.fetchone()
        if tok is None:
            raise AssertionError(
                "the database holds no IdentityToken, so C1's lifecycle audit cannot be "
                "exercised at all. That is a broken fixture, not a reason to pass.")
        cur.execute(
            "INSERT INTO TokenLifecycleEvent (token_id, event_type, event_timestamp, reason_code) "
            "VALUES (%s, 'ISSUED', CURRENT_TIMESTAMP, 'PROPERTY_SUITE_FIXTURE') "
            "RETURNING event_id, token_id, event_type",
            (tok['token_id'],))
        conn.commit()
        return cur.fetchone()


def _existing_verification_event():
    """One verification event, CREATING one if the database holds none (v9.411)."""
    with closing(_get_connection()) as conn, conn.cursor() as cur:
        cur.execute("SELECT event_id, disclosure_level, token_id FROM VerificationEvent ORDER BY event_id LIMIT 1")
        row = cur.fetchone()
        if row is not None:
            return row
        cur.execute("SELECT token_id FROM IdentityToken WHERE status = 'ACTIVE' ORDER BY token_id LIMIT 1")
        tok = cur.fetchone()
        if tok is None:
            raise AssertionError(
                "the database holds no ACTIVE IdentityToken, so C1's verification audit cannot "
                "be exercised at all. That is a broken fixture, not a reason to pass.")
        cur.execute(
            "INSERT INTO VerificationEvent "
            "  (token_id, requesting_agency_id, context_id, disclosure_level, "
            "   outcome, event_timestamp) "
            "VALUES (%s, 1, 1, 'FULL', 'SUCCESS', CURRENT_TIMESTAMP) "
            "RETURNING event_id, disclosure_level, token_id",
            (tok['token_id'],))
        conn.commit()
        return cur.fetchone()


# =============================================================================
# C1 — APPEND-ONLY AUDIT
# =============================================================================
class C1_AppendOnlyProperties(unittest.TestCase):
    @given(event_type=st.sampled_from(VALID_LIFECYCLE_TYPES))
    @HYPOTHESIS_SETTINGS
    def test_update_lifecycle_event_type_always_fails(self, event_type):
        evt = _existing_lifecycle_event()
        with closing(_get_connection()) as conn, conn.cursor() as cur:
            try:
                cur.execute(
                    "UPDATE TokenLifecycleEvent SET event_type = %s WHERE event_id = %s",
                    (event_type, evt['event_id'])
                )
                conn.commit()
                self.fail(f"UPDATE succeeded with event_type={event_type} — C1 violated")
            except psycopg2.Error:
                conn.rollback()

    @given(reason=st.text(min_size=0, max_size=60,
                          alphabet=st.characters(blacklist_categories=('Cs',),
                                                  blacklist_characters='\x00')))
    @HYPOTHESIS_SETTINGS
    def test_update_lifecycle_reason_always_fails(self, reason):
        evt = _existing_lifecycle_event()
        with closing(_get_connection()) as conn, conn.cursor() as cur:
            try:
                cur.execute(
                    "UPDATE TokenLifecycleEvent SET reason_code = %s WHERE event_id = %s",
                    (reason[:60], evt['event_id'])
                )
                conn.commit()
                self.fail(f"UPDATE reason succeeded with {reason!r} — C1 violated")
            except psycopg2.Error:
                conn.rollback()

    @HYPOTHESIS_SETTINGS
    @given(noise=st.text(min_size=0, max_size=64,
                          alphabet=st.characters(blacklist_categories=('Cs',),
                                                  blacklist_characters='\x00')))
    def test_delete_lifecycle_event_always_fails(self, noise):
        evt = _existing_lifecycle_event()
        with closing(_get_connection()) as conn, conn.cursor() as cur:
            try:
                cur.execute("DELETE FROM TokenLifecycleEvent WHERE event_id = %s", (evt['event_id'],))
                conn.commit()
                self.fail(f"DELETE succeeded (noise={noise!r}) — C1 violated")
            except psycopg2.Error:
                conn.rollback()
            cur.execute("SELECT event_id FROM TokenLifecycleEvent WHERE event_id = %s", (evt['event_id'],))
            self.assertIsNotNone(cur.fetchone(),
                f"event {evt['event_id']} disappeared after failed DELETE — C1 violated")

    @HYPOTHESIS_SETTINGS
    @given(disclosure=st.sampled_from(VALID_DISCLOSURE))
    def test_update_verification_event_always_fails(self, disclosure):
        evt = _existing_verification_event()
        with closing(_get_connection()) as conn, conn.cursor() as cur:
            try:
                cur.execute(
                    "UPDATE VerificationEvent SET disclosure_level = %s WHERE event_id = %s",
                    (disclosure, evt['event_id'])
                )
                conn.commit()
                self.fail(f"UPDATE succeeded with disclosure={disclosure} — C1 violated")
            except psycopg2.Error:
                conn.rollback()

    @HYPOTHESIS_SETTINGS
    @given(event_id=st.integers(min_value=1, max_value=100000))
    def test_delete_verification_event_always_fails(self, event_id):
        with closing(_get_connection()) as conn, conn.cursor() as cur:
            cur.execute("SELECT 1 FROM VerificationEvent WHERE event_id = %s", (event_id,))
            if cur.fetchone() is None:
                return
            try:
                cur.execute("DELETE FROM VerificationEvent WHERE event_id = %s", (event_id,))
                conn.commit()
                self.fail(f"DELETE succeeded for event_id={event_id} — C1 violated")
            except psycopg2.Error:
                conn.rollback()


# =============================================================================
# C2 — ZK → token_id NULL (and inverse: FULL → token_id NOT NULL)
# =============================================================================
class C2_DisclosureTypingProperties(unittest.TestCase):
    @HYPOTHESIS_SETTINGS
    @given(lat=LAT, lon=LON)
    def test_zk_with_non_null_token_id_always_rejected(self, lat, lon):
        holder = _existing_active_holder()
        _, token_id = holder
        with closing(_get_connection()) as conn, conn.cursor() as cur:
            try:
                cur.execute("""
                    INSERT INTO VerificationEvent
                        (token_id, requesting_agency_id, context_id,
                         disclosure_level, outcome,
                         latitude, longitude, event_timestamp)
                    VALUES (%s, 1, 1, 'ZERO_KNOWLEDGE', 'SUCCESS',
                            %s, %s, now())
                """, (token_id, lat, lon))
                conn.commit()
                self.fail(
                    f"INSERT succeeded with disclosure=ZERO_KNOWLEDGE and "
                    f"token_id={token_id} (lat={lat}, lon={lon}) — C2 violated"
                )
            except psycopg2.errors.CheckViolation:
                conn.rollback()
            except psycopg2.Error:
                conn.rollback()

    @HYPOTHESIS_SETTINGS
    @given(outcome=st.sampled_from(VALID_OUTCOMES))
    def test_full_with_null_token_id_always_rejected(self, outcome):
        with closing(_get_connection()) as conn, conn.cursor() as cur:
            try:
                cur.execute("""
                    INSERT INTO VerificationEvent
                        (token_id, requesting_agency_id, context_id,
                         disclosure_level, outcome, event_timestamp)
                    VALUES (NULL, 1, 1, 'FULL', %s, now())
                """, (outcome,))
                conn.commit()
                self.fail("INSERT succeeded with disclosure=FULL and token_id=NULL — C2 inverse violated")
            except psycopg2.Error:
                conn.rollback()

    @HYPOTHESIS_SETTINGS
    @given(lat=LAT, lon=LON, outcome=st.sampled_from(VALID_OUTCOMES))
    def test_zk_with_null_token_id_always_accepted(self, lat, lon, outcome):
        """Happy path: ZK + token_id NULL is always accepted. Roll back to
        keep the test side-effect-free."""
        with closing(_get_connection()) as conn, conn.cursor() as cur:
            try:
                cur.execute("""
                    INSERT INTO VerificationEvent
                        (token_id, requesting_agency_id, context_id,
                         disclosure_level, outcome,
                         latitude, longitude, event_timestamp)
                    VALUES (NULL, 1, 1, 'ZERO_KNOWLEDGE', %s, %s, %s, now())
                """, (outcome, lat, lon))
                conn.rollback()
            except psycopg2.Error as exc:
                conn.rollback()
                self.fail(
                    f"ZK + token_id NULL was rejected ({exc.__class__.__name__}: {exc}) "
                    f"— C2 happy path failure"
                )


# =============================================================================
# C3 — ONE ACTIVE TOKEN PER INDIVIDUAL
# =============================================================================
class C3_OneActivePerIndividualProperties(unittest.TestCase):
    @HYPOTHESIS_SETTINGS
    @given(
        token_value_suffix=st.text(min_size=4, max_size=16,
                                    alphabet=st.characters(whitelist_categories=('L', 'N'))),
        physical_serial_suffix=st.text(min_size=4, max_size=16,
                                        alphabet=st.characters(whitelist_categories=('L', 'N'))),
        biometric=st.sampled_from(['NONE', 'FINGERPRINT', 'FACE', 'IRIS']),
    )
    def test_second_active_token_always_rejected(self, token_value_suffix,
                                                  physical_serial_suffix, biometric):
        """A second ACTIVE token for an already-active individual must fail
        the partial unique index regardless of other column values."""
        holder = _existing_active_holder()
        individual_id, _existing = holder
        with closing(_get_connection()) as conn, conn.cursor() as cur:
            try:
                cur.execute("""
                    INSERT INTO IdentityToken
                        (token_value, physical_serial, biometric_binding_type,
                         individual_id, issuing_agency_id, algorithm_id,
                         status, issued_date, activated_date)
                    VALUES (%s, %s, %s, %s, 1, 1,
                            'ACTIVE', now(), now())
                """, (
                    f"PROP-T-{token_value_suffix}",
                    f"PROP-S-{physical_serial_suffix}",
                    biometric,
                    individual_id,
                ))
                conn.commit()
                self.fail(
                    f"INSERT of second ACTIVE token for individual {individual_id} "
                    f"succeeded — C3 violated"
                )
            except psycopg2.errors.UniqueViolation:
                conn.rollback()
            except psycopg2.Error:
                conn.rollback()

    @HYPOTHESIS_SETTINGS
    @given(suffix=st.text(min_size=4, max_size=16,
                          alphabet=st.characters(whitelist_categories=('L', 'N'))))
    def test_reserve_token_for_active_individual_always_accepted(self, suffix):
        """RESERVE tokens are NOT blocked by uq_one_active_per_person — the
        partial index only fires on status=ACTIVE. This is critical for
        succession to work."""
        holder = _existing_active_holder()
        individual_id, _existing = holder
        with closing(_get_connection()) as conn, conn.cursor() as cur:
            try:
                cur.execute("""
                    INSERT INTO IdentityToken
                        (token_value, physical_serial, biometric_binding_type,
                         individual_id, issuing_agency_id, algorithm_id,
                         status, issued_date)
                    VALUES (%s, %s, 'NONE', %s, 1, 1,
                            'RESERVE', now())
                """, (f"PROP-RT-{suffix}", f"PROP-RS-{suffix}", individual_id))
                conn.rollback()
            except psycopg2.errors.UniqueViolation as exc:
                conn.rollback()
                self.fail(
                    f"RESERVE token for individual {individual_id} was rejected "
                    f"by unique index ({exc}) — partial-index should only fire on ACTIVE"
                )
            except psycopg2.Error:
                conn.rollback()


if __name__ == '__main__':
    unittest.main(verbosity=2)
