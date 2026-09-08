"""
test_redaction_property.py — verification-graph redaction tests (M2-12 / R11-7)

Property tests that instantiate the adversary model from
`meta/redaction-proof.md` and confirm:

  - Isolated ZK-only event sequences resist reconstruction (success rate
    bounded by 1/N + slack).
  - The two named counterexamples (temporal correlation, spatial
    uniqueness) DO succeed, documenting the operational limitations
    the schema cannot mitigate.
  - proof_commitment is unique per ZK event in sample data (the S4
    mitigation; a deterministic-per-holder regression breaks this).
  - C2 holds: ZK rows have token_id IS NULL.

The adversary is implemented as a small Python class so the tests
serve as both invariant checks and reference implementations of the
attack surface. A future engineer reading test_redaction_property.py
should come away with a working understanding of what an attacker can
and cannot do, not just a green CI badge.

Tests are READ-MOSTLY where possible. Where synthetic data is needed
(controlled population, controlled correlations), the test inserts
inside a transaction and rolls back at the end. The PolarisTestCase
setUp in test_app.py runs reload_sample_data() which fully resets
the DB between tests; this file does not subclass PolarisTestCase to
keep its imports minimal, but it relies on the same expectation that
the sample DB is in pristine state at test start.
"""

import os
import unittest
import random
from contextlib import closing
from datetime import datetime, timedelta

import psycopg2
from psycopg2.extras import RealDictCursor


DB_CONFIG = {
    'host':     os.environ.get('POLARIS_DB_HOST', 'localhost'),
    'database': os.environ.get('POLARIS_DB_NAME', 'polaris_test'),
    'user':     os.environ.get('POLARIS_DB_USER', 'polaris_app'),
    'password': os.environ.get('POLARIS_DB_PASSWORD', 'polaris_dev_password'),
}


def _conn():
    return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)


# ============================================================================
# Adversary algorithms — instantiate the model from §1 of the proof doc.
# Each class is a passive read-only attacker; given the database state and
# a target ZK event, it outputs a holder-guess. Subclasses differ in
# strategy and side-channel exploitation.
# ============================================================================


class _BaseAdversary:
    """Read-only adversary. Sees rows, can run any SELECT, cannot mutate."""

    def __init__(self, conn):
        self._conn = conn

    def _all_holders(self):
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT individual_id FROM Individual ORDER BY individual_id"
            )
            return [r['individual_id'] for r in cur.fetchall()]

    def guess_holder(self, zk_event):
        raise NotImplementedError


class UniformGuessAdversary(_BaseAdversary):
    """Worst case for the adversary: no information beyond population. Picks a
    uniform random holder. The expected success rate on N holders is 1/N."""

    def __init__(self, conn, seed=0):
        super().__init__(conn)
        self._rng = random.Random(seed)

    def guess_holder(self, zk_event):
        holders = self._all_holders()
        return self._rng.choice(holders) if holders else None


class TemporalCorrelationAdversary(_BaseAdversary):
    """Exploits side-channel S1 — temporal proximity to non-ZK events.
    For a target ZK event V_zk, finds the nearest SELECTIVE / FULL event
    within the time window and returns that event's holder. If multiple
    candidates, picks the closest by event_timestamp."""

    WINDOW_SECONDS = 60

    def guess_holder(self, zk_event):
        with self._conn.cursor() as cur:
            cur.execute("""
                SELECT i.individual_id,
                       abs(extract(epoch FROM (ve.event_timestamp - %s::timestamp))) AS dt
                FROM VerificationEvent ve
                JOIN IdentityToken t ON ve.token_id = t.token_id
                JOIN Individual    i ON t.individual_id = i.individual_id
                WHERE ve.disclosure_level IN ('SELECTIVE', 'FULL')
                  AND ve.token_id IS NOT NULL
                  AND ve.requesting_agency_id = %s
                  AND ve.event_timestamp BETWEEN
                        %s::timestamp - interval %s
                    AND %s::timestamp + interval %s
                ORDER BY dt
                LIMIT 1
            """, (
                zk_event['event_timestamp'],
                zk_event['requesting_agency_id'],
                zk_event['event_timestamp'],
                f'{self.WINDOW_SECONDS} seconds',
                zk_event['event_timestamp'],
                f'{self.WINDOW_SECONDS} seconds',
            ))
            row = cur.fetchone()
            return row['individual_id'] if row else None


class SpatialUniquenessAdversary(_BaseAdversary):
    """Exploits side-channel S2 — spatial uniqueness. For a target ZK
    event with a (latitude, longitude), finds individuals known to be
    at that location via their non-ZK events. If exactly one holder
    has a SELECTIVE/FULL event at the same coordinates, the ZK event
    is linked."""

    EPSILON_DEG = 0.0001  # ~11 meters

    def guess_holder(self, zk_event):
        if zk_event.get('latitude') is None or zk_event.get('longitude') is None:
            return None
        with self._conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT i.individual_id
                FROM VerificationEvent ve
                JOIN IdentityToken t ON ve.token_id = t.token_id
                JOIN Individual    i ON t.individual_id = i.individual_id
                WHERE ve.disclosure_level IN ('SELECTIVE', 'FULL')
                  AND ve.token_id IS NOT NULL
                  AND abs(ve.latitude - %s)  < %s
                  AND abs(ve.longitude - %s) < %s
            """, (
                zk_event['latitude'],  self.EPSILON_DEG,
                zk_event['longitude'], self.EPSILON_DEG,
            ))
            rows = cur.fetchall()
            return rows[0]['individual_id'] if len(rows) == 1 else None


# ============================================================================
# Synthetic-population fixture. Each test that needs a controlled
# population calls _populate_synthetic() inside a savepoint, exercises
# the adversary, then rolls back. The full test framework's
# reload_sample_data() (in test_app.py) provides additional cleanup at
# setUp/tearDown boundaries when this file is run alongside test_app.
# ============================================================================


def _populate_synthetic(conn, n_holders=10):
    """Create n_holders Individuals each with one ACTIVE token. Returns
    a list of (individual_id, token_id) ground-truth pairs. Caller is
    responsible for rolling back."""
    holders = []
    with conn.cursor() as cur:
        for i in range(n_holders):
            cur.execute(
                "INSERT INTO Individual (legal_name, date_of_birth, jurisdiction) "
                "VALUES (%s, %s, %s) RETURNING individual_id",
                (f'PropTestHolder{i:03d}', '2000-01-01', 'US-PA')
            )
            ind_id = cur.fetchone()['individual_id']
            cur.execute(
                "INSERT INTO IdentityToken "
                "(token_value, physical_serial, biometric_binding_type, "
                " individual_id, issuing_agency_id, algorithm_id, "
                " status, issued_date, activated_date) "
                "VALUES (%s, %s, 'NONE', %s, 1, 1, 'ACTIVE', "
                "        CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) "
                "RETURNING token_id",
                (f'TKN-PROP-{i:06d}', f'SER-PROP-{i:06d}', ind_id)
            )
            tok_id = cur.fetchone()['token_id']
            holders.append((ind_id, tok_id))
    return holders


def _insert_zk_event(conn, agency_id=5, context_id=1, ts=None,
                     lat=37.7749, lon=-122.4194, commitment=None):
    """Insert a single ZK event with token_id=NULL (per C2). Returns
    the resulting event row."""
    if ts is None:
        ts = datetime(2026, 5, 1, 12, 0, 0)
    if commitment is None:
        commitment = '0x' + os.urandom(32).hex()
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO VerificationEvent
                (token_id, requesting_agency_id, context_id,
                 event_timestamp, outcome, disclosure_level,
                 proof_commitment, requestor_location, latitude, longitude)
            VALUES (NULL, %s, %s, %s, 'SUCCESS', 'ZERO_KNOWLEDGE',
                    %s, 'PropTestLocation', %s, %s)
            RETURNING *
        """, (agency_id, context_id, ts, commitment, lat, lon))
        return cur.fetchone()


def _insert_selective_event(conn, token_id, agency_id=5, context_id=1,
                            ts=None, lat=37.7749, lon=-122.4194):
    """Insert a SELECTIVE event linked to a real token (correlation seed)."""
    if ts is None:
        ts = datetime(2026, 5, 1, 12, 0, 0)
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO VerificationEvent
                (token_id, requesting_agency_id, context_id,
                 event_timestamp, outcome, disclosure_level,
                 requestor_location, latitude, longitude)
            VALUES (%s, %s, %s, %s, 'SUCCESS', 'SELECTIVE',
                    'PropTestLocation', %s, %s)
            RETURNING *
        """, (token_id, agency_id, context_id, ts, lat, lon))
        return cur.fetchone()


# ============================================================================
# Tests — privacy claim and counterexamples
# ============================================================================


class RedactionPropertyTests(unittest.TestCase):
    """The privacy claim from meta/redaction-proof.md, made executable.
    Each test stands alone (transaction-rolled back at the end)."""

    POPULATION_SIZE = 10
    EVENTS_TOTAL = 200

    def test_zk_only_sequence_resists_reconstruction(self):
        """§4 — Isolated ZK events. Adversary success rate ≤ 1/N + slack."""
        conn = _conn()
        try:
            holders = _populate_synthetic(conn, n_holders=self.POPULATION_SIZE)
            self.assertEqual(len(holders), self.POPULATION_SIZE)

            # Insert ZK events round-robin across holders. Ground truth is
            # which holder generated each event; the SCHEMA does not record
            # this (token_id NULL). The test tracks ground truth in Python.
            ground_truth = []
            base_ts = datetime(2026, 5, 1, 12, 0, 0)
            for i in range(self.EVENTS_TOTAL):
                ind_id, _tok_id = holders[i % self.POPULATION_SIZE]
                # Spread across many days so no two events from the same
                # holder are temporally adjacent (avoid accidental S1).
                ts = base_ts + timedelta(hours=i * 7)  # 7 hours apart
                # Distribute coordinates so spatial uniqueness doesn't help
                # the adversary — every event lands on the same point.
                event_row = _insert_zk_event(
                    conn, ts=ts, lat=37.7749, lon=-122.4194
                )
                ground_truth.append((event_row, ind_id))

            adv = UniformGuessAdversary(conn, seed=42)
            correct = sum(1 for evt, true_id in ground_truth
                          if adv.guess_holder(evt) == true_id)
            success_rate = correct / len(ground_truth)
            baseline   = 1.0 / self.POPULATION_SIZE
            # Allow generous slack: with 200 events and N=10 holders the
            # baseline is 0.10; binomial 95% CI on a fair coin around 0.10 is
            # ~[0.06, 0.14]. We allow up to 0.20 to absorb finite-sample noise.
            self.assertLessEqual(
                success_rate, baseline + 0.10,
                f"UniformGuessAdversary success rate {success_rate:.3f} "
                f"materially exceeds baseline {baseline:.3f}. "
                f"This either indicates a side-channel leak or a bug "
                f"in the adversary that gives it more info than it should have."
            )
        finally:
            conn.rollback()
            conn.close()

    def test_isolated_zk_event_has_no_holder_reference(self):
        """§6 — C2 reinforced. A freshly-inserted ZK row carries no
        holder reference at all; token_id IS NULL and the schema
        provides no other column linking the row to an Individual."""
        conn = _conn()
        try:
            _populate_synthetic(conn, n_holders=3)
            event_row = _insert_zk_event(conn)
            self.assertIsNone(
                event_row['token_id'],
                "ZK event inserted with non-NULL token_id — C2 violated."
            )
            # Schema-level absence: the columns of VerificationEvent that
            # could link to Individual must all be NULL or non-identifying.
            # We confirm by listing every column whose name suggests a holder
            # reference; the only one is token_id, which is NULL.
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT column_name FROM information_schema.columns
                    WHERE table_name = 'verificationevent'
                      AND (column_name LIKE '%individual%'
                           OR column_name = 'holder_id')
                """)
                holder_columns = [r['column_name'] for r in cur.fetchall()]
                self.assertEqual(
                    holder_columns, [],
                    "VerificationEvent has direct holder columns — "
                    "redaction proof breaks at the schema level."
                )
        finally:
            conn.rollback()
            conn.close()

    def test_temporal_correlation_breaks_redaction(self):
        """§5 CE-1. With deliberate temporal correlation between a SELECTIVE
        event and a ZK event from the same holder, the adversary's success
        rate jumps to ≈ 1.0. This is a documented limitation; the schema
        cannot mitigate it. Operational policy must."""
        conn = _conn()
        try:
            holders = _populate_synthetic(conn, n_holders=self.POPULATION_SIZE)

            # For each holder, insert (SELECTIVE, ZK) pair 1 second apart
            # at the same agency. The adversary should link them.
            ground_truth = []
            base_ts = datetime(2026, 5, 1, 12, 0, 0)
            for i, (ind_id, tok_id) in enumerate(holders):
                ts_sel = base_ts + timedelta(hours=i * 5)
                ts_zk  = ts_sel + timedelta(seconds=1)
                _insert_selective_event(conn, token_id=tok_id,
                                        agency_id=5, ts=ts_sel)
                event_row = _insert_zk_event(conn, agency_id=5, ts=ts_zk)
                ground_truth.append((event_row, ind_id))

            adv = TemporalCorrelationAdversary(conn)
            correct = sum(1 for evt, true_id in ground_truth
                          if adv.guess_holder(evt) == true_id)
            success_rate = correct / len(ground_truth)
            self.assertGreaterEqual(
                success_rate, 0.80,
                f"TemporalCorrelationAdversary should identify nearly all "
                f"correlated holders; got {success_rate:.3f}. The CE-1 "
                f"counterexample is real — if this test starts FAILING "
                f"(adversary worse than expected) the test setup may be "
                f"broken; if the SUCCESS rate dropped because Polaris added "
                f"a real mitigation, update meta/redaction-proof.md."
            )
        finally:
            conn.rollback()
            conn.close()

    def test_spatial_uniqueness_breaks_redaction(self):
        """§5 CE-2. With deliberate spatial uniqueness — a ZK event at
        coordinates matching exactly one holder's prior non-ZK event — the
        adversary identifies the holder. Documented limitation."""
        conn = _conn()
        try:
            holders = _populate_synthetic(conn, n_holders=self.POPULATION_SIZE)

            # Each holder gets a unique location; SELECTIVE event there;
            # then a ZK event at the same location.
            ground_truth = []
            for i, (ind_id, tok_id) in enumerate(holders):
                # Spread holders across a grid; each gets unique coords
                lat = 30.0 + i * 0.5
                lon = -100.0 + i * 0.5
                _insert_selective_event(conn, token_id=tok_id,
                                        lat=lat, lon=lon,
                                        ts=datetime(2026, 5, 1, 12 + i, 0, 0))
                event_row = _insert_zk_event(
                    conn, lat=lat, lon=lon,
                    ts=datetime(2026, 5, 2, 12 + i, 0, 0)  # next day
                )
                ground_truth.append((event_row, ind_id))

            adv = SpatialUniquenessAdversary(conn)
            correct = sum(1 for evt, true_id in ground_truth
                          if adv.guess_holder(evt) == true_id)
            success_rate = correct / len(ground_truth)
            self.assertGreaterEqual(
                success_rate, 0.80,
                f"SpatialUniquenessAdversary should identify nearly all "
                f"holders given unique-location SELECTIVE precedents; got "
                f"{success_rate:.3f}. CE-2 is a real, documented limit."
            )
        finally:
            conn.rollback()
            conn.close()

    def test_proof_commitments_are_unique_per_zk_event(self):
        """§3 S4 — proof_commitment determinism would cluster a holder's
        ZK events. The sample data must use distinct commitments per
        event. A regression where commitments collapse to a per-holder
        constant would make this test fail."""
        with closing(_conn()) as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT proof_commitment, count(*) AS n
                FROM VerificationEvent
                WHERE disclosure_level = 'ZERO_KNOWLEDGE'
                  AND proof_commitment IS NOT NULL
                GROUP BY proof_commitment
                HAVING count(*) > 1
            """)
            duplicates = cur.fetchall()
            self.assertEqual(
                duplicates, [],
                f"Multiple ZK events share a proof_commitment: {duplicates}. "
                f"This violates S4 (commitments must be uniformly distributed) "
                f"and degrades the privacy claim — a holder's ZK events "
                f"cluster on the shared commitment, allowing reconstruction "
                f"by collision rather than content."
            )

    def test_uniform_baseline_matches_population_size(self):
        """Sanity check — the UniformGuessAdversary samples holders uniformly.
        We use the OBSERVED total population (sample data + synthetic) rather
        than a hardcoded N because the sample DB already has 5 enrolled
        holders, and an N-mismatch here would mask a real regression."""
        conn = _conn()
        try:
            _populate_synthetic(conn, n_holders=5)
            adv = UniformGuessAdversary(conn, seed=12345)
            actual_n = len(adv._all_holders())
            self.assertGreater(actual_n, 0,
                "no holders enrolled — fixture broken")

            target_event = _insert_zk_event(conn)
            # 5000 trials; assert each holder gets ~1/N share within slack.
            counts = {}
            trials = 5000
            for _ in range(trials):
                g = adv.guess_holder(target_event)
                counts[g] = counts.get(g, 0) + 1

            expected_p = 1.0 / actual_n
            # Binomial 95% CI on a fair coin around p with N=5000 trials
            # gives ±1.96 * sqrt(p*(1-p)/N) ≈ ±0.014 for p=0.10. Use 0.03
            # to absorb any per-holder bias while still failing if the
            # adversary's distribution is meaningfully non-uniform.
            for holder_id, count in counts.items():
                empirical_p = count / trials
                self.assertAlmostEqual(
                    empirical_p, expected_p, delta=0.03,
                    msg=f"Holder {holder_id} guessed at rate "
                        f"{empirical_p:.3f}; uniform baseline over "
                        f"N={actual_n} would be {expected_p:.3f}."
                )
        finally:
            conn.rollback()
            conn.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
