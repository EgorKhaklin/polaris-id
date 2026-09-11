"""test_capacity.py - the national capacity model (roadmap P7.3).

The model's job is to say whether the roadmap's stated planning targets survive contact with
this schema. Its finding was that every throughput target clears by more than an order of
magnitude and that the system could not have run for a week at the sustained one, because
`VerificationEvent.event_id` was a 32-bit `SERIAL`.

These tests keep both halves honest: that the arithmetic is right, and that a comfortable
throughput figure is never allowed to stand in for a verdict.

Run: python3 -m unittest test_capacity
"""

import os
import unittest

import capacity
from capacity import (
    ASSUMED, DERIVED, INT4_MAX, MEASURED, UNVALIDATED, exhaustion, human_lifetime,
    nearest_survivor, sequence_columns, throughput, validate,
)

# A schema in the shape of the real one: a partitioned table whose CREATE TABLE does
# not end the way the others do, which is exactly where a whole-statement parser loses
# VerificationEvent -- the column that matters most.
NARROW = """
CREATE TABLE Individual (
    individual_id   SERIAL       PRIMARY KEY,
    legal_name      VARCHAR(200) NOT NULL
);

CREATE TABLE VerificationEvent (
    event_id             SERIAL,
    token_id             INTEGER,
    event_timestamp      TIMESTAMP NOT NULL
) PARTITION BY RANGE (event_timestamp);

CREATE TABLE VerificationEvent_default PARTITION OF VerificationEvent DEFAULT;

CREATE TABLE TokenStateEpochLeaf (
    leaf_id            SERIAL       PRIMARY KEY,
    epoch_id           INTEGER      NOT NULL
);

CREATE TABLE RevocationList (
    revocation_id      SERIAL       PRIMARY KEY
);
"""

WIDE = (NARROW
        .replace("event_id             SERIAL", "event_id             BIGSERIAL")
        .replace("leaf_id            SERIAL", "leaf_id            BIGSERIAL"))

REAL_SCHEMA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "polaris_sql", "01_schema.sql")


class ParsingTests(unittest.TestCase):

    def test_a_partitioned_table_is_not_lost(self):
        """The regression that would hide the finding.

        VerificationEvent ends its CREATE TABLE with PARTITION BY rather than the
        closing paren the other tables use. A parser that matched whole statements
        would skip the busiest table in the system and report the schema clean.
        """
        found = {(t, c) for t, c, _ in sequence_columns(NARROW)}
        self.assertIn(("VerificationEvent", "event_id"), found)

    def test_both_widths_are_reported(self):
        widths = {t: w for t, _, w in sequence_columns(WIDE)}
        self.assertEqual(widths["VerificationEvent"], "BIGSERIAL")
        self.assertEqual(widths["RevocationList"], "SERIAL")

    def test_a_partition_of_clause_is_not_read_as_a_table(self):
        tables = {t for t, _, _ in sequence_columns(NARROW)}
        self.assertNotIn("VerificationEvent_default", tables)


class ExhaustionTests(unittest.TestCase):

    def row(self, schema, table):
        return next(r for r in exhaustion(schema) if r["table"] == table)

    def test_a_32_bit_verification_id_lasts_days_at_the_sustained_target(self):
        """The finding, in the units that make it unarguable.

        Two billion divided by five thousand a second is under five days. The figure
        rests on one row per verification and a target quoted from the roadmap, so
        there is no assumption in it to disagree with.
        """
        r = self.row(NARROW, "VerificationEvent")
        self.assertEqual(r["basis"], DERIVED)
        self.assertTrue(r["exhausts_within_horizon"])
        self.assertAlmostEqual(r["lifetime"] / 86400.0, 4.97, places=1)
        self.assertIn("days", human_lifetime(r))

    def test_the_peak_target_shortens_it_to_hours(self):
        targets = {k: dict(v) for k, v in capacity.TARGETS.items()}
        targets["verification_sustained"]["value"] = 50_000
        r = next(r for r in exhaustion(NARROW, targets) if r["table"] == "VerificationEvent")
        self.assertLess(r["lifetime"], 86400)
        self.assertIn("hours", human_lifetime(r))

    def test_the_leaf_id_is_counted_in_epoch_closures_not_time(self):
        """One row per credential per epoch, so the answer needs no cadence.

        Expressing it in days would require assuming how often epochs close, and the
        finding is stronger without that: the sixth closure of a national population
        exhausts the space whenever it happens.
        """
        r = self.row(NARROW, "TokenStateEpochLeaf")
        self.assertEqual(r["unit"], "epoch closures")
        self.assertEqual(r["basis"], DERIVED)
        self.assertAlmostEqual(r["lifetime"], INT4_MAX / 350_000_000, places=1)
        self.assertIn("epoch closures", human_lifetime(r))

    def test_widening_clears_the_flag(self):
        self.assertFalse(self.row(WIDE, "VerificationEvent")["exhausts_within_horizon"])
        self.assertFalse(self.row(WIDE, "TokenStateEpochLeaf")["exhausts_within_horizon"])

    def test_an_assumed_row_prints_its_assumption(self):
        r = self.row(NARROW, "RevocationList")
        self.assertEqual(r["basis"], ASSUMED)
        self.assertIn("assuming", r["why"])

    def test_the_worst_row_comes_first(self):
        rows = exhaustion(NARROW)
        self.assertTrue(rows[0]["exhausts_within_horizon"])

    def test_a_longer_horizon_flags_more(self):
        short = {r["table"] for r in exhaustion(WIDE) if r["exhausts_within_horizon"]}
        long = {r["table"] for r in exhaustion(WIDE, horizon_years=100)
                if r["exhausts_within_horizon"]}
        self.assertIn("Individual", long - short)


class VerdictTests(unittest.TestCase):

    def test_a_narrow_id_blocks_a_target_its_traffic_writes_to(self):
        v = validate(NARROW)["targets"]
        self.assertEqual(v["verification_sustained"]["verdict"], "BLOCKED")
        self.assertIn("VerificationEvent",
                      [b["table"] for b in v["verification_sustained"]["blockers"]])

    def test_a_blocker_only_attaches_to_targets_that_touch_it(self):
        """An id space nothing on this path writes to is not this target's problem."""
        v = validate(NARROW)["targets"]
        tables = {b["table"] for b in v["verification_peak"]["blockers"]}
        self.assertEqual(tables, {"VerificationEvent"})

    def test_throughput_alone_never_earns_a_verdict(self):
        """The half of the picture that flatters the system.

        The sustained target is under a core of measured verification. Reporting MET
        on that basis while an insert on the same path is five days from failing is
        the error this function exists to prevent.
        """
        report = validate(NARROW)
        self.assertLess(report["throughput"]["verification_sustained"]["cores"], 1.0)
        self.assertEqual(report["targets"]["verification_sustained"]["verdict"], "BLOCKED")

    def test_widening_turns_blocked_into_met(self):
        v = validate(WIDE)["targets"]
        self.assertEqual(v["verification_sustained"]["verdict"], "MET")
        self.assertEqual(v["verification_peak"]["verdict"], "MET")

    def test_availability_is_never_met(self):
        """Nothing here can establish 52.6 minutes of downtime a year."""
        for schema in (NARROW, WIDE):
            entry = validate(schema)["targets"]["availability"]
            self.assertEqual(entry["verdict"], UNVALIDATED)
            self.assertIn("two-member", entry["because"].lower())

    def test_the_unvalidated_reason_says_what_would_settle_it(self):
        because = validate(WIDE)["targets"]["availability"]["because"]
        self.assertIn("multi-region", because)


class ThroughputTests(unittest.TestCase):

    def test_peak_verification_is_a_handful_of_cores(self):
        tp = throughput()
        self.assertAlmostEqual(tp["verification_peak"]["cores"],
                               50_000 / capacity.BENCHMARK["verify_per_core_single_witness"],
                               places=3)

    def test_a_core_count_is_extrapolated_and_says_so(self):
        """The per-core rate is measured; six and a half cores is division.

        Roadmap P1.18 item 6 names this move by its worst form, "no one-core x8",
        and this file made it while labelling the result MEASURED. The per-core
        figure is still reported, so a reader can see which half was measured.
        """
        tp = throughput()
        for key in ("verification_sustained", "verification_peak"):
            self.assertEqual(tp[key]["provenance"], capacity.EXTRAPOLATED)
            self.assertIn("measured on ONE core", tp[key]["assumption"])
            self.assertEqual(tp[key]["per_core_measured"],
                             capacity.BENCHMARK["verify_per_core_single_witness"])

    def test_signing_is_measured_because_it_does_not_fan_out(self):
        """The contrast that makes the label mean something.

        Enrollment stays MEASURED: it is one signer's rate and the target needs
        nine minutes of it, so nothing is being multiplied.
        """
        self.assertEqual(throughput()["enrollment_surge"]["provenance"], MEASURED)

    def test_enrollment_is_minutes_of_one_signer(self):
        tp = throughput()
        self.assertLess(tp["enrollment_surge"]["signer_seconds_per_day"], 600)

    def test_signing_is_marked_as_not_fanning_out(self):
        """The lever is an HSM's rate, not a core count, and the note must say so."""
        note = throughput()["enrollment_surge"]["note"]
        self.assertIn("does NOT fan out", note)
        self.assertIn("private key", note)

    def test_the_rollout_duration_the_target_implies(self):
        """350M at 200,000 a day is 4.8 years, which the target does not say out loud."""
        tp = throughput()
        self.assertAlmostEqual(tp["population"]["years_to_enroll"], 4.79, places=1)
        self.assertEqual(tp["population"]["provenance"], DERIVED)


class RealSchemaTests(unittest.TestCase):
    """The live guarantee, not a fixture."""

    def setUp(self):
        with open(REAL_SCHEMA) as fh:
            self.schema = fh.read()

    def test_no_sequence_runs_out_inside_the_horizon(self):
        doomed = [(r["table"], r["column"]) for r in exhaustion(self.schema)
                  if r["exhausts_within_horizon"]]
        self.assertEqual(doomed, [],
                         "a sequence in the live schema runs out before the national "
                         "targets are reached")

    def test_the_hot_columns_are_64_bit(self):
        widths = {(t, c): w for t, c, w in sequence_columns(self.schema)}
        for key in (("VerificationEvent", "event_id"),
                    ("TokenStateEpochLeaf", "leaf_id"),
                    ("TokenLifecycleEvent", "event_id"),
                    ("TokenSignature", "signature_id"),
                    ("AuthAuditLog", "audit_id")):
            self.assertEqual(widths.get(key), "BIGSERIAL",
                             f"{key[0]}.{key[1]} must be 64-bit at national volumes")

    def test_the_nearest_surviving_32_bit_column_is_reported(self):
        """Clearing the horizon by a few years is not the same as being safe."""
        near = nearest_survivor(validate(self.schema))
        self.assertIsNotNone(near)
        self.assertEqual(near["width"], "SERIAL")
        self.assertFalse(near["exhausts_within_horizon"])

    def test_every_target_is_quoted_from_the_roadmap(self):
        roadmap = os.path.join(os.path.dirname(REAL_SCHEMA), "..", "ROADMAP.md")
        with open(os.path.normpath(roadmap)) as fh:
            import re
            text = re.sub(r"\s+", " ", fh.read())
        for key, target in capacity.TARGETS.items():
            import re as _re
            quote = _re.sub(r"\s+", " ", target["quote"])
            self.assertIn(quote, text, f"{key} is not the roadmap's own words")

    def test_a_met_verdict_carries_what_it_rests_on(self):
        """A verdict and its assumption travel together or the verdict cannot be graded."""
        v = validate(self.schema)["targets"]["verification_peak"]
        self.assertEqual(v["verdict"], "MET")
        self.assertIn("measured on ONE core", v["rests_on"])
        md = capacity.render_markdown(validate(self.schema))
        self.assertIn("What the MET verdicts rest on", md)

    def test_the_rendering_leads_with_what_is_not_met(self):
        md = capacity.render_markdown(validate(self.schema))
        self.assertIn("## Verdicts", md)
        self.assertLess(md.index("## Verdicts"), md.index("## Throughput"))
        self.assertIn("UNVALIDATED", md)


if __name__ == "__main__":
    unittest.main()
