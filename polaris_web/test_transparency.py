"""test_transparency.py - the public transparency program (roadmap P7.7).

The module's job is to publish figures about the authority's most invasive power without
publishing the people behind the small ones. These tests are about the second half, because
the first half is arithmetic and the second half is where transparency programs go wrong: a
cell marked withheld that a reader recovers by subtraction is worse than a cell printed
plainly, since the marker tells the reader it was protected.

`scripts/polaris-transparency-report-drill.py` attacks thousands of random tables with an
independent solver. These are the cases worth naming.

Run: python3 -m unittest test_transparency
"""

import datetime
import unittest

import transparency
from transparency import (
    Cell, InvertibleReport, SOURCE_OPERATOR_ATTESTED, SOURCE_PUBLIC,
    SUPPRESSION_THRESHOLD, assert_not_invertible, build_report, canonical_json,
    missing_periods, quarter_of, quarters_between, render_markdown,
    report_digest, suppress,
)

K = SUPPRESSION_THRESHOLD


def keys(table):
    return {"/".join(k) for k in table.suppressed}


class SuppressionTests(unittest.TestCase):
    """What is withheld, and whether withholding it accomplished anything."""

    def test_small_cells_are_withheld(self):
        t = suppress([Cell(("Q1", "a"), 2), Cell(("Q1", "b"), 40),
                      Cell(("Q1", "c"), 51)])
        self.assertIn("Q1/a", keys(t))

    def test_a_lone_small_cell_is_not_recoverable_from_the_total(self):
        """The failure the whole module exists to prevent.

        One small cell, two large ones, and a published total: subtract and the
        small cell is back. Complementary suppression must take a second cell
        with it, and the smallest one, so the least is lost.
        """
        cells = [Cell(("Q1", "law"), 3), Cell(("Q1", "border"), 40),
                 Cell(("Q1", "health"), 12)]
        t = suppress(cells)
        self.assertEqual(keys(t), {"Q1/law", "Q1/health"})
        self.assertEqual(t.total, 55)
        self.assertEqual(t.published, {("Q1", "border"): 40})
        # And the withheld small cell still has room to move.
        self.assertGreaterEqual(t.narrowest_width, 1)

    def test_complementary_suppression_takes_the_smallest_survivor(self):
        cells = [Cell(("Q1", "a"), 1), Cell(("Q1", "b"), 9),
                 Cell(("Q1", "c"), 60), Cell(("Q1", "d"), 80)]
        t = suppress(cells)
        self.assertIn("Q1/b", keys(t))
        self.assertNotIn("Q1/c", keys(t))
        self.assertNotIn("Q1/d", keys(t))

    def test_two_cells_at_the_ceiling_are_still_determined(self):
        """A count of suppressed cells is not a safety argument.

        Two withheld cells summing to 8 with a ceiling of 4 pins both at 4. Rules
        that require "at least two suppressed cells" pass this table and disclose
        both figures.
        """
        cells = [Cell(("Q1", "a"), 4), Cell(("Q1", "b"), 4), Cell(("Q1", "c"), 40)]
        t = suppress(cells)
        self.assertIn("Q1/c", keys(t))
        self.assertGreaterEqual(t.narrowest_width, 1)

    def test_the_total_is_withheld_only_as_a_last_resort(self):
        """Nothing left to suppress complementarily, so the equation goes instead."""
        cells = [Cell(("Q1", "a"), 3), Cell(("Q1", "b"), 40)]
        t = suppress(cells, previously_published=[("Q1", "b")])
        self.assertEqual(t.published, {("Q1", "b"): 40})
        self.assertIsNone(t.total)
        self.assertIn("Q1/a", keys(t))

    def test_a_total_below_the_threshold_is_itself_a_small_count(self):
        t = suppress([Cell(("Q1", "a"), 1), Cell(("Q1", "b"), 2)])
        self.assertIsNone(t.total)

    def test_operations_counts_are_never_withheld(self):
        """Blurring the system's own numbers hides the operator, not a person."""
        t = suppress([Cell(("Q1", "anchors"), 2, counts_people=False)])
        self.assertEqual(t.suppressed, [])
        self.assertEqual(t.published, {("Q1", "anchors"): 2})

    def test_a_non_total_cell_adds_no_equation(self):
        """Distinct subjects are not an addend, so they cannot be subtracted with."""
        cells = [Cell(("Q1", "subjects"), 3, in_total=False),
                 Cell(("Q1", "audits"), 40)]
        t = suppress(cells)
        self.assertEqual(t.total, 40)
        self.assertEqual(keys(t), {"Q1/subjects"})
        self.assertEqual(t.narrowest_width, K - 1)

    def test_a_non_total_cell_is_unaffected_by_the_equation_beside_it(self):
        """Both kinds of withheld cell in one table: only one is in the equation."""
        cells = [Cell(("Q1", "subjects"), 2, in_total=False),
                 Cell(("Q1", "law"), 3), Cell(("Q1", "border"), 40),
                 Cell(("Q1", "health"), 12)]
        t = suppress(cells)
        self.assertIn("Q1/subjects", keys(t))
        self.assertIn("Q1/law", keys(t))
        # The subjects cell keeps the full interval the threshold promises; the
        # law cell is bounded by the total and still has room to move.
        self.assertGreaterEqual(t.narrowest_width, 1)

    def test_a_history_that_already_determined_a_cell_is_refused(self):
        """Suppressing more cannot protect against what the reader already holds.

        An earlier report published the total and every cell but one. There is no
        complementary suppression left to make and the equation cannot be
        withdrawn, so the report is not generated.
        """
        cells = [Cell(("Q1", "law"), 3), Cell(("Q1", "border"), 40),
                 Cell(("Q1", "health"), 12)]
        with self.assertRaises(InvertibleReport) as caught:
            suppress(cells, previously_published=[("Q1", "border"), ("Q1", "health")],
                     previously_published_total=55)
        self.assertIn("Q1/law", str(caught.exception))

    def test_published_cells_stay_published(self):
        t = suppress([Cell(("Q1", "a"), 2), Cell(("Q1", "b"), 40)],
                     previously_published=[("Q1", "a")])
        self.assertIn(("Q1", "a"), t.published)

    def test_a_threshold_below_two_is_not_a_threshold(self):
        with self.assertRaises(ValueError):
            suppress([Cell(("Q1", "a"), 1)], threshold=1)

    def test_duplicate_and_negative_cells_are_rejected(self):
        with self.assertRaises(ValueError):
            suppress([Cell(("Q1", "a"), 1), Cell(("Q1", "a"), 2)])
        with self.assertRaises(ValueError):
            Cell(("Q1", "a"), -1)

    def test_pinning_a_key_outside_the_series_is_rejected(self):
        with self.assertRaises(ValueError):
            suppress([Cell(("Q1", "a"), 9)], previously_published=[("Q9", "z")])


class IndependentRecheckTests(unittest.TestCase):
    """The guard that catches a bug in the decision procedure itself."""

    def test_a_hand_built_invertible_table_is_caught(self):
        """Simulates `suppress` going wrong: the marker is there, the protection is not."""
        cells = [Cell(("Q1", "law"), 3), Cell(("Q1", "border"), 40)]
        bad = transparency.SuppressedTable(
            {("Q1", "border"): 40}, [("Q1", "law")], 43, 4, K)
        with self.assertRaises(InvertibleReport) as caught:
            assert_not_invertible(bad, cells)
        self.assertIn("Q1/law", str(caught.exception))

    def test_a_sound_table_passes(self):
        cells = [Cell(("Q1", "law"), 3), Cell(("Q1", "border"), 40),
                 Cell(("Q1", "health"), 12)]
        assert_not_invertible(suppress(cells), cells)


class CadenceTests(unittest.TestCase):

    def test_quarter_labels(self):
        self.assertEqual(quarter_of(datetime.date(2026, 1, 31)), "2026-Q1")
        self.assertEqual(quarter_of(datetime.date(2026, 12, 1)), "2026-Q4")

    def test_quarters_span_a_year_boundary(self):
        self.assertEqual(
            quarters_between(datetime.date(2026, 11, 2), datetime.date(2027, 2, 9)),
            ["2026-Q4", "2027-Q1"])

    def test_a_skipped_period_is_reported(self):
        gaps = missing_periods(["2026-Q2", "2026-Q4"], datetime.date(2026, 4, 1),
                               datetime.date(2026, 12, 31))
        self.assertEqual(gaps, ["2026-Q3"])


class ReportTests(unittest.TestCase):

    WARRANT = [{"period": "2026-Q2", "outcome": "returned_records", "n": 3},
               {"period": "2026-Q2", "outcome": "returned_nothing", "n": 11},
               {"period": "2026-Q3", "outcome": "returned_records", "n": 47},
               {"period": "2026-Q3", "outcome": "returned_nothing", "n": 9}]
    DISTINCT = [{"period": "2026-Q2", "n": 12}, {"period": "2026-Q3", "n": 40}]
    ANCHORS = [{"period": "2026-Q2", "anchors": 812, "max_gap_hours": 6.5},
               {"period": "2026-Q3", "anchors": 903, "max_gap_hours": 211.0}]
    CHECKS = {"total": 222, "passed": 222, "failed": 0}
    AT = datetime.datetime(2026, 9, 10, 12, 0, 0, tzinfo=datetime.timezone.utc)

    def report(self, **kw):
        args = dict(period="2026-Q3", warrant_rows=self.WARRANT,
                    distinct_rows=self.DISTINCT, anchor_rows=self.ANCHORS,
                    check_results=self.CHECKS,
                    first_period_start=datetime.date(2026, 4, 1),
                    published_periods=["2026-Q2"], generated_at=self.AT)
        args.update(kw)
        return build_report(**args)

    def test_every_figure_declares_its_source(self):
        figures = self.report()["figures"]
        self.assertEqual(figures["anchor_cadence"]["source"], SOURCE_PUBLIC)
        self.assertEqual(figures["audit_results"]["source"], SOURCE_PUBLIC)
        self.assertEqual(figures["warrant_audits"]["source"],
                         SOURCE_OPERATOR_ATTESTED)

    def test_periods_are_suppressed_independently(self):
        """Q2's small cell must not cost Q3 a figure.

        A single pass over the series shares one equation across quarters, and
        the complementary suppression it forces lands wherever the numbers happen
        to be smallest. Per-period passes keep Q3 whole.
        """
        w = self.report()["figures"]["warrant_audits"]["by_period"]
        self.assertEqual(w["2026-Q2"]["suppressed"],
                         ["2026-Q2/returned_nothing", "2026-Q2/returned_records"])
        self.assertEqual(w["2026-Q3"]["suppressed"], [])
        self.assertEqual(w["2026-Q3"]["published"]["2026-Q3/returned_records"], 47)

    def test_there_is_no_cumulative_total(self):
        """Republished each quarter, a running total is every margin by subtraction."""
        w = self.report()["figures"]["warrant_audits"]
        self.assertNotIn("total", w)
        self.assertEqual(w["by_period"]["2026-Q2"]["total"], 14)
        self.assertEqual(w["by_period"]["2026-Q3"]["total"], 56)

    def test_the_report_does_not_list_itself_as_missing(self):
        self.assertEqual(self.report()["periods_with_no_report"], [])

    def test_a_skipped_quarter_appears_in_the_report(self):
        r = self.report(period="2026-Q4", published_periods=["2026-Q2"],
                        generated_at=datetime.datetime(2026, 12, 1, tzinfo=datetime.timezone.utc))
        self.assertEqual(r["periods_with_no_report"], ["2026-Q3"])

    def test_an_undeclared_anchor_target_leaves_the_gaps_ungraded(self):
        ac = self.report()["figures"]["anchor_cadence"]
        self.assertIsNone(ac["target_hours"])
        self.assertIsNone(ac["by_period"]["2026-Q3"]["exceeded_target"])

    def test_a_declared_anchor_target_grades_them(self):
        ac = self.report(anchor_cadence_target_hours=24)["figures"]["anchor_cadence"]
        self.assertFalse(ac["by_period"]["2026-Q2"]["exceeded_target"])
        self.assertTrue(ac["by_period"]["2026-Q3"]["exceeded_target"])

    def test_the_digest_is_deterministic_and_domain_separated(self):
        a, b = self.report(), self.report()
        self.assertEqual(a["digest"], b["digest"])
        naked = {k: v for k, v in a.items() if k != "digest"}
        self.assertEqual(a["digest"], report_digest(naked))
        import hashlib
        undomained = hashlib.sha3_256(canonical_json(naked)).hexdigest()
        self.assertNotEqual(a["digest"], undomained)

    def test_the_digest_changes_when_a_figure_does(self):
        a = self.report()
        b = self.report(check_results={"total": 222, "passed": 221, "failed": 1})
        self.assertNotEqual(a["digest"], b["digest"])

    def test_an_invertible_history_refuses_the_whole_report(self):
        with self.assertRaises(InvertibleReport):
            self.report(previously_published=[("2026-Q2", "returned_nothing"),
                                              ("2026-Q2", "distinct_subjects")],
                        previously_published_total={"2026-Q2": 14})

    def test_the_rendering_is_deterministic_and_states_its_limit(self):
        md = render_markdown(self.report())
        self.assertEqual(md, render_markdown(self.report()))
        self.assertIn("cannot show an access that was never recorded", md)
        self.assertIn("no running total is published", md)
        self.assertIn("withheld", md)
        self.assertIn(SOURCE_OPERATOR_ATTESTED, md)

    def test_a_withheld_subject_count_renders_as_withheld(self):
        md = render_markdown(self.report(
            distinct_rows=[{"period": "2026-Q2", "n": 2},
                           {"period": "2026-Q3", "n": 40}]))
        self.assertIn("| 2026-Q2 | withheld |", md)
        self.assertIn("| 2026-Q3 | 40 |", md)

    def test_the_rendering_grades_a_declared_target(self):
        md = render_markdown(self.report(anchor_cadence_target_hours=24))
        self.assertIn("Declared maximum gap: 24.0 hours.", md)
        self.assertIn("| 2026-Q3 | 903 | 211.0 | no |", md)


class QueryShapeTests(unittest.TestCase):
    """The SQL asks for what the report publishes, and only that."""

    class Recorder:
        def __init__(self):
            self.calls = []

        def __call__(self, sql, params=None):
            self.calls.append((sql, params))
            return []

    def test_warrant_query_selects_on_the_route_and_buckets_the_outcome(self):
        q = self.Recorder()
        transparency.query_warrant_audits(q)
        sql, params = q.calls[0]
        self.assertIn("AuditAccessLog", sql)
        self.assertIn("returned_nothing", sql)
        self.assertEqual(params, (transparency.WARRANT_AUDIT_ROUTE,))

    def test_distinct_subjects_counts_distinct_individuals(self):
        q = self.Recorder()
        transparency.query_distinct_subjects(q)
        sql, _ = q.calls[0]
        self.assertIn("count(DISTINCT", sql)
        self.assertIn("individual_id", sql)

    def test_anchor_query_reports_the_gap_not_only_the_count(self):
        q = self.Recorder()
        transparency.query_anchor_cadence(q)
        sql, _ = q.calls[0]
        self.assertIn("AnchorBatch", sql)
        self.assertIn("max_gap_hours", sql)
        self.assertIn("lag(created_at)", sql)

    def test_no_query_selects_a_subject_identifier_into_the_figures(self):
        """The report aggregates; it never carries a person out of the log."""
        q = self.Recorder()
        transparency.query_warrant_audits(q)
        transparency.query_anchor_cadence(q)
        for sql, _ in q.calls:
            self.assertNotIn("legal_name", sql)
            self.assertNotIn("token_value", sql)


if __name__ == "__main__":
    unittest.main()
