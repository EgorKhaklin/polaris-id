"""polaris_web/transparency.py - what the authority publishes about itself (roadmap P7.7).

An identity authority asks to be trusted with the most invasive power in the system: the
ability to pull one named person's entire verification history. Every control around that
power -- the warrant, the role, the disclosure model -- is invisible from outside. A
transparency program is the one surface where the authority says out loud how often it used
that power, and invites anybody to check the parts that are checkable.

Two things make such a program worth reading rather than worth filing.

THE FIRST IS THAT EVERY FIGURE SAYS WHERE IT COMES FROM. A number a reader can recompute for
themselves from the public transparency log is a different kind of claim from a number only
the operator can see. Both belong in the report; conflating them does not. So every figure
carries a source: PUBLIC means a reader with the published log can derive it independently and
catch the authority lying; OPERATOR_ATTESTED means they cannot, and the figure rests on the
authority's word. An authority whose interesting numbers are all operator-attested has written
a press release.

THE SECOND IS THAT SMALL COUNTS ARE NOT PUBLISHABLE AND SUPPRESSING THEM IS NOT ENOUGH.
"Warrant audits in this quarter, in this context: 2" identifies people in a small enough
jurisdiction. The standard answer is to suppress cells below a threshold. The standard answer
is also, on its own, wrong: publish the total alongside the surviving cells and the suppressed
one is recovered by subtraction. So suppression here is checked rather than assumed. The
report computes, for every suppressed cell, the interval of values still consistent with
everything published -- in this report and in every earlier one -- and REFUSES TO BE EMITTED
if any suppressed cell has been narrowed to a single value.

That check drives two design decisions that would otherwise look arbitrary:

  MARGINS ARE NOT PUBLISHED. One total per period, and no row or column subtotals. Every
  margin is another equation, and it is the number of equations, not the number of withheld
  cells, that makes a table invertible.

  AND THERE IS NO CUMULATIVE TOTAL, which is the same rule applied to time. A running total
  republished every quarter looks like one figure and is not: the reader keeps last quarter's
  and subtracts, and a program that published a cumulative total each period would be
  publishing every per-period margin without ever deciding to. So each period carries its own
  total over its own cells, the periods share no equation, and the arithmetic that protects a
  cell in Q1 cannot be undone by what Q3 publishes.

  THAT MAKES REPUBLICATION FREE. A period's cells never change, and its suppression depends on
  nothing else, so recomputing it years later gives the identical answer. Publication is sticky
  without anybody having to store which decisions were sticky.

Counts of PEOPLE are suppressed. Counts of the system's own operations -- anchors written,
epochs closed, checks passed -- are not, because no person is disclosed by them, and blurring
them would only hide the operator's own failures behind a privacy control.

Finally, the report is digested and the digest is meant for the transparency log (P3.3). A
transparency report the operator can quietly revise afterwards is not evidence of anything.

See docs/design/transparency-program.md.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json

# ----------------------------------------------------------------------------
# Figure provenance.
#
# The distinction that makes the report worth reading: can a reader check this
# number without asking the authority to be honest?
# ----------------------------------------------------------------------------
SOURCE_PUBLIC = "PUBLIC"
#: Derivable by any reader from the published transparency log, the published
#: epochs, or the published source tree. A false PUBLIC figure is catchable.
SOURCE_OPERATOR_ATTESTED = "OPERATOR_ATTESTED"
#: Visible only inside the authority. A false OPERATOR_ATTESTED figure is not
#: catchable from outside, and the report says so next to the number.

FIGURE_SOURCES = (SOURCE_PUBLIC, SOURCE_OPERATOR_ATTESTED)

#: Cells counting people are suppressed below this. Cells counting the system's
#: own operations are not suppressed at all (see module docstring).
SUPPRESSION_THRESHOLD = 5

#: The standing cadence. A transparency program without one is a transparency
#: gesture: the operator publishes when the numbers are comfortable.
CADENCE_DAYS = 90

#: Protocol label for the report digest, so a digest cannot be replayed as some
#: other artifact's digest (same discipline as the STH and cosignature labels).
REPORT_DIGEST_LABEL = "polaris-transparency-report/1"


class InvertibleReport(Exception):
    """Raised when a suppressed cell is recoverable from what would be published.

    This is not a warning. A report that trips it is not published, because
    publishing it would disclose exactly the counts the suppression exists to
    protect, while carrying a suppression marker that says it did not.
    """


class Cell:
    """One published (or suppressed) figure.

    Attributes:
        key: stable identifier, e.g. ("2026-Q1", "LAW_ENFORCEMENT").
        count: the true value. Never leaves the authority when suppressed.
        counts_people: True when the figure counts people or accesses to
            people's records, and is therefore subject to suppression. False
            for the system's own operations (anchors, epochs, checks), which
            are published exactly.
        in_total: True when this cell is one of the addends of the report's
            single published grand total, i.e. when it participates in the
            subtraction equation. Cells outside the partition (a distinct-subject
            count, say, which is not an addend of anything) set this False and
            are constrained only by the threshold itself.
    """

    __slots__ = ("key", "count", "counts_people", "in_total")

    def __init__(self, key, count, counts_people=True, in_total=True):
        if int(count) < 0:
            raise ValueError(f"cell {key!r}: negative count {count!r}")
        self.key = tuple(key) if isinstance(key, (list, tuple)) else (key,)
        self.count = int(count)
        self.counts_people = bool(counts_people)
        self.in_total = bool(in_total) and bool(counts_people)

    def __repr__(self):  # pragma: no cover - debugging aid
        return (f"Cell({self.key!r}, {self.count!r}, "
                f"counts_people={self.counts_people!r}, in_total={self.in_total!r})")


def feasible_interval(residual, bounds, index):
    """The interval a suppressed cell's value can still take, given one equation.

    `bounds` is the list of (lo, hi) a-priori intervals of every suppressed cell
    participating in the published total, and `index` selects the cell in
    question. The cells sum to `residual` (the total minus everything the reader
    already knows), so cell i is bounded below by what the others cannot absorb
    and above by what they cannot give up:

        lo_i = max(apriori_lo_i, residual - sum of the others' highs)
        hi_i = min(apriori_hi_i, residual - sum of the others' lows)

    For a single linear equation under box constraints these bounds are exact,
    not a relaxation: each is attained by pushing every other cell to its
    opposite end. A width of zero means publishing the table discloses the cell
    exactly, suppression marker notwithstanding.

    THE A-PRIORI INTERVALS ARE NOT ALL THE SAME, and that is the part worth
    getting right. A cell suppressed because it is small is known to lie in
    [0, threshold-1]. A cell suppressed to protect it -- complementary
    suppression -- is known to lie AT OR ABOVE the threshold, because the reader
    can see it was not small enough to be suppressed on its own account. Treating
    the second like the first makes the arithmetic look infeasible and drives the
    caller to withhold the entire table.
    """
    lo_i, hi_i = bounds[index]
    others_hi = sum(h for j, (l, h) in enumerate(bounds) if j != index)
    others_lo = sum(l for j, (l, h) in enumerate(bounds) if j != index)
    return max(lo_i, residual - others_hi), min(hi_i, residual - others_lo)


class SuppressedTable:
    """The publishable form of a set of cells, plus the evidence that it is safe.

    Attributes:
        published: {key: count} for cells whose exact value is published.
        suppressed: sorted keys whose value is withheld.
        total: the grand total over `in_total` cells, or None when the total is
            itself withheld (the last-resort protection, see `suppress`).
        narrowest_width: the tightest feasible interval over the cells suppressed
            for being small, published as report metadata so a reader can judge
            the protection actually achieved rather than trust the threshold
            alone. None when no such cell is suppressed.
    """

    __slots__ = ("published", "suppressed", "total", "narrowest_width", "threshold")

    def __init__(self, published, suppressed, total, narrowest_width, threshold):
        self.published = published
        self.suppressed = suppressed
        self.total = total
        self.narrowest_width = narrowest_width
        self.threshold = threshold

    def as_dict(self):
        return {
            "published": {"/".join(k): v for k, v in sorted(self.published.items())},
            "suppressed": ["/".join(k) for k in self.suppressed],
            "total": self.total,
            "threshold": self.threshold,
            "narrowest_feasible_width": self.narrowest_width,
        }


def _apriori(cell, threshold, cap):
    """What a reader knows about a suppressed cell before any arithmetic.

    Primary suppression (the cell is small): [0, threshold-1]. The reader can see
    it was withheld on its own account.

    Complementary suppression (the cell was withheld to protect another):
    [threshold, cap]. The reader can see it was NOT small, or it would not have
    needed protecting. `cap` is the published total, since no single addend can
    exceed it.
    """
    if cell.count < threshold:
        return 0, threshold - 1
    return threshold, cap


def _intervals(cells_by_key, known_keys, suppressed_keys, total, threshold):
    """Feasible interval per suppressed cell under the candidate publication.

    `known_keys` is everything the reader holds: cells published in this report
    plus cells published in any earlier one. The distinction between those two
    matters for what suppression can still fix, never for what the reader can
    compute.
    """
    ceiling = threshold - 1
    in_eq = [k for k in suppressed_keys if cells_by_key[k].in_total]
    if total is None or not in_eq:
        return {k: _apriori(cells_by_key[k], threshold, total or ceiling)
                for k in suppressed_keys}
    known_sum = sum(cells_by_key[k].count for k in known_keys
                    if cells_by_key[k].in_total)
    residual = total - known_sum
    bounds = [_apriori(cells_by_key[k], threshold, total) for k in in_eq]
    out = {}
    for key in suppressed_keys:
        if not cells_by_key[key].in_total:
            # Outside the partition: no equation touches it, so it keeps exactly
            # the protection the threshold promises and nothing less.
            out[key] = _apriori(cells_by_key[key], threshold, total)
            continue
        out[key] = feasible_interval(residual, bounds, in_eq.index(key))
    return out


def _unprotected(intervals, cells_by_key, threshold):
    """Cells suppressed for being small that have been narrowed to one value.

    Only cells suppressed BECAUSE THEY ARE SMALL are checked. A complementary
    cell holds a count at or above the threshold; pinning its exact value loses
    information but discloses nobody, and the equation has already accounted for
    it when bounding the small cells.
    """
    return sorted(k for k, (lo, hi) in intervals.items()
                  if cells_by_key[k].count < threshold and hi - lo < 1)


def suppress(cells, threshold=SUPPRESSION_THRESHOLD, previously_published=(),
             previously_published_total=None, publish_total=True):
    """Decide what is publishable, and prove by construction that it is.

    Primary suppression withholds every people-counting cell below `threshold`.
    Complementary suppression then withholds further cells -- smallest first, so
    the least information is lost -- until no small cell is determined by
    subtraction. The last resort is to withhold the grand total, which removes
    the equation entirely and restores every suppressed cell to the interval the
    threshold promises.

    Complementary suppression before withholding the total is a judgment, not a
    theorem: both protect, and the total is the figure an oversight reader came
    for. Losing one context's count is the cheaper loss.

    Args:
        cells: iterable of Cell.
        threshold: cells below this are suppressed. Must be at least 2.
        previously_published: keys already public from an earlier report.
            Publication cannot be retracted, so these are pinned as published and
            counted as known to the reader.
        previously_published_total: a grand total published in an earlier report
            over this same series. If set, the equation it creates is PERMANENT
            and this call cannot withhold the total to escape it.
        publish_total: whether to attempt publishing the grand total at all.

    Returns: SuppressedTable.

    Raises:
        InvertibleReport: when a small cell is determined and nothing this call
            can do will change that -- which happens only when the reader already
            holds the figures that determine it. SUPPRESSING MORE CELLS CANNOT
            PROTECT AGAINST WHAT WAS ALREADY PUBLISHED, and the report is not
            emitted rather than carry a suppression marker that means nothing.
    """
    if threshold < 2:
        raise ValueError("suppression threshold must be at least 2")
    cells = list(cells)
    by_key = {}
    for c in cells:
        if c.key in by_key:
            raise ValueError(f"duplicate cell key {c.key!r}")
        by_key[c.key] = c
    pinned = {tuple(k) if isinstance(k, (list, tuple)) else (k,)
              for k in previously_published}
    unknown = pinned - set(by_key)
    if unknown:
        raise ValueError(f"previously published keys not in this series: {sorted(unknown)}")

    suppressed = {k for k, c in by_key.items()
                  if c.counts_people and c.count < threshold and k not in pinned}
    published = set(by_key) - suppressed

    if previously_published_total is not None:
        total = int(previously_published_total)
        total_is_permanent = True
    else:
        total_is_permanent = False
        total = None
        if publish_total and any(c.in_total for c in cells):
            total = sum(c.count for c in cells if c.in_total)
            if total < threshold:
                # A total this small is itself a small count.
                total = None

    while True:
        ordered = sorted(suppressed)
        if not ordered:
            return SuppressedTable({k: by_key[k].count for k in published},
                                   [], total, None, threshold)
        iv = _intervals(by_key, published, ordered, total, threshold)
        bad = _unprotected(iv, by_key, threshold)
        if not bad:
            small = [hi - lo for k, (lo, hi) in iv.items()
                     if by_key[k].count < threshold]
            return SuppressedTable({k: by_key[k].count for k in published},
                                   ordered, total, min(small) if small else None,
                                   threshold)
        # Complementary suppression is only useful on a cell the reader does not
        # already hold, so pinned cells are not candidates.
        nxt = sorted((k for k in published
                      if by_key[k].counts_people and k not in pinned),
                     key=lambda k: (by_key[k].count, k))
        if nxt:
            published.discard(nxt[0])
            suppressed.add(nxt[0])
            continue
        if total is not None and not total_is_permanent:
            total = None
            continue
        raise InvertibleReport(
            "these small cells are determined by figures the reader already "
            f"holds, and no further suppression can protect them: "
            f"{['/'.join(k) for k in bad]}")


def assert_not_invertible(table, cells, threshold=SUPPRESSION_THRESHOLD,
                          previously_published=()):
    """Independently re-derive every small cell's feasible interval.

    `suppress` decides; this re-checks the decision against the table as it would
    actually be published, so a bug in the decision procedure fails closed rather
    than shipping a report whose suppression markers are decorative. Called by
    `build_report` before any bytes exist.

    Raises InvertibleReport naming every determined cell.
    """
    by_key = {c.key: c for c in cells}
    if not table.suppressed:
        return
    known = set(table.published) | {
        tuple(k) if isinstance(k, (list, tuple)) else (k,)
        for k in previously_published}
    iv = _intervals(by_key, known, list(table.suppressed), table.total, threshold)
    bad = _unprotected(iv, by_key, threshold)
    if bad:
        raise InvertibleReport(
            "these suppressed cells are recoverable by subtraction: "
            f"{['/'.join(k) for k in bad]}")


# ----------------------------------------------------------------------------
# Cadence.
# ----------------------------------------------------------------------------

def quarter_of(day):
    """The calendar quarter label ("2026-Q3") a date falls in."""
    return f"{day.year}-Q{(day.month - 1) // 3 + 1}"


def quarters_between(start, end):
    """Every quarter label from `start`'s quarter through `end`'s, inclusive."""
    out, y, q = [], start.year, (start.month - 1) // 3 + 1
    last = (end.year, (end.month - 1) // 3 + 1)
    while (y, q) <= last:
        out.append(f"{y}-Q{q}")
        q += 1
        if q == 5:
            y, q = y + 1, 1
    return out


def missing_periods(published_periods, first_period_start, through):
    """Quarters in the program's life with no published report.

    A transparency program is judged by the gaps as much as by the contents, and
    an operator who skipped the quarter the incident happened in should not be
    able to publish a tidy series that hides the hole. The gaps go in the report.
    """
    expected = quarters_between(first_period_start, through)
    have = set(published_periods)
    return [p for p in expected if p not in have]


# ----------------------------------------------------------------------------
# The figures themselves.
# ----------------------------------------------------------------------------

WARRANT_AUDIT_ROUTE = "/uc7/warrant-audit"


def warrant_audit_cells(rows, threshold=SUPPRESSION_THRESHOLD):
    """Build the warrant-audit cells from AuditAccessLog rows.

    Each row is a mapping with `period`, `outcome` ("returned_records" or
    "returned_nothing") and `n`. The outcome split is the one an oversight reader
    actually needs: an authority whose warrant audits mostly return nothing is
    either casting wide or being refused by the disclosure model, and both are
    facts about how the power is used rather than about any individual.

    Distinct-subject counts are carried as non-total cells: they are not addends
    of the grand total, so they add no equation to the table.
    """
    cells = []
    for row in rows:
        cells.append(Cell((row["period"], row["outcome"]), row["n"]))
    return cells


def query_warrant_audits(query_fn):
    """Read the warrant-audit figures out of AuditAccessLog.

    `query_fn` is the app's `query` helper (or any callable taking SQL + params
    and returning dict-like rows), so this module does not own a connection.

    Counts ACCESSES, not subjects: an audit run twice over one person is two
    exercises of the power. The distinct-subject figure is reported beside it.
    """
    rows = query_fn("""
        SELECT to_char(accessed_at, 'YYYY') || '-Q' ||
                   to_char(accessed_at, 'Q')                  AS period,
               CASE WHEN coalesce(result_row_count, 0) > 0
                    THEN 'returned_records' ELSE 'returned_nothing' END AS outcome,
               count(*)                                        AS n
        FROM   AuditAccessLog
        WHERE  filter_criteria_jsonb->>'route' = %s
        GROUP  BY 1, 2
        ORDER  BY 1, 2
    """, (WARRANT_AUDIT_ROUTE,))
    return [dict(r) for r in rows]


def query_distinct_subjects(query_fn):
    """Distinct individuals subject to a warrant audit, per quarter."""
    rows = query_fn("""
        SELECT to_char(accessed_at, 'YYYY') || '-Q' ||
                   to_char(accessed_at, 'Q')                   AS period,
               count(DISTINCT filter_criteria_jsonb->>'individual_id') AS n
        FROM   AuditAccessLog
        WHERE  filter_criteria_jsonb->>'route' = %s
          AND  filter_criteria_jsonb ? 'individual_id'
        GROUP  BY 1
        ORDER  BY 1
    """, (WARRANT_AUDIT_ROUTE,))
    return [dict(r) for r in rows]


def query_anchor_cadence(query_fn):
    """Anchors written per quarter, and the longest gap between consecutive anchors.

    PUBLIC: every figure here is recomputable by a reader who has replicated the
    transparency log, which is the point of publishing it. The gap matters more
    than the count -- an authority that anchored 900 times in a quarter and then
    went dark for nine days has a nine-day window in which the log was not
    committing, and the count alone hides it.
    """
    rows = query_fn("""
        WITH gaps AS (
            SELECT created_at,
                   to_char(created_at, 'YYYY') || '-Q' ||
                       to_char(created_at, 'Q')          AS period,
                   created_at - lag(created_at) OVER (ORDER BY created_at) AS gap
            FROM   AnchorBatch
        )
        SELECT period,
               count(*)                                            AS anchors,
               coalesce(max(extract(epoch FROM gap)) / 3600.0, 0)   AS max_gap_hours
        FROM   gaps
        GROUP  BY period
        ORDER  BY period
    """)
    return [dict(r) for r in rows]


# ----------------------------------------------------------------------------
# The report.
# ----------------------------------------------------------------------------

def canonical_json(report):
    """Deterministic bytes for a report, so two readers digest the same thing."""
    return json.dumps(report, sort_keys=True, separators=(",", ":"),
                      default=str).encode("utf-8")


def report_digest(report):
    """SHA3-256 over the canonical bytes, domain-separated by a protocol label.

    Meant to be anchored in the transparency log (P3.3): a report the operator
    can revise after publication is not evidence, and a digest that is also a
    valid digest of some other artifact is not a commitment.
    """
    h = hashlib.sha3_256()
    h.update(REPORT_DIGEST_LABEL.encode("ascii"))
    h.update(b"\x00")
    h.update(canonical_json(report))
    return h.hexdigest()


def build_report(period, warrant_rows, distinct_rows, anchor_rows, check_results,
                 first_period_start, published_periods=(), previously_published=(),
                 previously_published_total=None, threshold=SUPPRESSION_THRESHOLD,
                 anchor_cadence_target_hours=None, generated_at=None):
    """Assemble one transparency report, refusing to emit an invertible one.

    Args:
        period: the quarter this report covers, e.g. "2026-Q3".
        warrant_rows / distinct_rows / anchor_rows: as returned by the query
            helpers above, over the WHOLE series rather than this period alone.
            Each period is suppressed independently of the others.
        check_results: {"total": int, "passed": int, "failed": int}. Counts the
            system's own audit results, not people, so it is published exactly.
        first_period_start: date the program began, for the cadence gap list.
        published_periods: periods already published, for the same.
        previously_published: cell keys already public, pinned as published.
        previously_published_total: {period: total} for totals an earlier report
            published, whose equations are permanent. Normally unnecessary,
            because a period's suppression is a pure function of its own cells
            and recomputes to the same answer.
        anchor_cadence_target_hours: the longest anchoring gap the authority
            commits to. Nothing in the database knows this, so it is declared
            rather than derived, and a program that declares none publishes that
            fact instead of a column of gap figures nobody can grade.
        generated_at: overridable for reproducible tests.

    Returns a dict, plus its digest under "digest".

    Raises InvertibleReport if suppression cannot protect the small cells.
    """
    gen = generated_at or _dt.datetime.now(_dt.timezone.utc)
    cells = warrant_audit_cells(warrant_rows, threshold)
    for row in distinct_rows:
        # Not an addend of any total: adds no equation, only a threshold.
        cells.append(Cell((row["period"], "distinct_subjects"), row["n"],
                          in_total=False))

    # One independent suppression per period. The periods share no equation, so
    # no arithmetic crosses a period boundary and republishing an old period is
    # idempotent rather than a new disclosure.
    by_period = {}
    for cell in cells:
        by_period.setdefault(cell.key[0], []).append(cell)
    tables = {}
    for pname in sorted(by_period):
        pcells = by_period[pname]
        table = suppress(pcells, threshold=threshold,
                         previously_published=[k for k in previously_published
                                               if tuple(k)[0] == pname],
                         previously_published_total=(previously_published_total or {}
                                                     ).get(pname))
        assert_not_invertible(table, pcells, threshold,
                              previously_published=[k for k in previously_published
                                                    if tuple(k)[0] == pname])
        tables[pname] = table

    target = (float(anchor_cadence_target_hours)
              if anchor_cadence_target_hours is not None else None)
    anchors = {}
    for r in anchor_rows:
        gap = round(float(r["max_gap_hours"]), 2)
        anchors[r["period"]] = {
            "anchors": int(r["anchors"]),
            "max_gap_hours": gap,
            # A gap printed in a column and left ungraded is hidden in plain
            # sight. None means the authority declared no target to grade it by.
            "exceeded_target": None if target is None else gap > target,
        }
    # The report you are reading is not a missing report.
    gaps = missing_periods(tuple(published_periods) + (period,),
                           first_period_start, gen.date())

    report = {
        "label": REPORT_DIGEST_LABEL,
        "period": period,
        "generated_at": gen.replace(microsecond=0).isoformat(),
        "cadence_days": CADENCE_DAYS,
        "periods_with_no_report": gaps,
        "figures": {
            "warrant_audits": {
                "by_period": {p: t.as_dict() for p, t in tables.items()},
                "source": SOURCE_OPERATOR_ATTESTED,
            },
            "anchor_cadence": {"by_period": anchors, "source": SOURCE_PUBLIC,
                               "target_hours": target},
            "audit_results": dict(check_results, source=SOURCE_PUBLIC),
        },
        "notes": {
            "suppression":
                "Cells counting people below the threshold are withheld. Cells "
                "counting the system's own operations are published exactly: no "
                "person is disclosed by them, and blurring them would hide the "
                "operator's failures behind a privacy control.",
            "margins":
                "One total per period and no subtotals. Every margin is another "
                "equation, and the equation count is what makes a withheld table "
                "invertible.",
            "no_cumulative_total":
                "There is deliberately no running total across periods. "
                "Republished each quarter it would look like one figure and be "
                "many: the reader keeps the last one and subtracts, and the "
                "program would publish every per-period margin without ever "
                "deciding to.",
            "warrant_audits_are_attested":
                "Warrant-audit counts come from the authority's own append-only "
                "access log. A reader cannot recompute them from public data and "
                "cannot detect an authority that failed to record an access.",
        },
    }
    report["digest"] = report_digest(
        {k: v for k, v in report.items() if k != "digest"})
    return report


def render_markdown(report):
    """The human-readable publication. Deterministic for a given report."""
    f = report["figures"]
    w = f["warrant_audits"]
    lines = [
        f"# Transparency report {report['period']}",
        "",
        f"Generated {report['generated_at']}. Digest `{report['digest']}`.",
        f"Published on a {report['cadence_days']}-day cadence.",
        "",
        "## How to read the sources",
        "",
        f"`{SOURCE_PUBLIC}` figures are recomputable by any reader from the "
        "published transparency log or the published source tree; an authority "
        "that misstates one can be caught from outside. "
        f"`{SOURCE_OPERATOR_ATTESTED}` figures cannot be, and rest on the "
        "authority's word.",
        "",
        "## Warrant-authorized verification history",
        "",
        f"Source: {w['source']}. Counts are exercises of the power, not people: "
        "an audit run twice over one person is two exercises, and the distinct "
        "subjects are counted separately below.",
        "",
        "Each period carries its own total and no running total is published "
        "across periods. A cumulative figure republished every quarter would look "
        "like one number and be many, since a reader keeps the last one and "
        "subtracts.",
        "",
    ]
    aside = {}
    for pname in sorted(w["by_period"]):
        t = w["by_period"][pname]
        partition = {k: v for k, v in sorted(t["published"].items())
                     if not k.endswith("/distinct_subjects")}
        sup = [k for k in t["suppressed"] if not k.endswith("/distinct_subjects")]
        for k, v in t["published"].items():
            if k.endswith("/distinct_subjects"):
                aside[pname] = v
        for k in t["suppressed"]:
            if k.endswith("/distinct_subjects"):
                aside[pname] = None
        lines += [
            f"### {pname}",
            "",
            f"Cells below {t['threshold']} are withheld, and so is any cell whose "
            "publication would recover a withheld one.",
            "",
            "| Outcome | Audits |",
            "| --- | --- |",
        ]
        for key, value in partition.items():
            lines.append(f"| {key.split('/', 1)[1]} | {value} |")
        for key in sup:
            lines.append(f"| {key.split('/', 1)[1]} | withheld |")
        lines.append(f"| **{pname} total** | "
                     f"{t['total'] if t['total'] is not None else 'withheld'} |")
        if t["narrowest_feasible_width"] is not None:
            lines += [
                "",
                "Narrowest feasible interval over the withheld small cells: "
                f"{t['narrowest_feasible_width'] + 1} possible values. A width of "
                "one value would mean a withheld cell is recoverable by "
                "subtraction, and this report would not have been generated.",
            ]
        lines.append("")

    lines += [
        "### Distinct subjects",
        "",
        "Counted separately and deliberately excluded from every total above. It "
        "is not an addend of anything, so it adds no equation a reader could "
        "subtract with.",
        "",
        "| Period | Subjects |",
        "| --- | --- |",
    ]
    for pname in sorted(aside):
        v = aside[pname]
        lines.append(f"| {pname} | {v if v is not None else 'withheld'} |")

    ac = f["anchor_cadence"]
    lines += [
        "",
        "## Anchor cadence",
        "",
        f"Source: {ac['source']}. Recomputable by any reader who has replicated "
        "the transparency log. The longest gap matters more than the count: an "
        "authority that anchored nine hundred times and then went dark for a week "
        "has a week in which the log committed to nothing, and the count alone "
        "hides it.",
        "",
    ]
    if ac["target_hours"] is None:
        lines += [
            "This authority has declared no maximum anchoring gap, so the figures "
            "below are ungraded. Declaring one is what turns them into a "
            "commitment a reader can hold it to.",
            "",
            "| Period | Anchors | Longest gap (hours) |",
            "| --- | --- | --- |",
        ]
        for pname, row in sorted(ac["by_period"].items()):
            lines.append(f"| {pname} | {row['anchors']} | {row['max_gap_hours']} |")
    else:
        lines += [
            f"Declared maximum gap: {ac['target_hours']} hours.",
            "",
            "| Period | Anchors | Longest gap (hours) | Within declared gap |",
            "| --- | --- | --- | --- |",
        ]
        for pname, row in sorted(ac["by_period"].items()):
            met = "no" if row["exceeded_target"] else "yes"
            lines.append(f"| {pname} | {row['anchors']} | "
                         f"{row['max_gap_hours']} | {met} |")

    ar = f["audit_results"]
    lines += [
        "",
        "## Audit results",
        "",
        f"Source: {ar['source']}. {ar['passed']} of {ar['total']} checks passed, "
        f"{ar['failed']} failed. Re-runnable against the published tree by anyone.",
        "",
        "## Cadence",
        "",
    ]
    if report["periods_with_no_report"]:
        lines.append("Periods since the program began with no published report: "
                     + ", ".join(report["periods_with_no_report"])
                     + ". A missing period is part of the record.")
    else:
        lines.append("No period since the program began is missing a report.")
    lines += [
        "",
        "## What this report does not tell you",
        "",
        "It counts the accesses the authority recorded. It cannot show an access "
        "that was never recorded, and no reader can derive the warrant-audit "
        "figures independently. That limit is the reason the access log is "
        "append-only and the reason this report's digest belongs in the "
        "transparency log, not a reason to read the figures as proof.",
        "",
    ]
    return "\n".join(lines)
