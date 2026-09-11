#!/usr/bin/env python3
"""polaris-transparency-report-drill.py - attack the report the authority just published (P7.7).

Suppressing small counts is the part everybody does. Checking that the suppression survived
publication is the part that gets skipped, and it is the part that decides whether a withheld
cell was actually withheld. Publish the total beside the cells that survived and the cell
reading 3 comes back by subtraction, while the table still carries a marker claiming it was
protected. The marker is then worse than nothing: it tells a reader the figure is safe.

So this drill does not inspect the suppression logic. It takes the report AS PUBLISHED -- the
cells, the total, and nothing else -- and plays an adversary who wants the withheld numbers.

  THE ADVERSARY SOLVES, IT DOES NOT GUESS. For every assignment of the withheld cells
  consistent with what the reader can see (each small cell in [0, threshold), each cell
  withheld to protect another at or above the threshold, all of them summing to the published
  residual), it collects the values each cell could take. A cell with exactly one surviving
  value has been published, whatever the table says about it.

  IT RUNS OVER RANDOM TABLES, NOT FIXTURES. Thousands of them, with the shapes that actually
  break suppression: several cells pinned at the ceiling, one small cell among large ones,
  every cell small, totals that land exactly on the sum of the maxima. A fixture proves the
  case somebody thought of.

  IT ATTACKS THE SERIES, NOT THE REPORT. Publication cannot be retracted, so the adversary
  also gets every figure published in earlier reports. The interesting failure is not a single
  invertible table; it is a cell that was safely withheld in Q1 and becomes recoverable in Q3
  because the cell beside it grew past the threshold and got published.

  AND IT CHECKS THE REFUSAL FIRES. A system that never refuses has not been shown to be able
  to. The drill constructs a series whose history already determines a withheld cell and
  requires the report to refuse to exist rather than publish a reassuring marker over a number
  the reader can already compute.

Exits non-zero on any recovery. No database required: the adversary needs only what a member
of the public would have.
"""
from __future__ import annotations

import itertools
import random
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from polaris_web.transparency import (  # noqa: E402
    Cell, InvertibleReport, SUPPRESSION_THRESHOLD, suppress,
)

TRIALS = 4000
MAX_CELLS = 7


def _reach(ranges):
    """Reachable-sum bitsets, prefix and suffix, for a list of (lo, hi) ranges.

    Bit s of `prefix[i]` is set when cells 0..i-1 can sum to exactly s.
    """
    n = len(ranges)
    prefix = [1] + [0] * n
    for i, (lo, hi) in enumerate(ranges):
        mask = 0
        for v in range(lo, hi + 1):
            mask |= prefix[i] << v
        prefix[i + 1] = mask
    suffix = [0] * (n + 1)
    suffix[n] = 1
    for i in range(n - 1, -1, -1):
        lo, hi = ranges[i]
        mask = 0
        for v in range(lo, hi + 1):
            mask |= suffix[i + 1] << v
        suffix[i] = mask
    return prefix, suffix


def recover(table, cells, threshold, previously_published=()):
    """Play the reader. Return the withheld cells the published table determines.

    The adversary knows, for each withheld cell, only what publication itself
    reveals: a cell withheld on its own account is below the threshold, and a
    cell withheld to protect another is not, or it would have been withheld on
    its own account. Everything else is arithmetic on the published total.

    The method is deliberately NOT the module's: `transparency.feasible_interval`
    bounds each cell in closed form, and an attack that recomputed the same
    formula would confirm the formula against itself. This enumerates reachable
    sums instead -- a value survives for a cell when the cells before it can
    reach some sum, and the cells after it can reach the rest. Two different
    algorithms agreeing is evidence; one algorithm agreeing with itself is not.
    """
    by_key = {c.key: c for c in cells}
    known = set(table.published) | {tuple(k) for k in previously_published}
    withheld = [k for k in table.suppressed if by_key[k].in_total]
    if not withheld or table.total is None:
        return []
    residual = table.total - sum(by_key[k].count for k in known
                                 if by_key[k].in_total)
    if residual < 0:
        return [(k, None) for k in withheld]
    ranges = []
    for key in withheld:
        if by_key[key].count < threshold:
            ranges.append((0, threshold - 1))       # withheld for being small
        else:
            ranges.append((threshold, residual))    # withheld to protect another
    prefix, suffix = _reach(ranges)
    determined = []
    for j, key in enumerate(withheld):
        lo, hi = ranges[j]
        survivors = []
        for v in range(lo, hi + 1):
            rest = residual - v
            if rest < 0:
                break
            # Some split of `rest` between the cells before and after cell j.
            before, after = prefix[j], suffix[j + 1]
            hit = False
            for a in range(rest + 1):
                if (before >> a) & 1 and (after >> (rest - a)) & 1:
                    hit = True
                    break
            if hit:
                survivors.append(v)
                if len(survivors) > 1:
                    break
        if by_key[key].count < threshold and len(survivors) == 1:
            determined.append((key, survivors[0]))
        elif not survivors:
            # No assignment fits what was published: the figures are mutually
            # inconsistent, which is its own failure and must not pass silently.
            determined.append((key, None))
    return determined


def random_cells(rng):
    n = rng.randint(1, MAX_CELLS)
    shape = rng.choice(("mixed", "all_small", "ceiling", "one_small"))
    out = []
    for i in range(n):
        if shape == "all_small":
            v = rng.randint(0, SUPPRESSION_THRESHOLD - 1)
        elif shape == "ceiling":
            v = rng.choice([SUPPRESSION_THRESHOLD - 1] * 3 + [rng.randint(0, 60)])
        elif shape == "one_small":
            v = rng.randint(0, SUPPRESSION_THRESHOLD - 1) if i == 0 else rng.randint(20, 90)
        else:
            v = rng.randint(0, 40)
        out.append(Cell((f"P{i // 3}", f"c{i}"), v))
    return out


def main():
    rng = random.Random(20260910)
    failures = []
    attacked = 0

    # 1. Single reports, random shapes.
    for _ in range(TRIALS):
        cells = random_cells(rng)
        try:
            table = suppress(cells)
        except InvertibleReport:
            continue  # refused: nothing was published, so nothing is recoverable
        got = recover(table, cells, SUPPRESSION_THRESHOLD)
        attacked += 1
        if got:
            failures.append(("single", [(k, v) for k, v in got],
                             [(c.key, c.count) for c in cells]))

    # 2. The series attack: a program publishing quarter after quarter.
    #
    # Each period is suppressed independently and no running total is published
    # across periods, so the equations should be disjoint and nothing should
    # cross a period boundary. That is a claim about the design, and the drill
    # tests it rather than trusting it: the adversary is handed EVERY report the
    # program has ever published and attacks each period's table holding all of
    # them. A design that quietly reintroduced a cumulative figure would show up
    # here as a recovery in an old quarter that was safe when it was published.
    series_reports = 0
    for _ in range(TRIALS // 4):
        quarters = {f"Q{q}": [Cell((f"Q{q}", f"c{i}"), rng.randint(0, 45))
                              for i in range(rng.randint(2, 4))]
                    for q in range(1, rng.randint(3, 6))}
        published = []          # every table the program has published so far
        pinned = set()
        for pname in sorted(quarters):
            pcells = quarters[pname]
            try:
                table = suppress(pcells,
                                 previously_published=[k for k in pinned
                                                       if k[0] == pname])
            except InvertibleReport:
                continue
            series_reports += 1
            published.append((pname, table, pcells))
            pinned |= set(table.published)
            # Re-attack every quarter already out, now that a new one is public.
            for past_name, past_table, past_cells in published:
                got = recover(past_table, past_cells, SUPPRESSION_THRESHOLD,
                              previously_published=[k for k in pinned
                                                    if k[0] == past_name])
                attacked += 1
                if got:
                    failures.append(("series", [(k, v) for k, v in got],
                                     [(c.key, c.count) for c in past_cells]))

    # 3. The refusal must actually fire on a series history already determines.
    determined_history = [Cell(("Q1", "law"), 3), Cell(("Q1", "border"), 40),
                          Cell(("Q1", "health"), 12)]
    refused = False
    try:
        suppress(determined_history,
                 previously_published=[("Q1", "border"), ("Q1", "health")],
                 previously_published_total=55)
    except InvertibleReport:
        refused = True

    print(f"tables attacked: {attacked}")
    print(f"multi-quarter series simulated: {series_reports} period tables "
          f"published and re-attacked as the series grew")
    print(f"refusal fires on a history that already determined a cell: {refused}")

    if not refused:
        failures.append(("refusal", "a series whose history determines a withheld "
                                    "cell was published anyway", []))
    if series_reports < TRIALS // 4:
        failures.append(("series-coverage", f"only {series_reports} series reports were "
                                            "published; the growing-series attack must "
                                            "actually run", []))
    if attacked < TRIALS:
        failures.append(("coverage", f"only {attacked} tables were actually attacked; "
                                     "the drill must not pass by never attacking", []))

    if failures:
        print(f"\nFAIL: {len(failures)} case(s) recovered a withheld figure or "
              f"skipped the attack", file=sys.stderr)
        for kind, detail, cells in failures[:5]:
            print(f"  [{kind}] {detail}", file=sys.stderr)
            if cells:
                print(f"      true cells: {cells}", file=sys.stderr)
        return 1

    print("\nPASS: no withheld figure was recovered from any published table.")
    print("The adversary had the cells, the total, the threshold and every figure "
          "from earlier reports in the series, which is everything a member of the "
          "public would have. Where suppression could not protect a cell the report "
          "refused to exist rather than publish a marker claiming it had.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
