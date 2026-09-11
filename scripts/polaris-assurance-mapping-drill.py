#!/usr/bin/env python3
"""polaris-assurance-mapping-drill.py - the assurance mapping, resolved (roadmap P6.2).

A control mapping is the easiest document in any project to write and the easiest to let rot.
It is a table of claims about a codebase, maintained by hand, read by people who cannot check
it, and it goes stale the first time somebody deletes the thing a row was pointing at. Nothing
turns red. The document just becomes untrue.

So this drill treats docs/reference/NIST-800-63-MAPPING.md as executable. It parses every row,
resolves every citation against the tree, and RUNS every check cited:

  A `check:` citation must name a check that exists AND PASSES. Naming a check that fails, or
  one that was renamed away, fails here.
  A `test:` citation must name a test class that exists in the file it names.
  A `drill:` citation must name a script the repository actually has.
  A `schema:` citation must name a constraint, trigger or index present in polaris_sql/.

  And a GAP or WAIVED row must carry a REASON. A gap with no reason is a gap somebody meant to
  come back to, and the whole value of writing it down is the sentence saying why.

THE TOTALS ARE RECOMPUTED, NEVER READ. The document states how many gaps there are; this drill
counts them from the rows and fails on a disagreement. A summary that can drift from its own
table is worse than no summary, because it is the part a reader believes.

WHAT THIS DOES NOT DO. It cannot tell you the mapping is CORRECT: that a row's requirement is
really what 800-63 asks, or that the cited check really proves it. That is an assessor's
judgement and no script substitutes for it. What it guarantees is narrower and still worth
having: every claim in the document points at something that exists and passes today.

Run: python3 scripts/polaris-assurance-mapping-drill.py
Exit 0 iff every citation resolves, 3 to skip.
"""
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

MAPPING = os.path.join(ROOT, "docs", "reference", "NIST-800-63-MAPPING.md")
VERDICTS = ("MET", "PARTIAL", "GAP", "WAIVED", "EXTERNAL")
NEEDS_REASON = ("GAP", "WAIVED", "PARTIAL")
_ok_all = True


#: Cases this drill actually recorded. A drill whose cases are removed or
#: short-circuited in a refactor prints its whole summary and exits 0 anyway,
#: which is a guarantee reported by something that tested nothing (v9.403).
_cases_recorded = 0


def _row(label, got, want):
    global _cases_recorded
    _cases_recorded += 1
    global _ok_all
    ok = got == want
    _ok_all &= ok
    print("  %-58s %-14s %-14s %s" % (label[:58], str(got)[:14], str(want)[:14],
                                      "OK" if ok else "FAIL"))
    return ok


def _note(label, value):
    print("  %-58s %-14s %-14s %s" % (label[:58], str(value)[:14], "", "--"))


def parse_rows(text):
    """Every mapping row: (requirement, verdict, evidence). Header and rule rows skipped."""
    rows = []
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 3:
            continue
        requirement, verdict, evidence = cells
        if verdict not in VERDICTS:
            continue
        rows.append((requirement, verdict, evidence))
    return rows


def main():
    try:
        from polaris_checks.checks import CHECKS
    except ImportError as e:  # noqa: BLE001
        print("assurance-mapping drill needs polaris_checks: %s" % e, file=sys.stderr)
        return 3
    try:
        with open(MAPPING) as fh:
            text = fh.read()
    except OSError as e:  # noqa: BLE001
        print("the mapping is missing: %s" % e, file=sys.stderr)
        return 3

    import pathlib
    root = pathlib.Path(ROOT)
    by_name = {c.__name__.replace("check_", ""): c for c in CHECKS}

    print("the assurance mapping, resolved")
    print()
    print("  %-58s %-14s %-14s %s" % ("case", "got", "expected", "ok"))

    rows = parse_rows(text)
    _row("the mapping has rows to resolve", len(rows) > 20, True)
    counts = Counter(verdict for _, verdict, _ in rows)
    for verdict in VERDICTS:
        if counts[verdict]:
            _note("  rows marked %s" % verdict, counts[verdict])

    # EVERY CITATION RESOLVES.
    unresolved, failing = [], []
    schema_text = "\n".join(
        (root / "polaris_sql" / f).read_text()
        for f in ("01_schema.sql", "06_triggers.sql") if (root / "polaris_sql" / f).exists())
    for name in sorted(os.listdir(root / "polaris_sql" / "migrations")):
        if name.endswith(".up.sql"):
            schema_text += (root / "polaris_sql" / "migrations" / name).read_text()

    cited_checks = set()
    for requirement, verdict, evidence in rows:
        for kind, target in re.findall(r"`(check|test|drill|schema):([^`]+)`", evidence):
            if kind == "check":
                if target not in by_name:
                    unresolved.append("check:%s (%s)" % (target, requirement[:40]))
                else:
                    cited_checks.add(target)
            elif kind == "test":
                path, _, cls = target.partition("::")
                f = root / path
                if not f.exists():
                    unresolved.append("test file %s" % path)
                elif cls and ("class %s" % cls) not in f.read_text():
                    unresolved.append("test class %s in %s" % (cls, path))
            elif kind == "drill":
                if not (root / target).exists():
                    unresolved.append("drill %s" % target)
            elif kind == "schema":
                if target not in schema_text:
                    unresolved.append("schema object %s" % target)
    _row("every citation in the mapping resolves", unresolved, [])

    # EVERY CITED CHECK PASSES. Naming one that fails is the same as naming one that is gone.
    for target in sorted(cited_checks):
        findings = by_name[target](root)
        if any(f.level == "FAIL" for f in findings):
            failing.append(target)
    _row("every cited check PASSES against this tree", failing, [])
    _note("  distinct checks cited and run", len(cited_checks))

    # A GAP WITH NO REASON is a gap somebody meant to come back to.
    reasonless = [requirement[:40] for requirement, verdict, evidence in rows
                  if verdict in NEEDS_REASON and len(evidence) < 40
                  and not re.search(r"`(check|test|drill|schema):", evidence)]
    _row("every GAP, WAIVED and PARTIAL row carries a reason", reasonless, [])

    # A MET ROW WITH NO CITATION is an assertion wearing a checkmark.
    uncited = [requirement[:40] for requirement, verdict, evidence in rows
               if verdict == "MET" and not re.search(r"`(check|test|drill|schema):", evidence)]
    _row("every MET row cites something", uncited, [])

    # THE TOTALS ARE RECOMPUTED. A summary that can drift from its own table is worse than
    # none, because it is the part a reader believes.
    # Bold or not: the count is the claim, and the emphasis around it is not.
    stated = re.search(r"\*{0,2}(\w+)\*{0,2} rows above are GAP or EXTERNAL", text)
    words = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
             "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12}
    actual = counts["GAP"] + counts["EXTERNAL"]
    _row("the stated gap count matches the rows",
         words.get(stated.group(1).lower()) if stated else None, actual)

    # THE FRONT MATTER MUST NOT CLAIM CONFORMANCE. This is the row that keeps the document
    # from being quoted as a certification by somebody who read only its first page.
    low = " ".join(text.lower().split())
    _row("the document states it is NOT a conformance claim",
         "not a conformance claim" in low, True)
    _row("...and that no assessment has been performed",
         "no assessment has been performed" in low, True)
    _row("...and that a deployment does not inherit these properties",
         "does not inherit" in low or "it does not inherit" in low, True)
    _row("the highest AAL claimed is stated explicitly",
         "highest holder aal claimed" in low, True)
    _row("...and the highest FAL", "highest fal claimed" in low, True)

    print()
    if not _cases_recorded:
        print("FAIL: this drill recorded NO cases. It tested nothing and would "
              "have printed its summary regardless.", file=sys.stderr)
        return 1
    if _ok_all:
        print("OK: every claim in the assurance mapping points at something that exists and "
              "passes today. Each cited check was RUN, not merely found; each cited test class, "
              "drill and schema object was resolved against the tree; every gap and waiver "
              "carries a reason, because a gap with no reason is one somebody meant to come "
              "back to; every MET row cites something, because a checkmark with no citation is "
              "an assertion wearing one; and the gap total was recomputed from the rows rather "
              "than read from the summary, since a summary that can drift from its own table is "
              "the part a reader believes. What this does NOT establish is that the mapping is "
              "correct: whether a row's requirement is really what the standard asks, and "
              "whether the cited check really proves it, is an assessor's judgement and no "
              "script substitutes for it.")
        return 0
    print("FAIL: the mapping claims something the tree does not support", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
