#!/usr/bin/env python3
"""polaris-constitution-mutation-drill.py -- delete each constraint's enforcement, one at a time.

CHECK constraints are mutation-tested (v9.407), triggers are (v9.413), the ZK witnesses are
(v9.419), the conformance contract is (v9.429), the stored procedures are (v9.437), both SDKs
are (v9.458) and the Flask application is (2026-09-17). Every one of those asks the question
of a MECHANISM. Nothing asked it of the ten constraints themselves, which are the claims the
mechanisms exist to serve and the things MISSION.md is actually about.

THE QUESTION. For each of C1 to C10: delete the enforcement the constitution names, and does
any check fail? Not "is there a check", not "does the check read the right file" -- both of
those were already true of C8 on 2026-09-17 while its clamp could be deleted green.

WHAT IT FOUND, first run, 2026-09-17. Nine of ten held. C8 did not: the clamp on
`/api/atlas/points` could be removed with `check_c8_atlas_caps` still reporting "all 10
caller-controlled counts across 17 atlas routes are clamped", because its regex accepted
`limit <= 0`, a LOWER bound, as a cap. The application suite and the check's own detection
tests passed too. That is fixed; this drill is what stops it coming back, and what asks the
same question of the other nine every time it runs.

METHOD. One mutation per constraint, each the smallest edit that removes the enforcement
rather than breaking the file: drop one append-only trigger, delete one CHECK, delete the
partial unique index, take RETURNING off the atomic update, add 'unsafe-inline' to the CSP,
remove one ZK exclusion clause, widen the signer allowlist to a classical algorithm, delete
one Atlas clamp, take the threads out of the concurrency tests, add a monetary table.

  survivor = a constraint whose enforcement can be deleted with every check still green

RESTORATION. Every file is read before it is touched and written back afterwards, in a
`finally`. A killed run can still leave one mutated, so the repair line is printed BEFORE
anything is edited, and the drill refuses to start against a dirty tree: its repair is
`git checkout --`, which would throw away uncommitted work.

POSITIVE CONTROL. The unmutated tree must report READY first. Without that, a tree that was
already failing would make every mutation look detected, which is the shape that made the
first draft of the application drill report a perfect result in one second.

  python3 scripts/polaris-constitution-mutation-drill.py
  python3 scripts/polaris-constitution-mutation-drill.py --only C8
"""
from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _drop_statement(text: str, needle: str, opener: str = "(") -> str:
    """Remove the parenthesised statement containing `needle`, balanced rather than regexed.

    A regex of the form `[^;]*needle[^;]*;` looks equivalent and is not: on 2026-09-17 it
    matched a COMMENT mentioning `chk_disclosure_token_consistency` and removed that, so the
    constraint stayed and the drill reported it undetected. A mutation that does not mutate
    reports every check as blind.
    """
    i = text.index(needle)
    start = text.rfind("\n", 0, i) + 1
    depth, j = 0, text.index(opener, i)
    while True:
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
        if depth == 0:
            break
        j += 1
    return text[:start] + text[text.index("\n", j) + 1:]


def _drop_regex(text: str, pattern: str) -> str:
    m = re.search(pattern, text, re.S)
    if not m:
        raise AssertionError("mutation pattern did not match: %s" % pattern)
    return text[:m.start()] + text[m.end():]


#: (constraint, file, how to mutate it, the check whose name must appear in a FAIL).
#: The expected check is asserted BY NAME: a mutation that turns some unrelated check red is
#: not evidence that this constraint is pinned, and counting failures rather than naming one
#: is how a drill flatters itself.
MUTATIONS = [
    ("C1", "polaris_sql/06_triggers.sql",
     lambda t: _drop_regex(t, r"CREATE TRIGGER \w+[^;]*?EXECUTE FUNCTION reject_audit_modification\(\);"),
     "c1_aor", "one audit-of-record table loses its append-only trigger"),
    ("C2", "polaris_sql/01_schema.sql",
     lambda t: _drop_statement(t, "    CONSTRAINT chk_disclosure_token_consistency CHECK ("),
     # The check FUNCTION is check_c2_zk_token_null; the name it REPORTS is c2_zk_null, and
     # this drill asserts on what is reported. Getting that wrong made the first run call C2
     # a survivor while its own check was in the failure list.
     "c2_zk_null", "the bidirectional CHECK that nulls the token id for zero-knowledge"),
    ("C3", "polaris_sql/02_indexes.sql",
     lambda t: _drop_regex(t, r"CREATE UNIQUE INDEX uq_one_active_per_person[\s\S]*?;"),
     "c3_one_active", "the partial unique index behind one active token per person"),
    ("C4", "polaris_web/security.py",
     lambda t: t.replace('"RETURNING failed_login_count",', '"",', 1),
     "c4_atomic_login", "the counter stops being read and written in one statement"),
    ("C5", "polaris_web/security.py",
     lambda t: t.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'", 1),
     "csp", "the response policy starts admitting inline script"),
    ("C6", "polaris_sql/11_atlas.sql",
     lambda t: t.replace("disclosure_level <> 'ZERO_KNOWLEDGE'", "TRUE", 1),
     "c6_atlas_zk", "one Atlas function stops excluding zero-knowledge rows"),
    ("C7", "polaris_web/pqc_signing.py",
     lambda t: t.replace('ACCEPTED_ALGORITHMS = ("ML-DSA-65", "ML-DSA-87")',
                         'ACCEPTED_ALGORITHMS = ("ML-DSA-65", "ML-DSA-87", "ECDSA-P256")', 1),
     "algorithm_agility", "a classical algorithm joins the accepted-signer allowlist"),
    ("C8", "polaris_web/app.py",
     lambda t: t.replace("limit = min(int(request.args.get('limit', '500')), _ATLAS_MAX_POINTS)",
                         "limit = int(request.args.get('limit', '500'))", 1),
     "c8_atlas_caps", "one Atlas route stops clamping a caller-controlled count"),
    ("C9", "polaris_web/test_app.py",
     None,      # handled specially: the mutation is scoped to one class body
     "c9_concurrency", "the concurrency tests stop using real threads"),
    ("C10", "polaris_sql/01_schema.sql",
     lambda t: t + "\n\nCREATE TABLE PaymentLedger (\n    payment_id SERIAL PRIMARY KEY,\n"
                   "    amount NUMERIC(12,2) NOT NULL\n);\n",
     "c10_no_money", "a monetary table appears in the schema"),
]


def _mutate_c9(text: str) -> str:
    i = text.index("class ConcurrencyTests")
    j = text.index("\nclass ", i + 10)
    return text[:i] + text[i:j].replace("threading", "sequential_stub") + text[j:]


def _failing_checks() -> list[str]:
    """The `name` of every check reporting FAIL, read off the runner's own output."""
    r = subprocess.run([sys.executable, "-m", "polaris_checks.run"],
                       cwd=str(ROOT), capture_output=True)
    out = (r.stdout or b"").decode("utf-8", "replace")
    return re.findall(r"✗ \[(\w+)\]", out)


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0] or None)
    ap.add_argument("--only", help="run one constraint, e.g. C8")
    args = ap.parse_args()

    print("REPAIR, if this run is killed:  git checkout -- polaris_sql polaris_web")
    print()
    # Only the files this drill REWRITES. Asking about the whole tree makes the drill refuse
    # to run because of its own untracked self, which is how the first invocation went.
    touched = sorted({rel for _c, rel, _m, _e, _w in MUTATIONS})
    dirty = subprocess.run(["git", "status", "--porcelain", "--"] + touched,
                           cwd=str(ROOT), capture_output=True).stdout.decode().strip()
    if dirty:
        print("uncommitted changes in a file this drill rewrites:\n%s\n\nIts documented "
              "repair is `git checkout --`, which would throw them away. Commit or stash "
              "first." % dirty, file=sys.stderr)
        return 2

    print("positive control: the unmutated tree must report no failures")
    before = _failing_checks()
    if before:
        print("== VOID: %d check(s) already failing (%s). Every mutation below would look "
              "detected by a tree that was already red ==" % (before, ", ".join(before)),
              file=sys.stderr)
        return 2
    print("   clean\n")

    cases = [m for m in MUTATIONS if not args.only or m[0] == args.only.upper()]
    survivors, results = [], []
    for cid, rel, mutate, expected, what in cases:
        path = ROOT / rel
        original = path.read_text()
        try:
            path.write_text(_mutate_c9(original) if cid == "C9" else mutate(original))
            if path.read_text() == original:
                raise AssertionError("the mutation changed nothing")
            failing = _failing_checks()
        finally:
            path.write_text(original)
        caught = expected in failing
        results.append((cid, caught, expected, failing))
        print("%-4s %-58s %s" % (cid, what, "caught by %s" % expected if caught else "SURVIVED"))
        if not caught:
            survivors.append((cid, expected, failing, what))

    print("\nconstraints tested            %d" % len(cases))
    print("enforcement deleted, caught   %d" % (len(cases) - len(survivors)))
    print("SURVIVED                      %d" % len(survivors))

    if survivors:
        print("\n== %d CONSTRAINT(S) WHOSE ENFORCEMENT CAN BE DELETED GREEN ==" % len(survivors))
        for cid, expected, failing, what in survivors:
            print("   %-4s %s" % (cid, what))
            print("        expected %s to fail; what failed instead: %s"
                  % (expected, ", ".join(failing) or "nothing"))
        print("\nA constraint with a check that does not fail when its enforcement is deleted "
              "is a constraint nothing enforces. C8 was in this state until 2026-09-17.")
        return 1

    print("\n== Every constraint's enforcement, deleted one at a time, turns its OWN named "
          "check red. That is a statement about these ten mutations, not about the "
          "constraints in general: a mutation nobody thought of is this drill's standing "
          "limitation, and a check that fails for a neighbouring reason would not be "
          "credited here, because the expected check is asserted by name. ==")
    return 0


if __name__ == "__main__":
    sys.exit(main())
