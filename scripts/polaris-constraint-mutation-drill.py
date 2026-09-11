#!/usr/bin/env python3
"""polaris-constraint-mutation-drill.py - does the suite notice when a constraint is gone?

v9.406. MISSION.md's first claim is that the guarantees live in the DATABASE, not in
application code: a rule enforced by a CHECK constraint binds every client and survives every
restore. `test_check_constraints.py` is the evidence for that claim, and it is a suite of
"this INSERT must raise CheckViolation" assertions.

An assertion like that can pass for the wrong reason. A row crafted to violate one constraint
often violates a second on the way in, and `assertRaises(CheckViolation)` cannot tell them
apart; the suite's helper takes a constraint NAME for exactly that reason. But naming the
constraint in the assertion is still a claim about the database that only the database can
settle. The way to settle it is to take the constraint away.

So: for every constraint the suite names, drop it, run the tests that name it, and require them
to FAIL. A constraint whose removal leaves the suite green is a constraint the suite does not
test, whatever its assertion says. The drill restores every constraint it drops, verifies the
catalog came back, and refuses to run against a database that is not a test database.

  python3 scripts/polaris-constraint-mutation-drill.py

Exits 0 when every named constraint is load-bearing, 1 on a survivor, an unresolvable name, or
a restore that did not come back.
"""
from __future__ import annotations

import ast
import os
import pathlib
import re
import subprocess
import sys

try:
    import psycopg2
except ImportError:  # pragma: no cover - the drill needs the app stack
    print("polaris-constraint-mutation-drill: psycopg2 is required (use the test venv)",
          file=sys.stderr)
    raise SystemExit(1)

ROOT = pathlib.Path(__file__).resolve().parent.parent
SUITE = ROOT / "polaris_web" / "test_check_constraints.py"

#: The drill drops real constraints. It runs only against a database whose name says it is
#: disposable, because a half-restored schema is worse than no drill.
TEST_DB_MARKER = "test"

#: Constraints whose removal legitimately leaves the naming test green, each with the reason.
#: Empty on purpose: an entry here is a test that does not test what it says, and the entry
#: should be a fix, not a note. Kept so that a justified exception is declared rather than
#: silently tolerated.
SURVIVORS_EXPECTED: dict[str, str] = {}

#: The drill's own negative control. "Every constraint is load-bearing" is a measurement only
#: if this drill is capable of reporting the opposite, so before any verdict is trusted it drops
#: ONE constraint and runs a test that names a DIFFERENT constraint on a DIFFERENT table. That
#: test must stay green. If it goes red, the suite is failing for reasons other than the
#: constraint that was removed, and every "ok" in the run is unattributable.
CONTROL_CONSTRAINT = "chk_appuser_role"
CONTROL_UNRELATED_TEST = "TestAgencyChecks.test_agency_type_enum_rejects_unknown"

#: Cases this drill actually recorded. A drill whose cases are removed or short-circuited in a
#: refactor prints its whole summary and exits 0 anyway, which is a guarantee reported by
#: something that tested nothing (v9.403).
_cases_recorded = 0


def _env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("POLARIS_DB_HOST", "127.0.0.1")
    env.setdefault("POLARIS_DB_PORT", "5432")
    env.setdefault("POLARIS_DB_NAME", "polaris_test")
    env.setdefault("POLARIS_DB_USER", os.environ.get("USER", "postgres"))
    return env


def _named_constraints() -> dict[str, list[str]]:
    """constraint name -> the test methods that assert it, read out of the suite."""
    tree = ast.parse(SUITE.read_text())
    out: dict[str, list[str]] = {}
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        for fn in cls.body:
            if not (isinstance(fn, ast.FunctionDef) and fn.name.startswith("test_")):
                continue
            for m in re.finditer(r"constraint_name=['\"]([\w.]+)['\"]", ast.unparse(fn)):
                out.setdefault(m.group(1), []).append(f"{cls.__dict__['name']}.{fn.name}")
    return out


def _catalog(cur, fragment: str) -> list[tuple[str, str, str]]:
    """(table, conname, definition) for every TOP-LEVEL check constraint matching fragment.

    Partitioned event tables carry a copy of each parent constraint on every partition;
    coninhcount = 0 selects the parent, and dropping there cascades to the partitions.
    """
    cur.execute("""
        SELECT conrelid::regclass::text, conname, pg_get_constraintdef(oid)
          FROM pg_constraint
         WHERE connamespace = 'public'::regnamespace
           AND contype = 'c'
           AND coninhcount = 0
           AND conname LIKE %s
         ORDER BY conrelid::regclass::text, conname
    """, ("%" + fragment + "%",))
    return [tuple(r) for r in cur.fetchall()]


def _run_tests(tests: list[str], env: dict[str, str]) -> bool:
    """True when the named tests all PASS."""
    proc = subprocess.run(
        [sys.executable, "-m", "unittest"] + [f"test_check_constraints.{t}" for t in tests],
        cwd=str(ROOT / "polaris_web"), env=env, capture_output=True, text=True)
    return proc.returncode == 0


def main() -> int:
    global _cases_recorded
    env = _env()
    dbname = env["POLARIS_DB_NAME"]
    if TEST_DB_MARKER not in dbname:
        print(f"polaris-constraint-mutation-drill: refusing to drop constraints in '{dbname}'; "
              f"the database name must contain '{TEST_DB_MARKER}'", file=sys.stderr)
        return 1

    conn = psycopg2.connect(host=env["POLARIS_DB_HOST"], port=env["POLARIS_DB_PORT"],
                            dbname=dbname, user=env["POLARIS_DB_USER"],
                            password=env.get("POLARIS_DB_PASSWORD") or None)
    conn.autocommit = True
    named = _named_constraints()

    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM pg_constraint WHERE connamespace='public'::regnamespace")
        before_total = cur.fetchone()[0]

    survivors: list[tuple[str, str]] = []
    unresolved: list[str] = []
    broken_restores: list[str] = []
    print(f"Polaris constraint mutation drill: {len(named)} named constraints, database {dbname}")
    print()

    with conn.cursor() as cur:
        control_rows = _catalog(cur, CONTROL_CONSTRAINT)
    if not control_rows:
        print(f"FAIL: the negative control constraint {CONTROL_CONSTRAINT} is gone; the drill "
              "cannot show it is able to report a survivor.", file=sys.stderr)
        conn.close()
        return 1
    try:
        with conn.cursor() as cur:
            for table, conname, _ in control_rows:
                cur.execute(f'ALTER TABLE {table} DROP CONSTRAINT "{conname}"')
        control_green = _run_tests([CONTROL_UNRELATED_TEST], env)
    finally:
        with conn.cursor() as cur:
            for table, conname, definition in control_rows:
                cur.execute(f'ALTER TABLE {table} ADD CONSTRAINT "{conname}" {definition}')
    if not control_green:
        print(f"FAIL: the negative control went red. {CONTROL_UNRELATED_TEST} fails when "
              f"{CONTROL_CONSTRAINT} is dropped, which it has nothing to do with. The suite is "
              "failing for reasons other than the constraint removed, so no verdict below would "
              "mean anything.", file=sys.stderr)
        conn.close()
        return 1
    print(f"  control  {CONTROL_CONSTRAINT + ' dropped':44} "
          f"{CONTROL_UNRELATED_TEST.split('.')[-1]} stays green, so a red test below is "
          "attributable")
    print()

    for fragment in sorted(named):
        tests = sorted(set(named[fragment]))
        with conn.cursor() as cur:
            rows = _catalog(cur, fragment)
        if not rows:
            unresolved.append(fragment)
            print(f"  MISSING  {fragment:44} the suite names a constraint the database "
                  f"does not have")
            continue
        _cases_recorded += 1
        try:
            with conn.cursor() as cur:
                for table, conname, _ in rows:
                    cur.execute(f'ALTER TABLE {table} DROP CONSTRAINT "{conname}"')
            still_green = _run_tests(tests, env)
        finally:
            with conn.cursor() as cur:
                for table, conname, definition in rows:
                    try:
                        cur.execute(f'ALTER TABLE {table} ADD CONSTRAINT "{conname}" {definition}')
                    except psycopg2.Error as exc:
                        broken_restores.append(
                            f'{table}.{conname}: {exc}\n'
                            f'    ALTER TABLE {table} ADD CONSTRAINT "{conname}" {definition};')
        where = ", ".join(sorted({t for t, _, _ in rows}))
        if still_green:
            survivors.append((fragment, where))
            print(f"  SURVIVES {fragment:44} dropped from {where}; "
                  f"{len(tests)} naming test(s) still pass")
        else:
            print(f"  ok       {fragment:44} {len(tests)} test(s) go red without it ({where})")

    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM pg_constraint WHERE connamespace='public'::regnamespace")
        after_total = cur.fetchone()[0]
    conn.close()

    print()
    if broken_restores:
        print("FAIL: constraint(s) were NOT restored. The database is now missing them; the "
              "exact SQL to put each back is below.", file=sys.stderr)
        for line in broken_restores:
            print("  " + line, file=sys.stderr)
        return 1
    if after_total != before_total:
        print(f"FAIL: the catalog held {before_total} constraints before and {after_total} "
              "after; something did not come back.", file=sys.stderr)
        return 1
    if not _cases_recorded:
        print("FAIL: this drill recorded NO cases. It mutated nothing and would have printed "
              "its summary regardless.", file=sys.stderr)
        return 1
    if unresolved:
        print("FAIL: the suite asserts constraint name(s) the database does not define, so "
              "those assertions can only ever have matched something else: "
              + ", ".join(unresolved), file=sys.stderr)
        return 1
    unexpected = [(f, w) for f, w in survivors if f not in SURVIVORS_EXPECTED]
    if unexpected:
        print("FAIL: constraint(s) can be dropped with the suite still green, so the suite does "
              "not test them whatever its assertions say:", file=sys.stderr)
        for fragment, where in unexpected:
            print(f"  {fragment} ({where})", file=sys.stderr)
        return 1
    print(f"OK: {_cases_recorded} constraints mutated behind a passing negative control, "
          f"{len(survivors)} survive "
          f"({len(SURVIVORS_EXPECTED)} declared). Every constraint the suite names is "
          "load-bearing: drop it and the naming test goes red.")
    print(f"The catalog came back intact: {after_total} constraints, as before.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
