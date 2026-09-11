#!/usr/bin/env python3
"""polaris-trigger-mutation-drill.py - does the suite notice when a trigger is gone?

v9.413. The sibling of polaris-constraint-mutation-drill.py. MISSION names three
mechanisms for a guarantee that lives in the database: a trigger, a CHECK constraint,
or a unique index. v9.407 mutation-tested the constraints and found all 46
load-bearing. This does the triggers, which is where C1 lives.

The first run of this measurement (v9.411) found 14 of 37 covered by nothing: drop
one and the whole database suite stayed green. v9.412 covered all 14. This drill is
what keeps that true, because a coverage number nobody re-measures is a coverage
number that decays.

Two modes, because the two suites cost three orders of magnitude apart:

  python3 scripts/polaris-trigger-mutation-drill.py
      Per trigger, run the fast suites (the constraint suite and the property
      suite, about a second each). Every trigger must be caught by those, or be
      declared in APP_SUITE_COVERS as one whose coverage lives in the application
      suite. A new trigger in neither is a failure: it has not been classified,
      which means nobody has checked whether anything tests it.

  python3 scripts/polaris-trigger-mutation-drill.py --exhaustive
      Also run the full application suite for every trigger the fast suites do not
      catch, which re-establishes APP_SUITE_COVERS from scratch rather than
      trusting it. Takes hours; runs weekly, not on every push.

MUTATION METHOD. A trigger dropped from the catalog does not stay dropped: the
suites call reload_sample_data(), which re-runs 06_triggers.sql. So the drop is
also appended to that file, which makes every reload re-drop it. Both are needed:
the file edit alone loses to a migration that recreates the trigger after
06_triggers.sql runs, and the catalog drop alone loses to the next reload.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys

try:
    import psycopg2
except ImportError:  # pragma: no cover - the drill needs the app stack
    print("polaris-trigger-mutation-drill: psycopg2 is required (use the test venv)",
          file=sys.stderr)
    raise SystemExit(1)

ROOT = pathlib.Path(__file__).resolve().parent.parent
TRIGGERS_SQL = ROOT / "polaris_sql" / "06_triggers.sql"

#: The drill drops real triggers. It runs only against a database whose name says it
#: is disposable, because a half-restored schema is worse than no drill.
TEST_DB_MARKER = "test"

FAST_SUITES = ("test_check_constraints", "test_invariants_property")
APP_SUITE = "test_app"

#: Triggers whose coverage lives in the APPLICATION suite rather than the fast ones.
#: Established by a full per-trigger sweep, and re-established by --exhaustive. A
#: trigger here is not untested; it is tested somewhere this drill's default mode
#: cannot afford to look.
APP_SUITE_COVERS = {
    "trg_attestation_immutable",
    "trg_enforce_revocation_velocity",
    "trg_epoch_immutable",
    "trg_quota_issue",
    "trg_quota_revoke",
    "trg_quota_verify",
    "trg_seed_default_enrollment_status",
    "trg_token_audit_state_change",
    "trg_token_must_have_active_signature",
    "trg_token_signature_immutable",
    "trg_token_state_machine",
}

#: Triggers that nothing covers, each with the reason. Empty on purpose: an entry
#: here is a guarantee the database makes and the tests do not check.
SURVIVORS_EXPECTED: dict[str, str] = {}

#: Cases this drill actually recorded (v9.403).
_cases_recorded = 0


def _env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("POLARIS_DB_HOST", "127.0.0.1")
    env.setdefault("POLARIS_DB_PORT", "5432")
    env.setdefault("POLARIS_DB_NAME", "polaris_test")
    env.setdefault("POLARIS_DB_USER", os.environ.get("USER", "postgres"))
    return env


def _connect(env: dict[str, str]):
    conn = psycopg2.connect(host=env["POLARIS_DB_HOST"], port=env["POLARIS_DB_PORT"],
                            dbname=env["POLARIS_DB_NAME"], user=env["POLARIS_DB_USER"],
                            password=env.get("POLARIS_DB_PASSWORD") or None)
    conn.autocommit = True
    return conn


def _triggers(conn) -> list[tuple[str, str, str]]:
    """(table, name, definition) for every top-level trigger.

    Partitions carry a clone of each parent trigger; dropping on the parent takes
    them with it, so only parents are mutated.
    """
    with conn.cursor() as cur:
        cur.execute("""
            SELECT c.relname, t.tgname, pg_get_triggerdef(t.oid)
              FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
             WHERE c.relnamespace = 'public'::regnamespace
               AND NOT t.tgisinternal
               AND NOT c.relispartition
             ORDER BY t.tgname
        """)
        return [tuple(r) for r in cur.fetchall()]


def _count(conn) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
                    "WHERE c.relnamespace = 'public'::regnamespace AND NOT t.tgisinternal")
        return cur.fetchone()[0]


def _suite_is_red(module: str, env: dict[str, str]) -> bool:
    return subprocess.run([sys.executable, "-m", "unittest", module],
                          cwd=str(ROOT / "polaris_web"), env=env,
                          capture_output=True).returncode != 0


def main(argv: list[str]) -> int:
    global _cases_recorded
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--exhaustive", action="store_true",
                    help="also run the application suite for triggers the fast suites miss")
    args = ap.parse_args(argv[1:])

    env = _env()
    if TEST_DB_MARKER not in env["POLARIS_DB_NAME"]:
        print(f"polaris-trigger-mutation-drill: refusing to drop triggers in "
              f"'{env['POLARIS_DB_NAME']}'; the database name must contain "
              f"'{TEST_DB_MARKER}'", file=sys.stderr)
        return 1

    original = TRIGGERS_SQL.read_text()
    conn = _connect(env)
    before = _count(conn)
    trigs = _triggers(conn)
    mode = "exhaustive" if args.exhaustive else "fast suites only"
    print(f"Polaris trigger mutation drill: {len(trigs)} top-level triggers, {mode}")
    print(f"database {env['POLARIS_DB_NAME']}, catalog holds {before} including partitions")
    print()

    survivors: list[tuple[str, str]] = []
    unclassified: list[str] = []
    broken_restores: list[str] = []

    try:
        for table, name, definition in trigs:
            _cases_recorded += 1
            # Both halves: the file so a reload cannot put it back, the catalog so a
            # migration that ran after 06_triggers.sql cannot either.
            TRIGGERS_SQL.write_text(
                original + f'\n-- MUTATION (polaris-trigger-mutation-drill)\n'
                           f'DROP TRIGGER IF EXISTS "{name}" ON {table};\n')
            try:
                with conn.cursor() as cur:
                    cur.execute(f'DROP TRIGGER IF EXISTS "{name}" ON {table}')
                caught_by = next((s for s in FAST_SUITES if _suite_is_red(s, env)), None)
                if caught_by is None and args.exhaustive and _suite_is_red(APP_SUITE, env):
                    caught_by = APP_SUITE
            finally:
                TRIGGERS_SQL.write_text(original)
                try:
                    with conn.cursor() as cur:
                        cur.execute(definition)
                except psycopg2.Error as exc:
                    broken_restores.append(f"{table}.{name}: {exc}\n    {definition};")

            if caught_by:
                where = "the application suite" if caught_by == APP_SUITE else caught_by
                print(f"  ok        {name:44} {where} goes red")
            elif name in APP_SUITE_COVERS and not args.exhaustive:
                print(f"  declared  {name:44} covered by the application suite "
                      f"(not re-checked in this mode)")
            elif name in SURVIVORS_EXPECTED:
                survivors.append((name, table))
                print(f"  survives  {name:44} declared: {SURVIVORS_EXPECTED[name]}")
            elif name in APP_SUITE_COVERS:
                survivors.append((name, table))
                print(f"  SURVIVES  {name:44} declared as covered by the application "
                      f"suite, but it is not")
            else:
                unclassified.append(name)
                print(f"  UNTESTED  {name:44} on {table}: nothing goes red")
    finally:
        TRIGGERS_SQL.write_text(original)

    after = _count(conn)
    conn.close()
    print()

    if broken_restores:
        print("FAIL: trigger(s) were NOT restored. The SQL to put each back is below.",
              file=sys.stderr)
        for line in broken_restores:
            print("  " + line, file=sys.stderr)
        return 1
    if after != before:
        print(f"FAIL: the catalog held {before} triggers before and {after} after; something "
              "did not come back.", file=sys.stderr)
        return 1
    if not _cases_recorded:
        print("FAIL: this drill recorded NO cases. It mutated nothing and would have printed "
              "its summary regardless.", file=sys.stderr)
        return 1
    if unclassified:
        print("FAIL: trigger(s) can be dropped with nothing going red. Either the guarantee "
              "is untested, or it is tested only in the application suite and belongs in "
              "APP_SUITE_COVERS, which is a claim to verify with --exhaustive rather than "
              "assert: " + ", ".join(unclassified), file=sys.stderr)
        return 1
    if survivors:
        print("FAIL: trigger(s) are declared covered and are not:", file=sys.stderr)
        for name, table in survivors:
            print(f"  {name} on {table}", file=sys.stderr)
        return 1
    print(f"OK: {_cases_recorded} triggers mutated, 0 untested. Every trigger's removal turns "
          "something red.")
    if not args.exhaustive:
        print(f"{len(APP_SUITE_COVERS)} of them are declared as covered by the application "
              "suite and were not re-checked here; --exhaustive re-establishes that list.")
    print(f"The catalog came back intact: {after} triggers, as before.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
