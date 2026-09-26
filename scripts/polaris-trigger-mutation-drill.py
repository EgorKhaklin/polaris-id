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

  python3 scripts/polaris-trigger-mutation-drill.py --refusals
      (2026-09-26) Delete each RAISE EXCEPTION inside each trigger function, one at a
      time, and require the fast suites to notice. A refusal whose removal leaves the
      change refused by something else (the next check, a CHECK, a foreign key) is
      listed in REFUSALS_MASKED with what refuses it; one covered only by the
      application suite is in REFUSALS_APP_SUITE. The first run found sixteen that
      nothing noticed; TestEachTriggerRefusalIsNoticed covers them. A few minutes;
      runs weekly beside --exhaustive.

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
import re
import subprocess
import tempfile
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

#: --refusals (2026-09-26). Removing a whole trigger is one question; removing ONE refusal inside
#: its function is another, and the second found ten refusals nothing noticed. Refusals whose
#: removal is MASKED, the forbidden change still refused by something else, are listed with the
#: thing that refuses it. Key: "function#n", n counting RAISE EXCEPTION in definition order.
REFUSALS_MASKED: dict[str, str] = {
    "enforce_agency_quota_immutability#0":
        "DELETE: NEW is NULL, so the next check's IS DISTINCT FROM raises",
    "enforce_discretion_policy_immutability#0":
        "DELETE: NEW is NULL, so the next check's IS DISTINCT FROM raises",
    "enforce_retention_policy_immutability#0":
        "DELETE: NEW is NULL, so the next check's IS DISTINCT FROM raises",
    "enforce_attestation_immutability#0":
        "DELETE: every later comparison is NULL, RETURN NEW returns NULL, the delete is cancelled",
    "enforce_token_signature_immutability#0":
        "DELETE: every later comparison is NULL, RETURN NEW returns NULL, the delete is cancelled",
    "enforce_epoch_immutability#0":
        "DELETE falls through to the unconditional refusal after it",
    "enforce_epoch_immutability#1":
        "without it the function reaches its end with no RETURN, which is itself an error",
    "enforce_predecessor_same_individual#0":
        "identitytoken_predecessor_token_id_fkey refuses a predecessor that does not exist",
    "enforce_recovery_request_immutability#3":
        "recoveryrequest_status_check admits no status other than PENDING and the three it names",
}

#: Refusals whose coverage lives in the application suite, which this mode does not run (the
#: triggers they sit in are in APP_SUITE_COVERS for the same reason).
REFUSALS_APP_SUITE: dict[str, str] = {
    "enforce_agency_quota#0": "exceeding a quota needs the load the quota tests in test_app drive",
}


def _trigger_functions(conn) -> dict[str, str]:
    """name -> CREATE OR REPLACE definition, for every trigger function that refuses anything."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT p.proname, pg_get_functiondef(p.oid) FROM pg_proc p
             WHERE p.pronamespace = 'public'::regnamespace
               AND p.prorettype = 'trigger'::regtype
               AND p.prosrc ~* 'RAISE\\s+EXCEPTION'
             ORDER BY p.proname
        """)
        return dict(cur.fetchall())


def _raise_spans(body: str) -> list:
    """(start, end, text) for each RAISE EXCEPTION; the end is the first ';' outside a string."""
    spans = []
    for m in re.finditer(r"\bRAISE\s+EXCEPTION\b", body, re.I):
        i, in_str = m.end(), False
        while i < len(body):
            ch = body[i]
            if ch == "'":
                if in_str and i + 1 < len(body) and body[i + 1] == "'":
                    i += 2
                    continue
                in_str = not in_str
            elif ch == ";" and not in_str:
                break
            i += 1
        spans.append((m.start(), i + 1, re.sub(r"\s+", " ", body[m.start():i])[:70]))
    return spans


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



SELF = "scripts/" + pathlib.Path(__file__).name


def _interpreter_can_run_the_suite(modules, cwd) -> str:
    """"" if `sys.executable` can import the test modules, else why it cannot.

    THE DRILL RUNS TESTS IN A SUBPROCESS UNDER sys.executable, AND A SUBPROCESS THAT
    CANNOT IMPORT IS INDISTINGUISHABLE FROM ONE WHOSE TEST FAILED. Both exit non-zero.
    `unittest` even reports it as `Ran 1 test in 0.000s / FAILED (errors=1)`, which the
    drill reads as "the test went red".

    Two consequences, and the second is why this check exists. The negative control goes
    red and the drill blames a constraint/test relationship that is perfectly healthy,
    sending a reader to the wrong place entirely. And if the control ever stopped
    covering it, EVERY mutation would report as caught -- a wholly green run built on a
    suite that never executed a line.

    Seen on 2026-09-14: this machine's system python3 has psycopg2, so the drill itself
    starts, but not flask, so every subprocess died on import. The drill's own usage line
    says `python3 scripts/...`, which is the invocation that breaks it.
    """
    # IMPORT them, do not merely locate them. find_spec() answers "is there a file
    # called test_check_constraints.py", which there is; the failure is one layer in,
    # when that file imports flask. The first version of this check used find_spec and
    # passed happily on the very interpreter it exists to reject.
    #
    # The answer comes back through a FILE, not through stdout. Importing test_app boots
    # the application, which logs JSON to stdout, and the second version of this check
    # read that as its own output and rejected the interpreter that works. A probe whose
    # channel is the thing it is probing cannot report on it.
    with tempfile.NamedTemporaryFile("w+", suffix=".probe", delete=False) as fh:
        answer = fh.name
    try:
        proc = subprocess.run(
            [sys.executable, "-c",
             "import sys\n"
             "bad = []\n"
             "for m in %r:\n"
             "    try:\n"
             "        __import__(m)\n"
             "    except Exception as exc:\n"
             "        bad.append('%%s (%%s: %%s)' %% (m, type(exc).__name__, exc))\n"
             "open(%r, 'w').write('; '.join(bad))\n" % (list(modules), answer)],
            cwd=str(cwd), capture_output=True, text=True)
        failures = pathlib.Path(answer).read_text().strip()
    finally:
        pathlib.Path(answer).unlink(missing_ok=True)

    if proc.returncode != 0 and not failures:
        return "%s could not be asked what it imports at all: %s" % (
            sys.executable, " / ".join((proc.stderr or "").strip().splitlines()[-2:]))
    if failures:
        return ("%s cannot import %s from %s. Run this drill WITH the venv interpreter "
                "rather than the system one:\n    <venv>/bin/python %s\n"
                "A subprocess that dies on import exits non-zero exactly like a failing "
                "test, so every result below would be a statement about the interpreter "
                "rather than about the database."
                % (sys.executable, failures, cwd, SELF))
    return ""

def main(argv: list[str]) -> int:
    # Every suite this drill runs, not two of them: test_invariants_property needs hypothesis,
    # and a CI job without it made every trigger the constraint suite missed read as caught
    # by a suite that never imported (2026-09-26).
    _why = _interpreter_can_run_the_suite([APP_SUITE, *FAST_SUITES], ROOT / "polaris_web")
    if _why:
        print("polaris-trigger-mutation-drill: " + _why, file=sys.stderr)
        return 1
    global _cases_recorded
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--exhaustive", action="store_true",
                    help="also run the application suite for triggers the fast suites miss")
    ap.add_argument("--refusals", action="store_true",
                    help="delete each RAISE inside each trigger function instead of whole triggers")
    args = ap.parse_args(argv[1:])

    env = _env()
    if TEST_DB_MARKER not in env["POLARIS_DB_NAME"]:
        print(f"polaris-trigger-mutation-drill: refusing to drop triggers in "
              f"'{env['POLARIS_DB_NAME']}'; the database name must contain "
              f"'{TEST_DB_MARKER}'", file=sys.stderr)
        return 1

    if args.refusals:
        return _refusals(env)

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


def _refusals(env: dict[str, str]) -> int:
    """--refusals: delete each RAISE EXCEPTION inside each trigger function, one at a time, and
    require the fast suites to notice, unless REFUSALS_MASKED says what still refuses the change.

    The mutated function is installed in the catalog AND appended to 06_triggers.sql, for the
    same reason the trigger mode edits the file: the suites reload it, and a catalog-only
    mutation would be undone halfway through a run."""
    global _cases_recorded
    original = TRIGGERS_SQL.read_text()
    conn = _connect(env)
    fns = _trigger_functions(conn)
    print(f"Polaris trigger mutation drill: refusals inside {len(fns)} trigger functions")
    print()
    for suite in FAST_SUITES:
        if _suite_is_red(suite, env):
            # Say which tests: a red baseline that names nothing cannot be triaged from a CI log.
            r = subprocess.run([sys.executable, "-m", "unittest", suite], cwd=str(ROOT / "polaris_web"),
                               env=env, capture_output=True, text=True)
            named = [ln for ln in r.stderr.splitlines() if ln.startswith(("FAIL:", "ERROR:"))]
            tail = r.stderr.splitlines()[-25:]
            print(f"FAIL: {suite} is red before anything is mutated:\n"
                  + "\n".join("  " + ln for ln in named[:30] + ["last lines:"] + tail), file=sys.stderr)
            return 1
    untested: list[str] = []
    stale: list[str] = []
    broken: list[str] = []
    try:
        for name, body in fns.items():
            for i, (a, b, text) in enumerate(_raise_spans(body)):
                key = f"{name}#{i}"
                _cases_recorded += 1
                mutated = body[:a] + "NULL; /* MUTATION (polaris-trigger-mutation-drill) */" + body[b:]
                TRIGGERS_SQL.write_text(original + "\n-- MUTATION (polaris-trigger-mutation-drill)\n"
                                        + mutated + ";\n")
                try:
                    with conn.cursor() as cur:
                        cur.execute(mutated)
                    caught = next((s for s in FAST_SUITES if _suite_is_red(s, env)), None)
                finally:
                    TRIGGERS_SQL.write_text(original)
                    try:
                        with conn.cursor() as cur:
                            cur.execute(body)
                    except psycopg2.Error as exc:
                        broken.append(f"{name}: {exc}")
                if caught and key in REFUSALS_MASKED:
                    stale.append(key)
                    print(f"  STALE     {key:48} declared masked, but {caught} goes red")
                elif caught:
                    print(f"  ok        {key:48} {caught} goes red")
                elif key in REFUSALS_MASKED:
                    print(f"  masked    {key:48} {REFUSALS_MASKED[key]}")
                elif key in REFUSALS_APP_SUITE:
                    print(f"  declared  {key:48} {REFUSALS_APP_SUITE[key]}")
                else:
                    untested.append(key)
                    print(f"  UNTESTED  {key:48} {text}")
    finally:
        TRIGGERS_SQL.write_text(original)
        for name, body in fns.items():
            try:
                with conn.cursor() as cur:
                    cur.execute(body)
            except psycopg2.Error as exc:
                broken.append(f"{name}: {exc}")
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM pg_proc WHERE prosrc LIKE %s",
                    ("%MUTATION (polaris-trigger-mutation-drill)%",))
        left = cur.fetchone()[0]
    conn.close()
    print()
    missing = sorted(k for k in REFUSALS_MASKED
                     if k.split("#")[0] not in fns
                     or int(k.split("#")[1]) >= len(_raise_spans(fns[k.split("#")[0]])))
    if broken or left:
        print("FAIL: function(s) were NOT restored (%d left mutated): %s" % (left, "; ".join(broken)),
              file=sys.stderr)
        return 1
    if not _cases_recorded:
        print("FAIL: no refusal was found to delete; the catalog query or the parser has broken.",
              file=sys.stderr)
        return 1
    if untested:
        print("FAIL: refusal(s) can be deleted with the fast suites still green. Test each, or, if "
              "something else still refuses the change, say what in REFUSALS_MASKED: "
              + ", ".join(untested), file=sys.stderr)
        return 1
    if stale or missing:
        print("FAIL: REFUSALS_MASKED is out of date (now caught: %s; no such refusal: %s). A list of "
              "exceptions nobody prunes stops describing anything."
              % (", ".join(stale) or "none", ", ".join(missing) or "none"), file=sys.stderr)
        return 1
    print(f"OK: {_cases_recorded} refusals deleted one at a time; each turns a fast suite red or "
          f"is masked by the check REFUSALS_MASKED names ({len(REFUSALS_MASKED)}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
