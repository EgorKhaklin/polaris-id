#!/usr/bin/env python3
"""polaris-procedure-mutation-drill.py — is each refusal a stored procedure makes tested?

CHECK constraints are mutation-tested (v9.407), triggers are (v9.413), the ZK witnesses are
(v9.419) and the conformance contract is (v9.429). The stored procedures are the fourth
member of that family and the one with the most to hide: a trigger sees one row, while
`uc8_revoke_token` sees a whole revocation -- the token's state, the agency's bound, the
co-signer, the CRL entry -- and refuses across all of it. Those refusals are the
multi-step invariants, and nothing re-measured whether any test notices when one goes.

METHOD. Each `RAISE EXCEPTION` in a procedure is one refusal. The drill replaces exactly
one with `NULL;`, leaving the condition and every other statement intact, so the procedure
carries on and performs the write it should have refused. Then it runs the suites.

  survivor = a refusal that can be deleted with every test still green

That is a narrower and more honest mutation than dropping the procedure, which would fail
every test that calls it and prove only that the procedure is reachable.

RESTORATION. The definition of every procedure is captured before anything is touched and
reinstalled after each case. `reload_sample_data()` re-runs 04_data, 06_triggers, 09_grants
and 10_auth -- NOT 05_procedures -- so unlike the trigger drill a catalog change here
persists across a suite run, which is what makes the mutation stick, and also what makes
restoring non-optional. A restore failure is reported and the drill keeps going rather than
abandoning the database half-mutated (the v9.407 lesson).

AND IF IT IS KILLED. A long run can be killed outright -- the first exhaustive run of this
drill was, for memory -- and no handler catches that. It left one procedure mutated. So the
drill prints the one-line repair BEFORE it touches anything, and reinstalling
`polaris_sql/05_procedures.sql` restores every procedure from canonical source. A cleanup
path that only runs when the program is well behaved is not a cleanup path.

NEGATIVE CONTROL. A refusal known to be tested is mutated first and must turn the suites
red. If it does not, the harness is not running the tests and every "0 survivors" below
would be meaningless.

  python3 scripts/polaris-procedure-mutation-drill.py
  python3 scripts/polaris-procedure-mutation-drill.py --exhaustive   # also the app suite
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
    print("polaris-procedure-mutation-drill: psycopg2 is required (use the test venv)",
          file=sys.stderr)
    raise SystemExit(1)

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The drill rewrites real procedures. It runs only against a database whose name says it
#: is disposable, because a half-restored schema is worse than no drill.
TEST_DB_MARKER = "test"

#: Suites searched for the tests that exercise a given procedure. Procedure coverage lives
#: in the application suite, not the constraint suite: the first draft of this drill ran the
#: fast suites and its negative control correctly refused the run, because the refusal it
#: mutates is tested by test_app.IssuerDiscretionBoundsTests.
SUITE_FILES = ("test_app.py", "test_check_constraints.py", "test_invariants_property.py")

#: Running all of test_app per mutation exhausted this machine's memory on the first
#: attempt and the kill left a procedure mutated. So each mutation runs only the test
#: CLASSES that name the procedure under test, which is cheaper and also sharper: a
#: refusal in uc8_revoke_token should be caught by a test that calls uc8_revoke_token,
#: and if the only thing that notices is an unrelated class, that is worth seeing.
def _classes_exercising(name: str) -> list:
    """[suite.Class] for every test class whose body names this procedure."""
    out = []
    for fname in SUITE_FILES:
        path = ROOT / "polaris_web" / fname
        if not path.exists():
            continue
        module, current = fname[:-3], None
        for line in path.read_text(errors="replace").splitlines():
            m = re.match(r"class (\w+)\(", line)
            if m:
                current = m.group(1)
            elif current and name in line:
                out.append("%s.%s" % (module, current))
                current = None      # one hit per class is enough
    return sorted(set(out))

#: The refusal mutated as the negative control, and the suite that must notice. Chosen
#: because it is plainly tested: the co-signer rule is the subject of its own test.
CONTROL = ("uc8_revoke_token", "Co-signer must differ from actor")

#: Refusals nothing covers, each with the reason. Empty as of v9.437: every one of the
#: 59 refusals the 16 procedures make turns something red when it is deleted. On
#: 2026-09-23 the drill was extended to the use-case FUNCTIONS (see USE_CASE_ROUTINES),
#: which added eleven refusals; tests now catch eight of them, and the three below remain.
#:
#: The first measurement (v9.434) found 27 that nothing noticed, concentrated where the
#: invariants are multi-step and a trigger cannot see them. v9.435 covered the ten closest
#: to the constitution -- the four-eyes rule, the cool-down, the three out-of-band channels
#: and the third-person witness in uc9_complete_recovery, and the preconditions on an
#: irreversible erasure -- and v9.437 covered the remaining seventeen.
#:
#: An entry here is a guarantee a procedure makes and the tests do not check. The list is
#: checked in BOTH directions, so it cannot grow silently and a stale entry fails too.
SURVIVORS_EXPECTED: dict[str, str] = {
    # uc4_activate_reserve reads both tokens, takes a row lock on the holder, then re-reads
    # both under the lock (the fix for a stale second caller writing a duplicate revocation).
    # Each status check therefore exists twice, and on a single connection the two copies are
    # indistinguishable: delete either and its twin refuses with the same message.
    "uc4_activate_reserve#1": "pre-lock copy of the ACTIVE check; its twin #5, under the lock, "
                              "is the guarantee and the concurrent-uc4 test catches its loss",
    "uc4_activate_reserve#3": "pre-lock copy of the RESERVE check; its twin #6 refuses with the "
                              "same message on a single connection",
    "uc4_activate_reserve#6": "the RESERVE re-check under the lock. It fires only if another "
                              "procedure moves the reserve out of RESERVE between uc4's first "
                              "read and its lock; the pre-lock copy #3 catches every single-"
                              "connection case first, and no deterministic test drives that "
                              "interleaving yet. A real guarantee the tests do not check",
}


def _env() -> dict:
    env = dict(os.environ)
    env.setdefault("POLARIS_DB_HOST", "127.0.0.1")
    env.setdefault("POLARIS_DB_PORT", "5432")
    env.setdefault("POLARIS_DB_NAME", "polaris_test")
    env.setdefault("POLARIS_DB_USER", os.environ.get("USER", "postgres"))
    env.setdefault("POLARIS_TEST_RELOAD_USER", env["POLARIS_DB_USER"])
    return env


def _connect(env):
    return psycopg2.connect(host=env["POLARIS_DB_HOST"], port=env["POLARIS_DB_PORT"],
                            dbname=env["POLARIS_DB_NAME"], user=env["POLARIS_DB_USER"],
                            password=env.get("POLARIS_DB_PASSWORD") or None)


def _definitions(conn) -> dict:
    """procedure name -> its full CREATE OR REPLACE definition."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT p.proname, pg_get_functiondef(p.oid)
              FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'public' AND """ + USE_CASE_ROUTINES + """
             ORDER BY p.proname
        """, ())
        return {name: body for name, body in cur.fetchall()}


def _raise_spans(body: str) -> list:
    """(start, end, first line of the message) for every RAISE EXCEPTION in a body.

    A RAISE may span lines and its message may contain semicolons, so the end is the first
    `;` outside a quoted string rather than the first `;` at all.
    """
    spans = []
    for m in re.finditer(r"\bRAISE\s+EXCEPTION\b", body, re.I):
        i, in_str = m.end(), False
        while i < len(body):
            ch = body[i]
            if ch == "'":
                # '' inside a string is an escaped quote, not a terminator
                if in_str and i + 1 < len(body) and body[i + 1] == "'":
                    i += 2
                    continue
                in_str = not in_str
            elif ch == ";" and not in_str:
                break
            i += 1
        text = re.sub(r"\s+", " ", body[m.start():i])[:90]
        spans.append((m.start(), i + 1, text))
    return spans


def _suites_red(env, targets) -> bool:
    """True if any named test target reports a failure."""
    if not targets:
        return False
    r = subprocess.run([sys.executable, "-m", "unittest", *targets],
                       cwd=str(ROOT / "polaris_web"), env=env,
                       capture_output=True, text=True)
    return r.returncode != 0


def _install(conn, sql) -> str:
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()
        return ""
    except Exception as exc:      # noqa: BLE001 - reported, never fatal
        conn.rollback()
        return str(exc).splitlines()[0]


def _procedures_moved() -> bool:
    """Did this ship touch the procedures at all? None if that cannot be known.

    Deliberately coarse: it answers "did 05_procedures.sql or a migration change", not
    "which procedure changed". Two finer attempts both under-selected. Scraping names out
    of `git diff` missed an edit inside a body, because git's hunk headers carry no SQL
    function context and a changed line does not repeat the name it belongs to. Parsing
    the two versions into per-procedure bodies found 3 of 13, because the terminators in
    this file are not uniform, and it then reported the WRONG procedure as changed.

    Under-selecting here silently skips the thing that moved, which is the failure this
    drill exists to prevent, so the coarse answer is the right one: if the file moved, run
    all 59. That cost lands only on a ship that touches the procedures, which is rare, and
    a ship that does not touch them has nothing here to prove because the suites already
    ran.

    None rather than False when no baseline is reachable -- a shallow checkout, say --
    because "I could not tell" and "nothing changed" must not look alike.
    """
    try:
        base = subprocess.check_output(["git", "rev-parse", "HEAD~1"], cwd=str(ROOT),
                                       text=True, stderr=subprocess.DEVNULL).strip()
        out = subprocess.check_output(
            ["git", "diff", "--name-only", base, "--",
             "polaris_sql/05_procedures.sql", "polaris_sql/migrations"],
            cwd=str(ROOT), text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return None
    return bool(out.strip())


#: Which routines count. Stored PROCEDURES, and also the use-case FUNCTIONS: uc1_issue_and_activate,
#: uc4_activate_reserve and uc5_bind_device return the id they create, so they are declared
#: FUNCTION, and selecting prokind = 'p' alone left their eleven refusals (issuance,
#: activation, device binding) outside every mutation drill. Trigger functions are excluded:
#: the trigger drill answers for those. Found 2026-09-23 re-deriving the paper's claim that
#: the procedures "implement every state-changing use case".
USE_CASE_ROUTINES = ("(p.prokind = 'p' OR (p.prokind = 'f' AND p.proname LIKE 'uc%%' "
                     "AND p.prorettype <> 'trigger'::regtype))")

MUTATION_MARK = "mutation: this refusal deleted"


def _left_mutated(conn) -> list:
    """Procedures a previous, killed run left mutated."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'public' AND """ + USE_CASE_ROUTINES + """ AND p.prosrc LIKE %s
             ORDER BY 1
        """, ("%" + MUTATION_MARK + "%",))
        return [r[0] for r in cur.fetchall()]



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

def main(argv=None) -> int:
    _why = _interpreter_can_run_the_suite(['test_app', 'test_check_constraints'], ROOT / "polaris_web")
    if _why:
        print("polaris-procedure-mutation-drill: " + _why, file=sys.stderr)
        return 1
    ap = argparse.ArgumentParser()
    ap.add_argument("--exhaustive", action="store_true",
                    help="also run the application suite for refusals the fast suites miss")
    ap.add_argument("--only", default=None, help="one procedure name, for iterating")
    ap.add_argument("--changed", action="store_true",
                    help="only the procedures this ship touched (what CI runs per push)")
    args = ap.parse_args(argv)

    env = _env()
    if TEST_DB_MARKER not in env["POLARIS_DB_NAME"]:
        print("refusing to mutate %r: this drill rewrites procedures and runs only against "
              "a database whose name contains %r" % (env["POLARIS_DB_NAME"], TEST_DB_MARKER),
              file=sys.stderr)
        return 2

    conn = _connect(env)
    left = _left_mutated(conn)
    if left:
        print("a previous run left %d procedure(s) mutated: %s\n"
              "repair first: psql -d %s -f polaris_sql/05_procedures.sql"
              % (len(left), ", ".join(left), env["POLARIS_DB_NAME"]), file=sys.stderr)
        conn.close()
        return 2
    originals = _definitions(conn)
    if len(originals) < 10:
        print("only %d procedure(s) found; the catalog query has broken and this drill would "
              "be measuring almost nothing" % len(originals), file=sys.stderr)
        return 2

    if args.changed:
        moved = _procedures_moved()
        if moved is None:
            print("--changed cannot tell what this ship touched (no reachable HEAD~1). That is "
                  "not the same as 'nothing changed', so this is a refusal rather than a clean "
                  "run: give the checkout fetch-depth: 2, or run without --changed.",
                  file=sys.stderr)
            conn.close()
            return 2
        if not moved:
            print("  this ship did not touch polaris_sql/05_procedures.sql or a migration: "
                  "nothing to mutate")
            conn.close()
            return 0
        print("  the procedures moved in this ship: running all of them")

    cases = []
    for name, body in sorted(originals.items()):
        if args.only and name != args.only:
            continue
        for idx, (a, b, text) in enumerate(_raise_spans(body)):
            cases.append((name, idx, a, b, text))
    print("procedure mutation drill: %d refusal(s) across %d procedure(s)"
          % (len(cases), len({c[0] for c in cases})))
    # Refuse to report from nothing. `_raise_spans` parsing no RAISE at all, or an `--only`
    # naming a procedure that does not exist, both leave `cases` empty, and the verdict at
    # the end would then read "OK: 0 refusal(s) mutated ... deleting any of the rest turns
    # something red", which is a guarantee about an empty set. 2026-09-19.
    _cases_recorded = len(cases)
    if not _cases_recorded:
        print("FAIL: no refusal was found to mutate, so this drill would report a guarantee "
              "it never tested. Either 05_procedures.sql raises nowhere, the span parser has "
              "broken, or --only named a procedure that does not exist.", file=sys.stderr)
        return 1
    # Said before anything is mutated, because a killed run cannot say it afterwards.
    print("  if this run is interrupted, repair with:")
    print("    psql -d %s -f polaris_sql/05_procedures.sql" % env["POLARIS_DB_NAME"])

    def mutate(name, a, b):
        body = originals[name]
        return body[:a] + "NULL;  /* %s */" % MUTATION_MARK + body[b:]

    # BASELINE. Everything unmutated must be green, or nothing below means anything.
    targets_by_proc = {n: _classes_exercising(n) for n in {c[0] for c in cases}}
    uncovered = sorted(n for n, t in targets_by_proc.items() if not t)
    if uncovered:
        print("  no test class names: %s -- their refusals cannot be measured here"
              % ", ".join(uncovered))
    all_targets = sorted({t for ts in targets_by_proc.values() for t in ts})
    if _suites_red(env, all_targets):
        print("\nBASELINE IS RED before any mutation; fix the suites first.", file=sys.stderr)
        conn.close()
        return 1
    print("  baseline: the %d exercising test class(es) pass unmutated"
          % len(all_targets))

    # NEGATIVE CONTROL.
    cname, ctext = CONTROL
    ctl = [c for c in cases if c[0] == cname and ctext in c[4]]
    if not args.only:
        if not ctl:
            print("\nthe negative control refusal (%s: %s) is not in the catalog; without it a "
                  "clean run proves nothing" % CONTROL, file=sys.stderr)
            conn.close()
            return 1
        _n, _i, a, b, _t = ctl[0]
        err = _install(conn, mutate(cname, a, b))
        red = _suites_red(env, targets_by_proc.get(cname, [])) if not err else True
        _install(conn, originals[cname])
        if not red:
            print("\nNEGATIVE CONTROL FAILED: deleting a refusal that IS tested left the suites "
                  "green, so this harness is not running them.", file=sys.stderr)
            conn.close()
            return 1
        print("  negative control: deleting a tested refusal turns its own tests red")

    survivors, failed_restores, unmeasurable = [], [], []
    for name, idx, a, b, text in cases:
        # A procedure no test class names has an EMPTY target list, and an empty run is
        # green by definition, so every one of its refusals would read as a survivor. That
        # is the drill measuring nothing and reporting a finding. Their coverage lives
        # elsewhere -- polaris_sim, 08_tests.sql, the partition drill -- and saying
        # "unmeasurable here" is the honest answer.
        if not targets_by_proc.get(name):
            unmeasurable.append("%s#%d" % (name, idx))
            continue
        err = _install(conn, mutate(name, a, b))
        if err:
            print("  skip      %s#%d: the mutant would not install (%s)" % (name, idx, err))
            _install(conn, originals[name])
            continue
        red = _suites_red(env, targets_by_proc.get(name, []))
        if not red and args.exhaustive:
            red = _suites_red(env, all_targets)
        restore_err = _install(conn, originals[name])
        if restore_err:
            failed_restores.append((name, restore_err))
        if red:
            print("  ok        %s#%d  %s" % (name, idx, text))
        else:
            survivors.append(("%s#%d" % (name, idx), text))
            print("  SURVIVOR  %s#%d  %s" % (name, idx, text))

    # Whatever happened above, leave the database as it was found.
    for name, body in originals.items():
        err = _install(conn, body)
        if err:
            failed_restores.append((name, err))
    after = _definitions(conn)
    conn.close()

    print()
    if unmeasurable:
        print("%d refusal(s) are not measurable by this drill: no test class in %s names "
              "their procedure, so an empty run would call every one a survivor. They are "
              "exercised elsewhere (polaris_sim, polaris_sql/08_tests.sql, the partition "
              "drill)." % (len(unmeasurable), ", ".join(SUITE_FILES)))
    if failed_restores:
        print("RESTORE FAILED for %d procedure(s); the database may be mutated:"
              % len(failed_restores))
        for name, err in failed_restores:
            print("   %s: %s" % (name, err))
        return 1
    if after != originals:
        changed = sorted(k for k in originals if after.get(k) != originals[k])
        print("the catalog did not come back identical: %s" % ", ".join(changed))
        return 1
    print("the catalog came back intact: %d procedures, byte for byte." % len(after))

    found = {s[0] for s in survivors}
    # Compare only against the procedures this run actually measured. --only is for
    # iterating on one procedure, and without this every declared survivor belonging to a
    # procedure the run skipped reads as "now covered", so --only could never pass.
    measured = {c[0] for c in cases} - {u.split("#")[0] for u in unmeasurable}
    declared = {k for k in SURVIVORS_EXPECTED if k.split("#")[0] in measured}
    new_ones, gone = sorted(found - declared), sorted(declared - found)
    if new_ones:
        print("\nFAIL: %d refusal(s) can be deleted with every test still green:" % len(new_ones))
        for s in survivors:
            if s[0] in new_ones:
                print("   %s  %s" % s)
    if gone:
        print("\nSURVIVORS_EXPECTED names refusal(s) that are now covered; strike them: %s"
              % ", ".join(gone))
    if new_ones or gone:
        return 1
    # len(cases) counts the unmeasurable ones too, and saying "59 mutated" when ten were
    # skipped is this tool overstating its own work, which is the thing it exists to catch.
    print("OK: %d refusal(s) mutated, %d untested%s. Deleting any of the rest turns "
          "something red."
          % (len(cases) - len(unmeasurable), len(survivors),
             ("; %d not measurable here" % len(unmeasurable)) if unmeasurable else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
