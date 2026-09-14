#!/usr/bin/env python3
"""polaris-contract-reach-drill.py -- what does the published contract never touch?

`conformance/cases.json` is what a third-party implementation is measured against. The
conformance mutation drill already asks whether the contract constrains each verdict FIELD.
This asks the question one level up: **which published SDK entry points does the contract
never enter at all?**

A function no case reaches is a function an integrator could implement wrongly, or not at
all, and still be told they conform. That is not a bug in the function; it is a hole in the
contract, and it is invisible from inside the suite because every case passes either way.

METHOD. Run the whole published suite and record which lines of the SDK actually execute.
The suite drives the verifier as a SUBPROCESS, one per case, so the measurement is taken
inside the children: `coverage` is started there through COVERAGE_PROCESS_START and the
results combined. Measuring only the parent reports 0% of everything and looks like a broken
SDK rather than a wrongly aimed instrument, which cost one attempt to notice.

  unreached = a public function no published case enters

NEGATIVE CONTROL, and the run is VOID without it. If the measurement silently collected
nothing, every function looks unreached and this drill would report a catastrophe that is
really its own failure. So a run in which NOTHING is reached is refused, and so is a run
where the suite itself did not pass: a contract whose cases do not run constrains nothing,
and the interesting number would be measuring the harness.

`--prove-control` runs the suite with the collection deliberately disabled and REQUIRES the
void. A control that has never been watched failing is a comment.

  python3 scripts/polaris-contract-reach-drill.py
  python3 scripts/polaris-contract-reach-drill.py --json
"""
import argparse
import ast
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SDK = ROOT / "sdk" / "python"
MODULE = SDK / "polaris_verify" / "__init__.py"

#: Functions whose absence from the contract is a statement about the contract, not a gap to
#: be closed by this drill. Recorded so the count below is read as "unreached" rather than
#: "broken", and so a new one has to be added here deliberately rather than appearing in a
#: total nobody reads.
EXPECTED_UNREACHED = {
    # Linkability primitives. A relying party uses these to decide whether two presentations
    # could be the same holder; the published cases carry single artifacts, so there is no
    # case shaped like "here are two, are they linked".
    "nullifiers_link": "the contract publishes no case with two presentations to compare",
    "pairwise_handle": "same: a per-verifier handle has nothing to be compared against",
    "handles_link": "same",
    # Agent-grant authorization. The cases verify that a grant is GENUINE; whether a genuine
    # grant permits a particular action is a separate question the contract does not ask.
    "grant_covers": "the cases verify grant authenticity, never whether it covers an action",
    "grant_within_limits": "same: limits are checked by the SDK's own tests, not the contract",
    "revocation_ends_grant": "same: revocation is verified, its EFFECT on a grant is not",
}


def public_functions(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
            out[node.name] = set(range(node.body[0].lineno,
                                       (node.end_lineno or node.lineno) + 1))
    return out


def run_suite_with_coverage(workdir, collect=True):
    """Run the published suite, collecting coverage from every verifier subprocess."""
    rcfile = workdir / "coveragerc"
    rcfile.write_text("[run]\nparallel = True\nsource = %s\ndata_file = %s\n"
                      % (SDK / "polaris_verify", workdir / ".coverage"))
    # The child processes start coverage themselves, through the `a1_coverage.pth` that the
    # coverage package installs into site-packages: it calls `process_startup()` when
    # COVERAGE_PROCESS_START is set, and does nothing when it is not. So that ONE variable
    # is the whole mechanism, which is also what makes the control below work.
    #
    # An earlier version of this drill also wrote a `sitecustomize.py` into the work
    # directory and put it on PYTHONPATH, believing that was what started coverage. It was
    # not: Python imports the FIRST sitecustomize it finds, this interpreter already has
    # one, and the file written here was never imported. It was removed after emptying it
    # changed nothing, which is the only way that kind of decoration gets noticed.
    env = dict(os.environ)
    if collect:
        env["COVERAGE_PROCESS_START"] = str(rcfile)
    else:
        env.pop("COVERAGE_PROCESS_START", None)
    env["PYTHONPATH"] = os.pathsep.join([str(SDK),
                                         env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    proc = subprocess.run([sys.executable, str(ROOT / "conformance" / "run_conformance.py"),
                           "--self"], cwd=str(ROOT), env=env, capture_output=True, text=True)
    combine = subprocess.run([sys.executable, "-m", "coverage", "combine"],
                             cwd=str(workdir), env=dict(env, COVERAGE_FILE=str(workdir / ".coverage")),
                             capture_output=True, text=True)
    report = subprocess.run([sys.executable, "-m", "coverage", "json", "-o", str(workdir / "cov.json")],
                            cwd=str(workdir), env=dict(env, COVERAGE_FILE=str(workdir / ".coverage")),
                            capture_output=True, text=True)
    return proc, combine, report


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--json", action="store_true", help="machine-readable summary")
    ap.add_argument("--prove-control", action="store_true",
                    help="run with collection disabled; the drill must VOID")
    args = ap.parse_args()

    try:
        import coverage  # noqa: F401  presence is the point, not the name
    except ImportError:
        print("this drill needs the coverage package: pip install coverage", file=sys.stderr)
        return 2

    workdir = pathlib.Path(tempfile.mkdtemp(prefix="polaris-contract-reach-"))
    try:
        proc, combine, report = run_suite_with_coverage(workdir, collect=not args.prove_control)
        if proc.returncode != 0:
            print("the published suite did not pass, so there is nothing to measure:\n%s"
                  % (proc.stdout or proc.stderr)[-600:], file=sys.stderr)
            return 2
        cov_path = workdir / "cov.json"
        if not cov_path.is_file():
            if args.prove_control:
                print("control holds: with collection disabled nothing was measured, and "
                      "the drill refuses rather than reporting every function unreached")
                return 0
            print("no coverage data was produced (%s). Measuring only the parent process "
                  "reports every function unreached, which is this drill failing rather "
                  "than the contract being empty."
                  % (report.stderr.strip() or combine.stderr.strip())[:200], file=sys.stderr)
            return 2
        data = json.loads(cov_path.read_text())
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    key = next((k for k in data["files"] if k.endswith("polaris_verify/__init__.py")), None)
    if key is None:
        print("the coverage data names no SDK module; nothing was measured", file=sys.stderr)
        return 2
    executed = set(data["files"][key]["executed_lines"])

    functions = public_functions(MODULE)
    reached = {n for n, lines in functions.items() if lines & executed}
    unreached = sorted(set(functions) - reached)

    # The control. Nothing reached means the measurement failed, not that the contract is
    # empty, and the two look identical in the output.
    if not reached:
        if args.prove_control:
            print("control holds: with collection disabled the drill VOIDS rather than "
                  "reporting every function unreached")
            return 0
        print("== VOID: no public SDK function was reached by any of the published cases. "
              "That is this drill's measurement failing, not a contract with nothing in it "
              "==", file=sys.stderr)
        return 3
    if args.prove_control:
        print("== the control FAILED: collection was disabled and coverage was recorded "
              "anyway, so this drill is measuring through something it does not control ==",
              file=sys.stderr)
        return 3

    unexpected = [n for n in unreached if n not in EXPECTED_UNREACHED]
    if args.json:
        print(json.dumps({"public": len(functions), "reached": len(reached),
                          "unreached": unreached, "unexpected": unexpected}, indent=2))
    else:
        cases = json.loads((ROOT / "conformance" / "cases.json").read_text())["cases"]
        print("published contract: %d cases over %d public SDK functions"
              % (len(cases), len(functions)))
        print("  reached by at least one case:   %d" % len(reached))
        print("  reached by no case:             %d" % len(unreached))
        for name in unreached:
            why = EXPECTED_UNREACHED.get(name)
            print("      %-26s %s" % (name, why or "NOT ACCOUNTED FOR"))

    if unexpected:
        print("\n== %d public function(s) the contract does not reach and this drill does not "
              "account for: %s. Either the contract should carry a case for it, or this "
              "drill should say why it does not ==" % (len(unexpected), ", ".join(unexpected)),
              file=sys.stderr)
        return 1
    print("\n== every unreached function is accounted for. An unreached function is a hole in "
          "the CONTRACT, not a bug in the function: an integrator can implement it any way "
          "and still be told they conform. ==")
    return 0


if __name__ == "__main__":
    sys.exit(main())
