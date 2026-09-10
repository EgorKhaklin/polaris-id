#!/usr/bin/env bash
# ============================================================================
# scripts/polaris-coverage.sh — measure + gate test coverage (roadmap P0.8).
#
# Runs the Python suites under coverage.py in PARALLEL-APPEND mode (each suite
# writes its own .coverage.* data file), combines them, prints the report, and
# fails if total line coverage drops below the floor. The floor is a ratchet:
# it is set just below the measured baseline, so real regressions fail CI while
# noise does not, and it is raised deliberately as coverage improves.
#
# The DB suites need the same environment as scripts/polaris-test.sh (Postgres as the
# schema owner; see DEVNOTES / the polaris-test.sh header). CI provides it; locally,
# export POLARIS_DB_* first or run via polaris-test.sh's environment.
#
# Usage:
#   scripts/polaris-coverage.sh                 # run, report, gate on the floor
#   scripts/polaris-coverage.sh --no-gate       # run + report only (no fail-under)
#   COVERAGE_FLOOR=80 scripts/polaris-coverage.sh   # override the floor
# ============================================================================

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

# The floor. Set below the measured baseline so a real drop fails but a small
# flake does not. Raise it (never silently lower it) as coverage climbs.
#   v9.350  70  measured 70% -- the detached verifier's tests were being discarded
#   v9.351  72  measured 75% -- run_standalone stopped discarding them
#   v9.352  74  measured 75% -- ratcheted to sit just under the real baseline
COVERAGE_FLOOR="${COVERAGE_FLOOR:-74}"
GATE=1
[ "${1:-}" = "--no-gate" ] && GATE=0

PY="${POLARIS_TEST_PYTHON:-python3}"
"$PY" -c "import coverage" 2>/dev/null || {
    echo "error: coverage.py not installed for $PY (pip install coverage)" >&2
    exit 2
}

export COVERAGE_RCFILE="$ROOT/.coveragerc"
# Pin the data file to an ABSOLUTE path so the parallel per-suite files all land
# in one place regardless of each suite's cwd (test_app runs from polaris_web/,
# test_cli from polaris_cli/); otherwise `coverage combine` from the root would
# miss the files written inside those subdirs.
export COVERAGE_FILE="$ROOT/.coverage"

# Subprocess coverage. test_cli shells into polaris.py via `sys.executable`, so
# the CLI runs in a CHILD process the parent's `coverage run` cannot see
# (polaris.py measured 0% despite 64 passing tests until this was wired). The
# coverage subprocess pattern: a sitecustomize on PYTHONPATH calls
# coverage.process_startup(), which fires when COVERAGE_PROCESS_START is set, so
# every child interpreter records its own parallel data file. run_cli() copies
# os.environ, so the child inherits both vars.
SITE_DIR="$(mktemp -d)"
trap 'rm -rf "$SITE_DIR"' EXIT
printf 'import coverage; coverage.process_startup()\n' > "$SITE_DIR/sitecustomize.py"
export PYTHONPATH="$SITE_DIR${PYTHONPATH:+:$PYTHONPATH}"
export COVERAGE_PROCESS_START="$ROOT/.coveragerc"

"$PY" -m coverage erase

# Each suite runs under `coverage run -p` (parallel: a distinct data file per
# process), so nothing is double-counted and cwd differences do not collide.
# A suite FAILURE must fail this script: coverage of a green suite is
# meaningless if the suite is red, so SUITE_FAIL is tracked and gates the exit
# alongside the floor. (An early version swallowed suite failures with `|| echo`
# and would have passed CI on a broken test as long as coverage held.)
SUITE_FAIL=0
run() {  # run <cwd> <module...>  -- measures the product packages
    local dir="$1"; shift
    if ! ( cd "$dir" && COVERAGE_RCFILE="$ROOT/.coveragerc" \
        "$PY" -m coverage run -p --source="$ROOT/polaris_web,$ROOT/polaris_cli,$ROOT/polaris_checks,$ROOT/polaris_sim" \
        -m "$@" ); then
        echo "::error::suite failed: $dir $*" >&2
        SUITE_FAIL=1
    fi
}

# The standalone artifacts under scripts/ -- the detached verifier, the wallet, the
# relying-party client -- are shipped product that lives OUTSIDE the four package dirs, so
# --source would silently discard every line their tests cover. (It did: scripts/polaris-verify.py
# read 9% while its only measured lines came in through subprocesses.) These suites therefore
# run UNRESTRICTED, measuring exactly the files they import. The .coveragerc omits keep tests,
# venvs and generated code out; drills are not imported, so they never enter the denominator.
run_standalone() {  # run_standalone <cwd> <module...>
    local dir="$1"; shift
    if ! ( cd "$dir" && COVERAGE_RCFILE="$ROOT/.coveragerc" "$PY" -m coverage run -p -m "$@" ); then
        echo "::error::suite failed: $dir $*" >&2
        SUITE_FAIL=1
    fi
}

echo "== running suites under coverage =="
run "$ROOT"            pytest polaris_checks/test_checks.py -q
run "$ROOT/polaris_web" unittest test_app test_check_constraints test_pqc_signing test_custody test_secretstore
run "$ROOT/polaris_web" unittest test_invariants_property test_redaction_property test_canonical_equivalence
run "$ROOT/polaris_cli" unittest test_cli
run_standalone "$ROOT/scripts" unittest test_verify_load test_wallet test_relying_party \
                                       test_verify_conformance test_verify_p9
# polaris_sim's tests import the package (from polaris_sim import ...), so they
# run from the repo root with the dotted module path, not from inside the dir.
run "$ROOT" unittest polaris_sim.test_sim

echo "== combining =="
"$PY" -m coverage combine
"$PY" -m coverage report --skip-covered | tail -25
"$PY" -m coverage xml -o "$ROOT/coverage.xml" >/dev/null 2>&1 || true

TOTAL=$("$PY" -m coverage report | awk '/^TOTAL/{gsub("%","",$NF); print $NF}')
echo "== TOTAL line coverage: ${TOTAL}% (floor ${COVERAGE_FLOOR}%) =="

# Publish to the GitHub Actions step summary when running in CI.
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "### Python coverage"
        echo "Total line coverage: **${TOTAL}%** (floor ${COVERAGE_FLOOR}%)"
    } >> "$GITHUB_STEP_SUMMARY"
fi

# A red suite fails the script regardless of the coverage number.
if [ "$SUITE_FAIL" -ne 0 ]; then
    echo "::error::one or more suites failed; see above" >&2
    exit 1
fi

if [ "$GATE" -eq 1 ]; then
    "$PY" -m coverage report --fail-under="$COVERAGE_FLOOR" >/dev/null 2>&1 || {
        echo "::error::Python coverage ${TOTAL}% is below the floor ${COVERAGE_FLOOR}%" >&2
        exit 1
    }
fi
