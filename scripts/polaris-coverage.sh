#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
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
#   scripts/polaris-coverage.sh --no-gate       # run + report only (no floors)
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
#   rc.66   80  measured 84% (CI 36457520993) -- the OpenSSF silver criterion is 80% statement coverage
#   2026-09-29  84 / 82  statements 86.59%, branches 84.74% in a local run set up as CI's job is
#               (no liboqs), with the packages' suites added and tooling omitted. The floors sit
#               under CI's last own number (84%); raise them once CI reports the new measurement
#   2026-09-29  86 / 84  CI measured statements 86.57%, branches 84.68% (run 36519839718)
# Since 2026-09-29 branches are measured too (.coveragerc) and have their own floor, BRANCH_FLOOR.
# coverage.py's TOTAL blends the two once branches are on, so the gate reads each from coverage.json.
COVERAGE_FLOOR="${COVERAGE_FLOOR:-80}"
BRANCH_FLOOR="${BRANCH_FLOOR:-80}"
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

# The four database-heavy modules, SHARDED. They were 24 of this step's 26 minutes and this
# step is CI's critical path; polaris-ship.py already runs them across processes with a fresh
# database each, and `coverage run -p` writes one data file per process, which is what it is
# for. Verified 2026-09-18 by running the same modules serially and sharded and combining:
# 17087 statements, 16928 missed, identical both ways. A shard failure must fail this script
# exactly like a serial suite failure, so the exit status is tracked the same way.
# test_canonical_equivalence joined the sharded set on 2026-09-18: it was 127 tests in 507s
# and the single biggest serial block left in this step. It looks unshardable -- one class
# in the file -- but it BUILDS one TestCase per signed type at import, so the loader finds
# twenty-two classes and they distribute like any others. 6.9x locally.
# --no-unsharded (2026-10-08): `run` goes on to the unsharded suites, the schema-drift drill and the
# application-role suite, and this step had been running them all: the unsharded suites are the ones
# this script runs itself below, and the other two are steps of their own in the product suite's
# core part. That was 37 of this step's 64 minutes, measuring nothing new.
if ! POLARIS_SHIP_COVERAGE=1 "$PY" "$ROOT/scripts/polaris-ship.py" run --no-unsharded \
        --module test_app --module test_check_constraints \
        --module test_invariants_property --module test_redaction_property \
        --module test_canonical_equivalence; then
    echo "::error::sharded suite failed (test_app, test_check_constraints, test_invariants_property, test_redaction_property, test_canonical_equivalence)" >&2
    SUITE_FAIL=1
fi

run "$ROOT/polaris_web" unittest test_pqc_signing test_custody test_secretstore test_transparency test_capacity test_referee test_enrollment_code test_credential_copy_keys test_wallet_copy test_issuance_tunnel
run "$ROOT/polaris_cli" unittest test_cli
run_standalone "$ROOT/scripts" unittest test_verify_load test_wallet test_relying_party \
                                       test_verify_conformance test_verify_p9 test_verify_refusals test_ship_tool \
                                       test_pgbouncer_entrypoint test_issuance_scope test_sbom_enrich \
                                       test_conformance_runner test_pin_chart_images test_chain_anchor_tool test_migrate_runner \
                                       test_coverage_script test_trigger_drill test_db_init
# polaris_sim's tests import the package (from polaris_sim import ...), so they
# run from the repo root with the dotted module path, not from inside the dir.
run "$ROOT" unittest polaris_sim.test_sim

# The card profile, its emulator and the verifier device, and the ZK second witness's own suites,
# run in this job's other steps but were not measured (2026-09-30): polaris_card was missing from
# the denominator altogether, and the witness was measured only through test_app. Measuring them
# counts what they test and puts polaris_card where it belongs, even though it lowers the total.
run_standalone "$ROOT" unittest discover -s polaris_card -t . -p 'test_*.py'
run_standalone "$ROOT" pytest -q polaris_zk/witness2/test_witness2.py polaris_web/test_zk_second_witness.py

# The standalone packages, as they ship (2026-09-29). Their suites run in CI beside these; leaving
# them out measured the tree and not what PyPI and npm carry.
run_standalone "$ROOT/sdk/python" unittest test_sdk
run_standalone "$ROOT/packages/polaris-oid4vp" unittest test_sdjwt test_jwe test_verifier test_serve \
                                                       test_cli test_conformance_capture test_status
# The conformance suite drives the Python SDK's command line in a child process per case, which
# subprocess coverage records; and the detached verifier's own check of every published vector,
# as CI runs it. (Its --selftest needs liboqs, which this job does not install.)
( cd "$ROOT" && PYTHONPATH="$ROOT/sdk/python${PYTHONPATH:+:$PYTHONPATH}" \
      "$PY" conformance/run_conformance.py --self >/dev/null ) \
    || { echo "::error::suite failed: conformance/run_conformance.py --self" >&2; SUITE_FAIL=1; }
( cd "$ROOT" && "$PY" -m coverage run -p scripts/polaris-verify.py --pqc-provider auto --verify-dir vectors >/dev/null ) \
    || { echo "::error::suite failed: polaris-verify.py --verify-dir vectors" >&2; SUITE_FAIL=1; }

echo "== combining =="
# A gate that cannot read its numbers fails. From 2026-09-30 to 2026-10-08 `coverage json` failed
# ("No source for code"; see [paths] in .coveragerc), the totals came out empty, the floor
# comparison crashed, and its empty answer read as "nothing below the floor": CI passed unmeasured.
# scripts/test_coverage_script.py runs this part against a stub interpreter.
if ! "$PY" -m coverage combine; then
    echo "::error::coverage combine failed; the floors cannot be checked" >&2
    exit 1
fi
# Sorted by missed statements, so the tail CI prints is where the gap is: the files missing the
# most, then TOTAL. Sorted by name, the tail was the last 25 files alphabetically.
"$PY" -m coverage report --skip-covered --sort=miss | tail -42
"$PY" -m coverage xml -o "$ROOT/coverage.xml" >/dev/null 2>&1 || true
rm -f "$ROOT/coverage.json"
if ! "$PY" -m coverage json -q -o "$ROOT/coverage.json"; then
    echo "::error::coverage json failed; the floors cannot be checked" >&2
    exit 1
fi

# Statements and branches, each out of the JSON totals (coverage.py's TOTAL blends them).
if ! TOTALS=$("$PY" -c 'import json, sys
t = json.load(open(sys.argv[1]))["totals"]
print("%.2f %.2f" % (100.0 * t["covered_lines"] / max(t["num_statements"], 1),
                     100.0 * t["covered_branches"] / max(t["num_branches"], 1)))' "$ROOT/coverage.json") \
        || [ -z "$TOTALS" ]; then
    echo "::error::the totals could not be read out of coverage.json; the floors cannot be checked" >&2
    exit 1
fi
STMT=${TOTALS% *}
BRANCH=${TOTALS#* }
echo "== statements ${STMT}% (floor ${COVERAGE_FLOOR}%), branches ${BRANCH}% (floor ${BRANCH_FLOOR}%) =="

# Publish to the GitHub Actions step summary when running in CI.
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "### Python coverage"
        echo "Statements: **${STMT}%** (floor ${COVERAGE_FLOOR}%). Branches: **${BRANCH}%** (floor ${BRANCH_FLOOR}%)."
    } >> "$GITHUB_STEP_SUMMARY"
fi

# A red suite fails the script regardless of the coverage number.
if [ "$SUITE_FAIL" -ne 0 ]; then
    echo "::error::one or more suites failed; see above" >&2
    exit 1
fi

if [ "$GATE" -eq 1 ]; then
    if ! BELOW=$("$PY" -c 'import sys
s, b, fs, fb = map(float, sys.argv[1:])
print(" ".join(n for n, v, f in (("statements", s, fs), ("branches", b, fb)) if v < f))' \
            "$STMT" "$BRANCH" "$COVERAGE_FLOOR" "$BRANCH_FLOOR"); then
        echo "::error::the floors could not be compared (statements '${STMT}', branches '${BRANCH}')" >&2
        exit 1
    fi
    if [ -n "$BELOW" ]; then
        echo "::error::Python coverage is below its floor (${BELOW}): statements ${STMT}% (floor ${COVERAGE_FLOOR}%), branches ${BRANCH}% (floor ${BRANCH_FLOOR}%)" >&2
        exit 1
    fi
fi
