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
#   scripts/polaris-coverage.sh --shard 2/3     # CI: run one third of the work, keep the data
#   scripts/polaris-coverage.sh --combine DIR --of 3   # CI: combine the shards' data, gate
#
# Shards (2026-10-15). This was CI's critical path, one step of 22 to 38 minutes. With
# --shard I/N the script runs machine I's share and stops before combining: its share of the
# sharded database suites (polaris-ship.py --part I/N deals the test classes over N machines)
# and every N-th of the other suites below, in their order. It fails on a red suite exactly as
# the whole run does, and leaves its .coverage.* data and a marker naming I/N. --combine DIR
# --of N then requires DIR/coverage-data-shard-I for every I from 1 to N, each holding that
# marker and at least one non-empty data file, combines them and applies the same floors. A
# shard missing, empty or from a different N fails the gate: a combined number that silently
# lacks a third of the suites would read as a drop at best, and at worst as a pass.
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
SHARD_I=1
SHARD_N=1
COMBINE_DIR=""
COMBINE_N=""
while [ $# -gt 0 ]; do
    case "$1" in
        --no-gate) GATE=0 ;;
        --shard)
            [[ "${2:-}" =~ ^([0-9]+)/([0-9]+)$ ]] || { echo "error: --shard takes I/N, as in 2/3" >&2; exit 2; }
            SHARD_I=${BASH_REMATCH[1]}; SHARD_N=${BASH_REMATCH[2]}
            [ "$SHARD_N" -ge 1 ] && [ "$SHARD_I" -ge 1 ] && [ "$SHARD_I" -le "$SHARD_N" ] \
                || { echo "error: --shard $2: need 1 <= I <= N" >&2; exit 2; }
            shift ;;
        --combine)
            [ -n "${2:-}" ] || { echo "error: --combine takes the directory holding the shards' data" >&2; exit 2; }
            COMBINE_DIR="$2"; shift ;;
        --of)
            [[ "${2:-}" =~ ^[1-9][0-9]*$ ]] || { echo "error: --of takes the number of shards" >&2; exit 2; }
            COMBINE_N="$2"; shift ;;
        *) echo "error: unknown argument $1" >&2; exit 2 ;;
    esac
    shift
done
if [ -n "$COMBINE_DIR" ] && [ -z "$COMBINE_N" ]; then
    echo "error: --combine needs --of N, the number of shards it must find" >&2; exit 2
fi
if [ -n "$COMBINE_DIR" ] && [ "$SHARD_N" -gt 1 ]; then
    echo "error: --combine and --shard are different runs" >&2; exit 2
fi
SHARDED=0
[ "$SHARD_N" -gt 1 ] && SHARDED=1

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
rm -f "$ROOT/coverage-shard.txt"

SUITE_FAIL=0

# --combine: the shards ran the suites; this only collects their data. Each shard's artifact is
# a directory of its own, and every one of the N must be there, carry its marker and hold data.
if [ -n "$COMBINE_DIR" ]; then
    echo "== collecting $COMBINE_N shard(s) from $COMBINE_DIR =="
    for i in $(seq 1 "$COMBINE_N"); do
        d="$COMBINE_DIR/coverage-data-shard-$i"
        [ -d "$d" ] || { echo "::error::coverage shard $i of $COMBINE_N is missing ($d); the floors cannot be checked" >&2; exit 1; }
        marker=$(cat "$d/coverage-shard.txt" 2>/dev/null || true)
        [ "$marker" = "$i/$COMBINE_N" ] \
            || { echo "::error::coverage shard $i of $COMBINE_N carries the marker '$marker', not '$i/$COMBINE_N'" >&2; exit 1; }
        found=0
        for f in "$d"/.coverage.*; do
            [ -f "$f" ] || continue
            [ -s "$f" ] || { echo "::error::coverage shard $i's data file $(basename "$f") is empty" >&2; exit 1; }
            cp "$f" "$ROOT/" || { echo "::error::could not copy $f" >&2; exit 1; }
            found=$((found + 1))
        done
        [ "$found" -gt 0 ] || { echo "::error::coverage shard $i of $COMBINE_N holds no data file" >&2; exit 1; }
        echo "  shard $i/$COMBINE_N: $found data file(s)"
    done
fi

# --shard I/N: which of the suites below are this machine's. Every N-th, in the order they
# appear, starting at the I-th; unsharded, all of them.
ITEM=0
mine() {
    ITEM=$((ITEM + 1))
    [ $(( (ITEM - 1) % SHARD_N + 1 )) -eq "$SHARD_I" ]
}

if [ -z "$COMBINE_DIR" ]; then
# Each suite runs under `coverage run -p` (parallel: a distinct data file per
# process), so nothing is double-counted and cwd differences do not collide.
# A suite FAILURE must fail this script: coverage of a green suite is
# meaningless if the suite is red, so SUITE_FAIL is tracked and gates the exit
# alongside the floor. (An early version swallowed suite failures with `|| echo`
# and would have passed CI on a broken test as long as coverage held.)
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

echo "== running suites under coverage$([ "$SHARDED" = 1 ] && echo ", shard $SHARD_I of $SHARD_N") =="
mine && run "$ROOT"            pytest polaris_checks/test_checks.py -q

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
# Sharded across machines as well: each shard takes its part of the classes (--part I/N).
PART=()
[ "$SHARDED" = 1 ] && PART=(--part "$SHARD_I/$SHARD_N")
if ! POLARIS_SHIP_COVERAGE=1 "$PY" "$ROOT/scripts/polaris-ship.py" run --no-unsharded ${PART[@]+"${PART[@]}"} \
        --module test_app --module test_check_constraints \
        --module test_invariants_property --module test_redaction_property \
        --module test_canonical_equivalence; then
    echo "::error::sharded suite failed (test_app, test_check_constraints, test_invariants_property, test_redaction_property, test_canonical_equivalence)" >&2
    SUITE_FAIL=1
fi

mine && run "$ROOT/polaris_web" unittest test_pqc_signing test_custody test_secretstore test_transparency test_capacity test_referee test_enrollment_code test_credential_copy_keys test_wallet_copy test_issuance_tunnel
mine && run "$ROOT/polaris_cli" unittest test_cli
mine && run_standalone "$ROOT/scripts" unittest test_verify_load test_wallet test_relying_party \
                                       test_verify_conformance test_verify_p9 test_verify_refusals test_ship_tool \
                                       test_pgbouncer_entrypoint test_issuance_scope test_sbom_enrich \
                                       test_conformance_runner test_pin_chart_images test_release_tag_guard test_chain_anchor_tool test_migrate_runner \
                                       test_coverage_script test_trigger_drill test_procedure_drill test_oid4vp_drill test_sdk_drill test_ci_changes test_ci_gate test_compose_parse test_operator_env test_key_event test_doctor test_evaluate \
                                       test_sync_objects_parity test_event_partition_migration test_database_settings \
                                       test_db_state test_db_reference test_pgbackrest_conf test_db_init \
                                       test_dev_tunnel test_tree_gate test_transparency_tools
# Verbose, so the log names each restore case that passed (docs/operator/SECURITY-STATE-DRILLS.md cites it).
mine && run_standalone "$ROOT/scripts" unittest -v test_restore_schema_check
# polaris_sim's tests import the package (from polaris_sim import ...), so they
# run from the repo root with the dotted module path, not from inside the dir.
mine && run "$ROOT" unittest polaris_sim.test_sim

# The card profile, its emulator and the verifier device, and the ZK second witness's own suites,
# run in this job's other steps but were not measured (2026-09-30): polaris_card was missing from
# the denominator altogether, and the witness was measured only through test_app. Measuring them
# counts what they test and puts polaris_card where it belongs, even though it lowers the total.
mine && run_standalone "$ROOT" unittest discover -s polaris_card -t . -p 'test_*.py'
mine && run_standalone "$ROOT" pytest -q polaris_zk/witness2/test_witness2.py polaris_web/test_zk_second_witness.py

# The standalone packages, as they ship (2026-09-29). Their suites run in CI beside these; leaving
# them out measured the tree and not what PyPI and npm carry.
mine && run_standalone "$ROOT/sdk/python" unittest test_sdk
mine && run_standalone "$ROOT/packages/polaris-oid4vp" unittest test_sdjwt test_jwe test_verifier test_serve \
                                                       test_cli test_conformance_capture test_status
# The conformance suite drives the Python SDK's command line in a child process per case, which
# subprocess coverage records; and the detached verifier's own check of every published vector,
# as CI runs it. (Its --selftest needs liboqs, which this job does not install.)
if mine; then
    ( cd "$ROOT" && PYTHONPATH="$ROOT/sdk/python${PYTHONPATH:+:$PYTHONPATH}" \
          "$PY" conformance/run_conformance.py --self >/dev/null ) \
        || { echo "::error::suite failed: conformance/run_conformance.py --self" >&2; SUITE_FAIL=1; }
fi
if mine; then
    ( cd "$ROOT" && "$PY" -m coverage run -p scripts/polaris-verify.py --pqc-provider auto --verify-dir vectors >/dev/null ) \
        || { echo "::error::suite failed: polaris-verify.py --verify-dir vectors" >&2; SUITE_FAIL=1; }
fi
fi  # the suites (not --combine)

# --shard: this machine's share has run. A red suite fails the shard; otherwise the data files
# stay for the combining job, with a marker naming the share, and nothing is combined here.
if [ "$SHARDED" = 1 ]; then
    if [ "$SUITE_FAIL" -ne 0 ]; then
        echo "::error::one or more suites failed in coverage shard $SHARD_I of $SHARD_N; see above" >&2
        exit 1
    fi
    n=0
    for f in "$ROOT"/.coverage.*; do
        [ -s "$f" ] && n=$((n + 1))
    done
    [ "$n" -gt 0 ] || { echo "::error::coverage shard $SHARD_I of $SHARD_N wrote no data" >&2; exit 1; }
    echo "$SHARD_I/$SHARD_N" > "$ROOT/coverage-shard.txt"
    echo "== shard $SHARD_I of $SHARD_N: $n data file(s), ran $ITEM of the other suites' slots =="
    exit 0
fi

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
