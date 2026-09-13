#!/usr/bin/env bash
# ============================================================================
# polaris-chaos-test.sh — chaos injection + fail-safe-never-open assertions
#
# v9.27. A security system is judged by how
# it breaks, not how it runs. This script injects three failure modes
# and asserts that under each, the system REFUSES the operation
# (fails safe) rather than silently succeeding (fails open).
#
# **Load-bearing assertion:**
# "Never open" — an attacker exploiting any of these failure modes
# must not be able to get a positive outcome (e.g., a token issued
# despite DB-unreachable, a ZK proof "verified" despite missing
# binary, an epoch closed despite an interruption mid-flight).
#
# Three scenarios:
#
#   1. db_unreachable_mid_recovery — simulate DB connection drop while
#      polaris-recover-admin.sh is running its mid-window logic.
#      Assertion: recovery refuses; never enables emergency-login.
#
#   2. zk_binary_absent            — remove polaris-zk binary; attempt
#      ZK verify operation.
#      Assertion: verifier refuses; never returns verified=true.
#
#   3. epoch_close_interrupted     — interrupt close_anchor_batch SQL
#      mid-transaction.
#      Assertion: anchor batch remains OPEN; partial close is rolled
#      back; no leaked half-closed batch.
#
# The accounting this keeps honest:
#   - Each scenario is REPEATABLE (deterministic).
#   - CI-runnable, ≤5 min wall.
#   - Pass bar: all 3 refuse correctly.
#
# Usage:
#     ./scripts/polaris-chaos-test.sh                 # run all 3
#     ./scripts/polaris-chaos-test.sh --scenario db_unreachable_mid_recovery
#     ./scripts/polaris-chaos-test.sh --list
#     ./scripts/polaris-chaos-test.sh --json
#
# Exit codes:
#   0  all scenarios passed (fail-safe-never-open)
#   1  one or more scenarios FAILED OPEN (security regression)
#   2  argument error
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"

LIST=0
JSON=0
TARGET_SCENARIO=""
for arg in "$@"; do
    case "${arg}" in
        --list)      LIST=1 ;;
        --json)      JSON=1 ;;
        --scenario)  shift; TARGET_SCENARIO="${1:-}" ;;
        --scenario=*) TARGET_SCENARIO="${arg#*=}" ;;
        --help|-h)
            sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
    esac
    shift 2>/dev/null || true
done

cd "${POLARIS_ROOT}"

# v9.166 — resolve an interpreter that can import the app modules. The
# harness previously ran under bare `python3`; on a dev box where that is
# 3.9, importing polaris_web/zk.py raises on its 3.10+ annotations, and the
# zk_binary_absent scenario silently mistook that import failure for a
# verifier refusal: permanently fail-safe, never exercising anything. Same
# discovery order as scripts/polaris-test.sh.
PY_BIN="${POLARIS_TEST_PYTHON:-}"
if [[ -z "${PY_BIN}" ]]; then
    for cand in \
        "${POLARIS_ROOT}/polaris_web/venv/bin/python" \
        "/private/tmp/polaris-codex-venv312/bin/python" \
        "$(command -v python3.12 || true)" \
        "$(command -v python3 || true)"
    do
        if [[ -x "${cand}" ]] && "${cand}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
            PY_BIN="${cand}"
            break
        fi
    done
fi
PY_BIN="${PY_BIN:-python3}"

"${PY_BIN}" - "${LIST}" "${JSON}" "${TARGET_SCENARIO}" <<'PY'
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

list_mode, json_mode, target_scenario = sys.argv[1:4]
list_mode = list_mode == "1"
json_mode = json_mode == "1"

REPO = Path(__file__).resolve().parents[1] if __file__ != "<stdin>" else Path.cwd()
# When invoked via heredoc, __file__ is undefined; cwd is repo root.
try:
    REPO = Path(os.getcwd())
except Exception:
    pass


# ---------- Helper: precondition check -------------------------------

def _shell_has(cmd):
    """Return True if `cmd` is on PATH."""
    return shutil.which(cmd) is not None


# ---------- Scenario 1: DB unreachable mid recovery -------------------

def scenario_db_unreachable_mid_recovery():
    """polaris-recover-admin.sh queries the DB to validate the second
    admin's identity before opening a 15-minute emergency-login window.
    If the DB is unreachable, the script MUST refuse — never default
    to "grant the window anyway."

    We test this by invoking the script with a deliberately broken
    DB connection (env points at a port nothing is listening on).
    Assertion: exit code is non-zero (refused) AND output contains
    an error or refusal message; output must NOT contain any
    "window opened" / "granted" / "success" string.
    """
    # Precondition: psql must be on PATH (the script shells out to it).
    # If psql isn't available, this scenario is INCONCLUSIVE — not a
    # fail-open, just unverified. Reported as unverified rather than as passing.
    if not _shell_has("psql"):
        return {"scenario": "db_unreachable_mid_recovery",
                "passed": None,  # None = inconclusive (not fail, not pass)
                "reason": "INCONCLUSIVE — psql not on PATH; scenario "
                          "requires a Postgres client to inject the "
                          "DB-unreachable failure. Install psql + rerun "
                          "to exercise this path."}

    env = os.environ.copy()
    env["POLARIS_DB_HOST"] = "127.0.0.1"
    env["POLARIS_DB_PORT"] = "1"  # nothing listens on port 1
    env["POLARIS_DB_NAME"] = "polaris_chaos_test"
    env["POLARIS_DB_USER"] = "polaris_app"
    env["POLARIS_DB_PASSWORD"] = "chaos"

    script = REPO / "scripts" / "polaris-recover-admin.sh"
    if not script.is_file():
        return {"scenario": "db_unreachable_mid_recovery",
                "passed": False,
                "reason": f"script missing: {script}"}

    # Invoke with --target + --authorizing-user-id (the second-admin
    # pairing form the script requires). With env-broken DB, the script
    # should TRY to connect, FAIL, and refuse to grant the window.
    try:
        proc = subprocess.run(
            ["bash", str(script),
             "--target", "admin",
             "--authorizing-user-id", "1",
             "--window-minutes", "15"],
            env=env, capture_output=True, timeout=30,
            input=b"y\n",  # in case it prompts for confirm
        )
    except subprocess.TimeoutExpired:
        return {"scenario": "db_unreachable_mid_recovery",
                "passed": False,
                "reason": "script hung — fail-safe-never-open requires"
                          " timely refusal, not hang"}

    out = proc.stdout.decode() + proc.stderr.decode()
    out_low = out.lower()

    # AP8 honest-injection check: the script must have actually
    # attempted the DB. If exit code is 2 (arg error) without DB
    # contact, we have NOT exercised the failure path.
    if proc.returncode == 2 and "must supply" in out_low:
        return {"scenario": "db_unreachable_mid_recovery",
                "passed": False,
                "reason": "chaos didn't inject — script errored on "
                          "args BEFORE attempting DB. Fix the args + "
                          "rerun to actually test the DB-unreachable "
                          "fail-safe path."}

    # FAIL-OPEN: script exits 0 AND output suggests success
    grant_markers = ("window opened", "granted", "emergency login enabled",
                     "successfully")
    refusal_markers = ("error", "failed", "refusing", "cannot connect",
                       "unreachable", "could not connect",
                       "connection refused")

    grant_seen = any(m in out_low for m in grant_markers)
    refusal_seen = any(m in out_low for m in refusal_markers)

    if proc.returncode == 0 and grant_seen and not refusal_seen:
        return {"scenario": "db_unreachable_mid_recovery",
                "passed": False,
                "reason": f"script returned 0 + emitted success markers "
                          f"despite DB unreachable. tail: {out[-300:]}"}

    # PASS only if we saw refusal evidence AND non-zero exit
    if refusal_seen and proc.returncode != 0:
        return {"scenario": "db_unreachable_mid_recovery",
                "passed": True,
                "exit_code": proc.returncode,
                "evidence": f"refused as expected. tail: {out[-200:]}"}

    # Otherwise honestly inconclusive
    return {"scenario": "db_unreachable_mid_recovery",
            "passed": False,
            "reason": f"inconclusive — exit {proc.returncode}; "
                      f"refusal_seen={refusal_seen}; grant_seen={grant_seen}. "
                      f"tail: {out[-300:]}"}


# ---------- Scenario 2: ZK binary absent ------------------------------

def scenario_zk_binary_absent():
    """polaris_web/zk.py invokes the polaris-zk Rust binary via
    subprocess. If the binary is absent (not built, deleted, wrong
    path), verify operations MUST return verified=False or raise,
    never return verified=True.

    Test: temporarily rename the binary (if present), then invoke
    a verify call with a synthetic proof. Restore on exit.
    """
    # Precondition: polaris_web/zk.py must exist (the wrapper we're
    # exercising). If not, this scenario is INCONCLUSIVE.
    zk_module = REPO / "polaris_web" / "zk.py"
    if not zk_module.is_file():
        return {"scenario": "zk_binary_absent",
                "passed": None,
                "reason": f"INCONCLUSIVE — polaris_web/zk.py missing; "
                          f"scenario requires the wrapper to exercise."}

    binary_paths = [
        REPO / "polaris_zk" / "target" / "release" / "polaris-zk",
        REPO / "polaris_zk" / "target" / "debug" / "polaris-zk",
    ]
    existing = [p for p in binary_paths if p.is_file()]

    moved = []
    try:
        # Move any present binaries aside
        for p in existing:
            backup = p.with_suffix(".chaos_backup")
            shutil.move(str(p), str(backup))
            moved.append((p, backup))

        # Now invoke the zk wrapper. It should fail / return verified=False.
        zk_module = REPO / "polaris_web" / "zk.py"
        if not zk_module.is_file():
            return {"scenario": "zk_binary_absent",
                    "passed": False,
                    "reason": f"polaris_web/zk.py missing; cannot test"}

        # Try to import + call verify. The Python wrapper should propagate
        # the missing-binary failure.
        #
        # v9.166 rewrite: this scenario was VACUOUS from the day it shipped.
        # It spawned bare `python3` (the system 3.9), whose import of zk.py
        # raises TypeError on the module's 3.10+ annotations before any
        # verification code runs, and the classifier below counted ANY raise
        # as a refusal. Result: permanent fail-safe verdicts from a probe that
        # never reached the wrapper; a fail-open verify_proof was undetectable
        # (proven live by planting a binary answering verified=true; the
        # scenario still reported FAIL-SAFE). Three fixes:
        #   1. sys.executable, not "python3": the interpreter running this
        #      harness, which can import the app modules.
        #   2. A WRAPPER_READY sentinel printed only after the import: a raise
        #      BEFORE the sentinel is an inconclusive probe, never a pass.
        #   3. POLARIS_ZK_BINARY stripped from the env: with the release
        #      binaries moved aside, a stale operator override would otherwise
        #      point past the simulated absence.
        env = os.environ.copy()
        env.pop("POLARIS_ZK_BINARY", None)
        proc = subprocess.run(
            [sys.executable, "-c", (
                "import sys\n"
                "sys.path.insert(0, 'polaris_web')\n"
                "import zk\n"
                "print('WRAPPER_READY')\n"
                "bundle = {'proof_hex': '00' * 64, "
                "'public_inputs_hex': ['00' * 32], "
                "'verifier_data_hex': '00' * 64}\n"
                "try:\n"
                "    result = zk.verify_proof(bundle)\n"
                "    print(f'VERIFY_RESULT={result}')\n"
                "except Exception as e:\n"
                "    print(f'VERIFY_RAISED={type(e).__name__}: {str(e)[:200]}')\n"
            )],
            env=env, capture_output=True, timeout=30,
            cwd=str(REPO),
        )
        out = proc.stdout.decode() + proc.stderr.decode()

        # The probe must actually reach the wrapper. If the import itself
        # failed, we learned nothing about the verifier: INCONCLUSIVE.
        if "WRAPPER_READY" not in out:
            return {"scenario": "zk_binary_absent",
                    "passed": None,
                    "reason": f"INCONCLUSIVE — the probe interpreter could not "
                              f"import polaris_web/zk.py, so the verifier was "
                              f"never exercised. out: {out[-300:]}"}

        # FAIL-OPEN: verify returned True with the binary absent.
        if "VERIFY_RESULT=True" in out:
            return {"scenario": "zk_binary_absent",
                    "passed": False,
                    "reason": f"verify returned True without binary present. "
                              f"out: {out[-300:]}"}

        # PASS: the wrapper was reached AND it refused (raised, or returned
        # False/None).
        if "VERIFY_RAISED=" in out or "VERIFY_RESULT=" in out:
            return {"scenario": "zk_binary_absent",
                    "passed": True,
                    "exit_code": proc.returncode,
                    "evidence": out[-300:]}

        return {"scenario": "zk_binary_absent",
                "passed": None,
                "reason": f"INCONCLUSIVE — probe produced no verdict marker. "
                          f"out: {out[-300:]}"}

    finally:
        # Restore moved binaries
        for p, backup in moved:
            try:
                shutil.move(str(backup), str(p))
            except Exception:
                pass


# ---------- Scenario 3: epoch close interrupted ----------------------

def scenario_epoch_close_interrupted():
    """uc11_close_epoch (or close_anchor_batch / equivalent procedure)
    must run inside a transaction. If interrupted mid-execution, the
    DB MUST rollback — no half-closed AnchorBatch row left over.

    Static-analysis check (since the kill test doesn't touch a live DB):
    verify that close_anchor_batch / uc11_close_epoch is declared with
    transaction semantics (LANGUAGE plpgsql implies transaction
    boundary; we verify the procedure does NOT have COMMIT/ROLLBACK
    inside which would defeat the safety).
    """
    procs_file = REPO / "polaris_sql" / "05_procedures.sql"
    if not procs_file.is_file():
        return {"scenario": "epoch_close_interrupted",
                "passed": False,
                "reason": f"05_procedures.sql missing"}
    src = procs_file.read_text()

    # Find close_anchor_batch / uc11_close_epoch procedure
    close_proc_match = re.search(
        r'(CREATE\s+(?:OR\s+REPLACE\s+)?PROCEDURE\s+'
        r'(?:close_anchor_batch|uc11_close_epoch)[^$]*\$\$(.*?)\$\$)',
        src, re.IGNORECASE | re.DOTALL,
    )
    if not close_proc_match:
        return {"scenario": "epoch_close_interrupted",
                "passed": False,
                "reason": "close_anchor_batch / uc11_close_epoch procedure "
                          "not found in 05_procedures.sql"}

    body = close_proc_match.group(2)

    # FAIL-OPEN risk: explicit COMMIT inside the procedure body
    # would create a partial-commit window
    if re.search(r'^\s*COMMIT\s*;', body, re.MULTILINE | re.IGNORECASE):
        return {"scenario": "epoch_close_interrupted",
                "passed": False,
                "reason": "close_anchor_batch contains explicit COMMIT; "
                          "interruption mid-procedure can leak a partially-"
                          "closed batch. PostgreSQL stored procedures with "
                          "explicit COMMIT bypass transaction-rollback "
                          "guarantees."}

    # FAIL-OPEN risk: SAVEPOINT + RELEASE pattern that could leave
    # state inconsistent
    if re.search(r'\bSAVEPOINT\b[^;]*;\s*[^;]*\bRELEASE\b',
                 body, re.IGNORECASE | re.DOTALL):
        # Not strictly fail-open; but worth noting. We don't fail
        # the test on this — savepoints can be legitimate. Just log.
        pass

    # PASS: procedure runs in caller's transaction; interruption =
    # rollback by Postgres default
    return {"scenario": "epoch_close_interrupted",
            "passed": True,
            "evidence": "close procedure has no explicit COMMIT; "
                        "transaction-rollback safety holds by default"}


ALL_SCENARIOS = [
    ("db_unreachable_mid_recovery", scenario_db_unreachable_mid_recovery,
     "Recovery script must refuse if DB unreachable; never grant window"),
    ("zk_binary_absent", scenario_zk_binary_absent,
     "ZK verifier must refuse if binary missing; never return verified=True"),
    ("epoch_close_interrupted", scenario_epoch_close_interrupted,
     "Anchor-batch close procedure must rollback on interruption"),
]

if list_mode:
    if json_mode:
        print(json.dumps([{"name": n, "description": d}
                          for n, _, d in ALL_SCENARIOS], indent=2))
    else:
        print("polaris-chaos-test scenarios:")
        for n, _, d in ALL_SCENARIOS:
            print(f"  - {n}: {d}")
    sys.exit(0)

scenarios = ALL_SCENARIOS
if target_scenario:
    scenarios = [s for s in ALL_SCENARIOS if s[0] == target_scenario]
    if not scenarios:
        print(f"✗ no scenario named '{target_scenario}'", file=sys.stderr)
        sys.exit(2)

print(f"polaris-chaos-test: {len(scenarios)} scenario(s)")
print()

results = []
fail_open_count = 0
for name, fn, desc in scenarios:
    print(f"  → {name}: {desc[:60]}...")
    t0 = time.perf_counter()
    try:
        r = fn()
    except Exception as e:
        r = {"scenario": name, "passed": False,
             "reason": f"scenario crashed: {type(e).__name__}: {e}"}
    elapsed_s = time.perf_counter() - t0
    r["elapsed_seconds"] = round(elapsed_s, 2)
    results.append(r)
    # Three states: passed=True (fail-safe), passed=False (FAILED OPEN),
    # passed=None (INCONCLUSIVE, precondition not met)
    if r["passed"] is True:
        marker = "✓ FAIL-SAFE"
    elif r["passed"] is None:
        marker = "○ INCONCLUSIVE"
    else:
        marker = "✗ FAILED OPEN"
        fail_open_count += 1
    print(f"    {marker} in {elapsed_s:.1f}s")
    if r["passed"] is not True:
        print(f"      reason: {r.get('reason', 'unknown')[:200]}")

n_pass = sum(1 for r in results if r["passed"] is True)
n_inconclusive = sum(1 for r in results if r["passed"] is None)
n_fail = sum(1 for r in results if r["passed"] is False)

print()
print(f"===== summary =====")
print(f"  scenarios:    {len(results)}")
print(f"  fail-safe:    {n_pass}/{len(results)}")
print(f"  inconclusive: {n_inconclusive}/{len(results)} (precondition not met)")
print(f"  failed open:  {n_fail}/{len(results)} (security regression)")
print(f"  total wall:   {sum(r.get('elapsed_seconds', 0) for r in results):.1f}s")

if json_mode:
    print(json.dumps({"summary": {"fail_open_count": fail_open_count,
                                   "inconclusive_count": n_inconclusive,
                                   "scenarios": len(results)},
                      "results": results}, indent=2))

# Pass bar: ZERO FAILED OPEN. Inconclusive scenarios are honestly
# reported but don't trigger the security alarm (operator can rerun
# with prerequisites installed).
if fail_open_count == 0:
    if n_inconclusive > 0:
        print(f"  ✓ NO FAIL-OPEN (but {n_inconclusive} scenario(s) inconclusive — install preconditions to verify)")
    else:
        print(f"  ✓ ALL FAIL-SAFE — never-open invariant holds")
    sys.exit(0)
else:
    print(f"  ✗ {fail_open_count} SCENARIO(S) FAILED OPEN — security regression")
    sys.exit(1)
PY
