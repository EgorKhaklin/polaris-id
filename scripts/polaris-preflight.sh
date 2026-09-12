#!/usr/bin/env bash
# ============================================================================
# scripts/polaris-preflight.sh — the pre-ship gate a contributor runs before
# committing.
#
# Three things, all fast and offline: the C1-C10 invariant layer
# (`python3 -m polaris_checks.run`), the cross-reference check, and the working
# plan for the change (`polaris-ship.py plan`). It then
# reminds you to run the database-backed suites, which need Postgres and so
# cannot run here.
#
#   bash scripts/polaris-preflight.sh            # run the gate
#   bash scripts/polaris-preflight.sh --strict   # exit non-zero on any failure
# ============================================================================

set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${HERE}/.." &> /dev/null && pwd)"
STRICT=0; [ "${1:-}" = "--strict" ] && STRICT=1

fails=0
echo "═══ polaris-preflight — pre-ship gate ═══"
echo

# 1. polaris-checks — the C1-C10 invariant layer.
if python3 -m polaris_checks.run > /tmp/_polaris_checks.out 2>&1; then
  echo "  ✓ polaris-checks: all C1-C10 invariants pass"
else
  echo "  ✗ polaris-checks: failures —"
  grep '✗' /tmp/_polaris_checks.out | sed 's/^/    /'
  fails=$((fails+1))
fi

# 2. Cross-reference integrity.
if bash "${HERE}/polaris-link-check.sh" --ci > /tmp/_polaris_links.out 2>&1; then
  echo "  ✓ polaris-link-check: all references resolve"
else
  echo "  ! polaris-link-check: $(tail -1 /tmp/_polaris_links.out)"
  fails=$((fails+1))
fi

# 2b. Lint. CI runs `ruff check .` as its FIRST step in the product-test job, so a
#     single unused import fails the whole run before a test executes. v9.382 shipped
#     with one and cost a CI cycle, because this gate printed READY without ever
#     linting. If ruff is absent the gate says so rather than passing quietly: a
#     preflight that stays silent about what it did not check is how READY stops
#     meaning anything.
if command -v ruff > /dev/null 2>&1; then
  if ruff check . > /tmp/_polaris_ruff.out 2>&1; then
    echo "  ✓ ruff: no pyflakes findings"
  else
    echo "  ✗ ruff: $(grep -c '^' /tmp/_polaris_ruff.out) line(s) —"
    head -12 /tmp/_polaris_ruff.out | sed 's/^/    /'
    fails=$((fails+1))
  fi
else
  # v9.430: a gate failure, not a note. This block has said since v9.382 that a silent
  # preflight is how READY stops meaning anything, and then printed a note and printed
  # READY anyway. v9.429 shipped an unused import that way: preflight said it had linted
  # nothing, I read READY, and CI failed on the first step of the product job. The waiver
  # is the same shape as the drills one, for the same reason: a skip that is chosen and
  # visible is a decision, a skip that is silent is this bug again.
  echo "  ✗ ruff is not installed here, so NOTHING linted this tree. CI lints FIRST and"
  echo "    fails the whole product-test job before any test runs: 'pip install ruff'"
  if [ "${POLARIS_LINT_WAIVED:-0}" = "1" ]; then
    echo "  ! WAIVED by POLARIS_LINT_WAIVED=1: this tree is unlinted"
  else
    fails=$((fails+1))
  fi
fi

# 3. TypeScript SDK â the offline steps of CI's sdk-typescript job, when node
#    is present. `tsc --noEmit` is a TYPE gate the Python check layer cannot
#    see: a type-only regression (v9.315's verifyCrossAuthority) passed
#    polaris-checks, `node --test` and conformance yet turned CI red at v9.316.
#    Run them here so the failure surfaces locally, guarded so a node-less box
#    still runs the rest of the gate.
TS="${ROOT}/sdk/typescript"
if command -v node > /dev/null 2>&1 && [ -d "${TS}/node_modules" ]; then
  ts_fail=0
  ( cd "${TS}" && npx --no-install tsc --noEmit ) > /tmp/_polaris_ts.out 2>&1 || ts_fail=1
  ( cd "${TS}" && node --test ) >> /tmp/_polaris_ts.out 2>&1 || ts_fail=1
  ( cd "${ROOT}" && python3 conformance/run_conformance.py       --verifier "node sdk/typescript/src/conformance.ts" ) >> /tmp/_polaris_ts.out 2>&1 || ts_fail=1
  if [ "${ts_fail}" -eq 0 ]; then
    echo "  ✓ sdk-typescript: tsc --noEmit, node --test, conformance all pass"
  else
    echo "  ✗ sdk-typescript: failures —"
    tail -8 /tmp/_polaris_ts.out | sed 's/^/    /'
    fails=$((fails+1))
  fi
else
  echo "  · sdk-typescript: SKIP (node or sdk/typescript/node_modules absent)"
fi

# 4. The plan (v9.345): the verification this change needs, from the paths that
#    moved since the last tag and the drills that mention a changed route handler.
#    Informational; it skips itself where no tag is reachable (shallow clones).
( cd "${ROOT}" && python3 scripts/polaris-ship.py plan ) 2>&1 | sed 's/^/  /'

# 4b. The drills the plan names, made binding (v9.428).
#
#     Step 4 above has printed a verification plan since v9.345 under the word
#     "Informational", and step 2b already says what that costs: "a preflight that
#     stays silent about what it did not check is how READY stops meaning anything."
#     A list printed and not acted on is the same silence with extra words. v9.424,
#     v9.425 and v9.426 each altered a table that scripts/polaris-abuse-drill.sh
#     writes; two of those runs went red on that drill, and this gate said READY all
#     three times.
#
#     `drills --check` names every drill that exercises a schema object THIS ship
#     altered and has not been run against the tree as it now stands. Non-empty is a
#     gate failure. POLARIS_DRILLS_WAIVED=1 gets past it and says so in the output,
#     because some drills need Docker, an HSM or a cluster; a waiver that is visible
#     is a decision, a waiver that is silent is this bug again.
echo
echo "── drills this change needs ──"
if drill_out="$( cd "${ROOT}" && python3 scripts/polaris-ship.py drills --check 2>&1 )"; then
  echo "  ✓ every drill this change needs has run against this tree"
else
  echo "$drill_out" | sed 's/^/  /'
  if [ "${POLARIS_DRILLS_WAIVED:-0}" = "1" ]; then
    echo "  ! WAIVED by POLARIS_DRILLS_WAIVED=1: the drills above did not run"
  else
    echo "    run them: python3 scripts/polaris-ship.py drills --run"
    echo "    or waive deliberately: POLARIS_DRILLS_WAIVED=1 (the waiver is printed)"
    fails=$((fails+1))
  fi
fi

# 5. Reminder for the DB-backed product suites (need Postgres + the venv).
echo "  · DB suites: 'python3 scripts/polaris-ship.py run' (test_app, test_check_constraints,"
echo "    test_invariants_property, test_redaction_property sharded; about two minutes);"
echo "    test_cli runs from polaris_cli/ and rides along in CI via polaris-coverage.sh"

echo
if [ "$fails" -eq 0 ]; then
  echo "── READY ──"
  exit 0
fi
echo "── ${fails} gate failure(s) ──"
[ "$STRICT" -eq 1 ] && exit 1
exit 0
