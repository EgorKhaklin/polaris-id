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
  echo "  ! ruff is not installed here, so NOTHING linted this tree. CI lints first"
  echo "    and fails the product-test job before any test runs: 'pip install ruff'"
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
