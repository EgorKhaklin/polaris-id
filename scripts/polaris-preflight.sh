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

# 1b. The same two checks, against the tree AS CI WILL SEE IT.
#
# Three times in one session the local gate said READY on a tree CI then rejected, every
# time because this working directory holds files a fresh checkout does not: an untracked
# lab/ that check_system_map only counts once tracked, and a built sdk/typescript/dist/
# that made a link resolve. A gate whose verdict depends on what happens to be lying
# around does not predict anything.
#
# `git archive` writes exactly what is committed, so this is the checkout CI performs.
# Untracked and ignored files are absent by construction, which is the whole point.
if command -v git >/dev/null 2>&1 && git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  _pristine="$(mktemp -d)"
  # The INDEX, not HEAD: staged work is what is about to be committed, and a gate that
  # ignored it would report on the previous commit while you fix the current one.
  # Untracked files are still absent, which is the property being tested.
  _tree="$(git -C "$ROOT" write-tree 2>/dev/null || echo HEAD)"
  if git -C "$ROOT" archive "$_tree" 2>/dev/null | tar -x -C "$_pristine" 2>/dev/null; then
    # The EXPORT's own scripts, not this working tree's. Running the local link checker
    # against the export would mix a fixed checker with committed content and report a
    # pass that neither tree would produce -- which is exactly what it did the first time.
    if (cd "$_pristine" && python3 -m polaris_checks.run > /tmp/_polaris_pristine.out 2>&1 \
        && bash "$_pristine/scripts/polaris-link-check.sh" --ci >> /tmp/_polaris_pristine.out 2>&1); then
      echo "  ✓ pristine checkout: the same gate passes on what is actually committed"
    else
      echo "  ✗ pristine checkout: passes here, fails on a fresh clone —"
      { grep '✗' /tmp/_polaris_pristine.out; grep -A 4 '^BROKEN' /tmp/_polaris_pristine.out; } \
        | head -8 | sed 's/^/    /'
      echo "    (untracked files are invisible to this on purpose: git add them, then re-run)"
      fails=$((fails+1))
    fi
  fi
  rm -rf "$_pristine"
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
#     v9.451: it also has to look where ruff actually is. `pip install ruff` into an
#     environment whose scripts directory is not on PATH leaves `python3 -m ruff` working
#     and `command -v ruff` empty, and this gate then announced that NOTHING linted a tree
#     that lints clean. A gate that cannot find an installed tool reports the same thing as
#     a missing one, which is the failure it was written to prevent, one level up.
RUFF=""
if command -v ruff > /dev/null 2>&1; then
  RUFF="ruff"
elif python3 -m ruff --version > /dev/null 2>&1; then
  RUFF="python3 -m ruff"
fi
if [ -n "$RUFF" ]; then
  if $RUFF check . > /tmp/_polaris_ruff.out 2>&1; then
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
  echo "  ✗ ruff is not installed here (neither on PATH nor as 'python3 -m ruff'), so"
  echo "    NOTHING linted this tree. CI lints FIRST and fails the whole product-test job"
  echo "    before any test runs: 'pip install ruff'"
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

# 3b. The standalone packages' own suites. None of these needs a database, a network,
#     Redis or ML-DSA: they run in under two seconds on the plain interpreter, so there
#     is no reason for a break in one to be discovered in CI rather than here.
#
#     2026-09-17 is why this stage exists. A refusal note in `grant_within_limits` was
#     widened from "not a number" to "not a finite number"; `sdk/python/test_sdk.py`
#     held the old phrase; the gate reported READY because nothing local ran that file,
#     and CI went red on a commit the gate had passed. `check_local_gate_covers_ci` was
#     supposed to prevent exactly this and did not, because it compared the ship tool
#     against `polaris-coverage.sh` rather than against the workflow that gates the push.
#     That check now reads ci.yml; this stage is the other half, because a suite the ship
#     tool merely NAMES is not a suite anything runs.
pkg_fail=0
: > /tmp/_polaris_pkg.out
( cd "${ROOT}/sdk/python" && python3 -m unittest test_sdk ) >> /tmp/_polaris_pkg.out 2>&1 || pkg_fail=1
( cd "${ROOT}/scripts" && python3 -m unittest test_verify_p9 ) >> /tmp/_polaris_pkg.out 2>&1 || pkg_fail=1
( cd "${ROOT}/packages/polaris-oid4vp" && python3 -m unittest \
    test_sdjwt test_jwe test_verifier test_serve test_cli test_conformance_capture ) \
    >> /tmp/_polaris_pkg.out 2>&1 || pkg_fail=1
if [ "${pkg_fail}" -eq 0 ]; then
  echo "  ✓ packages: sdk-python, detached verifier (p9) and all six polaris-oid4vp suites pass"
else
  echo "  ✗ packages: failures —"
  tail -12 /tmp/_polaris_pkg.out | sed 's/^/    /'
  fails=$((fails+1))
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
#    Both halves, deliberately. Until v9.442 this named only the four sharded ones, which
#    read like the whole product suite and are not: v9.440 passed them and broke
#    polaris_sim.test_sim in CI, twice. check_local_gate_covers_ci binds this list to the
#    one polaris-coverage.sh actually runs.
echo "  · DB suites: 'python3 scripts/polaris-ship.py run'. It shards test_app,"
echo "    test_check_constraints, test_invariants_property and test_redaction_property,"
echo "    then runs every unsharded suite CI runs (polaris_web, polaris_cli, scripts,"
echo "    polaris_sim, the e2e and card suites, the ZK second witness) against one of the"
echo "    loaded databases. About four minutes. --no-unsharded skips that second half."
echo "    Until 2026-09-18 it only NAMED those, and a commit whose gate said READY went"
echo "    red in CI on a file none of the sharded modules imports."

echo
if [ "$fails" -eq 0 ]; then
  echo "── READY ──"
  exit 0
fi
echo "── ${fails} gate failure(s) ──"
[ "$STRICT" -eq 1 ] && exit 1
exit 0
