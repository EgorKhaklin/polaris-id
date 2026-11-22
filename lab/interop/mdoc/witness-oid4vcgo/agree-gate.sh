#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# agree-gate.sh OUT/annexc.jsonl [ROWS]: runs agree.py (beside this script) and passes only when it exits 0,
# prints the line "AGREEMENT TABLE: PASS" exactly once and prints no FAIL line. mdoc-witness.yml runs agree.py
# through it, so neither the exit status nor the printed table alone can pass the step. test_agree.py runs it over
# made-up agree.py outputs.
set -u -o pipefail

here=$(cd "$(dirname "$0")" && pwd) || exit 1
out=$(python -I "$here/agree.py" "$@")
status=$?
printf '%s\n' "$out"
passes=$({ printf '%s\n' "$out" | grep -c -x 'AGREEMENT TABLE: PASS'; } || true)
fails=$({ printf '%s\n' "$out" | grep -c -E '^FAIL |^AGREEMENT TABLE: FAIL$'; } || true)
if [ "$status" -ne 0 ]; then
  echo "agree-gate: FAIL: agree.py exited $status" >&2
  exit 1
fi
if [ "$passes" != 1 ]; then
  echo "agree-gate: FAIL: agree.py printed the line AGREEMENT TABLE: PASS ${passes:-an unknown number of} times, not once" >&2
  exit 1
fi
if [ "$fails" != 0 ]; then
  echo "agree-gate: FAIL: agree.py exited 0 and printed ${fails:-an unknown number of} FAIL lines" >&2
  exit 1
fi
echo "agree-gate: PASS"
