#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# polaris-cli-package-check.sh [WHEEL]: the polaris-id-cli wheel, installed alone into a fresh
# virtual environment outside the repository, runs, reports its own version, and refuses (exit 2,
# naming the clone it needs) the commands that run through the application's modules, instead
# of raising on an import. With no argument it builds the wheel from polaris_cli/ with pip.
# PYTHON must be 3.10 or later, the package's floor.
set -euo pipefail
case "${1:-}" in --help|-h) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;; esac
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python3}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail() { echo "polaris-id-cli package check: FAIL: $1" >&2; exit 1; }

WHEEL="${1:-}"
if [ -z "$WHEEL" ]; then
    "$PY" -m pip wheel --quiet --no-deps --wheel-dir "$WORK/dist" "$ROOT/polaris_cli"
    WHEEL="$(ls "$WORK"/dist/polaris_id_cli-*.whl)"
fi
"$PY" -m venv "$WORK/venv"
"$WORK/venv/bin/python" -m pip install --quiet "$WHEEL"
cd "$WORK"
CLI="$WORK/venv/bin/polaris-id"

want="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/polaris_cli/pyproject.toml")"
got="$("$CLI" --version)"
[ "$got" = "polaris-id $want (polaris-id-cli)" ] || fail "--version printed '$got'"
"$CLI" --help >/dev/null || fail "--help exited non-zero"

refuses() {
    local command="$1"; shift
    local out rc
    set +e
    out="$(POLARIS_DB_HOST=db.invalid "$CLI" "$command" "$@" 2>&1)"
    rc=$?
    set -e
    [ "$rc" = 2 ] || fail "$command exited $rc, not 2: $out"
    case "$out" in *"not in this package"*) ;; *) fail "$command did not say where it runs: $out" ;; esac
    case "$out" in *Traceback*) fail "$command raised: $out" ;; esac
}
refuses issue --legal-name "A. Holder" --dob 1990-01-15 --jurisdiction US-PA --agency 1 \
    --algorithm 1 --token-value TKN-PKG-1 --serial SN-PKG-1 --contexts 1
refuses transparency-report --period 2026-Q3 --since 2026-07-01
echo "polaris-id-cli package check: OK ($got installed alone; issue and transparency-report refuse and say where they run)"
