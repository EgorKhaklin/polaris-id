#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-ui-drill.sh — headless-browser UI verification (roadmap P2.14 S4, v9.262)
#
# Boots the app with the live-simulation mode on, then drives the REAL Atlas in
# a bundled headless Chromium (Playwright) and asserts the console actually
# streams — the sim counter climbs AND the Overview aggregate grows — capturing
# screenshots as evidence. This is the instrument that lets a UI ship be watched
# running, not just have its endpoints tested; it is what caught the live-sim
# aggregate-cache lag that v9.262 fixed.
#
#   scripts/polaris-ui-drill.sh                 # boots its own app, runs the drill
#   POLARIS_UI_URL=https://host scripts/polaris-ui-drill.sh   # against a running app
#
# Playwright + Chromium are installed on demand into a throwaway venv (like the
# PKCS#11 drill installs Kryoptic), so this needs no standing dependency. The app
# is booted with the SAME env the DB test suites use (POLARIS_DB_*), pointed at
# an expendable database — SIM_MODE is dev/demo only and never runs in production.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
PORT="${POLARIS_UI_PORT:-5077}"
URL="${POLARIS_UI_URL:-http://127.0.0.1:${PORT}}"
OUT="${POLARIS_UI_OUT:-${ROOT}/ui-drill-out}"
WORK="$(mktemp -d)"
APP_PID=""
fail() { echo "::error::$*" >&2; exit 1; }
cleanup() {
    if [[ -n "$APP_PID" ]]; then kill "$APP_PID" 2>/dev/null || true; wait "$APP_PID" 2>/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT

# --- a Python with Playwright (install on demand) ---------------------------
PW_PY="${POLARIS_UI_PYTHON:-}"
if [[ -z "$PW_PY" ]]; then
    python3 -m venv "$WORK/pw"
    PW_PY="$WORK/pw/bin/python"
    echo "== installing Playwright + Chromium (on demand) =="
    "$PW_PY" -m pip install -q --disable-pip-version-check playwright
    "$PW_PY" -m playwright install chromium
fi
"$PW_PY" -c "import playwright" 2>/dev/null || fail "Playwright is not importable in $PW_PY"

# --- boot the app (unless a URL was supplied) -------------------------------
if [[ -z "${POLARIS_UI_URL:-}" ]]; then
    APP_PY="${POLARIS_TEST_PYTHON:-$(command -v python3.12 || command -v python3)}"
    "$APP_PY" -c "import flask, psycopg2" 2>/dev/null \
        || fail "the app venv ($APP_PY) lacks flask/psycopg2; set POLARIS_TEST_PYTHON"
    echo "== booting the app on :$PORT with SIM_MODE on =="
    ( cd "$ROOT/polaris_web" && \
      POLARIS_SIM_MODE=1 POLARIS_DEMO_MODE=1 \
      POLARIS_SECRET_KEY="$("$APP_PY" -c 'import secrets;print(secrets.token_hex(32))')" \
      POLARIS_DB_HOST="${POLARIS_DB_HOST:-localhost}" \
      POLARIS_DB_NAME="${POLARIS_DB_NAME:-polaris_test}" \
      POLARIS_DB_USER="${POLARIS_DB_USER:-$(whoami)}" \
      POLARIS_DB_PASSWORD="${POLARIS_DB_PASSWORD:-}" \
      "$APP_PY" -m flask --app app run --port "$PORT" --no-reload >"$WORK/app.log" 2>&1 ) &
    APP_PID=$!
    for _ in $(seq 1 30); do
        curl -s -o /dev/null "$URL/api/health/live" && break || sleep 1
    done
    curl -sf -o /dev/null "$URL/api/health/live" \
        || { sed 's/^/    app: /' "$WORK/app.log" >&2; fail "the app did not come up on :$PORT"; }
fi

# --- run the drill ----------------------------------------------------------
echo "== driving the Atlas live-simulation mode in headless Chromium =="
POLARIS_UI_URL="$URL" POLARIS_UI_OUT="$OUT" \
    POLARIS_UI_USER="${POLARIS_UI_USER:-admin}" \
    POLARIS_UI_PASS="${POLARIS_UI_PASS:-Admin@123!}" \
    "$PW_PY" "$SCRIPT_DIR/polaris-ui-drill.py"

echo "== UI DRILL PASSED: the live simulation streams and the Atlas updates live =="
echo "   screenshots: $OUT/"
