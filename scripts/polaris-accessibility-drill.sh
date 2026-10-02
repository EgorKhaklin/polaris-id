#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-accessibility-drill.sh — WCAG 2.2 AA audit of every operator surface
# (roadmap P6.5).
#
# Boots the app against an expendable database, installs a PINNED axe-core, and
# drives every operator surface in a real headless Chromium, auditing the
# rendered DOM behind a real login.
#
# The axe pin is deliberate and load-bearing: axe 4.4, which the convenient
# Python wrapper bundles, is from 2022 and predates WCAG 2.2 entirely. Auditing
# with it and reporting "WCAG 2.2 AA" would be a claim about a standard the tool
# has never heard of.
#
#   scripts/polaris-accessibility-drill.sh                      # boots its own app
#   POLARIS_UI_URL=http://host:5077 scripts/polaris-accessibility-drill.sh
# ============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${POLARIS_A11Y_PORT:-5079}"
URL="${POLARIS_UI_URL:-http://127.0.0.1:${PORT}}"
AXE_VERSION="${POLARIS_AXE_VERSION:-4.13.0}"
WORK="$(mktemp -d)"
APP_PID=""

fail() { echo "accessibility drill: $*" >&2; exit 3; }
cleanup() {
    if [[ -n "$APP_PID" ]]; then
        # `wait` after the kill, so bash reaps the job quietly instead of printing a
        # "Terminated" line into the drill's own output after its verdict.
        kill "$APP_PID" 2>/dev/null || true
        wait "$APP_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

command -v npm >/dev/null || fail "needs npm to install the pinned axe-core"
# axe-core@${AXE_VERSION} comes from scripts/accessibility's lockfile, which pins it by integrity
# hash; `npm ci` installs exactly that and nothing else.
AXE_DIR="$ROOT/scripts/accessibility"
if [[ ! -f "$AXE_DIR/node_modules/axe-core/axe.min.js" ]]; then
    ( cd "$AXE_DIR" && npm ci --silent --ignore-scripts ) \
        || fail "could not install axe-core@${AXE_VERSION} from scripts/accessibility/package-lock.json"
fi
AXE_GOT=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['version'])" "$AXE_DIR/node_modules/axe-core/package.json")
[[ "$AXE_GOT" == "$AXE_VERSION" ]] \
    || fail "the lockfile installs axe-core@${AXE_GOT}, not axe-core@${AXE_VERSION}: update one to match the other"
export POLARIS_AXE_JS="$AXE_DIR/node_modules/axe-core/axe.min.js"

PW_PY="${POLARIS_UI_PYTHON:-$(command -v python3.12 || command -v python3)}"
"$PW_PY" -c 'import playwright' 2>/dev/null || fail "the python ($PW_PY) lacks playwright"

if [[ -z "${POLARIS_UI_URL:-}" ]]; then
    APP_PY="${POLARIS_TEST_PYTHON:-$(command -v python3.12 || command -v python3)}"
    "$APP_PY" -c 'import flask, psycopg2' 2>/dev/null \
        || fail "the app python ($APP_PY) lacks flask/psycopg2; set POLARIS_TEST_PYTHON"
    # The port must be free, and the app the drill boots must be the one it audits: a server
    # already on the port answers in its place, as one did for scripts/polaris-ui-drill.sh on
    # 2026-10-02. exec, so APP_PID is the app's own PID and the cleanup stops it.
    if curl -s -o /dev/null --max-time 2 "$URL/"; then
        fail "something already answers on :$PORT; stop it or set POLARIS_A11Y_PORT to a free port"
    fi
    ( cd "$ROOT/polaris_web" && \
      exec env POLARIS_DEMO_MODE=1 \
      POLARIS_SECRET_KEY="$("$APP_PY" -c 'import secrets;print(secrets.token_hex(32))')" \
      POLARIS_DB_HOST="${POLARIS_DB_HOST:-localhost}" \
      POLARIS_DB_NAME="${POLARIS_DB_NAME:-polaris_test}" \
      POLARIS_DB_USER="${POLARIS_DB_USER:-$(whoami)}" \
      POLARIS_DB_PASSWORD="${POLARIS_DB_PASSWORD:-}" \
      POLARIS_STATE_DIR="$WORK/state" \
      "$APP_PY" -m flask --app app run --port "$PORT" --no-reload >"$WORK/app.log" 2>&1 ) &
    APP_PID=$!
    for _ in $(seq 1 40); do
        curl -fsS "$URL/login" >/dev/null 2>&1 && break
        sleep 0.5
    done
    curl -fsS "$URL/login" >/dev/null 2>&1 || { sed -n '1,40p' "$WORK/app.log" >&2; fail "the app did not come up"; }
    kill -0 "$APP_PID" 2>/dev/null || fail "the app the drill booted has exited; something else answers on :$PORT"
fi

POLARIS_UI_URL="$URL" \
    POLARIS_UI_USER="${POLARIS_UI_USER:-admin}" \
    POLARIS_UI_PASS="${POLARIS_UI_PASS:-Admin@123!}" \
    "$PW_PY" "$ROOT/scripts/polaris-accessibility-drill.py"
