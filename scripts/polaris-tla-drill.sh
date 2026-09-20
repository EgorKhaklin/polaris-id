#!/usr/bin/env bash
# ============================================================================
# polaris-tla-drill.sh — model-check every TLA+ spec (roadmap P6.7).
#
# Fetches a PINNED tla2tools into .tla/ (gitignored) and runs the drill. The
# pin matters for the same reason the axe-core pin does: an unpinned checker is
# one whose semantics can change under the claim it is being used to support.
#
#   scripts/polaris-tla-drill.sh
#   POLARIS_JAVA=/path/to/java scripts/polaris-tla-drill.sh
# ============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TLA_VERSION="${POLARIS_TLA_VERSION:-v1.7.4}"
JAR="${POLARIS_TLA_JAR:-$ROOT/.tla/tla2tools.jar}"
JAVA="${POLARIS_JAVA:-java}"

if ! command -v "$JAVA" >/dev/null 2>&1 || ! "$JAVA" -version >/dev/null 2>&1; then
    for candidate in /opt/homebrew/opt/openjdk/bin/java /usr/lib/jvm/default-java/bin/java; do
        [[ -x "$candidate" ]] && { JAVA="$candidate"; break; }
    done
fi
"$JAVA" -version >/dev/null 2>&1 || { echo "tla drill needs a Java runtime" >&2; exit 3; }

# The fetch retries, and never leaves a half-downloaded jar behind.
#
# 2026-09-20: a single `curl -sSL` here timed out against github.com after 135 seconds and
# the whole formal-specs step exited 3, on a commit whose diff was one docstring.
# polaris_web/Dockerfile.caddy already retries its module fetch for exactly this reason; this
# one did not, so the same class of interruption was a red build rather than a slow one.
#
# The partial file is the worse half and it is silent. `curl -o` writes as bytes arrive, so a
# timeout leaves a truncated jar: measured, 4096 of 1000000 bytes, under the same curl exit 28
# the CI failure printed. CI never notices because the runner is fresh, but on a developer
# machine the `-f "$JAR"` test above is then TRUE, the fetch is skipped for good, and Java is
# handed a corrupt archive on every subsequent run. The failure that surfaces looks like a
# problem with TLA+ rather than a download that stopped early.
#
# So each attempt writes to a temporary file, is checked for the zip magic every jar starts
# with, and is only moved into place once it is whole.
if [[ ! -f "$JAR" ]]; then
    mkdir -p "$(dirname "$JAR")"
    _tla_url="https://github.com/tlaplus/tlaplus/releases/download/${TLA_VERSION}/tla2tools.jar"
    _tla_tmp="$JAR.part"
    for attempt in 1 2 3 4; do
        rm -f "$_tla_tmp"
        if curl -sSL --fail --connect-timeout 15 --max-time 300 -o "$_tla_tmp" "$_tla_url" \
           && [[ -s "$_tla_tmp" ]] \
           && [[ "$(head -c 2 "$_tla_tmp")" == "PK" ]]; then
            mv "$_tla_tmp" "$JAR"
            break
        fi
        rm -f "$_tla_tmp"
        if [[ "$attempt" == 4 ]]; then
            echo "tla drill could not fetch tla2tools ${TLA_VERSION} after 4 attempts" >&2
            exit 3
        fi
        echo "tla2tools fetch attempt $attempt failed (network, or a truncated archive);" \
             "retrying in $((attempt * 10))s" >&2
        sleep $((attempt * 10))
    done
fi

POLARIS_TLA_JAR="$JAR" POLARIS_JAVA="$JAVA" \
    "${POLARIS_TEST_PYTHON:-$(command -v python3.12 || command -v python3)}" \
    "$ROOT/scripts/polaris-tla-drill.py"
