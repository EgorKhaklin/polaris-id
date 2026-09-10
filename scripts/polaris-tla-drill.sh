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

if [[ ! -f "$JAR" ]]; then
    mkdir -p "$(dirname "$JAR")"
    curl -sSL -o "$JAR" \
        "https://github.com/tlaplus/tlaplus/releases/download/${TLA_VERSION}/tla2tools.jar" \
        || { echo "tla drill could not fetch tla2tools ${TLA_VERSION}" >&2; exit 3; }
fi

POLARIS_TLA_JAR="$JAR" POLARIS_JAVA="$JAVA" \
    "${POLARIS_TEST_PYTHON:-$(command -v python3.12 || command -v python3)}" \
    "$ROOT/scripts/polaris-tla-drill.py"
