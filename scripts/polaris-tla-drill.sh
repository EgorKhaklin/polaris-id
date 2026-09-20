#!/usr/bin/env bash
# ============================================================================
# polaris-tla-drill.sh — model-check every TLA+ spec (roadmap P6.7).
#
# Fetches a PINNED tla2tools into .tla/ (gitignored) and runs the drill. The
# pin matters for the same reason the axe-core pin does: an unpinned checker is
# one whose semantics can change under the claim it is being used to support.
# Pinned by version AND by digest, because a release asset can be re-uploaded
# under a fixed tag, and the digest is checked on a cached jar too.
#
#   scripts/polaris-tla-drill.sh
#   POLARIS_JAVA=/path/to/java scripts/polaris-tla-drill.sh
# ============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TLA_VERSION="${POLARIS_TLA_VERSION:-v1.7.4}"
# The bytes, not just the tag. A release asset can be re-uploaded under the same tag, so a
# version pin alone leaves the checker that model-checks the formal specs trusted to TLS and
# nothing else. Twenty images in this tree are pinned by @sha256: and check_prod_images_
# digest_pinned enforces it; this was the one downloaded artifact outside that policy.
#
# Observed twice before it was pinned, which is the whole basis for the value: on this
# machine (fetched 2026-09-10) and on a GitHub runner fetching fresh from the release page
# on 2026-09-20, different networks, byte-identical. That is the same evidence a lockfile
# rests on, not a claim about what upstream canonically publishes.
#
# Changing POLARIS_TLA_VERSION requires changing this too, and a mismatch is meant to stop
# the run: an asset that changed under a fixed tag is exactly what this is here to notice.
TLA_SHA256="${POLARIS_TLA_SHA256:-936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88}"
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
_tla_digest() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        echo "tla drill needs shasum or sha256sum to verify the checker it is about to run" >&2
        exit 3
    fi
}

if [[ ! -f "$JAR" ]]; then
    mkdir -p "$(dirname "$JAR")"
    _tla_url="https://github.com/tlaplus/tlaplus/releases/download/${TLA_VERSION}/tla2tools.jar"
    _tla_tmp="$JAR.part"
    for attempt in 1 2 3 4; do
        rm -f "$_tla_tmp"
        if curl -sSL --fail --connect-timeout 15 --max-time 300 -o "$_tla_tmp" "$_tla_url" \
           && [[ -s "$_tla_tmp" ]] \
           && [[ "$(head -c 2 "$_tla_tmp")" == "PK" ]]; then
            _got="$(_tla_digest "$_tla_tmp")"
            if [[ "$_got" != "$TLA_SHA256" ]]; then
                # Not a retry case. A whole, well-formed archive whose bytes are not the
                # pinned ones is either a re-released asset or something worse, and trying
                # again gets the same answer more slowly.
                rm -f "$_tla_tmp"
                echo "tla drill: tla2tools ${TLA_VERSION} does not match its pinned digest" >&2
                echo "  expected $TLA_SHA256" >&2
                echo "  got      $_got" >&2
                echo "  If the version was deliberately changed, set POLARIS_TLA_SHA256 to" >&2
                echo "  the new digest in the same commit. If it was not, the release asset" >&2
                echo "  changed under a fixed tag and that is worth understanding before" >&2
                echo "  this runs again." >&2
                exit 3
            fi
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

# Verified every run, not only on the run that downloaded it. A jar cached under .tla/ from
# an earlier fetch is exactly as load-bearing as a fresh one and nothing else re-checks it.
_have="$(_tla_digest "$JAR")"
if [[ "$_have" != "$TLA_SHA256" ]]; then
    echo "tla drill: the cached tla2tools does not match its pinned digest" >&2
    echo "  expected $TLA_SHA256" >&2
    echo "  got      $_have  ($JAR)" >&2
    echo "  Remove it and let the drill fetch again, or set POLARIS_TLA_SHA256 if the" >&2
    echo "  pinned version was changed deliberately." >&2
    exit 3
fi
echo "tla2tools ${TLA_VERSION}: sha256 $_have (matches the pin)"

POLARIS_TLA_JAR="$JAR" POLARIS_JAVA="$JAVA" \
    "${POLARIS_TEST_PYTHON:-$(command -v python3.12 || command -v python3)}" \
    "$ROOT/scripts/polaris-tla-drill.py"
