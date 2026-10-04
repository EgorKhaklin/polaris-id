#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# Credo presents to the PUBLISHED polaris-oid4vp, then the four controls, as one command.
#
# A fresh venv with polaris-oid4vp from PyPI (its dependencies by hash), Credo from the lock file
# (`npm ci`), then `npm run present` once and once per control. Each run's evidence goes under
# $WORK/evidence, never over the runs recorded in evidence/.
#
#   lab/interop/credo/run.sh                         # the pinned Credo (package.json)
#   CREDO_VERSION=0.7.2 lab/interop/credo/run.sh     # another release, installed without saving
#   CREDO_VERSION=latest lab/interop/credo/run.sh    # the newest release
#
# Exits 0 only if the presentation is accepted AND every control is refused.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PKG="${POLARIS_OID4VP:-polaris-oid4vp}"
WORK="${WORK:-$(mktemp -d)}"
PY="${PYTHON:-python3}"
export PORT="${PORT:-9543}"

echo "work dir   $WORK"
echo "verifier   pip install --pre $PKG"
mkdir -p "$WORK"
"$PY" -m venv "$WORK/venv"
"$WORK/venv/bin/pip" install -q --require-hashes -r "$HERE/../requirements.txt"
if [ -e "$PKG" ]; then
  "$WORK/venv/bin/python" -c 'import sys; sys.exit(sys.version_info < (3, 10))' || {
    echo "building $PKG from the tree needs Python 3.10 or newer; set PYTHON to one" >&2; exit 2; }
  "$WORK/venv/bin/pip" install -q --require-hashes -r "$HERE/../requirements-build.txt"
fi
"$WORK/venv/bin/pip" wheel -q --pre --no-deps --no-build-isolation -w "$WORK/wheel" "$PKG"
"$WORK/venv/bin/pip" install -q --no-deps "$WORK"/wheel/*.whl

cd "$HERE"
npm ci --no-audit --no-fund --loglevel=error
if [ -n "${CREDO_VERSION:-}" ]; then
  # Another release in place of the pinned one, without touching package.json or the lock; the
  # pinned install comes back at the end.
  trap 'npm ci --no-audit --no-fund --loglevel=error >/dev/null 2>&1 || true' EXIT
  npm install --no-save --no-audit --no-fund --loglevel=error \
    "@credo-ts/core@$CREDO_VERSION" "@credo-ts/node@$CREDO_VERSION" "@credo-ts/openid4vc@$CREDO_VERSION"
fi
echo "wallet     @credo-ts/core $(node -p "require('./node_modules/@credo-ts/core/package.json').version")"

fail=0
for control in "" wrong-issuer foreign-holder replay untrusted-verifier; do
  echo "== ${control:-the presentation}"
  if CONTROL="$control" EVIDENCE_DIR="$WORK/evidence" PATH="$WORK/venv/bin:$PATH" \
       PYTHON="$WORK/venv/bin/python" npm run --silent present > "$WORK/${control:-positive}.log" 2>&1; then
    grep -E '^(RESULT|CONTROL)' "$WORK/${control:-positive}.log" | sed 's/^/  ok    /'
  else
    echo "  FAIL  ${control:-the presentation} (see $WORK/${control:-positive}.log)"
    fail=1
  fi
done
[ "$fail" -eq 0 ] && echo "RESULT: accepted, and all four controls refused" || echo "RESULT: FAILED"
exit "$fail"
