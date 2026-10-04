#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# Token Status Lists made outside Polaris, decided by polaris-oid4vp: the IETF draft's test
# vectors and its signed example (checked with the example key the draft's authors publish), and
# tokens signed with the OpenWallet Foundation's @sd-jwt/jwt-status-list. Then the controls.
#
#   lab/interop/status-list/run.sh                                         # the newest release
#   POLARIS_OID4VP=packages/polaris-oid4vp lab/interop/status-list/run.sh  # the tree
#
# Needs Python 3, Node 20 or newer with npm, and the network for two downloads pinned by SHA-256.
# Exits 0 only if every status matches and every control is refused.
set -euo pipefail

PKG="${POLARIS_OID4VP:-polaris-oid4vp}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$(mktemp -d)}"
PY="${PYTHON:-python3}"
DRAFT=https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.txt
DRAFT_SHA256=21e4867a01f73cee2ebc1408d150c87f77898c3d1549ebc25c80fa352221f846
# The draft authors' example generator; the example key (kid 12) is in it.
UTIL=https://raw.githubusercontent.com/oauth-wg/draft-ietf-oauth-status-list/6a7502f1d9cc7046ee23c2457d9e36d86ae57d97/src/util.py
UTIL_SHA256=5c6289767229b5ac4172e01a8a5e0c9d67b7620975b380df35158d726319e29d

command -v node >/dev/null 2>&1 || { echo "the OpenWallet Foundation tokens are minted with Node: install Node 20 or newer" >&2; exit 2; }
[ -e "$PKG" ] && PKG="$(cd "$PKG" && pwd)"

echo "work dir   $WORK"
echo "verifier   pip install --pre $PKG"
mkdir -p "$WORK" && cd "$WORK"
"$PY" -m venv venv
venv/bin/pip install -q --require-hashes -r "$HERE/../requirements.txt"
if [ -e "$PKG" ]; then
  venv/bin/python -c 'import sys; sys.exit(sys.version_info < (3, 10))' || {
    echo "building $PKG from the tree needs Python 3.10 or newer; set PYTHON to one" >&2; exit 2; }
  venv/bin/pip install -q --require-hashes -r "$HERE/../requirements-build.txt"
fi
venv/bin/pip wheel -q --pre --no-deps --no-build-isolation -w wheel "$PKG"
venv/bin/pip install -q --no-deps wheel/*.whl
echo "installed  polaris-oid4vp $(venv/bin/python -c 'import importlib.metadata as m; print(m.version("polaris-oid4vp"))')"

fetch() {
  curl -fsSL "$1" -o "$2"
  echo "$3  $2" | shasum -a 256 -c - >/dev/null || { echo "$2 does not match its pinned SHA-256" >&2; exit 2; }
}
fetch "$DRAFT" draft.txt "$DRAFT_SHA256"
fetch "$UTIL" util.py "$UTIL_SHA256"

rm -rf owf && cp -R "$HERE/owf" owf
(cd owf && npm ci --ignore-scripts --no-audit --no-fund --silent)
echo "minted     with @sd-jwt/jwt-status-list $(node -p 'require("./owf/node_modules/@sd-jwt/jwt-status-list/package.json").version')"
node owf/mint.mjs > owf.json
venv/bin/python "$HERE/decide.py" draft.txt util.py owf.json
