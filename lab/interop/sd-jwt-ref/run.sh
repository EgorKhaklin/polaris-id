#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# sd-jwt-ref: the REVERSE of the other interop walks. Those are outside WALLETS presenting to the
# Polaris verifier; this is an outside VERIFIER (the reference `sd-jwt` library, by the SD-JWT
# spec editor) checking a credential the PRODUCT issued. It answers one question the top-level
# README left open for the wallet COPY: can a credential Polaris signs be verified by code that
# holds none of this repository? For the ML-DSA-65 core credential the answer is no (HAIP's floor
# is ES256). The OpenID4VCI wallet copy is a classical ES256 SD-JWT VC, and this walk measures it.
#
#   lab/interop/sd-jwt-ref/run.sh                 # default
#   WORK=/path SDJWT_VERSION=0.10.4 lab/interop/sd-jwt-ref/run.sh
#
# What it does, in order:
#   1. a venv with `cryptography`, for the test PKI and the product's issuer code;
#   2. a TEST agency ES256 chain (scripts/polaris-credential-copy-test-pki.py); the CA private key
#      is never written, so this CA can issue nothing else;
#   3. mint ONE wallet copy with polaris_web/wallet_copy.py:build_copy, the function the OpenID4VCI
#      endpoint calls (mint.py);
#   4. a SEPARATE clean-room venv holding only `sd-jwt` and its dependencies, no Polaris code;
#   5. verify the copy there, with two controls that must be refused (verify.py).
#
# Exit 0 only if the genuine copy is accepted AND the tampered signature and the forged disclosure
# are both refused. A verifier that accepts everything prints the same success line. LAB CODE: a
# TEST CA, notional claims, a scratch directory; never a deployment.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="${WORK:-$(mktemp -d -t polaris-sdjwt-ref.XXXXXX)}"
SDJWT_VERSION="${SDJWT_VERSION:-0.10.4}"

echo ">> work dir   $WORK"
echo ">> issuer     polaris_web/wallet_copy.py build_copy (the product), a TEST agency ES256 chain"
echo ">> verifier   sd-jwt==$SDJWT_VERSION (reference implementation), a clean venv with no Polaris code"
mkdir -p "$WORK/keys"

echo ">> preparing the issuer side"
python3 -m venv "$WORK/mint-venv"
"$WORK/mint-venv/bin/pip" install -q --disable-pip-version-check cryptography >/dev/null
"$WORK/mint-venv/bin/python" "$ROOT/scripts/polaris-credential-copy-test-pki.py" \
    --agency 7 --issuer-url https://polaris.test/api/v1/oid4vci/7 --out "$WORK/keys" >/dev/null
"$WORK/mint-venv/bin/python" "$HERE/mint.py" "$ROOT" "$WORK"

echo ">> preparing the verifier side (outside the repository)"
python3 -m venv "$WORK/verify-venv"
"$WORK/verify-venv/bin/pip" install -q --disable-pip-version-check "sd-jwt==$SDJWT_VERSION" >/dev/null

echo ">> verifying"
"$WORK/verify-venv/bin/python" "$HERE/verify.py" "$WORK"
