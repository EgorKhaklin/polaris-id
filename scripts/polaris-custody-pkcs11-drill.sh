#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-custody-pkcs11-drill.sh — prove the PKCS#11 custody driver against a
# REAL PKCS#11 v3.2 token with ML-DSA (roadmap P1.2). Runs INSIDE a Fedora 43
# container (Kryoptic is packaged there); the CI job custody-pkcs11 and a local
# run invoke it the same way:
#
#   docker run --rm -v "$PWD:/src:ro" -e POLARIS_CUSTODY_PKCS11_REQUIRE=1 \
#       fedora@sha256:<pinned> bash /src/scripts/polaris-custody-pkcs11-drill.sh
#
# What it does: installs Kryoptic + python-pkcs11 + cryptography + liboqs-python
# (liboqs built from source; on Fedora the build lands in lib64 and the binding
# needs the lib symlink + OQS_INSTALL_PATH, found by running this), initialises
# a token, then runs test_custody.Pkcs11CustodyTests: the ML-DSA-65 key is
# generated IN the token (non-extractable), CKM_ML_DSA signatures are verified
# by BOTH witnesses (liboqs and OpenSSL), a forged message is rejected, a
# duplicate label is refused, and pqc_signing routes through the driver by env.
#
# It lives in a file rather than a `bash -c '...'` block in ci.yml because the
# first CI run died on an apostrophe in a comment ending the quoted string, so
# `dnf` ran on the Ubuntu host. Quoting is not a place to be clever.
# ============================================================================
set -eo pipefail

[ -f /src/polaris_web/custody.py ] || { echo "run me inside the container with the repo mounted at /src" >&2; exit 2; }

echo "== packages (Fedora) =="
dnf -y -q install kryoptic python3 python3-pip python3-devel gcc cmake ninja-build git openssl-devel opensc >/dev/null
rpm -q kryoptic
pip -q install "$(grep -E '^python-pkcs11==' /src/polaris_web/requirements-custody.txt)" \
    "$(grep -E '^cryptography==' /src/polaris_web/requirements.txt)" liboqs-python 2>&1 | grep -v WARNING || true

echo "== liboqs (built by the binding on first import; Fedora installs it under lib64) =="
python3 -c "import oqs" >/dev/null 2>&1 || true
[ -e /root/_oqs/lib ] || ln -s /root/_oqs/lib64 /root/_oqs/lib
export OQS_INSTALL_PATH=/root/_oqs
python3 -c "import io,sys; _s=sys.stdout; sys.stdout=io.StringIO(); import oqs; sys.stdout=_s; print('liboqs', oqs.oqs_version(), 'loaded: both witnesses present')"

echo "== token =="
MOD=/usr/lib64/pkcs11/libkryoptic_pkcs11.so
export KRYOPTIC_CONF=/tmp/kryoptic.sql
pkcs11-tool --module "$MOD" --init-token --label polaris --so-pin 12345678 >/dev/null
pkcs11-tool --module "$MOD" --login --so-pin 12345678 --init-pin --pin 1234 >/dev/null
echo 1234 > /tmp/pin && chmod 0600 /tmp/pin
echo "  kryoptic token 'polaris' initialised"

echo "== Pkcs11CustodyTests =="
cp -r /src/polaris_web /work && cd /work
export POLARIS_CUSTODY_PKCS11_MODULE="$MOD" POLARIS_CUSTODY_PKCS11_PIN_FILE=/tmp/pin
export POLARIS_CUSTODY_PKCS11_REQUIRE="${POLARIS_CUSTODY_PKCS11_REQUIRE:-1}"
python3 -m unittest test_custody.Pkcs11CustodyTests -v 2>&1 | grep -vE "faulthandler|from oqs|liboqs version"
echo "== PKCS#11 CUSTODY DRILL PASSED =="
