#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Verify a Polaris-issued wallet copy with the reference `sd-jwt` library. No Polaris code here.

    verify.py <work_dir>

Runs in a venv that holds only the reference implementation (`sd-jwt`, by the SD-JWT spec editor)
and its dependencies: nothing from this repository is importable. It reads <work_dir>/copy.txt
and the test anchor, and:

  1. GENUINE: the library must accept the copy, chain the `x5c` leaf to the registered anchor,
     and return every disclosed claim.
  2. CONTROL, tampered signature: one byte of the issuer signature is flipped; the library must
     refuse it. A verifier that accepts everything proves nothing.
  3. CONTROL, forged disclosure: a disclosed value is changed; its SHA-256 no longer matches the
     `_sd` digest, so the library must not report the forged value.

Exit 0 only if 1 accepted and 2 and 3 both held.
"""
import base64
import json
import sys

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto import jwk
from sd_jwt.verifier import SDJWTVerifier

work = sys.argv[1]
copy = open(work + "/copy.txt").read()
anchor = x509.load_pem_x509_certificate(open(work + "/keys/7.anchor.pem", "rb").read())
chain_checked = {}


def issuer_key(issuer, header):
    """HAIP: the issuer key is `x5c[0]`, and the leaf must chain to the registered anchor."""
    leaf = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][0]))
    anchor.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes,
                               ec.ECDSA(leaf.signature_hash_algorithm))
    chain_checked["ok"] = True
    return jwk.JWK.from_pyca(leaf.public_key())


def b64u_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def verify(doc):
    return SDJWTVerifier(doc, issuer_key).get_verified_payload()


ok = True

print("1. GENUINE copy, verified by the reference sd-jwt library")
try:
    payload = verify(copy)
    disclosed = {k: payload[k] for k in
                 ("legal_name", "birthdate", "age_over_18", "age_over_21", "jurisdiction")
                 if k in payload}
    if chain_checked.get("ok") and len(disclosed) == 5 and payload.get("vct"):
        print("   ok    accepted; leaf chained to the test anchor; claims %s" % json.dumps(disclosed))
    else:
        ok = False
        print("   FAIL  accepted but incomplete: chain=%s claims=%s" % (chain_checked, disclosed))
except Exception as exc:
    ok = False
    print("   FAIL  the genuine copy was refused: %s: %s" % (type(exc).__name__, exc))

print("2. CONTROL: the issuer signature, one byte flipped")
head, rest = copy.split("~", 1)
jws_head, sig = head.rsplit(".", 1)
bad = bytearray(b64u_decode(sig))
bad[-1] ^= 0x01
tampered = "%s.%s~%s" % (jws_head, base64.urlsafe_b64encode(bytes(bad)).rstrip(b"=").decode(), rest)
try:
    verify(tampered)
    ok = False
    print("   FAIL  the tampered copy was accepted")
except Exception as exc:
    print("   ok    refused: %s" % type(exc).__name__)

print("3. CONTROL: a disclosed value forged (age_over_18 flipped)")
parts = copy.split("~")
forged = []
for d in [p for p in parts[1:] if p]:
    arr = json.loads(b64u_decode(d))
    if arr[1] == "age_over_18":
        arr[2] = not arr[2]
        d = base64.urlsafe_b64encode(json.dumps(arr).encode()).rstrip(b"=").decode()
    forged.append(d)
forged_doc = parts[0] + "~" + "".join(x + "~" for x in forged)
try:
    got = verify(forged_doc).get("age_over_18")
    if got is True or got is None:   # original kept, or digest-mismatched disclosure dropped
        print("   ok    the forged value was not honored (age_over_18=%r)" % got)
    else:
        ok = False
        print("   FAIL  the forged value was accepted (age_over_18=%r)" % got)
except Exception as exc:
    print("   ok    refused: %s" % type(exc).__name__)

print("\nPASS" if ok else "\nFAIL")
sys.exit(0 if ok else 1)
