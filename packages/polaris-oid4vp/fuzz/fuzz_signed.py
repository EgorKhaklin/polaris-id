#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Fuzz what comes AFTER the signature checks, by signing whatever the fuzzer writes.

A mutated presentation almost always fails a signature, so fuzz_presentation mostly explores
refusals that come early. Two parties can sign content of their choosing: the issuer, whose
key the verifier trusts, and the holder, who signs the key binding JWT with a key the issuer
bound. This target signs the fuzzer's bytes as one of them and builds the rest correctly, so
the claim processing, the disclosures and the key binding checks meet hostile content.

The first input byte picks the signer, the rest are the signed JSON bytes:

    0  the issuer payload, with the genuine header, disclosures and key binding
    1  the key binding payload; "$SD_HASH" in it becomes the real sd_hash
    2  the key binding header, over the genuine key binding payload
    3  the genuine issuer payload with one field replaced by a typed value
    4  the genuine key binding payload with one field replaced the same way
    5  the genuine issuer header with one field replaced the same way

The promise is verify_presentation's: a Verdict, never an exception. When the holder signed
the fuzzer's bytes, an accepted presentation must also carry this verifier's nonce and
audience and the right sd_hash, since those are what stop a replay.

    python3 fuzz_signed.py corpus/signed -max_total_time=60
"""
import json
import os
import sys

import atheris

# The package from this tree, not whatever release is installed.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

with atheris.instrument_imports(include=["polaris_oid4vp"]):
    from polaris_oid4vp import sdjwt

import _genuine  # noqa: E402

WALLET = _genuine.wallet()
KWARGS = _genuine.verify_kwargs(WALLET)
PAYLOAD, DISCLOSURES = _genuine.issuer_payload()
ISSUER_HEADER = json.dumps({"alg": "ES256", "typ": "dc+sd-jwt", "kid": "issuer-1"}).encode()
KB_HEADER = json.dumps({"alg": "ES256", "typ": "kb+jwt"}).encode()


def _kb_payload(sd_hash):
    return {"iat": _genuine.NOW, "aud": _genuine.AUDIENCE, "nonce": _genuine.NONCE,
            "sd_hash": sd_hash}


def _presented(payload_bytes):
    issuer_jwt = _genuine.sign(_genuine.ISSUER_KEY, ISSUER_HEADER, payload_bytes)
    return issuer_jwt + "~" + "".join(d + "~" for d in DISCLOSURES)


GENUINE_PRESENTED = _presented(json.dumps(PAYLOAD).encode())
GENUINE_SD_HASH = _genuine.sd_hash(GENUINE_PRESENTED)
ISSUER_FIELDS = [("iss",), ("vct",), ("iat",), ("exp",), ("nbf",), ("cnf",), ("cnf", "jwk"),
                 ("cnf", "jwk", "x"), ("cnf", "jwk", "crv"), ("cnf", "jwk", "kty"), ("_sd",),
                 ("_sd_alg",), ("status",), ("_sd", 0), ("given_name",)]
KB_FIELDS = [("iat",), ("aud",), ("nonce",), ("sd_hash",), ("cnf",)]
HEADER_FIELDS = [("alg",), ("typ",), ("kid",), ("x5c",), ("jwk",), ("crit",)]


def TestOneInput(data):
    if not data:
        return
    which, body = data[0] % 6, data[1:]
    if which >= 3 and not body:
        return
    if which == 3:
        body = json.dumps(_genuine.with_field(PAYLOAD, ISSUER_FIELDS, body)).encode()
        which = 0
    elif which == 4:
        body = json.dumps(_genuine.with_field(
            _kb_payload("$SD_HASH"), KB_FIELDS, body)).encode()
        which = 1
    if which == 0:
        presented = _presented(body)
        kb = _genuine.sign(_genuine.HOLDER_KEY, KB_HEADER, json.dumps(
            _kb_payload(_genuine.sd_hash(presented))).encode())
    elif which == 1:
        presented = GENUINE_PRESENTED
        body = body.replace(b"$SD_HASH", GENUINE_SD_HASH.encode())
        kb = _genuine.sign(_genuine.HOLDER_KEY, KB_HEADER, body)
    elif which == 2:
        presented = GENUINE_PRESENTED
        kb = _genuine.sign(_genuine.HOLDER_KEY, body,
                           json.dumps(_kb_payload(GENUINE_SD_HASH)).encode())
    else:
        header = json.dumps(_genuine.with_field(json.loads(ISSUER_HEADER), HEADER_FIELDS,
                                                body)).encode()
        issuer_jwt = _genuine.sign(_genuine.ISSUER_KEY, header, json.dumps(PAYLOAD).encode())
        presented = issuer_jwt + "~" + "".join(d + "~" for d in DISCLOSURES)
        kb = _genuine.sign(_genuine.HOLDER_KEY, KB_HEADER, json.dumps(
            _kb_payload(_genuine.sd_hash(presented))).encode())
    verdict = sdjwt.verify_presentation(presented + kb, **KWARGS)
    if not isinstance(verdict, sdjwt.Verdict):
        raise AssertionError("verify_presentation returned %r, not a Verdict" % (verdict,))
    if verdict.authentic and which == 1:
        try:
            signed = json.loads(body)
        except ValueError:
            raise AssertionError("accepted a key binding payload that is not JSON: %r" % body)
        aud = signed.get("aud") if isinstance(signed, dict) else None
        if not isinstance(signed, dict) or (signed.get("nonce"), signed.get("sd_hash")) != (
                _genuine.NONCE, GENUINE_SD_HASH) or _genuine.AUDIENCE not in (
                aud if isinstance(aud, list) else [aud]):
            raise AssertionError("accepted a key binding payload without this verifier's "
                                 "nonce, audience and sd_hash: %r" % (signed,))


if __name__ == "__main__":
    _genuine.seed(sys.argv, [
        b"\x00" + json.dumps(PAYLOAD).encode(),
        b"\x00" + json.dumps(dict(PAYLOAD, exp=_genuine.NOW + 60, nbf=_genuine.NOW - 60)).encode(),
        b"\x00" + json.dumps(dict(PAYLOAD, status={"status_list": {
            "idx": 1, "uri": _genuine.STATUS_URI}})).encode(),
        b"\x01" + json.dumps(_kb_payload("$SD_HASH")).encode(),
        b"\x02" + KB_HEADER,
    ] + [bytes([3, i]) + b"1" for i in range(len(ISSUER_FIELDS))]
      + [bytes([4, i]) + b"1" for i in range(len(KB_FIELDS))]
      + [bytes([5, i]) + b"1" for i in range(len(HEADER_FIELDS))])
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
