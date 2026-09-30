#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Fuzz the Status List Token a relying party fetches from someone else's server.

The promise is status.decide's: "Total on hostile input." The authority here accepts every
signature, so the fuzzer reaches the payload, the compressed list and the index arithmetic
that a real issuer's key would otherwise guard; totality has to hold there as well, because
an issuer's key is not a promise that its list is well formed. The verdict must be a dict
with a boolean `checked`, and a checked verdict must carry a status.

The first input byte is the index to read, the second picks the form, the rest is the input:

    0  the whole token, as text
    1  the payload's JSON, encoded by the harness under a genuine header
    2  the header's JSON, encoded by the harness over a genuine payload
    3  one payload field replaced by a typed value (_genuine.with_field)
    4  one header field replaced the same way

    python3 fuzz_status.py corpus/status -max_total_time=60
"""
import json
import os
import sys

import atheris

# The package from this tree, not whatever release is installed.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

with atheris.instrument_imports(include=["polaris_oid4vp"]):
    from polaris_oid4vp import status

import _genuine  # noqa: E402

AUTHORITY = status.StatedAuthority().state(
    credential_issuer=_genuine.STATUS_ISSUER, status_uri=_genuine.STATUS_URI,
    verify=lambda signing_input, signature, header: True,
    why="the fuzz target states that this key publishes status for this issuer")
TOKENS = _genuine.status_tokens()
HEADER, PAYLOAD, _ = TOKENS[0].split(".")
b64u_encode, b64u_decode = _genuine.test_sdjwt.b64u_encode, _genuine.jwe.b64u_decode
HEADER_OBJ, PAYLOAD_OBJ = json.loads(b64u_decode(HEADER)), json.loads(b64u_decode(PAYLOAD))
PAYLOAD_FIELDS = [("sub",), ("iat",), ("exp",), ("ttl",), ("status_list",),
                  ("status_list", "bits"), ("status_list", "lst"),
                  ("status_list", "aggregation_uri")]
HEADER_FIELDS = [("alg",), ("typ",), ("kid",), ("x5c",)]


def TestOneInput(data):
    if len(data) < 2:
        return
    form, body = data[1] % 5, data[2:]
    if form == 0:
        token = body.decode("utf-8", "surrogateescape")
    elif form == 1:
        token = HEADER + "." + b64u_encode(body) + ".c2ln"
    elif form == 2:
        token = b64u_encode(body) + "." + PAYLOAD + ".c2ln"
    elif not body:
        return
    elif form == 3:
        token = HEADER + "." + b64u_encode(json.dumps(
            _genuine.with_field(PAYLOAD_OBJ, PAYLOAD_FIELDS, body)).encode()) + ".c2ln"
    else:
        header = _genuine.with_field(HEADER_OBJ, HEADER_FIELDS, body)
        token = b64u_encode(json.dumps(header).encode()) + "." + PAYLOAD + ".c2ln"
    verdict = status.decide(token, index=data[0], expected_uri=_genuine.STATUS_URI,
                            authority=AUTHORITY, credential_issuer=_genuine.STATUS_ISSUER,
                            now=_genuine.NOW)
    if not isinstance(verdict, dict) or not isinstance(verdict.get("checked"), bool):
        raise AssertionError("decide returned %r" % (verdict,))
    if verdict["checked"] and "status" not in verdict:
        raise AssertionError("a checked verdict without a status: %r" % (verdict,))


if __name__ == "__main__":
    indexes = (1, 5, 2, 0)
    _genuine.seed(sys.argv,
                  [bytes([i, 0]) + t.encode() for i, t in zip(indexes, TOKENS)]
                  + [bytes([i, 1]) + b64u_decode(t.split(".")[1]) for i, t in zip(indexes, TOKENS)]
                  + [bytes([1, 2]) + b64u_decode(HEADER),
                     bytes([1, 2]) + json.dumps({"alg": "ES256", "typ": "statuslist+jwt",
                                                 "x5c": ["AA"]}).encode()]
                  + [bytes([1, 3, i]) + b"1" for i in range(len(PAYLOAD_FIELDS))]
                  + [bytes([1, 4, i]) + b"1" for i in range(len(HEADER_FIELDS))])
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
