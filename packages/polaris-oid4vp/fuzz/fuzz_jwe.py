#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Fuzz the JWE a wallet posts, before anything about it is authenticated.

The promise is decrypt_compact's: "Raises JweError with a reason for anything malformed,
unsupported or unauthenticated." verifier.py catches exactly JweError and moves on to the next
outstanding session, so any other exception aborts the whole response path. Anything that
escapes as something else is a crash here. A token that decrypts must come back as a dict.

The first input byte picks the form, the rest is the input:

    0  the whole compact token, as text
    1  the protected header's JSON; the harness encodes it and appends a genuine token's
       other four segments, so the fuzzer works on the JSON rather than on its base64url
    2  the genuine header with one field replaced by a typed value (_genuine.with_field)

    python3 fuzz_jwe.py corpus/jwe -max_total_time=60
"""
import json
import os
import sys

import atheris

# The package from this tree, not whatever release is installed.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

with atheris.instrument_imports(include=["polaris_oid4vp"]):
    from polaris_oid4vp import jwe

import _genuine  # noqa: E402

KEY = _genuine.VERIFIER_ENC_KEY
TOKENS = _genuine.jwe_tokens(_genuine.wallet())
REST = TOKENS[0].split(".", 1)[1]
HEADER_OBJ = json.loads(jwe.b64u_decode(TOKENS[0].split(".")[0]))
HEADER_FIELDS = [("alg",), ("enc",), ("epk",), ("epk", "kty"), ("epk", "crv"), ("epk", "x"),
                 ("epk", "y"), ("apu",), ("apv",), ("zip",), ("crit",)]


def TestOneInput(data):
    if not data:
        return
    form = data[0] % 3
    if form == 0:
        token = data[1:].decode("utf-8", "surrogateescape")
    elif form == 1:
        token = jwe.b64u_encode(data[1:]) + "." + REST
    elif len(data) > 1:
        token = jwe.b64u_encode(json.dumps(
            _genuine.with_field(HEADER_OBJ, HEADER_FIELDS, data[1:])).encode()) + "." + REST
    else:
        return
    try:
        body = jwe.decrypt_response(token, KEY)
    except jwe.JweError:
        return
    if not isinstance(body, dict):
        raise AssertionError("decrypt_response returned %r, not a dict" % (body,))


if __name__ == "__main__":
    _genuine.seed(sys.argv, [b"\x00" + t.encode() for t in TOKENS]
                  + [b"\x01" + jwe.b64u_decode(t.split(".")[0]) for t in TOKENS]
                  + [bytes([2, i]) + b"1" for i in range(len(HEADER_FIELDS))])
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
