#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Fuzz the decrypted authorization response, through the class that answers the wallet.

A response is encrypted to a per-request key, so random tokens never get past decryption.
This target writes the fuzzer's bytes as the PLAINTEXT, encrypts them to a fresh request's
key the way a wallet would, and posts them to Verifier.handle_direct_post. In the plaintext,
"$STATE" becomes the request's state and "$VP" a genuine presentation for its nonce and
audience, so the search starts from a response the verifier accepts.

The promise is handle_direct_post's: "Nothing returns 500": every outcome is a (status, body,
verdict) answer, 200 or 400, never an exception. A 200 must come with an authentic verdict.

    python3 fuzz_response.py corpus/response -max_total_time=60
"""
import json
import os
import sys

import atheris

# The package from this tree, not whatever release is installed.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

with atheris.instrument_imports(include=["polaris_oid4vp"]):
    from polaris_oid4vp import jwe, verifier

import _genuine  # noqa: E402
import test_verifier  # noqa: E402

CERT_PEM, KEY_PEM = test_verifier._client_chain()
WALLET = test_verifier.Wallet()
VERIFIER = verifier.Verifier(client_cert_pem=CERT_PEM, client_key_pem=KEY_PEM,
                             request_uri="https://verifier.test/request.jwt",
                             response_uri="https://verifier.test/response",
                             issuer_jwks=[WALLET.issuer_jwk])


def TestOneInput(data):
    session, jar = VERIFIER.new_request()
    _, request = WALLET.read_request(jar)
    if b"$VP" in data:
        vp = WALLET._presentation(nonce=request["nonce"], audience=request["client_id"],
                                  iat=None, sd_hash=None, corrupt_issuer_sig=False,
                                  corrupt_kb_sig=False, extra_disclosure=None)
        data = data.replace(b"$VP", vp.encode())
    data = data.replace(b"$STATE", session.state.encode())
    token = jwe.encrypt_compact(data, session.enc_key.public_key())
    answer = VERIFIER.handle_direct_post({"response": [token]})
    if not (isinstance(answer, tuple) and len(answer) == 3 and answer[0] in (200, 400)):
        raise AssertionError("handle_direct_post answered %r" % (answer,))
    status, _, verdict = answer
    if status == 200 and not verdict.authentic:
        raise AssertionError("200 for a verdict that is not authentic: %r" % (verdict,))


if __name__ == "__main__":
    _genuine.seed(sys.argv, [
        json.dumps(_genuine.response_body("$STATE", "$VP")).encode(),
        json.dumps({"state": "$STATE", "vp_token": {"pid": "$VP"}}).encode(),
        json.dumps({"state": "$STATE", "vp_token": {"pid": ["$VP", "$VP"]}}).encode(),
        json.dumps({"state": "$STATE", "error": "access_denied"}).encode(),
    ])
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
