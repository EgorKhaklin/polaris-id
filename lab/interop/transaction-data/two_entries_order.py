#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Write the two-entry order vector: one credential binds two transaction_data entries, and its key
binding JWT lists their hashes in the request's order or in the reverse.

OpenID4VP 1.0 B.3.3.1 says of transaction_data_hashes that "Each hash value ensures the integrity
of, and maps to, the respective transaction data object", and no sentence says whether the hash at
position i is entry i's. Verifiers differ: some read a hash by its position, and one accepts any
non-empty subset of the request's hashes, in any order. This vector has one credential query, `pay`, and two entries naming it: a TS12
payment and a second object of the example type urn:example:terms-acceptance. The file holds the
request, the hashes, and one response written each way, signed with throwaway keys whose private
halves are discarded; both responses carry the same claims but for the order of the hashes and the
TS12 `jti`.

It mints with its own code (`cryptography` only) and imports nothing from polaris-oid4vp, so the
package's tests check the package against a producer it did not write.

    python3 lab/interop/transaction-data/two_entries_order.py [OUT]

OUT defaults to packages/polaris-oid4vp/testdata/transaction-data-two-entries-order.json. Each run
makes new keys and a new `at`, so a re-run rewrites every signature; the tests read the file.
"""
import base64
import hashlib
import json
import pathlib
import secrets
import sys
import time
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = pathlib.Path(__file__).resolve().parents[3]
OUT = ROOT / "packages" / "polaris-oid4vp" / "testdata" / "transaction-data-two-entries-order.json"


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def compact(obj):
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def jwk(key):
    n = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")),
            "y": b64u(n.y.to_bytes(32, "big"))}


def jws(key, header, payload):
    signing_input = b64u(compact(header)) + "." + b64u(compact(payload))
    r, s = decode_dss_signature(key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256())))
    return signing_input + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def main():
    out = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else OUT
    at = int(time.time())
    issuer = ec.generate_private_key(ec.SECP256R1())
    holder = ec.generate_private_key(ec.SECP256R1())

    entries = [
        {"type": "urn:eudi:sca:payment:1", "credential_ids": ["pay"],
         "transaction_data_hashes_alg": ["sha-256"],
         "payload": {"transaction_id": "order-vector-0001",
                     "payee": {"name": "Example Shop", "id": "DE00EXAMPLE0001"},
                     "currency": "EUR", "amount": 12.5}},
        {"type": "urn:example:terms-acceptance", "credential_ids": ["pay"],
         "transaction_data_hashes_alg": ["sha-256"],
         "terms_uri": "https://rp.example/terms/2026-11"},
    ]
    raw = [b64u(compact(e)) for e in entries]
    digests = [b64u(hashlib.sha256(r.encode("ascii")).digest()) for r in raw]   # the strings, as sent
    request = {
        "client_id": "x509_hash:" + b64u(hashlib.sha256(b"order vector: no such certificate").digest()),
        "response_type": "vp_token",
        "response_mode": "direct_post.jwt",
        "nonce": secrets.token_urlsafe(32),
        "dcql_query": {"credentials": [
            {"id": "pay", "format": "dc+sd-jwt",
             "meta": {"vct_values": ["https://psp.example/sca-attestation"]},
             "claims": [{"path": ["account_holder"]}]}]},
        "transaction_data": raw,
    }
    disclosure = b64u(compact([secrets.token_urlsafe(16), "account_holder", "Jean Dupont"]))
    issued = jws(issuer, {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "issuer-1"},
                 {"iss": "https://issuer.example", "vct": "https://psp.example/sca-attestation",
                  "iat": at, "_sd": [b64u(hashlib.sha256(disclosure.encode("ascii")).digest())],
                  "_sd_alg": "sha-256", "cnf": {"jwk": jwk(holder)}})
    presented = issued + "~" + disclosure + "~"
    sd_hash = b64u(hashlib.sha256(presented.encode("ascii")).digest())

    orders = {"request_order": [digests[0], digests[1]], "reversed": [digests[1], digests[0]]}
    responses = {}
    for name, listed in orders.items():
        claims = {"iat": at, "aud": request["client_id"], "nonce": request["nonce"], "sd_hash": sd_hash,
                  "transaction_data_hashes": listed, "transaction_data_hashes_alg": "sha-256",
                  # TS12 section 3.6, for the presentation of the credential the TS12 entry names.
                  "response_mode": "direct_post.jwt",
                  "amr": [{"knowledge": "pin_6_or_more_digits"},
                          {"possession": "key_in_local_native_wscd"}],
                  "jti": str(uuid.uuid4())}
        responses[name] = {"vp_token": {"pay": [presented + jws(holder, {"alg": "ES256", "typ": "kb+jwt"},
                                                                     claims)]}}

    vector = {
        "description": (
            "One credential query (pay) and two transaction_data entries naming it: a TS12 payment "
            "(entry 0) and a urn:example:terms-acceptance object (entry 1). OpenID4VP 1.0 B.3.3.1: "
            "each hash \"maps to, the respective transaction data object\"; no sentence says whether "
            "the hash at position i is entry i's. `responses` holds the key binding JWT listing the "
            "two hashes in the request's order and in the reverse, its other claims alike but the "
            "TS12 jti. Under `by_position` a hash names the entry at its position, so the reversed "
            "list hashes entry 1 where entry 0 is due; under `in_any_order` any non-empty subset of "
            "the request's hashes, in any order, is accepted, so both lists pass. Judged at `at` "
            "with `issuer_jwks`. Hashes are "
            "base64url(SHA-256(the ASCII bytes of the string in transaction_data))."),
        "made_by": "lab/interop/transaction-data/two_entries_order.py, Polaris, Apache-2.0",
        "at": at,
        "issuer_jwks": [dict(jwk(issuer), kid="issuer-1")],
        "request": request,
        "transaction_data_hashes": {"sha-256": digests},
        "listed": orders,
        "responses": responses,
        "outcomes": {
            "request_order": {"by_position": "accepted", "in_any_order": "accepted"},
            "reversed": {"by_position": "refused: pay transaction_data_mismatch", "in_any_order": "accepted"},
        },
    }
    out.write_text(json.dumps(vector, indent=2) + "\n", encoding="utf-8")
    print("wrote %s (at %d; entry hashes %s)" % (out, at, ", ".join(digests)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
