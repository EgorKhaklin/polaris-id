#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Write the two-credential transaction_data vector: what each key binding JWT carries under each
reading of OpenID4VP 1.0's transaction data scoping (the question SIROS calls B8).

No published vector presents more than one credential, and the question only exists when one
does. This one asks for two, `pid` and `pay`, with ONE TS12 payment entry whose credential_ids
names `pay`. Under the per-credential reading the `pid` key binding JWT carries no
transaction_data_hashes and the `pay` one carries the payment's; under the all-entries reading
both carry it. The file holds the request, the hash, what each key binding JWT must carry under
each reading, and one captured response written each way, signed with throwaway keys whose
private halves are discarded.

It mints with its own code (`cryptography` only) and imports nothing from polaris-oid4vp, so the
package's tests check the package against a producer it did not write. The payment is TS12's type
urn:eudi:sca:payment:1 with a payload satisfying TS12's schema.

    python3 lab/interop/transaction-data/two_credentials.py [OUT]

OUT defaults to packages/polaris-oid4vp/testdata/transaction-data-two-credentials.json. Each run
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
OUT = ROOT / "packages" / "polaris-oid4vp" / "testdata" / "transaction-data-two-credentials.json"


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


def credential(issuer, holder, vct, name, value, at):
    """An SD-JWT VC with one selectively disclosable claim, bound to `holder`; its disclosures
    up to and including the final tilde."""
    disclosure = b64u(compact([secrets.token_urlsafe(16), name, value]))
    payload = {"iss": "https://issuer.example", "vct": vct, "iat": at,
               "_sd": [b64u(hashlib.sha256(disclosure.encode("ascii")).digest())],
               "_sd_alg": "sha-256", "cnf": {"jwk": jwk(holder)}}
    return jws(issuer, {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "issuer-1"}, payload) \
        + "~" + disclosure + "~"


def presentation(presented, holder, request, at, extra):
    """`presented` with a key binding JWT over it, carrying `extra` beside the standard claims."""
    claims = {"iat": at, "aud": request["client_id"], "nonce": request["nonce"],
              "sd_hash": b64u(hashlib.sha256(presented.encode("ascii")).digest())}
    claims.update(extra)
    return presented + jws(holder, {"alg": "ES256", "typ": "kb+jwt"}, claims)


def main():
    out = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else OUT
    at = int(time.time())
    issuer = ec.generate_private_key(ec.SECP256R1())
    holders = {"pid": ec.generate_private_key(ec.SECP256R1()),
               "pay": ec.generate_private_key(ec.SECP256R1())}

    entry = {"type": "urn:eudi:sca:payment:1", "credential_ids": ["pay"],
             "transaction_data_hashes_alg": ["sha-256"],
             "payload": {"transaction_id": "b8-two-credentials-0001",
                         "payee": {"name": "Example Shop", "id": "DE00EXAMPLE0001"},
                         "currency": "EUR", "amount": 12.5}}
    raw = b64u(compact(entry))
    digest = b64u(hashlib.sha256(raw.encode("ascii")).digest())   # the string, as sent
    request = {
        "client_id": "x509_hash:" + b64u(hashlib.sha256(b"b8 vector: no such certificate").digest()),
        "response_type": "vp_token",
        "response_mode": "direct_post.jwt",
        "nonce": secrets.token_urlsafe(32),
        "dcql_query": {"credentials": [
            {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]},
             "claims": [{"path": ["given_name"]}]},
            {"id": "pay", "format": "dc+sd-jwt",
             "meta": {"vct_values": ["https://psp.example/sca-attestation"]},
             "claims": [{"path": ["account_holder"]}]}]},
        "transaction_data": [raw],
    }
    presented = {
        "pid": credential(issuer, holders["pid"], "urn:eudi:pid:1", "given_name", "Jean", at),
        "pay": credential(issuer, holders["pay"], "https://psp.example/sca-attestation",
                          "account_holder", "Jean Dupont", at),
    }
    bound = {"transaction_data_hashes": [digest], "transaction_data_hashes_alg": "sha-256"}
    # TS12 section 3.6, for the presentation of the credential the TS12 entry names.
    sca = {"response_mode": "direct_post.jwt",
           "amr": [{"knowledge": "pin_6_or_more_digits"},
                   {"possession": "key_in_local_native_wscd"}]}
    must_carry = {"per_credential": {"pid": {}, "pay": dict(bound, **sca)},
                  "all_entries": {"pid": dict(bound), "pay": dict(bound, **sca)}}
    responses = {}
    for reading, carried in must_carry.items():
        responses[reading] = {"vp_token": {
            qid: [presentation(presented[qid], holders[qid], request, at,
                               dict(carried[qid], **({"jti": str(uuid.uuid4())} if qid == "pay" else {})))]
            for qid in ("pid", "pay")}}

    vector = {
        "description": (
            "Two credential queries (pid, pay) and one TS12 payment entry whose credential_ids "
            "names pay. OpenID4VP 1.0 does not say whether the pid key binding JWT carries the "
            "payment's hash: under per_credential it does not, under all_entries it does. "
            "`must_carry` gives each key binding JWT's transaction claims under each reading "
            "(the pay one also needs a fresh jti, TS12 3.6). `responses` holds one response "
            "written each way; judged at `at` with `issuer_jwks`, each is accepted under its own "
            "reading and refused under the other. Hashes are base64url(SHA-256(the ASCII bytes "
            "of the string in transaction_data))."),
        "made_by": "lab/interop/transaction-data/two_credentials.py, Polaris, Apache-2.0",
        "at": at,
        "issuer_jwks": [dict(jwk(issuer), kid="issuer-1")],
        "request": request,
        "transaction_data_hashes": {"sha-256": [digest]},
        "must_carry": must_carry,
        "responses": responses,
        "outcomes": {
            "per_credential": {"per_credential": "accepted",
                               "all_entries": "refused: pid transaction_data_missing"},
            "all_entries": {"per_credential": "refused: pid transaction_data_extra",
                            "all_entries": "accepted"},
        },
    }
    out.write_text(json.dumps(vector, indent=2) + "\n", encoding="utf-8")
    print("wrote %s (at %d; entry hash %s)" % (out, at, digest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
