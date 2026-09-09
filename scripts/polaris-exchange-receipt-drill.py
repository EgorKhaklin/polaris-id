#!/usr/bin/env python3
"""
polaris-exchange-receipt-drill.py -- the exchange receipt, run (P8.2).

The gateway's core primitive and the anti-surveillance inversion of an evidentiary message log.
A responder signs a RECEIPT committing to the SHA3-256 of a request and a response -- never
the bodies -- so a third party can prove, from the receipt alone, that the responder attests an authorized exchange
occurred, without ever seeing the payload. This drill stands up a requester, a responder, and
an attester with distinct real ML-DSA-65 roots, mints a receipt, and drives the matrix:

  - the receipt is authentic and bound to the responder;
  - the requester is authorized -- a trusted manifest attests its key in the receipt's context;
  - WITHOUT the payload, occurrence and authorization are still proven (evidence without
    retention), and WITH a body the commitment binds (request_hash == SHA3-256(request));
  - a wrong body does not bind; a tampered receipt is not authentic; an unauthorized requester
    (no attestation, or the wrong context) is not authorized; and the receipt carries only
    hashes, never a payload.

Red (exit 1) on any wrong verdict. Needs liboqs + cryptography.

    python3 scripts/polaris-exchange-receipt-drill.py
"""
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "polaris_web"))


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "polaris_verify", os.path.join(_ROOT, "scripts", "polaris-verify.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _iso(dt):
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main():
    os.environ["POLARIS_USE_REAL_PQC"] = "1"
    try:
        import pqc_signing
    except Exception as e:
        print("exchange-receipt drill needs the app's pqc_signing (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not (pqc_signing.is_available() and pqc_signing.second_witness_available()):
        print("exchange-receipt drill needs real ML-DSA (liboqs + cryptography); skipping", file=sys.stderr)
        return 3

    V = _load_verifier()
    tmp = tempfile.mkdtemp(prefix="polaris-exchange-receipt-")
    now = datetime.now(timezone.utc)

    def issuer(name):
        kp = pqc_signing.generate_keypair()
        kf = os.path.join(tmp, "%s.key.json" % name)
        with open(kf, "w") as f:
            json.dump(kp, f)
        return {"name": name, "key_file": kf, "key_hex": kp["public_key_hex"]}

    def sign_with(key_file, message):
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_file
        sig, _alg, pk = pqc_signing.signature_over_message(message)
        return sig, pk

    def manifest(iss, attestations):
        from datetime import timedelta
        body = {
            "format": "polaris-federation-manifest/1",
            "authority": {"agency_id": iss["name"], "name": iss["name"]},
            "anchors": [{"public_key_hex": iss["key_hex"], "algorithm": "ML-DSA-65", "status": "active"}],
            "attestations": attestations, "epoch": {"number": 1, "root_hex": "bb" * 16},
            "revocation": {"as_of": _iso(now)}, "issued_at": _iso(now),
            "expires_at": _iso(now + timedelta(hours=24)), "algorithm": "ML-DSA-65",
        }
        sig, pk = sign_with(iss["key_file"], V._manifest_canonical(body))
        body["signature_hex"], body["public_key_hex"] = sig.hex(), pk
        return body

    def receipt(responder, requester_key, context_id, request_hash, response_hash, authorized_via):
        body = {
            "format": "polaris-exchange-receipt/1",
            "requester": {"public_key_hex": requester_key},
            "responder": {"agency_id": responder["name"], "name": responder["name"]},
            "context_id": context_id, "request_hash": request_hash, "response_hash": response_hash,
            "authorized_via": authorized_via, "occurred_at": _iso(now), "algorithm": "ML-DSA-65",
        }
        sig, pk = sign_with(responder["key_file"], V._exchange_receipt_canonical(body))
        body["signature_hex"], body["public_key_hex"] = sig.hex(), pk
        return body

    Q, R, B = issuer("Q"), issuer("R"), issuer("B")   # requester, responder, attester
    CONTEXT = 1
    req_body = b"GET /register/person/effective-status"
    resp_body = b'{"status":"ACTIVE","as_of":"2026-06-01"}'
    req_hash = hashlib.sha3_256(req_body).hexdigest()
    resp_hash = hashlib.sha3_256(resp_body).hexdigest()

    B_attests_Q = manifest(B, [{"attested_agency_id": "Q", "attested_public_key_hex": Q["key_hex"], "context_id": CONTEXT}])
    B_attests_other = manifest(B, [{"attested_agency_id": "Q", "attested_public_key_hex": Q["key_hex"], "context_id": 99}])
    rcpt = receipt(R, Q["key_hex"], CONTEXT, req_hash, resp_hash, {"authority": {"name": "B"}, "context_id": CONTEXT})
    tampered = dict(rcpt)
    _b = bytearray.fromhex(tampered["signature_hex"]); _b[0] ^= 0x01
    tampered["signature_hex"] = _b.hex()

    trust = [B_attests_Q]

    checks = [
        ("receipt is authentic and bound to the responder",
         (lambda v: v["receipt_authentic"] and v["responder_matches"])(
             V.verify_exchange_receipt(rcpt, responder_key=R["key_hex"])), True),
        ("the requester is authorized (a trusted manifest attests its key in-context)",
         V.verify_exchange_receipt(rcpt, trusted_manifests=trust)["requester_authorized"], True),
        ("WITHOUT the payload, occurrence + authorization still proven (evidence without retention)",
         (lambda v: v["receipt_authentic"] and v["requester_authorized"] and v["request_bound"] is None)(
             V.verify_exchange_receipt(rcpt, trusted_manifests=trust)), True),
        ("WITH the bodies, the commitment binds",
         (lambda v: v["request_bound"] and v["response_bound"])(
             V.verify_exchange_receipt(rcpt, request_body=req_body, response_body=resp_body)), True),
        ("a WRONG request body does not bind",
         V.verify_exchange_receipt(rcpt, request_body=b"something else")["request_bound"], False),
        ("a tampered receipt is not authentic",
         V.verify_exchange_receipt(tampered, responder_key=R["key_hex"])["receipt_authentic"], False),
        ("an UNAUTHORIZED requester (attested only in another context) is not authorized",
         V.verify_exchange_receipt(rcpt, trusted_manifests=[B_attests_other])["requester_authorized"], False),
        ("no trusted manifest supplied: authorization is simply not asserted",
         V.verify_exchange_receipt(rcpt)["requester_authorized"], None),
        ("the receipt carries only hashes, never a payload",
         all(k not in json.dumps(rcpt).lower() for k in ("request_body", "response_body", "payload")), True),
    ]

    print("case                                                                       got        expected   ok")
    ok_all = True
    for label, got, expected in checks:
        ok = got == expected
        ok_all = ok_all and ok
        print("  %-72s %-10s %-10s %s" % (label, str(got), str(expected), "OK" if ok else "WRONG"))
    if ok_all:
        print("\nOK: an exchange receipt proves the responder's attestation of an authorized exchange OFFLINE, committing only to the "
              "SHA3-256 of the request and response -- a third party confirms occurrence and authorization with no "
              "access to the payload, a holder of a body confirms the commitment binds to it, and a tampered receipt "
              "or an unauthorized requester is caught. Evidence without retention.")
        return 0
    print("\nFAIL: an exchange-receipt verdict was wrong.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
