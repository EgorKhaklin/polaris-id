#!/usr/bin/env python3
"""
polaris-timestamp-drill.py -- the timestamp authority, run (P8.7a).

An authority binds an arbitrary SHA3-256 digest to an instant under its real ML-DSA-65 key; a
third party verifies the binding OFFLINE and checks it against the data it holds. This drill
stands up a timestamp authority and a stranger with distinct real roots and drives the matrix:

  - a timestamp is authentic and binds to the data it was requested for, and to nothing else;
  - the requester's nonce is echoed unchanged; the digest-only rule holds (no content anywhere);
  - a tampered signature, a swapped digest, and a rewritten instant are all caught;
  - the authority is trusted only under a relying party's own anchor set;
  - an EXCHANGE RECEIPT's canonical bytes timestamped by a SECOND authority is time evidence
    independent of the receipt's responder (the receipt's occurred_at is the responder's word;
    the timestamp is someone else's).

Red (exit 1) on any wrong verdict. Needs liboqs + cryptography.

    python3 scripts/polaris-timestamp-drill.py
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
        print("timestamp drill needs the app's pqc_signing (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not (pqc_signing.is_available() and pqc_signing.second_witness_available()):
        print("timestamp drill needs real ML-DSA (liboqs + cryptography); skipping", file=sys.stderr)
        return 3

    V = _load_verifier()
    tmp = tempfile.mkdtemp(prefix="polaris-timestamp-")
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

    def timestamp(authority, data, nonce=None):
        """What POST /api/v1/timestamp/<id> does, with this authority's key."""
        ts = {"format": "polaris-timestamp/1",
              "authority": {"agency_id": authority["name"], "name": authority["name"]},
              "digest_hex": hashlib.sha3_256(data).hexdigest(), "digest_algorithm": "SHA3-256",
              "nonce": nonce, "issued_at": _iso(now), "algorithm": "ML-DSA-65"}
        sig, pk = sign_with(authority["key_file"], V._timestamp_canonical(ts))
        ts["signature_hex"], ts["public_key_hex"] = sig.hex(), pk
        return ts

    TSA, TSA2, STRANGER = issuer("tsa"), issuer("tsa-2"), issuer("stranger")
    document = b"the document being timestamped; never sent to the authority"
    ts = timestamp(TSA, document, nonce="req-7f3a")

    tampered = dict(ts)
    bb = bytearray.fromhex(tampered["signature_hex"]); bb[0] ^= 0x01; tampered["signature_hex"] = bb.hex()
    swapped = dict(ts); swapped["digest_hex"] = hashlib.sha3_256(b"other data").hexdigest()
    retimed = dict(ts); retimed["issued_at"] = "2020-01-01T00:00:00Z"

    # A receipt timestamped by a SECOND authority: independent time evidence.
    responder = issuer("responder")
    receipt = {"format": "polaris-exchange-receipt/1", "requester": {"public_key_hex": STRANGER["key_hex"]},
               "responder": {"agency_id": "responder", "name": "responder"}, "context_id": 1,
               "request_hash": hashlib.sha3_256(b"q").hexdigest(), "response_hash": hashlib.sha3_256(b"r").hexdigest(),
               "authorized_via": {"authority": {"agency_id": "x", "name": "x"}, "context_id": 1},
               "occurred_at": _iso(now), "algorithm": "ML-DSA-65"}
    rsig, rpk = sign_with(responder["key_file"], V._exchange_receipt_canonical(receipt))
    receipt["signature_hex"], receipt["public_key_hex"] = rsig.hex(), rpk
    receipt_ts = timestamp(TSA2, V._exchange_receipt_canonical(receipt))

    checks = [
        ("the timestamp is authentic (two witnesses)",
         V.verify_timestamp(ts)["timestamp_authentic"], True),
        ("it binds to the data it was requested for",
         V.timestamp_binds(ts, document), True),
        ("it does NOT bind to other data",
         V.timestamp_binds(ts, b"a different document"), False),
        ("the requester's nonce is echoed unchanged",
         V.verify_timestamp(ts)["nonce"], "req-7f3a"),
        ("digest-only: the content appears nowhere in the artifact",
         document.decode() not in json.dumps(ts), True),
        ("a tampered signature is not authentic",
         V.verify_timestamp(tampered)["timestamp_authentic"], False),
        ("a swapped digest is not authentic (the binding is signed)",
         V.verify_timestamp(swapped)["timestamp_authentic"], False),
        ("a rewritten instant is not authentic (the instant is signed)",
         V.verify_timestamp(retimed)["timestamp_authentic"], False),
        ("the authority is trusted under an anchor set that includes it",
         V.verify_timestamp(ts, anchor_keys=[TSA["key_hex"]])["issuer_trusted"], True),
        ("... and untrusted under one that does not (authentic, but not trusted)",
         V.verify_timestamp(ts, anchor_keys=[STRANGER["key_hex"]])["issuer_trusted"], False),
        ("no anchor set: trust is simply not asserted",
         V.verify_timestamp(ts)["issuer_trusted"], None),
        ("a receipt timestamped by a SECOND authority: the timestamp is authentic",
         V.verify_timestamp(receipt_ts, anchor_keys=[TSA2["key_hex"]])["issuer_trusted"], True),
        ("... and binds to the receipt's canonical bytes (independent time evidence)",
         V.timestamp_binds(receipt_ts, V._exchange_receipt_canonical(receipt)), True),
        ("... signed by a key OTHER than the receipt's responder",
         receipt_ts["public_key_hex"] != receipt["public_key_hex"], True),
        ("hostile input does not crash the verifier",
         V.verify_timestamp("not a dict")["timestamp_authentic"], False),
    ]

    print("case                                                                       got        expected   ok")
    ok_all = True
    for label, got, expected in checks:
        ok = got == expected
        ok_all = ok_all and ok
        print("  %-72s %-10s %-10s %s" % (label, str(got), str(expected), "OK" if ok else "WRONG"))
    if ok_all:
        print("\nOK: a timestamp authority binds a digest to an instant under real ML-DSA-65; a third party "
              "verifies it offline and checks it binds to the data it holds and to nothing else; tampering, a "
              "swapped digest and a rewritten instant are caught; trust is the relying party's anchor decision; "
              "and a receipt timestamped by a second authority carries time evidence independent of its signer.")
        return 0
    print("\nFAIL: a timestamp verdict was wrong.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
