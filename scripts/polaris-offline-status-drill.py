#!/usr/bin/env python3
"""
polaris-offline-status-drill.py — offline verification, run end to end (P3.6).

The last connectivity gap in the holder<->verifier flow: authenticity was already
offline (the detached verifier), but "is this authoritative NOW?" needed an online
call. This drill exercises the offline answer — a short-lived, issuer-signed STATUS
ASSERTION the holder staples to a presentation — with real ML-DSA-65 and NO network
and NO database, the way the pqc-real CI job runs it.

An issuer (a real ML-DSA-65 key) signs both a credential (SHA3-256(token_value)) and
a status assertion (SHA3-256 of the canonical {format,token_value,status,issued_at,
expires_at}). The detached verifier then decides the whole thing offline:

    active, fresh            ACCEPT   (authentic + bound + fresh + ACTIVE)
    revoked                  REJECT   (a fresh assertion says REVOKED)
    expired                  REJECT   (now past expires_at -- the freshness bound)
    window over the ceiling  REJECT   (assertion window longer than the verifier accepts)
    tampered assertion       REJECT   (signature invalid)
    wrong credential binding REJECT   (assertion is for a different token)
    untrusted issuer         REJECT   (assertion key not in the anchor set)

Exits non-zero if any decision is wrong. Needs liboqs + cryptography.

    python3 scripts/polaris-offline-status-drill.py
"""
import importlib.util
import json
import os
import sys
import tempfile
from datetime import datetime, timezone, timedelta

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
    # This drill IS the real-ML-DSA path: declare the profile itself and guard on
    # LIBRARY availability, not the caller's env flag (the v9.290 e2e-drill lesson).
    os.environ["POLARIS_USE_REAL_PQC"] = "1"
    try:
        import pqc_signing
    except Exception as e:
        print("offline-status drill needs the app's pqc_signing (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not (pqc_signing.is_available() and pqc_signing.second_witness_available()):
        print("offline-status drill needs real ML-DSA (liboqs + cryptography); skipping", file=sys.stderr)
        return 3

    V = _load_verifier()
    tmp = tempfile.mkdtemp(prefix="polaris-offline-status-")
    kp = pqc_signing.generate_keypair()
    kf = os.path.join(tmp, "issuer.key.json")
    with open(kf, "w") as f:
        json.dump(kp, f)
    os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = kf
    anchor = [kp["public_key_hex"]]

    def pack_for(token_value):
        sig, alg, pk = pqc_signing.signature_with_key_for_token(token_value)
        return {"format": "polaris-authenticity-pack/1", "token_value": token_value,
                "algorithm": alg, "signature_hex": sig.hex(), "public_key_hex": pk}

    def assertion_for(token_value, status, issued, expires):
        statement = json.dumps({
            "format": "polaris-status-assertion/1", "token_value": token_value,
            "status": status, "issued_at": _iso(issued), "expires_at": _iso(expires),
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig, alg, pk = pqc_signing.signature_over_message(statement)
        return {"format": "polaris-status-assertion/1", "token_value": token_value,
                "status": status, "issued_at": _iso(issued), "expires_at": _iso(expires),
                "algorithm": alg, "signature_hex": sig.hex(), "public_key_hex": pk}

    now = datetime.now(timezone.utc)
    pack = pack_for("OFFLINE-STATUS-0001")
    active = assertion_for("OFFLINE-STATUS-0001", "ACTIVE", now, now + timedelta(hours=1))
    revoked = assertion_for("OFFLINE-STATUS-0001", "REVOKED", now, now + timedelta(hours=1))
    tampered = dict(active)
    b = bytearray.fromhex(tampered["signature_hex"]); b[0] ^= 0x01
    tampered["signature_hex"] = b.hex()
    other_pack = pack_for("OFFLINE-STATUS-0002")

    CEIL = 86400  # the verifier's accepted maximum window (1 day)
    checks = [
        ("active, fresh", V.verify_stapled(pack, active, now=now, max_window_seconds=CEIL, anchor_keys=anchor), "accept"),
        ("revoked", V.verify_stapled(pack, revoked, now=now, max_window_seconds=CEIL, anchor_keys=anchor), "reject"),
        ("expired", V.verify_stapled(pack, active, now=now + timedelta(hours=2), max_window_seconds=CEIL, anchor_keys=anchor), "reject"),
        ("window over ceiling", V.verify_stapled(pack, active, now=now, max_window_seconds=1, anchor_keys=anchor), "reject"),
        ("tampered assertion", V.verify_stapled(pack, tampered, now=now, max_window_seconds=CEIL, anchor_keys=anchor), "reject"),
        ("wrong binding", V.verify_stapled(other_pack, active, now=now, max_window_seconds=CEIL, anchor_keys=anchor), "reject"),
        ("untrusted issuer", V.verify_stapled(pack, active, now=now, max_window_seconds=CEIL, anchor_keys=["00"]), "reject"),
    ]

    print("case                     decision   status   fresh   expected  ok")
    ok_all = True
    for label, v, expected in checks:
        ok = v["decision"] == expected
        ok_all = ok_all and ok
        print("  %-22s %-9s  %-7s  %-6s  %-8s  %s"
              % (label, v["decision"].upper(), v["status"], v["fresh"], expected.upper(),
                 "OK" if ok else "WRONG"))
    if ok_all:
        print("\nOK: offline verification holds — a signed status assertion decides authorization "
              "with no connectivity, and every freshness/replay/binding bound rejects.")
        return 0
    print("\nFAIL: an offline-status decision was wrong.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
