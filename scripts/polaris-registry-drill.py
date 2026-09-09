#!/usr/bin/env python3
"""
polaris-registry-drill.py -- the signed registry, run (P8.3).

An instance publishes ONE signed, machine-readable artifact saying what it offers and trusts;
a consumer verifies it offline and then DISCOVERS services and trust from it instead of from
hardcoded knowledge. This drill builds a registry under a real ML-DSA-65 root and drives:

  - the registry is authentic, fresh, and signed by the key it lists for its own publisher;
  - a service path, an authority, and the in-context trust graph are discovered from it;
  - a stranger's registry in the publisher's name is rejected (self-consistency); a tampered
    registry is rejected; an expired one is not fresh; trust is the consumer's anchor decision;
  - hostile input does not crash the verifier.

Red (exit 1) on any wrong verdict. Needs liboqs + cryptography.

    python3 scripts/polaris-registry-drill.py
"""
import importlib.util
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

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
        print("registry drill needs the app's pqc_signing (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not (pqc_signing.is_available() and pqc_signing.second_witness_available()):
        print("registry drill needs real ML-DSA (liboqs + cryptography); skipping", file=sys.stderr)
        return 3

    V = _load_verifier()
    tmp = tempfile.mkdtemp(prefix="polaris-registry-")
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

    PUB, PEER, STRANGER = issuer("publisher"), issuer("peer"), issuer("stranger")

    def registry(signer, issued=None, ttl_hours=24):
        issued = issued or now
        body = {
            "format": "polaris-registry/1", "publisher": {"agency_id": 1, "name": "Authority A"},
            "instance": {"protocol": {"formats": {"polaris-registry": 1, "polaris-timestamp": 1}, "algorithms": ["ML-DSA-65"],
                                      "wire_spec": "docs/reference/WIRE-SPEC.md", "conformance": "conformance/cases.json"},
                         "services": [{"kind": "timestamp", "path": "/api/v1/timestamp/{agency_id}", "auth": "none", "method": "POST"},
                                      {"kind": "exchange-receipt", "path": "/api/v1/exchange-receipt/{agency_id}/signed",
                                       "auth": "responder-signature", "method": "POST"}],
                         "transparency_logs": ["polaris-audit-anchor-log", "polaris-exchange-receipt-log"],
                         "disclosure_levels": ["ZERO_KNOWLEDGE", "SELECTIVE", "FULL"]},
            "authorities": [
                {"agency_id": 1, "name": "Authority A", "agency_type": "FEDERAL", "jurisdiction": "US",
                 "authorization_level": 5, "public_key_hex": PUB["key_hex"], "algorithm": "ML-DSA-65", "status": "active"},
                {"agency_id": 2, "name": "Authority B", "agency_type": "STATE", "jurisdiction": "US-CA",
                 "authorization_level": 3, "public_key_hex": PEER["key_hex"], "algorithm": "ML-DSA-65", "status": "active"}],
            "contexts": [{"context_id": 1, "context_type": "BANKING", "requires_biometric": False, "min_security_level": 128}],
            "trust": [{"attesting_agency_id": 1, "attested_agency_id": 2, "attested_public_key_hex": PEER["key_hex"],
                       "context_id": 1, "valid_until": "2030-01-01"}],
            "relying_parties": [{"org_name": "Example Bank", "scope": "verify"}],
            "issued_at": _iso(issued), "expires_at": _iso(issued + timedelta(hours=ttl_hours)), "algorithm": "ML-DSA-65",
        }
        sig, pk = sign_with(signer["key_file"], V._registry_canonical(body))
        body["signature_hex"], body["public_key_hex"] = sig.hex(), pk
        return body

    reg = registry(PUB)
    impostor = registry(STRANGER)                       # a stranger publishing in A's name
    tampered = dict(reg); bb = bytearray.fromhex(tampered["signature_hex"]); bb[0] ^= 0x01; tampered["signature_hex"] = bb.hex()
    expired = registry(PUB, issued=now - timedelta(days=3))
    v = V.verify_registry(reg, trusted_anchors=[PUB["key_hex"]])

    checks = [
        ("the registry is authentic (two witnesses) and fresh", bool(v["registry_authentic"] and v["fresh"]), True),
        ("... and signed by the key it lists for its own publisher", v["note"], None),
        ("... and trusted under an anchor set that includes the publisher", v["issuer_trusted"], True),
        ("a service is DISCOVERED from it (the timestamp path template)",
         (V.registry_service(reg, "timestamp") or {}).get("path"), "/api/v1/timestamp/{agency_id}"),
        ("an unknown service kind is simply absent", V.registry_service(reg, "teleport"), None),
        ("an authority is looked up by key", (V.registry_authority(reg, PEER["key_hex"]) or {}).get("agency_id"), 2),
        ("the in-context trust graph: A attests B's key in context 1", V.registry_trusts(reg, PEER["key_hex"], 1), [1]),
        ("... and not in another context (non-transitive, in-context)", V.registry_trusts(reg, PEER["key_hex"], 2), []),
        ("a STRANGER's registry in the publisher's name is rejected (self-consistency)",
         V.verify_registry(impostor)["registry_authentic"], False),
        ("a tampered registry is not authentic", V.verify_registry(tampered)["registry_authentic"], False),
        ("an expired registry is authentic but not fresh",
         (V.verify_registry(expired)["registry_authentic"], V.verify_registry(expired)["fresh"]), (True, False)),
        ("untrusted under an anchor set that excludes the publisher (authentic, not trusted)",
         V.verify_registry(reg, trusted_anchors=[STRANGER["key_hex"]])["issuer_trusted"], False),
        ("institutional only: no token, holder, or verification record in the registry",
         all(k not in json.dumps(reg).lower() for k in ("token_value", "individual", "verificationevent")), True),
        ("hostile input does not crash the verifier", V.verify_registry("not a dict")["registry_authentic"], False),
    ]

    print("case                                                                       got        expected   ok")
    ok_all = True
    for label, got, expected in checks:
        ok = got == expected
        ok_all = ok_all and ok
        print("  %-72s %-10s %-10s %s" % (label, str(got), str(expected), "OK" if ok else "WRONG"))
    if ok_all:
        print("\nOK: a signed registry verifies offline under real ML-DSA-65 -- signed by the key it lists for its "
              "own publisher, fresh, trusted by the consumer's anchor decision -- and services, authorities, and the "
              "in-context trust graph are discovered from it; an impostor, a tampered copy, and an expired copy are caught.")
        return 0
    print("\nFAIL: a registry verdict was wrong.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
