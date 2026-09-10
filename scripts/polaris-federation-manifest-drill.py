#!/usr/bin/env python3
"""
polaris-federation-manifest-drill.py — the inter-authority protocol, run (P3.2).

Two independent authorities, each its own real ML-DSA-65 root (the federated topology
of docs/design/federation-topology.md). Each publishes a signed FEDERATION MANIFEST:
its own anchors, and the attestations it has made (who it accepts, in which context).
A relying party then decides whether to accept a credential from a FOREIGN authority
OFFLINE, from those manifests alone, with no issuer contact and no database.

    authority A ── issues token_A (signed by root_A)
    authority B ── publishes a manifest: "I accept A's key in context 1" (signed by root_B)
    relying party (trusts B) ── accepts token_A in context 1, because B attests to it

The drill checks the matrix and FAILS (exit 1) if any accept/reject is wrong: the
attestation is per-context (a foreign token in an un-attested context is rejected),
the relying party must trust the manifest's authority, a manifest must be signed by one
of its own declared anchors, and a stale manifest or a forged credential is rejected.
Needs liboqs + cryptography.

    python3 scripts/polaris-federation-manifest-drill.py
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
    os.environ["POLARIS_USE_REAL_PQC"] = "1"
    try:
        import pqc_signing
    except Exception as e:
        print("manifest drill needs the app's pqc_signing (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not (pqc_signing.is_available() and pqc_signing.second_witness_available()):
        print("manifest drill needs real ML-DSA (liboqs + cryptography); skipping", file=sys.stderr)
        return 3

    V = _load_verifier()
    tmp = tempfile.mkdtemp(prefix="polaris-manifest-")

    def issuer(name):
        kp = pqc_signing.generate_keypair()
        kf = os.path.join(tmp, "%s.key.json" % name)
        with open(kf, "w") as f:
            json.dump(kp, f)
        return {"name": name, "key_file": kf, "key_hex": kp["public_key_hex"], "agency_id": name}

    def sign_with(key_file, message):
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_file
        sig, _alg, pk = pqc_signing.signature_over_message(message)
        return sig, pk

    def pack_for(issuer_, token_value):
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = issuer_["key_file"]
        sig, alg, pk = pqc_signing.signature_with_key_for_token(token_value)
        return {"format": "polaris-authenticity-pack/1", "token_value": token_value,
                "algorithm": alg, "signature_hex": sig.hex(), "public_key_hex": pk}

    def manifest_for(issuer_, attestations, ttl_hours=24, issued=None):
        now = issued or datetime.now(timezone.utc)
        body = {
            "format": "polaris-federation-manifest/1",
            "authority": {"agency_id": issuer_["agency_id"], "name": issuer_["name"]},
            "anchors": [{"public_key_hex": issuer_["key_hex"], "algorithm": "ML-DSA-65", "status": "active"}],
            "attestations": attestations,
            "epoch": {"number": 1, "root_hex": "00" * 16},
            "revocation": {"as_of": _iso(now), "count": 0},
            "issued_at": _iso(now),
            "expires_at": _iso(now + timedelta(hours=ttl_hours)),
            "algorithm": "ML-DSA-65",
        }
        canonical = V._manifest_canonical(body)
        sig, pk = sign_with(issuer_["key_file"], canonical)
        body["signature_hex"], body["public_key_hex"] = sig.hex(), pk
        return body

    A, B, C = issuer("A"), issuer("B"), issuer("C")
    token_a = pack_for(A, "FED-TOKEN-A-0001")
    # B attests to A's key in context 1 (not context 2).
    b_attests_a = manifest_for(B, [{"attested_agency_id": "A", "attested_public_key_hex": A["key_hex"], "context_id": 1}])
    b_attests_none = manifest_for(B, [])
    b_signed_by_stranger = dict(b_attests_a)
    _sig, _pk = sign_with(C["key_file"], V._manifest_canonical({k: b_attests_a.get(k) for k in
                          ("format", "authority", "anchors", "attestations", "epoch", "revocation", "issued_at", "expires_at", "algorithm")}))
    b_signed_by_stranger = dict(b_attests_a); b_signed_by_stranger["signature_hex"], b_signed_by_stranger["public_key_hex"] = _sig.hex(), _pk
    b_expired = manifest_for(B, [{"attested_agency_id": "A", "attested_public_key_hex": A["key_hex"], "context_id": 1}],
                             ttl_hours=1, issued=datetime.now(timezone.utc) - timedelta(hours=2))
    tampered_token = dict(token_a)
    bb = bytearray.fromhex(tampered_token["signature_hex"]); bb[0] ^= 0x01
    tampered_token["signature_hex"] = bb.hex()

    # P9.5: a trust edge signed by the agency that made it, and the three ways it stops
    # binding. Until v9.348 an edge was a row an operator recorded and the manifest signed on
    # their behalf; a signed edge is evidence in its own right.
    def signed_edge(attester, attested, context_id, over=None):
        edge = {"format": "polaris-trust-attestation/1",
                "attesting_agency_id": attester["agency_id"], "attested_agency_id": attested["agency_id"],
                "attested_public_key_hex": (over or attested["key_hex"]), "context_id": context_id,
                "attested_date": _iso(datetime.now(timezone.utc) - timedelta(days=1)).replace("Z", ""),
                "valid_until": "2027-01-01", "algorithm": "ML-DSA-65"}
        sig, pk = sign_with(attester["key_file"], V._attestation_canonical(edge))
        edge["signature_hex"], edge["public_key_hex"] = sig.hex(), pk
        edge["attested_public_key_hex"] = attested["key_hex"]   # published beside the credential key
        return edge

    edge_ok = signed_edge(B, A, 1)
    b_signed = manifest_for(B, [edge_ok])
    # An edge signed over ANOTHER key: the attester never saw the key it is now vouching for.
    edge_rekeyed = signed_edge(B, A, 1, over=C["key_hex"])
    b_rekeyed = manifest_for(B, [edge_rekeyed])
    # An edge whose context was widened after signing.
    edge_widened = dict(signed_edge(B, A, 2)); edge_widened["context_id"] = 1
    b_widened = manifest_for(B, [edge_widened])
    # An edge whose signature names a different attesting agency than the manifest publishing it.
    edge_wrong_attester = signed_edge(C, A, 1)
    b_wrong_attester = manifest_for(B, [edge_wrong_attester])
    b_unsigned = manifest_for(B, [{"attested_agency_id": "A", "attested_public_key_hex": A["key_hex"], "context_id": 1}])

    trust_B = [B["key_hex"]]
    checks = [
        ("P9.5: B's SIGNED edge for A in ctx1",
         V.verify_cross_authority(token_a, 1, [b_signed], trusted_anchors=trust_B), "accept"),
        ("P9.5: the same, with signed edges REQUIRED",
         V.verify_cross_authority(token_a, 1, [b_signed], trusted_anchors=trust_B,
                                  require_signed_attestation=True), "accept"),
        ("P9.5: an edge signed over ANOTHER key",
         V.verify_cross_authority(token_a, 1, [b_rekeyed], trusted_anchors=trust_B), "reject"),
        ("P9.5: an edge widened to another context after signing",
         V.verify_cross_authority(token_a, 1, [b_widened], trusted_anchors=trust_B), "reject"),
        ("P9.5: an edge signed by an agency other than the publisher",
         V.verify_cross_authority(token_a, 1, [b_wrong_attester], trusted_anchors=trust_B), "reject"),
        ("P9.5: an UNSIGNED legacy edge still decides",
         V.verify_cross_authority(token_a, 1, [b_unsigned], trusted_anchors=trust_B), "accept"),
        ("P9.5: ... but not when signed edges are REQUIRED",
         V.verify_cross_authority(token_a, 1, [b_unsigned], trusted_anchors=trust_B,
                                  require_signed_attestation=True), "reject"),
        ("A-token, B attests A in ctx1, RP trusts B",
         V.verify_cross_authority(token_a, 1, [b_attests_a], trusted_anchors=trust_B), "accept"),
        ("same, but wrong context (ctx2)",
         V.verify_cross_authority(token_a, 2, [b_attests_a], trusted_anchors=trust_B), "reject"),
        ("B attests to nobody",
         V.verify_cross_authority(token_a, 1, [b_attests_none], trusted_anchors=trust_B), "reject"),
        ("RP does not trust B",
         V.verify_cross_authority(token_a, 1, [b_attests_a], trusted_anchors=[C["key_hex"]]), "reject"),
        ("manifest signed by a stranger key",
         V.verify_cross_authority(token_a, 1, [b_signed_by_stranger], trusted_anchors=trust_B), "reject"),
        ("expired manifest",
         V.verify_cross_authority(token_a, 1, [b_expired], trusted_anchors=trust_B), "reject"),
        ("forged credential",
         V.verify_cross_authority(tampered_token, 1, [b_attests_a], trusted_anchors=trust_B), "reject"),
    ]

    print("case                                       decision   expected  ok")
    ok_all = True
    for label, v, expected in checks:
        ok = v["decision"] == expected
        ok_all = ok_all and ok
        print("  %-40s %-9s  %-8s  %s" % (label, v["decision"].upper(), expected.upper(), "OK" if ok else "WRONG"))
    if ok_all:
        print("\nOK: two authorities interoperate through signed manifests -- a foreign credential is "
              "accepted OFFLINE iff a trusted authority attests to its key in the presented context.")
        return 0
    print("\nFAIL: an inter-authority decision was wrong.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
