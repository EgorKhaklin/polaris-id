#!/usr/bin/env python3
"""
polaris-trust-lifecycle-drill.py -- the trust-service lifecycle, run (P8.7b).

An authority key's life -- registered, retired, COMPROMISED from an instant that may predate
the discovery -- is published in a signed trust list, and a verifier decides a key's status AT
AN INSTANT from it, independently of the signer's own word. This drill builds a trust list
under real ML-DSA-65 roots and drives:

  - the trust list is authentic, fresh, signed by a key it lists as active for its publisher;
    an impostor's list, a list signed under the publisher's RETIRED key, and a tampered list are
    refused;
  - status at an instant: before registration unknown; active; retired from its instant;
    compromised from ITS instant even where that predates the recording;
  - COMPROMISE RECOVERY: a credential under a compromised issuer key is rejected by the
    cross-authority decision given the trust list; a long-term-validated document signed and
    timestamped BEFORE the compromise instant stays valid, one AFTER does not; after rotation
    the new key is active and the old one is not, and the old key's signatures are decided by
    their instants;
  - hostile input does not crash the verifier.

Red (exit 1) on any wrong verdict. Needs liboqs + cryptography.

    python3 scripts/polaris-trust-lifecycle-drill.py
"""
import hashlib
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
        print("trust-lifecycle drill needs the app's pqc_signing (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not (pqc_signing.is_available() and pqc_signing.second_witness_available()):
        print("trust-lifecycle drill needs real ML-DSA (liboqs + cryptography); skipping", file=sys.stderr)
        return 3

    V = _load_verifier()
    tmp = tempfile.mkdtemp(prefix="polaris-trust-")
    now = datetime.now(timezone.utc)
    T_REG, T_COMP, T_ROT = now - timedelta(days=365), now - timedelta(days=30), now - timedelta(days=10)

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

    PUB, PUB_OLD, ISS_OLD, ISS_NEW, STRANGER = issuer("publisher"), issuer("publisher-old"), issuer("issuer-old"), issuer("issuer-new"), issuer("stranger")

    def entry(who, agency_id, name, status, reg=T_REG, ret=None, comp=None):
        return {"agency_id": agency_id, "name": name, "public_key_hex": who["key_hex"], "algorithm": "ML-DSA-65",
                "status": status, "registered_at": _iso(reg), "retired_at": _iso(ret) if ret else None,
                "compromised_at": _iso(comp) if comp else None}

    def trust_list(keys, signer=PUB, issued=None):
        issued = issued or now
        tl = {"format": "polaris-trust-list/1", "publisher": {"agency_id": 1, "name": "Publisher"}, "keys": keys,
              "issued_at": _iso(issued), "expires_at": _iso(issued + timedelta(hours=24)), "algorithm": "ML-DSA-65"}
        sig, pk = sign_with(signer["key_file"], V._trust_list_canonical(tl))
        tl["signature_hex"], tl["public_key_hex"] = sig.hex(), pk
        return tl

    keys_before = [entry(PUB, 1, "Publisher", "active"), entry(PUB_OLD, 1, "Publisher", "retired", ret=T_ROT),
                   entry(ISS_OLD, 2, "Issuer", "active")]
    keys_after = [entry(PUB, 1, "Publisher", "active"), entry(PUB_OLD, 1, "Publisher", "retired", ret=T_ROT),
                  entry(ISS_OLD, 2, "Issuer", "compromised", comp=T_COMP),     # discovered now, effective 30 days ago
                  entry(ISS_NEW, 2, "Issuer", "active", reg=T_ROT)]
    tl_before, tl_after = trust_list(keys_before), trust_list(keys_after)
    impostor = trust_list(keys_after, signer=STRANGER)
    under_retired = trust_list(keys_after, signer=PUB_OLD)
    tampered = dict(tl_after); tampered["keys"] = list(keys_after); tampered["keys"][2] = dict(keys_after[2], status="active")
    v_after = V.verify_trust_list(tl_after, trusted_anchors=[PUB["key_hex"]])

    # a credential issued under the (later compromised) issuer key, with a manifest attesting it
    def manifest_for(iss_keys, signer):
        m = {"format": "polaris-federation-manifest/1", "authority": {"agency_id": 1, "name": "Publisher"},
             "anchors": [{"public_key_hex": PUB["key_hex"], "algorithm": "ML-DSA-65", "status": "active"}],
             "attestations": [{"attested_agency_id": 2, "attested_public_key_hex": k, "context_id": 1, "valid_until": "2030-01-01"} for k in iss_keys],
             "epoch": {"number": 1, "root_hex": "bb" * 16}, "revocation": {"as_of": _iso(now)},
             "issued_at": _iso(now), "expires_at": _iso(now + timedelta(hours=24)), "algorithm": "ML-DSA-65"}
        sig, pk = sign_with(signer["key_file"], V._manifest_canonical(m))
        m["signature_hex"], m["public_key_hex"] = sig.hex(), pk
        return m

    os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = ISS_OLD["key_file"]
    sig, alg, pk = pqc_signing.signature_with_key_for_token("TKN-OLD-KEY-1")
    pack_old = {"format": "polaris-authenticity-pack/1", "token_value": "TKN-OLD-KEY-1", "algorithm": alg, "signature_hex": sig.hex(), "public_key_hex": pk}
    os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = ISS_NEW["key_file"]
    sig2, alg2, pk2 = pqc_signing.signature_with_key_for_token("TKN-NEW-KEY-1")
    pack_new = {"format": "polaris-authenticity-pack/1", "token_value": "TKN-NEW-KEY-1", "algorithm": alg2, "signature_hex": sig2.hex(), "public_key_hex": pk2}
    manifest = manifest_for([ISS_OLD["key_hex"], ISS_NEW["key_hex"]], PUB)

    # documents signed by the old issuer key, with LTV evidence timestamped before / after the compromise
    def signed_doc(signer, when):
        doc = {"format": "polaris-signed-document/1",
               "document": {"digest_hex": hashlib.sha3_256(b"the deed").hexdigest(), "digest_algorithm": "SHA3-256", "media_type": None, "name": "deed"},
               "signer": {"agency_id": 2, "name": "Issuer"}, "on_behalf_of": None, "purpose": "drill",
               "signed_at": _iso(when), "algorithm": "ML-DSA-65"}
        s, p = sign_with(signer["key_file"], V._signed_document_canonical(doc)); doc["signature_hex"], doc["public_key_hex"] = s.hex(), p
        ts = {"format": "polaris-timestamp/1", "authority": {"agency_id": 1, "name": "Publisher"},
              "digest_hex": hashlib.sha3_256(V.document_signature_material(doc)).hexdigest(), "digest_algorithm": "SHA3-256",
              "nonce": None, "issued_at": _iso(when), "algorithm": "ML-DSA-65"}
        s, p = sign_with(PUB["key_file"], V._timestamp_canonical(ts)); ts["signature_hex"], ts["public_key_hex"] = s.hex(), p
        m = {"format": "polaris-federation-manifest/1", "authority": {"agency_id": 2, "name": "Issuer"},
             "anchors": [{"public_key_hex": signer["key_hex"], "algorithm": "ML-DSA-65", "status": "active"}], "attestations": [],
             "epoch": {"number": 1, "root_hex": "bb" * 16}, "revocation": {"as_of": _iso(when)},
             "issued_at": _iso(when), "expires_at": _iso(when + timedelta(hours=24)), "algorithm": "ML-DSA-65"}
        s, p = sign_with(signer["key_file"], V._manifest_canonical(m)); m["signature_hex"], m["public_key_hex"] = s.hex(), p
        return V.attach_ltv(doc, timestamp=ts, manifest=m)

    doc_before = signed_doc(ISS_OLD, T_COMP - timedelta(days=5))
    doc_after = signed_doc(ISS_OLD, T_COMP + timedelta(days=5))
    doc_new = signed_doc(ISS_NEW, now - timedelta(days=1))

    checks = [
        ("the trust list is authentic, fresh, signed by a key it lists active for its publisher, trusted",
         (v_after["trust_list_authentic"], v_after["fresh"], v_after["issuer_trusted"]), (True, True, True)),
        ("an IMPOSTOR's trust list in the publisher's name is refused", V.verify_trust_list(impostor)["trust_list_authentic"], False),
        ("a trust list signed under the publisher's RETIRED key is refused", V.verify_trust_list(under_retired)["trust_list_authentic"], False),
        ("a tampered trust list (a compromised key relabelled active) is refused", V.verify_trust_list(tampered)["trust_list_authentic"], False),
        ("status at an instant: unknown before registration", V.key_status_at(tl_after, ISS_NEW["key_hex"], T_ROT - timedelta(days=1)), None),
        ("status at an instant: the retired publisher key was active before its retirement and retired after",
         (V.key_status_at(tl_after, PUB_OLD["key_hex"], T_ROT - timedelta(days=1)), V.key_status_at(tl_after, PUB_OLD["key_hex"], T_ROT + timedelta(days=1))), ("active", "retired")),
        ("status at an instant: the compromised issuer key is active before ITS instant and compromised from it (predating the recording)",
         (V.key_status_at(tl_after, ISS_OLD["key_hex"], T_COMP - timedelta(days=1)), V.key_status_at(tl_after, ISS_OLD["key_hex"], T_COMP + timedelta(seconds=1))), ("active", "compromised")),
        ("before the compromise was recorded, the credential under the old issuer key was accepted",
         V.verify_cross_authority(pack_old, 1, [manifest], trusted_anchors=[PUB["key_hex"]], trust_list=tl_before)["decision"], "accept"),
        ("COMPROMISE RECOVERY: with the updated trust list the same credential is REJECTED (issuer key compromised)",
         V.verify_cross_authority(pack_old, 1, [manifest], trusted_anchors=[PUB["key_hex"]], trust_list=tl_after)["decision"], "reject"),
        ("... while a credential re-issued under the NEW key is accepted",
         V.verify_cross_authority(pack_new, 1, [manifest], trusted_anchors=[PUB["key_hex"]], trust_list=tl_after)["decision"], "accept"),
        ("a document signed and timestamped BEFORE the compromise instant stays valid long term (per the trust list)",
         V.verify_signed_document(doc_before, trust_list=tl_after, trusted_anchors=[PUB["key_hex"]])["valid_long_term"], True),
        ("... one signed AFTER the compromise instant is not, even though its own manifest says active",
         (V.verify_signed_document(doc_after)["valid_long_term"], V.verify_signed_document(doc_after, trust_list=tl_after, trusted_anchors=[PUB["key_hex"]])["valid_long_term"]), (True, False)),
        ("a document under the NEW key is valid long term per the trust list",
         V.verify_signed_document(doc_new, trust_list=tl_after, trusted_anchors=[PUB["key_hex"]])["valid_long_term"], True),
        ("no trust list: the decisions fall back to the issuer's own word (unchanged behaviour)",
         (V.verify_cross_authority(pack_old, 1, [manifest], trusted_anchors=[PUB["key_hex"]])["decision"], V.verify_signed_document(doc_after)["valid_long_term"]), ("accept", True)),
        ("hostile input does not crash the verifier",
         (V.verify_trust_list("nope")["trust_list_authentic"], V.key_status_at("nope", "x"), V.key_status_at(tl_after, "x", "not-a-time")), (False, None, None)),
    ]

    print("case                                                                       got        expected   ok")
    ok_all = True
    for label, got, expected in checks:
        ok = got == expected
        ok_all = ok_all and ok
        print("  %-72s %-10s %-10s %s" % (label, str(got), str(expected), "OK" if ok else "WRONG"))
    if ok_all:
        print("\nOK: a signed trust list under real ML-DSA-65 decides every authority key's status AT AN INSTANT -- a "
              "compromised issuer key rejects its credentials, a document timestamped before the compromise stays valid "
              "and one after does not, a re-issued key is accepted -- and impostor, retired-key and tampered lists are refused.")
        return 0
    print("\nFAIL: a trust-lifecycle verdict was wrong.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
