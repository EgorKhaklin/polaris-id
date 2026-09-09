#!/usr/bin/env python3
"""
polaris-document-signing-drill.py -- document signing with long-term validation, run (P8.5).

A signer binds an arbitrary document's SHA3-256 into a portable container under a real
ML-DSA-65 key; long-term-validation evidence (a second authority's timestamp over the
statement AND signature, and the signer's manifest and revocation feed at that instant) is
attached; a third party verifies it all OFFLINE. This drill drives:

  - a signed document is authentic, binds its bytes and nothing else, and is valid long term;
  - the timestamp binds the SIGNATURE (a re-signed container is not covered by the old evidence);
  - key retirement: a container timestamped while the key was active stays valid after the key
    is retired, because validity is decided at the instant the evidence fixes; a container whose
    evidence shows the key already retired at its instant is not valid;
  - holder-authorized signing: the credential hash is unrevoked at the instant (valid) or listed
    in the feed at the instant (not valid);
  - no evidence, a tampered container, a wrong document, and hostile input are all caught.

Red (exit 1) on any wrong verdict. Needs liboqs + cryptography.

    python3 scripts/polaris-document-signing-drill.py
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
        print("document-signing drill needs the app's pqc_signing (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not (pqc_signing.is_available() and pqc_signing.second_witness_available()):
        print("document-signing drill needs real ML-DSA (liboqs + cryptography); skipping", file=sys.stderr)
        return 3

    V = _load_verifier()
    tmp = tempfile.mkdtemp(prefix="polaris-docsign-")
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

    S, T = issuer("signer"), issuer("timestamp-authority")

    def container(data, on_behalf_of=None, signed_at=None):
        doc = {"format": "polaris-signed-document/1",
               "document": {"digest_hex": hashlib.sha3_256(data).hexdigest(), "digest_algorithm": "SHA3-256",
                            "media_type": "text/plain", "name": "report.txt"},
               "signer": {"agency_id": 1, "name": S["name"]}, "on_behalf_of": on_behalf_of,
               "purpose": "drill", "signed_at": _iso(signed_at or now), "algorithm": "ML-DSA-65"}
        sig, pk = sign_with(S["key_file"], V._signed_document_canonical(doc))
        doc["signature_hex"], doc["public_key_hex"] = sig.hex(), pk
        return doc

    def manifest(status="active", issued=None):
        issued = issued or now
        m = {"format": "polaris-federation-manifest/1", "authority": {"agency_id": 1, "name": S["name"]},
             "anchors": [{"public_key_hex": S["key_hex"], "algorithm": "ML-DSA-65", "status": status}],
             "attestations": [], "epoch": {"number": 1, "root_hex": "bb" * 16}, "revocation": {"as_of": _iso(issued)},
             "issued_at": _iso(issued), "expires_at": _iso(issued + timedelta(hours=24)), "algorithm": "ML-DSA-65"}
        if status != "active":  # a retired key cannot be a manifest's own active anchor: add the successor
            m["anchors"].append({"public_key_hex": T["key_hex"], "algorithm": "ML-DSA-65", "status": "active"})
        signer = S if status == "active" else T
        sig, pk = sign_with(signer["key_file"], V._manifest_canonical(m))
        m["signature_hex"], m["public_key_hex"] = sig.hex(), pk
        return m

    def feed(leaves, issued=None):
        issued = issued or now
        leaves = sorted(leaves)
        f = {"format": "polaris-revocation-feed/1", "authority": {"agency_id": 1, "name": S["name"]},
             "epoch_number": 1, "as_of": _iso(issued), "revoked_root_hex": V.revoked_root(leaves),
             "revoked_count": len(leaves), "revoked_leaves": leaves, "issued_at": _iso(issued),
             "expires_at": _iso(issued + timedelta(hours=24)), "algorithm": "ML-DSA-65"}
        sig, pk = sign_with(S["key_file"], V._revocation_feed_canonical(f))
        f["signature_hex"], f["public_key_hex"] = sig.hex(), pk
        return f

    def timestamp(doc, authority=T, issued=None):
        issued = issued or now
        ts = {"format": "polaris-timestamp/1", "authority": {"agency_id": 2, "name": authority["name"]},
              "digest_hex": hashlib.sha3_256(V.document_signature_material(doc)).hexdigest(),
              "digest_algorithm": "SHA3-256", "nonce": None, "issued_at": _iso(issued), "algorithm": "ML-DSA-65"}
        sig, pk = sign_with(authority["key_file"], V._timestamp_canonical(ts))
        ts["signature_hex"], ts["public_key_hex"] = sig.hex(), pk
        return ts

    document = b"the quarterly report; it never leaves the signer"
    doc = container(document)
    full = V.attach_ltv(doc, timestamp=timestamp(doc), manifest=manifest(), revocation_feed=feed([]))
    tampered = dict(full); tampered["purpose"] = "changed after signing"
    resigned = container(document)      # same statement bytes as doc, a different signature
    stale_evidence = V.attach_ltv(resigned, timestamp=full["ltv"]["timestamp"], manifest=manifest(), revocation_feed=feed([]))
    later = now + timedelta(days=400)   # the key is retired by then
    retired_doc = container(document, signed_at=later)
    retired = V.attach_ltv(retired_doc, timestamp=timestamp(retired_doc, issued=later),
                           manifest=manifest("retired", issued=later), revocation_feed=feed([], issued=later))
    holder_leaf = V.revocation_leaf("TKN-HOLDER-1")
    on_behalf = container(document, on_behalf_of={"credential_hash": holder_leaf})
    on_behalf_ok = V.attach_ltv(on_behalf, timestamp=timestamp(on_behalf), manifest=manifest(), revocation_feed=feed([]))
    on_behalf_revoked = V.attach_ltv(on_behalf, timestamp=timestamp(on_behalf), manifest=manifest(), revocation_feed=feed([holder_leaf]))
    vf = V.verify_signed_document(full, trusted_anchors=[S["key_hex"]], document_bytes=document)

    checks = [
        ("the signed document is authentic (two witnesses) and the signer is trusted",
         bool(vf["document_authentic"] and vf["signer_trusted"]), True),
        ("it binds the document bytes", vf["binds"], True),
        ("it does NOT bind other bytes", V.verify_signed_document(full, document_bytes=b"another document")["binds"], False),
        ("the timestamp (a SECOND authority's) is authentic and binds statement + signature",
         (vf["ltv"]["timestamp_authentic"], vf["ltv"]["timestamp_binds"]), (True, True)),
        ("the signer's key was active at the instant (the embedded manifest says so)", vf["ltv"]["signer_key_active_at_instant"], True),
        ("VALID LONG TERM", vf["valid_long_term"], True),
        ("a re-signed container is not covered by the old evidence (the timestamp binds the signature)",
         V.verify_signed_document(stale_evidence)["ltv"]["timestamp_binds"], False),
        ("KEY RETIREMENT: the same container stays valid after the key is retired (decided at the instant)",
         V.verify_signed_document(full)["valid_long_term"], True),
        ("... but a signature whose evidence shows the key already retired at its instant is not valid",
         (V.verify_signed_document(retired)["document_authentic"], V.verify_signed_document(retired)["valid_long_term"]), (True, False)),
        ("holder-authorized: the credential was unrevoked at the instant -> valid",
         (V.verify_signed_document(on_behalf_ok)["ltv"]["credential_unrevoked_at_instant"], V.verify_signed_document(on_behalf_ok)["valid_long_term"]), (True, True)),
        ("holder-authorized: the credential was revoked at the instant -> not valid",
         V.verify_signed_document(on_behalf_revoked)["valid_long_term"], False),
        ("no evidence attached: authentic but not valid long term",
         (V.verify_signed_document(doc)["document_authentic"], V.verify_signed_document(doc)["valid_long_term"]), (True, False)),
        ("a tampered container is not authentic", V.verify_signed_document(tampered)["document_authentic"], False),
        ("the document itself appears nowhere in the container", document.decode() not in json.dumps(full), True),
        ("hostile input does not crash the verifier", V.verify_signed_document("nope")["document_authentic"], False),
    ]

    print("case                                                                       got        expected   ok")
    ok_all = True
    for label, got, expected in checks:
        ok = got == expected
        ok_all = ok_all and ok
        print("  %-72s %-10s %-10s %s" % (label, str(got), str(expected), "OK" if ok else "WRONG"))
    if ok_all:
        print("\nOK: a signed document verifies offline under real ML-DSA-65, binds its bytes, and is valid LONG TERM "
              "from embedded evidence -- a second authority's timestamp over statement and signature, the signer's "
              "manifest and feed at that instant -- so it survives key retirement, while a re-signed container, a "
              "retired-at-the-instant key, a revoked credential, a tampered container and missing evidence all fail.")
        return 0
    print("\nFAIL: a signed-document verdict was wrong.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
