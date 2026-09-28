#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the federation-variant conformance vectors: one genuine cross-authority setup and
signed variants of it, each wrong in exactly one fact the trust decision must check.

2026-09-23 a held-out round removed rules from both SDKs' verify_cross_authority one at a time:
with the rule gone, a stale manifest, trust in a retired anchor, an attestation of another key, a
badly signed attestation, and a revocation feed that was stale, by another issuer or not
authentic were each accepted with every test green. The code was right and its tests were
missing; sdk/testdata/federation-variants.json added them to the SDK suites. The PUBLISHED
contract never carried those inputs, so a verifier written against it could skip all seven checks
and still conform. Measured 2026-09-28: a copy of the Python SDK with each rule removed passed
all 159 cases then published, and each is caught by exactly one case here.

The base setup is decided twice as the positive controls, with no feed and with a clean one:
without them a verifier that refuses everything would pass every variant. The one variant not
published here is an unsigned edge under `require_signed_attestation`, which is a caller's
option the case format does not carry.

Each vector is decided by the detached verifier before it is written. Keys are fresh per run.

    python3 conformance/make_federation_variant_vectors.py
"""
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"

#: The instant every cross-authority case is decided at.
NOW = "2026-06-01T00:00:00Z"
SINCE = "1.0.0-rc.66"
PROVENANCE = "real ML-DSA-65 (liboqs); conformance/make_federation_variant_vectors.py"


def main():
    try:
        import oqs  # type: ignore
    except Exception as e:  # noqa: BLE001
        print("needs liboqs-python: %s" % e, file=sys.stderr)
        return 3
    spec = importlib.util.spec_from_file_location("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)

    def keypair():
        with oqs.Signature("ML-DSA-65") as s:
            return bytes(s.generate_keypair()), bytes(s.export_secret_key())

    def sign(sk, digest):
        with oqs.Signature("ML-DSA-65", secret_key=sk) as s:
            return bytes(s.sign(digest))

    issuer_pk, issuer_sk = keypair()        # authority A: issued the credential, publishes its feed
    authority_pk, authority_sk = keypair()  # authority B: attests A's key in its manifest
    retired_pk, _ = keypair()               # a key B lists as RETIRED
    stranger_pk, stranger_sk = keypair()    # a key nobody attests

    token = "TKN-XA-VARIANTS-1"
    pack = {"format": "polaris-authenticity-pack/1", "algorithm": "ML-DSA-65", "token_value": token,
            "public_key_hex": issuer_pk.hex(),
            "signature_hex": sign(issuer_sk, hashlib.sha3_256(token.encode("utf-8")).digest()).hex(),
            "_vector": {"name": "cross-authority-variants-pack", "provenance": PROVENANCE,
                        "note": "A's authenticity pack, decided against each manifest and feed variant"}}

    def manifest(name, note, expires="2026-06-30T00:00:00Z", attested=None, attestation_extra=None):
        att = {"attested_agency_id": 1, "attested_public_key_hex": (attested or issuer_pk).hex(),
               "context_id": 1}
        att.update(attestation_extra or {})
        m = {"format": "polaris-federation-manifest/1", "algorithm": "ML-DSA-65",
             "authority": {"agency_id": 2, "name": "Authority B"},
             "anchors": [{"public_key_hex": authority_pk.hex(), "algorithm": "ML-DSA-65", "status": "active"},
                         {"public_key_hex": retired_pk.hex(), "algorithm": "ML-DSA-65", "status": "retired"}],
             "attestations": [att], "epoch": {"number": 1, "root_hex": "bb" * 32},
             "revocation": {"as_of": "2026-05-31T00:00:00Z"},
             "issued_at": "2026-05-31T00:00:00Z", "expires_at": expires,
             "public_key_hex": authority_pk.hex()}
        m["signature_hex"] = sign(authority_sk, hashlib.sha3_256(V._manifest_canonical(m)).digest()).hex()
        m["_vector"] = {"name": name, "note": note, "provenance": PROVENANCE}
        return m

    def feed(name, note, signer_sk=None, signer_pk=None, expires="2026-06-30T00:00:00Z"):
        f = {"format": "polaris-revocation-feed/1", "algorithm": "ML-DSA-65",
             "authority": {"agency_id": 1, "name": "Authority A"}, "epoch_number": 1,
             "as_of": "2026-05-31T00:00:00Z", "revoked_root_hex": V.revoked_root([]),
             "revoked_count": 0, "revoked_leaves": [],
             "issued_at": "2026-05-31T00:00:00Z", "expires_at": expires,
             "public_key_hex": (signer_pk or issuer_pk).hex()}
        f["signature_hex"] = sign(signer_sk or issuer_sk,
                                  hashlib.sha3_256(V._revocation_feed_canonical(f)).digest()).hex()
        f["_vector"] = {"name": name, "note": note, "provenance": PROVENANCE}
        return f

    base = manifest("cross-authority-variants-manifest",
                    "B attests A's key in context 1, fresh at now; the base every variant differs from")
    variants_m = {
        "stale": manifest("cross-authority-variants-manifest-stale",
                          "the base manifest with a window that closed before now",
                          expires="2026-05-15T00:00:00Z"),
        "other-key": manifest("cross-authority-variants-manifest-other-key",
                              "the base manifest attesting a key that is not the credential's",
                              attested=stranger_pk),
        "bad-attestation-signature": manifest(
            "cross-authority-variants-manifest-bad-attestation-signature",
            "the base edge carrying a signature that does not verify: a present-but-bad "
            "signature refuses the edge, which is stricter than an absent one",
            attestation_extra={"format": "polaris-trust-attestation/1", "algorithm": "ML-DSA-65",
                               "public_key_hex": authority_pk.hex(), "signature_hex": "00" * 3309}),
    }
    clean = feed("cross-authority-variants-feed-clean", "A's feed, authentic, fresh, revoking nothing")
    stale_feed = feed("cross-authority-variants-feed-stale", "A's feed with a window that closed before now",
                      expires="2026-05-15T00:00:00Z")
    other_issuer = feed("cross-authority-variants-feed-other-issuer",
                        "a genuine feed signed by a key that is not the credential issuer's",
                        signer_sk=stranger_sk, signer_pk=stranger_pk)
    not_authentic = feed("cross-authority-variants-feed-not-authentic", "A's clean feed with its signature altered")
    sig = not_authentic["signature_hex"]
    not_authentic["signature_hex"] = ("0" if sig[0] != "0" else "1") + sig[1:]

    files = {"cross-authority-variants-pack.json": pack, "cross-authority-variants-manifest.json": base,
             "cross-authority-variants-feed-clean.json": clean,
             "cross-authority-variants-feed-stale.json": stale_feed,
             "cross-authority-variants-feed-other-issuer.json": other_issuer,
             "cross-authority-variants-feed-not-authentic.json": not_authentic}
    for key, m in variants_m.items():
        files["cross-authority-variants-manifest-%s.json" % key] = m

    def case(name, manifest_file, want, note, feed_file=None, anchors="manifest"):
        c = {"name": name, "artifact": "cross-authority",
             "pack_file": "conformance/vectors/cross-authority-variants-pack.json",
             "manifest_files": ["conformance/vectors/%s" % manifest_file],
             "trusted_anchors": anchors, "context_id": 1, "now": NOW,
             "expect": {"decision": want}, "since": SINCE, "note": note}
        if feed_file:
            c["feed_file"] = "conformance/vectors/%s" % feed_file
        return c

    base_file = "cross-authority-variants-manifest.json"
    new = [
        case("cross-authority-variants-base", base_file, "accept",
             "The positive control: the genuine setup every variant below differs from in one fact."),
        case("cross-authority-variants-feed-clean", base_file, "accept",
             "The positive control for the feed variants: an authentic, fresh feed from the issuer "
             "that revokes nothing.", feed_file="cross-authority-variants-feed-clean.json"),
        case("cross-authority-variants-manifest-stale", "cross-authority-variants-manifest-stale.json",
             "reject", "A manifest past its own window confers nothing, however genuine."),
        case("cross-authority-variants-attestation-other-key",
             "cross-authority-variants-manifest-other-key.json", "reject",
             "An edge that attests another key does not attest this credential's issuer."),
        case("cross-authority-variants-attestation-bad-signature",
             "cross-authority-variants-manifest-bad-attestation-signature.json", "reject",
             "A present-but-invalid edge signature refuses the edge (wire spec section 3.14)."),
        case("cross-authority-variants-retired-anchor", base_file, "reject",
             "Trusting only a key the manifest lists as RETIRED confers no trust in it.",
             anchors=[retired_pk.hex()]),
        case("cross-authority-variants-feed-stale", base_file, "reject",
             "A supplied feed must be fresh (wire spec section 4, item 3): fail-closed.",
             feed_file="cross-authority-variants-feed-stale.json"),
        case("cross-authority-variants-feed-other-issuer", base_file, "reject",
             "A supplied feed must be bound to the issuer's key: another authority's word about "
             "this credential is not the issuer's.", feed_file="cross-authority-variants-feed-other-issuer.json"),
        case("cross-authority-variants-feed-not-authentic", base_file, "reject",
             "A supplied feed must be authentic: a forged or altered one rejects.",
             feed_file="cross-authority-variants-feed-not-authentic.json"),
    ]

    # Decide each case with the detached verifier before anything is written.
    for c in new:
        ms = [files[p.rsplit("/", 1)[1]] for p in c["manifest_files"]]
        anchors = c["trusted_anchors"]
        if anchors == "manifest":
            anchors = sorted({a["public_key_hex"] for m in ms for a in m["anchors"] if a["status"] == "active"})
        fd = files[c["feed_file"].rsplit("/", 1)[1]] if "feed_file" in c else None
        got = V.verify_cross_authority(pack, 1, ms, now=NOW, trusted_anchors=anchors, revocation_feed=fd)
        assert got["decision"] == c["expect"]["decision"], (c["name"], got)

    for fname, obj in files.items():
        (OUT / fname).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    names = {c["name"] for c in doc["cases"]}
    doc["cases"].extend(c for c in new if c["name"] not in names)
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote %d vectors, %d cases (total %d)" % (len(files), len(new), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
