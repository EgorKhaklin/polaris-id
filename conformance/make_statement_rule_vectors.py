#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the statement-rule conformance vectors and cases (1.0.0-rc.68).

Three wire-specification rules that a correctly SIGNED statement can still break, each of which
some verifier here skipped until 2026-09-30 (an audit of every MUST against all three):

  WIRE-SPEC 3.9, a timestamp: `digest_algorithm` MUST be SHA3-256 and `digest_hex` its lowercase
    hex; and `issued_at` is an instant. All three verifiers accepted a SHA-1 algorithm and an
    uppercase digest; both SDKs accepted an impossible date.
  WIRE-SPEC 3.3, a revocation feed: `revoked_count` MUST equal the number of distinct leaves.
    Both SDKs compared only the root; the detached verifier read `true` as one.
  WIRE-SPEC 3.1, a manifest: it MUST be signed by one of its own active anchors. All three
    verifiers enforced it and nothing pinned it: removed from all three, every suite passed.

Each refusal sits beside a positive control signed by the same fresh key, so the refusal is the
rule's and not the signature's. Every expected value is checked against the detached verifier
and the Python SDK before anything is written. Never modifies a published vector.

    python3 conformance/make_statement_rule_vectors.py
"""
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"
SINCE = "1.0.0-rc.68"
VEC = "conformance/vectors/"
NOW = "2026-06-01T00:00:00Z"
TS_KEYS = ["format", "authority", "digest_hex", "digest_algorithm", "nonce", "issued_at", "algorithm"]


def main():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError as e:
        print("needs cryptography with ML-DSA (>=48): %s" % e, file=sys.stderr)
        return 3
    spec = importlib.util.spec_from_file_location("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)
    sys.path.insert(0, str(ROOT / "sdk" / "python"))
    import polaris_verify as P  # noqa: E402

    def key():
        sk = mldsa.MLDSA65PrivateKey.generate()
        return sk, sk.public_key().public_bytes_raw().hex()

    def canon(obj, keys):
        return json.dumps({k: obj.get(k) for k in keys}, sort_keys=True, separators=(",", ":")).encode("utf-8")

    files, cases = {}, []

    def case(name, artifact, obj, authentic, note, now=None):
        files[name + ".json"] = obj
        c = {"name": name, "artifact": artifact, "object_file": VEC + name + ".json",
             "expect": {"authentic": authentic}, "since": SINCE, "note": note}
        if now:
            c["now"] = now
        cases.append(c)

    # --- 3.9 timestamps --------------------------------------------------------------------
    t_sk, t_pk = key()
    digest = hashlib.sha3_256(b"conformance statement-rule document").hexdigest()

    def timestamp(**over):
        t = {"format": "polaris-timestamp/1", "authority": {"agency_id": 1, "name": "Conformance Timestamp Authority"},
             "digest_hex": digest, "digest_algorithm": "SHA3-256", "nonce": "statement-rule-nonce",
             "issued_at": "2026-05-01T12:00:00Z", "algorithm": "ML-DSA-65"}
        t.update(over)
        t["signature_hex"] = t_sk.sign(hashlib.sha3_256(canon(t, TS_KEYS)).digest()).hex()
        t["public_key_hex"] = t_pk
        return t

    case("timestamp-rules-control", "timestamp", timestamp(), True,
         "The positive control for the timestamp-rule cases: the same key, a lowercase SHA3-256 digest.")
    case("timestamp-digest-algorithm-not-sha3", "timestamp", timestamp(digest_algorithm="SHA-1"), False,
         "WIRE-SPEC 3.9: digest_algorithm MUST be SHA3-256. Signed and otherwise well formed; before this "
         "case all three verifiers here accepted it.")
    case("timestamp-digest-hex-uppercase", "timestamp", timestamp(digest_hex=digest.upper()), False,
         "WIRE-SPEC 3.9: digest_hex MUST be the LOWERCASE SHA3-256 hex. Before this case all three "
         "verifiers here accepted the uppercase spelling.")
    case("timestamp-issued-at-not-an-instant", "timestamp", timestamp(issued_at="2026-02-31T00:00:00Z"), False,
         "A timestamp binds a digest to an instant, and 31 February is none. Before this case both SDKs "
         "accepted it; the detached verifier refused it.")

    # --- 3.3 revocation feeds ----------------------------------------------------------------
    template = json.loads((OUT / "revocation-feed-valid.json").read_text(encoding="utf-8"))
    f_sk, f_pk = key()

    def feed(leaves, count):
        f = {k: template[k] for k in ("format", "authority", "epoch_number", "as_of", "issued_at", "expires_at",
                                      "algorithm")}
        f.update(revoked_leaves=leaves, revoked_count=count, revoked_root_hex=V.revoked_root(leaves))
        f["signature_hex"] = f_sk.sign(hashlib.sha3_256(V._revocation_feed_canonical(f)).digest()).hex()
        f["public_key_hex"] = f_pk
        return f

    two = template["revoked_leaves"][:2]
    case("revocation-feed-rules-control", "revocation-feed", feed(two, 2), True,
         "The positive control for the feed-count cases: two leaves, counted as two.", NOW)
    case("revocation-feed-count-mismatch", "revocation-feed", feed(two, 1), False,
         "WIRE-SPEC 3.3: revoked_count MUST equal the number of distinct leaves. The root matches the two "
         "leaves and the signed count says one; before this case both SDKs accepted it.", NOW)
    case("revocation-feed-count-not-a-number", "revocation-feed", feed(two[:1], True), False,
         "A count of true is not one leaf (WIRE-SPEC section 1): before this case the detached verifier read "
         "it as 1.", NOW)

    # --- 3.1 manifests -------------------------------------------------------------------------
    r_sk, r_pk = key()
    s_sk, s_pk = key()
    base = json.loads((OUT / "cross-authority-manifest.json").read_text(encoding="utf-8"))

    def manifest(sk, pk):
        m = {k: base[k] for k in ("format", "authority", "attestations", "epoch", "revocation", "algorithm")}
        m.update(anchors=[{"public_key_hex": r_pk, "status": "active"}],
                 issued_at="2026-05-01T00:00:00Z", expires_at="2026-12-31T00:00:00Z")
        m["signature_hex"] = sk.sign(hashlib.sha3_256(V._manifest_canonical(m)).digest()).hex()
        m["public_key_hex"] = pk
        return m

    case("federation-manifest-rules-control", "federation-manifest", manifest(r_sk, r_pk), True,
         "The positive control: the manifest is signed by its own declared active anchor.", NOW)
    case("federation-manifest-signed-by-a-stranger", "federation-manifest", manifest(s_sk, s_pk), False,
         "WIRE-SPEC 3.1: a manifest MUST be signed by one of its own active anchors, so a stranger key "
         "cannot mint one. Every verifier here enforced it and nothing pinned it: with the rule removed "
         "from all three, every suite still passed.", NOW)

    for c in cases:
        obj = files[c["name"] + ".json"]
        d = V.verify_timestamp(obj)["timestamp_authentic"] if c["artifact"] == "timestamp" else (
            V.verify_revocation_feed(obj, now=NOW)["feed_authentic"] if c["artifact"] == "revocation-feed"
            else V.verify_manifest(obj, now=NOW)["manifest_authentic"])
        s = P.verify_signed_artifact(obj, now=c.get("now")).authentic
        if (bool(d), bool(s)) != (c["expect"]["authentic"],) * 2:
            print("a verifier disagrees with %s: detached=%s sdk=%s" % (c["name"], d, s), file=sys.stderr)
            return 1

    for name, obj in files.items():
        (OUT / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    mine = {c["name"] for c in cases}
    doc["cases"] = [c for c in doc["cases"] if c.get("name") not in mine] + cases
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote %d vectors and %d cases (total %d)" % (len(files), len(cases), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
