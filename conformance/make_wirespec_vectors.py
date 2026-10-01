#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the WIRE-SPEC rule vectors and cases (1.0.0-rc.69).

Three rules of docs/reference/WIRE-SPEC.md that a read of every verifier requirement found the
three verifiers here disagreeing on, or none of them enforcing:

  3.3, 3.16  a revoked leaf and an epoch leaf are each a SHA3-256: 64 hex digits. A leaf of
             another type was turned into a string before hashing, and Python and JavaScript
             turn `null` and `1.0` into different strings, so one signed feed had two verdicts.
  3.12       a signed document's digest_algorithm MUST be SHA3-256 and its digest_hex lowercase.
             No verifier checked either; a timestamp (3.9) has been held to the same rule since
             1.0.0-rc.68.
  2.2        a window is read to the microsecond. The TypeScript SDK rounded instants to the
             millisecond, so a checkpoint issued 100 microseconds after `now` was fresh there and
             not yet valid in both Python verifiers.

Each refusal sits beside a control signed by the same key that differs from it in the one thing
the rule reads. Every expected value is checked against the detached verifier and the Python SDK
before anything is written. Never modifies a published vector: every file here is new.

    python3 conformance/make_wirespec_vectors.py
"""
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"
SINCE = "1.0.0-rc.69"
VEC = "conformance/vectors/"


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

    def load(name):
        o = json.loads((OUT / name).read_text(encoding="utf-8"))
        for k in ("signature_hex", "public_key_hex", "_vector"):
            o.pop(k, None)
        return o

    def signed(obj, canonical):
        sk = mldsa.MLDSA65PrivateKey.generate()
        obj["signature_hex"] = sk.sign(hashlib.sha3_256(canonical(obj)).digest()).hex()
        obj["public_key_hex"] = sk.public_key().public_bytes_raw().hex()
        return obj

    def sha3(text):
        return hashlib.sha3_256(text.encode("utf-8")).hexdigest()

    files, cases = {}, []

    def case(name, artifact, fname, obj, expect, note, now=None):
        files[fname] = obj
        c = {"name": name, "artifact": artifact, "object_file": VEC + fname}
        if now is not None:
            c["now"] = now
        c.update({"expect": expect, "since": SINCE, "note": note})
        cases.append(c)

    # --- 3.3: a revoked leaf is 64 hex digits ---------------------------------------------------
    feed = load("revocation-feed-valid.json")
    good_leaf = feed["revoked_leaves"][0]
    for name, leaves, root, ok, note in (
            ("revocation-feed-leaf-rules-control", [good_leaf], V.revoked_root([good_leaf]), True,
             "The positive control: the same feed, re-signed, listing one genuine leaf."),
            ("revocation-feed-leaf-null-python-root", [None], sha3("none"), False,
             "A null leaf, its root computed as Python spells it (\"none\"). Both Python verifiers "
             "accepted this feed and the TypeScript SDK refused it."),
            ("revocation-feed-leaf-null-javascript-root", [None], sha3("null"), False,
             "The same null leaf, its root computed as JavaScript spells it (\"null\"). The TypeScript "
             "SDK accepted this feed and both Python verifiers refused it."),
            ("revocation-feed-leaf-a-number", [1.0], sha3("1.0"), False,
             "A leaf that is the number 1.0, rooted as Python spells it. A leaf is a SHA3-256, so 64 "
             "hex digits; anything else is refused before the root is computed.")):
        f = copy.deepcopy(feed)
        f.update(revoked_leaves=leaves, revoked_root_hex=root, revoked_count=1)
        case(name, "revocation-feed", name + ".json", signed(f, V._revocation_feed_canonical),
             {"authentic": True, "fresh": True} if ok else {"authentic": False}, note,
             now="2026-06-01T00:00:00Z")

    # --- 3.16: an epoch leaf is 64 hex digits too ------------------------------------------------
    bundle = load("epoch-leaves-valid.json")
    leaves = list(bundle["all_leaves_hex"])
    leaves[0] = "not-a-sha3-digest"
    b = copy.deepcopy(bundle)
    b.update(all_leaves_hex=leaves, leaves_root_hex=V._leaves_root(leaves))
    case("epoch-leaves-leaf-not-hex", "epoch-leaves", "epoch-leaves-leaf-not-hex.json",
         signed(b, V._epoch_leaves_canonical), {"authentic": False},
         "A published anonymity set with one entry that is not a SHA3-256, its commitment "
         "recomputed over it. Every verifier here accepted it; the entries are SHA3-256 hexes "
         "(WIRE-SPEC 3.16), so the set is refused.", now="2026-05-01T00:00:30Z")
    b2 = copy.deepcopy(bundle)
    case("epoch-leaves-leaf-rules-control", "epoch-leaves", "epoch-leaves-leaf-rules-control.json",
         signed(b2, V._epoch_leaves_canonical), {"authentic": True, "fresh": True},
         "The positive control: the published set, re-signed.", now="2026-05-01T00:00:30Z")

    # --- 3.12: a signed document binds a lowercase SHA3-256 digest ------------------------------
    doc = load("signed-document-valid.json")
    for name, change, ok, note in (
            ("signed-document-digest-rules-control", {}, True,
             "The positive control: the published document, re-signed."),
            ("signed-document-digest-algorithm-not-sha3", {"digest_algorithm": "MD5"}, False,
             "The same document labelled MD5. WIRE-SPEC 3.12: digest_algorithm MUST be SHA3-256. No "
             "verifier here checked it."),
            ("signed-document-digest-hex-uppercase", {"digest_hex": doc["document"]["digest_hex"].upper()}, False,
             "The same digest in upper case. WIRE-SPEC 3.12: digest_hex MUST be lowercase. No verifier "
             "here checked it, and the detached verifier's binding compared a lowercased copy.")):
        d = copy.deepcopy(doc)
        d["document"].update(change)
        case(name, "signed-document", name + ".json", signed(d, V._signed_document_canonical),
             {"authentic": ok}, note)

    # --- 2.2: a window is read to the microsecond ------------------------------------------------
    cp = load("epoch-checkpoint-valid.json")
    cp.update(issued_at="2026-05-01T00:00:00.000200Z")
    cp = signed(cp, V._epoch_checkpoint_canonical)
    for name, now, fresh, note in (
            ("epoch-checkpoint-issued-microseconds-ahead", "2026-05-01T00:00:00.000100Z", False,
             "A checkpoint issued 100 microseconds after `now`. WIRE-SPEC 2.2: issued_at <= now. The "
             "TypeScript SDK rounded both instants to the millisecond and read it as fresh; both Python "
             "verifiers read it as not yet valid."),
            ("epoch-checkpoint-issued-microseconds-behind", "2026-05-01T00:00:00.000300Z", True,
             "The positive control: the same checkpoint 100 microseconds after it was issued.")):
        case(name, "epoch-checkpoint", "epoch-checkpoint-issued-microseconds.json", cp,
             {"authentic": True, "fresh": fresh}, note, now=now)

    # Every expected value, against the detached verifier and the Python SDK, before writing.
    detached = {"revocation-feed": (V.verify_revocation_feed, "feed_authentic"),
                "epoch-leaves": (V.verify_epoch_leaves, "leaves_authentic"),
                "signed-document": (V.verify_signed_document, "document_authentic"),
                "epoch-checkpoint": (V.verify_epoch_checkpoint, "checkpoint_authentic")}
    for c in cases:
        o = files[c["object_file"][len(VEC):]]
        fn, key = detached[c["artifact"]]
        dv = fn(o) if c["artifact"] == "signed-document" else fn(o, now=c.get("now"))
        sv = P.verify_signed_artifact(o, now=c.get("now"))
        got = {"authentic": (bool(dv[key]), sv.authentic)}
        want = {"authentic": (c["expect"]["authentic"],) * 2}
        if "fresh" in c["expect"]:
            got["fresh"] = (dv.get("fresh"), sv.fresh)
            want["fresh"] = (c["expect"]["fresh"],) * 2
        if got != want:
            print("a verifier disagrees with %s: got %r, expected %r" % (c["name"], got, want), file=sys.stderr)
            return 1

    for name, o in files.items():
        (OUT / name).write_text(json.dumps(o, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    doc_cases = json.loads(CASES.read_text(encoding="utf-8"))
    mine = {c["name"] for c in cases}
    doc_cases["cases"] = [c for c in doc_cases["cases"] if c.get("name") not in mine] + cases
    CASES.write_text(json.dumps(doc_cases, indent=2) + "\n", encoding="utf-8")
    print("wrote %d vectors and %d cases (total %d)" % (len(files), len(cases), len(doc_cases["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
