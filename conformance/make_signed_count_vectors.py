#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the signed-count conformance vectors and cases (1.1.0).

WIRE-SPEC section 1: a count or size a signature covers is read one way in every language, so one
signed artifact gets one verdict. polaris-verify reads it as an integer from 0 to 2**53 - 1 (never
a boolean, a string, null or `1.0`), and until 2026-10-21 the two SDKs did not. Both accepted a
tree head signed with a size of 2**53 or 10**20, which polaris-verify refused; and the Python SDK
accepted a count the signer wrote as `1.0`, which polaris-verify refused and the TypeScript SDK
refused at the signature (JSON.parse reads `1.0` as 1, so its canonical bytes say `1`).

  transparency-sth-size-2-53-minus-1  a head of size 2**53 - 1, the positive control: authentic
  transparency-sth-size-2-53          a head of size 2**53: refused
  transparency-sth-size-10-20         a head of size 10**20: refused
  revocation-feed-count-one           one leaf counted as 1, the positive control: authentic
  revocation-feed-count-one-point-zero  one leaf counted as `1.0`: refused

Each refusal sits beside a control signed by the same fresh key, so the refusal is the rule's and
not the signature's. Every expected value is checked against the detached verifier's conformance
adapter and the Python SDK before anything is written. It never re-signs a published vector:
with any of them on disk it exits 2 and writes nothing.

    python3 conformance/make_signed_count_vectors.py
"""
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"
SINCE = "1.1.0"
VEC = "conformance/vectors/"
NOW = "2026-06-01T00:00:00Z"
PROVENANCE = "real ML-DSA-65 (pyca/cryptography); conformance/make_signed_count_vectors.py"
NAMES = ("transparency-sth-size-2-53-minus-1", "transparency-sth-size-2-53", "transparency-sth-size-10-20",
         "revocation-feed-count-one", "revocation-feed-count-one-point-zero")


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def main():
    published = [n for n in NAMES if (OUT / (n + ".json")).exists()]
    if published:
        print("refusing: %d of these vectors are published, and a published vector is never re-signed: %s"
              % (len(published), ", ".join(published)), file=sys.stderr)
        return 2
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError as e:
        print("needs cryptography with ML-DSA (>=48): %s" % e, file=sys.stderr)
        return 3
    V = _load("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    sys.path.insert(0, str(ROOT / "scripts"))
    harness = _load("polaris_conformance_harness", ROOT / "scripts" / "test_verify_conformance.py")
    sys.path.insert(0, str(ROOT / "sdk" / "python"))
    import polaris_verify as P  # noqa: E402

    files, cases = {}, []

    def case(name, artifact, obj, authentic, note, now=None):
        obj["_vector"] = {"name": name, "provenance": PROVENANCE}
        files[name + ".json"] = obj
        c = {"name": name, "artifact": artifact, "object_file": VEC + name + ".json",
             "expect": {"authentic": authentic}, "since": SINCE, "note": note}
        if now:
            c["now"] = now
        cases.append(c)

    # --- a tree head's size (WIRE-SPEC 3.6) ---------------------------------------------------
    h_sk = mldsa.MLDSA65PrivateKey.generate()
    h_pk = h_sk.public_key().public_bytes_raw().hex()

    def head(size):
        h = {"format": "polaris-transparency-sth/1", "log_id": "polaris-audit-anchor-log", "tree_size": size,
             "root_hash_hex": hashlib.sha3_256(b"conformance signed-count head %d" % size).hexdigest(),
             "timestamp": "2026-05-01T00:00:00Z", "algorithm": "ML-DSA-65"}
        h["signature_hex"] = h_sk.sign(hashlib.sha3_256(V._sth_canonical(h)).digest()).hex()
        h["public_key_hex"] = h_pk
        return h

    case("transparency-sth-size-2-53-minus-1", "transparency-sth", head(2 ** 53 - 1), True,
         "The positive control for the head-size cases: a head of size 2**53 - 1, the largest every "
         "verifier holds exactly, signed by the same key (WIRE-SPEC section 1).")
    case("transparency-sth-size-2-53", "transparency-sth", head(2 ** 53), False,
         "A size a signature covers is an integer from 0 to 2**53 - 1 (WIRE-SPEC section 1). JavaScript "
         "reads 2**53 + 1 as 2**53, so past 2**53 - 1 one signed size has two readings. Before this case "
         "both SDKs accepted this head; the detached verifier refused it.")
    case("transparency-sth-size-10-20", "transparency-sth", head(10 ** 20), False,
         "The same rule far past the bound: JavaScript holds 10**20 exactly and writes it as Python does, "
         "so the signature verifies everywhere and only the rule refuses the head. Before this case both "
         "SDKs accepted it; the detached verifier refused it.")

    # --- a signed count (WIRE-SPEC 3.3) --------------------------------------------------------
    template = json.loads((OUT / "revocation-feed-valid.json").read_text(encoding="utf-8"))
    f_sk = mldsa.MLDSA65PrivateKey.generate()
    f_pk = f_sk.public_key().public_bytes_raw().hex()

    def feed(count):
        leaves = template["revoked_leaves"][:1]
        f = {k: template[k] for k in ("format", "authority", "epoch_number", "as_of", "issued_at", "expires_at",
                                      "algorithm")}
        f.update(revoked_leaves=leaves, revoked_count=count, revoked_root_hex=V.revoked_root(leaves))
        f["signature_hex"] = f_sk.sign(hashlib.sha3_256(V._revocation_feed_canonical(f)).digest()).hex()
        f["public_key_hex"] = f_pk
        return f

    case("revocation-feed-count-one", "revocation-feed", feed(1), True,
         "The positive control for the count written as 1.0: one leaf, counted as the integer 1, signed by "
         "the same key.", NOW)
    case("revocation-feed-count-one-point-zero", "revocation-feed", feed(1.0), False,
         "A signed count is an integer, and the signer wrote 1.0 (WIRE-SPEC section 1). JavaScript reads it "
         "as 1, so a JavaScript verifier's canonical bytes say 1 and the signature over the bytes the signer "
         "wrote fails there. Before this case the Python SDK accepted it; the detached verifier refused it.",
         NOW)

    # The Python SDK first, in memory; then the detached verifier through its conformance adapter,
    # which reads each vector from disk as the published case will. On any disagreement the
    # vectors are removed and nothing is published.
    wrong = ["%s: python-sdk=%s" % (c["name"], P.verify_signed_artifact(files[c["name"] + ".json"],
                                                                         now=c.get("now")).authentic)
             for c in cases
             if P.verify_signed_artifact(files[c["name"] + ".json"], now=c.get("now")).authentic
             is not c["expect"]["authentic"]]
    for name, obj in files.items():
        (OUT / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for c in cases:
        got = harness._verdict_for(c)
        wrong += ["%s: detached %s=%s" % (c["name"], k, got.get(k)) for k, v in c["expect"].items()
                  if got.get(k) != v]
    if wrong:
        for name in files:
            (OUT / name).unlink()
        print("NOT PUBLISHED, a verifier disagrees with the expected verdict:\n  " + "\n  ".join(wrong),
              file=sys.stderr)
        return 1
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    names = {c["name"] for c in doc["cases"]}
    doc["cases"].extend(c for c in cases if c["name"] not in names)
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote %d vectors and %d cases (total %d)" % (len(files), len(cases), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
