#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the hostile-shape conformance vectors and cases (1.0.0-rc.68).

On 2026-09-30 every published case was run through the three verifiers with each field of
what a presenter controls replaced by a value of the wrong type, and the verdicts compared.
Where two verifiers disagreed, or all three accepted what WIRE-SPEC refuses, one of these
cases now says which answer is right. Each vector is a published one with one change and no
new signature, so every refusal is the rule's and not a bad signature's:

    federation-status-bundle-count-mismatch   the commitment-mismatch bundle with one of its two
        identical members removed: its root now matches, and its signed member_count (2) does
        not (WIRE-SPEC 3.4). Both SDKs accepted it.
    timestamp-anchor-proof-index-not-a-number  "index": false
    timestamp-anchor-proof-size-not-a-number   "tree_size": "1"
    timestamp-anchor-proof-path-not-a-list     "proof_hex": {}
        each on the one-leaf anchor of timestamp-anchor-variants-base, whose proof is index 0,
        size 1 and an empty path, so a verifier that coerces the malformed field reads the
        genuine proof back. All three verifiers accepted each of these.
    agent-grant-use-principal-credential-forged  the grant-principal chain with one bit of the
        credential's signature flipped. All three verifiers bound the grant to it.
    agent-grant-use-principal-no-credential      the same chain with no credential at all. The
        detached verifier bound the grant to it.

The generator checks every expected value against the detached verifier and the Python SDK,
and the controls (the lenient reading gives the genuine field back; the published base case
verifies), before anything is written. Never modifies a published vector.

    python3 conformance/make_hostile_shape_vectors.py
"""
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"
SINCE = "1.0.0-rc.68"
VEC = "conformance/vectors/"


def _load(name):
    return json.loads((OUT / name).read_text(encoding="utf-8"))


def main():
    spec = importlib.util.spec_from_file_location("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)
    sys.path.insert(0, str(ROOT / "sdk" / "python"))
    import polaris_verify as P  # noqa: E402

    files, cases, checks = {}, [], []

    # 1. The status bundle whose signed count and listed members disagree.
    b = _load("federation-status-bundle-commitment-mismatch.json")
    bundle = dict(b, members=b["members"][:1],
                  _vector={"expect": "invalid", "name": "federation-status-bundle-count-mismatch",
                           "note": "its members match members_root_hex; its signed member_count does not"})
    if V.bundle_members_root(bundle["members"]) != bundle["members_root_hex"]:
        print("control: the one-member root does not match, so the case would not isolate the count",
              file=sys.stderr)
        return 1
    files["federation-status-bundle-count-mismatch.json"] = bundle
    cases.append({"name": "federation-status-bundle-count-mismatch", "artifact": "federation-status-bundle",
                  "object_file": VEC + "federation-status-bundle-count-mismatch.json",
                  "expect": {"authentic": False}, "since": SINCE,
                  "note": "WIRE-SPEC 3.4: member_count MUST equal the number of members. The root matches "
                          "the one member listed and the signed count says two; before this case both "
                          "SDKs accepted it and only the detached verifier refused."})
    checks.append(("federation-status-bundle-count-mismatch",
                   lambda: V.verify_status_bundle(bundle)["bundle_authentic"],
                   lambda: P.verify_signed_artifact(bundle).authentic))

    # 2. Inclusion proofs with a field of the wrong type, on the one-leaf anchor.
    base = _load("timestamp-anchor-variants-base.json")
    proof = base["anchor"]["proof"]
    if (proof.get("index"), proof.get("tree_size"), proof.get("proof_hex")) != (0, 1, []):
        print("the base anchor is not the one-leaf proof these variants assume", file=sys.stderr)
        return 1
    base_case = next(c for c in json.loads(CASES.read_text(encoding="utf-8"))["cases"]
                     if c["name"] == "timestamp-anchor-variants-base")
    witnesses = sorted({x["public_key_hex"] for x in base["anchor"].get("cosignatures", [])})
    for name, change, lenient, why in (
            ("timestamp-anchor-proof-index-not-a-number", {"index": False}, ("index", int(False)),
             "an index of false, which int() and Number() both read as 0"),
            ("timestamp-anchor-proof-size-not-a-number", {"tree_size": "1"}, ("tree_size", int("1")),
             "a tree size written as the string \"1\", which int() and Number() both read as 1"),
            ("timestamp-anchor-proof-path-not-a-list", {"proof_hex": {}}, ("proof_hex", list({})),
             "an audit path that is an object, which `or []` and a non-array fallback both read as the empty path")):
        field, value = lenient
        if proof[field] != value:
            print("%s: the lenient reading does not give back the genuine %s" % (name, field), file=sys.stderr)
            return 1
        ts = json.loads(json.dumps(base))
        ts["anchor"]["proof"].update(change)
        ts["_vector"] = {"expect": "not anchored", "name": name, "note": why + "; MUST NOT be anchored"}
        files[name + ".json"] = ts
        cases.append({"name": name, "artifact": "timestamp-anchor", "timestamp_file": VEC + name + ".json",
                      "log_key": base_case["log_key"], "trusted_witnesses": base_case["trusted_witnesses"],
                      "threshold": base_case["threshold"], "expect": {"anchored": False}, "since": SINCE,
                      "note": "An inclusion proof's index and tree size are JSON integers and its path a "
                              "list (WIRE-SPEC, anchoring): " + why + ". Read leniently it is the genuine "
                              "one-leaf proof of timestamp-anchor-variants-base; before this case the "
                              "three verifiers each accepted it."})
        log_key = ts["anchor"]["sth"]["public_key_hex"]
        checks.append((name,
                       lambda ts=ts, lk=log_key: V.verify_timestamp_anchor(ts, log_key=lk, trusted_witnesses=witnesses,
                                                                           threshold=2)["anchored"],
                       lambda ts=ts, lk=log_key: P.verify_timestamp_anchor(ts, log_key=lk, trusted_witnesses=witnesses,
                                                                           threshold=2).anchored))

    # 3. The grant-principal chain with a forged credential, and with none.
    cred = _load("grant-principal-credential.json")
    sig = bytearray(bytes.fromhex(cred["signature_hex"]))
    sig[0] ^= 0x01
    forged = dict(cred, signature_hex=sig.hex(),
                  _vector={"expect": "invalid", "name": "grant-principal-credential-forged",
                           "note": "the grant-principal credential with one bit of its signature flipped"})
    files["grant-principal-credential-forged.json"] = forged
    principal = next(c for c in json.loads(CASES.read_text(encoding="utf-8"))["cases"]
                     if c["name"] == "agent-grant-use-principal-stranger")
    common = {"artifact": "agent-grant-use", "grant_file": VEC + "grant-principal-grant.json",
              "binding_file": VEC + "grant-principal-binding-active.json", "now": principal["now"],
              "since": SINCE}
    cases.append(dict(common, name="agent-grant-use-principal-credential-forged",
                      credential_file=VEC + "grant-principal-credential-forged.json",
                      expect={"authentic": True, "principal_bound": False},
                      note="WIRE-SPEC 3.17 names the issuer's signature on the credential as a link a "
                           "verifier MUST check. The binding names this credential and is signed by its "
                           "key, and the credential's signature does not verify; before this case all "
                           "three verifiers bound the grant to it."))
    cases.append(dict(common, name="agent-grant-use-principal-no-credential",
                      expect={"authentic": True, "principal_bound": False},
                      note="A binding with no credential beside it binds the holder key to nothing a "
                           "verifier has checked; before this case the detached verifier bound it."))
    grant, binding = _load("grant-principal-grant.json"), _load("grant-principal-binding-active.json")
    now = principal["now"]
    for name, credential in (("agent-grant-use-principal-credential-forged", forged),
                             ("agent-grant-use-principal-no-credential", None)):
        checks.append((name,
                       lambda c=credential: V.verify_agent_grant(grant, binding=binding, credential=c,
                                                                 now=V._parse_iso(now))["principal_bound"],
                       lambda c=credential: P.grant_principal_bound(grant, binding, c or {}, now)))
    # The control for 3: the genuine credential binds.
    if not (V.verify_agent_grant(grant, binding=binding, credential=cred, now=V._parse_iso(now))["principal_bound"]
            and P.grant_principal_bound(grant, binding, cred, now)):
        print("control: the genuine grant-principal chain is not bound, so nothing here discriminates",
              file=sys.stderr)
        return 1

    # Every expected value, before anything is written: a refusal under both verifiers here.
    for name, detached, sdk in checks:
        got = (bool(detached()), bool(sdk()))
        if got != (False, False):
            print("a verifier accepts %s (detached, sdk) = %s" % (name, got), file=sys.stderr)
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
