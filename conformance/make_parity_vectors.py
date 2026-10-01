#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the SDK parity vectors and cases (1.0.0-rc.70).

A function-by-function comparison of the two reference SDKs found signed bytes on which they
answered differently, and no published case constrained the answer:

  instants     the Python verifiers' `\\d` matched any script's digits and `strip()` removed a
               file separator; the TypeScript SDK's `trim()` removed a byte-order mark, it read
               an offset of 24 hours, and Date.UTC read years 0 to 99 as 1900 onwards;
  numbers      Python writes a non-integral number below 1e-4 in exponent form ("1.5e-05"),
               which the TypeScript SDK's canonical form wrote as "0.000015", so it refused a
               genuine grant signed with one;
  key order    Python sorts object keys by code point and JavaScript by UTF-16 unit, so a key
               outside the Basic Multilingual Plane moved and the TypeScript SDK refused a
               genuine registry carrying one;
  agency ids   Python's `==` matched a missing publisher id with a null one, and True with 1.

Each refusal sits beside a control. Every expected value is checked against the detached
verifier and the Python SDK before anything is written; the TypeScript SDK is held to the same
cases by the conformance run. Never modifies a published vector: every file here is new.

    python3 conformance/make_parity_vectors.py
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
SINCE = "1.0.0-rc.70"
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

    def key():
        sk = mldsa.MLDSA65PrivateKey.generate()
        return sk, sk.public_key().public_bytes_raw().hex()

    def signed(obj, canonical, sk=None, pk=None):
        if sk is None:
            sk, pk = key()
        obj["signature_hex"] = sk.sign(hashlib.sha3_256(canonical(obj)).digest()).hex()
        obj["public_key_hex"] = pk
        return obj

    files, cases = {}, []

    def case(name, artifact, obj, expect, note, now=None):
        files[name + ".json"] = obj
        c = {"name": name, "artifact": artifact, "object_file": VEC + name + ".json"}
        if now is not None:
            c["now"] = now
        c.update({"expect": expect, "since": SINCE, "note": note})
        cases.append(c)

    # --- instants: one grammar, read the same way ----------------------------------------------
    ts = load("timestamp-rules-control.json")
    for name, instant, ok, note in (
            ("timestamp-issued-at-year-0099", "0099-05-01T00:00:00Z", True,
             "Year 99, a valid RFC 3339 year. Both Python verifiers read it; the TypeScript SDK's "
             "Date.UTC read it as 1999 and its own check then refused the date."),
            ("timestamp-issued-at-offset-24-hours", "2026-05-01T00:00:00+24:00", False,
             "An offset of 24 hours is not one RFC 3339 allows; the TypeScript SDK read it."),
            ("timestamp-issued-at-non-ascii-digits", "\u0662\u0660\u0662\u0666-05-01T00:00:00Z", False,
             "A year in Arabic-Indic digits. Python's `\\d` matched them and int() converted them."),
            ("timestamp-issued-at-byte-order-mark", "\ufeff2026-05-01T00:00:00Z", False,
             "A leading byte-order mark, which the TypeScript SDK's trim() removed."),
            ("timestamp-issued-at-file-separator", "\u001c2026-05-01T00:00:00Z", False,
             "A leading file separator, which Python's strip() removed.")):
        t = copy.deepcopy(ts)
        t["issued_at"] = instant
        case(name, "timestamp", signed(t, V._timestamp_canonical), {"authentic": ok}, note)

    # --- numbers: a small non-integral limit is written as Python writes it -------------------
    grant = load("agent-grant-valid.json")
    g = copy.deepcopy(grant)
    g["limits"] = {"max_uses": 3, "max_amount": 0.000015}
    case("agent-grant-small-amount-limit", "agent-grant", signed(g, V._agent_grant_canonical),
         {"authentic": True},
         "A genuine grant whose signed max_amount is 0.000015, which the signer writes as 1.5e-05. The "
         "TypeScript SDK wrote it as 0.000015 when it rebuilt the statement, and refused the grant.",
         now="2026-05-01T00:00:30Z")

    # --- key order: by code point -------------------------------------------------------------
    reg = load("registry-valid.json")
    sk, pk = key()

    def publisher_key(r, pk_):
        mine = [a for a in r["authorities"] if a.get("agency_id") == 1]
        assert mine, "the published registry lists agency 1"
        mine[0]["public_key_hex"] = pk_
        mine[0].pop("keys", None)
        return r

    r = publisher_key(copy.deepcopy(reg), pk)
    r["instance"]["extensions"] = {"\uffff": "a BMP key", "\U0001F600": "a key outside the BMP"}
    case("registry-keys-outside-the-bmp", "registry", signed(r, V._registry_canonical, sk, pk),
         {"authentic": True, "fresh": True},
         "A genuine registry whose signed instance holds a key outside the Basic Multilingual Plane. "
         "Python sorts it after \"\\uffff\" (code point); the TypeScript SDK sorted it before (UTF-16 "
         "unit) and refused the registry.", now="2026-05-01T12:00:00Z")

    # --- agency ids: integers, equal ----------------------------------------------------------
    sk2, pk2 = key()
    r2 = publisher_key(copy.deepcopy(reg), pk2)
    r2["publisher"] = {k: v for k, v in r2["publisher"].items() if k != "agency_id"}
    for a in r2["authorities"]:
        if a.get("public_key_hex") == pk2:
            a["agency_id"] = None
    case("registry-publisher-agency-id-missing", "registry", signed(r2, V._registry_canonical, sk2, pk2),
         {"authentic": False},
         "A registry whose publisher names no agency id, signed by a key listed for an authority whose "
         "id is null. Python's == matched the two; the TypeScript SDK did not.", now="2026-05-01T12:00:00Z")
    tl = load("trust-list-valid.json")
    sk3, pk3 = key()
    t = copy.deepcopy(tl)
    t["publisher"]["agency_id"] = True
    t["keys"][0]["agency_id"] = 1
    t["keys"][0]["public_key_hex"] = pk3
    case("trust-list-publisher-agency-id-true", "trust-list", signed(t, V._trust_list_canonical, sk3, pk3),
         {"authentic": False},
         "A trust list whose publisher's agency id is the boolean true, signed by a key listed for "
         "agency 1. Python's == read True as 1; the TypeScript SDK did not.", now="2026-05-01T12:00:00Z")
    t2 = copy.deepcopy(tl)
    sk4, pk4 = key()
    t2["keys"][0]["public_key_hex"] = pk4
    case("trust-list-publisher-agency-id-control", "trust-list", signed(t2, V._trust_list_canonical, sk4, pk4),
         {"authentic": True, "fresh": True},
         "The positive control: the published trust list, signed by a key it lists for its own "
         "publisher.", now="2026-05-01T12:00:00Z")

    # Every expected value, against the detached verifier and the Python SDK, before writing.
    detached = {"timestamp": (V.verify_timestamp, "timestamp_authentic"),
                "agent-grant": (V.verify_agent_grant, "grant_authentic"),
                "registry": (V.verify_registry, "registry_authentic"),
                "trust-list": (V.verify_trust_list, "trust_list_authentic")}
    for c in cases:
        o = files[c["object_file"][len(VEC):]]
        fn, k = detached[c["artifact"]]
        dv = fn(o) if c["artifact"] == "timestamp" else fn(o, now=c.get("now"))
        sv = P.verify_signed_artifact(o, now=c.get("now"))
        got = (bool(dv[k]), sv.authentic)
        want = (c["expect"]["authentic"],) * 2
        if got != want:
            print("a verifier disagrees with %s: detached, sdk = %r, expected %r" % (c["name"], got, want),
                  file=sys.stderr)
            return 1

    for name, o in files.items():
        (OUT / name).write_text(json.dumps(o, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    mine = {c["name"] for c in cases}
    doc["cases"] = [c for c in doc["cases"] if c.get("name") not in mine] + cases
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote %d vectors and %d cases (total %d)" % (len(files), len(cases), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
