#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the hex-encoding conformance vectors and cases (1.0.0-rc.66, Unreleased).

A hex field holds hex digits and nothing else (WIRE-SPEC section 1: `signature_hex` and
`public_key_hex` are hex). The three verifiers read malformed hex three ways. The TypeScript
SDK decoded each pair with parseInt, which stops at the first character it cannot read, so
"eg" decoded as 0x0e; the two Python verifiers use bytes.fromhex, which skips whitespace
between bytes. Each accepted a genuine signature re-spelled in a way the others refused.

The vectors are the published genuine pack (vectors/ml-dsa-65-valid.json) with one field
re-spelled so that the lenient reader of the other side decodes the same bytes:

    pack-signature-hex-not-hex     a "0X" pair of signature_hex written "Xg"
    pack-signature-hex-whitespace  a space between the first two bytes of signature_hex
    pack-public-key-hex-not-hex    a "0X" pair of public_key_hex written "Xg"

Each MUST NOT verify. The genuine pack is the control (the published case `valid`), so the
refusal is the encoding rule's and not a bad signature's: the generator checks that undoing
the re-spelling gives back the genuine bytes, and every expected value against the detached
verifier, before anything is written. Never modifies a published vector: every file here is new.

    python3 conformance/make_hex_encoding_vectors.py
"""
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"
SINCE = "1.0.0-rc.66"
VEC = "conformance/vectors/"


def _not_hex(hex_str):
    """The first byte written "0X", re-spelled "Xg": what a parseInt reader decodes as 0X."""
    for i in range(0, len(hex_str), 2):
        if hex_str[i] == "0":
            return hex_str[:i] + hex_str[i + 1] + "g" + hex_str[i + 2:]
    raise ValueError("no byte below 0x10 to re-spell")


def main():
    spec = importlib.util.spec_from_file_location("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)

    genuine = json.loads((ROOT / "vectors" / "ml-dsa-65-valid.json").read_text(encoding="utf-8"))
    genuine = {k: v for k, v in genuine.items() if not k.startswith("_")}
    sig, pk = genuine["signature_hex"], genuine["public_key_hex"]
    variants = {
        "pack-signature-hex-not-hex": (
            {"signature_hex": _not_hex(sig)},
            "a byte of signature_hex written with a character that is not hex; a reader that stops "
            "at the first bad character decodes the genuine signature"),
        "pack-signature-hex-whitespace": (
            {"signature_hex": sig[:2] + " " + sig[2:]},
            "a space between two bytes of signature_hex; a reader that skips whitespace decodes "
            "the genuine signature"),
        "pack-public-key-hex-not-hex": (
            {"public_key_hex": _not_hex(pk)},
            "a byte of public_key_hex written with a character that is not hex; a reader that stops "
            "at the first bad character decodes the genuine key"),
    }
    files, cases = {}, []
    for name, (change, why) in variants.items():
        pack = dict(genuine, **change)
        # Undo the re-spelling the way each lenient reader did: the bytes must be the genuine ones.
        for field, value in change.items():
            lenient = bytes(int(value.replace(" ", "")[i:i + 2].rstrip("g") or "0", 16)
                            for i in range(0, len(value.replace(" ", "")), 2))
            if lenient != bytes.fromhex(genuine[field]):
                print("%s: the re-spelled %s does not decode to the genuine bytes" % (name, field), file=sys.stderr)
                return 1
        files[name + ".json"] = dict(pack, _vector={"expect": "invalid", "name": name, "note": why + "; MUST NOT verify"})
        cases.append({"name": name, "artifact": "authenticity-pack", "pack_file": VEC + name + ".json",
                      "expect": {"authentic": False}, "since": SINCE,
                      "note": "A hex field holds hex digits and nothing else: " + why + ". Before this case "
                              "the TypeScript SDK accepted a character that is not hex and the Python "
                              "verifiers accepted whitespace, each where the others refused."})

    # Every expected value, against the detached verifier, before anything is written; and the
    # control: the genuine pack verifies, so each refusal is the encoding's.
    if not V.verify_pack(genuine, None)["signature_valid"]:
        print("the genuine pack does not verify: nothing here would discriminate", file=sys.stderr)
        return 1
    for c in cases:
        v = V.verify_pack(files[c["name"] + ".json"], None)
        if bool(v["signature_valid"]) is not c["expect"]["authentic"]:
            print("the detached verifier disagrees with %s: %s" % (c["name"], v.get("note")), file=sys.stderr)
            return 1

    for name, obj in files.items():
        (OUT / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    # These cases are this generator's own, so a rerun replaces them in place.
    mine = {c["name"] for c in cases}
    doc["cases"] = [c for c in doc["cases"] if c.get("name") not in mine] + cases
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote %d vectors and %d cases (total %d)" % (len(files), len(cases), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
