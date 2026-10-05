# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Regenerate the FN-DSA family vectors: authenticity packs under Falcon-padded-1024.

    python3 conformance/make_fndsa_vectors.py

FN-DSA is FIPS 206, still a draft; its scheme is round-3 Falcon, which liboqs implements under
the name Polaris puts on the wire, Falcon-padded-1024 (category 5, fixed-length signatures).
Polaris verifies it and signs nothing under it (lab/strategy/015). Three vectors:

  - a genuine Falcon-padded-1024 pack, which must verify;
  - the same pack with one flipped signature byte, which must not;
  - a genuine Falcon-padded-512 pack, which must be refused: category 1 is below the floor.

liboqs signs. Before anything is written, @noble/post-quantum, the TypeScript SDK's independent
implementation, must verify the genuine pack and refuse the flipped one, and the detached
verifier must agree with it on all three. A vector the two implementations disagree on is never
published. Needs liboqs-python and `npm ci` in sdk/typescript.
"""
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"
SINCE = "1.0.0-rc.71"
TOKEN = "POLARIS-CONFORMANCE-FNDSA1024-0001"

NOBLE = """
const { falcon1024padded } = await import(process.argv[1]);
const [pk, msg, good, bad] = process.argv.slice(2).map((h) => Uint8Array.from(Buffer.from(h, "hex")));
console.log(JSON.stringify({ good: falcon1024padded.verify(good, msg, pk), bad: falcon1024padded.verify(bad, msg, pk) }));
"""


def _load_verifier():
    spec = importlib.util.spec_from_file_location("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    try:
        import oqs  # type: ignore
    except Exception as e:
        print("needs liboqs-python: %s" % e, file=sys.stderr)
        return 3
    falcon_js = ROOT / "sdk" / "typescript" / "node_modules" / "@noble" / "post-quantum" / "falcon.js"
    if not falcon_js.exists():
        print("needs `npm ci` in sdk/typescript (the second, independent implementation)", file=sys.stderr)
        return 3
    V = _load_verifier()
    digest = hashlib.sha3_256(TOKEN.encode("utf-8")).digest()

    def signed(alg):
        with oqs.Signature(alg) as s:
            pk = bytes(s.generate_keypair())
            return pk, bytes(s.sign(digest))

    pk, sig = signed("Falcon-padded-1024")
    assert len(pk) == 1793 and len(sig) == 1280, (len(pk), len(sig))
    flipped = bytearray(sig)
    flipped[len(flipped) // 2] ^= 0x01
    pk512, sig512 = signed("Falcon-padded-512")

    pack = {"format": "polaris-authenticity-pack/1", "token_value": TOKEN, "algorithm": "Falcon-padded-1024",
            "signature_hex": sig.hex(), "public_key_hex": pk.hex()}
    tampered = dict(pack, signature_hex=bytes(flipped).hex())
    below = dict(pack, algorithm="Falcon-padded-512", signature_hex=sig512.hex(), public_key_hex=pk512.hex())

    # The second implementation, before anything is written.
    noble = json.loads(subprocess.run(
        ["node", "--input-type=module", "-e", NOBLE, falcon_js.as_uri(), pk.hex(), digest.hex(), sig.hex(), bytes(flipped).hex()],
        check=True, capture_output=True, text=True).stdout)
    assert noble == {"good": True, "bad": False}, noble
    print("  cross-check: @noble/post-quantum verifies the genuine pack and refuses the flipped one")
    assert V.verify_pack(pack)["signature_valid"] is True
    assert V.verify_pack(tampered)["signature_valid"] is False
    assert V.verify_pack(below)["signature_valid"] is False
    print("  the detached verifier agrees on all three")

    written = []
    for name, obj in (("pack-fndsa1024-valid.json", pack), ("pack-fndsa1024-tampered.json", tampered),
                      ("pack-fndsa512-unaccepted.json", below)):
        (OUT / name).write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
        written.append(name)

    new_cases = [
        {"name": "pack-fndsa1024-valid", "artifact": "authenticity-pack",
         "pack_file": "conformance/vectors/pack-fndsa1024-valid.json", "expect": {"authentic": True},
         "note": "A genuine Falcon-padded-1024 pack verifies: the FN-DSA family (draft FIPS 206), category 5, verification only.",
         "since": SINCE},
        {"name": "pack-fndsa1024-tampered", "artifact": "authenticity-pack",
         "pack_file": "conformance/vectors/pack-fndsa1024-tampered.json", "expect": {"authentic": False},
         "note": "One flipped signature byte under Falcon-padded-1024.", "since": SINCE},
        {"name": "pack-fndsa512-unaccepted", "artifact": "authenticity-pack",
         "pack_file": "conformance/vectors/pack-fndsa512-unaccepted.json", "expect": {"authentic": False},
         "note": "A GENUINE Falcon-padded-512 signature MUST be refused: category 1 is below the floor (wire spec section 6).",
         "since": SINCE},
    ]
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    names = {c["name"] for c in new_cases}
    doc["cases"] = [c for c in doc["cases"] if c["name"] not in names] + new_cases
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("  wrote %d vectors; cases now %d" % (len(written), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
