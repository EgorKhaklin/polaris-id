#!/usr/bin/env python3
"""
polaris-kat-verify.py — ML-DSA-65 conformance against Project Wycheproof.

The published vectors/ (PE.2) prove three implementations agree with each other.
This proves something stronger: that Polaris's two PRODUCTION witnesses — liboqs
and cryptography/OpenSSL — agree with an INDEPENDENT authority's known-answer
verdicts. It verifies vectors/kat/mldsa_65_verify.json (curated Project Wycheproof
ML-DSA-65 verify vectors, empty-context) under both witnesses and asserts each
matches Wycheproof's expected valid/invalid result on every one. A conformance
failure — accepting a signature Wycheproof calls invalid, or rejecting a valid one
— fails the run.

    python3 scripts/polaris-kat-verify.py
    python3 scripts/polaris-kat-verify.py --json

Needs liboqs and cryptography (the two witnesses the KAT checks). Exit 0 iff every
vector conforms under both; 2 on any mismatch; 3 if a witness is unavailable.
"""
import argparse
import contextlib
import io
import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_VECTORS = os.path.join(_ROOT, "vectors", "kat", "mldsa_65_verify.json")

# liboqs prints a banner to stdout at import; swallow it so --json stays parseable.
try:
    with contextlib.redirect_stdout(io.StringIO()):
        import oqs as _oqs  # noqa: F401
except Exception:
    _oqs = None


def _liboqs_verify(pk, msg, sig):
    import oqs
    try:
        with oqs.Signature("ML-DSA-65") as v:
            return bool(v.verify(msg, sig, pk))
    except Exception:
        return False


def _crypto_verify(pk, msg, sig):
    from cryptography.hazmat.primitives.asymmetric import mldsa
    from cryptography.exceptions import InvalidSignature
    try:
        key = mldsa.MLDSA65PublicKey.from_public_bytes(pk)
    except Exception:
        return False
    try:
        key.verify(sig, msg)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def main(argv=None):
    ap = argparse.ArgumentParser(description="ML-DSA-65 conformance vs Project Wycheproof.")
    ap.add_argument("--vectors", default=_VECTORS)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if _oqs is None:
        print("KAT needs liboqs-python (the primary witness)", file=sys.stderr)
        return 3
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        if not hasattr(mldsa, "MLDSA65PublicKey"):
            raise ImportError("no MLDSA65PublicKey")
    except Exception as e:
        print("KAT needs the cryptography second witness (MLDSA65): %s" % e, file=sys.stderr)
        return 3

    with open(args.vectors) as f:
        data = json.load(f)
    checked = 0
    mism = {"liboqs": [], "cryptography": []}
    for g in data["testGroups"]:
        pk = bytes.fromhex(g["publicKey"])
        for t in g["tests"]:
            expect = (t["result"] == "valid")
            msg = bytes.fromhex(t["msg"])
            try:
                sig = bytes.fromhex(t["sig"])
            except ValueError:
                sig = b"\x00"  # malformed hex must verify as invalid
            checked += 1
            if _liboqs_verify(pk, msg, sig) != expect:
                mism["liboqs"].append(t["tcId"])
            if _crypto_verify(pk, msg, sig) != expect:
                mism["cryptography"].append(t["tcId"])

    prov = data.get("provenance", {})
    ok = not mism["liboqs"] and not mism["cryptography"]
    report = {"vectors": os.path.relpath(args.vectors, _ROOT), "source": prov.get("source"),
              "commit": prov.get("commit"), "checked": checked,
              "liboqs_mismatches": mism["liboqs"], "cryptography_mismatches": mism["cryptography"],
              "conformant": ok}
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("ML-DSA-65 KAT vs %s @ %s" % (prov.get("source"), (prov.get("commit") or "")[:12]))
        print("checked %d vectors under both witnesses" % checked)
        if ok:
            print("CONFORMANT: liboqs and cryptography match Wycheproof on every vector")
        else:
            print("NON-CONFORMANT: liboqs mismatches %s | cryptography mismatches %s"
                  % (mism["liboqs"], mism["cryptography"]))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
