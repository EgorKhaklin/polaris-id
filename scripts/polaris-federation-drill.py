#!/usr/bin/env python3
"""
polaris-federation-drill.py — two issuers on one box, with DISTINCT ROOTS (PE.3).

Today's AgencyTrustAttestation graph is administrative: rows saying agency A trusts
agency B, on top of a SINGLE signing key. This drill makes federation cryptographic
and RUNS it: it stands up two independent issuers (two real ML-DSA-65 signing keys =
two roots) plus a third issuer OUTSIDE the federation, issues a genuine token under
each through the real signing path, and proves with the DETACHED verifier that a
relying party accepts its own issuer, REJECTS a foreign issuer, and rejects the
outsider — the trust decision made against published KEYS, not a database.

    issuer A ── token_A signed by root_A
    issuer B ── token_B signed by root_B
    issuer C ── token_C signed by root_C   (outside the federation {A, B})

A relying party publishes a trust anchor set. The drill checks the whole matrix and
FAILS (exit 1) if any accept/reject is wrong, so a broken federation boundary turns
CI red. Needs liboqs + cryptography (the real two-witness issuance path).

    python3 scripts/polaris-federation-drill.py
"""
import importlib.util
import json
import os
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "polaris_web"))


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "polaris_verify", os.path.join(_ROOT, "scripts", "polaris-verify.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _make_issuer(pqc, tmp, name):
    """A distinct root: a real ML-DSA-65 keypair written to this issuer's key file.
    Returns (name, key_file, public_key_hex)."""
    kp = pqc.generate_keypair()
    kf = os.path.join(tmp, "issuer-%s.key.json" % name)
    with open(kf, "w") as f:
        json.dump(kp, f)
    return {"name": name, "key_file": kf, "anchor": kp["public_key_hex"]}


def _issue(pqc, issuer, token_value):
    """Issue a genuine token under this issuer's root, through the REAL signing
    entry point (signs SHA3-256(token_value) with the issuer's custodied key)."""
    os.environ["POLARIS_USE_REAL_PQC"] = "1"
    os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = issuer["key_file"]
    sig, alg, pk = pqc.signature_with_key_for_token(token_value)
    assert alg == "ML-DSA-65" and pk == issuer["anchor"], "issuer root mismatch"
    return {"format": "polaris-authenticity-pack/1", "token_value": token_value,
            "algorithm": alg, "signature_hex": sig.hex(), "public_key_hex": pk,
            "issuer": issuer["name"]}


def main():
    try:
        import pqc_signing
    except Exception as e:
        print("federation drill needs the app's pqc_signing (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not pqc_signing.second_witness_available():
        print("federation drill needs the cryptography second witness for real issuance", file=sys.stderr)
        return 3
    V = _load_verifier()

    with tempfile.TemporaryDirectory() as tmp:
        a = _make_issuer(pqc_signing, tmp, "A")
        b = _make_issuer(pqc_signing, tmp, "B")
        c = _make_issuer(pqc_signing, tmp, "C")  # outside the federation
        pack_a = _issue(pqc_signing, a, "FED-TOKEN-A-0001")
        pack_b = _issue(pqc_signing, b, "FED-TOKEN-B-0001")
        pack_c = _issue(pqc_signing, c, "FED-TOKEN-C-0001")

        anchors = {
            "trusts-A": [a["anchor"]],
            "trusts-B": [b["anchor"]],
            "federation-AB": [a["anchor"], b["anchor"]],
        }
        # (pack, relying-party anchor set) -> expected: accept iff the signing key
        # is in that party's trust set. accept = signature valid AND issuer trusted.
        expect = [
            (pack_a, "trusts-A", True), (pack_a, "trusts-B", False), (pack_a, "federation-AB", True),
            (pack_b, "trusts-B", True), (pack_b, "trusts-A", False), (pack_b, "federation-AB", True),
            (pack_c, "trusts-A", False), (pack_c, "trusts-B", False), (pack_c, "federation-AB", False),
        ]
        all_ok = True
        print("issuer  relying-party    signature_valid  issuer_trusted  verdict   expected")
        for pack, party, want_accept in expect:
            v = V.verify_pack(pack, anchor_keys=anchors[party])
            accepted = bool(v["signature_valid"]) and v.get("issuer_trusted") is True
            ok = accepted == want_accept
            all_ok = all_ok and ok
            print("  %-4s  %-15s  %-15s  %-14s  %-8s  %s%s"
                  % (pack["issuer"], party, v["signature_valid"], v.get("issuer_trusted"),
                     "ACCEPT" if accepted else "reject",
                     "ACCEPT" if want_accept else "reject",
                     "" if ok else "   <-- WRONG"))

        print()
        if all_ok:
            print("OK: two issuers on one box, distinct roots; each relying party accepts its own "
                  "issuer, rejects a foreign issuer, and rejects the outsider — cryptographically.")
            return 0
        print("FAIL: the federation boundary did not hold — a relying party accepted a foreign "
              "issuer or rejected its own.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
