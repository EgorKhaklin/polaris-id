#!/usr/bin/env python3
"""The signature transplant, run against all three shipped verifiers (lab evidence, 2026-09-27).

An authenticity pack (WIRE-SPEC 3.7) is signed over SHA3-256(token_value). Every other signed
artifact is signed over SHA3-256 of its canonical JSON statement. So a published, genuinely
signed artifact can be re-wrapped as a pack whose token_value is its canonical statement, and
the artifact's own signature then verifies as a credential the authority never issued:

    pack = {format: polaris-authenticity-pack/1,
            token_value: <the artifact's canonical statement, as text>,
            algorithm: <the artifact's algorithm>,
            signature_hex: <the artifact's signature>,
            public_key_hex: <the artifact's signing key>}

For every published signed vector below, this script first confirms the artifact's OWN
signature is genuine (so the material is real ML-DSA, not a stand-in), then builds the
transplanted pack and hands it, with the signing key as the only trusted issuer anchor, to:

    detached   packages/polaris-verify (verify_pack), loaded through scripts/polaris-verify.py
    sdk-py     sdk/python: `python -m polaris_verify.conformance`, a subprocess, as a relying party runs it
    sdk-ts     sdk/typescript: `node sdk/typescript/src/conformance.ts`, a subprocess

Exit 1 if ANY verifier reports a transplanted pack authentic (the defect is present), 0 if every
verifier refused every transplant (the defect is absent), 3 if no real ML-DSA backend is present.
Needs liboqs-python and cryptography>=48 (the 3.12 venv has both) and node for the TS SDK.

    ~/.local/share/polaris-venv312/bin/python lab/strategy/003/transplant_counterexample.py
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
VEC = ROOT / "conformance" / "vectors"

_spec = importlib.util.spec_from_file_location("polaris_verify_detached", ROOT / "scripts" / "polaris-verify.py")
V = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(V)

# (published vector, the detached verifier's canonical-statement function for its format)
TARGETS = [
    ("federation-manifest-valid.json", "_manifest_canonical"),
    ("trust-list-valid.json", "_trust_list_canonical"),
    ("registry-valid.json", "_registry_canonical"),
    ("revocation-feed-valid.json", "_revocation_feed_canonical"),
    ("epoch-checkpoint-valid.json", "_epoch_checkpoint_canonical"),
    ("status-assertion-valid.json", "_status_assertion_canonical"),
    ("signed-document-valid.json", "_signed_document_canonical"),
    ("id-token-valid.json", "_id_token_canonical"),
    ("exchange-receipt-valid.json", "_exchange_receipt_canonical"),
    ("holder-binding-valid.json", "_holder_binding_canonical"),
    ("trust-attestation-valid.json", "_attestation_canonical"),
]


def _genuine(obj, canonical):
    """The artifact's own signature, checked over SHA3-256(canonical) by both witnesses."""
    ok, ran, _note = V._two_witness_verify(hashlib.sha3_256(canonical).digest(),
                                           bytes.fromhex(obj["signature_hex"]),
                                           bytes.fromhex(obj["public_key_hex"]),
                                           obj.get("algorithm") or "ML-DSA-65")
    return bool(ok), ran


def _subprocess_verdict(cmd, payload, env=None):
    p = subprocess.run(cmd, input=json.dumps(payload), capture_output=True, text=True,
                       cwd=str(ROOT), env=env, timeout=120)
    try:
        return json.loads(p.stdout.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        return {"error": (p.stderr or p.stdout)[:200]}


def main():
    if not any(V._provider_available(n) for n in ("cryptography", "oqs")):
        print("no real ML-DSA backend; nothing here would be evidence", file=sys.stderr)
        return 3
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "sdk" / "python") + os.pathsep + env.get("PYTHONPATH", "")
    py_cmd = [sys.executable, "-m", "polaris_verify.conformance"]
    ts_cmd = ["node", "sdk/typescript/src/conformance.ts"]

    accepted, rows = 0, []
    for fname, fn in TARGETS:
        obj = json.loads((VEC / fname).read_text())
        canonical = getattr(V, fn)(obj)
        ok, ran = _genuine(obj, canonical)
        if not ok:
            rows.append((fname, "artifact's own signature did not verify (%s); skipped" % ", ".join(ran)))
            continue
        pack = {"format": "polaris-authenticity-pack/1", "token_value": canonical.decode("utf-8"),
                "algorithm": obj.get("algorithm") or "ML-DSA-65",
                "signature_hex": obj["signature_hex"], "public_key_hex": obj["public_key_hex"]}
        anchors = [obj["public_key_hex"]]
        d = V.verify_pack(pack, anchors)
        det = {"authentic": d["signature_valid"], "issuer_trusted": d["issuer_trusted"], "note": d["note"]}
        payload = {"artifact": "authenticity-pack", "pack": pack, "anchors": anchors}
        py = _subprocess_verdict(py_cmd, payload, env)
        ts = _subprocess_verdict(ts_cmd, payload)
        verdicts = {"detached": det, "sdk-py": py, "sdk-ts": ts}
        for who, v in verdicts.items():
            if v.get("authentic") is True:
                accepted += 1
        rows.append((fname, "artifact genuine (%s); token_value %d bytes, begins %r; transplanted pack: %s"
                     % (", ".join(ran), len(canonical), canonical[:1].decode(),
                        "  ".join("%s authentic=%s issuer_trusted=%s" % (w, v.get("authentic"), v.get("issuer_trusted"))
                                  for w, v in verdicts.items()))))
    for fname, line in rows:
        print("%-34s %s" % (fname, line))
    if accepted:
        print("\nDEFECT PRESENT: %d verdict(s) reported a transplanted artifact signature as an authentic "
              "credential from a trusted issuer." % accepted)
        return 1
    print("\nDEFECT ABSENT: every verifier refused every transplanted pack.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
