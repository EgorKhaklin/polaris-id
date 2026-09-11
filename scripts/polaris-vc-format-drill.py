#!/usr/bin/env python3
"""polaris-vc-format-drill.py - a verification RESULT as a W3C Verifiable Credential (P3.8).

The sibling of the mdoc bridge, and the same discipline: a FORMAT, not a trust model. What
differs is what the document is ABOUT. Not "this person is X" but "at this instant, presented
against this credential, the issuing authority's answer was this".

What a general VC verifier can do: parse the document, read its validity window, read the
subject. What it cannot do: verify the proof. The cryptosuite is `polaris-mldsa-jcs-2026`
because every registered Data Integrity suite is classical, and naming a registered one to
make a general verifier accept the proof would be a false statement about how the proof was
made, on top of trading the post-quantum property for the appearance of interoperability.

Two refusals, both asserted rather than assumed. The subject carries a verification result and
never an identity attribute, because Polaris makes no identity claims anywhere else and a VC
that did would be a larger claim than the whole system supports. And it never carries the token
value, for the reason every surface refuses it.

Run: python3 scripts/polaris-vc-format-drill.py
Exit 0 iff every case holds, 3 to skip (needs liboqs).
"""
import hashlib
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "polaris_web"))


#: Cases this drill actually recorded. A drill whose cases are removed or
#: short-circuited in a refactor prints its whole summary and exits 0 anyway,
#: which is a guarantee reported by something that tested nothing (v9.403).
_cases_recorded = 0


def _row(label, got, want):
    global _cases_recorded
    _cases_recorded += 1
    ok = got == want
    print("  %-66s %-10s %-10s %s" % (label[:66], str(got)[:10], str(want)[:10], "OK" if ok else "FAIL"))
    return ok


def main():
    try:
        import oqs  # type: ignore
        import vc
    except Exception as e:  # noqa: BLE001
        print("vc-format drill needs liboqs-python: %s" % e, file=sys.stderr)
        return 3
    spec = importlib.util.spec_from_file_location("polaris_verify",
                                                  os.path.join(HERE, "polaris-verify.py"))
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)

    with oqs.Signature("ML-DSA-65") as s:
        pk = bytes(s.generate_keypair()); sk = bytes(s.export_secret_key())
    with oqs.Signature("ML-DSA-65") as s:
        other_pk = bytes(s.generate_keypair())

    def sign(data):
        with oqs.Signature("ML-DSA-65", secret_key=sk) as signer:
            return bytes(signer.sign(hashlib.sha3_256(data).digest())), "ML-DSA-65", pk.hex()

    SUBJECT = {"verificationResult": "usable", "credentialStatus": "ACTIVE",
               "context": "BANKING", "assuranceLevel": "polaris:possession",
               "verifiedAt": "2026-09-10T12:00:00Z"}

    print("a verification result in the W3C Verifiable Credentials data model")
    print()
    print("  %-66s %-10s %-10s %s" % ("case", "got", "expected", "ok"))
    ok = True

    doc = vc.build_credential("polaris:agency:1", SUBJECT, sign,
                              subject_id="polaris:handle:abc")
    v = V.verify_verifiable_credential(doc, anchor_keys=[pk.hex()])
    ok &= _row("a genuine credential verifies end to end", v["proof_authentic"], True)
    ok &= _row("...and is fresh within its own window", v["fresh"], True)

    # THE FORMAT CLAIM, tested with no Polaris code: a plain JSON reader sees a VC.
    parsed = json.loads(json.dumps(doc))
    ok &= _row("a plain JSON reader sees a VerifiableCredential",
               "VerifiableCredential" in parsed["type"], True)
    ok &= _row("...with a validity window it can read itself",
               bool(parsed["validFrom"] and parsed["validUntil"]), True)
    ok &= _row("...and a DataIntegrityProof it can find", parsed["proof"]["type"],
               "DataIntegrityProof")

    # THE BOUND. The cryptosuite is named for what it is, so a general verifier refuses rather
    # than guesses, and the verdict says so rather than letting a parse read as a verification.
    ok &= _row("the cryptosuite names Polaris, not a registered classical suite",
               parsed["proof"]["cryptosuite"], "polaris-mldsa-jcs-2026")
    ok &= _row("the verdict states what a general verifier cannot do",
               "no general Data Integrity verifier knows" in (v["verifier_interop"] or ""), True)
    ok &= _row("...and reports the structure apart from the proof",
               v["structure_valid"] is True and v["proof_authentic"] is True, True)

    # The proof covers the document, minus itself.
    tampered = json.loads(json.dumps(doc))
    tampered["credentialSubject"]["credentialStatus"] = "REVOKED"
    ok &= _row("an edited subject breaks the proof",
               V.verify_verifiable_credential(tampered)["proof_authentic"], False)
    rewindowed = json.loads(json.dumps(doc))
    rewindowed["validUntil"] = "2099-01-01T00:00:00Z"
    ok &= _row("an extended validity window breaks the proof too",
               V.verify_verifiable_credential(rewindowed)["proof_authentic"], False)

    # A credential is not trusted under an anchor that did not sign it.
    ok &= _row("a stranger's anchor does not trust this credential",
               V.verify_verifiable_credential(doc, anchor_keys=[other_pk.hex()])["issuer_trusted"],
               False)

    # A document naming a REGISTERED suite is refused: it would be asserting something false
    # about how its proof was made.
    relabelled = json.loads(json.dumps(doc))
    relabelled["proof"]["cryptosuite"] = "eddsa-jcs-2022"
    vr = V.verify_verifiable_credential(relabelled)
    ok &= _row("a credential relabelled to a registered suite is refused",
               vr["proof_authentic"], False)
    ok &= _row("...and the refusal says why", "false" in (vr["note"] or ""), True)

    # THE SUBJECT REFUSALS.
    refused_identity = False
    try:
        vc.build_credential("polaris:agency:1", dict(SUBJECT, name="Maria"), sign)
    except ValueError as e:
        refused_identity = "identity attributes" in str(e)
    ok &= _row("refusing an identity attribute in the subject", refused_identity, True)
    refused_token = False
    try:
        vc.build_credential("polaris:agency:1", dict(SUBJECT, token_value="TKN-1"), sign)
    except ValueError as e:
        refused_token = "correlation handle" in str(e)
    ok &= _row("refusing the token value in the subject", refused_token, True)
    refused_unknown = False
    try:
        vc.build_credential("polaris:agency:1", {"favourite_colour": "blue"}, sign)
    except ValueError as e:
        refused_unknown = "unknown subject fields" in str(e)
    ok &= _row("the subject vocabulary is closed", refused_unknown, True)

    # P9.4: a per-verifier subject id, or none at all. Never a stable one.
    no_id = vc.build_credential("polaris:agency:1", SUBJECT, sign)
    ok &= _row("with no verifier scope the subject carries NO id",
               "id" in no_id["credentialSubject"], False)

    # A credential borrowing a standard type it is not.
    borrowed = json.loads(json.dumps(doc))
    borrowed["type"] = ["VerifiableCredential", "VerifiableId"]
    ok &= _row("a credential borrowing another standard type is refused",
               V.verify_verifiable_credential(borrowed)["structure_valid"], False)

    ok &= _row("hostile input returns a verdict, never an exception",
               all(isinstance(V.verify_verifiable_credential(x), dict)
                   for x in (None, b"", "x", [], {}, {"type": 7}, b"{bad")), True)

    print()
    if ok:
        if not _cases_recorded:
            print("FAIL: this drill recorded NO cases. It tested nothing and would "
                  "have printed its summary regardless.", file=sys.stderr)
            return 1
        print("OK: a verification result carries in the W3C Verifiable Credentials data model. A "
              "general reader parses the document, reads its window and finds its proof; it cannot "
              "verify that proof, because the cryptosuite is Polaris's own and every registered "
              "Data Integrity suite is classical, and a document naming a registered suite is "
              "refused rather than accepted, since it would be asserting something false about how "
              "its proof was made. The subject attests a verification RESULT and refuses identity "
              "attributes and the token value alike, and without a verifier scope it carries no "
              "subject identifier at all rather than minting a stable one.")
        return 0
    print("FAIL: at least one case did not hold", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
