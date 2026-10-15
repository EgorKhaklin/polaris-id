#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
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

It signs the way /api/v1/verifiable-credential signs: the app's own signature_over_message,
real ML-DSA-65 under a file key, handed the canonical bytes. Until 2026-10-14 it signed with
its own digest, so it agreed with the verifier while the route, which hashed the bytes twice,
did not; the old form is now a refused case here.

Run: python3 scripts/polaris-vc-format-drill.py
Exit 0 iff every case holds, 3 to skip (needs liboqs and cryptography).
"""
import atexit
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile

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
    # The real profile is declared here, and the guard is on the libraries, not the caller's
    # flag, as the other real-signer drills do. The key is the custodied file key the route
    # signs with in a single-key deployment, for the authority the route names.
    os.environ["POLARIS_USE_REAL_PQC"] = "1"
    os.environ.pop("POLARIS_CUSTODY_DRIVER", None)
    os.environ.pop("POLARIS_AGENCY_KEYS_DIR", None)
    try:
        import pqc_signing
        import vc
    except Exception as e:  # noqa: BLE001
        print("vc-format drill needs the app's pqc_signing (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not (pqc_signing.is_available() and pqc_signing.second_witness_available()):
        print("vc-format drill needs real ML-DSA (liboqs + cryptography); skipping", file=sys.stderr)
        return 3
    spec = importlib.util.spec_from_file_location("polaris_verify",
                                                  os.path.join(HERE, "polaris-verify.py"))
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)

    tmp = tempfile.mkdtemp(prefix="polaris-vc-format-")
    atexit.register(shutil.rmtree, tmp, True)
    kp = pqc_signing.generate_keypair()
    key_file = os.path.join(tmp, "issuer.key.json")
    with open(key_file, "w") as f:
        json.dump(kp, f)
    os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_file
    pk = kp["public_key_hex"]
    other_pk = pqc_signing.generate_keypair()["public_key_hex"]

    def sign(data):
        return pqc_signing.signature_over_message(data, agency_id=1)

    def sign_twice(data):
        # The route's form until 2026-10-14: the canonical bytes hashed before
        # signature_over_message hashed them again.
        return pqc_signing.signature_over_message(hashlib.sha3_256(data).digest(), agency_id=1)

    SUBJECT = {"verificationResult": "usable", "credentialStatus": "ACTIVE",
               "context": "BANKING", "assuranceLevel": "polaris:possession",
               "verifiedAt": "2026-09-10T12:00:00Z"}

    print("a verification result in the W3C Verifiable Credentials data model")
    print()
    print("  %-66s %-10s %-10s %s" % ("case", "got", "expected", "ok"))
    ok = True

    doc = vc.build_credential("polaris:agency:1", SUBJECT, sign,
                              subject_id="polaris:handle:abc")
    v = V.verify_verifiable_credential(doc, anchor_keys=[pk])
    ok &= _row("a genuine credential verifies end to end", v["proof_authentic"], True)
    ok &= _row("...and is fresh within its own window", v["fresh"], True)
    ok &= _row("...and is trusted under the custodied key that signed it", v["issuer_trusted"], True)

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

    # One proof, one meaning: ML-DSA over ONE SHA3-256 of the canonical bytes. The same bytes
    # hashed twice, as the route signed them until 2026-10-14, are refused.
    twice = vc.build_credential("polaris:agency:1", SUBJECT, sign_twice,
                                subject_id="polaris:handle:abc")
    ok &= _row("a proof over the canonical bytes hashed twice is refused",
               V.verify_verifiable_credential(twice, anchor_keys=[pk])["proof_authentic"], False)

    # A credential is not trusted under an anchor that did not sign it.
    ok &= _row("a stranger's anchor does not trust this credential",
               V.verify_verifiable_credential(doc, anchor_keys=[other_pk])["issuer_trusted"],
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
              "its proof was made. The proof is the app's own ML-DSA signature over one SHA3-256 "
              "of the canonical bytes, and the same bytes hashed twice are refused. The subject "
              "attests a verification RESULT and refuses identity "
              "attributes and the token value alike, and without a verifier scope it carries no "
              "subject identifier at all rather than minting a stable one.")
        return 0
    print("FAIL: at least one case did not hold", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
