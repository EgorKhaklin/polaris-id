#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris-mdoc-bridge-drill.py - a Polaris credential in ISO 18013-5 structure (P3.7).

A FORMAT bridge, not a trust bridge, and this drill exists as much to hold the second half of
that sentence as the first.

What bridges: the CBOR structure and the selective-disclosure mechanism. A reader that speaks
ISO/IEC 18013-5 parses the document, walks its namespaces, and verifies each disclosed
element's digest against the signed Mobile Security Object. Case 3 proves that with an
independent CBOR implementation rather than the one that wrote the bytes.

What does not bridge: the issuer signature. It is ML-DSA-65, COSE algorithm -49, and 18013-5
mandates ES256, ES384, ES512 or EdDSA. An unmodified mDL reader cannot check it. That is not a
gap to be closed by signing classically: a post-quantum credential that carries a classical
signature is a classical credential, and the appearance of interoperability is not worth the
property this whole system exists to have. Case 9 asserts the verdict says so rather than
reporting a digest check as an issuer check.

-49 is what RFC 9964 registers: pure ML-DSA-65 over the COSE Sig_structure itself. The documents
here are signed the way the app signs them (pqc_signing.signature_over_cose_sig_structure, real
ML-DSA-65, a persistent key), case 12 checks the signature with an independent implementation
over the raw Sig_structure, and case 13 shows a signature over its SHA3-256 refused.

Two refusals matter as much as the round trip. The document must not claim the mDL docType,
because a Polaris credential is not a driving licence and a document that claimed the namespace
while carrying none of its elements would be a lie in a machine-readable format. And it must
not carry the token value, because that is the correlation handle the presentation layer spent
a ship bounding, and an mdoc is not a way around it.

Run: python3 scripts/polaris-mdoc-bridge-drill.py
Exit 0 iff every case holds, 3 to skip (needs liboqs, cbor2 and the cryptography ML-DSA witness).
"""
import hashlib
import importlib.util
import json
import os
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
    try:
        import cbor2
        import oqs  # type: ignore
        import mdoc
        import pqc_signing
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except Exception as e:  # noqa: BLE001
        print("mdoc-bridge drill needs cbor2, liboqs-python and cryptography: %s" % e, file=sys.stderr)
        return 3
    if not pqc_signing.second_witness_available():
        print("mdoc-bridge drill needs the cryptography ML-DSA witness: the issuer's signer refuses "
              "to sign without it", file=sys.stderr)
        return 3
    spec = importlib.util.spec_from_file_location("polaris_verify", os.path.join(HERE, "polaris-verify.py"))
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)

    # The issuer signs the way the app does: real ML-DSA-65 under one persistent key, through
    # the COSE signer, which signs the Sig_structure itself and two-witnesses the result.
    key = pqc_signing.generate_keypair("ML-DSA-65")
    pk = bytes.fromhex(key["public_key_hex"])
    fd, key_file = tempfile.mkstemp(prefix="polaris-mdoc-drill-", suffix=".key.json")
    with os.fdopen(fd, "w") as f:
        json.dump(key, f)
    os.environ.update(POLARIS_USE_REAL_PQC="1", POLARIS_CUSTODY_DRIVER="file",
                      POLARIS_PQC_SIGNING_KEY_FILE=key_file)
    try:
        return _cases(cbor2, oqs, mdoc, pqc_signing, mldsa, V, pk, key)
    finally:
        os.unlink(key_file)


def _cases(cbor2, oqs, mdoc, pqc_signing, mldsa, V, pk, key):
    with oqs.Signature("ML-DSA-65") as s:
        other_pk = bytes(s.generate_keypair())
    sign = pqc_signing.signature_over_cose_sig_structure

    FULL = {"issuing_authority": "Authority A", "context": "BANKING",
            "assurance_level": "polaris:possession", "enrollment_status": "ENROLLED",
            "credential_status": "ACTIVE"}

    print("a Polaris credential in ISO 18013-5 structure")
    print()
    print("  %-66s %-10s %-10s %s" % ("case", "got", "expected", "ok"))
    ok = True

    # 1-2. The round trip, across two INDEPENDENT CBOR implementations: the app writes with
    #      cbor2, the detached verifier reads with its own hand-written decoder.
    doc = mdoc.build_document(FULL, "ML-DSA-65", sign)
    v = V.verify_mdoc(doc, anchor_keys=[pk.hex()])
    ok &= _row("a genuine document verifies end to end", v["issuer_authentic"], True)
    ok &= _row("...and every disclosed element matches the signed MSO", v["digests_match"], True)
    ok &= _row("...decoded by a CBOR implementation that did not write it",
               v["elements"] == FULL, True)

    # 3. THE INTEROP CLAIM, tested rather than asserted: an off-the-shelf CBOR reader parses
    #    the structure and can check the digests for itself, with no Polaris code involved.
    parsed = cbor2.loads(doc)
    items = parsed["issuerSigned"]["nameSpaces"][mdoc.NAMESPACE]
    mso = cbor2.loads(cbor2.loads(parsed["issuerSigned"]["issuerAuth"][2]).value)
    committed = mso["valueDigests"][mdoc.NAMESPACE]
    reader_ok = True
    for tagged in items:
        digest = hashlib.sha256(cbor2.dumps(tagged, canonical=True)).digest()
        if committed.get(cbor2.loads(tagged.value)["digestID"]) != digest:
            reader_ok = False
    ok &= _row("an INDEPENDENT reader checks every digest against the MSO itself", reader_ok, True)
    ok &= _row("...and reads the MSO's own validity window",
               bool(mso["validityInfo"]["validUntil"]), True)

    # 4. SELECTIVE DISCLOSURE: a subset still verifies, and withheld elements are absent.
    subset = {"context": "BANKING", "credential_status": "ACTIVE"}
    doc2 = mdoc.build_document(subset, "ML-DSA-65", sign)
    v2 = V.verify_mdoc(doc2, anchor_keys=[pk.hex()])
    ok &= _row("a two-element subset still verifies", v2["issuer_authentic"], True)
    ok &= _row("...and the withheld elements are simply absent",
               sorted(v2["elements"]), ["context", "credential_status"])

    # 5. A tampered element value breaks its digest.
    tampered = bytearray(doc)
    idx = tampered.find(b"ENROLLED")
    tampered[idx:idx + 8] = b"REVOKED_"
    vt = V.verify_mdoc(bytes(tampered), anchor_keys=[pk.hex()])
    ok &= _row("an element edited after signing fails its digest", vt["digests_match"], False)

    # 6. A stranger's key does not verify the MSO.
    vs = V.verify_mdoc(doc, anchor_keys=[other_pk.hex()])
    ok &= _row("a document is not trusted under an anchor that did not sign it",
               vs["issuer_trusted"], False)

    # 7. THE NAMING REFUSALS. A Polaris credential is not a driving licence.
    ok &= _row("the docType is Polaris, never the mDL", mdoc.DOC_TYPE, "id.polaris.credential.1")
    ok &= _row("...and the namespace is too", mdoc.NAMESPACE, "id.polaris.1")
    ok &= _row("a document claiming another docType is refused",
               V.verify_mdoc(cbor2.dumps({"docType": "org.iso.18013.5.1.mDL",
                                          "issuerSigned": {}}))["structure_valid"], False)

    # 8. THE CORRELATION REFUSAL. The token value is what P9.4 bounded; an mdoc is not a way
    #    around it, and the refusal is at BUILD time so it cannot be emitted by accident.
    refused = False
    try:
        mdoc.build_document(dict(FULL, token_value="TKN-0001"), "ML-DSA-65", sign)
    except ValueError as e:
        refused = "correlation handles" in str(e)
    ok &= _row("refusing to emit the token value in an mdoc", refused, True)
    unknown_refused = False
    try:
        mdoc.build_document({"favourite_colour": "blue"}, "ML-DSA-65", sign)
    except ValueError as e:
        unknown_refused = "unknown mdoc elements" in str(e)
    ok &= _row("the namespace is closed: an unknown element is refused", unknown_refused, True)

    # 9. THE BOUND, STATED IN THE VERDICT. A digest check is not an issuer check, and the
    #    verdict must not let a caller report one as the other.
    ok &= _row("the verdict names what an unmodified reader can and cannot do",
               "not the signature" in (v["reader_interop"] or "")
               or "but not the" in (v["reader_interop"] or ""), True)
    ok &= _row("...and reports the digest check separately from the issuer check",
               v["digests_match"] is True and v["issuer_authentic"] is True
               and "digests_match" != "issuer_authentic", True)

    # 10. The COSE signature is over the Sig_structure, not the payload. Signing the payload
    #     alone would leave the algorithm unauthenticated and relabellable.
    protected_only = V.verify_mdoc(doc)["issuer_authentic"]
    ok &= _row("the signature covers the protected header, not just the payload",
               protected_only, True)

    # 11. Totality: a verifier fed hostile bytes returns a verdict. The inputs after the first
    #     seven are this document with one field the sender writes replaced, none needing a key
    #     (2026-10-28: tag 24 over a map as the MSO payload raised KeyError; a non-map nameSpaces
    #     or valueDigests AttributeError; an integer signature OverflowError; tag 24 as an
    #     algorithm name TypeError).
    def altered(field, value):
        d = cbor2.loads(doc)
        signed, auth = d["issuerSigned"], d["issuerSigned"]["issuerAuth"]
        if field in ("valueDigests", "digestAlgorithm"):
            mso = cbor2.loads(cbor2.loads(auth[2]).value)
            mso[field] = value
            auth[2] = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(mso)))
        elif field == "polaris_algorithm":
            auth[1][field] = value
        elif field == "nameSpaces":
            signed[field] = value
        else:
            auth[{"payload": 2, "signature": 3}[field]] = value
        return cbor2.dumps(d)
    tag24 = cbor2.CBORTag(24, b"\x01")
    ok &= _row("hostile input returns a verdict, never an exception",
               all(isinstance(V.verify_mdoc(x), dict)
                   for x in (None, b"", b"\xff\xff", "zz", [], {}, b"\x9f\x00",
                             altered("payload", bytes.fromhex("d818a10102")),
                             altered("nameSpaces", [1]), altered("valueDigests", "x"),
                             altered("signature", 2 ** 64 - 1),
                             altered("digestAlgorithm", tag24), altered("polaris_algorithm", tag24))), True)

    # 12. RFC 9964: -49 is pure ML-DSA-65 over the Sig_structure itself. An implementation
    #     that is not the app's (cryptography's MLDSA65, handed the key from the document)
    #     checks the signature over the raw structure, rebuilt here with cbor2.
    auth = cbor2.loads(doc)["issuerSigned"]["issuerAuth"]
    raw_tbs = cbor2.dumps(["Signature1", auth[0], b"", auth[2]])
    witness = mldsa.MLDSA65PublicKey.from_public_bytes(bytes.fromhex(auth[1]["polaris_public_key_hex"]))

    def independent(message):
        try:
            witness.verify(auth[3], message)
            return True
        except Exception:  # noqa: BLE001  InvalidSignature, or anything it cannot read
            return False
    ok &= _row("the signature is pure ML-DSA-65 over the Sig_structure itself",
               (cbor2.loads(auth[0]), independent(raw_tbs)), ({1: -49}, True))
    ok &= _row("...and not over its SHA3-256", independent(hashlib.sha3_256(raw_tbs).digest()), False)

    # 13. NO SECOND MEANING: a signature over SHA3-256 of the Sig_structure, the form the
    #     detached verifier checked until 2026-10-14, is refused under -49, not also accepted.
    def prehash(data):
        with oqs.Signature("ML-DSA-65", secret_key=bytes.fromhex(key["secret_key_hex"])) as signer:
            return bytes(signer.sign(hashlib.sha3_256(data).digest())), "ML-DSA-65", pk.hex()
    ok &= _row("a signature over SHA3-256 of the Sig_structure is refused",
               V.verify_mdoc(mdoc.build_document(FULL, "ML-DSA-65", prehash))["issuer_authentic"], False)

    print()
    if ok:
        if not _cases_recorded:
            print("FAIL: this drill recorded NO cases. It tested nothing and would "
                  "have printed its summary regardless.", file=sys.stderr)
            return 1
        print("OK: a Polaris credential renders in the ISO 18013-5 mdoc structure and round-trips "
              "across two independent CBOR implementations. What bridges is the format: an "
              "off-the-shelf reader parses the document and checks every disclosed element's "
              "digest against the signed Mobile Security Object, which is the standard's whole "
              "selective-disclosure mechanism. What does not bridge is the issuer signature, "
              "because it is ML-DSA and the standard does not list it, and the verdict says so "
              "rather than letting a digest check be reported as an issuer check. That signature "
              "is pure ML-DSA-65 over the COSE Sig_structure itself, as RFC 9964 defines -49, and "
              "a signature over its digest is refused. The document "
              "never claims the mDL docType, because a Polaris credential is not a driving "
              "licence, and it refuses to carry the token value, because an mdoc is not a way "
              "around the correlation the presentation layer bounds.")
        return 0
    print("FAIL: at least one case did not hold", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
