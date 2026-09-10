"""mdoc.py - a Polaris credential rendered in the ISO/IEC 18013-5 mdoc structure (P3.7).

WHAT THIS IS, AND THE ONE SENTENCE THAT MATTERS MOST

This is a FORMAT bridge, not a trust bridge. A reader that speaks 18013-5 can parse what this
produces, walk its namespaces, and verify each disclosed element's digest against the signed
Mobile Security Object, which is the whole selective-disclosure mechanism of the standard. It
CANNOT verify the issuer signature, because that signature is ML-DSA-65 (COSE algorithm -49)
and 18013-5 mandates ES256, ES384, ES512 or EdDSA.

That is not an oversight to be fixed by signing classically. Signing classically to satisfy an
mDL reader would trade the property this entire system exists to have for the appearance of
interoperability, and a post-quantum credential that carries a classical signature is a
classical credential. So the structure bridges and the cryptography does not, and any consumer
is told which.

WHAT IT IS NOT

Not an mDL. The `docType` is `id.polaris.credential.1`, never `org.iso.18013.5.1.mDL`, and the
namespace is `id.polaris.1`, never `org.iso.18013.5.1`. Claiming those would assert that these
elements are driving-licence data elements, which they are not: Polaris holds no name, no date
of birth, no portrait and no driving privileges, and a document that claimed the mDL namespace
while carrying none of its elements would be a lie in a machine-readable format.

WHAT IT CARRIES, AND WHAT IT REFUSES TO CARRY

The elements are exactly the ID token's claim vocabulary: the issuing authority, the context,
the assurance reached, the enrollment status, the credential's status. No name, no attribute,
nothing the C6 disclosure vocabulary would have to redact.

It does NOT carry `token_value`. That is deliberate and load-bearing. The token value is the
stable identifier P9.4 spent a ship bounding: a presentation-layer handle is derived per
relying party precisely so two of them cannot join their records. An mdoc that carried the
token value would hand back the correlation handle in a different encoding, and the reader
would have no way to know it had been given something the presentation layer withholds.

STRUCTURE (18013-5 §9.1.2), for whoever has to read the bytes

    IssuerSigned = {"nameSpaces": {ns: [IssuerSignedItemBytes]}, "issuerAuth": COSE_Sign1}
    IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
    IssuerSignedItem = {"digestID", "random", "elementIdentifier", "elementValue"}
    MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)

The per-item `random` salt is what makes withholding an element safe: a reader given a subset
still verifies each digest, and cannot brute-force the values of the elements it was not given.
Sixteen bytes is the standard's floor; this uses thirty-two.
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone

import cbor2

# Deliberately NOT org.iso.18013.5.1: this is not a driving licence and must not claim to be.
DOC_TYPE = "id.polaris.credential.1"
NAMESPACE = "id.polaris.1"
DIGEST_ALGORITHM = "SHA-256"
MSO_VERSION = "1.0"
# COSE algorithm identifier for ML-DSA-65, the same one WebAuthn registration offers.
COSE_ALG_ML_DSA_65 = -49
COSE_ALG_ML_DSA_87 = -50
SALT_BYTES = 32

# The complete element vocabulary. A caller cannot introduce one: an mdoc is a signed
# assertion, and a namespace that accepts arbitrary keys is a namespace with no meaning.
ELEMENTS = (
    "issuing_authority",
    "context",
    "assurance_level",
    "enrollment_status",
    "credential_status",
)
# Never emitted, whatever a caller asks for. See the module docstring: this is the correlation
# handle the presentation layer bounds, and an mdoc is not a way around that.
FORBIDDEN_ELEMENTS = frozenset({"token_value", "token_id", "individual_id", "legal_name",
                                "date_of_birth", "signature_hex", "public_key_hex"})


def _tagged(obj) -> cbor2.CBORTag:
    """#6.24(bstr .cbor obj): the standard's embedded-CBOR wrapper.

    The digest is taken over THIS, the tagged and encoded form, not over the inner map. A
    verifier that digests the inner map instead gets a different value for the same element,
    which is the most common way an mdoc implementation fails to interoperate with itself.
    """
    return cbor2.CBORTag(24, cbor2.dumps(obj, canonical=True))


def _cose_alg(algorithm: str) -> int:
    if algorithm == "ML-DSA-87":
        return COSE_ALG_ML_DSA_87
    return COSE_ALG_ML_DSA_65


def sig_structure(protected: bytes, payload: bytes) -> bytes:
    """The bytes a COSE_Sign1 signature is actually over (RFC 9052 §4.4).

    ["Signature1", protected, external_aad, payload], canonically encoded. Signing the payload
    directly instead is a real and repeated implementation error: it makes the algorithm and
    the protected header unauthenticated, so an attacker can relabel a signature's algorithm.
    """
    return cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)


def build_issuer_signed(elements: dict, algorithm: str, sign, *, valid_from=None,
                        valid_until=None, now=None, device_key_cose=None) -> dict:
    """Build the IssuerSigned structure for the given elements.

    `sign` takes the bytes to sign and returns (signature_bytes, algorithm, public_key_hex),
    which is the shape `pqc_signing.signature_over_message` already has, so the issuing key
    never comes near this module.
    """
    # FORBIDDEN first, and deliberately not merely as a consequence of the vocabulary. If the
    # order were reversed, `token_value` would be refused only for being unknown, and the day
    # somebody added it to ELEMENTS the guard would vanish silently. This check must survive
    # that edit, so it stands on its own and names the real reason.
    forbidden = sorted(set(elements) & FORBIDDEN_ELEMENTS)
    if forbidden:
        raise ValueError("refusing to emit %s in an mdoc: these are the correlation handles the "
                         "presentation layer bounds, and an mdoc is not a way around that"
                         % ", ".join(forbidden))
    unknown = sorted(set(elements) - set(ELEMENTS))
    if unknown:
        raise ValueError("unknown mdoc elements: %s (the namespace is closed; a namespace that "
                         "accepts arbitrary keys is one with no meaning)" % ", ".join(unknown))

    now = now or datetime.now(timezone.utc).replace(microsecond=0)
    valid_from = valid_from or now
    valid_until = valid_until or (now + timedelta(hours=24))

    items, digests = [], {}
    for digest_id, name in enumerate(e for e in ELEMENTS if e in elements):
        item = {
            "digestID": digest_id,
            # A fresh salt per element, per issuance. Without it a reader given a subset could
            # confirm a guess at a withheld element by digesting it.
            "random": os.urandom(SALT_BYTES),
            "elementIdentifier": name,
            "elementValue": elements[name],
        }
        tagged = _tagged(item)
        encoded = cbor2.dumps(tagged, canonical=True)
        items.append(tagged)
        digests[digest_id] = hashlib.sha256(encoded).digest()

    mso = {
        "version": MSO_VERSION,
        "digestAlgorithm": DIGEST_ALGORITHM,
        "valueDigests": {NAMESPACE: digests},
        "deviceKeyInfo": {"deviceKey": device_key_cose} if device_key_cose else {},
        "docType": DOC_TYPE,
        "validityInfo": {
            "signed": now.isoformat().replace("+00:00", "Z"),
            "validFrom": valid_from.isoformat().replace("+00:00", "Z"),
            "validUntil": valid_until.isoformat().replace("+00:00", "Z"),
        },
    }
    payload = cbor2.dumps(_tagged(mso), canonical=True)
    protected = cbor2.dumps({1: _cose_alg(algorithm)}, canonical=True)
    sig_bytes, alg, pub = sign(sig_structure(protected, payload))
    # The unprotected header carries the key so a consumer can find it without a directory.
    # It is UNPROTECTED, so a verifier must check it against a trust anchor and never simply
    # use it: a signature verifies against the key it was made with, which proves nothing on
    # its own about who made it.
    issuer_auth = [protected, {"polaris_public_key_hex": pub, "polaris_algorithm": alg},
                   payload, sig_bytes]
    return {"nameSpaces": {NAMESPACE: items}, "issuerAuth": issuer_auth}


def build_document(elements: dict, algorithm: str, sign, **kw) -> bytes:
    """The full document, CBOR-encoded. `docType` names Polaris, never the mDL."""
    return cbor2.dumps({
        "docType": DOC_TYPE,
        "issuerSigned": build_issuer_signed(elements, algorithm, sign, **kw),
    }, canonical=True)
