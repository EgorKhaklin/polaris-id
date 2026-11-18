# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""cose.py -- COSE_Sign1 as an ISO/IEC 18013-5 mdoc uses it: parsed, and verified.

An mdoc carries two COSE_Sign1 structures (RFC 9052 section 4.2): IssuerAuth, the issuer's
signature over the Mobile Security Object, and the device signature, whose payload is
detached. This module reads the structure and checks the signature. It touches no socket,
decides nothing about certificates, and knows nothing about mdoc: `mdoc.py` says which key a
signature must verify under and what its payload must be.

THE HEADER RULES, each with a test in `test_mdoc.py` (`CoseTests`):

    alg is read from the protected header only. The unprotected header is not signed, so an
        `alg` there is whatever the sender of the bytes wrote last.
    alg is one of three: ES256 (-7) and ESP256 (-9), on P-256 only, and ES384 (-35), on
        P-384 only: the pairing RFC 9053 section 2.1 suggests, held as a rule here.
    a `crit` parameter (label 2) is refused, in either header: this verifier processes no
        critical extension, so it has none it could honour.
    a label in both headers is refused, so that no parameter has two values to choose from.
    a protected header that is not one CBOR map, a repeated label in it included, is refused.

A signature is r and s, each at the key's length (RFC 9053 section 2.1); a DER signature is
another length and is refused. What is signed is the `Sig_structure` of RFC 9052 section
4.4, built by this package's own encoder over the protected header's bytes as they arrived.
"""
from . import cbor

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - exercised by the import-failure path only
    _HAVE_CRYPTO = False

#: Header parameter labels (RFC 9052 section 3.1; RFC 9360 section 2 for x5chain).
LABEL_ALG = 1
LABEL_CRIT = 2
LABEL_X5CHAIN = 33

#: The algorithms read, by COSE identifier: its name, the curve its key must be on, and the
#: hash. HAIP 1.0 section 7 names -7 or -9 for P-256.
ES256, ESP256, ES384 = -7, -9, -35
ALG_VALUES = (ES256, ESP256, ES384)
_ALGS = {ES256: ("ES256", "secp256r1", "SHA256"), ESP256: ("ESP256", "secp256r1", "SHA256"),
         ES384: ("ES384", "secp384r1", "SHA384")}


class CoseError(ValueError):
    """The structure is not a COSE_Sign1 this verifier reads, or its signature does not verify."""


class Sign1:
    """A parsed COSE_Sign1. `protected_bytes` is the protected header exactly as it arrived,
    which is what the signature covers; `protected` and `unprotected` are the two maps; `alg`
    the algorithm identifier, one of ALG_VALUES; `payload` the payload, or None when detached."""

    __slots__ = ("protected_bytes", "protected", "unprotected", "payload", "signature", "alg")

    def __init__(self, protected_bytes, protected, unprotected, payload, signature, alg):
        self.protected_bytes = protected_bytes
        self.protected = protected
        self.unprotected = unprotected
        self.payload = payload
        self.signature = signature
        self.alg = alg


def parse_sign1(value):
    """The COSE_Sign1 in a decoded CBOR value (the array, or the array under tag 18). Raises
    CoseError for anything else, and for a header this module refuses."""
    if isinstance(value, cbor.Tagged) and value.tag == cbor.TAG_COSE_SIGN1:
        value = value.value
    if not isinstance(value, list) or len(value) != 4:
        raise CoseError("a COSE_Sign1 is an array of four items, alone or under tag 18")
    protected_bytes, unprotected, payload, signature = value
    if not isinstance(protected_bytes, bytes):
        raise CoseError("the protected header is not a byte string")
    if not isinstance(unprotected, dict):
        raise CoseError("the unprotected header is not a map")
    if payload is not None and not isinstance(payload, bytes):
        raise CoseError("the payload is neither a byte string nor null")
    if not isinstance(signature, bytes):
        raise CoseError("the signature is not a byte string")
    # A header with no protected parameter is the empty byte string.
    protected = {}
    if protected_bytes:
        try:
            protected = cbor.decode(protected_bytes)
        except cbor.CborError as exc:
            raise CoseError("the protected header is not CBOR this verifier reads: %s" % exc) from None
        if not isinstance(protected, dict):
            raise CoseError("the protected header is not a map")
    if LABEL_CRIT in protected or LABEL_CRIT in unprotected:
        raise CoseError("a crit header parameter (label 2), and this verifier processes no critical "
                        "extension")
    both = sorted((label for label in protected if label in unprotected), key=repr)
    if both:
        raise CoseError("label %r is in both the protected and the unprotected header" % (both[0],))
    if LABEL_ALG not in protected:
        raise CoseError("no alg in the protected header%s" % (
            "; the one in the unprotected header is not signed and is not read"
            if LABEL_ALG in unprotected else ""))
    alg = protected[LABEL_ALG]
    # The type is held exactly: True == 1 to Python, and no boolean is an algorithm.
    if type(alg) is not int or alg not in ALG_VALUES:
        raise CoseError("alg is %r; this verifier reads ES256 (-7), ESP256 (-9) and ES384 (-35)" % (alg,))
    return Sign1(protected_bytes, protected, unprotected, payload, signature, alg)


def x5chain(sign1):
    """The certificates of the x5chain header parameter, each as its DER bytes, signer first:
    one certificate, or an array of them (RFC 9360 section 2). From whichever header carries
    it; `parse_sign1` has refused a label in both. Raises CoseError when there is none."""
    if LABEL_X5CHAIN in sign1.protected:
        value = sign1.protected[LABEL_X5CHAIN]
    elif LABEL_X5CHAIN in sign1.unprotected:
        value = sign1.unprotected[LABEL_X5CHAIN]
    else:
        raise CoseError("no x5chain (label 33) in either header")
    chain = [value] if isinstance(value, bytes) else value
    if not isinstance(chain, list) or not chain or not all(isinstance(c, bytes) and c for c in chain):
        raise CoseError("x5chain is neither a certificate nor an array of certificates")
    return chain


def verify_sign1(sign1, public_key, payload=None):
    """Check a parsed COSE_Sign1 under `public_key` and return its algorithm's name. `payload`
    is the detached payload, given only when the structure carries none. Raises CoseError when
    the key is not on the algorithm's curve, the signature has another length, or it does not
    verify."""
    if not _HAVE_CRYPTO:  # mdoc.py refuses with `no_backend` before this
        raise CoseError("the cryptography package is not installed")
    if sign1.payload is not None:
        if payload is not None:
            raise CoseError("a payload was supplied for a COSE_Sign1 that carries its own payload")
        payload = sign1.payload
    elif payload is None:
        raise CoseError("no payload: the COSE_Sign1 is detached and none was supplied")
    name, curve, hash_name = _ALGS[sign1.alg]
    on = public_key.curve.name if isinstance(public_key, ec.EllipticCurvePublicKey) else None
    if on != curve:
        raise CoseError("%s needs a key on %s; this one is %s" % (
            name, curve, "on %s" % on if on else "not an elliptic-curve key"))
    size = (public_key.curve.key_size + 7) // 8
    if len(sign1.signature) != 2 * size:
        raise CoseError("the signature is %d bytes; %s on %s needs %d, r and s at the key's length "
                        "(RFC 9053 section 2.1)" % (len(sign1.signature), name, curve, 2 * size))
    signed = cbor.encode(["Signature1", sign1.protected_bytes, b"", payload])
    der = encode_dss_signature(int.from_bytes(sign1.signature[:size], "big"),
                               int.from_bytes(sign1.signature[size:], "big"))
    try:
        public_key.verify(der, signed, ec.ECDSA(getattr(hashes, hash_name)()))
    except InvalidSignature:
        raise CoseError("the %s signature does not verify" % name) from None
    return name
