"""polaris_card/profile.py - the on-card data model, normatively (roadmap P4.1).

The specification is docs/design/card-profile.md. This module is the same thing as code,
because a card profile that exists only as prose is a profile two implementers read
differently: the encoder here defines the bytes, and polaris_card/vectors/ publishes what
those bytes are, so an applet in C and a reader in anything else can agree without asking.

Deliberately dependency-free. A card profile has to be implementable inside a secure element's
toolchain and inside the detached verifier, which stays import-standalone, so the encoding is
one a few dozen lines of C can parse and nothing here imports a crypto library. Signature
verification is passed IN as a callable; this module decides what is signed and what a verdict
means, never how to compute one.

THE ENCODING is deterministic TLV: a one-byte tag, a two-byte big-endian length, the value.
Tags appear at most once and in ascending order, so one card object has exactly one encoding.
That matters because the object is signed: a format with two valid encodings of the same
content is a format where a signature can be moved onto something it did not authorise.

WHAT IS NOT ON THE CARD is as much of the profile as what is. The token value, the holder's
name and date of birth, biometric templates, and the duress code in any form are refused BY
NAME rather than merely being absent from the vocabulary, because "we did not think to put it
there" is not a property and the day someone extends the field list it stops being true. A
card is a key and a signed reference; it is not a copy of the record.
"""
from __future__ import annotations

import hashlib
import struct

PROFILE_VERSION = 1
DOC_TYPE = "id.polaris.card.1"

# The signed body. Ascending tag order is the canonical order.
TAG_PROFILE_VERSION = 0x01
TAG_DOC_TYPE = 0x02
TAG_CREDENTIAL_REF = 0x03
TAG_ISSUING_AUTHORITY = 0x04
TAG_ACTIVATION_SEQUENCE = 0x05
TAG_PREDECESSOR_REF = 0x06
TAG_ISSUED_AT = 0x07
TAG_EXPIRES_AT = 0x08
TAG_CARD_KEY_CLASSICAL = 0x09
TAG_CARD_KEY_PQ = 0x0A

# The signatures, which are NOT part of what they sign.
TAG_SIG_CLASSICAL = 0x20
TAG_SIG_PQ = 0x21

BODY_TAGS = {
    TAG_PROFILE_VERSION: "profile_version",
    TAG_DOC_TYPE: "doc_type",
    TAG_CREDENTIAL_REF: "credential_ref",
    TAG_ISSUING_AUTHORITY: "issuing_authority",
    TAG_ACTIVATION_SEQUENCE: "activation_sequence",
    TAG_PREDECESSOR_REF: "predecessor_ref",
    TAG_ISSUED_AT: "issued_at",
    TAG_EXPIRES_AT: "expires_at",
    TAG_CARD_KEY_CLASSICAL: "card_key_classical",
    TAG_CARD_KEY_PQ: "card_key_pq",
}
SIGNATURE_TAGS = {TAG_SIG_CLASSICAL: "issuer_sig_classical", TAG_SIG_PQ: "issuer_sig_pq"}
ALL_TAGS = {**BODY_TAGS, **SIGNATURE_TAGS}
NAME_TO_TAG = {v: k for k, v in ALL_TAGS.items()}

REQUIRED = ("profile_version", "doc_type", "credential_ref", "issuing_authority",
            "activation_sequence", "issued_at", "expires_at", "card_key_classical")
OPTIONAL = ("predecessor_ref", "card_key_pq")

# Refused by name. See the module docstring: absence is not a property.
FORBIDDEN_FIELDS = frozenset({
    "token_value", "legal_name", "date_of_birth", "dob", "name", "given_name", "family_name",
    "biometric", "biometric_template", "fingerprint", "face", "iris",
    "duress_code", "duress_code_hash", "duress_key", "duress_pubkey",
    "individual_id", "physical_serial", "address", "nationality",
})

_U8 = (TAG_PROFILE_VERSION,)
_U32 = (TAG_ISSUING_AUTHORITY, TAG_ACTIVATION_SEQUENCE)
_U64 = (TAG_ISSUED_AT, TAG_EXPIRES_AT)
_HASH32 = (TAG_CREDENTIAL_REF, TAG_PREDECESSOR_REF)

# The P-256 public key on today's certified silicon, and the ML-DSA-65 key for the day it is
# certified. Sizes are pinned so a truncated or padded key is a parse failure rather than a
# verification failure somewhere later.
CLASSICAL_KEY_LEN = 65        # SEC1 uncompressed P-256
PQ_KEY_LEN = 1952             # ML-DSA-65


class CardProfileError(ValueError):
    """The bytes are not a card object of this profile, or the fields are not admissible."""


# ---------------------------------------------------------------------------
# References. The card carries a reference to the credential, never its value.
# ---------------------------------------------------------------------------
def credential_ref(token_value: str) -> bytes:
    """SHA3-256("polaris-card-ref/1" || token_value).

    A card that emitted the token value would hand a reader the identifier the relying-party
    API accepts, so a single read of a card in a pocket would be as good as holding it. The
    reference is one-way: an authority that already knows a credential recognises it, and a
    reader that does not cannot work backwards to something it can present."""
    return hashlib.sha3_256(b"polaris-card-ref/1" + token_value.encode("utf-8")).digest()


def pairwise_handle(card_secret: bytes, reader_scope: str) -> bytes:
    """SHA3-256("polaris-pairwise/1" || card_secret || reader_scope).

    The same construction the presentation layer uses, because a card is subject to the same
    rule: two readers must not be able to tell they saw the same person. One hash is within
    reach of any secure element, which is why this is the card's default mode and showing the
    whole card object is the exception."""
    return hashlib.sha3_256(b"polaris-pairwise/1" + card_secret
                            + reader_scope.encode("utf-8")).digest()


# ---------------------------------------------------------------------------
# The encoding
# ---------------------------------------------------------------------------
def _encode_value(tag, value):
    if tag in _U8:
        return struct.pack(">B", int(value))
    if tag in _U32:
        return struct.pack(">I", int(value))
    if tag in _U64:
        return struct.pack(">Q", int(value))
    if tag == TAG_DOC_TYPE:
        return value.encode("utf-8") if isinstance(value, str) else bytes(value)
    return bytes(value)


def _decode_value(tag, raw):
    if tag in _U8:
        if len(raw) != 1:
            raise CardProfileError(f"tag 0x{tag:02x} must be one byte, got {len(raw)}")
        return raw[0]
    if tag in _U32:
        if len(raw) != 4:
            raise CardProfileError(f"tag 0x{tag:02x} must be four bytes, got {len(raw)}")
        return struct.unpack(">I", raw)[0]
    if tag in _U64:
        if len(raw) != 8:
            raise CardProfileError(f"tag 0x{tag:02x} must be eight bytes, got {len(raw)}")
        return struct.unpack(">Q", raw)[0]
    if tag == TAG_DOC_TYPE:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CardProfileError("doc_type is not UTF-8") from exc
    if tag in _HASH32 and len(raw) != 32:
        raise CardProfileError(f"tag 0x{tag:02x} must be a 32-byte reference, got {len(raw)}")
    if tag == TAG_CARD_KEY_CLASSICAL and len(raw) != CLASSICAL_KEY_LEN:
        raise CardProfileError(
            f"the classical card key must be {CLASSICAL_KEY_LEN} bytes (SEC1 uncompressed "
            f"P-256), got {len(raw)}")
    if tag == TAG_CARD_KEY_PQ and len(raw) != PQ_KEY_LEN:
        raise CardProfileError(
            f"the post-quantum card key must be {PQ_KEY_LEN} bytes (ML-DSA-65), got {len(raw)}")
    return raw


def encode(fields: dict) -> bytes:
    """Encode a card object. Tags ascend and appear once, so the encoding is the only one."""
    forbidden = sorted(set(fields) & FORBIDDEN_FIELDS)
    if forbidden:
        raise CardProfileError(
            "refusing to put %s on a card: a card is a key and a signed reference, not a copy "
            "of the record. These are refused by name rather than left out of the vocabulary, "
            "because absence is not a property" % ", ".join(forbidden))
    unknown = sorted(set(fields) - set(NAME_TO_TAG))
    if unknown:
        raise CardProfileError("unknown card fields: %s (the vocabulary is closed; extending "
                               "it is a profile version, not a field)" % ", ".join(unknown))
    missing = [f for f in REQUIRED if fields.get(f) is None]
    if missing:
        raise CardProfileError("a card object needs %s" % ", ".join(missing))
    out = bytearray()
    for tag in sorted(ALL_TAGS):
        name = ALL_TAGS[tag]
        if fields.get(name) is None:
            continue
        value = _encode_value(tag, fields[name])
        if len(value) > 0xFFFF:
            raise CardProfileError(f"{name} is too long for a two-byte length")
        out += struct.pack(">BH", tag, len(value)) + value
    return bytes(out)


def decode(blob: bytes) -> dict:
    """Decode a card object, refusing anything with more than one valid reading."""
    fields, seen, last, i = {}, set(), -1, 0
    blob = bytes(blob)
    while i < len(blob):
        if i + 3 > len(blob):
            raise CardProfileError("truncated: a tag/length header needs three bytes")
        tag, length = struct.unpack(">BH", blob[i:i + 3])
        i += 3
        if i + length > len(blob):
            raise CardProfileError(f"truncated: tag 0x{tag:02x} claims {length} bytes")
        raw = blob[i:i + length]
        i += length
        if tag not in ALL_TAGS:
            raise CardProfileError(
                f"unknown tag 0x{tag:02x}. A reader that skipped what it did not recognise "
                "would verify a signature over bytes it never looked at")
        if tag in seen:
            raise CardProfileError(f"tag 0x{tag:02x} appears twice; which one is signed?")
        if tag <= last:
            raise CardProfileError(
                f"tag 0x{tag:02x} is out of order. Tags ascend so one object has one encoding: "
                "a format with two encodings of the same content is one where a signature can "
                "be moved onto something it did not authorise")
        seen.add(tag)
        last = tag
        fields[ALL_TAGS[tag]] = _decode_value(tag, raw)
    missing = [f for f in REQUIRED if f not in fields]
    if missing:
        raise CardProfileError("card object is missing %s" % ", ".join(missing))
    if fields["doc_type"] != DOC_TYPE:
        raise CardProfileError(
            f"doc_type is {fields['doc_type']!r}, not {DOC_TYPE!r}. A card must not claim to be "
            "a document type it is not")
    if fields["profile_version"] != PROFILE_VERSION:
        raise CardProfileError(
            f"profile version {fields['profile_version']} is not supported by this reader "
            f"(expected {PROFILE_VERSION}); refusing rather than guessing at the layout")
    return fields


def signing_body(fields: dict) -> bytes:
    """The bytes the issuer signs: the card object WITHOUT its signatures.

    Signatures are excluded from what they cover, and the classical and post-quantum
    signatures therefore cover exactly the same bytes. If each covered the other, the second
    one written would be the only one that could be verified independently, and a verifier
    would have to reconstruct an intermediate state to check the first."""
    return encode({k: v for k, v in fields.items() if k in BODY_TAGS.values()})


def signing_digest(fields: dict) -> bytes:
    """SHA3-256 over the signing body, matching what the rest of the system signs."""
    return hashlib.sha3_256(signing_body(fields)).digest()


# ---------------------------------------------------------------------------
# Building and verifying
# ---------------------------------------------------------------------------
def build_card(*, token_value, issuing_authority, activation_sequence, issued_at, expires_at,
               card_key_classical, card_key_pq=None, predecessor_token_value=None,
               sign_classical=None, sign_pq=None) -> bytes:
    """Build and sign a card object. At least one signer is required.

    `sign_classical` and `sign_pq` each take the 32-byte digest and return a signature."""
    fields = {
        "profile_version": PROFILE_VERSION,
        "doc_type": DOC_TYPE,
        "credential_ref": credential_ref(token_value),
        "issuing_authority": issuing_authority,
        "activation_sequence": activation_sequence,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "card_key_classical": card_key_classical,
    }
    if card_key_pq is not None:
        fields["card_key_pq"] = card_key_pq
    if predecessor_token_value is not None:
        fields["predecessor_ref"] = credential_ref(predecessor_token_value)
    if sign_classical is None and sign_pq is None:
        raise CardProfileError("a card object must carry at least one issuer signature")
    digest = signing_digest(fields)
    if sign_classical is not None:
        fields["issuer_sig_classical"] = sign_classical(digest)
    if sign_pq is not None:
        fields["issuer_sig_pq"] = sign_pq(digest)
    return encode(fields)


def verify_card(blob, *, verify_classical=None, verify_pq=None, require_pq=False, now=None):
    """Decide a card object offline. Returns a verdict; never raises on untrusted input.

    The verdict separates what a reader established from what it could not, because the two
    are different facts and collapsing them is how a card gets accepted for a property nobody
    checked.

    THE ANTI-DOWNGRADE RULE. When both signatures are present, BOTH must verify. The obvious
    alternative, accept-if-either, hands the whole scheme to whoever breaks the weaker
    algorithm first: that is the entire reason the card carries two. And `require_pq` is what a
    verifier sets once post-quantum silicon is fielded, so a classical-only card is refused by
    policy rather than quietly accepted forever."""
    v = {"parsed": False, "classical_signature": None, "post_quantum_signature": None,
         "signatures_agree": False, "unexpired": None, "authentic": False, "note": None,
         "fields": None}
    try:
        fields = decode(blob)
    except CardProfileError as exc:
        v["note"] = str(exc)
        return v
    v["parsed"] = True
    v["fields"] = {k: val for k, val in fields.items() if k in BODY_TAGS.values()}

    digest = signing_digest(fields)
    has_classical = "issuer_sig_classical" in fields
    has_pq = "issuer_sig_pq" in fields
    if not has_classical and not has_pq:
        v["note"] = "the card object carries no issuer signature"
        return v
    if has_classical and verify_classical is not None:
        v["classical_signature"] = bool(verify_classical(digest, fields["issuer_sig_classical"]))
    if has_pq and verify_pq is not None:
        v["post_quantum_signature"] = bool(verify_pq(digest, fields["issuer_sig_pq"]))

    if require_pq and not has_pq:
        v["note"] = ("this verifier requires a post-quantum issuer signature and the card "
                     "carries none")
        return v
    checked = [x for x in (v["classical_signature"], v["post_quantum_signature"])
               if x is not None]
    if not checked:
        v["note"] = "no verifier was supplied for any signature the card carries"
        return v
    if False in checked:
        v["note"] = ("a signature the card carries did not verify. Both must verify when both "
                     "are present, or breaking the weaker algorithm is enough to forge a card")
        return v
    v["signatures_agree"] = True
    if now is not None:
        v["unexpired"] = int(now) < int(fields["expires_at"])
        if not v["unexpired"]:
            v["note"] = "the card object is past its expiry"
            return v
    v["authentic"] = True
    return v


# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------
def response_body(challenge: bytes, reader_scope: str, handle: bytes) -> bytes:
    """What the card signs at presentation: the reader's challenge, its scope, and the handle.

    The challenge is what makes the response non-replayable; the scope is what stops a reader
    from relaying a response to a different reader and being believed. Both are inside the
    signature, so neither can be changed by whatever sits between the card and the verifier."""
    if len(challenge) < 16:
        raise CardProfileError(
            "a reader challenge must be at least 16 bytes; a short one is a challenge an "
            "attacker can wait to see again")
    return (b"polaris-card-response/1" + struct.pack(">H", len(challenge)) + challenge
            + struct.pack(">H", len(reader_scope.encode("utf-8")))
            + reader_scope.encode("utf-8") + handle)
