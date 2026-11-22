# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""annexc.py -- ISO/IEC 18013-7 Annex C (`org-iso-mdoc`): the request a page hands the browser's
Digital Credentials API, and the encrypted DeviceResponse a wallet answers it with, opened and
judged.

It touches no socket, as `mdoc.py` does not. Nothing here is wired into `serve` yet.

THE REQUEST. `new_request` builds the two values the page passes to the Digital Credentials API
under the protocol `org-iso-mdoc`, each as base64url:

    deviceRequest   {"version": "1.0", "docRequests": [{"itemsRequest": 24(<<ItemsRequest>>)}]},
                    ItemsRequest = {"docType": ..., "nameSpaces": {namespace: {element: false}}}
    encryptionInfo  ["dcapi", {"nonce": 32 random bytes, "recipientPublicKey": COSE_Key}]

The COSE_Key is an EC2 key on P-256 made for this request alone (`{1: 2, -1: 1, -2: x, -3: y}`).
The `Session` it returns keeps the private key, the docType and elements asked for, and the
encryptionInfo text exactly as it was sent.

THE TRANSCRIPT IS THE VERIFIER'S. `session_transcript` builds

    [null, null, ["dcapi", SHA-256(CBOR([Base64EncryptionInfo, origin]))]]

from the encryptionInfo text this verifier sent and the origin it served the page from, read as
`mdoc.dc_api_origin` reads one. Nothing in it is read from the response.

THE RESPONSE. `open_response` takes the wallet's EncryptedResponse,
`["dcapi", {"enc": bstr, "cipherText": bstr}]`, as base64url. Its size and shape are held before
anything is decrypted. It is then opened with HPKE in base mode (RFC 9180; DHKEM(P-256,
HKDF-SHA256), HKDF-SHA256, AES-128-GCM) under the request's private key, with the encoded
transcript as `info` and an empty aad. The DeviceResponse inside is judged by
`mdoc.verify_device_response` under the same transcript and the session's docType, at this
verifier's clock: no function here takes an instant.

THE CODES. `malformed` for a response whose size or shape is wrong before it is opened; `hpke`
for one that does not open under this request's key and transcript; after it opens, `mdoc.py`'s
codes. `misconfigured` for a session that is not one.
"""
import hashlib
import secrets

from . import cbor, mdoc
from .sdjwt import Verdict, b64u_decode, b64u_encode

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric import ec

#: The protocol name the Digital Credentials API registry gives Annex C.
PROTOCOL = "org-iso-mdoc"

#: The EncryptionInfo nonce, in bytes.
NONCE_BYTES = 32

#: RFC 9180 section 7.1: DHKEM(P-256, HKDF-SHA256) encapsulates to Nenc = 65 bytes, an uncompressed
#: point. Section 7.3: AES-128-GCM's tag is Nt = 16 bytes.
ENC_BYTES = 65
TAG_BYTES = 16

#: The ciphertext of the largest DeviceResponse `mdoc.py` reads, and the EncryptedResponse around
#: it: enc, the two member names, the label and the heads take under 128 bytes.
MAX_CIPHERTEXT_BYTES = mdoc.MAX_DEVICE_RESPONSE_BYTES + TAG_BYTES
MAX_ENCRYPTED_RESPONSE_BYTES = MAX_CIPHERTEXT_BYTES + 128

#: The suite Annex C names, base mode.
SUITE = hpke.Suite(hpke.KEM.P256, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_128_GCM)

_P256_COORDINATE_BYTES = 32


class _Refused(Exception):
    """One refusal, raised where it is found and turned into the verdict in one place."""

    def __init__(self, code, reason):
        Exception.__init__(self, reason)
        self.code = code
        self.reason = reason


def session_transcript(encryption_info, origin):
    """The encoded SessionTranscript of an Annex C request:

        [null, null, ["dcapi", SHA-256(CBOR([Base64EncryptionInfo, origin]))]]

    `encryption_info` is the base64url text this verifier sent, as it sent it; `origin` the
    origin it served the page from, read as `mdoc.dc_api_origin` reads one. Raises ValueError
    for an origin that reads refuses and for an encryption_info that is not a non-empty string.
    """
    written = mdoc.dc_api_origin(origin)
    if not isinstance(encryption_info, str) or not encryption_info:
        raise ValueError("encryption_info is not the non-empty base64url text the request sent")
    info = cbor.encode([encryption_info, written])
    return cbor.encode([None, None, ["dcapi", hashlib.sha256(info).digest()]])


def _cose_key(public_key):
    """An EC2 P-256 public key as a COSE_Key: `{1: 2, -1: 1, -2: x, -3: y}`."""
    numbers = public_key.public_numbers()
    return {1: 2, -1: 1, -2: numbers.x.to_bytes(_P256_COORDINATE_BYTES, "big"),
            -3: numbers.y.to_bytes(_P256_COORDINATE_BYTES, "big")}


def _encryption_info_key(encryption_info):
    """The recipientPublicKey of an EncryptionInfo, as (x, y) integers, or None when the text is
    not the base64url of `["dcapi", {"nonce": bstr, "recipientPublicKey": EC2 P-256 COSE_Key}]`."""
    if not isinstance(encryption_info, str):
        return None
    try:
        value = cbor.decode(b64u_decode(encryption_info))
    except ValueError:  # a CborError is one, and so is a bad base64url or a non-ASCII text
        return None
    if not (isinstance(value, list) and len(value) == 2 and value[0] == "dcapi" and isinstance(value[1], dict)
            and set(value[1]) == {"nonce", "recipientPublicKey"}):
        return None
    nonce, key = value[1]["nonce"], value[1]["recipientPublicKey"]
    if not (isinstance(nonce, bytes) and nonce and isinstance(key, dict) and key.get(1) == 2 and key.get(-1) == 1
            and all(isinstance(key.get(k), bytes) and len(key[k]) == _P256_COORDINATE_BYTES for k in (-2, -3))):
        return None
    return int.from_bytes(key[-2], "big"), int.from_bytes(key[-3], "big")


def _items_request(doctype, namespaces):
    """`{"docType": doctype, "nameSpaces": {namespace: {element: false}}}`, the elements in the
    order given, or ValueError for a docType that is not a non-empty string or namespaces that are
    not a non-empty mapping of non-empty strings to non-empty lists of distinct non-empty strings."""
    if not (isinstance(doctype, str) and doctype and isinstance(namespaces, dict) and namespaces
            and all(isinstance(ns, str) and ns and isinstance(elements, (list, tuple)) and elements
                    and all(isinstance(e, str) and e for e in elements) and len(set(elements)) == len(elements)
                    for ns, elements in namespaces.items())):
        raise ValueError("a document request is a docType and {namespace: [element, ...]}, each a non-empty "
                         "string, no element named twice")
    return {"docType": doctype, "nameSpaces": {ns: {e: False for e in elements} for ns, elements in namespaces.items()}}


class Session:
    """One Annex C request: what this verifier sent, and the key that opens the answer.

    `encryption_info` is the base64url text sent to the page, `recipient_key` the P-256 private
    key whose public half it carries, `origin` the origin the page was served from, `doctype` and
    `namespaces` (`{namespace: [element, ...]}`) what the request asked for. Each is held at
    construction, with ValueError: a session that could not open its own answer is refused before
    any answer arrives.
    """

    __slots__ = ("origin", "encryption_info", "transcript", "doctype", "namespaces", "_recipient_key")

    def __init__(self, *, origin, encryption_info, recipient_key, doctype, namespaces):
        if not (isinstance(recipient_key, ec.EllipticCurvePrivateKey) and isinstance(recipient_key.curve, ec.SECP256R1)):
            raise ValueError("recipient_key is not a P-256 private key, the key DHKEM(P-256, HKDF-SHA256) opens with")
        carried = _encryption_info_key(encryption_info)
        if carried is None:
            raise ValueError("encryption_info is not the base64url of an EncryptionInfo, "
                             "[\"dcapi\", {\"nonce\": bstr, \"recipientPublicKey\": an EC2 P-256 COSE_Key}]")
        numbers = recipient_key.public_key().public_numbers()
        if carried != (numbers.x, numbers.y):
            raise ValueError("encryption_info carries another recipientPublicKey than recipient_key's: no answer "
                             "to it would open under this key")
        _items_request(doctype, namespaces)
        self.transcript = session_transcript(encryption_info, origin)
        self.origin = mdoc.dc_api_origin(origin)
        self.encryption_info = encryption_info
        self.doctype = doctype
        self.namespaces = {ns: tuple(elements) for ns, elements in namespaces.items()}
        self._recipient_key = recipient_key

    def __repr__(self):
        return "Session(origin=%r, doctype=%r)" % (self.origin, self.doctype)


def new_request(doc_requests, *, origin):
    """A new Annex C request for `doc_requests`, a list of one `(doctype, {namespace: [element,
    ...]})`, made from the page at `origin`. Returns `(session, {"deviceRequest": ...,
    "encryptionInfo": ...})`: the session to keep until the answer arrives, and the two base64url
    values the page hands the Digital Credentials API. One document per request, as
    `mdoc.verify_device_response` reads one. Raises ValueError for what it will not ask."""
    if not (isinstance(doc_requests, (list, tuple)) and len(doc_requests) == 1
            and isinstance(doc_requests[0], (list, tuple)) and len(doc_requests[0]) == 2):
        raise ValueError("doc_requests is a list of one (doctype, {namespace: [element, ...]}): one document "
                         "per request, as mdoc.verify_device_response reads one")
    doctype, namespaces = doc_requests[0]
    items = _items_request(doctype, namespaces)
    key = ec.generate_private_key(ec.SECP256R1())
    encryption_info = b64u_encode(cbor.encode(
        ["dcapi", {"nonce": secrets.token_bytes(NONCE_BYTES), "recipientPublicKey": _cose_key(key.public_key())}]))
    device_request = b64u_encode(cbor.encode(
        {"version": "1.0", "docRequests": [{"itemsRequest": cbor.tag24(cbor.encode(items))}]}))
    session = Session(origin=origin, encryption_info=encryption_info, recipient_key=key, doctype=doctype,
                      namespaces=namespaces)
    return session, {"deviceRequest": device_request, "encryptionInfo": encryption_info}


def _open(response, session):
    """The DeviceResponse bytes inside `response`, an EncryptedResponse as base64url, or _Refused."""
    if not isinstance(session, Session):
        raise _Refused("misconfigured", "session is not an annexc.Session: the request's key and transcript are "
                                        "what open its answer")
    if not isinstance(response, str):
        raise _Refused("malformed", "the response is not base64url text")
    if len(response) > (MAX_ENCRYPTED_RESPONSE_BYTES * 4 + 2) // 3:
        raise _Refused("malformed", "the response is longer than the largest EncryptedResponse this verifier "
                                    "opens (%d bytes)" % MAX_ENCRYPTED_RESPONSE_BYTES)
    try:
        envelope = cbor.decode(b64u_decode(response))
    except ValueError:  # a CborError is one, and so is a bad base64url or a non-ASCII text
        raise _Refused("malformed", "the response is not the base64url of one CBOR item") from None
    if not (isinstance(envelope, list) and len(envelope) == 2 and envelope[0] == "dcapi"
            and isinstance(envelope[1], dict) and set(envelope[1]) == {"enc", "cipherText"}
            and isinstance(envelope[1]["enc"], bytes) and isinstance(envelope[1]["cipherText"], bytes)):
        raise _Refused("malformed", "the response is not an EncryptedResponse, [\"dcapi\", {\"enc\": bstr, "
                                    "\"cipherText\": bstr}] and nothing else")
    enc, ciphertext = envelope[1]["enc"], envelope[1]["cipherText"]
    if len(enc) != ENC_BYTES:
        raise _Refused("malformed", "enc is %d bytes; DHKEM(P-256, HKDF-SHA256) encapsulates to %d (RFC 9180 "
                                    "section 7.1)" % (len(enc), ENC_BYTES))
    if len(ciphertext) > MAX_CIPHERTEXT_BYTES:
        raise _Refused("malformed", "cipherText is %d bytes, over the %d this verifier opens"
                                    % (len(ciphertext), MAX_CIPHERTEXT_BYTES))
    try:
        return SUITE.decrypt(enc + ciphertext, session._recipient_key, info=session.transcript)
    except (InvalidTag, ValueError):
        raise _Refused("hpke", "the response does not open under this request's key and SessionTranscript: "
                               "sealed to another key, for another origin or request, or altered") from None


def open_response(response, session, *, iaca_roots):
    """The verdict on `response`, the base64url EncryptedResponse a wallet answered `session`'s
    request with: opened under the session's key and transcript, then judged as a DeviceResponse
    for the session's docType against `iaca_roots`, at this verifier's clock. Returns a Verdict
    and never raises on bad input."""
    try:
        device_response = _open(response, session)
    except _Refused as refusal:
        return Verdict(False, refusal.code, refusal.reason)
    return mdoc.verify_device_response(device_response, session_transcript=session.transcript,
                                       iaca_roots=iaca_roots, doctype=session.doctype)
