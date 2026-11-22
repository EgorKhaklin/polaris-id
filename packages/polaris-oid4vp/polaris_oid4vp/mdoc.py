# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""mdoc.py -- an ISO/IEC 18013-5 mdoc DeviceResponse presented over OpenID4VP, verified.

It touches no socket, as `sdjwt.py` does not. Given the bytes a wallet sent, the
SessionTranscript this verifier built for its own request and the IACA roots its operator
configured, `verify_device_response` returns the package's `Verdict`: authentic or not, and
if not, the one check that said so.

WHAT AUTHENTIC MEANS HERE. A document signer certificate that chains to a configured root
bound to this docType signed the Mobile Security Object (MSO); every disclosed element
matches the digest the MSO signs for it, over the bytes the issuer wrote; the MSO is inside
its validity window; and the key the MSO names signed this session's transcript. It is not
a statement about revocation: the verdict's `revocation` says `no_status_claim` or
`unsupported_status`, never that a credential is current.

THE CHECKS, in order, each with the code a refusal carries:

    malformed            the container: its size, its CBOR, the members of the DeviceResponse
                         and of its one document
    doctype              the requested, the document's and the MSO's docType disagree
    issuer_signature     IssuerAuth is not a COSE_Sign1 this verifier reads, or does not verify
    issuer_key           every chain, certificate and trust refusal
    mso                  the MSO is not one, or names a digest algorithm outside SHA-256,
                         SHA-384 and SHA-512
    credential_validity  outside validFrom to validUntil, or signed ahead of the clock
    digest               an item that is not one, does not match its signed digest, repeats a
                         digestID or an element, or carries a salt under 16 bytes
    issuing_authority    an mDL's disclosed issuing_country or issuing_jurisdiction is not its
                         document signer's countryName or stateOrProvinceName
    device_auth          no device signature, a device MAC, or a signature header refused
    device_key           the MSO's device key is not an EC2 key on P-256 or P-384
    device_namespaces    device-signed elements, which this verifier does not read
    device_signature     the device signature does not verify over this verifier's transcript

TRUST COMES FROM CONFIGURATION ONLY. An `IacaRoot` is a certificate bound to the docTypes it
may sign. No root configured for a document's docType, and the document is refused; a root
carried in the response is never one. The chain is judged by `sdjwt.py`'s path rules, the
ones an SD-JWT VC's `x5c` is held to, and an mDL adds its own: its signer is issued directly
by the IACA, carries a SubjectKeyIdentifier and the id-mdl-ds extended key usage, and names the
IACA's countryName, and its stateOrProvinceName when the IACA carries one.

THE TRANSCRIPT IS THE VERIFIER'S. `redirect_session_transcript` builds OpenID4VP 1.0 B.2.6.1
from the request's own client_id, nonce, response_uri and the thumbprint of its response
key; `dc_api_session_transcript` builds B.2.6.2, for a request over the Digital Credentials
API, from the origin the request was made from, its nonce and the thumbprint of its response
key. Nothing in either is read from the response.
"""
import datetime
import hashlib
import hmac
import math
import re
import time

from . import cbor, cose, sdjwt
from .sdjwt import (DEFAULT_MAX_SKEW_SECONDS, MAX_X5C_CERTS, NO_STATUS_CLAIM, UNSUPPORTED_STATUS, Verdict,
                    b64u_decode, b64u_encode)

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate
except ImportError:  # pragma: no cover - exercised by the import-failure path only
    pass

#: A DeviceResponse larger than this is refused before the decoder runs. M1's captures are
#: under 3 KiB; a portrait is the largest element an mDL carries.
MAX_DEVICE_RESPONSE_BYTES = 512 * 1024

#: The docType whose document signer certificate has a profile of its own.
MDL_DOCTYPE = "org.iso.18013.5.1.mDL"
ID_MDL_DS = "1.0.18013.5.1.2"
#: The mDL's namespace, whose issuing_country and issuing_jurisdiction name its issuer (ISO/IEC 18013-5 7.2.1).
MDL_NAMESPACE = "org.iso.18013.5.1"

#: The shortest `random` an IssuerSignedItem may carry. A shorter salt lets a verifier that
#: holds the digest of a withheld element guess its value.
MIN_RANDOM_BYTES = 16

_DIGESTS = {"SHA-256": hashlib.sha256, "SHA-384": hashlib.sha384, "SHA-512": hashlib.sha512}
#: COSE elliptic curve identifiers this verifier reads for a device key: its name and the
#: length of a coordinate.
_COSE_CURVES = {1: ("P-256", "SECP256R1", 32), 2: ("P-384", "SECP384R1", 48)}
_JWK_COORDINATE_BYTES = {"P-256": 32, "P-384": 48, "P-521": 66}

_DEVICE_RESPONSE_MEMBERS = ("version", "documents", "status", "documentErrors")
_DOCUMENT_MEMBERS = ("docType", "issuerSigned", "deviceSigned", "errors")
_ITEM_MEMBERS = frozenset(("digestID", "random", "elementIdentifier", "elementValue"))

# RFC 3339 date-time as tag 0 carries it (RFC 8949 section 3.4.1): an uppercase T, and an
# uppercase Z or a numeric offset. ASCII digits only: Python's \d also matches other scripts'.
_TDATE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?"
                    r"(Z|[+-][0-9]{2}:[0-9]{2})")


class _Refused(Exception):
    """One refusal, raised where it is found and turned into the verdict in one place."""

    def __init__(self, code, reason):
        Exception.__init__(self, reason)
        self.code = code
        self.reason = reason


class _Unread(Exception):
    """An element value this verifier does not read."""


def _show(value):
    """A value from the response, for a reason an operator reads: escaped, and cut short."""
    text = repr(value)
    return text if len(text) <= 120 else text[:117] + "..."


# --------------------------------------------------------------------------- configuration

class IacaRoot:
    """An issuing authority's root certificate, and the docTypes its operator says it may sign.

    `certificate` is an `x509.Certificate`, PEM (text or bytes) or DER. `doctypes` is a
    non-empty list of docType strings. A certificate that does not parse, carries an extension
    that does not parse, or is not a CA is refused here, with a ValueError, so that a verifier
    cannot start with a root it would refuse every credential under.
    """

    __slots__ = ("certificate", "doctypes")

    def __init__(self, certificate, doctypes):
        if not sdjwt._HAVE_CRYPTO:
            raise ValueError("the cryptography package is not installed, so no certificate can be read")
        certificate = _load_certificate(certificate)
        why = _unparsed(certificate)
        if why:
            raise ValueError("the IACA root certificate carries %s" % why)
        try:
            is_ca = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except x509.ExtensionNotFound:
            is_ca = False
        if not is_ca:
            raise ValueError("the IACA root is not a CA certificate: its basicConstraints do not say cA")
        if (not isinstance(doctypes, (list, tuple, set, frozenset)) or not doctypes
                or not all(isinstance(d, str) and d for d in doctypes)):
            raise ValueError("an IACA root is bound to the docTypes it may sign, a non-empty list of docType "
                             "strings, not %s" % _show(doctypes))
        self.certificate = certificate
        self.doctypes = frozenset(doctypes)

    def __repr__(self):
        return "IacaRoot(%s, %s)" % (sdjwt._subject_of(self.certificate), sorted(self.doctypes))


def _load_certificate(value):
    if isinstance(value, x509.Certificate):
        return value
    try:
        if isinstance(value, str):
            return load_pem_x509_certificate(value.encode("ascii"))
        if isinstance(value, (bytes, bytearray)):
            value = bytes(value)
            return (load_pem_x509_certificate if b"-----BEGIN" in value else load_der_x509_certificate)(value)
    except Exception as exc:  # noqa: BLE001  any parse failure is the same refusal
        raise ValueError("the IACA root certificate does not parse: %s" % exc) from None
    raise ValueError("an IACA root certificate is an x509.Certificate, PEM or DER, not a %s" % type(value).__name__)


def _unparsed(certificate):
    """"" when the names and the extensions of `certificate` parse, else which does not and
    what the parser said. A certificate loads with a subject, an issuer or an extension that
    does not parse, and raises when it is first read: every certificate is asked here, once,
    so that no path rule meets that exception. The names are `sdjwt.py`'s rule, shared."""
    why = sdjwt._unparsed_name(certificate)
    if why:
        return why
    try:
        certificate.extensions
    except Exception as exc:  # noqa: BLE001  any parse failure is the same refusal
        return "an extension that does not parse: %s" % (str(exc) or type(exc).__name__)
    return ""


# --------------------------------------------------------------------------- the transcript

def jwk_thumbprint(jwk):
    """The RFC 7638 SHA-256 thumbprint of an EC public JWK, as 32 bytes. Raises ValueError for
    anything else. Only `crv`, `kty`, `x` and `y` are hashed (RFC 7638 section 3.2)."""
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC":
        raise ValueError("the response key is not an EC JWK")
    crv = jwk.get("crv")
    size = _JWK_COORDINATE_BYTES.get(crv) if isinstance(crv, str) else None
    if size is None:
        raise ValueError("the response key's crv is %s, not a curve this verifier reads" % _show(crv))
    for name in ("x", "y"):
        try:
            ok = isinstance(jwk.get(name), str) and len(b64u_decode(jwk[name])) == size
        except ValueError:
            ok = False
        if not ok:
            raise ValueError("the response key's %s is not the base64url of a %d-byte coordinate" % (name, size))
    # The members in lexical order with no whitespace. Each value has been held to an alphabet
    # that needs no JSON escaping, so this is the canonical form byte for byte.
    text = '{"crv":"%s","kty":"EC","x":"%s","y":"%s"}' % (crv, jwk["x"], jwk["y"])
    return hashlib.sha256(text.encode("ascii")).digest()


def redirect_session_transcript(*, client_id, nonce, jwk_thumbprint, response_uri):
    """The encoded SessionTranscript of a redirect request (OpenID4VP 1.0 B.2.6.1):

        [null, null, ["OpenID4VPHandover", SHA-256(CBOR([client_id, nonce, jwkThumbprint, response_uri]))]]

    `client_id` is the one the request carried, prefix and all; `jwk_thumbprint` the 32-byte
    thumbprint of the key the request asked the response to be encrypted to. This verifier
    reads encrypted responses only, so there is no transcript without that key. Raises
    ValueError for a missing or ill-typed value.
    """
    for name, value in (("client_id", client_id), ("nonce", nonce), ("response_uri", response_uri)):
        if not isinstance(value, str) or not value:
            raise ValueError("%s is not a non-empty string" % name)
    if not isinstance(jwk_thumbprint, bytes) or len(jwk_thumbprint) != 32:
        raise ValueError("jwk_thumbprint is not the 32-byte SHA-256 thumbprint of the response key")
    info = cbor.encode([client_id, nonce, jwk_thumbprint, response_uri])
    return cbor.encode([None, None, ["OpenID4VPHandover", hashlib.sha256(info).digest()]])


def dc_api_origin(origin):
    """`origin` as a request over the Digital Credentials API names it (OpenID4VP 1.0 Appendix A):
    a web origin, `scheme://host[:port]`, read by the parser `serve --cors-origin` reads one with
    (`serve.cors_origin`), so it comes back as a browser writes it: the scheme and the host
    lowercased and a default port dropped (`HTTPS://Verifier.Example:443` is
    `https://verifier.example`). Raises ValueError for a value written with the `origin:` prefix
    (B.2.6.2: "It MUST NOT be prefixed with origin:."), for `*`, which names no one origin, for
    every value `cors_origin` refuses (a path, a query, no scheme among them), and for an http
    origin a browser does not count as a secure context: the API exists only in one (Digital
    Credentials, section 7.7: "[Exposed=Window, SecureContext] interface DigitalCredential"), and
    over http only 127.0.0.0/8, ::1, localhost and a name ending in .localhost are one (W3C Secure
    Contexts, section 3.1)."""
    if isinstance(origin, str) and origin[:7].lower() == "origin:":
        raise ValueError("%r is written with the origin: prefix; the origin an OpenID4VPDCAPIHandoverInfo "
                         "carries \"MUST NOT be prefixed with origin:\" (OpenID4VP 1.0 B.2.6.2)" % (origin,))
    # serve.py's own parser. Imported when it is called: serve.py imports the verifier, which
    # imports this module.
    from .serve import cors_origin
    written = cors_origin(origin)
    if written == "*":
        raise ValueError("'*' is not one origin: a request over the Digital Credentials API is made from "
                         "one, scheme://host[:port]")
    if written.startswith("http:") and not _secure_context_over_http(written[len("http://"):]):
        raise ValueError("%r is not an origin a browser offers the Digital Credentials API at: it offers "
                         "the API only in a secure context (Digital Credentials, section 7.7), and over "
                         "http only 127.0.0.0/8, [::1], localhost and a name ending in .localhost are one "
                         "(W3C Secure Contexts, section 3.1); serve the page over https" % (origin,))
    return written


def _secure_context_over_http(host_port):
    """True for a `host[:port]`, as `serve.cors_origin` writes it, whose host W3C Secure Contexts
    section 3.1 counts as potentially trustworthy under http: an IPv4 address in 127.0.0.0/8, the
    IPv6 address ::1, and, either with one trailing dot, `localhost` or a name ending in
    `.localhost` ("If origin's host matches one of the CIDR notations 127.0.0.0/8 or ::1/128
    [RFC4632], return "Potentially Trustworthy"."; "origin's host is "localhost" or "localhost."
    origin's host ends with ".localhost" or ".localhost."")."""
    if host_port.startswith("["):
        return host_port[:host_port.find("]") + 1] == "[::1]"
    host = host_port.rsplit(":", 1)[0]
    labels = host.split(".")
    if len(labels) == 4 and all(label.isdigit() for label in labels):
        return labels[0] == "127"
    name = host[:-1] if host.endswith(".") else host
    return name == "localhost" or name.endswith(".localhost")


def dc_api_session_transcript(*, origin, nonce, jwk_thumbprint):
    """The encoded SessionTranscript of a request over the Digital Credentials API (OpenID4VP
    1.0 B.2.6.2), for Response Mode dc_api.jwt:

        [null, null, ["OpenID4VPDCAPIHandover", SHA-256(CBOR([origin, nonce, jwkThumbprint]))]]

    `origin` is the origin the request was made from, read as `dc_api_origin` reads it (B.2.6.2:
    "The first element MUST be the string representing the Origin of the request as described in
    Appendix A.2. It MUST NOT be prefixed with origin:."); `nonce` the request's nonce;
    `jwk_thumbprint` the 32-byte thumbprint of the key the request asked the response to be
    encrypted to ("For the Response Mode dc_api.jwt, the third element MUST be the JWK SHA-256
    Thumbprint as defined in [RFC7638], encoded as a Byte String, of the Verifier's public key
    used to encrypt the response."). Raises ValueError for an origin `dc_api_origin` refuses and
    for a missing or ill-typed nonce or thumbprint.
    """
    written = dc_api_origin(origin)
    if not isinstance(nonce, str) or not nonce:
        raise ValueError("nonce is not a non-empty string")
    if not isinstance(jwk_thumbprint, bytes) or len(jwk_thumbprint) != 32:
        raise ValueError("jwk_thumbprint is not the 32-byte SHA-256 thumbprint of the response key")
    info = cbor.encode([written, nonce, jwk_thumbprint])
    return cbor.encode([None, None, ["OpenID4VPDCAPIHandover", hashlib.sha256(info).digest()]])


# --------------------------------------------------------------------------- the verdict

def verify_device_response(device_response, *, session_transcript, iaca_roots, doctype=None, now=None,
                           max_skew_seconds=DEFAULT_MAX_SKEW_SECONDS):
    """Verify one DeviceResponse. Returns a Verdict and never raises on bad input.

    `session_transcript` is the encoded SessionTranscript the caller built for its own request
    (`redirect_session_transcript`, or `dc_api_session_transcript` for a request over the Digital
    Credentials API). `iaca_roots` is the configured `IacaRoot`s. `doctype`, when
    given, is the docType the request asked for. `now` is POSIX seconds, for judging a captured
    response: left None the clock is read, and when it is supplied the verdict's reason says
    "judged at the supplied instant".

    The verdict's `claims` are `{namespace: {element: value}}`, byte strings as base64url and
    dates as their text; `disclosed` holds each `(namespace, element)`; `issuer_subject` and
    `issuer_anchor` name the document signer and the root its chain ended at.
    """
    return judge_device_response(device_response, session_transcript=session_transcript, iaca_roots=iaca_roots,
                                 doctype=doctype, now=now, max_skew_seconds=max_skew_seconds)[0]


def judge_device_response(device_response, *, session_transcript, iaca_roots, doctype=None, now=None,
                          max_skew_seconds=DEFAULT_MAX_SKEW_SECONDS):
    """`verify_device_response`, and beside the verdict the disclosed elements as the issuer
    signed them, `{(namespace, element): value}` in CBOR's types, for a caller that holds a
    query's `values` to them. A refusal hands back no element."""
    stated = ""
    try:
        if not sdjwt._HAVE_CRYPTO:
            raise _Refused("no_backend", "the cryptography package is not installed, so no signature can be "
                                         "checked. Install polaris-oid4vp with its dependencies rather than "
                                         "reading this as a refusal of the credential")
        transcript, roots, at = _configuration(session_transcript, iaca_roots, doctype, now, max_skew_seconds)
        if now is not None:
            stated = "judged at the supplied instant %s, not at this verifier's clock" % (
                datetime.datetime.fromtimestamp(at, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        verdict, elements = _judge(device_response, transcript, roots, doctype, at, max_skew_seconds)
    except _Refused as refusal:
        reason = refusal.reason
        if stated:
            # Joined before the Verdict is made, so the cut of a long reason counts all of it.
            reason = "%s (%s)" % (reason, stated) if reason else stated
        return Verdict(False, refusal.code, reason), {}
    if stated:
        verdict.reason = "%s (%s)" % (verdict.reason, stated) if verdict.reason else stated
    return verdict, elements


def _configuration(session_transcript, iaca_roots, doctype, now, max_skew_seconds):
    """What the caller supplied, held to its type before anything from the wallet is read:
    (transcript bytes, roots, the instant as POSIX seconds)."""
    try:
        shape = cbor.decode(session_transcript) if isinstance(session_transcript, bytes) else None
    except cbor.CborError:
        shape = None
    if not isinstance(shape, list) or len(shape) != 3:
        raise _Refused("misconfigured", "session_transcript is not an encoded SessionTranscript: the bytes of a "
                                        "CBOR array of three items, as redirect_session_transcript builds it")
    roots = () if iaca_roots is None else iaca_roots
    if not isinstance(roots, (list, tuple)) or not all(isinstance(root, IacaRoot) for root in roots):
        raise _Refused("misconfigured", "iaca_roots is not a list of IacaRoot values: a root is trusted only "
                                        "for the docTypes it is bound to")
    if doctype is not None and (not isinstance(doctype, str) or not doctype):
        raise _Refused("misconfigured", "doctype is not a docType string")
    if type(max_skew_seconds) not in (int, float) or not math.isfinite(max_skew_seconds) or max_skew_seconds < 0:
        raise _Refused("misconfigured", "max_skew_seconds is not a number of seconds, zero or more")
    if now is None:
        return session_transcript, roots, time.time()
    try:
        if type(now) not in (int, float) or not math.isfinite(now):
            raise ValueError
        datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
    except (ValueError, OverflowError, OSError):
        raise _Refused("misconfigured", "now is not an instant in POSIX seconds") from None
    return session_transcript, roots, now


def _judge(device_response, transcript, roots, doctype, now, max_skew_seconds):
    # ---- the container
    if not isinstance(device_response, (bytes, bytearray)):
        raise _Refused("malformed", "the DeviceResponse is not bytes")
    if not device_response:
        raise _Refused("malformed", "the DeviceResponse is empty")
    if len(device_response) > MAX_DEVICE_RESPONSE_BYTES:
        # Before any parsing, as sdjwt.py bounds a presentation.
        raise _Refused("malformed", "the DeviceResponse is %d bytes, over the %d byte limit"
                       % (len(device_response), MAX_DEVICE_RESPONSE_BYTES))
    try:
        response = cbor.decode(bytes(device_response))
    except cbor.CborError as exc:
        raise _Refused("malformed", "the DeviceResponse is not CBOR this verifier reads: %s" % exc) from None
    if not isinstance(response, dict):
        raise _Refused("malformed", "the DeviceResponse is not a map")
    _no_other_member(response, _DEVICE_RESPONSE_MEMBERS, "malformed", "the DeviceResponse")
    if response.get("version") != "1.0":
        raise _Refused("malformed", "the DeviceResponse states version %s; this verifier reads 1.0"
                       % _show(response.get("version")))
    status = response.get("status")
    if type(status) is not int or status != 0:
        raise _Refused("malformed", "the DeviceResponse states status %s, not 0: it reports an error, not a "
                                    "presentation" % _show(status))
    if "documentErrors" in response:
        raise _Refused("malformed", "the DeviceResponse carries documentErrors: a document the wallet did not "
                                    "return")
    documents = response.get("documents")
    if not isinstance(documents, list):
        raise _Refused("malformed", "the DeviceResponse has no documents array")
    if len(documents) != 1:
        raise _Refused("malformed", "the DeviceResponse carries %d documents; exactly one is read, each mdoc in "
                                    "a DeviceResponse of its own (HAIP 1.0 section 5.3.1)" % len(documents))
    document = documents[0]
    if not isinstance(document, dict):
        raise _Refused("malformed", "a document is a map, and this one is not")
    _no_other_member(document, _DOCUMENT_MEMBERS, "malformed", "the document")
    if "errors" in document:
        raise _Refused("malformed", "the document carries errors: elements the wallet did not return")
    doc_type = document.get("docType")
    if not isinstance(doc_type, str) or not doc_type:
        raise _Refused("malformed", "the document's docType is not a text string")
    issuer_signed = document.get("issuerSigned")
    if not isinstance(issuer_signed, dict):
        raise _Refused("malformed", "the document has no issuerSigned map")
    _no_other_member(issuer_signed, ("nameSpaces", "issuerAuth"), "malformed", "issuerSigned")
    device_signed = document.get("deviceSigned")
    if isinstance(device_signed, dict):
        _no_other_member(device_signed, ("nameSpaces", "deviceAuth"), "malformed", "deviceSigned")
    if doctype is not None and doc_type != doctype:
        raise _Refused("doctype", "the request asked for docType %s and the document is %s"
                       % (_show(doctype), _show(doc_type)))

    # ---- who signed: IssuerAuth, its certificate chain, and the MSO signature
    try:
        issuer_auth = cose.parse_sign1(issuer_signed.get("issuerAuth"))
    except cose.CoseError as exc:
        raise _Refused("issuer_signature", "IssuerAuth: %s" % exc) from None
    leaf, anchor = _document_signer(issuer_auth, roots, doc_type, now)
    if issuer_auth.payload is None:
        raise _Refused("issuer_signature", "the MSO is not in the IssuerAuth payload: a detached payload is "
                                           "not read")
    try:
        cose.verify_sign1(issuer_auth, leaf.public_key())
    except cose.CoseError as exc:
        raise _Refused("issuer_signature", "IssuerAuth: %s" % exc) from None

    # ---- what was signed: the MSO
    try:
        mso_bytes = cbor.decode(issuer_auth.payload)
    except cbor.CborError as exc:
        raise _Refused("mso", "the IssuerAuth payload is not MobileSecurityObjectBytes (tag 24): %s" % exc) from None
    if not isinstance(mso_bytes, cbor.Tag24):
        raise _Refused("mso", "the IssuerAuth payload is not MobileSecurityObjectBytes (tag 24)")
    try:
        mso = cbor.decode(mso_bytes.inner)
    except cbor.CborError as exc:
        raise _Refused("mso", "the MSO is not CBOR this verifier reads: %s" % exc) from None
    if not isinstance(mso, dict):
        raise _Refused("mso", "the MSO is not a map")
    if mso.get("version") != "1.0":
        raise _Refused("mso", "the MSO states version %s; this verifier reads 1.0" % _show(mso.get("version")))
    if mso.get("docType") != doc_type:
        raise _Refused("doctype", "the MSO is for docType %s and the document says %s"
                       % (_show(mso.get("docType")), _show(doc_type)))
    algorithm = mso.get("digestAlgorithm")
    digest = _DIGESTS.get(algorithm) if isinstance(algorithm, str) else None
    if digest is None:
        raise _Refused("mso", "digestAlgorithm is %s; this verifier reads SHA-256, SHA-384 and SHA-512"
                       % _show(algorithm))
    value_digests = mso.get("valueDigests")
    if not (isinstance(value_digests, dict)
            and all(isinstance(ns, str) and isinstance(table, dict)
                    and all(type(n) is int and n >= 0 and isinstance(d, bytes) for n, d in table.items())
                    for ns, table in value_digests.items())):
        raise _Refused("mso", "valueDigests is not a map of namespaces to maps of digestID to digest")
    _validity_window(mso.get("validityInfo"), now, max_skew_seconds)

    # ---- what was disclosed, each item against its signed digest
    elements, claims = _disclosed(issuer_signed, value_digests, digest)

    # ---- whose document it says it is: an mDL's issuing elements, once their digests matched
    if doc_type == MDL_DOCTYPE:
        why = _issuing_authority_refusal(elements, leaf)
        if why:
            raise _Refused("issuing_authority", why)

    # ---- who presents it: the device signature, under the MSO's key, over this session
    _device_signature(device_signed, mso, transcript, doc_type)

    if "status" in mso:
        revocation = {"state": UNSUPPORTED_STATUS, "checked": False, "uri": None, "idx": None,
                      "reason": "the MSO names a status and this verifier did not read it: mdoc status is not "
                                "checked here, so whether the issuer has revoked this credential is unknown"}
    else:
        revocation = {"state": NO_STATUS_CLAIM, "checked": False, "uri": None, "idx": None,
                      "reason": "the MSO names no status, so there is none to read"}
    return Verdict(True, claims=claims, revocation=revocation, disclosed=elements,
                   issuer_subject=sdjwt._subject_of(leaf), issuer_anchor=sdjwt._subject_of(anchor)), elements


def _no_other_member(value, read, code, what):
    other = sorted((key for key in value if key not in read), key=repr)
    if other:
        raise _Refused(code, "%s carries a member this verifier does not read (%s)"
                       % (what, ", ".join(_show(key) for key in other[:4])))


def _mdoc_words(why):
    """A path rule's reason, written in sdjwt.py for an SD-JWT VC's x5c, in an mdoc's words."""
    for theirs, ours in (("the x5c leaf", "the document signer certificate"),
                         ("credential signing", "MSO signing"), (" (HAIP 1.0 6.1.1)", "")):
        why = why.replace(theirs, ours)
    return re.sub(r"\bx5c\b", "x5chain", why)


def _document_signer(issuer_auth, roots, doc_type, now):
    """(the document signer certificate, the configured root its chain ended at), or a refusal."""
    try:
        chain = cose.x5chain(issuer_auth)
    except cose.CoseError as exc:
        raise _Refused("issuer_key", "IssuerAuth: %s" % exc) from None
    if len(chain) > MAX_X5C_CERTS:
        # Before a certificate is parsed or a signature checked.
        raise _Refused("issuer_key", "x5chain carries %d certificates; at most %d are read, the document signer "
                                     "certificate and %d CAs" % (len(chain), MAX_X5C_CERTS, MAX_X5C_CERTS - 1))
    certificates = []
    for position, raw in enumerate(chain):
        try:
            certificate = load_der_x509_certificate(raw)
        except Exception as exc:  # noqa: BLE001  any parse failure is the same refusal
            raise _Refused("issuer_key", "x5chain certificate %d does not parse: %s" % (position, exc)) from None
        why = _unparsed(certificate)
        if why:
            raise _Refused("issuer_key", "x5chain certificate %d carries %s" % (position, why))
        certificates.append(certificate)
    leaf, intermediates = certificates[0], certificates[1:]
    if not roots:
        raise _Refused("issuer_key", "no IACA root is configured, so nothing can be said about who signed this "
                                     "document")
    admitted = [root for root in roots if doc_type in root.doctypes]
    if not admitted:
        raise _Refused("issuer_key", "no IACA root is configured for docType %s: the %d configured are bound to "
                                     "other docTypes" % (_show(doc_type), len(roots)))
    why = sdjwt._not_an_issuer_leaf(leaf)
    if why:
        raise _Refused("issuer_key", _mdoc_words(why))
    # A configured root is an anchor whatever docType it is bound to, and so is any self-signed
    # certificate: trust comes from configuration, never from what the response sends.
    if sdjwt._an_anchor_in_the_chain(intermediates, [root.certificate for root in roots]):
        raise _Refused("issuer_key", "the x5chain carries a trust anchor after the document signer certificate "
                                     "(a self-signed certificate, or one that holds a configured root's key); "
                                     "trust comes only from configuration")
    anchor = None
    for root in admitted:
        why = sdjwt._chains_to(leaf, root.certificate, now, intermediates)
        # "" chains and a string refuses; anything else is no chain to this root.
        if not isinstance(why, str):
            continue
        why = why or sdjwt._leaf_eku_refusal(leaf)
        why = why or sdjwt._outside_validity(
            root.certificate, datetime.datetime.fromtimestamp(now, datetime.timezone.utc), "the IACA root")
        if why:
            raise _Refused("issuer_key", _mdoc_words(why))
        anchor = root.certificate
        break
    if anchor is None:
        raise _Refused("issuer_key", "the document signer certificate does not chain to any IACA root configured "
                                     "for docType %s" % _show(doc_type))
    if doc_type == MDL_DOCTYPE:
        why = _mdl_profile_refusal(leaf, intermediates, anchor)
        if why:
            raise _Refused("issuer_key", why)
    return leaf, anchor


def _subject_values(certificate, oid):
    """The values of a certificate subject's attributes of type `oid`, in their order."""
    return [attribute.value for attribute in certificate.subject.get_attributes_for_oid(oid)]


def _mdl_profile_refusal(leaf, intermediates, iaca):
    """"" when the document signer certificate meets the mDL profile, else why not: issued
    directly by the IACA, with a SubjectKeyIdentifier and the id-mdl-ds extended key usage, and
    naming the IACA's countryName, and its stateOrProvinceName when the IACA carries one
    (ISO/IEC 18013-5 9.3.3, Tables B.1 and B.3). OID4VCgo's checkSignerNamesItsIACA makes the
    same two comparisons."""
    if intermediates:
        return ("the document signer certificate of an %s is issued directly by its IACA, and this x5chain "
                "carries %d CA certificate(s) between them" % (MDL_DOCTYPE, len(intermediates)))
    try:
        leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    except x509.ExtensionNotFound:
        return ("the document signer certificate has no SubjectKeyIdentifier, which the signer of an %s carries"
                % MDL_DOCTYPE)
    try:
        usages = [oid.dotted_string for oid in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value]
    except x509.ExtensionNotFound:
        usages = []
    if ID_MDL_DS not in usages:
        return ("the document signer certificate's extended key usage does not name id-mdl-ds (%s), which the "
                "signer of an %s carries" % (ID_MDL_DS, MDL_DOCTYPE))
    iaca_country = _subject_values(iaca, x509.NameOID.COUNTRY_NAME)
    if not iaca_country:
        return ("the IACA root names no countryName, which the IACA of an %s and its document signer each carry"
                % MDL_DOCTYPE)
    country = _subject_values(leaf, x509.NameOID.COUNTRY_NAME)
    if country != iaca_country:
        return ("the document signer certificate's countryName is %s and its IACA's is %s: the signer of an %s "
                "names its IACA's" % (_show(country), _show(iaca_country), MDL_DOCTYPE))
    iaca_state = _subject_values(iaca, x509.NameOID.STATE_OR_PROVINCE_NAME)
    state = _subject_values(leaf, x509.NameOID.STATE_OR_PROVINCE_NAME)
    if iaca_state and state != iaca_state:
        return ("the document signer certificate's stateOrProvinceName is %s and its IACA's is %s: the signer of "
                "an %s names its IACA's" % (_show(state), _show(iaca_state), MDL_DOCTYPE))
    return ""


def _issuing_authority_refusal(elements, leaf):
    """"" when an mDL's disclosed issuing_country is its document signer's countryName, and its
    disclosed issuing_jurisdiction the document signer's stateOrProvinceName when it carries one
    (ISO/IEC 18013-5 7.2.1), else why not. An element not disclosed is not judged. OID4VCgo's
    checkIssuingAuthority makes the same comparisons, there in further namespaces too."""
    for element, oid, attribute in (("issuing_country", x509.NameOID.COUNTRY_NAME, "countryName"),
                                    ("issuing_jurisdiction", x509.NameOID.STATE_OR_PROVINCE_NAME,
                                     "stateOrProvinceName")):
        if (MDL_NAMESPACE, element) not in elements:
            continue
        names = _subject_values(leaf, oid)
        if element == "issuing_jurisdiction" and not names:
            continue
        value = elements[(MDL_NAMESPACE, element)]
        if not isinstance(value, str) or value not in names:
            return ("the disclosed %s is %s, and the document signer certificate's %s is %s: an %s names the "
                    "issuer whose key signed it" % (element, _show(value), attribute, _show(names), MDL_DOCTYPE))
    return ""


def _tdate(value):
    """The instant of a date and time, in POSIX seconds, or None when `value` is not tag 0 over
    RFC 3339 text."""
    if not isinstance(value, cbor.Tagged) or value.tag != cbor.TAG_TDATE or not isinstance(value.value, str):
        return None
    match = _TDATE.fullmatch(value.value)
    if not match:
        return None
    year, month, day, hour, minute, second = (int(group) for group in match.groups()[:6])
    zone, offset = match.group(7), 0
    if zone != "Z":
        hours, minutes = int(zone[1:3]), int(zone[4:6])
        if hours > 23 or minutes > 59:
            return None
        offset = (hours * 3600 + minutes * 60) * (1 if zone[0] == "+" else -1)
    try:
        written = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    return written.timestamp() - offset


def _validity_window(validity, now, max_skew_seconds):
    if not isinstance(validity, dict):
        raise _Refused("mso", "the MSO's validityInfo is not a map")
    instants = {}
    for member in ("signed", "validFrom", "validUntil"):
        instants[member] = _tdate(validity.get(member))
        if instants[member] is None:
            raise _Refused("mso", "validityInfo's %s is not a date and time (tag 0 over RFC 3339 text)" % member)

    def text(member):
        return validity[member].value

    # The allowance for clock skew is the one an SD-JWT VC's exp and nbf get.
    if now > instants["validUntil"] + max_skew_seconds:
        raise _Refused("credential_validity", "the MSO's validUntil, %s, passed %d seconds ago, beyond the %d "
                       "second allowance" % (text("validUntil"), now - instants["validUntil"], max_skew_seconds))
    if now < instants["validFrom"] - max_skew_seconds:
        raise _Refused("credential_validity", "the MSO's validFrom, %s, is %d seconds ahead, beyond the %d second "
                       "allowance" % (text("validFrom"), instants["validFrom"] - now, max_skew_seconds))
    if now < instants["signed"] - max_skew_seconds:
        raise _Refused("credential_validity", "the MSO says it was signed at %s, %d seconds ahead, beyond the %d "
                       "second allowance" % (text("signed"), instants["signed"] - now, max_skew_seconds))


def _disclosed(issuer_signed, value_digests, digest):
    """({(namespace, element): the signed value}, {namespace: {element: its JSON form}})."""
    name_spaces = issuer_signed.get("nameSpaces", {})
    if not (isinstance(name_spaces, dict)
            and all(isinstance(ns, str) and isinstance(items, list) for ns, items in name_spaces.items())):
        raise _Refused("digest", "issuerSigned's nameSpaces is not a map of namespaces to arrays of items")
    elements, claims = {}, {}
    for ns, items in name_spaces.items():
        # A digest is looked up in the namespace its item arrives in, and nowhere else.
        table = value_digests.get(ns, {})
        seen = set()
        for item in items:
            if not isinstance(item, cbor.Tag24):
                raise _Refused("digest", "an item in namespace %s is not IssuerSignedItemBytes (tag 24)" % _show(ns))
            try:
                members = cbor.decode(item.inner)
            except cbor.CborError as exc:
                raise _Refused("digest", "an item in namespace %s is not CBOR this verifier reads: %s"
                               % (_show(ns), exc)) from None
            if not isinstance(members, dict) or frozenset(members) != _ITEM_MEMBERS:
                raise _Refused("digest", "an item in namespace %s is not a map of digestID, random, "
                                         "elementIdentifier and elementValue" % _show(ns))
            digest_id, element = members["digestID"], members["elementIdentifier"]
            if type(digest_id) is not int or digest_id < 0:
                raise _Refused("digest", "an item in namespace %s has a digestID that is not an unsigned integer"
                               % _show(ns))
            if not isinstance(element, str) or not element:
                raise _Refused("digest", "an item in namespace %s has an elementIdentifier that is not a text "
                                         "string" % _show(ns))
            shown = "%s (digestID %d)" % (_show("%s/%s" % (ns, element)), digest_id)
            if not isinstance(members["random"], bytes):
                raise _Refused("digest", "%s has a random that is not a byte string" % shown)
            if len(members["random"]) < MIN_RANDOM_BYTES:
                raise _Refused("digest", "%s has a random of %d bytes, fewer than %d"
                               % (shown, len(members["random"]), MIN_RANDOM_BYTES))
            if digest_id in seen:
                raise _Refused("digest", "namespace %s carries digestID %d twice" % (_show(ns), digest_id))
            if (ns, element) in elements:
                raise _Refused("digest", "namespace %s carries element %s twice" % (_show(ns), _show(element)))
            if digest_id not in table:
                raise _Refused("digest", "the MSO signs no digest for %s" % shown)
            # Over the item's bytes exactly as they arrived, tag 24 head included.
            if not hmac.compare_digest(table[digest_id], digest(item.raw).digest()):
                raise _Refused("digest", "%s does not match the digest the MSO signs" % shown)
            try:
                claims.setdefault(ns, {})[element] = _json_value(members["elementValue"])
            except _Unread as exc:
                raise _Refused("digest", "%s carries a value this verifier does not read (%s)" % (shown, exc)) from None
            seen.add(digest_id)
            elements[(ns, element)] = members["elementValue"]
    return elements, claims


def _json_value(value):
    """An element value as JSON can carry it: byte strings as base64url, a date or a date and
    time as its text, a map's integer keys as text."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, bytes):
        return b64u_encode(value)
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            name = key if isinstance(key, str) else str(key)
            if name in out:
                raise _Unread("two keys of a map read as %s" % _show(name))
            out[name] = _json_value(item)
        return out
    if isinstance(value, cbor.Tagged) and value.tag in (cbor.TAG_TDATE, cbor.TAG_FULL_DATE):
        if isinstance(value.value, str):
            return value.value
        raise _Unread("tag %d over something that is not text" % value.tag)
    if isinstance(value, cbor.Tagged):
        raise _Unread("tag %d" % value.tag)
    raise _Unread("an embedded CBOR item, tag 24")


def _device_public_key(key):
    if not isinstance(key, dict):
        raise _Refused("device_key", "deviceKeyInfo's deviceKey is not a COSE_Key, a map")
    if type(key.get(1)) is not int or key[1] != 2:
        raise _Refused("device_key", "the device key is not an EC2 key (its kty is %s)" % _show(key.get(1)))
    curve = _COSE_CURVES.get(key.get(-1)) if type(key.get(-1)) is int else None
    if curve is None:
        raise _Refused("device_key", "the device key's curve is %s, not P-256 or P-384" % _show(key.get(-1)))
    name, curve_class, size = curve
    x, y = key.get(-2), key.get(-3)
    if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == size and len(y) == size):
        raise _Refused("device_key", "the device key's x and y are not byte strings of %d bytes each, the "
                                     "length of a coordinate on %s" % (size, name))
    try:
        return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                             getattr(ec, curve_class)()).public_key()
    except ValueError:
        raise _Refused("device_key", "the device key is not a point on %s" % name) from None


def _device_signature(device_signed, mso, transcript, doc_type):
    auth = device_signed.get("deviceAuth") if isinstance(device_signed, dict) else None
    if isinstance(auth, dict) and "deviceMac" in auth:
        raise _Refused("device_auth", "the document carries a device MAC, which this verifier does not accept: "
                                      "its key cannot be named in this flow, and only a device signature is read")
    if isinstance(auth, dict):
        _no_other_member(auth, ("deviceSignature",), "device_auth", "deviceAuth")
    if not isinstance(auth, dict) or "deviceSignature" not in auth:
        raise _Refused("device_auth", "the document carries no device signature, so nothing binds it to its "
                                      "holder or to this request")
    try:
        signature = cose.parse_sign1(auth["deviceSignature"])
    except cose.CoseError as exc:
        raise _Refused("device_auth", "the device signature: %s" % exc) from None
    if signature.payload is not None:
        raise _Refused("device_auth", "the device signature carries its payload; DeviceAuthentication is "
                                      "detached, and this verifier builds it from its own transcript")
    info = mso.get("deviceKeyInfo")
    if not isinstance(info, dict):
        raise _Refused("device_key", "the MSO has no deviceKeyInfo map")
    public_key = _device_public_key(info.get("deviceKey"))
    name_spaces = device_signed.get("nameSpaces")
    if not isinstance(name_spaces, cbor.Tag24):
        raise _Refused("device_namespaces", "deviceSigned's nameSpaces is not DeviceNameSpacesBytes (tag 24)")
    try:
        signed_by_device = cbor.decode(name_spaces.inner)
    except cbor.CborError as exc:
        raise _Refused("device_namespaces", "DeviceNameSpaces is not CBOR this verifier reads: %s" % exc) from None
    if not isinstance(signed_by_device, dict):
        raise _Refused("device_namespaces", "DeviceNameSpaces is not a map")
    if signed_by_device:
        raise _Refused("device_namespaces", "the document carries device-signed elements (%s), which this "
                       "verifier does not read" % ", ".join(_show(ns) for ns in list(signed_by_device)[:4]))
    # DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes],
    # under tag 24. The transcript is this verifier's own bytes and the namespaces are the bytes
    # that arrived, so the array is written item by item and neither is decoded and re-encoded.
    authentication = cbor.encode(cbor.tag24(
        b"\x84" + cbor.encode("DeviceAuthentication") + transcript + cbor.encode(doc_type) + name_spaces.raw))
    try:
        cose.verify_sign1(signature, public_key, authentication)
    except cose.CoseError as exc:
        raise _Refused("device_signature", "the device signature: %s, under the MSO's device key and over the "
                                           "SessionTranscript this verifier built for its own request" % exc) from None
