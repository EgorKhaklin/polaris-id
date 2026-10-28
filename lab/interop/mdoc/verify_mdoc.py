#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Verify one ISO/IEC 18013-5 mdoc DeviceResponse presented over OpenID4VP 1.0, offline.

    python3 -I verify_mdoc.py CAPTURE_DIR [--root PEM ...] [--at 2026-10-11T00:00:00Z]

A lab prototype on cbor2 and cryptography, for plan 025 milestone 1. For every document it checks:

  issuer auth  the IssuerAuth COSE_Sign1 (ES256 under a P-256 key, ES384 under a P-384 key: a policy,
               RFC 9053 s2.1 suggests the pairing) under the x5chain leaf, x5chain taken from the
               protected header when it is there, else from the unprotected one (RFC 9052 s3); the
               chain up to a CONFIGURED IACA root (--root; none configured refuses), every
               certificate valid at the instant; for an mDL, the DS certificate's
               SubjectKeyIdentifier and id-mdl-ds EKU; in either COSE_Sign1 (IssuerAuth,
               DeviceSignature), a crit that is not a non-empty array of the alg and x5chain labels,
               or names one absent from the protected header (RFC 9052 s3.1: a fatal error),
               refuses, and so does a crit in the unprotected header (a choice of this verifier:
               s3.1's MUST there binds the sender);
  digests      the MSO's valueDigests over each IssuerSignedItemBytes, hashed as the ORIGINAL
               tag-24 bytes sliced from the response, never re-encoded; each item's random at
               least 16 bytes (a policy);
  docType      the MSO's docType is the document's;
  validity     validityInfo validFrom <= at <= validUntil, and signed <= at;
  device auth  the DeviceSignature COSE_Sign1 under the MSO's deviceKey over DeviceAuthentication,
               built from the OpenID4VP 1.0 SessionTranscript (Appendix B.2.6.1): client_id, nonce,
               the RFC 7638 thumbprint of the response encryption key (null for plain direct_post
               only), response_uri; over the Digital Credentials API (B.2.6.2) the origin, the nonce
               and that thumbprint (null for plain dc_api only). A DeviceMac refuses (not in scope);
  device keys  the MSO deviceKey is an EC2 key whose curve is consistent with its key type (RFC 9053 s7.1);
  device data  every element in DeviceSigned is authorized by the MSO's KeyAuthorizations;
  request      when the inputs carry the DCQL doctype_value, every document is of that docType;
  claims       when they carry the DCQL claims (OpenID4VP 1.0 6.3, 6.4.1), one option is met (every claim,
               or one of claim_sets): each of its claims disclosed in IssuerSigned, with a value among
               its values where it names them (a policy: 6.4.1 makes values best-effort), and nothing
               disclosed outside it (6.4). Each claims path is two strings (7.2.1).

The instant defaults to CAPTURE_DIR/captured-at.txt. Any failed check refuses the whole response,
and an empty response refuses. Exit 0 only if every check of every document passed.
"""
import argparse
import base64
import datetime
import hashlib
import json
import pathlib
import sys

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import ExtensionOID

# Each alg with the one curve this verifier takes it under: a policy, since RFC 9864 calls both polymorphic.
ALGS = {-7: ("ES256", ec.SECP256R1, hashes.SHA256), -35: ("ES384", ec.SECP384R1, hashes.SHA384)}
COSE_CRV = {1: ec.SECP256R1, 2: ec.SECP384R1}
DIGESTS = {"SHA-256": hashlib.sha256, "SHA-384": hashlib.sha384, "SHA-512": hashlib.sha512}
X5CHAIN = 33
CRIT = 2
UNDERSTOOD = (1, X5CHAIN)  # the header labels this verifier processes
# The fewest random bytes an IssuerSignedItem may carry: a policy.
RANDOM_MIN = 16


class Refused(Exception):
    def __init__(self, check, reason):
        super().__init__("%s: %s" % (check, reason))
        self.check = check


# --- raw spans: the original bytes of every tag-24 data item, as the response carries them -------

class Raw24:
    """A tag-24 data item: `raw` is its exact encoding in the response, `inner` the embedded CBOR."""

    def __init__(self, raw, inner):
        self.raw, self.inner = raw, inner


def _head(buf, i):
    if i >= len(buf):
        raise Refused("cbor", "truncated")
    ib = buf[i]
    major, info = ib >> 5, ib & 31
    i += 1
    if info < 24:
        return major, info, i
    if info in (24, 25, 26, 27):
        n = 1 << (info - 24)
        if i + n > len(buf):
            raise Refused("cbor", "truncated")
        return major, int.from_bytes(buf[i:i + n], "big"), i + n
    if info == 31 and major in (2, 3, 4, 5, 7):
        return major, None, i
    raise Refused("cbor", "reserved additional info %d" % info)


def walk(buf, i=0):
    """Decode one data item from buf[i:], keeping tag-24 items as Raw24. Returns (value, end)."""
    start = i
    major, arg, i = _head(buf, i)
    if major in (0, 1):
        return (arg if major == 0 else -1 - arg), i
    if major in (2, 3):
        if arg is None:
            raise Refused("cbor", "indefinite-length string")
        if i + arg > len(buf):
            raise Refused("cbor", "truncated")
        s = bytes(buf[i:i + arg])
        return (s if major == 2 else s.decode("utf-8")), i + arg
    if major == 4:
        if arg is None:
            raise Refused("cbor", "indefinite-length array")
        out = []
        for _ in range(arg):
            v, i = walk(buf, i)
            out.append(v)
        return out, i
    if major == 5:
        if arg is None:
            raise Refused("cbor", "indefinite-length map")
        out = {}
        for _ in range(arg):
            k, i = walk(buf, i)
            v, i = walk(buf, i)
            if isinstance(k, (list, dict)):
                raise Refused("cbor", "non-scalar map key")
            if k in out:
                raise Refused("cbor", "duplicate map key %r" % (k,))
            out[k] = v
        return out, i
    if major == 6:
        v, end = walk(buf, i)
        if arg == 24:
            if not isinstance(v, bytes):
                raise Refused("cbor", "tag 24 over a non-bstr")
            return Raw24(bytes(buf[start:end]), v), end
        return cbor2.CBORTag(arg, v), end
    # major 7
    simple = {20: False, 21: True, 22: None}
    if arg in simple and buf[start] & 31 < 24:
        return simple[arg], i
    raise Refused("cbor", "unexpected simple/float value 0x%02x" % buf[start])


def load_all(buf):
    v, end = walk(buf, 0)
    if end != len(buf):
        raise Refused("cbor", "%d trailing bytes" % (len(buf) - end))
    return v


# --- COSE -----------------------------------------------------------------------------------------

def cose_sign1(obj, check):
    if isinstance(obj, cbor2.CBORTag):
        if obj.tag != 18:
            raise Refused(check, "COSE_Sign1 under tag %d" % obj.tag)
        obj = obj.value
    if not (isinstance(obj, list) and len(obj) == 4 and isinstance(obj[0], bytes) and isinstance(obj[1], dict)
            and (obj[2] is None or isinstance(obj[2], bytes)) and isinstance(obj[3], bytes)):
        raise Refused(check, "not a COSE_Sign1")
    try:
        protected = load_all(obj[0]) if obj[0] else {}
    except Refused as e:
        raise Refused(check, "protected header is not well-formed CBOR (%s)" % e)
    if not isinstance(protected, dict):
        raise Refused(check, "protected header is not a map")
    if CRIT in obj[1]:
        raise Refused(check, "crit in the unprotected header; it MUST be in the protected one (RFC 9052 s3.1)")
    crit_understood(check, protected)
    return obj[0], protected, obj[1], obj[2], obj[3]


def crit_understood(check, protected):
    """A crit that is not a non-empty array of labels this verifier processes, each present in the protected header,
    refuses (RFC 9052 s3.1: a crit label whose parameter is not in the protected bucket is a fatal error)."""
    crit = protected.get(CRIT)
    if crit is not None and (not isinstance(crit, list) or not crit or any(label not in UNDERSTOOD for label in crit)):
        raise Refused(check, "crit %r names a header parameter this verifier does not process" % (crit,))
    for label in crit or ():
        if label not in protected:
            raise Refused(check, "crit names %r, which is not in the protected header" % (label,))


def verify_cose(check, public_key, prot_bytes, protected, payload, signature):
    alg = protected.get(1)
    if alg not in ALGS:
        raise Refused(check, "alg %r is not ES256/ES384 in the protected header" % (alg,))
    name, curve, hash_cls = ALGS[alg]
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, curve):
        raise Refused(check, "%s with a key on %s" % (name, getattr(getattr(public_key, "curve", None), "name", None)))
    size = (public_key.curve.key_size + 7) // 8  # r and s each at the key's length (RFC 9053 s2.1)
    if len(signature) != 2 * size:
        raise Refused(check, "signature is %d bytes, %s on %s needs %d" % (
            len(signature), name, public_key.curve.name, 2 * size))
    tbs = cbor2.dumps(["Signature1", prot_bytes, b"", payload])
    der = encode_dss_signature(int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big"))
    try:
        public_key.verify(der, tbs, ec.ECDSA(hash_cls()))
    except InvalidSignature:
        raise Refused(check, "%s signature does not verify" % name)
    return name


# --- X.509 ----------------------------------------------------------------------------------------

def _valid_at(cert, at, check, what):
    if not (cert.not_valid_before_utc <= at <= cert.not_valid_after_utc):
        raise Refused(check, "%s %s is not valid at %s (%s .. %s)" % (
            what, cert.subject.rfc4514_string(), at.isoformat(), cert.not_valid_before_utc, cert.not_valid_after_utc))


def _is_ca(cert):
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        return False


def chain_to_root(chain, roots, at):
    """chain: leaf first. Each certificate must be issued (name and signature) by the next, the last
    by a configured root, every issuer a CA, every certificate valid at `at`."""
    check = "issuer chain"
    if not roots:
        raise Refused(check, "no IACA root configured")
    if not chain:
        raise Refused(check, "empty x5chain")
    path = list(chain)
    for cert in path:
        _valid_at(cert, at, check, "certificate")
    for child, parent in zip(path, path[1:]):
        if not _is_ca(parent):
            raise Refused(check, "%s is not a CA" % parent.subject.rfc4514_string())
        try:
            child.verify_directly_issued_by(parent)
        except (ValueError, TypeError, InvalidSignature) as e:
            raise Refused(check, "%s is not issued by %s (%s)" % (
                child.subject.rfc4514_string(), parent.subject.rfc4514_string(), e))
    last = path[-1]
    for root in roots:
        if last == root:  # the root itself at the end of x5chain
            return root
        try:
            last.verify_directly_issued_by(root)
        except (ValueError, TypeError, InvalidSignature):
            continue
        if not _is_ca(root):
            raise Refused(check, "configured root %s is not a CA" % root.subject.rfc4514_string())
        _valid_at(root, at, check, "root")
        return root
    raise Refused(check, "%s chains to no configured root" % last.issuer.rfc4514_string())


# --- OpenID4VP SessionTranscript ------------------------------------------------------------------

def jwk_thumbprint(jwk):
    """RFC 7638 SHA-256 thumbprint of an EC public JWK."""
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC":
        raise Refused("session transcript", "the encryption key is not an EC JWK")
    canon = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canon.encode()).digest()


def session_transcript(inputs):
    """OpenID4VP 1.0 B.2.6.1: [null, null, ["OpenID4VPHandover", sha256(cbor([client_id, nonce,
    jwkThumbprint, response_uri]))]], jwkThumbprint null only for an unencrypted response.
    Over the Digital Credentials API (response_mode dc_api or dc_api.jwt), B.2.6.2: [null, null,
    ["OpenID4VPDCAPIHandover", sha256(cbor([origin, nonce, jwkThumbprint]))]], the origin without a prefix."""
    if inputs.get("response_mode") in DC_API_MODES:
        return _dcapi_transcript(inputs)
    for k in ("client_id", "nonce", "response_uri"):
        if not isinstance(inputs.get(k), str) or not inputs[k]:
            raise Refused("session transcript", "no %s" % k)
    mode = inputs.get("response_mode")
    if mode not in ("direct_post.jwt", "direct_post"):
        raise Refused("session transcript", "response_mode %r" % (mode,))
    if (inputs.get("encryption_jwk") is not None) != (mode == "direct_post.jwt"):
        raise Refused("session transcript", "%s with%s an encryption key" % (
            mode, "" if inputs.get("encryption_jwk") is not None else "out"))
    thumb = jwk_thumbprint(inputs["encryption_jwk"]) if mode == "direct_post.jwt" else None
    info = cbor2.dumps([inputs["client_id"], inputs["nonce"], thumb, inputs["response_uri"]])
    return [None, None, ["OpenID4VPHandover", hashlib.sha256(info).digest()]], thumb


DC_API_MODES = ("dc_api.jwt", "dc_api")


def _dcapi_transcript(inputs):
    for k in ("origin", "nonce"):
        if not isinstance(inputs.get(k), str) or not inputs[k]:
            raise Refused("session transcript", "no %s" % k)
    mode = inputs["response_mode"]
    if (inputs.get("encryption_jwk") is not None) != (mode == "dc_api.jwt"):
        raise Refused("session transcript", "%s with%s an encryption key" % (
            mode, "" if inputs.get("encryption_jwk") is not None else "out"))
    thumb = jwk_thumbprint(inputs["encryption_jwk"]) if mode == "dc_api.jwt" else None
    info = cbor2.dumps([inputs["origin"], inputs["nonce"], thumb])
    return [None, None, ["OpenID4VPDCAPIHandover", hashlib.sha256(info).digest()]], thumb


# The non-normative example of OpenID4VP 1.0 B.2.6.1: its JWK, client_id, nonce and response_uri,
# and the JWK thumbprint, OpenID4VPHandoverInfo and SessionTranscript it gives, as published.
SPEC_INPUTS = {
    "response_mode": "direct_post.jwt",
    "client_id": "x509_san_dns:example.com",
    "nonce": "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
    "response_uri": "https://example.com/response",
    "encryption_jwk": {"kty": "EC", "crv": "P-256", "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
                       "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc", "use": "enc", "alg": "ECDH-ES", "kid": "1"},
}
SPEC_THUMBPRINT = "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047"
SPEC_TRANSCRIPT = ("83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8e"
                   "ed494cefdd9d95240d254b046b11b68013722aad38ac")


# The same for B.2.6.2: the JWK above, origin https://example.com and the nonce above.
SPEC_DCAPI_INPUTS = {"response_mode": "dc_api.jwt", "origin": "https://example.com", "nonce": SPEC_INPUTS["nonce"],
                     "encryption_jwk": SPEC_INPUTS["encryption_jwk"]}
SPEC_DCAPI_TRANSCRIPT = ("83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4212f9762c74cfd"
                         "bf83b8c69e371d5d68cea09cb4c48ca6daab761a")


def check_spec_vector_dcapi():
    """session_transcript() must reproduce the example of OpenID4VP 1.0 B.2.6.2 byte for byte."""
    transcript, thumb = session_transcript(SPEC_DCAPI_INPUTS)
    got = cbor2.dumps(transcript).hex()
    if thumb.hex() != SPEC_THUMBPRINT or got != SPEC_DCAPI_TRANSCRIPT:
        raise Refused("session transcript", "does not reproduce the OpenID4VP 1.0 B.2.6.2 example (%s)" % got)
    return got


def check_spec_vector():
    """session_transcript() must reproduce the specification's example byte for byte."""
    transcript, thumb = session_transcript(SPEC_INPUTS)
    got = cbor2.dumps(transcript).hex()
    if thumb.hex() != SPEC_THUMBPRINT or got != SPEC_TRANSCRIPT:
        raise Refused("session transcript", "does not reproduce the OpenID4VP 1.0 B.2.6.1 example (%s)" % got)
    return got


# --- the verifier ---------------------------------------------------------------------------------

def tdate(v, what):
    if isinstance(v, cbor2.CBORTag) and v.tag == 0 and isinstance(v.value, str):
        s = v.value.replace("Z", "+00:00")
        d = datetime.datetime.fromisoformat(s)
        if d.tzinfo is None:
            raise Refused("validity", "%s has no time zone" % what)
        return d
    raise Refused("validity", "%s is not a tdate (tag 0)" % what)


def cose_key(k):
    if not isinstance(k, dict) or k.get(1) != 2 or k.get(-1) not in COSE_CRV:
        raise Refused("device key", "deviceKey is not an EC2 P-256/P-384 COSE_Key")
    curve = COSE_CRV[k[-1]]()
    x, y = k.get(-2), k.get(-3)
    if not (isinstance(x, bytes) and isinstance(y, bytes)):
        raise Refused("device key", "deviceKey x/y missing")
    try:
        return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), curve).public_key()
    except ValueError:
        raise Refused("device key", "deviceKey is not a point on %s" % curve.name)


ID_MDL_DS = "1.0.18013.5.1.2"
# The docTypes whose DS certificate must carry SubjectKeyIdentifier and the id-mdl-ds EKU (ISO 18013-5
# Annex B, table B.4, as isomdl implements it). The PID rulebook states no DS certificate profile.
PROFILE_DOCTYPES = {"org.iso.18013.5.1.mDL"}


def ds_profile(cert, doc_type, enforce, log=lambda c, d: None):
    """The DS certificate's SubjectKeyIdentifier and id-mdl-ds EKU: refused when absent for a docType
    in PROFILE_DOCTYPES (the EKU keeps a TLS or other key under the same root from signing MSOs);
    reported otherwise."""
    def has(oid):
        try:
            return cert.extensions.get_extension_for_oid(oid).value
        except x509.ExtensionNotFound:
            return None
    eku = has(ExtensionOID.EXTENDED_KEY_USAGE)
    missing = [name for name, ok in (
        ("SubjectKeyIdentifier", has(ExtensionOID.SUBJECT_KEY_IDENTIFIER) is not None),
        ("ExtendedKeyUsage id-mdl-ds (%s)" % ID_MDL_DS, eku is not None and any(o.dotted_string == ID_MDL_DS for o in eku)),
    ) if not ok]
    if missing and enforce and doc_type in PROFILE_DOCTYPES:
        raise Refused("ds profile", "the DS certificate lacks %s, required for %s" % (" and ".join(missing), doc_type))
    if missing:
        log("note: DS profile", "lacks %s (%s)" % (" and ".join(missing),
            "not enforced" if not enforce else "no DS profile stated for %s" % doc_type))
    else:
        log("ds profile", "SubjectKeyIdentifier and id-mdl-ds EKU present")


def device_signed_elements(device_name_spaces, mso):
    """The elements of DeviceNameSpaces, each of which the MSO's KeyAuthorizations (ISO/IEC 18013-5, clause
    not quoted) must authorize: its namespace in `nameSpaces`, or its identifier under its namespace in
    `dataElements`."""
    signed = load_all(device_name_spaces)
    if not isinstance(signed, dict):
        raise Refused("device data", "DeviceNameSpaces is not a map")
    auth = (mso.get("deviceKeyInfo") or {}).get("keyAuthorizations")
    auth = auth if isinstance(auth, dict) else {}
    ok_ns = auth.get("nameSpaces") if isinstance(auth.get("nameSpaces"), list) else []
    ok_elements = auth.get("dataElements") if isinstance(auth.get("dataElements"), dict) else {}
    out = []
    for ns, elements in signed.items():
        if not isinstance(elements, dict):
            raise Refused("device data", "namespace %r in DeviceNameSpaces is not a map" % (ns,))
        for name in elements:
            listed = ok_elements.get(ns)
            if ns not in ok_ns and not (isinstance(listed, list) and name in listed):
                raise Refused("device data", "%s/%s is signed by the device but KeyAuthorizations does not authorize it"
                              % (ns, name))
            out.append("%s/%s" % (ns, name))
    return out


def x5chain_of(protected, unprotected):
    """The x5chain certificates, from the protected header if it has label 33, else from the unprotected one (RFC 9052
    s3: an attribute is taken from the unprotected bucket only if it is not in the protected one)."""
    x5 = protected[X5CHAIN] if X5CHAIN in protected else unprotected.get(X5CHAIN)
    x5 = [x5] if isinstance(x5, bytes) else x5
    if not x5 or not all(isinstance(c, bytes) for c in x5):
        raise Refused("issuer chain", "no x5chain")
    return x5


def verify_document(doc, transcript, roots, at, log, enforce_profile=True):
    if not isinstance(doc, dict) or not isinstance(doc.get("docType"), str):
        raise Refused("document", "no docType")
    doc_type = doc["docType"]
    issuer_signed = doc.get("issuerSigned")
    if not isinstance(issuer_signed, dict):
        raise Refused("document", "no issuerSigned")

    # issuer auth
    prot_b, prot, unprot, payload, sig = cose_sign1(issuer_signed.get("issuerAuth"), "issuer signature")
    x5 = x5chain_of(prot, unprot)
    try:
        chain = [x509.load_der_x509_certificate(c) for c in x5]
    except ValueError as e:
        raise Refused("issuer chain", "an x5chain certificate is not DER X.509 (%s)" % e)
    root = chain_to_root(chain, roots, at)
    log("issuer chain", "x5chain %s -> configured root %s" % (
        " <- ".join(c.subject.rfc4514_string() for c in chain), root.subject.rfc4514_string()))
    ds_profile(chain[0], doc_type, enforce_profile, log)
    if payload is None:
        raise Refused("issuer signature", "detached MSO payload")
    alg = verify_cose("issuer signature", chain[0].public_key(), prot_b, prot, payload, sig)
    log("issuer signature", "%s over the MSO under the x5chain leaf" % alg)

    mso_tag = load_all(payload)
    if not isinstance(mso_tag, Raw24):
        raise Refused("mso", "the payload is not MobileSecurityObjectBytes (tag 24)")
    mso = load_all(mso_tag.inner)
    if not isinstance(mso, dict) or mso.get("version") != "1.0":
        raise Refused("mso", "not an MSO version 1.0")

    if mso.get("docType") != doc_type:
        raise Refused("docType", "MSO says %r, the document %r" % (mso.get("docType"), doc_type))
    log("docType", doc_type)

    vi = mso.get("validityInfo") or {}
    signed, vfrom, vuntil = (tdate(vi.get(k), k) for k in ("signed", "validFrom", "validUntil"))
    if not (vfrom <= at <= vuntil):
        raise Refused("validity", "%s is outside validFrom %s .. validUntil %s" % (at.isoformat(), vfrom, vuntil))
    if signed > at:
        raise Refused("validity", "signed %s is after %s" % (signed, at.isoformat()))
    log("validity", "signed %s, valid %s .. %s, checked at %s" % (signed, vfrom, vuntil, at.isoformat()))

    # digests over the original tag-24 bytes
    alg_name = mso.get("digestAlgorithm")
    if alg_name not in DIGESTS:
        raise Refused("digests", "digestAlgorithm %r" % (alg_name,))
    value_digests = mso.get("valueDigests")
    name_spaces = issuer_signed.get("nameSpaces")
    if not isinstance(name_spaces, dict) or not name_spaces:
        raise Refused("digests", "no disclosed nameSpaces")
    n, disclosed, elements = 0, [], {}
    for ns, items in name_spaces.items():
        table = value_digests.get(ns) if isinstance(value_digests, dict) else None
        if not isinstance(table, dict) or not isinstance(items, list) or not items:
            raise Refused("digests", "namespace %r has no digests or no items" % ns)
        seen = set()
        for item in items:
            if not isinstance(item, Raw24):
                raise Refused("digests", "an item in %r is not IssuerSignedItemBytes (tag 24)" % ns)
            if cbor2.dumps(cbor2.CBORTag(24, item.inner)) != item.raw:
                raise Refused("digests", "non-preferred tag-24 wrapper in %r" % ns)
            isi = load_all(item.inner)
            did = isi.get("digestID") if isinstance(isi, dict) else None
            if not isinstance(did, int) or did in seen:
                raise Refused("digests", "missing or repeated digestID in %r" % ns)
            seen.add(did)
            if not isinstance(isi.get("random"), bytes) or not isinstance(isi.get("elementIdentifier"), str) \
                    or "elementValue" not in isi:
                raise Refused("digests", "malformed IssuerSignedItem %r in %r" % (did, ns))
            if len(isi["random"]) < RANDOM_MIN:
                raise Refused("digests", "%s/%s (digestID %d) has a random of %d bytes, fewer than %d" % (
                    ns, isi["elementIdentifier"], did, len(isi["random"]), RANDOM_MIN))
            if did not in table:
                raise Refused("digests", "%s/%s (digestID %d) has no digest in the MSO" % (ns, isi["elementIdentifier"], did))
            if table[did] != DIGESTS[alg_name](item.raw).digest():
                raise Refused("digests", "%s/%s (digestID %d) does not match the MSO" % (ns, isi["elementIdentifier"], did))
            n += 1
            disclosed.append("%s/%s" % (ns, isi["elementIdentifier"]))
            elements[(ns, isi["elementIdentifier"])] = isi["elementValue"]
    log("digests", "%d of %d %s digests match, over the original tag-24 bytes: %s" % (
        n, n, alg_name, ", ".join(disclosed)))

    # device auth
    dev = doc.get("deviceSigned")
    if not isinstance(dev, dict):
        raise Refused("device signature", "no deviceSigned")
    dns = dev.get("nameSpaces")
    if not isinstance(dns, Raw24) or cbor2.dumps(cbor2.CBORTag(24, dns.inner)) != dns.raw:
        raise Refused("device signature", "deviceSigned nameSpaces is not DeviceNameSpacesBytes")
    auth = dev.get("deviceAuth") or {}
    if "deviceMac" in auth:
        raise Refused("device signature", "DeviceMac: out of scope for milestone 1")
    d_prot_b, d_prot, _, d_payload, d_sig = cose_sign1(auth.get("deviceSignature"), "device signature")
    if d_payload is not None:
        raise Refused("device signature", "the payload is not detached")
    device_key = cose_key((mso.get("deviceKeyInfo") or {}).get("deviceKey"))
    da = cbor2.dumps(["DeviceAuthentication", transcript, doc_type, cbor2.CBORTag(24, dns.inner)])
    da_bytes = cbor2.dumps(cbor2.CBORTag(24, da))
    alg = verify_cose("device signature", device_key, d_prot_b, d_prot, da_bytes, d_sig)
    log("device signature", "%s over DeviceAuthentication with the OpenID4VP SessionTranscript, under the MSO deviceKey" % alg)
    signed_by_device = device_signed_elements(dns.inner, mso)
    if signed_by_device:
        log("device data", "%s authorized by KeyAuthorizations" % ", ".join(signed_by_device))
    return elements


def _value_matches(value, values):
    """OpenID4VP 1.0 6.3: type and value both match exactly. Only text, integers and booleans convert to JSON
    one way; any other CBOR value matches nothing."""
    return type(value) in (str, int, bool) and any(type(v) is type(value) and v == value for v in values)


def requested_claims(inputs, elements, log):
    """The disclosed IssuerSigned `elements` ({(namespace, identifier): value}) against the claims and claim_sets
    of the request's DCQL Credential Query (OpenID4VP 1.0 6.3, 6.4, 6.4.1)."""
    claims, claim_sets = inputs["claims"], inputs.get("claim_sets")
    if not isinstance(claims, list) or not claims or not all(isinstance(c, dict) for c in claims):
        raise Refused("requested claims", "claims is not a non-empty array of claims queries")
    for c in claims:
        path = c.get("path")
        if not isinstance(path, list) or len(path) != 2 or not all(isinstance(p, str) for p in path):
            raise Refused("requested claims", "claims path %r is not two strings" % (path,))
        if "values" in c and (not isinstance(c["values"], list) or not c["values"]):
            raise Refused("requested claims", "claims values for %r is not a non-empty array" % (path,))
    if claim_sets is None:
        options = [claims]
    else:
        by_id = {c.get("id"): c for c in claims}
        if not isinstance(claim_sets, list) or not claim_sets or not all(
                isinstance(o, list) and o and all(i in by_id for i in o) for o in claim_sets):
            raise Refused("requested claims", "claim_sets is not an array of options naming claims ids")
        options = [[by_id[i] for i in o] for o in claim_sets]

    def unmet(c):
        key = tuple(c["path"])
        if key not in elements:
            return "the request asks for %s/%s; the document does not disclose it" % key
        if "values" in c and not _value_matches(elements[key], c["values"]):
            return "%s/%s is %r, none of the request's values %r" % (key + (elements[key], c["values"]))
        return None
    met = [o for o in options if not any(unmet(c) for c in o)]
    if not met:
        why = next(unmet(c) for c in options[0] if unmet(c))
        if claim_sets is not None:
            why = "none of the %d claim_sets options is met; the first: %s" % (len(options), why)
        raise Refused("requested claims", why)
    for option in met:
        if set(elements) <= {tuple(c["path"]) for c in option}:
            log("requested claims", "%s disclosed, as requested, and nothing else" % ", ".join(
                "%s/%s" % tuple(c["path"]) for c in option))
            return
    asked = {tuple(c["path"]) for c in met[0]}
    raise Refused("requested claims", "%s/%s is disclosed but not requested" % sorted(set(elements) - asked)[0])


def verify(response_bytes, inputs, roots, at, log=lambda c, d: None, enforce_profile=True):
    """Every failure is a Refused: a malformed input that slips past the named checks is refused as
    malformed, never raised as a traceback."""
    try:
        return _verify(response_bytes, inputs, roots, at, log, enforce_profile)
    except Refused:
        raise
    except (ValueError, TypeError, KeyError, IndexError, AttributeError) as e:
        raise Refused("malformed", "%s: %s" % (type(e).__name__, e))


def _verify(response_bytes, inputs, roots, at, log, enforce_profile):
    if not response_bytes:
        raise Refused("input", "empty DeviceResponse")
    resp = load_all(response_bytes)
    if not isinstance(resp, dict) or resp.get("version") != "1.0" or resp.get("status") != 0:
        raise Refused("device response", "not a DeviceResponse version 1.0 with status 0")
    docs = resp.get("documents")
    if not isinstance(docs, list) or not docs:
        raise Refused("device response", "no documents")
    transcript, thumb = session_transcript(inputs)
    shown = base64.urlsafe_b64encode(thumb).rstrip(b"=").decode() if thumb else "null"
    if inputs.get("response_mode") in DC_API_MODES:
        log("session transcript", "origin %s, nonce %s, jwk thumbprint %s" % (inputs["origin"], inputs["nonce"], shown))
    else:
        log("session transcript", "client_id %s, response_uri %s, nonce %s, jwk thumbprint %s" % (
            inputs["client_id"], inputs["response_uri"], inputs["nonce"], shown))
    wallet = inputs.get("wallet_session_transcript_hex")
    if wallet:
        log("note: wallet", "the wallet's own SessionTranscript bytes are %s ours" % (
            "identical to" if wallet == cbor2.dumps(transcript).hex() else "DIFFERENT from"))
    requested = inputs.get("doctype_value")
    if requested is not None and not isinstance(requested, str):
        raise Refused("requested docType", "doctype_value is not a string")
    out = []
    for doc in docs:
        if requested is not None and (not isinstance(doc, dict) or doc.get("docType") != requested):
            raise Refused("requested docType", "the request asked for %r, the document is %r" % (
                requested, doc.get("docType") if isinstance(doc, dict) else None))
        elements = verify_document(doc, transcript, roots, at, log, enforce_profile)
        if inputs.get("claims") is not None:
            requested_claims(inputs, elements, log)
        elif inputs.get("claim_sets") is not None:
            raise Refused("requested claims", "claim_sets without claims (OpenID4VP 1.0 6.4.1)")
        out.append(elements)
    return out


def load_capture(d):
    d = pathlib.Path(d)
    return (d / "device-response.cbor").read_bytes(), json.loads((d / "openid4vp-inputs.json").read_text())


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("capture")
    p.add_argument("--root", action="append", default=[], help="an IACA root (PEM); repeatable")
    p.add_argument("--at", help="the instant, ISO 8601 UTC; default CAPTURE/captured-at.txt")
    a = p.parse_args(argv)
    response, inputs = load_capture(a.capture)
    at_text = a.at or (pathlib.Path(a.capture) / "captured-at.txt").read_text().strip()
    at = datetime.datetime.fromisoformat(at_text.replace("Z", "+00:00"))
    roots = [x509.load_pem_x509_certificate(pathlib.Path(r).read_bytes()) for r in a.root]
    print("instant    %s; roots: %s" % (at.isoformat(), ", ".join(r.subject.rfc4514_string() for r in roots) or "NONE"))
    try:
        check_spec_vector()
        print("  ok   %-18s %s" % ("spec vector", "session_transcript() reproduces the OpenID4VP 1.0 B.2.6.1 example"))
        verify(response, inputs, roots, at, log=lambda c, d: print("  %-4s %-18s %s" % (
            "" if c.startswith("note") else "ok", c, d)))
    except Refused as e:
        print("REFUSED    %s" % e)
        print("done")
        return 1
    print("VERIFIED")
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
