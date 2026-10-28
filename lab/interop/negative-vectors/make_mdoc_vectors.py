#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""lab/interop/negative-vectors/make_mdoc_vectors.py: negative test vectors for ISO/IEC 18013-5 mdoc
DeviceResponses presented over OpenID4VP 1.0 (lab record 025). Area 1: the SessionTranscript the verifier builds
from its own request, and the device authentication over it. Area 2, in part: the issuer signature (the IssuerAuth
COSE_Sign1 and its payload), and the MSO against the items it digests and the document it names.

Every vector is one valid DeviceResponse with exactly one thing changed, re-signed wherever the change needs
it, and carries its repaired twin: the same response with that one thing put back, which a correct verifier
accepts. Two accept controls come first. The vectors judge the verifier side only: the verifier holds its own
request (the inputs), builds the SessionTranscript from it, and judges what the wallet signed.

The keys and certificates are TEST material derived from public seeds, signed with deterministic ECDSA
(RFC 6979): anyone can regenerate every byte, and nobody may trust them.

    python3 make_mdoc_vectors.py > mdoc-vectors.json
    python3 make_mdoc_vectors.py --out .          # writes ./mdoc-vectors.json

Needs cbor2 and cryptography 44 or later; the key helpers and the certificate validity are make_vectors.py's.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import sys

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))


def _load_make_vectors():
    spec = importlib.util.spec_from_file_location("make_vectors", os.path.join(HERE, "make_vectors.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mv = _load_make_vectors()
b64u = mv.b64u

VERSION = "0.1.0"
UTC = datetime.timezone.utc
# The verification instant. The certificates (make_vectors.py's validity, centred on this instant) and the
# MSO are valid at it.
AT = datetime.datetime.fromtimestamp(mv.NOW, UTC)
AT_TEXT = AT.strftime("%Y-%m-%dT%H:%M:%SZ")
MSO_SIGNED = "2026-09-30T00:00:00Z"
MSO_VALID_UNTIL = "2027-09-30T00:00:00Z"

MDL = "org.iso.18013.5.1.mDL"
MDL_NS = "org.iso.18013.5.1"
OTHER_DOCTYPE = "eu.europa.ec.eudi.pid.1"
ID_MDL_DS = "1.0.18013.5.1.2"  # the id-mdl-ds extended key usage (ISO/IEC 18013-5 Annex B)

# The verifier's request.
CLIENT_ID = "x509_san_dns:verifier.example"
NONCE = "mG3v7Rz0qLw5Hc1TfYb8Nd"
RESPONSE_URI = "https://verifier.example/response"
ORIGIN = "https://verifier.example"
OTHER_NONCE = "pQ8xK2sV6nE4uJ0aBt9RzW"
OTHER_CLIENT_ID = "x509_san_dns:other-verifier.example"
OTHER_RESPONSE_URI = "https://verifier.example/other-response"
OTHER_ORIGIN = "https://other-verifier.example"

# --- keys and certificates: make_vectors.py's seeded keys and validity, deterministic ECDSA -------------------------
IACA_K, DS_K = mv._key("mdoc-iaca"), mv._key("mdoc-document-signer")
DEVICE_K, OTHER_DEVICE_K = mv._key("mdoc-device"), mv._key("mdoc-device-other")
ENC_K, OTHER_ENC_K = mv._key("mdoc-response-encryption"), mv._key("mdoc-response-encryption-other")

IACA_CN = "Mdoc Vectors Test IACA"
DS_CN = "Mdoc Vectors Test Document Signer"
COUNTRY = "ZZ"  # a user-assigned ISO 3166-1 code: no country's
ISSUER_URI = "https://mdoc-vectors.example"  # the issuer alternative name
CRL_URI = "https://mdoc-vectors.example/iaca.crl"  # named, never served


def _annex_b_name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _annex_b_cert(cn, key, serial, *, iaca):
    """The IACA (self-signed, `iaca`) or the document signer under it, in the ISO/IEC 18013-5 Annex B profile the
    outside verifiers check: countryName and commonName in both subjects, the DS's countryName the IACA's; a
    SubjectKeyIdentifier (SHA-1 of the public key), an IssuerAlternativeName URI and a CRLDistributionPoints URI in
    both; the IACA critical basicConstraints cA with pathLen 0 and critical keyUsage keyCertSign and cRLSign only; the
    DS no basicConstraints, critical keyUsage digitalSignature only, the critical id-mdl-ds EKU only, and an
    AuthorityKeyIdentifier that is the IACA's SubjectKeyIdentifier."""
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    b = (x509.CertificateBuilder().subject_name(_annex_b_name(cn)).issuer_name(_annex_b_name(IACA_CN))
         .public_key(key.public_key()).serial_number(serial).not_valid_before(mv.T0).not_valid_after(mv.T1))
    if iaca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        b = b.add_extension(x509.ExtendedKeyUsage([x509.ObjectIdentifier(ID_MDL_DS)]), critical=True)
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            x509.SubjectKeyIdentifier.from_public_key(IACA_K.public_key())), critical=False)
    b = b.add_extension(ski, critical=False)
    b = b.add_extension(x509.IssuerAlternativeName([x509.UniformResourceIdentifier(ISSUER_URI)]), critical=False)
    b = b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
        [x509.UniformResourceIdentifier(CRL_URI)], None, None, None)]), critical=False)
    return b.sign(IACA_K, hashes.SHA256(), ecdsa_deterministic=True)


IACA = _annex_b_cert(IACA_CN, IACA_K, 1, iaca=True)
DS = _annex_b_cert(DS_CN, DS_K, 2, iaca=False)


def _enc_jwk(key, kid):
    return dict(mv._jwk(key), use="enc", alg="ECDH-ES", kid=kid)


ENC_JWK, OTHER_ENC_JWK = _enc_jwk(ENC_K, "enc-1"), _enc_jwk(OTHER_ENC_K, "enc-2")


def thumbprint(jwk):
    """The RFC 7638 SHA-256 thumbprint of an EC public JWK, from the canonical text the RFC gives."""
    canon = '{"crv":"%s","kty":"EC","x":"%s","y":"%s"}' % (jwk["crv"], jwk["x"], jwk["y"])
    return hashlib.sha256(canon.encode("ascii")).digest()


THUMB, OTHER_THUMB = thumbprint(ENC_JWK), thumbprint(OTHER_ENC_JWK)

# --- the SessionTranscripts (OpenID4VP 1.0 B.2.6.1 and B.2.6.2) ------------------------------------------------------


def redirect_transcript(client_id, nonce, thumb, response_uri):
    info = cbor2.dumps([client_id, nonce, thumb, response_uri])
    return [None, None, ["OpenID4VPHandover", hashlib.sha256(info).digest()]]


def dcapi_transcript(origin, nonce, thumb):
    info = cbor2.dumps([origin, nonce, thumb])
    return [None, None, ["OpenID4VPDCAPIHandover", hashlib.sha256(info).digest()]]


def _rt(**over):
    """The transcript a wallet signs for the verifier's redirect request, with `over` changed."""
    p = dict(client_id=CLIENT_ID, nonce=NONCE, thumb=THUMB, response_uri=RESPONSE_URI)
    p.update(over)
    return redirect_transcript(p["client_id"], p["nonce"], p["thumb"], p["response_uri"])


def _dt(**over):
    p = dict(origin=ORIGIN, nonce=NONCE, thumb=THUMB)
    p.update(over)
    return dcapi_transcript(p["origin"], p["nonce"], p["thumb"])


# The verifier's own inputs, which verify_mdoc.py builds the transcript from; doctype_value is the DCQL
# meta.doctype_value of the request (OpenID4VP 1.0 B.2.3).
REDIRECT_INPUTS = {"response_mode": "direct_post.jwt", "client_id": CLIENT_ID, "nonce": NONCE,
                   "response_uri": RESPONSE_URI, "encryption_jwk": ENC_JWK, "doctype_value": MDL}
DCAPI_INPUTS = {"response_mode": "dc_api.jwt", "origin": ORIGIN, "nonce": NONCE, "encryption_jwk": ENC_JWK,
                "doctype_value": MDL}

# --- the DeviceResponse ---------------------------------------------------------------------------------------------
ELEMENTS = ((0, "family_name", "Mustermann"), (1, "given_name", "Erika"),
            (2, "birth_date", cbor2.CBORTag(1004, "1964-08-12")))


def _random(name):
    return hashlib.sha256((mv.SEED + "mdoc/random/" + name).encode()).digest()  # 32 bytes


def _tag24(inner):
    return cbor2.CBORTag(24, inner)


def _cose_key(key, kty=2):
    n = key.public_key().public_numbers()
    return {1: kty, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}  # crv 1 is P-256


def _sign1(key, protected, payload, der=False):
    """The COSE_Sign1 signature (ES256, RFC 9052 s4.4): r || s over the Sig_structure (DER-encoded when `der`)."""
    return mv._es256(key, cbor2.dumps(["Signature1", protected, b"", payload]), der)


def _es384_by(key, protected, payload):
    """ECDSA with SHA-384 over the Sig_structure, r || s each at the key's length (RFC 9053 s2.1)."""
    der = key.sign(cbor2.dumps(["Signature1", protected, b"", payload]),
                   ec.ECDSA(hashes.SHA384(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    size = (key.curve.key_size + 7) // 8
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


ES256_HEADER = cbor2.dumps({1: -7})
CRIT_LABEL = -65537  # a private-use header label: no verifier understands it
# The protected header of each IssuerAuth form that changes it; the others keep ES256_HEADER.
ISSUER_AUTH_HEADERS = {
    "alg-curve": cbor2.dumps({1: -35}),  # ES384
    "crit-unknown": cbor2.dumps({1: -7, 2: [CRIT_LABEL], CRIT_LABEL: True}),
    "dup-label": bytes.fromhex("a201260126"),  # {1: -7, 1: -7}, the alg label twice
}


def _issuer_auth(form, mso):
    """IssuerAuth: the document signer's COSE_Sign1 over MobileSecurityObjectBytes, its x5chain (label 33) in the
    unprotected header. `form` is "valid" or names the one defect: sig-flipped, sig-der, alg-curve, crit-unknown,
    dup-label or not-tag24."""
    payload = cbor2.dumps(mso) if form == "not-tag24" else cbor2.dumps(_tag24(cbor2.dumps(mso)))
    protected = ISSUER_AUTH_HEADERS.get(form, ES256_HEADER)
    unprotected = {33: DS.public_bytes(serialization.Encoding.DER)}
    if form == "alg-curve":
        signature = _es384_by(DS_K, protected, payload)
    else:
        signature = _sign1(DS_K, protected, payload, der=form == "sig-der")
    if form == "sig-flipped":
        signature = signature[:-1] + bytes([signature[-1] ^ 1])
    return [protected, unprotected, payload, signature]


DIGEST_FUNCTIONS = {"SHA-256": hashlib.sha256, "SHA-1": hashlib.sha1}
# The byte changes _sent makes to the first (family_name) IssuerSignedItem.
SENT_EDITS = {"value-modified": (b"Mustermann", b"Nustermann"),  # one byte of elementValue: M (4d) to N (4e)
              "reencoded": (b"\x68digestID\x00", b"\x68digestID\x18\x00")}  # digestID 0 written in two bytes


def _sent(change, items):
    """The IssuerSignedItemBytes the response carries, after the MSO digested `items`: `change` is a SENT_EDITS
    change to the first item's bytes."""
    old, new = SENT_EDITS[change]
    if items[0].value.count(old) != 1:
        raise ValueError("the item does not hold %r once" % old)
    return [_tag24(items[0].value.replace(old, new))] + items[1:]


def mint(*, transcript, doc_type=MDL, mso_doc_type=None, signed_doc_type=None, signer=DEVICE_K, mso_kty=2,
         devsig="detached", device_signed=None, key_authorizations=None, issuer_auth="valid", digest_alg="SHA-256",
         mso_digests=None, sent=None, disclosed=None):
    """One DeviceResponse (CBOR bytes) of one mDL signed by the vectors' document signer, whose device key is
    DEVICE_K. `transcript` is the SessionTranscript the DeviceSignature is made over, `signer` the key that makes
    it, `signed_doc_type` the docType DeviceAuthentication names (default: the document's), `mso_kty` the COSE
    key type of the MSO's deviceKey, `devsig` how deviceAuth carries the signature (detached, embedded or
    missing), `device_signed` the elements DeviceSigned carries ({namespace: {identifier: value}}) and
    `key_authorizations` the MSO's KeyAuthorizations.

    The issuer side: `issuer_auth` is the IssuerAuth form (see _issuer_auth), `mso_doc_type` the MSO's docType
    (default: the document's), `digest_alg` the MSO's digestAlgorithm and the hash of its digests,
    `mso_digests` {digestID: None (no digest) or n (the digest's first n bytes)} and `sent` a change to the items
    after the MSO digested them (see _sent).
    `disclosed` names the elements IssuerSigned carries (default: all three); the MSO digests all three."""
    items = [_tag24(cbor2.dumps({"digestID": did, "random": _random(name), "elementIdentifier": name,
                                 "elementValue": value})) for did, name, value in ELEMENTS]
    device_key_info = {"deviceKey": _cose_key(DEVICE_K, mso_kty)}
    if key_authorizations is not None:
        device_key_info["keyAuthorizations"] = key_authorizations
    digests = {did: DIGEST_FUNCTIONS[digest_alg](cbor2.dumps(item)).digest()
               for (did, _, _), item in zip(ELEMENTS, items)}
    for did, length in (mso_digests or {}).items():
        if length is None:
            del digests[did]
        else:
            digests[did] = digests[did][:length]
    mso = {"version": "1.0", "digestAlgorithm": digest_alg, "valueDigests": {MDL_NS: digests},
           "deviceKeyInfo": device_key_info, "docType": mso_doc_type or doc_type,
           "validityInfo": {"signed": cbor2.CBORTag(0, MSO_SIGNED), "validFrom": cbor2.CBORTag(0, MSO_SIGNED),
                            "validUntil": cbor2.CBORTag(0, MSO_VALID_UNTIL)}}
    issuer_auth = _issuer_auth(issuer_auth, mso)
    if sent:
        items = _sent(sent, items)
    if disclosed is not None:
        items = [item for (_, name, _), item in zip(ELEMENTS, items) if name in disclosed]

    device_ns = _tag24(cbor2.dumps(device_signed or {}))
    auth_bytes = cbor2.dumps(_tag24(cbor2.dumps(["DeviceAuthentication", transcript, signed_doc_type or doc_type,
                                                 device_ns])))
    signature = _sign1(signer, ES256_HEADER, auth_bytes)
    device_auth = {"detached": {"deviceSignature": [ES256_HEADER, {}, None, signature]},
                   "embedded": {"deviceSignature": [ES256_HEADER, {}, auth_bytes, signature]},
                   "missing": {}}[devsig]
    return cbor2.dumps({"version": "1.0", "documents": [{
        "docType": doc_type, "issuerSigned": {"nameSpaces": {MDL_NS: items}, "issuerAuth": issuer_auth},
        "deviceSigned": {"nameSpaces": device_ns, "deviceAuth": device_auth}}], "status": 0})


# --- the vectors ----------------------------------------------------------------------------------------------------
B261 = "OpenID4VP 1.0 B.2.6.1"
B262 = "OpenID4VP 1.0 B.2.6.2"
S86 = "OpenID4VP 1.0 8.6"
T_NONCE = "The second element MUST be the value of the nonce request parameter."
T_CLIENT = "The first element MUST be the client_id request parameter. If applicable, this includes the Client Identifier Prefix."
T_THUMB = ("If the response is encrypted, e.g., using direct_post.jwt, the third element MUST be the JWK SHA-256 "
           "Thumbprint as defined in [RFC7638], encoded as a Byte String, of the Verifier's public key used to "
           "encrypt the response.")
T_THUMB_DCAPI = ("For the Response Mode dc_api.jwt, the third element MUST be the JWK SHA-256 Thumbprint as defined "
                 "in [RFC7638], encoded as a Byte String, of the Verifier's public key used to encrypt the response.")
T_REPLAY = ("The Verifier MUST validate every individual Verifiable Presentation in an Authorization Response and "
            "ensure that it is linked to the values of the client_id and the nonce parameter it had used for the "
            "respective Authorization Request.")
T_NONCE_REJECT = "If any Verifiable Presentation in the response does not contain the correct nonce value, the response MUST be rejected."
T_HOLDER_BINDING = ("For Verifiable Presentations, validate the Holder Binding, including the checks required to "
                    "prevent replay described in Section 14.1.")
NOT_QUOTED = "not quoted: the ISO text is paywalled and was not read; the clause number is inferred"
T_INTEGRITY = "Validate the integrity and authenticity of the Presentation and Credential."
T_CRITERIA = ("Validate that the returned Credential(s) meet all criteria defined in the query in the Authorization "
              "Request (e.g., Claims included in the presentation).")
T_SATISFIES = ("Check that the set of Presentations returned satisfies all requirements defined in the Verifier's "
               "request as described in Section 6.4.")
# Where an ISO/IEC 18013-5 clause number comes from: the implementation that gives it, with the edition that
# implementation names. No edition is named otherwise.
OWF_EDITION = "naming no edition there"
OID4VCGO_EDITION = "citing the 2025-09-14 CD ballot resolution draft of the second edition"


def _owf(what):
    return "@owf/mdoc 0.8.2 (formerly mdoc-ts) numbers %s, %s" % (what, OWF_EDITION)


def _oid4vcgo(what):
    return "OID4VCgo 0.49.0 numbers %s, %s" % (what, OID4VCGO_EDITION)


FROM_DIGESTS = _oid4vcgo("the IssuerSignedItem digests 12.3.5")
T_HAIP_TABLE = "Verifiers support all hash algorithms listed in table 21 of [ISO.18013-5]."
T_HAIP_ISO = ("ISO/IEC 18013-5:2021 Personal identification - ISO-compliant driving licence Part 5: Mobile driving "
              "licence (mDL) application")
# HAIP 1.0 numbers a table from the edition it references, in its own words.
FROM_HAIP_TABLE = ('HAIP 1.0 9.3.1.2, a non-normative example, says "%s"; its 3.3 lists [ISO.18013-5] as "%s"; '
                   'that the two numbers name one table is inferred' % (T_HAIP_TABLE, T_HAIP_ISO))
T_VERIFY = ("Call the signature verification algorithm, passing in K (the key to verify with), alg (the algorithm "
            "used to sign with), ToBeSigned (the value to sign), and sig (the signature to be verified).")
T_RS = ("The signature is encoded by converting the integers into byte strings of the same length as the key size. "
        "The length is rounded up to the nearest byte and is left padded with zero bits to get to the correct "
        "length. The two integers are then concatenated together to form a byte string that is the resulting "
        "signature.")
T_PAIRING = ("In order to promote interoperability, it is suggested that SHA-256 be used only with curve P-256, "
             "SHA-384 be used only with curve P-384, and SHA-512 be used only with curve P-521.")
T_POLYMORPHIC = "The COSE algorithm registrations for ECDSA are polymorphic, since they do not specify the curve used."
T_KEY_ALG = ("Before using the key in a certificate, the key MUST be checked against the algorithm to be used, and "
             "any algorithm-specific checks need to be made.")
T_CRIT = ("This header parameter is used to indicate which protected header parameters an application that is "
          "processing a message is required to understand.")
T_LABELS = ("Labels in each of the maps MUST be unique. When processing messages, if a label appears multiple times, "
            "the message MUST be rejected as malformed.")
# The named policy of each policy-graded vector, and what each policy is.
VECTOR_POLICY = {"md-issuerauth-alg-curve": "alg-curve-pairing", "md-sd-value-other": "values-checked"}
POLICIES = {"alg-curve-pairing": "the verifier takes ES256 only under a P-256 key and ES384 only under a P-384 key, "
                                 "the pairing RFC 9053 2.1 suggests; RFC 9864 2.1 calls these algorithm identifiers "
                                 "polymorphic, so no sentence requires the refusal",
            "values-checked": "the verifier refuses a document that discloses a requested claim whose value matches "
                              "none of the values the request names for it; OpenID4VP 1.0 6.4.1 makes value "
                              "matching best-effort, and a Verifier MUST NOT rely on it for security checks, so a "
                              "verifier that accepts the document and checks the value itself reads it legitimately"}

AUTHORIZED_NS = "org.example.authorized"
DEVICE_NS = "org.example.device"
DEVICE_SIGNED = {DEVICE_NS: {"device_note": "signed by the device key"}}

# id, what changed, class, layer, clauses, source, the request kind, the mint arguments both the vector and its
# twin share, the defect's mint arguments, the repair's (on top of the shared ones; none: the twin takes only the
# shared ones) and the defect's changes to the verifier's inputs. The twin is the response with the defect
# put back, under the inputs without the change.
_ST, _DA, _RQ, _IA, _MSO = "session-transcript", "device-auth", "request", "issuer-auth", "mso"
_REDIRECT, _DCAPI = "redirect", "dcapi"
T_ALL_CLAIMS = ("If the Wallet cannot deliver all claims requested by the Verifier according to these rules, it MUST "
                "NOT return the respective Credential.")


def _query(names, claim_sets=None, values=None):
    """The claims and claim_sets of the request's DCQL Credential Query (OpenID4VP 1.0 6.3, 6.4.1), which a
    request kind (_REDIRECT, query) adds to the verifier's inputs: a claim for each element of `names`, with the
    element's name as its id when there are claim_sets, and the values `values` names for it."""
    claims = [dict({"id": name} if claim_sets else {}, path=[MDL_NS, name],
                   **({"values": values[name]} if name in (values or {}) else {})) for name in names]
    return dict({"claims": claims}, **({"claim_sets": claim_sets} if claim_sets else {}))


VECTORS = (
    ("md-st-nonce", "the OpenID4VPHandover is built over another nonce", "spec", _ST,
     [(B261, T_NONCE), ("OpenID4VP 1.0 14.1.2", T_REPLAY), ("OpenID4VP 1.0 14.1.2", T_NONCE_REJECT)],
     None, _REDIRECT, {}, {"transcript": _rt(nonce=OTHER_NONCE)}, {}, {}),
    ("md-st-client-id-other", "the handover's clientId is another verifier's, x509_san_dns:other-verifier.example",
     "spec", _ST, [(B261, T_CLIENT), ("OpenID4VP 1.0 14.1.2", T_REPLAY)],
     None, _REDIRECT, {}, {"transcript": _rt(client_id=OTHER_CLIENT_ID)}, {}, {}),
    ("md-st-client-id-no-prefix", "the handover's clientId is the verifier's without its x509_san_dns: prefix",
     "spec", _ST, [(B261, T_CLIENT),
                   ("OpenID4VP 1.0 14.8", "Wallets MUST always use the full Client Identifier, including the prefix "
                                          "if provided, within the context of the Wallet or its responses to "
                                          "identify the client.")],
     None, _REDIRECT, {}, {"transcript": _rt(client_id=CLIENT_ID.split(":", 1)[1])}, {}, {}),
    ("md-st-response-uri", "the handover's responseUri is another response_uri of the same verifier", "spec", _ST,
     [(B261, "The fourth element MUST be either the redirect_uri or response_uri request parameter, depending on "
             "which is present, as determined by the Response Mode.")],
     None, _REDIRECT, {}, {"transcript": _rt(response_uri=OTHER_RESPONSE_URI)}, {}, {}),
    ("md-st-thumbprint-other-key", "the handover's jwkThumbprint is the thumbprint of a different encryption key",
     "spec", _ST, [(B261, T_THUMB), (B262, T_THUMB_DCAPI)],
     None, _REDIRECT, {}, {"transcript": _rt(thumb=OTHER_THUMB)}, {}, {}),
    ("md-st-thumbprint-absent", "the handover's jwkThumbprint is null, where the response is encrypted and needs one",
     "spec", _ST, [(B261, T_THUMB)],
     None, _REDIRECT, {}, {"transcript": _rt(thumb=None)}, {}, {}),
    ("md-st-dcapi-handover-on-redirect", "an OpenID4VPDCAPIHandover over a request the verifier made by redirect",
     "spec", _ST, [(B261, "Handover MUST be the OpenID4VPHandover CBOR structure as defined below.")],
     None, _REDIRECT, {}, {"transcript": _dt()}, {}, {}),
    ("md-st-redirect-handover-on-dcapi", "an OpenID4VPHandover over a request the verifier made through the Digital "
                                         "Credentials API", "spec", _ST,
     [(B262, "Handover MUST be the OpenID4VPDCAPIHandover CBOR structure as defined below.")],
     None, _DCAPI, {}, {"transcript": _rt()}, {}, {}),
    ("md-st-dcapi-origin-prefixed", "the OpenID4VPDCAPIHandover's origin is written origin:https://verifier.example",
     "spec", _ST, [(B262, "The first element MUST be the string representing the Origin of the request as described "
                          "in Appendix A.2. It MUST NOT be prefixed with origin:.")],
     None, _DCAPI, {}, {"transcript": _dt(origin="origin:" + ORIGIN)}, {}, {}),
    ("md-st-dcapi-origin-other", "the OpenID4VPDCAPIHandover's origin is another verifier's", "spec", _ST,
     [(B262, "The first element MUST be the string representing the Origin of the request as described in "
             "Appendix A.2.")],
     None, _DCAPI, {}, {"transcript": _dt(origin=OTHER_ORIGIN)}, {}, {}),
    ("md-devicesig-other-key", "the DeviceSignature is made by a key other than the MSO's deviceKey", "spec", _DA,
     [("ISO/IEC 18013-5 9.1.3 (inferred)", NOT_QUOTED), (S86, T_HOLDER_BINDING),
      ("OpenID4VP 1.0 2", "Cryptographic Holder Binding: Ability of the Holder to prove legitimate possession of a "
                          "Credential by proving control over the same private key during the issuance and "
                          "presentation.")],
     "9.1.3 is inferred from 9.1.3.4: " + _owf("DeviceAuth 9.1.3.4") + "; " + _oid4vcgo("mdoc authentication 12.4"),
     _REDIRECT, {}, {"signer": OTHER_DEVICE_K}, {}, {}),
    ("md-devicesig-missing", "deviceAuth is empty: no deviceSignature, where holder binding is required", "spec", _DA,
     [(S86, "Validate that all Presentations contain a cryptographic proof of Holder Binding (i.e., that they are "
            "Verifiable Presentations), unless specifically requested otherwise."),
      ("OpenID4VP 1.0 6.1 (require_cryptographic_holder_binding)",
       "The default value is true, i.e., a Verifiable Presentation with Cryptographic Holder Binding is required.")],
     None, _REDIRECT, {}, {"devsig": "missing"}, {}, {}),
    ("md-devicesig-not-detached", "the DeviceSignature carries its payload (DeviceAuthenticationBytes) instead of "
                                 "detaching it", "spec-implied", _DA,
     [("ISO/IEC 18013-5 (clause inferred)", NOT_QUOTED)],
     "the clause is cited without a number: "
     + _oid4vcgo("the detached DeviceAuthenticationBytes 12.4.4 and the signature over them 12.4.6") + "; "
     + _owf("DeviceAuth 9.1.3.4"), _REDIRECT, {}, {"devsig": "embedded"}, {}, {}),
    ("md-devicesig-doctype-other", "DeviceAuthentication names another docType than the document's",
     "spec-implied", _DA, [("ISO/IEC 18013-5 DeviceAuthentication (clause inferred)", NOT_QUOTED)],
     "the clause is cited without a number: " + _oid4vcgo("DeviceAuthenticationBytes 12.4.4"), _REDIRECT, {},
     {"signed_doc_type": OTHER_DOCTYPE}, {}, {}),
    ("md-devicekey-kty-crv", "the MSO's deviceKey has key type OKP with curve P-256", "spec", _DA,
     [("RFC 9053 7.1", "Applications MUST check that the curve and the key type are consistent and reject a key if "
                       "they are not.")],
     None, _REDIRECT, {}, {"mso_kty": 1}, {}, {}),
    ("md-devicesigned-unauthorized-ns", "DeviceSigned carries an element in a namespace the MSO's KeyAuthorizations "
                                       "do not list", "spec-implied", _DA,
     [("ISO/IEC 18013-5 9.1.3.4 and 12.3.4", NOT_QUOTED)],
     _owf("the rule 9.1.3.4 and KeyAuthorizations 9.1.2.4") + "; "
     + _oid4vcgo("KeyAuthorizations 12.3.4 and the reader's check 12.8.2 step 1"),
     _REDIRECT, {"device_signed": DEVICE_SIGNED},
     {"key_authorizations": {"nameSpaces": [AUTHORIZED_NS]}},
     {"key_authorizations": {"nameSpaces": [AUTHORIZED_NS, DEVICE_NS]}}, {}),
    ("md-doctype-not-requested", "the response is an mDL, where the request's DCQL doctype_value asks for another "
                                "docType", "spec", _RQ,
     [(S86, T_CRITERIA),
      ("OpenID4VP 1.0 B.2.3", "doctype_value: REQUIRED. String that specifies an allowed value for the doctype of "
                              "the requested Verifiable Credential."),
      ("OpenID4VP 1.0 14.9", "The Wallet is not controlled by the Verifier and the Verifier MUST perform its own "
                             "security checks on the returned Credentials and Presentations.")],
     None, _REDIRECT, {}, {}, {}, {"doctype_value": OTHER_DOCTYPE}),
    # The issuer signature: the IssuerAuth COSE_Sign1 and its payload.
    ("md-issuerauth-sig-flipped", "one byte of the IssuerAuth signature is changed (the low bit of its last byte)",
     "spec", _IA, [("RFC 9052 4.4", T_VERIFY), ("ISO/IEC 18013-5 9.3.1 (inferred)", NOT_QUOTED),
                   (S86, T_INTEGRITY)],
     "9.3.1 is inferred as the clause of the reader's checks of the issuer data: "
     + _owf("their docType check 9.3.1 step 4") + "; " + _oid4vcgo("the same check 12.8.1 step 4"),
     _REDIRECT, {}, {"issuer_auth": "sig-flipped"}, {}, {}),
    ("md-issuerauth-sig-der", "the IssuerAuth ES256 signature is DER-encoded, not the fixed-length r || s",
     "spec-implied", _IA, [("RFC 9053 2.1", T_RS)], None, _REDIRECT, {}, {"issuer_auth": "sig-der"}, {}, {}),
    ("md-issuerauth-alg-curve", "IssuerAuth declares ES384 and is signed with SHA-384 by the document signer's P-256 "
                                "key, r and s at that key's 32 bytes each", "policy", _IA,
     [("RFC 9053 2.1", T_PAIRING), ("RFC 9864 2.1", T_POLYMORPHIC), ("RFC 9360 5", T_KEY_ALG)],
     None, _REDIRECT, {}, {"issuer_auth": "alg-curve"}, {}, {}),
    ("md-issuerauth-crit-unknown", "IssuerAuth's protected header lists in crit a private-use label (-65537) that it "
                                   "carries and no verifier understands", "spec-implied", _IA,
     [("RFC 9052 3.1", T_CRIT)], None, _REDIRECT, {}, {"issuer_auth": "crit-unknown"}, {}, {}),
    ("md-issuerauth-dup-label", "IssuerAuth's protected header map carries the alg label twice (a2 01 26 01 26), "
                                "signed as those bytes", "spec", _IA,
     [("RFC 9052 3", T_LABELS)], None, _REDIRECT, {}, {"issuer_auth": "dup-label"}, {}, {}),
    ("md-mso-not-tag24", "IssuerAuth's payload is the bare MSO, not MobileSecurityObjectBytes (tag 24)",
     "spec-implied", _IA, [("ISO/IEC 18013-5 MobileSecurityObjectBytes (clause inferred)", NOT_QUOTED)],
     "the clause is cited without a number: "
     + _oid4vcgo("the MSO 12.3.4 and lists MobileSecurityObjectBytes among the tag-24 strings of 10.3.3") + "; "
     + _owf("the MSO's KeyAuthorizations and digest IDs 9.1.2.4"),
     _REDIRECT, {}, {"issuer_auth": "not-tag24"}, {}, {}),
    # The MSO and its digests.
    ("md-digest-value-modified", "one byte of family_name's elementValue is changed (Mustermann to Nustermann); the "
                                 "MSO is untouched", "spec", _MSO,
     [("ISO/IEC 18013-5 12.3.5 (inferred)", NOT_QUOTED), (S86, T_INTEGRITY)],
     FROM_DIGESTS, _REDIRECT, {}, {"sent": "value-modified"}, {}, {}),
    ("md-digest-reencoded-item", "family_name's IssuerSignedItemBytes are re-encoded: the same item with its "
                                 "digestID 0 written in two bytes (18 00), not the bytes the MSO digests",
     "spec-implied", _MSO, [("ISO/IEC 18013-5 12.3.5 (inferred)", NOT_QUOTED)],
     FROM_DIGESTS, _REDIRECT, {}, {"sent": "reencoded"}, {}, {}),
    ("md-digest-id-absent", "the MSO's valueDigests has no digestID 2, the disclosed birth_date's", "spec", _MSO,
     [("ISO/IEC 18013-5 12.3.5 (inferred)", NOT_QUOTED), (S86, T_INTEGRITY)],
     FROM_DIGESTS, _REDIRECT, {}, {"mso_digests": {2: None}}, {}, {}),
    ("md-digest-alg-sha1", "the MSO's digestAlgorithm is SHA-1, its digests SHA-1 over the items", "spec-implied",
     _MSO, [("ISO/IEC 18013-5 Table 16 (inferred)", NOT_QUOTED)],
     _oid4vcgo("the MSO digest algorithms Table 16") + "; " + FROM_HAIP_TABLE,
     _REDIRECT, {}, {"digest_alg": "SHA-1"}, {}, {}),
    ("md-digest-length", "the MSO's digest for digestID 0 is the first 20 bytes of its SHA-256", "spec-implied",
     _MSO, [("ISO/IEC 18013-5 12.3.5 (inferred)", NOT_QUOTED)],
     FROM_DIGESTS, _REDIRECT, {}, {"mso_digests": {0: 20}}, {}, {}),
    ("md-doctype-vs-mso", "the MSO's docType is eu.europa.ec.eudi.pid.1; the document's, and the request's, is the "
                          "mDL's", "spec-implied", _MSO,
     [("ISO/IEC 18013-5 9.3.1 (inferred)", NOT_QUOTED), ("ISO/IEC 18013-5 12.8.1 (inferred)", NOT_QUOTED)],
     _owf("this check 9.3.1 step 4") + "; " + _oid4vcgo("it 12.8.1 step 4"), _REDIRECT, {},
     {"mso_doc_type": OTHER_DOCTYPE}, {}, {}),
    ("md-sd-claim-absent", "the request's claims ask for family_name and birth_date; IssuerSigned discloses "
                           "family_name only", "spec", _RQ,
     [(S86, T_CRITERIA), ("OpenID4VP 1.0 6.4.1", "If claims is present, but claim_sets is absent, the Verifier "
                                                 "requests all claims listed in claims."),
      ("OpenID4VP 1.0 6.4.1", T_ALL_CLAIMS)],
     None, (_REDIRECT, _query(("family_name", "birth_date"))), {"disclosed": ("family_name", "birth_date")},
     {"disclosed": ("family_name",)}, {}, {}),
    ("md-sd-claim-sets-unmet", "the request's claim_sets ask for family_name with birth_date, or for given_name; "
                               "IssuerSigned discloses family_name only", "spec", _RQ,
     [(S86, T_CRITERIA), (S86, T_SATISFIES),
      ("OpenID4VP 1.0 6.4.1", "If both claims and claim_sets are present, the Verifier requests one combination of "
                              "the claims listed in claim_sets."),
      ("OpenID4VP 1.0 6.4.1", "If the Wallet cannot satisfy any of the options, it MUST NOT return any claims.")],
     None, (_REDIRECT, _query(("family_name", "birth_date", "given_name"),
                              [["family_name", "birth_date"], ["given_name"]])),
     {"disclosed": ("family_name", "birth_date")}, {"disclosed": ("family_name",)}, {}, {}),
    ("md-sd-value-other", "the request's claims ask for family_name with values [\"Nustermann\"]; IssuerSigned "
                          "discloses family_name Mustermann", "policy", _RQ,
     [(S86, T_CRITERIA),
      ("OpenID4VP 1.0 6.3", "If the values property is present, the Wallet SHOULD return the claim only if the type "
                            "and value of the claim both match exactly for at least one of the elements in the "
                            "array."),
      ("OpenID4VP 1.0 6.4.1", "Therefore, Verifiers MUST treat restrictions expressed using values as a best-effort "
                              "way to improve user privacy, but MUST NOT rely on it for security checks.")],
     None, (_REDIRECT, _query(("family_name",), values={"family_name": ["Mustermann"]})),
     {"disclosed": ("family_name",)}, {}, {}, _query(("family_name",), values={"family_name": ["Nustermann"]})),
)


def _case(vid, changed, cls, layer, clauses, source, expected, response, inputs):
    return {"id": vid, "changed": changed, "class": cls, "layer": layer,
            "clauses": [{"ref": r, "text": t} for r, t in clauses], "expected": expected,
            "at": AT_TEXT, "trust_anchors_pem": [_pem(IACA)], "inputs": inputs, "response": b64u(response),
            **({"source": source} if source else {}),
            **({"policy": VECTOR_POLICY[vid]} if vid in VECTOR_POLICY else {})}


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def build():
    """The vectors document: the two controls, then the vectors in the order of VECTORS, each with its twin."""
    redirect, dcapi = dict(REDIRECT_INPUTS), dict(DCAPI_INPUTS)
    base = {_REDIRECT: (redirect, _rt()), _DCAPI: (dcapi, _dt())}
    vectors = [
        _case("md-accept-redirect", "nothing: the control, an mDL over OpenID4VPHandover with a jwkThumbprint "
              "(redirect request, direct_post.jwt); it cites no clause", "control", "control", [], None,
              "accept", mint(transcript=_rt()), redirect),
        _case("md-accept-dcapi-oid4vp", "nothing: the control, an mDL over OpenID4VPDCAPIHandover with a "
              "jwkThumbprint (Digital Credentials API, dc_api.jwt); it cites no clause", "control", "control", [],
              None, "accept", mint(transcript=_dt()), dcapi)]
    for vid, changed, cls, layer, clauses, source, kind, common, defect, repair, input_change in VECTORS:
        kind, query = (kind, {}) if isinstance(kind, str) else kind
        inputs, transcript = base[kind]
        inputs = dict(inputs, **query)
        good = dict({"transcript": transcript}, **common)
        vector = _case(vid, changed, cls, layer, clauses, source, "reject",
                       mint(**dict(good, **defect)), dict(inputs, **input_change))
        # The twin: the defect put back. An input-side defect keeps the bytes; every other defect keeps the inputs.
        fixed = dict(good, **repair) if repair else good
        vector["repaired"] = {"response": b64u(mint(**fixed)), "inputs": inputs}
        vectors.append(vector)
    return {
        "name": "Negative test vectors for mdoc DeviceResponses presented over OpenID4VP 1.0: the SessionTranscript "
                "and the device authentication, the issuer signature, the MSO and its digests, and the claims the "
                "request asks for",
        "version": VERSION,
        "warning": "TEST KEYS AND CERTIFICATES, derived from public seeds by make_mdoc_vectors.py. Never trust them.",
        "settings": {"encoding": "response is the base64url DeviceResponse; inputs are the verifier's own request, "
                                 "from which it builds the SessionTranscript; repaired is the same vector with its "
                                 "one defect put back, expected accept; source says where each ISO/IEC 18013-5 "
                                 "clause number comes from: the implementation that gives it and the edition that "
                                 "implementation names, both where two number a clause differently"},
        "layers": {"control": "the controls, which every verifier judges",
                   _ST: "OpenID4VP 1.0 B.2.6: the SessionTranscript the verifier builds from its own request, "
                        "against the one the wallet signed over",
                   _DA: "the DeviceSignature, the device key and the DeviceSigned data (ISO/IEC 18013-5 mdoc "
                        "authentication, OpenID4VP 1.0 8.6)",
                   _RQ: "the response against the DCQL query the verifier made",
                   _IA: "the IssuerAuth COSE_Sign1 over the MSO: its signature, its headers and its payload (RFC "
                        "9052, RFC 9053, ISO/IEC 18013-5)",
                   _MSO: "the MSO against the document and the IssuerSignedItems it digests: docType, "
                         "digestAlgorithm, valueDigests and digestIDs, and each item's random (ISO/IEC 18013-5, "
                         "OpenID4VP 1.0 8.6)"},
        "classes": {"control": "a valid DeviceResponse: a correct verifier accepts it",
                    "spec": "a sentence of the cited text requires the refusal",
                    "spec-implied": "the cited sentence binds the issuer or the wallet, or a definition implies the "
                                    "refusal; or the clause is ISO-only, its text not read",
                    "policy": "no sentence of the cited text requires the refusal: the verdict is the one the "
                              "vector's named policy reaches"},
        "policies": POLICIES,
        "vectors": vectors,
    }


def write(doc, out_dir):
    path = os.path.join(out_dir, "mdoc-vectors.json")
    with open(path, "w") as fh:
        fh.write(json.dumps(doc, indent=1) + "\n")
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(description="Make the mdoc negative vectors.")
    ap.add_argument("--out", help="write mdoc-vectors.json into this directory, instead of stdout")
    args = ap.parse_args(argv)
    doc = build()
    if args.out:
        print("wrote", write(doc, args.out), file=sys.stderr)
    else:
        sys.stdout.write(json.dumps(doc, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
