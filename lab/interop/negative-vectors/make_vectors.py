#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""lab/interop/negative-vectors/make_vectors.py: negative test vectors for SD-JWT VC presentations
under OpenID4VP 1.0 and HAIP 1.0 (lab record 018).

Every vector is one valid presentation with exactly one thing changed, re-signed wherever the change
needs it, so the only reason to refuse it is the clause it cites. Two accept controls come first: a
verifier that refuses everything fails them, and a negative vector means nothing without them.

The keys and certificates are TEST material derived from public seeds, signed with deterministic
ECDSA (RFC 6979): anyone can regenerate every byte, and nobody may trust them.

    python3 make_vectors.py > vectors.json        # needs cryptography 44 or later
    python3 make_vectors.py --out .               # vectors.json and the views/ derived from it

Every presentation's Key Binding JWT names one verifier (its aud and nonce) and one instant. Re-bind
every vector, with the same defects, to another verifier:

    python3 make_vectors.py --audience A --nonce N --now T [--issuer-key K] [--holder-key H] --out DIR

K and H are PEM files holding a P-256 private key (PKCS#8 or SEC1). The views need polaris-oid4vp
(this tree's, or an installed one): `reference_rejected_at_mint` is its verdict on each vector.
"""
import argparse
import base64
import datetime
import hashlib
import hmac
import importlib.util
import json
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
SEED = "polaris-negative-vectors/v1/"
UTC = datetime.timezone.utc
# The binding: the verifier and instant every Key Binding JWT names. bind() changes all three.
NOW = int(datetime.datetime(2026, 10, 1, tzinfo=UTC).timestamp())
NONCE = "nV7cX2q-0bQ5mT9sKe4wLz"
AUDIENCE = "x509_hash:WJfeA4xR3mvFsWk2fEB3oiu4f3E1yBHkXjsN0P2s6RE"
# The Client Identifier Prefixes of OpenID4VP 1.0 s5.9.3, including the reserved origin (A.2): over the Digital
# Credentials API the Key Binding JWT's aud is origin:<Origin> (A.4). kb-aud-no-prefix strips the prefix, so the
# audience needs one; a pre-registered client_id without a prefix (s5.9) cannot be bound.
CLIENT_ID_PREFIXES = ("redirect_uri", "openid_federation", "decentralized_identifier", "verifier_attestation",
                      "x509_san_dns", "x509_hash", "origin")
ISSUER = "https://issuer.example"
VCT = "urn:eudi:pid:1"
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _key(label):
    d = int.from_bytes(hashlib.sha256((SEED + "key/" + label).encode()).digest(), "big") % (_P256_N - 1) + 1
    return ec.derive_private_key(d, ec.SECP256R1())


def _jwk(key):
    n = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}


def _es256(key, data, der=False):
    sig = key.sign(data, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    if der:
        return sig
    r, s = decode_dss_signature(sig)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _jws(header, payload_text, *, key=None, der=False, hmac_key=None):
    signing_input = b64u(json.dumps(header, separators=(",", ":")).encode()) + "." + b64u(payload_text.encode())
    alg = header.get("alg")
    if alg == "none":
        return signing_input + "."
    if alg == "HS256":
        return signing_input + "." + b64u(hmac.new(hmac_key, signing_input.encode("ascii"), hashlib.sha256).digest())
    return signing_input + "." + b64u(_es256(key, signing_input.encode("ascii"), der))


def _json(obj):
    return json.dumps(obj, separators=(",", ":"))


# --- the PKI: a root (the trust anchor), an intermediate, the issuer's leaf, and the bad ones ---------------
# Validity is relative to NOW, so a re-bound instant keeps every certificate's defect (and only it):
# at the default NOW (2026-10-01) these are 2026-01-01, 2030-01-01 and 2026-06-01.
_NOT_BEFORE_DAYS, _NOT_AFTER_DAYS, _EXPIRED_DAYS = 273, 1188, 122


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(cn, key, issuer_cn, issuer_key, serial, *, ca, pathlen=None, leaf_san=False, not_before=None, not_after=None):
    not_before = T0 if not_before is None else not_before
    not_after = T1 if not_after is None else not_after
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(issuer_cn))
         .public_key(key.public_key()).serial_number(serial).not_valid_before(not_before).not_valid_after(not_after))
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=pathlen), critical=True)
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        b = b.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
    if leaf_san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(ISSUER),
                                                         x509.DNSName("issuer.example")]), critical=False)
    return b.sign(issuer_key, hashes.SHA256(), ecdsa_deterministic=True)


ROOT_K, INT_K, ISS_K, HOLDER_K = _key("root"), _key("intermediate"), _key("issuer"), _key("holder")
ROGUE_K, BADINT_K = _key("rogue-root"), _key("not-a-ca")


def _make_pki():
    global T0, T1, ROOT, INTERMEDIATE, LEAF, SELF_SIGNED_LEAF, ROGUE_ROOT, ROGUE_LEAF, EXPIRED_LEAF, NOT_A_CA
    global LEAF_UNDER_NOT_A_CA
    now = datetime.datetime.fromtimestamp(NOW, UTC)
    T0, T1 = now - datetime.timedelta(days=_NOT_BEFORE_DAYS), now + datetime.timedelta(days=_NOT_AFTER_DAYS)
    ROOT = _cert("Negative Vectors Test Root", ROOT_K, "Negative Vectors Test Root", ROOT_K, 1, ca=True, pathlen=1)
    INTERMEDIATE = _cert("Negative Vectors Test Intermediate", INT_K, "Negative Vectors Test Root", ROOT_K, 2, ca=True,
                         pathlen=0)
    LEAF = _cert("Negative Vectors Test Issuer", ISS_K, "Negative Vectors Test Intermediate", INT_K, 3, ca=False,
                 leaf_san=True)
    SELF_SIGNED_LEAF = _cert("Negative Vectors Test Issuer", ISS_K, "Negative Vectors Test Issuer", ISS_K, 4, ca=False,
                             leaf_san=True)
    ROGUE_ROOT = _cert("Negative Vectors Unknown Root", ROGUE_K, "Negative Vectors Unknown Root", ROGUE_K, 5, ca=True,
                       pathlen=1)
    ROGUE_LEAF = _cert("Negative Vectors Test Issuer", ISS_K, "Negative Vectors Unknown Root", ROGUE_K, 6, ca=False,
                       leaf_san=True)
    EXPIRED_LEAF = _cert("Negative Vectors Test Issuer", ISS_K, "Negative Vectors Test Intermediate", INT_K, 7, ca=False,
                         leaf_san=True, not_after=now - datetime.timedelta(days=_EXPIRED_DAYS))
    NOT_A_CA = _cert("Negative Vectors Test Intermediate", BADINT_K, "Negative Vectors Test Root", ROOT_K, 8, ca=False)
    LEAF_UNDER_NOT_A_CA = _cert("Negative Vectors Test Issuer", ISS_K, "Negative Vectors Test Intermediate", BADINT_K, 9,
                                ca=False, leaf_san=True)


_make_pki()


def _der64(cert):
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


# --- one presentation, with knobs; every vector turns exactly one of them ----------------------------------
CLAIMS = (("given_name", "Erika"), ("family_name", "Mustermann"), ("birthdate", "1964-08-12"))


def _salt(name):
    return b64u(hashlib.sha256((SEED + "salt/" + name).encode()).digest()[:16])


def _disclosure(*elements):
    return b64u(_json(list(elements)).encode())


def _digest(disclosure):
    return b64u(hashlib.sha256(disclosure.encode("ascii")).digest())


def present(*, mode="x5c", x5c=None, issuer_header=None, payload=None, extra=(), drop_claims=(),
            issuer_der=False, kb_header=None, kb_payload=None, kb_text=None):
    """`extra` adds Disclosures the issuer commits to; `payload` edits the issuer's claims after the
    digests are in; the `kb_*` knobs edit the Key Binding JWT, re-signed by the holder."""
    disclosures = [_disclosure(_salt(n), n, v) for n, v in CLAIMS if n not in drop_claims]
    disclosures += [_disclosure(*e) for e in extra]
    body = {"iss": ISSUER, "vct": VCT, "iat": NOW - 86400, "exp": NOW + 365 * 86400,
            "_sd": sorted(_digest(d) for d in disclosures), "_sd_alg": "sha-256", "cnf": {"jwk": _jwk(HOLDER_K)}}
    if payload:
        payload(body)
    header = {"alg": "ES256", "typ": "dc+sd-jwt"}
    if mode == "jwks":
        header["kid"] = "issuer-1"
    else:
        header["x5c"] = [_der64(c) for c in (x5c or (LEAF, INTERMEDIATE))]
    header.update(issuer_header or {})
    issuer_jwt = _jws(header, _json(body), key=ISS_K, der=issuer_der)
    presented = issuer_jwt + "~" + "".join(d + "~" for d in disclosures)
    kb_head = {"alg": "ES256", "typ": "kb+jwt"}
    kb_head.update(kb_header or {})
    kb_body = {"iat": NOW, "aud": AUDIENCE, "nonce": NONCE, "sd_hash": b64u(hashlib.sha256(presented.encode("ascii")).digest())}
    if kb_payload:
        kb_payload(kb_body)
    text = kb_text(kb_body) if kb_text else _json(kb_body)
    return presented + _jws(kb_head, text, key=HOLDER_K, hmac_key=_json(_jwk(HOLDER_K)).encode())


def _set(**kv):
    return lambda body: body.update(kv)


def _drop(*names):
    return lambda body: [body.pop(n) for n in names]


def _dup_first_digest(body):
    body["_sd"] = body["_sd"] + [body["_sd"][0]]


CRIT = {"crit": ["urn:example:never-understood"], "urn:example:never-understood": True}

# Citations, quoted from the published texts.
RFC7515_CRIT = ("RFC 7515 s4.1.11", "If any of the listed extension Header Parameters are not understood and "
                "supported by the recipient, then the JWS is invalid.")
RFC7515_X5C = ("RFC 7515 s4.1.6", "The recipient MUST validate the certificate chain according to RFC 5280 "
               "[RFC5280] and consider the certificate or certificate chain to be invalid if any validation failure "
               "occurs.")
RFC9901_DIGEST_TWICE = ("RFC 9901 s7.1 step 4", "If any digest value is encountered more than once in the "
                        "Issuer-signed JWT payload (directly or recursively via other Disclosures), the SD-JWT MUST "
                        "be rejected.")
RFC9901_EXISTS = ("RFC 9901 s7.1 step 3.c.ii.3", "If the claim name already exists at the level of the _sd key, "
                  "the SD-JWT MUST be rejected.")
RFC9901_THREE = ("RFC 9901 s7.1 step 3.c.ii.1", "If the contents of the respective Disclosure is not a JSON array "
                 "of three elements (salt, claim name, claim value), the SD-JWT MUST be rejected.")
RFC9901_SD_NAME = ("RFC 9901 s7.1 step 3.c.ii.2", "If the claim name is _sd or ..., the SD-JWT MUST be rejected.")
RFC9901_KB_TYP = ("RFC 9901 s7.3 step 5.d", "Check that the typ of the Key Binding JWT is kb+jwt (see Section 4.3).")
RFC9901_NONE = ("RFC 9901 s7.3 step 5.b", "The \"none\" algorithm MUST NOT be accepted.")
RFC9901_AUD = ("RFC 9901 s4.3", "aud: REQUIRED. The value MUST be a single string that identifies the intended "
               "receiver of the Key Binding JWT.")
OID4VP_AUD = ("OpenID4VP 1.0 B.3.6", "the aud claim MUST be the value of the Client Identifier")
OID4VP_NONCE = ("OpenID4VP 1.0 B.3.6", "the nonce claim MUST be the value of nonce from the Authorization Request")
RFC9901_KB_AUD_REQUIRED = ("RFC 9901 s4.3", "The Key Binding JWT MUST be a JWT according to [RFC7519], and it MUST "
                           "contain the following elements: ... aud: REQUIRED.")
RFC9901_KB_NONCE_REQUIRED = ("RFC 9901 s4.3", "The Key Binding JWT MUST be a JWT according to [RFC7519], and it MUST "
                             "contain the following elements: ... \"nonce\": REQUIRED.")
RFC9901_KB_BOUND = ("RFC 9901 s7.3 step 5.f", "Determine that the Key Binding JWT is bound to the current transaction "
                    "and was created for this Verifier (replay detection) by validating nonce and aud claims.")
SDJWTVC_REGISTERED = ("SD-JWT VC draft-19 s2.2.2.3", "The following registered JWT claims, including any of their "
                      "sub-claims, when used in the SD-JWT component of an SD-JWT VC, MUST NOT be included in "
                      "Disclosures and therefore MUST NOT be selectively disclosed")
RFC8725_ONE_ALG = ("RFC 8725 s3.1", "each key MUST be used with exactly one algorithm, and this MUST be checked "
                   "when the cryptographic operation is performed.")
RFC8259_NAN = ("RFC 8259 s6", "Numeric values that cannot be represented in the grammar below (such as Infinity and "
               "NaN) are not permitted.")
RFC7519_NUMERICDATE = ("RFC 7519 s4.1.4", "Its value MUST be a number containing a NumericDate value.")
RFC7518_ES256 = ("RFC 7518 s3.4", "The JWS Signature value MUST be a 64-octet sequence. If it is not a 64-octet "
                 "sequence, the validation has failed.")
HAIP_SELF_SIGNED = ("HAIP 1.0 s6.1.1", "The X.509 certificate signing the request MUST NOT be self-signed.")
HAIP_NO_ANCHOR = ("HAIP 1.0 s6.1.1", "The X.509 certificate of the trust anchor MUST NOT be included in the x5c "
                  "JOSE header of the SD-JWT VC.")
RFC5280_VALIDITY = ("RFC 5280 s6.1.3 (a)(2)", "The certificate validity period includes the current time.")
RFC5280_CA = ("RFC 5280 s6.1.4 (k)", "verify that the basicConstraints extension is present and that cA is set to "
              "TRUE.")

def _make_vectors():
    # id, what is changed, class, layer, citations, how the presentation is built, the verdict a correct verifier
    # reaches. Built at call time, so bind() re-derives the instant, the audience and the certificates in them.
    return (
        ("accept-x5c", "nothing: the control, issuer key from x5c chaining to the anchor", "control", "control", (), {}, "accept"),
        ("accept-jwks", "nothing: the control, issuer key given as a JWK", "control", "control", (), {"mode": "jwks"}, "accept"),
        ("issuer-crit", "the issuer JWT's header marks an extension critical", "spec", "jose", (RFC7515_CRIT,),
         {"issuer_header": CRIT}, "reject"),
        ("kb-crit", "the Key Binding JWT's header marks an extension critical", "spec", "jose", (RFC7515_CRIT,),
         {"kb_header": CRIT}, "reject"),
        ("kb-aud-array", "the Key Binding JWT's aud is an array holding the right identifier", "spec", "sd-jwt", (RFC9901_AUD,),
         {"kb_payload": lambda b: b.update(aud=[AUDIENCE])}, "reject"),
        ("kb-aud-no-prefix", "the Key Binding JWT's aud is the Client Identifier without its %s: prefix"
         % AUDIENCE.split(":", 1)[0], "spec",
         "openid4vp", (OID4VP_AUD,), {"kb_payload": lambda b: b.update(aud=AUDIENCE.split(":", 1)[1])}, "reject"),
        ("digest-twice", "the issuer committed to one digest twice", "spec", "sd-jwt", (RFC9901_DIGEST_TWICE,),
         {"payload": _dup_first_digest}, "reject"),
        ("claim-overwrite", "a Disclosure names a claim the payload already holds in the clear", "spec", "sd-jwt", (RFC9901_EXISTS,),
         {"payload": _set(given_name="Max")}, "reject"),
        # spec-implied: SD-JWT VC draft-19 s2.2.2.3 constrains the issuer's format, and its verification
        # section adds no verifier refusal for a disclosed exp.
        ("disclosed-exp", "exp travels in a Disclosure instead of the payload", "spec-implied", "sd-jwt-vc", (SDJWTVC_REGISTERED,),
         {"payload": _drop("exp"), "extra": ((_salt("exp"), "exp", NOW + 365 * 86400),)}, "reject"),
        # spec-implied: SD-JWT VC draft-19 s2.2.2.3 constrains the issuer's format, and its verification
        # section adds no verifier refusal for a disclosed iss.
        ("disclosed-iss", "iss travels in a Disclosure instead of the payload", "spec-implied", "sd-jwt-vc", (SDJWTVC_REGISTERED,),
         {"payload": _drop("iss"), "extra": ((_salt("iss"), "iss", ISSUER),), "mode": "jwks"}, "reject"),
        ("disclosure-four-elements", "an object-property Disclosure with four elements", "spec", "sd-jwt", (RFC9901_THREE,),
         {"extra": ((_salt("nationality"), "nationality", "DE", "extra"),)}, "reject"),
        ("disclosure-named-sd", "a Disclosure whose claim name is _sd", "spec", "sd-jwt", (RFC9901_SD_NAME,),
         {"extra": ((_salt("_sd"), "_sd", ["x"]),)}, "reject"),
        ("kb-typ-jwt", "the Key Binding JWT's typ is JWT", "spec", "sd-jwt", (RFC9901_KB_TYP,), {"kb_header": {"typ": "JWT"}}, "reject"),
        ("kb-alg-none", "the Key Binding JWT is unsigned (alg none)", "spec", "sd-jwt", (RFC9901_NONE,),
         {"kb_header": {"alg": "none"}}, "reject"),
        ("kb-alg-hs256", "the Key Binding JWT is an HMAC keyed with the holder's public JWK (algorithm confusion)", "spec",
         "jose", (RFC8725_ONE_ALG,), {"kb_header": {"alg": "HS256"}}, "reject"),
        ("kb-iat-nan", "the Key Binding JWT's iat is NaN, which is not JSON", "spec", "sd-jwt", (RFC8259_NAN,),
         {"kb_text": lambda b: _json(dict(b, iat="__NAN__")).replace('"__NAN__"', "NaN")}, "reject"),
        ("kb-exp-string", "the Key Binding JWT's exp is a string", "spec-implied", "sd-jwt", (RFC7519_NUMERICDATE,),
         {"kb_payload": lambda b: b.update(exp="never")}, "reject"),
        ("issuer-sig-der", "the issuer JWT's ES256 signature is DER-encoded instead of R||S", "spec", "jose", (RFC7518_ES256,),
         {"issuer_der": True}, "reject"),
        ("x5c-self-signed", "x5c holds only a self-signed leaf", "spec-implied", "haip-x509", (HAIP_SELF_SIGNED,),
         {"x5c": (SELF_SIGNED_LEAF,)}, "reject"),
        ("x5c-includes-anchor", "x5c carries the trust anchor's own certificate", "spec-implied", "haip-x509", (HAIP_NO_ANCHOR,),
         {"x5c": (LEAF, INTERMEDIATE, ROOT)}, "reject"),
        ("x5c-unknown-root", "the leaf chains to a root the verifier was not given", "spec", "haip-x509", (RFC7515_X5C,),
         {"x5c": (ROGUE_LEAF,)}, "reject"),
        ("x5c-leaf-expired", "the leaf expired before the verification instant", "spec", "haip-x509", (RFC7515_X5C, RFC5280_VALIDITY),
         {"x5c": (EXPIRED_LEAF, INTERMEDIATE)}, "reject"),
        ("x5c-intermediate-not-ca", "the intermediate in x5c is not a CA", "spec", "haip-x509", (RFC7515_X5C, RFC5280_CA),
         {"x5c": (LEAF_UNDER_NOT_A_CA, NOT_A_CA)}, "reject"),
        # 0.2.0: absent, not wrong. A verifier that checks aud and nonce only when present accepts these.
        ("kb-aud-missing", "the Key Binding JWT has no aud", "spec", "sd-jwt",
         (RFC9901_KB_AUD_REQUIRED, RFC9901_KB_BOUND, OID4VP_AUD), {"kb_payload": lambda b: b.pop("aud")}, "reject"),
        ("kb-nonce-missing", "the Key Binding JWT has no nonce", "spec", "sd-jwt",
         (RFC9901_KB_NONCE_REQUIRED, RFC9901_KB_BOUND, OID4VP_NONCE), {"kb_payload": lambda b: b.pop("nonce")}, "reject"),
    )


VECTORS = _make_vectors()


def build():
    vectors = []
    for vid, what, cls, layer, cites, kw, expected in VECTORS:
        vectors.append({"id": vid, "changed": what, "class": cls, "layer": layer,
                        "clauses": [{"ref": r, "text": t} for r, t in cites],
                        "trust": kw.get("mode", "x5c"), "presentation": present(**kw), "expected": expected})
    return {
        "name": "Negative test vectors for SD-JWT VC presentations under OpenID4VP 1.0 and HAIP 1.0",
        "version": "0.2.0",
        "warning": "TEST KEYS AND CERTIFICATES, derived from public seeds by make_vectors.py. Never trust them."
                   + "".join(" The %s key came from %s." % kv for kv in _SUPPLIED),
        "settings": {"now": NOW, "nonce": NONCE, "audience": AUDIENCE, "vct": VCT, "max_skew_seconds": 300,
                     "trust_anchors_pem": [_pem(ROOT)],
                     "issuer_jwks": [dict(_jwk(ISS_K), kid="issuer-1", alg="ES256", use="sig")]},
        "layers": {"control": "the controls, which every verifier judges",
                   "jose": "JWS rules (RFC 7515, 7518, 8725) any JOSE verifier applies",
                   "sd-jwt": "RFC 9901, which any SD-JWT verifier applies",
                   "sd-jwt-vc": "the SD-JWT VC profile, which a verifier of SD-JWT VCs applies",
                   "openid4vp": "OpenID4VP 1.0, which a verifier receiving presentations over it applies",
                   "haip-x509": "the issuer's x5c chain under HAIP 1.0 and RFC 5280, which a verifier resolving keys from x5c applies"},
        "classes": {"control": "a valid presentation: a correct verifier accepts it",
                    "spec": "a sentence of the cited text requires the refusal",
                    "spec-implied": "the cited sentence binds the issuer or the wallet, or a definition implies the refusal"},
        "vectors": vectors,
    }


# --- re-binding: the same defects, bound to another verifier --------------------------------------------------
_SUPPLIED = []  # (role, file) for each key read from a file instead of derived from the seed


def load_key(path):
    """A P-256 private key from a PEM file (PKCS#8 "PRIVATE KEY" or SEC1 "EC PRIVATE KEY", unencrypted)."""
    with open(path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise ValueError("%s: not a P-256 private key; every signature here is ES256" % path)
    return key


def bind(*, audience=None, nonce=None, now=None, issuer_key=None, holder_key=None):
    """Re-bind every vector: the Key Binding JWTs name `audience` and `nonce`, every instant and certificate
    validity moves with `now`, and `issuer_key` / `holder_key` (paths, see load_key) replace the seeded keys.
    The root, intermediate and the bad CAs stay the seeded test ones. Unset arguments keep the defaults."""
    global AUDIENCE, NONCE, NOW, ISS_K, HOLDER_K, VECTORS
    if audience is not None:
        prefix, _, rest = audience.partition(":")
        if prefix not in CLIENT_ID_PREFIXES or not rest:
            raise ValueError("audience %r has no OpenID4VP 1.0 Client Identifier Prefix (%s), and kb-aud-no-prefix "
                             "strips it" % (audience, ", ".join(CLIENT_ID_PREFIXES)))
        AUDIENCE = audience
    if nonce is not None:
        if not nonce:
            raise ValueError("the nonce is empty")
        NONCE = nonce
    if now is not None:
        NOW = int(now)
    for role, path in (("issuer", issuer_key), ("holder", holder_key)):
        if path is not None:
            key = load_key(path)
            if role == "issuer":
                ISS_K = key
            else:
                HOLDER_K = key
            _SUPPLIED.append((role, os.path.basename(path)))
    _make_pki()
    VECTORS = _make_vectors()


# --- the views: the same vectors in the layouts other suites read; derived here, never edited by hand ------
EUDI_FIRST = 50  # the EU verifier's test resources number theirs from 00; ours start where nothing collides
# The EU reference verifier's own test binding, read at eudi-srv-verifier-endpoint df07af2f: the client_id its
# InitDCApiTransactionTest configures (x509_hash over the access certificate in its test keystore.jks), and the
# nonce its 08-invalidStatusList-dcql.json sends. eudi/README.md gives the command that binds the vectors to them.
EUDI_REPO = "eu-digital-identity-wallet/eudi-srv-verifier-endpoint"
EUDI_COMMIT = "df07af2f"
EUDI_TEST_CLIENT_HASH = "i7jZiSqa4GXNh1LzBwD2lVtKIcIhpinRQRo8BHSVMx0"
EUDI_TEST_AUDIENCE = "x509_hash:" + EUDI_TEST_CLIENT_HASH
EUDI_TEST_NONCE = "706f6c4d-c92d-4472-9dbf-d814c94f90c2"
EUDI_README_IS = ("**What this is:** Polaris-generated negative vectors (lab record 018), rendered in the EU verifier "
                  "endpoint's test-resource layout, each with its expected outcome and the spec clause it cites.")
EUDI_README_IS_NOT = ("**What this is not:** the EU project's own vectors. The EU project has not run them, and "
                      "nothing here claims how their verifier behaves.")


def _view_json(obj):
    return json.dumps(obj, indent=2) + "\n"


def reference_verdicts(doc):
    """{id: True when polaris-oid4vp refused it}: the generator's own check at mint time, made the way 018's
    test makes it, through run_vectors.py's polaris-oid4vp adapter with the settings the vectors carry."""
    tree = os.path.join(HERE, "..", "..", "..", "packages", "polaris-oid4vp")
    if os.path.isdir(tree) and tree not in sys.path:
        sys.path.insert(0, tree)
    spec = importlib.util.spec_from_file_location("run_vectors", os.path.join(HERE, "run_vectors.py"))
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    return {v["id"]: runner.polaris_oid4vp(v, doc["settings"])[0] == "reject" for v in doc["vectors"]}


def views(doc, rejected):
    """{path under views/: text}. `rejected` is reference_verdicts(doc)."""
    settings = doc["settings"]
    dcql = _view_json({"dcql_query": {"credentials": [{"id": "pid", "format": "dc+sd-jwt",
                                                       "meta": {"vct_values": [settings["vct"]]},
                                                       "claims": [{"id": name, "path": [name]}
                                                                  for name, _ in CLAIMS]}]},
                       "nonce": settings["nonce"], "request_uri_method": "post"})
    out, entries = {}, []
    for n, v in enumerate(doc["vectors"], EUDI_FIRST):
        pair = ["%02d-%s-dcql.json" % (n, v["id"]), "%02d-%s-vpToken.json" % (n, v["id"])]
        out["eudi/" + pair[0]] = dcql
        out["eudi/" + pair[1]] = _view_json({"pid": [v["presentation"]]})
        entries.append({"id": v["id"], "spec_section": v["clauses"][0]["ref"] if v["clauses"] else None,
                        "target": v["layer"], "input": v["presentation"], "expected": v["expected"],
                        "hardening": v["class"] == "spec-implied", "reference_rejected_at_mint": rejected[v["id"]],
                        "clauses": v["clauses"], "trust": v["trust"], "profile": "haip", "files": {"eudi": pair}})
    index = _view_json({"name": doc["name"], "version": doc["version"], "warning": doc["warning"],
                        "source": "vectors.json; these views are derived from it by make_vectors.py",
                        "reference": "reference_rejected_at_mint: polaris-oid4vp's verdict when the views were made",
                        "scope": "profile haip: the KB-JWT typ is kb+jwt (HAIP). A verifier that requires another "
                                 "KB-JWT typ (for example kb+sd-jwt) refuses the controls at the key-binding layer; "
                                 "for such a verifier only the issuer-signed cases apply, checked on their own.",
                        "settings": settings, "vectors": entries})
    out["index.json"] = index
    out["eudi/INDEX.json"] = index
    out["eudi/README.md"] = _eudi_readme(doc)
    out["expected-failures.example.json"] = "[]\n"
    return out


def _eudi_readme(doc):
    """eudi/README.md: what the view is and is not, the binding it carries, and how to re-bind it."""
    st = doc["settings"]
    when = datetime.datetime.fromtimestamp(st["now"], UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    n = len(doc["vectors"])
    last = "%02d" % (EUDI_FIRST + n - 1) if n else "none"
    return "\n".join([
        "# Record 018's negative vectors in the EU verifier endpoint's test-resource layout",
        "",
        EUDI_README_IS,
        "",
        EUDI_README_IS_NOT,
        "",
        "`make_vectors.py --out` writes this directory from `vectors.json`'s generator; never edit it by hand.",
        "",
        "## Files",
        "",
        "The layout is the one in `src/test/resources/` of %s at %s." % (EUDI_REPO, EUDI_COMMIT),
        "",
        "- `NN-<id>-dcql.json`: the transaction-init body: `dcql_query` (one `dc+sd-jwt` query, id `pid`, vct "
        "`%s`), `nonce`, `request_uri_method`." % st["vct"],
        "- `NN-<id>-vpToken.json`: `{\"pid\": [<presentation>]}`.",
        "- `INDEX.json`: per vector, `expected` (`accept` or `reject`), `clauses` (the spec text), `trust` and "
        "`files` (its pair).",
        "",
        "%d vectors, numbered %02d to %s in `vectors.json`'s order. The %d `accept-*` controls come first: a "
        "refusal counts only where the controls are accepted."
        % (n, EUDI_FIRST, last, sum(v["expected"] == "accept" for v in doc["vectors"])),
        "",
        "## The binding",
        "",
        "Every Key Binding JWT names `aud` `%s`, `nonce` `%s` and the instant %s (%d). A verifier with another "
        "client_id, nonce or clock refuses even the controls." % (st["audience"], st["nonce"], when, st["now"]),
        "",
        "## Bind them to the EU test harness",
        "",
        "Its KB-JWT check reads the verifier's clock (`kbJwt.clock.skew` PT5S), so no committed view stays bound. "
        "Make one just before the run (it lands in `DIR/views/eudi/`):",
        "",
        "```bash",
        "python3 make_vectors.py --audience %s --nonce %s --now \"$(date +%%s)\" --out DIR"
        % (EUDI_TEST_AUDIENCE, EUDI_TEST_NONCE),
        "```",
        "",
        "and configure the harness with:",
        "",
        "- `verifier.clientIdPrefix=x509_hash` and `verifier.originalClientId=%s`, as their "
        "InitDCApiTransactionTest does. The default client_id (`pre-registered`) has no Client Identifier Prefix, "
        "which `kb-aud-no-prefix` needs." % EUDI_TEST_CLIENT_HASH,
        "- The test root in `INDEX.json`'s `settings.trust_anchors_pem` as an issuer trust anchor: every x5c "
        "chain ends there, whichever key `--issuer-key` signs with. `accept-jwks` also needs "
        "`settings.issuer_jwks`; without it, run the `trust: x5c` vectors.",
        "",
    ])


def write(doc, out_dir):
    """Write vectors.json and views/ under out_dir. Never deletes: a stale file is the drift test's to find."""
    files = {"vectors.json": json.dumps(doc, indent=1) + "\n"}
    files.update({"views/" + k: v for k, v in views(doc, reference_verdicts(doc)).items()})
    for rel, text in files.items():
        path = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)
    return sorted(files)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Make the negative vectors, bound to one verifier.")
    ap.add_argument("--audience", help="the verifier's client_id, with its Client Identifier Prefix (default: ours)")
    ap.add_argument("--nonce", help="the nonce the verifier's request carries (default: ours)")
    ap.add_argument("--now", type=int, help="the verification instant, Unix seconds (default: 2026-10-01)")
    ap.add_argument("--issuer-key", help="PEM file, P-256 private key: signs every issuer JWT (default: seeded)")
    ap.add_argument("--holder-key", help="PEM file, P-256 private key: the holder's cnf key (default: seeded)")
    ap.add_argument("--out", help="write vectors.json and views/ here, instead of vectors.json to stdout")
    args = ap.parse_args(argv)
    try:
        bind(audience=args.audience, nonce=args.nonce, now=args.now, issuer_key=args.issuer_key,
             holder_key=args.holder_key)
    except (OSError, ValueError) as e:
        print("make_vectors.py: %s" % e, file=sys.stderr)
        return 2
    doc = build()
    if args.out:
        for rel in write(doc, args.out):
            print("wrote", os.path.join(args.out, rel), file=sys.stderr)
    else:
        json.dump(doc, sys.stdout, indent=1)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
