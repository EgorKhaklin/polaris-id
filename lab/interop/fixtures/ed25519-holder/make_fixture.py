#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""make_fixture.py: one SD-JWT VC whose holder key (`cnf.jwk`) is Ed25519, for testing a wallet or
verifier whose holder keys are Ed25519 only. Generated, not from an exchange. Writes, beside this file:

  credential.dc+sd-jwt              the issuer-signed SD-JWT VC, typ dc+sd-jwt, no Key Binding JWT
  credential.vc+sd-jwt              the same credential with typ vc+sd-jwt: only typ and the signature differ
  trust-anchor.pem                  the test CA the issuer's x5c leaf chains to
  holder-private.test-only.jwk.json the Ed25519 holder key, private half included: TEST material, published
  example-presentation.dc+sd-jwt    credential.dc+sd-jwt with two of its three claims disclosed and a
                                    Key Binding JWT signed EdDSA by the holder key
  fixture.json                      the instant, nonce, audience, claims and keys, listing every file

Every key is derived from a public seed (SEED below), every ECDSA signature is deterministic (RFC 6979)
and Ed25519 signatures are deterministic by construction, so a byte here never changes between runs and
nothing here is a secret. Run it again and `git diff` must be empty. Needs cryptography 44 or later.
"""
import base64
import datetime
import hashlib
import json
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
SEED = "polaris-ed25519-holder-fixture/v1/"
UTC = datetime.timezone.utc
NOW = int(datetime.datetime(2026, 10, 1, tzinfo=UTC).timestamp())        # iat, and the KB-JWT's iat
EXP = int(datetime.datetime(2099, 12, 31, tzinfo=UTC).timestamp())       # far future, on purpose
NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NOT_AFTER = datetime.datetime(2099, 12, 31, 23, 59, 59, tzinfo=UTC)
ISSUER = "https://issuer.example"
VCT = "urn:example:vct:ed25519-holder-test"
NONCE = "ed25519-holder-fixture-nonce-1"
AUDIENCE = "x509_san_dns:verifier.example"
CLAIMS = (("given_name", "Erika"), ("family_name", "Mustermann"), ("birthdate", "1964-08-12"))
PRESENTED = ("given_name", "family_name")   # what example-presentation discloses; birthdate stays hidden
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _seed(label):
    return hashlib.sha256((SEED + label).encode()).digest()


def _p256(label):
    return ec.derive_private_key(int.from_bytes(_seed("key/" + label), "big") % (_P256_N - 1) + 1, ec.SECP256R1())


HOLDER_K = ed25519.Ed25519PrivateKey.from_private_bytes(_seed("key/holder-ed25519"))
CA_K, ISS_K = _p256("ca"), _p256("issuer")


def _raw(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def holder_public_jwk():
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(_raw(HOLDER_K))}


def holder_private_jwk():
    d = HOLDER_K.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                               serialization.NoEncryption())
    return dict(holder_public_jwk(), d=b64u(d))


def did_key(raw_public):
    """did:key for an Ed25519 public key: multicodec 0xed01, then base58btc with the `z` prefix."""
    data = b"\xed\x01" + raw_public
    n, out = int.from_bytes(data, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "did:key:z" + "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(cn, key, issuer_cn, issuer_key, serial, *, ca):
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(issuer_cn))
         .public_key(key.public_key()).serial_number(serial).not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER))
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        b = b.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        b = b.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(ISSUER),
                                                         x509.DNSName("issuer.example")]), critical=False)
    return b.sign(issuer_key, hashes.SHA256(), ecdsa_deterministic=True)


CA = _cert("Ed25519 Holder Fixture Test CA", CA_K, "Ed25519 Holder Fixture Test CA", CA_K, 1, ca=True)
LEAF = _cert("Ed25519 Holder Fixture Test Issuer", ISS_K, "Ed25519 Holder Fixture Test CA", CA_K, 2, ca=False)


def _json(obj):
    return json.dumps(obj, separators=(",", ":"))


def _signing_input(header, payload):
    return b64u(_json(header).encode()) + "." + b64u(_json(payload).encode())


def _es256_jws(header, payload):
    signing_input = _signing_input(header, payload)
    der = ISS_K.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    return signing_input + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _eddsa_jws(header, payload):
    signing_input = _signing_input(header, payload)
    return signing_input + "." + b64u(HOLDER_K.sign(signing_input.encode("ascii")))


def disclosures():
    """name -> the Disclosure for it: [salt, name, value], compact JSON, base64url (RFC 9901 4.2.1)."""
    return {name: b64u(_json([b64u(_seed("salt/" + name)[:16]), name, value]).encode()) for name, value in CLAIMS}


def digest(disclosure):
    return b64u(hashlib.sha256(disclosure.encode("ascii")).digest())


def credential(typ):
    """The stored form: the issuer-signed JWT, each Disclosure followed by `~`, no Key Binding JWT."""
    ds = disclosures()
    payload = {"iss": ISSUER, "vct": VCT, "iat": NOW, "exp": EXP,
               "_sd": sorted(digest(d) for d in ds.values()), "_sd_alg": "sha-256",
               "cnf": {"jwk": holder_public_jwk()}}
    header = {"alg": "ES256", "typ": typ, "x5c": [base64.b64encode(LEAF.public_bytes(serialization.Encoding.DER))
                                                  .decode("ascii")]}
    return _es256_jws(header, payload) + "~" + "".join(ds[name] + "~" for name, _ in CLAIMS)


def presentation():
    """credential.dc+sd-jwt with PRESENTED disclosed and a Key Binding JWT over it (RFC 9901 4.3)."""
    ds = disclosures()
    presented = credential("dc+sd-jwt").split("~")[0] + "~" + "".join(ds[name] + "~" for name in PRESENTED)
    kb = {"iat": NOW, "aud": AUDIENCE, "nonce": NONCE,
          "sd_hash": b64u(hashlib.sha256(presented.encode("ascii")).digest())}
    return presented + _eddsa_jws({"alg": "EdDSA", "typ": "kb+jwt"}, kb)


def build():
    files = {"credential.dc+sd-jwt": credential("dc+sd-jwt"),
             "credential.vc+sd-jwt": credential("vc+sd-jwt"),
             "trust-anchor.pem": CA.public_bytes(serialization.Encoding.PEM).decode("ascii"),
             "holder-private.test-only.jwk.json": json.dumps(holder_private_jwk(), indent=1, sort_keys=True) + "\n",
             "example-presentation.dc+sd-jwt": presentation()}
    fixture = {
        "generated": "by make_fixture.py from public seeds; not from an exchange, and every key is test material",
        "now": NOW, "exp": EXP, "issuer": ISSUER, "vct": VCT, "nonce": NONCE, "audience": AUDIENCE,
        "claims": dict(CLAIMS), "presented_claims": list(PRESENTED),
        "issuer_alg": "ES256", "kb_alg": "EdDSA",
        "holder_public_jwk": holder_public_jwk(), "holder_did_key": did_key(_raw(HOLDER_K)),
        "files": {
            "credential.dc+sd-jwt": "issuer-signed SD-JWT VC, typ dc+sd-jwt, all three disclosures, no KB-JWT",
            "credential.vc+sd-jwt": "the same, typ vc+sd-jwt; only typ and the issuer signature differ",
            "trust-anchor.pem": "the test CA; the issuer JWT's x5c holds the leaf it signed",
            "holder-private.test-only.jwk.json": "the Ed25519 holder key with its private d: TEST ONLY, published",
            "example-presentation.dc+sd-jwt": "given_name and family_name disclosed, KB-JWT signed EdDSA",
            "fixture.json": "this file"}}
    files["fixture.json"] = json.dumps(fixture, indent=1, sort_keys=True) + "\n"
    return files


if __name__ == "__main__":
    built = build()
    for name, text in built.items():
        with open(os.path.join(HERE, name), "w", newline="") as f:
            f.write(text)
    print("wrote", ", ".join(sorted(built)))
