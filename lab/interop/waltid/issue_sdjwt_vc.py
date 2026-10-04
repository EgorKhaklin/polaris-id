#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Mint one SD-JWT VC bound to a key walt.id generated and holds.

This is the ISSUER half of the walt.id encounter. It is deliberately not a product:
polaris-oid4vp is a verifier, and to test a verifier against a foreign wallet something
has to put a credential in that wallet first. The credential is minted here with the
holder public key walt.id reported for its own generated key, so the key binding JWT
walt.id later produces is signed by a private key this repository has never seen. That
is the property that makes the exchange evidence of anything.
"""
import argparse
import base64
import hashlib
import json
import pathlib
import time

from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes


def b64u(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def public_jwk(key, kid=None):
    n = key.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256",
           "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}
    if kid:
        jwk["kid"] = kid
    return jwk


def jws(key, header, payload):
    signing_input = b64u(json.dumps(header, separators=(",", ":")).encode()) + "." + \
                    b64u(json.dumps(payload, separators=(",", ":")).encode())
    der = key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return signing_input + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def issuer_certificates(issuer_key, iss):
    """(the issuer leaf's DER, its CA's PEM): a CA made for this run and a leaf for `issuer_key`."""
    import datetime
    from urllib.parse import urlsplit
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "polaris interop issuer CA")])
    usage = dict(content_commitment=False, key_encipherment=False, data_encipherment=False,
                 key_agreement=False, encipher_only=False, decipher_only=False)
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False, key_cert_sign=True, crl_sign=True,
                                       **usage), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                         critical=False)
          .sign(ca_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "polaris interop issuer")]))
            .issuer_name(ca_name).public_key(issuer_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False,
                                         **usage), critical=True)
            .add_extension(x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(iss), x509.DNSName(urlsplit(iss).hostname)]),
                critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    return (leaf.public_bytes(serialization.Encoding.DER),
            ca.public_bytes(serialization.Encoding.PEM).decode("ascii"))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--holder-jwk", required=True, help="JSON file with walt.id's public JWK")
    ap.add_argument("--out", required=True, help="where to write the credential + issuer JWKS")
    ap.add_argument("--vct", default="urn:eudi:pid:1")
    ap.add_argument("--x5c", action="store_true",
                    help="sign under an issuer certificate in x5c, chaining to a CA made here (the "
                         "HAIP way to name an issuer); the CA is written beside the credential as "
                         "issuer_ca_pem, for the verifier's --issuer-trust-anchor and the wallet")
    args = ap.parse_args()

    holder = json.loads(pathlib.Path(args.holder_jwk).read_text())
    if "holder_jwk" in holder:
        holder = holder["holder_jwk"]

    issuer_key = ec.generate_private_key(ec.SECP256R1())
    issuer_jwk = public_jwk(issuer_key, kid="polaris-interop-issuer-1")

    # Two selectively-disclosable claims, the pair polaris-oid4vp asks for by default.
    disclosures = [
        b64u(json.dumps([s, n, v], separators=(",", ":")).encode())
        for s, n, v in (("s0", "given_name", "Jean"), ("s1", "family_name", "Dupont"))]
    digests = [b64u(hashlib.sha256(d.encode("ascii")).digest()) for d in disclosures]

    payload = {"iss": "https://issuer.polaris.test", "vct": args.vct,
               "iat": int(time.time()), "_sd": digests, "_sd_alg": "sha-256",
               "cnf": {"jwk": {k: v for k, v in holder.items() if k in ("kty", "crv", "x", "y")}}}
    header = {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "polaris-interop-issuer-1"}
    extra = {}
    if args.x5c:
        # A wallet that names issuers only by DID or certificate (Credo 0.7 and later) refuses a
        # bare `kid`. Here the issuer key is certified by a CA made for this run: the leaf names
        # the `iss` URL as its own, signs and is not a CA; the CA certifies and nothing else.
        leaf_der, ca_pem = issuer_certificates(issuer_key, payload["iss"])
        header = {"alg": "ES256", "typ": "dc+sd-jwt",
                  "x5c": [base64.b64encode(leaf_der).decode()]}
        extra["issuer_ca_pem"] = ca_pem
    issuer_jwt = jws(issuer_key, header, payload)
    credential = issuer_jwt + "~" + "~".join(disclosures) + "~"

    out = pathlib.Path(args.out)
    out.write_text(json.dumps({
        "credential": credential,
        "issuer_jwks": [issuer_jwk],
        "vct": args.vct,
        "holder_kid": holder.get("kid"),
        **extra,
    }, indent=2))
    print("credential   %s..." % credential[:60])
    print("disclosures  %d (given_name, family_name)" % len(disclosures))
    print("bound to     %s" % holder.get("kid"))
    print("wrote        %s" % out)


if __name__ == "__main__":
    main()
