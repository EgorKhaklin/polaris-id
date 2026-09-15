#!/usr/bin/env python3
"""Mint one SD-JWT VC bound to a key walt.id generated and holds.

This is the ISSUER half of the walt.id encounter. It is deliberately not a product:
polaris-oid4vp is a verifier, and to test a verifier against a foreign wallet something
has to put a credential in that wallet first. The credential is minted here with the
holder public key walt.id reported for its own generated key, so the key binding JWT
walt.id later produces is signed by a private key this repository has never seen. That
is the property that makes the exchange evidence of anything.
"""
import argparse
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


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--holder-jwk", required=True, help="JSON file with walt.id's public JWK")
    ap.add_argument("--out", required=True, help="where to write the credential + issuer JWKS")
    ap.add_argument("--vct", default="urn:eudi:pid:1")
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
    issuer_jwt = jws(issuer_key, {"alg": "ES256", "typ": "dc+sd-jwt",
                                  "kid": "polaris-interop-issuer-1"}, payload)
    credential = issuer_jwt + "~" + "~".join(disclosures) + "~"

    out = pathlib.Path(args.out)
    out.write_text(json.dumps({
        "credential": credential,
        "issuer_jwks": [issuer_jwk],
        "vct": args.vct,
        "holder_kid": holder.get("kid"),
    }, indent=2))
    print("credential   %s..." % credential[:60])
    print("disclosures  %d (given_name, family_name)" % len(disclosures))
    print("bound to     %s" % holder.get("kid"))
    print("wrote        %s" % out)


if __name__ == "__main__":
    main()
