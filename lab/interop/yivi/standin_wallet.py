# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""standin_wallet.py -- the REHEARSAL's wallet, in place of the phone. Not the Yivi app.

It answers the walk's request the way irmago does (lab/interop/irmago): the request object
fetched by GET, its signature checked under its x5c leaf and that leaf's SHA-256 checked against
the x509_hash client_id, one SD-JWT VC of vct pbdf.sidn-pbdf.email presented with the `domain`
disclosure only, a key binding JWT whose aud is the full client_id, and the response encrypted to
the first key in client_metadata.jwks (ECDH-ES, A128GCM) and posted as direct_post.jwt.

The credential is issued here, under a stand-in issuer made for the rehearsal: a root, an
"attestation providers" CA it certifies, and a leaf the CA certifies whose first URI name is the
`iss`. The x5c carries the leaf alone. Only the CA goes into the rehearsal's trust list.

    standin_wallet.py --make-issuer DIR      # once per rehearsal; DIR/anchor.pem is the CA
    standin_wallet.py --issuer DIR LINK      # present, LINK being the walk's launch link
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent / "packages" / "polaris-oid4vp"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from polaris_oid4vp.jwe import _public_key_from_jwk, b64u_decode, b64u_encode, encrypt_compact  # noqa: E402

ISS = "https://standin-issuer.invalid/rehearsal"
VCT = "pbdf.sidn-pbdf.email"


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca(subject, key, issuer, issuer_key, now):
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False,
                                         False), critical=True)
            .sign(issuer_key, hashes.SHA256()))


def make_issuer(out):
    out.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    root_key, ca_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    root_name = _name("Stand-in Requestors Root CA (rehearsal)")
    ca_name = _name("Stand-in Attestation Providers CA (rehearsal)")
    root = _ca(root_name, root_key, root_name, root_key, now)
    ca = _ca(ca_name, ca_key, root_name, root_key, now)
    leaf = (x509.CertificateBuilder().subject_name(_name("Stand-in email issuer (rehearsal)"))
            .issuer_name(ca_name).public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(ISS)]),
                           critical=False)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False,
                                         False), critical=True)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    (out / "anchor.pem").write_bytes(ca.public_bytes(pem))
    (out / "root.pem").write_bytes(root.public_bytes(pem))
    (out / "leaf.pem").write_bytes(leaf.public_bytes(pem))
    key_path = out / "leaf-key.pem"
    key_path.write_bytes(leaf_key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
    os.chmod(key_path, 0o600)


def _jws(key, header, payload):
    head = (b64u_encode(json.dumps(header, separators=(",", ":")).encode()) + "."
            + b64u_encode(json.dumps(payload, separators=(",", ":")).encode()))
    r, s = asym_utils.decode_dss_signature(key.sign(head.encode("ascii"), ec.ECDSA(hashes.SHA256())))
    return head + "." + b64u_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _jwk(key):
    n = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64u_encode(n.x.to_bytes(32, "big")),
            "y": b64u_encode(n.y.to_bytes(32, "big"))}


def _disclosure(name, value):
    return b64u_encode(json.dumps([b64u_encode(os.urandom(16)), name, value]).encode())


def _verify_request(jar, client_id):
    head, payload, sig = jar.split(".")
    header = json.loads(b64u_decode(head))
    leaf_der = base64.b64decode(header["x5c"][0])
    expected = "x509_hash:" + b64u_encode(hashlib.sha256(leaf_der).digest())
    if client_id != expected:
        raise SystemExit("the link's client_id is not the request object's x509_hash")
    raw = b64u_decode(sig)
    der = asym_utils.encode_dss_signature(int.from_bytes(raw[:32], "big"),
                                          int.from_bytes(raw[32:], "big"))
    x509.load_der_x509_certificate(leaf_der).public_key().verify(
        der, (head + "." + payload).encode("ascii"), ec.ECDSA(hashes.SHA256()))
    claims = json.loads(b64u_decode(payload))
    if claims.get("client_id") != client_id:
        raise SystemExit("the signed client_id is not the link's")
    return claims


def present(issuer_dir, link):
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(link).query)
    client_id, request_uri = query["client_id"][0], query["request_uri"][0]
    with urllib.request.urlopen(request_uri, timeout=30) as r:
        jar = r.read().decode("ascii")
    print("fetched the request object by GET: %s (%d bytes)" % (urllib.parse.urlsplit(request_uri).netloc, len(jar)))
    req = _verify_request(jar, client_id)
    print("request object signature checked under its x5c leaf; x509_hash matches the link")
    query_id = req["dcql_query"]["credentials"][0]["id"]

    leaf_key = serialization.load_pem_private_key((issuer_dir / "leaf-key.pem").read_bytes(), None)
    leaf_der = x509.load_pem_x509_certificate((issuer_dir / "leaf.pem").read_bytes()).public_bytes(
        serialization.Encoding.DER)
    holder = ec.generate_private_key(ec.SECP256R1())
    domain = _disclosure("domain", "example.org")
    email = _disclosure("email", "rehearsal@example.org")
    now = int(time.time())
    payload = {"iss": ISS, "vct": VCT, "iat": now, "exp": now + 3600, "_sd_alg": "sha-256",
               "_sd": sorted(b64u_encode(hashlib.sha256(d.encode()).digest()) for d in (domain, email)),
               "cnf": {"jwk": _jwk(holder)}}
    issuer_jwt = _jws(leaf_key, {"alg": "ES256", "typ": "dc+sd-jwt",
                                 "x5c": [base64.b64encode(leaf_der).decode()]}, payload)
    presented = issuer_jwt + "~" + domain + "~"
    kb = _jws(holder, {"alg": "ES256", "typ": "kb+jwt"},
              {"iat": now, "aud": client_id, "nonce": req["nonce"],
               "sd_hash": b64u_encode(hashlib.sha256(presented.encode()).digest())})
    body = {"state": req["state"], "vp_token": {query_id: [presented + kb]}}
    jwk = req["client_metadata"]["jwks"]["keys"][0]
    token = encrypt_compact(json.dumps(body).encode(), _public_key_from_jwk(jwk), "A128GCM",
                            extra_header={"kid": jwk["kid"]})
    data = urllib.parse.urlencode({"response": token}).encode("ascii")
    post = urllib.request.Request(req["response_uri"], data=data,
                                  headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(post, timeout=30) as r:
            status, text = r.status, r.read().decode()
    except urllib.error.HTTPError as exc:
        status, text = exc.code, exc.read().decode()
    print("posted the encrypted response to %s: %d %s"
          % (urllib.parse.urlsplit(req["response_uri"]).netloc, status, text))
    return 0 if status == 200 else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--make-issuer", metavar="DIR")
    ap.add_argument("--issuer", metavar="DIR")
    ap.add_argument("link", nargs="?")
    args = ap.parse_args()
    if args.make_issuer:
        make_issuer(pathlib.Path(args.make_issuer))
        return 0
    if not (args.issuer and args.link):
        ap.error("--issuer DIR LINK, or --make-issuer DIR")
    return present(pathlib.Path(args.issuer), args.link)


if __name__ == "__main__":
    sys.exit(main())
