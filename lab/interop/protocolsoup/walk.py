#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The issuer, and the person at the wallet, for run.sh.

ProtocolSoup's wallet harness is a service with a headless JSON API. It makes the holder key,
checks and stores the credential, and resolves and answers the request; this script does only
what is outside it:

  keys DIR ISS                  an issuer key certified by a CA made here (x5c, the HAIP way),
                                its JWKS, a second CA for control (a), a key the issuer does not
                                publish for control (f), and a TLS certificate for ISS's host
  serve DIR PORT                ISS's /.well-known/jwks.json over HTTPS, where the harness
                                fetches the issuer key from before it stores a credential
  enrol API SESSION DIR [KEY]   read the wallet's did:jwk (/api/session), mint one urn:eudi:pid:1
                                dc+sd-jwt bound to it (sub and cnf), signed with KEY (the issuer
                                key unless given), and import it (/api/import)
  present API SESSION DIR URI   hand the harness the launch URI with the user's approval
                                (/api/present, approve_external_trust) and print what it said

The credential is signed with ../waltid/issue_sdjwt_vc.py's own functions. That script's payload
has no `sub`, and the harness refuses a credential without one (it binds a credential to the
wallet's DID by `sub`), so the payload is put together here.
"""
import base64
import datetime
import hashlib
import http.server
import json
import os
import pathlib
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.dont_write_bytecode = True  # the import below would otherwise leave a cache in the tree
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "waltid"))
from issue_sdjwt_vc import b64u, issuer_certificates, jws, public_jwk  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402


def private_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def tls_certificate(host):
    """A self-signed listener certificate for `host`, as `polaris-oid4vp keygen` makes its own."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM), private_pem(key)


def keys(out, iss):
    out.mkdir(parents=True, exist_ok=True)
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    leaf_der, ca_pem = issuer_certificates(issuer_key, iss)
    _, other_ca_pem = issuer_certificates(ec.generate_private_key(ec.SECP256R1()), iss)
    tls_pem, tls_key_pem = tls_certificate(urllib.parse.urlsplit(iss).hostname)
    (out / "iss").write_text(iss)
    (out / "issuer-key.pem").write_bytes(private_pem(issuer_key))
    (out / "issuer-leaf.b64").write_text(base64.b64encode(leaf_der).decode())
    (out / "issuer-ca.pem").write_text(ca_pem)
    (out / "jwks.json").write_text(json.dumps({"keys": [public_jwk(issuer_key, kid="issuer-1")]}))
    (out / "other-issuer-ca.pem").write_text(other_ca_pem)
    (out / "stranger-key.pem").write_bytes(private_pem(ec.generate_private_key(ec.SECP256R1())))
    (out / "tls.pem").write_bytes(tls_pem)
    (out / "tls-key.pem").write_bytes(tls_key_pem)


def serve(directory, port):
    jwks = (directory / "jwks.json").read_bytes()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            found = self.path == "/.well-known/jwks.json"
            self.send_response(200 if found else 404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(jwks if found else b'{"error":"not_found"}')

        def log_message(self, fmt, *args):
            print("issuer: " + fmt % args, flush=True)

    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(directory / "tls.pem", directory / "tls-key.pem")
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print("issuer: serving %s/.well-known/jwks.json" % (directory / "iss").read_text(), flush=True)
    httpd.serve_forever()


def api(base, session, path, body=None):
    request = urllib.request.Request(
        base + path, method="GET" if body is None else "POST",
        data=None if body is None else json.dumps(body).encode(),
        headers={"X-Wallet-Session": session, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"error": raw.decode("utf-8", "replace")}


def enrol(base, session, directory, key_file=None):
    status, wallet = api(base, session, "/api/session")
    subject = wallet.get("wallet_subject", "")
    if status != 200 or not subject.startswith("did:jwk:"):
        sys.exit("ENROL FAILED: /api/session answered %d %s" % (status, wallet))
    encoded = subject[len("did:jwk:"):]
    holder = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))

    key_file = pathlib.Path(key_file) if key_file else directory / "issuer-key.pem"
    signer = serialization.load_pem_private_key(key_file.read_bytes(), None)
    disclosures = [b64u(json.dumps([b64u(os.urandom(16)), name, value],
                                   separators=(",", ":")).encode())
                   for name, value in (("given_name", "Jean"), ("family_name", "Dupont"))]
    payload = {"iss": (directory / "iss").read_text(), "sub": subject, "vct": "urn:eudi:pid:1",
               "iat": int(time.time()), "_sd_alg": "sha-256",
               "_sd": sorted(b64u(hashlib.sha256(d.encode("ascii")).digest()) for d in disclosures),
               "cnf": {"jwk": {k: holder[k] for k in ("kty", "crv", "x", "y")}}}
    header = {"alg": "ES256", "typ": "dc+sd-jwt",
              "x5c": [(directory / "issuer-leaf.b64").read_text()]}
    credential = jws(signer, header, payload) + "~" + "~".join(disclosures) + "~"

    status, stored = api(base, session, "/api/import",
                         {"credential": credential, "credential_format": "dc+sd-jwt"})
    if status != 200:
        sys.exit("IMPORT REFUSED %d %s: %s" % (status, stored.get("error"),
                                                stored.get("error_description")))
    print("IMPORTED %s %s, bound to %s..." % (
        stored.get("credential_format"), (stored.get("credential_summary") or {}).get("vct"),
        subject[:28]))
    (directory / ("credential-id-" + session)).write_text(stored["credential_id"])


def present(base, session, directory, uri):
    status, answer = api(base, session, "/api/present", {
        "openid4vp_uri": uri, "approve_external_trust": True,
        "credential_id": (directory / ("credential-id-" + session)).read_text(),
        "credential_format": "dc+sd-jwt"})
    if "upstream_status" in answer:
        verdict = "DISPATCHED" if answer["upstream_status"] == 200 else "DISPATCH FAILED"
        trust = answer.get("trust") or {}
        print("%s: the verifier answered %d %s; disclosed %s; %s request object verified %s, "
              "the wallet's own verifier %s, approved by the user %s" % (
                  verdict, answer["upstream_status"], json.dumps(answer.get("upstream_body")),
                  answer.get("disclosure_claims"), trust.get("client_id_scheme"),
                  (trust.get("request_object_verification") or {}).get("verified"),
                  trust.get("trusted_target"), answer.get("external_trust_approved")))
    else:
        print("REQUEST REFUSED %d %s: %s" % (status, answer.get("error"),
                                             answer.get("error_description")))


def main(argv):
    command, args = (argv[1], argv[2:]) if len(argv) > 1 else ("", [])
    if command == "keys" and len(args) == 2:
        keys(pathlib.Path(args[0]), args[1])
    elif command == "serve" and len(args) == 2:
        serve(pathlib.Path(args[0]), int(args[1]))
    elif command == "enrol" and len(args) in (3, 4):
        enrol(args[0], args[1], pathlib.Path(args[2]), *args[3:])
    elif command == "present" and len(args) == 4:
        present(args[0], args[1], pathlib.Path(args[2]), args[3])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
