#!/usr/bin/env python3
"""probe.py -- what does the OpenID Foundation conformance suite demand of a verifier?

THIS IS NOT A VERIFIER AND IT IS NOT PRODUCT CODE. It verifies nothing: it builds an
OpenID4VP 1.0 authorization request, hands it to the conformance suite's fake wallet, and
prints the suite's verdicts. The credential the wallet sends back is written to disk
UNOPENED. That is the whole point of the boundary: the product's job is to verify, this
thing's job is to find out what the profile requires, and a measurement harness that starts
verifying has become the product without anybody deciding to build it.

Run it against a LOCAL suite. It is MIT licensed with prebuilt images:

    git clone --depth 1 https://gitlab.com/openid/conformance-suite.git
    cd conformance-suite && docker compose -f docker-compose-prebuilt.yml up -d
    python3 lab/interop/probe.py

Requires `cryptography`. Nothing else, and nothing from the Polaris tree: an import of
Polaris here would make the result a statement about Polaris, which it is not.

WHAT IT MEASURED (2026-09-14, suite at master, plan oid4vp-1final-verifier-haip-test-plan,
variants sd_jwt_vc + direct_post.jwt): 59 SUCCESS, 0 FAILURE, 0 WARNING, 1 REVIEW. The
REVIEW is a screenshot of a verifier verifying, which this cannot produce and should not.

Three requirements were found by failing them, and each cost one run:

  1. client_metadata MUST carry `encrypted_response_enc_values_supported` containing BOTH
     A128GCM and A256GCM. The older `authorization_encrypted_response_alg`/`_enc` names are
     a HAIP-section-5 FAILURE plus an unknown-parameter WARNING.
  2. The x5c leaf MUST NOT be self-signed. A CA is needed, even a throwaway one.
  3. The registered trust anchor MUST NOT appear in the x5c chain. Leaf only.
"""
import argparse
import base64
import datetime
import hashlib
import http.server
import json
import pathlib
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.x509.oid import NameOID

#: The suite's containers reach the host under this name on Docker Desktop. The request_uri
#: and response_uri both have to be fetchable FROM the suite, which is the direction that
#: decides whether any of this can be run on one machine.
HOST = "host.docker.internal"
PORT = 9443
ALIAS = "polaris-lab"

#: The nonce this run asked for. Written out with the capture, because the whole point of a
#: nonce is that a verifier checks the presentation against what IT sent, and a capture
#: without it cannot be used to check anything.
_NONCE = ""


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


# ---------------------------------------------------------------- keys and certificates

def build_chain(workdir: pathlib.Path) -> dict:
    """A CA and a leaf. Requirements 2 and 3 above are both about this shape."""
    now = datetime.datetime.now(datetime.timezone.utc)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "polaris-lab interop CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True,
                                       False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)]))
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
            .sign(ca_key, hashes.SHA256()))

    # TLS for the request_uri. Self-signed is fine HERE: the suite fetched it without
    # complaint, which was the single biggest unknown before this ran.
    tls_key = ec.generate_private_key(ec.SECP256R1())
    tls_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    tls = (x509.CertificateBuilder().subject_name(tls_name).issuer_name(tls_name)
           .public_key(tls_key.public_key()).serial_number(x509.random_serial_number())
           .not_valid_before(now - datetime.timedelta(days=1))
           .not_valid_after(now + datetime.timedelta(days=90))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
           .sign(tls_key, hashes.SHA256()))

    (workdir / "tls_cert.pem").write_bytes(tls.public_bytes(serialization.Encoding.PEM))
    (workdir / "tls_key.pem").write_bytes(tls_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))

    leaf_der = leaf.public_bytes(serialization.Encoding.DER)
    return {
        "leaf_key": leaf_key,
        "leaf_der": leaf_der,
        "ca_pem": ca.public_bytes(serialization.Encoding.PEM).decode(),
        "client_id": "x509_hash:" + b64u(hashlib.sha256(leaf_der).digest()),
    }


def credential_signing_jwk() -> dict:
    """The key the suite's fake wallet signs its credential with. ES256, because HAIP."""
    key = ec.generate_private_key(ec.SECP256R1())
    priv = key.private_numbers()
    pub = priv.public_numbers
    return {"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
            "kid": "polaris-lab-cred",
            "d": b64u(priv.private_value.to_bytes(32, "big")),
            "x": b64u(pub.x.to_bytes(32, "big")),
            "y": b64u(pub.y.to_bytes(32, "big"))}


# ------------------------------------------------------------------- the request object

def build_request_object(chain: dict, workdir: pathlib.Path) -> str:
    """An ES256-signed JAR with an x5c header, carrying a DCQL query for one credential."""
    global _NONCE
    _NONCE = b64u(hashlib.sha256(("%f" % time.time()).encode()).digest())
    enc = ec.generate_private_key(ec.SECP256R1())
    priv = enc.private_numbers()
    pub = priv.public_numbers
    enc_jwk = {"kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES",
               "kid": "polaris-lab-enc",
               "x": b64u(pub.x.to_bytes(32, "big")),
               "y": b64u(pub.y.to_bytes(32, "big"))}
    # The private half is kept so the JWE the wallet POSTs back can be opened LATER, by
    # something else. This file still does not open it: capturing an artifact and making a
    # claim about it are different jobs, and only the second one is about Polaris.
    (workdir / "response_decryption_jwk.json").write_text(json.dumps(
        dict(enc_jwk, d=b64u(priv.private_value.to_bytes(32, "big")))))

    now = int(time.time())
    claims = {
        "iss": chain["client_id"],
        "aud": "https://self-issued.me/v2",
        "client_id": chain["client_id"],
        "response_type": "vp_token",
        "response_mode": "direct_post.jwt",
        "response_uri": "https://%s:%d/response" % (HOST, PORT),
        "nonce": _NONCE,
        "state": b64u(hashlib.sha256(b"polaris-lab-state").digest()[:16]),
        "iat": now,
        "exp": now + 300,
        # Exactly the three keys the suite knows. Anything else is an unknown-parameter
        # warning, and the two names an older draft used are a HAIP failure.
        "client_metadata": {
            "jwks": {"keys": [enc_jwk]},
            "vp_formats_supported": {"dc+sd-jwt": {"sd-jwt_alg_values": ["ES256"],
                                                   "kb-jwt_alg_values": ["ES256"]}},
            "encrypted_response_enc_values_supported": ["A128GCM", "A256GCM"],
        },
        # One credential. The plan's happy flow refuses a query that asks for more.
        "dcql_query": {"credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:eudi:pid:1"]},
            "claims": [{"path": ["family_name"]}, {"path": ["given_name"]}],
        }]},
    }
    header = {"alg": "ES256", "typ": "oauth-authz-req+jwt",
              "x5c": [base64.b64encode(chain["leaf_der"]).decode()]}
    signing_input = (b64u(json.dumps(header, separators=(",", ":")).encode()) + "." +
                     b64u(json.dumps(claims, separators=(",", ":")).encode()))
    der_sig = chain["leaf_key"].sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der_sig)
    return signing_input + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


# -------------------------------------------------------------------- the two endpoints

class Endpoints(http.server.BaseHTTPRequestHandler):
    """Serves the request object, and accepts the wallet's POST without reading it."""
    workdir = pathlib.Path(".")

    def do_GET(self):
        body = (self.workdir / "request.jwt").read_bytes()
        self._respond(body, "application/oauth-authz-req+jwt")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        # Written, not opened. See the module docstring.
        (self.workdir / "wallet_response.txt").write_bytes(raw)
        sys.stderr.write("  <- wallet POSTed %d bytes to response_uri (not opened)\n" % len(raw))
        # HAIP-5.1: the direct_post response body must carry a redirect_uri, and the suite
        # checks that it carries ONLY that.
        body = json.dumps({"redirect_uri": "https://%s:%d/done" % (HOST, PORT)}).encode()
        self._respond(body, "application/json")

    def _respond(self, body, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002  the base class names it this
        pass


def serve(workdir: pathlib.Path):
    Endpoints.workdir = workdir
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(workdir / "tls_cert.pem"), str(workdir / "tls_key.pem"))
    httpd = http.server.HTTPServer(("0.0.0.0", PORT), Endpoints)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


# ----------------------------------------------------------------------- the suite's API

def api(base, path, method="GET", body=None, timeout=60):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        raise SystemExit("%s %s -> %d %s" % (method, path, e.code, e.read()[:300]))
    return json.loads(raw) if raw else None


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--suite", default="https://localhost:8443",
                    help="a LOCAL conformance suite (default: %(default)s)")
    ap.add_argument("--test", default="oid4vp-1final-verifier-happy-flow")
    ap.add_argument("--workdir", default=None)
    args = ap.parse_args()

    workdir = pathlib.Path(args.workdir or ("/tmp/polaris-interop-probe-%d" % os_pid()))
    workdir.mkdir(parents=True, exist_ok=True)

    chain = build_chain(workdir)
    (workdir / "request.jwt").write_text(build_request_object(chain, workdir))
    httpd = serve(workdir)
    print("probe endpoints on https://%s:%d (request_uri and response_uri)" % (HOST, PORT))

    credential_jwk = credential_signing_jwk()
    config = {
        "alias": ALIAS,
        "description": "lab/interop probe: what the HAIP verifier plan demands",
        "client": {"client_id": chain["client_id"],
                   "request_object_trust_anchor_pem": chain["ca_pem"]},
        "credential": {"signing_jwk": credential_jwk},
    }
    # The capture manifest. A JWE on its own is bytes; these four values are what turn it
    # into something a verifier can be held to.
    (workdir / "capture.json").write_text(json.dumps({
        "client_id": chain["client_id"],
        "nonce": _NONCE,
        "issuer_jwk": {k: v for k, v in credential_jwk.items() if k != "d"},
        "note": "produced by the OpenID Foundation conformance suite's fake wallet",
    }, indent=2))
    variant = urllib.parse.quote(json.dumps({"credential_format": "sd_jwt_vc",
                                             "response_mode": "direct_post.jwt"}))
    plan = api(args.suite, "/api/plan?planName=oid4vp-1final-verifier-haip-test-plan"
                           "&variant=" + variant, "POST", config) or {}
    plan_id = plan.get("_id") or plan.get("id")
    run = api(args.suite, "/api/runner?test=%s&plan=%s" % (args.test, plan_id), "POST") or {}
    test_id = run["id"]
    print("plan %s, test %s" % (plan_id, test_id))

    authorize = "%s/test/a/%s/authorize?%s" % (args.suite, ALIAS, urllib.parse.urlencode({
        "client_id": chain["client_id"],
        "request_uri": "https://%s:%d/request.jwt" % (HOST, PORT),
    }))
    # The endpoint answers 3xx to a URL only the suite's containers can resolve. Following
    # it is not part of the measurement and dies on DNS, so the redirect is NOT followed.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), NoRedirect)
    try:
        code = opener.open(authorize, timeout=90).status
    except urllib.error.HTTPError as e:
        code = e.code
    print("  authorization endpoint answered %s" % code)

    entries = api(args.suite, "/api/log/" + test_id) or []
    entries = entries if isinstance(entries, list) else entries.get("data", [])
    tally = {}
    for e in entries:
        tally[e.get("result") or "(info)"] = tally.get(e.get("result") or "(info)", 0) + 1
    print("\nverdicts: " + ", ".join("%s %d" % (k, v) for k, v in sorted(tally.items())))
    for e in entries:
        if (e.get("result") or "") in ("FAILURE", "WARNING"):
            print("  ! %-8s %s" % (e["result"], str(e.get("msg", ""))[:120]))

    httpd.shutdown()
    bad = tally.get("FAILURE", 0)
    if bad:
        print("\n== %d condition(s) the suite refuses. Each one is a requirement, named. ==" % bad)
        return 1
    print("\n== every automated condition green. The REVIEW item is a screenshot of a "
          "verifier VERIFYING, which this probe cannot produce and must not fake. ==")
    return 0


def os_pid():
    import os
    return os.getpid()


if __name__ == "__main__":
    sys.exit(main())
