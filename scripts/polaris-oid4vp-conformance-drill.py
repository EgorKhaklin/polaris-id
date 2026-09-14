#!/usr/bin/env python3
"""polaris-oid4vp-conformance-drill.py -- run the real verifier against the real suite.

Everything else in `packages/polaris-oid4vp` is checked against material this repository
produced. This runs the actual `polaris_oid4vp.Verifier` against the OpenID Foundation
conformance suite's `oid4vp-1final-verifier-haip-test-plan`, module by module, and reports
what the suite says.

**It needs a suite.** MIT, prebuilt images, no account:

    git clone --depth 1 https://gitlab.com/openid/conformance-suite.git
    cd conformance-suite && docker compose -f docker-compose-prebuilt.yml up -d
    python3 scripts/polaris-oid4vp-conformance-drill.py

It does NOT run in CI for that reason, which is the same shape as every other drill in this
directory that needs infrastructure a runner does not have.

WHAT PASSING MEANS, AND WHAT IT DOES NOT. The seven negative modules are scored
automatically: the suite's wallet sends a presentation broken in one specific way and the
module passes the moment the verifier answers 4xx. Those are real, machine-checked verdicts
from somebody else's code. The four positive modules end in REVIEW instead, because the suite
wants a screenshot of a verifier displaying a successful verification, and this drill cannot
produce one and will not pretend to. A run here is not a certification and is not published:
see `lab/EXTERNAL-NOUNS.md` for what would be.

THE NEGATIVE CONTROL. A suite that is not really exercising anything, and a verifier that
refuses everything, produce the same seven green modules. So the drill also runs the happy
flow against a verifier whose `handle_direct_post` has been replaced with one that always
answers 400, and REQUIRES the suite to notice: if the suite reports the happy flow as
unaffected, the run is void and says so.
"""
import argparse
import datetime
import json
import pathlib
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packages" / "polaris-oid4vp"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from polaris_oid4vp.jwe import b64u_encode  # noqa: E402
from polaris_oid4vp.serve import serve  # noqa: E402
from polaris_oid4vp.verifier import Verifier  # noqa: E402

HOST = "host.docker.internal"
PORT = 9443
ALIAS = "polaris-verifier"
PLAN = "oid4vp-1final-verifier-haip-test-plan"

#: The eleven modules that apply to sd_jwt_vc. The seven marked False are scored
#: automatically on a 4xx; the four marked True end in REVIEW and need a human screenshot.
MODULES = [
    ("oid4vp-1final-verifier-happy-flow", True),
    ("oid4vp-1final-verifier-minimal-cnf-jwk", True),
    ("oid4vp-1final-verifier-request-uri-method-post", True),
    ("oid4vp-1final-verifier-request-uri-fetched-twice", True),
    ("oid4vp-1final-verifier-invalid-kb-jwt-signature", False),
    ("oid4vp-1final-verifier-invalid-credential-signature", False),
    ("oid4vp-1final-verifier-invalid-sd-hash", False),
    ("oid4vp-1final-verifier-invalid-kb-jwt-nonce", False),
    ("oid4vp-1final-verifier-invalid-kb-jwt-aud", False),
    ("oid4vp-1final-verifier-kb-jwt-iat-in-past", False),
    ("oid4vp-1final-verifier-kb-jwt-iat-in-future", False),
]

_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def api(base, path, method="GET", body=None, timeout=90):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=_CTX, timeout=timeout) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        raise SystemExit("%s %s -> %d %s" % (method, path, e.code, e.read()[:300]))
    return json.loads(raw) if raw else None


def build_pki(workdir):
    """A CA, a leaf for the request object, and a self-signed TLS cert for the listener."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "polaris verifier CA")])
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
            .issuer_name(ca_name).public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
            .sign(ca_key, hashes.SHA256()))

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
    return {
        "ca_pem": ca.public_bytes(serialization.Encoding.PEM).decode(),
        "leaf_pem": leaf.public_bytes(serialization.Encoding.PEM),
        "leaf_key_pem": leaf_key.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()),
    }


def credential_signing_jwk():
    key = ec.generate_private_key(ec.SECP256R1())
    priv = key.private_numbers()
    pub = priv.public_numbers
    return {"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "suite-issuer",
            "d": b64u_encode(priv.private_value.to_bytes(32, "big")),
            "x": b64u_encode(pub.x.to_bytes(32, "big")),
            "y": b64u_encode(pub.y.to_bytes(32, "big"))}


def run_module(suite, verifier, config, module):
    """Create the test, drive it, and return (result, tally, failures)."""
    variant = urllib.parse.quote(json.dumps({"credential_format": "sd_jwt_vc",
                                             "response_mode": "direct_post.jwt"}))
    plan = api(suite, "/api/plan?planName=%s&variant=%s" % (PLAN, variant), "POST", config)
    plan_id = (plan or {}).get("_id") or (plan or {}).get("id")
    run = api(suite, "/api/runner?test=%s&plan=%s" % (module, plan_id), "POST") or {}
    test_id = run["id"]

    session, _ = verifier.new_request()
    params = urllib.parse.urlencode({
        "client_id": verifier.client_id,
        "request_uri": "%s?state=%s" % (verifier.request_uri, session.state),
    })
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_CTX),
                                         _NoRedirect)
    try:
        opener.open("%s/test/a/%s/authorize?%s" % (suite, ALIAS, params), timeout=120).read()
    except urllib.error.HTTPError:
        pass

    entries = api(suite, "/api/log/" + test_id) or []
    entries = entries if isinstance(entries, list) else entries.get("data", [])
    tally, failures = {}, []
    for entry in entries:
        result = entry.get("result") or "(info)"
        tally[result] = tally.get(result, 0) + 1
        if result in ("FAILURE", "WARNING"):
            failures.append("%s %s" % (result, str(entry.get("msg", ""))[:100]))
    return test_id, tally, failures


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--suite", default="https://localhost:8443")
    ap.add_argument("--workdir", default="/tmp/polaris-oid4vp-drill")
    ap.add_argument("--only", default=None, help="run one module by name")
    args = ap.parse_args()

    workdir = pathlib.Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    pki = build_pki(workdir)
    issuer_jwk = credential_signing_jwk()

    verifier = Verifier(
        client_cert_pem=pki["leaf_pem"], client_key_pem=pki["leaf_key_pem"],
        request_uri="https://%s:%d/request.jwt" % (HOST, PORT),
        response_uri="https://%s:%d/response" % (HOST, PORT),
        issuer_jwks=[{k: v for k, v in issuer_jwk.items() if k != "d"}])
    httpd = serve(verifier, port=PORT, certfile=str(workdir / "tls_cert.pem"),
                  keyfile=str(workdir / "tls_key.pem"))
    print("verifier listening on https://%s:%d, client_id %s...\n"
          % (HOST, PORT, verifier.client_id[:26]))

    config = {
        "alias": ALIAS,
        "description": "polaris-oid4vp against the HAIP verifier plan",
        "client": {"client_id": verifier.client_id,
                   "request_object_trust_anchor_pem": pki["ca_pem"]},
        "credential": {"signing_jwk": issuer_jwk},
    }

    modules = [m for m in MODULES if args.only in (None, m[0])]
    rows, hard_failures = [], 0
    for module, needs_screenshot in modules:
        _, tally, failures = run_module(args.suite, verifier, config, module)
        bad = tally.get("FAILURE", 0)
        hard_failures += bad
        rows.append((module, needs_screenshot, tally, failures))
        short = module.replace("oid4vp-1final-verifier-", "")
        verdict = "FAILURE x%d" % bad if bad else (
            "REVIEW (screenshot)" if needs_screenshot else "PASS")
        print("  %-32s %-22s %s" % (short, verdict,
                                    "warn %d" % tally.get("WARNING", 0)
                                    if tally.get("WARNING") else ""))
        for line in failures[:3]:
            print("      %s" % line)

    # The negative control. Without it, a suite that stopped sending anything and a verifier
    # that refuses everything both print seven green modules.
    print("\n  negative control: a verifier that always answers 400")
    original = verifier.handle_direct_post
    verifier.handle_direct_post = lambda form: (400, {"error": "invalid_request",
                                                      "error_description": "control"}, None)
    try:
        _, tally, failures = run_module(args.suite, verifier, config, MODULES[0][0])
    finally:
        verifier.handle_direct_post = original
    control_noticed = bool(tally.get("FAILURE"))
    print("    happy flow under the control: %s"
          % ("NOTICED (%d failures)" % tally["FAILURE"] if control_noticed
             else "reported no failure"))

    print()
    if not control_noticed:
        print("== VOID: the suite did not notice a verifier that refuses everything, so the "
              "passes above are a statement about this harness and not about the verifier ==",
              file=sys.stderr)
        httpd.shutdown()
        return 3
    if hard_failures:
        print("== %d condition(s) the suite refuses. Each one is a requirement, named. =="
              % hard_failures, file=sys.stderr)
        httpd.shutdown()
        return 1
    automatic = sum(1 for m, needs, _, _ in rows if not needs)
    print("== %d of %d modules clean. The %d negative ones are scored automatically on a 4xx; "
          "the rest end in REVIEW because the suite wants a screenshot of a verifier "
          "verifying, which this drill will not fake. NOT a certification and not published. =="
          % (len(rows), len(rows), automatic))
    httpd.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
