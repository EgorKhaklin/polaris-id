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

TWO NEGATIVE CONTROLS, one per direction, because the two halves of this plan fail in
opposite ways and a control for one says nothing about the other.

A verifier that always answers **400** must break the four positive modules. A verifier that
always answers **200** must break all seven negative ones, and that is the control that
matters: the negative modules pass on a 4xx and nothing else, so seven green modules and a
suite that had quietly stopped sending anything look exactly alike without it. The run is VOID
if either control goes unnoticed, and says which.
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
    # The product's own parameters, not a hand-rolled copy. The drill building its own set
    # is how it drifts from what a caller would actually send, and it did: without
    # request_uri_method=post the request-uri-method-post module SKIPS itself, and a skipped
    # module reported as clean is the same lie as a vacuous pass.
    params = urllib.parse.urlencode(verifier.authorization_request_params(session))
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


def outcome(tally, needs_screenshot):
    """What the SUITE concluded, not what this drill infers from an absence.

    The first version of this drill reported PASS whenever the log held no FAILURE entry.
    That is a proxy, and on the seven negative modules it is the wrong one: a verifier that
    ACCEPTS a forged presentation produces no FAILURE either. The suite marks the difference
    in its terminal entry, measured against a verifier patched to answer 200 to everything:

        negative module, verifier answered 4xx   FINISHED   the automatic pass
        negative module, verifier answered 200   REVIEW     waiting for a human screenshot
                                                            of the verifier's error, which
                                                            is NOT a pass
        positive module, verifier answered 200   REVIEW     waiting for a screenshot of the
                                                            successful verification
        positive module, verifier answered 4xx   FAILURE    conditions recorded against it

    So the signal is FINISHED versus REVIEW, and counting failures cannot see it.
    """
    bad = tally.get("FAILURE", 0)
    if bad:
        return "FAILURE x%d" % bad, False
    if needs_screenshot:
        return ("REVIEW (screenshot)", True) if tally.get("REVIEW") else \
            ("no REVIEW placeholder: the flow did not complete", False)
    if tally.get("FINISHED"):
        return "PASS (automatic)", True
    if tally.get("REVIEW"):
        return "REVIEW: the verifier did NOT refuse it", False
    return "no terminal entry", False


def _stop(httpd):
    httpd.shutdown()
    httpd.server_close()


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
    rows, not_clean = [], []
    for module, needs_screenshot in modules:
        _, tally, failures = run_module(args.suite, verifier, config, module)
        verdict, clean = outcome(tally, needs_screenshot)
        if not clean:
            not_clean.append(module)
        rows.append((module, needs_screenshot, tally, failures))
        short = module.replace("oid4vp-1final-verifier-", "")
        print("  %-32s %-38s %s" % (short, verdict,
                                    "warn %d" % tally.get("WARNING", 0)
                                    if tally.get("WARNING") else ""))
        for line in failures[:3]:
            print("      %s" % line)

    # The negative control. Without it, a suite that stopped sending anything and a verifier
    # that refuses everything both print seven green modules.
    # TWO controls, one per direction, because the two halves of this plan fail in opposite
    # ways and a control for one says nothing about the other.
    print("\n  negative controls")
    original = verifier.handle_direct_post
    controls = []

    # 1. Always 400. If the suite does not notice, the four POSITIVE modules above are
    #    reporting on a harness rather than on a verifier.
    verifier.handle_direct_post = lambda form: (400, {"error": "invalid_request",
                                                      "error_description": "control"}, None)
    try:
        _, tally, _ = run_module(args.suite, verifier, config, "oid4vp-1final-verifier-happy-flow")
    finally:
        verifier.handle_direct_post = original
    controls.append(("always 400, against happy-flow", tally.get("FAILURE", 0)))

    # 2. Always 200, which is the control that matters. The seven negative modules PASS on a
    #    4xx and nothing else, so a verifier that accepts every forgery must FAIL every one
    #    of them. Without this leg, seven green modules and a suite that had stopped sending
    #    anything look exactly alike, and the seven are the automatically scored half: they
    #    are the claim. The first version of this drill controlled only direction 1, which
    #    is to say it validated the half that needs a human anyway.
    verifier.handle_direct_post = lambda form: (200, {"redirect_uri": verifier.redirect_uri},
                                               None)
    accepted_everything = []
    try:
        for module, needs_screenshot in MODULES:
            if needs_screenshot:
                continue
            _, tally, _ = run_module(args.suite, verifier, config, module)
            # Not "did it record a failure": it does not. "Did it withhold the automatic
            # pass", which is the thing the seven negative modules actually grant.
            accepted_everything.append((module, 0 if tally.get("FINISHED") else 1))
    finally:
        verifier.handle_direct_post = original
    unnoticed = [m for m, noticed in accepted_everything if not noticed]
    controls.append(("always 200, against all %d negative modules" % len(accepted_everything),
                     len(accepted_everything) - len(unnoticed)))

    for label, noticed in controls:
        print("    %-46s %s" % (label, "NOTICED (%d)" % noticed if noticed
                                else "reported nothing"))
    for module in unnoticed:
        print("      ! %s did not notice a verifier that accepts everything"
              % module.replace("oid4vp-1final-verifier-", ""))

    print()
    if not controls[0][1]:
        print("== VOID: the suite did not notice a verifier that refuses everything, so the "
              "positive modules above are a statement about this harness and not about the "
              "verifier ==", file=sys.stderr)
        _stop(httpd)
        return 3
    if unnoticed:
        print("== VOID: %d negative module(s) passed a verifier that accepts every forgery, "
              "so their PASS above says nothing about this verifier =="
              % len(unnoticed), file=sys.stderr)
        _stop(httpd)
        return 3
    if not_clean:
        print("== %d module(s) did not come out clean: %s =="
              % (len(not_clean), ", ".join(m.replace("oid4vp-1final-verifier-", "")
                                           for m in not_clean)), file=sys.stderr)
        _stop(httpd)
        return 1
    automatic = sum(1 for m, needs, _, _ in rows if not needs)
    print("== %d of %d modules clean. The %d negative ones are scored automatically on a 4xx; "
          "the rest end in REVIEW because the suite wants a screenshot of a verifier "
          "verifying, which this drill will not fake. NOT a certification and not published. =="
          % (len(rows), len(rows), automatic))
    _stop(httpd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
