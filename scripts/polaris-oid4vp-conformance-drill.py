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
import json
import secrets
import os
import pathlib
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packages" / "polaris-oid4vp"))

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from polaris_oid4vp.cli import FILES, keygen  # noqa: E402
from polaris_oid4vp.jwe import b64u_encode  # noqa: E402
from polaris_oid4vp.serve import serve  # noqa: E402
from polaris_oid4vp.verifier import Verifier  # noqa: E402

#: What the SUITE is told to fetch. Against the local suite in Docker that is
#: host.docker.internal; against the hosted one it has to be a public HTTPS name, which
#: is what POLARIS_PUBLIC_ORIGIN is for. The verifier still listens on PORT locally; the
#: origin only changes the URLs it puts in the request object.
HOST = "host.docker.internal"
PORT = 9443
PUBLIC_ORIGIN = os.environ.get("POLARIS_PUBLIC_ORIGIN", "")
#: The alias is the path segment the wallet is launched at, and the suite treats a
#: SECOND test started under an alias as a reason to interrupt the FIRST. One fixed
#: alias across eleven modules therefore had each test kill its predecessor: the seven
#: negative ones survived because a 4xx finishes them immediately, while all four
#: positive ones reached REVIEW, waited for a screenshot that never came, and were
#: INTERRUPTED the moment the next module started. The suite said so in as many words:
#: "Stopping test due to alias conflict ... you will need to rerun this test and ensure
#: you complete all steps in this test before you move onto the next test."
#: A unique alias per test is the fix the suite itself recommends.
ALIAS_BASE = "polaris-verifier"
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


#: Bearer token for a HOSTED suite. The local suite runs in dev mode and authenticates
#: nobody, which is why this drill needed no credential to reach eleven modules. The
#: Foundation's hosted service at certification.openid.net does authenticate, and its
#: token comes from a page you can only see after signing in with Google or GitLab. So
#: the token is read from the environment and never from this repository.
CONFORMANCE_TOKEN = os.environ.get("CONFORMANCE_TOKEN", "")


def api(base, path, method="GET", body=None, timeout=90):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    if CONFORMANCE_TOKEN:
        req.add_header("Authorization", "Bearer " + CONFORMANCE_TOKEN)
    try:
        with urllib.request.urlopen(req, context=_CTX, timeout=timeout) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        raise SystemExit("%s %s -> %d %s" % (method, path, e.code, e.read()[:300]))
    return json.loads(raw) if raw else None


def build_pki(workdir):
    """The certificates the profile requires, from the PACKAGE rather than from here.

    This function used to carry its own copy of the CA-and-leaf construction. Two copies of
    a rule the conformance suite enforces is two places for it to drift, and the copy inside
    the drill is the one that would stay right while the shipped one rotted: the drill is
    what gets run against the suite. `polaris-oid4vp keygen` is now the single source, and
    this reads what it wrote.
    """
    keygen(workdir, HOST)
    return {
        "ca_pem": (workdir / FILES["anchor"]).read_text(),
        "leaf_pem": (workdir / FILES["client_cert"]).read_bytes(),
        "leaf_key_pem": (workdir / FILES["client_key"]).read_bytes(),
    }


def credential_signing_jwk():
    key = ec.generate_private_key(ec.SECP256R1())
    priv = key.private_numbers()
    pub = priv.public_numbers
    return {"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "suite-issuer",
            "d": b64u_encode(priv.private_value.to_bytes(32, "big")),
            "x": b64u_encode(pub.x.to_bytes(32, "big")),
            "y": b64u_encode(pub.y.to_bytes(32, "big"))}


def create_plan(suite, config):
    """One plan on the suite; returns its id."""
    variant = urllib.parse.quote(json.dumps({"credential_format": "sd_jwt_vc",
                                             "response_mode": "direct_post.jwt"}))
    plan = api(suite, "/api/plan?planName=%s&variant=%s" % (PLAN, variant), "POST", config)
    return (plan or {}).get("_id") or (plan or {}).get("id")


def run_module(suite, verifier, config, module, plan_id=None):
    """Create the test, drive it, and return (result, tally, failures).

    With `plan_id`, the module runs inside that existing plan under the plan's own alias,
    which is what a certification package needs: every module in ONE plan. Without it, each
    module gets a fresh plan and a unique alias, so no module can interrupt another."""
    if plan_id is None:
        alias = "%s-%s" % (ALIAS_BASE, secrets.token_hex(4))
        config = dict(config, alias=alias)
        plan_id = create_plan(suite, config)
    else:
        alias = config["alias"]
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
        opener.open("%s/test/a/%s/authorize?%s" % (suite, alias, params), timeout=120).read()
    except urllib.error.HTTPError:
        pass

    # B3 of the externalization contract: a hosted run has to be pointable at. Print
    # the identifiers the Foundation's service generated, so the result can be checked
    # by somebody who does not have this terminal.
    print("      plan %s  test %s  %s/log-detail.html?log=%s"
          % (plan_id, test_id, suite, test_id))

    # The suite writes a module's terminal entry (FINISHED, or the REVIEW placeholder a
    # positive module waits on) a moment AFTER the verifier answers. Read at once, the log
    # can end short of it and a clean happy-flow scores as "the flow did not complete":
    # measured 2026-09-23 against the local suite. So wait briefly for a terminal entry.
    import time
    for _ in range(10):
        entries = api(suite, "/api/log/" + test_id) or []
        entries = entries if isinstance(entries, list) else entries.get("data", [])
        results = {e.get("result") for e in entries}
        if results & {"REVIEW", "FINISHED", "FAILURE"}:
            break
        time.sleep(2)
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


def wait_finished(suite, test_id, needs_screenshot, timeout=900):
    """Certification mode: a module must be FINISHED before the next starts, or the next
    one's start interrupts it under the shared alias. A positive module waits for a human
    to upload the screenshot the suite asks for (OID4VP-1FINAL-8.2); this asks for it and
    waits. Returns the final (status, result)."""
    import time
    asked = False
    deadline = time.time() + timeout
    while time.time() < deadline:
        info = api(suite, "/api/info/" + test_id) or {}
        status, result = info.get("status"), info.get("result")
        if status in ("FINISHED", "INTERRUPTED"):
            return status, result
        if needs_screenshot and not asked and status in ("WAITING", "RUNNING"):
            print("\n  >>> This module wants a screenshot of the ACCEPTED box printed above.\n"
                  "  >>> 1. Take the screenshot.  2. Open %s/log-detail.html?log=%s\n"
                  "  >>> 3. Upload it where the page asks.  4. Come back and press Enter."
                  % (suite, test_id), flush=True)
            try:
                input("  >>> Press Enter once it is uploaded... ")
            except EOFError:
                print("\n  >>> no terminal to wait on: run this from an interactive shell, "
                      "or upload the screenshot and re-run.", flush=True)
                return "WAITING", None
            asked = True
        time.sleep(3)
    return "TIMEOUT", None


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--suite", default="https://localhost:8443")
    ap.add_argument("--workdir", default="/tmp/polaris-oid4vp-drill")
    ap.add_argument("--only", default=None, help="run only these modules (comma-separated names)")
    ap.add_argument("--certification", action="store_true",
                    help="run every module inside ONE plan, one at a time, waiting for each to "
                         "finish (and for the screenshot on the four positive ones); no "
                         "negative controls, so the account holds only the plan to publish")
    args = ap.parse_args()

    workdir = pathlib.Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    pki = build_pki(workdir)
    issuer_jwk = credential_signing_jwk()

    verifier = Verifier(
        client_cert_pem=pki["leaf_pem"], client_key_pem=pki["leaf_key_pem"],
        request_uri=(PUBLIC_ORIGIN or "https://%s:%d" % (HOST, PORT)) + "/request.jwt",
        response_uri=(PUBLIC_ORIGIN or "https://%s:%d" % (HOST, PORT)) + "/response",
        issuer_jwks=[{k: v for k, v in issuer_jwk.items() if k != "d"}])
    # The four positive modules end by asking a human to "upload a screenshot showing
    # that the verifier successfully verified the presented credential (for example, a
    # page displaying the credential contents)" -- OID4VP-1FINAL-8.2. A verifier that
    # prints nothing gives the human nothing to photograph, so the verdict is displayed
    # here exactly as the shipped `polaris-oid4vp serve` displays it.
    def _show(status, body, verdict):
        if verdict and verdict.authentic:
            print("\n  ================ VERIFIER: PRESENTATION ACCEPTED ================")
            print("  <- %d authentic" % status)
            for name in sorted(verdict.claims):
                print("       %-14s %s" % (name, verdict.claims[name]))
            print("  ================================================================\n",
                  flush=True)
        elif verdict:
            print("  <- %d refused: %s: %s" % (status, verdict.code, verdict.reason),
                  flush=True)

    httpd = serve(verifier, port=PORT, certfile=str(workdir / FILES["tls_cert"]),
                  keyfile=str(workdir / FILES["tls_key"]), on_verdict=_show)
    print("verifier listening on https://%s:%d, client_id %s...\n"
          % (HOST, PORT, verifier.client_id[:26]))

    config = {
        "alias": ALIAS_BASE,   # replaced per test in run_module; see ALIAS_BASE
        "description": "polaris-oid4vp against the HAIP verifier plan",
        "client": {"client_id": verifier.client_id,
                   "request_object_trust_anchor_pem": pki["ca_pem"]},
        "credential": {"signing_jwk": issuer_jwk},
    }

    wanted = None if args.only is None else set(args.only.split(","))
    modules = [m for m in MODULES if wanted is None or m[0] in wanted]
    if args.certification:
        config = dict(config, alias="%s-cert-%s" % (ALIAS_BASE, secrets.token_hex(4)))
        plan_id = create_plan(args.suite, config)
        print("  certification plan %s  %s/plan-detail.html?plan=%s\n"
              % (plan_id, args.suite, plan_id), flush=True)
        final = []
        for module, needs_screenshot in modules:
            test_id, tally, failures = run_module(args.suite, verifier, config, module, plan_id)
            status, result = wait_finished(args.suite, test_id, needs_screenshot)
            final.append((module, status, result))
            print("  %-32s %s / %s" % (module.replace("oid4vp-1final-verifier-", ""),
                                       status, result), flush=True)
            for line in failures[:3]:
                print("      %s" % line)
        bad = [m for m, st, r in final if st != "FINISHED" or r in ("FAILED", "FAILURE", None)]
        print("\n  plan %s  %s/plan-detail.html?plan=%s" % (plan_id, args.suite, plan_id))
        print("  == %d of %d modules FINISHED without failure%s ==" % (
            len(final) - len(bad), len(final),
            "" if not bad else "; NOT READY: " + ", ".join(bad)))
        print("  Publish for certification ONLY if every module above is FINISHED and PASSED or "
              "REVIEW. Publishing cannot be undone.")
        _stop(httpd)
        return 0 if not bad else 1
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
