#!/usr/bin/env python3
"""polaris-app-mutation-drill.py -- is each refusal the application makes tested?

CHECK constraints are mutation-tested (v9.407), triggers are (v9.413), the ZK witnesses are
(v9.419), the conformance contract is (v9.429), the stored procedures are (v9.437) and both
SDKs are (v9.458). The Flask application is the member of that family nobody had measured,
and it is not a small one: three of the ten constraints are enforced THERE and nowhere else.
C4 is one `UPDATE ... RETURNING`; C6's server-side coercion of the disclosure level is a form
handler; C8's caps are route-level clamps that the SQL merely receives. On 2026-09-17 eleven
defects were found on the authentication surface by hand, which is evidence about how the
surface was being checked, not only about the surface.

METHOD. Every `if` whose body answers with a 4xx is one refusal. The drill replaces exactly
that condition with `False`, leaving the body, the route and every other statement intact, so
the route carries on and serves the request it should have refused. Then it runs the tests.

  survivor = a refusal that can be switched off with every test still green

Replacing the CONDITION rather than deleting the branch is the narrower mutation, and the
honest one: deleting the branch would change the function's shape and could fail a test for
reasons that have nothing to do with the refusal.

WHAT A SURVIVOR DOES AND DOES NOT MEAN. It means no test in the suites below notices that the
refusal stopped happening. Some refusals are genuinely not security decisions: a 404 for a
resource that does not exist is a courtesy, and a route that would fail two lines later
anyway is covered by whatever notices that. Those belong in DECLARED below WITH THE REASON,
not in a filtered-out category, because the count of things nobody looked at is the number
this drill exists to keep at zero.

SCOPE. Every non-test module of `polaris_web/`, not app.py alone. app.py is being decomposed
into route modules, and a drill that names one file mutates that file and calls it the
application: after four modules moved out on 2026-09-18 this would have examined the refusals
of the 66 routes still in app.py and reported on 123. It would not have failed. It would have
narrowed, which is worse, because a passing drill is read as coverage.

RESTORATION. The modules are rewritten in place, one condition at a time, and each module's
original bytes are held in memory and written back after every case. A long run can be killed
outright, and no handler catches that, so the drill prints the one-line repair BEFORE it
touches anything: `git checkout -- polaris_web` restores them, and the drill refuses to start
if any of those modules already has uncommitted changes, because then the repair line would
throw away work rather than a mutation.

TWO CONTROLS, AND THE POSITIVE ONE IS THE LOAD-BEARING HALF.

  POSITIVE: the control's tests are run with NOTHING mutated and must be GREEN.
  NEGATIVE: the control's refusal is then switched off and they must go RED.

The first draft of this drill had only the negative one and reported a perfect result in one
second. The suites were red before it started, for want of the database environment, so every
mutation was "detected" by a suite that was failing for a reason that had nothing to do with
it. A red suite detects every mutation and measures none of them. This is the same shape as
the three tools that reported results they had not established (v9.374 to v9.394) and as the
detection-control rule the check layer enforces on itself: assert the good fixture PASSES
before asserting the broken one fails.

ENVIRONMENT. The suites need PostgreSQL, Redis and the schema-owner role, exactly as
`scripts/polaris-test.sh` sets them up. The simplest correct invocation is to let that script
export them:

  POLARIS_DB_HOST=localhost POLARIS_DB_NAME=polaris_test \\
  POLARIS_DB_USER="$(whoami)" POLARIS_SECRET_KEY=drill \\
  POLARIS_PQC_PROFILE=placeholder POLARIS_STATE_DIR=/tmp/polaris-state \\
  POLARIS_TEST_RELOAD_VIA=direct POLARIS_TEST_RELOAD_USER="$(whoami)" \\
  POLARIS_TEST_REDIS_URL=redis://localhost:6399/0 \\
  python3 scripts/polaris-app-mutation-drill.py

The positive control turns a missing variable into a refusal to run, with the remedy printed,
rather than into a clean result.

SCOPE. By default this examines the refusals that answer "you may not": 401, 403, 409, 413
and 429. Those are clean, which is what lets the drill gate a ship. The 400 and 404 surface
is MEASURED AND OPEN, at 35 survivors of 76 as of 2026-09-17, and `--all` runs it; the note
on DEFAULT_STATUSES below says what those 35 do and do not mean, and every run prints how
many refusals it did not examine so the open surface cannot go quiet.

  python3 scripts/polaris-app-mutation-drill.py                 # the default scope
  python3 scripts/polaris-app-mutation-drill.py --all           # including 400/404: OPEN
  python3 scripts/polaris-app-mutation-drill.py --limit 12      # a sample, for a quick look
  python3 scripts/polaris-app-mutation-drill.py --status 401 403 # only these answers
  python3 scripts/polaris-app-mutation-drill.py --exhaustive    # whole suite per mutation
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
WEB = ROOT / "polaris_web"


def modules():
    """Every non-test module of the application, in a stable order.

    Was `polaris_web/app.py` alone. app.py is being decomposed into route modules, and a drill
    that names a file mutates that file and calls it the application: after four modules moved
    out on 2026-09-18 this would have examined the refusals of 66 routes and reported on 123.
    It would not have failed. It would have narrowed, which is worse, because a passing drill
    is read as coverage."""
    return [f for f in sorted(WEB.glob("*.py")) if not f.name.startswith("test_")]

#: Suites searched for the tests that exercise a given route.
SUITE_FILES = ("test_app.py",)

#: The default scope: the statuses that answer "you may not", as opposed to "that request is
#: malformed" or "there is no such thing". Every one of these is clean, which is what lets
#: this drill gate a ship.
#:
#: THE 400 AND 404 SURFACE IS MEASURED AND OPEN, and saying so is the point of this comment.
#: Run with --all: 76 refusals, 35 survivors as of 2026-09-17. They are not 35 defects. Most
#: are input-validation guards with another guard behind them, so switching one off does not
#: make the route accept the input; `JsonRouteTotalityTests` asserts the property that
#: actually matters there, which is that no shape reaches a raise, and it found a real defect
#: doing so (a JSON body that is not an object, fixed in 636e4ef). What is NOT established is
#: which of those 35 refuse for their own reason and which are masked by a neighbour, and
#: declaring them one way or the other without measuring it is the mistake this whole drill
#: exists to catch. The honest state is: measured, open, and written down here.
DEFAULT_STATUSES = (401, 403, 409, 413, 429)

#: The refusal mutated as the negative control: (route, a substring of its condition). It
#: must turn the suite red. This one is the zero-knowledge step-up on the authorization
#: endpoint, refused with `insufficient_assurance`, and
#: `AuthBrokerTests.test_registered_policy_binds_the_holder_request` asserts that exact
#: status and error. Its route names two test classes rather than thirty, which matters for a
#: control that runs twice on every invocation.
#:
#: Naming the CONDITION and not just the route is the second lesson from this drill's first
#: run. Pointed at a route alone it took that route's first `if` refusal, which happened to
#: be `if signed_by is None: return 401` -- a defence-in-depth assertion behind
#: `login_required` that cannot fire in a test, so the negative control correctly reported
#: the harness as broken when the harness was fine and the control was badly chosen.
CONTROL = ("/api/v1/auth/authorize", "not ok")

#: Refusals nothing notices, each with the reason it is acceptable. A survivor with no entry
#: here is the finding; an entry whose refusal is now covered is reported as stale, because a
#: declared-survivor list that is never re-read becomes a list of excuses.
#:
#: Keyed by (view function, a distinctive substring of the CONDITION). Not the line number:
#: the first version used one and every unrelated edit to app.py shifted every key below it,
#: so the whole list went stale at once and the drill failed a ship for no reason. The
#: condition text is stable against edits elsewhere and still specific to one refusal, and it
#: goes stale exactly when it should: when the refusal it names is rewritten.
DECLARED: dict[tuple[str, str], str] = {
    # `session['user_id']` is set by `login_required`, which every one of these routes is
    # behind. The refusal is a defence-in-depth assertion against a session shape that the
    # decorator makes impossible, so no test can construct the state that fires it. Covering
    # it would mean building a session the application cannot produce.
    ("api_federation_attest", "signed_by is None"): "unreachable behind login_required: session['user_id']",
    ("api_federation_revoke", "signed_by is None"): "unreachable behind login_required: session['user_id']",
    ("api_zk_epoch_close", "signed_by is None"): "unreachable behind login_required: session['user_id']",

    # The exchange gateway and the signed-receipt mint. Every one of these IS tested, by
    # `scripts/polaris-federation-instances-drill.py`, which stands up two instances and
    # speaks to them over HTTP because a mediated exchange needs real ML-DSA, two databases
    # and an upstream. `ExchangeGatewayTests` says so in its own docstring. What the survivor
    # means here is narrower and still worth knowing: a developer running the SUITE gets no
    # signal from these, so the drill has to actually run.
    ("api_v1_exchange", "_EXCHANGE_WINDOW"): "stale envelope: federation-instances drill, 'a stale envelope "
                               "is refused (401): the freshness window'",
    ("api_v1_exchange", "not known"): "unknown requester: federation-instances drill, 'a requester "
                               "whose key B does not know is refused (401)'",
    ("api_v1_exchange", "not ok"): "bad envelope signature: federation-instances drill, 'a tampered "
                               "envelope signature is refused (401)'",
    ("api_v1_exchange", "_exchange_attestation"): "not attested in context: federation-instances drill, 'a THIRD "
                               "authority's attestation of X does not authorize X at B (403)'",
    ("api_v1_exchange", "_consume_exchange_nonce"): "nonce replay: federation-instances drill, 'the SAME envelope "
                               "replayed is refused (409): the nonce was consumed'",
    # 2026-09-24, the 400 surface: switched off, the body-binding check is caught by the
    # federation-instances drill (measured: it goes red), which unit tests cannot drive.
    ("api_v1_exchange", "_canonical_body_hash"): "body not bound to the signed envelope: federation-instances "
                               "drill, 'the receipt ... binds BOTH bodies' (measured 2026-09-24)",
    # Masked by the register itself: HolderKeyEvent's CHECKs (chk_holder_key_event, _hex,
    # _algorithm) refuse each value, and the route answers that refusal 400 through
    # db_error_to_message. The route check gives the better message; the table is the boundary.
    # With both removed, HolderKeyBindingTests.test_only_an_accepted_parameter_set_is_registered
    # fails (measured 2026-09-24: an Ed25519 binding was issuer-signed).
    ("api_v1_holder_key_bind", "event not in"): "masked by chk_holder_key_event, answered 400",
    # 1.0.0-rc.43: a bound operator's hidden credential is refused before the write. On these two
    # the write itself runs as the application role, so the token policy already scopes the
    # UPDATE and the DELETE to nothing; measured one route at a time on rc.42, neither changed
    # authority 3's token. Kept because that is an accident of which role writes (rc.40 moved
    # uc5's write to the owner and its twin gate opened). uc5 and uc6's twins ARE caught.
    ("tokens_transition", "session.get('operator_agency_id') is not None"):
        "masked by the token policy on the write (measured rc.42); defence in depth",
    ("tokens_delete", "session.get('operator_agency_id') is not None"):
        "masked by the token policy on the write (measured rc.42); defence in depth",
    ("api_v1_holder_key_bind", "re.fullmatch"): "masked by chk_holder_key_hex, answered 400",
    ("api_v1_holder_key_bind", "holder_alg not in"): "masked by chk_holder_key_algorithm (2026-09-24), answered 400",
    ("api_v1_exchange_receipt_signed", "_EXCHANGE_MINT_WINDOW"): "stale mint time: federation-instances drill, "
                                              "'a STALE signed time (30 min) rejects (401)'",
    ("api_v1_exchange_receipt_signed", "not ok"): "bad mint signature: federation-instances drill, "
                                              "'an UNATTESTED requester is not authorized: 403 "
                                              "even under a valid responder signature'",

    # The coarse velocity bounds: 120 to 600 requests per minute, per authority or per
    # requester key. Driving one in a unit test means issuing hundreds of real timestamps or
    # receipts to prove a limiter exists, which costs more than it measures.
    #
    # They are pinned instead by `check_rate_limits_are_enforced`, and it catches THIS
    # mutation specifically: the check requires each limiter to sit inside a negated guard
    # that answers 429, and switching the condition to `False` removes the
    # `rate_limiter.allow` call from the source, so the check fails the build. That is a
    # structural pin, and it proves the guard is written rather than that it fires. The five
    # holder-facing limiters, whose bounds are 5 and 10, ARE driven past them by
    # `F03_RateLimitingTests`; these six are not, and the difference is the point.
    ("api_v1_verify", "rpverify:"): "rpverify: bound is the relying party's own rate_limit_per_min; "
                             "pinned by check_rate_limits_are_enforced",
    ("api_v1_exchange_receipt_signed", "exmint:"): "exmint: 120/min; pinned by "
                                              "check_rate_limits_are_enforced",
    ("api_v1_timestamp", "tsa:"): "tsa: 600/min; pinned by check_rate_limits_are_enforced",
    ("api_v1_exchange", "exch:"): "exch: 120/min; pinned by check_rate_limits_are_enforced",
    ("api_v1_sign_holder", "sign:"): "sign: 10/min, but reaching it needs a federated agency and "
                                  "a real presentation; pinned by check_rate_limits_are_enforced",
    ("api_v1_auth_authorize", "auth:"): "auth: 10/min, but reaching it needs a registered relying "
                                     "party and a credential; pinned by "
                                     "check_rate_limits_are_enforced",

    # Dead code behind a stronger layer. The schema carries `epoch_committed_count_cap`, a
    # CHECK refusing `committed_count > 10000`, so the database will not store an epoch this
    # route could answer 413 for. Writing the test found this rather than the other way
    # round. `EpochRevocationTests.test_the_leaves_route_is_bounded_by_the_schema_before_the
    # _application` pins the two numbers to each other, which is the condition that keeps
    # this entry true: raise the schema's cap alone and the 413 becomes reachable, untested,
    # and the only thing between a caller and an unbounded body.
    ("api_v1_epoch_leaves", "_EPOCH_LEAVES_MAX"): "unreachable: the schema's epoch_committed_count_cap "
                                   "refuses the row first, and a test pins the two caps equal",
}


def _status_of(node) -> int | None:
    """The HTTP status a single statement answers with, or None."""
    if isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple) \
            and len(node.value.elts) >= 2:
        last = node.value.elts[1]
        if isinstance(last, ast.Constant) and isinstance(last.value, int) \
                and 400 <= last.value < 600:
            return last.value
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        f = node.value.func
        if isinstance(f, ast.Name) and f.id == "abort" and node.value.args:
            a = node.value.args[0]
            if isinstance(a, ast.Constant) and isinstance(a.value, int):
                return a.value
    return None


def _route_of(fn, src) -> str | None:
    for d in fn.decorator_list:
        seg = ast.get_source_segment(src, d) or ""
        m = re.search(r"""route\(['"]([^'"]+)""", seg)
        if m:
            return m.group(1)
    return None


def refusals(src: str) -> list[dict]:
    """Every `if` in a route handler whose body answers with a 4xx or 5xx."""
    tree = ast.parse(src)
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef):
            continue
        route = _route_of(fn, src)
        if route is None:
            continue
        for node in ast.walk(fn):
            if not isinstance(node, ast.If):
                continue
            codes = [c for c in (_status_of(s) for s in node.body) if c]
            if not codes:
                continue
            t = node.test
            out.append({
                "view": fn.name, "route": route, "line": node.lineno, "status": codes[0],
                "span": (t.lineno, t.col_offset, t.end_lineno, t.end_col_offset),
                # The FULL condition, not a display-length slice: DECLARED matches against
                # this, and truncating first made a declared key silently stop matching the
                # refusal it named. Printing truncates; matching does not.
                "source": " ".join((ast.get_source_segment(src, t) or "").split()),
            })
    return out


def _concrete(route: str) -> str:
    """A rule with its parameters filled in, because a probe cannot POST to `<int:id>`."""
    return re.sub(r"<[^>]+>", "1", route)


def mutate(src: str, span) -> str:
    """The same source with one condition replaced by `False`, byte for byte elsewhere."""
    lo_line, lo_col, hi_line, hi_col = span
    lines = src.splitlines(keepends=True)
    head = lines[lo_line - 1][:lo_col]
    tail = lines[hi_line - 1][hi_col:]
    return "".join(lines[:lo_line - 1] + [head + "False" + tail] + lines[hi_line:])


def classes_exercising(route: str, view: str) -> list[str]:
    """[module.Class] for every test class whose body requests this route.

    The route must appear INSIDE a string literal, and a `<param>` segment matches whatever
    a test puts there (`%d`, an f-string hole, a literal id). Matching the bare view name
    instead, which the first draft also did, selected thirty classes for `/login` because
    half the suite mentions the word: the control then took four minutes and the drill was
    unusable before it had measured anything.
    """
    inner = re.sub(r"<[^>]+>", "[^'\"]*",
                   re.escape(route).replace(r"\<", "<").replace(r"\>", ">"))
    pat = re.compile(r"""['\"][^'\"]*""" + inner)
    out = []
    for fname in SUITE_FILES:
        path = ROOT / "polaris_web" / fname
        if not path.exists():
            continue
        module, current, hit = fname[:-3], None, False
        for line in path.read_text(errors="replace").splitlines():
            m = re.match(r"class (\w+)\(", line)
            if m:
                current, hit = m.group(1), False
            elif current and not hit and pat.search(line):
                out.append("%s.%s" % (module, current))
                hit = True
    return sorted(set(out))



# ---------------------------------------------------------------------------
# The probe: what does the ROUTE answer, with this refusal switched off?
# ---------------------------------------------------------------------------
# A survivor means no test noticed. It does not say what the route now does, and those are
# different facts. A refusal whose removal leaves the route answering exactly as before is
# redundant with something after it; a refusal whose removal makes the route ACCEPT input it
# used to turn away is a hole that nothing is watching. 2026-09-17: 35 refusals on the 400
# and 404 surface survived, and calling them all "masked by a neighbour" without measuring it
# would be the exact move this drill exists to catch somebody else making.
#
# So the probe asks the route directly, in a subprocess that imports the application fresh so
# it picks up the mutated source. Same bodies before and after; only the mutation differs.

PROBE_BODIES = [
    {},
    [],
    "a string, not an object",
    {"token_value": 1, "signature_hex": 1},
    {"token_value": "x", "signature_hex": "00"},
    {"event": 5, "holder_public_key_hex": 7, "holder_algorithm": []},
    {"digest_hex": "ab" * 32},
    {"client_id": "x", "nonce": "n" * 12, "code_challenge": "c" * 50, "context_id": 1},
    {"envelope": {}, "body": {}},
    {"id": "x", "rawId": "x"},
]

#: Seeded operator credentials, so a guarded route can be reached at all. A probe that is
#: bounced by `login_required` measures the decorator, not the refusal under test, and would
#: report every guarded refusal as "answers the same either way".
PROBE_LOGIN = ("admin", "Admin@123!")


def _probe_child(route: str) -> int:
    """Run inside the subprocess: print this route's answers as JSON."""
    sys.path.insert(0, str(ROOT / "polaris_web"))
    os.chdir(str(ROOT / "polaris_web"))
    import app as application

    application.app.config["TESTING"] = False   # a raise must become 500, not propagate
    client = application.app.test_client()
    client.post("/login", data={"username": PROBE_LOGIN[0], "password": PROBE_LOGIN[1]})
    page = client.get("/dashboard")
    # A probe that is not signed in measures `login_required`, not the refusal under test,
    # and its 302 to /login is BELOW 400, so the classifier reads it as the route ACCEPTING
    # input it used to turn away. That produced two false ACCEPTS on 2026-09-17, and the
    # cause is worth naming because it will recur: the test classes for the two WebAuthn
    # routes ENROL a credential for the seeded admin, so every probe after them lands on the
    # second factor instead of the dashboard. The three real ACCEPTS that run found were on
    # an unauthenticated route and were unaffected.
    #
    # Printing nothing is the honest answer: the case reports "unprobed", which is a third
    # thing from "masked" and from "a hole", and a probe that cannot tell those apart is
    # worse than none.
    if page.status_code != 200:
        print(json.dumps([]))
        return 0
    m = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', page.data or b"")
    csrf = m.group(1).decode() if m else ""

    out = []
    for body in PROBE_BODIES:
        try:
            r = client.post(route, json=body, headers={"X-CSRFToken": csrf})
            out.append(r.status_code)
        except Exception as exc:                # noqa: BLE001  a raise IS the answer
            out.append("raise:%s" % type(exc).__name__)
    print(json.dumps(out))
    return 0


def probe(route: str, env: dict) -> list:
    """This route's answers to PROBE_BODIES, or [] if the probe itself could not run."""
    r = subprocess.run([sys.executable, str(pathlib.Path(__file__).resolve()),
                        "--probe-route", route],
                       capture_output=True, env=env, cwd=str(ROOT))
    line = (r.stdout or b"").decode("utf-8", "replace").strip().splitlines()
    for candidate in reversed(line):
        try:
            return json.loads(candidate)
        except ValueError:
            continue
    return []


def classify(before: list, after: list) -> str:
    """What the mutation did to the route's answers, in one word."""
    if not before or not after or len(before) != len(after):
        return "unprobed"
    if before == after:
        return "same"
    accepted = [(b, a) for b, a in zip(before, after)
                if isinstance(b, int) and isinstance(a, int) and b >= 400 and a < 400]
    crashed = [(b, a) for b, a in zip(before, after)
               if str(a).startswith("raise") or (isinstance(a, int) and a >= 500
                                                 and not (isinstance(b, int) and b >= 500))]
    if accepted:
        return "ACCEPTS"
    if crashed:
        return "CRASHES"
    return "differs"


def run_tests(targets: list[str], env: dict) -> tuple[bool, str]:
    """(green, tail). No targets is not green: it is 'nothing looked'."""
    if not targets:
        return True, "no test class names this route"
    r = subprocess.run([sys.executable, "-m", "unittest", *targets],
                       cwd=str(ROOT / "polaris_web"), capture_output=True, env=env)
    text = (r.stderr or b"").decode("utf-8", "replace")
    return r.returncode == 0, text.strip().splitlines()[-1] if text.strip() else ""


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0] or None)
    ap.add_argument("--limit", type=int, help="mutate only the first N refusals")
    ap.add_argument("--status", type=int, nargs="+",
                    help="only these HTTP statuses (default: %s)"
                         % " ".join(str(s) for s in DEFAULT_STATUSES))
    ap.add_argument("--all", action="store_true",
                    help="every refusal, including the 400/404 surface that is measured and "
                         "OPEN: see the note in the module docstring")
    ap.add_argument("--probe", action="store_true",
                    help="also ask each route what it ANSWERS with the refusal switched off, "
                         "so 'masked by a neighbour' is measured instead of assumed")
    ap.add_argument("--probe-route", help=argparse.SUPPRESS)
    ap.add_argument("--exhaustive", action="store_true",
                    help="run the whole application suite per mutation, not the named classes")
    args = ap.parse_args()
    if args.probe_route:                      # the subprocess half of --probe
        return _probe_child(args.probe_route)

    mods = modules()
    print("REPAIR, if this run is killed:  git checkout -- polaris_web")
    print()
    dirty = subprocess.run(["git", "status", "--porcelain", "--"] + [str(m) for m in mods],
                           cwd=str(ROOT), capture_output=True).stdout.decode().strip()
    if dirty:
        print("polaris_web has uncommitted changes in a module this drill rewrites:\n%s\n\n"
              "Its documented repair is `git checkout --`, which would throw those away. "
              "Commit or stash first." % dirty, file=sys.stderr)
        return 2

    originals = {m: m.read_text() for m in mods}
    found = []
    for m in mods:
        for r in refusals(originals[m]):
            r["file"] = m
            found.append(r)
    if len(found) < 20:
        print("== VOID: %d refusals found across %d module(s) of polaris_web. The parser and "
              "the application have drifted, so this drill is measuring nothing =="
              % (len(found), len(mods)), file=sys.stderr)
        return 2
    print("scanning %d module(s) of polaris_web: %d refusals"
          % (len(mods), len(found)))
    by_file = {}
    for r in found:
        by_file[r["file"].name] = by_file.get(r["file"].name, 0) + 1
    print("   " + ", ".join("%s %d" % (k, v) for k, v in sorted(by_file.items())) + "\n")

    env = dict(os.environ)
    env.setdefault("POLARIS_PQC_PROFILE", "placeholder")

    croute, ccond = CONTROL
    control = next((r for r in found
                    if r["route"] == croute and ccond in r["source"]), None)
    if control is None:
        print("== VOID: no refusal on %s has a condition containing %r. Point CONTROL at one "
              "that exists ==" % (croute, ccond), file=sys.stderr)
        return 2

    control_targets = classes_exercising(control["route"], control["view"])
    print("positive control: %s unmutated, which must be GREEN"
          % ", ".join(control_targets) or "(no classes)")
    green, tail = run_tests(control_targets, env)
    if not green:
        print("== VOID: the suite is RED before anything was mutated (%s). A red suite "
              "'detects' every mutation and measures none of them, which is how the first "
              "draft of this drill reported a perfect result in one second. Fix the "
              "environment first: this needs PostgreSQL, Redis and the schema-owner role, and "
              "the module docstring carries the exact variables. ==" % tail, file=sys.stderr)
        return 2
    print("   green: %s\n" % (tail or "OK"))

    print("negative control: switching off the refusal on %s (%s:%d)"
          % (control["route"], control["file"].name, control["line"]))
    try:
        cf = control["file"]
        cf.write_text(mutate(originals[cf], control["span"]))
        green, tail = run_tests(control_targets, env)
    finally:
        cf.write_text(originals[cf])
    if green:
        print("== VOID: the control refusal was switched off and every test stayed green. The "
              "harness is not running the tests, so no result below would mean anything. %s =="
              % tail, file=sys.stderr)
        return 2
    print("   the suite went red, as it must: %s\n" % tail)

    scope = set(args.status or ([] if args.all else DEFAULT_STATUSES))
    cases = [r for r in found if not scope or r["status"] in scope]
    outside = [r for r in found if scope and r["status"] not in scope]
    if args.limit:
        cases = cases[:args.limit]

    baselines: dict[str, list] = {}
    if args.probe:
        routes = sorted({c["route"] for c in cases})
        print("probing %d route(s) unmutated, for the baseline every comparison rests on"
              % len(routes), flush=True)
        for r in routes:
            baselines[r] = probe(_concrete(r), env)
        unprobed = [r for r, v in baselines.items() if not v]
        if unprobed:
            print("   %d route(s) the probe could not reach; their cases report 'unprobed': %s"
                  % (len(unprobed), ", ".join(unprobed[:4])), flush=True)
        print()

    survivors, blind, started = [], [], time.time()
    for i, case in enumerate(cases, 1):
        targets = ([] if args.exhaustive else
                   classes_exercising(case["route"], case["view"]))
        if args.exhaustive:
            targets = ["test_app"]
        # The module is printed with the line: once the application is more than one file, a
        # bare line number cites nothing.
        print("[%3d/%3d] %-28s %-3d %s:%-5d %s"
              % (i, len(cases), case["route"][:28], case["status"],
                 case["file"].name[:20], case["line"],
                 "%d class(es)" % len(targets) if targets else "NO TEST NAMES THIS ROUTE"),
              flush=True)
        if not targets:
            blind.append(case)
            continue
        try:
            f = case["file"]
            f.write_text(mutate(originals[f], case["span"]))
            green, tail = run_tests(targets, env)
        finally:
            f.write_text(originals[f])
        if green:
            if args.probe:
                case["verdict"] = classify(baselines.get(case["route"], []),
                                           probe(_concrete(case["route"]), env))
            survivors.append(case)
            print("          SURVIVED%s: %s"
                  % (" [%s]" % case["verdict"] if case.get("verdict") else "",
                     case["source"][:78]))

    not_restored = [m.name for m in mods if m.read_text() != originals[m]]
    assert not not_restored, ("not restored: %s; repair with `git checkout -- polaris_web`"
                              % ", ".join(not_restored))

    print("\nrefusals examined              %d of %d" % (len(cases), len(found)))
    if outside:
        from collections import Counter as _C
        print("NOT examined by this run       %d (%s)"
              % (len(outside), ", ".join("%d x%d" % (s, n) for s, n in
                                         sorted(_C(r["status"] for r in outside).items()))))
    print("no test class names the route  %d" % len(blind))
    print("survived the mutation          %d" % len(survivors))
    if args.probe:
        from collections import Counter as _C
        tally = _C(c.get("verdict", "unprobed") for c in survivors)
        for verdict in ("ACCEPTS", "CRASHES", "differs", "same", "unprobed"):
            if tally.get(verdict):
                print("   %-28s %d%s" % (verdict, tally[verdict],
                                         "   <-- a hole nothing is watching"
                                         if verdict in ("ACCEPTS", "CRASHES") else ""))
    print("elapsed                        %d s" % (time.time() - started))

    def _declared(case):
        return any(view == case["view"] and cond in case["source"]
                   for (view, cond) in DECLARED)

    undeclared = [c for c in survivors + blind if not _declared(c)]
    if undeclared:
        print("\n== %d REFUSAL(S) NOTHING NOTICES ==" % len(undeclared))
        for c in undeclared:
            print("   %-30s %-3d %s:%d" % (c["route"][:30], c["status"], c["view"], c["line"]))
            print("        %s" % c["source"][:78])
        print("\nEach is a decision the application makes that no test would miss. Cover it, or "
              "add it to DECLARED with the reason it does not need covering.")
        return 1

    # STALENESS IS ONLY MEASURABLE FROM A COMPLETE RUN. `stale` asks which declarations name no
    # refusal that survived or went untested, and a run narrowed by --limit or by a status
    # scope did not examine most of them. A partial run therefore reported almost every
    # declaration as obsolete and exited 1 on a finding it had no evidence for: `--limit 4`
    # called 17 of them stale on 2026-09-18. Say so instead.
    partial = bool(args.limit) or bool(outside)
    matched = sorted(k for k in DECLARED
                     if any(k[0] == c["view"] and k[1] in c["source"] for c in survivors + blind))
    unmatched = sorted(set(DECLARED) - set(matched))
    # A partial run cannot prove a declaration OBSOLETE, because it did not examine most of
    # them. It can prove one LIVE, because a declaration matched by a survivor here is matched
    # whatever the rest of the run would have found. So report the half that is sound. When
    # every declaration is matched, the audit is complete even though the run was not, and
    # saying that is better than saying nothing: on 2026-09-18 the default scope matched all
    # 17 of 17 while examining 37 of 113 refusals.
    stale = [] if partial else unmatched
    if partial:
        if not unmatched:
            print("\ndeclarations: all %d matched a survivor in this run, so none is obsolete. "
                  "A partial run cannot prove a declaration stale, but a declaration matched "
                  "here is matched whatever the unexamined %d refusals would have shown, so "
                  "this audit is complete even though the run is not."
                  % (len(DECLARED), len(found) - len(cases)))
        else:
            print("\ndeclarations: %d of %d matched a survivor in this run. The other %d were "
                  "not examined (%s), and a partial run cannot tell an obsolete declaration "
                  "from an unexamined one. Re-run with --all and no --limit: %s"
                  % (len(matched), len(DECLARED), len(unmatched),
                     "--limit" if args.limit else "status scope",
                     ", ".join("%s(%s)" % k for k in unmatched[:6])))
    if stale:
        print("\nSTALE DECLARATIONS (%d): covered now, or the refusal was rewritten, so the "
              "reason is obsolete: %s"
              % (len(stale), ", ".join("%s(%s)" % s for s in stale)))
        return 1

    print("\n== Every refusal examined turns a test red when it is switched off. That is a "
          "statement about THESE refusals under THESE suites, not about the application: a "
          "route with no 4xx makes no refusal this drill can see, and a test that notices for "
          "the wrong reason still counts as noticing. ==")
    return 0


if __name__ == "__main__":
    sys.exit(main())
