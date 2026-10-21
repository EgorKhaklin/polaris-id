# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""run.sh's verdicts, each branch without a wallet; and, with EUDI_WALLET_TESTS=1, a walk that
shows no other wallet answers for it.

The walk judges each wallet run from the wallet's exit status and its --json output, and from
the verifier's record of its one request taken before and after the run: `serve --result`'s
JSON, or the same read off the log of a polaris-oid4vp without it. The functions that decide
(walk_py snap and judge, present, measure) are defined before run.sh does anything, and sourcing
it stops there, so these tests run them on files shaped as eudi-dev 2.x and 3.x write them.
No Docker, network or database.

NoOtherWalletTests runs the real walk with eudi-dev's own v2.3.7 binary (a download and a pip
install) while it holds a listener on localhost:8085 that answers as a running wallet server
would: eudi-dev 2.x's `wallet accept` without --port hands the request to such a server, which
presents its own credential. Nothing may reach it.
"""
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = pathlib.Path(__file__).resolve().parent
RUN = pathlib.Path(os.environ.get("EUDI_RUN_SH") or HERE / "run.sh")
BASH = "/bin/bash" if os.path.exists("/bin/bash") else "bash"

STATE = "Qx7v2N0bS8tWdLmPq3aZ"
URI = ("openid4vp://authorize?client_id=x509_hash%3Aabc&request_uri=https%3A%2F%2Flocalhost%3A9443"
       "%2Frequest.jwt%3Fstate%3D" + STATE + "&request_uri_method=post")
CLAIMS = ["cnf", "family_name", "given_name", "iat", "iss", "vct"]

# What eudi-dev writes to stdout with --json. 3.x: one JSON document and nothing else (its human
# lines go to stderr). 2.x: its human lines, then the verifier's answer as a JSON object.
V3_200 = json.dumps({"status": "submitted", "response": {
    "status_code": 200, "body": "{\"redirect_uri\":\"https://localhost:9443/done\"}"}}, indent=2)
V3_400 = json.dumps({"status": "submitted", "response": {
    "status_code": 400,
    "body": "{\"error\":\"invalid_request\",\"error_description\":\"the presentation was not accepted\"}"}},
    indent=2)
V2_200 = ("───────────────────────────────────────\n"
          "  Verifier: x509_hash:abc\n"
          "  Disclosing: [family_name given_name]\n"
          "  Submitted: Response: 200 → https://localhost:9443/done\n"
          "───────────────────────────────────────\n"
          + json.dumps({"status_code": 200, "body": "{}",
                        "redirect_uri": "https://localhost:9443/done"}, indent=2) + "\n")
V2_400 = ("  Error: Response: 400\n"
          "  Body:  {\"error\":\"invalid_request\",\"error_description\":\"the presentation was not accepted\"}\n"
          "───────────────────────────────────────\n"
          + json.dumps({"status_code": 400, "body": "{\"error\":\"invalid_request\"}"}, indent=2) + "\n")


def record(responses, outcome="nothing_received", served=0, refused=0, state=STATE, **members):
    """The verifier's record as `serve --result` writes it (walk_py snap adds the source)."""
    doc = {"outcome": outcome, "state": state, "responses": responses,
           "request_object": {"served": served, "refused": refused}, "source": "serve --result"}
    doc.update(members)
    return doc


def from_log(doc):
    """The same record as walk_py snap reads it off a log: no fetch counts."""
    return dict(doc, request_object=None, source="its log")


def bash(script, cwd, *args):
    """Source run.sh (which then only defines its functions) and run SCRIPT after it."""
    env = dict(os.environ, T_RUN_SH=str(RUN), T_PY=sys.executable)
    return subprocess.run([BASH, "-c", 'set -euo pipefail; source "$T_RUN_SH"; WALK_PY="$T_PY"; '
                           + script, "bash"] + list(args),
                          cwd=cwd, env=env, capture_output=True, text=True, timeout=60)


class Judged(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="test-walk-")
        self.addCleanup(tmp.cleanup)
        self.dir = pathlib.Path(tmp.name)

    def judge(self, kind, rc, out, before, after, err="", want="issuer_signature", uri=URI):
        (self.dir / "w.rc").write_text("%d\n" % rc)
        (self.dir / "w.out").write_text(out)
        (self.dir / "w.err").write_text(err)
        (self.dir / "before.json").write_text(json.dumps(before))
        (self.dir / "after.json").write_text(json.dumps(after))
        r = bash('walk_py judge "$1" w before.json after.json "$2" "$3"', self.dir, kind, uri, want)
        self.assertNotIn("Traceback", r.stderr, r.stderr)
        return r

    def passes(self, *a, **k):
        r = self.judge(*a, **k)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("FAIL", r.stdout)
        return r.stdout

    def fails(self, *a, **k):
        r = self.judge(*a, **k)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("  FAIL  ", r.stdout)
        return r.stdout


class GenuineTests(Judged):
    BEFORE = record(0)
    AFTER = record(1, "accepted", served=1, claims=CLAIMS, response={"status_code": 200})

    def test_3x_exit_0_and_200_and_the_verifier_accepting_this_request_passes(self):
        out = self.passes("genuine", 0, V3_200, self.BEFORE, self.AFTER)
        self.assertIn("the wallet exited 0 and reports the verifier's answer: HTTP 200", out)
        self.assertIn("1 response for this walk's request (state %s...); accepted, claims %s"
                      % (STATE[:8], CLAIMS), out)

    def test_2x_text_then_its_json_is_read(self):
        self.passes("genuine", 0, V2_200, self.BEFORE, self.AFTER)

    def test_read_off_a_log_without_fetch_counts(self):
        self.passes("genuine", 0, V3_200, from_log(self.BEFORE), from_log(self.AFTER))

    def test_a_wallet_that_exited_non_zero_fails_whatever_its_json_says(self):
        # The exit status is evidence: a 3.x run that exits 1 did not complete, so its JSON alone
        # cannot pass it.
        out = self.fails("genuine", 1, V3_200, self.BEFORE, self.AFTER)
        self.assertIn("FAIL  the wallet exited 1", out)

    def test_a_400_fails(self):
        self.fails("genuine", 1, V3_400, self.BEFORE,
                   record(1, "refused", served=1, check="issuer_signature", reason="r"))

    def test_3x_json_that_was_not_submitted_fails(self):
        self.fails("genuine", 0, json.dumps({"status": "denied", "response": {"status_code": 200}}),
                   self.BEFORE, self.AFTER)

    def test_no_json_fails(self):
        self.fails("genuine", 0, "", self.BEFORE, self.AFTER)

    def test_another_wallet_answering_fails(self):
        # A running wallet server took the request and answered 200: the wallet run looks right,
        # but nothing reached this walk's verifier.
        out = self.fails("genuine", 0, json.dumps({"status": "submitted", "response": {"status_code": 200}}),
                         self.BEFORE, self.BEFORE)
        self.assertIn("FAIL  the verifier, by serve --result: 0 response", out)

    def test_a_record_of_another_request_fails(self):
        out = self.fails("genuine", 0, V3_200, self.BEFORE, dict(self.AFTER, state="OtherState123"))
        self.assertIn("a request other than the one the wallet was launched with", out)

    def test_the_verifier_refusing_fails(self):
        self.fails("genuine", 0, V3_200, self.BEFORE,
                   record(1, "refused", served=1, check="nonce", reason="r"))

    def test_two_responses_fail(self):
        self.fails("genuine", 0, V3_200, self.BEFORE, dict(self.AFTER, responses=2))

    def test_no_fetch_of_the_request_object_fails(self):
        self.fails("genuine", 0, V3_200, self.BEFORE, dict(self.AFTER, request_object={"served": 0, "refused": 0}))


class IssuerControlTests(Judged):
    """(a): the verifier trusts another issuer key; it must refuse, naming that check."""
    BEFORE = record(0, served=3)
    AFTER = record(1, "refused", served=4, check="issuer_signature",
                   reason="the issuer signature does not verify", response={"status_code": 400})

    def test_3x_exits_non_zero_on_the_400(self):
        out = self.passes("a", 1, V3_400, self.BEFORE, self.AFTER)
        self.assertIn("the wallet exited 1 and reports the verifier's answer: HTTP 400", out)
        self.assertIn("refused: issuer_signature: the issuer signature does not verify", out)

    def test_2x_exits_0_on_the_400_and_its_json_is_read(self):
        out = self.passes("a", 0, V2_400, self.BEFORE, self.AFTER)
        self.assertIn("exited 0 (2.x exits 0 on a 400; its JSON is read)", out)

    def test_read_off_a_log(self):
        self.passes("a", 1, V3_400, from_log(self.BEFORE), from_log(self.AFTER))

    def test_3x_exiting_0_on_a_400_fails(self):
        self.fails("a", 0, V3_400, self.BEFORE, self.AFTER)

    def test_another_check_fails(self):
        out = self.fails("a", 1, V3_400, self.BEFORE, dict(self.AFTER, check="issuer_key"))
        self.assertIn("refused: issuer_key", out)

    def test_an_acceptance_fails(self):
        self.fails("a", 0, V3_200, self.BEFORE, record(1, "accepted", served=4, claims=CLAIMS))

    def test_no_json_fails(self):
        self.fails("a", 1, "", self.BEFORE, self.AFTER)

    def test_nothing_reaching_the_verifier_fails(self):
        self.fails("a", 1, V3_400, self.BEFORE, record(0, served=4))


class WalletRefusalTests(Judged):
    """(b), (c) and (d): the wallet refuses, so it exits non-zero, nothing reaches the verifier,
    and the wallet's refusal names the control's own reason. Its words are eudi-dev's on stderr,
    as v2.3.7 and v3.3.1 wrote them (3.x adds a prefix and the HTTP status)."""
    ANSWERED = record(1, "accepted", served=1, claims=CLAIMS)
    OPEN = record(0, served=0)
    FETCHED = record(0, served=1)  # the request once (c) has fetched it: what (d) starts from
    SAID = {
        "b": "parsing authorization request: fetching request_uri: POST to request_uri returned HTTP 404",
        "c": ('parsing authorization request: request object client_id "x509_hash:def" does not match '
              'outer client_id "x509_hash:abc"'),
        "d": ('parsing authorization request: fetching request_uri: POSTing to request_uri: Post '
              '"https://localhost:9443/request.jwt?state=%s": tls: failed to verify certificate: '
              'x509: certificate signed by unknown authority' % STATE),
    }
    V3 = "remote wallet: invalid_request: %s (HTTP 400)"

    def err(self, kind, v3=False):
        return "human lines\n" + (self.V3 % self.SAID[kind] if v3 else self.SAID[kind]) + "\n"

    def counts(self, kind):
        """The verifier's record before and after a run in which the control passes."""
        return {"b": (self.ANSWERED, dict(self.ANSWERED, request_object={"served": 1, "refused": 1})),
                "c": (self.OPEN, self.FETCHED), "d": (self.FETCHED, self.FETCHED)}[kind]

    def test_b_the_answered_request_refused_at_its_fetch(self):
        out = self.passes("b", 1, "", *self.counts("b"), err=self.err("b"))
        self.assertIn("the wallet exited 1, having presented nothing", out)
        self.assertIn("ok    the wallet refused at its fetch of the answered request (HTTP 404); it said: "
                      + self.SAID["b"], out)
        self.assertIn("no response for this walk's request (state %s...); it refused 1 fetch(es) of the "
                      "request object and served 0" % STATE[:8], out)

    def test_c_the_signed_request_fetched_then_refused(self):
        out = self.passes("c", 1, "", *self.counts("c"), err=self.err("c"))
        self.assertIn("ok    the wallet refused the request object, whose client_id is not x509_hash:abc", out)
        self.assertIn("it served the signed request object 1 time(s)", out)

    def test_d_nothing_fetched_where_the_count_is_live(self):
        out = self.passes("d", 1, "", *self.counts("d"), err=self.err("d"))
        self.assertIn("ok    the wallet refused the verifier's certificate when fetching this walk's request", out)
        self.assertIn("0 fetch(es) of the request object, which had counted 1 before this run", out)

    def test_each_in_3x_words(self):
        for kind in "bcd":
            with self.subTest(kind=kind):
                self.passes(kind, 1, "", *self.counts(kind), err=self.err(kind, v3=True))

    def test_read_off_a_log_each_needs_its_reason_and_no_fetch_counts(self):
        for kind in "bcd":
            with self.subTest(kind=kind):
                before, after = self.counts(kind)
                self.passes(kind, 1, "", from_log(before), from_log(after), err=self.err(kind))

    # A wallet that stopped for another reason exits non-zero and sends nothing too.
    def test_d_a_wallet_that_could_not_open_its_certificate_fails(self):
        out = self.fails("d", 1, "", *self.counts("d"),
                         err="open /work/in/pki/anchor.pem: no such file or directory\n")
        self.assertIn("FAIL  the wallet refused the verifier's certificate when fetching this walk's "
                      "request; it said: open /work/in/pki/anchor.pem", out)
        self.assertEqual(out.count("FAIL"), 1, out)

    def test_b_and_c_a_wallet_without_port_fail_read_off_a_log(self):
        for kind in "bc":
            with self.subTest(kind=kind):
                before, after = self.counts(kind)
                out = self.fails(kind, 2, "", from_log(before), from_log(after),
                                 err="Error: unknown flag: --port\n")
                self.assertIn("it said: Error: unknown flag: --port", out)
                self.assertEqual(out.count("FAIL"), 1, out)

    def test_each_with_another_controls_reason_fails(self):
        for kind, other in (("b", "c"), ("c", "d"), ("d", "b")):
            with self.subTest(kind=kind):
                out = self.fails(kind, 1, "", *self.counts(kind), err=self.err(other))
                self.assertEqual(out.count("FAIL"), 1, out)

    def test_c_naming_another_client_id_fails(self):
        self.fails("c", 1, "", *self.counts("c"), err=self.err("c").replace('"x509_hash:abc"', '"x509_hash:zzz"'))

    def test_d_refused_for_another_request_fails(self):
        self.fails("d", 1, "", *self.counts("d"), err=self.err("d").replace(STATE, "OtherState123"))

    def test_d_where_no_fetch_was_ever_counted_fails(self):
        out = self.fails("d", 1, "", self.OPEN, self.OPEN, err=self.err("d"))
        self.assertIn("which had counted 0 before this run", out)

    def test_a_wallet_exiting_0_fails_each(self):
        # Another wallet answered for it: the run exits 0 having reached nothing here.
        for kind in "bcd":
            with self.subTest(kind=kind):
                out = self.fails(kind, 0, json.dumps({"status": "submitted", "response": {"status_code": 200}}),
                                 *self.counts(kind))
                self.assertIn("FAIL  the wallet exited 0", out)

    def test_a_response_reaching_the_verifier_fails_each(self):
        # A wallet that presented anyway and was refused: 3.x exits 1 on that 400, so only the
        # verifier's record tells it from a refusal.
        for kind, before, after in (
                ("b", self.ANSWERED, dict(self.ANSWERED, responses=2, request_object={"served": 1, "refused": 1})),
                ("c", self.OPEN, record(1, "refused", served=1, check="issuer_signature", reason="r")),
                ("d", self.FETCHED, record(1, "refused", served=1, check="issuer_signature", reason="r"))):
            with self.subTest(kind=kind):
                out = self.fails(kind, 1, V3_400, before, after, err=self.err(kind))
                self.assertIn("1 response(s) for this walk's request", out)
        with self.subTest(kind="c, read off a log"):
            self.fails("c", 1, V3_400, from_log(self.OPEN),
                       from_log(record(1, "refused", check="issuer_signature", reason="r")), err=self.err("c"))

    def test_b_with_the_request_object_served_again_fails(self):
        self.fails("b", 1, "", self.ANSWERED, dict(self.ANSWERED, request_object={"served": 2, "refused": 0}),
                   err=self.err("b"))

    def test_c_without_a_fetch_fails(self):
        self.fails("c", 1, "", self.OPEN, self.OPEN, err=self.err("c"))

    def test_d_with_a_fetch_fails(self):
        self.fails("d", 1, "", self.FETCHED, record(0, served=2), err=self.err("d"))

    def test_a_record_of_another_request_fails(self):
        self.fails("d", 1, "", self.FETCHED, dict(self.FETCHED, state="OtherState123"), err=self.err("d"))

    def test_an_unknown_kind_stops(self):
        r = self.judge("e", 1, "", self.OPEN, self.OPEN)
        self.assertNotEqual(r.returncode, 0)


class SnapTests(unittest.TestCase):
    LOG = ("polaris-oid4vp serving on https://localhost:9443 (listening on 127.0.0.1:9443)\n"
           "  request_uri   https://localhost:9443/request.jwt\n"
           "  request_uri          https://localhost:9443/request.jwt?state=" + STATE + "\n")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="test-walk-")
        self.addCleanup(tmp.cleanup)
        self.dir = pathlib.Path(tmp.name)

    def snap(self, log, result=None, flag=False):
        (self.dir / "verifier.log").write_text(log)
        if result is not None:
            (self.dir / "verifier.result.json").write_text(result)
        r = bash('RESULT_FLAG="$1"; snap verifier.log', self.dir, "1" if flag else "")
        return r, (json.loads(r.stdout) if r.returncode == 0 else None)

    def test_serve_result_is_read_when_the_verifier_has_it(self):
        doc = {"outcome": "refused", "check": "nonce", "reason": "r", "state": STATE, "responses": 1,
               "request_object": {"served": 1, "refused": 0}, "response": {"status_code": 400}}
        r, got = self.snap(self.LOG + "  <- 400 refused: issuer_key: from the log\n", json.dumps(doc), flag=True)
        self.assertEqual(got, dict(doc, source="serve --result"))

    def test_a_missing_result_file_stops_the_walk(self):
        r, _ = self.snap(self.LOG, flag=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("serve --result file could not be read", r.stderr)

    def test_a_log_before_any_response(self):
        _, got = self.snap(self.LOG)
        self.assertEqual(got, {"source": "its log", "state": STATE, "responses": 0, "request_object": None,
                               "outcome": "nothing_received", "check": None, "reason": None})

    def test_a_refusal_read_off_the_log_names_its_check(self):
        _, got = self.snap(self.LOG + "  <- 400 refused: issuer_signature: the issuer signature does not verify\n")
        self.assertEqual((got["outcome"], got["check"], got["reason"], got["responses"], got["response"]),
                         ("refused", "issuer_signature", "the issuer signature does not verify", 1,
                          {"status_code": 400}))

    def test_an_acceptance_read_off_the_log_stays(self):
        _, got = self.snap(self.LOG + "  <- 200 authentic, claims %s\n" % CLAIMS
                           + "  <- 400 refused: nonce: replayed\n")
        self.assertEqual((got["outcome"], got["claims"], got["responses"]), ("accepted", CLAIMS, 2))

    def test_a_wallet_error_read_off_the_log(self):
        _, got = self.snap(self.LOG + "  <- 200 wallet error: access_denied: the user said no\n")
        self.assertEqual((got["outcome"], got["reason"]), ("wallet_error", "access_denied: the user said no"))


class PresentTests(unittest.TestCase):
    """present() passes --port and --json, and keeps the run's stdout, stderr and status apart."""
    STUB = ('wallet() { printf "%s\\n" "$@" > args; echo "{\\"status\\": \\"submitted\\"}"; '
            'echo "human line" >&2; return 3; }; WALLET_PORT=48123; ')

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="test-walk-")
        self.addCleanup(tmp.cleanup)
        self.dir = pathlib.Path(tmp.name)

    def run_present(self, tls, extra=""):
        r = bash(self.STUB + "TLS_CA=(%s); present \"$1\" w %s" % (tls, extra), self.dir, URI)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return (self.dir / "args").read_text().splitlines()

    def test_the_wallet_runs_on_the_walks_port_with_json(self):
        args = self.run_present("--tls-ca /in/pki-tls.pem")
        self.assertEqual(args, ["accept", URI, "--auto-accept", "--haip", "--mode", "strict", "--no-open",
                                "--port", "48123", "--json", "--tls-ca", "/in/pki-tls.pem"])
        self.assertEqual((self.dir / "w.out").read_text(), '{"status": "submitted"}\n')
        self.assertEqual((self.dir / "w.err").read_text(), "human line\n")
        self.assertEqual((self.dir / "w.rc").read_text(), "3\n")

    def test_without_a_tls_flag(self):
        self.assertEqual(self.run_present("")[-3:], ["--port", "48123", "--json"])

    def test_control_d_trusts_the_certificate_it_is_given(self):
        args = self.run_present("--tls-ca /in/pki-tls.pem", '"/in/pki-anchor.pem"')
        self.assertEqual(args[-2:], ["--tls-ca", "/in/pki-anchor.pem"])
        self.assertNotIn("/in/pki-tls.pem", args)


class MeasureTests(unittest.TestCase):
    """measure(): the record before, the wallet run, the record after, the verdict; fail=1 on a FAIL."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="test-walk-")
        self.addCleanup(tmp.cleanup)
        self.dir = pathlib.Path(tmp.name)
        (self.dir / "verifier.log").write_text("")
        (self.dir / "verifier.result.json").write_text(json.dumps(record(0)))
        (self.dir / "accepted.json").write_text(json.dumps(record(1, "accepted", served=1, claims=CLAIMS)))
        (self.dir / "200.json").write_text(V3_200)

    def measure(self, verifier_moves):
        script = ('present() { cp 200.json "$2.out"; : > "$2.err"; echo 0 > "$2.rc"; %s }; '
                  'RESULT_FLAG=1 REFUSAL_A=issuer_signature fail=0; measure genuine verifier.log "$1" w; '
                  'echo "fail=$fail"' % ("cp accepted.json verifier.result.json;" if verifier_moves else ":;"))
        return bash(script, self.dir, URI)

    def test_a_passing_verdict_leaves_fail_0(self):
        r = self.measure(True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(r.stdout.endswith("fail=0\n"), r.stdout)

    def test_a_failing_verdict_sets_fail_1(self):
        r = self.measure(False)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("  FAIL  the verifier", r.stdout)
        self.assertTrue(r.stdout.endswith("fail=1\n"), r.stdout)


class PortsTests(unittest.TestCase):
    def test_two_adjacent_free_ports(self):
        r = bash("walk_py ports", tempfile.gettempdir())
        self.assertEqual(r.returncode, 0, r.stderr)
        port = int(r.stdout)
        for p in (port, port + 1):
            with socket.socket() as s:
                s.bind(("127.0.0.1", p))


class _Decoy(BaseHTTPRequestHandler):
    """Answers as a running eudi-dev 2.x wallet server: 200 at GET /api/log, and a submitted
    presentation at POST /api/presentations. Records every request."""
    heard = None

    def _answer(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _record(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.heard.append((self.command, self.path, self.rfile.read(n).decode("utf-8", "replace")))

    def do_GET(self):
        self._record()
        self._answer(b"[]")

    def do_POST(self):
        self._record()
        self._answer(json.dumps({"status": "submitted", "response": {"status_code": 200, "body": "{}"}}).encode())

    def log_message(self, *args):
        pass


class _Decoy6(ThreadingHTTPServer):
    address_family = socket.AF_INET6


@unittest.skipUnless(os.environ.get("EUDI_WALLET_TESTS") == "1",
                     "runs the walk with eudi-dev's own binary (downloads it): set EUDI_WALLET_TESTS=1")
class NoOtherWalletTests(unittest.TestCase):
    def test_a_wallet_server_on_8085_hears_nothing_and_the_walk_passes(self):
        heard = []
        handler = type("Decoy", (_Decoy,), {"heard": heard})
        servers = []
        try:
            servers.append(ThreadingHTTPServer(("127.0.0.1", 8085), handler))
        except OSError as exc:
            self.fail("port 8085 is in use (%s): this test holds it, to show the walk never reaches it" % exc)
        try:
            servers.append(_Decoy6(("::1", 8085), handler))
        except OSError:
            pass  # no IPv6 loopback here; localhost reaches 127.0.0.1
        for s in servers:
            threading.Thread(target=s.serve_forever, daemon=True).start()
        try:
            # The positive control: the listener answers what eudi-dev asks a running server.
            with socket.create_connection(("127.0.0.1", 8085), timeout=5) as c:
                c.sendall(b"GET /api/log HTTP/1.0\r\nHost: localhost:8085\r\n\r\n")
                self.assertTrue(c.recv(64).startswith(b"HTTP/1.0 200"))
            self.assertEqual(heard, [("GET", "/api/log", "")])
            del heard[:]
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
            env = dict(os.environ, EUDI_NATIVE="1", PORT=str(port))
            env.pop("WORK", None)
            with tempfile.TemporaryDirectory() as d:
                r = subprocess.run(["bash", str(RUN)], cwd=d, env=env, capture_output=True, text=True,
                                   timeout=900)
        finally:
            for s in servers:
                s.shutdown()
                s.server_close()
        print("\n--- the walk (exit %d) ---\n%s" % (r.returncode, r.stdout), file=sys.stderr)
        self.assertEqual(heard, [], "a wallet server on 8085 was asked to present:\n%s\n%s" % (heard, r.stdout))
        self.assertEqual(r.returncode, 0, r.stdout[-4000:] + r.stderr[-4000:])
        self.assertIn("\nRESULT: accepted", r.stdout)


if __name__ == "__main__":
    unittest.main()
