# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_relying_party.py — the relying-party verifier (holder<->verifier flow, PE follow-up).

Drives the decision logic of scripts/polaris-relying-party.py with injected
authenticity and status verdicts (no crypto, no server), so the ACCEPT/REJECT/
PROVISIONAL combinations and the duress-deniability property are covered in the
suite. The full real-ML-DSA issue->pack->wallet->relying-party flow runs where
liboqs and a database are present."""
import base64
import contextlib
import http.server
import importlib.util
import io
import json
import os
import tempfile
import threading
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def _load_rp():
    spec = importlib.util.spec_from_file_location(
        "polaris_relying_party", os.path.join(_HERE, "polaris-relying-party.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class RelyingPartyDecisionTests(unittest.TestCase):
    def setUp(self):
        self.rp = _load_rp()
        self.verdict = {"signature_valid": True, "issuer_trusted": None, "note": None}
        outer = self

        class _StubVerifier:
            def verify_pack(self, pack, anchor_keys=None):
                return outer.verdict

            def _load_anchor(self, path):
                return []
        # Inject the stubbed detached verifier so we control authenticity.
        self.rp._load_verifier = lambda: _StubVerifier()

    def _present(self, code=None):
        return {"format": "polaris-presentation/1",
                "credential": {"token_id": 42, "token_value": "T"},
                "presented_code": code}

    @staticmethod
    def _status(active):
        return lambda token_id: {"currently_authoritative": active,
                                 "status": "ACTIVE" if active else "REVOKED"}

    def test_accept_when_authentic_and_active(self):
        v = self.rp.verify_presentation(self._present(), status_checker=self._status(True))
        self.assertEqual(v["decision"], "accept")

    def test_reject_when_authentic_but_revoked(self):
        v = self.rp.verify_presentation(self._present(), status_checker=self._status(False))
        self.assertEqual(v["decision"], "reject")
        self.assertTrue(v["authentic"])  # the signature is still genuine; it is just not current

    def test_reject_when_not_authentic(self):
        self.verdict = {"signature_valid": False, "issuer_trusted": None, "note": "tampered"}
        v = self.rp.verify_presentation(self._present(), status_checker=self._status(True))
        self.assertEqual(v["decision"], "reject")

    def test_reject_when_issuer_untrusted(self):
        self.verdict = {"signature_valid": True, "issuer_trusted": False, "note": None}
        v = self.rp.verify_presentation(self._present(), status_checker=self._status(True))
        self.assertEqual(v["decision"], "reject")

    def test_provisional_when_offline(self):
        v = self.rp.verify_presentation(self._present(), status_checker=None)
        self.assertEqual(v["decision"], "provisional")  # authentic, but status unverified

    def test_duress_presentation_is_indistinguishable_in_the_decision(self):
        normal = self.rp.verify_presentation(self._present(code="real-code"),
                                             status_checker=self._status(True))
        duress = self.rp.verify_presentation(self._present(code="duress-code"),
                                             status_checker=self._status(True))
        # The relying party cannot tell a duress presentation from a normal one.
        self.assertEqual(normal["decision"], duress["decision"])
        self.assertEqual(normal["decision"], "accept")
        self.assertEqual(sorted(normal), sorted(duress))
        self.assertTrue(normal["presented_code_present"] and duress["presented_code_present"])



class _Issuer(http.server.ThreadingHTTPServer):
    """A stand-in issuer on 127.0.0.1: answers from a route table and records each request."""

    def __init__(self, routes):
        self.routes, self.seen = routes, []
        super().__init__(("127.0.0.1", 0), _IssuerHandler)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.server_address[1]


class _IssuerHandler(http.server.BaseHTTPRequestHandler):
    def _answer(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.server.seen.append((self.command, self.path, dict(self.headers), body))
        route = self.server.routes.get((self.command, self.path))
        code, payload = route(self.headers, body) if callable(route) else route or (404, {"error": "no route"})
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = _answer

    def log_message(self, *args):
        pass


class RelyingPartyCommandLineTests(unittest.TestCase):
    """The command a relying party runs: it reads the presentation, reaches the issuer (plainly
    or as an OAuth client), and exits 0 ACCEPT, 2 REJECT or 3 PROVISIONAL. Authenticity is
    stubbed as in the class above; what is exercised here is everything after it."""

    def setUp(self):
        self.rp = _load_rp()

        class _StubVerifier:
            def verify_pack(self, pack, anchor_keys=None):
                return {"signature_valid": True, "issuer_trusted": None, "note": None}

            def _load_anchor(self, path):
                return []
        self.rp._load_verifier = lambda: _StubVerifier()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.presentation = os.path.join(tmp.name, "p.json")
        with open(self.presentation, "w") as f:
            json.dump({"format": "polaris-presentation/1",
                       "credential": {"token_id": 42, "token_value": "T", "signature_hex": "ab"},
                       "presented_code": None}, f)
        self.garbage = os.path.join(tmp.name, "garbage.json")
        with open(self.garbage, "w") as f:
            f.write("{not json")

    def _issuer(self, routes):
        issuer = _Issuer(routes)
        self.addCleanup(issuer.server_close)
        self.addCleanup(issuer.shutdown)
        return issuer

    def _run(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = self.rp.main(["verify-presentation", "--presentation", self.presentation, *argv])
        return code, out.getvalue()

    def test_offline_is_provisional_and_exits_3(self):
        code, out = self._run("--offline", "--issuer-url", "http://127.0.0.1:9")
        self.assertEqual(code, 3)
        self.assertIn("PROVISIONAL", out)

    def test_an_active_status_from_the_issuer_accepts_with_exit_0(self):
        issuer = self._issuer({("GET", "/api/tokens/42/verify"):
                               (200, {"currently_authoritative": True, "status": "ACTIVE"})})
        code, out = self._run("--issuer-url", issuer.url + "/")
        self.assertEqual((code, "ACCEPT" in out), (0, True), out)
        self.assertEqual([(m, p) for m, p, _, _ in issuer.seen], [("GET", "/api/tokens/42/verify")])

    def test_a_revoked_status_rejects_with_exit_2(self):
        issuer = self._issuer({("GET", "/api/tokens/42/verify"):
                               (200, {"currently_authoritative": False, "status": "REVOKED"})})
        code, out = self._run("--issuer-url", issuer.url, "--json")
        verdict = json.loads(out)
        self.assertEqual((code, verdict["decision"], verdict["currently_authoritative"]),
                         (2, "reject", False))
        self.assertIn("status=REVOKED", " ".join(verdict["reasons"]))

    def test_an_issuer_that_errors_is_a_reject_not_an_accept(self):
        issuer = self._issuer({("GET", "/api/tokens/42/verify"): (500, {"error": "down"})})
        code, out = self._run("--issuer-url", issuer.url, "--json")
        verdict = json.loads(out)
        self.assertEqual((code, verdict["decision"]), (2, "reject"))
        self.assertIn("status could not be read from the issuer", verdict["reasons"])

    def test_a_status_without_the_verdict_field_is_a_reject(self):
        issuer = self._issuer({("GET", "/api/tokens/42/verify"): (200, {"status": "ACTIVE"})})
        code, out = self._run("--issuer-url", issuer.url, "--json")
        self.assertEqual((code, json.loads(out)["currently_authoritative"]), (2, None))

    def test_as_an_oauth_client_it_authenticates_then_presents_the_credential(self):
        expected = "Basic " + base64.b64encode(b"rp-client:rp-secret").decode()

        def token(headers, body):
            if headers.get("Authorization") != expected or body != b"grant_type=client_credentials":
                return 401, {"error": "invalid_client"}
            return 200, {"access_token": "tok-123", "token_type": "Bearer"}

        def verify(headers, body):
            if headers.get("Authorization") != "Bearer tok-123":
                return 401, {"error": "invalid_token"}
            sent = json.loads(body)
            ok = sent == {"token_value": "T", "signature_hex": "ab"}
            return 200, {"currently_authoritative": ok, "status": "ACTIVE" if ok else "UNKNOWN"}

        issuer = self._issuer({("POST", "/api/v1/oauth/token"): token,
                               ("POST", "/api/v1/verify"): verify})
        code, out = self._run("--issuer-url", issuer.url, "--oauth-client-id", "rp-client",
                              "--oauth-client-secret", "rp-secret", "--json")
        self.assertEqual((code, json.loads(out)["decision"]), (0, "accept"), out)
        self.assertEqual([(m, p) for m, p, _, _ in issuer.seen],
                         [("POST", "/api/v1/oauth/token"), ("POST", "/api/v1/verify")])

    def test_an_oauth_client_the_issuer_refuses_is_a_reject(self):
        """Until 2026-09-30 the token request ran before any decision, so a refused client
        escaped main() as an HTTPError traceback, an exit status the docstring's table does
        not have. It is a status that could not be read, as an unreachable issuer is."""
        issuer = self._issuer({("POST", "/api/v1/oauth/token"): (401, {"error": "invalid_client"})})
        code, out = self._run("--issuer-url", issuer.url, "--oauth-client-id", "rp-client",
                              "--oauth-client-secret", "wrong", "--json")
        verdict = json.loads(out)
        self.assertEqual((code, verdict["decision"]), (2, "reject"))
        self.assertIn("status could not be read from the issuer", verdict["reasons"])
        self.assertEqual([p for _, p, _, _ in issuer.seen], ["/api/v1/oauth/token"],
                         "nothing is presented to /api/v1/verify without a token")

    def test_an_unreadable_presentation_exits_3(self):
        out = io.StringIO()
        with contextlib.redirect_stderr(out):
            code = self.rp.main(["verify-presentation", "--presentation", self.garbage, "--offline"])
        self.assertEqual(code, 3)
        self.assertIn("could not read the presentation", out.getvalue())

    def test_input_that_is_json_but_not_a_presentation_exits_3_or_rejects(self):
        """The review of 2026-09-30: a presentation file holding `[1]` raised AttributeError and
        an anchor path that did not exist raised FileNotFoundError, both tracebacks outside the
        exit table. A credential that is not an object got as far as `.get` too."""
        with open(self.garbage, "w") as f:
            f.write("[1]")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = self.rp.main(["verify-presentation", "--presentation", self.garbage, "--offline"])
        self.assertEqual(code, 3)
        self.assertIn("not a JSON object", err.getvalue())

        class _FileAnchors:
            def verify_pack(self, pack, anchor_keys=None):
                return {"signature_valid": True, "issuer_trusted": None, "note": None}

            def _load_anchor(self, path):
                return json.load(open(path))
        self.rp._load_verifier = lambda: _FileAnchors()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = self.rp.main(["verify-presentation", "--presentation", self.presentation,
                                 "--issuer-anchor", "/nonexistent/issuer.json", "--offline"])
        self.assertEqual(code, 3)
        self.assertIn("could not read the issuer anchor", err.getvalue())

        for credential in ([1], "credential", 7):
            with self.subTest(credential=credential):
                v = self.rp.verify_presentation({"credential": credential})
                self.assertIsNone(v["token_value"])
                self.assertIn(v["decision"], ("reject", "provisional"))

    def test_an_anchor_is_loaded_and_passed_to_the_verifier(self):
        seen = {}

        class _Recording:
            def verify_pack(self, pack, anchor_keys=None):
                seen["anchor"] = anchor_keys
                return {"signature_valid": True, "issuer_trusted": True, "note": None}

            def _load_anchor(self, path):
                seen["path"] = path
                return ["key"]
        self.rp._load_verifier = lambda: _Recording()
        code, out = self._run("--issuer-anchor", "issuer.json", "--offline")
        self.assertEqual((code, seen), (3, {"path": "issuer.json", "anchor": ["key"]}))
        self.assertIn("issuer_trusted:        True", out)

    def test_the_real_detached_verifier_is_what_it_loads(self):
        fresh = _load_rp()
        verifier = fresh._load_verifier()
        self.assertTrue(callable(verifier.verify_pack) and callable(verifier._load_anchor))


if __name__ == "__main__":
    unittest.main()
