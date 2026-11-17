# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_serve.py -- the wire surface, which had no test at all until coverage said so.

`test_verifier.py` drives `handle_direct_post` in process and asserts it returns 400. That is
the decision. **This file asserts the decision becomes an HTTP response**, which is the only
form the conformance plan can score: seven of its eleven modules pass on a 4xx and nothing
else, and a listener that answered 200 while the verifier said 400 would fail all seven while
every other test in this package stayed green.

Found by measuring rather than by thinking: `serve.py` was at 0% line coverage. The conformance
drill exercises it, and the conformance drill needs Docker and a running suite, so nothing in
CI touched the file that turns a verdict into a status code.

TLS is off here. The profile requires HTTPS of a real deployment and the suite enforces it;
what this file tests is routing, form parsing, content types and status codes, and wrapping
the socket changes none of them.
"""
import json
import os
import re
import sys
import unittest
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from polaris_oid4vp.serve import (  # noqa: E402
    MAX_BODY_BYTES, _content_length, _CorsHandler, _Handler, cors_origin, cors_origins_of, serve)
from polaris_oid4vp.verifier import Verifier  # noqa: E402
from test_verifier import Wallet, _client_chain  # noqa: E402


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status, r.headers.get("Content-Type"), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type"), e.read()


def _post(url, form):
    data = urllib.parse.urlencode(form, doseq=True).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.headers.get("Content-Type"), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type"), e.read()


class ServeTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cert_pem, key_pem = _client_chain()
        cls.wallet = Wallet()
        cls.verifier = Verifier(
            client_cert_pem=cert_pem, client_key_pem=key_pem,
            request_uri="http://127.0.0.1:0/request.jwt",
            response_uri="http://127.0.0.1:0/response",
            issuer_jwks=[cls.wallet.issuer_jwk])
        # Port 0 lets the OS choose, so the suite never collides with a developer's own
        # listener or with a conformance drill left running.
        cls.httpd = serve(cls.verifier, host="127.0.0.1", port=0)
        cls.base = "http://127.0.0.1:%d" % cls.httpd.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()


class RequestUriTests(ServeTestCase):

    def test_the_request_object_is_served_with_the_content_type_the_profile_names(self):
        session, jar = self.verifier.new_request()
        status, ctype, body = _get("%s/request.jwt?state=%s" % (self.base, session.state))
        self.assertEqual(status, 200)
        # EnsureContentTypeApplicationOauthAuthzReqJwt is a FAILURE-level condition in the
        # plan, so this header is not cosmetic.
        self.assertEqual(ctype, "application/oauth-authz-req+jwt")
        self.assertEqual(body.decode(), jar)

    def test_an_unknown_state_is_404_and_not_a_500(self):
        status, _, body = _get("%s/request.jwt?state=nonsense" % self.base)
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body)["error"], "not_found")

    def test_a_missing_state_is_404(self):
        status, _, _ = _get("%s/request.jwt" % self.base)
        self.assertEqual(status, 404)

    def test_an_unknown_path_is_404(self):
        for path in ("/", "/admin", "/response.jwt", "/request.jwt/extra"):
            status, _, _ = _get(self.base + path)
            self.assertEqual(status, 404, path)

    def test_the_request_object_survives_a_second_fetch(self):
        session, _ = self.verifier.new_request()
        url = "%s/request.jwt?state=%s" % (self.base, session.state)
        first = _get(url)
        second = _get(url)
        self.assertEqual(first, second)
        self.assertEqual(first[0], 200)

    def test_the_request_object_is_not_to_be_cached(self):
        session, _ = self.verifier.new_request()
        req = urllib.request.Request("%s/request.jwt?state=%s" % (self.base, session.state))
        with urllib.request.urlopen(req, timeout=10) as r:
            self.assertEqual(r.headers.get("Cache-Control"), "no-store")
            self.assertEqual(r.headers.get("Pragma"), "no-cache")

    def test_a_posted_wallet_nonce_reaches_the_request_object(self):
        session, _ = self.verifier.new_request()
        status, ctype, body = _post("%s/request.jwt?state=%s" % (self.base, session.state),
                                    {"wallet_nonce": "w-from-the-wire"})
        self.assertEqual(status, 200)
        self.assertEqual(ctype, "application/oauth-authz-req+jwt")
        _, claims = Wallet.read_request(body.decode())
        self.assertEqual(claims["wallet_nonce"], "w-from-the-wire")

    def test_a_posted_wallet_nonce_out_of_bounds_is_400_and_nothing_is_signed(self):
        """A 2 KiB nonce, or one with a control character, gets 400; 64 bytes still get the
        object carrying them."""
        session, _ = self.verifier.new_request()
        url = "%s/request.jwt?state=%s" % (self.base, session.state)
        for nonce in ("n" * 2048, "w\x01"):
            with self.subTest(length=len(nonce)):
                status, ctype, body = _post(url, {"wallet_nonce": nonce})
                self.assertEqual((status, ctype), (400, "application/json"))
                self.assertEqual(json.loads(body)["error"], "invalid_request")
                self.assertNotIn(b"nnnn", body)
        status, _, body = _post(url, {"wallet_nonce": "n" * 64})
        self.assertEqual(status, 200)
        self.assertEqual(Wallet.read_request(body.decode())[1]["wallet_nonce"], "n" * 64)

    def test_posted_wallet_metadata_that_asks_gets_the_object_encrypted(self):
        """The EUDI iOS wallet kit posts its key in wallet_metadata and refuses a request
        object that is not encrypted to it (lab/interop/eudi-ios, 2026-10-04)."""
        from cryptography.hazmat.primitives.asymmetric import ec
        from polaris_oid4vp.jwe import b64u_encode, decrypt_compact
        key = ec.generate_private_key(ec.SECP256R1())
        n = key.public_key().public_numbers()
        meta = {"jwks": {"keys": [{"kty": "EC", "crv": "P-256", "use": "enc",
                                   "x": b64u_encode(n.x.to_bytes(32, "big")),
                                   "y": b64u_encode(n.y.to_bytes(32, "big"))}]},
                "request_object_encryption_alg_values_supported": ["ECDH-ES"],
                "request_object_encryption_enc_values_supported": ["A128GCM"]}
        session, _ = self.verifier.new_request()
        status, ctype, body = _post("%s/request.jwt?state=%s" % (self.base, session.state),
                                    {"wallet_nonce": "w-wire",
                                     "wallet_metadata": json.dumps(meta)})
        self.assertEqual((status, ctype), (200, "application/oauth-authz-req+jwt"))
        self.assertEqual(len(body.split(b".")), 5)
        _, claims = Wallet.read_request(decrypt_compact(body.decode(), key).decode())
        self.assertEqual(claims["wallet_nonce"], "w-wire")

    def test_a_post_without_a_wallet_nonce_still_serves_the_object(self):
        session, jar = self.verifier.new_request()
        status, _, body = _post("%s/request.jwt?state=%s" % (self.base, session.state), {})
        self.assertEqual(status, 200)
        self.assertEqual(body.decode(), jar)

    def test_wallet_metadata_is_accepted_and_ignored(self):
        """A wallet may post its capabilities. This verifier's do not vary by wallet."""
        session, _ = self.verifier.new_request()
        status, _, body = _post(
            "%s/request.jwt?state=%s" % (self.base, session.state),
            {"wallet_metadata": json.dumps({"vp_formats_supported": {"dc+sd-jwt": {}}}),
             "wallet_nonce": "w-9"})
        self.assertEqual(status, 200)
        self.assertEqual(Wallet.read_request(body.decode())[1]["wallet_nonce"], "w-9")


class ResponseUriTests(ServeTestCase):

    def test_a_good_presentation_is_200_json_with_only_a_redirect_uri(self):
        _, jar = self.verifier.new_request()
        form = self.wallet.respond(jar)
        status, ctype, body = _post(self.base + "/response",
                                    {"response": form["response"][0]})
        self.assertEqual(status, 200)
        self.assertEqual(ctype, "application/json")
        self.assertEqual(set(json.loads(body)), {"redirect_uri"})

    def test_every_conformance_refusal_arrives_as_a_4xx_and_says_nothing_else(self):
        """The decision reaching the wire, which is the only form the plan can score.

        And ONLY that. The bodies must be indistinguishable: a 4xx that names which check
        failed is a per-check oracle, which is what this used to assert the presence of.
        """
        cases = {
            "issuer_signature": {"corrupt_issuer_sig": True},
            "kb_signature": {"corrupt_kb_sig": True},
            "nonce": {"nonce": "not-the-one-we-sent"},
            "audience": {"audience": "x509_hash:somebody-else"},
            "kb_freshness": {"iat": 1},
            "sd_hash": {"sd_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
        }
        bodies = set()
        for code, kw in cases.items():
            _, jar = self.verifier.new_request()
            form = self.wallet.respond(jar, **kw)
            status, ctype, body = _post(self.base + "/response",
                                        {"response": form["response"][0]})
            self.assertEqual(status, 400, "%s answered %d" % (code, status))
            self.assertEqual(ctype, "application/json")
            self.assertEqual(json.loads(body)["error"], "invalid_request")
            self.assertNotIn(code, body.decode(), "%s names itself on the wire" % code)
            bodies.add(body)
        self.assertEqual(len(bodies), 1,
                         "the wire distinguishes %d refusal causes" % len(bodies))

    def test_an_empty_post_is_400_not_500(self):
        status, _, body = _post(self.base + "/response", {})
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["error"], "invalid_request")

    def test_junk_in_the_response_field_is_400_not_500(self):
        for junk in ("", "x", "a.b.c", "not a jwe at all", "\x00\x01\x02"):
            status, _, _ = _post(self.base + "/response", {"response": junk})
            self.assertEqual(status, 400, "%r answered %d" % (junk, status))

    def test_a_body_that_is_not_a_form_is_400_not_500(self):
        req = urllib.request.Request(self.base + "/response", data=b"{}", method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                status = r.status
        except urllib.error.HTTPError as e:
            status = e.code
        self.assertEqual(status, 400)

    def test_a_verifier_that_raises_still_answers_4xx(self):
        """A 5xx tells the wallet to retry, and nothing it can retry will help."""
        cert_pem, key_pem = _client_chain()
        verifier = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                            request_uri="http://127.0.0.1:0/request.jwt",
                            response_uri="http://127.0.0.1:0/response")

        def boom(form):
            raise RuntimeError("a bug in the verifier, not in the wallet")

        verifier.handle_direct_post = boom
        httpd = serve(verifier, host="127.0.0.1", port=0)
        base = "http://127.0.0.1:%d" % httpd.server_address[1]
        try:
            status, ctype, body = _post(base + "/response", {"response": "anything"})
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertEqual(status, 400)
        self.assertEqual(ctype, "application/json")
        self.assertEqual(json.loads(body)["error"], "invalid_request")

    def test_a_verdict_callback_sees_MORE_than_the_wire_did(self):
        seen = []
        cert_pem, key_pem = _client_chain()
        verifier = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                            request_uri="http://127.0.0.1:0/request.jwt",
                            response_uri="http://127.0.0.1:0/response",
                            issuer_jwks=[self.wallet.issuer_jwk])
        httpd = serve(verifier, host="127.0.0.1", port=0,
                      on_verdict=lambda status, body, verdict: seen.append((status, verdict)))
        base = "http://127.0.0.1:%d" % httpd.server_address[1]
        try:
            _, jar = verifier.new_request()
            form = self.wallet.respond(jar)
            _post(base + "/response", {"response": form["response"][0]})
            _, jar = verifier.new_request()
            form = self.wallet.respond(jar, nonce="wrong")
            _post(base + "/response", {"response": form["response"][0]})
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertEqual([s for s, _ in seen], [200, 400])
        self.assertTrue(seen[0][1].authentic)
        # The operator's half of the split: the callback is told the cause the wallet was
        # not. Asserting None here was asserting that nobody was told, which was true only
        # because the cause was going out on the wire instead.
        self.assertFalse(seen[1][1].authentic)
        self.assertEqual(seen[1][1].code, "nonce")

    def test_a_request_object_callback_hears_each_answer_at_the_request_uri(self):
        """200 with the object, 404 for no such request, 400 for a wallet_nonce out of bounds,
        by GET and by POST. `serve --result` counts these, so a walk can tell a wallet that
        fetched and refused the request from one that never reached this verifier."""
        seen = []
        cert_pem, key_pem = _client_chain()
        verifier = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                            request_uri="http://127.0.0.1:0/request.jwt",
                            response_uri="http://127.0.0.1:0/response",
                            issuer_jwks=[self.wallet.issuer_jwk])
        httpd = serve(verifier, host="127.0.0.1", port=0, on_request_object=seen.append)
        base = "http://127.0.0.1:%d" % httpd.server_address[1]
        try:
            session, _ = verifier.new_request()
            url = "%s/request.jwt?state=%s" % (base, session.state)
            answers = [_get(url)[0], _post(url, {"wallet_nonce": "w"})[0],
                       _get(base + "/request.jwt?state=nonsense")[0],
                       _post(url, {"wallet_nonce": "w\x01"})[0],
                       _get(base + "/done")[0], _post(base + "/response", {})[0]]
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertEqual(answers, [200, 200, 404, 400, 404, 400])
        self.assertEqual(seen, [200, 200, 404, 400], "only the request URI's answers, each once")

    def test_each_callback_is_heard_before_its_answer_goes_out(self):
        """A caller that reads what a callback recorded once the wallet has its answer must find
        it there: the wallet's answer waits for the callback, here held until released."""
        import threading
        cert_pem, key_pem = _client_chain()
        verifier = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                            request_uri="http://127.0.0.1:0/request.jwt",
                            response_uri="http://127.0.0.1:0/response",
                            issuer_jwks=[self.wallet.issuer_jwk])
        entered, release = threading.Event(), threading.Event()

        def hold(*_):
            entered.set()
            release.wait(10)
        httpd = serve(verifier, host="127.0.0.1", port=0, on_verdict=hold, on_request_object=hold)
        base = "http://127.0.0.1:%d" % httpd.server_address[1]
        session, _ = verifier.new_request()
        try:
            for name, call in (("request URI", lambda: _get("%s/request.jwt?state=%s"
                                                            % (base, session.state))),
                               ("response URI", lambda: _post(base + "/response", {}))):
                with self.subTest(name):
                    entered.clear()
                    release.clear()
                    answered = threading.Event()
                    threading.Thread(target=lambda: (call(), answered.set()), daemon=True).start()
                    self.assertTrue(entered.wait(10), "the callback was not heard")
                    self.assertFalse(answered.wait(0.5), "the answer went out before the callback "
                                                         "returned")
                    release.set()
                    self.assertTrue(answered.wait(10))
        finally:
            release.set()
            httpd.shutdown()
            httpd.server_close()


class ErrorResponseOnTheWireTests(ServeTestCase):
    """OpenID4VP 1.0 section 8.2, where it is scored: a processed Authorization Error Response
    gets "an HTTP status code of 200 with Content-Type of application/json and a JSON object in
    the response body". Measured on 1.0.0rc18 through this listener: 400, both ways."""

    def test_an_error_in_the_clear_is_200_json_and_leaves_the_request_open(self):
        session, jar = self.verifier.new_request()
        status, ctype, body = _post(self.base + "/response",
                                    {"error": "access_denied", "state": session.state})
        self.assertEqual((status, ctype, json.loads(body)), (200, "application/json", {}))
        form = self.wallet.respond(jar)
        status, _, body = _post(self.base + "/response", {"response": form["response"][0]})
        self.assertEqual((status, set(json.loads(body))), (200, {"redirect_uri"}),
                         "the error in the clear closed the request")

    def test_an_encrypted_error_is_200_json_and_leaves_the_request_open(self):
        _, jar = self.verifier.new_request()
        token = self.wallet.respond_error(jar)["response"][0]
        status, ctype, body = _post(self.base + "/response", {"response": token})
        self.assertEqual((status, ctype, json.loads(body)), (200, "application/json", {}))
        form = self.wallet.respond(jar)
        status, _, body = _post(self.base + "/response", {"response": form["response"][0]})
        self.assertEqual((status, set(json.loads(body))), (200, {"redirect_uri"}),
                         "the encrypted error closed the request")
        status, ctype, body = _post(self.base + "/response", {"response": token})
        self.assertEqual((status, ctype, json.loads(body)),
                         (400, "application/json", Verifier.REFUSAL_BODY))

    def test_an_error_naming_no_outstanding_request_is_the_constant_400(self):
        for form in ({"error": "access_denied", "state": "not-a-request"},
                     {"error": "access_denied"},
                     {"error": "access\x1bdenied", "state": self.verifier.new_request()[0].state}):
            with self.subTest(form=form):
                status, ctype, body = _post(self.base + "/response", form)
                self.assertEqual((status, ctype, json.loads(body)),
                                 (400, "application/json", Verifier.REFUSAL_BODY))

    def test_the_operator_is_told_what_the_wallet_said_and_nothing_else_is(self):
        """The callback gets the record and the log gets one line, with the sender's text as
        printable ASCII: a line break in it cannot forge a second log line."""
        import contextlib
        import io
        seen = []
        cert_pem, key_pem = _client_chain()
        verifier = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                            request_uri="http://127.0.0.1:0/request.jwt",
                            response_uri="http://127.0.0.1:0/response",
                            issuer_jwks=[self.wallet.issuer_jwk])
        httpd = serve(verifier, host="127.0.0.1", port=0,
                      on_verdict=lambda status, body, verdict: seen.append((status, body, verdict)))
        base = "http://127.0.0.1:%d" % httpd.server_address[1]
        session, _ = verifier.new_request()
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                status, _, _ = _post(base + "/response", {
                    "error": "access_denied", "state": session.state,
                    "error_description": "\x1b[31mno\npolaris-oid4vp: refused: forged"})
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertEqual(status, 200)
        ((status, body, verdict),) = seen
        self.assertEqual((status, body, verdict.authentic, verdict.claims), (200, {}, False, {}))
        self.assertEqual(verdict.wallet_error, {
            "error": "access_denied", "error_description": "?[31mno?polaris-oid4vp: refused: forged",
            "state": session.state, "encrypted": False})
        log = err.getvalue()
        self.assertEqual(log.count("\n"), 1, log)
        self.assertNotIn("\x1b", log)
        self.assertIn("polaris-oid4vp: wallet error: access_denied for request %s, which anyone "
                      "who saw the request could send" % session.state, log)


class DonePageTests(ServeTestCase):
    """HAIP 5.1: an accepted response carries only a `redirect_uri`, and a same-device wallet
    follows it. Until 2026-09-28 this listener answered that path 404, measured with OID4VCgo's
    wallet (lab/interop/oid4vcgo/): a presentation that succeeded ended on an error page."""

    def accepted_redirect(self):
        _, jar = self.verifier.new_request()
        form = self.wallet.respond(jar)
        status, _, body = _post(self.base + "/response", {"response": form["response"][0]})
        self.assertEqual(status, 200)
        parts = urllib.parse.urlsplit(json.loads(body)["redirect_uri"])
        return parts.path + "?" + parts.query

    def test_the_redirect_an_accepted_presentation_returns_is_served_once(self):
        """OpenID4VP 1.0 section 8.2: only the receiver of the redirect fetches the result."""
        target = self.accepted_redirect()
        status, ctype, page = _get(self.base + target)
        self.assertEqual(status, 200)
        self.assertTrue(ctype.startswith("text/html"), ctype)
        self.assertIn(b"complete", page)
        self.assertEqual(_get(self.base + target)[0], 404, "a reused response_code was served")

    def test_the_page_needs_the_redirects_own_code(self):
        target = self.accepted_redirect()
        code = urllib.parse.parse_qs(urllib.parse.urlsplit(target).query)["response_code"][0]
        wrong = code[:-1] + ("A" if code[-1] != "A" else "B")
        for asked in ("/done", "/done?response_code=", "/done?response_code=" + wrong,
                      "/done?state=anything&x=1"):
            with self.subTest(asked=asked):
                self.assertEqual(_get(self.base + asked)[0], 404)
        self.assertEqual(_get(self.base + target)[0], 200, "a wrong code spent the right one")

    def test_the_page_varies_with_nothing_else(self):
        """Two accepted responses' pages are the same bytes: the page tells its receiver no more
        than the 200 had."""
        first = _get(self.base + self.accepted_redirect())
        self.assertEqual(first, _get(self.base + self.accepted_redirect()))


def _self_signed_tls(tmp):
    """A throwaway localhost certificate and key, written into tmp."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                           critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = os.path.join(tmp, "cert.pem"), os.path.join(tmp, "key.pem")
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    return cert_path, key_path


class TransportTests(unittest.TestCase):
    """TLS and logging, the two things `serve` does that are not routing."""

    def test_it_serves_over_tls_with_a_self_signed_certificate(self):
        """Which is what the profile requires and what the conformance suite accepted."""
        import datetime
        import ssl
        import tempfile
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        now = datetime.datetime.now(datetime.timezone.utc)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                               critical=False)
                .sign(key, hashes.SHA256()))
        with tempfile.TemporaryDirectory() as tmp:
            cert_path = os.path.join(tmp, "cert.pem")
            key_path = os.path.join(tmp, "key.pem")
            with open(cert_path, "wb") as fh:
                fh.write(cert.public_bytes(serialization.Encoding.PEM))
            with open(key_path, "wb") as fh:
                fh.write(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
            cert_pem, key_pem = _client_chain()
            verifier = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                                request_uri="https://127.0.0.1:0/request.jwt",
                                response_uri="https://127.0.0.1:0/response")
            httpd = serve(verifier, host="127.0.0.1", port=0,
                          certfile=cert_path, keyfile=key_path)
            try:
                session, jar = verifier.new_request()
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                url = "https://127.0.0.1:%d/request.jwt?state=%s" % (
                    httpd.server_address[1], session.state)
                with urllib.request.urlopen(url, context=ctx, timeout=10) as r:
                    self.assertEqual(r.status, 200)
                    self.assertEqual(r.read().decode(), jar)
            finally:
                httpd.shutdown()
                httpd.server_close()

    def test_it_refuses_tls_below_1_2_whatever_the_platform_default(self):
        """Code scanning (py/insecure-protocol, 2026-09-30), then a counterexample: on the macOS
        system Python 3.9 with LibreSSL 2.8.3, which this package supports, a server context
        defaults to TLS 1.0, and `serve` from the published 1.0.0rc9 completed TLS 1.0 and 1.1
        handshakes. Python 3.10 and later default to 1.2, which would hide a missing floor on
        the interpreters CI runs, so the context class is swapped for one with the old default."""
        import socket
        import ssl
        import tempfile
        import types
        from unittest import mock
        import polaris_oid4vp.serve as serve_module
        real = ssl.SSLContext

        class OldDefault(real):
            # The old default twice over: the lowest protocol version, and security level 0, as
            # LibreSSL has. On OpenSSL 3 the default level alone refuses TLS 1.1 whatever serve
            # does, so without the level the handshake half of this test proved nothing there
            # (the review of 2026-09-30 removed the floor assertion and it still passed).
            def __new__(cls, protocol=ssl.PROTOCOL_TLS_SERVER, *args, **kwargs):
                ctx = super().__new__(cls, protocol, *args, **kwargs)
                ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
                try:
                    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
                except ssl.SSLError:
                    pass
                return ctx

        def client(low=None, high=None):
            ctx = real(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if low is not None:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
                ctx.minimum_version, ctx.maximum_version = low, high
            return ctx

        with tempfile.TemporaryDirectory() as tmp:
            cert_path, key_path = _self_signed_tls(tmp)
            cert_pem, key_pem = _client_chain()
            verifier = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                                request_uri="https://127.0.0.1:0/request.jwt",
                                response_uri="https://127.0.0.1:0/response")
            # Only serve's view of the module changes: ssl.py's own properties look the name
            # SSLContext up at call time, so replacing the module global recurses.
            old_ssl = types.SimpleNamespace(**{k: getattr(ssl, k) for k in dir(ssl)
                                               if not k.startswith("__")})
            old_ssl.SSLContext = OldDefault
            with mock.patch.object(serve_module, "ssl", old_ssl):
                httpd = serve(verifier, host="127.0.0.1", port=0,
                              certfile=cert_path, keyfile=key_path)
            try:
                self.assertEqual(httpd.socket.context.minimum_version, ssl.TLSVersion.TLSv1_2,
                                 "the floor must be set by serve, not left to the platform")
                port = httpd.server_address[1]
                with socket.create_connection(("127.0.0.1", port), timeout=10) as raw, \
                        client().wrap_socket(raw) as tls:
                    self.assertIn(tls.version(), ("TLSv1.2", "TLSv1.3"))
                if not ssl.HAS_TLSv1_1:
                    return  # this TLS library cannot offer 1.1 at all; the floor above stands
                try:
                    old = client(ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1)
                except (ssl.SSLError, ValueError):
                    return
                with self.assertRaises((ssl.SSLError, OSError)):
                    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw, \
                            old.wrap_socket(raw):
                        pass
            finally:
                httpd.shutdown()
                httpd.server_close()

    def test_it_is_silent_unless_asked(self):
        """A library writing to a caller's stderr uninvited has to be grepped around."""
        import io
        import contextlib
        cert_pem, key_pem = _client_chain()
        for verbose, expect in ((False, ""), (True, "GET")):
            verifier = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                                request_uri="http://127.0.0.1:0/request.jwt",
                                response_uri="http://127.0.0.1:0/response")
            httpd = serve(verifier, host="127.0.0.1", port=0, verbose=verbose)
            captured = io.StringIO()
            try:
                with contextlib.redirect_stderr(captured):
                    _get("http://127.0.0.1:%d/request.jwt" % httpd.server_address[1])
            finally:
                httpd.shutdown()
                httpd.server_close()
            if expect:
                self.assertIn(expect, captured.getvalue())
            else:
                self.assertEqual(captured.getvalue(), "")

    def test_serve_listens_on_this_machine_only_by_default(self):
        """serve() given no host listens on 127.0.0.1, not on every interface."""
        cert_pem, key_pem = _client_chain()
        verifier = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                            request_uri="http://127.0.0.1:0/request.jwt",
                            response_uri="http://127.0.0.1:0/response")
        httpd = serve(verifier, port=0)
        try:
            self.assertEqual(httpd.server_address[0], "127.0.0.1")
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_a_post_to_an_unknown_path_is_404(self):
        cert_pem, key_pem = _client_chain()
        verifier = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                            request_uri="http://127.0.0.1:0/request.jwt",
                            response_uri="http://127.0.0.1:0/response")
        httpd = serve(verifier, host="127.0.0.1", port=0)
        try:
            status, _, body = _post(
                "http://127.0.0.1:%d/somewhere-else" % httpd.server_address[1], {"a": "b"})
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body)["error"], "not_found")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class BodyFramingTests(ServeTestCase):
    """Content-Length, which `int()` was parsing and HTTP does not define that way.

    Three defects lived in one unguarded `int()`, all measured 2026-09-17 against a raw
    socket rather than through urllib, because urllib will not send a malformed header.
    """

    def _raw(self, headers, body=b"", read_timeout=4.0, hold=False):
        """One request on a bare socket. Returns the status line, or None for no answer."""
        import socket
        host, port = self.httpd.server_address[0], self.httpd.server_address[1]
        s = socket.create_connection((host, port), timeout=read_timeout)
        s.settimeout(read_timeout)
        s.sendall(("POST /response HTTP/1.1\r\nHost: x\r\n%s\r\n" % headers).encode() + body)
        if hold:
            return s
        try:
            data = s.recv(128)
            return data.split(b"\r\n")[0].decode() if data else None
        except (OSError, socket.timeout):
            return None
        finally:
            s.close()

    def _still_serving(self, timeout=4.0):
        """Can anybody else get an answer right now?"""
        import socket
        host, port = self.httpd.server_address[0], self.httpd.server_address[1]
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.settimeout(timeout)
            s.sendall(b"GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            data = s.recv(64)
            s.close()
            return bool(data)
        except (OSError, socket.timeout):
            return False

    def test_a_negative_content_length_does_not_take_the_listener_off_the_air(self):
        """THE ONE THAT MATTERED. `int()` accepts -1 and `rfile.read(-1)` reads to EOF, so
        one socket that never closed held the single accept loop forever: every wallet got
        nothing, for one TCP connection and no credential."""
        self.assertTrue(self._still_serving(), "control: the listener answers before this")
        held = self._raw("Content-Length: -1\r\n", b"response=x", hold=True)
        try:
            self.assertTrue(self._still_serving(),
                            "a held connection with Content-Length: -1 stopped every other "
                            "client from being answered")
            self.assertTrue(self._still_serving(), "and the second one after it")
        finally:
            held.close()

    def test_a_huge_declared_body_is_refused_before_it_is_read(self):
        """The ATTACKER's own answer is the assertion, not whether anybody else is served.

        Checking only that other clients are still answered is satisfied by the threading
        alone, so removing this bound passed. The bound's own contribution is that the
        gigabyte is refused BEFORE a byte of it is read: the sender gets 413 immediately
        rather than the connection sitting open while the server waits for a body that will
        never arrive.
        """
        line = self._raw("Content-Length: %d\r\n" % (MAX_BODY_BYTES + 1), b"hello")
        self.assertIsNotNone(line, "an oversized body must be answered, not left hanging")
        self.assertIn("413", line,
                      "a body over the bound must be refused on the DECLARED length; "
                      "reading it first and judging afterwards is the same denial of "
                      "service with an extra step")
        self.assertTrue(self._still_serving())

    def test_a_body_at_the_bound_is_still_accepted(self):
        """The other direction. A bound that refused everything would pass the test above
        while making the verifier useless."""
        body = b"response=" + b"x" * (MAX_BODY_BYTES - 100)
        line = self._raw("Content-Length: %d\r\n" % len(body), body, read_timeout=10)
        self.assertIsNotNone(line)
        self.assertIn("400", line, "a body under the bound reaches the verifier and is "
                                   "refused on its CONTENT, not its size")

    def test_a_body_shorter_than_its_declared_length_is_refused_as_truncated(self):
        """The client declares more than it sends and stops. The server must say so rather
        than parse the fragment as a whole form. 2026-09-23: removing this guard survived,
        because the fragment is refused by the verifier anyway and both answers are a 400;
        only the reason tells them apart, so the reason is asserted."""
        import socket
        host, port = self.httpd.server_address[0], self.httpd.server_address[1]
        s = socket.create_connection((host, port), timeout=6)
        s.settimeout(6)
        s.sendall(b"POST /response HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nresponse=x")
        s.shutdown(socket.SHUT_WR)
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except (OSError, socket.timeout):
            pass
        finally:
            s.close()
        text = data.decode("utf-8", "replace")
        self.assertIn(" 400 ", text.split("\r\n")[0])
        self.assertIn("shorter than Content-Length", text)

    def test_a_short_body_of_invalid_utf8_is_still_refused_as_truncated(self):
        """The truncation check once compared a re-encoded decode: each invalid byte became
        U+FFFD, three bytes, so 35 bytes sent against 75 declared passed as whole and reached
        the handler. The raw byte count is what is compared now."""
        import socket
        host, port = self.httpd.server_address[0], self.httpd.server_address[1]
        s = socket.create_connection((host, port), timeout=6)
        s.settimeout(6)
        body = b"response=abc&x=" + b"\xff" * 20
        s.sendall(b"POST /response HTTP/1.1\r\nHost: x\r\nContent-Length: 75\r\n\r\n" + body)
        s.shutdown(socket.SHUT_WR)
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except (OSError, socket.timeout):
            pass
        finally:
            s.close()
        text = data.decode("utf-8", "replace")
        self.assertIn(" 400 ", text.split("\r\n")[0])
        self.assertIn("shorter than Content-Length", text)

    def test_a_non_numeric_content_length_is_answered_rather_than_dropped(self):
        """`int('abc')` raised out of do_POST and the connection closed with no response at
        all, which a wallet reads as a network fault rather than as a refusal."""
        for value in ("abc", "0x10", "", "  "):
            with self.subTest(value=repr(value)):
                line = self._raw("Content-Length: %s\r\n" % value)
                self.assertIsNotNone(line, "no answer at all for Content-Length: %r" % value)
                self.assertIn("400", line)

    def test_a_sign_or_underscore_is_not_read_as_a_number(self):
        """HTTP allows DIGIT+ only. `int()` also takes `+9` and `1_0`, so this server's idea
        of where a body ended differed from any conforming proxy in front of it, which is
        the shape of a request smuggling bug."""
        for value in ("+9", "1_0", "-0"):
            with self.subTest(value=repr(value)):
                line = self._raw("Content-Length: %s\r\n" % value, b"response=x")
                self.assertIsNotNone(line)
                self.assertIn("400", line)

    def test_a_slow_client_that_never_finishes_does_not_block_anyone_else(self):
        """The THREADING mechanism on its own, with nothing else standing in for it.

        Every other test here is satisfied by the Content-Length guard alone, so removing
        `ThreadingHTTPServer` passed all of them: two mechanisms, each masking the other's
        absence. This client sends a well-formed header and then simply stops, which the
        guard cannot refuse because there is nothing wrong with it. On a single accept loop
        it takes the listener off the air for everybody.
        """
        import socket
        host, port = self.httpd.server_address[0], self.httpd.server_address[1]
        slow = socket.create_connection((host, port), timeout=5)
        try:
            slow.sendall(b"POST /response HTTP/1.1\r\nHost: x\r\nContent-Length: 4000\r\n\r\n")
            slow.sendall(b"resp")   # four of the four thousand bytes, then silence
            self.assertTrue(self._still_serving(),
                            "one client that stops mid-body stopped every other client "
                            "from being served")
        finally:
            slow.close()


    def test_an_honest_request_still_works(self):
        """The direction that keeps the rest honest: a listener refusing everything would
        pass every test above."""
        status, _, _ = _post(self.base + "/response", {"response": "not-a-jwe"})
        self.assertEqual(status, 400)
        self.assertTrue(self._still_serving())


class HeldOutListenerTests(ServeTestCase):
    """A held-out round on 2026-09-24: of twelve mutations of serve.py, six survived every
    test in the package. Each test below is the one input that separates a mutant from the
    listener as written.

    Two of the seven are equivalent and have no test: deleting `close_connection = True` from
    the bad-Content-Length and oversized-body refusals. `BaseHTTPRequestHandler` answers as
    HTTP/1.0 unless told otherwise, and closes after every response, so no client can tell
    the difference. Measured: an ordinary 400 on an HTTP/1.1 request is followed by EOF too.
    The lines stay, because they state the intent and would matter under keep-alive.
    """

    _raw = BodyFramingTests._raw

    def test_a_body_of_exactly_the_bound_is_accepted(self):
        """The bound is inclusive. The test above sat 100 bytes under it, where `>=` and `>`
        agree."""
        body = b"response=" + b"x" * (MAX_BODY_BYTES - len(b"response="))
        self.assertEqual(len(body), MAX_BODY_BYTES)
        line = self._raw("Content-Length: %d\r\n" % len(body), body, read_timeout=10)
        self.assertIsNotNone(line)
        self.assertIn("400", line, "a body of exactly the bound was refused on its size")

    def test_a_path_that_starts_like_the_request_uri_is_not_it(self):
        """With a state that IS outstanding. The unknown-path test above sends none, so a
        prefix match there still ends in 404, from the missing state rather than the path."""
        session, _ = self.verifier.new_request()
        status, _, _ = _get("%s/request.jwt?state=%s" % (self.base, session.state))
        self.assertEqual(status, 200, "control: the state is outstanding")
        for path in ("/request.jwtx", "/request.jwt/", "/request.jwt.bak"):
            with self.subTest(path=path):
                status, _, _ = _get("%s%s?state=%s" % (self.base, path, session.state))
                self.assertEqual(status, 404)

    def test_the_operator_log_names_the_refusal(self):
        """The wallet is told nothing; the log is the only place the reason goes."""
        import contextlib
        import io
        _, jar = self.verifier.new_request()
        form = self.wallet.respond(jar, nonce="wrong")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            status, _, _ = _post(self.base + "/response", {"response": form["response"][0]})
        self.assertEqual(status, 400)
        self.assertIn("refused: nonce", err.getvalue())

    def test_the_verdict_callback_hears_about_a_verifier_that_raised(self):
        """The operator is told every answer, including the one with no verdict behind it."""
        import contextlib
        import io
        seen = []
        cert_pem, key_pem = _client_chain()
        verifier = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                            request_uri="http://127.0.0.1:0/request.jwt",
                            response_uri="http://127.0.0.1:0/response")

        def boom(form):
            raise RuntimeError("a bug in the verifier")

        verifier.handle_direct_post = boom
        httpd = serve(verifier, host="127.0.0.1", port=0,
                      on_verdict=lambda status, body, verdict: seen.append((status, verdict)))
        base = "http://127.0.0.1:%d" % httpd.server_address[1]
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                _post(base + "/response", {"response": "anything"})
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertEqual(seen, [(400, None)])

    def test_a_client_that_goes_quiet_is_hung_up_on(self):
        """The read timeout is what frees a thread a silent client holds. Checked in two
        halves, because waiting out the real twenty seconds in every run is not worth it:
        the value is finite and modest, and a handler with a short one really does close."""
        from polaris_oid4vp.serve import _Handler
        self.assertIsNotNone(_Handler.timeout)
        self.assertLessEqual(_Handler.timeout, 60)
        cert_pem, key_pem = _client_chain()
        verifier = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                            request_uri="http://127.0.0.1:0/request.jwt",
                            response_uri="http://127.0.0.1:0/response")
        httpd = serve(verifier, host="127.0.0.1", port=0)
        httpd.RequestHandlerClass.timeout = 1
        import socket
        import time
        try:
            s = socket.create_connection(httpd.server_address[:2], timeout=6)
            s.settimeout(6)
            s.sendall(b"POST /response HTTP/1.1\r\nHost: x\r\nContent-Length: 50\r\n\r\nresp")
            start = time.monotonic()
            try:
                while s.recv(4096):
                    pass
            except (OSError, socket.timeout):
                pass
            elapsed = time.monotonic() - start
            s.close()
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertLess(elapsed, 5, "a silent client held its connection past the timeout")


class ContentLengthParsingTests(unittest.TestCase):
    """`_content_length` on its own.

    Through the socket, every malformed value ends in the same 400 whether the digit check
    is there or not, because the `int()` below it raises ValueError and that is caught too.
    So the socket tests could not see this guard go. Here the return value is the assertion.
    """

    def test_only_a_run_of_digits_is_a_length(self):
        self.assertEqual(_content_length({"Content-Length": "9"}), 9)
        self.assertEqual(_content_length({"Content-Length": " 9 "}), 9)
        self.assertEqual(_content_length({"Content-Length": "0"}), 0)

    def test_an_absent_header_means_no_body(self):
        self.assertEqual(_content_length({}), 0)

    def test_everything_HTTP_does_not_allow_is_refused(self):
        for value in ("-1", "+9", "1_0", "-0", "abc", "0x10", "", "  ", "9.0", "9 9", "١٢"):
            with self.subTest(value=repr(value)):
                self.assertIsNone(_content_length({"Content-Length": value}),
                                  "%r must not be read as a length" % value)

    def test_the_bound_is_a_real_number_of_bytes(self):
        self.assertGreater(MAX_BODY_BYTES, 64 * 1024,
                           "the bound must leave room for a real presentation")
        self.assertLess(MAX_BODY_BYTES, 64 * 1024 * 1024,
                        "a bound this high is not a bound")


# ---------------------------------------------------------------------------------------- CORS
#
# `serve(cors_origins=...)`, for a wallet that runs in a browser page. Every positive test names
# its twin: the same request with the one thing changed that must take the headers away.

#: The list the CORS listener serves: a name, and an address with a port, as a wallet page on a
#: developer's machine has.
CORS_LISTED = ("https://wallet.example", "http://127.0.0.1:8080")

#: Refused when the list is given, by cors_origin, serve() and the CLI (exit 2): (value, reason).
CORS_REFUSED_AT_STARTUP = (
    ("ftp://wallet.example", "a scheme other than http or https"),
    ("wallet.example", "no scheme"),
    ("", "an empty value"),
    ("null", "null, the origin of an opaque page"),
    ("https://wallet.exämple", "a host outside ASCII"),
    ("https://wallet .example", "a space"),
    ("https://wallet.example\t", "a control character"),
    ("https://wal%6cet.example", "a percent escape, which a browser decodes"),
    ("https://wallet<.example", "<, which the URL Standard forbids in a host"),
    ("https://wallet>.example", ">, which the URL Standard forbids in a host"),
    ("https://wallet^.example", "^, which the URL Standard forbids in a host"),
    ("https://wallet|.example", "|, which the URL Standard forbids in a host"),
    ("https://wallet.example\x7f", "DEL, which the URL Standard forbids in a host"),
    ("https://user@wallet.example", "user information"),
    ("https://wallet.example/", "a bare slash"),
    ("https://wallet.example/app", "a path"),
    ("https://wallet.example\\app", "a backslash, a path to a browser"),
    ("https://wallet.example?x=1", "a query"),
    ("https://wallet.example#top", "a fragment"),
    ("https://wallet.example,https://other.example", "two origins in one value"),
    ("https://", "no host"),
    ("https://:8443", "a port and no host"),
    ("https://wallet.example:65536", "a port above 65535"),
    ("https://wallet.example:123456", "a port of six digits"),
    ("https://wallet.example:" + "9" * 5000, "a port of five thousand digits"),
    ("https://wallet.example:+1", "a port with a sign"),
    ("https://wallet.example:8x", "a port that is not digits"),
    ("https://wallet.example:443:443", "two ports"),
    ("https://[::1", "an IPv6 address not closed"),
    ("https://[1::2::3]", "brackets around what is not an IPv6 address"),
    ("http://[::ffff:7f00:1]", "an IPv4-mapped IPv6 address"),
    ("http://[::FFFF:127.0.0.1]:8080", "an IPv4-mapped IPv6 address written with a dotted tail"),
    ("http://[::ffff:0:1]", "an IPv4-mapped IPv6 address of 0.0.0.1"),
    ("http://127.1:3000", "an IPv4 address in short form, 127.0.0.1 to a browser"),
    ("http://0x7f.0.0.1", "an IPv4 part in hexadecimal"),
    ("http://127.0.0.0x1", "an IPv4 address whose last part is hexadecimal"),
    ("http://127.000.0.1", "an IPv4 part with a leading zero, octal to a browser"),
    ("http://127.0.0.1.", "an IPv4 address with a trailing dot, which a browser drops"),
    ("http://256.0.0.1", "an IPv4 part above 255"),
    ("http://1.2.3." + "9" * 5000, "an IPv4 part of five thousand digits"),
    ("http://127.0.1", "an IPv4 address of three parts"),
    ("http://wallet.123", "a name ending in a number, which a browser reads as IPv4"),
    (None, "not a string"),
    (443, "a number, not a string"),
    (b"https://wallet.example", "bytes, not a string"),
)

#: Accepted, and kept as a browser writes it in its Origin header: (given, kept, reason). Each
#: kept form is the origin the URL Standard's parser gives for the given one (Node 24.11.1's
#: URL, 2026-11-17).
CORS_KEPT = (
    ("https://wallet.example", "https://wallet.example", "as a browser writes it already"),
    ("HTTPS://Wallet.Example:443", "https://wallet.example",
     "lowercased, https's default port dropped"),
    ("http://wallet.example:80", "http://wallet.example", "http's default port dropped"),
    ("http://wallet.example:443", "http://wallet.example:443", "443 is not http's default port"),
    ("https://wallet.example:8443", "https://wallet.example:8443", "another port kept"),
    ("https://wallet.example:08443", "https://wallet.example:8443", "a port's leading zero dropped"),
    ("https://wallet.example:0000000443", "https://wallet.example",
     "leading zeros, then the default port"),
    ("https://wallet.example:", "https://wallet.example", "an empty port is the default"),
    ("https://wallet.example:0", "https://wallet.example:0", "port 0 kept"),
    ("https://wallet.example.", "https://wallet.example.", "a name's trailing dot kept"),
    ("http://localhost:3000", "http://localhost:3000", "a name with no dot"),
    ("http://127.0.0.1:8080", "http://127.0.0.1:8080", "an IPv4 address as a browser writes it"),
    ("http://[::1]:8080", "http://[::1]:8080", "an IPv6 address as a browser writes it"),
    ("http://[0:0::1]:8080", "http://[::1]:8080", "an IPv6 address compressed"),
    ("http://[2001:DB8::A]", "http://[2001:db8::a]", "IPv6 hexadecimal lowercased"),
    ("http://[::1.2.3.4]", "http://[::102:304]", "an IPv4 tail that is not mapped, in hexadecimal"),
    ("http://[1:0:0:2:0:0:3:4]", "http://[1::2:0:0:3:4]", "the first of two equal zero runs"),
    ("http://[1:0:0:2:0:0:0:4]", "http://[1:0:0:2::4]", "the longest zero run"),
    ("http://[1:0:2:3:4:5:6:7]", "http://[1:0:2:3:4:5:6:7]", "one zero piece is not a run"),
    ("http://[0:0:0:0:0:0:0:0]", "http://[::]", "every piece zero"),
    ("http://[2001:DB8::0001]", "http://[2001:db8::1]", "a piece's leading zeros dropped"),
    ("*", "*", "every origin"),
)

#: Sent in an Origin header to the listener serving CORS_LISTED, and answered with Vary alone,
#: no Access-Control-Allow-Origin: (sent, reason). The twin of each is a listed origin, answered.
CORS_MUST_NOT_MATCH = (
    ("https://wallet.example.evil.test", "the listed origin as the start of another host"),
    ("https://evilwallet.example", "the listed host as the end of another"),
    ("https://wallet.example:8443", "the listed host on another port"),
    ("http://wallet.example", "the listed host under another scheme"),
    ("http://127.0.0.1:8081", "the listed address on another port"),
    ("http://127.0.0.1", "the listed address on the default port"),
    ("https://WALLET.EXAMPLE", "the listed host in upper case, which no browser sends"),
    ("https://wallet.example.", "the listed host with a trailing dot"),
    ("https://wallet.example/app", "the listed origin with a path"),
    ("https://wallet.example, https://evil.test", "two origins in one header"),
    ("null", "the origin of an opaque page"),
    ("", "an empty Origin"),
)


def _send_raw(httpd, raw):
    """`raw` on a bare socket, and everything the listener sends back until it closes."""
    import socket
    s = socket.create_connection(httpd.server_address[:2], timeout=10)
    try:
        s.sendall(raw)
        answer, chunk = b"", s.recv(65536)
        while chunk:
            answer, chunk = answer + chunk, s.recv(65536)
        return answer
    finally:
        s.close()


def _exchange(httpd, method, path, headers=(), body=b"", declare=None):
    """One request as written, on a bare socket: urllib adds headers of its own and will not send
    a preflight as a browser does, and these tests need the request exactly as given and every
    header of the answer. `declare` sends a Content-Length other than the body's."""
    lines = ["%s %s HTTP/1.1" % (method, path), "Host: 127.0.0.1"]
    lines += ["%s: %s" % header for header in headers]
    if declare is not None or body or method == "POST":
        lines.append("Content-Length: %d" % (len(body) if declare is None else declare))
    return _send_raw(httpd, ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)


def _parse(raw):
    """(status, [(name, value), ...] in the order sent, body)."""
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    return int(lines[0].split()[1]), [tuple(line.split(": ", 1)) for line in lines[1:]], body


def _cors(headers):
    """The answer's Access-Control-* headers and its Vary, sorted: what the option adds."""
    return sorted((name, value) for name, value in headers
                  if name.lower().startswith("access-control-") or name.lower() == "vary")


def _without_date(raw):
    """The answer with its Date header cut, the one header two answers a second apart differ by."""
    return re.sub(rb"\r\nDate: [^\r]*", b"", raw)


class CorsTestCase(ServeTestCase):
    """Three listeners on one verifier: ServeTestCase's, without the option; one serving
    CORS_LISTED; one serving `*`. Each answers a request the verifier issued, so a test can put
    the twin of each request beside it."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.cors = serve(cls.verifier, host="127.0.0.1", port=0, cors_origins=list(CORS_LISTED))
        cls.star = serve(cls.verifier, host="127.0.0.1", port=0, cors_origins=["*"])

    @classmethod
    def tearDownClass(cls):
        for httpd in (cls.cors, cls.star):
            httpd.shutdown()
            httpd.server_close()
        super().tearDownClass()

    def _request_object(self):
        """A fetch of a fresh request's object: (status, label, method, path, body, declared)."""
        state = self.verifier.new_request()[0].state
        return (200, "the request object", "GET", "/request.jwt?state=%s" % state, b"", None)

    def _requests(self):
        """One request for each answer the two paths give, fresh where the verifier spends one."""
        _, jar = self.verifier.new_request()
        accepted = urllib.parse.urlencode({"response": self.wallet.respond(jar)["response"][0]})
        return [
            self._request_object(),
            (200, "the request object by POST", "POST",
             "/request.jwt?state=%s" % self.verifier.new_request()[0].state, b"", None),
            (404, "an unknown state", "GET", "/request.jwt?state=nope", b"", None),
            (400, "a wallet_nonce too long", "POST",
             "/request.jwt?state=%s" % self.verifier.new_request()[0].state,
             b"wallet_nonce=" + b"x" * 1025, None),
            (200, "an accepted presentation", "POST", "/response", accepted.encode(), None),
            (400, "an empty response", "POST", "/response", b"", None),
            (400, "an empty response, a query on the path", "POST", "/response?x=1", b"", None),
            (413, "a body over the bound", "POST", "/response", b"", MAX_BODY_BYTES + 1),
        ]

    def _ask(self, httpd, request, headers=()):
        status, label, method, path, body, declare = request
        got = _parse(_exchange(httpd, method, path, headers, body, declare))
        self.assertEqual(got[0], status, "%s answered %d" % (label, got[0]))
        return got


class CorsOffTests(CorsTestCase):
    """The option absent: the listener as it was before the option existed."""

    def test_without_the_option_no_answer_carries_a_cors_header(self):
        """Twin: test_a_listed_origin_is_answered_on_every_status, the same requests to the
        listener with the option. Each carries a listed Origin and a preflight's
        Access-Control-Request-Method; /done, another path and OPTIONS are asked too."""
        preflight = [("Origin", CORS_LISTED[0]), ("Access-Control-Request-Method", "POST")]
        requests = self._requests() + [
            (404, "/done", "GET", "/done?response_code=x", b"", None),
            (404, "another path", "GET", "/nope", b"", None),
            (501, "OPTIONS on the request URI", "OPTIONS", "/request.jwt", b"", None),
            (501, "OPTIONS on the response URI", "OPTIONS", "/response", b"", None),
        ]
        for request in requests:
            with self.subTest(request=request[1]):
                _, headers, _ = self._ask(self.httpd, request, preflight)
                self.assertEqual(_cors(headers), [])

    def test_without_the_option_the_handler_holds_no_cors_code(self):
        """cors_origins absent, None, an empty list or an empty tuple: the handler serve() builds
        derives from _Handler alone, with no do_OPTIONS. Twin: given origins, it derives from
        _CorsHandler."""
        for given in ({}, {"cors_origins": None}, {"cors_origins": []}, {"cors_origins": ()}):
            with self.subTest(given=given):
                httpd = serve(self.verifier, host="127.0.0.1", port=0, **given)
                try:
                    handler = httpd.RequestHandlerClass
                    self.assertEqual(handler.__bases__, (_Handler,))
                    self.assertFalse(hasattr(handler, "do_OPTIONS"))
                    self.assertNotIn("cors_origins", vars(handler))
                finally:
                    httpd.shutdown()
                    httpd.server_close()
        self.assertEqual(self.cors.RequestHandlerClass.__bases__, (_CorsHandler,))
        self.assertEqual(self.cors.RequestHandlerClass.cors_origins, CORS_LISTED)


class CorsTests(CorsTestCase):
    """The option given: what each answer on the two paths carries, by Origin."""

    def test_a_listed_origin_is_answered_on_every_status(self):
        """Access-Control-Allow-Origin naming the origin, and Vary: Origin, on every answer of the
        two paths, refusals included, and nothing else. Twins:
        test_an_unlisted_origin_is_answered_with_vary_alone (another origin);
        test_no_origin_header_gets_the_answer_without_the_option (no Origin);
        test_without_the_option_no_answer_carries_a_cors_header (the option off)."""
        for origin in CORS_LISTED:
            for request in self._requests():
                with self.subTest(origin=origin, request=request[1]):
                    _, headers, _ = self._ask(self.cors, request, [("Origin", origin)])
                    self.assertEqual(_cors(headers), [("Access-Control-Allow-Origin", origin),
                                                      ("Vary", "Origin")])

    def test_an_unlisted_origin_is_answered_with_vary_alone(self):
        """Twin: test_a_listed_origin_is_answered_on_every_status."""
        for request in self._requests():
            with self.subTest(request=request[1]):
                _, headers, _ = self._ask(self.cors, request, [("Origin", "https://other.example")])
                self.assertEqual(_cors(headers), [("Vary", "Origin")])

    def test_no_origin_header_gets_the_answer_without_the_option(self):
        """With no Origin header the listener with the option answers byte for byte as the one
        without, the Date aside. A request object is signed afresh for each fetch and an accepted
        presentation's redirect carries a fresh code, so for those the status and the headers
        but Content-Length are compared. Twin: test_a_listed_origin_is_answered_on_every_status,
        the same requests with an Origin."""
        fresh = {"the request object", "the request object by POST", "an accepted presentation"}
        for on, off in zip(self._requests(), self._requests()):
            with self.subTest(request=on[1]):
                with_option = _without_date(_exchange(self.cors, on[2], on[3], (), on[4], on[5]))
                without = _without_date(_exchange(self.httpd, off[2], off[3], (), off[4], off[5]))
                if on[1] not in fresh:
                    self.assertEqual(with_option, without)
                    continue
                status_on, headers_on, _ = _parse(with_option)
                status_off, headers_off, _ = _parse(without)
                self.assertEqual(
                    (status_on, [h for h in headers_on if h[0] != "Content-Length"]),
                    (status_off, [h for h in headers_off if h[0] != "Content-Length"]))

    def test_a_path_that_is_not_one_of_the_two_never_carries_cors(self):
        """/done, served and not, another path, and paths that start like the two: no CORS header
        and no Vary, for a listed Origin with a preflight's request method. Twin:
        test_a_listed_origin_is_answered_on_every_status, the two paths."""
        _, jar = self.verifier.new_request()
        accepted = urllib.parse.urlencode({"response": self.wallet.respond(jar)["response"][0]})
        redirect = json.loads(_parse(_exchange(self.httpd, "POST", "/response", (),
                                               accepted.encode()))[2])["redirect_uri"]
        done = urllib.parse.urlsplit(redirect)
        asked = [(200, "GET", "%s?%s" % (done.path, done.query)),
                 (404, "GET", "/done?response_code=x"), (404, "GET", "/nope"),
                 (404, "POST", "/nope"), (404, "GET", "/request.jwt/"), (404, "GET", "/request.jwtx"),
                 (404, "POST", "/response/x"), (404, "POST", "/responsex"),
                 (501, "OPTIONS", "/done"), (501, "OPTIONS", "/nope")]
        headers = [("Origin", CORS_LISTED[0]), ("Access-Control-Request-Method", "POST")]
        for status, method, path in asked:
            with self.subTest(method=method, path=path):
                got = _parse(_exchange(self.cors, method, path, headers))
                self.assertEqual(got[0], status)
                self.assertEqual(_cors(got[1]), [])

    def test_a_preflight_from_a_listed_origin_gets_its_paths_methods(self):
        """204 and no body, with the path's methods, the request headers a wallet sends,
        Allow-Origin naming the origin and Vary. Twins:
        test_a_preflight_from_an_unlisted_origin_allows_nothing (another origin);
        test_an_options_that_is_not_a_preflight_is_501 (no request method, or no Origin);
        test_without_the_option_no_answer_carries_a_cors_header (the option off: 501)."""
        for origin in CORS_LISTED:
            for path, methods in (("/request.jwt", "GET, POST"), ("/request.jwt?state=x", "GET, POST"),
                                  ("/response", "POST")):
                with self.subTest(origin=origin, path=path):
                    status, headers, body = _parse(_exchange(self.cors, "OPTIONS", path, [
                        ("Origin", origin), ("Access-Control-Request-Method", "POST"),
                        ("Access-Control-Request-Headers", "content-type")]))
                    self.assertEqual((status, body), (204, b""))
                    self.assertEqual(_cors(headers), [
                        ("Access-Control-Allow-Headers", "Content-Type, Accept"),
                        ("Access-Control-Allow-Methods", methods),
                        ("Access-Control-Allow-Origin", origin), ("Vary", "Origin")])

    def test_a_preflight_from_an_unlisted_origin_allows_nothing(self):
        """204 with Vary alone: no Access-Control-Allow-Origin, -Methods or -Headers, so nothing
        in it allows, and the browser's CORS check refuses on the missing Allow-Origin. Twin:
        test_a_preflight_from_a_listed_origin_gets_its_paths_methods."""
        for path in ("/request.jwt", "/response"):
            for origin in ("https://other.example", "https://wallet.example.evil.test"):
                with self.subTest(path=path, origin=origin):
                    status, headers, body = _parse(_exchange(self.cors, "OPTIONS", path, [
                        ("Origin", origin), ("Access-Control-Request-Method", "POST")]))
                    self.assertEqual((status, body), (204, b""))
                    self.assertEqual(_cors(headers), [("Vary", "Origin")])

    def test_an_options_that_is_not_a_preflight_is_501(self):
        """Without Access-Control-Request-Method, or without Origin, an OPTIONS is not a preflight
        and gets the 501 the listener without the option gives every OPTIONS, the same body; on
        the two paths it carries Allow-Origin and Vary for a listed Origin, as every answer there
        does. Twin: test_a_preflight_from_a_listed_origin_gets_its_paths_methods."""
        for path in ("/request.jwt", "/response"):
            with self.subTest(path=path, asked="Origin and no request method"):
                origin = [("Origin", CORS_LISTED[0])]
                status, headers, body = _parse(_exchange(self.cors, "OPTIONS", path, origin))
                self.assertEqual(status, 501)
                self.assertEqual(_cors(headers), [("Access-Control-Allow-Origin", CORS_LISTED[0]),
                                                  ("Vary", "Origin")])
                self.assertEqual(body, _parse(_exchange(self.httpd, "OPTIONS", path, origin))[2])
            with self.subTest(path=path, asked="a request method and no Origin"):
                method = [("Access-Control-Request-Method", "POST")]
                self.assertEqual(_without_date(_exchange(self.cors, "OPTIONS", path, method)),
                                 _without_date(_exchange(self.httpd, "OPTIONS", path, method)))

    def test_star_answers_every_origin_with_star(self):
        """`*` alone: Allow-Origin `*` and Vary for every Origin, preflight included. Twins:
        test_an_unlisted_origin_is_answered_with_vary_alone (a list answers its own origins);
        and below, `*` with no Origin header adds nothing."""
        for origin in ("https://wallet.example", "https://anything.example", "null"):
            with self.subTest(origin=origin):
                _, headers, _ = self._ask(self.star, self._request_object(), [("Origin", origin)])
                self.assertEqual(_cors(headers), [("Access-Control-Allow-Origin", "*"),
                                                  ("Vary", "Origin")])
                status, headers, _ = _parse(_exchange(self.star, "OPTIONS", "/response", [
                    ("Origin", origin), ("Access-Control-Request-Method", "POST")]))
                self.assertEqual(status, 204)
                self.assertEqual(_cors(headers), [
                    ("Access-Control-Allow-Headers", "Content-Type, Accept"),
                    ("Access-Control-Allow-Methods", "POST"),
                    ("Access-Control-Allow-Origin", "*"), ("Vary", "Origin")])
        _, headers, _ = self._ask(self.star, self._request_object())
        self.assertEqual(_cors(headers), [], "`*` and no Origin header")

    def test_a_request_that_fails_to_parse_carries_no_cors_header(self):
        """414 for a request line too long, 400 for a bad one and 431 for too many headers, on
        the request URI, with a listed Origin where one can be read: the bytes the listener
        without the option sends, and no exception in the handler. Twin:
        test_a_listed_origin_is_answered_on_every_status."""
        import contextlib
        import io
        origin = "Origin: %s\r\n" % CORS_LISTED[0]
        line = "GET /request.jwt?state="
        raws = {
            # Exactly the 65537 bytes the listener reads before it answers 414, and no more, so
            # nothing is left unread when it closes.
            414: (line + "x" * (65537 - len(line))).encode(),
            # Four words: the version is read (so the answer has a status line) and the path is not.
            400: ("GET /request.jwt x HTTP/1.1\r\n%s\r\n" % origin).encode(),
            431: ("GET /request.jwt HTTP/1.1\r\n%s%s\r\n" % (origin, "X-N: 1\r\n" * 101)).encode(),
        }
        for status, raw in raws.items():
            with self.subTest(status=status):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    answer = _send_raw(self.cors, raw)
                    unchanged = _send_raw(self.httpd, raw)
                self.assertEqual(_parse(answer)[0], status)
                self.assertEqual(_without_date(answer), _without_date(unchanged))
                self.assertNotIn("Traceback", stderr.getvalue())


class CorsDecisionPerRequestTests(CorsTestCase):
    """The handler decides whether a CORS answer is due for each request it parses."""

    def _parsed(self, origin, left_over):
        """A handler of the listener with the option, holding `left_over` as an earlier request on
        it would have left it, after parsing a request to the request URI with `origin` (None:
        no Origin header)."""
        import io
        handler = object.__new__(self.cors.RequestHandlerClass)
        handler._cors_due = left_over
        handler.client_address = ("127.0.0.1", 0)
        handler.raw_requestline = b"GET /request.jwt?state=x HTTP/1.1\r\n"
        head = "Host: 127.0.0.1\r\n" + ("Origin: %s\r\n" % origin if origin else "")
        handler.rfile = io.BytesIO((head + "\r\n").encode("latin-1"))
        handler.wfile = io.BytesIO()
        self.assertTrue(handler.parse_request())
        return handler._cors_due

    def test_a_request_without_an_origin_is_due_nothing_an_earlier_one_was(self):
        """Twin: the same request with an Origin is due its own answer, whatever was left."""
        left_over = ("/response", CORS_LISTED[0])
        self.assertIsNone(self._parsed(None, left_over))
        self.assertEqual(self._parsed(CORS_LISTED[1], left_over), ("/request.jwt", CORS_LISTED[1]))


class CorsOriginTableTests(CorsTestCase):
    """The origin values, one row each with its reason: data in the tests, not in the published
    vector files, which hold credential refusals; this is the listener."""

    def test_each_value_refused_at_startup_raises_naming_itself(self):
        """By cors_origin, and by serve() before it listens. Twin:
        test_each_value_kept_is_written_as_a_browser_writes_it."""
        for value, reason in CORS_REFUSED_AT_STARTUP:
            with self.subTest(reason=reason):
                with self.assertRaises(ValueError) as caught:
                    cors_origin(value)
                self.assertIn(repr(value), str(caught.exception))
                with self.assertRaises(ValueError):
                    serve(self.verifier, host="127.0.0.1", port=0, cors_origins=[value])

    def test_a_comma_is_told_to_give_each_origin_its_own_option(self):
        """Checked before anything else, so two origins joined by a comma are told what to write,
        not that the second one's `//` is a path; and a comma a host could otherwise hold is
        refused too. Twin: each origin alone is taken."""
        for value in ("https://wallet.example,https://other.example",
                      "https://wallet.example,other.example", "https://wallet.example,"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as caught:
                    cors_origin(value)
                self.assertEqual(str(caught.exception), "%r is not one origin: give each origin "
                                 "its own --cors-origin" % value)
        self.assertEqual(cors_origins_of(["https://wallet.example", "https://other.example"]),
                         ("https://wallet.example", "https://other.example"))

    def test_star_beside_an_origin_is_refused(self):
        """Twin: `*` alone, and `*` given twice, are taken."""
        for values in (["*", "https://wallet.example"], ["https://wallet.example", "*"]):
            with self.subTest(values=values):
                with self.assertRaises(ValueError) as caught:
                    cors_origins_of(values)
                self.assertIn("stands alone", str(caught.exception))
        self.assertEqual(cors_origins_of(["*"]), ("*",))
        self.assertEqual(cors_origins_of(["*", "*"]), ("*",))

    def test_a_string_is_refused_as_the_list(self):
        """A string would be read one character at a time (`"*"` would pass by accident):
        refused, naming the list to write. Twin: the same origin in a list is taken."""
        for values in ("https://wallet.example", "*", "", b"https://wallet.example"):
            with self.subTest(values=values):
                with self.assertRaises(ValueError) as caught:
                    cors_origins_of(values)
                self.assertIn("a list of origins", str(caught.exception))
                with self.assertRaises(ValueError):
                    serve(self.verifier, host="127.0.0.1", port=0, cors_origins=values)
        self.assertEqual(cors_origins_of(["https://wallet.example"]), ("https://wallet.example",))

    def test_none_and_an_empty_list_mean_no_cors(self):
        """Twin: a list with an origin, test_a_string_is_refused_as_the_list's last line."""
        for values in (None, [], ()):
            with self.subTest(values=values):
                self.assertIsNone(cors_origins_of(values))

    def test_a_value_given_twice_is_kept_once(self):
        """In any spelling written the same way, so the list and the startup line name it once.
        Twin: two different origins are both kept, in the order given."""
        self.assertEqual(cors_origins_of(["https://wallet.example", "HTTPS://Wallet.Example:443",
                                          "https://wallet.example"]), ("https://wallet.example",))
        self.assertEqual(cors_origins_of(list(reversed(CORS_LISTED))),
                         tuple(reversed(CORS_LISTED)))

    def test_a_refused_ip_address_is_told_what_to_write(self):
        """An IPv4 address in another form is told the shape to write, never a rewriting of the
        value (127.0.1 is 127.0.0.1 to a browser and 1.2.3 is 1.2.0.3); an IPv4-mapped IPv6
        address is told how a browser writes it and the IPv4 address to open the page at. Twin:
        test_each_value_kept_is_written_as_a_browser_writes_it, where 127.0.0.1 and the IPv6 rows
        that are not mapped are kept."""
        shape = ("write an IPv4 address as four decimal numbers, each 0 to 255 with no leading "
                 "zero (for example 127.0.0.1)")
        for value in ("http://127.1:3000", "http://127.0.1", "http://0x7f.0.0.1",
                      "http://256.0.0.1", "http://wallet.123"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as caught:
                    cors_origin(value)
                self.assertTrue(str(caught.exception).endswith(": " + shape), caught.exception)
        for value, written, ipv4 in (("http://[::FFFF:127.0.0.1]:8080", "[::ffff:7f00:1]",
                                      "127.0.0.1"),
                                     ("http://[::ffff:0:1]", "[::ffff:0:1]", "0.0.0.1")):
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as caught:
                    cors_origin(value)
                self.assertIn("an IPv4-mapped IPv6 address, %s as a browser writes it; open the "
                              "wallet page at its IPv4 address, %s, and name that origin"
                              % (written, ipv4), str(caught.exception))

    def test_each_value_kept_is_written_as_a_browser_writes_it(self):
        """Twin: test_each_value_refused_at_startup_raises_naming_itself."""
        for given, kept, reason in CORS_KEPT:
            with self.subTest(reason=reason):
                self.assertEqual(cors_origin(given), kept)
                self.assertEqual(cors_origins_of([given]), (kept,))

    def test_a_kept_value_is_answered_for_the_origin_a_browser_sends(self):
        """A listener given each rewritten row as written answers the origin as a browser sends
        it. Twin: test_each_value_that_must_not_match_is_answered_with_vary_alone."""
        rewritten = [(given, kept, reason) for given, kept, reason in CORS_KEPT if given != kept]
        httpd = serve(self.verifier, host="127.0.0.1", port=0,
                      cors_origins=[given for given, _, _ in rewritten])
        try:
            for _, kept, reason in rewritten:
                with self.subTest(reason=reason):
                    _, headers, _ = self._ask(httpd, self._request_object(), [("Origin", kept)])
                    self.assertEqual(_cors(headers), [("Access-Control-Allow-Origin", kept),
                                                      ("Vary", "Origin")])
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_each_value_that_must_not_match_is_answered_with_vary_alone(self):
        """At request time, against the listener serving CORS_LISTED, a fetch and a preflight.
        The first rows are the twins: each listed origin, answered."""
        for origin in CORS_LISTED:
            with self.subTest(reason="listed, %s" % origin):
                _, headers, _ = self._ask(self.cors, self._request_object(), [("Origin", origin)])
                self.assertIn(("Access-Control-Allow-Origin", origin), _cors(headers))
        for sent, reason in CORS_MUST_NOT_MATCH:
            with self.subTest(reason=reason):
                _, headers, _ = self._ask(self.cors, self._request_object(), [("Origin", sent)])
                self.assertEqual(_cors(headers), [("Vary", "Origin")])
                status, headers, _ = _parse(_exchange(self.cors, "OPTIONS", "/response", [
                    ("Origin", sent), ("Access-Control-Request-Method", "POST")]))
                self.assertEqual((status, _cors(headers)), (204, [("Vary", "Origin")]))
