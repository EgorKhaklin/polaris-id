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
import sys
import unittest
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from polaris_oid4vp.serve import serve  # noqa: E402
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

    def test_a_posted_wallet_nonce_reaches_the_request_object(self):
        session, _ = self.verifier.new_request()
        status, ctype, body = _post("%s/request.jwt?state=%s" % (self.base, session.state),
                                    {"wallet_nonce": "w-from-the-wire"})
        self.assertEqual(status, 200)
        self.assertEqual(ctype, "application/oauth-authz-req+jwt")
        _, claims = Wallet.read_request(body.decode())
        self.assertEqual(claims["wallet_nonce"], "w-from-the-wire")

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
