# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""lab/strategy/007/test_gate.py -- the gate's OIDC flow, end to end, with a wallet the certified
verifier judges for real. The wallet is polaris-oid4vp's own test wallet; nothing is mocked
between its presentation and the ID token.

    python3 -m unittest lab/strategy/007/test_gate.py
"""
import base64
import hashlib
import json
import pathlib
import secrets
import sys
import unittest
import urllib.error
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2] / "packages" / "polaris-oid4vp"))

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature  # noqa: E402

import gate as G  # noqa: E402
from polaris_oid4vp.jwe import b64u_decode, b64u_encode  # noqa: E402
from test_verifier import Wallet, _client_chain  # noqa: E402

REDIRECT = "https://proxy.test/oauth2/callback"
OTHER = "https://other.test/callback"


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


class GateTestCase(unittest.TestCase):

    def setUp(self):
        cert_pem, key_pem = _client_chain()
        self.wallet = Wallet()
        self.clock = Clock()
        self.verifier = G.GateVerifier(
            client_cert_pem=cert_pem, client_key_pem=key_pem,
            request_uri="https://gate.test:9443/request.jwt",
            response_uri="https://gate.test:9443/response",
            issuer_jwks=[self.wallet.issuer_jwk])
        self.gate = G.Gate(issuer="https://gate.test:9444", verifier=self.verifier, now=self.clock,
                           clients={"proxy": {"secret": "s3cret", "redirect_uris": [REDIRECT]},
                                    "other": {"secret": "0ther", "redirect_uris": [OTHER]},
                                    "spa": {"redirect_uris": [REDIRECT]}})

    def sign_in(self, client="proxy", redirect=REDIRECT, scope="openid profile", wallet=None, **wallet_kw):
        """Authorize, let the wallet present, and return (status body, PKCE verifier)."""
        verifier = secrets.token_urlsafe(48)
        challenge = b64u_encode(hashlib.sha256(verifier.encode()).digest())
        status, body = self.gate.authorize({
            "response_type": "code", "client_id": client, "redirect_uri": redirect,
            "scope": scope, "state": "xyz", "nonce": "n-123",
            "code_challenge": challenge, "code_challenge_method": "S256"})
        self.assertEqual(status, 200, body)
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(body["launch"]).query))
        state = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(query["request_uri"]).query))["state"]
        jar = self.verifier.request_object(state)
        form = (wallet or self.wallet).respond(jar, **wallet_kw)
        self.verifier.handle_direct_post(form)
        return self.gate.status(body["ticket"]), verifier

    def code_from(self, status):
        self.assertEqual(status[0], 200)
        self.assertEqual(status[1]["state"], "done", status)
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(status[1]["redirect"]).query))
        self.assertEqual(q["state"], "xyz")
        return q["code"]

    def exchange(self, code, verifier, client=("proxy", "s3cret"), redirect=REDIRECT):
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect,
                "code_verifier": verifier}
        basic = "Basic " + base64.b64encode(("%s:%s" % client).encode()).decode() if client[1] else None
        if basic is None:
            form["client_id"] = client[0]
        return self.gate.token(form, basic)

    def verified_claims(self, id_token):
        header_b64, claims_b64, sig_b64 = id_token.split(".")
        header = json.loads(b64u_decode(header_b64))
        self.assertEqual((header["alg"], header["kid"]), ("ES256", self.gate.kid))
        jwk = self.gate.jwks()["keys"][0]
        key = ec.EllipticCurvePublicNumbers(int.from_bytes(b64u_decode(jwk["x"]), "big"),
                                            int.from_bytes(b64u_decode(jwk["y"]), "big"),
                                            ec.SECP256R1()).public_key()
        sig = b64u_decode(sig_b64)
        der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        try:
            key.verify(der, (header_b64 + "." + claims_b64).encode(), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            self.fail("the ID token does not verify under the published JWKS")
        return json.loads(b64u_decode(claims_b64))


class SignInTests(GateTestCase):

    def test_discovery_names_pairwise_es256_and_pkce(self):
        d = self.gate.discovery()
        self.assertEqual(d["issuer"], "https://gate.test:9444")
        self.assertEqual(d["subject_types_supported"], ["pairwise"])
        self.assertEqual(d["id_token_signing_alg_values_supported"], ["ES256"])
        self.assertEqual(d["code_challenge_methods_supported"], ["S256"])
        self.assertEqual(self.gate.jwks()["keys"][0]["kid"], self.gate.kid)

    def test_a_wallet_presentation_signs_the_person_in(self):
        status, verifier = self.sign_in()
        code = self.code_from(status)
        st, body = self.exchange(code, verifier)
        self.assertEqual(st, 200, body)
        claims = self.verified_claims(body["id_token"])
        self.assertEqual(claims["iss"], "https://gate.test:9444")
        self.assertEqual(claims["aud"], "proxy")
        self.assertEqual(claims["nonce"], "n-123")
        self.assertEqual(claims["amr"], ["pop"])
        self.assertEqual((claims["given_name"], claims["family_name"]), ("Jean", "Dupont"))
        self.assertEqual(claims["exp"] - claims["iat"], G.TOKEN_TTL)
        st, info = self.gate.userinfo("Bearer " + body["access_token"])
        self.assertEqual((st, info["sub"], info["given_name"]), (200, claims["sub"], "Jean"))

    def test_without_the_profile_scope_only_the_subject_is_released(self):
        status, verifier = self.sign_in(scope="openid")
        claims = self.verified_claims(self.exchange(self.code_from(status), verifier)[1]["id_token"])
        self.assertNotIn("given_name", claims)
        self.assertNotIn("family_name", claims)

    def test_two_clients_see_two_subjects_and_one_client_sees_one(self):
        subs = []
        for client, secret, redirect in (("proxy", "s3cret", REDIRECT), ("other", "0ther", OTHER),
                                         ("proxy", "s3cret", REDIRECT)):
            status, verifier = self.sign_in(client=client, redirect=redirect)
            body = self.exchange(self.code_from(status), verifier, client=(client, secret),
                                 redirect=redirect)[1]
            subs.append(self.verified_claims(body["id_token"])["sub"])
        self.assertEqual(subs[0], subs[2], "one client sees one stable subject")
        self.assertNotEqual(subs[0], subs[1], "two clients cannot join their subjects")
        other_holder = Wallet()
        other_holder.issuer_key, other_holder.issuer_jwk = self.wallet.issuer_key, self.wallet.issuer_jwk
        status, verifier = self.sign_in(wallet=other_holder)
        body = self.exchange(self.code_from(status), verifier)[1]
        self.assertNotEqual(self.verified_claims(body["id_token"])["sub"], subs[0],
                            "another holder's key is another subject")

    def test_a_refused_presentation_is_access_denied_and_issues_no_code(self):
        status, _ = self.sign_in(corrupt_issuer_sig=True)
        self.assertEqual(status[1]["state"], "failed")
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(status[1]["redirect"]).query))
        self.assertEqual((q["error"], q["state"]), ("access_denied", "xyz"))
        self.assertNotIn("code", q)
        self.assertEqual(self.gate._codes, {})

    def test_only_a_200_answer_issues_a_code(self):
        """Belt and braces: the verifier never refuses with an authentic verdict, so this rule is
        reached only directly. A refusal at the HTTP layer issues no code whatever the verdict says."""
        class Authentic:
            authentic = True
            claims = {"cnf": {"jwk": {"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "BBBB"}}}
        st, body = self.gate.authorize({"response_type": "code", "client_id": "proxy",
                                        "redirect_uri": REDIRECT, "scope": "openid", "state": "xyz"})
        state = next(iter(self.gate._pending))
        self.gate._on_answer(state, 400, Authentic())
        self.assertEqual(self.gate.status(body["ticket"])[1]["state"], "failed")
        self.assertEqual(self.gate._codes, {})

    def test_a_presentation_for_another_nonce_is_refused(self):
        status, _ = self.sign_in(nonce="not-the-request-nonce")
        self.assertEqual(status[1]["state"], "failed")


class CodeAndClientTests(GateTestCase):

    def test_a_code_is_exchanged_once(self):
        status, verifier = self.sign_in()
        code = self.code_from(status)
        self.assertEqual(self.exchange(code, verifier)[0], 200)
        self.assertEqual(self.exchange(code, verifier), (400, {"error": "invalid_grant"}))

    def test_a_code_is_bound_to_its_client_redirect_and_verifier(self):
        for kw, expected in (({"client": ("other", "0ther")}, "invalid_grant"),
                             ({"redirect": OTHER}, "invalid_grant"),
                             ({"client": ("proxy", "wrong")}, "invalid_client")):
            with self.subTest(kw=kw):
                status, verifier = self.sign_in()
                st, body = self.exchange(self.code_from(status), verifier, **kw)
                self.assertEqual(body["error"], expected)
        status, _ = self.sign_in()
        self.assertEqual(self.exchange(self.code_from(status), "a-different-verifier")[1]["error"],
                         "invalid_grant")

    def test_a_code_expires(self):
        status, verifier = self.sign_in()
        code = self.code_from(status)
        self.clock.t += G.CODE_TTL + 1
        self.assertEqual(self.exchange(code, verifier), (400, {"error": "invalid_grant"}))

    def test_an_unanswered_request_expires(self):
        st, body = self.gate.authorize({"response_type": "code", "client_id": "proxy",
                                        "redirect_uri": REDIRECT, "scope": "openid"})
        self.assertEqual(self.gate.status(body["ticket"]), (200, {"state": "pending"}))
        self.clock.t += G.PENDING_TTL + 1
        self.assertEqual(self.gate.status(body["ticket"]), (404, {"state": "unknown"}))

    def test_refusals_before_the_redirect_uri_is_trusted_are_not_redirected(self):
        base = {"response_type": "code", "client_id": "proxy", "redirect_uri": REDIRECT, "scope": "openid"}
        for change, error in (({"client_id": "nobody"}, "invalid_request"),
                              ({"redirect_uri": "https://attacker.test/cb"}, "invalid_request"),
                              ({"scope": "profile"}, "invalid_scope"),
                              ({"response_type": "token"}, "unsupported_response_type"),
                              ({"code_challenge": "x", "code_challenge_method": "plain"}, "invalid_request")):
            with self.subTest(change=change):
                st, body = self.gate.authorize(dict(base, **change))
                self.assertEqual((st, body["error"]), (400, error))
                self.assertNotIn("redirect", body)

    def test_a_public_client_must_use_pkce(self):
        st, body = self.gate.authorize({"response_type": "code", "client_id": "spa",
                                        "redirect_uri": REDIRECT, "scope": "openid"})
        self.assertEqual((st, body["error"]), (400, "invalid_request"))
        status, verifier = self.sign_in(client="spa")
        st, body = self.exchange(self.code_from(status), verifier, client=("spa", None))
        self.assertEqual(st, 200, body)

    def test_nothing_about_the_sign_in_is_kept_after_the_exchange(self):
        status, verifier = self.sign_in()
        self.exchange(self.code_from(status), verifier)
        self.assertEqual((self.gate._pending, self.gate._tickets, self.gate._codes), ({}, {}, {}))
        self.clock.t += G.TOKEN_TTL + 1
        self.gate.userinfo("Bearer x")
        self.assertEqual(self.gate._tokens, {}, "the access token expires and is forgotten")

    def test_userinfo_refuses_an_unknown_token(self):
        self.assertEqual(self.gate.userinfo("Bearer nope"), (401, {"error": "invalid_token"}))
        self.assertEqual(self.gate.userinfo(None), (401, {"error": "invalid_token"}))


class HttpTests(GateTestCase):

    def test_the_http_layer_serves_discovery_and_refuses_unknown_paths(self):
        httpd = G.serve_gate(self.gate, host="127.0.0.1", port=0)
        try:
            port = httpd.server_address[1]
            with urllib.request.urlopen("http://127.0.0.1:%d/.well-known/openid-configuration" % port) as r:
                self.assertEqual(json.loads(r.read())["issuer"], "https://gate.test:9444")
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen("http://127.0.0.1:%d/nothing" % port)
            self.assertEqual(cm.exception.code, 404)
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
