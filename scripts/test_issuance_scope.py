# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_issuance_scope.py: the issuance tunnel's scope filter exposes the wallet's OID4VCI paths
and nothing else (lab/strategy/012-issuance-tunnel.md, falsifiers a and d).

The filter is the control that keeps the operator console, the relying-party API, sign-in and the
offer-minting route off a public tunnel. These assert both halves on the pure predicate (no
database): every wallet-facing path and method is allowed, and a representative set of the
application's other surfaces, plus path-normalisation attempts and method mismatches, is refused.
The WSGI cases prove the wrapper forwards an allowed request and answers a refused one 403 without
ever calling the application.
"""
import importlib.util
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load():
    spec = importlib.util.spec_from_file_location(
        "polaris_issuance_scope", os.path.join(_HERE, "polaris_issuance_scope.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scope = _load()

# The wallet's half of oid4vci_routes.py: the two metadata shapes, token, nonce, credential, status.
_ALLOWED = [
    ("GET", "/.well-known/openid-credential-issuer/api/v1/oid4vci/7"),
    ("GET", "/.well-known/oauth-authorization-server/api/v1/oid4vci/7"),
    ("GET", "/api/v1/oid4vci/7/.well-known/openid-credential-issuer"),
    ("GET", "/api/v1/oid4vci/7/.well-known/oauth-authorization-server"),
    ("POST", "/api/v1/oid4vci/7/token"),
    ("POST", "/api/v1/oid4vci/7/nonce"),
    ("POST", "/api/v1/oid4vci/7/credential"),
    ("GET", "/api/v1/oid4vci/7/status/2026-10-02/3"),
    ("GET", "/api/v1/oid4vci/123456/token".replace("/token", "/.well-known/openid-credential-issuer")),
]

# Everything else the application serves, and the shapes an attacker would try. The offer-minting
# route /tokens/<id>/wallet-offer is the critical exclusion: the operator mints an offer locally.
_REFUSED = [
    ("POST", "/tokens/7/wallet-offer"),     # operator mints the offer locally, never over the tunnel
    ("GET", "/tokens/7/wallet-offer"),
    ("GET", "/login"),
    ("POST", "/login"),
    ("GET", "/logout"),
    ("GET", "/operator"),
    ("GET", "/operator/tokens"),
    ("GET", "/investigate"),
    ("GET", "/atlas"),
    ("POST", "/api/v1/verify"),             # the relying-party API
    ("GET", "/api/v1/tokens/7/verify"),
    ("POST", "/uc1"),
    ("GET", "/sql-console"),
    ("GET", "/sql"),
    ("GET", "/"),
    ("GET", "/healthz"),
    ("GET", "/metrics"),
    ("GET", "/.well-known/security.txt"),
    # Right issuance resource, wrong method: token/nonce/credential are POST only, metadata is GET only.
    ("GET", "/api/v1/oid4vci/7/token"),
    ("POST", "/api/v1/oid4vci/7/.well-known/openid-credential-issuer"),
    ("DELETE", "/api/v1/oid4vci/7/credential"),
    # Normalisation and shape attacks: traversal, empty segment, trailing extra, non-numeric agency.
    ("POST", "/api/v1/oid4vci/7/credential/../../../login"),
    ("GET", "/api/v1/oid4vci/7/../../../etc/passwd"),
    ("GET", "//api/v1/oid4vci/7/.well-known/openid-credential-issuer"),
    ("GET", "/api/v1/oid4vci/7/.well-known/openid-credential-issuer/extra"),
    ("POST", "/api/v1/oid4vci/abc/token"),
    ("POST", "/api/v1/oid4vci//token"),
    ("GET", "/api/v1/oid4vci/7/status/2026-10-02/notanumber"),
    ("GET", "api/v1/oid4vci/7/token"),       # not absolute
    ("GET", "/api/v1/oid4vci/7/credential%00"),
]


class TestIssuanceScopeAllowlist(unittest.TestCase):
    def test_wallet_facing_paths_are_allowed(self):
        for method, path in _ALLOWED:
            with self.subTest(method=method, path=path):
                self.assertTrue(scope.is_issuance_path(method, path),
                                "a wallet-facing OID4VCI request must cross the tunnel")

    def test_non_issuance_paths_are_refused(self):
        for method, path in _REFUSED:
            with self.subTest(method=method, path=path):
                self.assertFalse(scope.is_issuance_path(method, path),
                                 "only the wallet's OID4VCI paths may cross the tunnel")

    def test_the_offer_minting_route_is_never_exposed(self):
        # The sharpest line: an offer carries a pre-authorized code; minting it is the operator's,
        # done on the loopback. If this ever crossed the tunnel, anyone could mint their own offer.
        for method in ("GET", "POST", "PUT", "OPTIONS", "HEAD"):
            self.assertFalse(scope.is_issuance_path(method, "/tokens/7/wallet-offer"))

    def test_preflight_and_head_are_allowed_on_wallet_paths(self):
        self.assertTrue(scope.is_issuance_path("OPTIONS", "/api/v1/oid4vci/7/credential"))
        self.assertTrue(scope.is_issuance_path("OPTIONS",
                        "/.well-known/openid-credential-issuer/api/v1/oid4vci/7"))
        self.assertTrue(scope.is_issuance_path("HEAD",
                        "/.well-known/openid-credential-issuer/api/v1/oid4vci/7"))


class TestIssuanceOnlyWSGI(unittest.TestCase):
    def _run(self, wrapped, method, path):
        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        body = b"".join(wrapped({"REQUEST_METHOD": method, "PATH_INFO": path}, start_response))
        return captured, body

    def _sentinel(self):
        state = {"called": False}

        def app(environ, start_response):
            state["called"] = True
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"ok"]

        return app, state

    def test_an_allowed_request_reaches_the_app(self):
        app, state = self._sentinel()
        wrapped = scope.IssuanceOnly(app)
        captured, body = self._run(wrapped, "POST", "/api/v1/oid4vci/7/credential")
        self.assertTrue(state["called"])
        self.assertEqual(captured["status"], "200 OK")
        self.assertEqual(body, b"ok")

    def test_a_refused_request_is_403_and_the_app_is_not_called(self):
        app, state = self._sentinel()
        refused = []
        wrapped = scope.IssuanceOnly(app, on_refuse=lambda m, p: refused.append((m, p)))
        captured, body = self._run(wrapped, "POST", "/tokens/7/wallet-offer")
        self.assertFalse(state["called"], "the application must never see a refused request")
        self.assertTrue(captured["status"].startswith("403"))
        self.assertEqual(refused, [("POST", "/tokens/7/wallet-offer")])
        self.assertNotIn(b"wallet-offer", body)


if __name__ == "__main__":
    unittest.main()
