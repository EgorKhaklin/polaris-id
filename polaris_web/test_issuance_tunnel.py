# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_issuance_tunnel.py: a wallet gets a copy THROUGH the issuance tunnel's filter, and only the
wallet's OpenID4VCI paths cross it (lab/strategy/012-issuance-tunnel.md, falsifiers a and b).

The filter is scripts/polaris_issuance_scope.py. These drive the real OID4VCI endpoints through it
against the live application and database: a wallet completes the pre-authorized-code flow and
receives a copy; the offer-minting route and sign-in are refused through the filter; and every
OID4VCI wallet route the application actually registers is one the filter admits, and nothing else.
The pre-authorized code is minted the way the operator route mints it (rp_auth.issue_vci_value), so
the round-trip needs no operator sign-in; that the offer route itself never crosses the filter is
asserted on its own.
"""
import base64
import importlib.util
import json
import os
import pathlib
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as app_module          # noqa: E402 -- the real application, every route registered
import credential_copy_keys       # noqa: E402
import rp_auth                    # noqa: E402
import wallet_copy as wc          # noqa: E402

_SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts")
sys.path.insert(0, _SCRIPTS)
import polaris_issuance_scope as scope  # noqa: E402

from werkzeug.test import Client  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: E402


def _load_pki():
    spec = importlib.util.spec_from_file_location(
        "polaris_copy_pki", os.path.join(_SCRIPTS, "polaris-credential-copy-test-pki.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pki = _load_pki()

# The eight wallet-facing OID4VCI rules, exactly as oid4vci_routes.py registers them. The filter must
# admit every one of these and refuse every other route the application serves.
WALLET_RULES = {
    "/.well-known/openid-credential-issuer/api/v1/oid4vci/<int:agency_id>",
    "/.well-known/oauth-authorization-server/api/v1/oid4vci/<int:agency_id>",
    "/api/v1/oid4vci/<int:agency_id>/.well-known/openid-credential-issuer",
    "/api/v1/oid4vci/<int:agency_id>/.well-known/oauth-authorization-server",
    "/api/v1/oid4vci/<int:agency_id>/token",
    "/api/v1/oid4vci/<int:agency_id>/nonce",
    "/api/v1/oid4vci/<int:agency_id>/credential",
    "/api/v1/oid4vci/<int:agency_id>/status/<day>/<int:list_no>",
}


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwk(key):
    n = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": _b64(n.x.to_bytes(32, "big")),
            "y": _b64(n.y.to_bytes(32, "big"))}


def _proof(key, issuer, nonce, iat):
    """A wallet's key-binding proof over the issued c_nonce, bound to this issuer (wallet_copy)."""
    header = {"typ": wc.PROOF_TYP, "alg": "ES256", "jwk": _jwk(key)}
    payload = {"aud": issuer, "iat": iat, "nonce": nonce}
    signing_input = "%s.%s" % (_b64(json.dumps(header).encode()), _b64(json.dumps(payload).encode()))
    r, s = utils.decode_dss_signature(key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
    return signing_input + "." + _b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _concrete(rule):
    """A concrete path for a Werkzeug rule: int converters get a number, the rest a plain segment."""
    import re
    return re.sub(r"<([^>]+)>", lambda m: "7" if m.group(1).startswith(("int:", "float:")) else "x",
                  rule.rule)


class IssuanceTunnel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = app_module.app
        row = app_module.query(
            "SELECT token_value, issuing_agency_id FROM IdentityToken "
            "WHERE status = 'ACTIVE' ORDER BY token_id LIMIT 1", fetch='one', primary=True)
        if row is None:
            raise unittest.SkipTest("no ACTIVE credential in the test database")
        cls.token_value = row["token_value"]
        cls.agency = int(row["issuing_agency_id"])
        cls.issuer = "https://tunnel.test/api/v1/oid4vci/%d" % cls.agency
        cls.tmp = tempfile.mkdtemp(prefix="polaris-vci-keys-")
        pki.make(pathlib.Path(cls.tmp), cls.agency, cls.issuer)
        cls._env = mock.patch.dict(os.environ, {credential_copy_keys.KEYS_DIR_ENV: cls.tmp})
        cls._env.start()
        credential_copy_keys.reset()
        cls.filtered = Client(scope.IssuanceOnly(cls.app.wsgi_app))

    @classmethod
    def tearDownClass(cls):
        cls._env.stop()
        credential_copy_keys.reset()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _p(self, suffix):
        return "/api/v1/oid4vci/%d%s" % (self.agency, suffix)

    def test_a_wallet_receives_a_copy_through_the_filter(self):
        secret = self.app.secret_key
        code = rp_auth.issue_vci_value(secret, "code", {"ag": self.agency, "tv": self.token_value})

        nonce_resp = self.filtered.post(self._p("/nonce"))
        self.assertEqual(nonce_resp.status_code, 200, nonce_resp.get_data(as_text=True))
        c_nonce = nonce_resp.json["c_nonce"]

        token_resp = self.filtered.post(self._p("/token"), data={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": code})
        self.assertEqual(token_resp.status_code, 200, token_resp.get_data(as_text=True))
        access = token_resp.json["access_token"]

        holder = ec.generate_private_key(ec.SECP256R1())
        proof = _proof(holder, self.issuer, c_nonce, int(time.time()))
        cred_resp = self.filtered.post(self._p("/credential"),
            headers={"Authorization": "Bearer %s" % access},
            json={"credential_configuration_id": wc.CONFIGURATION_ID, "proofs": {"jwt": [proof]}})
        self.assertEqual(cred_resp.status_code, 200, cred_resp.get_data(as_text=True))
        copy = cred_resp.json["credentials"][0]["credential"]
        self.assertTrue(copy and copy.count(".") >= 2, "the copy is a compact SD-JWT VC")
        self.assertTrue(copy.startswith("ey"), "the copy is a JWT")

    def test_the_offer_route_and_the_console_never_cross_the_filter(self):
        self.assertEqual(self.filtered.post("/tokens/1/wallet-offer").status_code, 403)
        self.assertEqual(self.filtered.get("/login").status_code, 403)
        self.assertEqual(self.filtered.get("/").status_code, 403)
        self.assertEqual(self.filtered.post("/api/v1/verify").status_code, 403)

    def test_every_wallet_route_is_admitted_and_no_other_route_is(self):
        seen = set()
        for rule in self.app.url_map.iter_rules():
            methods = (rule.methods or set()) - {"HEAD", "OPTIONS"}
            path = _concrete(rule)
            admitted = any(scope.is_issuance_path(m, path) for m in methods)
            if rule.rule in WALLET_RULES:
                seen.add(rule.rule)
                self.assertTrue(admitted, "the filter must admit wallet route %s" % rule.rule)
            else:
                self.assertFalse(admitted,
                                 "the filter must refuse %s %s" % (sorted(methods), rule.rule))
        self.assertEqual(seen, WALLET_RULES, "every wallet route must still be registered")


if __name__ == "__main__":
    unittest.main()
