# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_swiyu.py -- the lab verifier's checks (L1 to L15), the package members it leans on, and the owner's
scripts held against stubs.

Every fixture is made in the test, with keys made in the test (swiyu_fixtures.py). No test reaches a network
beyond a loopback address; no script test runs a real curl, docker or cloudflared (fake ones on PATH only
record their arguments).

    python -B -m unittest test_swiyu                       # from this folder
    python -B -m unittest lab/interop/swiyu/test_swiyu.py  # from the repository root
"""
import contextlib
import hashlib
import http.server
import inspect
import io
import json
import os
import pathlib
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock as mock
import urllib.error
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import swiyu_fixtures as F  # noqa: E402
import swiyu_verifier as sv  # noqa: E402
import polaris_oid4vp  # noqa: E402
from polaris_oid4vp import jwe, sdjwt, status  # noqa: E402
from polaris_oid4vp import serve as package_serve  # noqa: E402
from polaris_oid4vp import verifier as parent  # noqa: E402
from polaris_oid4vp.jwe import b64u_decode  # noqa: E402
from polaris_oid4vp.verifier import Verifier  # noqa: E402

PY = sys.executable
L3_KID = "is not an absolute URL of"  # _check_kid's own message
L3_DID = "is not a did:webvh DID on the registry host"  # _check_did's own message

_SAVED_GIT_ENV = {}
_REAL_GETADDRINFO = socket.getaddrinfo
_TRIPS = []  # every real host the guard refused in this process; tearDownModule fails the run if one is left here


def _only_loopback(host, *args, **kwargs):
    """The guard on socket.getaddrinfo that setUpModule installs, for this test process: no test and no mutant of one may
    reach a real host. Loopback goes to the real resolver; a name under .invalid does not exist, so it is answered as
    unknown and never reaches the real resolver; any other name is recorded in _TRIPS and refused. The scripts and
    dryrun.py run in subprocesses of their own: they reach nothing because of how they are built, not because of this guard."""
    name = host.decode() if isinstance(host, bytes) else host
    if name in (None, "", "localhost", "127.0.0.1", "::1"):
        return _REAL_GETADDRINFO(host, *args, **kwargs)
    lowered = str(name).lower().rstrip(".")
    if lowered == "invalid" or lowered.endswith(".invalid"):
        raise socket.gaierror(socket.EAI_NONAME, "%s is under .invalid and does not resolve" % (name,))
    _TRIPS.append(name)
    raise AssertionError("a test tried to resolve %r: nothing here may reach a real host" % (name,))


def setUpModule():
    # tests that run git start from no GIT_* variable (run from a hook they would write into its index)
    for name in [n for n in os.environ if n.startswith("GIT_")]:
        _SAVED_GIT_ENV[name] = os.environ.pop(name)
    socket.getaddrinfo = _only_loopback


def tearDownModule():
    socket.getaddrinfo = _REAL_GETADDRINFO
    os.environ.update(_SAVED_GIT_ENV)
    if _TRIPS:  # the guard refused these, but code between the test and the guard may have caught the error and gone on
        raise AssertionError("the resolver guard refused real hosts during the run: %s" % ", ".join(map(repr, _TRIPS)))


class ResolverGuardTests(unittest.TestCase):
    """The guard setUpModule installs: it is in place, it refuses a real host and keeps a record of the refusal (a caller
    that swallows the error, as sdjwt does for a resolver error, cannot hide it from tearDownModule), and a name under
    .invalid never reaches the real resolver."""

    def test_the_guard_is_installed_and_trips_on_a_real_host(self):
        self.assertIs(socket.getaddrinfo, _only_loopback)
        before = len(_TRIPS)
        with self.assertRaises(AssertionError):
            socket.getaddrinfo(F.STATUS_HOST, 443)
        self.assertEqual(_TRIPS[before:], [F.STATUS_HOST])  # on record, so tearDownModule would fail on it
        del _TRIPS[before:]  # this trip was made on purpose
        self.assertTrue(socket.getaddrinfo("127.0.0.1", 80))  # loopback is still answered

    def test_a_name_under_invalid_never_reaches_the_real_resolver(self):
        asked = []
        with mock.patch.dict(globals(), {"_REAL_GETADDRINFO": lambda *args, **kwargs: asked.append(args) or [("answer",)]}):
            for name in ("status.lab.invalid", b"status.lab.invalid", "STATUS.LAB.INVALID", "status.lab.invalid.", "invalid"):
                with self.assertRaises(socket.gaierror, msg=name) as caught:
                    socket.getaddrinfo(name, 443)
                self.assertEqual(caught.exception.errno, socket.EAI_NONAME, name)
            self.assertEqual(asked, [])
            self.assertTrue(socket.getaddrinfo("localhost", 80))  # loopback goes to the resolver
            self.assertEqual(len(asked), 1)


class Base(unittest.TestCase):
    def setUp(self):
        self.w = F.World()

    def request(self, w=None):
        w = w or self.w
        session, jar = w.verifier.new_request()
        header, claims = F.parts(jar)
        return session, jar, header, claims


class RequestTests(Base):
    # ---- L1, L2, L6, L14: the request the lab builds

    def test_client_id_is_the_prefixed_did(self):
        _, jar, header, claims = self.request()
        self.assertEqual(claims["client_id"], "decentralized_identifier:" + F.VERIFIER_DID)
        self.assertEqual(claims["iss"], claims["client_id"])
        self.assertEqual(self.w.verifier.client_id, claims["client_id"])

    def test_header_is_the_swiss_one(self):
        _, jar, header, _ = self.request()
        self.assertEqual(header, {"alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": self.w.kid,
                                  "profile_version": "swiss-profile-verification:1.0.0"})
        self.assertNotIn("x5c", header)

    def test_client_metadata_is_two_keys(self):
        _, _, _, claims = self.request()
        meta = claims["client_metadata"]
        self.assertEqual(sorted(meta), ["encrypted_response_enc_values_supported", "jwks"])
        self.assertEqual(meta["encrypted_response_enc_values_supported"], ["A256GCM"])
        keys = meta["jwks"]["keys"]
        self.assertEqual(len(keys), 1)
        self.assertEqual((keys[0]["kty"], keys[0]["crv"], keys[0]["alg"]), ("EC", "P-256", "ECDH-ES"))
        self.assertNotIn("vp_formats_supported", meta)

    def test_request_is_the_minimal_one(self):
        session, _, _, claims = self.request()
        self.assertEqual(sorted(claims), sorted(["iss", "aud", "client_id", "response_type", "response_mode",
                                                 "response_uri", "nonce", "state", "iat", "exp", "client_metadata",
                                                 "dcql_query"]))
        self.assertEqual(claims["aud"], "https://self-issued.me/v2")
        self.assertEqual((claims["response_type"], claims["response_mode"]), ("vp_token", "direct_post.jwt"))
        self.assertEqual(claims["dcql_query"], sv.lab_query())
        self.assertEqual(claims["dcql_query"], self.w.verifier._dcql_query())
        (query,) = claims["dcql_query"]["credentials"]
        self.assertEqual(query["meta"]["vct_values"], ["betaid-sdjwt", "urn:vct:ch.admin.bcs.betaid"])
        self.assertEqual(query["claims"], [{"path": ["age_over_18"]}])
        self.assertIs(self.w.verifier.redirect, False)
        with self.assertRaises(ValueError):
            self.w.verifier.new_request(transaction_data=[{"type": "x", "credential_ids": [sv.QUERY_ID]}])
        status_, body, _ = self.w.exchange()
        self.assertEqual((status_, body), (200, {}))

    def test_wallet_nonce_is_carried_back_in_the_same_request(self):
        session, _, _, _ = self.request()
        jar = self.w.verifier.request_object(session.state, wallet_nonce="wallet-nonce-1")
        header, claims = F.parts(jar)
        self.assertEqual(claims["wallet_nonce"], "wallet-nonce-1")
        self.assertEqual(sorted(header), ["alg", "kid", "profile_version", "typ"])
        self.assertEqual(claims["client_id"], "decentralized_identifier:" + F.VERIFIER_DID)
        self.assertNotIn("wallet_nonce", F.parts(self.w.verifier.request_object(session.state))[1])

    def test_public_url_must_be_https(self):
        for url in ("http://lab-verifier.test", "https://lab-verifier.test/base", "https://lab-verifier.test/?x=1",
                    "https:///x", "ftp://lab-verifier.test", ""):
            with self.assertRaises(sv.StartRefused, msg=url):
                F.World(public_url=url)
        F.World(public_url="http://127.0.0.1:9")
        F.World(public_url="https://lab-verifier.test/")

    # ---- L5: the link

    def test_link_carries_no_request_uri_method(self):
        session, _, _, _ = self.request()
        self.assertEqual(sorted(self.w.verifier.authorization_request_params(session)), ["client_id", "request_uri"])
        links = self.w.verifier.links(session)
        self.assertEqual(sorted(links), ["openid4vp", "swiyu-verify"])
        for scheme, url in links.items():
            split = urllib.parse.urlsplit(url)
            self.assertEqual(split.scheme, scheme)
            query = urllib.parse.parse_qs(split.query, keep_blank_values=True)
            self.assertEqual(sorted(query), ["client_id", "request_uri"])
            self.assertNotIn("request_uri_method", url)

    def test_link_round_trips(self):
        session, _, _, claims = self.request()
        for url in self.w.verifier.links(session).values():
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            self.assertEqual(query["client_id"], [claims["client_id"]])
            self.assertEqual(query["request_uri"], [F.PUBLIC_URL + "/request.jwt?state=" + session.state])
            self.assertIn("client_id=decentralized_identifier%3Adid%3Awebvh%3A", url)
            self.assertNotIn("request_uri=https://", url)


class ConstructorTests(Base):
    # ---- L3, L4, L11: what the verifier refuses to start on

    def make(self, **overrides):
        """A verifier on self.w's key and DID log unless a test replaces them, so a refusal is about the one
        thing the test changed."""
        overrides.setdefault("key_pem", self.w.options["key_pem"])
        overrides.setdefault("did_log", self.w.log)
        return F.World(**overrides)

    def test_kid_of_another_did_is_refused(self):
        other = F.VERIFIER_DID.replace("Verifier", "Intruder")
        kid = other + "#assert-key-01"
        # the log is for that other DID and names the kid with our key. L4 refuses this input too, so the
        # message is what says L3 did: the regex holds L3's own text
        with self.assertRaisesRegex(sv.StartRefused, L3_KID):
            self.make(kid=kid, did_log=F.did_log(other, {"assert-key-01": self.w.verifier_key}))

    def test_kid_without_a_fragment_is_refused(self):
        for kid in (F.VERIFIER_DID, F.VERIFIER_DID + "#"):
            with self.assertRaisesRegex(sv.StartRefused, L3_KID):
                self.make(kid=kid)

    def test_did_off_the_registry_is_refused(self):
        for did in ("did:webvh:QmTestVerifierScid00000000000000000000000000000:evil.example:api:v1:did:x",
                    "did:webvh:QmTestVerifierScid00000000000000000000000000000:evil.example:%s:did:x" % F.REGISTRY,
                    "did:web:%s:api:v1:did:x" % F.REGISTRY,
                    "did:tdw:QmTestVerifierScid00000000000000000000000000000:%s:api:v1:did:x" % F.REGISTRY,
                    "did:webvh:QmTestVerifierScid00000000000000000000000000000:%s" % F.REGISTRY,
                    "did:webvh::%s:api:v1:did:x" % F.REGISTRY,
                    "did:webvh:QmTestVerifierScid00000000000000000000000000000:%s::did:x" % F.REGISTRY):
            with self.assertRaisesRegex(sv.StartRefused, L3_DID):
                self.make(did=did, kid=did + "#assert-key-01", did_log=F.did_log(did, {"assert-key-01": self.w.verifier_key}))

    def test_key_not_in_the_log_refuses_to_start(self):
        with self.assertRaisesRegex(sv.StartRefused, "log"):
            self.make(did_log=F.did_log(F.VERIFIER_DID, {"assert-key-01": F.new_key()}))
        with self.assertRaisesRegex(sv.StartRefused, "log"):
            self.make(did_log=F.did_log(F.VERIFIER_DID, {"other-key": self.w.verifier_key}))
        with self.assertRaisesRegex(sv.StartRefused, "log"):
            self.make(did_log="")
        entry = json.loads(self.w.log)
        entry["state"]["id"] = F.OTHER_DID  # a log of another DID, whose method ids still say our kid
        with self.assertRaisesRegex(sv.StartRefused, "log"):
            self.make(did_log=json.dumps(entry) + "\n")
        entry = json.loads(self.w.log)
        del entry["state"]["verificationMethod"][0]["publicKeyJwk"]
        entry["state"]["verificationMethod"][0]["publicKeyMultibase"] = "z6Mk"
        with self.assertRaisesRegex(sv.StartRefused, "log"):
            self.make(did_log=json.dumps(entry) + "\n")
        entry = json.loads(self.w.log)
        entry["state"]["verificationMethod"][0]["publicKeyJwk"] = dict(entry["state"]["verificationMethod"][0]["publicKeyJwk"], crv="P-384")
        with self.assertRaisesRegex(sv.StartRefused, "log"):
            self.make(did_log=json.dumps(entry) + "\n")

    def test_log_with_relative_method_ids_is_read(self):
        entry = json.loads(self.w.log)
        entry["state"]["verificationMethod"][0]["id"] = "#assert-key-01"
        self.make(did_log=json.dumps(entry) + "\n")
        # the newest entry decides: an older line naming another key does not
        older = F.did_log(F.VERIFIER_DID, {"assert-key-01": F.new_key()})
        self.make(did_log=older + self.w.log)
        with self.assertRaisesRegex(sv.StartRefused, "log"):
            self.make(did_log=self.w.log + older)

    def test_key_must_be_a_p256_pem(self):
        for pem in (b"", b"not a key", F.key_pem(F.new_key())[:-30]):
            with self.assertRaises(sv.StartRefused, msg=pem):
                self.make(key_pem=pem)
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        p384 = ec.generate_private_key(ec.SECP384R1())
        with self.assertRaisesRegex(sv.StartRefused, "P-256"):
            self.make(key_pem=p384.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()))

    def test_request_signature_verifies_under_the_key_the_log_names(self):
        _, jar, header, _ = self.request()
        entry = json.loads(self.w.log.strip().splitlines()[-1])
        (method,) = [m for m in entry["state"]["verificationMethod"] if m["id"] == header["kid"]]
        signing_input, _, sig = jar.rpartition(".")
        raw = b64u_decode(sig)
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        sv_key = sdjwt._es256_public_key(method["publicKeyJwk"])
        sv_key.verify(utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                      signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))

    def test_stale_pin_refuses_to_start(self):
        old = F.pin(F.ISSUER_DID, {"assert-key-01": self.w.issuer_key}, resolved_at=time.time() - 25 * 3600)
        with self.assertRaisesRegex(sv.StartRefused, "pin"):
            self.make(issuer_pin=old)
        fresh = F.pin(F.ISSUER_DID, {"assert-key-01": self.w.issuer_key}, resolved_at=time.time() - 23 * 3600)
        self.make(issuer_pin=fresh)
        future = F.pin(F.ISSUER_DID, {"assert-key-01": self.w.issuer_key}, resolved_at=time.time() + 3600)
        with self.assertRaisesRegex(sv.StartRefused, "pin"):
            self.make(issuer_pin=future)

    def test_pin_without_log_hash_is_refused(self):
        for broken in ({"log_sha256": None}, {"log_sha256": ""}, {"log_sha256": "abc"}, {"log_sha256": "Z" * 64}):
            bad = dict(self.w.pin, **broken)
            if broken["log_sha256"] is None:
                del bad["log_sha256"]
            with self.assertRaisesRegex(sv.StartRefused, "pin"):
                self.make(issuer_pin=bad)
        for member in ("did", "resolver", "resolved_at", "keys"):
            bad = {k: v for k, v in self.w.pin.items() if k != member}
            with self.assertRaisesRegex(sv.StartRefused, "pin"):
                self.make(issuer_pin=bad)
        with self.assertRaisesRegex(sv.StartRefused, "pin"):
            self.make(issuer_pin=dict(self.w.pin, keys=[]))
        # a key of another DID in the pin
        stray = dict(self.w.pin, keys=[F.public_jwk(self.w.issuer_key, F.OTHER_DID + "#assert-key-01")])
        with self.assertRaisesRegex(sv.StartRefused, "pin"):
            self.make(issuer_pin=stray)


class StatementTests(Base):
    # ---- L8, L9: trust statements and the scope

    def statements(self, *extra, scope="ch.test.scope", **query):
        key = self.w.trust_key
        return F.as_info(F.identity_statement(key, F.VERIFIER_DID),
                         F.query_statement(key, F.VERIFIER_DID, scope, **query), *extra)

    def test_scope_mode_omits_dcql_query(self):
        w = F.World(verifier_info=self.statements(), scope="ch.test.scope")
        _, _, _, claims = self.request(w)
        self.assertEqual(claims["scope"], "ch.test.scope")
        self.assertNotIn("dcql_query", claims)
        self.assertEqual(claims["verifier_info"], w.options["verifier_info"])
        _, payload = F.parts(w.options["verifier_info"][1]["data"])
        self.assertEqual(payload["request"]["scope"], claims["scope"])
        # the response is still judged by the one query
        self.assertEqual(w.verifier._dcql_query(), payload["request"]["query"])
        status_, _, verdict = w.exchange()
        self.assertEqual((status_, verdict.authentic), (200, True))

    def test_identity_only_sends_dcql_query(self):
        info = F.as_info(F.identity_statement(self.w.trust_key, F.VERIFIER_DID))
        _, _, _, claims = self.request(F.World(verifier_info=info))
        self.assertIn("dcql_query", claims)
        self.assertNotIn("scope", claims)
        self.assertEqual(claims["verifier_info"], info)

    def test_scope_without_a_statement_or_a_statement_without_scope_is_refused(self):
        with self.assertRaisesRegex(sv.StartRefused, "scope"):
            F.World(scope="ch.test.scope")
        with self.assertRaisesRegex(sv.StartRefused, "scope"):
            F.World(verifier_info=self.statements())
        with self.assertRaisesRegex(sv.StartRefused, "scope"):
            F.World(verifier_info=self.statements(), scope="ch.other.scope")
        identity_only = F.as_info(F.identity_statement(self.w.trust_key, F.VERIFIER_DID))
        with self.assertRaisesRegex(sv.StartRefused, "scope"):
            F.World(verifier_info=identity_only, scope="ch.test.scope")

    def test_statement_for_another_did_is_refused(self):
        key = self.w.trust_key
        info = F.as_info(F.identity_statement(key, F.VERIFIER_DID), F.query_statement(key, F.OTHER_DID, "ch.test.scope"))
        with self.assertRaisesRegex(sv.StartRefused, "sub"):
            F.World(verifier_info=info, scope="ch.test.scope")
        with self.assertRaisesRegex(sv.StartRefused, "sub"):
            F.World(verifier_info=F.as_info(F.identity_statement(key, F.OTHER_DID)))

    def test_statement_query_must_equal_the_judged_query(self):
        other = sv.lab_query()
        other["credentials"][0]["claims"] = [{"path": ["age_over_18"]}, {"path": ["family_name"]}]
        with self.assertRaisesRegex(sv.StartRefused, "query"):
            F.World(verifier_info=self.statements(query=other), scope="ch.test.scope")
        other = sv.lab_query()
        other["credentials"][0]["meta"]["vct_values"] = ["betaid-sdjwt"]
        with self.assertRaisesRegex(sv.StartRefused, "query"):
            F.World(verifier_info=self.statements(query=other), scope="ch.test.scope")
        # a statement whose request is not a DCQL one, or has none
        key = self.w.trust_key
        for request in ({"type": "other", "scope": "ch.test.scope", "query": sv.lab_query()}, "text", None):
            bad = F.statement(key, sv.TYP_QUERY, F.VERIFIER_DID, request=request)
            with self.assertRaisesRegex(sv.StartRefused, "DCQL"):
                F.World(verifier_info=F.as_info(bad), scope="ch.test.scope")

    def test_two_identity_statements_are_refused(self):
        key = self.w.trust_key
        info = F.as_info(F.identity_statement(key, F.VERIFIER_DID), F.identity_statement(key, F.VERIFIER_DID))
        with self.assertRaisesRegex(sv.StartRefused, "typ"):
            F.World(verifier_info=info)
        with self.assertRaisesRegex(sv.StartRefused, "typ"):
            F.World(verifier_info=self.statements(F.query_statement(key, F.VERIFIER_DID, "ch.test.scope")),
                    scope="ch.test.scope")

    def test_credential_ids_are_refused(self):
        info = F.as_info(F.identity_statement(self.w.trust_key, F.VERIFIER_DID), credential_ids=[sv.QUERY_ID])
        with self.assertRaisesRegex(sv.StartRefused, "credential_ids"):
            F.World(verifier_info=info)

    def test_verifier_info_is_jwt_entries_only(self):
        good = F.identity_statement(self.w.trust_key, F.VERIFIER_DID)
        for entry in ({"format": "registration_cert", "data": good}, {"format": "jwt", "data": {"a": 1}},
                      {"format": "jwt", "data": "not.a-jws"}, {"format": "jwt", "data": good, "extra": 1},
                      {"data": good}, "text"):
            with self.assertRaises(sv.StartRefused, msg=repr(entry)):
                F.World(verifier_info=[entry])
        for info in ({"format": "jwt", "data": good}, []):
            with self.assertRaises(sv.StartRefused):
                F.World(verifier_info=info)
        unknown = F.statement(self.w.trust_key, "swiyu-something-else+jwt", F.VERIFIER_DID)
        with self.assertRaisesRegex(sv.StartRefused, "typ"):
            F.World(verifier_info=F.as_info(unknown))


class ResponseTests(Base):
    # ---- L7, L10, L12, L13: the response side

    def test_a128gcm_response_is_refused(self):
        _, jar, _, _ = self.request()
        form = self.w.wallet.respond(jar, enc="A128GCM")
        status_, body, verdict = self.w.front.handle_direct_post(form)
        self.assertEqual(status_, 400)
        self.assertFalse(verdict.authentic)
        self.assertEqual(self.w.last()["checks"]["L7"]["outcome"], "refused")
        # the package alone takes the same response: the refusal is the lab's
        _, jar2, _, _ = self.request()
        status2, _, verdict2 = self.w.verifier.handle_direct_post(self.w.wallet.respond(jar2, enc="A128GCM"))
        self.assertEqual((status2, verdict2.authentic), (200, True))
        # and the refused response left its request open for the holder's own
        status3, _, verdict3 = self.w.front.handle_direct_post(self.w.wallet.respond(jar, enc="A256GCM"))
        self.assertEqual((status3, verdict3.authentic), (200, True))

    def test_credential_without_kid_is_refused(self):
        status_, _, verdict = self.w.exchange(kid=None)
        self.assertEqual(status_, 400)
        self.assertFalse(verdict.authentic)
        self.assertEqual(self.w.last()["checks"]["L10"]["outcome"], "refused")
        # a kid that is no DID URL, a DID URL with no fragment, and a DID that is not in the pin
        for kid in ("assert-key-01", F.ISSUER_DID, F.OTHER_DID + "#assert-key-01"):
            status_, _, verdict = self.w.exchange(kid=kid)
            self.assertEqual((status_, verdict.authentic), (400, False), kid)
            self.assertEqual(self.w.last()["checks"]["L10"]["outcome"], "refused", kid)

    def test_issuer_is_the_kid_did_not_iss(self):
        status_, _, verdict = self.w.exchange(iss="https://evil.example/issuer")
        self.assertEqual((status_, verdict.authentic), (200, True))
        record = self.w.last()
        self.assertEqual(record["credential"]["issuer_did"], F.ISSUER_DID)
        self.assertEqual(record["credential"]["iss_claim"], "https://evil.example/issuer")
        self.assertTrue(record["counted"])
        # another key, the trusted iss, and the pinned kid: the signature does not verify
        status_, _, verdict = self.w.exchange(signer=F.new_key(), iss=F.ISSUER_DID)
        self.assertEqual((status_, verdict.authentic), (400, False))
        self.assertFalse(self.w.last()["counted"])
        # another key, the trusted iss, and a kid of a DID outside the pin
        status_, _, verdict = self.w.exchange(signer=F.new_key(), iss=F.ISSUER_DID, kid=F.OTHER_DID + "#assert-key-01")
        self.assertEqual((status_, verdict.authentic), (400, False))
        self.assertEqual(self.w.last()["checks"]["L10"]["outcome"], "refused")

    def test_kb_aud_without_prefix_is_refused(self):
        status_, _, verdict = self.w.exchange(audience=F.VERIFIER_DID)
        self.assertEqual((status_, verdict.authentic, verdict.code), (400, False, "audience"))
        status_, _, verdict = self.w.exchange(audience="decentralized_identifier:" + F.VERIFIER_DID)
        self.assertEqual((status_, verdict.authentic), (200, True))

    def test_status_uri_on_another_host_is_not_fetched(self):
        other = "https://evil.example/api/v1/statuslist/1.jwt"
        status_, _, verdict = self.w.exchange(status_uri=other)
        self.assertEqual(self.w.fetched, [])
        record = self.w.last()
        self.assertEqual(record["checks"]["L13"]["outcome"], "refused")
        self.assertFalse(record["counted"])
        self.assertEqual(record["status"]["state"], "no_authority")
        # the host must be the whole authority: userinfo, a port and a suffix host are not the registry
        for uri in ("https://%s@evil.example/x" % F.STATUS_HOST, "https://%s:8443/x" % F.STATUS_HOST,
                    "https://%s.evil.example/x" % F.STATUS_HOST, "http://%s/x" % F.STATUS_HOST):
            self.w.exchange(status_uri=uri)
            self.assertEqual(self.w.fetched, [], uri)
            self.assertFalse(self.w.last()["counted"], uri)

    def test_status_token_under_another_did_is_no_authority(self):
        # signed by the pinned key, but its header names another DID
        self.w.tokens[F.STATUS_URI] = F.status_token(self.w.issuer_key, F.OTHER_DID + "#assert-key-01", F.STATUS_URI, [0] * 16)
        self.w.exchange()
        record = self.w.last()
        self.assertEqual((record["status"]["state"], record["status"]["code"]), ("no_authority", "no_authority"))
        self.assertFalse(record["counted"])
        self.assertEqual(self.w.fetched, [F.STATUS_URI])
        # under the credential's DID, but signed by a key the pin does not hold
        self.w.tokens[F.STATUS_URI] = F.status_token(F.new_key(), self.w.wallet.kid, F.STATUS_URI, [0] * 16)
        self.w.exchange()
        self.assertEqual(self.w.last()["status"]["code"], "signature")
        self.assertFalse(self.w.last()["counted"])
        # under the credential's DID and signed by the pinned key, but a kid the pin does not name
        self.w.tokens[F.STATUS_URI] = F.status_token(self.w.issuer_key, F.ISSUER_DID + "#auth-key-02", F.STATUS_URI, [0] * 16)
        self.w.exchange()
        self.assertEqual(self.w.last()["status"]["code"], "signature")
        self.assertFalse(self.w.last()["counted"])

    def test_revoked_is_not_accepted(self):
        for value in (1, 2):
            w = F.World(status_list=[0] * 7 + [value] + [0] * 8)
            status_, body, verdict = w.exchange()
            self.assertEqual((status_, verdict.authentic, verdict.code), (400, False, "revoked"))
            self.assertFalse(w.last()["counted"])
            self.assertEqual(w.last()["status"]["status"], value)

    def test_happy_path_is_accepted_and_counted(self):
        status_, body, verdict = self.w.exchange()
        self.assertEqual((status_, body, verdict.authentic), (200, {}, True))
        record = self.w.last()
        self.assertEqual({k: v["outcome"] for k, v in record["checks"].items()}, {"L7": "ok", "L10": "ok", "L13": "ok"})
        self.assertEqual(record["verdict"]["authentic"], True)
        self.assertEqual((record["status"]["state"], record["status"]["status"], record["status"]["stale"]), ("checked", 0, False))
        self.assertTrue(record["counted"])
        self.assertEqual(record["credential"], {"typ": "dc+sd-jwt", "kid": self.w.wallet.kid, "vct": "betaid-sdjwt",
                                                "iss_claim": F.ISSUER_DID, "issuer_did": F.ISSUER_DID})
        self.assertEqual(self.w.fetched, [F.STATUS_URI])

    def test_a_vc_sd_jwt_credential_is_refused_by_the_package_and_recorded(self):
        status_, _, verdict = self.w.exchange(typ="vc+sd-jwt")
        self.assertEqual((status_, verdict.code), (400, "issuer_typ"))
        self.assertEqual(self.w.last()["credential"]["typ"], "vc+sd-jwt")
        self.assertEqual(self.w.last()["verdict"]["code"], "issuer_typ")

    def test_status_fetch_limits(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/ok")
                    self.end_headers()
                    return
                if self.path == "/missing":
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = b"x" * (200 * 1024 + 1) if self.path in ("/big", "/undeclared") else b"a.b.c"
                self.send_response(201 if self.path == "/created" else 200)
                if self.path != "/undeclared":
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass  # the client stopped reading at the limit

            def log_message(self, *args):
                return None

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            base = "http://127.0.0.1:%d" % httpd.server_port
            self.assertEqual(sv.bounded_fetch(base + "/ok", schemes=("http",)), b"a.b.c")
            for path in ("/redirect", "/big", "/undeclared", "/missing", "/created"):
                with self.assertRaises(Exception, msg=path):
                    sv.bounded_fetch(base + path, schemes=("http",))
            with self.assertRaises(Exception):
                sv.bounded_fetch(base + "/ok")  # http is not in the default schemes
        finally:
            httpd.shutdown()
            httpd.server_close()


class FetchTests(unittest.TestCase):
    """The status fetch a verifier uses when it is not handed one (the path main() takes)."""

    @staticmethod
    def serve(handler_class):
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return httpd

    @staticmethod
    def closed_port():
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]

    def test_a_verifier_without_a_fetch_uses_bounded_fetch(self):
        w = F.World(fetch=None, status_schemes=("https",))
        url = "https://127.0.0.1:9/x"  # a loopback address that nothing listens on: a mutant that really fetches reaches no host
        used = []

        def recording(uri, **kwargs):
            used.append((uri, kwargs))
            return b"a.b.c"

        with mock.patch.object(sv, "bounded_fetch", recording):
            try:
                got = w.verifier._fetch(url)
            except OSError as exc:  # a fetch that is not bounded_fetch is refused at 127.0.0.1:9; the record below says so
                got = exc
        self.assertEqual(used, [(url, {"schemes": ("https",)})], "the verifier's own fetch is not bounded_fetch")
        self.assertEqual(got, b"a.b.c")

    def test_the_default_fetch_end_to_end_follows_no_redirect_and_ignores_the_proxy_environment(self):
        box, seen = {}, []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path)
                if self.path == "/moved.jwt":
                    self.send_response(302)
                    self.send_header("Location", "/list.jwt")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                world = box["world"]
                uri = "http://127.0.0.1:%d%s" % (self.server.server_port, self.path)
                body = F.status_token(world.issuer_key, world.wallet.kid, uri, [0] * 16).encode("ascii")
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return None

        httpd = self.serve(Handler)
        host = "127.0.0.1:%d" % httpd.server_port
        proxy = "http://127.0.0.1:%d" % self.closed_port()
        env = {name: proxy for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy")}
        try:
            with mock.patch.dict(os.environ, env):
                for name in ("NO_PROXY", "no_proxy"):
                    os.environ.pop(name, None)
                # no fetch is given: the verifier goes to the loopback list by the fetch it builds for itself
                w = box["world"] = F.World(fetch=None, status_schemes=("http",), status_host=host)
                for path, counted in (("/list.jwt", True), ("/moved.jwt", False)):
                    status_, _, verdict = w.exchange(status_uri="http://%s%s" % (host, path))
                    self.assertEqual((status_, verdict.authentic), (200, True), path)
                    self.assertEqual(w.last()["counted"], counted, path)
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertEqual(seen, ["/list.jwt", "/moved.jwt"])  # the redirect was not followed

    def test_bounded_fetch_ignores_a_proxy_in_the_environment(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "5")
                self.end_headers()
                self.wfile.write(b"a.b.c")

            def log_message(self, *args):
                return None

        httpd = self.serve(Handler)
        proxy = "http://127.0.0.1:%d" % self.closed_port()  # nothing listens there
        env = {name: proxy for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy")}
        try:
            with mock.patch.dict(os.environ, env):
                for name in ("NO_PROXY", "no_proxy"):
                    os.environ.pop(name, None)
                self.assertEqual(sv.bounded_fetch("http://127.0.0.1:%d/ok" % httpd.server_port, schemes=("http",)), b"a.b.c")
        finally:
            httpd.shutdown()
            httpd.server_close()


class RecordTests(Base):
    def test_record_says_not_judged_for_a_check_that_did_not_run(self):
        self.w.exchange(status_idx=None)
        record = self.w.last()
        self.assertEqual(record["checks"]["L13"]["outcome"], "not judged")
        self.assertEqual(record["status"]["state"], "no_status_claim")
        self.assertFalse(record["counted"])
        # an error response in the clear reaches none of the three checks
        session, _ = self.w.verifier.new_request()
        status_, body, verdict = self.w.front.handle_direct_post({"error": ["access_denied"], "state": [session.state]})
        self.assertEqual((status_, body), (200, {}))
        record = self.w.last()
        self.assertEqual({k: v["outcome"] for k, v in record["checks"].items()}, {k: "not judged" for k in ("L7", "L10", "L13")})
        self.assertEqual(record["verdict"]["code"], "wallet_error")
        self.assertEqual(record["credential"], "not judged")
        self.assertEqual(record["checks"]["L10"]["parent"], "not judged")  # the package never reached _single_presentation
        self.assertEqual(record["status"], "not judged")  # neither the verdict nor L13 has an answer about the list
        self.assertFalse(record["counted"])

    def test_record_carries_the_parents_verdict_beside_each_check(self):
        """`verdict` is the answer handle_direct_post gave as run (the lab's checks inside it); each check's
        `parent` is the package's own answer at the place that check sits."""
        self.w.exchange(enc="A128GCM")
        record = self.w.last()
        self.assertNotIn("parent", record)
        self.assertEqual((record["verdict"]["status"], record["verdict"]["authentic"], record["verdict"]["code"]),
                         (400, False, "enc"))
        self.assertEqual(record["checks"]["L7"]["outcome"], "refused")
        for name in ("L7", "L10", "L13"):  # the package did not run
            self.assertEqual(record["checks"][name]["parent"], "not judged", name)
        self.assertEqual(record["checks"]["L10"]["outcome"], "not judged")
        # a credential with no kid: the package's _single_presentation passed it, L10 refused it
        self.w.exchange(kid=None)
        record = self.w.last()
        self.assertEqual((record["verdict"]["status"], record["verdict"]["authentic"], record["verdict"]["code"]),
                         (400, False, "invalid_request"))
        self.assertEqual(record["checks"]["L10"]["outcome"], "refused")
        self.assertEqual(record["checks"]["L10"]["parent"], "passed")
        self.assertEqual(record["checks"]["L7"]["parent"], {"status": 400, "code": "invalid_request"})
        self.assertEqual(record["checks"]["L13"]["parent"], "not judged")
        # a vp_token the package itself refuses: its refusal is L10's parent answer, and L10 judged nothing
        self.w.exchange(vp_token={"wrong_id": ["x"]})
        record = self.w.last()
        self.assertEqual(record["checks"]["L10"]["outcome"], "not judged")
        refusal = record["checks"]["L10"]["parent"]
        self.assertEqual(refusal["code"], "invalid_request")
        self.assertIn("vp_token", refusal["reason"])
        # accepted
        self.w.exchange()
        record = self.w.last()
        self.assertEqual(record["verdict"], {"status": 200, "authentic": True, "code": "", "reason": ""})
        self.assertEqual(record["checks"]["L7"]["parent"], {"status": 200, "code": ""})
        self.assertEqual(record["checks"]["L10"]["parent"], "passed")
        answer = record["checks"]["L13"]["parent"]
        self.assertEqual((answer["checked"], answer["status"], answer["code"]), (True, 0, None))
        json.dumps(record)  # every parent answer is plain data
        # L13's lab precondition failed (a host that is not the registry's): decide_by_fetching did not run
        self.w.exchange(status_uri="https://evil.example/api/v1/statuslist/1.jwt")
        record = self.w.last()
        self.assertEqual((record["checks"]["L13"]["outcome"], record["checks"]["L13"]["parent"]), ("refused", "not judged"))
        # the lab's authority callback declined a token (another DID): the package's answer is its own refusal
        self.w.tokens[F.STATUS_URI] = F.status_token(self.w.issuer_key, F.OTHER_DID + "#assert-key-01", F.STATUS_URI, [0] * 16)
        self.w.exchange()
        answer = self.w.last()["checks"]["L13"]["parent"]
        self.assertEqual((answer["checked"], answer["code"]), (False, "no_authority"))

    def test_a_response_with_padding_is_judged_by_l7_and_never_counted(self):
        """The package strips a token before it splits it; L7 reads the token the same way."""
        for name, pad in (("leading space", lambda t: " " + t), ("leading newline", lambda t: "\n" + t),
                          ("trailing space", lambda t: t + " ")):
            w = F.World()
            _, jar = w.verifier.new_request()
            form = w.wallet.respond(jar, enc="A128GCM")
            status_, _, verdict = w.front.handle_direct_post({"response": [pad(form["response"][0])]})
            record = w.last()
            self.assertEqual((status_, verdict.authentic), (400, False), name)
            self.assertEqual(record["checks"]["L7"]["outcome"], "refused", name)
            self.assertFalse(record["counted"], name)
        # the same padding on a response L7 accepts: the package takes it, L7 says ok, it counts
        w = F.World()
        _, jar = w.verifier.new_request()
        form = w.wallet.respond(jar)
        status_, _, verdict = w.front.handle_direct_post({"response": [" " + form["response"][0]]})
        self.assertEqual((status_, verdict.authentic, w.last()["checks"]["L7"]["outcome"], w.last()["counted"]),
                         (200, True, "ok", True))

    def test_a_padded_response_over_http_is_refused_by_l7(self):
        w = F.World()
        httpd = package_serve.serve(w.front, host="127.0.0.1", port=0, background=True)
        try:
            for name, pad in (("+", lambda t: " " + t), ("%0A", lambda t: "\n" + t), ("trailing", lambda t: t + " ")):
                _, jar = w.verifier.new_request()
                token = w.wallet.respond(jar, enc="A128GCM")["response"][0]
                body = urllib.parse.urlencode({"response": pad(token)})
                self.assertEqual(body[len("response="):][:1] == "+", name == "+")  # the wire really carries a '+'
                request = urllib.request.Request("http://127.0.0.1:%d/response" % httpd.server_port, data=body.encode("ascii"),
                                                 method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"})
                with self.assertRaises(urllib.error.HTTPError, msg=name) as caught:
                    F.OPENER.open(request, timeout=10)
                self.assertEqual(caught.exception.code, 400, name)
                self.assertEqual(w.last()["checks"]["L7"]["outcome"], "refused", name)
                self.assertFalse(w.last()["counted"], name)
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_a_check_that_did_not_judge_never_counts(self):
        """`counted` needs L7, L10 and L13 each to have said ok, besides the package's acceptance."""
        for name in ("L7", "L10", "L13"):
            w = F.World()
            real = sv.SwiyuVerifier.handle_direct_post
            _, jar = w.verifier.new_request()
            form = w.wallet.respond(jar)
            unjudged = {"outcome": sv.NOT_JUDGED, "detail": "forced"}
            if name == "L7":
                with mock.patch.object(sv, "check_enc", return_value=unjudged):
                    status_, _, verdict = w.front.handle_direct_post(form)
            else:
                def run_and_forget(verifier_self, f, _name=name):
                    out = real(verifier_self, f)
                    setattr(verifier_self._local, "l10" if _name == "L10" else "l13", None)
                    return out
                with mock.patch.object(sv.SwiyuVerifier, "handle_direct_post", run_and_forget):
                    status_, _, verdict = w.front.handle_direct_post(form)
            self.assertEqual((status_, verdict.authentic), (200, True), name)  # the package accepted it
            self.assertEqual(w.last()["checks"][name]["outcome"], sv.NOT_JUDGED, name)
            self.assertFalse(w.last()["counted"], name)

    def test_the_gate_does_not_lean_on_the_package_alone(self):
        """`counted` asks the list's answer itself: VALID, of a checked list, and fresh. The package refuses a revoked
        credential, so the other answers are put in its place by a stand-in for the package's verdict."""
        real = sv.SwiyuVerifier.handle_direct_post

        def with_revocation(revocation):
            def answer(verifier_self, form):
                real(verifier_self, form)
                return 200, {}, sdjwt.Verdict(True, revocation=revocation)
            return answer

        for revocation, counted in (({"state": "checked", "status": 0, "code": None, "stale": False}, True),
                                    ({"state": "checked", "status": 1, "code": None, "stale": False}, False),
                                    ({"state": "unreachable", "status": 0, "code": None, "stale": False}, False),
                                    ({"state": "checked", "status": 0, "code": None, "stale": True}, False),
                                    ({"state": "checked", "status": 0, "code": None, "stale": None}, False),
                                    ({"state": "checked", "status": 0, "code": None}, False)):
            w = F.World()
            _, jar = w.verifier.new_request()
            form = w.wallet.respond(jar)
            with mock.patch.object(sv.SwiyuVerifier, "handle_direct_post", with_revocation(revocation)):
                w.front.handle_direct_post(form)
            self.assertEqual(w.last()["checks"]["L13"]["outcome"], "ok", revocation)  # every check ran and passed
            self.assertEqual(w.last()["counted"], counted, revocation)

    def test_l7_says_not_judged_when_the_header_does_not_read(self):
        def b64(raw):
            return jwe.b64u_encode(raw)
        for name, header in (("not base64url", "!!!"), ("not UTF-8", b64(b"\xff\xfe\xfd")), ("not JSON", b64(b"{")),
                             ("not an object", b64(b"[1]")), ("empty", "")):
            w = F.World()
            w.verifier.new_request()
            status_, _, verdict = w.front.handle_direct_post({"response": ["%s.a.b.c.d" % header]})
            record = w.last()
            self.assertEqual(record["checks"]["L7"]["outcome"], sv.NOT_JUDGED, name)
            self.assertEqual((status_, verdict.authentic), (400, False), name)  # the package could not open it
            self.assertFalse(record["counted"], name)

    def test_a_stale_status_list_is_not_counted(self):
        self.w.tokens[F.STATUS_URI] = F.status_token(self.w.issuer_key, self.w.wallet.kid, F.STATUS_URI, [0] * 16,
                                                     iat=int(time.time()) - 7200)  # ttl 3600
        status_, _, verdict = self.w.exchange()
        record = self.w.last()
        self.assertEqual((status_, verdict.authentic), (200, True))  # the package accepts it
        self.assertEqual((record["status"]["state"], record["status"]["status"], record["status"]["stale"]),
                         ("checked", 0, True))
        self.assertFalse(record["counted"])

    def test_the_status_of_a_record_comes_from_l13_when_the_verdict_has_none(self):
        """The package refused after the list was read (a claim the request asked for is missing): the verdict
        carries no revocation, L13 ran, and the record says what L13 read, not "not judged"."""
        self.w.verifier.claims.append((["family_name"], None))
        status_, _, verdict = self.w.exchange()
        record = self.w.last()
        self.assertEqual((status_, verdict.authentic, verdict.code), (400, False, "claims"))
        self.assertIsNone(getattr(verdict, "revocation", None))
        self.assertEqual(record["checks"]["L13"]["outcome"], "ok")
        self.assertEqual(record["status"], {"state": "checked", "status": 0, "code": None, "stale": False})
        self.assertFalse(record["counted"])

    def test_the_record_names_the_package_that_judged(self):
        self.w.exchange()
        named = self.w.last()["package"]
        package_dir = pathlib.Path(polaris_oid4vp.__file__).resolve().parent
        self.assertEqual(named["name"], "polaris_oid4vp")
        # relative to the repository root, never an absolute path of this machine
        self.assertEqual(named["path"], "packages/polaris-oid4vp/polaris_oid4vp/__init__.py")
        self.assertFalse(os.path.isabs(named["path"]))
        self.assertNotIn(str(pathlib.Path.home()), json.dumps(named))
        self.assertRegex(named["version"], r"^\d+\.\d+\.\d+")
        self.assertTrue(re.fullmatch(r"[0-9a-f]{40}", named["commit"]) or named["commit"] == "unknown", named["commit"])
        self.assertIn(named["dirty"], (True, False, "unknown"))
        pyproject = (package_dir.parent / "pyproject.toml").read_text()
        self.assertIn('version = "%s"' % named["version"], pyproject)
        # a directory git does not answer for: "unknown", never a guess
        with tempfile.TemporaryDirectory() as tmp:
            outside = sv.package_identity(pathlib.Path(tmp) / "polaris_oid4vp")
            self.assertEqual((outside["commit"], outside["dirty"]), ("unknown", "unknown"))

    def test_a_package_outside_the_repository_is_named_without_its_absolute_path(self):
        with tempfile.TemporaryDirectory() as tree, tempfile.TemporaryDirectory() as elsewhere:
            package, root = pathlib.Path(elsewhere) / "polaris_oid4vp", pathlib.Path(tree)
            with self.assertRaises(ValueError):  # the precondition, by construction: the folder is not under the root it is told
                (package / "__init__.py").relative_to(root)
            named = sv.package_identity(package, root=root)
            self.assertEqual(named["path"], "outside the tree: polaris_oid4vp/__init__.py")
            self.assertNotIn(elsewhere, json.dumps(named))
            self.assertNotIn(tree, json.dumps(named))
            inside = sv.package_identity(root / "polaris_oid4vp", root=root)  # and a folder under the root is named from it
            self.assertEqual(inside["path"], "polaris_oid4vp/__init__.py")

    def test_the_record_says_whether_the_package_folder_held_uncommitted_changes(self):
        def run_git(tmp, *args):
            done = subprocess.run(["git", "-c", "user.name=lab", "-c", "user.email=lab@lab.invalid", "-c", "commit.gpgsign=false",
                                   "-C", tmp, *args], capture_output=True, text=True, timeout=60)
            self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual([n for n in os.environ if n.startswith("GIT_")], [])  # setUpModule cleared them
        with tempfile.TemporaryDirectory() as tmp:
            folder = pathlib.Path(tmp, "polaris_oid4vp")
            folder.mkdir()
            (folder / "__init__.py").write_text("X = 1\n")
            (pathlib.Path(tmp) / "other.txt").write_text("outside the package folder\n")
            run_git(tmp, "init", "-q")
            run_git(tmp, "add", ".")
            run_git(tmp, "commit", "-q", "-m", "scratch")
            sv._identity.cache_clear()
            clean = sv.package_identity(folder)
            self.assertRegex(clean["commit"], r"^[0-9a-f]{40}$")
            self.assertIs(clean["dirty"], False)
            (pathlib.Path(tmp) / "other.txt").write_text("changed, but not in the package folder\n")
            sv._identity.cache_clear()
            self.assertIs(sv.package_identity(folder)["dirty"], False)
            (folder / "__init__.py").write_text("X = 2\n")  # a tracked file changed
            sv._identity.cache_clear()
            self.assertIs(sv.package_identity(folder)["dirty"], True)
            run_git(tmp, "checkout", "--", "polaris_oid4vp/__init__.py")
            (folder / "new.py").write_text("Y = 1\n")  # an untracked file
            sv._identity.cache_clear()
            self.assertIs(sv.package_identity(folder)["dirty"], True)
        sv._identity.cache_clear()

    def test_the_package_under_test_is_the_trees_copy(self):
        tree = HERE.parents[2] / "packages" / "polaris-oid4vp"
        self.assertEqual(pathlib.Path(polaris_oid4vp.__file__).resolve().parent, (tree / "polaris_oid4vp").resolve())

    def test_an_installed_copy_never_judges_in_its_place(self):
        with tempfile.TemporaryDirectory() as decoy:
            os.mkdir(os.path.join(decoy, "polaris_oid4vp"))
            pathlib.Path(decoy, "polaris_oid4vp", "__init__.py").write_text("DECOY = True\n")
            code = ("import sys; sys.path.insert(0, %r); import swiyu_verifier, polaris_oid4vp; "
                    "print(polaris_oid4vp.__file__)" % str(HERE))
            done = subprocess.run([PY, "-B", "-c", code], capture_output=True, text=True, timeout=60, cwd=decoy,
                                  env=dict(os.environ, PYTHONPATH=decoy))
            self.assertEqual(done.returncode, 0, done.stderr)
            tree = HERE.parents[2] / "packages" / "polaris-oid4vp" / "polaris_oid4vp"
            self.assertEqual(pathlib.Path(done.stdout.strip()).resolve(), (tree / "__init__.py").resolve())

    # ---- the numbering of the files in a runs folder shared with an earlier process

    @staticmethod
    def seed(folder, *names):
        for name in names:
            pathlib.Path(folder, name).write_text('{"earlier": true}\n')

    def test_a_second_process_on_the_same_runs_folder_numbers_past_the_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.seed(tmp, "record-1.json", "capture-1.json")
            w = F.World(runs_dir=tmp)
            heard = []
            w.verifier.on_record = heard.append
            status_, body, verdict = w.exchange()
            self.assertEqual((status_, body, verdict.authentic), (200, {}, True))  # the package's own answer
            self.assertEqual(sorted(os.listdir(tmp)), ["capture-1.json", "capture-2.json", "record-1.json", "record-2.json"])
            self.assertEqual(len(heard), 1)
            self.assertEqual(heard[0]["n"], 2)
            self.assertEqual(json.loads(pathlib.Path(tmp, "record-2.json").read_text())["n"], 2)
            self.assertEqual(pathlib.Path(tmp, "record-1.json").read_text(), '{"earlier": true}\n')
            w.exchange()
            self.assertIn("record-3.json", os.listdir(tmp))

    def test_the_number_is_one_past_the_largest_of_either_kind(self):
        for seeded, expected in ((("record-1.json", "capture-1.json", "record-4.json"), 5), (("capture-7.json",), 8),
                                 (("record-3.json", "notes.txt", "record-x.json"), 4)):
            with tempfile.TemporaryDirectory() as tmp:
                self.seed(tmp, *seeded)
                w = F.World(runs_dir=tmp)
                w.exchange()
                self.assertEqual(w.last()["n"], expected, seeded)
                self.assertTrue(os.path.exists(os.path.join(tmp, "record-%d.json" % expected)))
                self.assertTrue(os.path.exists(os.path.join(tmp, "capture-%d.json" % expected)))

    def test_a_file_that_appears_after_the_scan_moves_to_the_next_number(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.seed(tmp, "capture-1.json")  # the scan is made blind, so number 1 is tried and its capture is taken
            w = F.World(runs_dir=tmp)
            with mock.patch.object(sv.SwiyuVerifier, "_highest_in_folder", return_value=0):
                status_, _, _ = w.exchange()
            self.assertEqual(status_, 200)
            self.assertEqual(w.last()["n"], 2)
            self.assertEqual(sorted(os.listdir(tmp)), ["capture-1.json", "capture-2.json", "record-2.json"],
                             "the record made for the number that was taken is not left behind")

    def test_the_search_for_a_free_number_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.seed(tmp, *["record-%d.json" % n for n in range(1, 101)])
            w = F.World(runs_dir=tmp)
            heard = []
            w.verifier.on_record = heard.append
            with mock.patch.object(sv.SwiyuVerifier, "_highest_in_folder", return_value=0):
                with self.assertRaises(FileExistsError):
                    w.exchange()
            self.assertEqual(heard, [])
            self.assertEqual(len(os.listdir(tmp)), 100)
        with tempfile.TemporaryDirectory() as tmp:
            self.seed(tmp, *["record-%d.json" % n for n in range(1, 100)])
            w = F.World(runs_dir=tmp)
            with mock.patch.object(sv.SwiyuVerifier, "_highest_in_folder", return_value=0):
                w.exchange()
            self.assertEqual(w.last()["n"], 100)

    def test_record_is_written_with_hashes_and_no_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = F.World(runs_dir=tmp, wallet_version="1.19.0-test")
            _, jar = w.verifier.new_request()
            form = w.wallet.respond(jar)
            token = form["response"][0]
            w.front.handle_direct_post(form)
            files = sorted(os.listdir(tmp))
            self.assertEqual(files, ["capture-1.json", "record-1.json"])
            for name in files:
                self.assertEqual(stat.S_IMODE(os.stat(os.path.join(tmp, name)).st_mode), 0o600)
            record = json.loads(pathlib.Path(tmp, "record-1.json").read_text())
            self.assertEqual(record["response_sha256"], hashlib.sha256(token.encode()).hexdigest())
            self.assertIn(hashlib.sha256(jar.encode()).hexdigest(), record["request_sha256"])
            self.assertEqual((record["wallet_version"], record["variant"]), ("1.19.0-test", "A"))
            self.assertNotIn(token, json.dumps(record))
            capture = json.loads(pathlib.Path(tmp, "capture-1.json").read_text())
            self.assertEqual(capture["response"], token)
            self.assertIn(jar, capture["request_objects"])
            self.assertEqual(list(capture["vp_token"]), [sv.QUERY_ID])

    def test_variant_follows_the_statements(self):
        self.assertEqual(self.w.verifier.variant, "A")
        info = F.as_info(F.identity_statement(self.w.trust_key, F.VERIFIER_DID))
        self.assertEqual(F.World(verifier_info=info).verifier.variant, "B")
        info = F.as_info(F.identity_statement(self.w.trust_key, F.VERIFIER_DID),
                         F.query_statement(self.w.trust_key, F.VERIFIER_DID, "s"))
        self.assertEqual(F.World(verifier_info=info, scope="s").verifier.variant, "C")


class DirtyTests(unittest.TestCase):
    """package_identity's `dirty`, in scratch git repositories (setUpModule cleared every GIT_* variable)."""

    def git(self, tmp, *args, check=True):
        done = subprocess.run(["git", "-c", "user.name=lab", "-c", "user.email=lab@lab.invalid", "-c", "commit.gpgsign=false",
                               "-C", str(tmp), *args], capture_output=True, text=True, timeout=60)
        if check:
            self.assertEqual(done.returncode, 0, done.stderr)
        return done

    def repo(self, tmp, gitignore=None):
        """A committed folder `polaris_oid4vp` (the package folder) and a committed file beside it."""
        self.assertEqual([n for n in os.environ if n.startswith("GIT_")], [])
        folder = pathlib.Path(tmp, "polaris_oid4vp")
        folder.mkdir()
        (folder / "__init__.py").write_text("X = 1\n")
        pathlib.Path(tmp, "other.txt").write_text("beside the package folder\n")
        if gitignore is not None:
            pathlib.Path(tmp, ".gitignore").write_text(gitignore)
        self.git(tmp, "init", "-q")
        self.git(tmp, "add", ".")
        self.git(tmp, "commit", "-q", "-m", "scratch")
        return folder

    def dirty(self, folder):
        sv._identity.cache_clear()
        try:
            return sv.package_identity(folder)["dirty"]
        finally:
            sv._identity.cache_clear()

    def plain_status(self, folder):
        """What an ordinary `git status --porcelain` lists for the folder."""
        return self.git(folder.parent, "status", "--porcelain", "--", "polaris_oid4vp").stdout.strip()

    def test_an_ignored_source_file_is_a_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = self.repo(tmp, gitignore="ignored_*.py\n")
            self.assertIs(self.dirty(folder), False)
            (folder / "ignored_x.py").write_text("Y = 1\n")
            self.assertEqual(self.plain_status(folder), "")  # the ordinary command does not list it
            self.assertIs(self.dirty(folder), True)

    def test_an_untracked_file_is_a_change_whatever_the_repository_says_about_untracked_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = self.repo(tmp)
            self.git(tmp, "config", "status.showUntrackedFiles", "no")
            (folder / "new.py").write_text("Y = 1\n")
            self.assertEqual(self.plain_status(folder), "")  # the repository hides it from the ordinary command
            self.assertIs(self.dirty(folder), True)

    def test_python_caches_alone_are_not_a_change(self):
        with tempfile.TemporaryDirectory() as tmp:  # not ignored: git lists each file
            folder = self.repo(tmp)
            (folder / "__pycache__").mkdir()
            (folder / "__pycache__" / "x.cpython-312.pyc").write_bytes(b"\0")
            (folder / "sub" / "__pycache__").mkdir(parents=True)
            (folder / "sub" / "__pycache__" / "y.cpython-312.pyc").write_bytes(b"\0")
            (folder / "__pycache__" / "notes.txt").write_text("a file inside a __pycache__ folder\n")
            (folder / "loose.pyc").write_bytes(b"\0")
            self.assertNotEqual(self.plain_status(folder), "")  # git does list them
            self.assertIs(self.dirty(folder), False)
            (folder / "my__pycache__").mkdir()
            (folder / "my__pycache__" / "z.py").write_text("Z = 1\n")  # a folder only NAMED like one is a change
            self.assertIs(self.dirty(folder), True)
        with tempfile.TemporaryDirectory() as tmp:  # ignored: git lists the folder
            folder = self.repo(tmp, gitignore="__pycache__/\n")
            (folder / "__pycache__").mkdir()
            (folder / "__pycache__" / "x.cpython-312.pyc").write_bytes(b"\0")
            self.assertEqual(self.plain_status(folder), "")
            self.assertIs(self.dirty(folder), False)
            (folder / "new.py").write_text("Y = 1\n")  # beside the cache, a real change
            self.assertIs(self.dirty(folder), True)

    def test_a_git_that_has_a_commit_but_no_status_says_unknown_never_clean(self):
        # rev-parse runs for real; only `git status` is faked, so no repository is touched
        real_run = subprocess.run

        def failing_status(command, *args, **kwargs):  # a status that exits non-zero
            if "status" in command:
                return subprocess.CompletedProcess(command, 128, stdout="", stderr="fatal: index file corrupt\n")
            return real_run(command, *args, **kwargs)

        def slow_status(command, *args, **kwargs):  # a status that does not finish in time
            if "status" in command:
                raise subprocess.TimeoutExpired(command, 10)
            return real_run(command, *args, **kwargs)

        for fake in (failing_status, slow_status):
            with self.subTest(fake.__name__), tempfile.TemporaryDirectory() as tmp:
                folder = self.repo(tmp)
                self.assertIs(self.dirty(folder), False)
                sv._identity.cache_clear()
                with mock.patch.object(sv.subprocess, "run", fake):
                    named = sv.package_identity(folder)
                sv._identity.cache_clear()
                self.assertRegex(named["commit"], r"^[0-9a-f]{40}$")
                self.assertEqual(named["dirty"], "unknown")


class OnlyRefuseTests(unittest.TestCase):
    """L15: a lab check may refuse what the package would accept; it never accepts what the package
    refuses. Each of L7, L10 and L13 is held with three inputs, the same for the lab and for the package
    alone: one both accept, one both refuse, one only the lab refuses."""

    class Bare(sv.SwiyuVerifier):
        """The lab verifier with the L10 override taken out and L13's resolver replaced by the package's
        own decision (a stated authority for the issuer's key, any host, any size)."""
        _single_presentation = Verifier._single_presentation

    @staticmethod
    def plain_resolver(w):
        def resolve(*, uri, idx, issuer):
            authority = status.StatedAuthority().state(
                credential_issuer=issuer, status_uri=uri, why="test",
                verify=lambda signing_input, signature, header: sdjwt._verify_es256(
                    w.issuer_key.public_key(), signing_input, signature))
            return status.decide_by_fetching(index=idx, expected_uri=uri, authority=authority, fetch=w._fetch,
                                             credential_issuer=issuer)
        return resolve

    def outcomes(self, kwargs, status_list=None):
        lab = F.World(status_list=status_list)
        bare = F.World(verifier_class=self.Bare, status_list=status_list)
        bare.verifier.status_resolver = self.plain_resolver(bare)
        _, jar = lab.verifier.new_request()
        s1, _, v1 = lab.front.handle_direct_post(lab.wallet.respond(jar, **kwargs))
        counted_lab = lab.last()["counted"]
        self.lab_record = lab.last()
        _, jar = bare.verifier.new_request()
        s2, _, v2 = bare.verifier.handle_direct_post(bare.wallet.respond(jar, **kwargs))
        rev = v2.revocation or {}
        counted_bare = bool(v2.authentic and rev.get("state") == "checked" and rev.get("status") == 0)
        return (s1, v1.authentic, v1.code, counted_lab), (s2, v2.authentic, v2.code, counted_bare)

    def test_lab_checks_only_refuse(self):
        revoked = [0] * 7 + [1] + [0] * 8
        # (good, both refuse with the lab check passing, only the lab refuses, the status list for "both refuse")
        cases = {
            "L7": ({}, {"nonce": "another"}, {"enc": "A128GCM"}, None),
            "L10": ({}, {"nonce": "another"}, {"kid": None}, None),
            "L13": ({}, {}, {"status_uri": "https://evil.example/api/v1/statuslist/1.jwt"}, revoked),
        }
        # what the lab's refusal looks like on the wire: L7 and L10 answer 400. L13 does not stop the answer: the
        # package accepts a credential whose list could not be read, and the record does not count it.
        lab_wire = {"L7": (400, False), "L10": (400, False), "L13": (200, True)}
        for check, (good, both_refuse, lab_only, bad_list) in cases.items():
            with self.subTest(check=check, case="both accept"):
                lab, bare = self.outcomes(good)
                self.assertEqual(lab, bare)
                self.assertEqual(lab, (200, True, "", True))
            with self.subTest(check=check, case="both refuse"):
                lab, bare = self.outcomes(both_refuse, bad_list)
                self.assertEqual(lab, bare)
                self.assertEqual(lab[:2], (400, False))
                # the lab's check passed and the package refused after it: the refusal is the package's
                self.assertEqual(self.lab_record["checks"][check]["outcome"], "ok")
            with self.subTest(check=check, case="only the lab refuses"):
                lab, bare = self.outcomes(lab_only)
                self.assertTrue(bare[3], "the package alone must accept and count it, or this case proves nothing")
                self.assertEqual(lab[:2], lab_wire[check], "the lab's answer on the wire")
                self.assertFalse(lab[3], "the lab check must stop it")
                self.assertFalse(lab[1] and not bare[1], "a lab acceptance the package refuses")
                self.assertEqual(self.lab_record["checks"][check]["outcome"], "refused")
        with self.subTest(check="L7", case="the lab refuses and the package would too"):
            lab, bare = self.outcomes({"enc": "A128GCM", "nonce": "another"})
            self.assertEqual(lab[:2], (400, False))
            self.assertEqual(bare[:2], (400, False))
            self.assertFalse(lab[3] or bare[3])
            self.assertEqual(self.lab_record["checks"]["L7"]["outcome"], "refused")


class PinTests(unittest.TestCase):
    """The members of the package the subclass leans on, and the one thing it must not change."""

    def test_handle_direct_post_is_the_parents(self):
        self.assertIs(sv.SwiyuVerifier.handle_direct_post, Verifier.handle_direct_post)
        self.assertIs(sv.SwiyuVerifier.request_object, Verifier.request_object)
        self.assertIsNot(sv.SwiyuVerifier._single_presentation, Verifier._single_presentation)
        self.assertIsNot(sv.SwiyuVerifier._request_object, Verifier._request_object)

    def test_parent_members_the_subclass_leans_on(self):
        def names(fn):
            return list(inspect.signature(fn).parameters)
        self.assertEqual(names(Verifier._request_object), ["self", "session", "wallet_nonce"])
        self.assertEqual(names(Verifier._dcql_query), ["self"])
        self.assertEqual(names(Verifier._single_presentation), ["self", "vp_token"])
        self.assertEqual(names(Verifier.handle_direct_post), ["self", "form"])
        self.assertEqual(names(Verifier.request_object), ["self", "state", "wallet_nonce", "wallet_metadata"])
        self.assertEqual(names(Verifier.new_request), ["self", "transaction_data"])
        self.assertEqual(names(Verifier.redeem), ["self", "response_code", "state"])
        self.assertEqual(names(Verifier.authorization_request_params), ["self", "session"])
        self.assertEqual(names(parent._sign_es256), ["key", "header", "claims"])
        self.assertEqual(names(jwe._loads_depth_bounded), ["raw", "what", "limit", "finite"])
        self.assertEqual(jwe.ACCEPTED_ENC, {"A128GCM": 16, "A256GCM": 32})  # L7 narrows this set
        self.assertEqual(names(sdjwt._parse_jws), ["token"])
        self.assertEqual(names(sdjwt._verify_es256), ["public_key", "signing_input", "signature"])
        self.assertEqual(names(sdjwt._es256_public_key), ["jwk"])
        self.assertEqual(names(status.StatedAuthority.state), ["self", "credential_issuer", "status_uri", "verify", "why"])
        self.assertIn("status_resolver", names(sdjwt.verify_presentation))
        self.assertEqual(names(status.decide_by_fetching),
                         ["index", "expected_uri", "authority", "fetch", "now", "credential_issuer",
                          "issuer_key_verify", "max_age_seconds"])
        # the resolver contract the parent calls (sdjwt._revocation_state): uri, idx, issuer
        self.assertIn('resolver(uri=ref["uri"], idx=ref["idx"], issuer=issuer)', inspect.getsource(sdjwt._revocation_state))
        # the response path the lab sits in front of: it decrypts, then asks _single_presentation
        source = inspect.getsource(Verifier.handle_direct_post)
        for fragment in ("decrypt_response(token, candidate.enc_key)", "self._single_presentation(body.get(\"vp_token\"))",
                         "status_resolver=self.status_resolver", "expected_audience=self.client_id"):
            self.assertIn(fragment, source)

    def test_the_package_alone_is_not_the_swiss_request(self):
        """What the lab changes: the same constructor inputs give the package's x509_hash request."""
        key = F.new_key()
        plain = Verifier(client_cert_pem=sv.self_signed_pem(key), client_key_pem=F.key_pem(key),
                         request_uri=F.PUBLIC_URL + "/request.jwt", response_uri=F.PUBLIC_URL + "/response",
                         vct_values=list(sv.VCT_VALUES), claims=[sv.CLAIM], credential_query_id=sv.QUERY_ID)
        session, jar = plain.new_request()
        header, claims = F.parts(jar)
        self.assertEqual(sorted(header), ["alg", "typ", "x5c"])
        self.assertTrue(claims["client_id"].startswith("x509_hash:"))
        self.assertEqual(sorted(claims["client_metadata"]), ["encrypted_response_enc_values_supported", "jwks", "vp_formats_supported"])
        self.assertIn("request_uri_method", plain.authorization_request_params(session))


SCRIPT_TOKEN = "tok-SECRET-0123456789"
JAR_SHA = "e1804393b2bb56164e22cad7cf852524118f92dc9e13677ee49ca3e38bf62af1"
IMAGE = "gradle:8.14.3-jdk21@sha256:21bd311ed01360c189b8870c6b6e988199ff10f72d445d02fb39d3cff9da91d7"
STUB_CURL = r"""#!/bin/bash
# records its arguments, its stdin and any @body file; copies what the script had printed so far; answers from a file.
# With an exit file for the call it exits with that status, as curl --fail-with-body does after writing an HTTP error's
# body; with an exit file and no answer file it writes no output file, as curl does when no answer comes.
t=curl; n=$(( $(wc -l < "$STUB_DIR/$t.calls" 2>/dev/null || echo 0) + 1 ))
{ printf '%s' "$t"; for a in "$@"; do printf ' [%s]' "$a"; done; printf '\n'; } >> "$STUB_DIR/$t.calls"
cp "$STUB_OUT" "$STUB_DIR/$t.out-at-call.$n"
cat > "$STUB_DIR/$t.stdin.$n"
out=""; prev=""
for a in "$@"; do
  [ "$prev" = "-o" ] && out="$a"
  case "$a" in @*) cp "${a#@}" "$STUB_DIR/$t.body.$n";; esac
  prev="$a"
done
if [ -n "$out" ]; then
  if [ -f "$STUB_DIR/$t.answer.$n" ]; then cat "$STUB_DIR/$t.answer.$n" > "$out"
  elif [ ! -f "$STUB_DIR/$t.exit.$n" ]; then : > "$out"; fi
fi
if [ -f "$STUB_DIR/$t.exit.$n" ]; then exit "$(cat "$STUB_DIR/$t.exit.$n")"; fi
exit 0
"""
STUB_DOCKER = r"""#!/bin/bash
t=docker; n=$(( $(wc -l < "$STUB_DIR/$t.calls" 2>/dev/null || echo 0) + 1 ))
{ printf '%s' "$t"; for a in "$@"; do printf ' [%s]' "$a"; done; printf '\n'; } >> "$STUB_DIR/$t.calls"
cp "$STUB_OUT" "$STUB_DIR/$t.out-at-call.$n"
work=""; prev=""; create=0
for a in "$@"; do
  if [ "$prev" = "-v" ]; then case "$a" in *:/work) work="${a%:/work}";; esac; fi
  [ "$a" = "create" ] && create=1
  prev="$a"
done
if [ "$create" = 1 ] && [ -n "$work" ]; then
  mkdir -p "$work/.didtoolbox"; chmod 755 "$work/.didtoolbox"
  for f in id_ed25519 id_ed25519.pub assert-key-01 assert-key-01.pub auth-key-01 auth-key-01.pub; do
    echo fake > "$work/.didtoolbox/$f"; chmod 644 "$work/.didtoolbox/$f"
  done
fi
if [ -f "$STUB_DIR/$t.answer.$n" ]; then cat "$STUB_DIR/$t.answer.$n"; fi
exit 0
"""
STUB_SHASUM = r"""#!/bin/bash
printf '%s  %s\n' "$(cat "$STUB_DIR/jar.sha")" "$3"
"""
STUB_CLOUDFLARED = r"""#!/bin/bash
t=cloudflared
{ printf '%s' "$t"; for a in "$@"; do printf ' [%s]' "$a"; done; printf '\n'; } >> "$STUB_DIR/$t.calls"
echo "INF |  https://stub-lab-test.trycloudflare.com  |"
exec bash -c 'while :; do sleep 1; done' "$STUB_DIR"
"""


def default_sigint():
    """A shell started in the background by another shell has SIGINT ignored, and a script cannot trap a signal that was
    ignored when it started: run.sh is started with SIGINT at its default, whatever started this suite."""
    signal.signal(signal.SIGINT, signal.SIG_DFL)


class ScriptBase(unittest.TestCase):
    """The owner's scripts, run with fake curl, docker, shasum and cloudflared first on PATH. The fakes
    record their arguments and answer from files; the real tools are never reached."""

    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        r = pathlib.Path(self.root.name)
        self.stub, self.cwd, self.home, self.tmp, self.key = r / "stub", r / "cwd", r / "home", r / "tmp", r / "keys"
        self.bin = r / "bin"
        for d in (self.stub, self.cwd, self.home, self.tmp, self.bin):
            d.mkdir()
        for name, body in (("curl", STUB_CURL), ("docker", STUB_DOCKER), ("shasum", STUB_SHASUM),
                           ("cloudflared", STUB_CLOUDFLARED)):
            (self.bin / name).write_text(body)
            os.chmod(self.bin / name, 0o755)
        self.jar = r / "didtoolbox-2.3.0.jar"
        self.jar.write_bytes(b"not a jar")
        (self.stub / "jar.sha").write_text(JAR_SHA)
        self.out = r / "out.txt"
        self.env = {"PATH": "%s:/usr/bin:/bin" % self.bin, "HOME": str(self.home), "TMPDIR": str(self.tmp),
                    "STUB_DIR": str(self.stub), "STUB_OUT": str(self.out), "PYTHON": PY,
                    "SWIYU_IDENTIFIER_REGISTRY_ACCESS_TOKEN": SCRIPT_TOKEN, "SWIYU_TRUST_REGISTRY_ACCESS_TOKEN": SCRIPT_TOKEN,
                    "SWIYU_PARTNER_ID": "8432e1f3-8119-4fb9-a879-190ab2cb9deb"}  # the onboarding cookbook's example value
                    # (cookbooks_onboarding-base-and-trust-registry.txt)

    def tearDown(self):
        self.root.cleanup()

    def answer(self, tool, n, text):
        (self.stub / ("%s.answer.%d" % (tool, n))).write_text(text)

    def run_script(self, name, *args, drop=(), extra=None, timeout=120):
        """Run a script in its own session. A script that has not stopped by `timeout` is a failure of the test, and its
        whole process group (the script, and any stub it started) is killed and waited for."""
        env = {k: v for k, v in self.env.items() if k not in drop}
        env.update(extra or {})
        with open(self.out, "w") as out:
            proc = subprocess.Popen(["bash", str(HERE / name), *args], env=env, cwd=self.cwd, stdin=subprocess.DEVNULL,
                                    stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                returncode = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.stop_group(proc)
                self.fail("%s %s did not stop within %s s:\n%s" % (name, " ".join(args), timeout, self.out.read_text()))
            finally:
                self.stop_group(proc)
        return returncode, self.out.read_text()

    @staticmethod
    def stop_group(proc):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait()

    def calls(self, tool):
        path = self.stub / (tool + ".calls")
        return path.read_text().splitlines() if path.exists() else []

    def forget(self, tool):
        for f in os.listdir(self.stub):
            if f.startswith(tool + "."):
                os.unlink(self.stub / f)

    def snapshot(self, tool, n):
        return (self.stub / ("%s.out-at-call.%d" % (tool, n))).read_text()

    def mode(self, path):
        return stat.S_IMODE(os.stat(path).st_mode)

    def assert_nothing_else_written(self):
        for d in (self.cwd, self.home, self.tmp):
            self.assertEqual(os.listdir(d), [], "%s was written to" % d)

    def assert_clean_output(self, text):
        self.assertNotIn(SCRIPT_TOKEN, text)
        self.assertEqual(text.splitlines()[-1], "done")


class DidScriptTests(ScriptBase):
    # the DID space and its URL are the onboarding cookbook's example values (cookbooks_onboarding-base-and-trust-registry.txt)
    REG = "https://identifier-reg.trust-infra.swiyu.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085"

    def prepare(self, listing=None):
        self.answer("curl", 1, json.dumps(listing if listing is not None else {"content": [
            {"id": "11111111-1111-4111-8111-111111111111", "identifierRegistryUrl": "https://x/used", "status": "ACTIVE"},
            {"id": "18fa7c77-9dd1-4e20-a147-fb1bec146085", "identifierRegistryUrl": self.REG, "status": "NOT_INITIALIZED"}]}))
        w = F.World()
        self.answer("docker", 1, w.log)
        return w

    def test_did_sh_prints_before_it_sends_and_hides_the_token(self):
        w = self.prepare()
        rc, text = self.run_script("did.sh", str(self.key), str(self.jar))
        self.assertEqual(rc, 0, text)
        self.assert_clean_output(text)
        partner = self.env["SWIYU_PARTNER_ID"]
        get = "REQUEST GET https://identifier-reg-api.trust-infra.swiyu-int.admin.ch/api/v1/identifier/business-entities/%s/identifier/" % partner
        put = ("REQUEST PUT https://identifier-reg-api.trust-infra.swiyu-int.admin.ch/api/v1/identifier/business-entities/%s/"
               "identifier-entries/18fa7c77-9dd1-4e20-a147-fb1bec146085" % partner)
        self.assertIn(get, text)
        self.assertIn(put, text)
        self.assertIn("Authorization: Bearer <redacted>", text)
        self.assertIn("Content-Type: application/jsonl+json", text)
        # printed before the fake curl was called, each time
        self.assertIn(get, self.snapshot("curl", 1))
        self.assertIn(put, self.snapshot("curl", 2))
        self.assertNotIn(put, self.snapshot("curl", 1))
        self.assertEqual(len(self.calls("curl")), 2)
        # the token went to curl on its standard input and appears in no argument
        self.assertIn(SCRIPT_TOKEN, (self.stub / "curl.stdin.1").read_text())
        self.assertNotIn(SCRIPT_TOKEN, "\n".join(self.calls("curl") + self.calls("docker")))
        # the DID tool: pinned image, no network, no pull, the jar read-only, the key folder as the work dir
        (call,) = self.calls("docker")
        for piece in ("[--network] [none]", "[--pull] [never]", "[%s]" % IMAGE, "[--name] [swiyu-did-", "[%s:/work]" % self.key,
                      "[%s:/opt/didtoolbox.jar:ro]" % self.jar, "[create] [--identifier-registry-url] [%s]" % self.REG):
            self.assertIn(piece, call)
        self.assertIn(get, self.snapshot("docker", 1))  # the listing was shown before the tool ran
        # what it left: a 700 folder, 600 files, the DID, and nothing anywhere else
        self.assertEqual(self.mode(self.key), 0o700)
        self.assertEqual(self.mode(self.key / ".didtoolbox"), 0o700)
        keys = os.listdir(self.key / ".didtoolbox")
        self.assertTrue(keys)
        for f in keys:
            self.assertEqual(self.mode(self.key / ".didtoolbox" / f), 0o600, f)
        for name in ("did.jsonl", "did"):
            self.assertEqual(self.mode(self.key / name), 0o600, name)
        self.assertEqual((self.key / "did.jsonl").read_text(), w.log)
        self.assertEqual((self.key / "did").read_text().strip(), F.VERIFIER_DID)
        self.assertEqual(sorted(os.listdir(self.key)), [".didtoolbox", "did", "did.jsonl"])
        self.assert_nothing_else_written()
        self.assertEqual((self.stub / "curl.body.2").read_text(), w.log)

    def test_did_sh_refuses_a_jar_with_another_hash(self):
        self.prepare()
        (self.stub / "jar.sha").write_text("0" * 64)
        rc, text = self.run_script("did.sh", str(self.key), str(self.jar))
        self.assertNotEqual(rc, 0)
        self.assertIn("jar sha256", text)
        self.assertIn(JAR_SHA, text)
        self.assertEqual((self.calls("curl"), self.calls("docker")), ([], []))
        self.assertFalse(self.key.exists())
        self.assertNotIn(SCRIPT_TOKEN, text)
        self.assert_nothing_else_written()

    def test_did_sh_keeps_nothing_it_cannot_use_and_uploads_nothing_it_cannot_read(self):
        # the tool wrote no log: nothing is left behind, nothing is uploaded
        self.prepare()
        self.answer("docker", 1, "")
        rc, text = self.run_script("did.sh", str(self.key), str(self.jar))
        self.assertNotEqual(rc, 0)
        self.assertIn("wrote no log", text)
        self.assertFalse((self.key / "did.jsonl").exists())
        self.assertEqual(len(self.calls("curl")), 1)
        # a log whose first entry names a DID that is not did:webvh: not saved as the DID, not uploaded
        self.forget("curl")
        self.forget("docker")
        (self.key / "did").unlink(missing_ok=True)
        (self.key / "did.jsonl").unlink(missing_ok=True)
        self.prepare()
        self.answer("docker", 1, json.dumps({"state": {"id": "did:web:example.org"}}) + "\n")
        rc, text = self.run_script("did.sh", str(self.key), str(self.jar))
        self.assertNotEqual(rc, 0)
        self.assertFalse((self.key / "did").exists())
        self.assertEqual(len(self.calls("curl")), 1)

    def test_did_sh_refuses_what_it_cannot_do_safely(self):
        self.prepare()
        rc, text = self.run_script("did.sh", str(self.key), str(self.jar), drop=("SWIYU_IDENTIFIER_REGISTRY_ACCESS_TOKEN",))
        self.assertEqual(rc, 2)
        self.assertIn("SWIYU_IDENTIFIER_REGISTRY_ACCESS_TOKEN", text)
        rc, text = self.run_script("did.sh", str(self.key), str(self.jar), drop=("SWIYU_PARTNER_ID",))
        self.assertEqual(rc, 2)
        rc, text = self.run_script("did.sh", str(self.key))
        self.assertEqual(rc, 2)
        self.assertEqual((self.calls("curl"), self.calls("docker")), ([], []))
        # no free DID space: the parsed list is empty, and nothing runs after it
        for listing in ({"content": []}, {"content": [{"id": "a", "identifierRegistryUrl": "u", "status": "ACTIVE"}]}, {}):
            self.forget("curl")
            self.prepare(listing)
            rc, text = self.run_script("did.sh", str(self.key), str(self.jar))
            self.assertNotEqual(rc, 0, listing)
            self.assertIn("NOT_INITIALIZED", text)
            self.assertEqual(self.calls("docker"), [])
            self.assertEqual(len(self.calls("curl")), 1)
            self.assertFalse((self.key / "did.jsonl").exists())
        # a folder that already has a DID log
        self.forget("curl")
        self.key.mkdir(exist_ok=True)
        (self.key / "did.jsonl").write_text("x\n")
        self.prepare()
        rc, text = self.run_script("did.sh", str(self.key), str(self.jar))
        self.assertNotEqual(rc, 0)
        self.assertEqual(self.calls("docker"), [])
        self.assertEqual(self.calls("curl"), [])
        self.assertEqual((self.key / "did.jsonl").read_text(), "x\n")
        self.assertNotIn(SCRIPT_TOKEN, text)


class PopScriptTests(ScriptBase):
    NONCE = "99A2BF79-3575-4824-87A5-8F66E6E8C2C7"  # the onboarding cookbook's example value
    # (cookbooks_onboarding-base-and-trust-registry.txt, the proof-of-possession challenge)
    POP = "aaaa.bbbb.cccc"

    def prepare(self, pop=None, entries=None):
        w = F.World()
        F.write_keyfolder(self.key, w)
        os.chmod(self.key, 0o700)
        self.answer("curl", 1, json.dumps(entries if entries is not None else [{"did": F.VERIFIER_DID, "nonce": self.NONCE}]))
        self.answer("docker", 1, (self.POP if pop is None else pop) + "\n")

    def test_pop_sh_prints_before_it_sends_and_hides_both_tokens(self):
        self.prepare()
        rc, text = self.run_script("pop.sh", str(self.key), str(self.jar))
        self.assertEqual(rc, 0, text)
        self.assert_clean_output(text)
        self.assertNotIn(self.POP, text)
        base = "https://trust-reg-api.trust-infra.swiyu-int.admin.ch/api/v1/trust/trust-onboarding-submission/proof-of-possessions"
        self.assertIn("REQUEST GET " + base, text)
        self.assertIn("REQUEST POST " + base, text)
        self.assertIn('{"proofOfPossessions": ["<redacted>"]}', text)
        self.assertIn("REQUEST POST " + base, self.snapshot("curl", 2))
        self.assertNotIn("REQUEST POST", self.snapshot("curl", 1))
        self.assertEqual(json.loads((self.stub / "curl.body.2").read_text()), {"proofOfPossessions": [self.POP]})
        self.assertNotIn(SCRIPT_TOKEN, "\n".join(self.calls("curl") + self.calls("docker")))
        (call,) = self.calls("docker")
        for piece in ("[--network] [none]", "[--pull] [never]", "[%s]" % IMAGE,
                      "[create-pop] [-d] [did.jsonl] [-k] [%s#assert-key-01]" % F.VERIFIER_DID,
                      "[-s] [.didtoolbox/assert-key-01] [-n] [%s]" % self.NONCE):
            self.assertIn(piece, call)
        self.assertNotIn("[create]", call)
        self.assertEqual(sorted(os.listdir(self.key)), [".didtoolbox", "did", "did.jsonl", "issuer-pin.json"])
        self.assert_nothing_else_written()

    def test_pop_sh_refuses_a_jar_with_another_hash_and_a_challenge_that_is_not_ours(self):
        self.prepare()
        (self.stub / "jar.sha").write_text("f" * 64)
        rc, text = self.run_script("pop.sh", str(self.key), str(self.jar))
        self.assertNotEqual(rc, 0)
        self.assertEqual((self.calls("curl"), self.calls("docker")), ([], []))
        (self.stub / "jar.sha").write_text(JAR_SHA)
        for entries in ([], [{"did": F.OTHER_DID, "nonce": self.NONCE}], [{"did": F.VERIFIER_DID, "nonce": ""}]):
            self.forget("curl")
            self.forget("docker")
            self.prepare(entries=entries)
            rc, text = self.run_script("pop.sh", str(self.key), str(self.jar))
            self.assertNotEqual(rc, 0, entries)
            self.assertIn("holds no challenge", text, entries)
            self.assertEqual(self.calls("docker"), [], entries)
            self.assertNotIn(SCRIPT_TOKEN, text)
        # a proof that is not one compact JWS is not sent
        for pop in ("", "no-dots", "a.b", "a.b.c\nd.e.f"):
            self.forget("curl")
            self.forget("docker")
            self.prepare(pop=pop)
            rc, text = self.run_script("pop.sh", str(self.key), str(self.jar))
            self.assertNotEqual(rc, 0, repr(pop))
            self.assertEqual(len(self.calls("curl")), 1, repr(pop))
            self.assertEqual(sorted(os.listdir(self.key)), [".didtoolbox", "did", "did.jsonl", "issuer-pin.json"])
            self.assertNotIn(SCRIPT_TOKEN, text)


class NoDidYetTests(ScriptBase):
    def test_pop_and_statement_say_to_run_did_sh_first(self):
        self.key.mkdir()
        rc, text = self.run_script("pop.sh", str(self.key), str(self.jar))
        self.assertEqual(rc, 2)
        self.assertIn("run did.sh first", text)
        rc, text = self.run_script("statement.sh", str(self.key), "identity")
        self.assertEqual(rc, 2)
        self.assertIn("run did.sh first", text)
        self.assertEqual((self.calls("curl"), self.calls("docker")), ([], []))
        rc, text = self.run_script("pop.sh", str(self.key / "missing"), str(self.jar))
        self.assertEqual(rc, 2)
        self.assertFalse((self.key / "missing").exists())


class StatementScriptTests(ScriptBase):
    JWT = "eyJh.eyJz.c2ln"

    def prepare(self):
        F.write_keyfolder(self.key, F.World())
        os.chmod(self.key, 0o700)

    def test_statement_sh_vqps(self):
        self.prepare()
        self.answer("curl", 1, json.dumps({"id": "x", "status": "PUBLICATION_SUCCEEDED",
                                           "publicationResult": {"jti": "j", "jwt": self.JWT}}))
        rc, text = self.run_script("statement.sh", str(self.key), "vqps", "ch.polaris.age-check")
        self.assertEqual(rc, 0, text)
        self.assert_clean_output(text)
        self.assertIn("REQUEST POST https://trust-reg-api.trust-infra.swiyu-int.admin.ch/api/v1/trust/vqps-submissions",
                      self.snapshot("curl", 1))
        self.assertIn("Authorization: Bearer <redacted>", text)
        body = json.loads((self.stub / "curl.body.1").read_text())
        self.assertEqual((body["sub"], body["scope"], body["waitForPublication"]), (F.VERIFIER_DID, "ch.polaris.age-check", True))
        self.assertEqual(body["query"], sv.lab_query())
        self.assertLessEqual(len(body["purpose_name"]["default"]), 40)
        self.assertLessEqual(len(body["purpose_description"]["default"]), 1000)
        self.assertIn('"scope": "ch.polaris.age-check"', self.snapshot("curl", 1))
        self.assertEqual((self.key / "statements" / "vqps.jwt").read_text().strip(), self.JWT)
        self.assertEqual((self.key / "statements" / "scope").read_text().strip(), "ch.polaris.age-check")
        self.assertEqual(self.mode(self.key / "statements" / "vqps.jwt"), 0o600)
        self.assert_nothing_else_written()

    def test_statement_sh_identity_is_an_anonymous_get(self):
        self.prepare()
        self.answer("curl", 1, '"%s"\n' % self.JWT)
        rc, text = self.run_script("statement.sh", str(self.key), "identity")
        self.assertEqual(rc, 0, text)
        self.assert_clean_output(text)
        quoted = urllib.parse.quote(F.VERIFIER_DID, safe="")
        self.assertIn("REQUEST GET https://trust-reg.trust-infra.swiyu-int.admin.ch/api/v2/identity-trust-statement/" + quoted, text)
        self.assertNotIn("Authorization", text)
        self.assertEqual((self.stub / "curl.stdin.1").read_text(), "")
        self.assertEqual((self.key / "statements" / "identity.jwt").read_text().strip(), self.JWT)
        self.assert_nothing_else_written()

    def test_statement_sh_refuses_an_answer_that_is_no_statement(self):
        self.prepare()
        for answer in ("", "<html>", '{"content": []}'):
            self.forget("curl")
            self.answer("curl", 1, answer)
            rc, text = self.run_script("statement.sh", str(self.key), "identity")
            self.assertNotEqual(rc, 0, answer)
            self.assertFalse((self.key / "statements" / "identity.jwt").exists())
        self.forget("curl")
        for args in (("vqps",), ("other",), ("vqps", "s", "extra")):
            rc, text = self.run_script("statement.sh", str(self.key), *args)
            self.assertEqual(rc, 2, args)
        rc, text = self.run_script("statement.sh", str(self.key), "vqps", "s", drop=("SWIYU_TRUST_REGISTRY_ACCESS_TOKEN",))
        self.assertEqual(rc, 2)
        self.assertEqual(self.calls("curl"), [])


    def test_statement_sh_refuses_a_multi_line_answer(self):
        """The compact check holds for the whole answer: one line, all of it a compact JWS."""
        self.prepare()
        for answer in (self.JWT + "\nnot a statement", self.JWT + "\n" + self.JWT, '"' + self.JWT + '"\n"x"',
                       self.JWT[:5] + "\n" + self.JWT[5:]):
            self.forget("curl")
            self.answer("curl", 1, answer)
            rc, text = self.run_script("statement.sh", str(self.key), "identity")
            self.assertNotEqual(rc, 0, repr(answer))
            self.assertIn("nothing saved", text)
            self.assertFalse((self.key / "statements" / "identity.jwt").exists(), repr(answer))
        for jwt in (self.JWT + "\nxx", self.JWT + "\n" + self.JWT):
            self.forget("curl")
            self.answer("curl", 1, json.dumps({"publicationResult": {"jwt": jwt}}))
            rc, text = self.run_script("statement.sh", str(self.key), "vqps", "ch.polaris.age-check")
            self.assertNotEqual(rc, 0, repr(jwt))
            self.assertFalse((self.key / "statements" / "vqps.jwt").exists(), repr(jwt))

    def test_statement_sh_needs_the_encoded_did_before_it_builds_the_url(self):
        self.prepare()
        bad = pathlib.Path(self.root.name) / "bad-python"
        for name, body in (("exits 1 after printing", "#!/bin/bash\necho partial\nexit 1\n"),
                           ("prints nothing", "#!/bin/bash\nexit 0\n")):
            bad.write_text(body)
            os.chmod(bad, 0o755)
            self.forget("curl")
            self.answer("curl", 1, '"%s"\n' % self.JWT)
            rc, text = self.run_script("statement.sh", str(self.key), "identity", extra={"PYTHON": str(bad)})
            self.assertNotEqual(rc, 0, name)
            self.assertEqual(self.calls("curl"), [], name)  # no request was built, let alone sent
            self.assertFalse((self.key / "statements" / "identity.jwt").exists(), name)

    def test_statement_sh_writes_the_scope_only_after_the_statement_passed(self):
        self.prepare()
        for answer in ({"publicationResult": {"jwt": "not a statement"}}, {"publicationResult": {}}):
            self.forget("curl")
            self.answer("curl", 1, json.dumps(answer))
            rc, text = self.run_script("statement.sh", str(self.key), "vqps", "ch.polaris.age-check")
            self.assertNotEqual(rc, 0)
            self.assertFalse((self.key / "statements" / "scope").exists(), "a scope was kept for a statement that never passed")
            self.assertFalse((self.key / "statements" / "vqps.jwt").exists())
        self.forget("curl")
        self.answer("curl", 1, json.dumps({"publicationResult": {"jwt": self.JWT}}))
        rc, text = self.run_script("statement.sh", str(self.key), "vqps", "ch.polaris.age-check")
        self.assertEqual(rc, 0, text)
        self.assertEqual((self.key / "statements" / "scope").read_text().strip(), "ch.polaris.age-check")


class FailedRequestTests(ScriptBase):
    """A request curl fails shows the owner what the registry answered, and the script stops there: the answer's first
    2000 bytes on standard error, the token's value redacted before the cut, control characters shown as ?, curl's
    status, and no "done"."""

    def fail_call(self, n, status, answer=None):
        if answer is not None:
            self.answer("curl", n, answer)
        (self.stub / ("curl.exit.%d" % n)).write_text(str(status))

    def test_an_http_error_prints_the_registry_s_reason_without_the_token_and_stops(self):
        body = json.dumps({"error": "Bad Request", "echo": SCRIPT_TOKEN, "detail": "THE-REGISTRY-REASON"}) + "\x1b[2J"
        # a second copy starts 10 bytes before the cut: every copy is redacted whole before the cut, so not even the
        # second's start shows; the redactions shorten the answer by 22 bytes, and the cut then falls in the tail
        body += " " * (1990 - len(body)) + SCRIPT_TOKEN + "TAIL-PAST-2000" + "x" * 1000
        self.fail_call(1, 22, body)
        rc, text = self.run_script("did.sh", str(self.key), str(self.jar))
        self.assertEqual(rc, 22, text)
        self.assertIn("swiyu: the request failed (curl exit 22); the answer, its first 2000 bytes:", text)
        self.assertIn('"echo": "<redacted>", "detail": "THE-REGISTRY-REASON"}?[2J', text)
        self.assertIn(" <redacted>TAIL-PAST-2\n", text)
        for absent in (SCRIPT_TOKEN[:8], "\x1b", "TAIL-PAST-2000", "answered,"):
            self.assertNotIn(absent, text)
        self.assertNotEqual(text.splitlines()[-1], "done")
        self.assertEqual(len(self.calls("curl")), 1)
        self.assertEqual(self.calls("docker"), [])
        self.assertFalse((self.key / ".response").exists())

    def test_a_failed_proof_submission_prints_the_reason_without_the_proof_or_the_token(self):
        F.write_keyfolder(self.key, F.World())
        os.chmod(self.key, 0o700)
        self.answer("curl", 1, json.dumps([{"did": F.VERIFIER_DID, "nonce": PopScriptTests.NONCE}]))
        self.answer("docker", 1, PopScriptTests.POP + "\n")
        self.fail_call(2, 22, json.dumps({"detail": "THE-REGISTRY-REASON", "errors": [
            {"field": "proofOfPossessions[0]", "rejectedValue": PopScriptTests.POP}], "echo": SCRIPT_TOKEN}))
        rc, text = self.run_script("pop.sh", str(self.key), str(self.jar))
        self.assertEqual(rc, 22, text)
        self.assertIn('"rejectedValue": "<redacted>"}], "echo": "<redacted>"}', text)
        self.assertIn("THE-REGISTRY-REASON", text)
        for absent in (PopScriptTests.POP[:8], SCRIPT_TOKEN[:8]):
            self.assertNotIn(absent, text)
        self.assertNotEqual(text.splitlines()[-1], "done")
        self.assertEqual(len(self.calls("curl")), 2)
        self.assertFalse((self.key / ".pop.jwt").exists())

    def test_an_anonymous_request_that_fails_shows_its_answer_as_it_is(self):
        F.write_keyfolder(self.key, F.World())
        os.chmod(self.key, 0o700)
        self.fail_call(1, 22, '{"detail": "NO-STATEMENT-FOR-THIS-DID"}')
        rc, text = self.run_script("statement.sh", str(self.key), "identity")
        self.assertEqual(rc, 22, text)
        self.assertIn('{"detail": "NO-STATEMENT-FOR-THIS-DID"}\n', text)
        self.assertNotEqual(text.splitlines()[-1], "done")
        self.assertFalse((self.key / "statements" / "identity.jwt").exists())

    def test_a_request_with_no_answer_says_so_and_stops(self):
        self.fail_call(1, 7)
        rc, text = self.run_script("did.sh", str(self.key), str(self.jar))
        self.assertEqual(rc, 7, text)
        self.assertIn("swiyu: the request failed (curl exit 7), and no answer came", text)
        self.assertNotEqual(text.splitlines()[-1], "done")
        self.assertEqual(self.calls("docker"), [])


class RunScriptTests(ScriptBase):
    def prepare(self):
        self.w = F.World()
        F.write_keyfolder(self.key, self.w)
        os.chmod(self.key, 0o700)
        (self.key / "statements").mkdir(exist_ok=True)
        t = self.w.trust_key
        (self.key / "statements" / "identity.jwt").write_text(F.identity_statement(t, F.VERIFIER_DID) + "\n")
        (self.key / "statements" / "vqps.jwt").write_text(F.query_statement(t, F.VERIFIER_DID, "ch.test.scope") + "\n")
        (self.key / "statements" / "scope").write_text("ch.test.scope\n")
        self.env.update(SWIYU_REGISTRY_HOST=F.REGISTRY, SWIYU_STATUS_HOST=F.STATUS_HOST)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.env["PORT"] = str(self.port)

    def start(self, *args):
        self.log = open(self.out, "w")
        return subprocess.Popen(["bash", str(HERE / "run.sh"), *args], env=dict(self.env), cwd=self.cwd,
                                stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True,
                                preexec_fn=default_sigint)

    def wait_for(self, text, timeout=30):
        end = time.time() + timeout
        while time.time() < end:
            if text in self.out.read_text():
                return
            time.sleep(0.1)
        self.fail("%r never printed:\n%s" % (text, self.out.read_text()))

    @staticmethod
    def alive(pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True

    def stop_run(self, variant, sig, expected, statements, default_host=False, during=None):
        self.prepare()
        if default_host:
            self.env.pop("SWIYU_REGISTRY_HOST")
        proc = self.start(str(self.key), variant, "1.19.0-test")
        tunnel = verifier = 0
        try:
            self.wait_for("LINK swiyu-verify")
            text = self.out.read_text()
            self.assertIn("variant %s, %d statement(s); wallet 1.19.0-test; status host %s" % (variant, statements, F.STATUS_HOST), text)
            self.assertIn("public https://stub-lab-test.trycloudflare.com;", text)
            tunnel = int(text.split("tunnel=")[1].split()[0])
            verifier = int(text.split("verifier=")[1].split()[0])
            self.assertTrue(self.alive(tunnel) and self.alive(verifier))
            self.assertIn("LINK openid4vp ", text)
            for scheme in ("openid4vp://?client_id=decentralized_identifier%3Adid%3Awebvh%3A", "swiyu-verify://?client_id="):
                self.assertIn(scheme, text)
            self.assertIn("https%3A%2F%2Fstub-lab-test.trycloudflare.com%2Frequest.jwt%3Fstate%3D", text)
            self.assertNotIn("request_uri_method", text)
            if during:
                during(text)
            os.kill(proc.pid, sig)
            status_ = proc.wait(timeout=30)
            left = [name for name, pid in (("tunnel", tunnel), ("verifier", verifier)) if self.alive(pid)]
        finally:
            # whatever the script left (and the script itself, if it did not stop) goes with its process group
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            proc.wait()
            self.log.close()
        self.assertEqual(status_, expected)
        self.assertEqual(left, [], "left running after the script stopped")
        self.assertEqual(os.listdir(self.tmp), [], "the tunnel log was not deleted")
        self.assertEqual(os.listdir(self.home), [])
        self.assertEqual(os.listdir(self.cwd), [])
        self.assertEqual(self.calls("cloudflared"), ["cloudflared [tunnel] [--url] [http://127.0.0.1:%d]" % self.port])
        self.assertEqual(self.mode(self.key / "runs"), 0o700)

    def test_run_sh_stops_both_on_term(self):
        self.stop_run("C", signal.SIGTERM, 143, 2)

    def test_run_sh_stops_both_on_int(self):
        self.stop_run("A", signal.SIGINT, 130, 0)

    def test_run_sh_defaults_to_the_int_registry_host(self):
        """With SWIYU_REGISTRY_HOST unset the verifier starts for a DID on the -int host the other scripts use."""
        self.stop_run("A", signal.SIGTERM, 143, 0, default_host=True)  # the behaviour first: a refusal to start fails here
        self.assertIn("${SWIYU_REGISTRY_HOST:-%s}" % F.REGISTRY, (HERE / "run.sh").read_text())

    def test_run_sh_prints_the_tunnel_the_pids_and_the_method_and_path_of_each_request_the_listener_answers(self):
        def ask_for_the_request_object(text):
            state = re.search(r"%3Fstate%3D([A-Za-z0-9_-]+)", text).group(1)
            path = "/request.jwt?state=" + state
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open("http://127.0.0.1:%d%s" % (self.port, path), timeout=30) as answer:
                self.assertEqual(answer.status, 200)
            self.wait_for("GET " + path)
            shown = self.out.read_text()
            self.assertIn("tunnel: https://stub-lab-test.trycloudflare.com -> http://127.0.0.1:%d" % self.port, shown)
            self.assertRegex(shown, r"pids: tunnel=\d+ verifier=\d+")
            self.assertRegex(shown, r"listening 127\.0\.0\.1:%d " % self.port)

        self.stop_run("A", signal.SIGTERM, 143, 0, during=ask_for_the_request_object)

    def test_run_sh_variant_b_carries_the_identity_statement_only(self):
        self.stop_run("B", signal.SIGTERM, 143, 1)

    def test_run_sh_refuses_without_its_inputs(self):
        self.prepare()
        for args in ((), (str(self.key),), (str(self.key), "A"), (str(self.key), "D", "v"), (str(self.key / "nope"), "A", "v")):
            rc, text = self.run_script("run.sh", *args, timeout=10)
            self.assertEqual(rc, 2, args)  # it refused, and promptly: a run that went on would have timed out above
            self.assertEqual(self.calls("cloudflared"), [], args)
        (self.key / "issuer-pin.json").unlink()
        rc, text = self.run_script("run.sh", str(self.key), "A", "v", timeout=10)
        self.assertEqual(rc, 2)
        self.assertIn("issuer-pin.json", text)
        self.prepare()
        (self.key / "statements" / "vqps.jwt").unlink()
        rc, text = self.run_script("run.sh", str(self.key), "C", "v", timeout=10)
        self.assertEqual(rc, 2)
        self.assertIn("vqps.jwt", text)
        self.assertEqual(self.calls("cloudflared"), [])
        self.assertEqual(os.listdir(self.tmp), [])

    def test_run_sh_stops_the_tunnel_when_the_verifier_refuses_to_start(self):
        self.prepare()
        old = F.pin(F.ISSUER_DID, {"assert-key-01": self.w.issuer_key}, resolved_at=time.time() - 30 * 3600)
        (self.key / "issuer-pin.json").write_text(json.dumps(old))
        rc, text = self.run_script("run.sh", str(self.key), "A", "v")
        self.assertEqual(rc, 2, text)
        self.assertIn("pin", text)
        self.assertEqual(os.listdir(self.tmp), [])
        self.assertNotEqual(text.splitlines()[-1], "done")


class ScriptDisciplineTests(unittest.TestCase):
    SCRIPTS = ("did.sh", "pop.sh", "statement.sh", "run.sh", "common.sh")

    def test_each_script_is_short_strict_and_ends_with_done(self):
        for name in self.SCRIPTS:
            text = (HERE / name).read_text()
            lines = text.splitlines()
            self.assertLessEqual(len(lines), 120, name)
            self.assertEqual(subprocess.run(["bash", "-n", str(HERE / name)]).returncode, 0, name)
            self.assertNotIn("rm -rf", text, name)
            if name != "common.sh":
                self.assertIn("set -euo pipefail", text, name)
                self.assertEqual([line for line in lines if line.strip()][-1].strip(), "echo done", name)

    def test_the_readme_and_common_sh_say_what_the_scripts_send_and_print(self):
        readme = " ".join((HERE / "README.md").read_text().split())
        self.assertNotIn("sends no request of its own", readme)  # the verifier run.sh starts GETs the credential's status list
        self.assertIn("`run.sh` sends no request itself", readme)
        self.assertIn("with a GET to `SWIYU_STATUS_HOST`", readme)
        self.assertIn("the method and path of each request the listener answers", readme)
        self.assertIn("for the DID log upload the file's name, size and sha256", readme)
        common = " ".join((HERE / "common.sh").read_text().split())
        self.assertNotIn("every script here", common)  # run.sh does not source it, and prints no body of its own
        self.assertIn("What each of the three", common)
        self.assertIn("for the DID log upload the file's name, size and sha256", common)

    def test_the_tool_and_image_are_the_pinned_ones(self):
        text = (HERE / "common.sh").read_text()
        self.assertIn(JAR_SHA, text)
        self.assertIn(IMAGE, text)

    def test_tokens_are_read_from_the_environment_only(self):
        for name in self.SCRIPTS:
            for line in (HERE / name).read_text().splitlines():
                if "ACCESS_TOKEN" in line and not line.lstrip().startswith("#"):
                    self.assertNotIn("=eyJ", line)
                    self.assertNotRegex(line, r"echo .*ACCESS_TOKEN")
                    self.assertNotRegex(line, r"printf [^|]*\$\{?SWIYU_[A-Z_]*ACCESS_TOKEN[^|]*>\s*[^&]")


class MainTests(unittest.TestCase):
    def run_main(self, *args):
        return subprocess.run([PY, "-I", "-B", str(HERE / "swiyu_verifier.py"), *args], capture_output=True, text=True, timeout=60)

    def test_print_query_is_the_lab_query(self):
        done = self.run_main("--print-query")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout), sv.lab_query())

    def test_main_refuses_without_its_inputs(self):
        done = self.run_main()
        self.assertEqual(done.returncode, 2)
        self.assertIn("--did", done.stderr)
        self.assertEqual(done.stdout, "")

    def test_main_refuses_a_stale_pin_before_listening(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = F.World()
            F.write_keyfolder(tmp, w, with_pin=False)
            old = F.pin(F.ISSUER_DID, {"assert-key-01": w.issuer_key}, resolved_at=time.time() - 30 * 3600)
            pathlib.Path(tmp, "pin.json").write_text(json.dumps(old))
            done = self.run_main("--did", w.verifier_did, "--kid", w.kid, "--key", os.path.join(tmp, ".didtoolbox", "assert-key-01"),
                                 "--did-log", os.path.join(tmp, "did.jsonl"), "--issuer-pin", os.path.join(tmp, "pin.json"),
                                 "--registry-host", F.REGISTRY, "--status-host", F.STATUS_HOST, "--public-url", F.PUBLIC_URL,
                                 "--runs", os.path.join(tmp, "runs"), "--port", "0")
            self.assertEqual(done.returncode, 2, done.stderr)
            self.assertIn("pin", done.stderr)
            self.assertNotIn("LINK", done.stdout)


class RunStateTests(unittest.TestCase):
    """What main() keeps across the records of one run."""

    def test_a_later_record_cannot_unset_a_counted_run(self):
        tally = sv.Tally(attempts=3)
        self.assertTrue(tally.add({"counted": True}))  # a counted record ends the run
        self.assertTrue(tally.counted)
        tally.add({"counted": False})  # a record that lands in the moment before the listener stops
        self.assertTrue(tally.counted)

    def test_attempts_are_counted_as_before(self):
        tally = sv.Tally(attempts=2)
        self.assertFalse(tally.add({"counted": False}))
        self.assertTrue(tally.add({"counted": False}))  # the second attempt ends the run
        self.assertFalse(tally.counted)

    def test_main_waits_for_the_answer_to_be_written_before_it_stops_the_listener(self):
        events, captured, jars = [], [], []
        real_serve, real_new_request, real_send = sv.serve, sv.SwiyuVerifier.new_request, package_serve._Handler._send

        def serve_and_keep(*args, **kwargs):
            httpd = real_serve(*args, **kwargs)
            captured.append(httpd)
            return httpd

        def new_request_and_keep(verifier_self, *args, **kwargs):
            session, jar = real_new_request(verifier_self, *args, **kwargs)
            jars.append(jar)
            return session, jar

        def slow_send(handler, status, body):
            if handler.path == "/response":
                time.sleep(0.6)  # the answer leaves after the verdict is recorded and the run is over
            real_send(handler, status, body)
            if handler.path == "/response":
                events.append("answer written")

        with tempfile.TemporaryDirectory() as tmp:
            w = F.World()
            F.write_keyfolder(tmp, w)
            argv = ["--did", w.verifier_did, "--kid", w.kid, "--key", os.path.join(tmp, ".didtoolbox", "assert-key-01"),
                    "--did-log", os.path.join(tmp, "did.jsonl"), "--issuer-pin", os.path.join(tmp, "issuer-pin.json"),
                    "--registry-host", F.REGISTRY, "--status-host", F.STATUS_HOST, "--public-url", "http://127.0.0.1:9",
                    "--port", "0", "--runs", os.path.join(tmp, "runs"), "--wait-seconds", "60", "--attempts", "1"]
            result = []

            def run_main():
                result.append(sv.main(argv))
                events.append("main returned")

            with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(sv, "serve", serve_and_keep), \
                    mock.patch.object(sv.shutil, "which", return_value=None), \
                    mock.patch.object(sv.SwiyuVerifier, "new_request", new_request_and_keep), \
                    mock.patch.object(package_serve._Handler, "_send", slow_send):
                thread = threading.Thread(target=run_main, daemon=True)
                thread.start()
                end = time.time() + 30
                while not (captured and jars) and time.time() < end:
                    time.sleep(0.05)
                self.assertTrue(captured and jars, "main did not start listening")
                form = w.wallet.respond(jars[0], status_idx=None)  # no status claim: no list is fetched, nothing leaves this machine
                body = urllib.parse.urlencode({"response": form["response"][0]}).encode("ascii")
                request = urllib.request.Request("http://127.0.0.1:%d/response" % captured[0].server_port, data=body, method="POST",
                                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
                with F.OPENER.open(request, timeout=30) as answer:
                    self.assertEqual(answer.status, 200)
                thread.join(30)
            self.assertFalse(thread.is_alive())
            self.assertEqual(result, [1])  # one attempt, not counted
            self.assertEqual(events, ["answer written", "main returned"])


class DryRunTests(unittest.TestCase):
    def test_dry_run_banner_loopback_and_nothing_left(self):
        done = subprocess.run([PY, "-I", "-B", str(HERE / "dryrun.py")], capture_output=True, text=True, timeout=120)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        lines = done.stdout.splitlines()
        banner = "DRY RUN: a local stand-in, not a wallet, never evidence"
        self.assertEqual((lines[0], lines[-1]), (banner, banner))
        text = done.stdout
        self.assertIn("127.0.0.1:", text)
        for needle in ("header ok", "kid ok", "client_id ok", "accepted (200)", "counted: True"):
            self.assertIn(needle, text)
        port = int(text.split("127.0.0.1:")[1].split()[0].rstrip("/"))
        with socket.socket() as probe:
            probe.settimeout(2)
            self.assertNotEqual(probe.connect_ex(("127.0.0.1", port)), 0, "the dry run left a listener")


if __name__ == "__main__":
    unittest.main()
