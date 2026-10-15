# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_verifier.py -- the seven refusals as HTTP status codes, which is how they are scored.

`test_sdjwt.py` proves the verifier NOTICES each of the conformance plan's seven negative
cases. This file proves the noticing reaches the wire, because that is what the plan actually
measures: a negative module passes when the verifier answers **4xx**, and a verifier that
notices a forged presentation and returns 200 anyway fails all seven at once while every unit
test stays green.

So the wallet here is a full one. It fetches the request object, reads the nonce and the
encryption key out of it the way a real wallet does, mints a presentation, encrypts it to
that key, and posts it back. Nothing is hand-fed: if the request object were malformed, this
wallet could not answer it.
"""
import base64
import datetime
import hashlib
import json
import os
import re
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from polaris_oid4vp.jwe import b64u_decode, b64u_encode, decrypt_compact, encrypt_compact  # noqa: E402
from polaris_oid4vp.verifier import (DEFAULT_REQUEST_TTL_SECONDS, Verifier,  # noqa: E402
                                     VerifierInfoError, claim_query)
from polaris_oid4vp import sdjwt  # noqa: E402

#: A claim value that removes the claim (Wallet.binding_claims).
DROP = object()


def _jws(key, header, payload):
    h = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64u_encode(json.dumps(payload, separators=(",", ":")).encode())
    r, s = asym_utils.decode_dss_signature(
        key.sign((h + "." + p).encode("ascii"), ec.ECDSA(hashes.SHA256())))
    return h + "." + p + "." + b64u_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _public_jwk(key):
    n = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256",
            "x": b64u_encode(n.x.to_bytes(32, "big")),
            "y": b64u_encode(n.y.to_bytes(32, "big"))}


def _client_chain():
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "verifier anchor")])
    # The anchor itself is not returned: the profile registers it out of band and the
    # request object must carry the leaf ALONE, which is a rule the suite enforces.
    (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
     .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
     .not_valid_before(now - datetime.timedelta(days=1))
     .not_valid_after(now + datetime.timedelta(days=30))
     .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
     .sign(ca_key, hashes.SHA256()))
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "verifier")]))
            .issuer_name(ca_name).public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(ca_key, hashes.SHA256()))
    return (leaf.public_bytes(serialization.Encoding.PEM),
            leaf_key.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))


class Wallet:
    """A wallet that reads the request object rather than being told what is in it."""

    def __init__(self):
        self.issuer_key = ec.generate_private_key(ec.SECP256R1())
        self.holder_key = ec.generate_private_key(ec.SECP256R1())
        self.issuer_jwk = dict(_public_jwk(self.issuer_key), kid="issuer-1")

    @staticmethod
    def read_request(jar):
        header, payload = jar.split(".")[:2]
        return json.loads(b64u_decode(header)), json.loads(b64u_decode(payload))

    def respond(self, jar, *, nonce=None, audience=None, iat=None, sd_hash=None,
                corrupt_issuer_sig=False, corrupt_kb_sig=False, extra_disclosure=None,
                state=None, enc="A128GCM", vp_token=None, vct=None, status=None, kb=None):
        _, claims = self.read_request(jar)
        enc_jwk = claims["client_metadata"]["jwks"]["keys"][0]
        enc_public = ec.EllipticCurvePublicNumbers(
            int.from_bytes(b64u_decode(enc_jwk["x"]), "big"),
            int.from_bytes(b64u_decode(enc_jwk["y"]), "big"), ec.SECP256R1()).public_key()

        bound = self.binding_claims(claims, kb)
        presentation = self._presentation(
            nonce=claims["nonce"] if nonce is None else nonce,
            audience=claims["client_id"] if audience is None else audience,
            iat=iat, sd_hash=sd_hash, corrupt_issuer_sig=corrupt_issuer_sig,
            corrupt_kb_sig=corrupt_kb_sig, extra_disclosure=extra_disclosure, vct=vct,
            status=status, **({"kb_extra": bound} if bound else {}))
        # Keyed by the id the request's credential query names, as section 8.1 has it.
        query_id = claims["dcql_query"]["credentials"][0]["id"]
        body = {"state": claims["state"] if state is None else state,
                "vp_token": {query_id: [presentation]} if vp_token is None else vp_token}
        token = encrypt_compact(json.dumps(body).encode(), enc_public, enc)
        return {"response": [token]}

    def respond_error(self, jar, error="access_denied", *, state=None, encrypted=True,
                      extra=None):
        """An Authorization Error Response (OpenID4VP 1.0 section 8.5) to the request object
        `jar`: encrypted to the request's key, as `respond` sends a presentation, or in the clear,
        as section 8.3.1 allows a wallet that cannot encrypt. `extra` adds members, or form
        parameters (a list is sent as repeated values)."""
        _, claims = self.read_request(jar)
        body = {"error": error, "state": claims["state"] if state is None else state}
        body.update(extra or {})
        if not encrypted:
            return {name: value if isinstance(value, list) else [value]
                    for name, value in body.items()}
        enc_jwk = claims["client_metadata"]["jwks"]["keys"][0]
        enc_public = ec.EllipticCurvePublicNumbers(
            int.from_bytes(b64u_decode(enc_jwk["x"]), "big"),
            int.from_bytes(b64u_decode(enc_jwk["y"]), "big"), ec.SECP256R1()).public_key()
        return {"response": [encrypt_compact(json.dumps(body).encode(), enc_public)]}

    @staticmethod
    def binding_claims(request, overrides=None):
        """What a TS12 wallet adds to its key binding JWT for the request's transaction_data:
        the SHA-256 of each string as received (computed here, with hashlib), the algorithm as a
        string, a fresh jti, the request's response_mode and two amr categories. `overrides`
        replaces a claim, or with DROP removes it."""
        out = {}
        raws = request.get("transaction_data")
        if raws:
            out = {"transaction_data_hashes": [
                       b64u_encode(hashlib.sha256(r.encode("ascii")).digest()) for r in raws],
                   "transaction_data_hashes_alg": "sha-256",
                   "jti": b64u_encode(os.urandom(16)),
                   "response_mode": request["response_mode"],
                   "amr": [{"knowledge": "pin_6_or_more_digits"},
                           {"possession": "key_in_local_native_wscd"}]}
        for name, value in (overrides or {}).items():
            if value is DROP:
                out.pop(name, None)
            else:
                out[name] = value
        return out

    def _presentation(self, *, nonce, audience, iat, sd_hash, corrupt_issuer_sig,
                      corrupt_kb_sig, extra_disclosure, vct=None, status=None, kb_extra=None):
        disclosures = [
            b64u_encode(json.dumps([s, n, v], separators=(",", ":")).encode())
            for s, n, v in (("s0", "given_name", "Jean"), ("s1", "family_name", "Dupont"))]
        digests = [b64u_encode(hashlib.sha256(d.encode("ascii")).digest())
                   for d in disclosures]
        payload = {"iss": "https://issuer.example",
                   "vct": "urn:eudi:pid:1" if vct is None else vct,
                   "iat": int(time.time()), "_sd": digests,
                   "cnf": {"jwk": _public_jwk(self.holder_key)}}
        if status is not None:
            payload["status"] = status
        issuer_jwt = _jws(self.issuer_key,
                          {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "issuer-1"}, payload)
        if corrupt_issuer_sig:
            head, _, sig = issuer_jwt.rpartition(".")
            raw = bytearray(b64u_decode(sig))
            raw[0] ^= 0xFF
            issuer_jwt = head + "." + b64u_encode(bytes(raw))
        if extra_disclosure is not None:
            disclosures = disclosures + [extra_disclosure]
        presented = issuer_jwt + "~" + "".join(d + "~" for d in disclosures)
        kb_payload = {"iat": int(time.time()) if iat is None else iat, "aud": audience,
                      "nonce": nonce,
                      "sd_hash": b64u_encode(hashlib.sha256(presented.encode("ascii")).digest())
                      if sd_hash is None else sd_hash}
        kb_payload.update(kb_extra or {})
        kb = _jws(self.holder_key, {"alg": "ES256", "typ": "kb+jwt"}, kb_payload)
        if corrupt_kb_sig:
            head, _, sig = kb.rpartition(".")
            raw = bytearray(b64u_decode(sig))
            raw[0] ^= 0xFF
            kb = head + "." + b64u_encode(bytes(raw))
        return presented + kb


def assert_redirect_with_code(test, body, base):
    """An accepted response's body: ONLY a redirect_uri (HAIP 5.1), which is `base` with a fresh
    `response_code` of 128 bits added (OpenID4VP 1.0 section 8.2). Returns the code."""
    test.assertEqual(list(body), ["redirect_uri"])
    prefix = base + ("&" if "?" in base else "?") + "response_code="
    test.assertTrue(body["redirect_uri"].startswith(prefix), body["redirect_uri"])
    code = body["redirect_uri"][len(prefix):]
    test.assertRegex(code, r"^[A-Za-z0-9_-]+$")
    test.assertGreaterEqual(len(b64u_decode(code)), 16, "fewer than 128 bits")
    return code


class VerifierTestCase(unittest.TestCase):

    def setUp(self):
        cert_pem, key_pem = _client_chain()
        self.wallet = Wallet()
        self.verifier = Verifier(
            client_cert_pem=cert_pem, client_key_pem=key_pem,
            request_uri="https://verifier.test/request.jwt",
            response_uri="https://verifier.test/response",
            issuer_jwks=[self.wallet.issuer_jwk])

    def exchange(self, **kw):
        session, jar = self.verifier.new_request()
        form = self.wallet.respond(jar, **kw)
        status, body, _ = self.verifier.handle_direct_post(form)
        return session, status, body


class PidWallet(Wallet):
    """A wallet holding an EUDI-PID-shaped credential. `age_equal_or_over` is an object whose
    statements are each selectively disclosable, as the PID Rulebook issues it, so a wallet can
    answer "18 or over" without the others. `ages` are the issued statements; `disclose` the
    ones this presentation reveals, and `names` the top-level claims it reveals besides."""

    def __init__(self, ages=(("18", True), ("21", True), ("65", False)), disclose=("18",),
                 names=("given_name", "family_name")):
        super().__init__()
        self.ages, self.disclose, self.names = ages, disclose, names

    def _presentation(self, *, nonce, audience, iat=None, sd_hash=None, corrupt_issuer_sig=False,
                      corrupt_kb_sig=False, extra_disclosure=None, vct=None, status=None,
                      kb_extra=None):
        def disclosure(*parts):
            d = b64u_encode(json.dumps(list(parts), separators=(",", ":")).encode())
            return d, b64u_encode(hashlib.sha256(d.encode("ascii")).digest())
        given = disclosure("s0", "given_name", "Jean")
        family = disclosure("s1", "family_name", "Dupont")
        members = {name: disclosure("a" + name, name, value) for name, value in self.ages}
        age = disclosure("s2", "age_equal_or_over", {"_sd": sorted(d for _, d in members.values())})
        payload = {"iss": "https://issuer.example", "vct": "urn:eudi:pid:1",
                   "iat": int(time.time()), "_sd": sorted([given[1], family[1], age[1]]),
                   "cnf": {"jwk": _public_jwk(self.holder_key)}}
        issuer_jwt = _jws(self.issuer_key,
                          {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "issuer-1"}, payload)
        top = {"given_name": given[0], "family_name": family[0]}
        shown = ([top[n] for n in self.names] + [age[0]]
                 + [members[n][0] for n in self.disclose])
        presented = issuer_jwt + "~" + "".join(d + "~" for d in shown)
        kb = _jws(self.holder_key, {"alg": "ES256", "typ": "kb+jwt"},
                  dict({"iat": int(time.time()), "aud": audience, "nonce": nonce,
                        "sd_hash": b64u_encode(hashlib.sha256(presented.encode("ascii")).digest())},
                       **(kb_extra or {})))
        return presented + kb


class NationalityWallet(Wallet):
    """A wallet whose credential holds an array claim, `nationalities`, each element its own
    selectively disclosable value (an array-element disclosure is [salt, value], SD-JWT section
    4.2.2), beside a disclosable `given_name`. `disclose_array` decides whether the presentation
    reveals the two elements."""

    def __init__(self, disclose_array=True):
        super().__init__()
        self.disclose_array = disclose_array

    def _presentation(self, *, nonce, audience, iat=None, sd_hash=None, corrupt_issuer_sig=False,
                      corrupt_kb_sig=False, extra_disclosure=None, vct=None, status=None,
                      kb_extra=None):
        def disclosure(*parts):
            d = b64u_encode(json.dumps(list(parts), separators=(",", ":")).encode())
            return d, b64u_encode(hashlib.sha256(d.encode("ascii")).digest())
        given = disclosure("s0", "given_name", "Jean")
        de, fr = disclosure("n0", "DE"), disclosure("n1", "FR")
        payload = {"iss": "https://issuer.example", "vct": "urn:eudi:pid:1",
                   "iat": int(time.time()), "_sd": [given[1]],
                   "nationalities": [{"...": de[1]}, {"...": fr[1]}],
                   "cnf": {"jwk": _public_jwk(self.holder_key)}}
        issuer_jwt = _jws(self.issuer_key,
                          {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "issuer-1"}, payload)
        shown = [given[0]] + ([de[0], fr[0]] if self.disclose_array else [])
        presented = issuer_jwt + "~" + "".join(d + "~" for d in shown)
        kb = _jws(self.holder_key, {"alg": "ES256", "typ": "kb+jwt"},
                  {"iat": int(time.time()), "aud": audience, "nonce": nonce,
                   "sd_hash": b64u_encode(hashlib.sha256(presented.encode("ascii")).digest())})
        return presented + kb

class NestedClaimTests(unittest.TestCase):
    """A claim is a path. The EUDI PID nests its age statements, so asking for
    `age_equal_or_over` would ask for every one of them; `age_equal_or_over.18` asks for one,
    and only that one answers. `values` is the value the request accepts."""

    AGE = {"path": ["age_equal_or_over", "18"], "values": [True]}

    def exchange(self, wallet, claims):
        cert_pem, key_pem = _client_chain()
        verifier = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                            request_uri="https://verifier.test/request.jwt",
                            response_uri="https://verifier.test/response",
                            issuer_jwks=[wallet.issuer_jwk], claims=claims)
        _, jar = verifier.new_request()
        status, _, verdict = verifier.handle_direct_post(wallet.respond(jar))
        return jar, status, verdict

    def test_the_request_asks_for_the_path_and_the_value(self):
        jar, _, _ = self.exchange(PidWallet(), ["given_name", self.AGE])
        query = Wallet.read_request(jar)[1]["dcql_query"]["credentials"][0]["claims"]
        self.assertEqual(query, [{"path": ["given_name"]},
                                 {"path": ["age_equal_or_over", "18"], "values": [True]}])

    def test_the_one_statement_answers(self):
        _, status, _ = self.exchange(PidWallet(disclose=("18",), names=("given_name",)),
                                     ["given_name", self.AGE])
        self.assertEqual(status, 200)

    def test_a_different_statement_does_not_answer(self):
        # 21 or over implies 18 or over, but it is not what was asked, and it says more.
        _, status, verdict = self.exchange(PidWallet(disclose=("21",), names=()), [self.AGE])
        self.assertEqual(status, 400)
        self.assertEqual(verdict.code, "claims")
        self.assertIn("'age_equal_or_over.18'", verdict.reason)

    def test_the_object_without_the_statement_does_not_answer(self):
        _, status, verdict = self.exchange(PidWallet(disclose=(), names=()), [self.AGE])
        self.assertEqual((status, verdict.code), (400, "claims"))

    def test_a_false_statement_is_not_the_value_asked_for(self):
        wallet = PidWallet(ages=(("18", False),), disclose=("18",), names=())
        _, status, verdict = self.exchange(wallet, [self.AGE])
        self.assertEqual((status, verdict.code), (400, "claims"))
        self.assertIn("a value the request does not accept", verdict.reason)

    def test_a_value_of_another_type_is_not_the_value_asked_for(self):
        # DCQL compares type and value: 1 is not true, although Python says 1 == True.
        wallet = PidWallet(ages=(("18", 1),), disclose=("18",), names=())
        _, status, verdict = self.exchange(wallet, [self.AGE])
        self.assertEqual((status, verdict.code), (400, "claims"))

    def test_without_values_the_disclosed_statement_answers_whatever_it_says(self):
        wallet = PidWallet(ages=(("18", False),), disclose=("18",), names=())
        _, status, _ = self.exchange(wallet, [["age_equal_or_over", "18"]])
        self.assertEqual(status, 200)

    def test_the_top_level_name_still_means_the_whole_claim(self):
        _, status, _ = self.exchange(PidWallet(disclose=("18",), names=()), ["age_equal_or_over"])
        self.assertEqual(status, 200)

    def test_claims_it_cannot_judge_are_refused_at_construction(self):
        for bad in ([], ["age_equal_or_over", 0], ["a", None], [""], None, 7,
                    {"path": ["a"], "values": []}, {"path": ["a"], "values": [1.5]},
                    {"path": ["a"], "values": [None]}, {"path": ["a"], "other": 1},
                    {"values": [True]}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                claim_query(bad)



class OverDisclosureTests(unittest.TestCase):
    """OpenID4VP 1.0 section 6.4: a wallet MUST NOT send selectively disclosable claims the
    request did not select. ERICA, the German EUDI Wallet programme's verifier testing tool,
    sends one as a negative case (OVER_DISCLOSURE); until 2026-10-04 it got 200 and the
    operator received claims nobody asked for."""

    AGE = NestedClaimTests.AGE
    exchange = NestedClaimTests.exchange

    def test_a_claim_the_request_did_not_select_is_refused(self):
        _, status, verdict = self.exchange(PidWallet(disclose=("18",)), [self.AGE])
        self.assertEqual((status, verdict.code), (400, "claims"))
        self.assertIn("did not select", verdict.reason)
        self.assertIn("'given_name'", verdict.reason)

    def test_an_array_element_the_request_did_not_select_is_refused(self):
        _, status, verdict = self.exchange(NationalityWallet(), ["given_name"])
        self.assertEqual((status, verdict.code), (400, "claims"))
        self.assertIn("did not select", verdict.reason)
        self.assertIn("nationalities", verdict.reason)

    def test_the_elements_of_a_requested_array_are_selected(self):
        _, status, verdict = self.exchange(NationalityWallet(), ["given_name", "nationalities"])
        self.assertEqual(status, 200, verdict.reason if verdict else None)
        self.assertTrue({("nationalities", 0), ("nationalities", 1)} <= set(verdict.disclosed))

    def test_an_array_left_undisclosed_is_not_extra(self):
        _, status, _ = self.exchange(NationalityWallet(disclose_array=False), ["given_name"])
        self.assertEqual(status, 200)

    def test_a_statement_beside_the_one_asked_for_is_refused(self):
        _, status, verdict = self.exchange(PidWallet(disclose=("18", "65"), names=()),
                                           [self.AGE])
        self.assertEqual((status, verdict.code), (400, "claims"))
        self.assertIn("'age_equal_or_over.65'", verdict.reason)

    def test_the_object_a_requested_member_is_reached_through_is_not_extra(self):
        _, status, verdict = self.exchange(PidWallet(disclose=("18",), names=()), [self.AGE])
        self.assertEqual(status, 200, verdict.reason if verdict else None)
        self.assertEqual(set(verdict.disclosed),
                         {("age_equal_or_over",), ("age_equal_or_over", "18")})

    def test_every_member_of_a_requested_object_is_selected(self):
        _, status, _ = self.exchange(PidWallet(disclose=("18", "21", "65"), names=()),
                                     ["age_equal_or_over"])
        self.assertEqual(status, 200)

    def test_what_the_issuer_signed_in_clear_text_is_not_a_disclosure(self):
        _, status, verdict = self.exchange(PidWallet(disclose=("18",)),
                                           ["given_name", "family_name", self.AGE])
        self.assertEqual(status, 200)
        self.assertIn("vct", verdict.claims)
        self.assertNotIn(("vct",), verdict.disclosed)

    def test_selection_is_by_path_prefix_in_both_directions(self):
        from polaris_oid4vp.verifier import _selected
        requested = [("address", "locality"), ("nationalities",)]
        for path, expected in ((("address",), True), (("address", "locality"), True),
                               (("address", "street"), False), (("nationalities", 0), True),
                               (("nationality",), False), (("address", "locality", "x"), True),
                               ((), True)):
            with self.subTest(path=path):
                self.assertEqual(_selected(path, requested), expected)



class VerifierInfoTests(unittest.TestCase):
    """OpenID4VP 1.0 section 5.1 `verifier_info`: attestations about the verifier, such as the
    registration certificate a registrar issues. The German EUDI Wallet ecosystem requires one
    for a PID request and ERICA, its verifier testing tool, refuses a request without it."""

    REGISTRATION = [{"format": "registration_cert", "data": "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"}]

    def verifier(self, **kw):
        cert_pem, key_pem = _client_chain()
        return Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                        request_uri="https://verifier.test/request.jwt",
                        response_uri="https://verifier.test/response", **kw)

    def test_the_request_object_carries_it_as_given(self):
        v = self.verifier(verifier_info=self.REGISTRATION + [
            {"format": "policy", "data": {"retention": "P0D"}, "credential_ids": ["pid"]}])
        _, jar = v.new_request()
        self.assertEqual(Wallet.read_request(jar)[1]["verifier_info"], self.REGISTRATION + [
            {"format": "policy", "data": {"retention": "P0D"}, "credential_ids": ["pid"]}])

    def test_a_request_object_minted_for_a_wallet_nonce_carries_it_too(self):
        v = self.verifier(verifier_info=self.REGISTRATION)
        session, _ = v.new_request()
        claims = Wallet.read_request(v.request_object(session.state, wallet_nonce="w"))[1]
        self.assertEqual(claims["verifier_info"], self.REGISTRATION)

    def test_a_single_object_is_carried_as_one_object(self):
        """ERICA and the German EUDI wallet guide read verifier_info.data, a single object."""
        v = self.verifier(verifier_info=self.REGISTRATION[0])
        _, jar = v.new_request()
        self.assertEqual(Wallet.read_request(jar)[1]["verifier_info"], self.REGISTRATION[0])

    def test_without_it_the_request_object_has_none(self):
        _, jar = self.verifier().new_request()
        self.assertNotIn("verifier_info", Wallet.read_request(jar)[1])

    def test_what_section_5_1_does_not_allow_is_refused_at_construction(self):
        for bad in ([], {}, {"data": "x"}, "registration_cert", [7], [{"data": "x"}],
                    [{"format": "", "data": "x"}],
                    [{"format": "f"}], [{"format": "f", "data": ""}], [{"format": "f", "data": 3}],
                    [{"format": "f", "data": "x", "credential_ids": []}],
                    [{"format": "f", "data": "x", "credential_ids": ["mdl"]}],
                    [{"format": "f", "data": "x", "other": 1}]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.verifier(verifier_info=bad)


#: ETSI TS 119 472-2 verifier_info as test material. Every identifier is in example.invalid, and
#: the registration certificate is a JWT signed by a key made for this run, never a registrar's.
_RC_KEY = ec.generate_private_key(ec.SECP256R1())
_PID = {"format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]}}
_NAMES = [{"path": ["given_name"]}, {"path": ["family_name"]}]
#: An ETSI TS 119 472-2 V1.2.1 requirement, as a refusal names it.
RO = "OIDFVP-HAIP-COMMON-REQ-RO-%02d"
#: The label check's reason, as the refusal gives it.
TYP_AS_FORMAT = ("rc-wrp+jwt is the registration certificate's JWT typ (ETSI TS 119 475); its "
                 "verifier_info format is registration_cert (ETSI TS 119 472-2 RO-15)")


def _registration_cert(credentials=None, typ="rc-wrp+jwt", payload=None):
    """A registration certificate (ETSI TS 119 475) for a test: a JWT whose `credentials` register
    what the default request asks for, unless given others or a whole `payload`."""
    if payload is None:
        payload = {"sub": "rp-0001.example.invalid",
                   "credentials": [dict(_PID, claim=_NAMES)] if credentials is None else credentials}
    return _jws(_RC_KEY, dict({"alg": "ES256"}, **({"typ": typ} if typ else {})), payload)


def _registrar(**members):
    """The registrar_dataset element: its six members and a credential. A member given replaces
    the default, and DROP removes it."""
    data = {"identifier": [{"type": "https://registry.example.invalid/identifier-types/number",
                            "identifier": "rp-0001.example.invalid"}],
            "srvDescription": [{"lang": "en", "content": "Example service (test material)"}],
            "registryURI": "https://registry.example.invalid/api/v1",
            "intendedUseIdentifier": "https://registry.example.invalid/intended-use/0001",
            "purpose": [{"lang": "en", "content": "Confirm the holder's name (test material)"}],
            "policyURI": "https://rp.example.invalid/privacy-policy",
            "credential": [_PID]}
    for name, value in members.items():
        if value is DROP:
            data.pop(name)
        else:
            data[name] = value
    return {"format": "registrar_dataset", "data": data}


def _certificate(data=None, **members):
    """The registration_cert element; DROP as `data` leaves data out."""
    element = {"format": "registration_cert"}
    if data is not DROP:
        element["data"] = _registration_cert() if data is None else data
    element.update(members)
    return element


class _EtsiProfile(unittest.TestCase):

    PROFILE = "etsi-119472-2"

    @classmethod
    def setUpClass(cls):
        cls.chain = _client_chain()

    def verifier(self, verifier_info, profile=PROFILE, **kw):
        return Verifier(client_cert_pem=self.chain[0], client_key_pem=self.chain[1],
                        request_uri="https://verifier.test/request.jwt",
                        response_uri="https://verifier.test/response",
                        verifier_info=verifier_info, verifier_info_profile=profile, **kw)

    def refused(self, verifier_info, *says, **kw):
        """The refusal's message, after asserting it names each of `says`. Every refusal test
        names its requirement: one that asserted ValueError alone would pass on another rule's
        refusal, and could not see this rule's absence."""
        with self.assertRaises(VerifierInfoError) as caught:
            self.verifier(verifier_info, **kw)
        for text in says:
            self.assertIn(text, str(caught.exception))
        return str(caught.exception)


class EtsiVerifierInfoTests(_EtsiProfile):
    """verifier_info_profile="etsi-119472-2": ETSI TS 119 472-2 V1.2.1's requirements for
    verifier_info in its HAIP-common request object, OIDFVP-HAIP-COMMON-REQ-RO-01 to -16. Each
    has a case it accepts and single defects it refuses, by the requirement's ID. Shape and labels
    only: the registration certificate's signature, chain and registry are not checked."""

    def test_the_control_constructs_and_is_carried_byte_for_byte(self):
        """A registrar_dataset with its six members and a credential, and a registration
        certificate: accepted, and the request object carries them byte for byte, fresh and
        minted for a wallet nonce."""
        info = [_registrar(), _certificate()]
        v = self.verifier(info)
        session, jar = v.new_request()
        sent = b'"verifier_info":' + json.dumps(info, separators=(",", ":")).encode()
        for token in (jar, v.request_object(session.state, wallet_nonce="w-1")):
            self.assertIn(sent, b64u_decode(token.split(".")[1]))

    def test_ro01_verifier_info_is_present(self):
        self.verifier([_registrar(), _certificate()])
        self.refused(None, RO % 1 + ":", "the request carries no verifier_info")
        self.refused([], RO % 1 + ":", "verifier_info is an empty array")

    def test_ro03_ro14_it_is_an_array(self):
        """RO-03 and RO-14 speak of "the element in the verifier_info array". The single object
        the German developer guide shows stays carried outside the profile."""
        self.verifier([_registrar()])
        self.refused(_registrar(), RO % 3 + " and " + RO % 14 + ":", "a single object")
        self.refused("registrar_dataset", RO % 3 + " and " + RO % 14 + ":")
        self.assertEqual(self.verifier(_registrar(), profile=None).verifier_info, _registrar())

    def test_ro03_ro14_a_string_element_is_refused(self):
        """Every element is an object: a string beside valid ones names no element."""
        self.verifier([_registrar(), _certificate()])
        for stray in ("registration_cert", "", 7, None, ["registration_cert"]):
            with self.subTest(stray=stray):
                self.refused([_registrar(), _certificate(), stray], RO % 3 + " and " + RO % 14 + ":",
                             "verifier_info element 2 is")
                self.refused([stray, _registrar()], "verifier_info element 0 is")

    def test_ro02_ro04_exactly_one_registrar_dataset(self):
        self.verifier([_registrar(), _certificate()])
        both = RO % 2 + " and " + RO % 4 + ":"
        self.refused([_certificate()], both, "has 0 elements with format registrar_dataset")
        self.refused([_registrar(), _registrar(), _certificate()], both, "has 2 elements")
        self.refused([dict(_registrar(), format="Registrar_Dataset")], both, "has 0 elements")

    def test_ro05_the_registrar_data_is_a_non_empty_object(self):
        self.verifier([_registrar(), _certificate()])
        for data in ({}, [], "registrar data", DROP):
            with self.subTest(data=data):
                element = {"format": "registrar_dataset"}
                if data is not DROP:
                    element["data"] = data
                self.refused([element, _certificate()], RO % 5 + ":", "not a non-empty JSON object")

    def test_ro03_ro14_neither_element_carries_credential_ids(self):
        self.verifier([_registrar(), _certificate()])
        self.refused([dict(_registrar(), credential_ids=["pid"]), _certificate()], RO % 3 + ":",
                     "the registrar_dataset element carries credential_ids")
        self.refused([_registrar(), _certificate(credential_ids=["pid"])], RO % 14 + ":",
                     "the registration_cert element carries credential_ids")

    def test_ro06_identifier(self):
        self.verifier([_registrar(identifier=[{"type": "t1", "identifier": "a.example.invalid"},
                                              {"type": "t2", "identifier": "b.example.invalid"}])])
        for bad in ([], [{"type": "t"}], [{"type": "t", "identifier": ""}],
                    [{"type": 1, "identifier": "i"}], ["rp-0001"], {"type": "t", "identifier": "i"},
                    "rp-0001", DROP):
            with self.subTest(identifier=bad):
                self.refused([_registrar(identifier=bad)], RO % 6 + ":", "data.identifier is")

    def test_ro07_srv_description(self):
        self.verifier([_registrar(srvDescription=[{"lang": "en", "content": "Service"},
                                                  {"lang": "de", "content": "Dienst"}])])
        for bad in ([], [{"lang": "en"}], [{"content": "Service"}], [{"lang": "", "content": "x"}],
                    [{"lang": "en", "content": ""}], ["Service"], "Service", DROP):
            with self.subTest(srvDescription=bad):
                self.refused([_registrar(srvDescription=bad)], RO % 7 + ":", "data.srvDescription is")

    def test_ro08_registry_uri(self):
        for good in ("https://registry.example.invalid/api?v=1", "urn:example:registry",
                     "https://registry.example.invalid/a%20b"):
            with self.subTest(registryURI=good):
                self.verifier([_registrar(registryURI=good)])
        for bad in ("", "/api/v1", "registry.example.invalid/api", "https:",
                    "https://registry.example.invalid/api#v1", "https://registry example.invalid",
                    "https://registry.example.invalid/%zz", "1https://registry.example.invalid",
                    "https://registry.example.invalid/\n", 7, DROP):
            with self.subTest(registryURI=bad):
                self.refused([_registrar(registryURI=bad)], RO % 8 + ":", "data.registryURI is")

    def test_ro09_intended_use_identifier(self):
        self.verifier([_registrar(intendedUseIdentifier="0001")])
        for bad in ("", 7, ["0001"], DROP):
            with self.subTest(intendedUseIdentifier=bad):
                self.refused([_registrar(intendedUseIdentifier=bad)], RO % 9 + ":",
                             "data.intendedUseIdentifier is")

    def test_ro10_purpose(self):
        self.verifier([_registrar(purpose=[{"lang": "en", "content": "Age check"},
                                           {"lang": "fr", "content": "Contrôle de l'âge"}])])
        for bad in ([], [{"lang": "en"}], [{"content": "Age check"}], [{"lang": "en", "content": 1}],
                    "Age check", DROP):
            with self.subTest(purpose=bad):
                self.refused([_registrar(purpose=bad)], RO % 10 + ":", "data.purpose is")

    def test_ro11_policy_uri(self):
        self.verifier([_registrar(policyURI="https://rp.example.invalid/privacy?lang=en")])
        for bad in ("", "privacy-policy", "rp.example.invalid/privacy-policy",
                    "https://rp.example.invalid/privacy#retention", " https://rp.example.invalid",
                    7, DROP):
            with self.subTest(policyURI=bad):
                self.refused([_registrar(policyURI=bad)], RO % 11 + ":", "data.policyURI is")

    def test_ro12_credential_may_be_absent_and_is_otherwise_objects(self):
        self.verifier([_registrar(credential=DROP)])
        self.verifier([_registrar(credential=[_PID, {"format": "mso_mdoc"}])])
        for bad in ([], [7], [_PID, "pid"], _PID, "pid"):
            with self.subTest(credential=bad):
                self.refused([_registrar(credential=bad)], RO % 12 + ":", "data.credential is")

    def test_ro13_ro15_a_format_naming_a_certificate_is_registration_cert(self):
        """A certificate this does not recognise by its typ (a CWT, or a JWT not typed
        rc-wrp+jwt) under a label that names one. Typed rc-wrp+jwt, the label check refuses it
        first, in every mode (test_ro15_...)."""
        self.verifier([_registrar(), _certificate()])
        opaque = b64u_encode(b"\xd2\x84test material, not a certificate")
        for label in ("WRPRC", "registration_certificate", "Registration_Cert", "registration-cert",
                      "rc_wrp_cwt", "RegistrationCert"):
            for data in (opaque, _registration_cert(typ="JWT"), _registration_cert(typ=None)):
                with self.subTest(label=label, data=data[:12]):
                    self.refused([_registrar(), {"format": label, "data": data}],
                                 RO % 13 + " and " + RO % 15 + ":", "%r, which names a "
                                 "registration certificate" % label)
        # A format that names something else is not judged by this rule.
        self.verifier([_registrar(), {"format": "policy", "data": opaque}])

    def test_ro15_the_label_check_holds_in_both_modes(self):
        """German EUDI Wallet iOS issue #38: a certificate under its own JWT typ is refused with
        the reason, profile or none, and the same data under registration_cert passes."""
        jwt = _registration_cert()
        for profile in (self.PROFILE, None):
            for label in ("rc-wrp+jwt", "RC-WRP+JWT", "application/rc-wrp+jwt"):
                with self.subTest(profile=profile, label=label):
                    self.refused([_registrar(), {"format": label, "data": jwt}], RO % 15 + ":",
                                 "entry 1 has format %r: " % label + TYP_AS_FORMAT, profile=profile)
            self.refused([_registrar(), {"format": "rc-wrp+cwt", "data": "0oRDoQEm"}],
                         "rc-wrp+cwt is the registration certificate's CWT typ", profile=profile)
            self.verifier([_registrar(), {"format": "registration_cert", "data": jwt}],
                          profile=profile)
        self.refused({"format": "rc-wrp+jwt", "data": jwt}, "the entry has format", TYP_AS_FORMAT,
                     profile=None)
        self.verifier({"format": "registration_cert", "data": jwt}, profile=None)

    def test_ro15_a_jws_typed_rc_wrp_jwt_is_a_certificate_under_any_label(self):
        """In both modes, and in both forms RO-16 can be read as: the compact serialization, or
        that serialization base64url-encoded once more."""
        jwt = _registration_cert()
        for profile in (self.PROFILE, None):
            for data in (jwt, b64u_encode(jwt.encode("ascii"))):
                for label in ("jwt", "attestation", "WRPRC"):
                    with self.subTest(profile=profile, label=label, form=len(data.split("."))):
                        self.refused([_registrar(), {"format": label, "data": data}],
                                     RO % 15 + ":", "its data is a JWS typed rc-wrp+jwt",
                                     profile=profile)
        self.verifier([{"format": "attestation", "data": _registration_cert(typ="JWT")}],
                      profile=None)

    def test_ro16_the_certificate_data_is_a_non_empty_string(self):
        self.verifier([_registrar(), _certificate()])
        for data in ("", {}, {"jwt": _registration_cert()}, [_registration_cert()], 7, DROP):
            with self.subTest(data=str(data)[:12]):
                self.refused([_registrar(), _certificate(data)], RO % 16 + ":",
                             "the registration_cert element's data is")

    def test_ro13_at_most_one_registration_certificate(self):
        """RO-13's "a" registration certificate: two separately issued ones cannot be combined.
        None is allowed, since RO-13 applies when the relying party has one."""
        self.verifier([_registrar(), _certificate()])
        self.verifier([_registrar()])
        self.refused([_registrar(), _certificate(), _certificate()], RO % 13 + ":",
                     "has 2 registration_cert elements", "at most one registration certificate")

    def test_empty_or_missing_input_is_refused_never_passed(self):
        """Nothing passes on empty input: the profile with no verifier_info, an empty array, an
        empty or missing data, and each of the six members present but empty."""
        self.refused(None, RO % 1 + ":")
        self.refused([], RO % 1 + ":")
        self.refused([{"format": "registrar_dataset", "data": {}}], RO % 5 + ":")
        self.refused([{"format": "registrar_dataset"}], RO % 5 + ":")
        for member, empty, number in (("identifier", [], 6), ("srvDescription", [], 7),
                                      ("registryURI", "", 8), ("intendedUseIdentifier", "", 9),
                                      ("purpose", [], 10), ("policyURI", "", 11)):
            with self.subTest(member=member):
                self.refused([_registrar(**{member: empty})], RO % number + ":", "data.%s is"
                             % member)
        all_empty = _registrar(identifier=[], srvDescription=[], registryURI="",
                               intendedUseIdentifier="", purpose=[], policyURI="")
        self.refused([all_empty], RO % 6 + ":")
        self.refused([_registrar(), _certificate(DROP)], RO % 16 + ":", "data is absent")
        self.refused([_registrar(), _certificate("")], RO % 16 + ":")

    def test_an_unknown_profile_is_refused_not_ignored(self):
        for profile in ("etsi", "ETSI-119472-2", "etsi-119472-2 ", ""):
            with self.subTest(profile=profile):
                self.refused([_registrar()], "is not a profile this verifier knows", profile=profile)

    def test_without_the_profile_only_section_5_1_and_the_label_check_apply(self):
        """Outside the profile, verifier_info the profile refuses is carried as given, so long as
        section 5.1 allows it: the registrar data, its members and the over-asking check are the
        profile's alone."""
        for info in ([_certificate("eyJhbGciOiJFUzI1NiJ9.e30.c2ln")],
                     [_registrar(identifier=DROP, registryURI="/api")],
                     [_registrar(), _certificate(), _certificate()],
                     [_registrar(), _certificate(_registration_cert([dict(_PID, claims=_NAMES)]))],
                     [{"format": "WRPRC", "data": "opaque"}]):
            with self.subTest(info=str(info)[:40]):
                v = self.verifier(info, profile=None)
                _, jar = v.new_request()
                self.assertEqual(Wallet.read_request(jar)[1]["verifier_info"], info)


class OverAskingTests(_EtsiProfile):
    """Under the profile, a request whose DCQL query asks for a credential, or a claim path, that
    its registration certificate does not register is refused before it is made. The German EUDI
    Wallet refuses one (iOS 0.3.9; Android #40). The certificate is the operator's own and its
    payload is read without checking its signature, which every refusal says."""

    def verifier(self, certificate, **kw):
        return super().verifier([_registrar(), _certificate(certificate)], **kw)

    def refused(self, certificate, *says, **kw):
        return super().refused(certificate, "the over-asking check refuses this request",
                               "its signature is NOT checked", *says, **kw)

    def test_a_certificate_registering_what_is_asked_passes(self):
        self.verifier(_registration_cert())
        self.verifier(_registration_cert([dict(
            _PID, meta={"vct_values": ["urn:eudi:pid:de:1", "urn:eudi:pid:1"]},
            claim=_NAMES + [{"path": ["birthdate"]}])]))
        self.verifier(_registration_cert([dict(_PID, claim=[{"path": ["given_name"]}])]),
                      claims=["given_name"])
        self.verifier(_registration_cert([dict(_PID, claim=[{"path": ["age_equal_or_over", "18"],
                                                             "values": [True]}])]),
                      claims=[{"path": ["age_equal_or_over", "18"], "values": [True]}])

    def test_a_claim_path_it_does_not_register_is_refused(self):
        self.refused(_registration_cert([dict(_PID, claim=[{"path": ["given_name"]}])]),
                     "credential query 'pid' asks for the claim path [\"family_name\"], which the "
                     "certificate's credential of that type does not register")
        # Paths compare exactly, as the Android wallet compares them: a member is not its object.
        self.refused(_registration_cert([dict(_PID, claim=[{"path": ["age_equal_or_over"]}])]),
                     "[\"age_equal_or_over\", \"18\"]", claims=[["age_equal_or_over", "18"]])
        # One credential registers the whole query; two halves in two credentials do not.
        self.refused(_registration_cert([dict(_PID, claim=[{"path": ["given_name"]}]),
                                         dict(_PID, claim=[{"path": ["family_name"]}])]),
                     "asks for the claim path")

    def test_without_claim_only_the_format_and_meta_are_held(self):
        """ETSI TS 119 475: "If claim is absent, the WRPRC does not declare any specific
        attributes intended to be requested by the WRP"."""
        self.verifier(_registration_cert([dict(_PID)]))
        self.verifier(_registration_cert([dict(_PID)]), claims=["given_name", "birthdate"])
        self.refused(_registration_cert([dict(_PID, meta={"vct_values": ["urn:eudi:pid:de:1"]})]),
                     "none of the certificate's credentials registers that")

    def test_claims_in_the_certificate_is_not_etsis_key(self):
        """A certificate that says `claims` is reported, never read as registering no claim."""
        for claims in (_NAMES, []):
            with self.subTest(claims=claims):
                self.refused(_registration_cert([dict(_PID, claims=claims)]),
                             "credentials[0] has `claims`, which is not ETSI's key")
        self.refused(_registration_cert([dict(_PID, claim=_NAMES, claims=_NAMES)]),
                     "not ETSI's key")

    def test_a_credential_it_does_not_register_is_refused(self):
        for registered in ([dict(_PID, format="mso_mdoc", claim=_NAMES)],
                           [dict(_PID, format="vc+sd-jwt", claim=_NAMES)],
                           [dict(_PID, meta={"vct_values": ["urn:eudi:pid:de:1"]}, claim=_NAMES)],
                           [dict(_PID, meta={"vct_values": "urn:eudi:pid:1"}, claim=_NAMES)],
                           [dict(_PID, meta={"vct_values": ["urn:eudi:pid:1"],
                                             "doctype_value": "eu.europa.ec.eudi.pid.1"},
                                 claim=_NAMES)]):
            with self.subTest(registered=registered):
                self.refused(_registration_cert(registered), "credential query 'pid' asks for "
                             "format \"dc+sd-jwt\" with meta", "none of the certificate's "
                             "credentials registers that")
        # A credential that states no meta, or an empty one, restricts none of it.
        self.verifier(_registration_cert([{"format": "dc+sd-jwt", "claim": _NAMES}]))
        self.verifier(_registration_cert([dict(_PID, meta={}, claim=_NAMES)]))

    def test_a_certificate_it_cannot_read_is_refused_not_passed(self):
        header = b64u_encode(b'{"alg":"ES256","typ":"rc-wrp+jwt"}')
        for data in ("not-a-jwt", "a.b", header + ".e30", header + ".W10.c2ln",
                     header + ".bm90IGpzb24.c2ln", header + ".%%%.c2ln",
                     "eyJhbGciOiJFUzI1NiJ9.e30.c2ln.extra"):
            with self.subTest(data=data[-16:]):
                self.refused(data, "the registration certificate is not a JWT")
        for payload, shown in (({"sub": "rp"}, "absent"), ({"credentials": []}, "[]"),
                               ({"credentials": {"format": "dc+sd-jwt"}}, "{"),
                               ({"credentials": "pid"}, '"pid"')):
            with self.subTest(payload=payload):
                self.refused(_registration_cert(payload=payload),
                             "credentials are %s" % shown, "registers no credential to ask for")
        self.refused(_registration_cert([7]), "credentials[0] is 7, not an object")
        self.refused(_registration_cert([dict(_PID), "pid"]), "credentials[1] is \"pid\"")
        for claim in ("given_name", [{"name": "given_name"}], [["given_name"]],
                      [{"path": "given_name"}]):
            with self.subTest(claim=claim):
                self.refused(_registration_cert([dict(_PID, claim=claim)]),
                             "credentials[0].claim is", "not an array of claims each with a path")
        self.refused(_registration_cert([dict(_PID, meta="urn:eudi:pid:1", claim=_NAMES)]),
                     "credentials[0].meta is \"urn:eudi:pid:1\", not an object")

    def test_both_readings_of_ro16_are_read(self):
        """RO-16: "the base64url encoding of the serialized RP registration certificate". A JWT's
        compact serialization is base64url already, or it is encoded once more: both are read,
        and the second must decode to an ASCII compact serialization."""
        once_more = b64u_encode(_registration_cert().encode("ascii"))
        self.assertEqual(len(once_more.split(".")), 1)
        self.verifier(once_more)
        narrow = _registration_cert([dict(_PID, claim=[{"path": ["given_name"]}])])
        self.refused(b64u_encode(narrow.encode("ascii")),
                     "asks for the claim path [\"family_name\"]")
        # The signature is never decoded here, so non-ASCII there would pass unseen if the
        # second reading took any bytes: a payload this registers, under a signature that is not.
        signed = _registration_cert().rsplit(".", 1)[0]
        for name, data in (("not ASCII", b64u_encode("\u00e9.\u00e9.\u00e9".encode("utf-8"))),
                           ("a signature not ASCII",
                            b64u_encode((signed + ".sig\u00e9").encode("utf-8"))),
                           ("two parts", b64u_encode(narrow.rsplit(".", 1)[0].encode("ascii"))),
                           ("four parts", b64u_encode((narrow + ".x").encode("ascii"))),
                           ("not base64url", narrow.replace(".", "!"))):
            with self.subTest(name):
                self.refused(data, "is not a JWT this check can read", "as it is or base64url-"
                             "encoded once more")

    def test_it_holds_the_query_the_request_sends(self):
        v = self.verifier(_registration_cert([dict(_PID, claim=[{"path": ["given_name"]}])]),
                          claims=["given_name"], credential_query_id="pid")
        _, jar = v.new_request()
        self.assertEqual(Wallet.read_request(jar)[1]["dcql_query"], v._dcql_query())
        self.refused(_registration_cert([dict(_PID, claim=[{"path": ["given_name"]}])]),
                     "credential query 'age' asks for", claims=["given_name", "birthdate"],
                     credential_query_id="age")

    def test_outside_the_profile_it_is_not_applied(self):
        over = _registration_cert([dict(_PID, claim=[{"path": ["given_name"]}])])
        super().verifier([_registrar(), _certificate(over)], profile=None)
        super().verifier([_certificate("not-a-jwt")], profile=None)


VERIFIER_INFO_VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata",
                                     "verifier-info")


def verifier_info_vectors():
    """testdata/verifier-info: (file name, vector) for each case, the control first."""
    out = []
    for name in sorted(os.listdir(VERIFIER_INFO_VECTORS)):
        if name.endswith(".json"):
            with open(os.path.join(VERIFIER_INFO_VECTORS, name), encoding="utf-8") as fh:
                out.append((name, json.load(fh)))
    return out


class VerifierInfoVectorTests(_EtsiProfile):
    """testdata/verifier-info: the control, one single-defect case per rule, a certificate
    without `claim` and the same verifier_info outside the profile, as JSON another verifier can
    read. Each reaches its verdict here, and each refusal says what its file says."""

    def test_every_vector_reaches_its_verdict(self):
        vectors = verifier_info_vectors()
        self.assertEqual(sorted(v["expect"] for _, v in vectors), ["accept"] * 3 + ["refuse"] * 17,
                         "three accepted, and one refusal per rule")
        for name, vector in vectors:
            s = vector["settings"]
            kw = dict(profile=s["verifier_info_profile"], vct_values=s["vct_values"],
                      claims=s["claims"], credential_query_id=s["credential_query_id"])
            with self.subTest(vector=name):
                if vector["expect"] == "accept":
                    self.verifier(vector["verifier_info"], **kw)
                    continue
                self.refused(vector["verifier_info"], vector["says"],
                             *([vector["requirement"] + ":"] if vector["requirement"] else []),
                             **kw)

    def test_they_are_test_material(self):
        """Every URI in example.invalid, every certificate typed rc-wrp+jwt carrying no key."""
        for name, vector in verifier_info_vectors():
            text = json.dumps(vector["verifier_info"])
            with self.subTest(vector=name):
                for uri in re.findall(r"https?://[^\"/]+", text):
                    self.assertTrue(uri.endswith(".example.invalid"), uri)
                self.assertNotIn('"d":', text)
                self.assertNotIn("PRIVATE KEY", text)


class WhatTheGermanWalletRefusesTests(VerifierTestCase):
    """Shapes the German EUDI Wallet refuses, which this request already avoids, pinned so a
    regression is caught: the DCQL key `claim` (Android #36: "By putting them in `claim` the
    wallet will ignore it"), `trusted_authorities` (iOS #27), a `claim_sets` fallback (Android
    #21), `response_mode` `direct_post` (iOS #29), and an x5c carrying more than the access
    certificate (the German guide: "Only include the access certificate and no other certificate
    in the header!")."""

    def test_every_credential_query_names_claims_never_claim(self):
        _, jar = self.verifier.new_request()
        for query in Wallet.read_request(jar)[1]["dcql_query"]["credentials"]:
            self.assertIn("claims", query)
            self.assertNotIn("claim", query)

    def test_the_dcql_query_has_no_trusted_authorities_or_claim_sets(self):
        _, jar = self.verifier.new_request()
        dcql = Wallet.read_request(jar)[1]["dcql_query"]
        self.assertEqual(set(dcql), {"credentials"})
        for query in dcql["credentials"]:
            self.assertEqual(set(query), {"id", "format", "meta", "claims"})

    def test_the_response_mode_is_direct_post_jwt(self):
        _, jar = self.verifier.new_request()
        self.assertEqual(Wallet.read_request(jar)[1]["response_mode"], "direct_post.jwt")

    def test_x5c_is_the_signing_leaf_alone(self):
        _, jar = self.verifier.new_request()
        header, _ = Wallet.read_request(jar)
        self.assertEqual(len(header["x5c"]), 1)
        leaf = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][0]))
        self.assertEqual(leaf, self.verifier.cert)
        signing_input, _, signature = jar.rpartition(".")
        raw = b64u_decode(signature)
        leaf.public_key().verify(
            asym_utils.encode_dss_signature(int.from_bytes(raw[:32], "big"),
                                            int.from_bytes(raw[32:], "big")),
            signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))


class TheDefaultRequestIsUnchangedTests(VerifierTestCase):
    """Without a verifier_info profile, the request object is byte for byte the one 1.0.0rc19
    built: these templates were checked against that release's code before the profile existed.
    Only what is fresh per request is filled in, and each of those is checked against its source."""

    HEADER = '{"alg":"ES256","typ":"oauth-authz-req+jwt","x5c":["<X5C>"]}'
    PAYLOAD = ('{"iss":"<CLIENT_ID>","aud":"https://self-issued.me/v2","client_id":"<CLIENT_ID>",'
               '"response_type":"vp_token","response_mode":"direct_post.jwt",'
               '"response_uri":"https://verifier.test/response","nonce":"<NONCE>",'
               '"state":"<STATE>","iat":<IAT>,"exp":<EXP>,"client_metadata":{"jwks":{"keys":[{'
               '"kty":"EC","crv":"P-256","use":"enc","alg":"ECDH-ES","kid":"enc-<STATE>",'
               '"x":"<X>","y":"<Y>"}]},"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":'
               '["ES256"],"kb-jwt_alg_values":["ES256"]}},"encrypted_response_enc_values_supported":'
               '["A128GCM","A256GCM"]},"dcql_query":{"credentials":[{"id":"pid","format":'
               '"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":'
               '["given_name"]},{"path":["family_name"]}]}]}<TAIL>}')

    def assert_as_before(self, verifier, tail=""):
        before = int(time.time())
        session, jar = verifier.new_request()
        header, payload, _ = jar.split(".")
        iat = json.loads(b64u_decode(payload))["iat"]
        self.assertTrue(before <= iat <= time.time())
        numbers = session.enc_key.public_key().public_numbers()
        fill = {"<CLIENT_ID>": verifier.client_id, "<NONCE>": session.nonce,
                "<STATE>": session.state, "<IAT>": str(iat),
                "<EXP>": str(iat + DEFAULT_REQUEST_TTL_SECONDS),
                "<X>": b64u_encode(numbers.x.to_bytes(32, "big")),
                "<Y>": b64u_encode(numbers.y.to_bytes(32, "big")),
                "<X5C>": verifier.x5c[0], "<TAIL>": tail}
        expected_header, expected_payload = self.HEADER, self.PAYLOAD
        for slot, value in fill.items():
            expected_header = expected_header.replace(slot, value)
            expected_payload = expected_payload.replace(slot, value)
        self.assertEqual(b64u_decode(header).decode("ascii"), expected_header)
        self.assertEqual(b64u_decode(payload).decode("ascii"), expected_payload)

    def test_the_default_request_object_is_as_before(self):
        self.assert_as_before(self.verifier)

    def test_verifier_info_without_a_profile_is_carried_as_before(self):
        cert_pem, key_pem = _client_chain()
        for info in ([{"format": "registration_cert", "data": "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"}],
                     {"format": "registration_cert", "data": "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"}):
            with self.subTest(info=type(info).__name__):
                v = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                             request_uri="https://verifier.test/request.jwt",
                             response_uri="https://verifier.test/response", verifier_info=info)
                self.assert_as_before(v, ',"verifier_info":' + json.dumps(info, separators=(",", ":")))

    def test_naming_no_profile_is_the_default(self):
        cert_pem, key_pem = _client_chain()
        v = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                     request_uri="https://verifier.test/request.jwt",
                     response_uri="https://verifier.test/response", verifier_info_profile=None)
        self.assertIsNone(v.verifier_info_profile)
        self.assert_as_before(v)


class TheRequestTests(VerifierTestCase):
    """Built from what the running conformance suite accepted, condition by condition."""

    def test_the_request_object_is_a_signed_jar_with_only_the_leaf_in_x5c(self):
        _, jar = self.verifier.new_request()
        header, _ = Wallet.read_request(jar)
        self.assertEqual(header["typ"], "oauth-authz-req+jwt")
        self.assertEqual(header["alg"], "ES256")
        self.assertEqual(len(header["x5c"]), 1,
                         "the registered trust anchor must NOT be in the chain")

    def test_the_client_id_is_the_leaf_hash_and_matches_the_request_object(self):
        _, jar = self.verifier.new_request()
        header, claims = Wallet.read_request(jar)
        digest = hashlib.sha256(base64.b64decode(header["x5c"][0])).digest()
        self.assertEqual(claims["client_id"], "x509_hash:" + b64u_encode(digest))
        self.assertEqual(claims["iss"], claims["client_id"])

    def test_client_metadata_carries_exactly_the_three_keys_the_suite_knows(self):
        _, jar = self.verifier.new_request()
        _, claims = Wallet.read_request(jar)
        self.assertEqual(set(claims["client_metadata"]),
                         {"jwks", "vp_formats_supported",
                          "encrypted_response_enc_values_supported"})
        self.assertEqual(set(claims["client_metadata"]
                             ["encrypted_response_enc_values_supported"]),
                         {"A128GCM", "A256GCM"}, "HAIP section 5 requires both")

    def test_the_encryption_key_is_never_reused_between_requests(self):
        _, first = self.verifier.new_request()
        _, second = self.verifier.new_request()
        keys = [Wallet.read_request(j)[1]["client_metadata"]["jwks"]["keys"][0]["x"]
                for j in (first, second)]
        self.assertNotEqual(keys[0], keys[1],
                            "one long-lived response key makes every past presentation "
                            "readable by whoever later obtains it")

    def test_the_nonce_is_fresh_and_has_real_entropy(self):
        nonces = {Wallet.read_request(self.verifier.new_request()[1])[1]["nonce"]
                  for _ in range(8)}
        self.assertEqual(len(nonces), 8)
        for nonce in nonces:
            self.assertGreaterEqual(len(b64u_decode(nonce)) * 8, 128)

    def test_the_dcql_query_asks_for_exactly_one_credential(self):
        _, jar = self.verifier.new_request()
        _, claims = Wallet.read_request(jar)
        self.assertEqual(len(claims["dcql_query"]["credentials"]), 1,
                         "the plan's happy flow refuses a query for more than one")

    def test_the_request_object_may_be_fetched_twice(self):
        """A module in the plan does exactly this. Single-use would fail it for nothing."""
        session, _ = self.verifier.new_request()
        first = self.verifier.request_object(session.state)
        second = self.verifier.request_object(session.state)
        self.assertTrue(first and first == second)

    def test_request_uri_method_post_is_advertised(self):
        """Without it the request-uri-method-post module SKIPS itself, and a skipped module
        reported as clean is the same lie as a vacuous pass."""
        session, _ = self.verifier.new_request()
        params = self.verifier.authorization_request_params(session)
        self.assertEqual(params["request_uri_method"], "post")
        self.assertIn(session.state, params["request_uri"])

    def test_a_posted_wallet_nonce_comes_back_as_a_claim(self):
        """OpenID4VP 1.0 section 5.10. It is the wallet's half of the replay protection."""
        session, _ = self.verifier.new_request()
        jar = self.verifier.request_object(session.state, wallet_nonce="w-123456")
        _, claims = Wallet.read_request(jar)
        self.assertEqual(claims["wallet_nonce"], "w-123456")

    def test_a_cached_object_is_never_served_to_a_post(self):
        """Serving the cached one would silently drop the wallet's nonce."""
        session, _ = self.verifier.new_request()
        cached = self.verifier.request_object(session.state)
        posted = self.verifier.request_object(session.state, wallet_nonce="w-abc")
        self.assertNotEqual(cached, posted)
        self.assertNotIn("wallet_nonce", Wallet.read_request(cached)[1])

    def test_a_wallet_nonce_for_an_unknown_state_gets_nothing(self):
        self.assertIsNone(self.verifier.request_object("no-such-state",
                                                       wallet_nonce="w-1"))



class RequestObjectEncryptionTests(VerifierTestCase):
    """OpenID4VP 1.0 section 5.10: a wallet that asks gets the request object encrypted to its
    key. The EUDI iOS wallet kit (0.54.5) always asks, and refused the signed object it got
    instead (lab/interop/eudi-ios, 2026-10-04)."""

    def _metadata(self, **over):
        self.wallet_key = ec.generate_private_key(ec.SECP256R1())
        jwk = dict(_public_jwk(self.wallet_key), use="enc", alg="ECDH-ES", kid="wallet-enc-1")
        meta = {"jwks": {"keys": [jwk]},
                "request_object_encryption_alg_values_supported": ["ECDH-ES"],
                "request_object_encryption_enc_values_supported": ["A128GCM"]}
        meta.update(over)
        return json.dumps(meta)

    def test_a_wallet_that_asks_gets_the_signed_object_encrypted_to_its_key(self):
        session, _ = self.verifier.new_request()
        jwe = self.verifier.request_object(session.state, wallet_nonce="w-1",
                                           wallet_metadata=self._metadata())
        self.assertEqual(len(jwe.split(".")), 5)
        header = json.loads(b64u_decode(jwe.split(".")[0]))
        self.assertEqual((header["alg"], header["enc"], header["cty"], header["kid"]),
                         ("ECDH-ES", "A128GCM", "JWT", "wallet-enc-1"))
        jws_header, claims = Wallet.read_request(decrypt_compact(jwe, self.wallet_key).decode())
        self.assertEqual(jws_header["typ"], "oauth-authz-req+jwt")
        self.assertEqual((claims["wallet_nonce"], claims["state"]), ("w-1", session.state))

    def test_without_a_nonce_the_cached_object_is_what_gets_encrypted(self):
        session, cached = self.verifier.new_request()
        jwe = self.verifier.request_object(session.state, wallet_metadata=self._metadata())
        self.assertEqual(decrypt_compact(jwe, self.wallet_key).decode(), cached)

    def test_the_wallets_enc_order_is_followed_where_this_can_produce_it(self):
        session, _ = self.verifier.new_request()
        meta = self._metadata(request_object_encryption_enc_values_supported=[
            "A128CBC-HS256", "A256GCM", "A128GCM"])
        jwe = self.verifier.request_object(session.state, wallet_nonce="w", wallet_metadata=meta)
        self.assertEqual(json.loads(b64u_decode(jwe.split(".")[0]))["enc"], "A256GCM")
        self.assertIn(b"w", decrypt_compact(jwe, self.wallet_key))

    def test_a_wallet_that_asks_for_nothing_gets_the_signed_object(self):
        session, _ = self.verifier.new_request()
        for meta in (None, "{}", json.dumps({"vp_formats_supported": {}}),
                     self._metadata(request_object_encryption_alg_values_supported=None)):
            with self.subTest(meta=meta):
                jar = self.verifier.request_object(session.state, wallet_nonce="w",
                                                   wallet_metadata=meta)
                self.assertEqual(len(jar.split(".")), 3)

    def test_what_this_cannot_produce_is_served_signed_as_before(self):
        session, _ = self.verifier.new_request()
        off_curve = dict(_public_jwk(ec.generate_private_key(ec.SECP256R1())),
                         y=b64u_encode(b"\x01" * 32))
        cases = {
            "an enc this cannot produce": self._metadata(
                request_object_encryption_enc_values_supported=["A128CBC-HS256"]),
            "an alg this cannot produce": self._metadata(
                request_object_encryption_alg_values_supported=["RSA-OAEP-256"]),
            "a key marked for signing": self._metadata(jwks={"keys": [dict(
                _public_jwk(ec.generate_private_key(ec.SECP256R1())), use="sig")]}),
            "a point off the curve": self._metadata(jwks={"keys": [off_curve]}),
            "no keys": self._metadata(jwks={"keys": []}),
            "metadata that does not parse": "{",
            "metadata nested past the bound": "[" * 5000 + "]" * 5000,
        }
        for label, meta in cases.items():
            with self.subTest(label):
                jar = self.verifier.request_object(session.state, wallet_nonce="w",
                                                   wallet_metadata=meta)
                self.assertEqual(len(jar.split(".")), 3)

    def test_an_unknown_state_gets_nothing_even_when_encryption_is_asked(self):
        for nonce in (None, "w"):
            with self.subTest(nonce=nonce):
                self.assertIsNone(self.verifier.request_object(
                    "no-such-state", wallet_nonce=nonce, wallet_metadata=self._metadata()))


class TheHappyPathTests(VerifierTestCase):
    """The positive control. Without it every 4xx below is a verifier that never says yes."""

    def test_a_good_presentation_is_answered_200(self):
        _, status, body = self.exchange()
        self.assertEqual(status, 200, body)

    def test_the_200_body_carries_only_a_redirect_uri(self):
        """HAIP 5.1, and the suite checks the 'only' part."""
        _, _, body = self.exchange()
        self.assertEqual(set(body), {"redirect_uri"})
        self.assertTrue(body["redirect_uri"])

    def test_the_claims_come_back_to_the_caller(self):
        _, jar = self.verifier.new_request()
        form = self.wallet.respond(jar)
        status, _, verdict = self.verifier.handle_direct_post(form)
        self.assertEqual(status, 200)
        self.assertEqual(verdict.claims["given_name"], "Jean")

    def test_a256gcm_is_accepted_because_it_is_advertised(self):
        _, status, body = self.exchange(enc="A256GCM")
        self.assertEqual(status, 200, body)


class RevocationReachesTheOperatorTests(unittest.TestCase):
    """The resolver has to be reachable from the CLASS, not only from the function under it.

    2026-09-19: `verify_presentation` gained `status_resolver` and `Verifier` did not thread
    it, so the capability existed in the package and not in the product. `Verifier` is what an
    operator constructs and what answers the wallet; a parameter reachable only from the layer
    beneath it is a capability nobody can use.
    """

    def _verifier(self, **kw):
        cert_pem, key_pem = _client_chain()
        self.wallet = Wallet()
        return Verifier(
            client_cert_pem=cert_pem, client_key_pem=key_pem,
            request_uri="https://verifier.test/request.jwt",
            response_uri="https://verifier.test/response",
            issuer_jwks=[self.wallet.issuer_jwk], **kw)

    def _exchange(self, verifier):
        _, jar = verifier.new_request()
        status, _, verdict = verifier.handle_direct_post(self.wallet.respond(jar))
        return status, verdict

    def test_without_a_resolver_the_verdict_says_nobody_looked(self):
        status, verdict = self._exchange(self._verifier())
        self.assertEqual(status, 200)
        self.assertFalse(verdict.revocation["checked"])
        self.assertIn(verdict.revocation["state"],
                      (sdjwt.NO_STATUS_CLAIM, sdjwt.NOT_EVALUATED))

    STATUS = {"status_list": {"uri": "https://issuer.example/sl/1", "idx": 5}}

    def test_a_resolver_given_to_the_class_is_reached(self):
        """The regression this class exists for: the class must pass it DOWN.

        Written first as `assertIs(v.status_resolver, resolver)` plus a credential carrying
        no status claim, which passed with the resolver never threaded past __init__: the
        resolver was held and not used, and nothing could tell. The credential has to name a
        list, and the assertion has to be that the resolver's ANSWER reached the verdict.
        """
        asked = []

        def resolver(*, uri, idx, issuer):
            asked.append((uri, idx, issuer))
            return {"checked": True, "status": 1, "meaning": "INVALID"}

        v = self._verifier(status_resolver=resolver)
        _, jar = v.new_request()
        status, _, verdict = v.handle_direct_post(
            self.wallet.respond(jar, status=self.STATUS))
        # A checked INVALID is refused on the wire (2026-10-01); it was answered 200.
        self.assertEqual((status, verdict.code), (400, "revoked"))
        self.assertEqual(asked, [("https://issuer.example/sl/1", 5, "https://issuer.example")])
        self.assertTrue(verdict.revocation["checked"])
        self.assertEqual(verdict.revocation["meaning"], "INVALID")

    def test_a_checked_status_decides_the_answer(self):
        """The review of 2026-09-30: the resolver's answer reached the verdict and changed
        nothing on the wire, so a credential the issuer had revoked was answered 200. A value
        that is not VALID is a fact and is refused; a status nobody could read stays a reported
        state for the relying party's policy, as before."""
        for value, meaning, answer in ((0, "VALID", 200), (1, "INVALID", 400), (2, "SUSPENDED", 400)):
            with self.subTest(meaning=meaning):
                v = self._verifier(status_resolver=lambda *, uri, idx, issuer, value=value, meaning=meaning:
                                   {"checked": True, "status": value, "meaning": meaning})
                _, jar = v.new_request()
                status, _, verdict = v.handle_direct_post(self.wallet.respond(jar, status=self.STATUS))
                self.assertEqual(status, answer)

        def unreachable(*, uri, idx, issuer):
            raise OSError("the status host did not answer")
        v = self._verifier(status_resolver=unreachable)
        _, jar = v.new_request()
        status, _, verdict = v.handle_direct_post(self.wallet.respond(jar, status=self.STATUS))
        self.assertEqual((status, verdict.revocation["state"]), (200, sdjwt.UNREACHABLE))

    def test_without_a_resolver_a_named_list_is_not_evaluated(self):
        """The same credential, no resolver: nobody looked, and the verdict says so."""
        v = self._verifier()
        _, jar = v.new_request()
        status, _, verdict = v.handle_direct_post(
            self.wallet.respond(jar, status=self.STATUS))
        self.assertEqual(status, 200)
        self.assertFalse(verdict.revocation["checked"])
        self.assertEqual(verdict.revocation["state"], sdjwt.NOT_EVALUATED)


class TheRequestIsWhatIsAnsweredTests(unittest.TestCase):
    """The review of 2026-09-30: a presentation withholding a claim the DCQL query asked for was
    answered 200, and a request past its lifetime was still served, even re-signed with a new
    `exp` for a wallet nonce."""

    def _verifier(self, **kw):
        cert_pem, key_pem = _client_chain()
        self.wallet = Wallet()
        return Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                        request_uri="https://verifier.test/request.jwt",
                        response_uri="https://verifier.test/response",
                        issuer_jwks=[self.wallet.issuer_jwk], **kw)

    def test_a_presentation_missing_a_requested_claim_is_refused(self):
        v = self._verifier()
        _, jar = v.new_request()
        self.assertEqual(v.handle_direct_post(self.wallet.respond(jar))[0], 200, "control")
        v = self._verifier(claims=("given_name", "family_name", "birthdate"))
        _, jar = v.new_request()
        status, _, verdict = v.handle_direct_post(self.wallet.respond(jar))
        self.assertEqual((status, verdict.code), (400, "claims"))
        self.assertIn("birthdate", verdict.reason)

    def test_a_request_past_its_lifetime_is_not_served(self):
        v = self._verifier(request_ttl_seconds=60)
        session, jar = v.new_request()
        self.assertEqual(v.request_object(session.state), jar, "control: served while outstanding")
        self.assertIsNotNone(v.request_object(session.state, wallet_nonce="n-1"))
        session.created -= 61
        self.assertIsNone(v.request_object(session.state))
        self.assertIsNone(v.request_object(session.state, wallet_nonce="n-2"))


class TheSevenRefusalsReachTheWireTests(VerifierTestCase):
    """One per negative module. The plan passes each of these on a 4xx and nothing else."""

    def _refused(self, **kw):
        """Refuse on the wire, and return the code from the VERDICT, not from the body.

        The body is a constant. Reading the cause out of it is what an attacker would do,
        and the whole point of the change these tests were rewritten for is that they
        cannot.
        """
        _, jar = self.verifier.new_request()
        status, body, verdict = self.verifier.handle_direct_post(self.wallet.respond(jar, **kw))
        self.assertEqual(status, 400, "answered %d, so this module would FAIL" % status)
        self.assertEqual(body, self.verifier.REFUSAL_BODY, "the wire body varies with the cause")
        self.assertIsNotNone(verdict, "the operator was told nothing either")
        return verdict.code

    def test_invalid_credential_signature_is_4xx(self):
        self.assertEqual("issuer_signature", self._refused(corrupt_issuer_sig=True))

    def test_invalid_sd_hash_is_4xx(self):
        self.assertEqual("sd_hash", self._refused(sd_hash=b64u_encode(b"x" * 32)))

    def test_invalid_kb_jwt_signature_is_4xx(self):
        self.assertEqual("kb_signature", self._refused(corrupt_kb_sig=True))

    def test_invalid_kb_jwt_nonce_is_4xx(self):
        self.assertEqual("nonce", self._refused(nonce="not-the-one-we-sent"))

    def test_invalid_kb_jwt_aud_is_4xx(self):
        self.assertEqual("audience", self._refused(audience="x509_hash:somebody-else"))

    def test_kb_jwt_iat_in_past_is_4xx(self):
        self.assertEqual("kb_freshness", self._refused(iat=int(time.time()) - 365 * 86400))

    def test_kb_jwt_iat_in_future_is_4xx(self):
        self.assertEqual("kb_freshness", self._refused(iat=int(time.time()) + 365 * 86400))


class TheTransportRefusalsTests(VerifierTestCase):

    def test_a_response_encrypted_to_another_verifier_is_4xx(self):
        other = Verifier(client_cert_pem=_client_chain()[0], client_key_pem=_client_chain()[1],
                         request_uri="https://other.test/request.jwt",
                         response_uri="https://other.test/response",
                         issuer_jwks=[self.wallet.issuer_jwk])
        _, their_jar = other.new_request()
        self.verifier.new_request()
        form = self.wallet.respond(their_jar)
        status, body, _ = self.verifier.handle_direct_post(form)
        self.assertEqual(status, 400)
        self.assertEqual(body, self.verifier.REFUSAL_BODY)

    def test_an_empty_post_is_4xx(self):
        status, body, _ = self.verifier.handle_direct_post({})
        self.assertEqual(status, 400)
        self.assertEqual(body, self.verifier.REFUSAL_BODY)

    def test_a_replayed_response_is_4xx_the_second_time(self):
        _, jar = self.verifier.new_request()
        form = self.wallet.respond(jar)
        first, _, _ = self.verifier.handle_direct_post(form)
        second, body, _ = self.verifier.handle_direct_post(form)
        self.assertEqual(first, 200)
        self.assertEqual(second, 400, "the same presentation was accepted twice")
        self.assertEqual(body, self.verifier.REFUSAL_BODY)

    def test_a_vp_token_with_two_credentials_is_4xx(self):
        _, status, body = self.exchange(vp_token={"pid": ["a~b~c"], "other": ["d~e~f"]})
        self.assertEqual(status, 400)
        self.assertEqual(body, self.verifier.REFUSAL_BODY)

    def test_a_smuggled_disclosure_is_4xx(self):
        smuggled = b64u_encode(json.dumps(["s9", "is_over_18", True],
                                          separators=(",", ":")).encode())
        _, status, body = self.exchange(extra_disclosure=smuggled)
        self.assertEqual(status, 400)
        self.assertEqual(body, self.verifier.REFUSAL_BODY)

    def test_nothing_ever_answers_5xx(self):
        """A 5xx tells the wallet to retry something that will never work."""
        for kw in ({}, {"corrupt_kb_sig": True}, {"nonce": "x"}, {"vp_token": {}},
                   {"vp_token": {"pid": []}}, {"vp_token": {"pid": ["not-a-presentation"]}}):
            _, status, _ = self.exchange(**kw)
            self.assertLess(status, 500, "%r produced %d" % (kw, status))

    def test_an_expired_request_cannot_be_answered(self):
        verifier = Verifier(client_cert_pem=_client_chain()[0],
                            client_key_pem=_client_chain()[1],
                            request_uri="https://verifier.test/request.jwt",
                            response_uri="https://verifier.test/response",
                            issuer_jwks=[self.wallet.issuer_jwk],
                            request_ttl_seconds=0)
        _, jar = verifier.new_request()
        form = self.wallet.respond(jar)
        status, body, verdict = verifier.handle_direct_post(form)
        self.assertEqual(status, 400)
        self.assertEqual(body, verifier.REFUSAL_BODY)
        self.assertIn("expired", verdict.reason, "the operator was not told why either")


class TheLastTwoRefusalsTests(VerifierTestCase):
    """Both found by coverage, and one of them only exists under concurrency."""

    def test_a_state_that_does_not_match_its_own_session_is_4xx(self):
        """The response decrypts under our key and then names a different request."""
        _, jar = self.verifier.new_request()
        form = self.wallet.respond(jar, state="some-other-request")
        status, body, _ = self.verifier.handle_direct_post(form)
        self.assertEqual(status, 400)
        self.assertEqual(body, self.verifier.REFUSAL_BODY)

    def test_two_threads_racing_the_same_response_leave_exactly_one_winner(self):
        """The `answered` flag guards a window that a SEQUENTIAL replay never reaches.

        Once a request is answered its session is removed, so a second POST fails to decrypt
        and never gets near the flag. The flag exists for the case where both requests read
        the outstanding session BEFORE either removed it, and a plain pair of threads does
        not reliably produce that: the first often finishes inside one scheduler slice, the
        second then takes the decrypt path, and the test passes while the branch it claims
        to exercise is never entered. Coverage said so.

        So the window is held open deliberately: both threads are made to sit inside
        `decrypt_response`, after the snapshot and before the lock, until both have arrived.
        The refusal is then asserted BY NAME, because "one of them got a 400" is true of the
        wrong reason too.
        """
        import threading

        from polaris_oid4vp import verifier as verifier_module

        _, jar = self.verifier.new_request()
        form = self.wallet.respond(jar)
        results = []
        inside = threading.Barrier(2, timeout=10)
        real_decrypt = verifier_module.decrypt_response

        def decrypt_then_wait(token, key):
            body = real_decrypt(token, key)
            inside.wait()
            return body

        def race():
            results.append(self.verifier.handle_direct_post(form))

        verifier_module.decrypt_response = decrypt_then_wait
        try:
            threads = [threading.Thread(target=race) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=15)
        finally:
            verifier_module.decrypt_response = real_decrypt

        statuses = sorted(status for status, _, _ in results)
        self.assertEqual(statuses, [200, 400],
                         "one presentation was accepted twice: %r" % statuses)
        loser = [v for status, _, v in results if status == 400][0]
        self.assertIn("already been answered", loser.reason)



class HeldOutTransportTests(VerifierTestCase):
    """2026-09-23: a held-out round of ten mutations of this module, written after its drill
    was green. Four survived, and three of them were masked by a different refusal: the
    two-credential test sent presentations that were not genuine, so the verification refused
    them and the one-presentation rule could be deleted; the sequential replay was refused by
    the `answered` flag once the session was no longer removed; and the only lifetime test
    used a lifetime of zero, which doubling does not change. Each test here makes every other
    check pass, so only the mechanism named can refuse."""

    def _genuine(self):
        """A genuine presentation for a request, extracted from the wallet's own response."""
        _, jar = self.verifier.new_request()
        _, claims = self.wallet.read_request(jar)
        return jar, self.wallet._presentation(
            nonce=claims["nonce"], audience=claims["client_id"], iat=None, sd_hash=None,
            corrupt_issuer_sig=False, corrupt_kb_sig=False, extra_disclosure=None, vct=None,
            status=None)

    def test_a_genuine_presentation_beside_a_second_credential_is_refused_for_that(self):
        jar, genuine = self._genuine()
        form = self.wallet.respond(jar, vp_token={"pid": [genuine], "other": [genuine]})
        status, body, verdict = self.verifier.handle_direct_post(form)
        self.assertEqual((status, body), (400, self.verifier.REFUSAL_BODY))
        self.assertIn("not one presentation", verdict.reason)

    def test_two_genuine_presentations_for_one_credential_are_refused_for_that(self):
        jar, genuine = self._genuine()
        form = self.wallet.respond(jar, vp_token={"pid": [genuine, genuine]})
        status, _, verdict = self.verifier.handle_direct_post(form)
        self.assertEqual(status, 400)
        self.assertIn("not one presentation", verdict.reason)

    def test_a_genuine_presentation_under_an_id_the_query_did_not_use_is_refused(self):
        """OpenID4VP 1.0 section 8.1 keys vp_token by the DCQL credential query id."""
        jar, genuine = self._genuine()
        form = self.wallet.respond(jar, vp_token={"not-pid": [genuine]})
        status, body, verdict = self.verifier.handle_direct_post(form)
        self.assertEqual((status, body), (400, self.verifier.REFUSAL_BODY))
        self.assertIn("not one presentation", verdict.reason)

    def test_one_genuine_presentation_is_accepted_through_the_same_path(self):
        """The positive control for the two above."""
        jar, genuine = self._genuine()
        form = self.wallet.respond(jar, vp_token={"pid": [genuine]})
        self.assertEqual(self.verifier.handle_direct_post(form)[0], 200)

    def test_an_answered_request_is_forgotten_not_merely_flagged(self):
        session, jar = self.verifier.new_request()
        form = self.wallet.respond(jar)
        self.assertEqual(self.verifier.handle_direct_post(form)[0], 200)
        self.assertNotIn(session.state, self.verifier._sessions)
        self.assertNotIn(session.state, self.verifier._by_request)
        _, _, replay = self.verifier.handle_direct_post(form)
        self.assertIn("did not decrypt", replay.reason,
                      "a sequential replay finds no session at all; the answered flag is "
                      "for the concurrent case")

    def test_a_request_expires_at_its_lifetime_not_later(self):
        from unittest import mock
        from polaris_oid4vp import verifier as verifier_module
        verifier = Verifier(client_cert_pem=_client_chain()[0],
                            client_key_pem=_client_chain()[1],
                            request_uri="https://verifier.test/request.jwt",
                            response_uri="https://verifier.test/response",
                            issuer_jwks=[self.wallet.issuer_jwk], request_ttl_seconds=100)
        t0 = time.time()
        with mock.patch.object(verifier_module.time, "time", return_value=t0):
            _, jar = verifier.new_request()
        form = self.wallet.respond(jar)
        with mock.patch.object(verifier_module.time, "time", return_value=t0 + 101):
            status, _, verdict = verifier.handle_direct_post(form)
        self.assertEqual(status, 400)
        self.assertIn("expired", verdict.reason)
        with mock.patch.object(verifier_module.time, "time", return_value=t0):
            _, jar = verifier.new_request()
        with mock.patch.object(verifier_module.time, "time", return_value=t0 + 99):
            self.assertEqual(verifier.handle_direct_post(self.wallet.respond(jar))[0], 200)

if __name__ == "__main__":
    unittest.main(verbosity=2)


class TheWireTellsAnAttackerNothingTests(VerifierTestCase):
    """Every refusal looks identical from outside. The reason reaches the operator only.

    The first version of this verifier put the refusal code and its explanation in
    `error_description`, justified as debuggability for the wallet. That serves a
    cooperative wallet and hands an attacker a per-check oracle: probe once, be told which
    check failed, work on that one. Three of the messages leaked more than the code. The
    audience refusal echoed this verifier's own client_id. The freshness refusal named the
    acceptance window in seconds. The decrypt refusal enumerated its causes, disclosing that
    outstanding-request state and an expiry exist.
    """

    CAUSES = {
        "issuer_signature": {"corrupt_issuer_sig": True},
        "kb_signature": {"corrupt_kb_sig": True},
        "nonce": {"nonce": "a-nonce-nobody-asked-for"},
        "audience": {"audience": "x509_hash:somebody-else"},
        "kb_freshness": {"iat": 1},
        "sd_hash": {"sd_hash": "A" * 43},
        "disclosure": {"extra_disclosure": "WyJzOSIsImlzX2FkbWluIix0cnVlXQ"},
    }

    def test_every_refusal_is_byte_identical_on_the_wire(self):
        seen = {}
        for label, kw in self.CAUSES.items():
            _, jar = self.verifier.new_request()
            status, body, verdict = self.verifier.handle_direct_post(
                self.wallet.respond(jar, **kw))
            self.assertEqual(status, 400, label)
            seen[label] = json.dumps(body, sort_keys=True)
            self.assertEqual(verdict.code, label, "the operator got the wrong reason")
        distinct = set(seen.values())
        self.assertEqual(len(distinct), 1,
                         "the wire distinguishes %d causes: %s" % (len(distinct), seen))

    def test_the_wire_never_carries_a_refusal_code_or_a_number(self):
        """No code, and no figure an attacker could read a threshold or a count out of."""
        for label, kw in self.CAUSES.items():
            _, jar = self.verifier.new_request()
            _, body, _ = self.verifier.handle_direct_post(self.wallet.respond(jar, **kw))
            wire = json.dumps(body)
            for code in self.CAUSES:
                self.assertNotIn(code, wire, "%s leaks the code %r" % (label, code))
            self.assertFalse(any(ch.isdigit() for ch in wire),
                             "%s puts a number on the wire: %s" % (label, wire))

    def test_the_wire_does_not_echo_anything_the_caller_supplied(self):
        """Echoing input back is how the audience refusal used to leak two identifiers."""
        marker = "x509_hash:MARKER-SUPPLIED-BY-THE-CALLER"
        _, jar = self.verifier.new_request()
        _, body, _ = self.verifier.handle_direct_post(
            self.wallet.respond(jar, audience=marker))
        self.assertNotIn("MARKER", json.dumps(body))
        self.assertNotIn(self.verifier.client_id, json.dumps(body),
                         "the refusal echoes this verifier's own client_id")

    def test_a_crash_is_not_distinguishable_from_a_refusal(self):
        """Finding an input that crashes the verifier is the most interesting thing an
        attacker could learn from probing it, so it must look like everything else."""
        _, jar = self.verifier.new_request()
        _, good_body, _ = self.verifier.handle_direct_post(
            self.wallet.respond(jar, nonce="wrong"))
        self.assertEqual(good_body, self.verifier.REFUSAL_BODY)


class CredentialTypeOnTheWireTests(VerifierTestCase):
    """The DCQL query carries `vct_values` and `handle_direct_post` has to pass it on.

    `test_sdjwt.py` proves `verify_presentation` compares the type when it is given one.
    That is not the same as proving this class gives it one, and until 2026-09-17 it did
    not: the query asked for a personal identification credential and any credential the
    same issuer signed was accepted. Removing the argument from `verifier.py` passed every
    test in the package, because nothing exercised the wiring.
    """

    def test_a_credential_of_another_type_is_refused_through_the_network_path(self):
        _, jar = self.verifier.new_request()
        form = self.wallet.respond(jar, vct="https://attacker.example/loyalty-card")
        status, body, verdict = self.verifier.handle_direct_post(form)
        self.assertEqual(status, 400,
                         "the query asked for %r and this is a loyalty card"
                         % self.verifier.vct_values)
        self.assertEqual(body, self.verifier.REFUSAL_BODY)
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.code, "vct")

    def test_the_type_the_query_asked_for_is_still_accepted(self):
        """The positive control: a verifier refusing every type would pass the test above
        while accepting nothing at all."""
        _, jar = self.verifier.new_request()
        form = self.wallet.respond(jar)
        status, _, verdict = self.verifier.handle_direct_post(form)
        self.assertEqual(status, 200, verdict.reason if verdict else "")


class HeldOutRequestTests(VerifierTestCase):
    """A held-out round on 2026-09-24: of twelve mutations of verifier.py, three survived.
    Each is a property of what the verifier ASKS for or where it sends the wallet, and every
    test of the request had read the claims the suite checks and not these."""

    def test_the_request_expires_after_the_configured_lifetime_not_later(self):
        """`exp` is the wallet's deadline for this request. Ten times the TTL survived: the
        verifier's own expiry is enforced on its side, so nothing read the one it tells the
        wallet, and a wallet honouring it would answer after the session is gone."""
        _, jar = self.verifier.new_request()
        _, claims = Wallet.read_request(jar)
        self.assertEqual(claims["exp"] - claims["iat"], self.verifier.request_ttl_seconds)

    def test_the_query_asks_for_every_configured_claim(self):
        """Asking for only the first survived, because the test wallet discloses everything
        it has whatever the query says. A real wallet discloses what is asked."""
        cert_pem, key_pem = _client_chain()
        verifier = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                            request_uri="https://verifier.test/request.jwt",
                            response_uri="https://verifier.test/response",
                            claims=("given_name", "family_name", "birthdate"))
        _, jar = verifier.new_request()
        _, claims = Wallet.read_request(jar)
        (credential,) = claims["dcql_query"]["credentials"]
        self.assertEqual([c["path"] for c in credential["claims"]],
                         [["given_name"], ["family_name"], ["birthdate"]])

    def test_the_default_redirect_is_beside_the_response_uri_not_under_it(self):
        cert_pem, key_pem = _client_chain()
        verifier = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                            request_uri="https://v.test/oid4vp/request.jwt",
                            response_uri="https://v.test/oid4vp/response")
        self.assertEqual(verifier.redirect_uri, "https://v.test/oid4vp/done")
        explicit = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                            request_uri="https://v.test/oid4vp/request.jwt",
                            response_uri="https://v.test/oid4vp/response",
                            redirect_uri="https://app.test/finished")
        self.assertEqual(explicit.redirect_uri, "https://app.test/finished")

    def test_an_authentic_answer_carries_the_redirect_and_nothing_else(self):
        _, status, body = self.exchange()
        self.assertEqual(status, 200)
        assert_redirect_with_code(self, body, "https://verifier.test/done")


class TheRedirectCarriesAResponseCodeTests(VerifierTestCase):
    """OpenID4VP 1.0 section 8.2: a redirect URI "MUST include a fresh, cryptographically random
    value", so that "only the receiver of the redirect can fetch and process the Authorization
    Response". Until 2026-10-14 every accepted response got the same fixed URI."""

    def accept(self):
        session, jar = self.verifier.new_request()
        status, body, verdict = self.verifier.handle_direct_post(self.wallet.respond(jar))
        self.assertEqual(status, 200, verdict.reason)
        return session, assert_redirect_with_code(self, body, self.verifier.redirect_uri), verdict

    def test_two_accepted_responses_get_different_redirects(self):
        _, first, _ = self.accept()
        _, second, _ = self.accept()
        self.assertNotEqual(first, second)

    def test_the_code_fetches_its_own_result_once(self):
        session, code, verdict = self.accept()
        self.assertEqual(verdict.response_code, code)
        fetched = self.verifier.redeem(code, state=session.state)
        self.assertIs(fetched, verdict)
        self.assertTrue(fetched.authentic)
        self.assertEqual(fetched.claims["given_name"], "Jean")
        self.assertIsNone(self.verifier.redeem(code, state=session.state), "a reused code fetched again")

    def test_a_wrong_code_fetches_nothing_and_spends_nothing(self):
        session, code, verdict = self.accept()
        wrong = code[:-1] + ("A" if code[-1] != "A" else "B")
        self.assertIsNone(self.verifier.redeem(wrong, state=session.state))
        self.assertIsNone(self.verifier.redeem("", state=session.state))
        self.assertIs(self.verifier.redeem(code, state=session.state), verdict)

    def test_a_code_fetches_nothing_for_another_request(self):
        first, _, _ = self.accept()
        second, second_code, second_verdict = self.accept()
        self.assertIsNone(self.verifier.redeem(second_code, state=first.state))
        self.assertIs(self.verifier.redeem(second_code, state=second.state), second_verdict)

    def test_an_expired_code_fetches_nothing(self):
        session, code, _ = self.accept()
        for key, (when, state, verdict) in list(self.verifier._results.items()):
            self.verifier._results[key] = (when - self.verifier.request_ttl_seconds - 1, state,
                                           verdict)
        self.assertIsNone(self.verifier.redeem(code, state=session.state))

    def test_only_strings_are_redeemed(self):
        session, code, _ = self.accept()
        for given, state in ((None, session.state), (code.encode(), session.state), (code, 7)):
            self.assertIsNone(self.verifier.redeem(given, state=state))

    def test_a_refusal_and_a_wallet_error_issue_no_code(self):
        _, status, body = self.exchange(corrupt_issuer_sig=True)
        self.assertEqual((status, body), (400, Verifier.REFUSAL_BODY))
        _, jar = self.verifier.new_request()
        status, body, verdict = self.verifier.handle_direct_post(self.wallet.respond_error(jar))
        self.assertEqual((status, body), (200, {}))
        self.assertIsNone(verdict.response_code)
        self.assertEqual(self.verifier._results, {})

    def test_without_a_state_the_code_alone_fetches_it_once(self):
        _, code, verdict = self.accept()
        self.assertIs(self.verifier.redeem(code), verdict)
        self.assertIsNone(self.verifier.redeem(code))

    def test_redirect_false_answers_an_empty_object_and_issues_no_code(self):
        cert_pem, key_pem = _client_chain()
        quiet = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                         request_uri="https://verifier.test/request.jwt",
                         response_uri="https://verifier.test/response",
                         issuer_jwks=[self.wallet.issuer_jwk], redirect=False)
        _, jar = quiet.new_request()
        status, body, verdict = quiet.handle_direct_post(self.wallet.respond(jar))
        self.assertEqual((status, body), (200, {}), verdict.reason)
        self.assertTrue(verdict.authentic)
        self.assertIsNone(verdict.response_code)
        self.assertEqual(quiet._results, {})

    def test_the_code_stays_out_of_as_dict(self):
        _, code, verdict = self.accept()
        self.assertNotIn(code, json.dumps(verdict.as_dict()))


class TheResponsePathReturnsRatherThanRaisesTests(VerifierTestCase):
    """`handle_direct_post` is documented to return, never to raise ("Nothing returns 500").

    `serve` catches whatever escapes it, so the bundled server answered 400 regardless. A
    relying party that puts `Verifier` behind its own server has no such net, and these two
    responses escaped as TypeError until 2026-09-28: one from a wallet holding any genuine
    credential, one from anybody able to POST.
    """

    def test_a_disclosure_named_by_an_array_is_answered_400(self):
        junk = b64u_encode(json.dumps(["salt", ["iss"], 1]).encode())
        try:
            _, status, body = self.exchange(extra_disclosure=junk)
        except TypeError as exc:
            self.fail("handle_direct_post raised %r" % exc)
        self.assertEqual(status, 400)
        self.assertEqual(body, Verifier.REFUSAL_BODY)

    def test_an_enc_of_the_wrong_json_type_is_answered_400(self):
        _, jar = self.verifier.new_request()
        parts = self.wallet.respond(jar)["response"][0].split(".")
        header = json.loads(b64u_decode(parts[0]))
        header["enc"] = ["A128GCM"]
        parts[0] = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
        try:
            status, body, _ = self.verifier.handle_direct_post({"response": [".".join(parts)]})
        except TypeError as exc:
            self.fail("handle_direct_post raised %r" % exc)
        self.assertEqual(status, 400)
        self.assertEqual(body, Verifier.REFUSAL_BODY)


# ------------------------------------------------------------- the wallet's error response


class AWalletsErrorResponseTests(VerifierTestCase):
    """OpenID4VP 1.0 section 8.2: "If the Response URI has successfully processed the
    Authorization Response or Authorization Error Response, it MUST respond with an HTTP status
    code of 200 with Content-Type of application/json and a JSON object in the response body."
    Until 2026-10-11 an error response got 400, encrypted or in the clear (measured on
    1.0.0rc18, lab/interop/response-uri-statuses/). Processed means its state names an
    outstanding request. It is answered `{}`, is never authentic, carries no claims, is recorded
    in `verdict.wallet_error`, and in neither form closes the request. The tests marked THREAT
    MODEL are the attacks the design was held to."""

    def _record(self, form):
        """Post `form`; it must be processed as an error response. Returns the verdict."""
        status, body, verdict = self.verifier.handle_direct_post(form)
        self.assertEqual((status, body), (200, {}), verdict.reason if verdict else None)
        self.assertFalse(verdict.authentic)
        self.assertEqual((verdict.code, verdict.claims), ("wallet_error", {}))
        return verdict

    def _genuine(self, jar):
        _, claims = self.wallet.read_request(jar)
        return self.wallet._presentation(
            nonce=claims["nonce"], audience=claims["client_id"], iat=None, sd_hash=None,
            corrupt_issuer_sig=False, corrupt_kb_sig=False, extra_disclosure=None)

    def test_an_encrypted_error_is_answered_200_and_accepts_nothing(self):
        session, jar = self.verifier.new_request()
        verdict = self._record(self.wallet.respond_error(
            jar, extra={"error_description": "The holder declined"}))
        self.assertEqual(verdict.wallet_error, {
            "error": "access_denied", "error_description": "The holder declined",
            "state": session.state, "encrypted": True})
        self.assertEqual(verdict.as_dict()["wallet_error"], verdict.wallet_error)
        self.assertIn("anyone who saw the request could send, so it does not close the request",
                      verdict.reason)
        self.assertIs(self.verifier._sessions.get(session.state), session)

    def test_an_error_in_the_clear_is_answered_200_and_accepts_nothing(self):
        session, jar = self.verifier.new_request()
        verdict = self._record(self.wallet.respond_error(jar, "vp_formats_not_supported",
                                                         encrypted=False))
        self.assertEqual(verdict.wallet_error, {
            "error": "vp_formats_not_supported", "error_description": None,
            "state": session.state, "encrypted": False})
        self.assertIn("anyone who saw the request could send", verdict.reason)

    def test_a_forged_encrypted_error_does_not_cancel_the_presentation(self):
        """THREAT MODEL. The key a response is encrypted to is in the request object, served to
        anyone with the request_uri: an onlooker fetches it, encrypts error=access_denied to the
        request's own key and posts it before the wallet answers, and again. Encryption says
        nothing about the sender, so the request stays open and takes the genuine presentation;
        once that has answered it, the forgery finds no key to open it."""
        session, jar = self.verifier.new_request()
        served = self.verifier.request_object(session.state)
        forged = Wallet().respond_error(served)
        for _ in range(2):
            self.assertTrue(self._record(forged).wallet_error["encrypted"])
        self.assertIs(self.verifier._sessions.get(session.state), session)
        self.assertFalse(session.answered)
        self.assertEqual(self.verifier.request_object(session.state), jar)
        status, body, verdict = self.verifier.handle_direct_post(self.wallet.respond(jar))
        self.assertEqual(status, 200)
        assert_redirect_with_code(self, body, self.verifier.redirect_uri)
        self.assertTrue(verdict.authentic)
        self.assertEqual(verdict.claims["given_name"], "Jean")
        status, body, verdict = self.verifier.handle_direct_post(forged)
        self.assertEqual((status, body), (400, Verifier.REFUSAL_BODY))
        self.assertIn("did not decrypt", verdict.reason)

    def test_a_forged_error_in_the_clear_does_not_cancel_the_presentation(self):
        """THREAT MODEL. The state is in the request_uri, so in the QR code: an onlooker posts
        error=access_denied&state=... before the wallet answers, and again. The request stays
        open, is served as before, and takes the genuine presentation."""
        session, jar = self.verifier.new_request()
        forged = self.wallet.respond_error(jar, encrypted=False)
        for _ in range(2):
            self.assertFalse(self._record(forged).wallet_error["encrypted"])
        self.assertIs(self.verifier._sessions.get(session.state), session)
        self.assertFalse(session.answered)
        self.assertEqual(self.verifier.request_object(session.state), jar)
        status, body, verdict = self.verifier.handle_direct_post(self.wallet.respond(jar))
        self.assertEqual(status, 200)
        assert_redirect_with_code(self, body, self.verifier.redirect_uri)
        self.assertTrue(verdict.authentic)
        self.assertEqual(verdict.claims["given_name"], "Jean")
        # Answered now, the request is gone, and the error has nothing to name.
        status, body, verdict = self.verifier.handle_direct_post(forged)
        self.assertEqual((status, body), (400, Verifier.REFUSAL_BODY))
        self.assertIn("names no outstanding request", verdict.reason)

    def test_an_error_naming_no_outstanding_request_is_the_constant_400(self):
        """Section 14.3.2: "checking that the value of the received state parameter corresponds
        to a recent Authorization Request". Without one there is nothing to process, and the
        refusal is the constant one, whatever the cause."""
        session, _ = self.verifier.new_request()
        cases = {
            "an unknown state": {"error": ["access_denied"], "state": ["not-a-request"]},
            "an empty state": {"error": "access_denied", "state": ""},
            "no state": {"error": ["access_denied"]},
            "a state that is not a string": {"error": "access_denied", "state": 7},
            # Unhashable: looked up, it would raise out of a method that promises to return.
            "a state that is an object": {"error": "access_denied", "state": {"a": 1}},
            "the request's state less a character": {"error": ["access_denied"],
                                                     "state": [session.state[:-1]]},
        }
        for label, form in cases.items():
            with self.subTest(label):
                status, body, verdict = self.verifier.handle_direct_post(form)
                self.assertEqual((status, body), (400, Verifier.REFUSAL_BODY))
                self.assertIn("names no outstanding request", verdict.reason)
        self._record({"error": ["access_denied"], "state": [session.state]})

    def test_an_error_for_an_expired_request_is_the_constant_400(self):
        from unittest import mock
        from polaris_oid4vp import verifier as verifier_module
        t0 = time.time()
        with mock.patch.object(verifier_module.time, "time", return_value=t0):
            _, jar = self.verifier.new_request()
        form = self.wallet.respond_error(jar, encrypted=False)
        ttl = self.verifier.request_ttl_seconds
        with mock.patch.object(verifier_module.time, "time", return_value=t0 + ttl - 1):
            self._record(form)
        with mock.patch.object(verifier_module.time, "time", return_value=t0 + ttl + 1):
            status, body, verdict = self.verifier.handle_direct_post(form)
        self.assertEqual((status, body), (400, Verifier.REFUSAL_BODY))
        self.assertIn("names no outstanding request", verdict.reason)

    BAD_CODES = ("", " ", "access_denied ", "access_denied\n", "access\x1b[31mdenied",
                 "acc\u00e8s_refus\u00e9", "x" * 65, "access-denied",
                 # Each of these is RFC 6749 syntax, and each could put another answer's marker
                 # into the operator's line: the counterexample that narrowed the shape.
                 "access denied", "x <- 200 authentic", "!#[]~")

    def test_an_error_that_is_not_an_error_code_is_refused(self):
        """OpenID4VP 1.0 section 8.5 follows RFC 6749, and every code they define is letters and
        underscores. Processed here: 1 to 64 letters, digits or underscores."""
        for encrypted in (True, False):
            codes = self.BAD_CODES + ((7, True, ["access_denied"], {"error": "x"})
                                      if encrypted else ())
            for code in codes:
                with self.subTest(code=code, encrypted=encrypted):
                    _, jar = self.verifier.new_request()
                    status, body, verdict = self.verifier.handle_direct_post(
                        self.wallet.respond_error(jar, code, encrypted=encrypted))
                    self.assertEqual((status, body), (400, Verifier.REFUSAL_BODY))
                    self.assertFalse(verdict.authentic)
                    # A blank form value is no value, so that form is no error response at all.
                    self.assertIn("no 'response' parameter" if code == "" and not encrypted
                                  else "is not an error code", verdict.reason)
        session, _ = self.verifier.new_request()
        status, _, verdict = self.verifier.handle_direct_post({"error": 7, "state": session.state})
        self.assertEqual(status, 400)
        self.assertIn("is not an error code", verdict.reason)
        # The boundary, both ways: 64 characters, capitals, digits.
        for code in ("x" * 64, "Access_Denied", "a1_"):
            for encrypted in (True, False):
                with self.subTest(code=code, encrypted=encrypted):
                    _, jar = self.verifier.new_request()
                    verdict = self._record(self.wallet.respond_error(jar, code,
                                                                     encrypted=encrypted))
                    self.assertEqual(verdict.wallet_error["error"], code)

    def test_an_error_beside_a_presentation_is_never_accepted(self):
        """THREAT MODEL. A response that says both no and yes, as no wallet would, is refused
        whichever half is genuine. In either form it changes nothing, and the genuine
        presentation alone still gets through."""
        session, jar = self.verifier.new_request()
        status, body, verdict = self.verifier.handle_direct_post(self.wallet.respond_error(
            jar, extra={"vp_token": {"pid": [self._genuine(jar)]}}))
        self.assertEqual((status, body), (400, Verifier.REFUSAL_BODY))
        self.assertFalse(verdict.authentic)
        self.assertIn("both an error and a vp_token", verdict.reason)
        self.assertIs(self.verifier._sessions.get(session.state), session)
        status, _, verdict = self.verifier.handle_direct_post(self.wallet.respond(jar))
        self.assertEqual(status, 200)
        self.assertTrue(verdict.authentic)

        session, jar = self.verifier.new_request()
        presentation = self.wallet.respond(jar)["response"][0]
        for label, extra in (("response", {"response": presentation}),
                             ("vp_token", {"vp_token": json.dumps(
                                 {"pid": [self._genuine(jar)]})})):
            with self.subTest(label):
                status, body, verdict = self.verifier.handle_direct_post(
                    self.wallet.respond_error(jar, encrypted=False, extra=extra))
                self.assertEqual((status, body), (400, Verifier.REFUSAL_BODY))
                self.assertIn("both an error and a presentation", verdict.reason)
        self.assertIs(self.verifier._sessions.get(session.state), session)
        status, _, verdict = self.verifier.handle_direct_post({"response": [presentation]})
        self.assertEqual(status, 200)
        self.assertTrue(verdict.authentic)

        # JSON null is no value: an error beside a null vp_token is an error, and a null error
        # beside a genuine presentation is a presentation.
        _, jar = self.verifier.new_request()
        self._record(self.wallet.respond_error(jar, extra={"vp_token": None}))
        _, jar = self.verifier.new_request()
        status, _, verdict = self.verifier.handle_direct_post(self.wallet.respond_error(
            jar, None, extra={"vp_token": {"pid": [self._genuine(jar)]}}))
        self.assertEqual(status, 200)
        self.assertTrue(verdict.authentic)

    def test_a_repeated_parameter_is_refused(self):
        """RFC 6749 section 3.1: "Request and response parameters MUST NOT be included more than
        once." Which of two states, or two codes, would be the answer?"""
        session, jar = self.verifier.new_request()
        other, _ = self.verifier.new_request()
        for label, extra in (("two codes", {"error": ["access_denied", "invalid_request"]}),
                             ("two states", {"state": [session.state, other.state]}),
                             ("two descriptions", {"error_description": ["one", "two"]})):
            with self.subTest(label):
                status, body, verdict = self.verifier.handle_direct_post(
                    self.wallet.respond_error(jar, encrypted=False, extra=extra))
                self.assertEqual((status, body), (400, Verifier.REFUSAL_BODY))
                self.assertIn("repeats", verdict.reason)
        verdict = self._record(self.wallet.respond_error(
            jar, encrypted=False, extra={"error_description": ["once"]}))
        self.assertEqual(verdict.wallet_error["error_description"], "once")

    HOSTILE = ("\x1b[2J\x1b[31mACCEPTED\x1b[0m\r\n  <- 200 authentic, claims ['given_name']"
               "\x00\u202e\u00e9\"\\" + "x" * 5000)

    def test_the_description_reaches_the_operator_only_as_printable_ascii(self):
        """THREAT MODEL. error_description is the sender's free text, in the clear from anyone
        who saw the request, and it lands on the operator's terminal and log: an escape sequence
        repaints the terminal, a line break and a `<-` forge another answer's line, and a long
        one floods both. The operator is shown RFC 6749's characters but `<`, cut to 200;
        anything else is `?`."""
        expected = ("?[2J?[31mACCEPTED?[0m??  ?- 200 authentic, claims ['given_name']?????"
                    + "x" * 200)[:197] + "..."
        for encrypted in (True, False):
            with self.subTest(encrypted=encrypted):
                _, jar = self.verifier.new_request()
                verdict = self._record(self.wallet.respond_error(
                    jar, encrypted=encrypted, extra={"error_description": self.HOSTILE}))
                self.assertEqual(verdict.wallet_error["error_description"], expected)
                for ch in ("\x1b", "\r", "\n", "\x00", "\u202e", "<- 200", "x" * 198):
                    self.assertNotIn(ch, verdict.reason)
        # An empty one is none; one that is not a string refuses the response.
        _, jar = self.verifier.new_request()
        verdict = self._record(self.wallet.respond_error(jar, extra={"error_description": ""}))
        self.assertIsNone(verdict.wallet_error["error_description"])
        session, _ = self.verifier.new_request()
        # In a form, a list is the values the parameter was given, so ["x"] is JSON's alone.
        for value, channels in ((5, (True, False)), ({"a": 1}, (True, False)),
                                (True, (True, False)), (["x"], (True,))):
            for encrypted in channels:
                with self.subTest(value=value, encrypted=encrypted):
                    _, jar = self.verifier.new_request()
                    form = (self.wallet.respond_error(jar, extra={"error_description": value})
                            if encrypted else {"error": "access_denied", "state": session.state,
                                               "error_description": value})
                    status, body, verdict = self.verifier.handle_direct_post(form)
                    self.assertEqual((status, body), (400, Verifier.REFUSAL_BODY))
                    self.assertIn("error_description is not a string", verdict.reason)

    def test_the_cut_is_at_200_characters_and_not_before(self):
        from polaris_oid4vp.verifier import ERROR_DESCRIPTION_MAX, _printable
        self.assertEqual(ERROR_DESCRIPTION_MAX, 200)
        self.assertEqual(_printable("x" * 200), "x" * 200)
        self.assertEqual(_printable("x" * 201), "x" * 197 + "...")
        self.assertEqual(_printable(" !#[]~"), " !#[]~")
        self.assertEqual(_printable("\x1f\x7f\"\\<"), "?????")

    def test_the_wire_answers_every_error_with_the_same_empty_object(self):
        """No code, state or description goes back, and no redirect_uri: the page it leads to
        says the presentation is complete."""
        bodies = set()
        for encrypted in (True, False):
            for code, description in (("access_denied", None),
                                      ("invalid_request", "unsupported client_id_prefix"),
                                      ("wallet_unavailable", "x" * 300)):
                _, jar = self.verifier.new_request()
                status, body, _ = self.verifier.handle_direct_post(self.wallet.respond_error(
                    jar, code, encrypted=encrypted,
                    extra={"error_description": description} if description else None))
                self.assertEqual(status, 200)
                bodies.add(json.dumps(body))
        self.assertEqual(bodies, {"{}"})


# ------------------------------------------------------------------- transaction data

from polaris_oid4vp.sdjwt import transaction_data_hash  # noqa: E402
from polaris_oid4vp.verifier import verify_response  # noqa: E402


def _raw(entry):
    return b64u_encode(json.dumps(entry, separators=(",", ":")).encode())


PAYMENT = {"type": "urn:eudi:sca:payment:1", "credential_ids": ["pay"],
           "payload": {"transaction_id": "polaris-test-0001",
                       "payee": {"name": "Example Shop", "id": "DE00EXAMPLE0001"},
                       "currency": "EUR", "amount": 49.99}}
RAW_PAYMENT = _raw(PAYMENT)


def _payment(**payload):
    return dict(PAYMENT, payload=dict(PAYMENT["payload"], **payload))


class _PayVerifier(unittest.TestCase):

    def verifier(self, **kw):
        cert_pem, key_pem = _client_chain()
        self.wallet = Wallet()
        kw.setdefault("credential_query_id", "pay")
        return Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                        request_uri="https://verifier.test/request.jwt",
                        response_uri="https://verifier.test/response",
                        issuer_jwks=[self.wallet.issuer_jwk], **kw)


class TransactionDataRequestTests(_PayVerifier):
    """The request side: the strings carried as given, and an entry a wallet would refuse
    refused here rather than sent (OpenID4VP 1.0 section 5.1, B.3.3.1, TS12 section 4)."""

    def test_a_string_is_carried_byte_for_byte_and_an_object_is_encoded(self):
        v = self.verifier()
        obj = _payment(transaction_id="t-é")
        session, jar = v.new_request(transaction_data=[RAW_PAYMENT, obj])
        sent = Wallet.read_request(jar)[1]["transaction_data"]
        self.assertEqual(sent[0], RAW_PAYMENT)
        self.assertEqual(b64u_decode(sent[1]), json.dumps(
            obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        again = Wallet.read_request(v.request_object(session.state, wallet_nonce="w-1"))[1]
        self.assertEqual(again["transaction_data"], sent, "a re-minted object changed the strings")

    def test_the_credential_query_is_the_one_named(self):
        _, jar = self.verifier().new_request()
        self.assertEqual(Wallet.read_request(jar)[1]["dcql_query"]["credentials"][0]["id"], "pay")
        for bad in ("", "pay me", "pay.1", 7, "päy"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.verifier(credential_query_id=bad)
        with self.assertRaises(ValueError):
            self.verifier(verifier_info=[{"format": "f", "data": "x", "credential_ids": ["pid"]}])

    def test_entries_a_wallet_would_refuse_are_refused_at_construction(self):
        """Each for its own reason: the operator reads the sentence, and a refusal that fires for
        another check's reason hides that its own check is gone (found by mutation: the entry
        allowing no algorithm this computes was also caught, unnamed, by the shared-algorithm
        check)."""
        v = self.verifier()
        cases = {
            "an empty list": ([], "a non-empty JSON array"),
            "not a list": (RAW_PAYMENT, "a non-empty JSON array"),
            "a number": ([5], "entry 0 is a JSON int"),
            "not base64url": (["%%%"], "entry 0: a transaction_data entry does not decode"),
            "naming a query the request does not make":
                ([_raw(dict(PAYMENT, credential_ids=["pid"]))], "must name this request's"),
            "naming the query twice":
                ([_raw(dict(PAYMENT, credential_ids=["pay", "pay"]))], "each once"),
            "a bare-string algorithm":
                ([_raw(dict(PAYMENT, transaction_data_hashes_alg="sha-256"))], "not a bare string"),
            "only algorithms this cannot compute":
                ([_raw(dict(PAYMENT, transaction_data_hashes_alg=["sha3-256"]))],
                 "entry 0 allows sha3-256, none of which this verifier computes"),
            "a TS12 type without a payload":
                ([_raw({"type": "urn:eudi:sca:login_risk_transaction:1", "credential_ids": ["pay"]})],
                 "carries no payload object (TS12 section 4.2)"),
            "entries sharing no algorithm":
                ([_raw(dict(PAYMENT, transaction_data_hashes_alg=["sha-384"])),
                  _raw(dict(_payment(transaction_id="t-2"), transaction_data_hashes_alg=["sha-512"]))],
                 "share no hash algorithm"),
        }
        for label, (entries, reason) in cases.items():
            with self.subTest(label), self.assertRaises(ValueError) as caught:
                v.new_request(transaction_data=entries)
            self.assertIn(reason, str(caught.exception), label)
        self.assertEqual(v._sessions, {}, "a refused request left a session behind")

    def test_a_ts12_payment_must_satisfy_ts12s_own_schema(self):
        v = self.verifier()
        p = PAYMENT["payload"]
        bad = {
            "an amount written as a string": dict(p, amount="49.99"),
            "a boolean amount": dict(p, amount=True),
            "a payee without its id": dict(p, payee={"name": "Example Shop"}),
            "no currency": {k: x for k, x in p.items() if k != "currency"},
            "a lower-case currency": dict(p, currency="eur"),
            "a currency ending in a newline": dict(p, currency="EUR\n"),
            "a 37-character transaction_id": dict(p, transaction_id="x" * 37),
            "an empty transaction_id": dict(p, transaction_id=""),
            "a member the schema does not have": dict(p, note="hi"),
            "a recurrence without a frequency": dict(p, recurrence={"number": 3}),
            "a frequency ISO 20022 does not list": dict(p, recurrence={"frequency": "DAILY"}),
            "a fractional number of payments": dict(p, recurrence={"frequency": "MNTH", "number": 1.5}),
            "a PISP without its brand": dict(p, pisp={"legal_name": "P", "domain_name": "p.example"}),
            "a payload that is not an object": [p],
        }
        for label, payload in bad.items():
            with self.subTest(label), self.assertRaises(ValueError) as caught:
                v.new_request(transaction_data=[dict(PAYMENT, payload=payload)])
            self.assertIn("TS12", str(caught.exception))
        full = dict(p, date_time="2026-10-10T12:00:00+00:00",
                    payee=dict(p["payee"], logo="https://shop.example/logo.png",
                               website="https://shop.example"),
                    pisp={"legal_name": "Pay Initiation AB", "brand_name": "PayInit",
                          "domain_name": "payinit.example"},
                    amount=-5, amount_estimated=False, amount_earmarked=True, sct_inst=True,
                    recurrence={"start_date": "2026-11-01T00:00:00+00:00",
                                "end_date": "2027-10-01T00:00:00+00:00", "number": 12.0,
                                "frequency": "MNTH",
                                "mit_options": {"amount_variable": True, "min_amount": 1,
                                                "max_amount": 100.5, "total_amount": 500,
                                                "initial_amount": 5, "initial_amount_number": 1,
                                                "apr": 3.5, "beyond": "nested objects may"}})
        session, _ = v.new_request(transaction_data=[dict(PAYMENT, payload=full)])
        self.assertEqual(len(session.transaction_data), 1)

    def test_another_type_is_carried_without_a_schema(self):
        v = self.verifier()
        for entry in ({"type": "example_type", "credential_ids": ["pay"]},
                      {"type": "urn:eudi:sca:login_risk_transaction:1", "credential_ids": ["pay"],
                       "payload": {"anything": "goes"}}):
            with self.subTest(entry["type"]):
                session, _ = v.new_request(transaction_data=[entry])
                self.assertEqual(session.transaction_data[0].type, entry["type"])


class TransactionDataOnTheWireTests(_PayVerifier):
    """A request carrying a TS12 payment, answered by a wallet that binds it as TS12 says."""

    def setUp(self):
        self.v = self.verifier()

    def exchange(self, kb=None, entries=(RAW_PAYMENT,)):
        _, jar = self.v.new_request(transaction_data=list(entries))
        return self.v.handle_direct_post(self.wallet.respond(jar, kb=kb))

    def test_a_presentation_that_binds_the_payment_is_answered_200(self):
        status, body, verdict = self.exchange()
        self.assertEqual(status, 200, verdict.reason)
        assert_redirect_with_code(self, body, self.v.redirect_uri)
        report = verdict.transaction_data
        self.assertEqual((report["credential"], report["expected"], report["alg"], report["ts12"]),
                         ("pay", [0], "sha-256", True))
        self.assertTrue(report["readings_agree"], "one credential: both readings expect it all")

    def test_two_entries_are_bound_in_the_requests_order(self):
        status, _, verdict = self.exchange(entries=(RAW_PAYMENT, _raw(_payment(transaction_id="t-2"))))
        self.assertEqual(status, 200, verdict.reason)
        self.assertEqual(verdict.transaction_data["expected"], [0, 1])

    CAUSES = {
        "transaction_data_missing": {"transaction_data_hashes": DROP},
        "transaction_data_extra": {"transaction_data_hashes": [transaction_data_hash(RAW_PAYMENT)] * 2},
        "transaction_data_mismatch": {"transaction_data_hashes": [
            b64u_encode(hashlib.sha256(b64u_decode(RAW_PAYMENT)).digest())]},
        "transaction_data_alg": {"transaction_data_hashes_alg": ["sha-256"]},
        "ts12_jti": {"jti": DROP},
        "ts12_response_mode": {"response_mode": "direct_post"},
        "ts12_amr": {"amr": [{"knowledge": "pattern"}]},
    }

    def test_every_refusal_reaches_the_wire_as_the_one_constant_400(self):
        for code, kb in self.CAUSES.items():
            with self.subTest(code):
                status, body, verdict = self.exchange(kb=kb)
                self.assertEqual((status, body, verdict.code), (400, Verifier.REFUSAL_BODY, code))

    def test_a_jti_answers_once_across_requests(self):
        self.assertEqual(self.exchange(kb={"jti": "one-and-the-same"})[0], 200)
        status, _, verdict = self.exchange(kb={"jti": "one-and-the-same"})
        self.assertEqual((status, verdict.code), (400, "ts12_jti"))

    def test_a_presentation_under_another_query_id_is_refused(self):
        _, jar = self.v.new_request(transaction_data=[RAW_PAYMENT])
        claims = Wallet.read_request(jar)[1]
        genuine = self.wallet._presentation(
            nonce=claims["nonce"], audience=claims["client_id"], iat=None, sd_hash=None,
            corrupt_issuer_sig=False, corrupt_kb_sig=False, extra_disclosure=None,
            kb_extra=Wallet.binding_claims(claims))
        status, _, verdict = self.v.handle_direct_post(
            self.wallet.respond(jar, vp_token={"pid": [genuine]}))
        self.assertEqual(status, 400)
        self.assertIn("not one presentation", verdict.reason)


class WithoutTransactionDataTheRequestIsAsBeforeTests(VerifierTestCase):
    """Non-regression, on the wire: a request that carries no transaction_data is the request it
    always was, and the key binding JWT's transaction claims are not read."""

    BEFORE = {"iss", "aud", "client_id", "response_type", "response_mode", "response_uri",
              "nonce", "state", "iat", "exp", "client_metadata", "dcql_query"}

    def test_the_request_object_carries_what_it_always_did(self):
        session, jar = self.verifier.new_request()
        self.assertEqual(set(Wallet.read_request(jar)[1]), self.BEFORE)
        self.assertEqual(session.transaction_data, ())
        self.assertEqual(Wallet.read_request(jar)[1]["dcql_query"]["credentials"][0]["id"], "pid")

    def test_stray_transaction_claims_change_nothing(self):
        stray = {"transaction_data_hashes": ["x"], "transaction_data_hashes_alg": ["y"],
                 "amr": "none", "response_mode": "fragment"}
        for kb in (None, stray):
            with self.subTest(kb=kb):
                _, jar = self.verifier.new_request()
                status, body, verdict = self.verifier.handle_direct_post(
                    self.wallet.respond(jar, kb=kb))
                self.assertEqual(status, 200)
                assert_redirect_with_code(self, body, self.verifier.redirect_uri)
                self.assertIsNone(verdict.transaction_data)
                self.assertNotIn("transaction_data", verdict.as_dict())
                self.assertEqual(set(verdict.as_dict()), set(sdjwt.Verdict(True).as_dict()))


VECTOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata",
                      "transaction-data-two-credentials.json")


class TwoCredentialVectorTests(unittest.TestCase):
    """B8, measured: two credential queries, pid and pay, and one TS12 payment naming pay. The
    vector was written by lab/interop/transaction-data/two_credentials.py with its own code."""

    @classmethod
    def setUpClass(cls):
        with open(VECTOR, encoding="utf-8") as fh:
            cls.v = json.load(fh)

    def judge(self, response, scope, now=None):
        return verify_response(self.v["request"], self.v["responses"][response]["vp_token"],
                               transaction_data_scope=scope, issuer_jwks=self.v["issuer_jwks"],
                               now=self.v["at"] if now is None else now)

    def test_the_hash_is_of_the_string_as_sent(self):
        raw = self.v["request"]["transaction_data"][0]
        # OpenSSL, not Python: printf %s RAW | openssl dgst -sha256 -binary | base64url
        self.assertEqual(self.v["transaction_data_hashes"]["sha-256"],
                         ["yUmPIT-FIjqquKu1XOi1cf8HieQ3BU1Mw8dvLPm6ppU"])
        self.assertEqual(transaction_data_hash(raw), "yUmPIT-FIjqquKu1XOi1cf8HieQ3BU1Mw8dvLPm6ppU")

    def test_what_each_key_binding_jwt_must_carry_under_each_reading(self):
        expected = self.judge("per_credential", None)["expected"]
        self.assertEqual(expected, {"per_credential": {"pid": [], "pay": [0]},
                                    "all_entries": {"pid": [0], "pay": [0]}})
        hashes = self.v["transaction_data_hashes"]["sha-256"]
        for reading, by_query in self.v["must_carry"].items():
            for qid, carried in by_query.items():
                with self.subTest(reading=reading, credential=qid):
                    self.assertEqual(carried.get("transaction_data_hashes", []),
                                     [hashes[i] for i in expected[reading][qid]])

    def test_each_response_passes_its_own_reading_and_fails_the_other(self):
        for response, outcomes in self.v["outcomes"].items():
            for scope, outcome in outcomes.items():
                with self.subTest(response=response, scope=scope):
                    result = self.judge(response, scope)
                    self.assertEqual(result["scope"], scope)
                    if outcome == "accepted":
                        self.assertTrue(result["accepted"], result["problem"])
                        self.assertEqual(result["verdicts"]["pay"].transaction_data["expected"], [0])
                        continue
                    _, qid, code = outcome.split()
                    self.assertFalse(result["accepted"])
                    self.assertEqual(result["verdicts"][qid].code, code)
                    self.assertTrue(result["verdicts"]["pay"].authentic,
                                    "the pay presentation is the same under both readings")

    def test_without_a_named_reading_nothing_is_decided(self):
        for response in self.v["responses"]:
            with self.subTest(response=response):
                result = self.judge(response, None)
                self.assertIsNone(result["accepted"])
                self.assertIn("name the transaction_data scope", result["problem"])
                self.assertEqual(set(result["readings"]), {"per_credential", "all_entries"})

    def test_it_goes_stale_as_a_capture_does(self):
        result = self.judge("per_credential", "per_credential", now=self.v["at"] + 365 * 86400)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["verdicts"]["pid"].code, "kb_freshness")


class VerifyResponseTests(unittest.TestCase):
    """verify_response's own refusals: a request nothing can be held to, a vp_token that does not
    answer it, and a request with no transaction_data at all."""

    @classmethod
    def setUpClass(cls):
        with open(VECTOR, encoding="utf-8") as fh:
            cls.v = json.load(fh)

    def test_a_request_nothing_can_be_held_to_is_refused(self):
        """Each for its own reason (found by mutation: the query-id and empty-query refusals could
        go, and the entries' "does not ask for" refusal caught the same requests unnamed)."""
        r = self.v["request"]
        q = r["dcql_query"]["credentials"]
        cases = {
            "not an object": ([r], "the request is a JSON object"),
            "no nonce": ({k: x for k, x in r.items() if k != "nonce"}, "names no nonce or no client_id"),
            "no client_id": (dict(r, client_id=""), "names no nonce or no client_id"),
            "no credentials": (dict(r, dcql_query={"credentials": []}), "has no credentials"),
            "a repeated id": (dict(r, dcql_query={"credentials": [q[0], q[0]]}),
                              "missing, malformed or repeated: 'pid'"),
            "an id DCQL does not allow": (dict(r, dcql_query={"credentials": [dict(q[0], id="p d")]}),
                                          "missing, malformed or repeated: 'p d'"),
            "an mdoc query": (dict(r, dcql_query={"credentials": [dict(q[0], format="mso_mdoc"), q[1]]}),
                              "this verifier checks dc+sd-jwt only"),
            "an entry naming no query": (dict(r, dcql_query={"credentials": [q[0]]}),
                                         "names pay, which the request's dcql_query does not ask for"),
            "an entry that is not one": (dict(r, transaction_data=["%%%"]), "transaction_data entry 0:"),
            "an empty transaction_data": (dict(r, transaction_data=[]), "not a non-empty array"),
            "TS12 without a response_mode": ({k: x for k, x in r.items() if k != "response_mode"},
                                             "names no response_mode"),
        }
        for label, (request, reason) in cases.items():
            with self.subTest(label), self.assertRaises(ValueError) as caught:
                verify_response(request, self.v["responses"]["per_credential"]["vp_token"],
                                issuer_jwks=self.v["issuer_jwks"], now=self.v["at"])
            self.assertIn(reason, str(caught.exception), label)
        with self.assertRaises(ValueError) as caught:
            verify_response(r, {}, transaction_data_scope="both")
        self.assertIn("it is one of per_credential, all_entries", str(caught.exception))

    def test_a_vp_token_that_does_not_answer_the_request_is_not_accepted(self):
        token = self.v["responses"]["per_credential"]["vp_token"]
        for label, bad in (("one credential", {"pay": token["pay"]}),
                           ("one more", dict(token, extra=token["pay"])),
                           ("two for one", dict(token, pay=token["pay"] * 2)),
                           ("not an object", [token])):
            with self.subTest(label):
                result = verify_response(self.v["request"], bad, issuer_jwks=self.v["issuer_jwks"],
                                         now=self.v["at"], transaction_data_scope="per_credential")
                self.assertIs(result["accepted"], False)
                self.assertIn("vp_token", result["problem"])

    def test_without_transaction_data_the_presentations_are_judged_as_they_are(self):
        request = {k: x for k, x in self.v["request"].items() if k != "transaction_data"}
        result = verify_response(request, self.v["responses"]["per_credential"]["vp_token"],
                                 issuer_jwks=self.v["issuer_jwks"], now=self.v["at"])
        self.assertTrue(result["accepted"], result["problem"])
        self.assertEqual((result["readings"], result["expected"], result["scope"]), ({}, {}, None))
        self.assertTrue(all(v.transaction_data is None for v in result["verdicts"].values()))


class _TwoCredentials:
    """Two credentials, pid and pay, from one issuer, each bound to its own holder key, and the
    response a wallet makes with the transaction claims a test chooses. Minted here, with this
    module's own helpers; the hashes with hashlib."""

    QUERIES = ("pid", "pay")
    TWO_FACTORS = [{"knowledge": "pin_6_or_more_digits"}, {"possession": "key_in_local_native_wscd"}]

    def __init__(self, entries):
        self.issuer = ec.generate_private_key(ec.SECP256R1())
        self.holders = {q: ec.generate_private_key(ec.SECP256R1()) for q in self.QUERIES}
        self.at = int(time.time())
        self.request = {
            "client_id": "x509_hash:two-credential-test", "nonce": b64u_encode(os.urandom(24)),
            "response_type": "vp_token", "response_mode": "direct_post.jwt",
            "dcql_query": {"credentials": [{"id": q, "format": "dc+sd-jwt",
                                            "meta": {"vct_values": ["urn:test:" + q]}}
                                           for q in self.QUERIES]},
            "transaction_data": [_raw(e) for e in entries]}
        self.issuer_jwks = [dict(_public_jwk(self.issuer), kid="issuer-1")]

    def _presentation(self, qid, kb_extra):
        disclosure = b64u_encode(json.dumps(["salt-" + qid, "name", "Jean"],
                                            separators=(",", ":")).encode())
        payload = {"iss": "https://issuer.example", "vct": "urn:test:" + qid, "iat": self.at,
                   "_sd": [b64u_encode(hashlib.sha256(disclosure.encode("ascii")).digest())],
                   "cnf": {"jwk": _public_jwk(self.holders[qid])}}
        presented = (_jws(self.issuer, {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "issuer-1"},
                          payload) + "~" + disclosure + "~")
        kb = dict({"iat": self.at, "aud": self.request["client_id"], "nonce": self.request["nonce"],
                   "sd_hash": b64u_encode(hashlib.sha256(presented.encode("ascii")).digest())},
                  **kb_extra)
        return presented + _jws(self.holders[qid], {"alg": "ES256", "typ": "kb+jwt"}, kb)

    def judge(self, binds, scope="per_credential", sca=True):
        """`binds` maps a query id to the positions its key binding JWT hashes, in that order."""
        raws = self.request["transaction_data"]
        token = {}
        for qid in self.QUERIES:
            extra = {}
            if qid in binds:
                extra = {"transaction_data_hashes": [
                    b64u_encode(hashlib.sha256(raws[i].encode("ascii")).digest()) for i in binds[qid]],
                    "transaction_data_hashes_alg": "sha-256"}
                if sca:
                    extra.update(jti=b64u_encode(os.urandom(16)), response_mode="direct_post.jwt",
                                 amr=self.TWO_FACTORS)
            token[qid] = [self._presentation(qid, extra)]
        return verify_response(self.request, token, transaction_data_scope=scope,
                               issuer_jwks=self.issuer_jwks, now=self.at)


class AnEntryNamingTwoPresentedCredentialsTests(unittest.TestCase):
    """OpenID4VP 1.0 section 5.1: "If there is more than one element in the array, the Wallet
    MUST use only one of the referenced Credentials for transaction authorization." Under
    per_credential such an entry is bound by exactly one of them, the wallet's choice."""

    SHARED = {"type": "example_type", "credential_ids": ["pid", "pay"]}

    def test_bound_by_either_one_of_the_two_it_is_accepted(self):
        for chooser, other in (("pay", "pid"), ("pid", "pay")):
            with self.subTest(chooser=chooser):
                result = _TwoCredentials([self.SHARED]).judge({chooser: [0]})
                self.assertTrue(result["accepted"], result["problem"])
                self.assertEqual(result["verdicts"][chooser].transaction_data["bound"], [0])
                self.assertEqual(result["verdicts"][other].transaction_data["bound"], [])
                self.assertEqual(result["either"], {0: ["pid", "pay"]})
                self.assertEqual(result["expected"]["per_credential"], {"pid": [], "pay": []})

    def test_bound_by_both_it_is_refused(self):
        result = _TwoCredentials([self.SHARED]).judge({"pid": [0], "pay": [0]})
        self.assertIs(result["accepted"], False)
        self.assertTrue(result["problem"].startswith("transaction_data_extra"), result["problem"])
        self.assertIn("MUST use only one of the referenced Credentials", result["problem"])
        self.assertTrue(all(v.authentic for v in result["verdicts"].values()),
                        "each presentation alone is authentic; the response is what is wrong")

    def test_bound_by_neither_it_is_refused(self):
        result = _TwoCredentials([self.SHARED]).judge({})
        self.assertIs(result["accepted"], False)
        self.assertTrue(result["problem"].startswith("transaction_data_missing"), result["problem"])
        self.assertIn("no key binding JWT binds it", result["problem"])

    def test_all_entries_still_wants_it_in_both(self):
        both = _TwoCredentials([self.SHARED]).judge({"pid": [0], "pay": [0]}, "all_entries")
        self.assertTrue(both["accepted"], both["problem"])
        one = _TwoCredentials([self.SHARED]).judge({"pay": [0]}, "all_entries")
        self.assertIs(one["accepted"], False)
        self.assertEqual(one["verdicts"]["pid"].code, "transaction_data_missing")

    def test_a_shared_ts12_payment_needs_ts12s_claims_only_where_it_is_bound(self):
        shared = dict(PAYMENT, credential_ids=["pid", "pay"])
        ok = _TwoCredentials([shared]).judge({"pay": [0]})
        self.assertTrue(ok["accepted"], ok["problem"])
        self.assertTrue(ok["verdicts"]["pay"].transaction_data["ts12"])
        self.assertFalse(ok["verdicts"]["pid"].transaction_data["ts12"])
        bare = _TwoCredentials([shared]).judge({"pay": [0]}, sca=False)
        self.assertEqual(bare["verdicts"]["pay"].code, "ts12_jti")

    def test_a_shared_entry_keeps_its_place_in_the_request_order(self):
        entries = [self.SHARED, dict(self.SHARED, credential_ids=["pay"])]
        for binds, accepted in (({"pay": [0, 1]}, True), ({"pid": [0], "pay": [1]}, True),
                                ({"pay": [1, 0]}, False), ({"pay": [1], "pid": [0, 1]}, False)):
            with self.subTest(binds=binds):
                result = _TwoCredentials(entries).judge(binds)
                self.assertIs(result["accepted"], accepted, result["problem"])
