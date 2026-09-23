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
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from polaris_oid4vp.jwe import b64u_decode, b64u_encode, encrypt_compact  # noqa: E402
from polaris_oid4vp.verifier import Verifier  # noqa: E402
from polaris_oid4vp import sdjwt  # noqa: E402


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
                state=None, enc="A128GCM", vp_token=None, vct=None, status=None):
        _, claims = self.read_request(jar)
        enc_jwk = claims["client_metadata"]["jwks"]["keys"][0]
        enc_public = ec.EllipticCurvePublicNumbers(
            int.from_bytes(b64u_decode(enc_jwk["x"]), "big"),
            int.from_bytes(b64u_decode(enc_jwk["y"]), "big"), ec.SECP256R1()).public_key()

        presentation = self._presentation(
            nonce=claims["nonce"] if nonce is None else nonce,
            audience=claims["client_id"] if audience is None else audience,
            iat=iat, sd_hash=sd_hash, corrupt_issuer_sig=corrupt_issuer_sig,
            corrupt_kb_sig=corrupt_kb_sig, extra_disclosure=extra_disclosure, vct=vct,
            status=status)
        body = {"state": claims["state"] if state is None else state,
                "vp_token": {"pid": [presentation]} if vp_token is None else vp_token}
        token = encrypt_compact(json.dumps(body).encode(), enc_public, enc)
        return {"response": [token]}

    def _presentation(self, *, nonce, audience, iat, sd_hash, corrupt_issuer_sig,
                      corrupt_kb_sig, extra_disclosure, vct=None, status=None):
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
        kb = _jws(self.holder_key, {"alg": "ES256", "typ": "kb+jwt"},
                  {"iat": int(time.time()) if iat is None else iat, "aud": audience,
                   "nonce": nonce,
                   "sd_hash": b64u_encode(hashlib.sha256(presented.encode("ascii")).digest())
                   if sd_hash is None else sd_hash})
        if corrupt_kb_sig:
            head, _, sig = kb.rpartition(".")
            raw = bytearray(b64u_decode(sig))
            raw[0] ^= 0xFF
            kb = head + "." + b64u_encode(bytes(raw))
        return presented + kb


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
        self.assertEqual(status, 200)
        self.assertEqual(asked, [("https://issuer.example/sl/1", 5, "https://issuer.example")])
        self.assertTrue(verdict.revocation["checked"])
        self.assertEqual(verdict.revocation["meaning"], "INVALID")

    def test_without_a_resolver_a_named_list_is_not_evaluated(self):
        """The same credential, no resolver: nobody looked, and the verdict says so."""
        v = self._verifier()
        _, jar = v.new_request()
        status, _, verdict = v.handle_direct_post(
            self.wallet.respond(jar, status=self.STATUS))
        self.assertEqual(status, 200)
        self.assertFalse(verdict.revocation["checked"])
        self.assertEqual(verdict.revocation["state"], sdjwt.NOT_EVALUATED)


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
