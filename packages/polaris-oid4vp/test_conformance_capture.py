"""test_conformance_capture.py -- verify something this project did not make.

Every other test in this package builds its own material, which means every other test is
this package agreeing with itself. Two consistent mistakes pass a round trip. This one takes
an encrypted authorization response produced by the **OpenID Foundation conformance suite's
wallet**, captured from a real `oid4vp-1final-verifier-haip-test-plan` run, and asks whether
polaris-oid4vp can open it and verify what is inside.

The fixture is committed rather than fetched, so this runs in CI with no Docker and no
network. `lab/interop/probe.py` is what produced it and is how it would be produced again.

WHAT THIS IS EVIDENCE OF. A JWE built by an independent implementation (Nimbus JOSE, in
Java) decrypts under this package's ECDH-ES and ConcatKDF, and an SD-JWT VC built by that
suite's own code verifies under this package's rules. That is interoperability on the
transport and on the credential, measured rather than asserted.

WHAT IT IS NOT. It is not a conformance result: the suite ran locally, nothing was scored or
published, and the seven negative modules are not exercised here because refusing them is an
HTTP 4xx from a listener this package does not yet have. `lab/EXTERNAL-NOUNS.md` stays at
zero and says so.
"""
import json
import os
import pathlib
import sys
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from polaris_oid4vp.jwe import JweError, b64u_decode, decrypt_response  # noqa: E402
from polaris_oid4vp.sdjwt import verify_presentation  # noqa: E402

FIXTURE = pathlib.Path(__file__).parent / "testdata" / "conformance-suite-capture.json"


def _load():
    data = json.loads(FIXTURE.read_text())
    jwk = data["response_decryption_jwk"]
    key = ec.derive_private_key(int.from_bytes(b64u_decode(jwk["d"]), "big"), ec.SECP256R1())
    return data, key


def _presentation(data, key):
    token = data["response_jwe"]
    if token.startswith("response="):
        token = urllib.parse.parse_qs(token)["response"][0]
    body = decrypt_response(token, key)
    vp = body["vp_token"]["pid"]
    return body, vp[0] if isinstance(vp, list) else vp


class TheSuitesOwnResponseTests(unittest.TestCase):

    def test_the_jwe_the_suite_produced_decrypts(self):
        data, key = _load()
        body, _ = _presentation(data, key)
        self.assertIn("vp_token", body)
        self.assertIn("state", body)

    def test_the_presentation_the_suite_produced_verifies(self):
        data, key = _load()
        _, presentation = _presentation(data, key)
        # `now` is pinned to the key binding JWT's own iat. Freshness is relative to when a
        # presentation was made, and a fixture ages: pinning it is what lets this assert the
        # verdict that was correct at capture time rather than quietly widening the window
        # until an old presentation passes, which is the check deleting itself.
        kb_iat = json.loads(b64u_decode(presentation.split("~")[-1].split(".")[1]))["iat"]
        verdict = verify_presentation(presentation,
                                      expected_nonce=data["nonce"],
                                      expected_audience=data["client_id"],
                                      issuer_jwks=[data["issuer_jwk"]],
                                      now=kb_iat)
        self.assertTrue(verdict.authentic, "%s: %s" % (verdict.code, verdict.reason))
        self.assertEqual(verdict.claims.get("vct"), "urn:eudi:pid:1")
        self.assertEqual(verdict.claims.get("given_name"), "Jean")
        self.assertEqual(verdict.claims.get("family_name"), "Dupont")

    def test_only_the_requested_claims_came_back(self):
        """The DCQL query asked for two claims. The credential commits to eleven."""
        data, key = _load()
        _, presentation = _presentation(data, key)
        kb_iat = json.loads(b64u_decode(presentation.split("~")[-1].split(".")[1]))["iat"]
        verdict = verify_presentation(presentation, expected_nonce=data["nonce"],
                                      expected_audience=data["client_id"],
                                      issuer_jwks=[data["issuer_jwk"]], now=kb_iat)
        self.assertTrue(verdict.authentic)
        for never_asked_for in ("birthdate", "nationalities", "place_of_birth", "portrait"):
            self.assertNotIn(never_asked_for, verdict.claims)


class TheSameFixtureRefusedTests(unittest.TestCase):
    """The fixture proves the refusals too, which is the half a happy path cannot show."""

    def setUp(self):
        self.data, self.key = _load()
        _, self.presentation = _presentation(self.data, self.key)
        self.kb_iat = json.loads(
            b64u_decode(self.presentation.split("~")[-1].split(".")[1]))["iat"]

    def _verify(self, **kw):
        args = {"expected_nonce": self.data["nonce"],
                "expected_audience": self.data["client_id"],
                "issuer_jwks": [self.data["issuer_jwk"]], "now": self.kb_iat}
        args.update(kw)
        return verify_presentation(self.presentation, **args)

    def test_a_real_presentation_still_expires(self):
        """Replayed a year later it is refused, and that is the point of iat."""
        verdict = self._verify(now=self.kb_iat + 365 * 24 * 3600)
        self.assertFalse(verdict.authentic)
        self.assertEqual(verdict.code, "kb_freshness")

    def test_it_is_refused_for_a_nonce_we_did_not_send(self):
        verdict = self._verify(expected_nonce="a-nonce-from-another-request")
        self.assertFalse(verdict.authentic)
        self.assertEqual(verdict.code, "nonce")

    def test_it_is_refused_for_another_verifier(self):
        verdict = self._verify(expected_audience="x509_hash:not-this-verifier")
        self.assertFalse(verdict.authentic)
        self.assertEqual(verdict.code, "audience")

    def test_it_is_refused_under_an_issuer_we_do_not_trust(self):
        other = dict(self.data["issuer_jwk"])
        other["x"] = "AAAA" + other["x"][4:]
        verdict = self._verify(issuer_jwks=[other])
        self.assertFalse(verdict.authentic)
        self.assertIn(verdict.code, ("issuer_signature", "issuer_key"))

    def test_a_tampered_disclosure_is_refused(self):
        """Rewrite 'Jean' to 'Jeanne' and the digest no longer matches what was signed."""
        parts = self.presentation.split("~")
        import base64
        for i, d in enumerate(parts[1:-1], start=1):
            if not d:
                continue
            claim = json.loads(b64u_decode(d))
            if claim[1] == "given_name":
                claim[2] = "Jeanne"
                parts[i] = base64.urlsafe_b64encode(
                    json.dumps(claim, separators=(",", ":")).encode()).decode().rstrip("=")
                break
        else:
            self.fail("the fixture no longer carries a given_name disclosure")
        verdict = verify_presentation("~".join(parts), expected_nonce=self.data["nonce"],
                                      expected_audience=self.data["client_id"],
                                      issuer_jwks=[self.data["issuer_jwk"]], now=self.kb_iat)
        self.assertFalse(verdict.authentic)
        self.assertEqual(verdict.code, "disclosure")

    def test_the_jwe_does_not_open_under_another_key(self):
        with self.assertRaises(JweError):
            _presentation(self.data, ec.generate_private_key(ec.SECP256R1()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
