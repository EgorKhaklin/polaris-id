"""test_sdjwt.py -- the seven refusals the conformance suite scores, each built and caught.

ANTI-VACUITY. A verifier that refuses everything passes every negative test in this file and
is worthless. So the first test is the positive control: this module's own wallet mints a
presentation and the verifier must call it AUTHENTIC. Every refusal case below is that same
presentation with exactly one thing changed, which is the only way "it refused" means "it
noticed" rather than "it never accepts anything".

The wallet here mirrors what the OpenID Foundation conformance suite's fake wallet does,
measured from its source rather than from the specification alone: issuer JWT `typ` is
`dc+sd-jwt`, key binding JWT `typ` is `kb+jwt`, both ES256, and `sd_hash` is the base64url
SHA-256 of the US-ASCII bytes up to and including the final tilde.
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

from polaris_oid4vp.sdjwt import b64u_encode, verify_presentation  # noqa: E402

NONCE = "vJ3xQ2kZ8fLpN1sT7wRm5bYc0aHdEgUi"
AUDIENCE = "x509_hash:0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"


def _jws(key, header, payload):
    header_b64 = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64u_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    r, s = asym_utils.decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    return header_b64 + "." + payload_b64 + "." + b64u_encode(
        r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _public_jwk(key):
    numbers = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256",
            "x": b64u_encode(numbers.x.to_bytes(32, "big")),
            "y": b64u_encode(numbers.y.to_bytes(32, "big"))}


def _disclosure(salt, name, value):
    raw = json.dumps([salt, name, value], separators=(",", ":")).encode()
    return b64u_encode(raw)


class Wallet:
    """Mints presentations the way the conformance suite's fake wallet does."""

    def __init__(self):
        self.issuer_key = ec.generate_private_key(ec.SECP256R1())
        self.holder_key = ec.generate_private_key(ec.SECP256R1())
        self.issuer_jwk = dict(_public_jwk(self.issuer_key), kid="issuer-1")

    def present(self, *, nonce=NONCE, audience=AUDIENCE, iat=None, sd_hash=None,
                claims=(("given_name", "Jean"), ("family_name", "Dupont")),
                corrupt_issuer_sig=False, corrupt_kb_sig=False, drop_key_binding=False,
                extra_disclosure=None, issuer_typ="dc+sd-jwt", kb_typ="kb+jwt",
                issuer_alg="ES256", include_cnf=True):
        disclosures = [_disclosure("salt%d" % i, name, value)
                       for i, (name, value) in enumerate(claims)]
        digests = [b64u_encode(hashlib.sha256(d.encode("ascii")).digest()) for d in disclosures]

        payload = {"iss": "https://issuer.example", "vct": "urn:eudi:pid:1",
                   "iat": int(time.time()), "_sd": digests, "_sd_alg": "sha-256"}
        if include_cnf:
            payload["cnf"] = {"jwk": _public_jwk(self.holder_key)}
        issuer_jwt = _jws(self.issuer_key,
                          {"alg": issuer_alg, "typ": issuer_typ, "kid": "issuer-1"}, payload)
        if corrupt_issuer_sig:
            head, _, sig = issuer_jwt.rpartition(".")
            flipped = bytearray(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)))
            flipped[0] ^= 0xFF
            issuer_jwt = head + "." + b64u_encode(bytes(flipped))

        if extra_disclosure is not None:
            disclosures = disclosures + [extra_disclosure]
        presented = issuer_jwt + "~" + "".join(d + "~" for d in disclosures)
        if drop_key_binding:
            return presented

        computed = b64u_encode(hashlib.sha256(presented.encode("ascii")).digest())
        kb = _jws(self.holder_key, {"alg": "ES256", "typ": kb_typ},
                  {"iat": int(time.time()) if iat is None else iat, "aud": audience,
                   "nonce": nonce, "sd_hash": computed if sd_hash is None else sd_hash})
        if corrupt_kb_sig:
            head, _, sig = kb.rpartition(".")
            flipped = bytearray(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)))
            flipped[0] ^= 0xFF
            kb = head + "." + b64u_encode(bytes(flipped))
        return presented + kb

    def verify(self, presentation, **kw):
        kw.setdefault("expected_nonce", NONCE)
        kw.setdefault("expected_audience", AUDIENCE)
        kw.setdefault("issuer_jwks", [self.issuer_jwk])
        return verify_presentation(presentation, **kw)


class PositiveControlTests(unittest.TestCase):
    """If this fails, every refusal below is meaningless."""

    def test_a_well_formed_presentation_is_authentic(self):
        w = Wallet()
        v = w.verify(w.present())
        self.assertTrue(v.authentic, "the positive control was refused (%s: %s); every "
                                     "refusal test in this file is now vacuous"
                                     % (v.code, v.reason))

    def test_the_disclosed_claims_come_back(self):
        w = Wallet()
        v = w.verify(w.present())
        self.assertEqual(v.claims.get("given_name"), "Jean")
        self.assertEqual(v.claims.get("family_name"), "Dupont")
        self.assertEqual(v.claims.get("vct"), "urn:eudi:pid:1")
        self.assertNotIn("_sd", v.claims)

    def test_an_undisclosed_claim_does_not_appear(self):
        w = Wallet()
        v = w.verify(w.present(claims=(("given_name", "Jean"),)))
        self.assertTrue(v.authentic)
        self.assertNotIn("family_name", v.claims)


class TheSevenConformanceRefusalsTests(unittest.TestCase):
    """One test per negative module in oid4vp-1final-verifier-haip-test-plan."""

    def test_invalid_credential_signature(self):
        w = Wallet()
        v = w.verify(w.present(corrupt_issuer_sig=True))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "issuer_signature")

    def test_invalid_sd_hash(self):
        w = Wallet()
        v = w.verify(w.present(sd_hash=b64u_encode(b"x" * 32)))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "sd_hash")

    def test_invalid_kb_jwt_signature(self):
        w = Wallet()
        v = w.verify(w.present(corrupt_kb_sig=True))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "kb_signature")

    def test_invalid_kb_jwt_nonce(self):
        w = Wallet()
        v = w.verify(w.present(nonce="a-nonce-nobody-asked-for"))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "nonce")

    def test_invalid_kb_jwt_aud(self):
        w = Wallet()
        v = w.verify(w.present(audience="x509_hash:some-other-verifier-entirely"))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "audience")

    def test_kb_jwt_iat_in_past(self):
        w = Wallet()
        v = w.verify(w.present(iat=int(time.time()) - 365 * 24 * 3600))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "kb_freshness")

    def test_kb_jwt_iat_in_future(self):
        w = Wallet()
        v = w.verify(w.present(iat=int(time.time()) + 365 * 24 * 3600))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "kb_freshness")


class StructuralRefusalsTests(unittest.TestCase):
    """Everything else a presentation can be, that is not a presentation."""

    def test_a_presentation_with_no_key_binding_is_refused(self):
        w = Wallet()
        v = w.verify(w.present(drop_key_binding=True))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "kb_missing")

    def test_a_credential_with_no_cnf_cannot_be_key_bound(self):
        w = Wallet()
        v = w.verify(w.present(include_cnf=False))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "kb_cnf")

    def test_an_unknown_issuer_typ_is_refused(self):
        w = Wallet()
        v = w.verify(w.present(issuer_typ="JWT"))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "issuer_typ")

    def test_an_unknown_kb_typ_is_refused(self):
        w = Wallet()
        v = w.verify(w.present(kb_typ="JWT"))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "kb_typ")

    def test_the_header_algorithm_is_not_followed(self):
        """`alg` is attacker-controlled. A verifier that obeys it can be walked to none."""
        w = Wallet()
        v = w.verify(w.present(issuer_alg="none"))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "issuer_alg")

    def test_a_disclosure_the_issuer_never_committed_to_is_refused(self):
        w = Wallet()
        smuggled = _disclosure("salt99", "is_over_18", True)
        v = w.verify(w.present(extra_disclosure=smuggled))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "disclosure")

    def test_a_presentation_signed_by_an_untrusted_issuer_is_refused(self):
        mine, theirs = Wallet(), Wallet()
        v = mine.verify(theirs.present())
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "issuer_signature")

    def test_with_no_issuer_key_configured_nothing_is_authentic(self):
        w = Wallet()
        v = verify_presentation(w.present(), expected_nonce=NONCE,
                                expected_audience=AUDIENCE)
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "issuer_key")

    def test_a_caller_that_supplies_no_nonce_is_refused_not_indulged(self):
        w = Wallet()
        v = verify_presentation(w.present(), expected_nonce="", expected_audience=AUDIENCE,
                                issuer_jwks=[w.issuer_jwk])
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "misconfigured")

    def test_garbage_is_refused_without_raising(self):
        for junk in ("", "   ", "~~~", "not.a.jwt~~", "a~b~c", "\x00\x01"):
            v = verify_presentation(junk, expected_nonce=NONCE, expected_audience=AUDIENCE,
                                    issuer_jwks=[{}])
            self.assertFalse(v.authentic, "%r was accepted" % junk)


class X5CTests(unittest.TestCase):
    """The other way an issuer key is established, which is the one the suite uses."""

    @staticmethod
    def _chain():
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test anchor")])
        ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - datetime.timedelta(days=1))
              .not_valid_after(now + datetime.timedelta(days=30))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .sign(ca_key, hashes.SHA256()))
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "issuer")]))
                .issuer_name(ca_name).public_key(leaf_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=30))
                .sign(ca_key, hashes.SHA256()))
        return ca, leaf, leaf_key

    def _present_with_x5c(self, leaf, leaf_key):
        w = Wallet()
        w.issuer_key = leaf_key
        der = leaf.public_bytes(serialization.Encoding.DER)
        original = _jws

        def patched(key, header, payload):
            if header.get("typ") == "dc+sd-jwt":
                header = dict(header, x5c=[base64.b64encode(der).decode()])
                header.pop("kid", None)
            return original(key, header, payload)

        globals()["_jws"] = patched
        try:
            return w.present()
        finally:
            globals()["_jws"] = original

    def test_a_leaf_chaining_to_the_anchor_is_authentic(self):
        ca, leaf, leaf_key = self._chain()
        presentation = self._present_with_x5c(leaf, leaf_key)
        v = verify_presentation(presentation, expected_nonce=NONCE, expected_audience=AUDIENCE,
                                trust_anchors=[ca])
        self.assertTrue(v.authentic, "%s: %s" % (v.code, v.reason))

    def test_a_leaf_from_another_anchor_is_refused(self):
        _, leaf, leaf_key = self._chain()
        other_ca, _, _ = self._chain()
        presentation = self._present_with_x5c(leaf, leaf_key)
        v = verify_presentation(presentation, expected_nonce=NONCE, expected_audience=AUDIENCE,
                                trust_anchors=[other_ca])
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "issuer_key")

    def test_an_x5c_with_no_anchor_configured_is_refused(self):
        _, leaf, leaf_key = self._chain()
        presentation = self._present_with_x5c(leaf, leaf_key)
        v = verify_presentation(presentation, expected_nonce=NONCE, expected_audience=AUDIENCE)
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "issuer_key")


if __name__ == "__main__":
    unittest.main(verbosity=2)
