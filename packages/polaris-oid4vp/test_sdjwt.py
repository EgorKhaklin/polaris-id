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
                issuer_alg="ES256", include_cnf=True, payload_extra=None):
        disclosures = [_disclosure("salt%d" % i, name, value)
                       for i, (name, value) in enumerate(claims)]
        digests = [b64u_encode(hashlib.sha256(d.encode("ascii")).digest()) for d in disclosures]

        payload = {"iss": "https://issuer.example", "vct": "urn:eudi:pid:1",
                   "iat": int(time.time()), "_sd": digests, "_sd_alg": "sha-256"}
        if include_cnf:
            payload["cnf"] = {"jwk": _public_jwk(self.holder_key)}
        # Claims the issuer signs that this wallet does not normally mint: `exp`, `nbf`, a
        # different `vct`. The issuer signs whatever it is given, which is the point: these
        # are things a REAL issuer sets and this verifier has to read.
        if payload_extra:
            payload.update(payload_extra)
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


class RefusalsCoverageFoundTests(unittest.TestCase):
    """Refusals that existed with nothing exercising them, found by measuring coverage.

    Every one of these is a way a presentation can be wrong that the conformance plan does
    NOT send. The plan is eleven modules; the refusal surface is wider than eleven, and the
    parts it does not reach are exactly the parts that rot unnoticed.
    """

    def _mutate_issuer_payload(self, mutate):
        """Rebuild a presentation with the issuer payload changed, signature and all."""
        w = Wallet()
        disclosures = [_disclosure("salt0", "given_name", "Jean")]
        digests = [b64u_encode(hashlib.sha256(d.encode("ascii")).digest())
                   for d in disclosures]
        payload = {"iss": "https://issuer.example", "vct": "urn:eudi:pid:1",
                   "iat": int(time.time()), "_sd": digests, "_sd_alg": "sha-256",
                   "cnf": {"jwk": _public_jwk(w.holder_key)}}
        mutate(payload, disclosures)
        issuer_jwt = _jws(w.issuer_key, {"alg": "ES256", "typ": "dc+sd-jwt",
                                         "kid": "issuer-1"}, payload)
        presented = issuer_jwt + "~" + "".join(d + "~" for d in disclosures)
        kb = _jws(w.holder_key, {"alg": "ES256", "typ": "kb+jwt"},
                  {"iat": int(time.time()), "aud": AUDIENCE, "nonce": NONCE,
                   "sd_hash": b64u_encode(
                       hashlib.sha256(presented.encode("ascii")).digest())})
        return w, presented + kb

    def test_an_unknown_sd_alg_is_refused_rather_than_assumed_to_be_sha256(self):
        w, presentation = self._mutate_issuer_payload(
            lambda payload, d: payload.__setitem__("_sd_alg", "sha-512"))
        v = w.verify(presentation)
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "sd_alg")

    def test_an_array_element_disclosure_resolves(self):
        """The `{"...": digest}` form. The suite's own PID uses it for `nationalities`, and
        the DCQL query in the conformance run filters it out, so the plan never sent one."""
        element = b64u_encode(json.dumps(["saltN", "FR"], separators=(",", ":")).encode())
        digest = b64u_encode(hashlib.sha256(element.encode("ascii")).digest())

        def mutate(payload, disclosures):
            payload["nationalities"] = [{"...": digest}]
            disclosures.append(element)

        w, presentation = self._mutate_issuer_payload(mutate)
        v = w.verify(presentation)
        self.assertTrue(v.authentic, "%s: %s" % (v.code, v.reason))
        self.assertEqual(v.claims["nationalities"], ["FR"])

    def test_a_disclosure_that_resolves_to_nothing_is_refused(self):
        """Committed to by the issuer, but pointing at no digest the payload still uses."""
        orphan = b64u_encode(json.dumps(["saltO", "x"], separators=(",", ":")).encode())
        digest = b64u_encode(hashlib.sha256(orphan.encode("ascii")).digest())

        def mutate(payload, disclosures):
            # The digest is committed inside an array the resolver reaches, but the
            # disclosure is a 2-element array in an _sd slot, so nothing consumes it.
            payload["_sd"].append(digest)
            disclosures.append(orphan)

        w, presentation = self._mutate_issuer_payload(mutate)
        v = w.verify(presentation)
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "disclosure")

    def test_the_same_disclosure_presented_twice_is_refused(self):
        w = Wallet()
        presentation = w.present()
        head, rest = presentation.split("~", 1)
        first = rest.split("~")[0]
        v = w.verify(head + "~" + first + "~" + rest)
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "disclosure")

    def test_a_disclosure_that_is_not_an_array_is_refused(self):
        w = Wallet()
        junk = b64u_encode(json.dumps({"not": "an array"}).encode())
        v = w.verify(w.present(extra_disclosure=junk))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "disclosure")

    def test_a_disclosure_that_does_not_decode_is_refused(self):
        w = Wallet()
        v = w.verify(w.present(extra_disclosure="!!!not-base64!!!"))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "disclosure")

    def test_a_key_binding_jwt_with_a_non_numeric_iat_is_refused(self):
        w = Wallet()
        v = w.verify(w.present(iat="yesterday"))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "kb_freshness")

    def test_a_boolean_iat_is_not_a_number(self):
        """True == 1 in Python, so a bool sails through an isinstance(int) check."""
        w = Wallet()
        v = w.verify(w.present(iat=True))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "kb_freshness")

    def test_a_key_binding_jwt_declaring_another_algorithm_is_refused(self):
        w = Wallet()
        presentation = w.present()
        head, kb = presentation.rsplit("~", 1)
        header_b64, payload_b64, sig = kb.split(".")
        header = json.loads(b64u_decode_for_test(header_b64))
        header["alg"] = "HS256"
        patched = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
        v = w.verify(head + "~" + ".".join([patched, payload_b64, sig]))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "kb_alg")

    def test_a_credential_whose_cnf_jwk_is_unusable_is_refused(self):
        def mutate(payload, disclosures):
            payload["cnf"] = {"jwk": {"kty": "RSA", "n": "AAAA", "e": "AQAB"}}

        w, presentation = self._mutate_issuer_payload(mutate)
        v = w.verify(presentation)
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "kb_cnf")

    def test_an_x5c_that_is_not_an_array_is_refused(self):
        w = Wallet()
        presentation = w.present()
        issuer_jwt, rest = presentation.split("~", 1)
        header_b64, payload_b64, sig = issuer_jwt.split(".")
        header = json.loads(b64u_decode_for_test(header_b64))
        header["x5c"] = "a string, not a chain"
        patched = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
        v = w.verify(".".join([patched, payload_b64, sig]) + "~" + rest)
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "issuer_key")

    def test_an_x5c_leaf_that_does_not_parse_is_refused(self):
        w = Wallet()
        presentation = w.present()
        issuer_jwt, rest = presentation.split("~", 1)
        header_b64, payload_b64, sig = issuer_jwt.split(".")
        header = json.loads(b64u_decode_for_test(header_b64))
        header["x5c"] = [base64.b64encode(b"not a certificate").decode()]
        patched = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
        v = verify_presentation(".".join([patched, payload_b64, sig]) + "~" + rest,
                                expected_nonce=NONCE, expected_audience=AUDIENCE,
                                trust_anchors=[object()])
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "issuer_key")

    def test_a_signature_of_the_wrong_length_is_refused_not_padded(self):
        w = Wallet()
        presentation = w.present()
        issuer_jwt, rest = presentation.split("~", 1)
        head, _, sig = issuer_jwt.rpartition(".")
        short = b64u_encode(b64u_decode_for_test(sig)[:40])
        v = w.verify(head + "." + short + "~" + rest)
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "issuer_signature")

    def test_a_jwk_that_is_not_an_object_is_refused(self):
        w = Wallet()
        v = verify_presentation(w.present(), expected_nonce=NONCE,
                                expected_audience=AUDIENCE,
                                issuer_jwks=["not-a-jwk", {"kty": "EC", "crv": "P-521"}])
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "issuer_key")

    def test_a_p256_jwk_with_short_coordinates_is_refused(self):
        w = Wallet()
        short = dict(w.issuer_jwk, x=b64u_encode(b"\x01" * 8))
        v = verify_presentation(w.present(), expected_nonce=NONCE,
                                expected_audience=AUDIENCE, issuer_jwks=[short])
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "issuer_key")

    def test_a_jws_without_three_parts_is_refused(self):
        w = Wallet()
        presentation = w.present()
        _, rest = presentation.split("~", 1)
        v = w.verify("only.two~" + rest)
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "malformed")

    def test_a_jws_whose_payload_is_not_an_object_is_refused(self):
        w = Wallet()
        presentation = w.present()
        issuer_jwt, rest = presentation.split("~", 1)
        header_b64, _, sig = issuer_jwt.split(".")
        v = w.verify(".".join([header_b64, b64u_encode(b"[1,2,3]"), sig]) + "~" + rest)
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "malformed")

    def test_a_verdict_renders_both_ways(self):
        w = Wallet()
        good = w.verify(w.present())
        bad = w.verify(w.present(nonce="x"))
        self.assertIn("authentic", repr(good))
        self.assertIn("refused", repr(bad))
        self.assertEqual(good.as_dict()["authentic"], True)
        self.assertEqual(bad.as_dict()["code"], "nonce")


class ResolverAndOptionsTests(unittest.TestCase):
    """The remaining reachable branches, each a thing a real credential can contain."""

    def test_digests_nested_below_a_list_are_collected(self):
        """A credential's structure is arbitrary JSON. The collector has to walk all of it,
        or a disclosure hides under one list level and is accepted uncommitted."""
        buried = _disclosure("saltB", "licence_number", "X1")
        digest = b64u_encode(hashlib.sha256(buried.encode("ascii")).digest())
        w = Wallet()
        disclosures = [_disclosure("salt0", "given_name", "Jean"), buried]
        payload = {"iss": "https://issuer.example", "vct": "urn:eudi:pid:1",
                   "iat": int(time.time()),
                   "_sd": [b64u_encode(hashlib.sha256(disclosures[0].encode("ascii")).digest())],
                   "documents": [{"kind": "permit", "_sd": [digest]}],
                   "cnf": {"jwk": _public_jwk(w.holder_key)}}
        issuer_jwt = _jws(w.issuer_key, {"alg": "ES256", "typ": "dc+sd-jwt",
                                         "kid": "issuer-1"}, payload)
        presented = issuer_jwt + "~" + "".join(d + "~" for d in disclosures)
        kb = _jws(w.holder_key, {"alg": "ES256", "typ": "kb+jwt"},
                  {"iat": int(time.time()), "aud": AUDIENCE, "nonce": NONCE,
                   "sd_hash": b64u_encode(hashlib.sha256(presented.encode("ascii")).digest())})
        v = w.verify(presented + kb)
        self.assertTrue(v.authentic, "%s: %s" % (v.code, v.reason))
        self.assertEqual(v.claims["documents"][0]["licence_number"], "X1")

    def test_key_binding_can_be_waived_only_by_the_caller(self):
        """Off by default, because a presentation without it is a copy anybody can replay."""
        w = Wallet()
        bare = w.present(drop_key_binding=True)
        self.assertFalse(w.verify(bare).authentic)
        v = w.verify(bare, require_key_binding=False)
        self.assertTrue(v.authentic, "%s: %s" % (v.code, v.reason))
        self.assertEqual(v.claims["given_name"], "Jean")

    def test_a_key_binding_jwt_that_does_not_parse_is_refused(self):
        w = Wallet()
        head, _ = w.present().rsplit("~", 1)
        v = w.verify(head + "~" + "not.a.valid.jwt")
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "malformed")

    def test_an_issuer_jwk_list_is_tried_until_one_works(self):
        w = Wallet()
        v = verify_presentation(w.present(), expected_nonce=NONCE,
                                expected_audience=AUDIENCE,
                                issuer_jwks=[{"kty": "EC", "crv": "P-521", "x": "AA", "y": "AA"},
                                             dict(w.issuer_jwk, kid=None)])
        self.assertTrue(v.authentic, "%s: %s" % (v.code, v.reason))


def b64u_decode_for_test(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class CredentialValidityTests(unittest.TestCase):
    """`exp` and `nbf`: neither string appeared anywhere in sdjwt.py until 2026-09-17.

    A credential its own issuer stamped as expired ten years ago verified as authentic. For
    an offline SD-JWT VC these two claims are the only expiry mechanism there is: the status
    list is a separate, online question, and a verifier that reads neither has no way to
    stop a revoked-by-expiry credential at all. The capture from the OpenID Foundation's
    hosted suite carries an `exp` fourteen days out, so this is a claim real issuers set.
    """

    def setUp(self):
        self.w = Wallet()
        self.now = time.time()

    def test_a_credential_that_expired_ten_years_ago_is_refused(self):
        v = self.w.verify(self.w.present(payload_extra={"exp": self.now - 10 * 365 * 86400}))
        self.assertFalse(v.authentic, "an expired credential must not verify")
        self.assertEqual(v.code, "credential_validity")

    def test_exp_zero_is_refused_rather_than_read_as_absent(self):
        """0 is falsy. A check written as `if payload.get('exp')` would skip it, which makes
        the one timestamp an attacker most wants also the one that turns the check off."""
        v = self.w.verify(self.w.present(payload_extra={"exp": 0}))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "credential_validity")

    def test_a_credential_not_valid_until_next_century_is_refused(self):
        v = self.w.verify(self.w.present(payload_extra={"nbf": self.now + 500 * 365 * 86400}))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "credential_validity")

    def test_a_non_finite_or_non_numeric_lifetime_is_refused_not_ignored(self):
        """A credential that says `exp: NaN` has made a statement about its own lifetime
        that cannot be evaluated. Treating that as "no expiry" is precisely how NaN defeated
        the key binding window one field over."""
        for bad in (float("nan"), float("inf"), float("-inf"), "soon", None, True, [1]):
            with self.subTest(exp=repr(bad)):
                v = self.w.verify(self.w.present(payload_extra={"exp": bad}))
                self.assertFalse(v.authentic, "exp=%r must not be ignored" % (bad,))
                self.assertEqual(v.code, "credential_validity")

    def test_a_credential_inside_its_window_still_verifies(self):
        """The direction that keeps the others honest: if every credential were refused,
        every test above would pass while the verifier accepted nothing."""
        v = self.w.verify(self.w.present(payload_extra={"exp": self.now + 86400,
                                                        "nbf": self.now - 86400}))
        self.assertTrue(v.authentic, v.reason)

    def test_a_credential_with_no_exp_is_not_refused_for_that(self):
        """Absent is not expired. `exp` is optional in SD-JWT VC."""
        self.assertTrue(self.w.verify(self.w.present()).authentic)

    def test_expiry_is_allowed_the_same_clock_skew_as_the_key_binding(self):
        """A credential that expired one second ago on a fast clock is not a forgery."""
        v = self.w.verify(self.w.present(payload_extra={"exp": self.now - 5}))
        self.assertTrue(v.authentic, v.reason)


class NonFiniteTimestampTests(unittest.TestCase):
    """Python's json parses the bare literals NaN, Infinity and -Infinity, and all three are
    floats. They walked straight past `isinstance(iat, (int, float))`."""

    def setUp(self):
        self.w = Wallet()

    def test_a_nan_iat_does_not_defeat_the_freshness_window(self):
        """Every comparison against NaN is False, so `abs(now - nan) > 300` was False and the
        presentation verified. Checked a YEAR out of date, which is the exact condition the
        two conformance modules this file is built around test for."""
        pres = self.w.present(iat=float("nan"))
        for label, now in (("at mint time", time.time()),
                           ("a year later", time.time() + 365 * 86400)):
            with self.subTest(label):
                v = self.w.verify(pres, now=now)
                self.assertFalse(v.authentic, "a NaN iat must not pass the window")
                self.assertEqual(v.code, "kb_freshness")

    def test_an_infinite_iat_is_refused_rather_than_crashing_the_refusal(self):
        """`abs(now - inf) > 300` is True, so this reached the refusal, and the refusal
        formatted `now - iat` with %d: OverflowError out of a function documented to never
        raise. The refusal path was the crash."""
        for bad in (float("inf"), float("-inf")):
            with self.subTest(iat=repr(bad)):
                v = self.w.verify(self.w.present(iat=bad))
                self.assertFalse(v.authentic)
                self.assertEqual(v.code, "kb_freshness")

    def test_a_finite_iat_inside_the_window_still_verifies(self):
        self.assertTrue(self.w.verify(self.w.present()).authentic)


class DisclosureCollisionTests(unittest.TestCase):
    """SD-JWT section 9.3: a disclosure whose name is already a claim must be REJECTED.

    Clear-text claims are written first and disclosed ones second, so before 2026-09-17 the
    disclosure silently won. `cnf` is the sharpest case: the returned claims named a key
    that was not the key the key binding had actually been checked against.
    """

    def setUp(self):
        self.w = Wallet()

    def test_a_disclosure_cannot_overwrite_a_protected_claim(self):
        for name, value in (("iss", "https://attacker.example"),
                            ("cnf", {"jwk": {"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}}),
                            ("exp", 4102444800),
                            ("vct", "https://attacker.example/loyalty-card"),
                            ("_sd_alg", "none")):
            with self.subTest(claim=name):
                v = self.w.verify(self.w.present(
                    claims=(("given_name", "Jean"), (name, value))))
                self.assertFalse(v.authentic,
                                 "a disclosure named %r overwrote a signed claim" % name)
                self.assertEqual(v.code, "disclosure")

    def test_the_issuer_in_the_returned_claims_is_the_one_that_signed(self):
        """The consequence, stated as a property rather than a code. A relying party reads
        `claims['iss']` to decide whose credential this is."""
        v = self.w.verify(self.w.present(
            claims=(("given_name", "Jean"), ("iss", "https://attacker.example"))))
        self.assertFalse(v.authentic)
        self.assertNotEqual(v.claims.get("iss"), "https://attacker.example")

    def test_two_disclosures_with_the_same_name_collide_with_each_other(self):
        v = self.w.verify(self.w.present(
            claims=(("given_name", "Jean"), ("given_name", "Someone Else"))))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "disclosure")

    def test_distinct_disclosure_names_still_verify(self):
        v = self.w.verify(self.w.present(
            claims=(("given_name", "Jean"), ("family_name", "Dupont"), ("birthdate", "1990-04-17"))))
        self.assertTrue(v.authentic, v.reason)
        self.assertEqual(v.claims["birthdate"], "1990-04-17")
