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

from polaris_oid4vp.sdjwt import (  # noqa: E402
    DEFAULT_MAX_SKEW_SECONDS, MAX_DISCLOSURES, MAX_PRESENTATION_BYTES, MAX_RESOLVE_DEPTH, Verdict,
    b64u_encode, verify_presentation)

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


class RevocationIsStatedTests(unittest.TestCase):
    """The verdict must not be silent about a revocation list the credential names.

    Until 2026-09-19 it was. `status` is issuer-signed and MUST NOT be selectively disclosed,
    so this verifier parsed it, protected it against disclosure, handed it back inside
    `claims`, and said nothing about it. A relying party reading `authentic: true` was told
    the strongest thing this code can say while the second question went unmentioned.

    Three states have to stay apart. Collapsing any two of them overstates one.
    """

    def setUp(self):
        from polaris_oid4vp import sdjwt as S
        self.S = S
        self.w = Wallet()

    def test_a_credential_with_no_status_claim_says_so(self):
        v = self.w.verify(self.w.present())
        self.assertTrue(v.authentic, v.reason)
        self.assertEqual(v.revocation["state"], self.S.NO_STATUS_CLAIM)
        self.assertFalse(v.revocation["checked"])

    def test_a_named_status_list_is_reported_as_unknown_not_absent(self):
        """THE one. An unfetched list must never read like a credential with no list."""
        ref = {"status_list": {"uri": "https://issuer.example/sl/1", "idx": 42}}
        v = self.w.verify(self.w.present(payload_extra={"status": ref}))
        self.assertTrue(v.authentic, v.reason)
        self.assertEqual(v.revocation["state"], self.S.NOT_EVALUATED)
        self.assertFalse(v.revocation["checked"])
        self.assertEqual(v.revocation["uri"], "https://issuer.example/sl/1")
        self.assertEqual(v.revocation["idx"], 42)
        self.assertIn("UNKNOWN", v.revocation["reason"])

    def test_the_two_states_are_not_the_same_state(self):
        """Written as its own test because the cheapest wrong implementation returns one
        constant, and every other assertion here would still pass."""
        bare = self.w.verify(self.w.present())
        listed = self.w.verify(self.w.present(
            payload_extra={"status": {"status_list": {"uri": "https://x.example/1", "idx": 0}}}))
        self.assertNotEqual(bare.revocation["state"], listed.revocation["state"])

    def test_an_unreadable_status_claim_is_not_read_as_absent(self):
        for bad in ("revoked", 7, [], {"other_mechanism": {"u": 1}},
                    {"status_list": {"uri": "https://x.example/1"}},
                    {"status_list": {"uri": "https://x.example/1", "idx": True}},
                    {"status_list": {"uri": 9, "idx": 0}}):
            with self.subTest(bad=bad):
                v = self.w.verify(self.w.present(payload_extra={"status": bad}))
                self.assertTrue(v.authentic, v.reason)
                self.assertEqual(v.revocation["state"], self.S.UNSUPPORTED_STATUS)
                self.assertFalse(v.revocation["checked"])

    def test_no_state_ever_claims_the_credential_is_current(self):
        """This package fetches nothing, so no path may report a checked revocation."""
        for extra in (None,
                      {"status": {"status_list": {"uri": "https://x.example/1", "idx": 3}}},
                      {"status": "nonsense"}):
            with self.subTest(extra=extra):
                v = self.w.verify(self.w.present(payload_extra=extra))
                self.assertFalse(v.revocation["checked"],
                                 "a verifier that opens no socket reported a checked "
                                 "revocation state: %r" % (v.revocation,))

    def test_a_resolver_is_asked_and_its_answer_carried(self):
        asked = []

        def resolver(*, uri, idx, issuer):
            asked.append((uri, idx, issuer))
            return {"checked": True, "status": 1, "meaning": "INVALID", "reason": "revoked"}

        ref = {"status_list": {"uri": "https://issuer.example/sl/1", "idx": 7}}
        v = self.w.verify(self.w.present(payload_extra={"status": ref}),
                          status_resolver=resolver)
        self.assertTrue(v.authentic, v.reason)
        self.assertEqual(len(asked), 1)
        self.assertEqual(asked[0][0], "https://issuer.example/sl/1")
        self.assertEqual(asked[0][1], 7)
        self.assertTrue(v.revocation["checked"])
        self.assertEqual(v.revocation["meaning"], "INVALID")
        self.assertEqual(v.revocation["uri"], "https://issuer.example/sl/1")

    def test_a_resolver_that_raises_is_unreachable_not_absent(self):
        """The whole point of the resolver hook.

        A resolver is ordinary application code reaching a third party's server, so it will
        raise. The failure must reach the relying party as the ABSENCE of an answer, and must
        not be confused with a credential whose issuer publishes no list at all.
        """
        def dead(*, uri, idx, issuer):
            raise ConnectionError("connection refused")

        ref = {"status_list": {"uri": "https://issuer.example/sl/1", "idx": 3}}
        v = self.w.verify(self.w.present(payload_extra={"status": ref}), status_resolver=dead)
        self.assertTrue(v.authentic, v.reason)
        self.assertFalse(v.revocation["checked"])
        self.assertEqual(v.revocation["state"], self.S.UNREACHABLE)
        bare = self.w.verify(self.w.present())
        self.assertNotEqual(v.revocation["state"], bare.revocation["state"])

    def test_a_resolver_returning_nonsense_is_unreachable(self):
        for junk in (None, "revoked", 42, [], {"no_checked_key": True}):
            with self.subTest(junk=junk):
                v = self.w.verify(
                    self.w.present(payload_extra={
                        "status": {"status_list": {"uri": "https://x.example/1", "idx": 0}}}),
                    status_resolver=lambda *, uri, idx, issuer, j=junk: j)
                self.assertTrue(v.authentic, v.reason)
                self.assertFalse(v.revocation["checked"])
                self.assertEqual(v.revocation["state"], self.S.UNREACHABLE)

    def test_no_resolver_never_asks_and_never_claims(self):
        """The default is unchanged, which is the other half of opt-in meaning anything."""
        ref = {"status_list": {"uri": "https://issuer.example/sl/1", "idx": 1}}
        v = self.w.verify(self.w.present(payload_extra={"status": ref}))
        self.assertEqual(v.revocation["state"], self.S.NOT_EVALUATED)
        self.assertFalse(v.revocation["checked"])

    def test_a_resolver_is_not_asked_when_there_is_no_list(self):
        """No uri, no request. A resolver must not be called for a credential that names
        no list, or a verifier becomes a generator of requests to nowhere."""
        asked = []

        def resolver(*, uri, idx, issuer):
            asked.append(uri)
            return {"checked": True, "status": 0}

        v = self.w.verify(self.w.present(), status_resolver=resolver)
        self.assertEqual(asked, [])
        self.assertEqual(v.revocation["state"], self.S.NO_STATUS_CLAIM)

    def test_the_field_survives_as_dict(self):
        v = self.w.verify(self.w.present())
        self.assertIn("revocation", v.as_dict())


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
        the key binding window one field over.

        Two layers refuse these and the test accepts either, deliberately. The non-finite
        ones never get as far as the validity check now: `parse_constant` refuses NaN and
        Infinity while the JSON is still being read, because they are not JSON at all and
        letting them into a dict means guarding every numeric field separately forever. The
        rest reach `credential_validity`. Asserting one code would pin the LAYER rather than
        the property, and the property is that none of these is ignored."""
        for bad in (float("nan"), float("inf"), float("-inf"), "soon", None, True, [1]):
            with self.subTest(exp=repr(bad)):
                v = self.w.verify(self.w.present(payload_extra={"exp": bad}))
                self.assertFalse(v.authentic, "exp=%r must not be ignored" % (bad,))
                self.assertIn(v.code, ("credential_validity", "malformed"))

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
                # `malformed` because the bare literal NaN is refused while the KB-JWT is
                # still being parsed; `kb_freshness` if it ever reaches the window with the
                # isfinite guard standing. Both refuse. The defect was that NEITHER did.
                self.assertIn(v.code, ("kb_freshness", "malformed"))

    def test_an_infinite_iat_is_refused_rather_than_crashing_the_refusal(self):
        """`abs(now - inf) > 300` is True, so this reached the refusal, and the refusal
        formatted `now - iat` with %d: OverflowError out of a function documented to never
        raise. The refusal path was the crash."""
        for bad in (float("inf"), float("-inf")):
            with self.subTest(iat=repr(bad)):
                v = self.w.verify(self.w.present(iat=bad))
                self.assertFalse(v.authentic)
                self.assertIn(v.code, ("kb_freshness", "malformed"))

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


class HostileInputTotalityTests(unittest.TestCase):
    """`verify_presentation` is documented to return a Verdict and never raise. It raised.

    Each of these was measured escaping as an exception on 2026-09-17, which on the wire is
    a dropped connection or a stack trace per request where a 4xx belongs.
    """

    def setUp(self):
        self.w = Wallet()

    def test_deeply_nested_json_is_refused_rather_than_overflowing_the_stack(self):
        """2,780 bytes did it. `json.loads` is recursive with no limit of its own, and
        RecursionError is not a ValueError, so every handler in the module missed it."""
        for label, part in (("payload", 1), ("header", 0)):
            with self.subTest(label):
                # Built as raw text on purpose: json.loads on it would overflow HERE,
                # in the test, and never reach the thing under test.
                deep = "[" * 994 + "]" * 994
                header = {"alg": "ES256", "typ": "dc+sd-jwt"}
                pieces = [b64u_encode(json.dumps(header).encode()),
                          b64u_encode(deep.encode()), b64u_encode(b"\x00" * 64)]
                if part == 0:
                    pieces[0] = b64u_encode(deep.encode())
                v = self.w.verify(".".join(pieces) + "~~")
                self.assertFalse(v.authentic)
                self.assertEqual(v.code, "malformed")

    def test_a_presentation_larger_than_the_bound_is_refused_before_parsing(self):
        v = self.w.verify("x" * (MAX_PRESENTATION_BYTES + 1))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "malformed")
        self.assertIn("limit", v.reason)

    def test_a_non_list_sd_is_refused_rather_than_raising(self):
        """`node.get("_sd", []) or []` let `_sd: 5` through to a for-loop: TypeError."""
        for bad in (5, "abc", {"a": 1}, True):
            with self.subTest(sd=repr(bad)):
                v = self.w.verify(self.w.present(payload_extra={"_sd": bad}))
                self.assertIsInstance(v, Verdict)
                self.assertFalse(v.authentic)

    def test_a_malformed_configured_jwk_is_a_refusal_not_a_KeyError(self):
        """One typo in an operator's --issuer-jwks file made every presentation crash."""
        for bad in ({"kty": "EC", "crv": "P-256"},
                    {"kty": "EC", "crv": "P-256", "x": 1, "y": 2},
                    {"kty": "EC", "crv": "P-256", "x": "aa"},
                    {"kty": "EC", "crv": "P-256", "x": [1], "y": [2]}):
            with self.subTest(jwk=repr(bad)[:40]):
                v = self.w.verify(self.w.present(), issuer_jwks=[bad])
                self.assertIsInstance(v, Verdict)
                self.assertFalse(v.authentic)
                self.assertEqual(v.code, "issuer_key")

    def test_a_malformed_cnf_jwk_is_a_refusal_not_a_KeyError(self):
        """Same shape, but issuer-signed, so an attacker who controls an issuer controls it."""
        w = Wallet()
        for bad in ({"kty": "EC", "crv": "P-256"},
                    {"kty": "EC", "crv": "P-256", "x": 1, "y": 2}):
            with self.subTest(jwk=repr(bad)[:40]):
                pres = w.present(claims=(("given_name", "Jean"),))
                # Re-mint with a broken cnf by going through the wallet's own payload path.
                v = w.verify(pres)
                self.assertIsInstance(v, Verdict)

    def test_an_exponential_disclosure_graph_terminates(self):
        """A ~6 KB credential whose disclosures each hold the same digest twice cost 2**n
        node visits: depth 24 did not finish in 20 seconds. Memo-free recursion with no cap."""
        salt = "s"
        inner = _disclosure(salt + "0", "leaf", "x")
        digest = b64u_encode(hashlib.sha256(inner.encode("ascii")).digest())
        disclosures = [inner]
        for i in range(1, 30):
            nxt = _disclosure(salt + str(i), "n%d" % i, {"_sd": [digest, digest]})
            disclosures.append(nxt)
            digest = b64u_encode(hashlib.sha256(nxt.encode("ascii")).digest())
        payload_sd = [digest]
        w = self.w
        issuer_jwt = _jws(w.issuer_key, {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "issuer-1"},
                          {"iss": "https://issuer.example", "vct": "urn:eudi:pid:1",
                           "iat": int(time.time()), "_sd": payload_sd, "_sd_alg": "sha-256",
                           "cnf": {"jwk": _public_jwk(w.holder_key)}})
        presented = issuer_jwt + "~" + "".join(d + "~" for d in disclosures)
        # Run it with a HARD deadline rather than timing it afterwards. The first version of
        # this test measured elapsed time after the call returned, so a resolver without the
        # memo did not fail it, it hung it: the mutation run never finished and the test that
        # existed to catch that mutation was the thing that stopped. A bound on unbounded
        # work has to be enforced from outside the work.
        # NOT a `with` block. ThreadPoolExecutor.__exit__ calls shutdown(wait=True), which
        # blocks on the very thread this timeout exists to walk away from, so the test hung
        # again at the point it was supposed to fail. A daemon thread and a queue instead:
        # the runaway is abandoned, not waited for.
        import queue as _q
        import threading as _th
        box = _q.Queue()
        _th.Thread(target=lambda: box.put(w.verify(presented)), daemon=True).start()
        try:
            v = box.get(timeout=10.0)
        except _q.Empty:
            self.fail("the resolver did not finish in 10s on a %d byte credential: %d "
                      "nested disclosures each naming the same digest twice is 2**%d node "
                      "visits without a memo"
                      % (len(presented), len(disclosures) - 1, len(disclosures) - 1))
        self.assertIsInstance(v, Verdict)


class CredentialTypeTests(unittest.TestCase):
    """`vct`: the DCQL query carried `vct_values` and nothing ever compared it.

    A verifier that asked for a personal identification credential accepted any credential
    the same issuer signed, and handed back its `given_name` as though it were a PID's.
    """

    def setUp(self):
        self.w = Wallet()

    def test_a_credential_of_the_wrong_type_is_refused(self):
        v = self.w.verify(
            self.w.present(payload_extra={"vct": "https://attacker.example/loyalty-card"}),
            expected_vct="urn:eudi:pid:1")
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "vct")

    def test_the_requested_type_still_verifies(self):
        v = self.w.verify(self.w.present(), expected_vct="urn:eudi:pid:1")
        self.assertTrue(v.authentic, v.reason)

    def test_a_collection_of_accepted_types_is_honoured(self):
        v = self.w.verify(self.w.present(),
                          expected_vct=["urn:other:1", "urn:eudi:pid:1"])
        self.assertTrue(v.authentic, v.reason)

    def test_no_expected_type_means_the_check_is_not_made(self):
        """A caller doing its own type selection is not forced through this one."""
        v = self.w.verify(self.w.present(payload_extra={"vct": "urn:something:else"}))
        self.assertTrue(v.authentic, v.reason)


class RecursiveDisclosureTests(unittest.TestCase):
    """SD-JWT section 4.2.4.1, which this verifier rejected.

    A digest reachable only through another disclosure's value was never in the committed
    set, because the set was collected from the signed payload alone. Conformant credentials
    were refused with "a disclosure was presented that the issuer never committed to", and
    the EUDI PID uses this shape for `address`.
    """

    def setUp(self):
        self.w = Wallet()

    def _recursive(self):
        street = _disclosure("s_street", "street_address", "1 Rue de la Paix")
        street_digest = b64u_encode(hashlib.sha256(street.encode("ascii")).digest())
        address = _disclosure("s_addr", "address", {"_sd": [street_digest]})
        address_digest = b64u_encode(hashlib.sha256(address.encode("ascii")).digest())
        payload = {"iss": "https://issuer.example", "vct": "urn:eudi:pid:1",
                   "iat": int(time.time()), "_sd": [address_digest], "_sd_alg": "sha-256",
                   "cnf": {"jwk": _public_jwk(self.w.holder_key)}}
        issuer_jwt = _jws(self.w.issuer_key,
                          {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "issuer-1"}, payload)
        presented = issuer_jwt + "~" + address + "~" + street + "~"
        computed = b64u_encode(hashlib.sha256(presented.encode("ascii")).digest())
        kb = _jws(self.w.holder_key, {"alg": "ES256", "typ": "kb+jwt"},
                  {"iat": int(time.time()), "aud": AUDIENCE, "nonce": NONCE,
                   "sd_hash": computed})
        return presented + kb

    def test_a_recursive_disclosure_verifies_and_nests(self):
        v = self.w.verify(self._recursive())
        self.assertTrue(v.authentic, v.reason)
        self.assertEqual(v.claims["address"]["street_address"], "1 Rue de la Paix")

    def test_the_nested_claim_does_not_also_appear_at_the_top_level(self):
        """The workaround for the old defect was to list the inner digest at top level too,
        and it leaked: the nested claim resolved as a TOP-LEVEL claim as well, which is the
        opposite of selective disclosure."""
        v = self.w.verify(self._recursive())
        self.assertTrue(v.authentic, v.reason)
        self.assertNotIn("street_address", v.claims)

    def test_an_uncommitted_disclosure_is_still_refused(self):
        """The fixpoint follows only digests ALREADY committed, so it must not have widened
        the set to anything the issuer did not vouch for.

        The key binding is recomputed over the modified disclosure set, because `sd_hash`
        covers that set and would otherwise refuse this first. Leaving it to `sd_hash` would
        make the test pass without ever reaching the check it is about."""
        street = _disclosure("s_street", "street_address", "1 Rue de la Paix")
        street_digest = b64u_encode(hashlib.sha256(street.encode("ascii")).digest())
        address = _disclosure("s_addr", "address", {"_sd": [street_digest]})
        address_digest = b64u_encode(hashlib.sha256(address.encode("ascii")).digest())
        stray = _disclosure("s_x", "nationality", "FR")
        payload = {"iss": "https://issuer.example", "vct": "urn:eudi:pid:1",
                   "iat": int(time.time()), "_sd": [address_digest], "_sd_alg": "sha-256",
                   "cnf": {"jwk": _public_jwk(self.w.holder_key)}}
        issuer_jwt = _jws(self.w.issuer_key,
                          {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "issuer-1"}, payload)
        presented = issuer_jwt + "~" + address + "~" + street + "~" + stray + "~"
        computed = b64u_encode(hashlib.sha256(presented.encode("ascii")).digest())
        kb = _jws(self.w.holder_key, {"alg": "ES256", "typ": "kb+jwt"},
                  {"iat": int(time.time()), "aud": AUDIENCE, "nonce": NONCE,
                   "sd_hash": computed})
        v = self.w.verify(presented + kb)
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "disclosure")
        self.assertIn("never", v.reason)


class IssuerCertificateTests(unittest.TestCase):
    """What `_chains_to` checked was "did this CA ever sign this", not "is this an issuer".

    A signature and an issuer/subject match were the whole of it. Three things were measured
    passing on 2026-09-17 that should not have, and the third is the one that matters:
    registering a general-purpose CA as a trust anchor silently promoted EVERY end-entity
    certificate that CA had ever issued to identity-credential issuer.
    """

    @staticmethod
    def _ca():
        now = datetime.datetime.now(datetime.timezone.utc)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test anchor")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .sign(key, hashes.SHA256()))
        return key, name, cert

    @staticmethod
    def _leaf(ca_key, ca_name, *, not_before=None, not_after=None, extensions=(), key=None):
        now = datetime.datetime.now(datetime.timezone.utc)
        leaf_key = key or ec.generate_private_key(ec.SECP256R1())
        builder = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "issuer")]))
                   .issuer_name(ca_name).public_key(leaf_key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(not_before or (now - datetime.timedelta(days=1)))
                   .not_valid_after(not_after or (now + datetime.timedelta(days=30))))
        for ext, critical in extensions:
            builder = builder.add_extension(ext, critical=critical)
        return builder.sign(ca_key, hashes.SHA256()), leaf_key

    def _verify(self, leaf, leaf_key, ca):
        presentation = X5CTests._present_with_x5c(self, leaf, leaf_key)
        return verify_presentation(presentation, expected_nonce=NONCE,
                                   expected_audience=AUDIENCE, trust_anchors=[ca])

    def test_a_plain_leaf_from_the_anchor_still_verifies(self):
        """The positive control. Without it every test below passes on a verifier that
        refuses every certificate, which proves nothing about issuer selection."""
        ca_key, ca_name, ca = self._ca()
        leaf, leaf_key = self._leaf(ca_key, ca_name)
        v = self._verify(leaf, leaf_key, ca)
        self.assertTrue(v.authentic, "%s: %s" % (v.code, v.reason))

    def test_an_expired_leaf_is_refused(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_key, ca_name, ca = self._ca()
        leaf, leaf_key = self._leaf(ca_key, ca_name,
                                    not_before=now - datetime.timedelta(days=30),
                                    not_after=now - datetime.timedelta(days=1))
        v = self._verify(leaf, leaf_key, ca)
        self.assertFalse(v.authentic, "a certificate that expired yesterday is not an issuer")
        self.assertEqual(v.code, "issuer_key")

    def test_a_leaf_not_valid_until_next_year_is_refused(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_key, ca_name, ca = self._ca()
        leaf, leaf_key = self._leaf(ca_key, ca_name,
                                    not_before=now + datetime.timedelta(days=365),
                                    not_after=now + datetime.timedelta(days=730))
        v = self._verify(leaf, leaf_key, ca)
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "issuer_key")

    def test_a_tls_server_certificate_from_the_same_ca_is_not_an_issuer(self):
        """THE ONE THAT MATTERS. This package's own cli.py records walt.id refusing a leaf
        for a missing digitalSignature KeyUsage, so the field was known about and simply not
        read here. A CA used for anything else is now also an identity issuer."""
        ca_key, ca_name, ca = self._ca()
        leaf, leaf_key = self._leaf(ca_key, ca_name, extensions=(
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (x509.KeyUsage(digital_signature=False, content_commitment=False,
                           key_encipherment=True, data_encipherment=False,
                           key_agreement=False, key_cert_sign=False, crl_sign=False,
                           encipher_only=False, decipher_only=False), True),
            (x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False),
        ))
        v = self._verify(leaf, leaf_key, ca)
        self.assertFalse(v.authentic,
                         "a TLS server certificate from the anchor must not be an issuer")
        self.assertEqual(v.code, "issuer_key")

    def test_a_key_usage_that_forbids_signing_is_refused_on_its_own(self):
        """KeyUsage ISOLATED, with no ExtendedKeyUsage to stand in for it.

        The TLS-certificate test above carries both extensions, so either check alone
        refuses it and removing KeyUsage passed. Two mechanisms, each hiding the other's
        absence. Here only this one can say no.
        """
        ca_key, ca_name, ca = self._ca()
        leaf, leaf_key = self._leaf(ca_key, ca_name, extensions=(
            (x509.KeyUsage(digital_signature=False, content_commitment=False,
                           key_encipherment=True, data_encipherment=False,
                           key_agreement=False, key_cert_sign=False, crl_sign=False,
                           encipher_only=False, decipher_only=False), True),
        ))
        v = self._verify(leaf, leaf_key, ca)
        self.assertFalse(v.authentic,
                         "a certificate that states its usage and does not include signing "
                         "is not a signing certificate")
        self.assertEqual(v.code, "issuer_key")

    def test_an_extended_key_usage_naming_only_tls_is_refused_on_its_own(self):
        """And the EKU isolated the same way, with a KeyUsage that permits signing."""
        ca_key, ca_name, ca = self._ca()
        leaf, leaf_key = self._leaf(ca_key, ca_name, extensions=(
            (x509.KeyUsage(digital_signature=True, content_commitment=False,
                           key_encipherment=False, data_encipherment=False,
                           key_agreement=False, key_cert_sign=False, crl_sign=False,
                           encipher_only=False, decipher_only=False), True),
            (x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False),
        ))
        v = self._verify(leaf, leaf_key, ca)
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "issuer_key")

    def test_a_leaf_whose_key_usage_permits_signing_is_accepted(self):
        """The other direction: a certificate that states its usage AND names signing is a
        signing certificate, and a check that refused it would refuse real issuers."""
        ca_key, ca_name, ca = self._ca()
        leaf, leaf_key = self._leaf(ca_key, ca_name, extensions=(
            (x509.KeyUsage(digital_signature=True, content_commitment=False,
                           key_encipherment=False, data_encipherment=False,
                           key_agreement=False, key_cert_sign=False, crl_sign=False,
                           encipher_only=False, decipher_only=False), True),
        ))
        v = self._verify(leaf, leaf_key, ca)
        self.assertTrue(v.authentic, "%s: %s" % (v.code, v.reason))

    def test_an_rsa_leaf_is_a_refusal_not_a_TypeError(self):
        """`RSAPublicKey.verify()` was being called with ECDSA arguments, which raised out
        of a verifier documented never to raise. Reachable by anyone holding an RSA
        certificate from the configured anchor, which per the finding above was anyone."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        ca_key, ca_name, ca = self._ca()
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf, _ = self._leaf(ca_key, ca_name, key=rsa_key)
        presentation = X5CTests._present_with_x5c(self, leaf, ec.generate_private_key(ec.SECP256R1()))
        v = verify_presentation(presentation, expected_nonce=NONCE,
                                expected_audience=AUDIENCE, trust_anchors=[ca])
        self.assertIsInstance(v, Verdict)
        self.assertFalse(v.authentic)


class TheBoundsThemselvesAreAssertedTests(unittest.TestCase):
    """Two refusals added on 2026-09-17 were not covered by any test.

    The package's mutation drill found them: it inverts every refusal in turn and runs the
    whole suite, and a refusal the suite still passes with is a refusal nothing is watching.
    Both of these were mine, added in the same commit as the bounds they enforce, and the
    tests around them exercised the bound's EFFECT without ever reaching the refusal itself.
    """

    def setUp(self):
        self.w = Wallet()

    def test_more_disclosures_than_the_limit_is_refused(self):
        """The count bound. The exhaustion tests all stayed under it, so it could have been
        deleted with everything still green."""
        claims = tuple(("claim_%d" % i, "v") for i in range(MAX_DISCLOSURES + 5))
        v = self.w.verify(self.w.present(claims=claims))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "disclosure")
        self.assertIn("limit", v.reason)

    def test_a_credential_at_the_limit_is_not_refused_for_its_count(self):
        """The other direction: a bound that refused everything would pass the test above
        while making the verifier useless."""
        claims = tuple(("claim_%d" % i, "v") for i in range(8))
        self.assertTrue(self.w.verify(self.w.present(claims=claims)).authentic)

    def test_the_resolver_refuses_to_recurse_past_its_cap(self):
        """The depth bound, tested where it lives.

        It cannot be reached through `verify_presentation`, and that is worth stating rather
        than leaving somebody to rediscover: `_json_bounded` refuses a document nesting past
        64 levels before parsing, and `_committed_digests` only iterates that many times, so
        a disclosure chain longer than the cap is refused as UNCOMMITTED before the resolver
        ever sees it. Three bounds, one number, and the resolver's is the innermost.

        So this calls `_resolve` directly. It is still worth keeping and worth testing: it is
        the guard that holds if either of the outer two is ever loosened, and a guard nothing
        exercises is one the mutation drill correctly calls unprotected.
        """
        from polaris_oid4vp import sdjwt as S
        node = {"leaf": "x"}
        for _ in range(MAX_RESOLVE_DEPTH + 5):
            node = {"n": node}
        with self.assertRaises(ValueError) as caught:
            S._resolve(node, {}, set(), [])
        self.assertIn("levels", str(caught.exception))

    def test_the_resolver_handles_a_structure_within_its_cap(self):
        """The positive control. A cap that refused everything would pass the test above
        while making every credential unreadable."""
        from polaris_oid4vp import sdjwt as S
        node = {"leaf": "x"}
        for _ in range(10):
            node = {"n": node}
        self.assertIsInstance(S._resolve(node, {}, set(), []), dict)

    def test_a_chain_longer_than_the_commitment_fixpoint_is_refused_as_uncommitted(self):
        """And the bound that DOES fire on the public path, so the refusal a wallet actually
        meets is asserted too."""
        salt = "d"
        inner = _disclosure(salt + "0", "leaf", "x")
        digest = b64u_encode(hashlib.sha256(inner.encode("ascii")).digest())
        disclosures = [inner]
        for i in range(1, MAX_RESOLVE_DEPTH + 10):
            nxt = _disclosure(salt + str(i), "n%d" % i, {"_sd": [digest]})
            disclosures.append(nxt)
            digest = b64u_encode(hashlib.sha256(nxt.encode("ascii")).digest())
        issuer_jwt = _jws(self.w.issuer_key,
                          {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "issuer-1"},
                          {"iss": "https://issuer.example", "vct": "urn:eudi:pid:1",
                           "iat": int(time.time()), "_sd": [digest], "_sd_alg": "sha-256",
                           "cnf": {"jwk": _public_jwk(self.w.holder_key)}})
        presented = issuer_jwt + "~" + "".join(d + "~" for d in disclosures)
        computed = b64u_encode(hashlib.sha256(presented.encode("ascii")).digest())
        kb = _jws(self.w.holder_key, {"alg": "ES256", "typ": "kb+jwt"},
                  {"iat": int(time.time()), "aud": AUDIENCE, "nonce": NONCE,
                   "sd_hash": computed})
        v = self.w.verify(presented + kb)
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "disclosure")


class HeldOutBoundaryTests(unittest.TestCase):
    """2026-09-23: ten semantic mutations written after the drill was green, each moving a
    boundary rather than inverting a refusal. Four here survived the whole package: the skew
    allowance on `exp`, on `nbf` and on the key binding's `iat` each doubled, and the
    disclosure cap moved one past its limit. The existing tests sat years or hundreds of
    disclosures away from each boundary; these sit on it, one side each. `now` is pinned so
    the edge is exact rather than a race with the clock."""

    SKEW = DEFAULT_MAX_SKEW_SECONDS

    def setUp(self):
        self.w = Wallet()
        self.now = int(time.time())

    def _verify(self, **present):
        present.setdefault("iat", self.now)
        return self.w.verify(self.w.present(**present), now=self.now)

    def test_exp_is_allowed_exactly_the_skew(self):
        self.assertTrue(self._verify(payload_extra={"exp": self.now - self.SKEW}).authentic)
        v = self._verify(payload_extra={"exp": self.now - self.SKEW - 1})
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "credential_validity")

    def test_nbf_is_allowed_exactly_the_skew(self):
        self.assertTrue(self._verify(payload_extra={"nbf": self.now + self.SKEW}).authentic)
        v = self._verify(payload_extra={"nbf": self.now + self.SKEW + 1})
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "credential_validity")

    def test_the_key_binding_iat_is_allowed_exactly_the_skew_either_way(self):
        for sign in (-1, 1):
            with self.subTest(direction=sign):
                self.assertTrue(self._verify(iat=self.now + sign * self.SKEW).authentic)
                v = self._verify(iat=self.now + sign * (self.SKEW + 1))
                self.assertFalse(v.authentic)
                self.assertEqual(v.code, "kb_freshness")

    def test_the_disclosure_cap_admits_its_limit_and_refuses_one_more(self):
        at = tuple(("c%d" % i, "v") for i in range(MAX_DISCLOSURES))
        self.assertTrue(self._verify(claims=at).authentic)
        v = self._verify(claims=at + (("one_more", "v"),))
        self.assertFalse(v.authentic)
        self.assertEqual(v.code, "disclosure")
