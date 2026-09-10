"""test_card_profile.py - the card profile's own suite (roadmap P4.1).

Two jobs. Prove the encoder and decoder agree with the PUBLISHED VECTORS, because an
implementer who is not running this code has nothing else to check against. And prove the
refusals, since a profile is defined as much by what it will not accept as by what it encodes.
"""
import json
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
# Imported the same way emulator.py imports it, and in the same ORDER. Under discovery from
# the repo root `polaris_card` is a package, so a flat `import card_profile` here beside a
# packaged import there would bind TWO module objects with two distinct CardProfileError
# classes, and assertRaises would stop catching what the code raises.
try:
    from polaris_card import card_profile as cp   # type: ignore  # noqa: E402
except ImportError:                               # pragma: no cover - the flat layout
    import card_profile as cp                     # type: ignore  # noqa: E402

VECTORS = os.path.join(_HERE, "vectors", "card-objects.json")


def _fields_from_vector(case):
    out = {}
    for name, value in case["fields"].items():
        tag = cp.NAME_TO_TAG[name]
        out[name] = bytes.fromhex(value) if isinstance(value, str) and tag not in (
            cp.TAG_DOC_TYPE,) else value
    return out


class PublishedVectorTests(unittest.TestCase):
    """The vectors are the contract. If this suite and the file disagree, one of them is a bug
    that would otherwise be discovered by an implementer writing an applet in C."""

    @classmethod
    def setUpClass(cls):
        with open(VECTORS) as fh:
            cls.doc = json.load(fh)

    def test_the_vectors_cover_the_profile_the_code_implements(self):
        self.assertEqual(self.doc["profile"], cp.DOC_TYPE)
        self.assertEqual(self.doc["profile_version"], cp.PROFILE_VERSION)

    def test_every_vector_decodes_and_re_encodes_to_the_same_bytes(self):
        for case in self.doc["cases"]:
            with self.subTest(case["name"]):
                blob = bytes.fromhex(case["card_object_hex"])
                fields = cp.decode(blob)
                self.assertEqual(cp.encode(fields), blob,
                                 "the encoding must be the only one for this content")

    def test_every_vector_reproduces_its_signing_body_and_digest(self):
        # The half an implementer actually has to match: what is signed.
        for case in self.doc["cases"]:
            with self.subTest(case["name"]):
                fields = cp.decode(bytes.fromhex(case["card_object_hex"]))
                self.assertEqual(cp.signing_body(fields).hex(), case["signing_body_hex"])
                self.assertEqual(cp.signing_digest(fields).hex(), case["signing_digest_hex"])

    def test_the_signing_body_excludes_the_signatures(self):
        for case in self.doc["cases"]:
            with self.subTest(case["name"]):
                body = bytes.fromhex(case["signing_body_hex"])
                # The body decodes on its own and carries no signature field at all: what is
                # signed is the card minus its signatures, and nothing else.
                self.assertEqual(set(cp.decode(body)) & set(cp.SIGNATURE_TAGS.values()), set())
                fields = cp.decode(bytes.fromhex(case["card_object_hex"]))
                stripped = {k: v for k, v in fields.items() if k in cp.BODY_TAGS.values()}
                self.assertEqual(cp.encode(stripped), body)

    def test_both_signatures_cover_the_same_bytes(self):
        # If each covered the other, only the second written could be verified independently.
        dual = [c for c in self.doc["cases"] if c["name"] == "dual-signature"][0]
        fields = cp.decode(bytes.fromhex(dual["card_object_hex"]))
        self.assertIn("issuer_sig_classical", fields)
        self.assertIn("issuer_sig_pq", fields)
        classical_only = dict(fields); classical_only.pop("issuer_sig_pq")
        self.assertEqual(cp.signing_digest(fields), cp.signing_digest(classical_only))


class EncodingRefusalTests(unittest.TestCase):
    def _good(self):
        return cp.decode(cp.build_card(
            token_value="TOK", issuing_authority=1, activation_sequence=1,
            issued_at=1_757_000_000, expires_at=1_914_766_400,
            card_key_classical=bytes(cp.CLASSICAL_KEY_LEN),
            sign_classical=lambda d: b"\x01" * 71))

    def test_the_record_does_not_go_on_the_card(self):
        for field in ("token_value", "legal_name", "date_of_birth", "biometric",
                      "duress_code_hash", "physical_serial"):
            with self.subTest(field):
                fields = dict(self._good()); fields[field] = "x"
                with self.assertRaises(cp.CardProfileError) as ctx:
                    cp.encode(fields)
                self.assertIn("refusing to put", str(ctx.exception),
                              "it must be refused for being FORBIDDEN, not for being unknown")

    def test_an_unknown_field_is_refused_rather_than_dropped(self):
        fields = dict(self._good()); fields["favourite_colour"] = "x"
        with self.assertRaises(cp.CardProfileError):
            cp.encode(fields)

    def test_a_repeated_tag_is_refused(self):
        blob = cp.encode(self._good())
        with self.assertRaises(cp.CardProfileError):
            cp.decode(blob + blob[:3 + 1])

    def test_tags_out_of_order_are_refused(self):
        a = cp.encode(self._good())
        # Swap the first two records so the tags descend.
        first_len = 3 + int.from_bytes(a[1:3], "big")
        second_len = 3 + int.from_bytes(a[first_len + 1:first_len + 3], "big")
        swapped = a[first_len:first_len + second_len] + a[:first_len] + a[first_len + second_len:]
        with self.assertRaises(cp.CardProfileError) as ctx:
            cp.decode(swapped)
        self.assertIn("order", str(ctx.exception))

    def test_an_unknown_tag_is_refused_rather_than_skipped(self):
        # A reader that skipped what it did not recognise would verify a signature over bytes
        # it never looked at.
        blob = cp.encode(self._good()) + bytes([0x7F, 0x00, 0x02]) + b"hi"
        with self.assertRaises(cp.CardProfileError):
            cp.decode(blob)

    def test_truncation_is_refused(self):
        blob = cp.encode(self._good())
        for cut in (1, 2, 5, len(blob) - 1):
            with self.subTest(cut=cut), self.assertRaises(cp.CardProfileError):
                cp.decode(blob[:cut])

    def test_a_wrong_doc_type_or_version_is_refused(self):
        fields = dict(self._good()); fields["doc_type"] = "org.iso.18013.5.1.mDL"
        with self.assertRaises(cp.CardProfileError):
            cp.decode(cp.encode(fields))
        fields = dict(self._good()); fields["profile_version"] = 2
        with self.assertRaises(cp.CardProfileError) as ctx:
            cp.decode(cp.encode(fields))
        self.assertIn("refusing rather than guessing", str(ctx.exception))

    def test_a_key_of_the_wrong_length_is_a_parse_failure(self):
        fields = dict(self._good()); fields["card_key_classical"] = bytes(64)
        with self.assertRaises(cp.CardProfileError):
            cp.decode(cp.encode(fields))

    def test_a_card_without_a_signature_is_refused_at_build(self):
        with self.assertRaises(cp.CardProfileError):
            cp.build_card(token_value="T", issuing_authority=1, activation_sequence=1,
                          issued_at=1, expires_at=2,
                          card_key_classical=bytes(cp.CLASSICAL_KEY_LEN))


class VerdictTests(unittest.TestCase):
    def _card(self, pq=False):
        kw = dict(token_value="TOK", issuing_authority=1, activation_sequence=1,
                  issued_at=1_757_000_000, expires_at=1_914_766_400,
                  card_key_classical=bytes(cp.CLASSICAL_KEY_LEN),
                  sign_classical=lambda d: b"\x01" * 71)
        if pq:
            kw["card_key_pq"] = bytes(cp.PQ_KEY_LEN)
            kw["sign_pq"] = lambda d: b"\x02" * 3309
        return cp.build_card(**kw)

    def test_a_good_card_is_authentic(self):
        v = cp.verify_card(self._card(), verify_classical=lambda d, s: True, now=1_757_000_001)
        self.assertTrue(v["authentic"])
        self.assertTrue(v["unexpired"])

    def test_garbage_gets_a_verdict_not_an_exception(self):
        for blob in (b"", b"\x00", b"\xff" * 40, bytes(range(256))):
            with self.subTest(blob=blob[:4]):
                v = cp.verify_card(blob, verify_classical=lambda d, s: True)
                self.assertFalse(v["authentic"])
                self.assertIsNotNone(v["note"])

    def test_both_signatures_must_verify_when_both_are_present(self):
        # The anti-downgrade rule. Accept-if-either hands the scheme to whoever breaks the
        # weaker algorithm first, which is the entire reason the card carries two.
        v = cp.verify_card(self._card(pq=True), verify_classical=lambda d, s: True,
                           verify_pq=lambda d, s: False)
        self.assertFalse(v["authentic"])
        self.assertIn("Both must verify", v["note"])
        v = cp.verify_card(self._card(pq=True), verify_classical=lambda d, s: False,
                           verify_pq=lambda d, s: True)
        self.assertFalse(v["authentic"])

    def test_a_pq_requiring_verifier_refuses_a_classical_only_card(self):
        v = cp.verify_card(self._card(), verify_classical=lambda d, s: True, require_pq=True)
        self.assertFalse(v["authentic"])
        self.assertIn("post-quantum", v["note"])
        # ...and accepts the transitional card.
        v = cp.verify_card(self._card(pq=True), verify_classical=lambda d, s: True,
                           verify_pq=lambda d, s: True, require_pq=True)
        self.assertTrue(v["authentic"])

    def test_an_expired_card_is_refused(self):
        v = cp.verify_card(self._card(), verify_classical=lambda d, s: True,
                           now=2_000_000_000)
        self.assertFalse(v["authentic"])
        self.assertFalse(v["unexpired"])

    def test_a_tampered_body_changes_the_digest(self):
        blob = self._card()
        fields = cp.decode(blob)
        fields["activation_sequence"] = 2
        self.assertNotEqual(cp.signing_digest(fields), cp.signing_digest(cp.decode(blob)))

    def test_the_verdict_never_carries_a_signature_field(self):
        # The verdict is what a reader learned, not a copy of the card.
        v = cp.verify_card(self._card(pq=True), verify_classical=lambda d, s: True,
                           verify_pq=lambda d, s: True)
        self.assertNotIn("issuer_sig_classical", v["fields"])
        self.assertNotIn("issuer_sig_pq", v["fields"])


class PresentationTests(unittest.TestCase):
    def test_two_readers_cannot_link_one_card(self):
        secret = b"\x11" * 32
        a = cp.pairwise_handle(secret, "reader-a")
        b = cp.pairwise_handle(secret, "reader-b")
        self.assertNotEqual(a, b)
        self.assertEqual(a, cp.pairwise_handle(secret, "reader-a"),
                         "one reader must recognise the same card twice")

    def test_two_cards_do_not_collide_at_one_reader(self):
        self.assertNotEqual(cp.pairwise_handle(b"\x11" * 32, "r"),
                            cp.pairwise_handle(b"\x22" * 32, "r"))

    def test_the_credential_reference_is_not_the_credential(self):
        ref = cp.credential_ref("POLARIS-TOKEN-0001")
        self.assertEqual(len(ref), 32)
        self.assertNotIn(b"POLARIS", ref)
        self.assertEqual(ref, cp.credential_ref("POLARIS-TOKEN-0001"))
        self.assertNotEqual(ref, cp.credential_ref("POLARIS-TOKEN-0002"))

    def test_the_response_binds_the_challenge_the_scope_and_the_handle(self):
        h = cp.pairwise_handle(b"\x11" * 32, "reader-a")
        base = cp.response_body(b"\x00" * 16, "reader-a", h)
        self.assertNotEqual(base, cp.response_body(b"\x01" * 16, "reader-a", h))
        self.assertNotEqual(base, cp.response_body(b"\x00" * 16, "reader-b", h))
        self.assertNotEqual(base, cp.response_body(b"\x00" * 16, "reader-a", b"\x00" * 32))

    def test_a_short_challenge_is_refused(self):
        # A challenge an attacker can wait to see again is not a challenge.
        with self.assertRaises(cp.CardProfileError):
            cp.response_body(b"\x00" * 8, "reader-a", bytes(32))

    def test_the_scope_cannot_be_shifted_by_a_length_trick(self):
        # Length-prefixed, so "ab"+"c" and "a"+"bc" are different bodies.
        h = bytes(32)
        self.assertNotEqual(cp.response_body(b"\x00" * 16, "ab", h),
                            cp.response_body(b"\x00" * 16 + b"a", "b", h))


if __name__ == "__main__":
    unittest.main()
