"""test_emulator.py - the software token's behaviour (roadmap P4.2).

The profile suite proves what is on a card. This proves what a card DOES: what it answers
before a PIN, how the retry counter moves, what a blocked card says, and above all that a
coercer watching the reader cannot tell which PIN was entered.

That last one is the reason this file is careful about response LENGTH. An ECDSA signature is
DER, so its length varies by a byte or two per signature. Asserting that one duress response
happens to be the same length as one normal response would be a coincidence dressed as a
property. What is actually true, and what is asserted here, is that both slots draw from the
same distribution of lengths: the variation is a property of ECDSA, not of which slot signed.
"""
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
try:
    from polaris_card import emulator as em       # type: ignore  # noqa: E402
except ImportError:                               # pragma: no cover - the flat layout
    import emulator as em                         # type: ignore  # noqa: E402


def _crypto():
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


class TokenTestCase(unittest.TestCase):
    def setUp(self):
        if not _crypto():
            self.skipTest("the software token needs cryptography for its P-256 slots")
        self.token, self.detail = em.new_software_token()

    def _select(self):
        return self.token.transmit(em.select())

    def _pin(self, pin):
        return self.token.transmit(em.verify_pin(pin))

    def _sign(self, scope="reader-a", challenge=None):
        return self.token.transmit(em.sign_challenge(scope, challenge or b"\x01" * 32))


class BeforeAuthenticationTests(TokenTestCase):
    def test_nothing_answers_before_select(self):
        # A card that answered before SELECT would let a reader skip the step that says which
        # application it is talking to.
        for command in (em.verify_pin("1234"), em.get_card_object(),
                        em.sign_challenge("r", b"\x00" * 32)):
            with self.subTest(ins=command[1]):
                self.assertEqual(em.status_word(self.token.transmit(command)),
                                 em.SW_CONDITIONS_NOT_SATISFIED)

    def test_select_announces_the_profile_and_the_tries_left(self):
        r = self._select()
        self.assertTrue(em.is_ok(r))
        body = em.payload(r)
        self.assertTrue(body.startswith(cp.DOC_TYPE.encode()))
        self.assertEqual(body[-2], cp.PROFILE_VERSION)
        self.assertEqual(body[-1], em.MAX_PIN_TRIES)

    def test_the_card_signs_nothing_before_a_pin(self):
        self._select()
        self.assertEqual(em.status_word(self._sign()), em.SW_SECURITY_NOT_SATISFIED)
        self.assertEqual(em.status_word(self.token.transmit(em.get_card_object())),
                         em.SW_SECURITY_NOT_SATISFIED)

    def test_select_drops_a_previous_authentication(self):
        self._select(); self._pin("1234")
        self.assertTrue(em.is_ok(self._sign()))
        self._select()
        self.assertEqual(em.status_word(self._sign()), em.SW_SECURITY_NOT_SATISFIED)

    def test_a_malformed_command_gets_a_status_word_not_a_crash(self):
        # Half of what a reader is written against is what happens when it gets it wrong.
        for junk in (b"", b"\x80", b"\x80\x20", b"\x00\x00\x00\x00", b"\x80\x20\x00\x80\xff",
                     bytes(range(256)), os.urandom(64)):
            with self.subTest(junk=junk[:4]):
                r = self.token.transmit(junk)
                self.assertGreaterEqual(len(r), 2)
                self.assertNotEqual(em.status_word(r), em.SW_OK)

    def test_a_foreign_class_byte_is_refused(self):
        self.assertEqual(em.status_word(self.token.transmit(b"\x00\xa4\x04\x00\x00")),
                         em.SW_CLA_NOT_SUPPORTED)

    def test_an_unsupported_instruction_is_refused(self):
        self._select()
        self.assertEqual(em.status_word(self.token.transmit(bytes([em.CLA, 0xFE, 0, 0, 0]))),
                         em.SW_INS_NOT_SUPPORTED)


class PinTests(TokenTestCase):
    def test_a_wrong_pin_decrements_and_announces_the_count(self):
        self._select()
        for expected in (2, 1):
            sw = em.status_word(self._pin("0000"))
            self.assertEqual(em.tries_left(sw), expected)

    def test_three_wrong_pins_block_the_card(self):
        self._select()
        self._pin("0000"); self._pin("0000")
        self.assertEqual(em.status_word(self._pin("0000")), em.SW_BLOCKED)
        self.assertTrue(self.token.blocked)

    def test_a_blocked_card_refuses_the_CORRECT_pin_identically(self):
        # And identically for both correct PINs, or being blocked would leak which is which.
        self._select()
        for _ in range(em.MAX_PIN_TRIES):
            self._pin("0000")
        self.assertEqual(em.status_word(self._pin("1234")), em.SW_BLOCKED)
        self.assertEqual(em.status_word(self._pin("9999")), em.SW_BLOCKED)

    def test_the_counter_survives_a_power_cycle(self):
        # A counter that reset on power cycle would make a wrong PIN free to retry forever.
        self._select(); self._pin("0000")
        self.token.reset()
        self._select()
        self.assertEqual(em.tries_left(em.status_word(self._pin("0000"))), 1)

    def test_the_puk_unblocks_and_a_wrong_puk_does_not(self):
        self._select()
        for _ in range(em.MAX_PIN_TRIES):
            self._pin("0000")
        self.assertEqual(em.status_word(self.token.transmit(em.unblock("00000000"))),
                         em.SW_WRONG_PIN | (em.MAX_PUK_TRIES - 1))
        self.assertTrue(self.token.blocked)
        self.assertTrue(em.is_ok(self.token.transmit(em.unblock("12345678"))))
        self.assertFalse(self.token.blocked)
        self.assertTrue(em.is_ok(self._pin("1234")))

    def test_a_card_refuses_a_duress_pin_equal_to_the_normal_one(self):
        with self.assertRaises(ValueError):
            em.SoftwareToken(card_object=self.detail["card_object"], normal_pin="1234",
                             duress_pin="1234", puk="1", slot_secret_normal=b"\x00" * 32,
                             slot_secret_duress=b"\x01" * 32)

    def test_a_duress_pin_without_its_own_slot_is_refused(self):
        with self.assertRaises(ValueError):
            em.SoftwareToken(card_object=self.detail["card_object"], normal_pin="1234",
                             duress_pin="9999", puk="1", slot_secret_normal=b"\x00" * 32)


class DuressIndistinguishabilityTests(TokenTestCase):
    """The property the whole class exists to hold. Every assertion here is about what a
    coercer standing at the reader can observe."""

    def test_both_pins_unlock_with_the_same_status_word(self):
        self._select()
        self.assertEqual(em.status_word(self._pin("1234")), em.SW_OK)
        self._select()
        self.assertEqual(em.status_word(self._pin("9999")), em.SW_OK)

    def test_the_duress_pin_resets_the_counter_exactly_as_the_normal_one_does(self):
        # A duress PIN that left the counter alone would announce itself on the NEXT wrong
        # attempt, which is the sort of leak that only shows up two commands later.
        def counter_after(correct_pin):
            token, _ = em.new_software_token()
            token.transmit(em.select())
            token.transmit(em.verify_pin("0000"))
            token.transmit(em.verify_pin(correct_pin))
            token.transmit(em.verify_pin("0000"))
            return em.tries_left(em.status_word(token.transmit(em.verify_pin("0000"))))
        self.assertEqual(counter_after("1234"), counter_after("9999"))

    def test_a_duress_response_is_structurally_identical(self):
        def respond(pin):
            self._select(); self._pin(pin)
            r = self._sign()
            return em.status_word(r), em.parse_signed_response(r)
        n_sw, (n_handle, n_sig) = respond("1234")
        d_sw, (d_handle, d_sig) = respond("9999")
        self.assertEqual(n_sw, d_sw)
        self.assertEqual(len(n_handle), len(d_handle))
        self.assertNotEqual(n_handle, d_handle,
                            "the AUTHORITY must be able to tell them apart, even though the "
                            "coercer cannot")
        self.assertNotEqual(n_sig, d_sig)

    def test_every_response_is_exactly_the_same_length(self):
        # EXACT, not statistical. The card emits a fixed-length raw signature, as a secure
        # element does, so there is one response length and it carries no information. An
        # earlier version of this emulator emitted DER, whose length varies by a byte or two
        # per signature; that made this property something you could only sample for, and a
        # sampled indistinguishability claim is not one.
        def lengths(pin, trials=40):
            seen = set()
            for i in range(trials):
                token, _ = em.new_software_token()
                token.transmit(em.select()); token.transmit(em.verify_pin(pin))
                seen.add(len(token.transmit(em.sign_challenge("reader-a", bytes([i]) * 32))))
            return seen
        normal, duress = lengths("1234"), lengths("9999")
        self.assertEqual(len(normal), 1, "the response length must not vary at all")
        self.assertEqual(normal, duress,
                         "and it must be the same length for both slots")

    def test_a_duress_pin_of_a_different_length_is_refused(self):
        # The PIN travels in the command's data field, so its length is on the wire: a
        # six-digit duress PIN beside a four-digit normal one announces which was entered
        # without anyone needing to see the keypad.
        with self.assertRaises(ValueError):
            em.SoftwareToken(card_object=self.detail["card_object"], normal_pin="1234",
                             duress_pin="999999", puk="1", slot_secret_normal=b"\x00" * 32,
                             slot_secret_duress=b"\x01" * 32)

    def test_the_duress_key_is_not_on_the_card(self):
        # Carrying it would make the existence of a duress PIN readable off the card.
        self._select(); self._pin("1234")
        card = em.payload(self.token.transmit(em.get_card_object()))
        self.assertNotIn(self.detail["slot_public"]["duress"], card)
        self.assertIn(self.detail["slot_public"]["normal"], card)
        self.assertNotIn(b"duress", card.lower())


class PresentationTests(TokenTestCase):
    def test_the_signature_verifies_under_the_slot_the_authority_registered(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
        import hashlib
        self._select(); self._pin("1234")
        challenge = os.urandom(32)
        handle, sig = em.parse_signed_response(self._sign("reader-a", challenge))
        body = cp.response_body(challenge, "reader-a", handle)
        pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), self.detail["slot_public"]["normal"])
        # The card emits raw r||s, as a secure element does; the reader wraps it.
        self.assertEqual(len(sig), em.RAW_SIGNATURE_LEN)
        pub.verify(em.der_from_raw(sig), hashlib.sha256(body).digest(),
                   ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))

    def test_the_authority_can_tell_a_duress_presentation_apart(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
        import hashlib
        self._select(); self._pin("9999")
        challenge = os.urandom(32)
        handle, sig = em.parse_signed_response(self._sign("reader-a", challenge))
        digest = hashlib.sha256(cp.response_body(challenge, "reader-a", handle)).digest()
        alg = ec.ECDSA(asym_utils.Prehashed(hashes.SHA256()))
        duress_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), self.detail["slot_public"]["duress"])
        der = em.der_from_raw(sig)
        duress_pub.verify(der, digest, alg)     # the authority holds this key
        normal_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), self.detail["slot_public"]["normal"])
        with self.assertRaises(Exception):
            normal_pub.verify(der, digest, alg)

    def test_two_readers_cannot_link_one_card(self):
        self._select(); self._pin("1234")
        a = em.parse_signed_response(self._sign("reader-a"))[0]
        b = em.parse_signed_response(self._sign("reader-b"))[0]
        self.assertNotEqual(a, b)
        self.assertEqual(a, em.parse_signed_response(self._sign("reader-a"))[0],
                         "one reader must recognise the same card twice")

    def test_a_short_challenge_is_refused_by_the_CARD(self):
        # A card that signed anything a reader asked for would be an oracle.
        self._select(); self._pin("1234")
        self.assertEqual(em.status_word(self._sign("reader-a", b"\x00" * 8)),
                         em.SW_WRONG_DATA)

    def test_the_response_is_bound_to_the_challenge(self):
        self._select(); self._pin("1234")
        one = em.parse_signed_response(self._sign("reader-a", b"\x01" * 32))[1]
        two = em.parse_signed_response(self._sign("reader-a", b"\x02" * 32))[1]
        self.assertNotEqual(one, two, "a response that ignored the challenge would replay")

    def test_the_card_object_the_card_presents_is_the_one_it_was_given(self):
        self._select(); self._pin("1234")
        self.assertEqual(em.payload(self.token.transmit(em.get_card_object())),
                         self.detail["card_object"])
        cp.decode(self.detail["card_object"])   # and it is a valid object

    def test_a_card_object_the_profile_refuses_cannot_be_loaded(self):
        with self.assertRaises(cp.CardProfileError):
            em.SoftwareToken(card_object=b"\xff" * 40, normal_pin="1", puk="1",
                             slot_secret_normal=b"\x00" * 32)


if __name__ == "__main__":
    unittest.main()


class PublishedApduVectorTests(TokenTestCase):
    """The APDU contract, walked against the real emulator.

    An implementer writing a reader has this file and nothing else. If the session it
    describes and the card's actual answers diverge, the file is a lie in the shape of a
    specification, so the divergence has to fail here rather than in somebody's lab."""

    @classmethod
    def setUpClass(cls):
        import json
        with open(os.path.join(_HERE, "vectors", "apdu-exchanges.json")) as fh:
            cls.doc = json.load(fh)

    def test_every_published_command_is_what_the_builder_emits(self):
        built = {
            "select": em.select(),
            "verify_pin": em.verify_pin("1234"),
            "unblock": em.unblock("12345678"),
            "get_card_object": em.get_card_object(),
        }
        for entry in self.doc["commands"]:
            if entry["name"] in built:
                with self.subTest(entry["name"]):
                    self.assertEqual(entry["apdu_hex"], built[entry["name"]].hex())

    def test_the_published_sign_command_matches_its_published_challenge(self):
        body = self.doc["response_body"]
        challenge = bytes.fromhex(body["challenge_hex"])
        entry = [c for c in self.doc["commands"] if c["name"] == "sign_challenge"][0]
        self.assertEqual(entry["apdu_hex"],
                         em.sign_challenge(body["reader_scope"], challenge).hex())

    def test_the_published_response_body_is_what_the_card_signs(self):
        body = self.doc["response_body"]
        self.assertEqual(
            cp.response_body(bytes.fromhex(body["challenge_hex"]), body["reader_scope"],
                             bytes.fromhex(body["handle_hex"])).hex(),
            body["response_body_hex"])

    def test_the_class_byte_is_the_published_one(self):
        self.assertEqual(self.doc["class_byte"], "%02x" % em.CLA)
        self.assertEqual(self.doc["profile"], cp.DOC_TYPE)

    def test_the_published_session_is_the_session_the_card_walks(self):
        # Step by step, in order, against a real token.
        steps = [(s["step"], s["sw"]) for s in self.doc["session"]]
        expected = [
            ("select", em.status_word(self.token.transmit(em.select()))),
            ("sign_challenge", em.status_word(self._sign())),
            ("verify_pin (wrong)", em.status_word(self._pin("0000"))),
            ("verify_pin (wrong)", em.status_word(self._pin("0000"))),
            ("verify_pin (wrong)", em.status_word(self._pin("0000"))),
            ("verify_pin (correct)", em.status_word(self._pin("1234"))),
            ("unblock (correct PUK)", em.status_word(self.token.transmit(em.unblock("12345678")))),
            ("verify_pin (normal or duress)", em.status_word(self._pin("9999"))),
            ("sign_challenge", em.status_word(self._sign())),
        ]
        self.assertEqual(len(steps), len(expected),
                         "the published session and the walked one must have the same steps")
        for (pub_step, pub_sw), (step, sw) in zip(steps, expected):
            with self.subTest(step=step):
                self.assertEqual(pub_step, step)
                self.assertEqual(pub_sw, "%04x" % sw,
                                 "the published status word must be the one the card returns")

    def test_the_published_status_words_are_the_ones_the_card_uses(self):
        published = set(self.doc["status_words"])
        for sw in (em.SW_OK, em.SW_SECURITY_NOT_SATISFIED, em.SW_BLOCKED,
                   em.SW_CONDITIONS_NOT_SATISFIED, em.SW_WRONG_DATA,
                   em.SW_INS_NOT_SUPPORTED, em.SW_CLA_NOT_SUPPORTED):
            with self.subTest(sw=hex(sw)):
                self.assertIn("%04x" % sw, published)
        self.assertIn("63cX", published, "the retry-count family must be documented")
