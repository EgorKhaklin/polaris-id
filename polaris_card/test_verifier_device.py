"""test_verifier_device.py - the device at the counter (roadmap P4.5).

The drill runs the device end to end under real signatures. What belongs here is the part that
is about the device's own bookkeeping rather than about cryptography: which challenges it
remembers, what it refuses to parse, and above all what it says it LEARNED, which is a separate
question from what it accepted.
"""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
try:
    from polaris_card import card_profile as cp, verifier_device as vd   # type: ignore
except ImportError:                      # pragma: no cover - the flat layout
    import card_profile as cp            # type: ignore
    import verifier_device as vd         # type: ignore


def _presentation(device, challenge=None, scope=None, card_object=None):
    return {"transport": "test", "scope": scope or device.scope,
            "challenge": challenge if challenge is not None else device.challenge(),
            "handle": b"\x11" * 32, "signature": b"\x22" * 64, "card_object": card_object}


class ChallengeTests(unittest.TestCase):
    def setUp(self):
        self.device = vd.VerifierDevice("counter-1")

    def test_a_device_needs_a_scope(self):
        # Without one its handles belong to nobody, and every device would see the same one.
        with self.assertRaises(ValueError):
            vd.VerifierDevice("")

    def test_challenges_are_fresh_and_long_enough(self):
        seen = {self.device.challenge() for _ in range(200)}
        self.assertEqual(len(seen), 200)
        for c in seen:
            self.assertEqual(len(c), vd.CHALLENGE_BYTES)

    def test_a_challenge_is_answered_once(self):
        # THE thing a signature cannot refuse: the signature over a challenge is perfectly
        # valid the second time, so only the device remembering it can refuse a replay.
        p = _presentation(self.device)
        first = self.device.decide(p, verify_response=lambda b, s: True,
                                   online_status={"status": "ACTIVE"})
        self.assertTrue(first["possession_proven"])
        second = self.device.decide(p, verify_response=lambda b, s: True,
                                    online_status={"status": "ACTIVE"})
        self.assertFalse(second["possession_proven"])
        self.assertIn("already been answered", second["note"])

    def test_a_challenge_this_device_never_issued_is_refused(self):
        p = _presentation(self.device, challenge=b"\x00" * vd.CHALLENGE_BYTES)
        v = self.device.decide(p, verify_response=lambda b, s: True)
        self.assertFalse(v["possession_proven"])
        self.assertIn("did not issue", v["note"])

    def test_a_presentation_for_another_scope_is_refused(self):
        p = _presentation(self.device, scope="somebody-else")
        v = self.device.decide(p, verify_response=lambda b, s: True)
        self.assertFalse(v["possession_proven"])
        self.assertIn("relayed", v["note"])

    def test_a_refused_scope_does_not_burn_the_challenge(self):
        # A relayed presentation must not let an attacker consume challenges the holder is
        # about to use, which would be a denial of service against the honest exchange.
        c = self.device.challenge()
        self.device.decide(_presentation(self.device, challenge=c, scope="elsewhere"),
                           verify_response=lambda b, s: True)
        v = self.device.decide(_presentation(self.device, challenge=c),
                               verify_response=lambda b, s: True,
                               online_status={"status": "ACTIVE"})
        self.assertTrue(v["possession_proven"])


class VerdictShapeTests(unittest.TestCase):
    def setUp(self):
        self.device = vd.VerifierDevice("counter-1")
        self.ok = lambda b, s: True

    def test_possession_alone_is_not_acceptance(self):
        # A card that was revoked this morning still signs.
        v = self.device.decide(_presentation(self.device), verify_response=self.ok)
        self.assertTrue(v["possession_proven"])
        self.assertFalse(v["accepted"])
        self.assertIn("still stands", v["note"])

    def test_the_three_facts_are_reported_separately(self):
        v = self.device.decide(_presentation(self.device), verify_response=self.ok,
                               online_status={"status": "ACTIVE"})
        for field in ("possession_proven", "card_authentic", "authorization_fresh"):
            self.assertIn(field, v)

    def test_authorization_without_a_card_object_does_not_accept(self):
        # The device never saw a signed object, so it has not established that this authority
        # issued this card.
        v = self.device.decide(_presentation(self.device), verify_response=self.ok,
                               online_status={"status": "ACTIVE"})
        self.assertFalse(v["accepted"])
        self.assertIsNone(v["card_authentic"])
        self.assertIn("never saw a signed card object", v["note"])

    def test_a_non_active_status_is_refused(self):
        for status in ("REVOKED", "EXPIRED", "SUSPENDED", None):
            with self.subTest(status=status):
                v = self.device.decide(_presentation(self.device), verify_response=self.ok,
                                       online_status={"status": status})
                self.assertFalse(v["accepted"])

    def test_a_response_that_does_not_verify_stops_there(self):
        v = self.device.decide(_presentation(self.device), verify_response=lambda b, s: False,
                               online_status={"status": "ACTIVE"})
        self.assertFalse(v["possession_proven"])
        self.assertIsNone(v["status"], "nothing downstream of possession should have run")

    def test_no_verifier_supplied_is_a_refusal_not_an_acceptance(self):
        v = self.device.decide(_presentation(self.device))
        self.assertFalse(v["accepted"])
        self.assertFalse(v["possession_proven"])

    def test_an_incomplete_presentation_is_refused(self):
        for missing in ("challenge", "handle", "signature", "scope"):
            with self.subTest(missing=missing):
                p = _presentation(self.device)
                p[missing] = None
                v = self.device.decide(p, verify_response=self.ok)
                self.assertFalse(v["accepted"])
                self.assertIn(missing, v["note"])


class LinkabilityTests(unittest.TestCase):
    """What the device says it LEARNED, which is not the same question as what it accepted."""

    def setUp(self):
        self.device = vd.VerifierDevice("counter-1")
        self.ok = lambda b, s: True

    def test_a_handle_only_read_stays_pairwise(self):
        v = self.device.decide(_presentation(self.device), verify_response=self.ok)
        self.assertEqual(v["linkability"], "pairwise")

    def test_an_online_check_that_names_the_credential_is_linkable(self):
        v = self.device.decide(_presentation(self.device), verify_response=self.ok,
                               online_status={"status": "ACTIVE", "token_value": "TOK-1"})
        self.assertEqual(v["linkability"], "credential-linkable")

    def test_a_status_assertion_is_linkable_even_when_it_FAILS(self):
        # The ordering is the point. The device read the token value off the assertion the
        # moment it held it; a failed verification does not un-disclose an identifier, and a
        # verdict that reported linkability only on success would be accounting for what the
        # device accepted rather than for what it learned.
        v = self.device.decide(
            _presentation(self.device), verify_response=self.ok,
            status_assertion={"token_value": "TOK-1", "status": "ACTIVE"},
            verify_status_assertion=lambda a, now=None, max_window_seconds=None: {
                "status_authentic": False, "note": "nope"})
        self.assertFalse(v["accepted"])
        self.assertEqual(v["linkability"], "credential-linkable")

    def test_nothing_established_is_unknown_rather_than_pairwise(self):
        v = self.device.decide(_presentation(self.device), verify_response=lambda b, s: False)
        self.assertEqual(v["linkability"], "unknown")


class QrTests(unittest.TestCase):
    def setUp(self):
        self.device = vd.VerifierDevice("kiosk-1")

    def test_the_request_carries_the_scope_and_a_fresh_challenge(self):
        text, challenge = self.device.qr_request()
        prefix, scope, _ = text.split(":")
        self.assertEqual(prefix, vd.QR_REQUEST_PREFIX)
        self.assertEqual(scope, "kiosk-1")
        self.assertEqual(len(challenge), vd.CHALLENGE_BYTES)
        self.assertNotEqual(self.device.qr_request()[1], challenge)

    def test_a_response_round_trips(self):
        _, challenge = self.device.qr_request()
        text = vd.qr_response(challenge, b"\x11" * 32, b"\x22" * 64, b"\x33" * 40)
        parsed = self.device.read_qr(text)
        self.assertEqual(parsed["challenge"], challenge)
        self.assertEqual(parsed["handle"], b"\x11" * 32)
        self.assertEqual(parsed["signature"], b"\x22" * 64)
        self.assertEqual(parsed["card_object"], b"\x33" * 40)
        self.assertEqual(parsed["scope"], "kiosk-1")

    def test_a_response_without_a_card_object_parses(self):
        _, challenge = self.device.qr_request()
        parsed = self.device.read_qr(vd.qr_response(challenge, b"\x11" * 32, b"\x22" * 64))
        self.assertIsNone(parsed["card_object"])

    def test_junk_is_refused_rather_than_parsed(self):
        for junk in ("", "hello", "PCR1", "PCR1:", "PCR1:a:b", "PCQ1:x:y:z",
                     "PCR1:!!!:x:y", "PCR1:a:b:c:d:e", "\x00" * 20):
            with self.subTest(junk=junk[:10]), self.assertRaises(vd.DeviceRefusal):
                self.device.read_qr(junk)

    def test_a_non_string_payload_is_refused(self):
        for junk in (None, 42, b"PCR1:a:b:c", ["PCR1"]):
            with self.subTest(junk=junk), self.assertRaises(vd.DeviceRefusal):
                self.device.read_qr(junk)


class QrCapacityTests(unittest.TestCase):
    """The measurement that decides the protocol rather than decorating it."""

    def test_a_presentation_fits_easily(self):
        report = vd.qr_capacity_report({})
        self.assertTrue(report["presentation_only"]["fits"])
        self.assertLess(report["presentation_only"]["chars"], vd.QR_PRACTICAL_CHARS // 2)

    def test_a_classical_card_object_fits(self):
        report = vd.qr_capacity_report({"classical": 237})
        self.assertTrue(report["classical"]["fits"])

    def test_a_post_quantum_card_object_does_not_fit_at_any_qr_version(self):
        # Not "it is tight": it is past the absolute maximum a version-40 code holds. A device
        # that needs post-quantum authenticity needs NFC.
        report = vd.qr_capacity_report({"dual": 5504})
        self.assertFalse(report["dual"]["fits"])
        self.assertFalse(report["dual"]["fits_absolute_max"])
        self.assertGreater(report["dual"]["chars"], vd.QR_MAX_ALPHANUMERIC)

    def test_the_report_measures_rather_than_asserts(self):
        # The numbers come from encoding, so they move if the encoding does.
        small = vd.qr_capacity_report({"x": 100})["x"]["chars"]
        large = vd.qr_capacity_report({"x": 1000})["x"]["chars"]
        self.assertGreater(large, small)
        self.assertGreater(large - small, 1000)   # base64url expands, it does not shrink


class ResponseBindingTests(unittest.TestCase):
    def test_the_body_the_device_checks_is_the_profile_body(self):
        # The device must not invent its own idea of what the card signed.
        device = vd.VerifierDevice("counter-1")
        seen = {}

        def capture(body, signature):
            seen["body"] = body
            return True
        p = _presentation(device)
        device.decide(p, verify_response=capture, online_status={"status": "ACTIVE"})
        self.assertEqual(seen["body"],
                         cp.response_body(p["challenge"], p["scope"], p["handle"]))


if __name__ == "__main__":
    unittest.main()
