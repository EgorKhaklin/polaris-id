"""test_relying_party.py — the relying-party verifier (holder<->verifier flow, PE follow-up).

Drives the decision logic of scripts/polaris-relying-party.py with injected
authenticity and status verdicts (no crypto, no server), so the ACCEPT/REJECT/
PROVISIONAL combinations and the duress-deniability property are covered in the
suite. The full real-ML-DSA issue->pack->wallet->relying-party flow runs where
liboqs and a database are present."""
import importlib.util
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def _load_rp():
    spec = importlib.util.spec_from_file_location(
        "polaris_relying_party", os.path.join(_HERE, "polaris-relying-party.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class RelyingPartyDecisionTests(unittest.TestCase):
    def setUp(self):
        self.rp = _load_rp()
        self.verdict = {"signature_valid": True, "issuer_trusted": None, "note": None}
        outer = self

        class _StubVerifier:
            def verify_pack(self, pack, anchor_keys=None):
                return outer.verdict

            def _load_anchor(self, path):
                return []
        # Inject the stubbed detached verifier so we control authenticity.
        self.rp._load_verifier = lambda: _StubVerifier()

    def _present(self, code=None):
        return {"format": "polaris-presentation/1",
                "credential": {"token_id": 42, "token_value": "T"},
                "presented_code": code}

    @staticmethod
    def _status(active):
        return lambda token_id: {"currently_authoritative": active,
                                 "status": "ACTIVE" if active else "REVOKED"}

    def test_accept_when_authentic_and_active(self):
        v = self.rp.verify_presentation(self._present(), status_checker=self._status(True))
        self.assertEqual(v["decision"], "accept")

    def test_reject_when_authentic_but_revoked(self):
        v = self.rp.verify_presentation(self._present(), status_checker=self._status(False))
        self.assertEqual(v["decision"], "reject")
        self.assertTrue(v["authentic"])  # the signature is still genuine; it is just not current

    def test_reject_when_not_authentic(self):
        self.verdict = {"signature_valid": False, "issuer_trusted": None, "note": "tampered"}
        v = self.rp.verify_presentation(self._present(), status_checker=self._status(True))
        self.assertEqual(v["decision"], "reject")

    def test_reject_when_issuer_untrusted(self):
        self.verdict = {"signature_valid": True, "issuer_trusted": False, "note": None}
        v = self.rp.verify_presentation(self._present(), status_checker=self._status(True))
        self.assertEqual(v["decision"], "reject")

    def test_provisional_when_offline(self):
        v = self.rp.verify_presentation(self._present(), status_checker=None)
        self.assertEqual(v["decision"], "provisional")  # authentic, but status unverified

    def test_duress_presentation_is_indistinguishable_in_the_decision(self):
        normal = self.rp.verify_presentation(self._present(code="real-code"),
                                             status_checker=self._status(True))
        duress = self.rp.verify_presentation(self._present(code="duress-code"),
                                             status_checker=self._status(True))
        # The relying party cannot tell a duress presentation from a normal one.
        self.assertEqual(normal["decision"], duress["decision"])
        self.assertEqual(normal["decision"], "accept")
        self.assertEqual(sorted(normal), sorted(duress))
        self.assertTrue(normal["presented_code_present"] and duress["presented_code_present"])


if __name__ == "__main__":
    unittest.main()
