"""test_sdk.py -- the polaris-verify Python SDK (P3.5).

Offline authenticity is exercised against the published vectors under real
ML-DSA-65 (cryptography); the presentation decision logic is exercised with an
injected online status (no server); and the conformance runner is driven against
the bundled SDK. Skips where cryptography lacks ML-DSA-65."""
import json
import os
import subprocess
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _HERE)

import polaris_verify as pv


def _mldsa_available():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        return hasattr(mldsa, "MLDSA65PublicKey")
    except Exception:
        return False


def _vector(name):
    with open(os.path.join(_ROOT, "vectors", name)) as f:
        return json.load(f)


@unittest.skipUnless(_mldsa_available(), "cryptography lacks ML-DSA-65 (needs cryptography>=48 / OpenSSL 3.5)")
class AuthenticityTests(unittest.TestCase):
    def test_valid_is_authentic(self):
        self.assertTrue(pv.verify_authenticity(_vector("ml-dsa-65-valid.json")).authentic)

    def test_tampered_and_wrong_key_are_not_authentic(self):
        for n in ("ml-dsa-65-tampered-signature.json", "ml-dsa-65-tampered-token.json", "ml-dsa-65-wrong-key.json"):
            self.assertFalse(pv.verify_authenticity(_vector(n)).authentic, n)

    def test_placeholder_is_not_authenticatable(self):
        v = pv.verify_authenticity(_vector("placeholder.json"))
        self.assertFalse(v.authentic)

    def test_anchor_trust(self):
        valid = _vector("ml-dsa-65-valid.json")
        self.assertIsNone(pv.verify_authenticity(valid).issuer_trusted)
        self.assertTrue(pv.verify_authenticity(valid, anchors=[valid["public_key_hex"]]).issuer_trusted)
        self.assertFalse(pv.verify_authenticity(valid, anchors=["00"]).issuer_trusted)


@unittest.skipUnless(_mldsa_available(), "needs ML-DSA-65")
class PresentationDecisionTests(unittest.TestCase):
    def _verifier(self, status=None, anchors=None):
        v = pv.PolarisVerifier(issuer_url=("http://x" if status is not None else None), anchors=anchors)
        if status is not None:
            v._online_status = lambda cred: status
        return v

    def _pres(self):
        return {"credential": _vector("ml-dsa-65-valid.json")}

    def test_offline_is_provisional(self):
        self.assertEqual(self._verifier().verify_presentation(self._pres()).decision, "provisional")

    def test_active_is_accept(self):
        v = self._verifier(status={"currently_authoritative": True, "status": "ACTIVE"})
        self.assertEqual(v.verify_presentation(self._pres()).decision, "accept")

    def test_revoked_is_reject_but_authentic(self):
        v = self._verifier(status={"currently_authoritative": False, "status": "REVOKED"})
        out = v.verify_presentation(self._pres())
        self.assertEqual(out.decision, "reject")
        self.assertTrue(out.authentic)

    def test_untrusted_issuer_is_reject(self):
        v = self._verifier(status={"currently_authoritative": True}, anchors=["00"])
        self.assertEqual(v.verify_presentation(self._pres()).decision, "reject")

    def test_tampered_is_reject(self):
        out = self._verifier(status={"currently_authoritative": True}).verify_presentation(
            {"credential": _vector("ml-dsa-65-tampered-signature.json")})
        self.assertEqual(out.decision, "reject")
        self.assertFalse(out.authentic)


@unittest.skipUnless(_mldsa_available(), "needs ML-DSA-65")
class ConformanceRunnerTest(unittest.TestCase):
    def test_bundled_sdk_passes_the_conformance_suite(self):
        r = subprocess.run([sys.executable, os.path.join(_ROOT, "conformance", "run_conformance.py"), "--self"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("conformance cases passed", r.stdout)


class RefusalsAreTestedTests(unittest.TestCase):
    """Every refusal in the SDK, exercised so that inverting it goes red.

    `scripts/polaris-sdk-mutation-drill.py` turns each `return False` in
    `polaris_verify` into `return True` and asks whether anything notices. The first run
    answered 18 of 18: every refusal in the reference implementation an integrator builds
    against could be made to ACCEPT what it exists to reject, with this file and the
    published conformance suite both green.

    That is not the conformance suite being broken -- an SDK whose signature backends
    accept anything IS caught by it. The published cases reach the happy path and a
    tampered-signature path; these guards sit on inputs no case contains. Which is exactly
    why they belong here rather than in the frozen contract.
    """

    # -- the signature backends ------------------------------------------

    def test_an_unaccepted_algorithm_never_verifies(self):
        """Neither backend may VERIFY under a parameter set the SDK does not accept.

        The two answer differently and both are correct: `_verify_liboqs` returns False
        (refused), `_verify_cryptography` returns None (this backend cannot answer, so the
        caller falls through to the other). What neither may do is return True, which is
        what inverting either refusal makes it do.
        """
        for backend in (pv._verify_cryptography, pv._verify_liboqs):
            with self.subTest(backend=backend.__name__):
                self.assertIsNot(backend(b"digest", b"sig", b"\x00" * 32, "RSA-2048"), True,
                                 "an unaccepted algorithm must never verify")
        self.assertIs(pv._verify_liboqs(b"digest", b"sig", b"\x00" * 32, "RSA-2048"), False,
                      "liboqs refuses an unaccepted algorithm outright rather than abstaining")

    def test_a_bad_signature_is_refused_by_both_backends(self):
        """A wrong signature over real material. The backend must answer False, never
        True and never an exception."""
        for backend in (pv._verify_cryptography, pv._verify_liboqs):
            with self.subTest(backend=backend.__name__):
                got = backend(b"a digest", b"not a signature", b"\x01" * 1952, pv.ALGORITHM)
                self.assertIn(got, (False, None),
                              "a bad signature must be refused or unavailable, never accepted")

    def test_a_signature_that_is_not_bytes_is_refused_rather_than_accepted(self):
        """The catch-all handlers, which the other cases do not reach.

        A wrong signature raises InvalidSignature; a signature that is not bytes at all
        raises something else, and lands in the `except Exception` arm. Inverting that arm
        turns every unexpected error during verification into an ACCEPT, which is the worst
        possible direction for a failure nobody anticipated.
        """
        pk = b"\x01" * 1952   # an ML-DSA-65 public key length
        for label, sig in (("a str", "not bytes"), ("an int", 12345),
                           ("None", None), ("empty", b"")):
            for backend in (pv._verify_cryptography, pv._verify_liboqs):
                with self.subTest(signature=label, backend=backend.__name__):
                    self.assertIsNot(backend(b"a digest", sig, pk, pv.ALGORITHM), True,
                                     "an unexpected error must never verify")

    # -- Merkle inclusion -------------------------------------------------

    def test_an_index_outside_the_tree_is_refused(self):
        leaf = b"\x11" * 32
        for idx, size in ((-1, 4), (4, 4), (99, 4)):
            with self.subTest(idx=idx, tree_size=size):
                self.assertFalse(pv.verify_inclusion(idx, size, leaf, b"\x22" * 32, []),
                                 "a leaf index outside the tree must not verify")

    def test_a_non_integer_index_is_refused_rather_than_raising(self):
        self.assertFalse(pv.verify_inclusion("two", 4, b"\x11" * 32, b"\x22" * 32, []))

    def test_a_malformed_proof_node_is_refused(self):
        """A path element that is not bytes, and a path longer than the tree can justify."""
        leaf = b"\x11" * 32
        self.assertFalse(pv.verify_inclusion(0, 4, leaf, b"\x22" * 32, ["not bytes"]),
                         "a proof node that is not bytes must not verify")
        self.assertFalse(pv.verify_inclusion(0, 1, leaf, b"\x22" * 32, [b"\x33" * 32]),
                         "a one-leaf tree admits no path; a supplied one must not verify")

    # -- the correlation helpers -----------------------------------------

    def test_linking_refuses_anything_that_is_not_a_pair_of_strings(self):
        """A False from these reads as 'different person'. Returning it for a type error
        would be answering a question that was never asked."""
        for fn in (pv.nullifiers_link, pv.handles_link):
            for a, b in ((None, "ab"), ("ab", None), (1, 2), (b"ab", "ab"), ({}, [])):
                with self.subTest(fn=fn.__name__, a=type(a).__name__, b=type(b).__name__):
                    self.assertFalse(fn(a, b))

    # -- delegation: what a grant covers ---------------------------------

    def test_a_grant_that_is_not_a_dict_covers_nothing(self):
        for bad in (None, "grant", [], 7):
            with self.subTest(grant=type(bad).__name__):
                self.assertFalse(pv.grant_covers(bad, "transfer"))

    def test_a_grant_with_no_usable_action_list_covers_nothing(self):
        """An empty or malformed action list is not 'all actions'."""
        for actions in (None, [], "transfer", {}, 0):
            with self.subTest(actions=repr(actions)[:18]):
                self.assertFalse(pv.grant_covers({"actions": actions}, "transfer"))

    # -- delegation: the limits ------------------------------------------

    def test_a_limit_this_verifier_does_not_understand_is_refused(self):
        """The bounded grant that silently becomes unbounded. A verifier that has never
        heard of `max_transfers` must refuse, not ignore it."""
        ok, note = pv.grant_within_limits({"limits": {"max_transfers": 3}})
        self.assertFalse(ok)
        self.assertIn("max_transfers", note)

    def test_an_exhausted_use_limit_is_refused(self):
        for uses in (3, 4, 99):
            with self.subTest(uses_so_far=uses):
                ok, note = pv.grant_within_limits({"limits": {"max_uses": 3}}, uses_so_far=uses)
                self.assertFalse(ok, "a grant used up must not authorize another use")
                self.assertIn("use limit", note)
        ok, _ = pv.grant_within_limits({"limits": {"max_uses": 3}}, uses_so_far=2)
        self.assertTrue(ok, "a grant with uses remaining must still authorize")

    def test_an_amount_over_the_grants_ceiling_is_refused(self):
        ok, note = pv.grant_within_limits({"limits": {"max_amount": 100}}, amount=100.01)
        self.assertFalse(ok, "an amount above the ceiling must not be authorized")
        self.assertIn("exceeds", note)
        ok, _ = pv.grant_within_limits({"limits": {"max_amount": 100}}, amount=100)
        self.assertTrue(ok, "an amount at the ceiling is within it")

    def test_a_limit_that_is_not_a_number_is_refused(self):
        """Never treated as absent: a grant whose ceiling cannot be compared is refused."""
        ok, note = pv.grant_within_limits({"limits": {"max_amount": "lots"}}, amount=5)
        self.assertFalse(ok)
        self.assertIn("not a number", note)

    # -- delegation: revocation binding ----------------------------------

    def test_a_revocation_must_be_a_revocation_and_name_this_grant(self):
        grant = {"grant_id": "g-1", "public_key_hex": "AA" * 32}
        good = {"format": "polaris-grant-revocation/1", "grant_id": "g-1",
                "public_key_hex": "aa" * 32}
        self.assertTrue(pv.revocation_ends_grant(good, grant),
                        "the matching revocation must end the grant")
        for label, bad in (
                ("not a dict", "revoked"),
                ("wrong format", dict(good, format="polaris-grant/1")),
                ("another grant's id", dict(good, grant_id="g-2")),
                ("a different holder's key", dict(good, public_key_hex="bb" * 32))):
            with self.subTest(case=label):
                self.assertFalse(pv.revocation_ends_grant(bad, grant),
                                 "%s must not end this grant" % label)
        self.assertFalse(pv.revocation_ends_grant(good, "grant"))


if __name__ == "__main__":
    unittest.main()
