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
        """Never treated as absent: a grant whose ceiling cannot be compared is refused.

        The assertion reads the FIELD out of the note, not a phrase. 2026-09-17: the note
        was widened from "not a number" to "not a finite number" when NaN and infinity were
        added to the same refusal, and this test held the old phrase, so a correct mechanism
        failed its own test. A note is written for an operator and is allowed to be reworded;
        what must not change is that the refusal names the limit it could not evaluate.
        """
        # `null` is deliberately NOT in this list. Both implementations read an explicit
        # null as "this limit is not set", which is the absent case, not the uncomparable
        # one; `scripts/polaris-verifier-differential.py` is what holds them to the same
        # reading of it.
        for bad in ("lots", [], {}, float("nan"), float("inf"), float("-inf")):
            with self.subTest(limit=repr(bad)):
                ok, note = pv.grant_within_limits({"limits": {"max_amount": bad}}, amount=5)
                self.assertFalse(ok, "a ceiling of %r must not authorize" % bad)
                self.assertIn("max_amount", note)

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


class MalformedInputIsRefusedTests(unittest.TestCase):
    """Every structural refusal, driven from a table.

    v9.455 inverted the SDK's `return False` statements and closed 18 of 18. It did not
    reach the refusals expressed as a CONSTRUCTED VERDICT -- `AuthenticityVerdict(False,
    ..., note="pack missing token_value or signature_hex")` -- and there are 26 of those.
    Inverted, each returns an AUTHENTIC verdict for material it exists to reject: a pack
    with no signature at all, a status assertion in the wrong format, an attestation whose
    signature is a development placeholder.

    Table-driven because the refusals are regular and a hand-written test per case covers
    the cases somebody remembered.
    """

    #: (label, callable, input) -> the verdict's authenticity must be falsy.
    CASES = [
        # 2026-09-19, from polaris-sdk-mutation-drill.py: the `isinstance(pack, dict)` guard
        # could be inverted, so a pack that is not an object at all reported AUTHENTIC, with
        # this suite and the conformance suite both green. The guard exists because a wallet
        # handed a relying party a compact-serialised credential STRING and crashed it, and
        # the repair for a crash had no test of its own. Every other entry in this table
        # hands a dict that is wrong in one field; none of them asks whether the argument is
        # a dict, which is how a whole branch stayed uncovered in a table built to be
        # exhaustive.
        ("pack that is a string, not an object",
         pv.verify_authenticity,
         "eyJmb3JtYXQiOiAicG9sYXJpcy1hdXRoZW50aWNpdHktcGFjay8xIn0"),
        ("pack that is a list, not an object",
         pv.verify_authenticity,
         [{"format": "polaris-authenticity-pack/1", "token_value": "T"}]),
        ("pack missing signature_hex",
         pv.verify_authenticity,
         {"format": "polaris-authenticity-pack/1", "token_value": "T",
          "algorithm": "ML-DSA-65", "public_key_hex": "ab" * 1952}),
        ("pack missing token_value",
         pv.verify_authenticity,
         {"format": "polaris-authenticity-pack/1", "algorithm": "ML-DSA-65",
          "signature_hex": "ab" * 3309, "public_key_hex": "cd" * 1952}),
        ("pack with non-hex signature",
         pv.verify_authenticity,
         {"format": "polaris-authenticity-pack/1", "token_value": "T",
          "algorithm": "ML-DSA-65", "signature_hex": "zz-not-hex",
          "public_key_hex": "cd" * 1952}),
        ("pack with an unaccepted algorithm",
         pv.verify_authenticity,
         {"format": "polaris-authenticity-pack/1", "token_value": "T",
          "algorithm": "ML-DSA-44", "signature_hex": "ab" * 100,
          "public_key_hex": "cd" * 100}),
        ("status assertion in the wrong format",
         pv.verify_status_assertion,
         {"format": "not-a-status-assertion", "algorithm": "ML-DSA-65",
          "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}),
        ("status assertion signed with the dev placeholder",
         pv.verify_status_assertion,
         {"format": "polaris-status-assertion/1", "algorithm": pv.PLACEHOLDER_LABEL,
          "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}),
        ("id token in the wrong format",
         pv.verify_id_token,
         {"format": "not-an-id-token", "algorithm": "ML-DSA-65",
          "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}),
        ("artifact of an unknown type",
         pv.verify_signed_artifact,
         {"format": "polaris-nonesuch/1", "algorithm": "ML-DSA-65",
          "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}),
        ("artifact signed with the dev placeholder",
         pv.verify_signed_artifact,
         {"format": "polaris-revocation-feed/1", "algorithm": pv.PLACEHOLDER_LABEL,
          "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}),
        ("cosignature in the wrong format",
         pv.verify_cosignature,
         {"format": "not-a-cosignature", "algorithm": "ML-DSA-65",
          "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}),
        ("cosignature signed with the dev placeholder",
         pv.verify_cosignature,
         {"format": "polaris-transparency-cosignature/1", "algorithm": pv.PLACEHOLDER_LABEL,
          "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}),
        ("attestation with no signature at all (legacy)",
         pv.verify_attestation,
         {"format": "polaris-trust-attestation/1", "algorithm": "ML-DSA-65"}),
        ("attestation in the wrong format",
         pv.verify_attestation,
         {"format": "not-an-attestation", "algorithm": "ML-DSA-65",
          "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}),
        ("attestation signed with the dev placeholder",
         pv.verify_attestation,
         {"format": "polaris-trust-attestation/1", "algorithm": pv.PLACEHOLDER_LABEL,
          "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}),
    ]

    def test_a_cosignature_from_the_wrong_witness_is_refused(self):
        """The expected-key branch, which no structural input reaches.

        A cosignature can be perfectly valid and still be from the wrong witness. That is
        the difference between authentic and authoritative, and inverting this line accepts
        a genuine signature by a key the caller did not ask for.
        """
        cosig = {"format": "polaris-transparency-cosignature/1", "algorithm": "ML-DSA-65",
                 "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}
        v = pv.verify_cosignature(cosig, witness_key="ff" * 1952)
        self.assertFalse(v.authentic,
                         "a cosignature whose key is not the expected witness must be "
                         "refused even when the signature itself is well formed")

    def test_every_structural_refusal_refuses(self):
        for label, fn, obj in self.CASES:
            with self.subTest(case=label):
                v = fn(obj)
                authentic = getattr(v, "authentic", None)
                self.assertFalse(
                    authentic,
                    "%s must not be reported authentic; the verifier returned %r"
                    % (label, authentic))


def _conformance_vector(name):
    """A published conformance vector: real signed material, genuine or tampered."""
    with open(os.path.join(_ROOT, "conformance", "vectors", name)) as f:
        return json.load(f)


@unittest.skipUnless(_mldsa_available(), "cryptography lacks ML-DSA-65")
class TamperedMaterialIsRefusedTests(unittest.TestCase):
    """The SIGNATURE-FAILURE return paths, which structural input cannot reach.

    `return ArtifactVerdict(False, None, note, ran)` is taken only when real material was
    verified and the signature did not check out. Malformed input returns earlier, so the
    table of structural refusals never reaches these lines: inverting them accepts a
    genuine artifact whose signature has been altered, which is the single thing a verifier
    exists to refuse.

    Driven from the published tampered vectors, so the material is real rather than
    constructed to fail.
    """

    TAMPERED = [
        ("epoch-checkpoint-tampered.json", pv.verify_signed_artifact),
        ("revocation-feed-tampered.json", pv.verify_signed_artifact),
        ("federation-manifest-tampered.json", pv.verify_signed_artifact),
        ("trust-list-tampered.json", pv.verify_signed_artifact),
        ("registry-tampered.json", pv.verify_signed_artifact),
        ("signed-document-tampered.json", pv.verify_signed_artifact),
        ("timestamp-tampered.json", pv.verify_signed_artifact),
        ("transparency-sth-tampered.json", pv.verify_signed_artifact),
        ("exchange-receipt-tampered.json", pv.verify_signed_artifact),
        ("exchange-request-tampered.json", pv.verify_signed_artifact),
        ("status-assertion-tampered.json", pv.verify_status_assertion),
        ("id-token-tampered.json", pv.verify_id_token),
        ("trust-attestation-rekeyed.json", pv.verify_attestation),
    ]

    def test_every_tampered_vector_is_refused(self):
        for name, fn in self.TAMPERED:
            with self.subTest(vector=name):
                try:
                    obj = _conformance_vector(name)
                except FileNotFoundError:
                    self.fail("published vector %s is missing; this test cannot measure "
                              "anything without it" % name)
                v = fn(obj)
                authentic = getattr(v, "authentic", None)
                self.assertFalse(
                    authentic,
                    "%s carries an altered signature and must not be reported authentic; "
                    "the verifier returned %r" % (name, authentic))


@unittest.skipUnless(_mldsa_available(), "needs ML-DSA-65")
class OnlineDecisionHeldOutTests(unittest.TestCase):
    """2026-09-23: a held-out round on the online half of verify_presentation, which the
    tests above reach only through an injected status of the cleanest shape. Four of six
    mutations survived: a status check that FAILED returned accept; `current` read from the
    status string; a missing `currently_authoritative` read as true; an expired bearer token
    reused for an hour. Each test gives every other check a passing answer."""

    def _pres(self):
        return {"credential": _vector("ml-dsa-65-valid.json")}

    def _with(self, status):
        v = pv.PolarisVerifier(issuer_url="http://x")
        v._online_status = status if callable(status) else (lambda cred: status)
        return v

    def test_a_status_check_that_fails_rejects(self):
        def down(cred):
            raise OSError("connection refused")
        out = self._with(down).verify_presentation(self._pres())
        self.assertEqual(out.decision, "reject")
        self.assertTrue(out.authentic)

    def test_only_the_authoritative_flag_makes_a_credential_current(self):
        for status in ({"currently_authoritative": False, "status": "SUSPENDED"},
                       {"currently_authoritative": False, "status": "ACTIVE"},
                       {"status": "ACTIVE"}, {}):
            with self.subTest(status=status):
                self.assertEqual(self._with(status).verify_presentation(self._pres()).decision,
                                 "reject")

    def _token_answer(self, token):
        from unittest import mock
        answer = mock.MagicMock()
        answer.__enter__.return_value.read.return_value = json.dumps(
            {"access_token": token, "expires_in": 300}).encode()
        return answer

    def test_a_bearer_token_is_reused_until_five_seconds_before_expiry_and_no_later(self):
        import time
        from unittest import mock
        v = pv.PolarisVerifier(issuer_url="http://x", client_id="c", client_secret="s")
        v._bearer = "old"
        with mock.patch("urllib.request.urlopen", return_value=self._token_answer("new")) as call:
            v._bearer_exp = time.time() + 60
            self.assertEqual(v._access_token(), "old")
            self.assertEqual(call.call_count, 0)
            v._bearer_exp = time.time() + 4
            self.assertEqual(v._access_token(), "new", "a token about to expire is replaced")
            v._bearer, v._bearer_exp = "old", time.time() - 1
            self.assertEqual(v._access_token(), "new", "an expired token is never reused")


@unittest.skipUnless(_mldsa_available(), "needs ML-DSA-65")
class HolderChainHeldOutTests(unittest.TestCase):
    """2026-09-23: a held-out round on verify_holder dropped each of the facts `proved` needs
    and 10 of 12 mutations survived this suite and the conformance runner: only the key match
    and the nonce were ever isolated. Two chains, both genuinely signed: the published
    conformance chain, and sdk/testdata/holder-chain-early-binding.json, whose binding opens a
    day before its proof, so the proof's own one-minute skew can be tested on its own."""

    @classmethod
    def setUpClass(cls):
        cls.early = json.load(open(os.path.join(_ROOT, "sdk", "testdata", "holder-chain-early-binding.json")))
        cls.conf = {n: _conformance_vector("holder-%s.json" % n)
                    for n in ("credential", "binding-valid", "proof-valid")}

    def early_proved(self, now="2026-05-01T00:00:10Z", context=1, credential=None, binding=None, proof=None):
        e = self.early
        return pv.verify_holder(credential or e["credential"], binding or e["binding"], proof or e["proof"],
                                expected_nonce="held-out-nonce", expected_context=context, now=now).proved

    @staticmethod
    def _flip(obj):
        out = dict(obj); sig = out["signature_hex"]
        out["signature_hex"] = ("0" if sig[0] != "0" else "1") + sig[1:]
        return out

    def test_the_genuine_chain_proves(self):
        self.assertIs(self.early_proved(), True)

    def test_something_that_is_not_a_holder_chain_proves_nothing(self):
        """The early refusal returns the initial verdict, so the initial verdict IS the
        answer on this path; the SDK drill once declared it unobservable."""
        e = self.early
        for binding, proof in ((dict(e["binding"], format="x"), e["proof"]),
                               (e["binding"], dict(e["proof"], format="x")), (None, None)):
            v = pv.verify_holder(e["credential"], binding, proof, expected_nonce="held-out-nonce",
                                 expected_context=1, now="2026-05-01T00:00:10Z")
            self.assertIs(v.proved, False)

    def test_each_link_alone_refuses(self):
        e = self.early
        for label, kw in (("binding not authentic", {"binding": self._flip(e["binding"])}),
                          ("proof not authentic", {"proof": self._flip(e["proof"])}),
                          ("binding about another token", {"credential": dict(e["credential"], token_value="X")}),
                          ("binding by another issuer", {"credential": dict(e["credential"], public_key_hex="ab" * 1952)}),
                          ("another context", {"context": 2})):
            with self.subTest(label):
                self.assertIs(self.early_proved(**kw), False)

    def test_the_proof_window_is_five_minutes_and_a_minute_of_skew(self):
        for now, proved in (("2026-05-01T00:05:00Z", True), ("2026-05-01T00:05:01Z", False),
                            ("2026-04-30T23:59:00Z", True), ("2026-04-30T23:58:59Z", False)):
            with self.subTest(now=now):
                self.assertIs(self.early_proved(now=now), proved)

    def test_a_binding_not_yet_valid_refuses_while_the_proof_is_fresh(self):
        c = self.conf
        at = lambda now: pv.verify_holder(c["credential"], c["binding-valid"], c["proof-valid"],  # noqa: E731
                                          expected_nonce="rp-nonce-1", now=now)
        self.assertIs(at("2026-05-01T00:00:10Z").proved, True)
        v = at("2026-04-30T23:59:30Z")  # the proof is inside its skew; the binding has not opened
        self.assertIs(v.binding_fresh, False)
        self.assertIs(v.proved, False)


@unittest.skipUnless(_mldsa_available(), "needs ML-DSA-65")
class CrossAuthorityHeldOutTests(unittest.TestCase):
    """2026-09-23: ten of verify_cross_authority's rules removed in turn, eight survived this
    suite and the conformance runner. sdk/testdata/federation-variants.json is one genuine
    setup and signed variants, each differing from the base in one property."""

    @classmethod
    def setUpClass(cls):
        cls.f = json.load(open(os.path.join(_ROOT, "sdk", "testdata", "federation-variants.json")))

    def decide(self, manifest="base", feed="clean", anchors=None, require_signed=False):
        f = self.f
        return pv.verify_cross_authority(
            f["pack"], f["_fixture"]["context_id"], [f["manifests"][manifest]],
            anchors if anchors is not None else [f["trusted_anchor"]], f["feeds"][feed],
            now=f["_fixture"]["now"], require_signed_attestation=require_signed).decision

    def test_the_base_setup_is_accepted(self):
        self.assertEqual(self.decide(), "accept")

    def test_each_variant_is_refused(self):
        for label, kw in (("a stale manifest", {"manifest": "stale"}),
                          ("an attestation of another key", {"manifest": "other_key"}),
                          ("a badly signed attestation", {"manifest": "bad_attestation_signature"}),
                          ("trust in a RETIRED anchor of the manifest", {"anchors": [self.f["retired_anchor"]]}),
                          ("an unsigned edge when signed edges are required", {"require_signed": True}),
                          ("a stale revocation feed", {"feed": "stale"}),
                          ("a feed signed by another issuer", {"feed": "other_issuer"}),
                          ("a feed that is not authentic", {"feed": "not_authentic"})):
            with self.subTest(label):
                self.assertEqual(self.decide(**kw), "reject")


@unittest.skipUnless(_mldsa_available(), "needs ML-DSA-65")
class TimestampAnchorHeldOutTests(unittest.TestCase):
    """2026-09-23: ten of verify_timestamp_anchor's rules removed in turn; nine survived this
    suite and the conformance runner. Several sit BEFORE a signature check, so a test that
    alters a signed field is refused by the signature and not by the rule; those tests replace
    the one signature verdict, so only the rule named can refuse. The base is the genuine,
    twice-witnessed anchor in the published vectors."""

    def setUp(self):
        import copy
        self.ts = copy.deepcopy(_conformance_vector("timestamp-anchor-witnessed.json"))
        self.cos = self.ts["anchor"]["cosignatures"]
        self.both = [c["public_key_hex"] for c in self.cos]

    def verdict(self, trusted=None, threshold=2, **kw):
        return pv.verify_timestamp_anchor(self.ts, trusted_witnesses=self.both if trusted is None else trusted,
                                          threshold=threshold, **kw)

    def test_the_genuine_anchor_is_anchored_and_witnessed(self):
        v = self.verdict()
        self.assertTrue(v.anchored, v.note)
        self.assertTrue(v.witnessed)
        self.assertEqual(v.cosigner_count, 2)

    def test_a_proof_for_another_entry_does_not_anchor(self):
        self.ts["anchor"]["proof"]["entry_hex"] = "00" * 32
        self.assertFalse(self.verdict().anchored)

    def test_a_proof_naming_another_root_does_not_anchor(self):
        self.ts["anchor"]["proof"]["root_hash_hex"] = "00" * 32
        self.assertFalse(self.verdict().anchored)

    def test_an_unauthentic_head_does_not_anchor(self):
        sth = self.ts["anchor"]["sth"]
        sth["signature_hex"] = ("0" if sth["signature_hex"][0] != "0" else "1") + sth["signature_hex"][1:]
        v = self.verdict()
        self.assertFalse(v.sth_authentic)
        self.assertFalse(v.anchored)

    def test_a_head_by_another_log_key_does_not_anchor(self):
        self.assertFalse(self.verdict(log_key="ab" * 1952).anchored)

    def test_a_head_from_another_log_does_not_anchor(self):
        from unittest import mock
        self.ts["anchor"]["sth"]["log_id"] = "some-other-log"
        with mock.patch.object(pv, "verify_signed_artifact", return_value=pv.ArtifactVerdict(True, None)):
            self.assertFalse(self.verdict().anchored)

    def test_only_trusted_distinct_witnesses_count(self):
        v = self.verdict(trusted=self.both[:1])
        self.assertEqual((v.cosigner_count, v.witnessed), (1, False), "an untrusted cosigner counted")
        self.ts["anchor"]["cosignatures"] = [self.cos[0], dict(self.cos[0])]
        v = self.verdict()
        self.assertEqual((v.cosigner_count, v.witnessed), (1, False), "one witness counted twice")

    def test_a_cosignature_of_another_head_does_not_count(self):
        from unittest import mock
        for field, value in (("tree_size", 5), ("root_hash_hex", "00" * 32)):
            with self.subTest(field=field):
                self.setUp()
                self.cos[1][field] = value
                with mock.patch.object(pv, "verify_cosignature", return_value=pv.ArtifactVerdict(True, None)):
                    v = self.verdict()
                self.assertEqual((v.cosigner_count, v.witnessed), (1, False))


class GrantCoverageTests(unittest.TestCase):
    """2026-09-23: a held-out mutation made grant_covers answer yes to ANY action of a grant
    with a non-empty list, and this suite stayed green: every test here asked about empty or
    malformed grants, none about an action the grant does not list. Actions are exact
    strings; a grant for `read:status` does not cover `READ:STATUS` or `transfer:funds`."""

    GRANT = {"actions": ["read:status", "sign:document"]}

    def test_a_listed_action_is_covered(self):
        self.assertTrue(pv.grant_covers(self.GRANT, "read:status"))

    def test_an_unlisted_action_is_not(self):
        for action in ("transfer:funds", "READ:STATUS", "read:status ", "read"):
            with self.subTest(action=action):
                self.assertFalse(pv.grant_covers(self.GRANT, action))


class TheTokenCacheLifetimeIsBoundedTests(unittest.TestCase):
    """The issuer says how long its access token lives. The client believed it without
    reading it.

    2026-09-17. `int(body.get("expires_in", 300))` sat outside any try. Two shapes broke it,
    and both arrive from an ordinary `json.loads` of a server response:

      `Infinity`  raised OverflowError out of `_access_token`, a method that only ever
                  promised to return a bearer token.
      `1e308`     converted cleanly and pinned the cached token for longer than the process
                  will ever run, so a client whose credentials were revoked kept presenting
                  a token it should have stopped using at the next refresh.

    The issuer is trusted to issue. It is not trusted to set an unbounded lifetime inside
    someone else's client.
    """

    def test_a_non_finite_lifetime_falls_back_to_the_conservative_default(self):
        for bad in (float("inf"), float("-inf"), float("nan")):
            with self.subTest(value=repr(bad)):
                self.assertEqual(pv._expires_in(bad), pv._DEFAULT_TOKEN_CACHE_SECONDS)

    def test_a_wrong_typed_or_absent_lifetime_falls_back(self):
        for bad in (None, "300", [], {}, True, False, 0, -1):
            with self.subTest(value=repr(bad)):
                self.assertEqual(pv._expires_in(bad), pv._DEFAULT_TOKEN_CACHE_SECONDS)

    def test_an_enormous_lifetime_is_capped_rather_than_believed(self):
        for huge in (1e308, 10 ** 30, 99999999):
            with self.subTest(value=repr(huge)):
                self.assertEqual(pv._expires_in(huge), pv._MAX_TOKEN_CACHE_SECONDS)

    def test_an_ordinary_lifetime_is_used_as_given(self):
        self.assertEqual(pv._expires_in(300), 300)
        self.assertEqual(pv._expires_in(3599.9), 3599)
        self.assertEqual(pv._expires_in(pv._MAX_TOKEN_CACHE_SECONDS),
                         pv._MAX_TOKEN_CACHE_SECONDS)


@unittest.skipUnless(_mldsa_available(), "cryptography lacks ML-DSA-65")
class HeldOutSemanticMutationsTests(unittest.TestCase):
    """2026-09-23: ten semantic mutations written AFTER the refusal drill was green (a
    not-yet-valid window accepted, a replay window doubled, a future-dated proof accepted,
    an inclusion bound off by one, the exhausted-tree test skipped, a case-sensitive
    revocation lookup, the two-witness disagreement ignored at either site). Eight survived
    this suite and the conformance runner: the drill inverts refusals, and none of these is
    an inverted refusal, it is a boundary moved. Each test below pins one boundary at the
    exact instant or index where the mutation changes the answer."""

    T0 = "2026-05-01T00:00:00Z"   # the conformance holder proof's issued_at

    def test_a_status_assertion_is_not_fresh_before_its_window_opens(self):
        a = _conformance_vector("status-assertion-valid.json")   # [2026-01-01, 2027-01-01)
        self.assertIs(pv.verify_status_assertion(a, "2026-01-01T00:00:00Z").fresh, True)
        self.assertIs(pv.verify_status_assertion(a, "2025-12-31T23:59:59Z").fresh, False,
                      "an assertion is not fresh one second before it was issued")
        self.assertIs(pv.verify_status_assertion(a, "2027-01-01T00:00:00Z").fresh, False,
                      "the window is half-open: expires_at itself is outside it")

    def test_a_holder_proof_is_fresh_for_exactly_its_replay_window(self):
        p = _conformance_vector("holder-proof-valid.json")
        self.assertIs(pv.verify_signed_artifact(p, "2026-05-01T00:05:00Z").fresh, True)
        self.assertIs(pv.verify_signed_artifact(p, "2026-05-01T00:05:01Z").fresh, False,
                      "a holder proof 301 seconds old is a replay")

    def test_a_holder_proof_from_the_future_is_fresh_only_within_the_skew(self):
        p = _conformance_vector("holder-proof-valid.json")
        self.assertIs(pv.verify_signed_artifact(p, "2026-04-30T23:59:00Z").fresh, True)
        self.assertIs(pv.verify_signed_artifact(p, "2026-04-30T23:58:59Z").fresh, False,
                      "a proof 61 seconds ahead of the verifier's clock is not fresh")

    def test_an_index_equal_to_the_tree_size_does_not_verify(self):
        # A one-leaf tree whose root is the leaf: at idx == tree_size an empty path walks
        # nothing and the comparison alone would say yes.
        leaf = bytes([0x11]) * 32
        self.assertTrue(pv.verify_inclusion(0, 1, leaf, leaf, []))
        self.assertFalse(pv.verify_inclusion(1, 1, leaf, leaf, []))

    def test_a_path_too_short_for_the_tree_does_not_verify(self):
        leaf = bytes([0x11]) * 32
        self.assertFalse(pv.verify_inclusion(0, 2, leaf, leaf, []),
                         "a two-leaf tree needs one sibling; an empty path proves nothing")

    def test_an_upper_case_leaf_in_a_genuine_feed_still_revokes(self):
        with open(os.path.join(_ROOT, "sdk", "testdata", "revocation-uppercase-leaf.json")) as f:
            fx = json.load(f)
        meta = fx["_fixture"]
        self.assertTrue(pv.verify_signed_artifact(fx["feed"], meta["now"]).authentic)
        v = pv.verify_cross_authority(fx["pack"], meta["context_id"], [fx["manifest"]],
                                      None, fx["feed"], now=meta["now"])
        self.assertEqual(v.decision, "reject", v.reason)
        self.assertIn("revoked", v.reason)
        v = pv.verify_cross_authority(fx["pack"], meta["context_id"], [fx["manifest"]],
                                      None, None, now=meta["now"])
        self.assertEqual(v.decision, "accept", "without the feed the same inputs are accepted")

    def test_a_cosignature_from_another_witness_is_refused(self):
        cos = _conformance_vector("timestamp-anchor-witnessed.json")["anchor"]["cosignatures"]
        self.assertTrue(pv.verify_cosignature(cos[0], cos[0]["public_key_hex"]).authentic)
        self.assertFalse(pv.verify_cosignature(cos[0], cos[1]["public_key_hex"]).authentic)

    def test_a_grant_amount_is_bounded_at_its_limit(self):
        g = {"limits": {"max_amount": 100}}
        self.assertEqual(pv.grant_within_limits(g, 0, 100)[0], True)
        self.assertEqual(pv.grant_within_limits(g, 0, 100.01)[0], False)
        self.assertEqual(pv.grant_within_limits(g, 0, 150)[0], False)

    def test_two_witnesses_that_disagree_are_not_a_verdict(self):
        from unittest import mock
        pack = _vector("ml-dsa-65-valid.json")
        art = _conformance_vector("holder-proof-valid.json")
        for primary, witness in ((True, False), (False, True)):
            with mock.patch.object(pv, "_verify_cryptography", return_value=primary), \
                 mock.patch.object(pv, "_verify_liboqs", return_value=witness):
                v = pv.verify_authenticity(pack)
                self.assertFalse(v.authentic, (primary, witness))
                self.assertIn("DISAGREE", v.note or "")
                a = pv.verify_signed_artifact(art, "2026-05-01T00:00:00Z")
                self.assertFalse(a.authentic, (primary, witness))
                self.assertIn("DISAGREE", a.note or "")


class IsoInstantGrammarTests(unittest.TestCase):
    """sdk/testdata/iso-instants.json: the grammar both reference SDKs share. Until 2026-09-24
    this kit used datetime.fromisoformat, whose grammar depends on the interpreter."""

    def test_the_shared_vectors(self):
        import json
        import os
        cases = json.load(open(os.path.join(_ROOT, "sdk", "testdata", "iso-instants.json")))["cases"]
        for c in cases:
            with self.subTest(c["input"]):
                got = pv._iso_to_epoch(c["input"])
                self.assertEqual(None if got is None else int(got), c["epoch"])
