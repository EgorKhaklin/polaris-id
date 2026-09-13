"""test_verify_p9.py — unit tests for the P9 additions to scripts/polaris-verify.py.

The P9 surface is exercised end to end by drills and the conformance suite, both of which
run outside the coverage harness. These are the fast tests: the pure logic, the refusal
paths, and above all TOTALITY. A detached verifier is a trust boundary that strangers feed
hostile input to, so every function here must return a verdict rather than raise.

One test is not about coverage at all. `test_holder_proof_statement_ignores_the_presented_code`
is the anti-coercion property in unit-test form: if the holder proof ever covered the
presented code, a coerced presentation would become distinguishable from a consenting one.
The invariant check reads the key list statically; this proves it on the bytes.

Run: python3 -m unittest test_verify_p9   (from scripts/)
"""
import hashlib
import importlib.util
import json
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("polaris_verify", os.path.join(_HERE, "polaris-verify.py"))
V = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(V)

# Every P9 entry point, with an argument shape that is valid but meaningless. Used by the
# totality tests, which feed each of them the same battery of hostile inputs.
_HOSTILE = [None, 0, "", [], {}, {"format": None}, {"format": 123}, [1, 2, 3], True,
            {"format": "polaris-holder-proof/1", "signature_hex": "zz", "public_key_hex": "zz"}]


class TotalityTests(unittest.TestCase):
    """A refusal is a verdict. None of these may raise, whatever they are handed."""

    def _each(self, fn, **kw):
        for bad in _HOSTILE:
            with self.subTest(value=repr(bad)[:40]):
                out = fn(bad, **kw)
                self.assertIsInstance(out, dict, "a verdict, not an exception")

    def test_verify_attestation_is_total(self):
        self._each(V.verify_attestation)

    def test_verify_holder_binding_is_total(self):
        self._each(V.verify_holder_binding)

    def test_verify_holder_proof_is_total(self):
        self._each(V.verify_holder_proof)

    def test_verify_epoch_leaves_is_total(self):
        self._each(V.verify_epoch_leaves)

    def test_verify_timestamp_anchor_is_total(self):
        for bad in _HOSTILE:
            with self.subTest(value=repr(bad)[:40]):
                self.assertIsInstance(V.verify_timestamp_anchor(bad), dict)

    def test_member_index_is_total(self):
        for bad in _HOSTILE:
            self.assertIsNone(V.member_index(bad, "aa"))
        self.assertIsNone(V.member_index({"all_leaves_hex": "not-a-list"}, "aa"))


class ScopedNullifierTests(unittest.TestCase):
    """P9.3: the verifier's half of one-person-once. No Plonky2 needed for these.

    Every case here is about the PUBLIC INPUTS, which is where a relying party's rule
    actually lives. The proof bytes are the crate's business; whether this verifier binds
    the scope and holds a ledger is this file's.
    """

    ROOT = "ab" * 32
    NULL = "cd" * 32

    def _bundle(self, **over):
        pi = {"epoch_root_hex": self.ROOT, "epoch_id": 7, "context_id": 3, "nonce": 11,
              "scope": 1001, "nullifier_hex": self.NULL}
        pi.update(over)
        return {"proof_hex": "00", "public_inputs": pi}

    def test_a_proof_made_for_another_verifier_is_refused(self):
        v = V.verify_zk_against_root(self._bundle(), self.ROOT, 7, 3, expected_scope=2002)
        self.assertFalse(v["bound"])
        self.assertIn("scope", v["note"])

    def test_the_verifier_gets_the_nullifier_back(self):
        v = V.verify_zk_against_root(self._bundle(), self.ROOT, 7, 3, expected_scope=1001)
        self.assertTrue(v["bound"])
        self.assertEqual(v["nullifier"], self.NULL)

    def test_a_repeat_in_the_same_scope_is_refused(self):
        ledger = {self.NULL}
        v = V.verify_zk_against_root(self._bundle(), self.ROOT, 7, 3, expected_scope=1001,
                                     seen_nullifiers=ledger)
        self.assertFalse(v["fresh_nullifier"])
        self.assertIn("already been accepted", v["note"])

    def test_a_first_visit_is_fresh(self):
        v = V.verify_zk_against_root(self._bundle(), self.ROOT, 7, 3, expected_scope=1001,
                                     seen_nullifiers=set())
        self.assertTrue(v["fresh_nullifier"])

    def test_the_ledger_comparison_ignores_hex_case(self):
        v = V.verify_zk_against_root(self._bundle(nullifier_hex=self.NULL.upper()), self.ROOT, 7, 3,
                                     seen_nullifiers={self.NULL})
        self.assertFalse(v["fresh_nullifier"], "hex case must not let one person prove twice")

    def test_a_proof_with_no_nullifier_cannot_satisfy_a_scoped_verifier(self):
        # A pre-P9.3 bundle carries no nullifier. Accepting it would mean the verifier's
        # one-person-once rule silently stops applying to exactly the proofs that predate it.
        bundle = self._bundle()
        del bundle["public_inputs"]["nullifier_hex"]
        v = V.verify_zk_against_root(bundle, self.ROOT, 7, 3, seen_nullifiers=set())
        self.assertFalse(v["fresh_nullifier"])
        self.assertIn("no nullifier", v["note"])

    def test_without_a_ledger_the_verifier_does_not_guess(self):
        v = V.verify_zk_against_root(self._bundle(), self.ROOT, 7, 3)
        self.assertIsNone(v["fresh_nullifier"], "no ledger means no opinion, not a free pass")

    def test_it_is_total_on_hostile_public_inputs(self):
        for bad in (None, {}, {"public_inputs": None}, {"public_inputs": {"scope": "many"}},
                    {"public_inputs": {"epoch_root_hex": ROOT_JUNK}}):
            with self.subTest(value=repr(bad)[:40]):
                self.assertIsInstance(
                    V.verify_zk_against_root(bad, self.ROOT, 7, 3, expected_scope=1), dict)


ROOT_JUNK = object()


class CorrelationIsAboutTheTranscriptTests(unittest.TestCase):
    """`correlation: bounded` is a claim about THIS transcript, not about the mechanism.

    Until it was measured, the verdict was set whenever a scoped nullifier was present and
    never checked its own stated premise, that the presentation showed no stable
    credential. A presentation carrying a nullifier AND the full credential pack reported
    "bounded" while handing the verifier a stable token value, issuer key and signature.
    Two colluding verifiers link on any one of the three in a single comparison, and both
    of their verifiers had told them the correlation was bounded.

    That is the shape the lab exists to catch: a mechanism was present, so the property was
    assumed. Mechanism existence is not the property.
    """

    CRED = {"format": "polaris-authenticity-pack/1", "token_value": "STABLE-TOKEN-0001",
            "algorithm": "ML-DSA-65", "public_key_hex": "aa" * 1952,
            "signature_hex": "bb" * 3309}
    ZK = {"proof_hex": "00", "public_inputs": {"nullifier_hex": "cc" * 32}}

    def _corr(self, **parts):
        pres = {"format": "polaris-presentation/1"}
        pres.update(parts)
        return V.verify_presentation(pres, verifier_scope="verifier-A")

    def test_a_nullifier_beside_the_credential_is_not_bounded(self):
        v = self._corr(credential=self.CRED, zk_proof=self.ZK)
        self.assertEqual(v["correlation"], "exposed",
                         "a transcript containing a stable token value is correlatable "
                         "whatever handle the verifier keys its records by")

    def test_a_nullifier_with_the_credential_withheld_is_bounded(self):
        v = self._corr(zk_proof=self.ZK)
        self.assertEqual(v["correlation"], "bounded")
        self.assertEqual(v["pairwise_handle"], "cc" * 32)

    def test_the_holder_key_alone_exposes_it(self):
        """The holder key is the same value at every verifier, which is exactly why the
        pairwise handle is derived FROM it and why showing it defeats the point."""
        v = self._corr(zk_proof=self.ZK,
                       holder_binding={"holder_public_key_hex": "dd" * 32})
        self.assertEqual(v["correlation"], "exposed")

    def test_each_stable_field_alone_is_enough(self):
        for field in ("token_value", "public_key_hex", "signature_hex"):
            with self.subTest(field=field):
                v = self._corr(credential={"format": "polaris-authenticity-pack/1",
                                           field: "ee" * 8},
                               zk_proof=self.ZK)
                self.assertEqual(v["correlation"], "exposed",
                                 "%s is identical at every verifier" % field)

    def test_no_nullifier_is_never_bounded(self):
        self.assertEqual(self._corr(credential=self.CRED)["correlation"], "exposed")


class HolderProofStatementTests(unittest.TestCase):
    """P9.1's constitutional property, on the bytes."""

    BASE = {"format": "polaris-holder-proof/1", "token_value": "T", "context_id": 1,
            "verifier_nonce": "n", "issued_at": "2026-09-10T00:00:00Z", "algorithm": "ML-DSA-65"}

    def test_holder_proof_statement_ignores_the_presented_code(self):
        consent = V._holder_proof_canonical(dict(self.BASE, presented_code="ORDINARY"))
        duress = V._holder_proof_canonical(dict(self.BASE, presented_code="PLEASE-HELP-ME"))
        self.assertEqual(consent, duress,
                         "a holder proof that covered the presented code would make a coerced "
                         "presentation distinguishable from a consenting one")

    def test_the_statement_covers_what_it_must(self):
        signed = json.loads(V._holder_proof_canonical(self.BASE).decode("utf-8"))
        self.assertEqual(set(signed), {"format", "token_value", "context_id",
                                       "verifier_nonce", "issued_at", "algorithm"})

    def test_the_statement_is_canonical(self):
        a = V._holder_proof_canonical({k: self.BASE[k] for k in sorted(self.BASE)})
        b = V._holder_proof_canonical({k: self.BASE[k] for k in reversed(sorted(self.BASE))})
        self.assertEqual(a, b, "key order must not change the bytes a holder signs")


class MerkleTests(unittest.TestCase):
    """RFC 6962 inclusion, the arithmetic the SDKs had to reimplement (P9.6)."""

    def setUp(self):
        self.entries = [hashlib.sha3_256(("e%d" % i).encode()).hexdigest() for i in range(7)]
        self.root = V.merkle_tree_head(self.entries)

    def test_every_entry_proves(self):
        for i, e in enumerate(self.entries):
            self.assertTrue(V.verify_inclusion(i, len(self.entries), V._lh(e), self.root,
                                               V.inclusion_proof(i, self.entries)),
                            "entry %d must prove" % i)

    def test_a_wrong_index_does_not_prove(self):
        self.assertFalse(V.verify_inclusion(1, len(self.entries), V._lh(self.entries[0]),
                                            self.root, V.inclusion_proof(0, self.entries)))

    def test_an_index_out_of_range_is_refused(self):
        self.assertFalse(V.verify_inclusion(99, 7, V._lh(self.entries[0]), self.root, []))
        self.assertFalse(V.verify_inclusion(-1, 7, V._lh(self.entries[0]), self.root, []))

    def test_a_truncated_path_does_not_prove(self):
        self.assertFalse(V.verify_inclusion(3, len(self.entries), V._lh(self.entries[3]),
                                            self.root, V.inclusion_proof(3, self.entries)[:-1]))


class EpochLeavesTests(unittest.TestCase):
    """P9.2: the published anonymity set, checkable with SHA3-256 alone."""

    def setUp(self):
        self.leaves = [hashlib.sha3_256(("m%d" % i).encode()).hexdigest() for i in range(5)]

    def test_the_commitment_is_order_independent(self):
        import random
        shuffled = list(self.leaves)
        random.shuffle(shuffled)
        self.assertEqual(V._leaves_root(self.leaves), V._leaves_root(shuffled),
                         "the set is a set; publishing order must not change its commitment")

    def test_the_commitment_changes_when_a_member_changes(self):
        swapped = self.leaves[:-1] + [hashlib.sha3_256(b"intruder").hexdigest()]
        self.assertNotEqual(V._leaves_root(self.leaves), V._leaves_root(swapped))

    def test_a_member_finds_itself_and_a_stranger_does_not(self):
        bundle = {"all_leaves_hex": self.leaves}
        self.assertEqual(V.member_index(bundle, self.leaves[2]), 2)
        self.assertEqual(V.member_index(bundle, self.leaves[2].upper()), 2, "hex case must not matter")
        self.assertIsNone(V.member_index(bundle, "ff" * 32))

    def test_a_non_bundle_is_refused_by_format(self):
        v = V.verify_epoch_leaves({"format": "polaris-revocation-feed/1"})
        self.assertFalse(v["leaves_authentic"])
        self.assertIn("not a", v["note"])


class LegacyAndRefusalTests(unittest.TestCase):
    """The paths that decide without a signature: legacy attestations, absent anchors."""

    def test_an_unsigned_attestation_is_legacy_not_a_failure(self):
        v = V.verify_attestation({"attested_agency_id": 2, "context_id": 1})
        self.assertFalse(v["signed"])
        self.assertFalse(v["attestation_authentic"])
        self.assertIn("legacy", v["note"])

    def test_a_signed_attestation_of_the_wrong_format_is_refused(self):
        v = V.verify_attestation({"format": "polaris-timestamp/1", "signature_hex": "ab",
                                  "public_key_hex": "cd"})
        self.assertTrue(v["signed"])
        self.assertFalse(v["attestation_authentic"])

    def test_a_timestamp_without_an_anchor_says_so(self):
        v = V.verify_timestamp_anchor({"format": "polaris-timestamp/1"})
        self.assertFalse(v["anchored"])
        self.assertIn("no anchor", v["note"])

    def test_an_anchor_proof_for_another_timestamp_is_refused(self):
        ts = {"format": "polaris-timestamp/1", "digest_hex": "00" * 32,
              "anchor": {"proof": {"entry_hex": "ff" * 32}, "sth": {}}}
        v = V.verify_timestamp_anchor(ts)
        self.assertFalse(v["anchored"])
        self.assertIn("not for this timestamp", v["note"])

    def test_a_holder_binding_of_the_wrong_format_is_refused(self):
        v = V.verify_holder_binding({"format": "polaris-status-assertion/1"})
        self.assertFalse(v["binding_authentic"])

    def test_a_holder_proof_with_bad_hex_is_refused_not_raised(self):
        v = V.verify_holder_proof({"format": "polaris-holder-proof/1", "algorithm": "ML-DSA-65",
                                   "public_key_hex": "nothex", "signature_hex": "alsonothex"})
        self.assertFalse(v["proof_authentic"])
        self.assertIn("hex", v["note"])


if __name__ == "__main__":
    unittest.main()
