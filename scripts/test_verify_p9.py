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
            {"format": "polaris-holder-proof/1", "signature_hex": "zz", "public_key_hex": "zz"},
            # 2026-09-17: the battery above had no dict carrying a WRONG-TYPED value, and
            # that is the class that broke five functions. `token_value: 1` reached
            # `.encode()`; `signature_hex: 1` reached `bytes.fromhex`, which raises TypeError
            # where only ValueError was caught; `_sd`-style list fields reached iteration;
            # `public_key_hex: 5` reached `.lower()`. Every one of them raised out of a
            # function whose docstring promises a verdict.
            {"token_value": 1, "algorithm": "ML-DSA-65", "signature_hex": "aa", "public_key_hex": "bb"},
            {"token_value": "t", "algorithm": "ML-DSA-65", "signature_hex": 1, "public_key_hex": 1},
            {"public_key_hex": 5}, {"root_hash_hex": 5}, {"revoked_leaves": 5},
            {"epoch": {"number": "a"}}, {"epoch": {"number": float("nan")}},
            {"epoch": 5}, {"prev": 5}, {"keys": 5}, {"cosignatures": ["a string"]},
            # And no non-finite number anywhere, which is the other half of the same story.
            {"number": float("inf")}, {"tree_size": "1"}, {"leaf_index": float("inf")}]


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

    # ---- 2026-09-16: the same defect, one container over -------------------------------
    # The fix above enumerated the containers somebody had thought of, not the ones the
    # presentation format defines. `holder_proof` carries the token value AND the holder's
    # public key, and neither was looked at, so this transcript reported `bounded`.

    HOLDER_PROOF = {"format": "polaris-holder-proof/1", "token_value": "STABLE-TOKEN-0001",
                    "context_id": 4, "verifier_nonce": "nonce-from-verifier-A",
                    "issued_at": "2026-09-16T00:00:00Z", "algorithm": "ML-DSA-65",
                    "signature_hex": "bb" * 3309, "public_key_hex": "aa" * 1952}

    def test_a_holder_proof_without_a_binding_is_not_bounded(self):
        """The counterexample. The wallet emits `holder_proof` whenever a verifier supplies
        a nonce, and `holder_binding` only when the wallet holds a binding file, so a
        transcript with the proof and no binding is a shape the shipped tool produces."""
        v = self._corr(zk_proof=self.ZK, holder_proof=self.HOLDER_PROOF)
        self.assertEqual(v["correlation"], "exposed",
                         "the holder proof showed a stable token value and the holder's "
                         "public key; two verifiers link on either in one comparison")

    def test_each_container_that_can_carry_stable_material_is_checked(self):
        """One field per container, alone, with nothing else stable in the transcript."""
        for container, field, value in (
                ("credential", "token_value", "STABLE-TOKEN-0001"),
                ("credential", "token_id", 4711),
                ("holder_binding", "token_value", "STABLE-TOKEN-0001"),
                ("holder_binding", "signature_hex", "ff" * 64),
                ("holder_proof", "token_value", "STABLE-TOKEN-0001"),
                ("holder_proof", "public_key_hex", "aa" * 1952),
                ("status_assertion", "token_value", "STABLE-TOKEN-0001"),
                ("status_assertion", "signature_hex", "ff" * 64)):
            with self.subTest(container=container, field=field):
                v = self._corr(zk_proof=self.ZK, **{container: {field: value}})
                self.assertEqual(v["correlation"], "exposed",
                                 "%s.%s is the same value at every verifier" % (container, field))

    def test_an_integer_token_id_is_as_linkable_as_a_string_one(self):
        """The check tested `isinstance(val, str)`, so a numeric id would have walked past
        it. A token id is a small integer in every pack the application builds."""
        v = self._corr(zk_proof=self.ZK, credential={"token_id": 4711})
        self.assertEqual(v["correlation"], "exposed")

    def test_the_presented_code_alone_is_enough(self):
        """It is opaque and never interpreted. It does not have to be interpreted to be a
        handle: the holder sends the same code wherever they present."""
        v = self._corr(zk_proof=self.ZK, presented_code="CODE-HOLDER-0001")
        self.assertEqual(v["correlation"], "exposed")

    def test_the_strong_form_still_reaches_bounded(self):
        """The direction that keeps the widening honest. If every transcript became
        `exposed`, these tests would all pass and the verdict would carry no information."""
        v = self._corr(zk_proof=self.ZK)
        self.assertEqual(v["correlation"], "bounded")
        self.assertEqual(v["pairwise_handle"], "cc" * 32)

    def test_the_epoch_root_does_not_make_a_presentation_exposed(self):
        """It is identical at every verifier and must NOT be listed: it is the commitment
        the proof is made against and is deliberately shared by the whole epoch. Listing it
        would make `bounded` unreachable and would misdescribe the anonymity set."""
        zk = {"proof_hex": "00",
              "public_inputs": {"epoch_root_hex": "ab" * 32, "epoch_id": 3, "scope": 77,
                                "nullifier_hex": "cc" * 32}}
        self.assertEqual(self._corr(zk_proof=zk)["correlation"], "bounded")

    def test_every_container_the_format_defines_has_been_decided_about(self):
        """The structural guard, and the actual lesson. An allowlist of field paths repeats
        this defect every time a sub-object is added. This fails if a container appears in
        the format with no entry in the stable-field table and no recorded reason."""
        listed = {c for c, _, _ in V._STABLE_CROSS_VERIFIER_FIELDS}
        # zk_proof carries nothing stable, for reasons stated beside the table: its
        # nullifier is scoped and its epoch root is the anonymity set.
        decided = listed | {"zk_proof"}
        self.assertEqual(set(V._PRESENTATION_CONTAINERS) - decided, set(),
                         "a container the presentation format defines has no decision "
                         "recorded about whether stable material can ride in it")
        for container, _field, why in V._PER_VERIFIER_SIGNATURES:
            self.assertIn(container, V._PRESENTATION_CONTAINERS)
            self.assertTrue(why.strip(), "say WHY it differs per verifier, not just that it does")


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


class TheEightFunctionsTheBatteryDidNotCoverTests(unittest.TestCase):
    """Totality for the entry points `_HOSTILE` never reached, and the class it never had.

    An adversarial review on 2026-09-17 found every one of these raising out of a function
    whose docstring promises a verdict. `verify_pack` is the sharpest: it is the primary
    external door, the stranger chooses the JSON, and the crash came out of the shipped
    command as a traceback on stderr, an EMPTY stdout and exit 1, a code the module's own
    docstring does not define. A relying party parsing stdout got nothing.
    """

    def _each(self, label, call):
        for bad in _HOSTILE:
            with self.subTest(fn=label, value=repr(bad)[:44]):
                out = call(bad)
                self.assertTrue(isinstance(out, (dict, tuple, bool, type(None))),
                                "%s must return a verdict, got %r" % (label, out))

    def test_verify_pack_is_total(self):
        self._each("verify_pack", V.verify_pack)

    def test_verify_stapled_is_total_in_both_arguments(self):
        self._each("verify_stapled(pack)", lambda b: V.verify_stapled(b, {}))
        self._each("verify_stapled(assertion)", lambda b: V.verify_stapled({}, b))

    def test_verify_cosignature_is_total(self):
        self._each("verify_cosignature", V.verify_cosignature)

    def test_verify_publication_is_total(self):
        self._each("verify_publication", lambda b: V.verify_publication(b, b, "k"))

    def test_the_three_structural_detectors_are_total(self):
        """These take two artifacts off the wire from two DIFFERENT sources and compare
        them, which is the whole point of a fork detector, and none had a type guard."""
        for label, call in (("check_epoch_chain", lambda b: V.check_epoch_chain(b, {})),
                            ("check_epoch_chain(2)", lambda b: V.check_epoch_chain({}, b)),
                            ("epoch_aligned", lambda b: V.epoch_aligned(b, {})),
                            ("epoch_aligned(2)", lambda b: V.epoch_aligned({}, b)),
                            ("check_revocation_progression",
                             lambda b: V.check_revocation_progression(b, {})),
                            ("check_revocation_progression(2)",
                             lambda b: V.check_revocation_progression({}, b))):
            self._each(label, call)

    def test_a_hostile_cosignature_list_does_not_crash_the_anchor_check(self):
        """`anchor` is unsigned by design, so an attacker writes the list freely, and
        `verify_witnessed_checkpoint` calls `verify_cosignature` on every element of it.
        One string in that list raised out of `verify_timestamp_anchor`, whose docstring
        ends "Total on hostile input"."""
        for junk in (["a string"], [None], [5], [[]], "not-a-list", 5):
            with self.subTest(cosignatures=repr(junk)[:30]):
                ts = {"format": "polaris-timestamp/1",
                      "anchor": {"proof": {}, "sth": {}, "cosignatures": junk}}
                self.assertIsInstance(V.verify_timestamp_anchor(ts), dict)


class ForkDetectionSurvivesANonFiniteEpochTests(unittest.TestCase):
    """A fork detector defeated by three characters is a fork detector that is not there.

    Every comparison against NaN is False, so `n1 <= n2`, `nlo == nhi` and `nhi == nlo + 1`
    were all False and the pair fell through to the "monotone but non-adjacent" SUCCESS
    return at the bottom of the function. `json.loads` accepts the bare literal `NaN` by
    default, which is how it arrives.
    """

    KEY = "ab" * 32

    def _cp(self, number, root, prev=None):
        # `prev` hangs off the CHECKPOINT, not the epoch: check_epoch_chain reads
        # `hi.get("prev")` where `hi` is the checkpoint it decided was the later one.
        cp = {"public_key_hex": self.KEY, "epoch": {"number": number, "root_hex": root}}
        if prev is not None:
            cp["prev"] = prev
        return cp

    def test_two_roots_at_one_epoch_is_a_fork(self):
        v = V.check_epoch_chain(self._cp(5, "aa"), self._cp(5, "bb"))
        self.assertTrue(v["fork"], "the positive control: this IS a fork")

    def test_a_non_finite_epoch_number_cannot_turn_a_fork_into_agreement(self):
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(number=repr(bad)):
                v = V.check_epoch_chain(self._cp(5, "aa"), self._cp(bad, "bb"))
                self.assertFalse(v["consistent"],
                                 "a checkpoint whose epoch number is %r must not be "
                                 "reported as consistent with anything" % bad)

    def test_a_non_numeric_epoch_number_is_refused_rather_than_compared(self):
        for bad in ("5", None, [], True, {}):
            with self.subTest(number=repr(bad)):
                v = V.check_epoch_chain(self._cp(5, "aa"), self._cp(bad, "bb"))
                self.assertFalse(v["consistent"])

    def test_a_clean_adjacent_pair_still_chains(self):
        """The direction that keeps the rest honest. A detector that called every pair
        inconsistent would pass every test above while telling a relying party nothing."""
        later = self._cp(6, "bb", prev={"number": 5, "root_hex": "aa"})
        v = V.check_epoch_chain(self._cp(5, "aa"), later)
        self.assertTrue(v["consistent"], v["note"])
        self.assertFalse(v["fork"])


class GrantLimitsSurviveANonFiniteNumberTests(unittest.TestCase):
    """`limits` is inside the SIGNED statement, so a grant signed with `max_amount: NaN` was
    a signed UNLIMITED grant wearing a limit field."""

    def test_a_nan_limit_does_not_authorise_any_amount(self):
        ok, note = V.grant_within_limits({"limits": {"max_amount": float("nan")}}, 0, 10 ** 9)
        self.assertFalse(ok, "a limit this verifier cannot evaluate must be REFUSED, which "
                             "is what the docstring promises, not ignored")
        self.assertIn("finite", note)

    def test_a_nan_amount_does_not_clear_a_real_limit(self):
        ok, _ = V.grant_within_limits({"limits": {"max_amount": 100}}, 0, float("nan"))
        self.assertFalse(ok)

    def test_an_infinite_use_count_is_refused_rather_than_crashing(self):
        """`int(float('inf'))` raises OverflowError, which `(TypeError, ValueError)` does
        not catch, so this crashed instead of refusing."""
        for grant, uses in (({"limits": {"max_uses": float("inf")}}, 0),
                            ({"limits": {"max_uses": 3}}, float("inf"))):
            with self.subTest(uses=repr(uses)):
                ok, note = V.grant_within_limits(grant, uses)
                self.assertFalse(ok)
                self.assertIsInstance(note, str)

    def test_a_real_limit_still_admits_and_still_refuses(self):
        self.assertEqual(V.grant_within_limits({"limits": {"max_amount": 100}}, 0, 50), (True, None))
        self.assertFalse(V.grant_within_limits({"limits": {"max_amount": 100}}, 0, 1000)[0])
        self.assertEqual(V.grant_within_limits({"limits": {"max_uses": 3}}, 1), (True, None))
        self.assertFalse(V.grant_within_limits({"limits": {"max_uses": 3}}, 3)[0])


class TheAttestationWindowIsReadTests(unittest.TestCase):
    """`valid_until` is in the signed statement and was compared to NOTHING.

    It appeared exactly once in the verifier, inside `_attestation_canonical`, and no
    consumer read it. A trust edge an authority time-boxed to one year kept granting
    cross-authority acceptance six years past its end, because the manifest carrying the row
    was fresh and the row's own window was never looked at. Two published promises said
    otherwise: WIRE-SPEC section 3.14 ("and the window, so it cannot be extended") and the
    Python SDK's own comment ("which the trust decision reads").
    """

    def _att(self, valid_until):
        return {"format": "polaris-trust-attestation/1", "attesting_agency_id": "A",
                "attested_agency_id": "B", "attested_public_key_hex": "cc" * 32,
                "context_id": 1, "attested_date": "2020-01-01", "valid_until": valid_until}

    def test_an_expired_window_is_closed(self):
        for until in ("2020-01-01T00:00:00Z", "1970-01-01T00:00:00Z"):
            with self.subTest(valid_until=until):
                self.assertFalse(V._attestation_window_open(self._att(until),
                                                            "2026-09-17T00:00:00Z"))

    def test_an_unreadable_window_is_closed_not_open(self):
        """Otherwise `valid_until: "forever"` is how you sign a permanent trust edge."""
        for until in ("not-a-date", "", 5, [], {}, True):
            with self.subTest(valid_until=repr(until)):
                self.assertFalse(V._attestation_window_open(self._att(until),
                                                            "2026-09-17T00:00:00Z"))

    def test_a_live_window_is_open(self):
        self.assertTrue(V._attestation_window_open(self._att("2099-01-01T00:00:00Z"),
                                                   "2026-09-17T00:00:00Z"))

    def test_no_window_stated_is_not_a_window_that_closed(self):
        att = self._att(None)
        att.pop("valid_until")
        self.assertTrue(V._attestation_window_open(att, "2026-09-17T00:00:00Z"))

    def test_the_verdict_reports_the_window_it_read(self):
        v = V.verify_attestation(self._att("2020-01-01T00:00:00Z"), now="2026-09-17T00:00:00Z")
        self.assertIn("expired", v)
        self.assertIn("valid_until", v)


class TheKeyStatusDefaultSaysUnknownTests(unittest.TestCase):
    """A key-revocation function defaulted to "active" for every value it did not
    recognise, so `COMPROMISED` with a capital letter read as a usable key."""

    KEY = "ab" * 32

    def _tl(self, status):
        return {"keys": [{"public_key_hex": self.KEY, "status": status,
                          "registered_at": "2020-01-01T00:00:00Z"}]}

    def test_the_three_words_the_specification_fixes_are_read(self):
        for status in ("active", "retired", "compromised"):
            with self.subTest(status=status):
                self.assertEqual(V.key_status_at(self._tl(status), self.KEY,
                                                 "2026-09-17T00:00:00Z"), status)

    def test_anything_else_is_unknown_rather_than_active(self):
        for status in ("COMPROMISED", "Compromised", "revoked", "suspended", None, 1, [], {}):
            with self.subTest(status=repr(status)):
                self.assertEqual(V.key_status_at(self._tl(status), self.KEY,
                                                 "2026-09-17T00:00:00Z"), "unknown",
                                 "an out-of-vocabulary status must not read as usable")


class TheCborDecoderIsBoundedTests(unittest.TestCase):
    """996 nested arrays, 997 bytes of input, raised RecursionError out of `verify_mdoc`,
    whose catch clause does not list it. With the recursion limit raised, which embedders
    do, the same input segmentation-faulted the process, and a SIGSEGV is not an exception
    anybody can catch."""

    def test_deep_nesting_is_a_verdict_not_a_stack_overflow(self):
        for label, data in (("996 nested arrays", b"\x81" * 996 + b"\x00"),
                            ("50000 nested maps", b"\xaa" * 50000)):
            with self.subTest(label):
                self.assertIsInstance(V.verify_mdoc(data), dict)

    def test_a_non_scalar_cbor_map_key_is_a_verdict(self):
        """`out[k] = v` raised `TypeError: unhashable type`, which the handler did not
        catch. The two INNER cbor decodes already caught it; the outer one did not."""
        for label, data in (("map with a list key", b"\xa1\x80\x00"),
                            ("map with a map key", b"\xa1\xa0\x00")):
            with self.subTest(label):
                self.assertIsInstance(V.verify_mdoc(data), dict)

    def test_a_shallow_document_still_decodes(self):
        self.assertIsInstance(V.verify_mdoc(b"\xa1\x00\x00"), dict)


class TheQrDecoderIsTotalOnANonAsciiFrameTests(unittest.TestCase):
    """The digest line sat OUTSIDE the try, so one stray byte raised UnicodeEncodeError out
    of a function documented "Total: hostile input yields a reason, never a crash". A QR or
    NFC payload is exactly where a stray byte arrives."""

    def test_a_non_ascii_frame_is_a_reason(self):
        frame = "PLRS1/1/0/" + "00" * 32 + "/é"
        out, reason = V.decode_presentation_frames([frame])
        self.assertIsNone(out)
        self.assertIn("ASCII", reason)

    def test_an_ascii_frame_still_reaches_the_digest_check(self):
        frame = "PLRS1/1/0/" + "00" * 32 + "/abcd"
        out, reason = V.decode_presentation_frames([frame])
        self.assertIsNone(out)
        self.assertIn("digest", reason)


class TheWindowCapFailsClosedOnANonFiniteValueTests(unittest.TestCase):
    """Two functions hand-rolled `if width > max_window_seconds` and failed OPEN on a
    non-finite cap, because `anything > nan` is False, while the shared gate, written as
    `0 < width <= max`, refused. And the shared gate then RAISED while formatting the note
    that said so: `"%ds" % nan` is a ValueError."""

    OBJ = {"issued_at": "2026-01-01T00:00:00Z", "expires_at": "2125-01-01T00:00:00Z"}

    def test_a_99_year_window_is_refused_under_every_cap_shape(self):
        for cap in (60, float("nan"), float("inf"), float("-inf"), "x", []):
            with self.subTest(cap=repr(cap)):
                v = {"fresh": None, "note": None}
                V._verify_window(self.OBJ, v, "2026-06-01T00:00:00Z", cap)
                self.assertFalse(v["fresh"], "cap=%r must not admit a 99-year window" % cap)
                self.assertIsInstance(v["note"], str)

    def test_no_cap_supplied_still_means_no_cap(self):
        v = {"fresh": None, "note": None}
        V._verify_window(self.OBJ, v, "2026-06-01T00:00:00Z", None)
        self.assertTrue(v["fresh"], "None is 'the caller set no cap', not 'the cap is zero'")
