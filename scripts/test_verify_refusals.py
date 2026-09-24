"""test_verify_refusals.py -- the detached verifier's refusals, each one driven directly.

WHY THIS FILE EXISTS. On 2026-09-23 every refusal in `polaris_verify_cli/verifier.py` (the
`polaris-verify` package, the first thing a stranger installs) was inverted in turn, made to
accept what it exists to reject, and every instrument CI runs against that verifier was
re-run: its unit suites, the self-test, `--verify-dir vectors`, the crypto attack suite, the
verifier fuzzer and the twenty-four drills that load it. 32 of 45 inversions left all of
them green. Among them: the RFC 6962 consistency check (a log that rewrote its history),
the inclusion check, the `cryptography` witness's refusal of a forged signature (hidden
because liboqs, the second witness, was also installed; a stranger following the README
installs only `cryptography`), and a zero-knowledge prover that exits non-zero.

Every test here calls the function that owns the refusal, with an input that reaches that
refusal and no other, and asserts the refusing answer. Each is paired with the genuine case
passing, so a verifier that refuses everything cannot satisfy it. The mutation drill
(`scripts/polaris-sdk-mutation-drill.py`, the `verify` entry) re-measures this file's reach.

    cd scripts && python3 -m unittest test_verify_refusals
"""
import importlib.util
import json
import os
import pathlib
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
_spec = importlib.util.spec_from_file_location("polaris_verify_refusals", HERE / "polaris-verify.py")
V = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(V)


def _cryptography_mldsa():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except Exception:  # noqa: BLE001  absent or too old: the same answer
        return False
    return hasattr(mldsa, "MLDSA65PublicKey")


# --------------------------------------------------------------------------- the logs

class ConsistencyRefusals(unittest.TestCase):
    """RFC 6962 consistency: the size-m head is a prefix of the size-n head."""

    ENTRIES = ["entry-%02d" % i for i in range(13)]

    def heads(self, m, n):
        return V.merkle_tree_head(self.ENTRIES[:m]), V.merkle_tree_head(self.ENTRIES[:n])

    def test_every_genuine_proof_verifies(self):
        for n in range(1, len(self.ENTRIES) + 1):
            for m in range(1, n + 1):
                r1, r2 = self.heads(m, n)
                proof = V.consistency_proof(m, self.ENTRIES[:n])
                self.assertTrue(V.verify_consistency(m, n, r1, r2, proof), (m, n))

    def test_sizes_out_of_order_are_refused(self):
        r1, r2 = self.heads(3, 7)
        self.assertFalse(V.verify_consistency(7, 3, r2, r1, []))
        self.assertFalse(V.verify_consistency(-1, 7, r1, r2, []))

    def test_a_growing_log_with_no_proof_is_refused(self):
        r1, r2 = self.heads(3, 7)
        self.assertFalse(V.verify_consistency(3, 7, r1, r2, []))

    def test_every_truncated_proof_is_refused(self):
        # Reaches each point where the walk runs out of proof: inside the node loop on both
        # arms, and in the final climb.
        for n in range(2, len(self.ENTRIES) + 1):
            for m in range(1, n):
                r1, r2 = self.heads(m, n)
                proof = V.consistency_proof(m, self.ENTRIES[:n])
                for k in range(len(proof)):
                    self.assertFalse(V.verify_consistency(m, n, r1, r2, proof[:k]), (m, n, k))

    def test_a_proof_with_an_extra_node_is_refused(self):
        r1, r2 = self.heads(5, 11)
        proof = V.consistency_proof(5, self.ENTRIES[:11])
        self.assertFalse(V.verify_consistency(5, 11, r1, r2, proof + [proof[0]]))

    def test_a_rewritten_history_is_refused(self):
        m, n = 5, 11
        r1, _ = self.heads(m, n)
        rewritten = self.ENTRIES[:2] + ["rewritten"] + self.ENTRIES[3:n]
        r2 = V.merkle_tree_head(rewritten)
        self.assertFalse(V.verify_consistency(m, n, r1, r2, V.consistency_proof(m, rewritten)))

    def test_equal_sizes_need_equal_heads_and_no_proof(self):
        r1, _ = self.heads(4, 4)
        self.assertTrue(V.verify_consistency(4, 4, r1, r1, []))
        self.assertFalse(V.verify_consistency(4, 4, r1, r1, [r1]))


class InclusionRefusals(unittest.TestCase):

    ENTRIES = ["leaf-%02d" % i for i in range(11)]

    def test_every_genuine_proof_verifies(self):
        root = V.merkle_tree_head(self.ENTRIES)
        for i, e in enumerate(self.ENTRIES):
            proof = V.inclusion_proof(i, self.ENTRIES)
            self.assertTrue(V.verify_inclusion(i, len(self.ENTRIES), V._lh(e), root, proof), i)

    def test_an_index_outside_the_tree_is_refused(self):
        root = V.merkle_tree_head(self.ENTRIES)
        leaf = V._lh(self.ENTRIES[0])
        self.assertFalse(V.verify_inclusion(len(self.ENTRIES), len(self.ENTRIES), leaf, root, []))
        self.assertFalse(V.verify_inclusion(-1, len(self.ENTRIES), leaf, root, []))

    def test_a_proof_longer_than_the_tree_is_refused(self):
        root = V.merkle_tree_head(self.ENTRIES)
        i = len(self.ENTRIES) - 1
        proof = V.inclusion_proof(i, self.ENTRIES)
        self.assertFalse(V.verify_inclusion(i, len(self.ENTRIES), V._lh(self.ENTRIES[i]), root,
                                            proof + [root, root, root, root]))

    def test_a_leaf_that_is_not_there_is_refused(self):
        root = V.merkle_tree_head(self.ENTRIES)
        proof = V.inclusion_proof(3, self.ENTRIES)
        self.assertFalse(V.verify_inclusion(3, len(self.ENTRIES), V._lh("not in the log"), root, proof))


# --------------------------------------------------------------------------- membership

class RevocationMembershipIsTotal(unittest.TestCase):
    """`is_revoked` answers False (not listed) on hostile input rather than raising."""

    def test_listed_leaf_is_found(self):
        leaf = V.revocation_leaf("TOK-1")
        self.assertTrue(V.is_revoked({"revoked_leaves": [leaf]}, "TOK-1"))
        self.assertTrue(V.is_revoked_leaf({"revoked_leaves": [leaf.upper()]}, leaf))

    def test_a_feed_that_is_not_a_dict_lists_nothing(self):
        for feed in (None, [], "revoked", 7):
            self.assertIs(V.is_revoked(feed, "TOK-1"), False)
            self.assertIs(V.is_revoked_leaf(feed, "ab"), False)

    def test_leaves_that_are_not_a_collection_list_nothing(self):
        for leaves in (None, "ab", 7, {"ab": 1}):
            self.assertIs(V.is_revoked({"revoked_leaves": leaves}, "TOK-1"), False)
            self.assertIs(V.is_revoked_leaf({"revoked_leaves": leaves}, "ab"), False)


class PairwiseHandles(unittest.TestCase):

    def test_equal_handles_link_and_non_strings_do_not(self):
        self.assertTrue(V.handles_link("AB12", "ab12 "))
        for a, b in ((None, None), (1, 1), (["ab"], ["ab"]), ("ab", None)):
            self.assertIs(V.handles_link(a, b), False)


# --------------------------------------------------------------------------- windows

class Windows(unittest.TestCase):

    def test_window_within_its_cap(self):
        t = datetime(2026, 9, 23, tzinfo=timezone.utc)
        self.assertTrue(V._window_within(t, t + timedelta(seconds=60), 3600))

    def test_a_cap_that_is_not_a_finite_number_refuses(self):
        t = datetime(2026, 9, 23, tzinfo=timezone.utc)
        for cap in (float("nan"), float("inf"), None, "3600", True):
            self.assertIs(V._window_within(t, t + timedelta(seconds=60), cap), False, cap)

    def test_times_that_cannot_be_subtracted_refuse(self):
        self.assertIs(V._window_within("yesterday", "today", 3600), False)

    def test_an_attestation_that_is_not_a_dict_is_closed(self):
        self.assertTrue(V._attestation_window_open({}, datetime(2026, 9, 23, tzinfo=timezone.utc)))
        for att in (None, [], "open", 1):
            self.assertIs(V._attestation_window_open(att, datetime(2026, 9, 23, tzinfo=timezone.utc)),
                          False)


# --------------------------------------------------------------------------- witnesses

class Witnesses(unittest.TestCase):
    """Each witness refuses on its own. A relying party that installed only the
    `cryptography` extra, as the README recommends, has ONE witness, so its refusal cannot
    lean on the other's."""

    @classmethod
    def setUpClass(cls):
        pack = json.loads((ROOT / "vectors" / "ml-dsa-65-valid.json").read_text())
        cls.digest = V._digest(pack["token_value"])
        cls.sig = bytes.fromhex(pack["signature_hex"])
        cls.pk = bytes.fromhex(pack["public_key_hex"])

    @unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
    def test_cryptography_witness_alone(self):
        self.assertIs(V._verify_cryptography(self.digest, self.sig, self.pk), True)
        bad = bytearray(self.sig); bad[0] ^= 1
        self.assertIs(V._verify_cryptography(self.digest, bytes(bad), self.pk), False)
        self.assertIs(V._verify_cryptography(self.digest[::-1], self.sig, self.pk), False)

    @unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
    def test_cryptography_witness_refuses_a_signature_of_the_wrong_length(self):
        self.assertIs(V._verify_cryptography(self.digest, self.sig[:10], self.pk), False)

    @unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
    def test_cryptography_witness_refuses_a_signature_that_is_not_bytes(self):
        # Not InvalidSignature: the library raises a TypeError, and that arm must refuse too.
        self.assertIs(V._verify_cryptography(self.digest, self.sig.hex(), self.pk), False)

    def test_liboqs_witness_refuses_what_the_library_throws_on(self):
        try:
            V._import_oqs()
        except Exception:  # noqa: BLE001
            self.skipTest("liboqs absent")
        self.assertIs(V._verify_liboqs(self.digest, self.sig, self.pk), True)
        self.assertIs(V._verify_liboqs(self.digest, self.sig.hex(), self.pk), False)   # the library raises TypeError

    def test_an_unknown_provider_is_not_available(self):
        for name in ("bogus", "", None, "OQS"):
            self.assertIs(V._provider_available(name), False, name)

    def test_liboqs_witness_refuses_an_algorithm_below_the_floor_before_loading(self):
        # Decided before the library is imported, so it holds with or without liboqs.
        self.assertIs(V._verify_liboqs(self.digest, self.sig, self.pk, "ML-DSA-44"), False)
        self.assertIs(V._verify_liboqs(self.digest, self.sig, self.pk, "RSA-2048"), False)


# --------------------------------------------------------------------------- the prover

class ZeroKnowledgeProverOutcomes(unittest.TestCase):
    """A prover that exits non-zero, or answers with something that is not a verdict, is a
    refusal. Driven with stand-in binaries, so this needs no Rust build."""

    def binary(self, body):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "fake-zk")
        with open(p, "w") as f:
            f.write("#!/bin/sh\ncat >/dev/null\n" + body + "\n")
        os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC)
        return p

    def test_a_verified_answer_is_accepted(self):
        self.assertIs(V._zk_verify_proof({}, zk_binary=self.binary('echo \'{"verified": true}\'')), True)

    def test_a_failing_prover_is_a_refusal(self):
        self.assertIs(V._zk_verify_proof({}, zk_binary=self.binary('echo \'{"verified": true}\'; exit 1')),
                      False)

    def test_an_answer_that_is_not_json_is_a_refusal(self):
        self.assertIs(V._zk_verify_proof({}, zk_binary=self.binary("echo verified")), False)

    def test_no_binary_abstains(self):
        self.assertIsNone(V._zk_verify_proof({}, zk_binary="/nonexistent/polaris-zk"))


# --------------------------------------------------------------------------- delegation

class GrantLimits(unittest.TestCase):

    def test_known_limits_within_bounds_pass(self):
        self.assertEqual(V.grant_within_limits({"limits": {"max_uses": 3}}, uses_so_far=1), (True, None))

    def test_a_limit_this_verifier_does_not_understand_is_refused(self):
        ok, note = V.grant_within_limits({"limits": {"max_uses": 3, "max_transfers": 1}}, uses_so_far=0)
        self.assertIs(ok, False)
        self.assertIn("max_transfers", note)


# --------------------------------------------------------------------------- CBOR and mdoc

def _hdr(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    if n < 256:
        return bytes([major << 5 | 24, n])
    return bytes([major << 5 | 25]) + n.to_bytes(2, "big")


def _cbor(x):
    """The smallest encoder these fixtures need: ints, bytes, text, lists, maps, tag 24."""
    if isinstance(x, tuple) and x[0] == "tag24":
        return b"\xd8\x18" + _cbor(x[1])
    if isinstance(x, bool) or x is None:
        return {False: b"\xf4", True: b"\xf5", None: b"\xf6"}[x]
    if isinstance(x, int):
        return _hdr(0, x) if x >= 0 else _hdr(1, -1 - x)
    if isinstance(x, (bytes, bytearray)):
        return _hdr(2, len(x)) + bytes(x)
    if isinstance(x, str):
        b = x.encode("utf-8")
        return _hdr(3, len(b)) + b
    if isinstance(x, list):
        return _hdr(4, len(x)) + b"".join(_cbor(i) for i in x)
    if isinstance(x, dict):
        return _hdr(5, len(x)) + b"".join(_cbor(k) + _cbor(v) for k, v in x.items())
    raise TypeError(type(x))


class CborRefusals(unittest.TestCase):

    def test_well_formed_documents_decode(self):
        self.assertEqual(V._cbor_decode(_cbor({"a": [1, b"x", "y"]})), {"a": [1, b"x", "y"]})

    def test_each_malformed_encoding_is_refused(self):
        for label, buf in (("empty", b""),
                           ("truncated array", _hdr(4, 2) + _cbor(1)),
                           ("indefinite length", b"\x9f\x01\xff"),
                           ("reserved additional information", b"\x1c"),
                           ("truncated string", _hdr(2, 5) + b"ab"),
                           ("a list as a map key", _hdr(5, 1) + _cbor([1]) + _cbor(1)),
                           ("trailing bytes", _cbor(1) + _cbor(2))):
            with self.assertRaises(ValueError, msg=label):
                V._cbor_decode(buf)


class MdocTag24Refusals(unittest.TestCase):
    """Both refusals sit before any signature is checked, so a hand-built document reaches
    them with no crypto library at all."""

    def document(self, payload, items):
        return _cbor({"docType": V._MDOC_DOC_TYPE,
                      "issuerSigned": {"nameSpaces": {V._MDOC_NAMESPACE: items},
                                       "issuerAuth": [_cbor({1: -49}), {}, payload, b"sig"]}})

    def mso(self):
        return _cbor(("tag24", _cbor({"docType": V._MDOC_DOC_TYPE, "digestAlgorithm": "SHA-256",
                                      "valueDigests": {V._MDOC_NAMESPACE: {}}})))

    def test_an_mso_outside_tag_24_is_refused(self):
        v = V.verify_mdoc(self.document(_cbor({"docType": V._MDOC_DOC_TYPE}), []))
        self.assertIs(v["issuer_authentic"], False)
        self.assertIn("tag 24", v["note"] or "")

    def test_an_element_outside_tag_24_is_refused(self):
        v = V.verify_mdoc(self.document(self.mso(), [_cbor({"digestID": 0})]))
        self.assertIs(v["issuer_authentic"], False)
        self.assertIsNot(v["digests_match"], True)
        self.assertIn("tag 24", json.dumps(v))



# --------------------------------------------------------------------------- held-out round

class HeldOutSemanticMutations(unittest.TestCase):
    """2026-09-23: ten semantic mutations written after the refusal tests above (half a
    comparison dropped, an off-by-one, a lookup made case-sensitive) were run against every
    instrument CI runs on this verifier. Six survived. Each test here is aimed at one of them."""

    def test_an_inclusion_proof_for_a_smaller_tree_is_refused_at_a_larger_size(self):
        small = ["e%d" % i for i in range(5)]
        root_small = V.merkle_tree_head(small)
        proof = V.inclusion_proof(2, small)
        self.assertTrue(V.verify_inclusion(2, 5, V._lh(small[2]), root_small, proof))
        self.assertFalse(V.verify_inclusion(2, 11, V._lh(small[2]), root_small, proof))

    def test_an_index_equal_to_the_tree_size_is_refused(self):
        entries = ["only"]
        root = V.merkle_tree_head(entries)
        self.assertTrue(V.verify_inclusion(0, 1, V._lh(entries[0]), root, []))
        self.assertFalse(V.verify_inclusion(1, 1, V._lh(entries[0]), root, []))

    def test_a_window_that_ends_before_it_starts_is_refused(self):
        t = datetime(2026, 9, 23, tzinfo=timezone.utc)
        self.assertIs(V._window_within(t, t - timedelta(seconds=60), 3600), False)
        self.assertIs(V._window_within(t, t, 3600), False)

    def test_a_revoked_leaf_is_found_whatever_case_the_feed_uses(self):
        leaf = V.revocation_leaf("TOK-UPPER")
        self.assertTrue(V.is_revoked({"revoked_leaves": [leaf.upper()]}, "TOK-UPPER"))

    def test_an_amount_over_the_limit_by_any_margin_is_refused(self):
        grant = {"limits": {"max_amount": 100}}
        self.assertEqual(V.grant_within_limits(grant, amount=100), (True, None))
        self.assertIs(V.grant_within_limits(grant, amount=101)[0], False)
        self.assertIs(V.grant_within_limits(grant, amount=150)[0], False)

    def test_two_witnesses_that_disagree_are_a_refusal(self):
        pack = json.loads((ROOT / "vectors" / "ml-dsa-65-valid.json").read_text())
        saved = (V._verify_liboqs, V._verify_cryptography)
        try:
            for a, b in ((True, False), (False, True)):
                V._verify_liboqs = lambda *args, _a=a, **kw: _a
                V._verify_cryptography = lambda *args, _b=b, **kw: _b
                v = V.verify_pack(pack)
                self.assertIs(v["signature_valid"], False, (a, b))
                self.assertEqual(v.get("authenticity"), "witness-disagreement")
        finally:
            V._verify_liboqs, V._verify_cryptography = saved


# --------------------------------------------------------------------------- the exit codes

@unittest.skipUnless(any(V._provider_available(p) for p in V.REAL_PROVIDERS),
                     "no real ML-DSA backend; the exit-code contract is about real verdicts")
class CommandLineExitCodes(unittest.TestCase):
    """The README's exit-code table is what a script built on this command relies on, and
    held-out mutations of `main` (2026-09-23) moved codes with every suite green: nothing
    ran `main` and read its return value. Each test asserts one row of that table.

    Where a row depends on a verdict no published fixture produces (a stapled pair that is
    genuine but whose trust was not evaluated, an unusable presentation, an abstaining ZK
    decision), the verdict function is replaced for the one call and only `main`'s mapping
    from verdict to exit code is under test. That is the mechanism the rows describe."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-cli-exit-"))
        valid = json.loads((ROOT / "vectors" / "ml-dsa-65-valid.json").read_text())
        cls.pack = cls.tmp / "pack.json"
        cls.pack.write_text(json.dumps(valid))
        cls.good_anchor = cls.tmp / "good.json"
        cls.good_anchor.write_text(json.dumps([valid["public_key_hex"]]))
        cls.other_anchor = cls.tmp / "other.json"
        cls.other_anchor.write_text(json.dumps(["ab" * 1952]))
        cls.blob = cls.tmp / "blob.json"
        cls.blob.write_text("{}")

    def main(self, *argv):
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return V.main(list(argv))

    def test_a_run_that_declares_no_cryptography_refuses_to_start(self):
        """For the RIGHT reason. With this refusal deleted the run still exits 4, because the
        next check finds backend `None` unusable, and tells the caller that a backend called
        None is not installed instead of that no mode was declared. The exit code alone is
        satisfied by the wrong mechanism, so the message is asserted too."""
        import contextlib
        import io
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = V.main(["--pack", str(self.pack)])
        self.assertEqual(code, 4)
        self.assertIn("say what cryptography this run uses", err.getvalue())

    def test_a_run_that_declares_both_modes_refuses_to_start(self):
        self.assertEqual(self.main("--pqc-provider", "auto", "--dev-placeholder",
                                   "--pack", str(self.pack)), 4)

    def test_a_named_backend_that_is_not_usable_refuses_to_start(self):
        from unittest import mock
        with mock.patch.object(V, "_provider_available", return_value=False):
            for provider in ("oqs", "cryptography", "auto"):
                with self.subTest(provider=provider):
                    self.assertEqual(self.main("--pqc-provider", provider, "--pack", str(self.pack)), 4)

    def test_a_genuine_signature_with_no_anchor_abstains(self):
        self.assertEqual(self.main("--pqc-provider", "auto", "--pack", str(self.pack)), 2)
        self.assertEqual(self.main("--pqc-provider", "auto", "--signature-only",
                                   "--pack", str(self.pack)), 0)

    def test_the_anchor_decides_the_exit(self):
        self.assertEqual(self.main("--pqc-provider", "auto", "--pack", str(self.pack),
                                   "--issuer-anchor", str(self.good_anchor)), 0)
        self.assertEqual(self.main("--pqc-provider", "auto", "--pack", str(self.pack),
                                   "--issuer-anchor", str(self.other_anchor)), 2)

    def test_a_stapled_accept_without_evaluated_trust_abstains(self):
        from unittest import mock
        accepted = {"decision": "accept", "authentic": True, "status": "ACTIVE", "fresh": True,
                    "bound": True, "reasons": [], "credential": {"trust_evaluated": False},
                    "status_assertion": {"trust_evaluated": False}}
        with mock.patch.object(V, "verify_stapled", return_value=accepted):
            self.assertEqual(self.main("--pqc-provider", "auto", "--pack", str(self.pack),
                                       "--status-assertion", str(self.blob)), 2)
            self.assertEqual(self.main("--pqc-provider", "auto", "--signature-only",
                                       "--pack", str(self.pack),
                                       "--status-assertion", str(self.blob)), 0)

    def test_an_unusable_presentation_exits_non_zero(self):
        from unittest import mock
        with mock.patch.object(V, "verify_presentation",
                               return_value={"usable_offline": False, "note": "x"}):
            self.assertEqual(self.main("--pqc-provider", "auto", "--presentation", str(self.blob)), 1)

    def test_an_abstaining_zero_knowledge_decision_exits_2(self):
        from unittest import mock
        for decision, code in (("abstain", 2), ("reject", 1), ("accept", 0)):
            with self.subTest(decision=decision), \
                    mock.patch.object(V, "verify_cross_authority_zk",
                                      return_value={"decision": decision, "reasons": []}):
                self.assertEqual(self.main("--pqc-provider", "auto", "--zk-proof", str(self.blob)), code)


class StapledDecisionNeedsEveryFact(unittest.TestCase):
    """verify_stapled accepts only when seven facts hold at once. 2026-09-23: a held-out round
    dropped each from the acceptance in turn, and five survived every suite and the offline
    status drill, because each drill case breaks more than one fact (a tampered assertion is
    also not fresh and has no status) and the others refused for it. Here the two inner
    verdicts are replaced for one call each: every fact passes, then exactly one does not."""

    GOOD_PACK = {"signature_valid": True, "issuer_trusted": True}
    GOOD_SA = {"status_authentic": True, "issuer_trusted": True, "fresh": True, "status": "ACTIVE"}

    def decide(self, pack=None, sa=None, token=("T", "T")):
        from unittest import mock
        with mock.patch.object(V, "verify_pack", return_value=dict(self.GOOD_PACK, **(pack or {}))), \
                mock.patch.object(V, "verify_status_assertion", return_value=dict(self.GOOD_SA, **(sa or {}))):
            return V.verify_stapled({"token_value": token[0]}, {"token_value": token[1]})["decision"]

    def test_all_seven_facts_accept(self):
        self.assertEqual(self.decide(), "accept")
        self.assertEqual(self.decide(pack={"issuer_trusted": None}, sa={"issuer_trusted": None}),
                         "accept", "no anchor given is not an untrusted issuer")

    def test_each_fact_alone_refuses(self):
        for label, pack, sa in (("credential signature", {"signature_valid": False}, None),
                                ("credential issuer", {"issuer_trusted": False}, None),
                                ("assertion signature", None, {"status_authentic": False}),
                                ("assertion issuer", None, {"issuer_trusted": False}),
                                ("freshness", None, {"fresh": False}),
                                ("freshness unknown", None, {"fresh": None}),
                                ("status", None, {"status": "SUSPENDED"})):
            with self.subTest(label):
                self.assertEqual(self.decide(pack=pack, sa=sa), "reject")

    def test_binding_is_to_this_credential_and_never_to_nothing(self):
        self.assertEqual(self.decide(token=("T", "U")), "reject")
        self.assertEqual(self.decide(token=("", "")), "reject",
                         "two missing token values are not a binding")
        self.assertEqual(self.decide(token=(None, None)), "reject")


@unittest.skipUnless(any(V._provider_available(p) for p in V.REAL_PROVIDERS),
                     "no real ML-DSA backend; these run on real signatures")
class AgentGrantPrincipalBinding(unittest.TestCase):
    """The grant's holder key must be one an issuer bound, freshly, to this credential.
    2026-09-23: a held-out round found three rules here that nothing isolated: the binding
    dropped from `usable` altogether, a stale binding accepted, and a binding to another
    credential accepted. The agent-grant drill's cases break several links at once. The
    genuine grant vector is used as it is; the binding verdict is replaced for one call, so
    each test starts from a usable grant and breaks one property of the binding."""

    NOW = "2026-05-01T00:00:30Z"

    def setUp(self):
        self.grant = json.loads((ROOT / "conformance" / "vectors" / "agent-grant-valid.json").read_text())
        self.good = {"binding_authentic": True, "fresh": True, "bound_to_credential": True,
                     "holder_public_key_hex": self.grant["public_key_hex"], "note": None}

    def verdict(self, **binding):
        from unittest import mock
        with mock.patch.object(V, "verify_holder_binding", return_value=dict(self.good, **binding)):
            return V.verify_agent_grant(self.grant, binding={"format": "x"}, credential={},
                                        now=self.NOW)

    def test_a_good_binding_leaves_the_grant_usable(self):
        v = self.verdict()
        self.assertTrue(v["grant_authentic"], v["note"])
        self.assertIs(v["principal_bound"], True)
        self.assertIs(v["usable"], True)

    def test_each_broken_property_of_the_binding_makes_the_grant_unusable(self):
        for label, change in (("not authentic", {"binding_authentic": False}),
                              ("stale", {"fresh": False}),
                              ("bound to another credential", {"bound_to_credential": False}),
                              ("another holder's key", {"holder_public_key_hex": "ab" * 32})):
            with self.subTest(label):
                v = self.verdict(**change)
                self.assertIs(v["principal_bound"], False)
                self.assertIs(v["usable"], False)


@unittest.skipUnless(any(V._provider_available(p) for p in V.REAL_PROVIDERS),
                     "no real ML-DSA backend; these run on real signatures")
class HolderChainBoundaries(unittest.TestCase):
    """2026-09-23: a held-out round on the holder chain found six rules no suite isolated: a
    binding about another token, or signed by another issuer, still bound; the proof's context
    ignored; the one-minute skew and the five-minute age each doubled; and a verifier clock it
    cannot read treated as fresh. The published vectors form one genuine chain (issuer ->
    binding -> holder key -> proof), so these run on real signatures and change one input."""

    @classmethod
    def setUpClass(cls):
        vec = lambda n: json.loads((ROOT / "conformance" / "vectors" / n).read_text())  # noqa: E731
        cls.proof, cls.binding, cls.credential = (vec("holder-proof-valid.json"),
                                                  vec("holder-binding-valid.json"),
                                                  vec("holder-credential.json"))

    def bound(self, **credential_change):
        return V.verify_holder_binding(self.binding, credential=dict(self.credential, **credential_change),
                                       now="2026-05-01T00:00:00Z")["bound_to_credential"]

    def test_a_binding_binds_only_its_own_token_under_its_issuer(self):
        self.assertIs(self.bound(), True)
        self.assertIs(self.bound(token_value="SOMEONE-ELSE-0001"), False)
        self.assertIs(self.bound(public_key_hex="ab" * 1952), False)

    def proof_at(self, now, **kw):
        return V.verify_holder_proof(self.proof, binding=self.binding, now=now, **kw)

    def test_the_context_must_be_the_one_expected(self):
        self.assertIs(self.proof_at("2026-05-01T00:00:10Z", expected_context=1)["context_matches"], True)
        self.assertIs(self.proof_at("2026-05-01T00:00:10Z", expected_context=2)["context_matches"], False)

    def test_the_proof_is_fresh_for_exactly_five_minutes_and_a_minute_of_skew(self):
        # issued_at is 2026-05-01T00:00:00Z
        for now, fresh in (("2026-05-01T00:05:00Z", True), ("2026-05-01T00:05:01Z", False),
                           ("2026-04-30T23:59:00Z", True), ("2026-04-30T23:58:59Z", False)):
            with self.subTest(now=now):
                self.assertIs(self.proof_at(now)["fresh"], fresh)

    def test_a_clock_the_verifier_cannot_read_is_never_fresh(self):
        v = self.proof_at("not a time")
        self.assertIs(v["proof_authentic"], True, "the signature itself is fine")
        self.assertIs(v["fresh"], False)


class PresentationUsableNeedsEveryFact(unittest.TestCase):
    """usable_offline is a conjunction of eleven facts. 2026-09-23: a held-out round dropped each
    and found five no suite or drill isolated: the credential's authenticity, its issuer's
    trust, the status assertion being present at all, its authenticity, and (in the holder
    chain) the binding's freshness. The drills' negative cases each break several facts. Here
    the inner verdicts are replaced for one call, every fact passes, then exactly one fails."""

    CRED = {"token_value": "T", "public_key_hex": "aa" * 32}
    SA = {"token_value": "T", "public_key_hex": "aa" * 32}

    def usable(self, pack=None, sa=None, staple=True, binding=None):
        from unittest import mock
        pres = {"format": V._PRESENTATION_FORMAT, "credential": dict(self.CRED)}
        if staple:
            pres["status_assertion"] = dict(self.SA)
        patches = [mock.patch.object(V, "verify_pack", return_value=dict(
                       {"signature_valid": True, "issuer_trusted": True}, **(pack or {}))),
                   mock.patch.object(V, "verify_status_assertion", return_value=dict(
                       {"status_authentic": True, "fresh": True, "status": "ACTIVE"}, **(sa or {})))]
        if binding is not None:
            pres["holder_binding"], pres["holder_proof"] = {}, {}
            patches += [mock.patch.object(V, "verify_holder_binding", return_value=dict(
                            {"binding_authentic": True, "fresh": True, "bound_to_credential": True,
                             "holder_public_key_hex": "bb" * 32}, **binding)),
                        mock.patch.object(V, "verify_holder_proof", return_value={
                            "proof_authentic": True, "fresh": True, "key_matches_binding": True,
                            "nonce_matches": True, "context_matches": None})]
        for p in patches:
            p.start()
        try:
            return V.verify_presentation(pres)["usable_offline"]
        finally:
            for p in patches:
                p.stop()

    def test_every_fact_holding_is_usable(self):
        self.assertIs(self.usable(), True)
        self.assertIs(self.usable(binding={}), True)

    def test_each_fact_alone_makes_it_unusable(self):
        for label, kw in (("credential not authentic", {"pack": {"signature_valid": False}}),
                          ("issuer not trusted", {"pack": {"issuer_trusted": False}}),
                          ("no status assertion stapled", {"staple": False}),
                          ("status assertion not authentic", {"sa": {"status_authentic": False}}),
                          ("a stale holder binding", {"binding": {"fresh": False}})):
            with self.subTest(label):
                self.assertIs(self.usable(**kw), False)


class CrossAuthorityZkTrustChain(unittest.TestCase):
    """verify_cross_authority_zk trusts a foreign epoch only through a fresh checkpoint, a
    fresh and trusted manifest, and an attestation of THAT key, in THIS context, inside its own
    window; then it refuses a replayed nullifier. 2026-09-23: a held-out round removed each of
    those six rules in turn and every suite and the cross-authority drill stayed green, because
    each drill case breaks several links at once. The three inner verdicts are replaced here,
    every link passes, then exactly one fails."""

    KEY = "cc" * 32

    def decide(self, cv=None, mv=None, att=None, zk=None, context=1, anchors=("aa" * 32,)):
        from unittest import mock
        attestation = dict({"attested_public_key_hex": self.KEY, "context_id": 1}, **(att or {}))
        cvr = dict({"checkpoint_authentic": True, "fresh": True}, **(cv or {}))
        mvr = dict({"manifest_authentic": True, "fresh": True, "issuer_trusted": True,
                    "authority": {"agency_id": "B"}, "attestations": [attestation]}, **(mv or {}))
        zkr = dict({"bound": True, "proof_verified": True, "nullifier": "ab", "fresh_nullifier": True,
                    "note": "replayed"}, **(zk or {}))
        checkpoint = {"public_key_hex": self.KEY, "epoch": {"root_hex": "00", "number": 1}}
        with mock.patch.object(V, "verify_epoch_checkpoint", return_value=cvr), \
                mock.patch.object(V, "verify_manifest", return_value=mvr), \
                mock.patch.object(V, "verify_zk_against_root", return_value=zkr):
            return V.verify_cross_authority_zk({}, checkpoint, context, [{}],
                                               trusted_anchors=list(anchors))["decision"]

    def test_every_link_holding_accepts(self):
        self.assertEqual(self.decide(), "accept")

    def test_each_broken_link_refuses(self):
        for label, kw in (("a stale checkpoint", {"cv": {"fresh": False}}),
                          ("a stale manifest", {"mv": {"fresh": False}}),
                          ("a manifest from an authority nobody trusts", {"mv": {"issuer_trusted": False}}),
                          ("an attestation of another key", {"att": {"attested_public_key_hex": "dd" * 32}}),
                          ("an attestation for another context", {"att": {"context_id": 2}}),
                          ("an attestation past its window", {"att": {"valid_until": "2000-01-01T00:00:00Z"}}),
                          ("a replayed nullifier", {"zk": {"fresh_nullifier": False}})):
            with self.subTest(label):
                self.assertEqual(self.decide(**kw), "reject")

if __name__ == "__main__":
    unittest.main()


class IsoInstantGrammarTests(unittest.TestCase):
    """sdk/testdata/iso-instants.json: the one instant grammar the verifier shares with both
    reference SDKs. Until 2026-09-24 this used datetime.fromisoformat, which on Python 3.11+
    accepts compact, week-date and hour-only forms the TypeScript kit refuses."""

    def test_the_shared_vectors(self):
        cases = json.loads((ROOT / "sdk" / "testdata" / "iso-instants.json").read_text())["cases"]
        for c in cases:
            with self.subTest(c["input"]):
                try:
                    got = int(V._parse_iso(c["input"]).timestamp())
                except ValueError:
                    got = None
                self.assertEqual(got, c["epoch"])
