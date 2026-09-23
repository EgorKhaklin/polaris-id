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

if __name__ == "__main__":
    unittest.main()
