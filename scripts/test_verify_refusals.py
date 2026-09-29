# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
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
import hashlib
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



# --------------------------------------------------------------------------- genuine VC and mdoc

def _mldsa_signer():
    """A fresh ML-DSA-65 key through the cryptography witness: (sign, public key bytes)."""
    from cryptography.hazmat.primitives.asymmetric import mldsa
    sk = mldsa.MLDSA65PrivateKey.generate()
    return sk.sign, sk.public_key().public_bytes_raw()


@unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
class VerifiableCredentialDecisions(unittest.TestCase):
    """2026-09-29: only malformed credentials were under test, never a genuine one, so nothing
    showed the verifier accepts what it should. Every refusal here sits beside the genuine
    credential passing, signed with a fresh key."""

    NOW = "2026-06-01T00:00:00Z"

    @classmethod
    def setUpClass(cls):
        cls.sign, cls.pk = _mldsa_signer()

    def credential(self, proof_changes=None, **changes):
        doc = {"@context": ["https://www.w3.org/ns/credentials/v2"],
               "type": ["VerifiableCredential", V._VC_TYPE], "issuer": "did:example:authority",
               "validFrom": "2026-01-01T00:00:00Z", "validUntil": "2027-01-01T00:00:00Z",
               "credentialSubject": {"verification": "authentic", "status": "ACTIVE"}}
        doc.update(changes)
        proof = {"type": "DataIntegrityProof", "cryptosuite": V._VC_CRYPTOSUITE,
                 "polarisAlgorithm": "ML-DSA-65", "polarisPublicKeyHex": self.pk.hex()}
        proof["proofValue"] = self.sign(hashlib.sha3_256(V._vc_canonical(doc)).digest()).hex()
        proof.update(proof_changes or {})
        doc["proof"] = proof
        return doc

    def test_a_genuine_credential_verifies_and_is_trusted_only_under_its_key(self):
        v = V.verify_verifiable_credential(self.credential(), anchor_keys=[self.pk.hex().upper()], now=self.NOW)
        self.assertIs(v["structure_valid"], True)
        self.assertIs(v["proof_authentic"], True, v["note"])
        self.assertIs(v["fresh"], True)
        self.assertIs(v["issuer_trusted"], True)
        self.assertIn("structure and validity window only", v["verifier_interop"])
        self.assertIs(V.verify_verifiable_credential(self.credential(), anchor_keys=["00"], now=self.NOW)["issuer_trusted"], False)
        self.assertIsNone(V.verify_verifiable_credential(self.credential(), now=self.NOW)["issuer_trusted"])
        as_bytes = json.dumps(self.credential()).encode("utf-8")
        self.assertIs(V.verify_verifiable_credential(as_bytes, now=self.NOW)["proof_authentic"], True)

    def test_freshness_is_the_window_and_an_unreadable_window_is_not_fresh(self):
        self.assertIs(V.verify_verifiable_credential(self.credential(), now="2027-01-01T00:00:00Z")["fresh"], False)
        v = V.verify_verifiable_credential(self.credential(validUntil="not a date"), now=self.NOW)
        self.assertIs(v["fresh"], False)
        self.assertIs(v["proof_authentic"], True, "the window is refused, the proof is still judged")
        self.assertIn("validity window is not readable", v["note"] or "")

    def test_each_refusal_with_its_reason(self):
        good = self.credential()
        for doc, why in ((b"\xff\xfe", "not decodable JSON"),
                         ([good], "not an object"),
                         (dict(good, type=["VerifiableCredential"]), V._VC_TYPE),
                         (dict(good, credentialSubject="authentic"), "no subject object"),
                         (self.credential(credentialSubject={"legal_name": "A. Person"}), "identity attributes"),
                         (dict(good, proof="none"), "carries no proof"),
                         (self.credential(proof_changes={"cryptosuite": "ecdsa-rdfc-2019"}), "unexpected cryptosuite"),
                         (self.credential(proof_changes={"proofValue": "zz"}), "not valid hex"),
                         (self.credential(proof_changes={"polarisAlgorithm": "ML-DSA-44"}), "unaccepted signature algorithm"),
                         (dict(good, credentialSubject={"verification": "forged"}), "proof is invalid")):
            v = V.verify_verifiable_credential(doc, now=self.NOW)
            self.assertIs(v["proof_authentic"], False, why)
            self.assertIn(why, v["note"] or "", why)


@unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
class MdocDecisions(unittest.TestCase):
    """2026-09-29: the same gap for the ISO 18013-5-structured credential: tag-24 refusals were
    tested, a genuine document never was. Built here the way the issuer builds one: each element
    tag-24 wrapped and digested, the digests in a Mobile Security Object, the MSO signed as a
    COSE_Sign1 Sig_structure under ML-DSA."""

    NOW = "2026-06-01T00:00:00Z"

    @classmethod
    def setUpClass(cls):
        cls.sign, cls.pk = _mldsa_signer()
        cls.other_sign, cls.other_pk = _mldsa_signer()

    def document(self, elements=None, mso_changes=None, unprotected=None, after=None):
        elements = elements if elements is not None else {"status": "ACTIVE", "checked_at": "2026-05-01T00:00:00Z"}
        items, digests = [], {}
        for i, (name, value) in enumerate(elements.items()):
            item = ("tag24", _cbor({"digestID": i, "random": bytes([i + 1]) * 16,
                                    "elementIdentifier": name, "elementValue": value}))
            items.append(item)
            digests[i] = hashlib.sha256(_cbor(item)).digest()
        mso = {"version": "1.0", "digestAlgorithm": "SHA-256", "docType": V._MDOC_DOC_TYPE,
               "valueDigests": {V._MDOC_NAMESPACE: digests},
               "validityInfo": {"validFrom": "2026-01-01T00:00:00Z", "validUntil": "2027-01-01T00:00:00Z"}}
        mso.update(mso_changes or {})
        protected, payload = _cbor({1: -49}), _cbor(("tag24", _cbor(mso)))
        signature = self.sign(hashlib.sha3_256(V._cbor_sig_structure(protected, payload)).digest())
        header = {"polaris_public_key_hex": self.pk.hex(), "polaris_algorithm": "ML-DSA-65"}
        header.update(unprotected or {})
        if after:
            after(items)
        return _cbor({"docType": V._MDOC_DOC_TYPE,
                      "issuerSigned": {"nameSpaces": {V._MDOC_NAMESPACE: items},
                                       "issuerAuth": [protected, header, payload, signature]}})

    def test_a_genuine_document_verifies_digests_and_signature(self):
        doc = self.document()
        v = V.verify_mdoc(doc, anchor_keys=[self.pk.hex()], now=self.NOW)
        self.assertIs(v["structure_valid"], True)
        self.assertIs(v["digests_match"], True, v["note"])
        self.assertIs(v["issuer_authentic"], True, v["note"])
        self.assertIs(v["fresh"], True)
        self.assertIs(v["issuer_trusted"], True)
        self.assertEqual(v["elements"], {"status": "ACTIVE", "checked_at": "2026-05-01T00:00:00Z"})
        self.assertIn("structure and digests only", v["reader_interop"])
        self.assertIs(V.verify_mdoc(doc.hex(), now=self.NOW)["issuer_authentic"], True, "hex in, same answer")
        self.assertIs(V.verify_mdoc(doc, anchor_keys=["00"], now=self.NOW)["issuer_trusted"], False)
        self.assertIs(V.verify_mdoc(doc, now="2027-01-01T00:00:00Z")["fresh"], False)

    def test_each_refusal_before_the_signature(self):
        def swap_first(items):
            items[0] = ("tag24", _cbor({"digestID": 0, "random": b"\x01" * 16,
                                        "elementIdentifier": "status", "elementValue": "REVOKED"}))
        for doc, why in (("zz", "neither bytes nor valid hex"),
                         (7, "not bytes"),
                         (b"\xff", "not decodable CBOR"),
                         (_cbor({"docType": "org.iso.18013.5.1.mDL"}), "does not claim the mDL docType"),
                         (_cbor({"docType": V._MDOC_DOC_TYPE}), "no issuerSigned"),
                         (_cbor({"docType": V._MDOC_DOC_TYPE, "issuerSigned": {"issuerAuth": [1, 2]}}), "COSE_Sign1 quadruple"),
                         (_cbor({"docType": V._MDOC_DOC_TYPE, "issuerSigned": {"issuerAuth": [1, {}, 2, b""]}}), "not a byte string"),
                         (self.document(mso_changes={"docType": "other"}), "docType does not match"),
                         (self.document(mso_changes={"digestAlgorithm": "SHA-512"}), "unsupported MSO digest algorithm"),
                         (self.document(mso_changes={"valueDigests": {}}), "digests are missing"),
                         (self.document(elements={"token_value": "TKN-1"}), "correlation handle"),
                         (self.document(after=swap_first), "digest does not match")):
            v = V.verify_mdoc(doc, now=self.NOW)
            self.assertIs(v["issuer_authentic"], False, why)
            self.assertIn(why, v["note"] or "", why)

    def test_each_refusal_at_the_signature(self):
        for doc, why in ((self.document(unprotected={"polaris_public_key_hex": "zz"}), "not usable"),
                         (self.document(unprotected={"polaris_algorithm": "ES256"}), "unaccepted signature algorithm"),
                         (self.document(unprotected={"polaris_public_key_hex": self.other_pk.hex()}), "MSO signature is invalid")):
            v = V.verify_mdoc(doc, now=self.NOW)
            self.assertIs(v["digests_match"], True, "the digests are fine; the refusal is the signature's")
            self.assertIs(v["issuer_authentic"], False, why)
            self.assertIn(why, v["note"] or "", why)

    def test_an_unreadable_window_is_not_fresh(self):
        v = V.verify_mdoc(self.document(mso_changes={"validityInfo": {}}), now=self.NOW)
        self.assertIs(v["fresh"], False)
        self.assertIs(v["issuer_authentic"], True, "the window is refused, the signature is still judged")
        self.assertIn("validity window is not readable", v["note"] or "")


@unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
class SignedDocumentLongTermValidation(unittest.TestCase):
    """2026-09-29: long-term validation had no genuine container under test. Its promise is the
    one a relying party leans on years later: the signature stays valid after the key is
    retired because the evidence fixes the instant (a timestamp by an independent, trusted
    authority over the statement AND the signature; the signer's manifest listing the key as
    active then; no revocation of the credential then). Each rule below is broken alone, beside
    the complete container passing."""

    SIGNED, STAMPED, NOW = "2026-05-01T00:00:00Z", "2026-05-01T00:00:10Z", "2026-09-01T00:00:00Z"

    @classmethod
    def setUpClass(cls):
        cls.signer, cls.stamper, cls.second, cls.publisher = (_mldsa_signer() for _ in range(4))
        cls.body = b"%PDF-1.7 a notional report\n"

    @staticmethod
    def seal(obj, canonical, key):
        sign, pk = key
        out = dict(obj, algorithm="ML-DSA-65")
        out["signature_hex"] = sign(hashlib.sha3_256(canonical(out)).digest()).hex()
        out["public_key_hex"] = pk.hex()
        return out

    def document(self, on_behalf_of=None):
        return self.seal({"format": V._SIGNED_DOCUMENT_FORMAT,
                          "document": {"name": "report.pdf", "digest_algorithm": "SHA3-256",
                                       "digest_hex": hashlib.sha3_256(self.body).hexdigest()},
                          "signer": {"agency_id": 1, "name": "Notional Authority"},
                          "on_behalf_of": on_behalf_of, "purpose": "approval", "signed_at": self.SIGNED},
                         V._signed_document_canonical, self.signer)

    def timestamp(self, doc, key=None, digest_hex=None):
        return self.seal({"format": V._TIMESTAMP_FORMAT, "authority": "Notional Time Authority",
                          "digest_hex": digest_hex or hashlib.sha3_256(V.document_signature_material(doc)).hexdigest(),
                          "digest_algorithm": "SHA3-256", "nonce": "n-1", "issued_at": self.STAMPED},
                         V._timestamp_canonical, key or self.stamper)

    def manifest(self, status="active", expires="2026-06-01T00:00:00Z"):
        return self.seal({"format": "polaris-federation-manifest/1",
                          "authority": {"agency_id": 1, "name": "Notional Authority"},
                          "anchors": [{"public_key_hex": self.signer[1].hex(), "algorithm": "ML-DSA-65", "status": status}],
                          "attestations": [], "epoch": None, "revocation": None,
                          "issued_at": "2026-04-01T00:00:00Z", "expires_at": expires},
                         V._manifest_canonical, self.signer)

    def feed(self, leaves):
        return self.seal({"format": V._REVOCATION_FEED_FORMAT, "authority": {"agency_id": 1},
                          "epoch_number": 1, "as_of": self.STAMPED, "revoked_root_hex": V.revoked_root(leaves),
                          "revoked_count": len(set(leaves)), "revoked_leaves": leaves,
                          "issued_at": "2026-04-30T00:00:00Z", "expires_at": "2026-05-02T00:00:00Z"},
                         V._revocation_feed_canonical, self.signer)

    def trust_list(self, signer_status="active", retired_at=None):
        signer = {"agency_id": 1, "public_key_hex": self.signer[1].hex(), "status": signer_status,
                  "registered_at": "2026-01-01T00:00:00Z"}
        if retired_at:
            signer["retired_at"] = retired_at
        keys = [{"agency_id": 9, "public_key_hex": self.publisher[1].hex(), "status": "active",
                 "registered_at": "2026-01-01T00:00:00Z"}, signer,
                {"agency_id": 5, "public_key_hex": self.stamper[1].hex(), "status": "active",
                 "registered_at": "2026-01-01T00:00:00Z"}]
        return self.seal({"format": "polaris-trust-list/1", "publisher": {"agency_id": 9, "name": "Notional Registry"},
                          "keys": keys, "issued_at": "2026-04-01T00:00:00Z", "expires_at": "2027-01-01T00:00:00Z"},
                         V._trust_list_canonical, self.publisher)

    def container(self, doc=None, **kw):
        doc = doc or self.document()
        return V.attach_ltv(doc, timestamp=kw.get("timestamp") or self.timestamp(doc),
                            manifest=kw.get("manifest") or self.manifest(),
                            revocation_feed=kw.get("feed"), timestamps=kw.get("timestamps"))

    def decide(self, container, **kw):
        kw.setdefault("timestamp_anchors", [self.stamper[1].hex(), self.second[1].hex()])
        return V.verify_signed_document(container, now=self.NOW, **kw)

    def test_the_signature_alone_is_authentic_binds_its_bytes_and_claims_nothing_long_term(self):
        doc = self.document()
        v = V.verify_signed_document(doc, trusted_anchors=[self.signer[1].hex()], document_bytes=self.body)
        self.assertIs(v["document_authentic"], True, v["note"])
        self.assertIs(v["signer_trusted"], True)
        self.assertIs(v["binds"], True)
        self.assertIs(v["valid_long_term"], False)
        self.assertIn("no long-term-validation evidence", v["note"])
        self.assertIs(V.verify_signed_document(doc, document_bytes=b"another file")["binds"], False)
        self.assertIs(V.verify_signed_document(doc, trusted_anchors=["00"])["signer_trusted"], False)

    def test_complete_evidence_is_valid_long_term(self):
        v = self.decide(self.container())
        self.assertIs(v["valid_long_term"], True, v["note"])
        L = v["ltv"]
        self.assertEqual((L["timestamp_authentic"], L["timestamp_binds"], L["timestamp_authority_trusted"],
                          L["timestamp_independent"], L["signer_key_active_at_instant"], L["independent_timestamps"]),
                         (True, True, True, True, True, 1))
        self.assertEqual(L["instant"], self.STAMPED)

    def test_each_long_term_rule_broken_alone(self):
        doc = self.document()
        for container, kw, why in (
                (self.container(), {"timestamp_anchors": None}, "no trusted timestamp-authority anchors given"),
                (self.container(), {"timestamp_anchors": ["00"]}, "timestamp authority not trusted"),
                (self.container(doc, timestamp=self.timestamp(doc, key=self.signer)),
                 {"timestamp_anchors": [self.signer[1].hex()]}, "timestamp_independent"),
                (self.container(doc, timestamp=self.timestamp(doc, digest_hex="00" * 32)), {}, "timestamp_binds"),
                (self.container(manifest=self.manifest(status="retired")), {}, "signer_key_active_at_instant"),
                (self.container(manifest=self.manifest(expires="2026-04-15T00:00:00Z")), {}, "signer_key_active_at_instant"),
                (self.container(), {"timestamp_quorum": 2}, "quorum not met (1 of 2"),
                (self.container(), {"require_anchored": True}, "no anchored timestamp")):
            v = self.decide(container, **kw)
            self.assertIs(v["valid_long_term"], False, why)
            self.assertIn(why, v["note"] or "", why)

    def test_a_quorum_counts_distinct_trusted_authorities(self):
        doc = self.document()
        both = self.container(doc, timestamps=[self.timestamp(doc, key=self.second)])
        v = self.decide(both, timestamp_quorum=2)
        self.assertIs(v["valid_long_term"], True, v["note"])
        self.assertEqual(v["ltv"]["independent_timestamps"], 2)

    def test_a_credential_revoked_at_the_instant_ends_long_term_validity(self):
        leaf = hashlib.sha3_256(b"TKN-NOTIONAL-1").hexdigest()
        doc = self.document(on_behalf_of={"credential_hash": leaf, "holder": "notional"})
        ok = self.decide(self.container(doc, feed=self.feed(["aa" * 32])))
        self.assertIs(ok["valid_long_term"], True, ok["note"])
        self.assertIs(ok["ltv"]["credential_unrevoked_at_instant"], True)
        revoked = self.decide(self.container(doc, feed=self.feed([leaf])))
        self.assertIs(revoked["valid_long_term"], False)
        self.assertIn("credential revoked at the instant", revoked["note"])
        # Missing evidence is not a revocation, and the note must not say it is.
        no_feed = self.decide(self.container(doc))
        self.assertIs(no_feed["valid_long_term"], False, "a holder-authorized signature needs the feed")
        self.assertIn("no revocation feed at the instant", no_feed["note"])
        self.assertNotIn("credential revoked", no_feed["note"])
        foreign = self.seal({k: val for k, val in self.feed([]).items() if k not in ("signature_hex", "public_key_hex")},
                            V._revocation_feed_canonical, self.second)
        unproven = self.decide(self.container(doc, feed=foreign))
        self.assertIs(unproven["valid_long_term"], False, "a feed from another key proves nothing about this credential")
        self.assertIn("no authentic, fresh revocation feed from the signer", unproven["note"])
        self.assertNotIn("credential revoked", unproven["note"])

    def test_the_trust_list_decides_the_signer_key_at_the_instant(self):
        anchors = [self.publisher[1].hex()]
        active = self.decide(self.container(), trust_list=self.trust_list(), trusted_anchors=anchors)
        self.assertEqual(active["ltv"]["signer_key_status_per_trust_list"], "active")
        self.assertIs(active["valid_long_term"], True, active["note"])
        retired = self.decide(self.container(), trust_list=self.trust_list("retired", "2026-04-20T00:00:00Z"),
                              trusted_anchors=anchors)
        self.assertEqual(retired["ltv"]["signer_key_status_per_trust_list"], "retired")
        self.assertIs(retired["valid_long_term"], False)

    def test_each_refusal_of_the_signature_itself(self):
        good = self.document()
        for doc, why in ((dict(good, format="polaris-signed-document/2"), "not a polaris-signed-document/1"),
                         (dict(good, public_key_hex=""), "placeholder signature"),
                         (dict(good, signature_hex="zz"), "not valid hex"),
                         (dict(good, algorithm="ML-DSA-44"), "unaccepted signature algorithm"),
                         (dict(good, purpose="a different purpose"), "document signature is invalid")):
            v = V.verify_signed_document(doc)
            self.assertIs(v["document_authentic"], False, why)
            self.assertIn(why, v["note"] or "", why)


class VerifyDirIsTotal(unittest.TestCase):
    """--verify-dir promises 0 (all match), 2 (a disagreement) or 3 (usage). A vector that was not
    a JSON object raised AttributeError instead: a traceback and exit 1."""

    def test_a_file_that_is_not_an_object_is_reported_not_raised_on(self):
        genuine = (ROOT / "vectors" / "ml-dsa-65-valid.json").read_text()
        with tempfile.TemporaryDirectory() as d:
            import contextlib
            import io
            (pathlib.Path(d) / "a-genuine-pack.json").write_text(genuine)
            with contextlib.redirect_stdout(io.StringIO()):
                alone = V.verify_dir(d)
            self.assertEqual(alone, 0 if V._provider_available("oqs") or _cryptography_mldsa() else 2)
            (pathlib.Path(d) / "b-bare-true.json").write_text("true")
            (pathlib.Path(d) / "c-vector-meta-a-string.json").write_text(
                json.dumps(dict(json.loads(genuine), _vector="valid")))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = V.verify_dir(d)
            self.assertEqual(code, 2, "a file that is not a pack is a disagreement, not a crash")
            self.assertIn("b-bare-true.json", out.getvalue())
            self.assertIn("NOT A PACK", out.getvalue())
            self.assertIn("c-vector-meta-a-string.json", out.getvalue())


# (verifier, the published genuine vector, the key that says it is authentic)
_SIGNED_ARTIFACTS = (("verify_manifest", "federation-manifest-valid.json", "manifest_authentic"),
                     ("verify_trust_list", "trust-list-valid.json", "trust_list_authentic"),
                     ("verify_registry", "registry-valid.json", "registry_authentic"),
                     ("verify_id_token", "id-token-valid.json", "token_authentic"),
                     ("verify_timestamp", "timestamp-valid.json", "timestamp_authentic"),
                     ("verify_status_assertion", "status-assertion-valid.json", "status_authentic"),
                     ("verify_revocation_feed", "revocation-feed-valid.json", "feed_authentic"),
                     ("verify_status_bundle", "federation-status-bundle-valid.json", "bundle_authentic"),
                     ("verify_epoch_checkpoint", "epoch-checkpoint-valid.json", "checkpoint_authentic"),
                     ("verify_agent_grant", "agent-grant-valid.json", "grant_authentic"))


class EverySignedArtifactRefusesTheSameWay(unittest.TestCase):
    """2026-09-29: every artifact verifier opens with the same refusals (another format, a
    placeholder signature, hex that does not decode, an algorithm below the floor, no ML-DSA
    backend, two backends that disagree), and for most artifacts only the genuine path and a
    tampered signature had ever been driven. Here each refusal meets each artifact, beside that
    artifact's published genuine vector passing."""

    @staticmethod
    def vector(name):
        return json.loads((ROOT / "conformance" / "vectors" / name).read_text())

    @unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
    def test_each_input_refusal_on_each_artifact(self):
        for fn, name, key in _SIGNED_ARTIFACTS:
            good = self.vector(name)
            self.assertIs(getattr(V, fn)(good)[key], True, fn)
            for change, why in (({"format": "polaris-something-else/1"}, "not a "),
                                ({"public_key_hex": ""}, "placeholder"),
                                ({"signature_hex": "zz"}, "not valid hex"),
                                ({"algorithm": "ML-DSA-44"}, "unaccepted signature algorithm")):
                v = getattr(V, fn)(dict(good, **change))
                self.assertIs(v[key], False, "%s %s" % (fn, change))
                if fn == "verify_agent_grant" and "public_key_hex" in change:
                    # A grant is signed by the holder, never by the placeholder signer, so an
                    # empty key has no refusal of its own and falls through to the witnesses.
                    # What they say depends on which are installed (liboqs refuses the key;
                    # cryptography alone cannot load it and reports that it could not run),
                    # so only the refusal is asserted.
                    continue
                self.assertIn(why, v["note"] or "", "%s %s" % (fn, change))

    def test_no_backend_and_disagreeing_backends_are_refusals(self):
        saved = (V._verify_liboqs, V._verify_cryptography)
        try:
            for (lib, crypto), why in (((None, None), "no ML-DSA"), ((True, False), "DISAGREE")):
                V._verify_liboqs = lambda *a, _r=lib, **k: _r
                V._verify_cryptography = lambda *a, _r=crypto, **k: _r
                for fn, name, key in _SIGNED_ARTIFACTS:
                    v = getattr(V, fn)(self.vector(name))
                    self.assertIs(v[key], False, "%s: %s" % (fn, why))
                    self.assertIn(why, v["note"] or "", "%s: %s" % (fn, why))
        finally:
            V._verify_liboqs, V._verify_cryptography = saved



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


class WitnessedCheckpointIsTotal(unittest.TestCase):
    """`verify_timestamp_anchor` says it is total on hostile input. Cosignatures that are not a
    list raised TypeError from `verify_witnessed_checkpoint` until 2026-09-28."""

    def test_cosignatures_that_are_not_a_list_witness_nothing(self):
        import copy
        ts = json.loads((ROOT / "conformance" / "vectors" / "timestamp-anchor-witnessed.json").read_text())
        both = [c["public_key_hex"] for c in ts["anchor"]["cosignatures"]]
        good = V.verify_timestamp_anchor(ts, trusted_witnesses=both, threshold=2)
        if not good.get("anchored"):
            self.skipTest("no ML-DSA-65 backend here: %s" % good.get("note"))
        self.assertTrue(good.get("witnessed"))
        for bad in (True, 5):
            with self.subTest(cosignatures=bad):
                t = copy.deepcopy(ts)
                t["anchor"]["cosignatures"] = bad
                v = V.verify_timestamp_anchor(t, trusted_witnesses=both, threshold=2)
                self.assertTrue(v.get("anchored"))
                self.assertFalse(v.get("witnessed"))


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

    def test_an_unusable_presentation_is_not_accepted_2(self):
        """Row 2. It exited 1 until 2026-09-28, the code the table gives undecodable frames."""
        from unittest import mock
        with mock.patch.object(V, "verify_presentation",
                               return_value={"usable_offline": False, "note": "x"}):
            self.assertEqual(self.main("--pqc-provider", "auto", "--presentation", str(self.blob)), 2)
        self.assertEqual(self.main("--pqc-provider", "auto", "--presentation", str(self.blob)), 2,
                         "and with the real verdict: {} is no presentation anyone can use")

    def test_frames_that_do_not_decode_exit_1(self):
        """Row 1, the documented inconsistency: kept, because a script may depend on it."""
        frames = self.tmp / "frames.txt"
        frames.write_text("not a polaris-qr/1 frame\n")
        self.assertEqual(self.main("--pqc-provider", "auto", "--qr-frames", str(frames)), 1)

    def test_a_zero_knowledge_decision_that_is_not_accept_exits_2(self):
        from unittest import mock
        for decision, code in (("abstain", 2), ("reject", 2), ("accept", 0)):
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
    ABSENT = object()

    def decide(self, cv=None, mv=None, att=None, zk=None, context=1, anchors=("aa" * 32,),
               size=20, **floor):
        from unittest import mock
        attestation = dict({"attested_public_key_hex": self.KEY, "context_id": 1}, **(att or {}))
        cvr = dict({"checkpoint_authentic": True, "fresh": True}, **(cv or {}))
        mvr = dict({"manifest_authentic": True, "fresh": True, "issuer_trusted": True,
                    "authority": {"agency_id": "B"}, "attestations": [attestation]}, **(mv or {}))
        zkr = dict({"bound": True, "proof_verified": True, "nullifier": "ab", "fresh_nullifier": True,
                    "note": "replayed"}, **(zk or {}))
        epoch = {"root_hex": "00", "number": 1}
        if size is not self.ABSENT:
            epoch["committed_count"] = size
        checkpoint = {"public_key_hex": self.KEY, "epoch": epoch}
        with mock.patch.object(V, "verify_epoch_checkpoint", return_value=cvr), \
                mock.patch.object(V, "verify_manifest", return_value=mvr), \
                mock.patch.object(V, "verify_zk_against_root", return_value=zkr):
            return V.verify_cross_authority_zk({}, checkpoint, context, [{}],
                                               trusted_anchors=list(anchors), **floor)["decision"]

    def test_every_link_holding_accepts(self):
        self.assertEqual(self.decide(), "accept")

    def test_each_broken_link_refuses(self):
        for label, kw in (("a stale checkpoint", {"cv": {"fresh": False}}),
                          ("a stale manifest", {"mv": {"fresh": False}}),
                          ("a manifest from an authority nobody trusts", {"mv": {"issuer_trusted": False}}),
                          ("an attestation of another key", {"att": {"attested_public_key_hex": "dd" * 32}}),
                          ("an attestation for another context", {"att": {"context_id": 2}}),
                          ("an attestation past its window", {"att": {"valid_until": "2000-01-01T00:00:00Z"}}),
                          ("a replayed nullifier", {"zk": {"fresh_nullifier": False}}),
                          # 2026-09-25: the anonymity floor, as the online verifier applies it.
                          ("an epoch one below the default floor", {"size": 19}),
                          ("an epoch of one member", {"size": 1}),
                          ("a checkpoint that does not state its size", {"size": ABSENT_SIZE}),
                          ("a size that is a boolean", {"size": True}),
                          ("a size that is a string", {"size": "20"})):
            with self.subTest(label):
                kw = {k: (self.ABSENT if v is ABSENT_SIZE else v) for k, v in kw.items()}
                self.assertEqual(self.decide(**kw), "reject")

    def test_the_floor_is_the_callers_to_name(self):
        """A relying party may accept a smaller set on purpose, by naming it; the default is the
        issuing authority's own (20)."""
        self.assertEqual(V.DEFAULT_MIN_ANONYMITY_SET, 20)
        self.assertEqual(self.decide(size=5), "reject")
        self.assertEqual(self.decide(size=5, min_anonymity_set=5), "accept")
        self.assertEqual(self.decide(size=4, min_anonymity_set=5), "reject")


ABSENT_SIZE = "the checkpoint has no committed_count"

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
