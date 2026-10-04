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
import unittest.mock
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
class StapledStatusIsTheIssuers(unittest.TestCase):
    """WIRE-SPEC 3.5: a stapled status assertion is bound to the credential by the same token AND
    the credential's own key. Until 2026-09-30 verify_stapled bound by the token alone, so with
    two authorities trusted, the second one's ACTIVE assertion overrode the first one's
    revocation. verify_presentation, deciding the same two artifacts, always refused it."""

    @classmethod
    def setUpClass(cls):
        cls.sign_a, pk_a = _mldsa_signer()
        cls.sign_b, pk_b = _mldsa_signer()
        cls.a, cls.b = pk_a.hex(), pk_b.hex()
        tv = "ISSUER-A-0001"
        cls.pack = {"format": "polaris-authenticity-pack/1", "token_value": tv, "algorithm": "ML-DSA-65",
                    "public_key_hex": cls.a,
                    "signature_hex": cls.sign_a(hashlib.sha3_256(tv.encode("utf-8")).digest()).hex()}

    def assertion(self, sign, pk, status):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        iso = lambda d: d.isoformat().replace("+00:00", "Z")  # noqa: E731
        sa = {"format": "polaris-status-assertion/1", "token_value": self.pack["token_value"],
              "status": status, "issued_at": iso(now - timedelta(minutes=1)),
              "expires_at": iso(now + timedelta(minutes=10))}
        sa.update(algorithm="ML-DSA-65", public_key_hex=pk,
                  signature_hex=sign(hashlib.sha3_256(V._status_assertion_canonical(sa)).digest()).hex())
        return sa

    def test_the_issuers_own_assertion_decides(self):
        both = [self.a, self.b]
        self.assertEqual(V.verify_stapled(self.pack, self.assertion(self.sign_a, self.a, "ACTIVE"),
                                          anchor_keys=both)["decision"], "accept", "control")
        self.assertEqual(V.verify_stapled(self.pack, self.assertion(self.sign_a, self.a, "REVOKED"),
                                          anchor_keys=both)["decision"], "reject")

    def test_another_trusted_key_does_not_answer_for_this_credential(self):
        both = [self.a, self.b]
        vouched = self.assertion(self.sign_b, self.b, "ACTIVE")
        v = V.verify_stapled(self.pack, vouched, anchor_keys=both)
        self.assertEqual(v["decision"], "reject")
        self.assertIs(v["bound"], False)
        p = V.verify_presentation({"format": "polaris-presentation/1", "credential": self.pack,
                                   "status_assertion": vouched}, anchor_keys=both)
        self.assertIs(p["usable_offline"], False, "and the presentation path agrees")


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

    def test_a_feed_that_was_not_current_at_the_instant_proves_nothing(self):
        """Found by the daily adversarial review (2026-09-30): with `and fv.get("fresh")` removed
        from the feed decision, every verifier test still passed, so a signer's feed that had
        expired months before the timestamp fixed the instant counted as proof of non-revocation.
        The signer's own key signs each of these; only the window is wrong."""
        leaf = hashlib.sha3_256(b"TKN-NOTIONAL-1").hexdigest()
        doc = self.document(on_behalf_of={"credential_hash": leaf, "holder": "notional"})

        def feed(issued, expires, leaves=()):
            body = {k: val for k, val in self.feed(list(leaves)).items() if k not in ("signature_hex", "public_key_hex")}
            body.update(issued_at=issued, expires_at=expires)
            return self.seal(body, V._revocation_feed_canonical, self.signer)

        for label, stale in (("expired months before the instant", feed("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")),
                             ("issued after the instant", feed("2026-06-01T00:00:00Z", "2026-06-02T00:00:00Z"))):
            with self.subTest(label):
                v = self.decide(self.container(doc, feed=stale))
                self.assertIs(v["valid_long_term"], False, label)
                self.assertIs(v["ltv"]["credential_unrevoked_at_instant"], False, label)
                self.assertIn("no authentic, fresh revocation feed from the signer", v["note"])
        # A feed from another key that LISTS the credential is not a revocation either: the note
        # must say the evidence is missing, not that the credential was revoked.
        foreign = self.seal({k: val for k, val in self.feed([leaf]).items() if k not in ("signature_hex", "public_key_hex")},
                            V._revocation_feed_canonical, self.second)
        v = self.decide(self.container(doc, feed=foreign))
        self.assertIs(v["valid_long_term"], False)
        self.assertNotIn("credential revoked", v["note"])

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

    def test_a_usable_presentation_without_a_trust_root_abstains(self):
        """2026-09-30. The presentation path exited 0 with no --issuer-anchor, where the pack
        and stapled paths abstain, so a presentation whose credential and status assertion
        were signed by anybody's key was accepted."""
        from unittest import mock
        for trusted, flags, code in ((None, (), 2), (None, ("--signature-only",), 0),
                                     (True, (), 0), (False, (), 2)):
            verdict = {"usable_offline": trusted is not False, "issuer_trusted": trusted, "note": None}
            with self.subTest(issuer_trusted=trusted, flags=flags), \
                    mock.patch.object(V, "verify_presentation", return_value=verdict):
                self.assertEqual(self.main("--pqc-provider", "auto", "--presentation", str(self.blob),
                                           *flags), code)

    def test_a_usable_agent_grant_without_a_trust_root_abstains(self):
        """2026-09-30. The grant path had no abstention: it exited 0 whenever the chain was
        usable, whether or not any trust root was given."""
        from unittest import mock
        base = {"grant_authentic": True, "fresh": True, "credential_authentic": True,
                "principal_bound": True, "action_in_scope": True, "revoked": None,
                "agent_proved": True, "pairwise_handle": None, "correlation": None, "note": None}
        for trusted, usable, flags, code in ((None, True, (), 2), (None, True, ("--signature-only",), 0),
                                             (True, True, (), 0), (True, False, (), 2)):
            verdict = dict(base, usable=usable, issuer_trusted=trusted)
            with self.subTest(issuer_trusted=trusted, usable=usable, flags=flags), \
                    mock.patch.object(V, "verify_agent_grant", return_value=verdict):
                self.assertEqual(self.main("--pqc-provider", "auto", "--agent-grant", str(self.blob),
                                           *flags), code)

    def test_an_anchor_file_that_is_not_a_key_list_exits_3(self):
        """2026-09-30: `null` or a number as the anchor file raised TypeError out of the
        presentation and grant paths, a traceback and exit 1; the table says 3."""
        bad = self.tmp / "anchor-bad.json"
        for body in ("null", "7"):
            bad.write_text(body)
            for flag, target in (("--pack", self.pack), ("--presentation", self.blob),
                                 ("--agent-grant", self.blob)):
                with self.subTest(anchor=body, path=flag):
                    self.assertEqual(self.main("--pqc-provider", "auto", flag, str(target),
                                               "--issuer-anchor", str(bad)), 3)

    def test_the_trusted_anchor_flag_is_a_trust_root_on_every_path(self):
        """2026-09-30: --trusted-anchor reached only --zk-proof; on a pack it was ignored, so a
        run that named its trust root with it abstained whatever key it named (README: both
        flags are trust roots)."""
        key = json.loads(self.pack.read_text())["public_key_hex"]
        self.assertEqual(self.main("--pqc-provider", "auto", "--pack", str(self.pack), "--trusted-anchor", key), 0)
        self.assertEqual(self.main("--pqc-provider", "auto", "--pack", str(self.pack),
                                   "--trusted-anchor", "ab" * 1952), 2)

    def test_a_presentation_with_a_holder_proof_is_held_to_this_services_nonce(self):
        """2026-09-30: --nonce and --verifier-scope never reached the presentation path, so a
        captured holder proof replayed; without a nonce the run now abstains."""
        from unittest import mock
        verdict = {"usable_offline": True, "issuer_trusted": True, "holder": {"present": True}, "note": None}
        with mock.patch.object(V, "verify_presentation", return_value=verdict) as vp:
            self.assertEqual(self.main("--pqc-provider", "auto", "--presentation", str(self.blob)), 2)
            self.assertEqual(self.main("--pqc-provider", "auto", "--presentation", str(self.blob),
                                       "--nonce", "n-1", "--verifier-scope", "bank.example"), 0)
            self.assertEqual(vp.call_args.kwargs.get("expected_nonce"), "n-1")
            self.assertEqual(vp.call_args.kwargs.get("verifier_scope"), "bank.example")

    def test_a_zero_knowledge_nonce_must_be_an_integer(self):
        """Row 4, before any file is read: the proof named here does not exist, and the run that
        read it first exited 3 (2026-10-01)."""
        self.assertEqual(self.main("--pqc-provider", "auto", "--zk-proof", str(self.tmp / "absent.json"),
                                   "--nonce", "abc"), 4)

    def test_frames_that_do_not_decode_exit_1(self):
        """Row 1, the documented inconsistency: kept, because a script may depend on it."""
        frames = self.tmp / "frames.txt"
        frames.write_text("not a polaris-qr/1 frame\n")
        self.assertEqual(self.main("--pqc-provider", "auto", "--qr-frames", str(frames)), 1)

    def test_a_zero_knowledge_decision_takes_the_rules_of_every_other_path(self):
        """2026-10-01. Abstain, the decision a missing polaris-zk binary makes, is a check that
        could not run (3); it exited 2. An accept with no trust root, or with no nonce, abstains
        (2) as a pack and a presentation do; both exited 0. And --issuer-anchor reaches the
        verdict as --trusted-anchor does: the path read only --trusted-anchor."""
        from unittest import mock
        key = json.loads(self.pack.read_text())["public_key_hex"]
        zk = ("--pqc-provider", "auto", "--zk-proof", str(self.blob))
        for decision, flags, code in (
                ("abstain", ("--signature-only", "--nonce", "7"), 3),
                ("reject", ("--signature-only", "--nonce", "7"), 2),
                ("accept", (), 2),
                ("accept", ("--nonce", "7"), 2),
                ("accept", ("--signature-only",), 2),
                ("accept", ("--signature-only", "--nonce", "7"), 0),
                ("accept", ("--trusted-anchor", key, "--nonce", "7"), 0),
                ("accept", ("--issuer-anchor", str(self.good_anchor), "--nonce", "7"), 0)):
            with self.subTest(decision=decision, flags=flags), \
                    mock.patch.object(V, "verify_cross_authority_zk",
                                      return_value={"decision": decision, "reasons": []}) as vz:
                self.assertEqual(self.main(*zk, *flags), code)
                if "--issuer-anchor" in flags:
                    self.assertEqual(vz.call_args.kwargs["trusted_anchors"], [key])
                    self.assertEqual(vz.call_args.kwargs["expected_nonce"], 7)

    def test_a_json_decision_says_what_the_exit_code_says(self):
        """2026-10-01. A zero-knowledge accept held for a trust root or a nonce, and a stapled accept
        held for trust, printed `"decision": "accept"` and exited 2; a script reading the verdict
        read an acceptance the run did not make."""
        import contextlib
        import io
        from unittest import mock
        stapled = {"decision": "accept", "authentic": True, "status": "ACTIVE", "fresh": True,
                   "bound": True, "reasons": [], "credential": {"trust_evaluated": False},
                   "status_assertion": {"trust_evaluated": False}}
        runs = (("verify_cross_authority_zk", {"decision": "accept", "reasons": []},
                 ("--zk-proof", str(self.blob), "--nonce", "7"), "abstain", 2),
                ("verify_cross_authority_zk", {"decision": "accept", "reasons": []},
                 ("--zk-proof", str(self.blob), "--signature-only"), "abstain", 2),
                ("verify_cross_authority_zk", {"decision": "accept", "reasons": []},
                 ("--zk-proof", str(self.blob), "--signature-only", "--nonce", "7"), "accept", 0),
                ("verify_stapled", stapled,
                 ("--pack", str(self.pack), "--status-assertion", str(self.blob)), "abstain", 2),
                ("verify_stapled", stapled,
                 ("--pack", str(self.pack), "--status-assertion", str(self.blob), "--signature-only"),
                 "accept", 0),
                ("verify_stapled", dict(stapled, decision="reject"),
                 ("--pack", str(self.pack), "--status-assertion", str(self.blob)), "reject", 2),
                ("verify_cross_authority_zk", {"decision": "abstain", "reasons": ["no polaris-zk binary"]},
                 ("--zk-proof", str(self.blob), "--signature-only", "--nonce", "7"), "abstain", 3),
                ("verify_cross_authority_zk", {"decision": "reject", "reasons": ["tampered"]},
                 ("--zk-proof", str(self.blob), "--nonce", "7"), "reject", 2))
        for fn, verdict, argv, decision, code in runs:
            out, err = io.StringIO(), io.StringIO()
            with self.subTest(argv=argv), mock.patch.object(V, fn, return_value=verdict), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(V.main(["--pqc-provider", "auto", "--json", *argv]), code)
                self.assertEqual(json.loads(out.getvalue())["decision"], decision)
                self.assertEqual("abstain:" in err.getvalue(), decision == "abstain",
                                 "an abstention says why on stderr, and only an abstention does")

    def test_a_flag_the_mode_does_not_read_refuses_to_start(self):
        """Row 4, 2026-10-01. --presentation took --status-assertion and never read it, so a
        revoked assertion named there left exit 0 standing; --zk-proof took --issuer-anchor, and a
        pack --max-window, and read neither. The inputs named here do not exist: a run that read
        them would exit 3, so 4 is the refusal before any file is read."""
        import contextlib
        import io
        absent = str(self.tmp / "absent.json")
        for argv, flag in ((("--presentation", absent, "--status-assertion", absent), "--status-assertion"),
                           (("--qr-frames", absent, "--presentation", absent), "--presentation"),
                           (("--pack", absent, "--max-window", "60"), "--max-window"),
                           (("--pack", absent, "--min-anonymity-set", str(V.DEFAULT_MIN_ANONYMITY_SET)),
                            "--min-anonymity-set"),
                           (("--zk-proof", absent, "--verifier-scope", "bank.example"), "--verifier-scope"),
                           (("--agent-grant", absent, "--nonce", "n-1"), "--nonce"),
                           (("--zk-proof", absent, "--pack", absent), "--pack"),
                           (("--selftest", "--json"), "--json"),
                           (("--verify-dir", absent, "--signature-only"), "--signature-only")):
            err = io.StringIO()
            with self.subTest(argv=argv), contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(err):
                self.assertEqual(V.main(["--pqc-provider", "auto", *argv]), 4)
                self.assertIn("does not read %s;" % flag, err.getvalue())

    def test_a_value_flag_given_twice_refuses_to_start(self):
        """Row 4, 2026-10-01: argparse keeps the last of a repeated flag, so `--issuer-anchor A
        --issuer-anchor B` trusted B alone and `--pack X --pack Y` decided Y. The files named here
        do not exist, so 4 is the refusal before any is read; a flag that collects every value
        (--trusted-manifest) and one that takes no value lose nothing by repeating."""
        import contextlib
        import io
        a, b = str(self.tmp / "absent-a.json"), str(self.tmp / "absent-b.json")
        for argv, flag in ((("--pack", a, "--issuer-anchor", a, "--issuer-anchor", b), "--issuer-anchor"),
                           (("--pack", a, "--pack", b), "--pack"),
                           (("--pack", a, "--issuer-anc", a, "--issuer-anchor", b), "--issuer-anchor"),
                           (("--presentation", a, "--nonce", "n-1", "--nonce", "n-2"), "--nonce")):
            err = io.StringIO()
            with self.subTest(argv=argv), contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(err):
                self.assertEqual(V.main(["--pqc-provider", "auto", *argv]), 4)
                self.assertIn("%s given more than once" % flag, err.getvalue())
        self.assertEqual(self.main("--pqc-provider", "auto", "--zk-proof", a, "--trusted-manifest", a,
                                   "--trusted-manifest", b), 3, "every manifest is read, so the run reads")
        self.assertEqual(self.main("--pqc-provider", "auto", "--signature-only", "--signature-only",
                                   "--pack", str(self.pack)), 0)

    def test_an_argument_it_does_not_take_exits_4(self):
        """Row 4: argparse's own exit was 2, this table's "not accepted", so a mistyped flag read
        to a script as a credential that did not verify (2026-10-01)."""
        for argv in (("--registry", str(self.blob)), ("--max-window", "soon", "--pack", str(self.pack)),
                     ("--pqc-provider", "none", "--pack", str(self.pack))):
            with self.subTest(argv=argv), self.assertRaises(SystemExit) as raised:
                self.main(*argv)
            self.assertEqual(raised.exception.code, 4)

    def test_a_pack_path_handed_another_artifact_says_so(self):
        """Row 2 names it: a JSON file that is not an authenticity pack. A signed grant handed to
        --pack read as a signature that did not verify (2026-10-01)."""
        import contextlib
        import io
        grant = ROOT / "conformance" / "vectors" / "agent-grant-valid.json"
        for flags in ((), ("--json",), ("--json", "--status-assertion", str(self.blob))):
            out, err = io.StringIO(), io.StringIO()
            with self.subTest(flags=flags), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = V.main(["--pqc-provider", "auto", "--signature-only", "--pack", str(grant), *flags])
            self.assertEqual(code, 2)
            self.assertIn("not an authenticity pack: this is a polaris-agent-grant/1", err.getvalue())
            if "--json" in flags:
                verdict = json.loads(out.getvalue())
                self.assertEqual((verdict["decision"], verdict["signature_valid"]), ("reject", False),
                                 "a --json reader gets a verdict that agrees with the exit code")


class CallerKeysThatAreNotTextTests(unittest.TestCase):
    """Total on hostile input: a caller's key that is not text matches nothing, where `.lower()`
    raised AttributeError, and the bytes a timestamp or a ledger binds keep their form (2026-10-01)."""

    def setUp(self):
        import json
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "conformance", "vectors", "timestamp-anchor-witnessed.json")) as f:
            self.ts = json.load(f)

    @unittest.skipUnless(any(V._provider_available(p) for p in V.REAL_PROVIDERS),
                         "no real ML-DSA backend; the cosignatures must verify")
    def test_witnesses_and_log_keys_that_are_not_text(self):
        sth, cos = self.ts["anchor"]["sth"], self.ts["anchor"]["cosignatures"]
        both = [c["public_key_hex"] for c in cos]
        v = V.verify_witnessed_checkpoint(sth, cos, [None, 7] + both, threshold=2)
        self.assertIs(v["witnessed"], True)
        self.assertIs(V.verify_witnessed_checkpoint(sth, cos, [None, None], threshold=1)["witnessed"], False)
        self.assertIs(V.verify_sth(sth, issuer_key=123)["issuer_matches"], False)

    def test_material_keeps_its_bytes(self):
        self.assertTrue(V.document_signature_material({"document": {}, "signature_hex": None}).endswith(b"\n"))
        self.assertTrue(V._publication_entry("log", 1, None).endswith("|"))


class StapledDecisionNeedsEveryFact(unittest.TestCase):
    """verify_stapled accepts only when seven facts hold at once. 2026-09-23: a held-out round
    dropped each from the acceptance in turn, and five survived every suite and the offline
    status drill, because each drill case breaks more than one fact (a tampered assertion is
    also not fresh and has no status) and the others refused for it. Here the two inner
    verdicts are replaced for one call each: every fact passes, then exactly one does not."""

    GOOD_PACK = {"signature_valid": True, "issuer_trusted": True}
    GOOD_SA = {"status_authentic": True, "issuer_trusted": True, "fresh": True, "status": "ACTIVE"}

    def decide(self, pack=None, sa=None, token=("T", "T"), key=("ab" * 32, "AB" * 32)):
        from unittest import mock
        with mock.patch.object(V, "verify_pack", return_value=dict(self.GOOD_PACK, **(pack or {}))), \
                mock.patch.object(V, "verify_status_assertion", return_value=dict(self.GOOD_SA, **(sa or {}))):
            return V.verify_stapled({"token_value": token[0], "public_key_hex": key[0]},
                                    {"token_value": token[1], "public_key_hex": key[1]})["decision"]

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
        self.assertEqual(self.decide(key=(None, None)), "reject",
                         "two missing keys are not the same issuer (they compared as \"\" until 2026-10-01)")
        self.assertEqual(self.decide(key=(["ab" * 32], "ab" * 32)), "reject", "a list is not a key")


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
        vec = lambda n: json.loads((ROOT / "conformance" / "vectors" / n).read_text())  # noqa: E731
        self.grant, self.proof = vec("agent-grant-valid.json"), vec("agent-proof-valid.json")
        self.good = {"binding_authentic": True, "fresh": True, "bound_to_credential": True,
                     "holder_public_key_hex": self.grant["public_key_hex"], "note": None}

    def verdict(self, **binding):
        # 2026-09-30: a usable grant is the WHOLE chain (WIRE-SPEC 3.17), so the starting point
        # carries the credential's verdict, the action, the agent's proof and the service's
        # nonce; before, a link nobody supplied counted as passed. The credential verdict is
        # replaced as the binding's is, so each test still breaks one property of the binding.
        from unittest import mock
        with mock.patch.object(V, "verify_holder_binding", return_value=dict(self.good, **binding)), \
                mock.patch.object(V, "verify_pack", return_value={"signature_valid": True,
                                                                  "issuer_trusted": None, "note": None}):
            return V.verify_agent_grant(self.grant, binding={"format": "x"}, credential={},
                                        now=self.NOW, requested_action="read:status",
                                        agent_proof=self.proof, expected_nonce="svc-nonce-1")

    def test_a_good_binding_leaves_the_grant_usable(self):
        v = self.verdict()
        self.assertTrue(v["grant_authentic"], v["note"])
        self.assertIs(v["principal_bound"], True)
        self.assertIs(v["usable"], True)

    def test_each_missing_link_makes_the_grant_unusable(self):
        """WIRE-SPEC 3.17 names five links and `usable` must have CHECKED each; a link nobody
        supplied counted as passed until 2026-09-30."""
        from unittest import mock
        full = dict(binding={"format": "x"}, credential={}, now=self.NOW, requested_action="read:status",
                    agent_proof=self.proof, expected_nonce="svc-nonce-1")
        for missing in ("binding", "requested_action", "agent_proof", "expected_nonce"):
            with self.subTest(missing=missing), \
                    mock.patch.object(V, "verify_holder_binding", return_value=dict(self.good)), \
                    mock.patch.object(V, "verify_pack", return_value={"signature_valid": True,
                                                                      "issuer_trusted": None, "note": None}):
                v = V.verify_agent_grant(self.grant, **dict(full, **{missing: None}))
                self.assertIs(v["usable"], False)

    def test_the_credentials_verdict_decides_the_principal(self):
        from unittest import mock
        for label, pack, anchors in (("a credential signature that does not verify",
                                      {"signature_valid": False, "issuer_trusted": None, "note": None}, None),
                                     ("an issuer outside the anchors",
                                      {"signature_valid": True, "issuer_trusted": False, "note": None},
                                      ["ab" * 32])):
            with self.subTest(label), \
                    mock.patch.object(V, "verify_holder_binding", return_value=dict(self.good)), \
                    mock.patch.object(V, "verify_pack", return_value=pack):
                v = V.verify_agent_grant(self.grant, binding={"format": "x"}, credential={},
                                         now=self.NOW, requested_action="read:status",
                                         agent_proof=self.proof, expected_nonce="svc-nonce-1",
                                         anchor_keys=anchors)
                self.assertIs(v["principal_bound"], False)
                self.assertIs(v["usable"], False)

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
                     "no real ML-DSA backend; the control needs real cosignatures")
class WitnessThresholdIsAWholeNumber(unittest.TestCase):
    def test_a_threshold_below_one_or_not_a_whole_number_witnesses_nothing(self):
        """2026-09-30: -1 was met by no cosignature at all, and a string raised."""
        ts = json.loads((ROOT / "conformance" / "vectors" / "timestamp-anchor-witnessed.json").read_text())
        sth, cos = ts["anchor"]["sth"], ts["anchor"]["cosignatures"]
        both = [c["public_key_hex"] for c in cos]
        self.assertIs(V.verify_witnessed_checkpoint(sth, cos, both, threshold=2)["witnessed"], True, "control")
        for bad in (-1, 0, 0.5, "2", True, float("nan")):
            with self.subTest(threshold=bad):
                v = V.verify_witnessed_checkpoint(sth, cos, both, threshold=bad)
                self.assertIs(v["witnessed"], False)
                self.assertIn("whole number", v["note"])


class SignedCountsAreNumbers(unittest.TestCase):
    """A signed count is a JSON number equal to what it counts: never a boolean, and never
    absent (2026-09-30). `(x or 0)` read an absent member_count as zero members, and Python's
    `True == 1` read `true` as one member or one leaf, where the TypeScript SDK's `===`
    refuses both. The signature is stubbed to verify: only a signer can write these counts,
    so the count rule is what is under test."""

    def stub(self):
        from unittest import mock
        return mock.patch.object(V, "_two_witness_verify", return_value=(True, ["stub"], None))

    def test_a_status_bundle_is_held_to_its_member_count(self):
        b = json.loads((ROOT / "conformance" / "vectors" / "federation-status-bundle-count-mismatch.json").read_text())
        with self.stub():
            self.assertIs(V.verify_status_bundle(dict(b, member_count=1))["commitment_ok"], True, "control")
            for bad in (2, True, "1", None):
                with self.subTest(member_count=bad):
                    self.assertFalse(V.verify_status_bundle(dict(b, member_count=bad))["commitment_ok"])
            empty = {k: v for k, v in b.items() if k != "member_count"}
            empty.update(members=[], members_root_hex=V.bundle_members_root([]))
            self.assertFalse(V.verify_status_bundle(empty)["commitment_ok"], "an absent count is not zero")

    def test_an_epoch_leaves_count_of_true_is_not_one_leaf(self):
        one = ["aa" * 32]
        e = dict(json.loads((ROOT / "conformance" / "vectors" / "epoch-leaves-valid.json").read_text()),
                 all_leaves_hex=one, leaves_root_hex=V._leaves_root(one))
        with self.stub():
            self.assertIs(V.verify_epoch_leaves(dict(e, leaf_count=1))["count_matches"], True, "control")
            self.assertIs(V.verify_epoch_leaves(dict(e, leaf_count=True))["count_matches"], False)


@unittest.skipUnless(any(V._provider_available(p) for p in V.REAL_PROVIDERS),
                     "no real ML-DSA backend; these run on real signatures")
class AgentGrantChainsToTheTrustedIssuer(unittest.TestCase):
    """WIRE-SPEC 3.17: a verifier MUST check the issuer's signature on the credential and on the
    holder binding. Until 2026-09-30 the credential was compared with the binding and never
    verified, a binding with no credential counted as bound, and `anchor_keys` reached a field
    nothing read: a chain an attacker signed end to end under a key of their own, checked with
    the documented command against the real issuer's anchor, was usable and exited 0. The
    published grant-principal chain is genuine; each test changes one input."""

    NOW = "2026-05-01T00:00:30Z"

    @classmethod
    def setUpClass(cls):
        vec = lambda n: json.loads((ROOT / "conformance" / "vectors" / n).read_text())  # noqa: E731
        cls.grant = vec("grant-principal-grant.json")
        cls.binding = vec("grant-principal-binding-active.json")
        cls.credential = vec("grant-principal-credential.json")
        cls.forged = vec("grant-principal-credential-forged.json")
        cls.issuer = cls.credential["public_key_hex"]

    def chain(self, credential, anchors):
        return V.verify_agent_grant(self.grant, binding=self.binding, credential=credential,
                                    now=self.NOW, anchor_keys=anchors)

    def test_the_genuine_chain_under_its_issuers_anchor_is_bound(self):
        v = self.chain(self.credential, [self.issuer])
        self.assertIs(v["principal_bound"], True, v["note"])
        self.assertIs(v["credential_authentic"], True)
        self.assertIs(v["issuer_trusted"], True)

    def test_a_chain_by_an_issuer_outside_the_anchors_is_not_bound(self):
        """An attacker's own chain, as a verifier sees it: genuine throughout, and signed by a
        key the relying party never trusted."""
        v = self.chain(self.credential, ["ab" * 1952])
        self.assertIs(v["issuer_trusted"], False)
        self.assertIs(v["principal_bound"], False)
        self.assertIn("not in the trusted anchors", v["note"])

    def test_a_credential_whose_signature_does_not_verify_binds_nothing(self):
        for anchors in (None, [self.issuer]):
            with self.subTest(anchors=anchors):
                v = self.chain(self.forged, anchors)
                self.assertIs(v["credential_authentic"], False)
                self.assertIs(v["principal_bound"], False)

    def test_a_binding_without_its_credential_binds_nothing(self):
        v = self.chain(None, [self.issuer])
        self.assertIs(v["principal_bound"], False)
        self.assertIn("no credential", v["note"])

    def test_a_chain_missing_a_link_is_not_usable(self):
        """`usable` read a link nobody supplied as a pass, so a bare grant was usable."""
        v = V.verify_agent_grant(self.grant, now=self.NOW)
        self.assertIs(v["grant_authentic"], True, "control: the grant itself is genuine")
        self.assertIs(v["usable"], False)
        self.assertIn("incomplete", v["note"])


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


@unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
class SignedTreeHeadDecisions(unittest.TestCase):
    """verify_log_consistency and verify_equivocation over GENUINELY signed heads.

    The primitives underneath (verify_consistency, merkle_tree_head) are tested above; these
    are the decisions a monitor and two gossiping observers act on. Each refusal is the one
    genuine pair with exactly one thing changed, so a refusal is attributable to that change.
    """

    ENTRIES = ["entry-%02d" % i for i in range(13)]

    @classmethod
    def setUpClass(cls):
        cls.sign, cls.pk = _mldsa_signer()
        cls.other_sign, cls.other_pk = _mldsa_signer()

    def sth(self, size, *, log_id="log-1", root=None, sign=None, pk=None, **over):
        head = {"format": V._STH_FORMAT, "log_id": log_id, "tree_size": size,
                "root_hash_hex": root if root is not None else V.merkle_tree_head(self.ENTRIES[:size]).hex(),
                "timestamp": "2026-09-30T00:00:00Z", "algorithm": V._ALG}
        head.update(over)
        head["public_key_hex"] = (pk or self.pk).hex()
        head["signature_hex"] = (sign or self.sign)(
            __import__("hashlib").sha3_256(V._sth_canonical(head)).digest()).hex()
        return head

    def proof(self, m, n):
        return [h.hex() for h in V.consistency_proof(m, self.ENTRIES[:n])]

    # -- verify_log_consistency ----------------------------------------------------------

    def test_a_genuine_extension_is_consistent(self):
        v = V.verify_log_consistency(self.sth(5), self.sth(11), self.proof(5, 11), issuer_key=self.pk.hex())
        self.assertEqual((v["consistent"], v["fork"]), (True, False), v["note"])

    def test_equal_sizes_decide_on_the_roots(self):
        same = V.verify_log_consistency(self.sth(6), self.sth(6), [])
        self.assertEqual((same["consistent"], same["fork"]), (True, False), same["note"])
        other = V.merkle_tree_head(["x"] * 6).hex()
        split = V.verify_log_consistency(self.sth(6), self.sth(6, root=other), [])
        self.assertEqual((split["consistent"], split["fork"]), (False, True), split["note"])

    def test_a_shrinking_tree_is_a_fork(self):
        v = V.verify_log_consistency(self.sth(9), self.sth(4), [])
        self.assertEqual((v["consistent"], v["fork"]), (False, True))
        self.assertIn("SMALLER", v["note"])

    def test_a_rewritten_history_is_a_fork(self):
        rewritten = self.ENTRIES[:2] + ["rewritten"] + self.ENTRIES[3:11]
        head = self.sth(11, root=V.merkle_tree_head(rewritten).hex())
        proof = [h.hex() for h in V.consistency_proof(5, rewritten)]
        v = V.verify_log_consistency(self.sth(5), head, proof)
        self.assertEqual((v["consistent"], v["fork"]), (False, True), v["note"])

    def test_heads_from_two_logs_are_not_compared(self):
        v = V.verify_log_consistency(self.sth(5), self.sth(11, log_id="log-2"), self.proof(5, 11))
        self.assertEqual((v["consistent"], v["fork"]), (False, False))
        self.assertIn("different logs", v["note"])

    def test_an_inauthentic_head_decides_nothing(self):
        forged = dict(self.sth(11), root_hash_hex=V.merkle_tree_head(["x"] * 11).hex())
        v = V.verify_log_consistency(self.sth(5), forged, self.proof(5, 11))
        self.assertEqual((v["consistent"], v["fork"]), (False, False))
        self.assertIn("not authentic", v["note"])

    def test_a_head_from_another_key_is_refused_when_a_key_is_expected(self):
        foreign = self.sth(11, sign=self.other_sign, pk=self.other_pk)
        v = V.verify_log_consistency(self.sth(5), foreign, self.proof(5, 11), issuer_key=self.pk.hex())
        self.assertFalse(v["consistent"])
        self.assertIn("expected log key", v["note"])

    def test_a_boolean_or_missing_size_is_refused(self):
        for bad in (True, None, -1, "5"):
            with self.subTest(tree_size=bad):
                v = V.verify_log_consistency(self.sth(5), self.sth(11, tree_size=bad), self.proof(5, 11))
                self.assertFalse(v["consistent"])
                self.assertIn("tree_size", v["note"])

    def test_a_proof_that_is_not_hex_is_refused(self):
        v = V.verify_log_consistency(self.sth(5), self.sth(11), ["zz"])
        self.assertFalse(v["consistent"])
        self.assertIn("not valid hex", v["note"])

    # -- verify_equivocation --------------------------------------------------------------

    def test_two_signed_roots_at_one_size_are_proven_equivocation(self):
        other = V.merkle_tree_head(["x"] * 7).hex()
        v = V.verify_equivocation(self.sth(7), self.sth(7, root=other), self.pk.hex())
        self.assertTrue(v["proven"], v["note"])

    def test_identical_heads_prove_nothing(self):
        head = self.sth(7)
        self.assertFalse(V.verify_equivocation(head, dict(head), self.pk.hex())["proven"])

    def test_heads_of_different_sizes_are_left_to_consistency(self):
        v = V.verify_equivocation(self.sth(5), self.sth(7), self.pk.hex())
        self.assertFalse(v["proven"])
        self.assertIn("verify_log_consistency", v["note"])

    def test_heads_of_two_logs_prove_nothing(self):
        other = V.merkle_tree_head(["x"] * 7).hex()
        v = V.verify_equivocation(self.sth(7), self.sth(7, log_id="log-2", root=other), self.pk.hex())
        self.assertFalse(v["proven"])

    def test_a_head_not_signed_by_the_log_key_proves_nothing(self):
        other = V.merkle_tree_head(["x"] * 7).hex()
        foreign = self.sth(7, root=other, sign=self.other_sign, pk=self.other_pk)
        v = V.verify_equivocation(self.sth(7), foreign, self.pk.hex())
        self.assertFalse(v["proven"])
        self.assertIn("validly signed by the log key", v["note"])

    # -- verify_sth -----------------------------------------------------------------------

    def test_a_placeholder_or_unknown_head_is_not_authentic(self):
        head = self.sth(3)
        for over in ({"algorithm": V._PLACEHOLDER}, {"public_key_hex": None},
                     {"format": "something-else/1"}, {"signature_hex": "not hex"}):
            with self.subTest(**{k: str(v) for k, v in over.items()}):
                self.assertFalse(V.verify_sth(dict(head, **over))["sth_authentic"])
        self.assertFalse(V.verify_sth("not a head")["sth_authentic"])



@unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
class ReceiptInclusionDecisions(unittest.TestCase):
    """verify_receipt_inclusion over a genuinely signed receipt-log head (P8.2c).

    A receipt is in the log when its hash is the proof's entry, the RFC 6962 path rebuilds
    the head, and the head is an authentic head of THE receipt log. The genuine case first;
    every refusal changes one thing.
    """

    # The fields the canonical statement signs; a receipt is its statement, so fixtures that
    # differed only in other fields would all be one entry.
    RECEIPTS = [{"format": "polaris-exchange-receipt/1", "requester": "agency-a", "responder": "agency-b",
                 "context_id": 1, "request_hash": "%064x" % i, "response_hash": "%064x" % (100 + i),
                 "authorized_via": "trust-edge", "occurred_at": "2026-09-30T00:00:%02dZ" % i,
                 "algorithm": "ML-DSA-65"} for i in range(7)]

    @classmethod
    def setUpClass(cls):
        cls.sign, cls.pk = _mldsa_signer()
        cls.other_sign, cls.other_pk = _mldsa_signer()
        cls.hashes = [V.receipt_hash(r) for r in cls.RECEIPTS]
        assert len(set(cls.hashes)) == len(cls.RECEIPTS), "control: each receipt is its own entry"
        cls.root = V.merkle_tree_head(cls.hashes).hex()

    def head(self, *, sign=None, pk=None, **over):
        h = {"format": V._STH_FORMAT, "log_id": V._RECEIPT_LOG_ID, "tree_size": len(self.hashes),
             "root_hash_hex": self.root, "timestamp": "2026-09-30T00:01:00Z", "algorithm": V._ALG}
        h.update(over)
        h["public_key_hex"] = (pk or self.pk).hex()
        h["signature_hex"] = (sign or self.sign)(
            __import__("hashlib").sha3_256(V._sth_canonical(h)).digest()).hex()
        return h

    def proof(self, idx=3, **over):
        p = {"entry_hex": self.hashes[idx], "index": idx, "tree_size": len(self.hashes),
             "root_hash_hex": self.root, "proof_hex": [x.hex() for x in V.inclusion_proof(idx, self.hashes)]}
        p.update(over)
        return p

    def test_a_logged_receipt_is_included(self):
        for idx in range(len(self.RECEIPTS)):
            with self.subTest(index=idx):
                v = V.verify_receipt_inclusion(self.RECEIPTS[idx], self.proof(idx), self.head(),
                                               log_key=self.pk.hex())
                self.assertTrue(v["included"], v["note"])
                self.assertTrue(v["log_matches"])

    def test_a_proof_for_another_receipt_is_refused(self):
        v = V.verify_receipt_inclusion(self.RECEIPTS[2], self.proof(3), self.head())
        self.assertFalse(v["included"])
        self.assertIn("not for this receipt", v["note"])

    def test_a_head_of_another_log_is_refused(self):
        v = V.verify_receipt_inclusion(self.RECEIPTS[3], self.proof(3), self.head(log_id="another-log"))
        self.assertFalse(v["included"])
        self.assertIn(V._RECEIPT_LOG_ID, v["note"])

    def test_a_malformed_proof_is_refused_not_raised(self):
        # 2026-09-30: 3.5 and "7" were read by int() as 3 and 7, the genuine index and size,
        # so a proof with a malformed field was included; the SDKs read them otherwise.
        for over in ({"index": float("inf")}, {"index": "three"}, {"proof_hex": ["zz"]},
                     {"index": 3.5}, {"tree_size": "7"}, {"index": True}, {"proof_hex": "00"}):
            with self.subTest(**{k: str(v) for k, v in over.items()}):
                v = V.verify_receipt_inclusion(self.RECEIPTS[3], self.proof(3, **over), self.head())
                self.assertFalse(v["included"])
                self.assertEqual(v["note"], "malformed proof")

    def test_a_proof_and_head_of_different_trees_are_refused(self):
        v = V.verify_receipt_inclusion(self.RECEIPTS[3], self.proof(3, tree_size=6), self.head())
        self.assertFalse(v["included"])
        self.assertIn("different trees", v["note"])

    def test_an_inauthentic_head_is_refused(self):
        altered = dict(self.head(), timestamp="2026-10-01T00:00:00Z")
        v = V.verify_receipt_inclusion(self.RECEIPTS[3], self.proof(3), altered)
        self.assertFalse(v["included"])
        self.assertFalse(v["sth_authentic"])

    def test_a_head_from_another_key_is_refused_when_a_key_is_expected(self):
        v = V.verify_receipt_inclusion(self.RECEIPTS[3], self.proof(3),
                                       self.head(sign=self.other_sign, pk=self.other_pk),
                                       log_key=self.pk.hex())
        self.assertFalse(v["included"])
        self.assertIn("expected log key", v["note"])

    def test_a_path_that_does_not_rebuild_the_head_is_refused(self):
        v = V.verify_receipt_inclusion(self.RECEIPTS[3], self.proof(3, index=4), self.head())
        self.assertFalse(v["included"])
        self.assertIn("does not reconstruct", v["note"])

    def test_anything_but_three_objects_is_refused(self):
        v = V.verify_receipt_inclusion("receipt", self.proof(3), self.head())
        self.assertFalse(v["included"])
        self.assertIn("must be objects", v["note"])


# --------------------------------------------------------------------------- the chain anchor

class ChainAnchorDecisions(unittest.TestCase):
    """013: a checkpoint of the transparency logs committed in a Bitcoin block. The fixture is
    the real one (sdk/testdata/chain-anchor-969876.json): lab/strategy/013's checkpoint, its
    OpenTimestamps proof, and the raw headers of blocks 969876 (the attested block) and 969877,
    as blockstream.info and mempool.space both returned them on 2026-10-04."""

    FIXTURE = json.loads((ROOT / "sdk" / "testdata" / "chain-anchor-969876.json").read_text())
    CHECKPOINT = FIXTURE["anchor"]["checkpoint"]
    PROOF_HEX = FIXTURE["anchor"]["proof_hex"]
    HEADER = {int(h): x for h, x in FIXTURE["headers"].items()}
    BLOCK_HASH = FIXTURE["block_hash"]
    FIRST_APPEND = "3ebbefd5c20718220b3c7641d87febb2"   # the proof's first operation's argument

    def anchor(self, **changes):
        a = {"format": "polaris-chain-anchor/1", "checkpoint": self.CHECKPOINT, "proof_hex": self.PROOF_HEX}
        a.update(changes)
        return a

    def sources(self, header=None, n=2):
        return {"source-%d" % i: {969876: header or self.HEADER[969876]} for i in range(n)}

    def digest(self, text=None):
        return hashlib.sha256((text or self.CHECKPOINT).encode("utf-8")).digest()

    @staticmethod
    def proof(digest, body):
        """A proof over `digest` whose timestamp is `body`, built from the format directly."""
        return (V._OTS_MAGIC + b"\x01" + b"\x08" + digest + body).hex()

    @staticmethod
    def bitcoin(height, extra=b""):
        payload = bytes([height]) + extra if height < 128 else None
        return b"\x00" + V._OTS_BITCOIN + bytes([len(payload)]) + payload

    def refused(self, anchor, sources=None, why="", **kw):
        v = V.verify_chain_anchor(anchor, self.sources() if sources is None else sources, **kw)
        self.assertFalse(v["anchored"], v)
        self.assertIn(why, v["note"])
        return v

    # The genuine anchor, and the one decision it needs from the caller.
    def test_the_genuine_anchor_holds_from_two_sources(self):
        v = V.verify_chain_anchor(self.anchor(), self.sources())
        self.assertTrue(v["anchored"], v)
        self.assertEqual((v["block_height"], v["block_hash"], v["block_time"]),
                         (969876, self.BLOCK_HASH, 1791133260))
        self.assertEqual([h["tree_size"] for h in v["heads"]], [2, 2, 194])
        self.assertEqual(V.chain_anchor_heights(self.anchor()), [969876])

    def test_the_record_s_own_block_fields_are_never_read(self):
        """013 falsifier 2: the record is not evidence. A published anchor carries the block it
        was recorded against; the verdict comes from the proof and the caller's sources alone."""
        lying = self.anchor(block_height=1, block_header_hex=self.HEADER[969877], anchor_id=7)
        v = V.verify_chain_anchor(lying, self.sources())
        self.assertTrue(v["anchored"], v)
        self.assertEqual(v["block_height"], 969876)
        self.refused(self.anchor(block_height=969876, block_header_hex=self.HEADER[969876]),
                     self.sources(self.HEADER[969877]), "Merkle root is")

    def test_the_lab_checkpoint_is_the_canonical_form(self):
        heads = json.loads(self.CHECKPOINT)["heads"]
        self.assertEqual(V.chain_checkpoint(list(reversed(heads))), self.CHECKPOINT.encode("utf-8"))

    def test_one_source_holds_only_when_the_caller_says_one_is_enough(self):
        self.refused(self.anchor(), self.sources(n=1), "1 of 2 sources")
        self.assertTrue(V.verify_chain_anchor(self.anchor(), self.sources(n=1), min_sources=1)["anchored"])
        self.refused(self.anchor(), self.sources(), "positive integer", min_sources=0)

    def test_sources_that_disagree_are_refused_even_when_one_matches(self):
        mixed = {"a": {969876: self.HEADER[969876]}, "b": {969876: self.HEADER[969877]},
                 "c": {969876: self.HEADER[969876]}}
        self.refused(self.anchor(), mixed, "disagree about block 969876")

    def test_a_height_key_read_from_json_text_is_the_same_height(self):
        v = V.verify_chain_anchor(self.anchor(), {s: {"969876": self.HEADER[969876]} for s in "ab"})
        self.assertTrue(v["anchored"], v)

    # The checkpoint.
    def test_a_changed_checkpoint_is_refused(self):
        changed = self.CHECKPOINT.replace('"tree_size":194', '"tree_size":195')
        self.assertNotEqual(changed, self.CHECKPOINT)
        self.refused(self.anchor(checkpoint=changed), why="for another digest")

    def test_a_stated_digest_that_is_not_the_checkpoint_s_is_refused(self):
        self.refused(self.anchor(checkpoint_sha256="00" * 32), why="not the digest of its checkpoint")
        self.assertTrue(V.verify_chain_anchor(self.anchor(checkpoint_sha256=self.digest().hex()),
                                              self.sources())["anchored"])

    def test_a_checkpoint_not_in_canonical_form_is_refused(self):
        spaced = json.dumps(json.loads(self.CHECKPOINT), sort_keys=True)
        self.refused(self.anchor(checkpoint=spaced), why="canonical form")

    def test_a_checkpoint_naming_one_log_twice_is_refused(self):
        heads = json.loads(self.CHECKPOINT)["heads"]
        twice = V.chain_checkpoint([heads[0], dict(heads[0], tree_size=3)]).decode()
        self.refused(self.anchor(checkpoint=twice), why="one log twice")

    def test_a_head_that_is_not_a_statement_is_refused(self):
        heads = json.loads(self.CHECKPOINT)["heads"]
        for bad in (dict(heads[0], tree_size=True), dict(heads[0], tree_size=-1),
                    dict(heads[0], format="other"), dict(heads[0], root_hash_hex=7)):
            with self.subTest(bad=bad):
                text = V.chain_checkpoint([bad]).decode()
                self.refused(self.anchor(checkpoint=text), why="not a tree-head statement")

    def test_anything_but_an_anchor_with_checkpoint_text_is_refused(self):
        self.refused({"format": "other"}, why="not a polaris-chain-anchor/1")
        self.refused(self.anchor(checkpoint=None), why="no checkpoint text")
        self.refused(self.anchor(checkpoint="[]"), why="not a polaris-chain-checkpoint/1")
        self.refused(self.anchor(checkpoint="{"), why="not JSON")
        self.refused(self.anchor(checkpoint='{"format":"polaris-chain-checkpoint/1","heads":[]}'), why="lists no heads")

    # The proof.
    def test_a_changed_operation_is_refused(self):
        self.assertEqual(self.PROOF_HEX.count(self.FIRST_APPEND), 1)
        flipped = self.PROOF_HEX.replace(self.FIRST_APPEND, "3f" + self.FIRST_APPEND[2:])
        self.refused(self.anchor(proof_hex=flipped), why="Merkle root is")

    def test_the_wrong_block_is_refused(self):
        self.refused(self.anchor(), self.sources(self.HEADER[969877]), "Merkle root is")

    def test_a_pending_proof_is_refused(self):
        pending = b"\x00" + bytes.fromhex("83dfe30d2ef90c8e") + b"\x06\x05https"
        self.refused(self.anchor(proof_hex=self.proof(self.digest(), pending)), why="pending")
        self.assertEqual(V.chain_anchor_heights(self.anchor(proof_hex=self.proof(self.digest(), pending))), [])

    def test_a_proof_that_ends_early_or_runs_on_is_refused(self):
        self.refused(self.anchor(proof_hex=self.PROOF_HEX[:-10]), why="ends early")
        self.refused(self.anchor(proof_hex=self.PROOF_HEX + "00"), why="bytes after its timestamp")

    def test_a_proof_that_is_not_one_is_refused(self):
        self.refused(self.anchor(proof_hex="00" * 40), why="not an OpenTimestamps proof")
        self.refused(self.anchor(proof_hex="zz"), why="does not open")
        self.refused(self.anchor(proof_hex=None), why="does not open")
        self.refused(self.anchor(proof_hex="00" * (V._OTS_MAX_PROOF + 1)), why="at most")
        v2 = (V._OTS_MAGIC + b"\x02\x08" + self.digest()).hex()
        self.refused(self.anchor(proof_hex=v2), why="major version")
        sha1 = (V._OTS_MAGIC + b"\x01\x02" + self.digest()).hex()
        self.refused(self.anchor(proof_hex=sha1), why="not over a SHA-256 digest")

    def test_an_operation_this_verifier_does_not_know_is_refused(self):
        self.refused(self.anchor(proof_hex=self.proof(self.digest(), b"\x67" + self.bitcoin(5))),
                     why="does not know: 0x67")

    def test_an_operation_this_python_cannot_compute_is_refused(self):
        real = hashlib.new

        def no_ripemd(name, *a):
            if name == "ripemd160":
                raise ValueError("unsupported hash type")
            return real(name, *a)
        body = b"\x03" + self.bitcoin(5)
        with unittest.mock.patch.object(V.hashlib, "new", no_ripemd):
            self.refused(self.anchor(proof_hex=self.proof(self.digest(), body)), why="cannot compute operation 0x03")
        try:                                               # OpenSSL 3 without its legacy provider
            real("ripemd160", b"")
        except ValueError:
            return
        self.assertEqual(len(V.ots_bitcoin_attestations(bytes.fromhex(self.proof(self.digest(), body)), self.digest())), 1)

    def test_an_append_with_no_argument_is_refused(self):
        self.refused(self.anchor(proof_hex=self.proof(self.digest(), b"\xf0\x00" + self.bitcoin(5))),
                     why="outside 1..4096")

    def test_a_result_longer_than_the_format_allows_is_refused(self):
        big = b"\xf0" + bytes([0x80, 0x20]) + b"\x00" * 4096   # varuint 4096
        self.refused(self.anchor(proof_hex=self.proof(self.digest(), big + self.bitcoin(5))),
                     why="exceeds 4096")

    def test_a_proof_nested_deeper_than_the_format_allows_is_refused(self):
        deep = b"\x08" * 300 + self.bitcoin(5)
        self.refused(self.anchor(proof_hex=self.proof(self.digest(), deep)), why="nests deeper")
        shallow = b"\x08" * 200 + self.bitcoin(5)
        self.assertEqual(len(V.ots_bitcoin_attestations(bytes.fromhex(self.proof(self.digest(), shallow)),
                                                        self.digest())), 1)

    def test_a_length_past_64_bits_is_refused(self):
        self.refused(self.anchor(proof_hex=(V._OTS_MAGIC + b"\x80" * 10 + b"\x01").hex()), why="64 bits")

    def test_a_bitcoin_attestation_with_bytes_after_its_height_is_refused(self):
        self.refused(self.anchor(proof_hex=self.proof(self.digest(), self.bitcoin(5, extra=b"\x00"))),
                     why="bytes after its height")

    # The block header.
    def test_a_header_whose_hash_misses_its_target_is_refused(self):
        raw = bytearray(bytes.fromhex(self.HEADER[969876]))
        raw[76] ^= 0x01                                    # the nonce: same Merkle root, new hash
        self.refused(self.anchor(), self.sources(raw.hex()), "proof of work")

    def test_a_header_declaring_an_easier_target_than_mainnet_is_refused(self):
        raw = bytearray(bytes.fromhex(self.HEADER[969876]))
        raw[72:76] = (0x207FFFFF).to_bytes(4, "little")    # a test network's target
        for nonce in range(1 << 16):                       # half of all hashes meet it
            raw[76:80] = nonce.to_bytes(4, "little")
            h = hashlib.sha256(hashlib.sha256(bytes(raw)).digest()).digest()
            if int.from_bytes(h, "little") <= 0x7FFFFF << 232:
                break
        self.assertFalse(V.bitcoin_header(raw.hex())["pow_ok"])
        self.refused(self.anchor(), self.sources(raw.hex()), "proof of work")

    def test_a_header_that_is_not_80_bytes_is_refused(self):
        self.refused(self.anchor(), self.sources(self.HEADER[969876][:-2]), "80 bytes")
        self.refused(self.anchor(), self.sources("zz" * 80), "malformed")


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
