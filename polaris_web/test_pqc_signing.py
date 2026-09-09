"""test_pqc_signing.py — unit tests for the post-quantum signing module.

`pqc_signing` is the single entry point `uc1_issue` calls to produce the bytes
stored in `TokenSignature.signature_bytes`. Its load-bearing safety property,
stated in the module docstring, is FAIL LOUD: with `POLARIS_USE_REAL_PQC=1` but
liboqs missing, issuance must raise rather than silently downgrade to the
deterministic placeholder. That path — and the placeholder's determinism and
its non-signature label — had no direct test (only the flag-unset DB integration
test in `test_app` and the static `check_pqc_signing_wired` wiring grep). This
file closes that gap. Pure module behavior; no DB, no liboqs required.

Run: python3 -m unittest test_pqc_signing
"""

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pqc_signing


class PlaceholderPathTests(unittest.TestCase):
    """Flag-off (the default, including CI): a deterministic SHA3-256 binding,
    explicitly labelled so it can never be mistaken for a real signature."""

    def setUp(self):
        self._saved = os.environ.pop('POLARIS_USE_REAL_PQC', None)

    def tearDown(self):
        if self._saved is not None:
            os.environ['POLARIS_USE_REAL_PQC'] = self._saved
        else:
            os.environ.pop('POLARIS_USE_REAL_PQC', None)

    def test_placeholder_is_sha3_256_of_token(self):
        token = 'TKN-CA-2026-000002'
        sig, label = pqc_signing.signature_bytes_for_token(token)
        self.assertEqual(sig, hashlib.sha3_256(token.encode('utf-8')).digest())
        self.assertEqual(label, pqc_signing.PLACEHOLDER_LABEL)

    def test_placeholder_is_deterministic(self):
        a, _ = pqc_signing.signature_bytes_for_token('repeatable-input')
        b, _ = pqc_signing.signature_bytes_for_token('repeatable-input')
        self.assertEqual(a, b)

    def test_distinct_tokens_get_distinct_placeholders(self):
        a, _ = pqc_signing.signature_bytes_for_token('token-A')
        b, _ = pqc_signing.signature_bytes_for_token('token-B')
        self.assertNotEqual(a, b)

    def test_label_marks_placeholder_as_non_signature(self):
        _, label = pqc_signing.signature_bytes_for_token('anything')
        self.assertIn('PLACEHOLDER', label)
        self.assertNotEqual(label, 'ML-DSA-65')

    def test_is_enabled_false_when_flag_unset(self):
        self.assertFalse(pqc_signing.is_enabled())

    def test_verify_token_signature_placeholder_roundtrip(self):
        token = 'TKN-PLACEHOLDER-VERIFY'
        sig, label = pqc_signing.signature_bytes_for_token(token)
        self.assertTrue(pqc_signing.verify_token_signature(token, sig, label))

    def test_verify_token_signature_placeholder_rejects_tamper(self):
        token = 'TKN-PLACEHOLDER-VERIFY'
        sig, label = pqc_signing.signature_bytes_for_token(token)
        # A different token recomputes a different binding.
        self.assertFalse(pqc_signing.verify_token_signature('OTHER-TOKEN', sig, label))
        # A flipped byte no longer matches.
        tampered = bytes([sig[0] ^ 0xFF]) + sig[1:]
        self.assertFalse(pqc_signing.verify_token_signature(token, tampered, label))

    def test_verify_token_signature_unknown_label_is_false(self):
        self.assertFalse(
            pqc_signing.verify_token_signature('t', b'\x00' * 32, 'SOME-OTHER-ALG'))

    def test_signature_with_key_placeholder_has_no_key(self):
        sig, label, pk = pqc_signing.signature_with_key_for_token('TKN-PH')
        self.assertEqual(label, pqc_signing.PLACEHOLDER_LABEL)
        self.assertIsNone(pk)
        # verify_stored_signature with no key is the integrity recompute.
        self.assertTrue(pqc_signing.verify_stored_signature('TKN-PH', sig, None))
        self.assertFalse(pqc_signing.verify_stored_signature('OTHER-TOKEN', sig, None))


class FailLoudTests(unittest.TestCase):
    """Flag-on but liboqs unavailable: every entry point MUST raise rather than
    silently downgrade an operator who explicitly asked for real PQC."""

    def setUp(self):
        self._saved_flag = os.environ.get('POLARIS_USE_REAL_PQC')
        self._saved_avail = pqc_signing._OQS_AVAILABLE
        os.environ['POLARIS_USE_REAL_PQC'] = '1'
        pqc_signing._OQS_AVAILABLE = False  # simulate liboqs absent

    def tearDown(self):
        pqc_signing._OQS_AVAILABLE = self._saved_avail
        if self._saved_flag is not None:
            os.environ['POLARIS_USE_REAL_PQC'] = self._saved_flag
        else:
            os.environ.pop('POLARIS_USE_REAL_PQC', None)

    def test_signature_bytes_raises_not_downgrades(self):
        # The dangerous regression would be returning the placeholder digest.
        with self.assertRaises(pqc_signing.PQCUnavailableError):
            pqc_signing.signature_bytes_for_token('TKN-CA-2026-000002')

    def test_sign_raises_when_unavailable(self):
        with self.assertRaises(pqc_signing.PQCUnavailableError):
            pqc_signing.sign(b'message')

    def test_verify_raises_when_unavailable(self):
        with self.assertRaises(pqc_signing.PQCUnavailableError):
            pqc_signing.verify(b'message', 'aa', 'bb')

    def test_is_enabled_false_when_liboqs_missing(self):
        self.assertFalse(pqc_signing.is_enabled())


@unittest.skipUnless(pqc_signing.is_available(),
                     "liboqs (oqs) not importable; real-PQC tests skip")
class PersistentKeyTests(unittest.TestCase):
    """The production signing path: a PERSISTENT keypair (loaded from
    POLARIS_PQC_SIGNING_KEY_FILE) gives a stable public key that is a real
    verification trust anchor, vs the ephemeral-per-call dev fallback. Runs only
    where liboqs is installed (locally / the pqc-real CI job)."""

    def setUp(self):
        import json
        import tempfile
        self._kp = pqc_signing.generate_keypair()
        self.assertEqual(self._kp["algorithm"], "ML-DSA-65")
        self._kf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(self._kp, self._kf)
        self._kf.close()
        self._saved = os.environ.get("POLARIS_PQC_SIGNING_KEY_FILE")
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = self._kf.name
        # Reset the module's key cache so it re-reads our file.
        pqc_signing._PERSISTENT_LOADED = False
        pqc_signing._PERSISTENT_KEYPAIR = None

    def tearDown(self):
        os.unlink(self._kf.name)
        if self._saved is None:
            os.environ.pop("POLARIS_PQC_SIGNING_KEY_FILE", None)
        else:
            os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = self._saved
        pqc_signing._PERSISTENT_LOADED = False
        pqc_signing._PERSISTENT_KEYPAIR = None

    def test_persistent_public_key_is_stable_and_verifies(self):
        r1 = pqc_signing.sign(b"token-ABC")
        r2 = pqc_signing.sign(b"token-ABC")
        # Stable public key = a real trust anchor (the ephemeral path would differ).
        self.assertEqual(r1.public_key_hex, r2.public_key_hex)
        self.assertEqual(r1.public_key_hex, self._kp["public_key_hex"])
        self.assertTrue(pqc_signing.verify(b"token-ABC", r1.signature_hex, r1.public_key_hex))
        self.assertTrue(pqc_signing.verify(b"token-ABC", r2.signature_hex, r2.public_key_hex))

    def test_forged_message_and_wrong_key_fail(self):
        r = pqc_signing.sign(b"token-ABC")
        self.assertFalse(pqc_signing.verify(b"token-XYZ", r.signature_hex, r.public_key_hex))
        other = pqc_signing.generate_keypair()
        self.assertFalse(pqc_signing.verify(b"token-ABC", r.signature_hex, other["public_key_hex"]))

    def test_malformed_key_file_fails_loud(self):
        with open(self._kf.name, "w") as fh:
            fh.write("{not json")
        pqc_signing._PERSISTENT_LOADED = False
        with self.assertRaises(RuntimeError):
            pqc_signing.sign(b"x")

    def test_trust_anchor_is_the_persistent_public_key(self):
        self.assertEqual(
            pqc_signing.trust_anchor_public_key_hex(), self._kp["public_key_hex"])

    def test_verify_token_signature_real_roundtrip_and_tamper(self):
        os.environ["POLARIS_USE_REAL_PQC"] = "1"
        try:
            token = "TKN-REAL-VERIFY"
            sig, label = pqc_signing.signature_bytes_for_token(token)
            self.assertEqual(label, "ML-DSA-65")
            # A real signature verifies against the trust anchor at use.
            self.assertTrue(pqc_signing.verify_token_signature(token, sig, label))
            # Wrong token / tampered signature are rejected.
            self.assertFalse(pqc_signing.verify_token_signature("WRONG-TOKEN", sig, label))
            tampered = bytes([sig[0] ^ 0xFF]) + sig[1:]
            self.assertFalse(pqc_signing.verify_token_signature(token, tampered, label))
        finally:
            os.environ.pop("POLARIS_USE_REAL_PQC", None)

    def test_issuance_refuses_a_signature_that_does_not_self_verify(self):
        # The enforcement: if the produced signature fails its self-check,
        # issuance raises rather than persisting an unverifiable signature.
        os.environ["POLARIS_USE_REAL_PQC"] = "1"
        orig_verify = pqc_signing.verify
        pqc_signing.verify = lambda *a, **k: False  # force the self-check to fail
        try:
            with self.assertRaises(pqc_signing.SigningError):
                pqc_signing.signature_bytes_for_token("TKN-SELFCHECK")
        finally:
            pqc_signing.verify = orig_verify
            os.environ.pop("POLARIS_USE_REAL_PQC", None)

    def test_signature_with_key_real_returns_pubkey_and_verifies_self_contained(self):
        os.environ["POLARIS_USE_REAL_PQC"] = "1"
        try:
            sig, label, pk = pqc_signing.signature_with_key_for_token("TKN-REAL-SC")
            self.assertEqual(label, "ML-DSA-65")
            self.assertEqual(pk, self._kp["public_key_hex"])
            # verify_stored_signature uses the STORED key — no live anchor lookup.
            self.assertTrue(pqc_signing.verify_stored_signature("TKN-REAL-SC", sig, pk))
            self.assertFalse(pqc_signing.verify_stored_signature("WRONG-TOKEN", sig, pk))
            tampered = bytes([sig[0] ^ 0xFF]) + sig[1:]
            self.assertFalse(pqc_signing.verify_stored_signature("TKN-REAL-SC", tampered, pk))
            # A signature is self-contained: it verifies against its stored key
            # even with no POLARIS_PQC_SIGNING_KEY_FILE configured (no live anchor).
            other = pqc_signing.generate_keypair()
            self.assertFalse(pqc_signing.verify_stored_signature("TKN-REAL-SC", sig, other["public_key_hex"]))
        finally:
            os.environ.pop("POLARIS_USE_REAL_PQC", None)

    def test_real_signature_unverifiable_without_a_trust_anchor(self):
        # With no persistent key there is no anchor, so even a genuine real
        # signature cannot be verified at use — the anchor is required.
        os.environ["POLARIS_USE_REAL_PQC"] = "1"
        saved = os.environ.pop("POLARIS_PQC_SIGNING_KEY_FILE", None)
        pqc_signing._PERSISTENT_LOADED = False
        pqc_signing._PERSISTENT_KEYPAIR = None
        try:
            token = "TKN-NO-ANCHOR"
            sig, label = pqc_signing.signature_bytes_for_token(token)
            self.assertEqual(label, "ML-DSA-65")
            self.assertIsNone(pqc_signing.trust_anchor_public_key_hex())
            self.assertFalse(pqc_signing.verify_token_signature(token, sig, label))
        finally:
            if saved is not None:
                os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = saved
            os.environ.pop("POLARIS_USE_REAL_PQC", None)
            pqc_signing._PERSISTENT_LOADED = False
            pqc_signing._PERSISTENT_KEYPAIR = None


@unittest.skipUnless(pqc_signing.is_available() and pqc_signing.second_witness_available(),
                     "needs BOTH liboqs (oqs) and the cryptography ML-DSA witness")
class SecondWitnessTests(unittest.TestCase):
    """v9.133 — the ML-DSA-65 verify path is two-witnessed: liboqs (primary) and
    cryptography/OpenSSL (independent second witness) must AGREE. A real signature
    a single implementation would accept can hide a bug or compromise in that one
    library; two independent FIPS-204 implementations that agree close that gap (the
    same discipline polaris_zk/witness2 gives the ZK path). Runs only where BOTH
    libraries are present (locally / the pqc-real CI job)."""

    def setUp(self):
        self._kp = pqc_signing.generate_keypair()
        # A genuine ML-DSA-65 signature over the SHA3-256 digest, via the primary.
        self._msg = b"two-witness-message"
        import oqs  # type: ignore
        digest = hashlib.sha3_256(self._msg).digest()
        with oqs.Signature("ML-DSA-65", bytes.fromhex(self._kp["secret_key_hex"])) as signer:
            self._sig_hex = signer.sign(digest).hex()
        self._pk_hex = self._kp["public_key_hex"]

    def test_witness_independently_verifies_an_oqs_signature(self):
        # The cross-implementation interop claim: a signature produced by liboqs
        # verifies under cryptography/OpenSSL. If this fails the two are not the
        # same FIPS 204 primitive and the whole witness is meaningless.
        self.assertTrue(pqc_signing._verify_second_witness(self._msg, self._sig_hex, self._pk_hex))

    def test_witness_rejects_a_tampered_signature(self):
        sig = bytes.fromhex(self._sig_hex)
        tampered = bytes([sig[0] ^ 0xFF]) + sig[1:]
        self.assertFalse(
            pqc_signing._verify_second_witness(self._msg, tampered.hex(), self._pk_hex))

    def test_witness_rejects_wrong_message(self):
        self.assertFalse(
            pqc_signing._verify_second_witness(b"OTHER-MESSAGE", self._sig_hex, self._pk_hex))

    def test_verify_both_true_when_both_agree_valid(self):
        self.assertTrue(pqc_signing.verify_both(self._msg, self._sig_hex, self._pk_hex))

    def test_verify_both_false_when_both_agree_invalid(self):
        self.assertFalse(pqc_signing.verify_both(b"WRONG", self._sig_hex, self._pk_hex))

    def test_verify_both_false_on_disagreement(self):
        # The load-bearing case: if the witness DISAGREES with the primary, the
        # signature is refused even though the primary alone would accept it.
        orig = pqc_signing._verify_second_witness
        pqc_signing._verify_second_witness = lambda *a, **k: False  # force disagreement
        try:
            # primary accepts (genuine sig) but witness says False -> refused.
            self.assertFalse(pqc_signing.verify_both(self._msg, self._sig_hex, self._pk_hex))
        finally:
            pqc_signing._verify_second_witness = orig

    def test_verify_both_degrades_to_primary_when_witness_unavailable(self):
        # Witness returns None (library too old / cannot load key) -> lone primary
        # verdict stands; no worse than pre-v9.133. The primary still accepts.
        orig = pqc_signing._verify_second_witness
        pqc_signing._verify_second_witness = lambda *a, **k: None
        try:
            self.assertTrue(pqc_signing.verify_both(self._msg, self._sig_hex, self._pk_hex))
        finally:
            pqc_signing._verify_second_witness = orig

    def test_availability_report_surfaces_the_witness(self):
        report = pqc_signing.availability_report()
        self.assertTrue(report["second_witness_available"])
        self.assertIsNone(report["second_witness_error"])

    # v9.258 — verify-AT-USE single-witness path (docs/design/verification-scaling.md).
    def test_verify_stored_single_witness_accepts_genuine_rejects_tamper(self):
        # The throughput path: single-witness verifies a genuine signature and
        # still rejects a tampered one. liboqs alone catches the forgery; only
        # the redundant second implementation of the same check is dropped.
        tv = self._msg.decode()
        sig = bytes.fromhex(self._sig_hex)
        self.assertTrue(pqc_signing.verify_stored_signature(tv, sig, self._pk_hex, witnesses="single"))
        self.assertTrue(pqc_signing.verify_stored_signature(tv, sig, self._pk_hex, witnesses="both"))
        tampered = bytes([sig[0] ^ 0xFF]) + sig[1:]
        self.assertFalse(pqc_signing.verify_stored_signature(tv, tampered, self._pk_hex, witnesses="single"))

    def test_single_witness_consults_only_the_primary(self):
        # The claim the throughput path rests on: single-witness does NOT run the
        # second witness. Force the witness to DISAGREE; single-witness still
        # accepts (it never asked it), while two-witness refuses on that same
        # disagreement. So "both" is strictly stronger, and "single" is genuinely
        # the ~10x-cheaper one-implementation check, not a silent alias for it.
        tv = self._msg.decode()
        sig = bytes.fromhex(self._sig_hex)
        orig = pqc_signing._verify_second_witness
        pqc_signing._verify_second_witness = lambda *a, **k: False
        try:
            self.assertTrue(pqc_signing.verify_stored_signature(tv, sig, self._pk_hex, witnesses="single"))
            self.assertFalse(pqc_signing.verify_stored_signature(tv, sig, self._pk_hex, witnesses="both"))
        finally:
            pqc_signing._verify_second_witness = orig

    # v9.264 — issuance may not silently degrade to one witness.
    def test_verify_both_require_witness_refuses_a_missing_witness(self):
        # With require_witness=True (the issuance self-check), a witness that
        # cannot run is a REFUSAL, not a downgrade to the lone primary...
        orig = pqc_signing._verify_second_witness
        pqc_signing._verify_second_witness = lambda *a, **k: None
        try:
            self.assertFalse(pqc_signing.verify_both(
                self._msg, self._sig_hex, self._pk_hex, require_witness=True))
            # ...while the default (re-verification / display) path still tolerates
            # it, since the signature was already two-witnessed at issuance.
            self.assertTrue(pqc_signing.verify_both(self._msg, self._sig_hex, self._pk_hex))
        finally:
            pqc_signing._verify_second_witness = orig

    def test_issuance_refuses_when_the_second_witness_is_unavailable(self):
        # Real issuance is where the two-witness claim is MADE; it may only be made
        # if the witness is actually present. Simulate it missing and confirm
        # signature_with_key_for_token REFUSES rather than issuing on one witness.
        saved_env = os.environ.get("POLARIS_USE_REAL_PQC")
        saved_avail = pqc_signing._WITNESS_AVAILABLE
        os.environ["POLARIS_USE_REAL_PQC"] = "1"
        pqc_signing._WITNESS_AVAILABLE = False
        try:
            with self.assertRaises(pqc_signing.SigningError):
                pqc_signing.signature_with_key_for_token("TKN-NO-WITNESS")
        finally:
            pqc_signing._WITNESS_AVAILABLE = saved_avail
            if saved_env is None:
                os.environ.pop("POLARIS_USE_REAL_PQC", None)
            else:
                os.environ["POLARIS_USE_REAL_PQC"] = saved_env


class SecondWitnessDegradationTests(unittest.TestCase):
    """The graceful-degradation contract is testable even without the witness
    library: when _WITNESS_AVAILABLE is forced off, verify_both must fall back to
    the primary rather than crash."""

    def setUp(self):
        self._saved = pqc_signing._WITNESS_AVAILABLE
        pqc_signing._WITNESS_AVAILABLE = False

    def tearDown(self):
        pqc_signing._WITNESS_AVAILABLE = self._saved

    def test_second_witness_returns_none_when_unavailable(self):
        self.assertIsNone(pqc_signing._verify_second_witness(b"m", "aa", "bb"))

    def test_second_witness_available_reflects_flag(self):
        self.assertFalse(pqc_signing.second_witness_available())


if __name__ == '__main__':
    unittest.main(verbosity=2)


class AlgorithmAgilityTests(unittest.TestCase):
    """P8.8a (v9.329): the accepted parameter sets agree across modules, a key file names its
    parameter set and the file driver signs under it, and an unaccepted set is refused."""

    def test_accepted_sets_agree_with_custody(self):
        import custody
        self.assertEqual(tuple(pqc_signing.ACCEPTED_ALGORITHMS), tuple(custody.ACCEPTED_ALGORITHMS))
        self.assertEqual(pqc_signing.DEFAULT_ALGORITHM, custody.DEFAULT_ALGORITHM)
        self.assertIsNone(pqc_signing.algorithm_for_public_key_hex("ab" * 1312))   # ML-DSA-44: not accepted
        self.assertEqual(pqc_signing.algorithm_for_public_key_hex("ab" * 1952), "ML-DSA-65")
        self.assertEqual(pqc_signing.algorithm_for_public_key_hex("ab" * 2592), "ML-DSA-87")

    def test_unaccepted_parameter_set_is_refused(self):
        if not pqc_signing.is_available():
            self.skipTest("liboqs not importable")
        with self.assertRaises(ValueError):
            pqc_signing.generate_keypair(algorithm="ML-DSA-44")

    def test_file_key_names_its_parameter_set_and_signs_under_it(self):
        if not pqc_signing.is_available():
            self.skipTest("liboqs not importable")
        import json, tempfile, custody
        old = dict(os.environ)
        try:
            os.environ["POLARIS_USE_REAL_PQC"] = "1"
            for alg, pk_len in (("ML-DSA-65", 1952), ("ML-DSA-87", 2592)):
                kp = pqc_signing.generate_keypair(algorithm=alg)
                self.assertEqual(kp["algorithm"], alg)
                self.assertEqual(len(bytes.fromhex(kp["public_key_hex"])), pk_len)
                with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
                    json.dump(kp, fh)
                os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = fh.name
                custody._reset_for_tests() if hasattr(custody, "_reset_for_tests") else None
                self.assertEqual(pqc_signing.algorithm_name(), alg)
                res = pqc_signing.sign(b"agile")
                self.assertEqual(res.algorithm_name, alg)
                self.assertTrue(pqc_signing.verify(b"agile", res.signature_hex, res.public_key_hex))
                self.assertTrue(pqc_signing.verify(b"agile", res.signature_hex, res.public_key_hex, algorithm=alg))
                other = "ML-DSA-87" if alg == "ML-DSA-65" else "ML-DSA-65"
                self.assertFalse(pqc_signing.verify(b"agile", res.signature_hex, res.public_key_hex, algorithm=other))
                self.assertFalse(pqc_signing.verify(b"agile", res.signature_hex, res.public_key_hex, algorithm="ML-DSA-44"))
        finally:
            os.environ.clear(); os.environ.update(old)

