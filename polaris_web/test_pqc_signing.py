# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
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
import types
import unittest
import unittest.mock

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

    def test_issuance_refuses_a_token_value_that_is_not_a_serial(self):
        """2026-09-27 (WIRE-SPEC 3.7): every issuing entry point refuses, before signing, a
        token value that could be a signed JSON statement or is otherwise not a serial. The
        placeholder path too: the refusal does not depend on which signer runs."""
        bad = {
            "a signed JSON statement": '{"format":"polaris-trust-list/1"}',
            "empty": "",
            "a control character": "TKN-\n-1",
            "a C1 control character": "TKN-\u0085-1",
            "more than 128 bytes of UTF-8": "é" * 65,
            "an unpaired surrogate": "TKN-\ud800",
            "not a string": 12345,
        }
        for label, value in bad.items():
            for name, call in (
                    ("signature_with_key_for_token", lambda v: pqc_signing.signature_with_key_for_token(v)),
                    ("signature_bytes_for_token", lambda v: pqc_signing.signature_bytes_for_token(v)),
                    ("signature_for_migration", lambda v: pqc_signing.signature_for_migration(v, "ML-DSA-87"))):
                with self.subTest(label=label, entry=name):
                    with self.assertRaises(pqc_signing.NotACredentialSerial):
                        call(value)
        # Positive controls: the longest serial and a non-ASCII one are issued.
        for good in ("A" * 128, "TKN-é-2026", "TKN-CA-2026-000002"):
            sig, _label = pqc_signing.signature_bytes_for_token(good)
            self.assertEqual(sig, hashlib.sha3_256(good.encode("utf-8")).digest())

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

    def test_a_value_that_is_not_text_is_false_not_raised(self):
        """verify's docstring: it returns False on any failure and does not raise. A key or
        signature that is not a string raised bytes.fromhex's TypeError out of it."""
        for sig, pk in ((None, self._pk_hex), (self._sig_hex, None), (123, self._pk_hex)):
            self.assertIs(pqc_signing.verify(self._msg, sig, pk), False, (type(sig), type(pk)))
            self.assertIs(pqc_signing._verify_second_witness(self._msg, sig, pk), False)
            self.assertIs(pqc_signing.verify_both(self._msg, sig, pk), False)

    def test_a_genuine_signature_respelled_verifies_under_neither_witness(self):
        """The exchange doors verify a partner's signature_hex with verify_both, so this is
        where they read hex: the genuine signature with a space between bytes is refused by
        both witnesses, as it is by the three published verifiers."""
        self.assertTrue(pqc_signing.verify_both(self._msg, self._sig_hex, self._pk_hex), 'control')
        spaced = ' '.join(self._sig_hex[i:i + 2] for i in range(0, len(self._sig_hex), 2))
        self.assertFalse(pqc_signing.verify(self._msg, spaced, self._pk_hex))
        self.assertFalse(pqc_signing._verify_second_witness(self._msg, spaced, self._pk_hex))
        self.assertFalse(pqc_signing.verify_both(self._msg, spaced, self._pk_hex))
        self.assertFalse(pqc_signing.verify_both(self._msg, self._sig_hex, self._pk_hex + '\n'))

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


class ExactSizeIsCheckedTests(unittest.TestCase):
    """2026-10-10: verify() and verify_both() with an explicit algorithm did not check an ML-DSA
    public key's or signature's length before verifying, so an empty key (from a missing
    configuration) or a truncated one could verify. `_size_problem` now runs on verify_both before
    either witness, and verify() and the second witness check it before their library sees the
    bytes. Arbitrary bytes of the wrong length, not a forgery: a wrong length is refused at the
    size check. A wrong-length key is a recognised conformance case
    (fido-alliance/conformance-test-tools-resources#817)."""

    def test_the_tables_match_liboqs_details(self):
        if not pqc_signing.is_available():
            self.skipTest("liboqs absent")
        import oqs  # type: ignore
        enabled = set(oqs.get_enabled_sig_mechanisms())
        self.assertTrue(pqc_signing.custody.ALGORITHM_SIZES, "the size table is empty")
        for alg, (pk_len, sig_len) in pqc_signing.custody.ALGORITHM_SIZES.items():
            with self.subTest(alg):
                if alg not in enabled:
                    self.skipTest("%s is not enabled in this liboqs" % alg)  # a counted skip, never a pass
                with oqs.Signature(alg) as s:
                    self.assertEqual((pk_len, sig_len),
                                     (s.details["length_public_key"], s.details["length_signature"]), alg)

    def test_size_problem_names_a_wrong_length_and_passes_the_exact_one(self):
        pk_len, sig_len = pqc_signing.custody.ALGORITHM_SIZES["ML-DSA-65"]
        self.assertEqual((pk_len, sig_len), (1952, 3309))
        self.assertIsNone(pqc_signing._size_problem("ML-DSA-65", b"\x01" * pk_len, b"\x02" * sig_len))
        for bad in (0, 1, 32, pk_len - 1, pk_len + 1):
            self.assertIn("public key", pqc_signing._size_problem("ML-DSA-65", b"\x01" * bad, b"\x02" * sig_len))
        for bad in (0, 1, sig_len - 1, sig_len + 1):
            self.assertIn("signature", pqc_signing._size_problem("ML-DSA-65", b"\x01" * pk_len, b"\x02" * bad))

    def test_verify_both_refuses_a_wrong_length_without_a_backend(self):
        # verify_both checks the size before it calls either witness, so it refuses a wrong length
        # even here, and the lone-primary fallback never decides bytes of the wrong length.
        msg = b"a stored credential"
        pk_len, sig_len = pqc_signing.custody.ALGORITHM_SIZES["ML-DSA-65"]
        for bad_pk in (b"", b"\x01", b"\x01" * 32, b"\x01" * (pk_len - 1)):
            self.assertIs(pqc_signing.verify_both(msg, (b"\x02" * sig_len).hex(), bad_pk.hex(),
                                                  algorithm="ML-DSA-65"), False, len(bad_pk))

    def test_a_lone_primary_that_would_accept_cannot_resurrect_a_wrong_length(self):
        # The size check is upstream of the fallback: stub the primary to accept and the witness
        # to "not installed" (None); verify_both still refuses a wrong-length key.
        msg = b"a stored credential"
        _, sig_len = pqc_signing.custody.ALGORITHM_SIZES["ML-DSA-65"]
        saved = (pqc_signing.verify, pqc_signing._verify_second_witness)
        try:
            pqc_signing.verify = lambda *a, **k: True
            pqc_signing._verify_second_witness = lambda *a, **k: None
            self.assertIs(pqc_signing.verify_both(msg, (b"\x02" * sig_len).hex(), (b"\x01" * 32).hex(),
                                                  algorithm="ML-DSA-65"), False)
        finally:
            pqc_signing.verify, pqc_signing._verify_second_witness = saved

    @unittest.skipUnless(pqc_signing.is_available(), "needs liboqs for verify() and the control")
    def test_verify_refuses_a_wrong_length_key_and_a_real_signature_still_verifies(self):
        msg = b"a stored credential"
        digest = hashlib.sha3_256(msg).digest()
        pk_len, sig_len = pqc_signing.custody.ALGORITHM_SIZES["ML-DSA-65"]
        for bad_pk in (b"", b"\x01", b"\x01" * 32, b"\x01" * (pk_len - 1), b"\x01" * (pk_len + 1)):
            self.assertIs(pqc_signing.verify(msg, (b"\x02" * sig_len).hex(), bad_pk.hex(),
                                             algorithm="ML-DSA-65"), False, len(bad_pk))
        # positive control: a real key and a real signature still verify
        import oqs  # type: ignore
        with oqs.Signature("ML-DSA-65") as s:
            pk = bytes(s.generate_keypair())
            sig = bytes(s.sign(digest))
        self.assertIs(pqc_signing.verify(msg, sig.hex(), pk.hex(), algorithm="ML-DSA-65"), True)
        self.assertIs(pqc_signing.verify_both(msg, sig.hex(), pk.hex(), algorithm="ML-DSA-65"), True)

    @unittest.skipUnless(pqc_signing.is_available() and pqc_signing.second_witness_available(),
                         "needs both witnesses")
    def test_the_second_witness_returns_False_not_None_on_a_wrong_length(self):
        msg = b"a stored credential"
        pk_len, sig_len = pqc_signing.custody.ALGORITHM_SIZES["ML-DSA-65"]
        for bad_pk in (b"", b"\x01", b"\x01" * 32, b"\x01" * (pk_len - 1)):
            self.assertIs(pqc_signing._verify_second_witness(msg, (b"\x02" * sig_len).hex(),
                                                             bad_pk.hex(), algorithm="ML-DSA-65"), False, len(bad_pk))


class SelfCheckNamesASizeRefusalTests(unittest.TestCase):
    """2026-10-10: the three signing self-checks (issuance, a status assertion, a migration) said a
    key or signature of the wrong size "failed two-witness self-verification", though verify_both
    refuses those bytes before either witness runs. They now raise with _size_problem's reason, and
    keep the two-witness message for a refusal the witnesses made. The signer and the witnesses are
    stand-ins and the bytes are arbitrary, so no backend is needed."""

    PK_LEN, SIG_LEN = pqc_signing.custody.ALGORITHM_SIZES["ML-DSA-65"]

    def setUp(self):
        patches = [unittest.mock.patch.dict(os.environ, {"POLARIS_USE_REAL_PQC": "1"}),
                   unittest.mock.patch.object(pqc_signing, "_OQS_AVAILABLE", True),
                   unittest.mock.patch.object(pqc_signing, "_WITNESS_AVAILABLE", True)]
        if "oqs" not in sys.modules:   # the migration signer imports oqs before it asks custody
            patches.append(unittest.mock.patch.dict(sys.modules, {"oqs": types.ModuleType("oqs")}))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def refusals(self, pk, sig):
        """What each self-checking signer raises when its key gives `pk` and `sig`."""
        result = pqc_signing.SigningResult(algorithm_name="ML-DSA-65", public_key_hex=pk.hex(),
                                           signature_hex=sig.hex(), message_hash_hex="00" * 32)

        class Key:
            algorithm = "ML-DSA-65"

            def public_key(self):
                return pk

            def sign(self, digest):
                return sig

        signers = (("issuance", lambda: pqc_signing.signature_with_key_for_token("TKN-SELF-CHECK")),
                   ("status assertion", lambda: pqc_signing.signature_over_message(b"a status assertion")),
                   ("migration", lambda: pqc_signing.signature_for_migration("TKN-SELF-CHECK", "ML-DSA-65")))
        said = {}
        with unittest.mock.patch.object(pqc_signing, "sign", return_value=result), \
                unittest.mock.patch.object(pqc_signing.custody, "get_custody_for_algorithm", return_value=Key()):
            for label, signer in signers:
                with self.assertRaises(pqc_signing.SigningError, msg=label) as raised:
                    signer()
                said[label] = str(raised.exception)
        return said

    def test_a_key_of_the_wrong_size_is_refused_with_its_size(self):
        pk, sig = bytes(range(32)), b"\x02" * self.SIG_LEN
        reason = pqc_signing._size_problem("ML-DSA-65", pk, sig)
        self.assertEqual(reason, "the public key is 32 bytes; ML-DSA-65 takes exactly 1952")
        said = self.refusals(pk, sig)
        for label, made, refusing in (("issuance", "the produced ML-DSA-65 signature", "refusing to issue"),
                                      ("status assertion", "the produced ML-DSA-65 status assertion", "refusing to sign"),
                                      ("migration", "the ML-DSA-65 migration signature", "refusing to write it")):
            with self.subTest(label):
                self.assertEqual(said[label], "%s is refused before either witness runs: %s; %s"
                                 % (made, reason, refusing))

    def test_a_witness_disagreement_keeps_the_two_witness_message(self):
        with unittest.mock.patch.object(pqc_signing, "verify", return_value=True), \
                unittest.mock.patch.object(pqc_signing, "_verify_second_witness", return_value=False):
            said = self.refusals(b"\x01" * self.PK_LEN, b"\x02" * self.SIG_LEN)
        for label, message in (
                ("issuance", "produced ML-DSA-65 signature failed two-witness self-verification; refusing to issue"),
                ("status assertion", "produced ML-DSA-65 status assertion failed two-witness self-verification; "
                                     "refusing to sign"),
                ("migration", "an ML-DSA-65 migration signature failed two-witness self-verification; "
                              "refusing to write it")):
            with self.subTest(label):
                self.assertEqual(said[label], message)

    def test_the_migration_message_takes_its_sets_article(self):
        pk_len, sig_len = pqc_signing.custody.EXPERIMENTAL_ALGORITHM_SIZES["Falcon-padded-1024"]

        class Key:
            algorithm = "Falcon-padded-1024"

            def public_key(self):
                return b"\x01" * pk_len

            def sign(self, digest):
                return b"\x02" * sig_len

        with unittest.mock.patch.object(pqc_signing, "_signs_under", return_value=True), \
                unittest.mock.patch.object(pqc_signing.custody, "get_custody_for_algorithm", return_value=Key()), \
                unittest.mock.patch.object(pqc_signing, "verify", return_value=True), \
                unittest.mock.patch.object(pqc_signing, "_verify_second_witness", return_value=False):
            with self.assertRaises(pqc_signing.SigningError) as raised:
                pqc_signing.signature_for_migration("TKN-SELF-CHECK", "Falcon-padded-1024")
        self.assertEqual(str(raised.exception), "a Falcon-padded-1024 migration signature failed two-witness "
                                                "self-verification; refusing to write it")


class HexFieldTests(unittest.TestCase):
    """unhex reads a hex field the way the three published verifiers do (1218b649): hex digits
    in either case and nothing else, with bytes.fromhex's own exceptions."""

    def test_hex_digits_in_either_case_decode(self):
        self.assertEqual(pqc_signing.unhex('00ff7e'), b'\x00\xff\x7e')
        self.assertEqual(pqc_signing.unhex('00FF7E'), b'\x00\xff\x7e')
        self.assertEqual(pqc_signing.unhex(''), b'')

    def test_anything_but_an_even_run_of_hex_digits_is_refused(self):
        for bad in ('00 ff', '00ff\n', '\t00ff', '00\u00a0ff', '0ff', '0g', '\u0660\u0661'):
            with self.assertRaises(ValueError, msg=repr(bad)):
                pqc_signing.unhex(bad)

    def test_a_value_that_is_not_a_string_is_a_type_error(self):
        for bad in (None, b'00ff', 255, ['00']):
            with self.assertRaises(TypeError, msg=repr(bad)):
                pqc_signing.unhex(bad)


class HeldOutVerificationTests(unittest.TestCase):
    """A held-out round on 2026-09-24: of eleven mutations of the verification functions,
    five survived test_pqc_signing, test_custody, the simulator and nine test_app classes.
    Each test below is the one input that separates a mutant from the code as written."""

    def test_a_placeholder_differing_only_in_its_last_byte_is_refused(self):
        """Both placeholder paths compare all 32 bytes. The existing tamper test changed the
        token, which changes every byte of the digest, so a comparison of any prefix passed."""
        token = 'TKN-CA-2026-000002'
        good = hashlib.sha3_256(token.encode('utf-8')).digest()
        near = good[:-1] + bytes([good[-1] ^ 1])
        self.assertTrue(pqc_signing.verify_stored_signature(token, good, None))
        self.assertFalse(pqc_signing.verify_stored_signature(token, near, None))
        self.assertTrue(pqc_signing.verify_token_signature(token, good, pqc_signing.PLACEHOLDER_LABEL))
        self.assertFalse(pqc_signing.verify_token_signature(token, near, pqc_signing.PLACEHOLDER_LABEL))

    def test_a_claimed_key_is_never_checked_as_a_placeholder(self):
        """A stored row that names a public key is a real signature or nothing. Without liboqs
        it cannot be checked, and the answer is False, not a fall-through to the placeholder
        comparison, which the placeholder's own bytes would pass."""
        from unittest import mock
        token = 'TKN-CA-2026-000002'
        placeholder = hashlib.sha3_256(token.encode('utf-8')).digest()
        with mock.patch.object(pqc_signing, '_OQS_AVAILABLE', False):
            self.assertFalse(pqc_signing.verify_stored_signature(token, placeholder, 'ab' * 1952))

    def _anchors_file(self, doc):
        import json
        import tempfile
        fd, path = tempfile.mkstemp(suffix='.json')
        with os.fdopen(fd, 'w') as fh:
            json.dump(doc, fh)
        return path

    def _anchors(self, doc):
        from unittest import mock
        path = self._anchors_file(doc)
        with mock.patch.dict(os.environ, {'POLARIS_PQC_TRUST_ANCHORS_FILE': path}), \
                mock.patch.object(pqc_signing, 'trust_anchor_public_key_hex', return_value=None):
            return pqc_signing.trust_anchor_public_keys()

    def test_a_previous_anchor_is_read_from_the_file(self):
        """The control for the two refusals below: a well-formed file adds its anchors."""
        self.assertEqual(self._anchors({'anchors': [{'public_key_hex': 'ab' * 1952}]}), ['ab' * 1952])

    def test_an_anchor_that_is_not_hex_fails_loud(self):
        """Trust must not shrink silently, and it must not grow by a key nothing can parse."""
        with self.assertRaises(RuntimeError):
            self._anchors({'anchors': [{'public_key_hex': 'not-hex'}]})

    def test_an_anchor_entry_with_no_key_fails_loud(self):
        with self.assertRaises(RuntimeError):
            self._anchors({'anchors': [{'label': 'retired 2026', 'retired': True}]})

    def test_an_anchor_of_no_accepted_length_fails_loud(self):
        """KEY-CEREMONY: a malformed anchors file fails loud rather than silently shrinking
        trust. An empty key, a short one or a genuine key cut short loaded and verified nothing."""
        for pk in ('', 'abababab', 'ab' * 1951):
            with self.assertRaises(RuntimeError, msg='%d hex characters' % len(pk)):
                self._anchors({'anchors': [{'public_key_hex': pk}]})

    def test_an_anchor_written_with_whitespace_fails_loud(self):
        """Every verify reads a key as hex digits only, so an anchor with a space in it would
        load and then verify nothing: trust shrinking silently, which this loader refuses."""
        with self.assertRaises(RuntimeError):
            self._anchors({'anchors': [{'public_key_hex': 'abab abab'}]})


@unittest.skipUnless(pqc_signing.is_available(),
                     "liboqs-python not importable; the allowlist is only reachable with it")
class HeldOutAllowlistTests(unittest.TestCase):

    def test_a_valid_signature_under_an_unaccepted_parameter_set_is_refused(self):
        """ML-DSA-44 is a real parameter set liboqs will verify. It is not one this system
        accepts, so a signature under it is refused even when it is genuine. The existing test
        of this sent a signature made under ANOTHER set, which failed verification whether or
        not the allowlist ran."""
        import oqs
        digest = hashlib.sha3_256(b"agile").digest()
        with oqs.Signature("ML-DSA-44") as signer:
            pk = signer.generate_keypair()
            sig = signer.sign(digest)
        with oqs.Signature("ML-DSA-44") as check:
            self.assertTrue(check.verify(digest, sig, pk), "control: the signature is genuine")
        self.assertNotIn("ML-DSA-44", pqc_signing.ACCEPTED_ALGORITHMS)
        self.assertFalse(pqc_signing.verify(b"agile", sig.hex(), pk.hex(), algorithm="ML-DSA-44"))


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



def _falcon_ready():
    """liboqs with Falcon (the primary) and Node with @noble/post-quantum (the second witness)."""
    if not pqc_signing.is_available():
        return False
    import shutil
    import oqs  # type: ignore
    return ("Falcon-padded-1024" in oqs.get_enabled_sig_mechanisms() and shutil.which("node") is not None
            and os.path.isfile(os.path.join(pqc_signing._noble_dir(), "falcon.js")))


class ExperimentalSignerGateTests(unittest.TestCase):
    """2026-10-06: the FN-DSA family signs only under its opt-in, never in production, and never
    with one witness. Falsifiers F1, F2 and F3 of the step-2 plan, as tests."""

    A = "Falcon-padded-1024"

    def setUp(self):
        self._env = dict(os.environ)
        for k in ("POLARIS_EXPERIMENTAL_SIGNERS", "POLARIS_ENV", "POLARIS_NOBLE_DIR", "POLARIS_PQC_ALGORITHM"):
            os.environ.pop(k, None)

    def tearDown(self):
        os.environ.clear(); os.environ.update(self._env)

    def test_the_gate(self):
        import custody
        self.assertFalse(custody.experimental_signer_allowed(self.A), "no opt-in")
        os.environ["POLARIS_EXPERIMENTAL_SIGNERS"] = self.A
        self.assertTrue(custody.experimental_signer_allowed(self.A))
        os.environ["POLARIS_ENV"] = "production"
        self.assertFalse(custody.experimental_signer_allowed(self.A), "F1: production never signs under it")
        os.environ["POLARIS_ENV"] = "development"
        os.environ["POLARIS_EXPERIMENTAL_SIGNERS"] = "ML-DSA-87, Falcon-padded-512"
        self.assertFalse(custody.experimental_signer_allowed(self.A), "only the named set")
        self.assertFalse(custody.experimental_signer_allowed("Falcon-padded-512"), "never one not on the list")

    def test_a_configured_falcon_algorithm_is_refused_without_the_opt_in(self):
        import custody
        os.environ["POLARIS_PQC_ALGORITHM"] = self.A
        with self.assertRaises(custody.CustodyError):
            custody.configured_algorithm()
        os.environ["POLARIS_EXPERIMENTAL_SIGNERS"] = self.A
        self.assertEqual(custody.configured_algorithm(), self.A)
        os.environ["POLARIS_ENV"] = "production"
        with self.assertRaises(custody.CustodyError):
            custody.configured_algorithm()

    def test_verification_needs_no_opt_in(self):
        self.assertTrue(pqc_signing._verifies_under(self.A))
        self.assertFalse(pqc_signing._signs_under(self.A))
        self.assertFalse(pqc_signing._verifies_under("Falcon-padded-512"))

    @unittest.skipUnless(_falcon_ready(), "needs liboqs with Falcon and Node with @noble/post-quantum")
    def test_end_to_end_two_witnessed_and_fail_closed(self):
        import oqs  # type: ignore
        with self.assertRaises(ValueError):
            pqc_signing.generate_keypair(self.A)
        os.environ["POLARIS_EXPERIMENTAL_SIGNERS"] = self.A
        kp = pqc_signing.generate_keypair(self.A)
        self.assertEqual(len(kp["public_key_hex"]), 2 * 1793)
        msg = b"POLARIS-FNDSA-UNIT-0001"
        with oqs.Signature(self.A, secret_key=bytes.fromhex(kp["secret_key_hex"])) as s:
            sig = bytes(s.sign(hashlib.sha3_256(msg).digest())).hex()
        self.assertEqual(len(sig), 2 * 1280)
        self.assertTrue(pqc_signing.verify_both(msg, sig, kp["public_key_hex"], require_witness=True))
        bad = sig[:400] + ("0" if sig[400] != "0" else "1") + sig[401:]
        self.assertFalse(pqc_signing.verify_both(msg, bad, kp["public_key_hex"], require_witness=True),
                         "F3: a tampered signature is not certified")
        os.environ["POLARIS_NOBLE_DIR"] = "/nonexistent"
        self.assertIsNone(pqc_signing._falcon_witness(hashlib.sha3_256(msg).digest(), bytes.fromhex(sig),
                                                      bytes.fromhex(kp["public_key_hex"])))
        self.assertFalse(pqc_signing.verify_both(msg, sig, kp["public_key_hex"], require_witness=True),
                         "F2: with the second witness absent, nothing is certified on one")


# --------------------------------------------------------------------------- COSE (RFC 9964)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RFC9964_COSE = os.path.join(_ROOT, "vectors", "kat", "rfc9964_mldsa_65_cose.json")
_MDOC_FULL = {"issuing_authority": "Authority A", "context": "BANKING",
              "assurance_level": "polaris:possession", "enrollment_status": "ENROLLED",
              "credential_status": "ACTIVE"}


def _rfc9964_vector():
    import json
    with open(_RFC9964_COSE, encoding="utf-8") as fh:
        return json.load(fh)


def _detached_verifier():
    """The polaris-verify package's verifier, loaded from its file as a stranger's install runs it."""
    import importlib.util
    path = os.path.join(_ROOT, "packages", "polaris-verify", "polaris_verify_cli", "verifier.py")
    spec = importlib.util.spec_from_file_location("_cose_test_detached_verifier", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _issuer_auth(document):
    import cbor2
    return cbor2.loads(document)["issuerSigned"]["issuerAuth"]


class CoseSigStructureRefusalTests(unittest.TestCase):
    """The COSE signer signs a COSE_Sign1 Sig_structure and nothing else, on every path, before
    anything is signed. Its output is pure ML-DSA over the bytes it is given, so a 32-byte digest
    handed to it would come back as the signature the digest signer makes over that digest's
    preimage. No backend is needed: the refusal comes first."""

    def setUp(self):
        self._saved = os.environ.get("POLARIS_USE_REAL_PQC")

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("POLARIS_USE_REAL_PQC", None)
        else:
            os.environ["POLARIS_USE_REAL_PQC"] = self._saved

    def test_anything_but_a_sig_structure_is_refused_in_either_profile(self):
        for flag in ("0", "1"):
            os.environ["POLARIS_USE_REAL_PQC"] = flag
            for bad in (hashlib.sha3_256(b"a canonical statement").digest(), b"",
                        b"\x84\x6aSignature", b"\x84\x6aSignature2", "\x84\x6aSignature1", None):
                with self.subTest(flag=flag, bad=bad):
                    with self.assertRaises(pqc_signing.NotACoseSigStructure):
                        pqc_signing.signature_over_cose_sig_structure(bad)

    def test_the_placeholder_is_the_labelled_sha3_256_of_the_structure_with_no_key(self):
        os.environ.pop("POLARIS_USE_REAL_PQC", None)
        to_be_signed = pqc_signing.COSE_SIGN1_SIG_STRUCTURE_HEAD + b"\x44\xa1\x01\x38\x30\x40\x41\x00"
        self.assertEqual(pqc_signing.signature_over_cose_sig_structure(to_be_signed),
                         (hashlib.sha3_256(to_be_signed).digest(), pqc_signing.PLACEHOLDER_LABEL, None))


class CosePlaceholderNeverVerifiesTests(unittest.TestCase):
    """Without POLARIS_USE_REAL_PQC the mdoc issuer signature is the development placeholder under
    a protected header that says -49: SHA3-256 of the Sig_structure, labelled
    DETERMINISTIC-PLACEHOLDER-SHA3-256, with no key. It is not a signature, and nothing may
    accept it: the detached verifier in the mode `--pqc-provider` runs (real backends) or the mode
    `--dev-placeholder` runs (none), the same bytes relabelled ML-DSA-65 under a genuine key, and
    the app's own raw two-witness check. Built through mdoc.py's real path, with the signer the
    route uses; the genuine key is RFC 9964's, so no backend is needed."""

    def setUp(self):
        self._saved = os.environ.pop("POLARIS_USE_REAL_PQC", None)

    def tearDown(self):
        if self._saved is not None:
            os.environ["POLARIS_USE_REAL_PQC"] = self._saved

    def test_the_placeholder_under_minus_49_never_verifies(self):
        import cbor2
        import mdoc
        document = mdoc.build_document(_MDOC_FULL, "ML-DSA-65", pqc_signing.signature_over_cose_sig_structure)
        protected, unprotected, payload, signature = _issuer_auth(document)
        to_be_signed = mdoc.sig_structure(protected, payload)
        self.assertEqual(cbor2.loads(protected), {1: -49})
        self.assertEqual(unprotected, {"polaris_public_key_hex": None,
                                       "polaris_algorithm": pqc_signing.PLACEHOLDER_LABEL})
        self.assertEqual(signature, hashlib.sha3_256(to_be_signed).digest())

        genuine_key = _rfc9964_vector()["raw_public_key"]
        relabelled = cbor2.loads(document)
        relabelled["issuerSigned"]["issuerAuth"][1] = {"polaris_public_key_hex": genuine_key,
                                                      "polaris_algorithm": "ML-DSA-65"}
        relabelled = cbor2.dumps(relabelled, canonical=True)
        V = _detached_verifier()
        for dev_placeholder in (False, True):        # --pqc-provider, then --dev-placeholder
            V.set_dev_placeholder_mode(dev_placeholder)
            try:
                for doc, why in ((document, "unaccepted signature algorithm"),
                                 (relabelled, "the signature is 32 bytes")):
                    verdict = V.verify_mdoc(doc, anchor_keys=[genuine_key])
                    with self.subTest(dev_placeholder=dev_placeholder, why=why):
                        self.assertIs(verdict["digests_match"], True, "the format still bridges")
                        self.assertIs(verdict["issuer_authentic"], False)
                        self.assertIsNot(verdict["issuer_trusted"], True)
                        self.assertIn(why, verdict["note"] or "")
            finally:
                V.set_dev_placeholder_mode(False)
        self.assertFalse(pqc_signing.verify_both_raw(to_be_signed, signature.hex(), genuine_key))
        self.assertFalse(pqc_signing.verify_both_raw(to_be_signed, signature.hex(), genuine_key,
                                                     require_witness=True, algorithm="ML-DSA-65"))


@unittest.skipUnless(pqc_signing.is_available() and pqc_signing.second_witness_available(),
                     "needs BOTH liboqs (oqs) and the cryptography ML-DSA witness")
class CoseRfc9964KnownAnswerTests(unittest.TestCase):
    """RFC 9964, Appendix A.2, Figure 7: the IETF's own ML-DSA-65 COSE_Sign1, pinned in
    vectors/kat/rfc9964_mldsa_65_cose.json with its provenance. COSE -49 is pure ML-DSA-65, empty
    context, over the Sig_structure itself, so the tree's raw two-witness verify must accept the
    RFC's signature over the RFC's ToBeSigned, under both witnesses, and nothing one bit away."""

    @classmethod
    def setUpClass(cls):
        cls.vector = _rfc9964_vector()
        cls.to_be_signed = bytes.fromhex(cls.vector["raw_to_be_signed"])
        cls.signature = bytes.fromhex(cls.vector["raw_signature"])
        cls.public_key = bytes.fromhex(cls.vector["raw_public_key"])

    def test_the_vector_is_the_rfc_figure_it_names(self):
        import cbor2
        import mdoc
        provenance = self.vector["provenance"]
        self.assertIn("RFC 9964", provenance["source"])
        self.assertIn("Figure 7: ML_DSA_65", provenance["source"])
        self.assertEqual(len(provenance["sha256_of_retrieved_file"]), 64)
        # Its parts agree: sign1 carries the signature, and the tree's own Sig_structure builder
        # rebuilds raw_to_be_signed from sign1's protected header and payload.
        tagged = cbor2.loads(bytes.fromhex(self.vector["sign1"]))
        self.assertEqual(tagged.tag, 18)
        protected, _unprotected, payload, signature = tagged.value
        self.assertEqual(cbor2.loads(protected)[1], -49)
        self.assertEqual(signature, self.signature)
        self.assertEqual(mdoc.sig_structure(protected, payload), self.to_be_signed)
        # And the key is the one the figure's all-zero seed derives (cryptography, not the tree).
        from cryptography.hazmat.primitives.asymmetric import mldsa
        if hasattr(mldsa.MLDSA65PrivateKey, "from_seed_bytes"):
            seed = bytes.fromhex(self.vector["priv"])
            self.assertEqual(mldsa.MLDSA65PrivateKey.from_seed_bytes(seed).public_key().public_bytes_raw(),
                             self.public_key)

    def test_both_witnesses_verify_the_rfc_signature_over_the_raw_to_be_signed(self):
        args = (self.to_be_signed, self.signature.hex(), self.public_key.hex())
        self.assertTrue(pqc_signing.verify_raw(*args), "liboqs")
        self.assertIs(pqc_signing._verify_second_witness_raw(*args), True, "cryptography")
        self.assertTrue(pqc_signing.verify_both_raw(*args, require_witness=True, algorithm="ML-DSA-65"))

    def test_one_bit_away_is_refused(self):
        for at in (0, len(self.signature) // 2, len(self.signature) - 1):
            bad = bytearray(self.signature)
            bad[at] ^= 0x01
            with self.subTest(signature_byte=at):
                self.assertFalse(pqc_signing.verify_both_raw(self.to_be_signed, bytes(bad).hex(),
                                                             self.public_key.hex(), require_witness=True))
        for at in (0, 20, len(self.to_be_signed) - 1):
            bad = bytearray(self.to_be_signed)
            bad[at] ^= 0x01
            with self.subTest(to_be_signed_byte=at):
                self.assertFalse(pqc_signing.verify_both_raw(bytes(bad), self.signature.hex(),
                                                             self.public_key.hex(), require_witness=True))

    def test_the_sha3_256_pre_hash_is_not_what_an_rfc_9964_signature_is_over(self):
        # The digest path, which the mdoc route used until 2026-10-14, does not accept it.
        self.assertFalse(pqc_signing.verify_both(self.to_be_signed, self.signature.hex(),
                                                 self.public_key.hex()))


@unittest.skipUnless(pqc_signing.is_available() and pqc_signing.second_witness_available(),
                     "needs BOTH liboqs (oqs) and the cryptography ML-DSA witness")
class CoseSignerTests(unittest.TestCase):
    """The COSE signer through mdoc.py's real path, under real ML-DSA with a persistent key file,
    exactly as the /api/v1/mdoc route calls it. What it makes is checked by pyca/cryptography
    directly, over a Sig_structure rebuilt here with cbor2: no verify code of the tree's."""

    def setUp(self):
        import json
        import tempfile
        self._saved = {k: os.environ.get(k) for k in ("POLARIS_USE_REAL_PQC", "POLARIS_PQC_SIGNING_KEY_FILE",
                                                      "POLARIS_CUSTODY_DRIVER")}
        self.keys = {}
        self._files = []
        for algorithm in ("ML-DSA-65", "ML-DSA-87"):
            self.keys[algorithm] = pqc_signing.generate_keypair(algorithm)
            fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
            json.dump(self.keys[algorithm], fh)
            fh.close()
            self._files.append(fh.name)
        self._key_files = dict(zip(("ML-DSA-65", "ML-DSA-87"), self._files))
        os.environ.pop("POLARIS_CUSTODY_DRIVER", None)
        os.environ["POLARIS_USE_REAL_PQC"] = "1"
        self._use("ML-DSA-65")

    def tearDown(self):
        for name in self._files:
            os.unlink(name)
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        pqc_signing.custody.reset()

    def _use(self, algorithm):
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = self._key_files[algorithm]

    def _independent(self, algorithm, public_key_hex, signature, message):
        """pyca/cryptography's ML-DSA, not the tree's: True iff it accepts `signature` over
        `message` itself, with the empty context."""
        from cryptography.hazmat.primitives.asymmetric import mldsa
        from cryptography.exceptions import InvalidSignature
        cls = {"ML-DSA-65": mldsa.MLDSA65PublicKey, "ML-DSA-87": mldsa.MLDSA87PublicKey}[algorithm]
        key = cls.from_public_bytes(bytes.fromhex(public_key_hex))
        try:
            key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def test_a_tree_made_cose_sign1_is_pure_ml_dsa_65_over_the_raw_sig_structure(self):
        import cbor2
        import mdoc
        document = mdoc.build_document(_MDOC_FULL, "ML-DSA-65", pqc_signing.signature_over_cose_sig_structure)
        protected, unprotected, payload, signature = _issuer_auth(document)
        self.assertEqual(cbor2.loads(protected), {1: -49})
        self.assertEqual(unprotected, {"polaris_public_key_hex": self.keys["ML-DSA-65"]["public_key_hex"],
                                       "polaris_algorithm": "ML-DSA-65"})
        to_be_signed = cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)
        key = self.keys["ML-DSA-65"]["public_key_hex"]
        self.assertTrue(self._independent("ML-DSA-65", key, signature, to_be_signed),
                        "pyca/cryptography refused the signature over the raw Sig_structure")
        self.assertFalse(self._independent("ML-DSA-65", key, signature, hashlib.sha3_256(to_be_signed).digest()),
                         "the signature is over the digest of the Sig_structure")
        # The detached verifier a relying party installs accepts it, under the issuer's key.
        verdict = _detached_verifier().verify_mdoc(document, anchor_keys=[key])
        self.assertIs(verdict["issuer_authentic"], True, verdict["note"])
        self.assertIs(verdict["issuer_trusted"], True)

    def test_ml_dsa_87_is_cose_minus_50_the_same_way(self):
        import cbor2
        import mdoc
        self._use("ML-DSA-87")
        document = mdoc.build_document(_MDOC_FULL, "ML-DSA-87", pqc_signing.signature_over_cose_sig_structure)
        protected, unprotected, payload, signature = _issuer_auth(document)
        self.assertEqual(cbor2.loads(protected), {1: -50})
        to_be_signed = cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)
        self.assertTrue(self._independent("ML-DSA-87", unprotected["polaris_public_key_hex"], signature, to_be_signed))
        # A document that names -49 is refused rather than carrying an ML-DSA-87 signature.
        with self.assertRaises(ValueError):
            mdoc.build_document(_MDOC_FULL, "ML-DSA-65", pqc_signing.signature_over_cose_sig_structure)

    def test_a_signature_that_fails_its_raw_self_check_is_refused(self):
        with unittest.mock.patch.object(pqc_signing, "verify_raw", return_value=False):
            with self.assertRaises(pqc_signing.SigningError) as raised:
                pqc_signing.signature_over_cose_sig_structure(
                    pqc_signing.COSE_SIGN1_SIG_STRUCTURE_HEAD + b"\x44\xa1\x01\x38\x30\x40\x41\x00")
        self.assertIn("over the raw Sig_structure", str(raised.exception))


@unittest.skipUnless(pqc_signing.is_available() and pqc_signing.second_witness_available(),
                     "needs BOTH liboqs (oqs) and the cryptography ML-DSA witness")
class StoredSignatureAlgorithmTests(unittest.TestCase):
    """A stored signature is checked under the algorithm its row records when the caller passes
    it, as the relying-party door does (rp_api._possession_authenticated): a key or signature of
    another parameter set's length is refused, and so is a set nothing here verifies. With no
    algorithm the set is read from the key's length, as callers with no row do."""

    TOKEN = "TKN-ALGORITHM-LABEL-1"

    @classmethod
    def setUpClass(cls):
        import oqs  # type: ignore
        cls.signed = {}
        for algorithm in ("ML-DSA-65", "ML-DSA-87"):
            with oqs.Signature(algorithm) as signer:
                public_key = signer.generate_keypair()
                signature = signer.sign(hashlib.sha3_256(cls.TOKEN.encode("utf-8")).digest())
            cls.signed[algorithm] = (signature, public_key.hex())

    def _verifies(self, made_under, recorded, witnesses):
        signature, public_key_hex = self.signed[made_under]
        return pqc_signing.verify_stored_signature(self.TOKEN, signature, public_key_hex,
                                                   witnesses=witnesses, algorithm=recorded)

    def test_a_signature_verifies_under_the_algorithm_that_made_it(self):
        for algorithm in ("ML-DSA-65", "ML-DSA-87"):
            for witnesses in ("single", "both"):
                with self.subTest(algorithm=algorithm, witnesses=witnesses):
                    self.assertTrue(self._verifies(algorithm, algorithm, witnesses))
                    self.assertTrue(self._verifies(algorithm, None, witnesses),
                                    "with no row, the key's length names the set")

    def test_a_row_that_records_another_algorithm_is_refused(self):
        for made_under, recorded in (("ML-DSA-65", "ML-DSA-87"), ("ML-DSA-87", "ML-DSA-65"),
                                     ("ML-DSA-65", "SLH-DSA-256s"), ("ML-DSA-65", "ECDSA-P256")):
            for witnesses in ("single", "both"):
                with self.subTest(made_under=made_under, recorded=recorded, witnesses=witnesses):
                    self.assertFalse(self._verifies(made_under, recorded, witnesses))
