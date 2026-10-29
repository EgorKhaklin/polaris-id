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
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from datetime import datetime, timedelta, timezone

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
_spec = importlib.util.spec_from_file_location("polaris_verify_refusals", HERE / "polaris-verify.py")
V = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(V)

# Run from a hook, git hands this process GIT_INDEX_FILE and GIT_DIR. The probes below put a stub
# git first on PATH; whatever answers to `git` there must not inherit the commit being made.
_HOOK_GIT_ENV = {}


def setUpModule():
    _HOOK_GIT_ENV.update({k: os.environ.pop(k) for k in list(os.environ) if k.startswith("GIT_")})


def tearDownModule():
    os.environ.update(_HOOK_GIT_ENV)


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
        # Refused at the size check since 2026-10-10 (a signature that is not bytes has no
        # length to check); the library's own error arm is driven by the test below.
        self.assertIs(V._verify_cryptography(self.digest, self.sig.hex(), self.pk), False)

    @unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
    def test_cryptography_witness_refuses_what_the_library_throws_on(self):
        # Not InvalidSignature: a key and signature of the right length (arbitrary bytes) pass the
        # size check, the message is not bytes, so the library itself raises and its error arm
        # must refuse. The drill's environment has the library, so this never skips there.
        self.assertIs(V._verify_cryptography("not bytes", b"\x02" * 3309, b"\x01" * 1952), False)

    def test_liboqs_witness_refuses_what_the_library_throws_on(self):
        try:
            V._import_oqs()
        except Exception:  # noqa: BLE001
            self.skipTest("liboqs absent (the drill's environment has it)")
        self.assertIs(V._verify_liboqs(self.digest, self.sig, self.pk), True)
        self.assertIs(V._verify_liboqs(self.digest, self.sig.hex(), self.pk), False)   # refused at the size check
        # A key and signature of the right length (arbitrary bytes) pass the size check; the
        # message is not bytes, so the library itself raises and its error arm must refuse.
        self.assertIs(V._verify_liboqs("not bytes", b"\x02" * 3309, b"\x01" * 1952), False)

    def test_an_unknown_provider_is_not_available(self):
        for name in ("bogus", "", None, "OQS"):
            self.assertIs(V._provider_available(name), False, name)

    def test_liboqs_witness_refuses_an_algorithm_below_the_floor_before_loading(self):
        # Decided before the library is imported, so it holds with or without liboqs.
        self.assertIs(V._verify_liboqs(self.digest, self.sig, self.pk, "ML-DSA-44"), False)
        self.assertIs(V._verify_liboqs(self.digest, self.sig, self.pk, "RSA-2048"), False)


class AnotherProjectsOqsModule(unittest.TestCase):
    """A module named `oqs` that is not liboqs-python must not count as a backend.

    PyPI's `oqs` is an unrelated project whose wheel installs a top-level `oqs` package, and
    every polaris-verify release through 1.0.0rc8 named it as the `oqs` extra. Imported, it
    made `--pqc-provider oqs` start and `auto` choose it ahead of cryptography, and under any
    provider its liboqs witness voted every genuine credential invalid, so the two witnesses
    disagreed and nothing was accepted. A stub with no `Signature` stands in for it here: the
    real one is never installed. A fresh interpreter, so no other test's import of liboqs can
    mask the stub."""

    PROBE = (
        "import importlib.util, json, sys\n"
        "spec = importlib.util.spec_from_file_location('v', sys.argv[1])\n"
        "V = importlib.util.module_from_spec(spec); spec.loader.exec_module(V)\n"
        "pack = json.load(open(sys.argv[2]))\n"
        "import oqs\n"
        "print(json.dumps({'stub': getattr(oqs, 'POLARIS_TEST_STUB', False),\n"
        "    'oqs': V._provider_available('oqs'),\n"
        "    'cryptography': V._provider_available('cryptography'),\n"
        "    'auto': V.resolve_crypto_mode('auto', False),\n"
        "    'witness': V._verify_liboqs(V._digest(pack['token_value']),\n"
        "        bytes.fromhex(pack['signature_hex']), bytes.fromhex(pack['public_key_hex']))}))\n")

    @classmethod
    def setUpClass(cls):
        cls.stub = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oqs-stub-"))
        (cls.stub / "oqs").mkdir()
        (cls.stub / "oqs" / "__init__.py").write_text(
            "POLARIS_TEST_STUB = True\n\ndef evaluate(expression):\n    return None\n")
        cls.env = dict(os.environ, PYTHONPATH=str(cls.stub))
        cls.vector = ROOT / "vectors" / "ml-dsa-65-valid.json"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.stub, ignore_errors=True)

    def run_python(self, *argv):
        return subprocess.run([sys.executable, *argv], env=self.env, cwd=str(self.stub),
                              capture_output=True, text=True, timeout=120)

    def test_the_stub_is_imported_and_is_not_a_backend(self):
        r = self.run_python("-c", self.PROBE, str(HERE / "polaris-verify.py"), str(self.vector))
        self.assertEqual(r.returncode, 0, r.stderr)
        got = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertIs(got["stub"], True, "positive control: the stub must be the `oqs` imported")
        self.assertIs(got["oqs"], False)
        self.assertIsNone(got["witness"], "the stub is no liboqs: absent, not a vote")
        if got["cryptography"]:
            self.assertEqual(got["auto"], ["cryptography", None])
        else:
            self.assertIsNone(got["auto"][0])
            self.assertIn("found no real ML-DSA backend", got["auto"][1])

    @unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
    def test_cryptography_alone_decides_beside_it(self):
        for provider in ("auto", "cryptography"):
            with self.subTest(provider=provider):
                verdicts = {}
                for name in ("ml-dsa-65-valid", "ml-dsa-65-tampered-signature"):
                    r = self.run_python(str(HERE / "polaris-verify.py"), "--pqc-provider", provider,
                                        "--signature-only",
                                        "--pack", str(ROOT / "vectors" / ("%s.json" % name)))
                    self.assertNotIn("liboqs=", r.stdout + r.stderr, "the stub must not vote")
                    verdicts[name] = (r.returncode, "cryptography=valid" in r.stdout + r.stderr)
                self.assertEqual(verdicts["ml-dsa-65-valid"], (0, True))
                self.assertEqual(verdicts["ml-dsa-65-tampered-signature"], (2, False))

    def test_naming_it_refuses_to_start(self):
        r = self.run_python(str(HERE / "polaris-verify.py"), "--pqc-provider", "oqs",
                            "--pack", str(self.vector))
        self.assertEqual(r.returncode, 4, r.stderr)
        self.assertIn("refusing to start: --pqc-provider oqs", r.stderr)


def _loadable_library():
    """A shared library this interpreter can load: a copy stands in for liboqs."""
    import importlib
    import importlib.machinery
    for name in ("_json", "_ctypes", "select", "_socket", "math", "_struct"):
        try:
            path = getattr(importlib.import_module(name), "__file__", None)
        except ImportError:
            continue
        if path and path.endswith(tuple(importlib.machinery.EXTENSION_SUFFIXES)):
            return path
    return None


class OqsIsImportedOnlyWhenItIsLiboqs(unittest.TestCase):
    """Nothing named `oqs` is imported unless it is liboqs-python with its library in place.

    Importing a module runs its code. The stubs keep liboqs-python's layout (the code in
    oqs/oqs.py, which __init__.py imports) and are installed under a distribution name:
    - named `oqs` (PyPI's unrelated project), with a `Signature` and an import that writes a
      marker file: never imported under `auto` or `oqs`, and the refusal names the repair;
    - named `liboqs-python`, with the liboqs library where liboqs-python looks: imported, and
      a backend (the control), whether the library is under lib, lib64 or where
      ctypes.util.find_library finds it (the library is a copy of one of this interpreter's
      own extension modules, which loads);
    - the same without its __init__.py (what `pip uninstall oqs` leaves): the same repair;
    - `liboqs-python` without the library, whose import runs `git clone` (a stub git on PATH
      records it) and raises SystemExit, as liboqs-python 0.16.0 does: not imported, nothing
      fetched, `auto` goes on to cryptography and `oqs` refuses naming the library;
    - the same with a library file that does not load (an empty one): the same as none;
    - `liboqs-python` whose import raises SystemExit with the library in place: no backend.
    A fresh interpreter each time, with ctypes.util.find_library answering only what the test
    names, so no library on the machine stands in for the one the test places or withholds."""

    CODE = ("import os\n"
            "open(os.environ['POLARIS_OQS_CANARY'], 'w').write('imported')\n"
            "class Signature:\n"
            "    pass\n")
    CLONE = ("import subprocess\n"
             "subprocess.call('git clone https://github.com/open-quantum-safe/liboqs --depth 1',\n"
             "                shell=True)\n"
             "raise SystemExit(1)\n")
    PROBE = (
        "import ctypes.util, importlib.util, json, os, sys\n"
        "ctypes.util.find_library = lambda name: os.environ.get('POLARIS_FIND_LIBRARY')\n"
        "spec = importlib.util.spec_from_file_location('v', sys.argv[1])\n"
        "V = importlib.util.module_from_spec(spec); spec.loader.exec_module(V)\n"
        "print(json.dumps({'oqs': V._provider_available('oqs'),\n"
        "    'mode': V.resolve_crypto_mode(sys.argv[2], False)}))\n")
    REPAIR = "`pip install --force-reinstall --no-deps liboqs-python`"
    LIBRARY = {"Darwin": "liboqs.dylib", "Windows": "oqs.dll"}.get(platform.system(), "liboqs.so")
    LOADABLE = _loadable_library()

    def setUp(self):
        if self.LOADABLE is None:
            self.skipTest("this interpreter has no extension module to stand in for liboqs")

    def site(self, distribution, code=CODE, init=True, library="loads", where="lib"):
        d = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oqs-dist-"))
        self.addCleanup(shutil.rmtree, d, True)
        if code is not None:
            (d / "oqs").mkdir()
            (d / "oqs" / "oqs.py").write_text(code)
            if init:
                (d / "oqs" / "__init__.py").write_text("from .oqs import *  # noqa: F401,F403\n")
            info = d / ("%s-0.0.0.dist-info" % distribution.replace("-", "_"))
            info.mkdir()
            (info / "METADATA").write_text(
                "Metadata-Version: 2.1\nName: %s\nVersion: 0.0.0\n" % distribution)
        lib = d / "_oqs" / ("bin" if platform.system() == "Windows" else where)
        lib.mkdir(parents=True)
        if library == "loads":
            shutil.copyfile(self.LOADABLE, lib / self.LIBRARY)
        elif library == "empty":
            (lib / self.LIBRARY).write_bytes(b"")
        (d / "stub-bin").mkdir()
        git = d / "stub-bin" / "git"
        git.write_text("#!/bin/sh\necho \"$@\" >> \"$POLARIS_GIT_MARKER\"\nexit 128\n")
        git.chmod(0o755)
        return d

    def probe(self, site, provider, isolated=True, find_library=None):
        """`isolated` (-S) keeps an installed liboqs-python from standing in for a stub."""
        env = dict(os.environ, PYTHONPATH=str(site), POLARIS_OQS_CANARY=str(site / "imported"),
                   POLARIS_GIT_MARKER=str(site / "git-called"), OQS_INSTALL_PATH=str(site / "_oqs"),
                   PATH=str(site / "stub-bin") + os.pathsep + os.environ.get("PATH", ""))
        env.pop("POLARIS_FIND_LIBRARY", None)
        if find_library:
            env["POLARIS_FIND_LIBRARY"] = find_library
        r = subprocess.run([sys.executable] + (["-S"] if isolated else []) +
                           ["-c", self.PROBE, str(HERE / "polaris-verify.py"), provider],
                           env=env, cwd=str(site), capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((site / "git-called").exists(), "git ran: %s" % r.stderr[-400:])
        return json.loads(r.stdout.strip().splitlines()[-1]), (site / "imported").exists()

    def test_a_distribution_named_oqs_is_never_imported(self):
        site = self.site("oqs")
        for provider in ("auto", "oqs"):
            with self.subTest(provider=provider):
                got, imported = self.probe(site, provider)
                self.assertIs(imported, False, "the package's code ran")
                self.assertIs(got["oqs"], False)
                self.assertIsNone(got["mode"][0])
                self.assertIn("a distribution named `oqs` is installed", got["mode"][1])
                self.assertIn(self.REPAIR, got["mode"][1])

    def test_liboqs_python_with_its_library_is_imported(self):
        got, imported = self.probe(self.site("liboqs-python"), "oqs")
        self.assertIs(imported, True, "positive control: liboqs-python's oqs must load")
        self.assertIs(got["oqs"], True)
        self.assertEqual(got["mode"], ["oqs", None])

    @unittest.skipIf(platform.system() == "Windows", "liboqs-python looks only in bin there")
    def test_the_library_under_lib64_is_found(self):
        got, imported = self.probe(self.site("liboqs-python", where="lib64"), "oqs")
        self.assertIs(imported, True)
        self.assertEqual(got["mode"], ["oqs", None])

    def test_the_library_ctypes_finds_on_the_system_path_is_found(self):
        site = self.site("liboqs-python", library=None)
        got, imported = self.probe(site, "oqs", find_library=self.LOADABLE)
        self.assertIs(imported, True)
        self.assertEqual(got["mode"], ["oqs", None])

    def test_what_uninstalling_oqs_leaves_gets_the_same_repair(self):
        got, _ = self.probe(self.site("liboqs-python", init=False), "oqs")
        self.assertIs(got["oqs"], False)
        self.assertIsNone(got["mode"][0])
        self.assertIn("it has no Signature", got["mode"][1])
        self.assertIn(self.REPAIR, got["mode"][1])

    def test_without_the_library_nothing_is_fetched_or_imported(self):
        site = self.site("liboqs-python", code=self.CLONE, library=None)
        got, _ = self.probe(site, "oqs")
        self.assertIs(got["oqs"], False)
        self.assertIsNone(got["mode"][0])
        self.assertIn("liboqs-python needs the liboqs shared library", got["mode"][1])
        self.assertIn(str(site / "_oqs"), got["mode"][1])
        got, _ = self.probe(site, "auto", isolated=False)
        if _cryptography_mldsa():
            self.assertEqual(got["mode"], ["cryptography", None])
        else:
            self.assertIn("liboqs-python needs the liboqs shared library", got["mode"][1])

    def test_a_library_file_that_does_not_load_counts_as_none(self):
        site = self.site("liboqs-python", code=self.CLONE, library="empty")
        got, _ = self.probe(site, "oqs")
        self.assertIs(got["oqs"], False)
        self.assertIsNone(got["mode"][0])
        self.assertIn("liboqs-python needs the liboqs shared library", got["mode"][1])

    def test_an_import_that_exits_is_no_backend(self):
        got, _ = self.probe(self.site("liboqs-python", code="raise SystemExit(1)\n"), "oqs")
        self.assertIs(got["oqs"], False)
        self.assertIsNone(got["mode"][0])
        self.assertIn("importing `oqs` exited (1)", got["mode"][1])

    NOT_LIBOQS = "raise AttributeError('undefined symbol: OQS_init')\n"

    def test_an_import_that_raises_is_no_backend(self):
        # A library that loads but is not liboqs: liboqs-python's import raises AttributeError.
        got, _ = self.probe(self.site("liboqs-python", code=self.NOT_LIBOQS), "oqs")
        self.assertIs(got["oqs"], False)
        self.assertIsNone(got["mode"][0])
        self.assertIn("importing `oqs` failed (AttributeError: undefined symbol: OQS_init)",
                      got["mode"][1])

    def test_with_no_oqs_module_the_refusal_names_the_library_once(self):
        got, _ = self.probe(self.site("liboqs-python", code=None, library=None), "auto")
        self.assertIsNone(got["mode"][0])
        self.assertIn("Install one (liboqs-python with the liboqs shared library", got["mode"][1])
        self.assertNotIn("liboqs-python needs", got["mode"][1])

    REPEAT = (
        "import ctypes.util, importlib.util, json, os, subprocess, sys\n"
        "ctypes.util.find_library = lambda name: os.environ.get('POLARIS_FIND_LIBRARY')\n"
        "spec = importlib.util.spec_from_file_location('v', sys.argv[1])\n"
        "V = importlib.util.module_from_spec(spec); spec.loader.exec_module(V)\n"
        "args = (b'd' * 32, b'\\x02' * 3309, b'\\x01' * 1952)\n"
        "first = V._verify_liboqs(*args)\n"
        "calls = []\n"
        "def counted(name, f):\n"
        "    def g(*a, **k):\n"
        "        calls.append(name)\n"
        "        return f(*a, **k)\n"
        "    return g\n"
        "V._liboqs_library = counted('_liboqs_library', V._liboqs_library)\n"
        "V._unrelated_oqs_installed = counted('_unrelated_oqs_installed', V._unrelated_oqs_installed)\n"
        "ctypes.util.find_library = counted('find_library', ctypes.util.find_library)\n"
        "subprocess.Popen.__init__ = counted('Popen', subprocess.Popen.__init__)\n"
        "later = [V._verify_liboqs(*args) for _ in range(3)] + [V._provider_available('oqs')]\n"
        "print(json.dumps({'first': first, 'later': later, 'calls': calls}))\n")

    def repeat(self, site):
        env = dict(os.environ, PYTHONPATH=str(site), POLARIS_OQS_CANARY=str(site / "imported"),
                   POLARIS_GIT_MARKER=str(site / "git-called"), OQS_INSTALL_PATH=str(site / "_oqs"),
                   PATH=str(site / "stub-bin") + os.pathsep + os.environ.get("PATH", ""))
        env.pop("POLARIS_FIND_LIBRARY", None)
        r = subprocess.run([sys.executable, "-S", "-c", self.REPEAT, str(HERE / "polaris-verify.py")],
                           env=env, cwd=str(site), capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((site / "git-called").exists(), "git ran: %s" % r.stderr[-400:])
        return json.loads(r.stdout.strip().splitlines()[-1])

    def test_liboqs_is_looked_for_once_per_process(self):
        # Finding the library runs ctypes.util.find_library, which on Linux starts ldconfig, then
        # gcc and then ld if the one before found nothing: a later signature, liboqs found, absent
        # or failing to import, looks nowhere and starts nothing.
        for label, site, first, later in (
                ("found", self.site("liboqs-python"), False, [False, False, False, True]),
                ("no library", self.site("liboqs-python", code=self.CLONE, library=None),
                 None, [None, None, None, False]),
                ("a library that is not liboqs", self.site("liboqs-python", code=self.NOT_LIBOQS),
                 None, [None, None, None, False])):
            with self.subTest(label):
                got = self.repeat(site)
                # The stub's Signature takes no algorithm: the witness ran and refused.
                self.assertIs(got["first"], first)
                self.assertEqual(got["later"], later)
                self.assertEqual(got["calls"], [])


class ExactSizeIsCheckedBeforeEitherWitness(unittest.TestCase):
    """2026-10-10: the detached verifier did not check an ML-DSA public key's or signature's
    length before verifying, so a missing or truncated key could come back as a valid signature
    from one witness. `_size_problem` now runs on every door BEFORE either witness, and each
    witness re-checks before its library sees the bytes, so a wrong length is a refusal and never
    a witness that "could not run". These tests use arbitrary bytes of the wrong length; they do
    not forge anything, because a wrong length is refused at the size check, upstream of any
    cryptography. A wrong-length key is a recognised conformance case
    (fido-alliance/conformance-test-tools-resources#817)."""

    PK_LEN, SIG_LEN = 1952, 3309   # ML-DSA-65, FIPS 204

    def test_the_accepted_sizes_match_liboqs_details(self):
        try:
            oqs = V._import_oqs()
        except Exception:  # noqa: BLE001
            self.skipTest("liboqs absent")
        enabled = set(oqs.get_enabled_sig_mechanisms())
        for alg, (_cls, pk_len, sig_len) in V._ACCEPTED.items():
            with self.subTest(alg=alg):
                if alg not in enabled:
                    self.skipTest("%s not enabled in this liboqs build" % alg)   # counted, never silent
                with oqs.Signature(alg) as s:
                    self.assertEqual((pk_len, sig_len),
                                     (s.details["length_public_key"], s.details["length_signature"]), alg)

    def test_size_problem_names_a_wrong_length_and_passes_the_exact_one(self):
        self.assertIsNone(V._size_problem("ML-DSA-65", b"\x01" * self.PK_LEN, b"\x02" * self.SIG_LEN))
        for pk_len in (0, 1, 32, self.PK_LEN - 1, self.PK_LEN + 1):
            self.assertIn("public key", V._size_problem("ML-DSA-65", b"\x01" * pk_len, b"\x02" * self.SIG_LEN))
        for sig_len in (0, 1, self.SIG_LEN - 1, self.SIG_LEN + 1):
            self.assertIn("signature", V._size_problem("ML-DSA-65", b"\x01" * self.PK_LEN, b"\x02" * sig_len))
        # empty input is a wrong length, not an abstention
        self.assertIn("public key", V._size_problem("ML-DSA-65", b"", b"\x02" * self.SIG_LEN))
        self.assertIn("signature", V._size_problem("ML-DSA-65", b"\x01" * self.PK_LEN, b""))

    def test_each_witness_returns_False_not_None_on_a_wrong_length(self):
        # Never None (which would let the other witness decide alone): a size mismatch is refused.
        for pk_len in (0, 1, 32, self.PK_LEN - 1):
            self.assertIs(V._verify_liboqs(b"d" * 32, b"\x02" * self.SIG_LEN, b"\x01" * pk_len), False, pk_len)
            self.assertIs(V._verify_cryptography(b"d" * 32, b"\x02" * self.SIG_LEN, b"\x01" * pk_len), False, pk_len)
        for sig_len in (0, 1, self.SIG_LEN - 1, self.SIG_LEN + 1):
            self.assertIs(V._verify_liboqs(b"d" * 32, b"\x02" * sig_len, b"\x01" * self.PK_LEN), False, sig_len)
            self.assertIs(V._verify_cryptography(b"d" * 32, b"\x02" * sig_len, b"\x01" * self.PK_LEN), False, sig_len)

    def test_the_shared_combiner_refuses_a_wrong_length_with_its_reason(self):
        ok, ran, note = V._two_witness_verify(b"d" * 32, b"\x02" * self.SIG_LEN, b"\x01" * 32)
        self.assertIs(ok, False)
        self.assertEqual(ran, [])
        self.assertIn("public key", note)

    def test_a_lone_witness_that_would_accept_cannot_resurrect_a_wrong_length(self):
        # The size check is upstream of the fallback: even if the only installed witness were
        # patched to accept, a wrong length never reaches it. Both witnesses stubbed to a verdict.
        saved = (V._verify_liboqs, V._verify_cryptography)
        try:
            V._verify_liboqs = lambda *a, **k: None          # "not installed"
            V._verify_cryptography = lambda *a, **k: True     # the lone witness says yes
            ok, ran, note = V._two_witness_verify(b"d" * 32, b"\x02" * self.SIG_LEN, b"\x01" * 32)
            self.assertIs(ok, False, "a wrong-length key must not reach the lone witness")
            self.assertIn("public key", note)
        finally:
            V._verify_liboqs, V._verify_cryptography = saved

    def test_pack_refuses_a_wrong_length_key_and_a_real_pack_still_verifies(self):
        tok = "TKN-SIZE-0001"

        def pack(sig_hex, pk_hex):
            return {"format": "polaris-authenticity-pack/1", "token_value": tok,
                    "algorithm": "ML-DSA-65", "signature_hex": sig_hex, "public_key_hex": pk_hex}
        # An empty key is caught by the earlier missing-field guard (also a refusal); a non-empty
        # wrong length is refused at the size check, with its reason and no witness run.
        v0 = V.verify_pack(pack((b"\x02" * self.SIG_LEN).hex(), ""))
        self.assertIs(v0["signature_valid"], False)
        self.assertNotEqual(v0["authenticity"], "genuine")
        for pk_len in (1, 32, self.PK_LEN - 1, self.PK_LEN + 1):
            v = V.verify_pack(pack((b"\x02" * self.SIG_LEN).hex(), (b"\x01" * pk_len).hex()))
            self.assertIs(v["signature_valid"], False, pk_len)
            self.assertNotEqual(v["authenticity"], "genuine")
            self.assertIn("public key", v["note"] or "")
            self.assertEqual(v["witnesses"], [], "no witness ran on a wrong length")
        for sig_len in (1, self.SIG_LEN - 1, self.SIG_LEN + 1):   # wrong signature length
            v = V.verify_pack(pack((b"\x02" * sig_len).hex(), (b"\x01" * self.PK_LEN).hex()))
            self.assertIs(v["signature_valid"], False, sig_len)
            self.assertIn("signature", v["note"] or "")
        # positive control: a real key and a real signature still verify
        try:
            oqs = V._import_oqs()
        except Exception:  # noqa: BLE001
            self.skipTest("liboqs absent for the positive control")
        with oqs.Signature("ML-DSA-65") as s:
            pk = bytes(s.generate_keypair())
            sig = bytes(s.sign(V._digest(tok)))
        good = V.verify_pack(pack(sig.hex(), pk.hex()))
        self.assertIs(good["signature_valid"], True, good["note"])
        self.assertGreaterEqual(len(good["witnesses"]), 1)


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
    if n < 65536:
        return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    if n < 2 ** 32:
        return bytes([major << 5 | 26]) + n.to_bytes(4, "big")
    return bytes([major << 5 | 27]) + n.to_bytes(8, "big")


def _cbor(x):
    """The smallest encoder these fixtures need: ints, bytes, text, lists, maps, tag 24, and
    ("raw", bytes) spliced in as given, for an encoding the encoder does not write."""
    if isinstance(x, tuple) and x[0] == "tag24":
        return b"\xd8\x18" + _cbor(x[1])
    if isinstance(x, tuple) and x[0] == "raw":
        return bytes(x[1])
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
                           ("a map that repeats a key", _hdr(5, 2) + _cbor(1) + _cbor(-7) + _cbor(1) + _cbor(-49)),
                           ("1 and true, keys this decoder reads as one", _hdr(5, 2) + _cbor(1) + _cbor(0) + _cbor(True) + _cbor(0)),
                           ("trailing bytes", _cbor(1) + _cbor(2))):
            with self.subTest(label), self.assertRaises(ValueError):
                V._cbor_decode(buf)

    def test_only_tag_24_and_four_simple_values_decode(self):
        # The decoder's docstring names the subset and promises a ValueError for anything else.
        # Until 2026-10-28 major type 7 handed any other value back as its raw integer (a
        # float16 1.0 came back as 15360) and major type 6 handed back any tag at all.
        for buf, want in ((b"\xf4", False), (b"\xf5", True), (b"\xf6", None), (b"\xf7", None)):
            self.assertIs(V._cbor_decode(buf), want, buf.hex())
        # A tag-24 item also carries its own bytes as they sat in the input: an element's
        # digest is over those, never over a re-encoding of them.
        self.assertEqual(V._cbor_decode(_cbor(("tag24", b"ab"))), ("tag", 24, b"ab", b"\xd8\x18\x42ab"))
        for label, buf in (("float16 1.0", b"\xf9\x3c\x00"),
                           ("float32 1.0", b"\xfa\x3f\x80\x00\x00"),
                           ("float64 1.0", b"\xfb\x3f\xf0" + bytes(6)),
                           ("simple value 32", b"\xf8\x20"),
                           ("simple value 0", b"\xe0"),
                           ("simple value 19", b"\xf3"),
                           ("tag 0, a date-time string", b"\xc0" + _cbor("2026-01-01T00:00:00Z")),
                           ("tag 1, epoch seconds", b"\xc1\x1a" + (1767225600).to_bytes(4, "big")),
                           ("tag 18, a COSE_Sign1", b"\xd2" + _cbor([b"", {}, b"", b""])),
                           ("tag 1004, a full-date", b"\xd9\x03\xec" + _cbor("2000-01-01")),
                           ("tag 24 over a map", b"\xd8\x18" + _cbor({1: 2})),
                           ("tag 24 over an array", b"\xd8\x18" + _cbor([1, 2])),
                           ("tag 24 over an integer", b"\xd8\x18" + _cbor(5)),
                           ("tag 24 over a text string", b"\xd8\x18" + _cbor("ab"))):
            with self.subTest(label), self.assertRaises(ValueError):
                V._cbor_decode(buf)
        # Every tag above wraps something other than a byte string, which the tag-24 guard
        # refuses too. Over a byte string, only the refusal that names the subset is left.
        with self.subTest("tag 2, an unsigned bignum"), \
                self.assertRaisesRegex(ValueError, "outside the mdoc subset"):
            V._cbor_decode(b"\xc2\x41\x01")


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

    def test_tag_24_over_anything_but_bytes_is_a_refusal(self):
        # 2026-10-28. An MSO payload of tag 24 over the map {1: 2} raised KeyError out of
        # verify_mdoc (the MSO path read the map as if it were bytes); a list of small integers
        # under tag 24 was read as bytes outright. Each is a verdict now, for the MSO and for an
        # element alike.
        for label, inner in (("a map", {1: 2}), ("an array", [1, 2]), ("an integer", 5), ("a text string", "ab")):
            wrapped = b"\xd8\x18" + _cbor(inner)
            with self.subTest("the MSO, " + label):
                v = V.verify_mdoc(self.document(wrapped, []))
                self.assertIs(v["issuer_authentic"], False)
                self.assertIn("must wrap a byte string", v["note"] or "")
            with self.subTest("an element, " + label):
                v = V.verify_mdoc(self.document(self.mso(), [("raw", wrapped)]))
                self.assertIs(v["issuer_authentic"], False)
                self.assertIsNot(v["digests_match"], True)
                self.assertIn("must wrap a byte string", json.dumps(v))


class MdocFieldsOfAnotherType(unittest.TestCase):
    """verify_mdoc is total on hostile input: a field the sender writes, given a CBOR type it
    does not expect, is a verdict. No key is needed for any of them, so a hand-built document
    reaches each with no crypto library at all."""

    def document(self, name_spaces=None, value_digests=None, digest_algorithm="SHA-256",
                 unprotected=None, signature=b"sig"):
        mso = {"docType": V._MDOC_DOC_TYPE, "digestAlgorithm": digest_algorithm,
               "valueDigests": {V._MDOC_NAMESPACE: {}} if value_digests is None else value_digests}
        return _cbor({"docType": V._MDOC_DOC_TYPE,
                      "issuerSigned": {"nameSpaces": {V._MDOC_NAMESPACE: []} if name_spaces is None else name_spaces,
                                       "issuerAuth": [_cbor({1: -49}), unprotected or {}, _cbor(("tag24", _cbor(mso))), signature]}})

    def test_the_hand_built_document_reaches_the_signature(self):
        v = V.verify_mdoc(self.document())
        self.assertIs(v["digests_match"], True)
        self.assertIn("unaccepted signature algorithm", v["note"] or "")

    def test_a_namespace_or_digest_map_of_another_type_is_a_verdict(self):
        # 2026-10-28. Each raised AttributeError out of verify_mdoc: the map's .get ran on a list,
        # an integer or a text string.
        for label, value in (("a list", [1]), ("an integer", 5), ("a text string", "x")):
            for field, doc in (("nameSpaces", self.document(name_spaces=value)),
                               ("valueDigests", self.document(value_digests=value))):
                with self.subTest(field + ", " + label):
                    v = V.verify_mdoc(doc)
                    self.assertIs(v["issuer_authentic"], False)
                    self.assertIsNot(v["digests_match"], True)
                    self.assertIn("digests are missing or malformed", v["note"] or "")

    def test_a_signature_that_is_not_a_byte_string_is_a_verdict(self):
        # 2026-10-28. bytes() read an integer signature as a length: 2**64 - 1 raised
        # OverflowError, and a smaller one is allocated as that many zero bytes before any check.
        for label, value in (("an integer past the index range", 2 ** 64 - 1), ("a small integer", 5),
                             ("a list of small integers", [1, 2]), ("a text string", "ab")):
            with self.subTest(label):
                v = V.verify_mdoc(self.document(signature=value))
                self.assertIs(v["issuer_authentic"], False)
                self.assertIn("signature is not a byte string", v["note"] or "")

    def test_a_tag_24_algorithm_name_is_a_verdict(self):
        # 2026-10-28. The decoder returns tag 24 as a tuple, and the note's bare % read it as its
        # arguments: TypeError, for the MSO's digestAlgorithm and the unprotected polaris_algorithm.
        tagged = ("tag24", b"\x01")
        for label, doc, why in (("digestAlgorithm", self.document(digest_algorithm=tagged), "unsupported MSO digest algorithm"),
                                ("polaris_algorithm", self.document(unprotected={"polaris_algorithm": tagged}),
                                 "unaccepted signature algorithm")):
            with self.subTest(label):
                v = V.verify_mdoc(doc)
                self.assertIs(v["issuer_authentic"], False)
                self.assertIn(why, v["note"] or "")



# --------------------------------------------------------------------------- genuine VC and mdoc

def _mldsa_signer():
    """A fresh ML-DSA-65 key through the cryptography witness: (sign, public key bytes)."""
    from cryptography.hazmat.primitives.asymmetric import mldsa
    sk = mldsa.MLDSA65PrivateKey.generate()
    return sk.sign, sk.public_key().public_bytes_raw()


@unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
class IdTokenAudienceAndNonceAreCompared(unittest.TestCase):
    """A signed `aud` or `nonce` matches only a value of its own kind, as the TypeScript SDK's
    `===` decides it. Until 2026-10-15 `==` let a token signed with "aud": true match audience
    1, and nonce 1.0 match 1, in Python only."""

    @classmethod
    def setUpClass(cls):
        cls.signer = _mldsa_signer()

    def token(self, **over):
        body = {"format": V._ID_TOKEN_FORMAT, "iss": "https://issuer.example", "sub": "ab" * 32,
                "aud": "rp-1", "nonce": "n-1", "context_id": 1, "disclosure_level": 1,
                "acr": "urn:polaris:acr:1", "enrollment": None, "auth_time": "2026-05-01T00:00:00Z",
                "iat": "2026-05-01T00:00:00Z", "exp": "2026-05-01T01:00:00Z"}
        body.update(over)
        return SignedDocumentLongTermValidation.seal(body, V._id_token_canonical, self.signer)

    def decide(self, tok, audience, nonce):
        return V.verify_id_token(tok, audience=audience, nonce=nonce, now="2026-05-01T00:00:30Z")

    def test_the_same_text_matches(self):
        v = self.decide(self.token(), "rp-1", "n-1")
        self.assertIs(v["token_authentic"], True, v["note"])
        self.assertEqual((v["audience_matches"], v["nonce_matches"]), (True, True))
        v = self.decide(self.token(aud=7, nonce=9), 7, 9)
        self.assertEqual((v["audience_matches"], v["nonce_matches"]), (True, True))

    def test_another_kind_of_value_matches_nothing(self):
        for label, signed, expected in (("true against 1", True, 1), ("1.0 against 1", 1.0, 1),
                                        ("\"1\" against 1", "1", 1), ("null against null", None, None)):
            with self.subTest(label):
                v = self.decide(self.token(aud=signed, nonce=signed), expected, expected)
                self.assertIs(v["token_authentic"], True, v["note"])
                if expected is not None:
                    self.assertIs(v["audience_matches"], False)
                    self.assertIs(v["nonce_matches"], False)
                else:
                    self.assertEqual((v["audience_matches"], v["nonce_matches"]), (None, None))


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

    def credential(self, proof_changes=None, twice=False, **changes):
        doc = {"@context": ["https://www.w3.org/ns/credentials/v2"],
               "type": ["VerifiableCredential", V._VC_TYPE], "issuer": "did:example:authority",
               "validFrom": "2026-01-01T00:00:00Z", "validUntil": "2027-01-01T00:00:00Z",
               "credentialSubject": {"verification": "authentic", "status": "ACTIVE"}}
        doc.update(changes)
        proof = {"type": "DataIntegrityProof", "cryptosuite": V._VC_CRYPTOSUITE,
                 "polarisAlgorithm": "ML-DSA-65", "polarisPublicKeyHex": self.pk.hex()}
        signed = hashlib.sha3_256(V._vc_canonical(doc)).digest()
        if twice:   # the form /api/v1/verifiable-credential signed until 2026-10-14
            signed = hashlib.sha3_256(signed).digest()
        proof["proofValue"] = self.sign(signed).hex()
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

    def test_a_proof_over_the_canonical_bytes_hashed_twice_is_refused(self):
        # 2026-10-14. The route hashed the canonical bytes before signature_over_message hashed
        # them again, so it signed SHA3-256 twice. The proof is ML-DSA over ONE SHA3-256 of the
        # canonical bytes (the digest step of WIRE-SPEC 2.1's signed statements), and the old
        # form gets no second meaning: refused, under the very key that made it.
        anchor = [self.pk.hex()]
        self.assertIs(V.verify_verifiable_credential(self.credential(), anchor_keys=anchor,
                                                     now=self.NOW)["proof_authentic"], True, "control")
        v = V.verify_verifiable_credential(self.credential(twice=True), anchor_keys=anchor, now=self.NOW)
        self.assertIs(v["structure_valid"], True, "the structure is fine; the refusal is the proof's")
        self.assertIs(v["proof_authentic"], False)
        self.assertIsNot(v["issuer_trusted"], True)
        self.assertIn("the credential proof is invalid", v["note"] or "")

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
    COSE_Sign1 under COSE -49: pure ML-DSA-65 over the Sig_structure itself (RFC 9964)."""

    NOW = "2026-06-01T00:00:00Z"

    @classmethod
    def setUpClass(cls):
        cls.sign, cls.pk = _mldsa_signer()
        cls.other_sign, cls.other_pk = _mldsa_signer()

    def document(self, elements=None, mso_changes=None, unprotected=None, after=None,
                 protected=None, prehash=False, repeat=None):
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
        if not isinstance(protected, bytes):
            protected = _cbor(protected if protected is not None else {1: -49})
        payload = _cbor(("tag24", _cbor(mso)))
        # The Sig_structure itself is what is signed. `prehash` signs its SHA3-256 instead, the
        # form this verifier checked until 2026-10-14 and no RFC 9964 verifier accepts.
        to_be_signed = V._cbor_sig_structure(protected, payload)
        signature = self.sign(hashlib.sha3_256(to_be_signed).digest() if prehash else to_be_signed)
        header = {"polaris_public_key_hex": self.pk.hex(), "polaris_algorithm": "ML-DSA-65"}
        header.update(unprotected or {})
        if after:
            after(items)
        issuer_signed = {"nameSpaces": {V._MDOC_NAMESPACE: items},
                         "issuerAuth": [protected, header, payload, signature]}
        if repeat:  # (key, value): that key once more, ahead of the genuine entries
            body = _cbor(repeat[0]) + _cbor(repeat[1]) + b"".join(_cbor(k) + _cbor(v) for k, v in issuer_signed.items())
            issuer_signed = ("raw", _hdr(5, len(issuer_signed) + 1) + body)
        return _cbor({"docType": V._MDOC_DOC_TYPE, "issuerSigned": issuer_signed})

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

    def test_a_signature_over_the_digest_of_the_sig_structure_is_refused(self):
        # 2026-10-14. COSE -49 is pure ML-DSA-65 over the Sig_structure itself (RFC 9964). This
        # verifier checked a signature over its SHA3-256, which no RFC 9964 verifier accepts. It
        # now checks the structure itself and only that: the old form gets no second meaning.
        v = V.verify_mdoc(self.document(prehash=True), anchor_keys=[self.pk.hex()], now=self.NOW)
        self.assertIs(v["digests_match"], True, "the digests are fine; the refusal is the signature's")
        self.assertIs(v["issuer_authentic"], False)
        self.assertIsNot(v["issuer_trusted"], True)
        self.assertIn("MSO signature is invalid", v["note"] or "")

    def test_the_protected_header_decides_the_algorithm(self):
        # The signature covers the protected header, so its alg is the one checked, and the
        # unprotected polaris_algorithm, which nobody signed, must be that set. Each document is
        # genuinely signed over its own Sig_structure: what is refused is the label.
        for protected, unprotected, why in (
                ({1: -50}, None, "names COSE algorithm -50 and ML-DSA-65 is -49"),
                ({1: -7}, None, "names COSE algorithm -7"),
                ({4: b"kid"}, None, "names COSE algorithm None"),
                (b"\xff", None, "protected header does not decode"),
                ({1: -49}, {"polaris_algorithm": "ML-DSA-87"}, "names COSE algorithm -49 and ML-DSA-87 is -50"),
                ({1: -49}, {"polaris_algorithm": "Falcon-padded-1024"}, "is no COSE algorithm")):
            v = V.verify_mdoc(self.document(protected=protected, unprotected=unprotected), now=self.NOW)
            self.assertIs(v["digests_match"], True, why)
            self.assertIs(v["issuer_authentic"], False, why)
            self.assertIn(why, v["note"] or "", why)
        # More than alg in the protected header (a kid, as RFC 9964's own example carries) is fine.
        v = V.verify_mdoc(self.document(protected={1: -49, 4: b"kid"}), now=self.NOW)
        self.assertIs(v["issuer_authentic"], True, v["note"])

    def test_a_map_that_repeats_a_key_is_refused(self):
        # 2026-10-28. RFC 9052 s3: header labels MUST be unique, and a repeated one MUST be
        # rejected. The decoder kept the last value of a repeated key, so each document below,
        # genuinely signed, verified: alg -7 then -49 in the protected header was read as -49,
        # and an issuerAuth nobody signed ahead of the genuine one was read as the genuine one.
        decoy = [_cbor({1: -49}), {}, _cbor(("tag24", _cbor({}))), b"\x00" * 16]
        for doc, why in ((self.document(protected=_hdr(5, 2) + _cbor(1) + _cbor(-7) + _cbor(1) + _cbor(-49)),
                          "protected header does not decode"),
                         (self.document(repeat=("issuerAuth", decoy)), "not decodable CBOR")):
            with self.subTest(why):
                v = V.verify_mdoc(doc, anchor_keys=[self.pk.hex()], now=self.NOW)
                self.assertIs(v["issuer_authentic"], False)
                self.assertIsNot(v["issuer_trusted"], True)
                self.assertIn(why, v["note"] or "")
                self.assertIn("repeats the key", v["note"] or "")

    def test_an_element_value_outside_the_subset_is_refused(self):
        # 2026-10-28. A genuinely signed document whose element value was a float16 1.0
        # verified, with the value reported as 15360; a tagged value came back as a tuple. Each
        # is now an element that does not decode, and no value is reported for it.
        for raw, why in ((b"\xf9\x3c\x00", "float16 1.0"),
                         (b"\xfa\x3f\x80\x00\x00", "float32 1.0"),
                         (b"\xc0" + _cbor("2026-01-01T00:00:00Z"), "tag 0")):
            with self.subTest(why):
                doc = self.document(elements={"status": "ACTIVE", "credential_status": ("raw", raw)})
                v = V.verify_mdoc(doc, anchor_keys=[self.pk.hex()], now=self.NOW)
                self.assertIs(v["digests_match"], False)
                self.assertIs(v["issuer_authentic"], False)
                self.assertIsNone(v["elements"])
                self.assertIn("an element does not decode", v["note"] or "")

    def test_an_item_reframed_after_signing_is_refused(self):
        # 2026-10-28. An element's digest is over the IssuerSignedItemBytes as received. It was
        # recomputed over a minimal re-encoding of them, so the same item under a longer header,
        # which anyone holding the document can write without a key, still matched: one signed
        # credential, many accepted byte strings, and a reader that hashes the bytes it received
        # refuses what this one accepted.
        def reframe(head):
            def after(items):
                inner = items[0][1]
                items[0] = ("raw", head(len(inner)) + inner)
            return after
        for head, why in ((lambda n: b"\xd8\x18\x59" + n.to_bytes(2, "big"), "a two-byte length"),
                          (lambda n: b"\xd8\x18\x5a" + n.to_bytes(4, "big"), "a four-byte length"),
                          (lambda n: b"\xd9\x00\x18\x58" + bytes([n]), "a two-byte tag number"),
                          (lambda n: b"\xd9\x00\x18\x59" + n.to_bytes(2, "big"), "both")):
            with self.subTest(why):
                v = V.verify_mdoc(self.document(after=reframe(head)), anchor_keys=[self.pk.hex()], now=self.NOW)
                self.assertIs(v["digests_match"], False)
                self.assertIs(v["issuer_authentic"], False)
                self.assertIn("digest does not match", v["note"] or "")
        # The same item rebuilt by hand in the framing it was signed in still verifies: what is
        # refused is the re-framing, not the splice.
        v = V.verify_mdoc(self.document(after=reframe(lambda n: b"\xd8\x18\x58" + bytes([n]))),
                          anchor_keys=[self.pk.hex()], now=self.NOW)
        self.assertIs(v["issuer_authentic"], True, v["note"])

    def test_disagreeing_witnesses_are_a_refusal(self):
        # The two-witness DISAGREE guard had no test on this path: without it every mdoc test
        # stayed green. Either direction is a refusal, and the note says which.
        doc = self.document()
        saved = (V._verify_liboqs, V._verify_cryptography)
        try:
            for lib, crypto in ((True, False), (False, True)):
                V._verify_liboqs = lambda *a, _r=lib, **k: _r
                V._verify_cryptography = lambda *a, _r=crypto, **k: _r
                with self.subTest(liboqs=lib, cryptography=crypto):
                    v = V.verify_mdoc(doc, anchor_keys=[self.pk.hex()], now=self.NOW)
                    self.assertIs(v["digests_match"], True)
                    self.assertIs(v["issuer_authentic"], False)
                    self.assertIsNot(v["issuer_trusted"], True)
                    self.assertIn("DISAGREE", v["note"] or "")
        finally:
            V._verify_liboqs, V._verify_cryptography = saved

    def test_an_unreadable_window_is_not_fresh(self):
        v = V.verify_mdoc(self.document(mso_changes={"validityInfo": {}}), now=self.NOW)
        self.assertIs(v["fresh"], False)
        self.assertIs(v["issuer_authentic"], True, "the window is refused, the signature is still judged")
        self.assertIn("validity window is not readable", v["note"] or "")

    def test_a_wrong_length_issuer_key_is_refused_at_the_size_check(self):
        # 2026-10-10: a keyless (or short-key) document reported issuer_authentic True, because the
        # key's length was never checked. The digests are fine; the refusal is the key's length,
        # before either witness runs. Arbitrary bytes of the wrong length, not a forgery.
        for pk_len, why in ((0, "public key"), (1, "public key"), (32, "public key"), (1951, "public key")):
            doc = self.document(unprotected={"polaris_public_key_hex": (b"\x01" * pk_len).hex()})
            v = V.verify_mdoc(doc, now=self.NOW)
            self.assertIs(v["digests_match"], True, "the digests are fine; the refusal is the key's length")
            self.assertIs(v["issuer_authentic"], False, pk_len)
            self.assertIn(why, v["note"] or "", pk_len)


_RFC9964_COSE = ROOT / "vectors" / "kat" / "rfc9964_mldsa_65_cose.json"


@unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
class CoseRfc9964KnownAnswer(unittest.TestCase):
    """RFC 9964, Appendix A.2, Figure 7: the IETF's own ML-DSA-65 COSE_Sign1 (provenance in the
    vector file). COSE -49 is pure ML-DSA-65 over the Sig_structure itself; the verifier's COSE
    decision, the one verify_mdoc makes, must accept the RFC's signature and refuse it one bit
    away. Read with the verifier's own CBOR decoder, which is how it reads an mdoc."""

    @classmethod
    def setUpClass(cls):
        cls.vector = json.loads(_RFC9964_COSE.read_text(encoding="utf-8"))
        sign1 = bytes.fromhex(cls.vector["sign1"])
        # Figure 7's sign1 is COSE_Sign1_Tagged: tag 18, the one byte 0xd2. The verifier's decoder
        # reads tag 24 only (verify_mdoc takes issuerAuth's COSE_Sign1 untagged), so the tag byte
        # is checked here and the quadruple after it is decoded on its own.
        assert sign1[0] == 0xD2, "Figure 7's sign1 is a tagged COSE_Sign1"
        cls.protected, cls.unprotected, cls.payload, cls.signature = V._cbor_decode(sign1[1:])
        cls.pk = bytes.fromhex(cls.vector["raw_public_key"])

    def test_the_sig_structure_is_the_rfcs_to_be_signed(self):
        self.assertIn("RFC 9964", self.vector["provenance"]["source"])
        self.assertEqual(V._cbor_decode(self.protected)[1], -49)
        self.assertEqual(V._cbor_sig_structure(self.protected, self.payload),
                         bytes.fromhex(self.vector["raw_to_be_signed"]))
        self.assertEqual(self.signature, bytes.fromhex(self.vector["raw_signature"]))

    def test_the_rfc_signature_verifies_and_one_bit_away_does_not(self):
        ok, ran, note = V._cose_sign1_verdict(self.protected, self.payload, self.signature, self.pk, "ML-DSA-65")
        self.assertIs(ok, True, note)
        self.assertIn("cryptography=valid", ran)
        bad = bytearray(self.signature)
        bad[1000] ^= 1
        self.assertIs(V._cose_sign1_verdict(self.protected, self.payload, bytes(bad), self.pk, "ML-DSA-65")[0], False)
        altered = bytearray(self.payload)
        altered[0] ^= 1
        self.assertIs(V._cose_sign1_verdict(self.protected, bytes(altered), self.signature, self.pk, "ML-DSA-65")[0], False)
        # Told it is another set's, it is not checked at all: the protected header says -49.
        self.assertIs(V._cose_sign1_verdict(self.protected, self.payload, self.signature, self.pk, "ML-DSA-87")[0], False)


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
        cls.log, cls.witness, cls.stranger = (_mldsa_signer() for _ in range(3))
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
        kw.setdefault("trusted_anchors", [self.signer[1].hex()])
        return V.verify_signed_document(container, now=self.NOW, **kw)

    def anchored(self, doc, head_key, witnessed=True):
        """A container whose timestamp (the stamper's) carries an anchor: its inclusion proof in a
        timestamp log whose head `head_key` signed, cosigned by the witness when `witnessed`."""
        ts = self.timestamp(doc)
        h = V.timestamp_hash(ts)
        entries = [hashlib.sha3_256(b"other-%d" % i).hexdigest() for i in range(5)] + [h]
        idx = len(entries) - 1
        sth = self.seal({"format": "polaris-transparency-sth/1", "log_id": V._TIMESTAMP_LOG_ID,
                         "tree_size": len(entries), "root_hash_hex": V.merkle_tree_head(entries).hex(),
                         "timestamp": self.STAMPED}, V._sth_canonical, head_key)
        cosignatures = [self.seal({"format": "polaris-transparency-cosignature/1", "log_id": sth["log_id"],
                                   "tree_size": sth["tree_size"], "root_hash_hex": sth["root_hash_hex"]},
                                  V._cosignature_canonical, self.witness)] if witnessed else []
        ts["anchor"] = {"log_id": V._TIMESTAMP_LOG_ID, "timestamp_hash": h,
                        "proof": {"log_id": V._TIMESTAMP_LOG_ID, "index": idx, "tree_size": len(entries),
                                  "entry_hex": h, "proof_hex": [p.hex() for p in V.inclusion_proof(idx, entries)],
                                  "root_hash_hex": sth["root_hash_hex"]},
                        "sth": sth, "cosignatures": cosignatures}
        return self.container(doc, timestamp=ts)

    #: The clause an anchored policy adds to the note when the relying party named no log key.
    NO_LOG_KEY = "no anchored timestamp under an anchored policy (no timestamp log key was named)"

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

    def test_an_anchor_counts_under_the_log_key_the_relying_party_names(self):
        """The product signs a timestamp with the agency key and the timestamp log's head with the
        instance key."""
        doc = self.document()
        log_key, witnesses = self.log[1].hex(), [self.witness[1].hex()]
        genuine = self.anchored(doc, self.log)
        v = self.decide(genuine, require_anchored=True, trusted_witnesses=witnesses, timestamp_log_key=log_key)
        self.assertIs(v["valid_long_term"], True, v["note"])
        self.assertEqual((v["ltv"]["timestamp_anchored"], v["ltv"]["timestamp_witnessed"]), (True, True))
        unwitnessed = self.decide(self.anchored(doc, self.log, witnessed=False), require_anchored=True,
                                  timestamp_log_key=log_key)
        self.assertIs(unwitnessed["valid_long_term"], True, unwitnessed["note"])
        without = self.decide(genuine, require_anchored=True, trusted_witnesses=witnesses)
        self.assertIs(without["valid_long_term"], False)
        self.assertIn(self.NO_LOG_KEY, without["note"])

    def test_the_timestamp_authority_s_key_is_no_default_log_key(self):
        """A head signed by the timestamp authority's own key anchors nothing until the relying
        party names that key as the log key."""
        doc = self.document()
        own = self.anchored(doc, self.stamper)
        witnesses = [self.witness[1].hex()]
        v = self.decide(own, require_anchored=True, trusted_witnesses=witnesses)
        self.assertIs(v["valid_long_term"], False)
        self.assertIs(v["ltv"]["timestamp_anchored"], False)
        self.assertIn(self.NO_LOG_KEY, v["note"])
        named = self.decide(own, require_anchored=True, trusted_witnesses=witnesses,
                            timestamp_log_key=self.stamper[1].hex())
        self.assertIs(named["valid_long_term"], True, named["note"])

    def test_a_stranger_s_head_anchors_nothing_under_the_named_log_key(self):
        doc = self.document()
        for witnessed in (False, True):
            with self.subTest(witnessed=witnessed):
                v = self.decide(self.anchored(doc, self.stranger, witnessed=witnessed), require_anchored=True,
                                trusted_witnesses=[self.witness[1].hex()], timestamp_log_key=self.log[1].hex())
                self.assertIs(v["valid_long_term"], False)
                self.assertIs(v["ltv"]["timestamp_anchored"], False)
                self.assertIn("no anchored timestamp under an anchored policy", v["note"])
                self.assertNotIn("no timestamp log key was named", v["note"])

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

    def test_with_anchors_an_untrusted_signer_is_not_valid_long_term(self):
        """The container's manifest is the signer's own, so it says only that the key was active
        in the signer's view. Before 2026-10-15 a stranger's key, its own manifest and a trusted
        authority's timestamp were valid_long_term with signer_trusted False beside it."""
        stranger = self.decide(self.container(), trusted_anchors=[self.second[1].hex()])
        self.assertIs(stranger["signer_trusted"], False)
        self.assertIs(stranger["ltv"]["signer_key_active_at_instant"], True,
                      "the signer's own manifest still lists its key: only trust is missing")
        self.assertIs(stranger["valid_long_term"], False)
        self.assertIn("signer not trusted", stranger["note"])
        # A trust list whose publisher is not an anchor does not vouch for the signer either.
        unvouched = self.decide(self.container(), trust_list=self.trust_list(),
                                trusted_anchors=[self.second[1].hex()])
        self.assertEqual(unvouched["ltv"]["signer_key_status_per_trust_list"], "active")
        self.assertIs(unvouched["valid_long_term"], False)
        self.assertIn("signer not trusted", unvouched["note"])
        # The controls: the signer among the anchors, or listed by an anchor's trust list.
        anchored = self.decide(self.container(), trusted_anchors=[self.signer[1].hex()])
        self.assertIs(anchored["valid_long_term"], True, anchored["note"])
        listed = self.decide(self.container(), trust_list=self.trust_list(),
                             trusted_anchors=[self.publisher[1].hex()])
        self.assertIs(listed["valid_long_term"], True, listed["note"])

    def test_with_no_signer_anchors_nothing_is_valid_long_term(self):
        """2026-10-21: with no signer anchors the signer's trust held by default, so a document any
        key signed, which a trusted authority timestamped, was valid long-term."""
        v = self.decide(self.container(), trusted_anchors=None)
        self.assertIsNone(v["signer_trusted"])
        self.assertIs(v["valid_long_term"], False)
        self.assertEqual(v["note"], "long-term validation failed: no signer anchors were given, so signer "
                                    "trust was not evaluated")
        self.assertIs(self.decide(self.container())["valid_long_term"], True, "control: the signer as the anchor")
        self.assertIs(self.decide(self.container(), trusted_anchors=None, timestamp_anchors=None)["valid_long_term"],
                      False, "no timestamp anchors either")
        good = self.container()
        sig = good["signature_hex"]
        flipped = dict(good, signature_hex=("00" if sig[:2] != "00" else "01") + sig[2:])
        self.assertIs(self.decide(flipped, trusted_anchors=None)["valid_long_term"], False, "a flipped signature")

    def test_an_untrusted_signer_s_note_names_its_reason_alone(self):
        """The note joins its reasons once. It read "failed: , signer not trusted" when only the
        trust gates failed, each clause carrying its own separator (before this change)."""
        v = self.decide(self.container(), trusted_anchors=[self.second[1].hex()])
        self.assertEqual(v["note"], "long-term validation failed: signer not trusted: its key is not among the "
                                    "trusted anchors nor active on a trust list they publish")

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


def _an_ml_dsa_backend():
    """Is a real ML-DSA backend usable here? --verify-dir needs one to verify a genuine pack."""
    return V._provider_available("oqs") or _cryptography_mldsa()


class VerifyDirHoldsEveryPackToItsExpectation(unittest.TestCase):
    """--verify-dir holds each pack's verdict to its `_vector.expect`. Until 2026-10-10 a pack refused
    before either witness ran (a public key of the wrong length, hex that does not decode) was
    reported SKIPPED, which fails the run, so a vector set holding such a negative could not pass on
    a correct verifier. A refusal is a verdict. SKIPPED is left for a file that is not a pack and a
    pack no backend here can verify, and neither passes; a run in which no real witness decided
    anything does not pass. A run that does not pass ends "N of M as expected" (a refused forgery is
    as expected, not verified) and a line naming each cause it met; one that passes ends with the
    real witnesses, as before.

    The wrong-length pack is arbitrary bytes, a 32-byte key and a signature-length run of one
    byte, refused at the size check before any witness sees it."""

    GENUINE = json.loads((ROOT / "vectors" / "ml-dsa-65-valid.json").read_text())
    TAMPERED = json.loads((ROOT / "vectors" / "ml-dsa-65-tampered-signature.json").read_text())
    PLACEHOLDER = json.loads((ROOT / "vectors" / "placeholder.json").read_text())
    VERIFIED = "(verified with the app's real witnesses)"
    NO_WITNESS = "no real witness decided any pack"

    @staticmethod
    def run_dir(files):
        """(exit code, stdout) of verify_dir over a directory holding `files`: name -> a JSON
        value, or text written as it is."""
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as d:
            for name, body in files.items():
                (pathlib.Path(d) / name).write_text(body if isinstance(body, str) else json.dumps(body))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = V.verify_dir(d)
        return code, out.getvalue()

    def run_dir_with_no_witness(self, files, installed):
        """run_dir with neither witness running, and `installed` saying whether a backend is."""
        with unittest.mock.patch.object(V, "_verify_liboqs", return_value=None), \
                unittest.mock.patch.object(V, "_verify_cryptography", return_value=None), \
                unittest.mock.patch.object(V, "_provider_available", return_value=installed):
            return self.run_dir(files)

    @staticmethod
    def row(out, name):
        return next(line for line in out.splitlines() if line.startswith(name + " "))

    @staticmethod
    def closing(out):
        """The last two lines: the count, and the causes of a run that does not pass."""
        return out.splitlines()[-2:]

    def pack(self, expect, **fields):
        """The genuine pack with `fields` changed, expecting `expect`."""
        changed = dict(self.GENUINE, **fields)
        changed["_vector"] = {"expect": expect}
        return changed

    def wrong_length(self, expect):
        return self.pack(expect, public_key_hex=bytes(range(32)).hex(), signature_hex=(b"\x02" * 3309).hex())

    @unittest.skipUnless(_an_ml_dsa_backend(), "no ML-DSA backend: the genuine pack cannot verify here")
    def test_a_refusal_before_either_witness_is_held_to_its_expectation(self):
        negatives = {"b-key-of-the-wrong-length.json": self.wrong_length("invalid"),
                     "c-signature-not-hex.json": self.pack("invalid", signature_hex="zz" + self.GENUINE["signature_hex"][2:]),
                     "d-statement-not-a-serial.json": self.pack("invalid", token_value='{"format":"polaris-x/1"}'),
                     "e-set-below-the-floor.json": self.pack("invalid", algorithm="ML-DSA-44")}
        files = {"a-genuine.json": self.GENUINE}
        files.update(negatives)
        code, out = self.run_dir(files)
        self.assertNotIn("SKIPPED", out)
        for name in negatives:
            self.assertRegex(self.row(out, name), r"expect=invalid\s+got=invalid\s+OK$", name)
        self.assertEqual(out.splitlines()[-1], self.VERIFIED)
        self.assertEqual(code, 0, out)

    def test_the_same_wrong_length_pack_expected_valid_is_a_mismatch(self):
        code, out = self.run_dir({"a-genuine.json": self.GENUINE,
                                  "b-key-of-the-wrong-length.json": self.wrong_length("valid")})
        self.assertRegex(self.row(out, "b-key-of-the-wrong-length.json"), r"expect=valid\s+got=invalid\s+MISMATCH$")
        self.assertNotEqual(code, 0, out)

    def test_another_artifact_is_skipped_whatever_it_expects(self):
        # Judged as a pack it is refused for not being one, and its "invalid" would pass for that.
        trust_list = json.loads((ROOT / "conformance" / "vectors" / "trust-list-valid.json").read_text())
        trust_list["_vector"] = {"expect": "invalid"}
        code, out = self.run_dir({"a-genuine.json": self.GENUINE, "b-trust-list.json": trust_list})
        self.assertTrue(self.row(out, "b-trust-list.json").endswith(
            " SKIPPED (a polaris-trust-list/1, not an authenticity pack: no flag checks it, see the README)"), out)
        self.assertIn("1 skipped: not an authenticity pack", out.splitlines()[-1])
        self.assertEqual(code, 2, out)

    def test_another_artifact_is_skipped_with_the_flag_that_checks_it(self):
        how = {"polaris-agent-grant/1": "check it with --agent-grant",
               "polaris-agent-proof/1": "check it with --agent-proof beside --agent-grant",
               "polaris-holder-binding/1": "check it with --holder-binding beside --agent-grant",
               "polaris-grant-revocation/1": "check it with --grant-revocation beside --agent-grant",
               "polaris-epoch-checkpoint/1": "check it with --epoch-checkpoint beside --zk-proof",
               "polaris-federation-manifest/1": "check it with --trusted-manifest beside --zk-proof",
               "polaris-status-assertion/1": "check it with --status-assertion beside --pack",
               "polaris-presentation/1": "check it with --presentation"}
        names = {fmt: "%s.json" % fmt.split("/")[0] for fmt in how}
        code, out = self.run_dir({names[fmt]: {"format": fmt, "_vector": {"expect": "invalid"}} for fmt in how})
        for fmt, check in how.items():
            with self.subTest(fmt):
                self.assertEqual(self.row(out, names[fmt]), "%-34s SKIPPED (a %s, not an authenticity pack: %s)"
                                 % (names[fmt], fmt, check))
        self.assertEqual(self.closing(out), ["0 of 8 as expected",
                                             "8 skipped: not an authenticity pack; " + self.NO_WITNESS])
        self.assertEqual(code, 2, out)
        # Each flag named is one its mode reads, so the advice runs rather than exiting 4.
        modes = {"--agent-grant": "--agent-grant", "--zk-proof": "--zk-proof",
                 "--pack": "--pack with --status-assertion", "--presentation": "--presentation"}
        for check in V._FLAG_FOR_FORMAT.values():
            flag, _, beside = check.partition(" beside ")
            self.assertIn(flag[2:].replace("-", "_"), V._MODE_FLAGS[modes[beside or flag]], check)

    def test_an_object_with_no_pack_field_is_not_a_pack(self):
        # No format, token, algorithm, signature or key: nothing was refused, so it is not a negative
        # that passed. Until 2026-10-10 it was compared, and beside a genuine pack the run exited 0.
        no_field = "SKIPPED (not an authenticity pack: no format, token_value, algorithm, signature_hex or public_key_hex)"
        code, out = self.run_dir({"a-genuine.json": self.GENUINE, "b-empty.json": {"_vector": {"expect": "invalid"}}})
        self.assertEqual(self.row(out, "b-empty.json"), "%-34s %s" % ("b-empty.json", no_field))
        self.assertIn("1 skipped: not an authenticity pack", out.splitlines()[-1])
        self.assertNotEqual(code, 0, out)
        code, out = self.run_dir({"a-genuine.json": self.GENUINE, "c-note.json": {"_note": "the key is in anchors/"}})
        self.assertEqual(self.row(out, "c-note.json"), "%-34s %s" % ("c-note.json", no_field))
        self.assertNotEqual(code, 0, out)

    def test_a_pack_no_witness_can_verify_is_skipped_with_its_cause(self):
        files = {"a-genuine.json": self.GENUINE, "b-key-of-the-wrong-length.json": self.wrong_length("invalid")}
        for installed, why in ((False, "no ML-DSA verifier installed"),
                               (True, "no installed backend verifies ML-DSA-65")):
            with self.subTest(why):
                code, out = self.run_dir_with_no_witness(files, installed)
                self.assertTrue(self.row(out, "a-genuine.json").endswith(" SKIPPED (%s)" % why), out)
                # The wrong length beside it is still a refusal: that needs no backend.
                self.assertRegex(self.row(out, "b-key-of-the-wrong-length.json"), r"expect=invalid\s+got=invalid\s+OK$")
                self.assertEqual(self.closing(out), ["1 of 2 as expected", "1 skipped: %s; %s" % (why, self.NO_WITNESS)])
                self.assertEqual(code, 2, out)
        with unittest.mock.patch.object(V, "_verify_liboqs", return_value=None), \
                unittest.mock.patch.object(V, "_verify_cryptography", return_value=None):
            self.assertEqual(V.verify_pack(self.GENUINE)["note"], "no ML-DSA-65 verifier available: install "
                             "liboqs-python with the liboqs shared library (and optionally "
                             "cryptography>=48 for the second witness)")
        self.addCleanup(V.set_dev_placeholder_mode, False)
        V.set_dev_placeholder_mode(True)
        self.assertEqual(V.verify_pack(self.GENUINE)["note"], "this run declared --dev-placeholder, so no "
                         "real backend was consulted: NOTHING here is authenticated")
        code, out = self.run_dir({"a-genuine.json": self.GENUINE})
        why = "--dev-placeholder: no real backend was consulted"
        self.assertTrue(self.row(out, "a-genuine.json").endswith(" SKIPPED (%s)" % why), out)
        self.assertEqual(self.closing(out), ["0 of 1 as expected", "1 skipped: %s; %s" % (why, self.NO_WITNESS)])
        self.assertEqual(code, 2, out)

    def test_a_directory_in_which_no_witness_decided_anything_does_not_pass(self):
        import contextlib
        import io
        for label, files in (("an empty directory", {}), ("no *.json", {"notes.txt": "not a vector"})):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code, out = self.run_dir(files)
            self.assertEqual(code, 3, label)
            self.assertEqual(out, "", label)
            self.assertRegex(err.getvalue(), r"^no \*\.json vectors in .+\n$", label)
        artifact = {"format": "polaris-trust-list/1", "_vector": {"expect": "invalid"}}
        for label, vector, closing in (
                ("an expectation and nothing else", {"_vector": {"expect": "invalid"}},
                 ["0 of 1 as expected", "1 skipped: not an authenticity pack; " + self.NO_WITNESS]),
                ("the placeholder", self.PLACEHOLDER, ["1 of 1 as expected", self.NO_WITNESS]),
                ("another artifact", artifact,
                 ["0 of 1 as expected", "1 skipped: not an authenticity pack; " + self.NO_WITNESS]),
                ("a key of the wrong length", self.wrong_length("invalid"), ["1 of 1 as expected", self.NO_WITNESS])):
            with self.subTest(label):
                code, out = self.run_dir({"only.json": vector})
                self.assertEqual(self.closing(out), closing)
                self.assertNotIn(self.VERIFIED, out)
                self.assertEqual(code, 2, out)

    def test_the_line_after_the_count_names_each_cause(self):
        code, out = self.run_dir_with_no_witness({
            "a-genuine.json": self.GENUINE,                                  # skipped: no backend
            "b-key-of-the-wrong-length.json": self.wrong_length("valid"),    # mismatched
            "c-trust-list.json": {"format": "polaris-trust-list/1"},         # skipped: another artifact
            "d-true.json": "true",                                           # not an object
            "e-cut-short.json": '{"format": "polaris-authenticity'}, installed=False)   # unreadable
        self.assertEqual(self.row(out, "d-true.json"), "d-true.json".ljust(34) + " NOT A PACK (a JSON bool, not an object)")
        self.assertRegex(self.row(out, "e-cut-short.json"), r"^e-cut-short\.json +UNREADABLE \(.+\)$")
        self.assertEqual(self.closing(out), [
            "0 of 5 as expected",
            "1 mismatched; 1 skipped: no ML-DSA verifier installed; 1 skipped: not an authenticity pack; "
            "1 not a pack (not a JSON object); 1 unreadable; " + self.NO_WITNESS])
        self.assertEqual(code, 2, out)

    @unittest.skipUnless(_an_ml_dsa_backend(), "no ML-DSA backend: the genuine pack cannot verify here")
    def test_the_closing_lines_say_what_the_exit_code_says(self):
        code, out = self.run_dir({"a-genuine.json": self.GENUINE, "b-tampered.json": self.TAMPERED})
        self.assertEqual(out.splitlines()[-1], self.VERIFIED)
        self.assertNotIn("as expected", out)
        self.assertEqual(code, 0, out)
        code, out = self.run_dir({"a-genuine.json": self.GENUINE, "b-tampered.json": self.TAMPERED,
                                  "c-key-of-the-wrong-length.json": self.wrong_length("valid")})
        self.assertEqual(self.closing(out), ["2 of 3 as expected", "1 mismatched"])
        self.assertNotIn(self.VERIFIED, out)
        self.assertEqual(code, 2, out)


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


def _case_log_key(name):
    """The log key a published case names (conformance/cases.json): the relying party's input,
    never read off the head being judged."""
    cases = json.loads((ROOT / "conformance" / "cases.json").read_text())["cases"]
    return next(c["log_key"] for c in cases if c["name"] == name)


class WitnessedCheckpointIsTotal(unittest.TestCase):
    """`verify_timestamp_anchor` says it is total on hostile input. Cosignatures that are not a
    list raised TypeError from `verify_witnessed_checkpoint` until 2026-09-28."""

    def test_cosignatures_that_are_not_a_list_witness_nothing(self):
        import copy
        ts = json.loads((ROOT / "conformance" / "vectors" / "timestamp-anchor-witnessed.json").read_text())
        both = [c["public_key_hex"] for c in ts["anchor"]["cosignatures"]]
        log_key = _case_log_key("timestamp-anchor-witnessed")
        good = V.verify_timestamp_anchor(ts, log_key=log_key, trusted_witnesses=both, threshold=2)
        if not good.get("anchored"):
            self.skipTest("no ML-DSA-65 backend here: %s" % good.get("note"))
        self.assertTrue(good.get("witnessed"))
        for bad in (True, 5):
            with self.subTest(cosignatures=bad):
                t = copy.deepcopy(ts)
                t["anchor"]["cosignatures"] = bad
                v = V.verify_timestamp_anchor(t, log_key=log_key, trusted_witnesses=both, threshold=2)
                self.assertTrue(v.get("anchored"))
                self.assertFalse(v.get("witnessed"))


#: The note a log-head verdict carries when the caller named no log key.
_NO_LOG_KEY = "no log key was named: the head must be signed by a log key the caller names"


@unittest.skipUnless(_an_ml_dsa_backend(), "no ML-DSA-65 backend here")
class TimestampAnchorNamesItsLogKey(unittest.TestCase):
    """A head anchors a timestamp only under the log key the caller names (WIRE-SPEC 3.9). The
    published base anchor, and the same anchor with its head re-signed by a key no case names
    (conformance/make_stranger_head_vectors.py): only the signer differs."""

    @classmethod
    def setUpClass(cls):
        vectors = ROOT / "conformance" / "vectors"
        cls.base = json.loads((vectors / "timestamp-anchor-variants-base.json").read_text())
        cls.stranger = json.loads((vectors / "timestamp-anchor-stranger-head.json").read_text())
        cls.log_key = _case_log_key("timestamp-anchor-variants-base")

    def test_the_log_s_head_under_its_log_key_is_anchored(self):
        v = V.verify_timestamp_anchor(self.base, log_key=self.log_key)
        self.assertTrue(v["anchored"], v["note"])

    def test_a_stranger_s_head_with_no_log_key_is_not_anchored(self):
        self.assertTrue(V.verify_sth(self.stranger["anchor"]["sth"])["sth_authentic"],
                        "control: the stranger's head is authentic under its own key")
        v = V.verify_timestamp_anchor(self.stranger)
        self.assertFalse(v["anchored"])
        self.assertEqual(v["note"], _NO_LOG_KEY)

    def test_the_log_s_own_head_with_no_log_key_is_not_anchored(self):
        v = V.verify_timestamp_anchor(self.base)
        self.assertFalse(v["anchored"])
        self.assertEqual(v["note"], _NO_LOG_KEY)

    def test_a_stranger_s_head_under_the_log_key_is_not_anchored(self):
        v = V.verify_timestamp_anchor(self.stranger, log_key=self.log_key)
        self.assertFalse(v["anchored"])
        self.assertEqual(v["note"], "the head is not signed by the expected log key")


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

    def test_require_signed_attestation_reaches_the_zero_knowledge_decision(self):
        """2026-10-15: the command line had no way to ask for a signed trust edge."""
        from unittest import mock
        zk = ("--pqc-provider", "auto", "--zk-proof", str(self.blob), "--signature-only", "--nonce", "7")
        for flags, want in (((), False), (("--require-signed-attestation",), True)):
            with self.subTest(flags=flags), \
                    mock.patch.object(V, "verify_cross_authority_zk",
                                      return_value={"decision": "accept", "reasons": []}) as vz:
                self.assertEqual(self.main(*zk, *flags), 0)
                self.assertIs(vz.call_args.kwargs["require_signed_attestation"], want)

    def test_an_accept_on_an_unsigned_edge_says_so(self):
        """WIRE-SPEC 3.14: a verifier that accepts an unsigned edge MUST report that it did. The
        --json verdict carries attestation_signed; the plain output said nothing (2026-10-15)."""
        import contextlib
        import io
        from unittest import mock
        zk = ("--pqc-provider", "auto", "--zk-proof", str(self.blob), "--signature-only", "--nonce", "7")
        for signed, said in ((False, True), (True, False), (None, False)):
            out = io.StringIO()
            verdict = {"decision": "accept", "reasons": [], "attestation_signed": signed}
            with self.subTest(signed=signed), contextlib.redirect_stdout(out), \
                    mock.patch.object(V, "verify_cross_authority_zk", return_value=verdict):
                self.assertEqual(V.main(list(zk)), 0)
                self.assertEqual("the trust edge is unsigned" in out.getvalue(), said)

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
                           (("--pack", absent, "--require-signed-attestation"), "--require-signed-attestation"),
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

    def decide(self, pack=None, sa=None, token=("T", "T"), key=("ab" * 32, "AB" * 32), **kw):
        from unittest import mock
        with mock.patch.object(V, "verify_pack", return_value=dict(self.GOOD_PACK, **(pack or {}))), \
                mock.patch.object(V, "verify_status_assertion", return_value=dict(self.GOOD_SA, **(sa or {}))):
            return V.verify_stapled({"token_value": token[0], "public_key_hex": key[0]},
                                    {"token_value": token[1], "public_key_hex": key[1]}, **kw)["decision"]

    def test_all_seven_facts_accept(self):
        self.assertEqual(self.decide(), "accept")

    def test_trust_not_evaluated_abstains_unless_the_signature_alone_is_asked_for(self):
        """2026-10-21: no anchor given read as a trusted issuer, and the pair was accepted."""
        unevaluated = {"issuer_trusted": None}
        self.assertEqual(self.decide(pack=unevaluated, sa=unevaluated), "abstain")
        self.assertEqual(self.decide(pack=unevaluated), "abstain")
        self.assertEqual(self.decide(sa=unevaluated), "abstain")
        self.assertEqual(self.decide(pack=unevaluated, sa=unevaluated, signature_only=True), "accept")
        self.assertEqual(self.decide(pack={"issuer_trusted": False}, signature_only=True), "reject",
                         "an untrusted issuer is not a signature-only question")

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


@unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
class AgentGrantContextAndProofTime(unittest.TestCase):
    """Two signed fields nothing read until 2026-10-15: the grant's `context_id`, which the holder
    signs to scope the grant, and the agent proof's `issued_at`. Real signatures throughout, so
    each verdict is the verifier's whole decision; the binding and the credential are stubbed as
    in AgentGrantPrincipalBinding, so `usable` turns on the link under test."""

    NOW = "2026-05-01T00:00:30Z"

    @classmethod
    def setUpClass(cls):
        cls.holder, cls.agent = _mldsa_signer(), _mldsa_signer()

    @staticmethod
    def seal(obj, canonical, key):
        return SignedDocumentLongTermValidation.seal(obj, canonical, key)

    def grant(self, **over):
        body = {"format": "polaris-agent-grant/1", "grant_id": "g-ctx-1",
                "agent_public_key_hex": self.agent[1].hex(), "agent_algorithm": "ML-DSA-65",
                "actions": ["read:status"], "limits": {}, "context_id": 7,
                "issued_at": "2026-05-01T00:00:00Z", "expires_at": "2026-05-01T06:00:00Z"}
        body.update(over)
        return self.seal(body, V._agent_grant_canonical, self.holder)

    def proof(self, issued_at="2026-05-01T00:00:10Z"):
        return self.seal({"format": "polaris-agent-proof/1", "grant_id": "g-ctx-1",
                          "action": "read:status", "service_nonce": "svc-1", "issued_at": issued_at},
                         V._agent_proof_canonical, self.agent)

    def decide(self, grant=None, proof=None, **kw):
        from unittest import mock
        good = {"binding_authentic": True, "fresh": True, "bound_to_credential": True,
                "holder_public_key_hex": self.holder[1].hex(), "note": None}
        with mock.patch.object(V, "verify_holder_binding", return_value=good), \
                mock.patch.object(V, "verify_pack", return_value={"signature_valid": True,
                                                                  "issuer_trusted": None, "note": None}):
            return V.verify_agent_grant(grant or self.grant(), binding={"status": "active"},
                                        credential={}, now=kw.pop("now", self.NOW),
                                        requested_action="read:status", signature_only=True,
                                        agent_proof=proof or self.proof(), expected_nonce="svc-1", **kw)

    def test_the_whole_chain_is_usable_in_its_own_context(self):
        """The control, and the default: a service that names no context is not asked about one."""
        for kw in ({}, {"expected_context": 7}):
            with self.subTest(**kw):
                v = self.decide(**kw)
                self.assertIs(v["usable"], True, v["note"])
                self.assertIs(v["agent_proved"], True)
        self.assertIs(self.decide(expected_context=7)["context_matches"], True)
        self.assertIsNone(self.decide()["context_matches"])

    def test_a_grant_for_another_context_is_not_usable_here(self):
        for other in (8, "7", True):
            with self.subTest(expected_context=other):
                v = self.decide(expected_context=other)
                self.assertIs(v["context_matches"], False)
                self.assertIs(v["usable"], False)

    def test_a_proof_made_outside_the_grant_or_ahead_of_the_clock_proves_nothing(self):
        for label, issued_at, why in (
                ("before the grant was issued", "2026-04-30T23:59:59Z", "outside the grant's window"),
                ("after the grant lapsed", "2026-05-01T06:00:00Z", "outside the grant's window"),
                ("ahead of this clock", "2026-05-01T00:02:00Z", "ahead of this verifier's clock"),
                ("not a timestamp", "yesterday", "not a timestamp")):
            with self.subTest(label):
                v = self.decide(proof=self.proof(issued_at))
                self.assertIs(v["agent_proved"], False)
                self.assertIs(v["usable"], False)
                self.assertIn(why, v["note"])
        # Within the clock's 60 seconds of skew it still proves.
        self.assertIs(self.decide(proof=self.proof("2026-05-01T00:01:20Z"))["agent_proved"], True)

    def test_the_command_line_takes_this_services_context(self):
        import contextlib
        import io
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            g, pr = pathlib.Path(d, "grant.json"), pathlib.Path(d, "proof.json")
            g.write_text(json.dumps(self.grant()))
            pr.write_text(json.dumps(self.proof()))
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                V.main(["--pqc-provider", "cryptography", "--agent-grant", str(g),
                        "--agent-proof", str(pr), "--action", "read:status",
                        "--service-nonce", "svc-1", "--context", "8", "--json"])
            self.assertIs(json.loads(out.getvalue())["context_matches"], False)


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
                                        agent_proof=self.proof, expected_nonce="svc-nonce-1",
                                        signature_only=True)

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


def _iso(d):
    return d.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _issued(token="NOTIONAL-0001"):
    """A fresh issuer key S, its credential and an ACTIVE status assertion valid now, each
    genuinely signed."""
    sign, pk = _mldsa_signer()
    now = datetime.now(timezone.utc)
    win = {"issued_at": _iso(now - timedelta(minutes=1)), "expires_at": _iso(now + timedelta(minutes=30))}
    pack = {"format": "polaris-authenticity-pack/1", "token_value": token, "algorithm": "ML-DSA-65",
            "public_key_hex": pk.hex(), "signature_hex": sign(hashlib.sha3_256(token.encode("utf-8")).digest()).hex()}
    sa = dict({"format": "polaris-status-assertion/1", "token_value": token, "status": "ACTIVE"}, **win)
    sa.update(algorithm="ML-DSA-65", public_key_hex=pk.hex(),
              signature_hex=sign(hashlib.sha3_256(V._status_assertion_canonical(sa)).digest()).hex())
    return {"key": pk.hex(), "sign": sign, "pack": pack, "assertion": sa, "now": now, "window": win,
            "presentation": {"format": V._PRESENTATION_FORMAT, "credential": pack, "status_assertion": sa}}


def _holder_chain(issued):
    """A holder key H bound to `issued`'s credential, and a maker of presentations whose holder
    proof answers a given nonce."""
    sign_h, pk_h = _mldsa_signer()
    tok, win = issued["pack"]["token_value"], issued["window"]
    b = dict({"format": "polaris-holder-binding/1", "token_value": tok, "holder_public_key_hex": pk_h.hex(),
              "holder_algorithm": "ML-DSA-65", "bound_at": win["issued_at"], "status": "active",
              "algorithm": "ML-DSA-65", "public_key_hex": issued["key"]}, **win)
    b["signature_hex"] = issued["sign"](hashlib.sha3_256(V._holder_binding_canonical(b)).digest()).hex()

    def presentation(nonce):
        p = {"format": "polaris-holder-proof/1", "token_value": tok, "context_id": 7, "verifier_nonce": nonce,
             "issued_at": _iso(issued["now"] - timedelta(seconds=30)), "algorithm": "ML-DSA-65",
             "public_key_hex": pk_h.hex()}
        p["signature_hex"] = sign_h(hashlib.sha3_256(V._holder_proof_canonical(p)).digest()).hex()
        return dict(issued["presentation"], holder_binding=b, holder_proof=p)
    return presentation


@unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
class NoTrustAnchorIsNoTrustedIssuer(unittest.TestCase):
    """2026-10-21: with no anchor given, a credential and an ACTIVE status assertion a stranger
    signed were usable offline (`issuer_trusted is not False`) and accepted stapled
    (`issuer_trusted in (None, True)`). A genuine signature is not a trusted issuer: with no
    anchor each now withholds, and a caller who wants the signature alone says so. Real
    signatures by a stranger S throughout; R is another issuer's key."""

    @classmethod
    def setUpClass(cls):
        cls.x = _issued("STRANGER-0001")
        cls.s, cls.r = cls.x["key"], _mldsa_signer()[1].hex()

    def test_a_stranger_s_presentation_with_no_anchor_is_not_usable(self):
        pres = self.x["presentation"]
        v = V.verify_presentation(pres)
        self.assertEqual((v["credential_authentic"], v["issuer_trusted"]), (True, None), "genuine, trust not evaluated")
        self.assertIs(v["usable_offline"], False)
        self.assertEqual(v["note"], "no anchor_keys were given, so issuer trust was not evaluated")
        self.assertIs(V.verify_presentation(pres, anchor_keys=[self.s])["usable_offline"], True,
                      "control: the issuer's key as the anchor")
        self.assertIs(V.verify_presentation(pres, anchor_keys=[self.r])["usable_offline"], False,
                      "control: another issuer's key")
        self.assertIs(V.verify_presentation(pres, signature_only=True)["usable_offline"], True,
                      "a genuine signature alone, asked for by name")

    def test_a_stranger_s_stapled_pair_with_no_anchor_is_not_accepted(self):
        pack, sa = self.x["pack"], self.x["assertion"]
        v = V.verify_stapled(pack, sa)
        self.assertEqual(v["decision"], "abstain")
        self.assertIn("no anchor_keys were given, so issuer trust was not evaluated", v["reasons"])
        self.assertEqual(V.verify_stapled(pack, sa, anchor_keys=[self.s])["decision"], "accept",
                         "control: the issuer's key as the anchor")
        self.assertEqual(V.verify_stapled(pack, sa, anchor_keys=[self.r])["decision"], "reject",
                         "control: another issuer's key")
        self.assertEqual(V.verify_stapled(pack, sa, signature_only=True)["decision"], "accept",
                         "a genuine signature alone, asked for by name")


@unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
class HolderProofNeedsTheNonceThisVerifierIssued(unittest.TestCase):
    """WIRE-SPEC (holder proof): a verifier MUST require `verifier_nonce` to equal the one it
    issued. Before this change verify_presentation read the unchecked nonce (None, no
    `expected_nonce` given) as a match, so a proof replayed from another verifier proved, where
    neither SDK and the published case `holder-chain-no-nonce` read it so. Real signatures."""

    MINE, OTHER = "nonce-this-verifier-issued", "nonce-issued-by-another-verifier"

    @classmethod
    def setUpClass(cls):
        cls.x = _issued("HOLDER-0001")
        cls.presentation = staticmethod(_holder_chain(cls.x))

    def test_a_holder_proof_checked_against_no_nonce_is_not_proved(self):
        for required in (True, False):
            with self.subTest(require_holder_proof=required):
                v = V.verify_presentation(self.presentation(self.OTHER), anchor_keys=[self.x["key"]],
                                          require_holder_proof=required)
                self.assertIsNone(v["holder"]["nonce_matches"], "no nonce was given, so none was compared")
                self.assertIs(v["holder"]["proved"], False)
                self.assertIs(v["usable_offline"], False)
                self.assertEqual(v["note"], "no expected_nonce was given, so the holder proof was not checked "
                                            "against a nonce this verifier issued")

    def test_the_controls(self):
        mine = V.verify_presentation(self.presentation(self.MINE), anchor_keys=[self.x["key"]],
                                     expected_nonce=self.MINE, require_holder_proof=True)
        self.assertEqual((mine["holder"]["proved"], mine["usable_offline"]), (True, True), mine["note"])
        replay = V.verify_presentation(self.presentation(self.OTHER), anchor_keys=[self.x["key"]],
                                       expected_nonce=self.MINE, require_holder_proof=True)
        self.assertEqual((replay["holder"]["nonce_matches"], replay["usable_offline"]), (False, False))


@unittest.skipUnless(any(V._provider_available(p) for p in V.REAL_PROVIDERS) and _cryptography_mldsa(),
                     "no real ML-DSA backend")
class CommandLineJsonSaysWhatTheExitCodeSays(unittest.TestCase):
    """2026-10-21: the presentation path abstained (exit 2) with no --issuer-anchor, or with a
    holder proof and no --nonce, while its --json verdict said `usable_offline: true`; a script
    reading the verdict read a usable presentation the run did not accept. Every run here reads
    the JSON verdict beside the exit code, and stderr says why only for an abstention. The rows
    run on real signatures and the library's own decision, except where a verdict the library
    no longer gives is replaced to show the command line holds it on its own."""

    NONCE = "nonce-this-verifier-issued"

    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-cli-json-"))
        x, held = _issued("STRANGER-0001"), _issued("HOLDER-0001")
        files = {"stranger.json": x["presentation"], "pack.json": x["pack"], "assertion.json": x["assertion"],
                 "holder.json": _holder_chain(held)(cls.NONCE), "s.json": [x["key"]],
                 "r.json": [_mldsa_signer()[1].hex()], "i.json": [held["key"]], "blob.json": {}}
        for name, body in files.items():
            (cls.tmp / name).write_text(json.dumps(body))

    def run_json(self, *argv):
        import contextlib
        import io
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = V.main(["--pqc-provider", "auto", "--json", *argv])
        return code, json.loads(out.getvalue()), err.getvalue()

    def f(self, name):
        return str(self.tmp / name)

    def test_the_presentation_path(self):
        rows = ((("--presentation", self.f("stranger.json")), 2, True),
                (("--presentation", self.f("stranger.json"), "--issuer-anchor", self.f("s.json")), 0, False),
                (("--presentation", self.f("stranger.json"), "--issuer-anchor", self.f("r.json")), 2, False),
                (("--presentation", self.f("stranger.json"), "--signature-only"), 0, False))
        for argv, want, abstains in rows:
            with self.subTest(argv=argv[2:]):
                code, verdict, err = self.run_json(*argv)
                self.assertEqual(code, want)
                self.assertIs(verdict["usable_offline"], code == 0, "the JSON verdict says what the exit code says")
                self.assertEqual("abstain:" in err, abstains)

    def test_a_holder_proof_with_no_nonce(self):
        holder = ("--presentation", self.f("holder.json"))
        for flags, want, abstains in ((("--issuer-anchor", self.f("i.json")), 2, True), (("--signature-only",), 2, True),
                                      (("--issuer-anchor", self.f("i.json"), "--nonce", self.NONCE), 0, False)):
            with self.subTest(flags=flags):
                code, verdict, err = self.run_json(*holder, *flags)
                self.assertEqual(code, want)
                self.assertIs(verdict["usable_offline"], code == 0, "the JSON verdict says what the exit code says")
                self.assertEqual("abstain:" in err, abstains)

    def test_a_usable_verdict_is_still_held_for_what_the_run_was_not_given(self):
        """As on the stapled and zero-knowledge paths, the command line holds a usable verdict for
        a missing trust root or nonce on its own, and the JSON says so."""
        from unittest import mock
        usable = {"usable_offline": True, "issuer_trusted": None, "note": None, "holder": {"present": False}}
        proved = dict(usable, issuer_trusted=True, holder={"present": True})
        for verdict, flags, want in ((usable, (), 2), (usable, ("--signature-only",), 0),
                                     (proved, (), 2), (proved, ("--nonce", self.NONCE), 0)):
            with self.subTest(issuer_trusted=verdict["issuer_trusted"], flags=flags), \
                    mock.patch.object(V, "verify_presentation", return_value=dict(verdict)):
                code, out, err = self.run_json("--presentation", self.f("blob.json"), *flags)
                self.assertEqual(code, want)
                self.assertIs(out["usable_offline"], code == 0, "the JSON verdict says what the exit code says")
                self.assertEqual("abstain:" in err, code == 2)

    def test_the_stapled_path(self):
        staple = ("--pack", self.f("pack.json"), "--status-assertion", self.f("assertion.json"))
        for flags, want, decision in (((), 2, "abstain"), (("--issuer-anchor", self.f("s.json")), 0, "accept"),
                                      (("--issuer-anchor", self.f("r.json")), 2, "reject"),
                                      (("--signature-only",), 0, "accept")):
            with self.subTest(flags=flags):
                code, verdict, err = self.run_json(*staple, *flags)
                self.assertEqual((code, verdict["decision"]), (want, decision))
                self.assertEqual("abstain:" in err, decision == "abstain")

    def test_the_zero_knowledge_path(self):
        """With no trust root the library refuses the run itself (2026-10-21), before any proof is
        read; the command line prints that refusal as the abstention it printed before. Only the
        checkpoint's own verdict is replaced: the library decides the rest."""
        from unittest import mock
        checkpoint = {"checkpoint_authentic": True, "fresh": True}
        for flags, decision in (((), "abstain"), (("--signature-only",), "reject")):
            with self.subTest(flags=flags), mock.patch.object(V, "verify_epoch_checkpoint", return_value=checkpoint), \
                    mock.patch.object(V, "verify_cross_authority_zk", wraps=V.verify_cross_authority_zk) as vz:
                code, verdict, err = self.run_json("--zk-proof", self.f("blob.json"), "--nonce", "7", *flags)
                self.assertEqual((code, verdict["decision"]), (2, decision))
                self.assertEqual("abstain:" in err, decision == "abstain")
                self.assertIs(vz.call_args.kwargs.get("signature_only"), "--signature-only" in flags,
                              "the question the run asks reaches the library")

    def test_the_agent_grant_path(self):
        """Its abstention printed `usable: true` in the JSON beside exit 2 as well."""
        from unittest import mock
        base = {"grant_authentic": True, "fresh": True, "credential_authentic": True, "principal_bound": True,
                "action_in_scope": True, "revoked": None, "agent_proved": True, "pairwise_handle": None,
                "correlation": None, "note": None, "usable": True}
        for trusted, flags, want in ((None, (), 2), (None, ("--signature-only",), 0), (True, (), 0)):
            with self.subTest(issuer_trusted=trusted, flags=flags), \
                    mock.patch.object(V, "verify_agent_grant", return_value=dict(base, issuer_trusted=trusted)):
                code, verdict, err = self.run_json("--agent-grant", self.f("pack.json"), *flags)
                self.assertEqual(code, want)
                self.assertIs(verdict["usable"], code == 0, "the JSON verdict says what the exit code says")
                self.assertEqual("abstain:" in err, code == 2)


class AgentGrantNeedsATrustAnchor(unittest.TestCase):
    """2026-10-28: with no anchor_keys, verify_agent_grant answered usable True for a chain whose
    credential a stranger issued, where every other function here abstains. The signatures are
    stubbed to hold (as in the limits rows of test_verify_p9), so the anchors are the only thing
    that can make the verdict differ; the credential's issuer is trusted only when the anchors
    name its key."""

    ISSUER = "cd" * 32
    GRANT = {"format": "polaris-agent-grant/1", "grant_id": "g-1",
             "public_key_hex": "cd" * 32, "algorithm": "ML-DSA-65",
             "agent_public_key_hex": "ab" * 32, "agent_algorithm": "ML-DSA-65",
             "actions": ["read"], "issued_at": "2026-05-01T00:00:00Z",
             "expires_at": "2026-05-01T06:00:00Z"}
    PROOF = {"format": "polaris-agent-proof/1", "grant_id": "g-1", "public_key_hex": "ab" * 32,
             "action": "read", "service_nonce": "n-1", "algorithm": "ML-DSA-65",
             "issued_at": "2026-05-01T00:00:10Z", "signature_hex": "00" * 8}

    def setUp(self):
        self._saved = (V._signed_by, V.verify_pack, V.verify_holder_binding)
        V._signed_by = lambda obj, msg, pk, alg: (True, ["stub"], None)

        def pack(cred, anchor_keys=None):
            trusted = None if anchor_keys is None else self.ISSUER in [str(a).lower() for a in anchor_keys]
            return {"signature_valid": True, "issuer_trusted": trusted, "note": None}
        V.verify_pack = pack
        V.verify_holder_binding = lambda b, credential=None, now=None, anchor_keys=None: {
            "binding_authentic": True, "fresh": True, "holder_public_key_hex": self.ISSUER,
            "bound_to_credential": True}

    def tearDown(self):
        V._signed_by, V.verify_pack, V.verify_holder_binding = self._saved

    def chain(self, **kw):
        return V.verify_agent_grant(self.GRANT, binding={"status": "active"}, credential={},
                                    now="2026-05-01T00:00:30Z", requested_action="read",
                                    agent_proof=self.PROOF, expected_nonce="n-1", **kw)

    def test_a_chain_no_anchor_vouches_for_is_not_usable(self):
        v = self.chain()
        self.assertEqual((v["usable"], v["issuer_trusted"], v["principal_bound"]), (False, None, True), v["note"])
        self.assertEqual(v["note"], V._NO_ISSUER_ANCHOR)
        self.assertIs(self.chain(anchor_keys=None, signature_only=False)["usable"], False)

    def test_the_controls(self):
        trusted = self.chain(anchor_keys=[self.ISSUER.upper()])
        self.assertEqual((trusted["usable"], trusted["issuer_trusted"]), (True, True), trusted["note"])
        other = self.chain(anchor_keys=["ee" * 32])
        self.assertEqual((other["usable"], other["issuer_trusted"]), (False, False))
        self.assertIs(self.chain(anchor_keys=[]) ["usable"], False, "an empty anchor list trusts nobody")

    def test_the_signature_alone_is_asked_for_by_name(self):
        alone = self.chain(signature_only=True)
        self.assertEqual((alone["usable"], alone["issuer_trusted"]), (True, None), alone["note"])
        wrong = self.chain(signature_only=True, anchor_keys=["ee" * 32])
        self.assertIs(wrong["usable"], False, "signature_only does not excuse an anchor that names another issuer")
        bare = V.verify_agent_grant(self.GRANT, requested_action="read", signature_only=True)
        self.assertIs(bare["usable"], False, "signature_only does not supply the missing links")

    @unittest.skipUnless(any(V._provider_available(p) for p in V.REAL_PROVIDERS) and _cryptography_mldsa(),
                         "no real ML-DSA backend")
    def test_the_command_says_what_its_exit_code_says(self):
        import contextlib
        import io
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-grant-json-"))
        # The command reads the clock: a window that has not closed.
        grant = dict(self.GRANT, expires_at="2099-01-01T00:00:00Z")
        files = {"grant.json": grant, "binding.json": {"status": "active"}, "credential.json": {},
                 "proof.json": self.PROOF, "issuer.json": [self.ISSUER], "other.json": ["ee" * 32]}
        for name, body in files.items():
            (tmp / name).write_text(json.dumps(body))
        chain = ("--agent-grant", str(tmp / "grant.json"), "--holder-binding", str(tmp / "binding.json"),
                 "--credential", str(tmp / "credential.json"), "--agent-proof", str(tmp / "proof.json"),
                 "--action", "read", "--service-nonce", "n-1")
        for flags, want, abstains in (((), 2, True), (("--issuer-anchor", str(tmp / "issuer.json")), 0, False),
                                      (("--issuer-anchor", str(tmp / "other.json")), 2, False),
                                      (("--signature-only",), 0, False)):
            out, err = io.StringIO(), io.StringIO()
            with self.subTest(flags=flags):
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = V.main(["--pqc-provider", "auto", "--json", *chain, *flags])
                verdict = json.loads(out.getvalue())
                self.assertEqual(code, want, err.getvalue())
                self.assertIs(verdict["usable"], code == 0, "the JSON verdict says what the exit code says")
                self.assertEqual("abstain:" in err.getvalue(), abstains)


@unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
class CrossAuthorityNeedsATrustAnchor(unittest.TestCase):
    """2026-10-21: with no trust anchor given, verify_cross_authority honoured any authentic,
    fresh manifest named to it, and every manifest is signed by a key it lists itself; so a
    stranger M's manifest attesting a stranger T's credential was accepted, directly and through
    a status bundle, where both SDKs refuse. Real signatures: R is the authority the relying
    party trusts, M and T strangers, P a bundle publisher."""

    CTX, NOW = 1, "2026-10-21T02:00:00Z"
    WIN = {"issued_at": "2026-10-21T00:00:00Z", "expires_at": "2026-10-22T00:00:00Z"}

    @classmethod
    def setUpClass(cls):
        keys = {n: _mldsa_signer() for n in "RMTP"}
        cls.pk = {n: k[1].hex() for n, k in keys.items()}
        cls.key = keys

        def seal(obj, canonical, who):
            out = dict(obj, algorithm="ML-DSA-65", public_key_hex=cls.pk[who])
            out["signature_hex"] = keys[who][0](hashlib.sha3_256(canonical(out)).digest()).hex()
            return out

        def manifest(who):
            return seal(dict({"format": "polaris-federation-manifest/1", "authority": {"agency_id": who, "name": who},
                              "anchors": [{"public_key_hex": cls.pk[who], "status": "active"}],
                              "attestations": [{"attested_public_key_hex": cls.pk["T"], "context_id": cls.CTX}],
                              "epoch": None, "revocation": None}, **cls.WIN), V._manifest_canonical, who)

        tv = "T-0001"
        cls.pack = {"format": "polaris-authenticity-pack/1", "token_value": tv, "algorithm": "ML-DSA-65",
                    "public_key_hex": cls.pk["T"],
                    "signature_hex": keys["T"][0](hashlib.sha3_256(tv.encode("utf-8")).digest()).hex()}
        sig = cls.pack["signature_hex"]
        cls.forged = dict(cls.pack, signature_hex=("00" if sig[:2] != "00" else "01") + sig[2:])
        feed = seal(dict({"format": V._REVOCATION_FEED_FORMAT, "authority": {"agency_id": "T"}, "epoch_number": 1,
                          "as_of": cls.WIN["issued_at"], "revoked_root_hex": V.revoked_root([]), "revoked_count": 0,
                          "revoked_leaves": []}, **cls.WIN), V._revocation_feed_canonical, "T")
        members = [{"revocation_feed": feed}]
        cls.bundle = seal(dict({"format": V._STATUS_BUNDLE_FORMAT, "publisher": {"agency_id": "P"}, "members": members,
                                "members_root_hex": V.bundle_members_root(members), "member_count": 1}, **cls.WIN),
                          V._status_bundle_canonical, "P")
        cls.m_r, cls.m_m = manifest("R"), manifest("M")

    def bundled(self, pack, manifest, **kw):
        return V.verify_cross_authority_via_bundle(pack, self.CTX, [manifest], self.bundle, now=self.NOW, **kw)

    def test_a_stranger_s_manifest_with_no_anchor_is_not_accepted(self):
        v = V.verify_cross_authority(self.pack, self.CTX, [self.m_m], now=self.NOW)
        self.assertEqual(v["decision"], "reject")
        self.assertEqual(v["reasons"], ["no trust anchors were given: a manifest vouches for nothing by itself"])

    def test_through_a_status_bundle(self):
        self.assertEqual(self.bundled(self.pack, self.m_m)["decision"], "reject", "a stranger's manifest, no anchor")
        self.assertEqual(self.bundled(self.pack, self.m_m, trusted_anchors=[self.pk["R"]])["decision"], "reject",
                         "control: the same, with the relying party's anchor")
        accepted = self.bundled(self.pack, self.m_r, trusted_anchors=[self.pk["R"]])
        self.assertEqual((accepted["decision"], accepted["revocation_checked"]), ("accept", True),
                         "control: the trusted authority's manifest")
        self.assertEqual(self.bundled(self.forged, self.m_r, trusted_anchors=[self.pk["R"]])["decision"], "reject",
                         "a forged credential signature, all else trusted")

    def test_the_published_case_with_its_anchors_left_out(self):
        """`cross-authority-untrusted` rejects under its anchors; with them omitted the detached
        verifier accepted and the Python SDK rejected."""
        cases = {c["name"]: c for c in json.loads((ROOT / "conformance" / "cases.json").read_text())["cases"]}
        load = lambda c: (json.loads((ROOT / c["pack_file"]).read_text()),  # noqa: E731
                          [json.loads((ROOT / f).read_text()) for f in c["manifest_files"]])
        c = cases["cross-authority-untrusted"]
        pack, manifests = load(c)
        self.assertEqual(V.verify_cross_authority(pack, c["context_id"], manifests, now=c["now"])["decision"], "reject")
        self.assertEqual(V.verify_cross_authority(pack, c["context_id"], manifests, now=c["now"],
                                                  trusted_anchors=c["trusted_anchors"])["decision"], "reject")
        c = cases["cross-authority-accept"]
        pack, manifests = load(c)
        anchors = [a["public_key_hex"] for m in manifests for a in m["anchors"] if a.get("status") in (None, "active")]
        self.assertEqual(V.verify_cross_authority(pack, c["context_id"], manifests, now=c["now"],
                                                  trusted_anchors=anchors)["decision"], "accept", "control")


class CrossAuthorityZkTrustChain(unittest.TestCase):
    """verify_cross_authority_zk trusts a foreign epoch only through a fresh checkpoint, a
    fresh and trusted manifest, and an attestation of THAT key, in THIS context, inside its own
    window; then it refuses a replayed nullifier. 2026-09-23: a held-out round removed each of
    those six rules in turn and every suite and the cross-authority drill stayed green, because
    each drill case breaks several links at once. The three inner verdicts are replaced here,
    every link passes, then exactly one fails."""

    KEY = "cc" * 32
    ABSENT = object()

    def verdict(self, cv=None, mv=None, att=None, zk=None, context=1, anchors=("aa" * 32,),
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
                                               trusted_anchors=None if anchors is None else list(anchors), **floor)

    def decide(self, **kw):
        return self.verdict(**kw)["decision"]

    def test_every_link_holding_accepts(self):
        self.assertEqual(self.decide(), "accept")

    def test_no_trust_anchor_is_no_trusted_authority(self):
        """2026-10-21: with no anchor given the manifest trust check was skipped, so any authentic,
        fresh manifest named here attested the checkpoint's issuer and the proof was accepted."""
        v = self.verdict(anchors=None)
        self.assertEqual(v["decision"], "reject")
        self.assertEqual(v["reasons"], ["no trust anchors were given: a manifest vouches for nothing by itself"])
        self.assertIsNone(v["issuer_trusted"])
        self.assertEqual(self.decide(anchors=None, signature_only=True), "accept",
                         "the proof and its binding alone, asked for by name")

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


@unittest.skipUnless(V._provider_available("oqs") or _cryptography_mldsa(), "no ML-DSA verifier here")
class CrossAuthorityZkEdgeSignature(unittest.TestCase):
    """2026-10-15: verify_cross_authority_zk took any edge naming the checkpoint's key, signed
    well, badly or not at all, while the credential path refused a badly signed edge and let a
    relying party require a signed one. The edge here is the genuinely signed one in
    sdk/testdata/federation-edge-window.json; the checkpoint, the manifest's own verdict and the
    proof are replaced, so only the edge decides."""

    @classmethod
    def setUpClass(cls):
        cls.f = json.loads((ROOT / "sdk" / "testdata" / "federation-edge-window.json").read_text())
        cls.manifest = cls.f["manifests"]["open"]
        cls.edge = cls.manifest["attestations"][0]

    def decide(self, edge=None, manifest=None, field="decision", **kw):
        from unittest import mock
        edge = self.edge if edge is None else edge
        manifest = self.manifest if manifest is None else manifest
        mvr = {"manifest_authentic": True, "fresh": True, "issuer_trusted": True,
               "authority": manifest["authority"], "attestations": [edge]}
        zkr = {"bound": True, "proof_verified": True, "nullifier": "ab", "fresh_nullifier": True}
        checkpoint = {"public_key_hex": self.edge["attested_public_key_hex"],
                      "epoch": {"root_hex": "00", "number": 1, "committed_count": 20}}
        with mock.patch.object(V, "verify_epoch_checkpoint",
                               return_value={"checkpoint_authentic": True, "fresh": True}), \
                mock.patch.object(V, "verify_manifest", return_value=mvr), \
                mock.patch.object(V, "verify_zk_against_root", return_value=zkr):
            return V.verify_cross_authority_zk({}, checkpoint, self.f["_fixture"]["context_id"], [manifest],
                                               trusted_anchors=[self.f["trusted_anchor"]],
                                               now=self.f["_fixture"]["now"], **kw)[field]

    def unsigned(self):
        return {k: v for k, v in self.edge.items() if k not in ("signature_hex", "public_key_hex")}

    def test_a_signed_edge_is_accepted_with_or_without_the_requirement(self):
        self.assertEqual(self.decide(), "accept")
        self.assertEqual(self.decide(require_signed_attestation=True), "accept")

    def test_an_unsigned_edge_is_accepted_by_default_and_refused_when_signatures_are_required(self):
        """Version 1 manifests carry unsigned edges, so the default accepts one; a relying party
        that wants the attesting agency's own signature asks for it."""
        self.assertEqual(self.decide(edge=self.unsigned()), "accept")
        self.assertEqual(self.decide(edge=self.unsigned(), require_signed_attestation=True), "reject")

    def test_the_verdict_says_whether_the_edge_was_signed(self):
        """WIRE-SPEC 3.14: a verifier that accepts an unsigned edge MUST report that it did."""
        self.assertIs(self.decide(field="attestation_signed"), True)
        self.assertIs(self.decide(edge=self.unsigned(), field="attestation_signed"), False)

    def test_a_badly_signed_edge_is_refused(self):
        sig = self.edge["signature_hex"]
        bad = dict(self.edge, signature_hex=("00" if sig[:2] != "00" else "01") + sig[2:])
        self.assertEqual(self.decide(edge=bad), "reject")

    def test_an_edge_signed_by_a_key_the_manifest_does_not_anchor_is_refused(self):
        self.assertEqual(self.decide(manifest=dict(self.manifest, anchors=[])), "reject")


@unittest.skipUnless(V._provider_available("oqs") or _cryptography_mldsa(), "no ML-DSA verifier here")
class CrossAuthorityViaBundleRequiresSignedEdges(unittest.TestCase):
    """require_signed_attestation reaches the decision a status bundle carries. The bundle's own
    verdict is replaced, and its member's feed is not genuine, so every run rejects; what the
    option changes is whether the unsigned edge was admitted before the feed was read."""

    @classmethod
    def setUpClass(cls):
        cls.f = json.loads((ROOT / "sdk" / "testdata" / "federation-edge-window.json").read_text())

    def decide(self, window, **kw):
        from unittest import mock
        f = self.f
        member = {"revocation_feed": {"public_key_hex": f["pack"]["public_key_hex"]}}
        bv = {"bundle_authentic": True, "fresh": True, "publisher_matches": None, "members": [member]}
        with mock.patch.object(V, "verify_status_bundle", return_value=bv):
            return V.verify_cross_authority_via_bundle(
                f["pack"], f["_fixture"]["context_id"], [f["manifests"][window]], {},
                now=f["_fixture"]["now"], trusted_anchors=[f["trusted_anchor"]], **kw)

    def test_the_requirement_refuses_the_unsigned_edge_and_keeps_the_signed_one(self):
        self.assertIs(self.decide("unsigned-open")["attestation_signed"], False)
        refused = self.decide("unsigned-open", require_signed_attestation=True)
        self.assertIsNone(refused["attestation_signed"])
        self.assertIn("with a signature by the attesting agency", " ".join(refused["reasons"]))
        self.assertIs(self.decide("open", require_signed_attestation=True)["attestation_signed"], True)


@unittest.skipUnless(V._provider_available("oqs") or _cryptography_mldsa(), "no ML-DSA verifier here")
class ExchangeEdgeSignature(unittest.TestCase):
    """2026-10-15: verify_exchange_request and verify_exchange_receipt counted any edge naming
    the requester's key, so a badly signed edge, or one signed by a key the manifest does not
    anchor, authorized the requester; WIRE-SPEC 3.14 refuses both. sdk/testdata/
    exchange-edge-signature.json holds one exchange and four genuine, fresh manifests that differ
    only in the requester's edge."""

    @classmethod
    def setUpClass(cls):
        cls.f = json.loads((ROOT / "sdk" / "testdata" / "exchange-edge-signature.json").read_text())

    def verdicts(self, name):
        f, now = self.f, self.f["_fixture"]["now"]
        m = [f["manifests"][name]]
        q = V.verify_exchange_request(f["request"], trusted_manifests=m, now=now)
        r = V.verify_exchange_receipt(f["receipt"], now=now, trusted_manifests=m)
        self.assertTrue(q["request_authentic"] and r["receipt_authentic"], (q["note"], r["note"]))
        return q, r

    def test_a_badly_signed_edge_authorizes_nothing(self):
        for v in self.verdicts("badly-signed"):
            self.assertIs(v["requester_authorized"], False)
            self.assertIsNone(v["attestation_signed"])

    def test_an_edge_signed_by_a_key_the_manifest_does_not_anchor_authorizes_nothing(self):
        for v in self.verdicts("stranger"):
            self.assertIs(v["requester_authorized"], False)
            self.assertIsNone(v["attestation_signed"])

    def test_the_verdict_says_whether_the_edge_was_signed(self):
        """WIRE-SPEC 3.14: a verifier that accepts an unsigned edge MUST report that it did."""
        for name, signed in (("signed", True), ("unsigned", False)):
            q, r = self.verdicts(name)
            self.assertEqual((q["requester_authorized"], q["attestation_signed"]), (True, signed), name)
            self.assertEqual((r["requester_authorized"], r["attestation_signed"]), (True, signed), name)
            self.assertEqual(r["via"], {"agency_id": "B", "name": "Authority B"})


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
        same = V.verify_log_consistency(self.sth(6), self.sth(6), [], issuer_key=self.pk.hex())
        self.assertEqual((same["consistent"], same["fork"]), (True, False), same["note"])
        other = V.merkle_tree_head(["x"] * 6).hex()
        split = V.verify_log_consistency(self.sth(6), self.sth(6, root=other), [], issuer_key=self.pk.hex())
        self.assertEqual((split["consistent"], split["fork"]), (False, True), split["note"])

    def test_a_shrinking_tree_is_a_fork(self):
        v = V.verify_log_consistency(self.sth(9), self.sth(4), [], issuer_key=self.pk.hex())
        self.assertEqual((v["consistent"], v["fork"]), (False, True))
        self.assertIn("SMALLER", v["note"])

    def test_a_rewritten_history_is_a_fork(self):
        rewritten = self.ENTRIES[:2] + ["rewritten"] + self.ENTRIES[3:11]
        head = self.sth(11, root=V.merkle_tree_head(rewritten).hex())
        proof = [h.hex() for h in V.consistency_proof(5, rewritten)]
        v = V.verify_log_consistency(self.sth(5), head, proof, issuer_key=self.pk.hex())
        self.assertEqual((v["consistent"], v["fork"]), (False, True), v["note"])

    def test_heads_from_two_logs_are_not_compared(self):
        v = V.verify_log_consistency(self.sth(5), self.sth(11, log_id="log-2"), self.proof(5, 11),
                                     issuer_key=self.pk.hex())
        self.assertEqual((v["consistent"], v["fork"]), (False, False))
        self.assertIn("different logs", v["note"])

    def test_an_inauthentic_head_decides_nothing(self):
        forged = dict(self.sth(11), root_hash_hex=V.merkle_tree_head(["x"] * 11).hex())
        v = V.verify_log_consistency(self.sth(5), forged, self.proof(5, 11), issuer_key=self.pk.hex())
        self.assertEqual((v["consistent"], v["fork"]), (False, False))
        self.assertIn("not authentic", v["note"])

    def test_a_head_from_another_key_is_refused_when_a_key_is_expected(self):
        foreign = self.sth(11, sign=self.other_sign, pk=self.other_pk)
        v = V.verify_log_consistency(self.sth(5), foreign, self.proof(5, 11), issuer_key=self.pk.hex())
        self.assertFalse(v["consistent"])
        self.assertIn("expected log key", v["note"])

    def test_a_stranger_s_newer_head_with_no_log_key_is_not_consistent(self):
        # The log's head and a stranger's newer head over the same entries, with a genuine
        # proof between them: only the missing key can refuse it.
        foreign = self.sth(11, sign=self.other_sign, pk=self.other_pk)
        v = V.verify_log_consistency(self.sth(5), foreign, self.proof(5, 11))
        self.assertEqual((v["consistent"], v["fork"]), (False, False))
        self.assertEqual(v["note"], "no log key was named: both heads must be signed by a log key the caller names")

    def test_a_boolean_or_missing_size_is_refused(self):
        for bad in (True, None, -1, "5"):
            with self.subTest(tree_size=bad):
                v = V.verify_log_consistency(self.sth(5), self.sth(11, tree_size=bad), self.proof(5, 11),
                                             issuer_key=self.pk.hex())
                self.assertFalse(v["consistent"])
                self.assertIn("tree_size", v["note"])

    def test_a_proof_that_is_not_hex_is_refused(self):
        v = V.verify_log_consistency(self.sth(5), self.sth(11), ["zz"], issuer_key=self.pk.hex())
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

    def test_a_size_that_is_not_a_whole_number_is_not_authentic(self):
        # Each head is signed, so only its size can refuse it.
        self.assertTrue(V.verify_sth(self.sth(1))["sth_authentic"], "control: the size 1")
        for bad in (True, False, None, -1, "1", 1.0, 1.5, float("inf")):
            with self.subTest(tree_size=repr(bad)):
                v = V.verify_sth(self.sth(1, tree_size=bad))
                self.assertFalse(v["sth_authentic"])
                self.assertEqual(v["note"], "tree_size is not an integer from 0 to 2**53 - 1")



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
        v = V.verify_receipt_inclusion(self.RECEIPTS[2], self.proof(3), self.head(), log_key=self.pk.hex())
        self.assertFalse(v["included"])
        self.assertIn("not for this receipt", v["note"])

    def test_a_head_of_another_log_is_refused(self):
        v = V.verify_receipt_inclusion(self.RECEIPTS[3], self.proof(3), self.head(log_id="another-log"),
                                       log_key=self.pk.hex())
        self.assertFalse(v["included"])
        self.assertIn(V._RECEIPT_LOG_ID, v["note"])

    def test_a_malformed_proof_is_refused_not_raised(self):
        # 2026-09-30: 3.5 and "7" were read by int() as 3 and 7, the genuine index and size,
        # so a proof with a malformed field was included; the SDKs read them otherwise.
        for over in ({"index": float("inf")}, {"index": "three"}, {"proof_hex": ["zz"]},
                     {"index": 3.5}, {"tree_size": "7"}, {"index": True}, {"proof_hex": "00"}):
            with self.subTest(**{k: str(v) for k, v in over.items()}):
                v = V.verify_receipt_inclusion(self.RECEIPTS[3], self.proof(3, **over), self.head(),
                                               log_key=self.pk.hex())
                self.assertFalse(v["included"])
                self.assertEqual(v["note"], "malformed proof")

    def test_a_head_signed_with_a_size_of_true_or_a_float_includes_nothing(self):
        # Read by `!=`, a signed `true` was the size 1, and `7.0` was 7. Each proof is first
        # included under the same head with its genuine size, so only the size refuses it.
        one = V.merkle_tree_head(self.hashes[:1]).hex()
        for idx, size, root, bad in ((0, 1, one, True), (0, 1, one, 1.0), (3, 7, self.root, 7.0)):
            proof = self.proof(idx, tree_size=size, root_hash_hex=root,
                               proof_hex=[x.hex() for x in V.inclusion_proof(idx, self.hashes[:size])])
            with self.subTest(tree_size=repr(bad)):
                genuine = V.verify_receipt_inclusion(self.RECEIPTS[idx], proof,
                                                     self.head(tree_size=size, root_hash_hex=root),
                                                     log_key=self.pk.hex())
                self.assertTrue(genuine["included"], genuine["note"])
                v = V.verify_receipt_inclusion(self.RECEIPTS[idx], proof,
                                               self.head(tree_size=bad, root_hash_hex=root),
                                               log_key=self.pk.hex())
                self.assertFalse(v["included"])
                self.assertEqual(v["note"], "tree_size is not an integer from 0 to 2**53 - 1")

    def test_a_proof_and_head_of_different_trees_are_refused(self):
        v = V.verify_receipt_inclusion(self.RECEIPTS[3], self.proof(3, tree_size=6), self.head(),
                                       log_key=self.pk.hex())
        self.assertFalse(v["included"])
        self.assertIn("different trees", v["note"])

    def test_an_inauthentic_head_is_refused(self):
        altered = dict(self.head(), timestamp="2026-10-01T00:00:00Z")
        v = V.verify_receipt_inclusion(self.RECEIPTS[3], self.proof(3), altered, log_key=self.pk.hex())
        self.assertFalse(v["included"])
        self.assertFalse(v["sth_authentic"])

    def test_a_head_from_another_key_is_refused_when_a_key_is_expected(self):
        v = V.verify_receipt_inclusion(self.RECEIPTS[3], self.proof(3),
                                       self.head(sign=self.other_sign, pk=self.other_pk),
                                       log_key=self.pk.hex())
        self.assertFalse(v["included"])
        self.assertIn("expected log key", v["note"])

    def test_a_stranger_s_head_with_no_log_key_includes_nothing(self):
        v = V.verify_receipt_inclusion(self.RECEIPTS[3], self.proof(3),
                                       self.head(sign=self.other_sign, pk=self.other_pk))
        self.assertTrue(v["sth_authentic"], "control: the stranger's head is authentic under its own key")
        self.assertFalse(v["included"])
        self.assertEqual(v["note"], _NO_LOG_KEY)

    def test_the_log_s_own_head_with_no_log_key_includes_nothing(self):
        v = V.verify_receipt_inclusion(self.RECEIPTS[3], self.proof(3), self.head())
        self.assertFalse(v["included"])
        self.assertEqual(v["note"], _NO_LOG_KEY)

    def test_a_path_that_does_not_rebuild_the_head_is_refused(self):
        v = V.verify_receipt_inclusion(self.RECEIPTS[3], self.proof(3, index=4), self.head(), log_key=self.pk.hex())
        self.assertFalse(v["included"])
        self.assertIn("does not reconstruct", v["note"])

    def test_anything_but_three_objects_is_refused(self):
        v = V.verify_receipt_inclusion("receipt", self.proof(3), self.head(), log_key=self.pk.hex())
        self.assertFalse(v["included"])
        self.assertIn("must be objects", v["note"])


@unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
class SectionOneIntegersAreReadByTheirRule(unittest.TestCase):
    """Each WIRE-SPEC section 1 count, size and proof index at every reader, under `true`, `1.0`,
    `"1"`, null and -1, each beside the integer it stands for (2026-10-21).

    Two kinds, two rules. A count or size a signature covers (a tree head's or a cosignature's
    `tree_size`, `revoked_count`, `member_count`, `leaf_count`) refuses all five. An inclusion
    proof's `index` and `tree_size`, and a publication receipt's `leaf_index` and `tree_size`, are
    not signed, and `1.0` there is 1: JavaScript's JSON.parse reads it so, a TypeScript verifier
    cannot see it, and refusing it here alone would give one proof two verdicts. Every artifact is
    signed for real, so only the value under test can refuse it, and a refusal is a verdict with
    its note, never an exception.
    """

    FIVE = (True, 1.0, "1", None, -1)
    NOW = "2026-10-20T12:00:00Z"
    WINDOW = {"issued_at": "2026-10-20T00:00:00Z", "expires_at": "2026-10-21T00:00:00Z"}
    LEAF = "ab" * 32
    MEMBER = {"authority": {"agency_id": 2}, "label": "member"}
    OTHER_HEAD = "polaris-published-head/1|another-log|1|" + "aa" * 32
    RECEIPTS = [{"format": "polaris-exchange-receipt/1", "requester": "agency-a", "responder": "agency-b",
                 "context_id": 1, "request_hash": "%064x" % i, "response_hash": "%064x" % (100 + i),
                 "authorized_via": "trust-edge", "occurred_at": "2026-09-30T00:00:%02dZ" % i,
                 "algorithm": "ML-DSA-65"} for i in range(2)]

    @classmethod
    def setUpClass(cls):
        cls.log, cls.witness, cls.ledger, cls.authority = (_mldsa_signer() for _ in range(4))
        cls.ts = json.loads((ROOT / "conformance" / "vectors" / "timestamp-anchor-variants-base.json").read_text())
        cls.ts_hash = V.timestamp_hash(cls.ts)
        cls.receipt_hashes = [V.receipt_hash(r) for r in cls.RECEIPTS]

    @staticmethod
    def signed(obj, canonical, signer):
        sign, pk = signer
        obj = dict(obj, algorithm=V._ALG, public_key_hex=pk.hex())
        obj["signature_hex"] = sign(hashlib.sha3_256(canonical(obj)).digest()).hex()
        return obj

    def head(self, size, entries, log_id, signer=None):
        return self.signed({"format": V._STH_FORMAT, "log_id": log_id, "tree_size": size,
                            "root_hash_hex": V.merkle_tree_head(entries).hex(),
                            "timestamp": "2026-10-20T00:00:00Z"}, V._sth_canonical, signer or self.log)

    def decide(self, v, key, want):
        """`want` is True (accepted) or the note the refusal carries."""
        if want is True:
            self.assertIs(v[key], True, v["note"])
        else:
            self.assertIs(v[key], False)
            self.assertEqual(v["note"], want)

    # -- signed: all five refused --------------------------------------------------------

    def test_a_cosignature_whose_size_is_not_an_integer_witnesses_nothing(self):
        # One reader serves the witnessed checkpoint and the timestamp anchor's witnesses. By `==`
        # alone a witness's signed `true` was the size 1 and `1.0` was 1, and each one counted.
        entries, trusted = [self.ts_hash], [self.witness[1].hex()]
        head = self.head(1, entries, V._TIMESTAMP_LOG_ID)

        def both(size):
            cos = [self.signed({"format": V._COSIGNATURE_FORMAT, "log_id": V._TIMESTAMP_LOG_ID, "tree_size": size,
                                "root_hash_hex": V.merkle_tree_head(entries).hex()},
                               V._cosignature_canonical, self.witness)]
            wc = V.verify_witnessed_checkpoint(head, cos, trusted, threshold=1, issuer_key=self.log[1].hex())
            ta = V.verify_timestamp_anchor(self.anchored(0, 1, 1, entries, cos), log_key=self.log[1].hex(),
                                           trusted_witnesses=trusted, threshold=1)
            self.assertIs(ta["anchored"], True, ta["note"])
            return wc, ta

        wc, ta = both(1)
        self.assertEqual((wc["witnessed"], wc["cosigner_count"], ta["witnessed"]), (True, 1, True), "control: 1")
        for size in self.FIVE:
            with self.subTest(tree_size=repr(size)):
                for v in both(size):
                    self.assertEqual((v["witnessed"], v["cosigner_count"]), (False, 0))
                    self.assertEqual(v["note"], "only 0 trusted witness cosignature(s), need 1")

    def test_a_cosignature_checked_alone_is_held_to_its_size(self):
        # verify_cosignature read no size and left it to verify_witnessed_checkpoint, so a
        # witness's cosignature checked alone was authentic at each size below. Each is signed for
        # real, so only the size refuses it.
        top, root = V._MAX_SAFE_INTEGER, V.merkle_tree_head([self.ts_hash]).hex()

        def alone(size):
            return V.verify_cosignature(self.signed({"format": V._COSIGNATURE_FORMAT, "log_id": V._TIMESTAMP_LOG_ID,
                                                     "tree_size": size, "root_hash_hex": root},
                                                    V._cosignature_canonical, self.witness))
        for size in (1, top):
            with self.subTest(tree_size=size):
                self.decide(alone(size), "cosignature_authentic", True)
        for size in self.FIVE + (1.5, top + 1, top + 2, top + 3, 10 ** 20):
            with self.subTest(tree_size=repr(size)):
                self.decide(alone(size), "cosignature_authentic",
                            "the cosignature's tree_size is not an integer from 0 to 2**53 - 1")

    def test_a_revoked_count_that_is_not_an_integer_is_refused(self):
        def feed(count):
            return self.signed(dict(self.WINDOW, format="polaris-revocation-feed/1",
                                    authority={"agency_id": 1, "name": "A"}, epoch_number=1,
                                    as_of="2026-10-20T00:00:00Z", revoked_root_hex=V.revoked_root([self.LEAF]),
                                    revoked_count=count, revoked_leaves=[self.LEAF]),
                               V._revocation_feed_canonical, self.authority)
        self.decide(V.verify_revocation_feed(feed(1), now=self.NOW), "feed_authentic", True)
        for count in self.FIVE:
            with self.subTest(revoked_count=repr(count)):
                self.decide(V.verify_revocation_feed(feed(count), now=self.NOW), "feed_authentic",
                            "the revoked-set commitment does not match the listed leaves")

    def test_a_member_count_that_is_not_an_integer_is_refused(self):
        def bundle(count):
            return self.signed(dict(self.WINDOW, format="polaris-federation-status-bundle/1",
                                    publisher={"agency_id": 9, "name": "P"}, members=[self.MEMBER],
                                    members_root_hex=V.bundle_members_root([self.MEMBER]), member_count=count),
                               V._status_bundle_canonical, self.authority)
        self.decide(V.verify_status_bundle(bundle(1), now=self.NOW), "bundle_authentic", True)
        for count in self.FIVE:
            with self.subTest(member_count=repr(count)):
                self.decide(V.verify_status_bundle(bundle(count), now=self.NOW), "bundle_authentic",
                            "the members_root does not match the embedded members (the set was tampered)")

    def test_a_leaf_count_that_is_not_an_integer_is_refused(self):
        def leaves(count):
            return self.signed(dict(self.WINDOW, format="polaris-epoch-leaves/1", authority={"agency_id": 1},
                                    epoch_id=1, context_id=1, merkle_root="cd" * 32, leaf_count=count,
                                    all_leaves_hex=[self.LEAF], leaves_root_hex=V._leaves_root([self.LEAF])),
                               V._epoch_leaves_canonical, self.authority)
        self.decide(V.verify_epoch_leaves(leaves(1), now=self.NOW), "leaves_authentic", True)
        for count in self.FIVE:
            with self.subTest(leaf_count=repr(count)):
                self.decide(V.verify_epoch_leaves(leaves(count), now=self.NOW), "leaves_authentic",
                            "the published leaf count does not match the signed one")

    def test_a_log_head_whose_size_is_not_an_integer_is_not_published(self):
        # verify_publication runs verify_sth on the ledger's head only, and writes the log head's
        # size into the ledger entry with "%s": a size of "1" wrote the integer head's entry, and
        # a ledger holding a head's own spelling ("True", "1.0", "None", "-1") published all five.
        self.decide(self.publication(1, 1, 1, recorded=1), "published", True)
        for size in self.FIVE:
            for recorded in (size, 1):
                with self.subTest(tree_size=repr(size), ledger_holds=repr(recorded)):
                    self.decide(self.publication(size, size, 1, recorded=recorded), "published",
                                "the log head's tree_size is not an integer from 0 to 2**53 - 1")

    # -- signed: the bound, 0 to 2**53 - 1 ------------------------------------------------

    def test_a_signed_size_past_2_53_minus_1_is_refused_by_the_rule(self):
        # JSON.parse reads 2**53 + 1 as 2**53, so the TypeScript SDK computed other canonical
        # bytes for a head of that size, and one head had two verdicts. Every head here is signed
        # for real, so only the rule refuses it. A cosignature's own size is held to the bound in
        # test_a_cosignature_checked_alone_is_held_to_its_size, and a signed count must equal a
        # list's length, which no list reaches; the rule they share is held at its bound below.
        top = V._MAX_SAFE_INTEGER
        self.assertEqual(top, 2 ** 53 - 1)
        for size in (1, top, top + 1, top + 2):
            self.assertIs(V._signed_count(size), size <= top, size)
        entries, trusted = [self.ts_hash], [self.witness[1].hex()]
        for size in (1, top):
            with self.subTest(size=size):
                head = self.head(size, entries, V._TIMESTAMP_LOG_ID)
                self.decide(V.verify_sth(head, self.log[1].hex()), "sth_authentic", True)
                cos = [self.signed({"format": V._COSIGNATURE_FORMAT, "log_id": V._TIMESTAMP_LOG_ID,
                                    "tree_size": size, "root_hash_hex": V.merkle_tree_head(entries).hex()},
                                   V._cosignature_canonical, self.witness)]
                wc = V.verify_witnessed_checkpoint(head, cos, trusted, threshold=1, issuer_key=self.log[1].hex())
                self.assertEqual((wc["witnessed"], wc["cosigner_count"]), (True, 1), wc["note"])
                self.assertIs(V.verify_log_consistency(head, head, [], self.log[1].hex())["consistent"], True)
                self.decide(self.publication(size, size, 1, recorded=size), "published", True)
        for size in (top + 1, top + 2):
            with self.subTest(size=size):
                head = self.head(size, entries, V._TIMESTAMP_LOG_ID)
                self.decide(V.verify_sth(head, self.log[1].hex()), "sth_authentic",
                            "tree_size is not an integer from 0 to 2**53 - 1")
                self.assertEqual(V.verify_log_consistency(head, head, [], self.log[1].hex())["note"],
                                 "an STH is not authentic (tree_size is not an integer from 0 to 2**53 - 1)")
                self.decide(self.publication(size, size, 1, recorded=size), "published",
                            "the log head's tree_size is not an integer from 0 to 2**53 - 1")

    # -- unsigned: read by _wire_int, so 1.0 is 1 ------------------------------------------

    def test_inclusion_reads_its_index_and_size_by_one_rule_and_never_raises(self):
        # Called as a library, `true` was 1, and "1", null and an index of 1.0 or 1.5 raised.
        two, one = ["e0", "e1"], ["e0"]
        root2, path, leaf1 = V.merkle_tree_head(two), V.inclusion_proof(1, two), V._lh("e1")
        root1, leaf0 = V.merkle_tree_head(one), V._lh("e0")
        self.assertIs(V.verify_inclusion(1, 2, leaf1, root2, path), True, "control: the index 1")
        self.assertIs(V.verify_inclusion(0, 1, leaf0, root1, []), True, "control: the size 1")
        for value, accepted in ((True, False),
                                (1.0, True),  # 1.0 is 1: JSON.parse reads it so, and TypeScript cannot refuse it
                                ("1", False), (None, False), (-1, False), (1.5, False), (10 ** 400, False)):
            with self.subTest(index=repr(value)[:12]):
                self.assertIs(V.verify_inclusion(value, 2, leaf1, root2, path), accepted)
            with self.subTest(tree_size=repr(value)[:12]):
                self.assertIs(V.verify_inclusion(0, value, leaf0, root1, []), accepted)

    def test_consistency_reads_its_sizes_by_one_rule_and_never_raises(self):
        # Called as a library, `true` was 1, and "1", null and 1.0 raised.
        three = ["e0", "e1", "e2"]
        root1, root3, proof = V.merkle_tree_head(three[:1]), V.merkle_tree_head(three), V.consistency_proof(1, three)
        self.assertIs(V.verify_consistency(1, 3, root1, root3, proof), True, "control: the old size 1")
        self.assertIs(V.verify_consistency(0, 1, root1, root1, []), True, "control: the new size 1")
        for value, accepted in ((True, False),
                                (1.0, True),  # 1.0 is 1, as verify_inclusion reads it
                                ("1", False), (None, False), (-1, False), (1.5, False), (10 ** 400, False)):
            with self.subTest(old_size=repr(value)[:12]):
                self.assertIs(V.verify_consistency(value, 3, root1, root3, proof), accepted)
            with self.subTest(new_size=repr(value)[:12]):
                self.assertIs(V.verify_consistency(0, value, root1, root1, []), accepted)

    def publication(self, log_size, receipt_size, leaf_index, recorded):
        """verify_publication of a log head of `log_size`, under a ledger that holds another head's
        entry and then the entry of a head of size `recorded`."""
        root = V.merkle_tree_head([self.ts_hash]).hex()
        entries = [self.OTHER_HEAD, V._publication_entry(V._TIMESTAMP_LOG_ID, recorded, root)]
        receipt = {"format": V._PUBLICATION_FORMAT, "log_id": V._TIMESTAMP_LOG_ID, "tree_size": receipt_size,
                   "root_hash_hex": root, "ledger_sth": self.head(2, entries, "polaris-ledger", self.ledger),
                   "leaf_index": leaf_index, "inclusion_proof_hex": [x.hex() for x in V.inclusion_proof(1, entries)]}
        return V.verify_publication(self.head(log_size, [self.ts_hash], V._TIMESTAMP_LOG_ID), receipt,
                                    self.ledger[1].hex())

    def test_a_publication_receipt_size_that_is_not_an_integer_binds_no_head(self):
        # The receipt is unsigned. By `!=` alone its `true` was the size 1 and bound the head.
        unbound = "the receipt does not bind to this log head"
        self.decide(self.publication(1, 1, 1, recorded=1), "published", True)
        for size, want in ((True, unbound),
                           (1.0, True),  # 1.0 is 1: JSON.parse reads it so, and TypeScript cannot refuse it
                           ("1", unbound), (None, unbound), (-1, unbound), (10 ** 400, unbound)):
            with self.subTest(tree_size=repr(size)[:12]):
                self.decide(self.publication(1, size, 1, recorded=1), "published", want)

    def test_a_publication_receipt_leaf_index_that_is_not_an_integer_places_nothing(self):
        malformed = "the receipt's leaf_index, proof, or ledger root is malformed"
        self.decide(self.publication(1, 1, 1, recorded=1), "published", True)
        for index, want in ((True, malformed),
                            (1.0, True),  # 1.0 is 1: JSON.parse reads it so, and TypeScript cannot refuse it
                            ("1", malformed), (None, malformed),
                            (-1, "the inclusion proof does not place this head in the ledger")):
            with self.subTest(leaf_index=repr(index)):
                self.decide(self.publication(1, 1, index, recorded=1), "published", want)

    def receipt_inclusion(self, index, proof_size, head_size, n):
        """verify_receipt_inclusion of the last of `n` receipts in a log of `n`."""
        hashes, at = self.receipt_hashes[:n], n - 1
        proof = {"entry_hex": hashes[at], "index": index, "tree_size": proof_size,
                 "root_hash_hex": V.merkle_tree_head(hashes).hex(),
                 "proof_hex": [x.hex() for x in V.inclusion_proof(at, hashes)]}
        return V.verify_receipt_inclusion(self.RECEIPTS[at], proof, self.head(head_size, hashes, V._RECEIPT_LOG_ID),
                                          log_key=self.log[1].hex())

    def test_a_receipt_inclusion_proof_or_head_size_that_is_not_an_integer_includes_nothing(self):
        # The head is signed (verify_sth refuses all five); the proof is not (1.0 is 1).
        malformed, apart = "malformed proof", "the proof and the head describe different trees"
        self.decide(self.receipt_inclusion(1, 2, 2, n=2), "included", True)
        self.decide(self.receipt_inclusion(0, 1, 1, n=1), "included", True)
        for index, want in ((True, malformed),
                            (1.0, True),  # 1.0 is 1: JSON.parse reads it so, and TypeScript cannot refuse it
                            ("1", malformed), (None, malformed),
                            (-1, "the inclusion proof does not reconstruct the head")):
            with self.subTest(index=repr(index)):
                self.decide(self.receipt_inclusion(index, 2, 2, n=2), "included", want)
        for size, want in ((True, malformed),
                           (1.0, True),  # 1.0 is 1: JSON.parse reads it so, and TypeScript cannot refuse it
                           ("1", malformed), (None, malformed), (-1, apart)):
            with self.subTest(proof_tree_size=repr(size)):
                self.decide(self.receipt_inclusion(0, size, 1, n=1), "included", want)
        for size, want in ((True, "tree_size is not an integer from 0 to 2**53 - 1"),
                           (1.0, "tree_size is not an integer from 0 to 2**53 - 1"), ("1", apart), (None, apart), (-1, apart)):
            with self.subTest(head_tree_size=repr(size)):
                v = self.receipt_inclusion(0, 1, size, n=1)
                self.decide(v, "included", want)
                self.assertIs(v["sth_authentic"], False)

    def anchored(self, index, proof_size, head_size, entries, cosignatures=None):
        """The published timestamp, anchored in a log of `entries` under a head of `head_size`."""
        t = json.loads(json.dumps(self.ts))
        root, at = V.merkle_tree_head(entries).hex(), entries.index(self.ts_hash)
        t["anchor"] = {"log_id": V._TIMESTAMP_LOG_ID, "timestamp_hash": self.ts_hash,
                       "sth": self.head(head_size, entries, V._TIMESTAMP_LOG_ID),
                       "proof": {"entry_hex": self.ts_hash, "index": index, "log_id": V._TIMESTAMP_LOG_ID,
                                 "tree_size": proof_size, "root_hash_hex": root,
                                 "proof_hex": [x.hex() for x in V.inclusion_proof(at, entries)]}}
        if cosignatures is not None:
            t["anchor"]["cosignatures"] = cosignatures
        return t

    def test_a_timestamp_anchor_proof_or_head_size_that_is_not_an_integer_anchors_nothing(self):
        malformed, apart = "malformed proof", "the proof and the head describe different trees"
        two, one, key = ["00" * 32, self.ts_hash], [self.ts_hash], self.log[1].hex()

        def anchor(index, proof_size, head_size, entries):
            return V.verify_timestamp_anchor(self.anchored(index, proof_size, head_size, entries), log_key=key)
        self.decide(anchor(1, 2, 2, two), "anchored", True)
        self.decide(anchor(0, 1, 1, one), "anchored", True)
        for index, want in ((True, malformed),
                            (1.0, True),  # 1.0 is 1: JSON.parse reads it so, and TypeScript cannot refuse it
                            ("1", malformed), (None, malformed),
                            (-1, "the inclusion proof does not reconstruct the head")):
            with self.subTest(index=repr(index)):
                self.decide(anchor(index, 2, 2, two), "anchored", want)
        for size, want in ((True, malformed),
                           (1.0, True),  # 1.0 is 1: JSON.parse reads it so, and TypeScript cannot refuse it
                           ("1", malformed), (None, malformed), (-1, apart)):
            with self.subTest(proof_tree_size=repr(size)):
                self.decide(anchor(0, size, 1, one), "anchored", want)
        for size, want in ((True, "tree_size is not an integer from 0 to 2**53 - 1"),
                           (1.0, "tree_size is not an integer from 0 to 2**53 - 1"), ("1", apart), (None, apart), (-1, apart)):
            with self.subTest(head_tree_size=repr(size)):
                v = anchor(0, 1, size, one)
                self.decide(v, "anchored", want)
                self.assertIs(v["sth_authentic"], False)


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



@unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
class AnEpochCheckpointIsComparedOnlyOnceItVerifies(unittest.TestCase):
    """2026-10-21: verify_epoch_leaves compared the bundle's merkle_root with the root of whatever
    dict it was handed as the epoch checkpoint and verified nothing, so a dict of another format
    with a signature of 00, or a bare {merkle_root}, gave epoch_matches True. The published
    vectors: the bundle epoch-leaves-valid, and the checkpoint epoch-checkpoint-valid, which names
    another root under another key."""

    @classmethod
    def setUpClass(cls):
        def vector(name):
            return json.loads((ROOT / "conformance" / "vectors" / (name + ".json")).read_text())
        cls.bundle, cls.cp = vector("epoch-leaves-valid"), vector("epoch-checkpoint-valid")
        cls.now = cls.bundle["issued_at"]

    def compared(self, bundle, checkpoint, **kw):
        return V.verify_epoch_leaves(bundle, now=self.now, epoch_checkpoint=checkpoint, **kw)

    def signed(self, sign, pk, bundle_root=None):
        """A fresh bundle and a checkpoint naming its root, each signed by `sign`."""
        b = dict(self.bundle, public_key_hex=pk.hex())
        b["signature_hex"] = sign(hashlib.sha3_256(V._epoch_leaves_canonical(b)).digest()).hex()
        cp = dict(self.cp, epoch=dict(self.cp["epoch"], root_hex=bundle_root or b["merkle_root"]),
                  public_key_hex=pk.hex())
        cp["signature_hex"] = sign(hashlib.sha3_256(V._epoch_checkpoint_canonical(cp)).digest()).hex()
        return b, cp

    def test_a_dict_that_does_not_verify_as_a_checkpoint_is_not_compared(self):
        root, key = self.bundle["merkle_root"], self.bundle["public_key_hex"]
        for label, forged in (
                ("another format, a signature of 00", {"format": "not-a-checkpoint", "merkle_root": root,
                                                       "signature_hex": "00", "public_key_hex": "00",
                                                       "algorithm": "ML-DSA-65"}),
                ("a bare merkle_root", {"merkle_root": root}),
                ("the bundle's key, a signature that does not verify",
                 dict(self.cp, epoch=dict(self.cp["epoch"], root_hex=root), public_key_hex=key))):
            with self.subTest(label):
                v = self.compared(self.bundle, forged)
                self.assertEqual((v["leaves_authentic"], v["epoch_matches"]), (True, None), v["note"])
                self.assertIn("the epoch checkpoint does not verify", v["note"])

    def test_a_checkpoint_signed_by_a_key_nobody_named_is_not_compared(self):
        v = self.compared(self.bundle, self.cp)
        self.assertIsNone(v["epoch_matches"])
        self.assertIn("signed by neither the bundle's key nor a trust anchor", v["note"])
        b, _ = self.signed(*_mldsa_signer())
        _, stranger = self.signed(*_mldsa_signer(), bundle_root=b["merkle_root"])
        self.assertIsNone(self.compared(b, stranger)["epoch_matches"], "a stranger's checkpoint naming the same root")

    def test_a_root_beside_the_checkpoint_signature_is_not_read(self):
        """A checkpoint signs its root inside `epoch`; a `merkle_root` beside it was read when the
        signed epoch named none."""
        sign, pk = _mldsa_signer()
        b, cp = self.signed(sign, pk)
        rootless = dict(cp, epoch={k: x for k, x in cp["epoch"].items() if k != "root_hex"})
        rootless["signature_hex"] = sign(hashlib.sha3_256(V._epoch_checkpoint_canonical(rootless)).digest()).hex()
        v = self.compared(b, dict(rootless, merkle_root=b["merkle_root"]))
        self.assertIs(v["epoch_matches"], False, v["note"])

    def test_control_the_published_checkpoint_names_another_root(self):
        v = self.compared(self.bundle, self.cp, anchor_keys=[self.bundle["public_key_hex"], self.cp["public_key_hex"]])
        self.assertEqual((v["issuer_trusted"], v["epoch_matches"]), (True, False))
        self.assertEqual(v["note"], "the bundle names a different epoch root than the published checkpoint")

    def test_control_a_checkpoint_under_the_bundles_key_or_an_anchor_is_compared(self):
        b, cp = self.signed(*_mldsa_signer())
        v = self.compared(b, cp)
        self.assertEqual((v["leaves_authentic"], v["epoch_matches"], v["note"]), (True, True, None))
        sign, pk = _mldsa_signer()
        _, other = self.signed(sign, pk, bundle_root=b["merkle_root"])
        self.assertIs(self.compared(b, other, anchor_keys=[pk.hex()])["epoch_matches"], True,
                      "a checkpoint under a key the caller trusts")


@unittest.skipUnless(_cryptography_mldsa(), "cryptography without ML-DSA")
class AMintIsUnderTheSetItsKeyLengthIdentifies(unittest.TestCase):
    """WIRE-SPEC 3.8.1: the mint statement does not sign `algorithm`. Present, it must name an
    accepted set; absent, the mint is under the accepted set whose public-key length its key
    has, as the instance's mint route reads it (scripts/polaris-federation-instances-drill.py
    mints with no `algorithm`)."""

    BODY = {"format": "polaris-exchange-mint/1", "requester_public_key_hex": "ab" * 1952, "context_id": 1,
            "request_hash": "cd" * 32, "response_hash": "ef" * 32, "responder_agency_id": 1,
            "occurred_at": "2026-05-01T00:00:00Z"}

    @classmethod
    def mint(cls, sk):
        out = dict(cls.BODY)
        out["signature_hex"] = sk.sign(hashlib.sha3_256(V._exchange_mint_canonical(out)).digest()).hex()
        out["public_key_hex"] = sk.public_key().public_bytes_raw().hex()
        return out

    def test_no_label_is_the_set_the_key_length_identifies(self):
        from cryptography.hazmat.primitives.asymmetric import mldsa
        m65 = self.mint(mldsa.MLDSA65PrivateKey.generate())
        self.assertNotIn("algorithm", m65)
        v = V.verify_exchange_mint(m65)
        self.assertIs(v["mint_authentic"], True, v["note"])
        self.assertIs(V.verify_exchange_mint(dict(m65, algorithm=None))["mint_authentic"], True, "null is no label")
        if not hasattr(mldsa, "MLDSA87PrivateKey"):
            self.skipTest("cryptography without ML-DSA-87: the 87 case is not measured here")
        v = V.verify_exchange_mint(self.mint(mldsa.MLDSA87PrivateKey.generate()))
        self.assertIs(v["mint_authentic"], True, v["note"])

    def test_a_label_outside_the_set_or_a_key_no_set_fits_refuses(self):
        from cryptography.hazmat.primitives.asymmetric import mldsa
        m65 = self.mint(mldsa.MLDSA65PrivateKey.generate())
        for label, bad in (("a label outside the accepted set", dict(m65, algorithm="ML-DSA-44")),
                           ("a label the key does not fit", dict(m65, algorithm="ML-DSA-87")),
                           ("a key no accepted set fits", dict(m65, public_key_hex="ab" * 1000))):
            with self.subTest(label):
                v = V.verify_exchange_mint(bad)
                self.assertIs(v["mint_authentic"], False)
                self.assertTrue(v["note"], label)


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
