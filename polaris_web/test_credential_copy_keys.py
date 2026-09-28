"""test_credential_copy_keys.py: the ES256 keys wallet copies are signed with (005 S2).

Every refusal credential_copy_keys.py makes has a test that builds exactly the chain it refuses,
so removing a refusal turns a test red. The well-formed cases are verified the way a wallet
would verify them: from the x5c header alone, with no access to the module's key object.

Run: python3 -m unittest test_credential_copy_keys
"""

import base64
import datetime
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import credential_copy_keys as cck

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

_REPO = pathlib.Path(__file__).resolve().parent.parent
_SCRIPT = _REPO / "scripts" / "polaris-credential-copy-test-pki.py"
_URL = "https://polaris.test/api/v1/oid4vci/7"
_NOW = datetime.datetime.now(datetime.timezone.utc)
_DAY = datetime.timedelta(days=1)


def _usage(**on):
    names = ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
             "key_agreement", "key_cert_sign", "crl_sign", "encipher_only", "decipher_only")
    return x509.KeyUsage(**{n: on.get(n, False) for n in names})


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject_key, subject, issuer_key, issuer, ca, usage=None, start=None, end=None,
          san=True):
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
         .public_key(subject_key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(start or _NOW - _DAY).not_valid_after(end or _NOW + 30 * _DAY))
    if ca is not None:
        b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    if usage is not None:
        b = b.add_extension(usage, critical=True)
    if san and not ca:
        b = b.add_extension(x509.SubjectAlternativeName(
            [x509.UniformResourceIdentifier(_URL), x509.DNSName("polaris.test")]), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def _pem(*certs):
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def _key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


class _Pki:
    """A root, an intermediate and a leaf, all well formed; tests break one thing at a time."""

    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root = _cert(self.root_key, "root", self.root_key, "root", True,
                          _usage(key_cert_sign=True, crl_sign=True))
        self.mid_key = ec.generate_private_key(ec.SECP256R1())
        self.mid = _cert(self.mid_key, "mid", self.root_key, "root", True,
                         _usage(key_cert_sign=True, crl_sign=True))
        self.leaf_key = ec.generate_private_key(ec.SECP256R1())
        self.leaf = self.leaf_signed_by(self.root_key, "root")

    def leaf_signed_by(self, issuer_key, issuer, **kw):
        kw.setdefault("usage", _usage(digital_signature=True))
        kw.setdefault("ca", False)
        return _cert(self.leaf_key, "wallet-copy issuer", issuer_key, issuer, **kw)


class _Dir(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._tmp.name)
        self.pki = _Pki()
        cck.reset()

    def tearDown(self):
        cck.reset()
        self._tmp.cleanup()

    def write(self, chain_pem, key=None, mode=0o600, agency="7"):
        key_path = self.dir / ("%s.key.pem" % agency)
        chain_path = self.dir / ("%s.chain.pem" % agency)
        if key_path.exists():
            key_path.chmod(0o600)
        key_path.write_bytes(_key_pem(key or self.pki.leaf_key))
        key_path.chmod(mode)
        chain_path.write_bytes(chain_pem)
        return str(key_path), str(chain_path)

    def load(self, chain_pem, **kw):
        return cck.load_from_files(7, *self.write(chain_pem, **kw))

    def refused(self, fragment, chain_pem, **kw):
        with self.assertRaises(cck.CopyKeyError) as caught:
            self.load(chain_pem, **kw)
        self.assertIn(fragment, str(caught.exception))
        self.assertTrue(caught.exception.configured)


def _verify_as_a_wallet(jws: str) -> bool:
    """Verify a compact JWS the way a wallet does: the key comes from x5c[0] and nowhere else."""
    header_b64, payload_b64, sig_b64 = jws.split(".")
    pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
    header = json.loads(base64.urlsafe_b64decode(pad(header_b64)))
    leaf = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][0]))
    raw = base64.urlsafe_b64decode(pad(sig_b64))
    der = utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    try:
        leaf.public_key().verify(der, ("%s.%s" % (header_b64, payload_b64)).encode(),
                                 ec.ECDSA(hashes.SHA256()))
    except Exception:  # noqa: BLE001
        return False
    return True


def _jws(key, payload: dict) -> str:
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
    header = {"alg": "ES256", "typ": "dc+sd-jwt", "x5c": list(key.x5c)}
    signing_input = "%s.%s" % (b64(json.dumps(header).encode()), b64(json.dumps(payload).encode()))
    return "%s.%s" % (signing_input, b64(key.sign(signing_input.encode())))


class WellFormedTests(_Dir):
    def test_a_leaf_under_a_registered_root_signs_what_a_wallet_verifies(self):
        key = self.load(_pem(self.pki.leaf))
        jws = _jws(key, {"iss": _URL, "vct": "urn:polaris:wallet-copy:1"})
        self.assertTrue(_verify_as_a_wallet(jws))
        tampered = jws.split(".")
        tampered[1] = tampered[1][:-2] + ("AA" if tampered[1][-2:] != "AA" else "BB")
        self.assertFalse(_verify_as_a_wallet(".".join(tampered)))
        self.assertEqual(len(key.x5c), 1)
        self.assertEqual(base64.b64decode(key.x5c[0]),
                         self.pki.leaf.public_bytes(serialization.Encoding.DER))

    def test_a_chain_through_an_intermediate_carries_both_and_not_the_root(self):
        self.pki.leaf = self.pki.leaf_signed_by(self.pki.mid_key, "mid")
        key = self.load(_pem(self.pki.leaf, self.pki.mid))
        self.assertEqual(len(key.x5c), 2)
        self.assertTrue(_verify_as_a_wallet(_jws(key, {"iss": _URL})))

    def test_the_leaf_names_its_issuer_and_no_other(self):
        key = self.load(_pem(self.pki.leaf))
        self.assertTrue(key.names_issuer(_URL))
        self.assertFalse(key.names_issuer("https://polaris.test/api/v1/oid4vci/8"))
        self.assertFalse(key.names_issuer("https://evil.test/api/v1/oid4vci/7"))

    def test_describe_says_nothing_secret(self):
        key = self.load(_pem(self.pki.leaf))
        facts = json.dumps(key.describe())
        self.assertNotIn("PRIVATE", facts)
        secret = self.pki.leaf_key.private_numbers().private_value
        self.assertNotIn(str(secret), facts)
        self.assertNotIn(format(secret, "x"), facts)
        self.assertEqual(key.describe()["chain_length"], 1)


class RefusalTests(_Dir):
    def test_a_key_file_open_to_group_or_others_is_refused(self):
        for mode in (0o640, 0o604, 0o660, 0o644):
            with self.subTest(mode=oct(mode)):
                self.refused("open to group or others", _pem(self.pki.leaf), mode=mode)

    def test_a_key_path_that_is_not_a_file_is_refused(self):
        key_path = self.dir / "7.key.pem"
        key_path.mkdir(mode=0o700)
        chain_path = self.dir / "7.chain.pem"
        chain_path.write_bytes(_pem(self.pki.leaf))
        with self.assertRaises(cck.CopyKeyError) as caught:
            cck.load_from_files(7, str(key_path), str(chain_path))
        self.assertIn("not a regular file", str(caught.exception))

    def test_a_key_that_is_not_p256_is_refused(self):
        other = ec.generate_private_key(ec.SECP384R1())
        self.refused("not EC P-256", _pem(self.pki.leaf), key=other)

    def test_a_chain_that_is_not_the_keys_is_refused(self):
        other = ec.generate_private_key(ec.SECP256R1())
        self.refused("the first certificate is not the key's", _pem(self.pki.leaf), key=other)

    def test_a_chain_in_the_wrong_order_is_refused(self):
        self.pki.leaf = self.pki.leaf_signed_by(self.pki.mid_key, "mid")
        self.refused("the first certificate is not the key's", _pem(self.pki.mid, self.pki.leaf))

    def test_a_leaf_without_digital_signature_is_refused(self):
        self.pki.leaf = self.pki.leaf_signed_by(self.pki.root_key, "root",
                                                usage=_usage(key_agreement=True))
        self.refused("digitalSignature", _pem(self.pki.leaf))

    def test_a_leaf_with_no_key_usage_at_all_is_refused(self):
        self.pki.leaf = _cert(self.pki.leaf_key, "wallet-copy issuer", self.pki.root_key, "root",
                              ca=False, usage=None)
        self.refused("digitalSignature", _pem(self.pki.leaf))

    def test_a_leaf_that_is_a_ca_is_refused(self):
        self.pki.leaf = self.pki.leaf_signed_by(self.pki.root_key, "root", ca=True)
        self.refused("the leaf is a CA certificate", _pem(self.pki.leaf))

    def test_a_leaf_that_can_sign_certificates_is_refused(self):
        self.pki.leaf = self.pki.leaf_signed_by(
            self.pki.root_key, "root", usage=_usage(digital_signature=True, key_cert_sign=True))
        self.refused("keyCertSign", _pem(self.pki.leaf))

    def test_a_self_signed_leaf_is_refused(self):
        self.pki.leaf = _cert(self.pki.leaf_key, "wallet-copy issuer", self.pki.leaf_key,
                              "wallet-copy issuer", ca=False, usage=_usage(digital_signature=True))
        self.refused("certificate 0 is self-signed", _pem(self.pki.leaf))

    def test_a_chain_that_carries_its_trust_anchor_is_refused(self):
        self.refused("certificate 1 is self-signed", _pem(self.pki.leaf, self.pki.root))

    def test_a_chain_whose_links_do_not_verify_is_refused(self):
        self.pki.leaf = self.pki.leaf_signed_by(self.pki.mid_key, "mid")
        stranger_key = ec.generate_private_key(ec.SECP256R1())
        stranger = _cert(stranger_key, "mid", self.pki.root_key, "root", True,
                         _usage(key_cert_sign=True))
        self.refused("certificate 0 is not issued by certificate 1",
                     _pem(self.pki.leaf, stranger))

    def test_an_intermediate_that_is_not_a_ca_is_refused(self):
        not_ca = _cert(self.pki.mid_key, "mid", self.pki.root_key, "root", False,
                       _usage(digital_signature=True), san=False)
        self.pki.leaf = self.pki.leaf_signed_by(self.pki.mid_key, "mid")
        self.refused("certificate 1 follows the leaf but is not a CA", _pem(self.pki.leaf, not_ca))

    def test_an_intermediate_with_no_basic_constraints_is_refused(self):
        bare = _cert(self.pki.mid_key, "mid", self.pki.root_key, "root", None,
                     _usage(key_cert_sign=True))
        self.pki.leaf = self.pki.leaf_signed_by(self.pki.mid_key, "mid")
        self.refused("certificate 1 follows the leaf but is not a CA", _pem(self.pki.leaf, bare))

    def test_an_expired_leaf_is_refused(self):
        self.pki.leaf = self.pki.leaf_signed_by(self.pki.root_key, "root",
                                                start=_NOW - 30 * _DAY, end=_NOW - _DAY)
        self.refused("the chain is valid only from", _pem(self.pki.leaf))

    def test_a_leaf_not_yet_valid_is_refused(self):
        self.pki.leaf = self.pki.leaf_signed_by(self.pki.root_key, "root",
                                                start=_NOW + _DAY, end=_NOW + 30 * _DAY)
        self.refused("the chain is valid only from", _pem(self.pki.leaf))

    def test_an_expired_intermediate_is_refused_though_the_leaf_is_current(self):
        old_mid = _cert(self.pki.mid_key, "mid", self.pki.root_key, "root", True,
                        _usage(key_cert_sign=True), start=_NOW - 30 * _DAY, end=_NOW - _DAY)
        self.pki.leaf = self.pki.leaf_signed_by(self.pki.mid_key, "mid")
        self.refused("the chain is valid only from", _pem(self.pki.leaf, old_mid))

    def test_a_chain_file_with_no_certificate_is_refused(self):
        self.refused("unreadable", b"-----BEGIN NOTHING-----\nAA==\n-----END NOTHING-----\n")
        self.refused("unreadable", b"")


class KeyForAgencyTests(_Dir):
    def setUp(self):
        super().setUp()
        self._env = mock.patch.dict(os.environ, {cck.KEYS_DIR_ENV: str(self.dir)})
        self._env.start()

    def tearDown(self):
        self._env.stop()
        super().tearDown()

    def test_unset_directory_means_not_offered(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(cck.CopyKeyError) as caught:
                cck.key_for_agency(7)
        self.assertFalse(caught.exception.configured)

    def test_an_agency_with_no_key_is_not_offered(self):
        with self.assertRaises(cck.CopyKeyError) as caught:
            cck.key_for_agency(8)
        self.assertFalse(caught.exception.configured)

    def test_only_a_canonical_agency_id_names_a_file(self):
        self.write(_pem(self.pki.leaf))
        self.write(_pem(self.pki.leaf), agency="007")
        for bad in ("007", "0", "-7", "7.0", "../7", "7/", " 7", "7\n", True, None, 1e3):
            with self.subTest(agency=bad):
                with self.assertRaises(cck.CopyKeyError) as caught:
                    cck.key_for_agency(bad)
                self.assertFalse(caught.exception.configured)
        self.assertEqual(cck.key_for_agency(7).agency_id, 7)
        self.assertEqual(cck.key_for_agency("7").agency_id, 7)

    def test_a_supplied_but_broken_key_is_a_fault_not_an_absence(self):
        self.write(_pem(self.pki.leaf), mode=0o644)
        with self.assertRaises(cck.CopyKeyError) as caught:
            cck.key_for_agency(7)
        self.assertTrue(caught.exception.configured)

    def test_a_replaced_key_is_picked_up_without_a_restart(self):
        self.write(_pem(self.pki.leaf))
        first = cck.key_for_agency(7)
        self.assertIs(cck.key_for_agency(7), first)
        rotated = _Pki()
        self.write(_pem(rotated.leaf), key=rotated.leaf_key)
        second = cck.key_for_agency(7)
        self.assertNotEqual(second.leaf_fingerprint, first.leaf_fingerprint)
        self.assertTrue(_verify_as_a_wallet(_jws(second, {"iss": _URL})))

    def test_a_cached_key_is_refused_once_its_chain_expires(self):
        self.write(_pem(self.pki.leaf))
        key = cck.key_for_agency(7)
        later = key.valid_until + datetime.timedelta(seconds=1)
        with mock.patch.object(cck, "_now", return_value=later):
            with self.assertRaises(cck.CopyKeyError) as caught:
                cck.key_for_agency(7)
        self.assertIn("the chain is valid only from", str(caught.exception))
        self.assertTrue(caught.exception.configured)


class TestPkiScriptTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out = pathlib.Path(self._tmp.name) / "keys"
        cck.reset()

    def tearDown(self):
        cck.reset()
        self._tmp.cleanup()

    def run_script(self, *extra):
        return subprocess.run([sys.executable, str(_SCRIPT), "--agency", "7", "--issuer-url", _URL,
                               "--out", str(self.out), *extra],
                              capture_output=True, text=True, timeout=60)

    def test_the_script_writes_a_chain_the_loader_accepts(self):
        done = self.run_script()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(stat.S_IMODE((self.out / "7.key.pem").stat().st_mode), 0o600)
        key = cck.load_from_files(7, str(self.out / "7.key.pem"), str(self.out / "7.chain.pem"))
        self.assertEqual(len(key.x5c), 1)
        self.assertTrue(key.names_issuer(_URL))
        anchor = x509.load_pem_x509_certificate((self.out / "7.anchor.pem").read_bytes())
        leaf = x509.load_der_x509_certificate(base64.b64decode(key.x5c[0]))
        leaf.verify_directly_issued_by(anchor)
        self.assertIn("TEST", anchor.subject.rfc4514_string())
        self.assertIn("TEST", leaf.subject.rfc4514_string())
        self.assertTrue(_verify_as_a_wallet(_jws(key, {"iss": _URL})))

    def test_the_script_never_overwrites_a_key(self):
        self.assertEqual(self.run_script().returncode, 0)
        before = (self.out / "7.key.pem").read_bytes()
        again = self.run_script()
        self.assertNotEqual(again.returncode, 0)
        self.assertIn("refusing to overwrite", again.stderr)
        self.assertEqual((self.out / "7.key.pem").read_bytes(), before)

    def test_the_script_refuses_an_issuer_that_is_not_https(self):
        done = subprocess.run([sys.executable, str(_SCRIPT), "--agency", "7", "--issuer-url",
                               "http://polaris.test/api/v1/oid4vci/7", "--out", str(self.out)],
                              capture_output=True, text=True, timeout=60)
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse((self.out / "7.key.pem").exists())


class RefusalMutationTests(unittest.TestCase):
    """Switch each refusal off, one at a time, and require the tests above to go red.

    The refusals are found, not listed: every `if` whose body raises CopyKeyError, plus every
    call to `_check_window` (the validity window is a refusal made by a call, not by an `if`).
    Each mutant replaces one condition with `False`, or one call with `None`, and is loaded as
    a fresh module that the refusal tests then run against. The positive control runs the same
    tests against the unmutated source first: a harness that is red for another reason would
    otherwise make every mutant look caught."""

    SUITES = (RefusalTests, KeyForAgencyTests)
    #: Change deliberately: a refusal was added or removed, and this is the inventory.
    EXPECTED = 15

    @staticmethod
    def _sites(src):
        import ast
        tree = ast.parse(src)
        sites = []
        for node in ast.walk(tree):
            if isinstance(node, ast.If) and any(
                    isinstance(s, ast.Raise) and isinstance(s.exc, ast.Call)
                    and getattr(s.exc.func, "id", None) == "CopyKeyError" for s in node.body):
                sites.append((node.test, "False"))
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) \
                    and getattr(node.value.func, "id", None) == "_check_window":
                sites.append((node.value, "None"))
        return sites

    @staticmethod
    def _mutate(src, node, replacement):
        lines = src.splitlines(keepends=True)
        head = lines[node.lineno - 1][:node.col_offset]
        tail = lines[node.end_lineno - 1][node.end_col_offset:]
        return "".join(lines[:node.lineno - 1] + [head + replacement + tail]
                       + lines[node.end_lineno:])

    def _run_against(self, src):
        import types
        mutant = types.ModuleType("credential_copy_keys_mutant")
        mutant.__file__ = cck.__file__
        sys.modules[mutant.__name__] = mutant
        try:
            exec(compile(src, cck.__file__, "exec"), mutant.__dict__)
        finally:
            sys.modules.pop(mutant.__name__, None)
        result = unittest.TestResult()
        with mock.patch.object(sys.modules[__name__], "cck", mutant):
            suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c)
                                       for c in self.SUITES)
            suite.run(result)
        return result

    def test_every_refusal_is_noticed_when_switched_off(self):
        src = pathlib.Path(cck.__file__).read_text()
        control = self._run_against(src)
        self.assertTrue(control.wasSuccessful() and control.testsRun > 0,
                        "positive control: the unmutated module must pass: %s"
                        % (control.failures + control.errors))
        sites = self._sites(src)
        self.assertEqual(len(sites), self.EXPECTED, "the refusal inventory changed")
        survivors = []
        for node, replacement in sites:
            if self._run_against(self._mutate(src, node, replacement)).wasSuccessful():
                survivors.append("line %d: %s" % (node.lineno, ast_text(src, node)))
        self.assertEqual(survivors, [], "refusals nothing notices")


def ast_text(src, node):
    import ast
    return " ".join((ast.get_source_segment(src, node) or "").split())


if __name__ == "__main__":
    unittest.main()
