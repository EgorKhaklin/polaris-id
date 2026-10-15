# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_custody.py — the key custody abstraction (roadmap P1.2).

Three drivers, one contract: raw ML-DSA-65 public key + raw signature over the
SHA3-256 digest, so the two-witness verify path is unchanged whichever custody
signs. Each driver is exercised for real, not mocked:

  FileCustodyTests      the JSON key file, signed via liboqs (needs liboqs).
  AwsKmsCustodyTests    the driver's real botocore wire path (JSON 1.1, SigV4,
                        base64 blobs, SPKI parsing) against a local STAND-IN
                        that implements KMS's DescribeKey/GetPublicKey/Sign and
                        signs with OpenSSL's ML-DSA-65 (cryptography). The only
                        thing faked is the remote service, which cannot be real
                        in CI; the cryptography is real. An opt-in live test
                        runs against a real key when POLARIS_CUSTODY_AWSKMS_LIVE
                        _KEY_ID is set.
  Pkcs11CustodyTests    a real PKCS#11 token (CI: Kryoptic, a software token
                        with ML-DSA, job custody-pkcs11). Runs when
                        POLARIS_CUSTODY_PKCS11_MODULE is set; the CI job also
                        sets POLARIS_CUSTODY_PKCS11_REQUIRE=1 so a skip is a
                        failure there.
  EnvSelectionTests     driver selection and the PIN-never-from-env refusal.

Run: python3 -m unittest test_custody
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import custody
import pqc_signing

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa
    _MLDSA_OK = hasattr(_mldsa, "MLDSA65PrivateKey")
except Exception:
    _MLDSA_OK = False

_DIGEST = hashlib.sha3_256(b"token-ABC").digest()


def _verify(sig: bytes, pk: bytes, message: bytes = b"token-ABC") -> bool:
    """Verify with whichever independent witnesses this environment has: both
    (liboqs + OpenSSL) when liboqs is present, else OpenSSL alone."""
    if pqc_signing.is_available():
        return pqc_signing.verify_both(message, sig.hex(), pk.hex())
    v = pqc_signing._verify_second_witness(message, sig.hex(), pk.hex())
    assert v is not None, "no ML-DSA verifier available at all"
    return v


def _verify_raw(sig: bytes, pk: bytes, message: bytes) -> bool:
    """`_verify` over `message` ITSELF, not its SHA3-256: the sign_message contract (COSE)."""
    if pqc_signing.is_available():
        return pqc_signing.verify_both_raw(message, sig.hex(), pk.hex(), require_witness=True)
    v = pqc_signing._verify_second_witness_raw(message, sig.hex(), pk.hex())
    assert v is not None, "no ML-DSA verifier available at all"
    return v


#: A COSE_Sign1 Sig_structure, the only kind of message sign_message is handed in the product.
_SIG_STRUCTURE = b"\x84\x6aSignature1\x44\xa1\x01\x38\x30\x40\x58\x40" + bytes(range(64))


class _EnvSnapshot:
    KEYS = ("POLARIS_CUSTODY_DRIVER", "POLARIS_PQC_SIGNING_KEY_FILE", "POLARIS_CUSTODY_PKCS11_MODULE",
            "POLARIS_CUSTODY_PKCS11_TOKEN_LABEL", "POLARIS_CUSTODY_PKCS11_PIN_FILE", "POLARIS_CUSTODY_PKCS11_PIN",
            "POLARIS_CUSTODY_PKCS11_KEY_LABEL", "POLARIS_CUSTODY_AWSKMS_KEY_ID", "POLARIS_CUSTODY_AWSKMS_REGION",
            "POLARIS_CUSTODY_AWSKMS_ENDPOINT_URL", "POLARIS_USE_REAL_PQC",
            "POLARIS_AGENCY_KEYS_DIR", "POLARIS_MIGRATION_SIGNING_KEY_FILE", "POLARIS_ENV",
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION")

    def __enter__(self):
        self._saved = {k: os.environ.get(k) for k in self.KEYS}
        for k in self.KEYS:
            os.environ.pop(k, None)
        custody.reset()
        return self

    def __exit__(self, *a):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        custody.reset()
        pqc_signing._PERSISTENT_LOADED = False


# ---------------------------------------------------------------------------
@unittest.skipUnless(pqc_signing.is_available(), "liboqs not installed")
class FileCustodyTests(unittest.TestCase):
    def setUp(self):
        self._env = _EnvSnapshot().__enter__()
        self.kp = pqc_signing.generate_keypair()
        self.kf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(self.kp, self.kf); self.kf.close()

    def tearDown(self):
        os.unlink(self.kf.name)
        self._env.__exit__()

    def test_file_driver_signs_and_both_witnesses_verify(self):
        c = custody.FileCustody(self.kf.name)
        pk = c.public_key()
        self.assertEqual(pk.hex(), self.kp["public_key_hex"])
        sig = c.sign(_DIGEST)
        self.assertEqual(len(sig), custody.SIGNATURE_LEN)
        self.assertTrue(_verify(sig, pk))
        self.assertFalse(_verify(sig, pk, b"token-XYZ"))
        d = c.describe()
        self.assertEqual(d["driver"], "file")
        self.assertEqual(d["public_key_fingerprint"], custody.fingerprint(pk))
        self.assertNotIn(self.kf.name, json.dumps(d), "describe() must not leak the path")

    def test_env_selects_file_driver_and_pqc_signing_routes_through_it(self):
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = self.kf.name
        custody.reset()
        c = custody.get_custody()
        self.assertIsInstance(c, custody.FileCustody)
        r = pqc_signing.sign(b"token-ABC")
        self.assertEqual(r.public_key_hex, self.kp["public_key_hex"])
        self.assertTrue(pqc_signing.verify_both(b"token-ABC", r.signature_hex, r.public_key_hex))
        self.assertEqual(pqc_signing.trust_anchor_public_key_hex(), self.kp["public_key_hex"])
        self.assertEqual(pqc_signing.availability_report()["custody"]["driver"], "file")

    def test_malformed_file_fails_loud(self):
        bad = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        bad.write('{"algorithm": "ML-DSA-65", "secret_key_hex": "zz"}'); bad.close()
        try:
            with self.assertRaises(custody.CustodyError):
                custody.FileCustody(bad.name)
            os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = bad.name
            custody.reset()
            with self.assertRaises(RuntimeError):
                pqc_signing.sign(b"x")   # never degrades to ephemeral
        finally:
            os.unlink(bad.name)

    def test_digest_length_is_enforced(self):
        c = custody.FileCustody(self.kf.name)
        with self.assertRaises(custody.CustodyError):
            c.sign(b"not-a-digest")
        with self.assertRaises(custody.CustodyError):
            c.sign(_SIG_STRUCTURE)      # sign() stays the digest contract; sign_message is apart

    def test_sign_message_is_pure_ml_dsa_over_the_message_itself(self):
        c = custody.FileCustody(self.kf.name)
        sig = c.sign_message(_SIG_STRUCTURE)
        self.assertEqual(len(sig), custody.SIGNATURE_LEN)
        self.assertTrue(_verify_raw(sig, c.public_key(), _SIG_STRUCTURE))
        self.assertFalse(_verify_raw(sig, c.public_key(), hashlib.sha3_256(_SIG_STRUCTURE).digest()))
        for bad in (b"", "text", None):
            with self.assertRaises(custody.CustodyError, msg=repr(bad)):
                c.sign_message(bad)

    def test_after_a_rotation_an_old_token_verifies_under_its_stored_key(self):
        """A rotation switches the custody key. A token signed before it still verifies under
        the public key stored with its signature, as the relying-party door checks it; the
        custody key, now the new one, does not verify it, and the new key signs."""
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = self.kf.name
        os.environ["POLARIS_USE_REAL_PQC"] = "1"
        custody.reset()
        sig, alg, pk_old = pqc_signing.signature_with_key_for_token("token-ABC")
        self.assertEqual((alg, pk_old), ("ML-DSA-65", self.kp["public_key_hex"]))
        self.assertTrue(pqc_signing.verify_token_signature("token-ABC", sig, alg))
        newkp = pqc_signing.generate_keypair()
        nf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(newkp, nf); nf.close()
        try:
            os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = nf.name
            custody.reset()
            self.assertEqual(pqc_signing.trust_anchor_public_key_hex(), newkp["public_key_hex"])
            self.assertTrue(pqc_signing.verify_stored_signature("token-ABC", sig, pk_old, algorithm=alg))
            self.assertFalse(pqc_signing.verify_token_signature("token-ABC", sig, alg))
            sig_new, alg_new, pk_new = pqc_signing.signature_with_key_for_token("token-DEF")
            self.assertEqual(pk_new, newkp["public_key_hex"])
            self.assertTrue(pqc_signing.verify_token_signature("token-DEF", sig_new, alg_new))
        finally:
            os.unlink(nf.name)


# ---------------------------------------------------------------------------
class _Owned:
    """A stat result with another owner: the owners a test cannot create without root."""

    def __init__(self, st, uid):
        self._st, self.st_uid = st, uid

    def __getattr__(self, attr):
        return getattr(self._st, attr)


def _lstat_owned_by(path, uid):
    """os.lstat, reporting `uid` as the owner of the entry `path` names."""
    real, name = os.lstat, os.path.abspath(path)

    def lstat(p, *a, **kw):
        st = real(p, *a, **kw)
        return _Owned(st, uid) if os.fspath(p) == name else st
    return mock.patch.object(custody.os, "lstat", lstat)


def _fstat_owned_by(path, uid):
    """os.fstat, reporting `uid` as the owner of the file `path` names, once opened."""
    real, target = os.fstat, os.stat(path)

    def fstat(fd):
        st = real(fd)
        same = (st.st_dev, st.st_ino) == (target.st_dev, target.st_ino)
        return _Owned(st, uid) if same else st
    return mock.patch.object(custody.os, "fstat", fstat)


#: Loads the key file argv[2] with the custody module in argv[1], as whichever user runs it.
_LOAD = ("import sys\n"
         "sys.path.insert(0, sys.argv[1])\n"
         "import custody\n"
         "try:\n"
         "    custody.FileCustody(sys.argv[2])\n"
         "    print('loaded')\n"
         "except custody.CustodyError as exc:\n"
         "    print('refused:', exc)\n")


class FileKeyLoaderTests(unittest.TestCase):
    """The file driver reads the issuer key only from a regular file that group and others
    cannot write, in directories they cannot write, or in a sticky one where root or this
    process owns the entry: whoever can write the file can rewrite the key, whoever can write
    its directory can replace it, and in a sticky directory whoever creates the name first owns
    it. Read bits are accepted, since the shipped Compose secret is 0644 inside the 0700
    secrets directory and Helm mounts it 0440. The key here has the right shape and is never
    used (zeros), so loading it needs no liboqs."""

    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.dir = d.name
        self.path = os.path.join(self.dir, "polaris_signing_key")
        with open(self.path, "w") as fh:
            json.dump({"algorithm": "ML-DSA-65", "secret_key_hex": "00" * 4032,
                       "public_key_hex": "00" * custody.PUBLIC_KEY_LEN}, fh)

    def test_the_shipped_modes_load(self):
        for mode in (0o600, 0o644, 0o440, 0o400):
            with self.subTest(mode=oct(mode)):
                os.chmod(self.path, mode)
                self.assertEqual(custody.FileCustody(self.path).public_key(),
                                 bytes(custody.PUBLIC_KEY_LEN))

    def test_a_key_file_group_or_others_can_write_is_refused(self):
        for mode in (0o666, 0o620, 0o602):
            with self.subTest(mode=oct(mode)):
                os.chmod(self.path, mode)
                with self.assertRaisesRegex(custody.CustodyError, "writable by group or others"):
                    custody.FileCustody(self.path)

    def test_a_key_in_a_directory_others_can_write_is_refused(self):
        for dir_mode in (0o777, 0o775, 0o770, 0o703):
            with self.subTest(dir_mode=oct(dir_mode)):
                os.chmod(self.dir, dir_mode)
                try:
                    with self.assertRaisesRegex(custody.CustodyError, "which group or others can write"):
                        custody.FileCustody(self.path)
                finally:
                    os.chmod(self.dir, 0o700)

    def test_a_key_in_a_sticky_directory_loads(self):
        """The sticky bit lets only an entry's owner, the directory's owner or root rename or
        remove it, so others cannot replace a key this process owns there. /tmp on Linux is
        1777."""
        for dir_mode in (0o1777, 0o1770):
            with self.subTest(dir_mode=oct(dir_mode)):
                os.chmod(self.dir, dir_mode)
                try:
                    self.assertEqual(custody.FileCustody(self.path).public_key(),
                                     bytes(custody.PUBLIC_KEY_LEN))
                finally:
                    os.chmod(self.dir, 0o700)

    def test_in_a_sticky_directory_the_key_must_be_root_s_or_this_process_s(self):
        """Anyone who can write a sticky directory can create the key's name before the key
        exists and keep what they planted, so there the name and the file must belong to root
        or to this process. The other owners are simulated, so this runs as any user: the
        name's owner comes from lstat, the opened file's from fstat. A directory others cannot
        write keeps any owner: under Compose the key carries the host operator's uid."""
        other = os.geteuid() + 1
        self.addCleanup(os.chmod, self.dir, 0o700)
        for dir_mode in (0o1777, 0o1770):
            os.chmod(self.dir, dir_mode)
            for owned in (_lstat_owned_by, _fstat_owned_by):
                with self.subTest(dir_mode=oct(dir_mode), owner_from=owned.__name__), \
                        owned(self.path, other):
                    with self.assertRaisesRegex(custody.CustodyError,
                                                f"sticky directory others can write .*uid {other} owns it"):
                        custody.FileCustody(self.path)
            with self.subTest(dir_mode=oct(dir_mode), owner="root"), \
                    _lstat_owned_by(self.path, 0), _fstat_owned_by(self.path, 0):
                self.assertEqual(custody.FileCustody(self.path).public_key(),
                                 bytes(custody.PUBLIC_KEY_LEN))
        for dir_mode in (0o755, 0o700):
            os.chmod(self.dir, dir_mode)
            with self.subTest(dir_mode=oct(dir_mode), owner="another user"), \
                    _lstat_owned_by(self.path, other), _fstat_owned_by(self.path, other):
                self.assertEqual(custody.FileCustody(self.path).public_key(),
                                 bytes(custody.PUBLIC_KEY_LEN))

    @unittest.skipUnless(os.geteuid() == 0, "creates files as other users, which needs root")
    def test_a_key_name_another_user_planted_in_a_sticky_directory_is_refused(self):
        """The case above, for real. In a sticky directory anyone can write, uid 65534 creates
        the key's name before the key exists, 0644 so no write bit gives it away, and uid 1000
        (the image's user) and root load it: refused. A key root created in the same directory,
        as the kubelet creates a secret mount's entries, loads for both."""
        os.chmod(self.dir, 0o1777)
        self.addCleanup(os.chmod, self.dir, 0o700)
        os.chmod(self.path, 0o644)
        planted = os.path.join(self.dir, "planted_signing_key")
        with open(self.path, "rb") as fh:
            key = fh.read()
        subprocess.run([sys.executable, "-c",
                        "import os, sys\n"
                        "fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)\n"
                        "os.fchmod(fd, 0o644)\n"
                        "os.write(fd, sys.stdin.buffer.read())\n", planted],
                       input=key, check=True, user=65534, group=65534, extra_groups=[])
        self.assertEqual((os.stat(planted).st_uid, os.stat(self.path).st_uid), (65534, 0))
        here = os.path.dirname(os.path.abspath(__file__))

        def load_as_uid_1000(path):
            return subprocess.run([sys.executable, "-c", _LOAD, here, path], check=True,
                                  capture_output=True, text=True, user=1000, group=1000,
                                  extra_groups=[]).stdout.strip()
        self.assertRegex(load_as_uid_1000(planted), "^refused: .*uid 65534 owns it there")
        with self.assertRaisesRegex(custody.CustodyError, "uid 65534 owns it there"):
            custody.FileCustody(planted)
        self.assertEqual(load_as_uid_1000(self.path), "loaded")
        self.assertEqual(custody.FileCustody(self.path).public_key(), bytes(custody.PUBLIC_KEY_LEN))

    def test_the_kubernetes_secret_layout(self):
        """The kubelet's atomic writer (pkg/volume/util/atomic_writer.go) writes each key into a
        0755 timestamped directory and gives the pod the name as a symlink beside it, name ->
        ..data/name and ..data -> that directory, on a tmpfs that is world-writable and sticky.
        That layout loads. Each of the two directories, made writable without the sticky bit,
        refuses the key: the name's directory holds the symlink, the other holds the file."""
        mount = os.path.join(self.dir, "secrets")
        stamped = os.path.join(mount, "..2026_10_15_00_00_00.000000001")
        os.makedirs(stamped)
        key = os.path.join(stamped, "polaris_signing_key")
        os.rename(self.path, key)
        os.chmod(key, 0o440)
        os.symlink(os.path.basename(stamped), os.path.join(mount, "..data"))
        name = os.path.join(mount, "polaris_signing_key")
        os.symlink(os.path.join("..data", "polaris_signing_key"), name)
        self.addCleanup(os.chmod, mount, 0o700)
        self.addCleanup(os.chmod, stamped, 0o700)
        os.chmod(stamped, 0o755)
        os.chmod(mount, 0o1777)
        self.assertEqual(custody.FileCustody(name).public_key(), bytes(custody.PUBLIC_KEY_LEN))
        # The kubelet creates the name as root; a name another user planted first is refused.
        with _lstat_owned_by(name, 0):
            self.assertEqual(custody.FileCustody(name).public_key(), bytes(custody.PUBLIC_KEY_LEN))
        with _lstat_owned_by(name, os.geteuid() + 1), self.assertRaises(custody.CustodyError) as caught:
            custody.FileCustody(name)
        self.assertIn("/secrets, a sticky directory others can write", str(caught.exception))
        for writable, other, other_mode in ((mount, stamped, 0o755), (stamped, mount, 0o1777)):
            with self.subTest(writable=os.path.basename(writable)):
                os.chmod(other, other_mode)
                os.chmod(writable, 0o777)
                with self.assertRaises(custody.CustodyError) as caught:
                    custody.FileCustody(name)
                self.assertIn("/%s, which group or others can write" % os.path.basename(writable),
                              str(caught.exception))

    def test_a_fifo_is_refused_without_blocking(self):
        """Opened for reading, a FIFO blocks until a writer comes. A load still blocked after
        five seconds reads red, and the test then releases it, so a failure never leaves the
        suite stuck."""
        fifo = os.path.join(self.dir, "fifo")
        os.mkfifo(fifo, 0o600)
        outcome = []

        def load():
            try:
                custody.FileCustody(fifo)
                outcome.append("loaded")
            except Exception as exc:  # noqa: BLE001  the assertion below names what it was
                outcome.append(f"{type(exc).__name__}: {exc}")

        t = threading.Thread(target=load, daemon=True)
        t.start()
        t.join(5)
        if t.is_alive():
            try:  # a writer that opens and closes gives the blocked reader end-of-file
                os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
            except OSError:
                pass
            t.join(5)
            self.fail("FileCustody blocked opening a FIFO instead of refusing it")
        self.assertEqual(len(outcome), 1, outcome)
        self.assertTrue(outcome[0].startswith("CustodyError: "), outcome)
        self.assertIn("is not a regular file", outcome[0])


# ---------------------------------------------------------------------------
@unittest.skipUnless(pqc_signing.is_available(), "liboqs not installed")
class PerAgencyCustodyTests(unittest.TestCase):
    """PE.3b: custody selects the ISSUING AGENCY's own key from
    POLARIS_AGENCY_KEYS_DIR (federation in the running app), falling back to the
    single global key when the agency has no key file — so an agency's tokens are
    signed by the agency, and single-key deployments are unchanged."""

    def test_per_agency_custody_and_signing_use_the_agency_key(self):
        d = tempfile.mkdtemp()
        keys = {}
        for aid in (1, 2):
            kp = pqc_signing.generate_keypair()
            with open(os.path.join(d, "%d.json" % aid), "w") as f:
                json.dump(kp, f)
            keys[aid] = kp["public_key_hex"]
        gk = pqc_signing.generate_keypair()
        gkf = os.path.join(d, "global.json")
        with open(gkf, "w") as f:
            json.dump(gk, f)
        with _EnvSnapshot():
            os.environ["POLARIS_AGENCY_KEYS_DIR"] = d
            os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = gkf
            os.environ["POLARIS_USE_REAL_PQC"] = "1"
            custody.reset()
            self.assertNotEqual(keys[1], keys[2])
            # Each agency's custody is its OWN key.
            self.assertEqual(custody.get_custody_for_agency(1).public_key().hex(), keys[1])
            self.assertEqual(custody.get_custody_for_agency(2).public_key().hex(), keys[2])
            # An agency with no key file falls back to the global key.
            self.assertEqual(custody.get_custody_for_agency(9999).public_key(),
                             custody.get_custody().public_key())
            # Issuance signs a token with the ISSUING agency's own key.
            _sig1, alg1, pk1 = pqc_signing.signature_with_key_for_token("tok-A1", agency_id=1)
            _sig2, alg2, pk2 = pqc_signing.signature_with_key_for_token("tok-A2", agency_id=2)
            self.assertEqual((alg1, pk1), ("ML-DSA-65", keys[1]))
            self.assertEqual((alg2, pk2), ("ML-DSA-65", keys[2]))


# ---------------------------------------------------------------------------
@unittest.skipUnless(_MLDSA_OK and hasattr(_mldsa, "MLDSAMuHasher")
                     and hasattr(_mldsa.MLDSA65PrivateKey, "sign_mu"),
                     "needs cryptography with ML-DSA's external mu (MLDSAMuHasher, sign_mu)")
class ExternalMuTests(unittest.TestCase):
    """custody.external_mu, with no KMS and no boto3: FIPS 204's mu for pure ML-DSA with an
    empty context, held against cryptography's own MLDSAMuHasher (another implementation's mu,
    context None, which is empty), and a signature over it checked over the raw message. The
    awskms driver sends exactly this as EXTERNAL_MU past 4,096 bytes."""

    def test_external_mu_is_fips_204_mu_and_a_signature_over_it_is_over_the_message(self):
        sk = _mldsa.MLDSA65PrivateKey.generate()
        pk = sk.public_key()
        for n in (1, len(_SIG_STRUCTURE), custody.KMS_RAW_MESSAGE_MAX, custody.KMS_RAW_MESSAGE_MAX + 1, 20000):
            message = (_SIG_STRUCTURE * (n // len(_SIG_STRUCTURE) + 1))[:n]
            hasher = _mldsa.MLDSAMuHasher(pk)
            hasher.update(message)
            mu = hasher.finalize()
            self.assertEqual(len(mu), 64, n)
            self.assertEqual(custody.external_mu(pk.public_bytes_raw(), message), mu, n)
            sig = sk.sign_mu(mu)
            pk.verify(sig, message)                    # pure ML-DSA-65 over the message itself
            self.assertTrue(_verify_raw(sig, pk.public_bytes_raw(), message), n)
            self.assertFalse(_verify_raw(sig, pk.public_bytes_raw(), message + b"\x00"), n)


# ---------------------------------------------------------------------------
from kms_standin import KmsStandIn as _KmsStandIn  # shared with test_secretstore


def _boto3_present():
    try:
        import boto3  # noqa: F401
        return True
    except ImportError:
        return False


@unittest.skipUnless(_MLDSA_OK and _boto3_present(), "needs cryptography with ML-DSA and boto3")
class AwsKmsCustodyTests(unittest.TestCase):
    def setUp(self):
        self._env = _EnvSnapshot().__enter__()
        os.environ["AWS_ACCESS_KEY_ID"] = "AKIATESTONLY"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "test-only-not-a-secret"
        self.kms = _KmsStandIn()

    def tearDown(self):
        self.kms.close()
        self._env.__exit__()

    def test_kms_driver_fetches_spki_and_signs_with_the_real_wire_protocol(self):
        c = custody.AwsKmsCustody(self.kms.key_id, region="us-east-1", endpoint_url=self.kms.url)
        self.assertEqual(c.public_key(), self.kms.pub_raw, "SPKI -> raw ML-DSA-65 public key")
        sig = c.sign(_DIGEST)
        self.assertEqual(len(sig), custody.SIGNATURE_LEN)
        self.assertTrue(_verify(sig, c.public_key()))
        self.assertFalse(_verify(sig, c.public_key(), b"token-XYZ"))
        targets = [t for t, _ in self.kms.calls]
        self.assertTrue(any(t.endswith("DescribeKey") for t in targets))
        self.assertTrue(any(t.endswith("GetPublicKey") for t in targets))
        sign_call = next(b for t, b in self.kms.calls if t.endswith("Sign"))
        self.assertEqual(sign_call["SigningAlgorithm"], "ML_DSA_SHAKE_256")
        self.assertEqual(sign_call["MessageType"], "RAW")
        self.assertEqual(base64.b64decode(sign_call["Message"]), _DIGEST)
        self.assertTrue(c.key_id.startswith("awskms:arn:aws:kms:"))

    def test_sign_message_sends_kms_raw_up_to_4096_bytes(self):
        c = custody.AwsKmsCustody(self.kms.key_id, region="us-east-1", endpoint_url=self.kms.url)
        for n in (len(_SIG_STRUCTURE), custody.KMS_RAW_MESSAGE_MAX):
            message = (_SIG_STRUCTURE * (n // len(_SIG_STRUCTURE) + 1))[:n]
            sig = c.sign_message(message)
            call = [b for t, b in self.kms.calls if t.endswith("Sign")][-1]
            self.assertEqual((call["MessageType"], call["SigningAlgorithm"]), ("RAW", "ML_DSA_SHAKE_256"), n)
            self.assertEqual(base64.b64decode(call["Message"]), message, n)
            self.assertTrue(_verify_raw(sig, c.public_key(), message), n)

    @unittest.skipUnless(_MLDSA_OK and hasattr(_mldsa, "MLDSAMuHasher")
                         and hasattr(_mldsa.MLDSA65PrivateKey, "sign_mu"),
                         "needs cryptography with ML-DSA's external mu (MLDSAMuHasher, sign_mu)")
    def test_past_4096_bytes_sign_message_sends_mu_and_the_signature_is_over_the_message(self):
        """KMS takes at most 4,096 bytes RAW. Past that the driver computes FIPS 204's mu itself
        and sends it as EXTERNAL_MU; the signature that comes back must be pure ML-DSA over the
        MESSAGE, which both witnesses check over the raw bytes. The mu is held against
        cryptography's own MLDSAMuHasher, an implementation that is not this module's."""
        c = custody.AwsKmsCustody(self.kms.key_id, region="us-east-1", endpoint_url=self.kms.url)
        for n in (custody.KMS_RAW_MESSAGE_MAX + 1, 20000):
            message = bytes((i * 7 + n) % 256 for i in range(n))
            hasher = _mldsa.MLDSAMuHasher(self.kms.priv.public_key())
            hasher.update(message)
            mu = hasher.finalize()
            self.assertEqual(len(mu), 64)
            self.assertEqual(custody.external_mu(c.public_key(), message), mu, n)
            sig = c.sign_message(message)
            call = [b for t, b in self.kms.calls if t.endswith("Sign")][-1]
            self.assertEqual(call["MessageType"], "EXTERNAL_MU", n)
            self.assertEqual(base64.b64decode(call["Message"]), mu, n)
            self.assertTrue(_verify_raw(sig, c.public_key(), message), n)
            self.kms.priv.public_key().verify(sig, message)      # pure ML-DSA-65 over the message
            self.assertFalse(_verify_raw(sig, c.public_key(), message[:-1]), n)

    def test_wrong_key_spec_is_refused_at_load(self):
        self.kms.key_spec = "RSA_2048"
        with self.assertRaises(custody.CustodyError):
            custody.AwsKmsCustody(self.kms.key_id, region="us-east-1", endpoint_url=self.kms.url)

    def test_disabled_key_is_refused_at_load(self):
        self.kms.state = "Disabled"
        with self.assertRaises(custody.CustodyError):
            custody.AwsKmsCustody(self.kms.key_id, region="us-east-1", endpoint_url=self.kms.url)

    def test_env_selects_kms_and_pqc_signing_routes_through_it(self):
        os.environ.update({"POLARIS_CUSTODY_DRIVER": "awskms", "POLARIS_CUSTODY_AWSKMS_KEY_ID": self.kms.key_id,
                           "POLARIS_CUSTODY_AWSKMS_REGION": "us-east-1",
                           "POLARIS_CUSTODY_AWSKMS_ENDPOINT_URL": self.kms.url})
        custody.reset()
        self.assertIsInstance(custody.get_custody(), custody.AwsKmsCustody)
        self.assertEqual(pqc_signing.trust_anchor_public_key_hex(), self.kms.pub_raw.hex())
        self.assertIsNone(pqc_signing._load_persistent_keypair(), "a KMS key has no exportable secret")
        rep = pqc_signing.availability_report()["custody"]
        self.assertEqual(rep["driver"], "awskms")
        if pqc_signing.is_available():
            os.environ["POLARIS_USE_REAL_PQC"] = "1"
            sig, alg, pkhex = pqc_signing.signature_with_key_for_token("token-ABC")
            self.assertEqual((alg, pkhex), ("ML-DSA-65", self.kms.pub_raw.hex()))
            self.assertTrue(pqc_signing.verify_token_signature("token-ABC", sig, alg))

    @unittest.skipUnless(os.environ.get("POLARIS_CUSTODY_AWSKMS_LIVE_KEY_ID"), "opt-in: needs a real KMS key")
    def test_live_aws_kms(self):
        self._env.__exit__()   # use the real ambient AWS credentials
        c = custody.AwsKmsCustody(os.environ["POLARIS_CUSTODY_AWSKMS_LIVE_KEY_ID"],
                                  region=os.environ.get("AWS_DEFAULT_REGION"))
        sig = c.sign(_DIGEST)
        self.assertTrue(_verify(sig, c.public_key()))


# ---------------------------------------------------------------------------
_P11 = os.environ.get("POLARIS_CUSTODY_PKCS11_MODULE")
_P11_REQUIRE = os.environ.get("POLARIS_CUSTODY_PKCS11_REQUIRE") == "1"


class Pkcs11CustodyTests(unittest.TestCase):
    """Against a real PKCS#11 token (CI: Kryoptic). Needs the module path, a
    token labelled POLARIS_CUSTODY_PKCS11_TOKEN_LABEL (default polaris) with the
    user PIN in POLARIS_CUSTODY_PKCS11_PIN_FILE."""

    def setUp(self):
        if not _P11:
            if _P11_REQUIRE:
                self.fail("POLARIS_CUSTODY_PKCS11_REQUIRE=1 but no POLARIS_CUSTODY_PKCS11_MODULE")
            self.skipTest("no PKCS#11 module configured")
        self.module = _P11
        self.token = os.environ.get("POLARIS_CUSTODY_PKCS11_TOKEN_LABEL", "polaris")
        with open(os.environ["POLARIS_CUSTODY_PKCS11_PIN_FILE"]) as fh:
            self.pin = fh.read().strip()
        # One key per TEST, not per process: the driver refuses a duplicate label
        # by design, and a per-process label made the second setUp trip it (found
        # by running the drill, v9.179).
        self.label = "polaris-test-%d-%s" % (os.getpid(), self._testMethodName)
        self.pk = custody.pkcs11_generate_key(self.module, self.token, self.pin, self.label)

    def test_key_is_generated_in_token_and_signatures_verify_by_both_witnesses(self):
        self.assertEqual(len(self.pk), custody.PUBLIC_KEY_LEN)
        c = custody.Pkcs11Custody(self.module, self.token, self.pin, self.label)
        self.assertEqual(c.public_key(), self.pk)
        sig = c.sign(_DIGEST)
        self.assertEqual(len(sig), custody.SIGNATURE_LEN)
        self.assertTrue(_verify(sig, self.pk))
        self.assertFalse(_verify(sig, self.pk, b"token-XYZ"))
        self.assertEqual(c.describe()["driver"], "pkcs11")

    def test_duplicate_label_is_refused(self):
        with self.assertRaises(custody.CustodyError):
            custody.pkcs11_generate_key(self.module, self.token, self.pin, self.label)

    def test_sign_message_is_ckm_ml_dsa_over_the_message_itself(self):
        c = custody.Pkcs11Custody(self.module, self.token, self.pin, self.label)
        sig = c.sign_message(_SIG_STRUCTURE)
        self.assertEqual(len(sig), custody.SIGNATURE_LEN)
        self.assertTrue(_verify_raw(sig, self.pk, _SIG_STRUCTURE))
        self.assertFalse(_verify_raw(sig, self.pk, hashlib.sha3_256(_SIG_STRUCTURE).digest()))

    def test_env_selects_pkcs11_and_pqc_signing_routes_through_it(self):
        pf = tempfile.NamedTemporaryFile("w", delete=False); pf.write(self.pin); pf.close()
        with _EnvSnapshot():
            os.environ.update({"POLARIS_CUSTODY_DRIVER": "pkcs11", "POLARIS_CUSTODY_PKCS11_MODULE": self.module,
                               "POLARIS_CUSTODY_PKCS11_TOKEN_LABEL": self.token,
                               "POLARIS_CUSTODY_PKCS11_PIN_FILE": pf.name,
                               "POLARIS_CUSTODY_PKCS11_KEY_LABEL": self.label})
            custody.reset()
            self.assertIsInstance(custody.get_custody(), custody.Pkcs11Custody)
            self.assertEqual(pqc_signing.trust_anchor_public_key_hex(), self.pk.hex())
            if pqc_signing.is_available():
                os.environ["POLARIS_USE_REAL_PQC"] = "1"
                sig, alg, pkhex = pqc_signing.signature_with_key_for_token("token-ABC")
                self.assertEqual((alg, pkhex), ("ML-DSA-65", self.pk.hex()))
                self.assertTrue(pqc_signing.verify_token_signature("token-ABC", sig, alg))
        os.unlink(pf.name)

    def test_in_token_rotation_old_token_still_verifies_new_key_signs(self):
        """PE.4: rotate the in-token issuer key. New issuance signs under the NEW key, and a
        token signed under the OLD key still verifies under the public key stored with its
        signature, as the relying-party door checks it, while the custody key, now the new
        one, no longer verifies it: the sole-HSM profile's rotation, end to end and in-token.
        The key register says whether the old key was authorized when it signed."""
        if not pqc_signing.is_available():
            self.skipTest("liboqs not installed")
        pin_file = tempfile.NamedTemporaryFile("w", delete=False)
        pin_file.write(self.pin); pin_file.close()
        new_label = self.label + "-v2"
        new_pk = custody.pkcs11_generate_key(self.module, self.token, self.pin, new_label)
        self.assertNotEqual(new_pk, self.pk)  # two distinct in-token roots
        try:
            with _EnvSnapshot():
                base = {"POLARIS_CUSTODY_DRIVER": "pkcs11",
                        "POLARIS_CUSTODY_PKCS11_MODULE": self.module,
                        "POLARIS_CUSTODY_PKCS11_TOKEN_LABEL": self.token,
                        "POLARIS_CUSTODY_PKCS11_PIN_FILE": pin_file.name,
                        "POLARIS_USE_REAL_PQC": "1"}
                # Sign token T1 under the OLD key (v1).
                os.environ.update(base)
                os.environ["POLARIS_CUSTODY_PKCS11_KEY_LABEL"] = self.label
                custody.reset()
                sig_old, alg, pk_old = pqc_signing.signature_with_key_for_token("token-ROT-1")
                self.assertEqual(pk_old, self.pk.hex())
                self.assertTrue(pqc_signing.verify_token_signature("token-ROT-1", sig_old, alg))
                # ROTATE: the custody key is now v2.
                os.environ["POLARIS_CUSTODY_PKCS11_KEY_LABEL"] = new_label
                custody.reset()
                sig_new, alg2, pk_new = pqc_signing.signature_with_key_for_token("token-ROT-2")
                self.assertEqual(pk_new, new_pk.hex())
                self.assertEqual(pqc_signing.trust_anchor_public_key_hex(), new_pk.hex())
                self.assertTrue(pqc_signing.verify_token_signature("token-ROT-2", sig_new, alg2))
                # The OLD token still verifies under the key stored with its signature (v1), and
                # the custody key (v2) does not verify it.
                self.assertTrue(pqc_signing.verify_stored_signature("token-ROT-1", sig_old, pk_old,
                                                                    algorithm=alg))
                self.assertFalse(pqc_signing.verify_token_signature("token-ROT-1", sig_old, alg))
        finally:
            os.unlink(pin_file.name)


# ---------------------------------------------------------------------------
class EnvSelectionTests(unittest.TestCase):
    def test_nothing_configured_means_no_custody(self):
        """The lookup reports None in every environment. What refuses in production is
        signing without custody (ProductionSigningKeyTests)."""
        with _EnvSnapshot():
            self.assertIsNone(custody.get_custody())
            self.assertIsNone(pqc_signing.trust_anchor_public_key_hex())
            self.assertIsNone(pqc_signing.availability_report()["custody"])

    def test_unknown_driver_fails_loud(self):
        with _EnvSnapshot():
            os.environ["POLARIS_CUSTODY_DRIVER"] = "vault"
            with self.assertRaises(custody.CustodyError):
                custody.get_custody()

    def test_pin_in_env_is_refused(self):
        with _EnvSnapshot():
            os.environ.update({"POLARIS_CUSTODY_DRIVER": "pkcs11", "POLARIS_CUSTODY_PKCS11_MODULE": "/x.so",
                               "POLARIS_CUSTODY_PKCS11_PIN_FILE": "/x", "POLARIS_CUSTODY_PKCS11_PIN": "1234"})
            with self.assertRaises(custody.CustodyError) as cm:
                custody.get_custody()
            self.assertIn("PIN_FILE", str(cm.exception))

    def test_the_pin_file_is_read_under_the_key_file_checks(self):
        """The PIN file goes through the key file's reader: one that group or others can write,
        or one in a directory they can write, is refused before any module loads. A PIN file
        that passes gets as far as the module, which does not exist here."""
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        pin = os.path.join(d.name, "pkcs11_pin")
        with open(pin, "w") as fh:
            fh.write("1234\n")
        for file_mode, dir_mode, refusal in ((0o620, 0o700, "is writable by group or others"),
                                             (0o600, 0o777, "which group or others can write"),
                                             (0o600, 0o700, None)):
            with self.subTest(file_mode=oct(file_mode), dir_mode=oct(dir_mode)), _EnvSnapshot():
                os.chmod(pin, file_mode)
                os.chmod(d.name, dir_mode)
                os.environ.update({"POLARIS_CUSTODY_DRIVER": "pkcs11",
                                   "POLARIS_CUSTODY_PKCS11_MODULE": "/nonexistent/libpkcs11.so",
                                   "POLARIS_CUSTODY_PKCS11_PIN_FILE": pin})
                try:
                    with self.assertRaises(custody.CustodyError) as cm:
                        custody.get_custody()
                finally:
                    os.chmod(d.name, 0o700)
                if refusal:
                    self.assertTrue(str(cm.exception).startswith("pkcs11 PIN: "), cm.exception)
                    self.assertIn(refusal, str(cm.exception))
                else:
                    self.assertFalse(str(cm.exception).startswith("pkcs11 PIN"), cm.exception)

    def test_incomplete_driver_config_fails_loud(self):
        with _EnvSnapshot():
            os.environ["POLARIS_CUSTODY_DRIVER"] = "awskms"
            with self.assertRaises(custody.CustodyError):
                custody.get_custody()
            os.environ["POLARIS_CUSTODY_DRIVER"] = "pkcs11"
            with self.assertRaises(custody.CustodyError):
                custody.get_custody()

    def test_misconfigured_custody_is_reported_not_raised_in_the_availability_report(self):
        with _EnvSnapshot():
            os.environ["POLARIS_CUSTODY_DRIVER"] = "nope"
            self.assertIn("error", pqc_signing.availability_report()["custody"])



@unittest.skipUnless(pqc_signing.is_available() and pqc_signing.second_witness_available(),
                     "needs liboqs and the second witness")
class ProductionSigningKeyTests(unittest.TestCase):
    """With no custody configured, real signing makes a keypair for each call, which no key
    register, trust list or anchor file names. Development and test sign that way; under
    POLARIS_ENV=production every entry point that would refuses instead (app.py also refuses
    to boot there without a key)."""

    def setUp(self):
        self._env = _EnvSnapshot().__enter__()
        os.environ["POLARIS_USE_REAL_PQC"] = "1"

    def tearDown(self):
        self._env.__exit__()

    ENTRY_POINTS = (
        ("sign", lambda: pqc_signing.sign(b"token-ABC")),
        ("issuance", lambda: pqc_signing.signature_with_key_for_token("token-ABC")),
        ("a signed statement", lambda: pqc_signing.signature_over_message(b'{"format":"x"}')),
        ("COSE", lambda: pqc_signing.signature_over_cose_sig_structure(_SIG_STRUCTURE)),
        ("migration", lambda: pqc_signing.signature_for_migration("token-ABC", "ML-DSA-65")),
    )

    def test_development_signs_under_a_key_made_for_each_call(self):
        self.assertIsNone(custody.get_custody())
        first, second = pqc_signing.sign(b"token-ABC"), pqc_signing.sign(b"token-ABC")
        self.assertNotEqual(first.public_key_hex, second.public_key_hex)
        for name, call in self.ENTRY_POINTS:
            self.assertTrue(call(), name)

    def test_production_refuses_to_sign_without_custody(self):
        os.environ["POLARIS_ENV"] = "production"
        self.assertIsNone(custody.get_custody(), "the lookup reports the absence; signing refuses")
        for name, call in self.ENTRY_POINTS:
            with self.assertRaises(custody.CustodyError, msg=name) as cm:
                call()
            self.assertIn("no signing key is configured", str(cm.exception), name)


@unittest.skipUnless(pqc_signing.is_available(), "liboqs not installed")
class HeldOutCustodyTests(unittest.TestCase):
    """A held-out round on 2026-09-24: of twelve mutations of custody.py, six survived this
    file, test_pqc_signing, the simulator and nine test_app classes. Each test is the one input
    that separates a mutant from the code as written."""

    def setUp(self):
        self._env = _EnvSnapshot().__enter__()
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        self._env.__exit__()

    def _key(self, path, kp=None):
        kp = kp or pqc_signing.generate_keypair()
        with open(path, "w") as fh:
            json.dump(kp, fh)
        return kp["public_key_hex"]

    def test_an_agency_id_cannot_reach_outside_the_keys_directory(self):
        """The id becomes a file name. A path in place of an id would load whatever key file
        sat where it pointed; it is refused as an id and the global key answers instead."""
        keys = os.path.join(self.dir, "agencies")
        os.mkdir(keys)
        outside = self._key(os.path.join(self.dir, "outside.json"))
        glob = self._key(os.path.join(self.dir, "global.json"))
        os.environ["POLARIS_AGENCY_KEYS_DIR"] = keys
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = os.path.join(self.dir, "global.json")
        custody.reset()
        got = custody.get_custody_for_agency("../outside").public_key().hex()
        self.assertNotEqual(got, outside)
        self.assertEqual(got, glob)

    def test_a_rotated_agency_key_is_picked_up_without_a_restart(self):
        path = os.path.join(self.dir, "7.json")
        first = self._key(path)
        os.environ["POLARIS_AGENCY_KEYS_DIR"] = self.dir
        custody.reset()
        self.assertEqual(custody.get_custody_for_agency(7).public_key().hex(), first)
        second = self._key(path)
        st = os.stat(path)
        os.utime(path, (st.st_atime + 10, st.st_mtime + 10))
        self.assertEqual(custody.get_custody_for_agency(7).public_key().hex(), second)

    def test_the_configured_key_is_not_used_for_another_parameter_set(self):
        """With no migration key file, a migration to a set the running key is not under is
        refused. The existing test of this refusal went through the migration key file."""
        self._key(os.path.join(self.dir, "global.json"))
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = os.path.join(self.dir, "global.json")
        custody.reset()
        self.assertEqual(custody.get_custody().algorithm, "ML-DSA-65")
        self.assertIs(custody.get_custody_for_algorithm("ML-DSA-65"), custody.get_custody())
        with self.assertRaises(custody.AlgorithmUnavailableError):
            custody.get_custody_for_algorithm("ML-DSA-87")

    def test_an_unaccepted_parameter_set_is_refused_before_any_key_is_looked_at(self):
        with self.assertRaises(custody.CustodyError):
            custody.get_custody_for_algorithm("ML-DSA-44")

    def test_a_named_migration_key_file_that_is_absent_is_refused(self):
        """Set but missing is a misconfiguration: the running key must not answer for a
        migration the operator pointed at a different key, whichever set is targeted."""
        self._key(os.path.join(self.dir, "global.json"))
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = os.path.join(self.dir, "global.json")
        os.environ["POLARIS_MIGRATION_SIGNING_KEY_FILE"] = os.path.join(self.dir, "absent.json")
        custody.reset()
        for algorithm in ("ML-DSA-65", "ML-DSA-87"):
            with self.assertRaises(custody.CustodyError) as ctx:
                custody.get_custody_for_algorithm(algorithm)
            self.assertNotIsInstance(ctx.exception, custody.AlgorithmUnavailableError)
            self.assertIn("names no file", str(ctx.exception))

    def test_the_driver_name_is_not_case_sensitive(self):
        self._key(os.path.join(self.dir, "global.json"))
        os.environ["POLARIS_CUSTODY_DRIVER"] = "  FILE "
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = os.path.join(self.dir, "global.json")
        custody.reset()
        self.assertEqual(custody.get_custody().driver, "file")

    def test_a_signature_of_the_wrong_length_is_refused(self):
        """A driver's backend returning the wrong material must fail loud, the same way the
        digest check refuses the wrong input. Tested for the digest, not for the output."""
        path = os.path.join(self.dir, "global.json")
        self._key(path)
        c = custody.FileCustody(path)
        sig = c.sign(_DIGEST)
        self.assertEqual(c._check_signature(sig), sig, "control: a real signature passes")
        for bad in (sig[:-1], sig + b"\x00", b""):
            with self.assertRaises(custody.CustodyError):
                c._check_signature(bad)


if __name__ == "__main__":
    unittest.main()
