"""test_secretstore.py — the sealed secret store (roadmap P1.3).

Every backend is exercised for real: `age` through the real age CLI with
throwaway identities (skipped only where age is not installed; CI installs
it), `awskms` through the real botocore wire path against the local KMS
stand-in whose envelope cryptography is real AES-256-GCM. Rotation of the
wrapping key is tested end to end for both, and the write-through invariant
(`verify` against the materialized directory) is what the prod-stack CI
rotation drill relies on.

Run: python3 -m unittest test_secretstore
"""

import json
import os
import stat
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secretstore as ss

_AGE = shutil.which("age") is not None and shutil.which("age-keygen") is not None


def _boto3():
    try:
        import boto3  # noqa: F401
        return True
    except ImportError:
        return False


def _make_plain(root):
    plain = os.path.join(root, "secrets")
    os.makedirs(plain, mode=0o700)
    files = {"polaris_secret_key": (b"a" * 64 + b"\n", 0o644), "polaris_db_password": (b"b" * 48 + b"\n", 0o644),
             "polaris_db_root_password": (b"c" * 48 + b"\n", 0o600),
             "polaris_signing_key": (json.dumps({"algorithm": "ML-DSA-65", "secret_key_hex": "00", "public_key_hex": "11"}).encode(), 0o644),
             "postgres_server.key": (b"-----BEGIN PRIVATE KEY-----\nxyz\n-----END PRIVATE KEY-----\n", 0o644)}
    for name, (data, mode) in files.items():
        p = os.path.join(plain, name)
        with open(p, "wb") as fh:
            fh.write(data)
        os.chmod(p, mode)
    # things seal must skip
    os.makedirs(os.path.join(plain, ".archive"))
    with open(os.path.join(plain, ".archive", "polaris_secret_key.old"), "wb") as fh:
        fh.write(b"old")
    with open(os.path.join(plain, "polaris_secret_key.new"), "wb") as fh:
        fh.write(b"tmp")
    return plain, files


class _Common:
    """Backend-agnostic assertions; subclasses provide self.backend / self.new_backend()."""

    def test_seal_unseal_roundtrip_restores_bytes_and_modes(self):
        sealed = os.path.join(self.root, "sealed")
        m = ss.seal(self.backend, self.plain, sealed)
        self.assertEqual(set(m["files"]), set(self.files), "skips .archive and .new")
        self.assertTrue(os.path.exists(os.path.join(sealed, ss.MANIFEST)))
        for name in self.files:
            blob = open(os.path.join(sealed, name + self.backend.ext), "rb").read()
            self.assertNotIn(self.files[name][0].strip(), blob, "sealed blob must not contain the plaintext")
        dst = os.path.join(self.root, "run")
        names = ss.unseal(self.backend, sealed, dst)
        self.assertEqual(set(names), set(self.files))
        for name, (data, mode) in self.files.items():
            p = os.path.join(dst, name)
            self.assertEqual(open(p, "rb").read(), data)
            self.assertEqual(os.stat(p).st_mode & 0o777, mode, f"{name} mode restored (the v9.140 lesson)")
        self.assertEqual(os.stat(dst).st_mode & 0o777, 0o700)

    def test_unseal_removes_stale_files_and_verify_detects_drift(self):
        sealed = os.path.join(self.root, "sealed")
        ss.seal(self.backend, self.plain, sealed)
        dst = os.path.join(self.root, "run")
        os.makedirs(dst)
        with open(os.path.join(dst, "retired_secret"), "wb") as fh:
            fh.write(b"gone")
        ss.unseal(self.backend, sealed, dst)
        self.assertFalse(os.path.exists(os.path.join(dst, "retired_secret")))
        self.assertEqual(ss.verify(self.backend, sealed, dst)["drift"], [])
        with open(os.path.join(dst, "polaris_db_password"), "wb") as fh:
            fh.write(b"rotated-but-not-sealed\n")
        with self.assertRaises(ss.SecretStoreError) as cm:
            ss.verify(self.backend, sealed, dst)
        self.assertIn("polaris_db_password", str(cm.exception))

    def test_tampered_blob_is_refused(self):
        sealed = os.path.join(self.root, "sealed")
        ss.seal(self.backend, self.plain, sealed)
        p = os.path.join(sealed, "polaris_secret_key" + self.backend.ext)
        blob = bytearray(open(p, "rb").read())
        blob[-5] ^= 0x01
        open(p, "wb").write(bytes(blob))
        with self.assertRaises(ss.SecretStoreError):
            ss.unseal_to_memory(self.backend, sealed)

    def test_manifest_hash_mismatch_is_refused(self):
        sealed = os.path.join(self.root, "sealed")
        ss.seal(self.backend, self.plain, sealed)
        mp = os.path.join(sealed, ss.MANIFEST)
        m = json.load(open(mp))
        m["files"]["polaris_secret_key"]["sha256"] = "0" * 64
        json.dump(m, open(mp, "w"))
        with self.assertRaises(ss.SecretStoreError):
            ss.unseal_to_memory(self.backend, sealed)

    def test_seal_only_writes_one_secret_through_and_keeps_prev(self):
        sealed = os.path.join(self.root, "sealed")
        ss.seal(self.backend, self.plain, sealed)
        with open(os.path.join(self.plain, "polaris_db_password"), "wb") as fh:
            fh.write(b"new-password\n")
        m = ss.seal(self.backend, self.plain, sealed, only="polaris_db_password")
        self.assertEqual(set(m["files"]), set(self.files), "other entries untouched")
        self.assertTrue(os.path.exists(os.path.join(sealed, "polaris_db_password" + self.backend.ext + ".prev")))
        files = ss.unseal_to_memory(self.backend, sealed)
        self.assertEqual(files["polaris_db_password"][0], b"new-password\n")
        self.assertEqual(files["polaris_secret_key"][0], self.files["polaris_secret_key"][0])

    def test_rotate_wrapping_changes_the_key_not_the_secrets(self):
        sealed = os.path.join(self.root, "sealed")
        ss.seal(self.backend, self.plain, sealed)
        new = self.new_backend()
        m = ss.rotate_wrapping(self.backend, new, sealed)
        self.assertEqual(set(m["files"]), set(self.files))
        self.assertTrue(os.path.isdir(sealed + ".prev"))
        with self.assertRaises(ss.SecretStoreError):
            ss.unseal_to_memory(self.backend, sealed)        # the OLD key no longer opens it
        files = ss.unseal_to_memory(new, sealed)             # the NEW key does
        for name, (data, _) in self.files.items():
            self.assertEqual(files[name][0], data)
        files_prev = ss.unseal_to_memory(self.backend, sealed + ".prev")
        self.assertEqual(files_prev["polaris_secret_key"][0], self.files["polaris_secret_key"][0])

    def test_backend_mismatch_is_refused(self):
        sealed = os.path.join(self.root, "sealed")
        ss.seal(self.backend, self.plain, sealed)
        with self.assertRaises(ss.SecretStoreError):
            ss.unseal_to_memory(ss.FileBackend(), sealed)


@unittest.skipUnless(_AGE, "age CLI not installed")
class AgeBackendTests(_Common, unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="polaris-ss-age-")
        self.plain, self.files = _make_plain(self.root)
        self.identity, self.recipients = self._keygen("k1")
        self.backend = ss.AgeBackend(self.recipients, self.identity)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _keygen(self, tag):
        ident = os.path.join(self.root, f"{tag}.identity")
        out = subprocess.run(["age-keygen", "-o", ident], capture_output=True, text=True, check=True)
        pub = [l.split(":", 1)[1].strip() for l in (out.stderr + out.stdout).splitlines() if "public key:" in l.lower()][0]
        rec = os.path.join(self.root, f"{tag}.recipients")
        with open(rec, "w") as fh:
            fh.write(pub + "\n")
        return ident, rec

    def new_backend(self):
        ident, rec = self._keygen("k2")
        return ss.AgeBackend(rec, ident)

    def test_unseal_without_identity_fails_loud(self):
        sealed = os.path.join(self.root, "sealed")
        ss.seal(self.backend, self.plain, sealed)
        with self.assertRaises(ss.SecretStoreError):
            ss.unseal_to_memory(ss.AgeBackend(self.recipients, None), sealed)


@unittest.skipUnless(_boto3(), "boto3 not installed")
class AwsKmsBackendTests(_Common, unittest.TestCase):
    def setUp(self):
        from kms_standin import KmsStandIn
        self.root = tempfile.mkdtemp(prefix="polaris-ss-kms-")
        self.plain, self.files = _make_plain(self.root)
        self._saved = {k: os.environ.get(k) for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")}
        os.environ["AWS_ACCESS_KEY_ID"] = "AKIATESTONLY"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "test-only-not-a-secret"
        self.kms = KmsStandIn()
        self.backend = ss.AwsKmsBackend(self.kms.key_id, region="us-east-1", endpoint_url=self.kms.url)

    def tearDown(self):
        self.kms.close()
        shutil.rmtree(self.root, ignore_errors=True)
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def new_backend(self):
        self.kms.add_symmetric_key("new-key-0000-0000-0000-000000000002")
        return ss.AwsKmsBackend("new-key-0000-0000-0000-000000000002", region="us-east-1", endpoint_url=self.kms.url)

    def test_envelope_uses_generate_data_key_and_decrypt_on_the_wire(self):
        sealed = os.path.join(self.root, "sealed")
        ss.seal(self.backend, self.plain, sealed)
        ops = [t.split(".")[-1] for t, _ in self.kms.calls]
        self.assertEqual(ops.count("GenerateDataKey"), len(self.files), "one data key per file")
        gen = next(b for t, b in self.kms.calls if t.endswith("GenerateDataKey"))
        self.assertEqual(gen["KeySpec"], "AES_256")
        blob = json.loads(open(os.path.join(sealed, "polaris_secret_key.kms"), "rb").read())
        self.assertEqual(blob["name"], "polaris_secret_key")
        self.assertIn(self.kms.key_id, blob["key_id"])
        self.kms.calls.clear()
        ss.unseal_to_memory(self.backend, sealed)
        self.assertEqual([t.split(".")[-1] for t, _ in self.kms.calls].count("Decrypt"), len(self.files))

    def test_blob_presented_under_another_name_is_refused(self):
        sealed = os.path.join(self.root, "sealed")
        ss.seal(self.backend, self.plain, sealed)
        # COPIED, not moved: moving it left polaris_db_password.kms missing, and the missing
        # file refused the store before the name was ever compared.
        shutil.copy(os.path.join(sealed, "polaris_db_password.kms"), os.path.join(sealed, "polaris_secret_key.kms"))
        with self.assertRaises(ss.SecretStoreError) as caught:
            ss.unseal_to_memory(self.backend, sealed)
        # The name check, not the AEAD behind it, and it says which: held out 2026-09-24,
        # deleting the name check survived because the AEAD refused the same blob.
        self.assertIn("renamed/tampered", str(caught.exception))

    def test_a_renamed_blob_with_its_name_field_edited_fails_authentication(self):
        """The blob's JSON is not authenticated, so an attacker renaming a file can edit its
        `name` to match. The AEAD's associated data is what still binds it to the name it was
        sealed under; with it empty, this swap decrypted to the other secret's value."""
        sealed = os.path.join(self.root, "sealed")
        ss.seal(self.backend, self.plain, sealed)
        doc = json.loads(open(os.path.join(sealed, "polaris_db_password.kms"), "rb").read())
        doc["name"] = "polaris_secret_key"
        with open(os.path.join(sealed, "polaris_secret_key.kms"), "w") as fh:
            json.dump(doc, fh)
        with self.assertRaises(ss.SecretStoreError) as caught:
            ss.unseal_to_memory(self.backend, sealed)
        self.assertIn("failed authentication", str(caught.exception))


class EnvSelectionTests(unittest.TestCase):
    def test_default_is_file_and_unknown_fails_loud(self):
        self.assertIsInstance(ss.backend_from_env({}), ss.FileBackend)
        with self.assertRaises(ss.SecretStoreError):
            ss.backend_from_env({"POLARIS_SECRETS_BACKEND": "vault"})
        with self.assertRaises(ss.SecretStoreError):
            ss.backend_from_env({"POLARIS_SECRETS_BACKEND": "awskms"})   # no key id

    def test_file_backend_is_identity(self):
        root = tempfile.mkdtemp(prefix="polaris-ss-file-")
        try:
            plain, files = _make_plain(root)
            sealed = os.path.join(root, "sealed")
            ss.seal(ss.FileBackend(), plain, sealed)
            self.assertEqual(open(os.path.join(sealed, "polaris_secret_key"), "rb").read(), files["polaris_secret_key"][0])
            self.assertEqual(ss.verify(ss.FileBackend(), sealed, plain)["drift"], [])
        finally:
            shutil.rmtree(root, ignore_errors=True)



class HeldOutSecretStoreTests(unittest.TestCase):
    """A held-out round on secretstore.py, 2026-09-24. Six of twelve mutations survived this
    file, test_custody and the check layer, and reading the code for them found a name in the
    manifest used as a path."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="polaris-ss-held-")
        self.plain, self.files = _make_plain(self.root)
        self.sealed = os.path.join(self.root, "sealed")
        ss.seal(ss.FileBackend(), self.plain, self.sealed)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _manifest(self, edit):
        path = os.path.join(self.sealed, ss.MANIFEST)
        with open(path) as fh:
            m = json.load(fh)
        edit(m)
        with open(path, "w") as fh:
            json.dump(m, fh)

    def test_a_manifest_name_cannot_write_outside_the_destination(self):
        """`unseal` joined each manifest name onto the destination directory. The manifest is
        not authenticated, and under age anybody holding the public recipients can seal a
        file, so a name like ../x wrote attacker-chosen bytes outside the tmpfs the secrets
        are meant to live in. A manifest name is a file name or the store is refused."""
        payload = b"planted\n"
        # Where the file backend reads the blob for that name: sealed/../escaped.
        with open(os.path.join(self.root, "escaped"), "wb") as fh:
            fh.write(payload)
        self._manifest(lambda m: m["files"].update(
            {"../escaped": {"sha256": ss._sha256(payload), "mode": "0600", "size": len(payload)}}))
        dst = os.path.join(self.root, "run", "secrets")
        os.makedirs(os.path.dirname(dst))
        target = os.path.join(self.root, "run", "escaped")
        with self.assertRaises(ss.SecretStoreError) as caught:
            ss.unseal(ss.FileBackend(), self.sealed, dst)
        self.assertIn("../escaped", str(caught.exception))
        self.assertFalse(os.path.exists(target), "a file was written outside the destination")
        for bad in ("/etc/x", "a/b", "..", ".", ""):
            with self.subTest(name=bad):
                self._manifest(lambda m: m.update(files={bad: {"sha256": "0" * 64}}))
                with self.assertRaises(ss.SecretStoreError):
                    ss.unseal_to_memory(ss.FileBackend(), self.sealed)

    def test_a_store_sealed_by_another_backend_is_refused_for_that_reason(self):
        """The existing test unsealed an age store with the file backend, whose file names
        have no extension, so a missing file refused it whether or not the backend was
        compared. The reason is what tells the operator which variable is wrong."""
        self._manifest(lambda m: m.update(backend="age"))
        with self.assertRaises(ss.SecretStoreError) as caught:
            ss.unseal_to_memory(ss.FileBackend(), self.sealed)
        self.assertIn("sealed with backend", str(caught.exception))

    def test_a_manifest_with_no_mode_unseals_owner_only(self):
        self._manifest(lambda m: [meta.pop("mode") for meta in m["files"].values()])
        dst = os.path.join(self.root, "out")
        ss.unseal(ss.FileBackend(), self.sealed, dst)
        for name in self.files:
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(dst, name)).st_mode), 0o600, name)

    def test_a_manifest_listing_no_files_is_refused(self):
        self._manifest(lambda m: m.update(files={}))
        with self.assertRaises(ss.SecretStoreError):
            ss.unseal_to_memory(ss.FileBackend(), self.sealed)

    def test_the_backend_name_is_not_case_sensitive(self):
        self.assertIsInstance(ss.backend_from_env({"POLARIS_SECRETS_BACKEND": " FILE "}),
                              ss.FileBackend)


if __name__ == "__main__":
    unittest.main()
