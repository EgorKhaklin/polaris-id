# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The pgBackRest repo renderer keeps the local repo and adds the bucket as an encrypted repo2.

polaris_web/pgbackrest-conf.sh writes conf.d/repo.conf at every postgres start. Without a bucket
the repository is local (repo1). With one, the bucket is repo2 beside the local repo1, encrypted by
pgBackRest, and the passphrase comes from the mounted secret fragment (conf.d/repo-creds.conf)
alone: a bucket without it (or with one under 32 characters), or a passphrase in env, is refused.
An operator-mounted repo.conf, or a fragment, that configures a repository off this host without a
cipher is refused too. These tests run the real script against a temporary conf.d with a minimal
environment; they need no Docker and no pgBackRest. The drill that runs the result against an S3
endpoint is scripts/polaris-offsite-drill.sh.

    python3 -m unittest test_pgbackrest_conf      (from scripts/)
"""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
RENDERER = ROOT / "polaris_web" / "pgbackrest-conf.sh"
BUCKET = {"POLARIS_PGBACKREST_S3_BUCKET": "polaris-backups",
          "POLARIS_PGBACKREST_S3_ENDPOINT": "s3.eu-central-1.amazonaws.com",
          "POLARIS_PGBACKREST_S3_REGION": "eu-central-1"}
PASS = "a-test-passphrase-only-7f3c-0123456789abcdef"
CREDS_FULL = ("[global]\nrepo2-s3-key=AKIATEST\nrepo2-s3-key-secret=test-secret\n"
              "repo2-cipher-pass=%s\n" % PASS)


class RendererKeepsTheLocalRepoAndEncryptsTheOffsiteOne(unittest.TestCase):

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="pgbr-conf-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.confd = self.tmp / "conf.d"
        self.confd.mkdir()
        self.out = self.confd / "repo.conf"

    def _run(self, creds=None, args=None, **env):
        if creds is not None:
            (self.confd / "repo-creds.conf").write_text(creds)
        full = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                # No mount table unless a test supplies one: the host's own must not decide.
                "POLARIS_PGBACKREST_MOUNTINFO": str(self.tmp / "no-mountinfo")}
        full.update(env)
        return subprocess.run(["bash", str(RENDERER), *(args or [str(self.out)])], env=full,
                              capture_output=True, text=True, timeout=30)

    def _mounted(self, conf, creds=None, **env):
        """Run with OUT listed as a mount point in a fixture mount table, as a bind mount is."""
        self.out.write_text(conf)
        table = self.tmp / "mountinfo"
        table.write_text("36 35 98:0 / %s ro,relatime - ext4 /dev/sda1 rw\n" % self.out)
        return self._run(creds=creds, POLARIS_PGBACKREST_MOUNTINFO=str(table), **env)

    def _lines(self):
        return [l for l in self.out.read_text().splitlines() if l and not l.startswith("#")]

    def test_no_bucket_renders_the_local_repo1_only(self):
        r = self._run()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self._lines(), ["[global]", "repo1-path=/var/lib/pgbackrest"])
        self.assertIn("NOT offsite", r.stdout)

    def test_bucket_with_a_passphrase_adds_an_encrypted_repo2_beside_the_local_repo1(self):
        r = self._run(creds=CREDS_FULL, POLARIS_PGBACKREST_S3_PORT="9000",
                      POLARIS_PGBACKREST_S3_URI_STYLE="path",
                      POLARIS_PGBACKREST_S3_CA_FILE="/etc/pgbackrest/s3-ca.crt", **BUCKET)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = self._lines()
        self.assertIn("repo1-path=/var/lib/pgbackrest", lines)
        for want in ("repo2-type=s3", "repo2-s3-bucket=polaris-backups",
                     "repo2-s3-endpoint=s3.eu-central-1.amazonaws.com", "repo2-s3-region=eu-central-1",
                     "repo2-s3-uri-style=path", "repo2-storage-verify-tls=y", "repo2-path=/polaris",
                     "repo2-cipher-type=aes-256-cbc", "repo2-retention-full=2", "repo2-bundle=y",
                     "repo2-storage-port=9000", "repo2-storage-ca-file=/etc/pgbackrest/s3-ca.crt"):
            self.assertIn(want, lines)
        # The bucket no longer replaces the local repo, and repo1 carries nothing of S3.
        self.assertEqual([l for l in lines if l.startswith("repo1-")], ["repo1-path=/var/lib/pgbackrest"])
        # The passphrase stays in the secret fragment: never copied into the 0644 repo.conf.
        text = self.out.read_text()
        self.assertNotIn(PASS, text)
        self.assertNotIn("cipher-pass", text)
        self.assertNotIn(PASS, r.stdout + r.stderr)

    def test_bucket_without_a_passphrase_is_refused_and_nothing_is_written(self):
        cases = {
            "no fragment at all": None,
            "the key pair only": "[global]\nrepo2-s3-key=AKIATEST\nrepo2-s3-key-secret=test-secret\n",
            "a commented-out passphrase": CREDS_FULL.replace("repo2-cipher-pass=", "# repo2-cipher-pass="),
            "an empty passphrase": CREDS_FULL.replace("repo2-cipher-pass=%s" % PASS, "repo2-cipher-pass="),
            "a repo1 passphrase": CREDS_FULL.replace("repo2-cipher-pass=", "repo1-cipher-pass="),
        }
        for what, creds in cases.items():
            with self.subTest(what=what):
                (self.confd / "repo-creds.conf").unlink(missing_ok=True)
                r = self._run(creds=creds, **BUCKET)
                self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
                self.assertIn("repo2-cipher-pass", r.stderr)
                self.assertFalse(self.out.exists(), "a refused render must not write repo.conf")

    def test_a_passphrase_under_32_characters_is_refused(self):
        for short in ("x" * 31, "correct horse battery staple"):
            with self.subTest(length=len(short)):
                r = self._run(creds=CREDS_FULL.replace(PASS, short), **BUCKET)
                self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
                self.assertIn("At least 32 are required", r.stderr)
                self.assertNotIn(short, r.stdout + r.stderr)
                self.assertFalse(self.out.exists())
        r = self._run(creds=CREDS_FULL.replace(PASS, "y" * 32), **BUCKET)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_the_deploy_preflight_form_reads_the_named_fragment(self):
        # polaris-deploy.sh runs the renderer against the host's secrets/pgbackrest_repo_creds.conf.
        host = self.tmp / "host-secrets.conf"
        host.write_text("[global]\nrepo2-s3-key=AKIATEST\nrepo2-s3-key-secret=test-secret\n")
        r = self._run(args=[str(self.out), str(host)], **BUCKET)
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn(str(host), r.stderr)
        self.assertIn("repo2-cipher-pass. The offsite repo", r.stderr)
        host.write_text(CREDS_FULL)
        r = self._run(args=[str(self.out), str(host)], **BUCKET)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("repo2-cipher-type=aes-256-cbc", self._lines())

    def test_a_mounted_repo_conf_off_this_host_without_a_cipher_is_refused(self):
        S3 = "[global]\nrepo1-path=/var/lib/pgbackrest\nrepo2-type=s3\nrepo2-s3-bucket=b\nrepo2-path=/p\n"
        cases = {
            "no cipher": (S3, None),
            "cipher none": (S3 + "repo2-cipher-type=none\n", None),
            "an un-indexed name": ("[global]\nrepo-type=azure\nrepo-path=/p\n", None),
            "a gcs repo1": ("[global]\nrepo1-type=gcs\nrepo1-path=/p\n", None),
        }
        for what, (conf, creds) in cases.items():
            with self.subTest(what=what):
                r = self._mounted(conf, creds=creds)
                self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
                self.assertIn("with no cipher", r.stderr)
                self.assertEqual(self.out.read_text(), conf, "a mounted file is never rewritten")

    def test_a_mounted_repo_conf_that_encrypts_or_stays_local_is_left_in_place(self):
        S3 = "[global]\nrepo1-path=/var/lib/pgbackrest\nrepo2-type=s3\nrepo2-path=/p\n"
        cases = {
            "cipher in the mounted file": (S3 + "repo2-cipher-type=aes-256-cbc\n", None),
            "cipher in the fragment": (S3, "[global]\nrepo2-cipher-type=aes-256-cbc\nrepo2-cipher-pass=%s\n" % PASS),
            "a local repo": ("[global]\nrepo1-type=posix\nrepo1-path=/srv/backups\n", None),
        }
        for what, (conf, creds) in cases.items():
            with self.subTest(what=what):
                (self.confd / "repo-creds.conf").unlink(missing_ok=True)
                r = self._mounted(conf, creds=creds)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("operator-mounted", r.stdout)
                self.assertEqual(self.out.read_text(), conf)

    def test_a_repository_written_into_the_fragment_without_a_cipher_is_refused(self):
        smuggled = "[global]\nrepo3-type=s3\nrepo3-s3-bucket=b\nrepo3-path=/p\n"
        for bucket in ({}, BUCKET):
            with self.subTest(bucket=bool(bucket)):
                r = self._run(creds=CREDS_FULL + smuggled, **bucket)
                self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
                self.assertIn("repo3 (repo3-type=s3) with no cipher", r.stderr)
                self.assertFalse(self.out.exists())

    def test_a_fragment_still_naming_repo1_s3_keys_is_told_how_to_migrate(self):
        r = self._run(creds="[global]\nrepo1-s3-key=AKIATEST\nrepo1-s3-key-secret=test-secret\n", **BUCKET)
        self.assertEqual(r.returncode, 4, r.stderr)
        self.assertIn("rename those lines repo2-s3-*", r.stderr)

    def test_a_passphrase_in_env_is_refused_with_or_without_a_bucket(self):
        for name in ("POLARIS_PGBACKREST_CIPHER_PASS", "POLARIS_PGBACKREST_S3_CIPHER_PASS",
                     "PGBACKREST_REPO2_CIPHER_PASS", "PGBACKREST_REPO1_CIPHER_PASS"):
            for bucket in ({}, BUCKET):
                with self.subTest(name=name, bucket=bool(bucket)):
                    r = self._run(creds=CREDS_FULL, **{name: "leaked-passphrase-value"}, **bucket)
                    self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
                    self.assertIn(name, r.stderr)
                    self.assertIn("ENVIRONMENT", r.stderr)
                    self.assertNotIn("leaked-passphrase-value", r.stdout + r.stderr)
                    self.assertFalse(self.out.exists(), "a refused render must not write repo.conf")

    def test_the_key_pair_in_env_is_still_refused(self):
        for name in ("POLARIS_PGBACKREST_S3_KEY", "POLARIS_PGBACKREST_S3_KEY_SECRET"):
            with self.subTest(name=name):
                r = self._run(creds=CREDS_FULL, **{name: "leaked"}, **BUCKET)
                self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
                self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
