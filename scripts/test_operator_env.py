# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""An operator script run by hand reads the configuration polaris.service runs with.

On a systemd host the unit reads /etc/polaris/polaris.env; `sudo` resets the environment, so a
script run by hand had none of it: docker-compose.prod.yml refused to load for want of
POLARIS_DOMAIN, and a domain exported alone gave a deploy without the rest of the file. And
polaris.service runs compose with POLARIS_SECRETS_DIR alone, so a sealed host with that variable
empty started from the shredded plaintext directory. These tests run scripts/polaris-env.sh and
the real scripts under bash, with a stand-in `systemctl` and `docker` on PATH. They need no
database, no Docker and no systemd.

    python3 -m unittest test_operator_env      (from scripts/)
"""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOADER = ROOT / "scripts" / "polaris-env.sh"

ENV_FILE = "\n".join([
    "# polaris.env the way install.sh writes it",
    "; a systemd comment",
    "POLARIS_DOMAIN=polaris.example.org",
    "POLARIS_COMPOSE_EXTRA=-f docker-compose.citest.yml",
    'WEB_CONCURRENCY="6"',
    "POLARIS_QUOTED='a b'",
    "POLARIS_TRAILING=x" + "   ",
    "POLARIS_LEADING=   y",
    "POLARIS_INLINE=v # systemd keeps this",
    "POLARIS_NEVER_RUN=$(touch {canary})",
    "  POLARIS_INDENTED=ok",
    "not a variable line",
    "POLARIS_SECRETS_DIR=",
    "POLARIS_LAST=no-newline",
])


class _Base(unittest.TestCase):

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-env-"))
        self.canary = self.tmp / "executed"
        self.env_file = self.tmp / "polaris.env"
        self.env_file.write_text(ENV_FILE.format(canary=self.canary))
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        # The stand-in systemctl answers `show -p <property> --value polaris.service`.
        (self.bin / "systemctl").write_text(
            '#!/bin/sh\ncase "$*" in\n'
            '  *WorkingDirectory*) printf "%s\\n" "$STUB_WD" ;;\n'
            '  *EnvironmentFiles*) [ -n "$STUB_EF" ] && printf "%s (ignore_errors=no)\\n" "$STUB_EF" ;;\n'
            'esac\nexit 0\n')
        # The stand-in docker records that it was called and fails, so a script that reaches it
        # is caught rather than run against this machine.
        self.docker_log = self.tmp / "docker-called"
        (self.bin / "docker").write_text('#!/bin/sh\necho "$*" >> "%s"\nexit 99\n' % self.docker_log)
        for f in self.bin.iterdir():
            f.chmod(0o755)

    def _bash(self, script, **env):
        full = {"PATH": "%s:/usr/bin:/bin:/usr/sbin:/sbin" % self.bin, "HOME": str(self.tmp),
                "STUB_WD": "", "STUB_EF": ""}
        full.update(env)
        return subprocess.run(["bash", "-c", script], env=full, capture_output=True, text=True, timeout=60)

    def _load(self, *names, **env):
        script = 'set -euo pipefail\nsource "%s"\n' % LOADER
        script += "".join('printf "%%s=[%%s]\\n" %s "${%s-UNSET}"\n' % (n, n) for n in names)
        r = self._bash(script, **env)
        self.assertEqual(r.returncode, 0, r.stderr)
        return dict(line.split("=", 1) for line in r.stdout.splitlines()), r


class LoaderTests(_Base):

    def test_the_named_file_is_parsed_the_way_systemd_reads_it(self):
        got, r = self._load("POLARIS_DOMAIN", "POLARIS_COMPOSE_EXTRA", "WEB_CONCURRENCY", "POLARIS_QUOTED",
                            "POLARIS_TRAILING", "POLARIS_LEADING", "POLARIS_INLINE", "POLARIS_INDENTED",
                            "POLARIS_SECRETS_DIR", "POLARIS_LAST", POLARIS_ENV_FILE=str(self.env_file))
        self.assertEqual(got["POLARIS_DOMAIN"], "[polaris.example.org]")
        self.assertEqual(got["POLARIS_COMPOSE_EXTRA"], "[-f docker-compose.citest.yml]")
        self.assertEqual(got["WEB_CONCURRENCY"], "[6]")
        self.assertEqual(got["POLARIS_QUOTED"], "[a b]")
        self.assertEqual(got["POLARIS_TRAILING"], "[x]")
        self.assertEqual(got["POLARIS_LEADING"], "[y]")
        self.assertEqual(got["POLARIS_INLINE"], "[v # systemd keeps this]")
        self.assertEqual(got["POLARIS_INDENTED"], "[ok]")
        self.assertEqual(got["POLARIS_SECRETS_DIR"], "[]", "an empty value is set, and empty")
        self.assertEqual(got["POLARIS_LAST"], "[no-newline]", "a last line without a newline is read")
        self.assertIn("polaris-env: read %s" % self.env_file, r.stderr)

    def test_nothing_in_the_file_is_executed(self):
        got, _ = self._load("POLARIS_NEVER_RUN", "POLARIS_COMPOSE_EXTRA", POLARIS_ENV_FILE=str(self.env_file))
        self.assertFalse(self.canary.exists(), "a $(...) in a value ran")
        self.assertEqual(got["POLARIS_NEVER_RUN"], "[$(touch %s)]" % self.canary)
        self.assertFalse((self.bin / "docker-compose.citest.yml").exists())

    def test_a_variable_the_caller_set_wins(self):
        got, _ = self._load("POLARIS_DOMAIN", "WEB_CONCURRENCY", POLARIS_ENV_FILE=str(self.env_file),
                            POLARIS_DOMAIN="from.the.command.line", WEB_CONCURRENCY="")
        self.assertEqual(got["POLARIS_DOMAIN"], "[from.the.command.line]")
        self.assertEqual(got["WEB_CONCURRENCY"], "[]", "set and empty is still the caller's")

    def test_the_units_file_is_read_only_for_the_checkout_the_unit_runs(self):
        got, _ = self._load("POLARIS_DOMAIN", STUB_WD=str(ROOT / "polaris_web"), STUB_EF=str(self.env_file))
        self.assertEqual(got["POLARIS_DOMAIN"], "[polaris.example.org]")
        other = self.tmp / "another-checkout" / "polaris_web"
        other.mkdir(parents=True)
        got, r = self._load("POLARIS_DOMAIN", STUB_WD=str(other), STUB_EF=str(self.env_file))
        self.assertEqual(got["POLARIS_DOMAIN"], "[UNSET]", "another checkout's unit was read")
        self.assertNotIn("polaris-env: read", r.stderr)
        got, _ = self._load("POLARIS_DOMAIN")
        self.assertEqual(got["POLARIS_DOMAIN"], "[UNSET]", "without a unit nothing is read")

    def test_an_empty_POLARIS_ENV_FILE_reads_nothing(self):
        got, _ = self._load("POLARIS_DOMAIN", POLARIS_ENV_FILE="", STUB_WD=str(ROOT / "polaris_web"),
                            STUB_EF=str(self.env_file))
        self.assertEqual(got["POLARIS_DOMAIN"], "[UNSET]")

    def test_an_unreadable_file_is_named_and_not_fatal(self):
        got, r = self._load("POLARIS_DOMAIN", POLARIS_ENV_FILE=str(self.tmp / "missing.env"))
        self.assertEqual(got["POLARIS_DOMAIN"], "[UNSET]")
        self.assertIn("cannot read", r.stderr)


class SecretsDirTests(_Base):

    def _dir(self, **env):
        return self._bash('set -euo pipefail\nsource "%s"\npolaris_secrets_dir' % LOADER,
                          POLARIS_ENV_FILE="", **env)

    def test_the_file_backend_reads_the_plaintext_directory(self):
        r = self._dir()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), str(ROOT / "polaris_web" / "secrets"))

    def test_a_sealed_backend_without_a_directory_is_refused(self):
        for backend in ("age", "awskms"):
            with self.subTest(backend=backend):
                r = self._dir(POLARIS_SECRETS_BACKEND=backend, POLARIS_SECRETS_DIR="")
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertEqual(r.stdout, "")
                self.assertIn("needs POLARIS_SECRETS_DIR=/run/polaris/secrets", r.stderr)

    def test_a_sealed_backend_reads_the_directory_it_names(self):
        r = self._dir(POLARIS_SECRETS_BACKEND="age", POLARIS_SECRETS_DIR="/run/polaris/secrets")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "/run/polaris/secrets")


class ScriptsRefuseBeforeTouchingTheStack(_Base):
    """The real scripts, run as `sudo` would run them: an empty environment, the unit's file found
    through systemctl. A sealed store without a directory is refused before Docker is called."""

    def _script(self, *argv, env_text):
        self.env_file.write_text(env_text)
        r = subprocess.run(["bash", str(ROOT / "scripts" / argv[0]), *argv[1:]], capture_output=True, text=True,
                           timeout=60, env={"PATH": "%s:/usr/bin:/bin:/usr/sbin:/sbin" % self.bin,
                                            "HOME": str(self.tmp), "STUB_WD": str(ROOT / "polaris_web"),
                                            "STUB_EF": str(self.env_file)})
        self.assertFalse(self.docker_log.exists(), "Docker was called: %s" % (
            self.docker_log.read_text() if self.docker_log.exists() else ""))
        return r

    SEALED_NO_DIR = "POLARIS_DOMAIN=polaris.example.org\nPOLARIS_SECRETS_BACKEND=age\nPOLARIS_SECRETS_DIR=\n"

    def test_deploy_refuses_a_sealed_store_without_a_directory(self):
        r = self._script("polaris-deploy.sh", "prod", "--no-pull", env_text=self.SEALED_NO_DIR)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("needs POLARIS_SECRETS_DIR", r.stderr)
        self.assertNotIn("POLARIS_DOMAIN must be set", r.stderr, "the domain came from the unit's file")

    def test_the_units_unseal_refuses_it_too(self):
        r = self._script("polaris-secrets.sh", "unseal-if-configured", env_text=self.SEALED_NO_DIR)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("needs POLARIS_SECRETS_DIR", r.stderr)

    def test_rotation_refuses_it_too(self):
        r = self._script("polaris-rotate-secret.sh", "polaris_db_password", env_text=self.SEALED_NO_DIR)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("needs POLARIS_SECRETS_DIR", r.stderr)

    def test_the_file_backend_says_the_secrets_are_plaintext_on_disk(self):
        r = self._script("polaris-secrets.sh", "unseal-if-configured",
                         env_text="POLARIS_DOMAIN=polaris.example.org\nPOLARIS_SECRETS_BACKEND=file\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("plaintext files in", r.stdout)
        self.assertIn("seal them", r.stdout)


class ComposeRunsWhereTheUnitRunsIt(_Base):
    """polaris.service runs compose in polaris_web, so an overlay polaris.env names (CI's
    `-f docker-compose.citest.yml`, an operator's blue-green file) is relative to it. #311's first CI
    run: the rotation, run by hand from /opt/polaris, passed that overlay to compose there, compose
    did not find it, and a running stack read as stopped."""

    def test_every_compose_call_runs_in_polaris_web(self):
        cwd_log = self.tmp / "docker-cwd"
        # Only compose cares where it runs (`docker info` does not): record its directory, answer the
        # rest, and fail compose so nothing runs against this machine.
        (self.bin / "docker").write_text('#!/bin/sh\ncase "$1" in compose) pwd -P >> "%s"; exit 99 ;; esac\nexit 0\n'
                                         % cwd_log)
        (self.bin / "docker").chmod(0o755)
        env_file = self.tmp / "overlay.env"
        env_file.write_text("POLARIS_DOMAIN=polaris.example.org\nPOLARIS_COMPOSE_EXTRA=-f docker-compose.citest.yml\n")
        want = str((ROOT / "polaris_web").resolve())
        for script, args in (("polaris-key-event.sh", "register 1 " + "ab" * 1952),
                             ("polaris-doctor.sh", "")):
            with self.subTest(script):
                cwd_log.unlink(missing_ok=True)
                self._bash('cd "%s" && bash "%s" %s' % (self.tmp, ROOT / "scripts" / script, args),
                           POLARIS_ENV_FILE=str(env_file))
                ran = cwd_log.read_text().split() if cwd_log.exists() else []
                self.assertTrue(ran, "%s never reached compose" % script)
                self.assertEqual(set(ran), {want}, "%s ran compose outside polaris_web" % script)


if __name__ == "__main__":
    unittest.main()
