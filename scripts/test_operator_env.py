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


class DeploysTakeTurns(_Base):
    """A deploy pins the running app image as its rollback point. Under one host-wide tag, a second
    deploy that started during the first one's smoke test pinned the first one's failed release over
    it, and the first "rolled back" onto that release; and every stack on a host builds the same tags
    (reviews of #317, 2026-10-09). One build or deploy of the host's images runs at a time, and the pin
    is named for the project. The lock is a network in the Docker daemon; this stand-in keeps it in a file."""

    def setUp(self):
        super().setUp()
        self.project = "lockt%d" % (abs(hash(str(self.tmp))) % 10 ** 8)
        self.lock = self.tmp / "network"       # the stand-in daemon's polaris-host-lock network: its labels
        secrets = self.tmp / "secrets"
        secrets.mkdir()
        for name in ("polaris_secret_key", "polaris_db_password", "polaris_db_root_password",
                     "pgbackrest_repo_creds.conf"):
            (secrets / name).write_text("x\n")
        self.env_text = ("POLARIS_DOMAIN=polaris.example.org\nPOLARIS_SECRETS_BACKEND=file\n"
                         "POLARIS_SECRETS_DIR=%s\n" % secrets)
        # The stand-in Docker: compose names the project and a stopped app (only `ps -a` lists it), inspect
        # names its image, tag succeeds, and the polaris-host-lock network is a file holding its ID and labels:
        # one create makes it and prints the ID, a second is refused, rm removes it by that ID only. Anything
        # further fails, so the deploy stops at step 4 having run nothing against this machine.
        (self.bin / "docker").write_text(
            '#!/bin/sh\necho "$*" >> "%(log)s"\nNET="%(net)s"\ncase "$*" in\n'
            '  "compose version") exit 0 ;;\n'
            '  *" config") echo "name: %(project)s"; exit 0 ;;\n'
            '  *" ps -a -q app") echo cid-app; exit 0 ;;\n'
            '  "inspect --format={{.Image}} cid-app") echo sha256:feed; exit 0 ;;\n'
            '  "tag "*) exit 0 ;;\n'
            '  "network create "*)\n'
            '    [ -e "$NET" ] && { echo "Error response from daemon: network with name polaris-host-lock already exists" >&2; exit 1; }\n'
            '    id="net$$"; echo "id=$id" > "$NET"\n'
            '    for a in "$@"; do case "$a" in org.polaris.lock.*) echo "$a" >> "$NET" ;; esac; done; echo "$id"; exit 0 ;;\n'
            '  "network ls -q --filter name=^polaris-host-lock\\$") [ -e "$NET" ] && sed -n "s/^id=//p" "$NET"; exit 0 ;;\n'
            '  "network inspect -f "*)\n'
            '    [ -e "$NET" ] || exit 1; eval "last=\\${$#}"; id=$(sed -n "s/^id=//p" "$NET")\n'
            '    [ "$last" = polaris-host-lock ] || [ "$last" = "$id" ] || exit 1\n'
            '    key=$(printf %%s "$*" | sed -n "s/.*org.polaris.lock.\\([a-z]*\\).*/\\1/p")\n'
            '    sed -n "s/^org.polaris.lock.$key=//p" "$NET"; exit 0 ;;\n'
            '  "network rm "*) [ -e "$NET" ] && [ "$3" = "$(sed -n "s/^id=//p" "$NET")" ] && rm -f "$NET"; exit 0 ;;\n'
            'esac\nexit 99\n' % {"log": self.docker_log, "net": self.lock, "project": self.project})
        (self.bin / "docker").chmod(0o755)

    def _deploy(self, **env):
        self.env_file.write_text(self.env_text)
        return subprocess.run(["bash", str(ROOT / "scripts" / "polaris-deploy.sh"), "prod", "--no-pull"],
                              capture_output=True, text=True, timeout=60,
                              env=dict({"PATH": "%s:/usr/bin:/bin:/usr/sbin:/sbin" % self.bin,
                                        "HOME": str(self.tmp), "STUB_WD": str(ROOT / "polaris_web"),
                                        "STUB_EF": str(self.env_file)}, **env))

    def _calls(self):
        return self.docker_log.read_text().splitlines() if self.docker_log.exists() else []

    def test_a_deploy_pins_the_running_image_under_its_projects_name(self):
        r = self._deploy()
        tag = "tag sha256:feed polaris-app:rollback-%s" % self.project
        self.assertIn(tag, self._calls(), r.stdout + r.stderr)
        self.assertIn("pinned as polaris-app:rollback-%s" % self.project, r.stdout)
        self.assertFalse(self.lock.exists(), "the deploy's lock outlived it")
        again = self._deploy()
        self.assertEqual(self._calls().count(tag), 2, again.stdout + again.stderr)

    def _held(self, token, holder, host="another-host", boot="b", pid="1"):
        self.lock.write_text("id=netX\norg.polaris.lock.token=%s\norg.polaris.lock.holder=%s\n"
                             "org.polaris.lock.host=%s\norg.polaris.lock.boot=%s\norg.polaris.lock.pid=%s\n"
                             % (token, holder, host, boot, pid))

    def test_a_second_deploy_on_the_host_changes_nothing_and_says_who_holds_it(self):
        self._held("other", "try.sh, pid 7 on host")
        r = self._deploy()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("another Polaris build or deploy holds this host's images (try.sh, pid 7 on host)", r.stderr)
        self.assertIn("docker network rm polaris-host-lock", r.stderr)
        self.assertFalse([c for c in self._calls() if c.startswith(("tag", "inspect")) or " pull" in c],
                         "the refused deploy acted: %s" % self._calls())
        self.assertTrue(self.lock.exists(), "the refused deploy released another run's lock")

    def test_a_lock_this_host_left_is_taken_over_naming_its_holder(self):
        """Review 4 of #317: a network outlives its run, a reboot too. One this host left, by an earlier boot or
        a process that is gone, is taken over; one from another host is not."""
        import socket
        here = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip() or socket.gethostname()
        self._held("old", "a killed deploy", host=here, boot="an-earlier-boot")
        r = self._deploy()
        self.assertIn("left by a killed deploy, which is gone: taking it over", r.stderr)
        self.assertIn("tag sha256:feed polaris-app:rollback-%s" % self.project, self._calls(), r.stdout + r.stderr)
        self._held("old", "a deploy elsewhere", host="elsewhere", boot="an-earlier-boot")
        r = self._deploy()
        self.assertEqual(r.returncode, 1, "another host's lock was taken over: %s" % (r.stdout + r.stderr))

    def test_in_this_boot_a_gone_process_is_stale_and_a_live_one_holds(self):
        import os
        here = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()
        boot = subprocess.run(["bash", "-c", "cat /proc/sys/kernel/random/boot_id 2>/dev/null || sysctl -n kern.boottime"],
                              capture_output=True, text=True).stdout.strip()
        self._held("old", "a deploy that was killed", host=here, boot=boot, pid="999999")
        r = self._deploy()
        self.assertIn("which is gone: taking it over", r.stderr, r.stdout + r.stderr)
        self._held("live", "a deploy still running", host=here, boot=boot, pid=str(os.getpid()))
        r = self._deploy()
        self.assertEqual(r.returncode, 1, "a running holder's lock was taken over: %s" % (r.stdout + r.stderr))
        self.assertIn("(a deploy still running)", r.stderr)

    def test_a_run_releases_only_its_own_network(self):
        """Review 4 of #317: an operator removes a lock by hand and another run takes the name; the first run,
        exiting, must not remove the second's."""
        script = self.tmp / "first.sh"
        script.write_text('set -euo pipefail\nsource "%s"\npolaris_host_lock first\n'
                          'printf "id=net-second\\norg.polaris.lock.holder=second\\n" > "%s"\n'
                          % (ROOT / "scripts" / "polaris-host-lock.sh", self.lock))
        r = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=30,
                           env={"PATH": "%s:/usr/bin:/bin" % self.bin, "HOME": str(self.tmp)})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("org.polaris.lock.holder=second", self.lock.read_text(), "the first run removed the second's")

    def test_what_the_holder_runs_goes_on_under_its_lock(self):
        self._held("drill-1", "the upgrade drill")
        r = self._deploy(POLARIS_HOST_LOCK_TOKEN="drill-1")
        self.assertIn("tag sha256:feed polaris-app:rollback-%s" % self.project, self._calls(), r.stdout + r.stderr)
        self.assertTrue(self.lock.exists(), "a deploy run under the drill's lock released it")
        forged = self._deploy(POLARIS_HOST_LOCK_TOKEN="not-the-holders")
        self.assertEqual(forged.returncode, 1, "a token that is not the holder's is no lock")

    def test_the_callers_own_exit_trap_still_runs_before_the_release(self):
        script = self.tmp / "caller.sh"
        helper = ROOT / "scripts" / "polaris-host-lock.sh"
        # The caller sets its own trap, takes the lock, and runs a child that takes it too (the upgrade drill
        # runs try.sh and the deploy): the child goes on under it and leaves it held.
        # Its trap carries a quote (review 4 of #317: pasted into one trap string, it no longer parsed).
        import shlex
        caller_trap = shlex.quote('echo "caller\'s cleanup"')
        script.write_text('set -euo pipefail\ntrap %s EXIT\n'
                          'source "%s"\npolaris_host_lock "a caller"\necho holding\n'
                          'bash -c \'source "%s"; polaris_host_lock child; echo child-under-lock\'\n'
                          '[ -e "%s" ] && echo still-held\n' % (caller_trap, helper, helper, self.lock))
        r = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=30,
                           env={"PATH": "%s:/usr/bin:/bin" % self.bin, "HOME": str(self.tmp)})
        self.assertEqual(r.stdout.splitlines(), ["holding", "child-under-lock", "still-held", "caller's cleanup"],
                         r.stdout + r.stderr)
        self.assertFalse(self.lock.exists(), "released after the caller's own trap")


if __name__ == "__main__":
    unittest.main()
