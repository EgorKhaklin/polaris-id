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
import shutil
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
    is named for the project. The lock is a network in the Docker daemon; this stand-in daemon keeps each
    network as a file, named by its ID, holding its labels."""

    # The stand-in Docker: compose names the project and a stopped app (only `ps -a` lists it), inspect
    # names its image, tag succeeds; networks are files in $NETS. A create of the name is refused while one
    # exists, unless STUB_OLD_ENGINE is set (an engine before 25, which checked and then created); inspect by
    # name answers only when the name is unambiguous; rm removes by ID. Anything further fails, so the deploy
    # stops at step 4 having run nothing against this machine.
    DOCKER = r'''#!/bin/sh
echo "$*" >> "%(log)s"
NETS="%(nets)s"; mkdir -p "$NETS"
resolve() {   # NAME-OR-ID -> the one file it names, or nothing
    if [ "$1" = polaris-host-lock ]; then
        [ "$(ls "$NETS" | grep -c .)" -eq 1 ] && echo "$NETS/$(ls "$NETS")"
    elif [ -e "$NETS/$1" ]; then echo "$NETS/$1"; fi
}
case "$*" in
  "compose version") exit 0 ;;
  *" config") echo "name: %(project)s"; exit 0 ;;
  *" ps -a -q app") echo cid-app; exit 0 ;;
  "inspect --format={{.Image}} cid-app") echo sha256:feed; exit 0 ;;
  "tag "*) exit 0 ;;
  "network create "*)
    if [ -z "${STUB_OLD_ENGINE:-}" ] && [ -n "$(ls "$NETS")" ]; then
        echo "Error response from daemon: network with name polaris-host-lock already exists" >&2; exit 1
    fi
    id="net$$"
    for a in "$@"; do case "$a" in org.polaris.lock.*) echo "$a" >> "$NETS/$id" ;; esac; done
    echo "$id"; exit 0 ;;
  "network ls -q --filter name=^polaris-host-lock\$") ls "$NETS"; exit 0 ;;
  "network inspect -f "*)
    eval "last=\${$#}"; f=$(resolve "$last"); [ -n "$f" ] || exit 1
    key=$(printf %%s "$*" | sed -n "s/.*org.polaris.lock.\([a-z]*\).*/\1/p")
    sed -n "s/^org.polaris.lock.$key=//p" "$f"; exit 0 ;;
  "network rm "*) f=$(resolve "$3"); [ -n "$f" ] && rm -f "$f"; exit 0 ;;
esac
exit 99
'''

    def setUp(self):
        super().setUp()
        self.project = "lockt%d" % (abs(hash(str(self.tmp))) % 10 ** 8)
        self.nets = self.tmp / "networks"
        secrets = self.tmp / "secrets"
        secrets.mkdir()
        for name in ("polaris_secret_key", "polaris_db_password", "polaris_db_root_password",
                     "pgbackrest_repo_creds.conf"):
            (secrets / name).write_text("x\n")
        self.env_text = ("POLARIS_DOMAIN=polaris.example.org\nPOLARIS_SECRETS_BACKEND=file\n"
                         "POLARIS_SECRETS_DIR=%s\n" % secrets)
        (self.bin / "docker").write_text(self.DOCKER % {"log": self.docker_log, "nets": self.nets,
                                                        "project": self.project})
        (self.bin / "docker").chmod(0o755)

    def _deploy(self, **env):
        self.env_file.write_text(self.env_text)
        return subprocess.run(["bash", str(ROOT / "scripts" / "polaris-deploy.sh"), "prod", "--no-pull"],
                              capture_output=True, text=True, timeout=60,
                              env=dict({"PATH": "%s:/usr/bin:/bin:/usr/sbin:/sbin" % self.bin,
                                        "HOME": str(self.tmp), "STUB_WD": str(ROOT / "polaris_web"),
                                        "STUB_EF": str(self.env_file)}, **env))

    def _run(self, text, **env):
        script = self.tmp / "caller.sh"
        script.write_text(text)
        return subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=30,
                              env=dict({"PATH": "%s:/usr/bin:/bin" % self.bin, "HOME": str(self.tmp)}, **env))

    def _calls(self):
        return self.docker_log.read_text().splitlines() if self.docker_log.exists() else []

    def _networks(self):
        return sorted(p.name for p in self.nets.iterdir()) if self.nets.is_dir() else []

    def _held(self, token, holder, host="another-host", boot="b", pid="1", pidns="none", net="netX"):
        self.nets.mkdir(exist_ok=True)
        for p in self.nets.iterdir():
            p.unlink()
        (self.nets / net).write_text("org.polaris.lock.token=%s\norg.polaris.lock.holder=%s\n"
                                     "org.polaris.lock.host=%s\norg.polaris.lock.boot=%s\norg.polaris.lock.pid=%s\n"
                                     "org.polaris.lock.pidns=%s\n" % (token, holder, host, boot, pid, pidns))

    def _here(self, fn):
        """What the helper itself says this machine is (_polaris_host_id, _polaris_boot_id, _polaris_pid_ns)."""
        return subprocess.run(["bash", "-c", 'source "%s"; %s' % (HELPER, fn)],
                              capture_output=True, text=True).stdout.strip()

    def test_a_deploy_pins_the_running_image_under_its_projects_name(self):
        r = self._deploy()
        tag = "tag sha256:feed polaris-app:rollback-%s" % self.project
        self.assertIn(tag, self._calls(), r.stdout + r.stderr)
        self.assertIn("pinned as polaris-app:rollback-%s" % self.project, r.stdout)
        self.assertEqual(self._networks(), [], "the deploy's lock outlived it")
        again = self._deploy()
        self.assertEqual(self._calls().count(tag), 2, again.stdout + again.stderr)

    def test_a_second_deploy_on_the_host_changes_nothing_and_says_who_holds_it(self):
        self._held("other", "try.sh, pid 7 on host")
        r = self._deploy()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("another Polaris build or deploy holds this host's images (try.sh, pid 7 on host)", r.stderr)
        self.assertIn("docker network rm polaris-host-lock", r.stderr)
        self.assertFalse([c for c in self._calls() if c.startswith(("tag", "inspect")) or " pull" in c],
                         "the refused deploy acted: %s" % self._calls())
        self.assertEqual(self._networks(), ["netX"], "the refused deploy released another run's lock")

    def test_a_lock_this_host_left_is_taken_over_naming_its_holder(self):
        """Review 4 of #317: a network outlives its run, a reboot too. One this host left, by an earlier boot or
        a process that is gone, is taken over; one from another host, or a namesake machine, is not."""
        here = self._here("_polaris_host_id")
        # Review 5: two machines can share a host name (one daemon through DOCKER_HOST); the identity carries the
        # machine's own ID beside it, or a namesake's lock reads as this host's.
        self.assertTrue(here.partition(" ")[2], "this host's identity is its name alone: %r" % here)
        self._held("old", "a killed deploy", host=here, boot="an-earlier-boot")
        r = self._deploy()
        self.assertIn("left by a killed deploy, which is gone: taking it over", r.stderr)
        self.assertIn("tag sha256:feed polaris-app:rollback-%s" % self.project, self._calls(), r.stdout + r.stderr)
        for host in ("elsewhere", here.split(" ")[0] + " another-machine-id"):
            self._held("old", "a deploy on " + host, host=host, boot="an-earlier-boot")
            r = self._deploy()
            self.assertEqual(r.returncode, 1, "%s's lock was taken over: %s" % (host, r.stdout + r.stderr))

    def test_in_this_boot_a_gone_process_is_stale_and_a_live_one_holds(self):
        import os
        here, boot, ns = self._here("_polaris_host_id"), self._here("_polaris_boot_id"), self._here("_polaris_pid_ns")
        self._held("old", "a deploy that was killed", host=here, boot=boot, pid="999999", pidns=ns)
        r = self._deploy()
        self.assertIn("which is gone: taking it over", r.stderr, r.stdout + r.stderr)
        # A holder in another pid namespace (a container with this host's name): its pid means nothing here.
        self._held("ns", "a deploy in a container", host=here, boot=boot, pid="999999", pidns="pid:[other]")
        r = self._deploy()
        self.assertEqual(r.returncode, 1, "a holder in another pid namespace was taken over: %s" % (r.stdout + r.stderr))
        self._held("live", "a deploy still running", host=here, boot=boot, pid=str(os.getpid()), pidns=ns)
        r = self._deploy()
        self.assertEqual(r.returncode, 1, "a running holder's lock was taken over: %s" % (r.stdout + r.stderr))
        self.assertIn("(a deploy still running)", r.stderr)

    def test_an_older_engine_never_lets_two_hold_it_and_still_clears_a_stale_one(self):
        """Review 5 of #317: an engine before 25 creates a second network of the name rather than refusing, so
        a run counts after creating; a stale lock it finds there is taken over, a live one wins."""
        here = self._here("_polaris_host_id")
        self._held("old", "a killed deploy", host=here, boot="an-earlier-boot")
        r = self._deploy(STUB_OLD_ENGINE="1")
        self.assertIn("left by a killed deploy, which is gone: taking it over", r.stderr, r.stdout + r.stderr)
        self.assertIn("tag sha256:feed polaris-app:rollback-%s" % self.project, self._calls(), r.stdout + r.stderr)
        self.assertEqual(self._networks(), [], "the deploy left its lock, or the stale one")
        self._held("live", "a deploy elsewhere", host="elsewhere", boot="b")
        r = self._deploy(STUB_OLD_ENGINE="1")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("took this host's images at the same moment", r.stderr)
        self.assertEqual(self._networks(), ["netX"], "the run did not give its own network back")

    def test_a_run_releases_only_its_own_network(self):
        """Review 4 of #317: an operator removes a lock by hand and another run takes the name; the first run,
        exiting, must not remove the second's."""
        r = self._run('set -euo pipefail\nsource "%s"\npolaris_host_lock first\n'
                      'rm -f "%s"/*; printf "org.polaris.lock.holder=second\\n" > "%s/net-second"\n'
                      % (HELPER, self.nets, self.nets))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self._networks(), ["net-second"], "the first run removed the second's")

    def test_what_the_holder_runs_goes_on_under_its_lock(self):
        self._held("drill-1", "the upgrade drill")
        r = self._deploy(POLARIS_HOST_LOCK_TOKEN="drill-1")
        self.assertIn("tag sha256:feed polaris-app:rollback-%s" % self.project, self._calls(), r.stdout + r.stderr)
        self.assertEqual(self._networks(), ["netX"], "a deploy run under the drill's lock released it")
        forged = self._deploy(POLARIS_HOST_LOCK_TOKEN="not-the-holders")
        self.assertEqual(forged.returncode, 1, "a token that is not the holder's is no lock")

    def test_the_callers_own_exit_trap_still_runs_before_the_release(self):
        # The caller sets its own trap, takes the lock, and runs a child that takes it too (the upgrade drill
        # runs try.sh and the deploy): the child goes on under it and leaves it held. Its trap carries a quote
        # (review 4 of #317: pasted into one trap string, it no longer parsed).
        import shlex
        caller_trap = shlex.quote('echo "caller\'s cleanup"')
        r = self._run('set -euo pipefail\ntrap %s EXIT\n'
                      'source "%s"\npolaris_host_lock "a caller"\necho holding\n'
                      'bash -c \'source "%s"; polaris_host_lock child; echo child-under-lock\'\n'
                      '[ -n "$(ls "%s")" ] && echo still-held\n' % (caller_trap, HELPER, HELPER, self.nets))
        self.assertEqual(r.stdout.splitlines(), ["holding", "child-under-lock", "still-held", "caller's cleanup"],
                         r.stdout + r.stderr)
        self.assertEqual(self._networks(), [], "released after the caller's own trap")

    def test_a_run_can_give_the_lock_back_before_it_ends(self):
        """install.sh builds under the lock, then starts polaris.service, whose ExecStartPre takes it in a process
        of its own: it gives its own back first, and its exit then releases nothing more."""
        r = self._run('set -euo pipefail\nsource "%s"\npolaris_host_lock install\npolaris_host_release\n'
                      '[ -z "$(ls "%s")" ] && echo released\nbash -c \'source "%s"; polaris_host_lock unit; echo unit-took-it\'\n'
                      % (HELPER, self.nets, HELPER))
        self.assertEqual(r.stdout.splitlines(), ["released", "unit-took-it"], r.stdout + r.stderr)
        self.assertEqual(self._networks(), [])

    def test_a_failing_caller_trap_neither_skips_the_release_nor_loses_the_status(self):
        """Review 5 of #317: under set -e a caller's trap that fails ended the trap before the release, and it saw
        $? as 0 rather than the status the run ended with."""
        r = self._run('set -euo pipefail\ncleanup() { echo "saw $?"; false; echo never; }\ntrap cleanup EXIT\n'
                      'source "%s"\npolaris_host_lock "a caller"\nexit 3\n' % HELPER)
        self.assertEqual(r.stdout.splitlines(), ["saw 3"], r.stdout + r.stderr)
        self.assertEqual(r.returncode, 3, "the run's own status was lost")
        self.assertEqual(self._networks(), [], "a failing caller trap kept the lock")


HELPER = ROOT / "scripts" / "polaris-host-lock.sh"


# A stand-in kubectl for a cluster where one member never schedules: it answers as kubectl does,
# failing for a pod with no previous container, a Pending pod's log and Endpoints not yet made.
_KUBECTL = r"""#!/bin/bash
case "$*" in
  *"get pods -o name"*) printf 'pod/polaris-app-1\npod/polaris-postgres-1\n' ;;
  *"get pods"*) echo "polaris-postgres-1 0/1 Pending" ;;
  *"get endpoints"*) echo 'Error from server (NotFound): endpoints not found' >&2; exit 1 ;;
  *"get events"*) echo "Warning FailedScheduling pod/polaris-postgres-1 0/1 nodes are available: 1 Insufficient cpu." ;;
  *"describe nodes"*) printf 'Allocated resources:\n  cpu 3950m (98%%)\nEvents: <none>\n' ;;
  *describe*) printf 'Events:\n  Warning FailedScheduling Insufficient cpu\n' ;;
  *"--previous"*) echo 'Error from server (BadRequest): previous terminated container not found' >&2; exit 1 ;;
  *postgres-1*) echo 'Error from server (BadRequest): container "postgres" is waiting to start' >&2; exit 1 ;;
  *logs*) echo "a log line" ;;
esac
"""


class DrillDiagnosticsReachTheirFail(unittest.TestCase):
    """A drill's diagnostics run when something already failed, so each command in them may fail
    too. Under `set -euo pipefail` the first that did ended the drill there: the kind job of
    2026-10-09 stopped at the first pod's previous log, before the Pending member whose scheduler
    reason was the answer, and before the `fail` that names what broke. The blocks run here, cut
    from the drills, under their own options and a stand-in kubectl."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        bin_dir = pathlib.Path(self.tmp.name)
        (bin_dir / "kubectl").write_text(_KUBECTL)
        (bin_dir / "kubectl").chmod(0o755)
        self.path = f"{bin_dir}:/usr/bin:/bin"

    def tearDown(self):
        self.tmp.cleanup()

    def run_block(self, block):
        script = ('NS=polaris; REL=polaris; LAST_INSERT_ERR=; fail() { echo "FAIL: $*"; exit 1; }\n'
                  + block + '\necho "REACHED THE FAIL"\n')
        return subprocess.run(["bash", "-euo", "pipefail", "-c", script], capture_output=True, text=True,
                              env={"PATH": self.path}, timeout=30)

    def diagnose(self, rel):
        lines = (ROOT / rel).read_text().splitlines()
        start = next(i for i, line in enumerate(lines) if line.startswith("diagnose() {"))
        if lines[start].rstrip().endswith("}"):
            return lines[start] + "\ndiagnose"
        end = next(i for i in range(start, len(lines)) if lines[i] == "}")
        return "\n".join(lines[start:end + 1]) + "\ndiagnose"

    def test_each_diagnose_reaches_the_fail_after_it(self):
        for rel in ("scripts/polaris-helm-drill.sh", "scripts/polaris-helm-upgrade-drill.sh",
                    "scripts/polaris-zone-loss-drill.sh"):
            with self.subTest(rel):
                r = self.run_block(self.diagnose(rel))
                self.assertIn("REACHED THE FAIL", r.stdout, f"{rel}: diagnose ended the drill:\n{r.stdout}{r.stderr}")

    def test_the_install_diagnostics_reach_the_pending_member(self):
        text = (ROOT / "scripts/polaris-helm-drill.sh").read_text()
        block = text.split("--wait --timeout 12m >/dev/null || {\n", 1)[1].split("\n    }\n", 1)[0]
        r = self.run_block(block)
        self.assertIn("FAIL: helm install did not reach ready", r.stdout, r.stdout + r.stderr)
        self.assertIn("== pod/polaris-postgres-1: events ==", r.stdout, "the loop must reach the Pending member")
        self.assertIn("Insufficient cpu", r.stdout, "the scheduler's reason must be printed")
        self.assertIn("Allocated resources", r.stdout, "the node's room must be printed")


# A stand-in polaris-migrate.sh: records the environment it was run with and its arguments, and
# fails --up or --sync-objects when the case asks.
_MIGRATE = r"""#!/bin/sh
echo "POLARIS_ENV=${POLARIS_ENV-unset} $*" >> "$STUB_LOG"
case "$*" in
  *--up*) exit "${STUB_UP_RC:-0}" ;;
  *--sync-objects*) exit "${STUB_SYNC_RC:-0}" ;;
esac
exit 0
"""


class UpgradesRunTheSyncAsProduction(unittest.TestCase):
    """Every path that upgrades a production database runs `polaris-migrate.sh --sync-objects` with
    POLARIS_ENV=production, so the sync raises the notional sample's anonymity floor of one there
    (test_migrate_runner.py proves the raise); and the Linux installer stops when a migration fails.
    Until 2026-10-10 it ran both inside an && list, which set -e does not stop, and went on to the
    health check. The blocks run here, cut from the scripts, under their own options."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-upgrade-env-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / "scripts").mkdir()
        (self.tmp / "scripts" / "polaris-migrate.sh").write_text(_MIGRATE)
        (self.tmp / "scripts" / "polaris-migrate.sh").chmod(0o755)
        self.log = self.tmp / "migrate.log"

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def run_block(self, block, **env):
        full = {"PATH": "/usr/bin:/bin", "HOME": str(self.tmp), "STUB_LOG": str(self.log)}
        full.update(env)
        return subprocess.run(["bash", "-c", "set -euo pipefail\n" + block + '\necho "REACHED THE HEALTH CHECK"\n'],
                              env=full, capture_output=True, text=True, timeout=30)

    @staticmethod
    def function(text, name):
        lines = text.splitlines()
        start = lines.index(name + "() {")
        end = next(i for i in range(start, len(lines)) if lines[i] == "}")
        return "\n".join(lines[start:end + 1])

    def install_block(self):
        text = (ROOT / "deploy" / "linux" / "install.sh").read_text()
        helpers = [line for line in text.splitlines() if line.startswith(("ok()", "die()"))]
        self.assertEqual(len(helpers), 2, helpers)
        return "\n".join(helpers + [self.function(text, "migrate_stack"),
                                    'INSTALL_DIR="%s"' % self.tmp, "migrate_stack"])

    def test_the_installer_migrates_and_syncs_as_production(self):
        r = self.run_block(self.install_block())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.calls(), ["POLARIS_ENV=production --up --target=docker-stack",
                                        "POLARIS_ENV=production --sync-objects --target=docker-stack"])
        self.assertIn("ok   migrations applied + DB objects synced", r.stdout)

    def test_a_failed_migration_stops_the_install(self):
        r = self.run_block(self.install_block(), STUB_UP_RC="5")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("install: the migrations did not apply", r.stderr)
        self.assertNotIn("REACHED THE HEALTH CHECK", r.stdout)
        self.assertEqual(len(self.calls()), 1, "the objects were synced after a migration failed")

    def test_a_failed_sync_stops_the_install(self):
        r = self.run_block(self.install_block(), STUB_SYNC_RC="5")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("install: the database objects did not sync", r.stderr)
        self.assertNotIn("REACHED THE HEALTH CHECK", r.stdout)

    def test_the_installer_migrates_only_through_that_step(self):
        text = (ROOT / "deploy" / "linux" / "install.sh").read_text()
        self.assertIn("\n    migrate_stack\n", self.function(text, "stage_app") + "\n",
                      "stage_app no longer runs the migration step")
        outside = text.replace(self.function(text, "migrate_stack"), "")
        self.assertNotIn("polaris-migrate.sh --", outside, "a migration call outside migrate_stack")

    def test_the_deploy_migrates_and_syncs_as_production(self):
        text = (ROOT / "scripts" / "polaris-deploy.sh").read_text()
        lines = [line for line in text.splitlines()
                 if "polaris-migrate.sh" in line and not line.lstrip().startswith("#")]
        self.assertEqual(len(lines), 2, lines)
        r = self.run_block('SCRIPT_DIR="%s"\n%s' % (self.tmp / "scripts", "\n".join(lines)), POLARIS_ENV="staging")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.calls(), ["POLARIS_ENV=production --up --target=docker-stack",
                                        "POLARIS_ENV=production --sync-objects --target=docker-stack"])

    def test_the_charts_migration_job_runs_as_production(self):
        job = (ROOT / "deploy" / "helm" / "polaris" / "templates" / "migrate-job.yaml").read_text()
        container = job.split("        - name: migrate\n", 1)[1]
        env = container.split("          env:\n", 1)[1].split("          resources:", 1)[0]
        self.assertIn("            - {name: POLARIS_ENV, value: production}\n", env)
        self.assertIn("/opt/polaris/scripts/polaris-migrate.sh --sync-objects", container)

    def test_the_databases_they_upgrade_are_initialised_as_production(self):
        """What the three rest on: the database each upgrades was initialised by docker-init.sh with
        POLARIS_ENV=production, so its production block (the demo accounts, the floor) ran there."""
        compose = (ROOT / "polaris_web" / "docker-compose.prod.yml").read_text()
        block = []
        for line in compose.split("\n  postgres:\n", 1)[1].splitlines():
            if line.startswith("  ") and not line.startswith("    "):
                break
            block.append(line)
        self.assertIn("      POLARIS_ENV: production", block)
        chart = (ROOT / "deploy" / "helm" / "polaris" / "templates" / "postgres.yaml").read_text()
        self.assertIn("- {name: POLARIS_ENV, value: production}", chart)


class TheInstallerStopsAtAFailedStep(unittest.TestCase):
    """install.sh's docker.service, image build and secrets steps, cut from the script and run under its
    options: each failure stops the install there, naming the command to re-run. Until 2026-10-10 each
    ran as `... && ok`, which set -e does not stop, so the install went on without a running Docker,
    its images or its secrets."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-install-steps-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / "polaris_web").mkdir()
        (self.tmp / "scripts").mkdir()
        (self.tmp / "bin").mkdir()
        for path, rc in ((self.tmp / "bin" / "docker", "STUB_BUILD_RC"),
                         (self.tmp / "bin" / "systemctl", "STUB_SYSTEMCTL_RC"),
                         (self.tmp / "scripts" / "polaris-generate-secrets.sh", "STUB_SECRETS_RC")):
            path.write_text('#!/bin/sh\necho "$(basename "$0") $*" >> "%s"\nexit "${%s:-0}"\n'
                            % (self.tmp / "calls.log", rc))
            path.chmod(0o755)
        self.text = (ROOT / "deploy" / "linux" / "install.sh").read_text()

    def cut(self, first, last):
        lines = self.text.splitlines()
        start = next(i for i, line in enumerate(lines) if first in line)
        end = next(i for i in range(start, len(lines)) if last in lines[i])
        self.assertLessEqual(end - start, 3, "the step grew: %r" % lines[start:end + 1])
        return "\n".join(lines[start:end + 1])

    def run_step(self, step, **env):
        helpers = [line for line in self.text.splitlines() if line.startswith(("ok()", "die()"))]
        script = "set -euo pipefail\n%s\nINSTALL_DIR=\"%s\"\n%s\necho \"REACHED THE NEXT STEP\"\n" % (
            "\n".join(helpers), self.tmp, step)
        full = {"PATH": "%s:/usr/bin:/bin" % (self.tmp / "bin"), "HOME": str(self.tmp)}
        full.update(env)
        return subprocess.run(["bash", "-c", script], env=full, capture_output=True, text=True, timeout=30)

    def test_a_docker_service_that_does_not_start_stops_the_install(self):
        step = self.cut("systemctl enable --now docker", 'ok "docker.service enabled and running"')
        ok = self.run_step(step)
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.assertIn("ok   docker.service enabled and running", ok.stdout)
        self.assertIn("systemctl enable --now docker", (self.tmp / "calls.log").read_text())
        r = self.run_step(step, STUB_SYSTEMCTL_RC="1")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("install: docker.service could not be enabled and started (systemctl enable --now docker",
                      r.stderr)
        self.assertNotIn("REACHED THE NEXT STEP", r.stdout)
        self.assertNotIn("docker.service enabled and running", r.stdout)

    def test_no_step_reports_ok_through_an_and_list(self):
        self.assertEqual([line for line in self.text.splitlines() if "&& ok" in line], [])

    def test_a_failed_image_build_stops_the_install(self):
        step = self.cut("docker-compose.prod.yml build -q )", 'ok "production images built"')
        ok = self.run_step(step)
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.assertIn("ok   production images built", ok.stdout)
        r = self.run_step(step, STUB_BUILD_RC="17")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("install: the production images did not build (cd %s/polaris_web && docker compose" % self.tmp,
                      r.stderr)
        self.assertNotIn("REACHED THE NEXT STEP", r.stdout)
        self.assertNotIn("production images built", r.stdout)

    def test_failed_secrets_stop_the_install(self):
        step = self.cut("bash scripts/polaris-generate-secrets.sh >/dev/null )", 'ok "secrets present')
        ok = self.run_step(step)
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.assertIn("ok   secrets present under polaris_web/secrets/", ok.stdout)
        r = self.run_step(step, STUB_SECRETS_RC="3")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("install: the secrets were not generated (cd %s && bash scripts/polaris-generate-secrets.sh)"
                      % self.tmp, r.stderr)
        self.assertNotIn("REACHED THE NEXT STEP", r.stdout)


if __name__ == "__main__":
    unittest.main()
