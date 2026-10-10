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


def _cut(rel, first, last="}"):
    """The lines of ROOT/rel from the one starting with FIRST to the first after it that is exactly LAST."""
    lines = (ROOT / rel).read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(first))
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == last)
    return "\n".join(lines[start:end + 1])


class _CutBlock(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_bash(self, script, **env):
        return subprocess.run(["bash", "-c", "set -euo pipefail\n" + script], capture_output=True, text=True,
                              timeout=60, env=dict({"PATH": "/usr/bin:/bin", "HOME": self.tmp.name}, **env))


class ArchivingFailureWarnsAndTheDeployGoesOn(_CutBlock):
    """polaris-deploy.sh's step 5c promises that a pgBackRest failure warns and does not block. Its
    failure branch printed the log's ERROR and HINT lines with a grep, and under the deploy's
    `set -euo pipefail` a log without them (a daemon or compose failure says "Error") ended the deploy
    there, after the infrastructure was up and before the app was rolled. The block runs here, cut from
    the script, with a stand-in compose."""

    BLOCK = _cut("scripts/polaris-deploy.sh", 'if [[ "${POLARIS_PGBACKREST_ENABLED:-1}" == "1" ]]; then', "fi")
    COMPOSE = r'''COMPOSE_FILE=polaris_web/docker-compose.prod.yml; SCRIPT_DIR=/nonexistent
compose() {
    case "$*" in
      *"SHOW archive_mode"*) echo on ;;
      *stanza-create*) [ -n "${STUB_CREATE_FAILS:-}" ] && { printf '%s\n' "$STUB_CREATE_FAILS"; return 1; }; return 0 ;;
      *"--stanza=polaris check"*) printf '%s\n' "$STUB_CHECK_FAILS"; return 28 ;;
      *) echo "unexpected compose $*" >&2; return 99 ;;
    esac
}
'''

    def run_5c(self, **env):
        self.assertIn("stanza-create", self.BLOCK, "the cut missed step 5c")
        tmpdir = self.dir / "t"
        tmpdir.mkdir()
        r = self.run_bash(self.COMPOSE + self.BLOCK + '\necho "THE DEPLOY GOES ON"\n', TMPDIR=str(tmpdir), **env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("THE DEPLOY GOES ON", r.stdout)
        self.assertEqual(list(tmpdir.iterdir()), [], "the stanza log was left behind")
        return r

    def test_a_failure_without_pgbackrest_lines_warns_and_goes_on(self):
        r = self.run_5c(STUB_CREATE_FAILS="Error response from daemon: container 4f2a is restarting")
        self.assertIn("pgBackRest stanza-create/check FAILED", r.stderr)
        self.assertIn("pgbackrest --stanza=polaris check", r.stderr, "the generic advice must be printed")

    def test_error_028_names_the_stanza_upgrade_and_the_backup_after_it(self):
        r = self.run_5c(STUB_CHECK_FAILS="ERROR: [028]: backup and archive info files exist but do not match the database\n"
                                         "HINT: is this the correct stanza?")
        self.assertIn("       ERROR: [028]", r.stderr, "pgBackRest's own line must be printed")
        self.assertIn("pgbackrest --stanza=polaris stanza-upgrade", r.stderr)
        self.assertIn("pgbackrest --stanza=polaris --type=full backup", r.stderr)


class DeployRefusesAnotherMajorsCluster(_CutBlock):
    """A PostgreSQL server refuses a cluster another major initialised. A FROM line moved to a new major
    and deployed recreated postgres on a cluster it could not open, and the database stayed down until the
    line went back. The deploy's check, cut from polaris-deploy.sh, with a stand-in docker that lists the
    project's pg_data volumes and reads PG_VERSION from one."""

    FN = _cut("scripts/polaris-deploy.sh", "pg_major_check() {")
    DOCKER = r'''PROJECT=proj
docker() {
    case "$1 $2" in
      "volume ls") printf '%s' "${STUB_VOLS:-}" ;;
      "run --rm") [ -z "${STUB_RUN_FAILS:-}" ] || return 125; printf '%s\n' "$STUB_PG_VERSION" ;;
      *) echo "unexpected docker $*" >&2; return 99 ;;
    esac
}
'''

    def check(self, from_line, vols="proj_pg_data", pg_version="16", run_fails=""):
        (self.dir / "polaris_web").mkdir(exist_ok=True)
        (self.dir / "polaris_web" / "Dockerfile.postgres").write_text("# the base\n%s\nENTRYPOINT [\"x\"]\n" % from_line)
        r = self.run_bash(self.DOCKER + self.FN + '\nif pg_major_check; then echo PASSED; else echo REFUSED; fi\n',
                          POLARIS_ROOT=self.tmp.name, STUB_VOLS=vols, STUB_PG_VERSION=pg_version,
                          STUB_RUN_FAILS=run_fails)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r.stdout.strip(), r.stderr

    def test_a_cluster_of_another_major_is_refused_both_ways(self):
        for cluster, image in (("16", "17"), ("17", "16")):
            with self.subTest(cluster=cluster, image=image):
                got, err = self.check("FROM postgres:%s-alpine@sha256:%s" % (image, "ab" * 32), pg_version=cluster)
                self.assertEqual(got, "REFUSED", err)
                self.assertIn("proj_pg_data holds a PostgreSQL %s cluster" % cluster, err)
                self.assertIn("is PostgreSQL %s" % image, err)
                self.assertIn('"Postgres version upgrade"', err)

    def test_the_same_major_a_new_volume_and_an_empty_one_pass(self):
        base = "FROM postgres:16-alpine@sha256:%s" % ("ab" * 32)
        self.assertEqual(self.check(base)[0], "PASSED")
        self.assertEqual(self.check(base, vols="")[0], "PASSED", "a first deploy has no volume")
        self.assertEqual(self.check(base, pg_version="none")[0], "PASSED", "an empty volume is initialised by the image")

    def test_what_cannot_be_read_is_refused(self):
        base = "FROM postgres:16-alpine@sha256:%s" % ("ab" * 32)
        for name, kw, says in (("unreadable cluster", {"run_fails": "1"}, "could not read proj_pg_data's PG_VERSION"),
                               ("two volumes", {"vols": "proj_pg_data\nproj_other"}, "more than one pg_data volume"),
                               ("no major in FROM", {"from_line": "FROM postgres:latest"}, "no single 'FROM postgres:<major>'")):
            with self.subTest(name):
                got, err = self.check(kw.pop("from_line", base), **kw)
                self.assertEqual(got, "REFUSED", err)
                self.assertIn(says, err)


class UpgradeRollbackStopsAtAFailedCopy(_CutBlock):
    """OPERATIONS.md's rollback from a PostgreSQL major upgrade copies the old cluster back and redeploys,
    then moves pgBackRest's stanza back to it. Pasted into a shell, its lines ran one after another, so a
    copy that failed (a full disk) was followed by a deploy onto half a cluster. The block runs here, cut
    from the document the way scripts/polaris-pg-upgrade-drill.sh cuts it, with a stand-in docker and deploy."""

    DOCKER = r'''#!/bin/sh
echo "docker $*" >> "$CALLS"
case "$*" in
  *"config --no-interpolate"*) echo "name: proj" ;;
  "volume inspect"*) ;;
  *" down") ;;
  "run --rm"*) exit "${STUB_COPY_RC:-0}" ;;
  *"printenv POLARIS_PGBACKREST_ENABLED") echo "$STUB_ARCHIVING" ;;
  *pgbackrest*) ;;
  *) echo "unexpected docker $*" >&2; exit 99 ;;
esac
'''

    def walk(self, **env):
        doc = (ROOT / "docs" / "operator" / "OPERATIONS.md").read_text()
        sec = doc[doc.index("### Postgres version upgrade"):doc.index("### TLS certificate renewal")]
        a = sec.index("```bash", sec.index("To go back")) + len("```bash\n")
        block = sec[a:sec.index("```", a)]
        for d in ("bin", "polaris_web", "scripts"):
            (self.dir / d).mkdir(exist_ok=True)
        (self.dir / "bin" / "docker").write_text(self.DOCKER)
        (self.dir / "scripts" / "polaris-deploy.sh").write_text('#!/bin/sh\necho "deploy $*" >> "$CALLS"\n')
        for f in (self.dir / "bin" / "docker", self.dir / "scripts" / "polaris-deploy.sh"):
            f.chmod(0o755)
        calls = self.dir / "calls"
        r = subprocess.run(["bash", "-c", block], cwd=self.dir, capture_output=True, text=True, timeout=60,
                           env=dict({"PATH": "%s:/usr/bin:/bin" % (self.dir / "bin"), "CALLS": str(calls)}, **env))
        return r, (calls.read_text().splitlines() if calls.exists() else [])

    def test_a_failed_copy_is_not_deployed_onto(self):
        r, calls = self.walk(STUB_COPY_RC="1", STUB_ARCHIVING="1")
        self.assertNotEqual(r.returncode, 0, "a failed rollback must end non-zero")
        self.assertTrue(any(c.startswith("docker run --rm") for c in calls), calls)
        self.assertFalse([c for c in calls if c.startswith("deploy") or "pgbackrest" in c or "printenv" in c], calls)

    def test_the_stanza_follows_the_old_cluster_back_when_the_stack_archives(self):
        r, calls = self.walk(STUB_ARCHIVING="1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        tail = [c for c in calls if c.startswith("deploy") or "pgbackrest" in c]
        self.assertEqual(len(tail), 3, calls)
        self.assertTrue(tail[0].startswith("deploy prod --no-pull"), tail)
        self.assertTrue(tail[1].endswith("pgbackrest --stanza=polaris stanza-upgrade"), tail)
        self.assertTrue(tail[2].endswith("pgbackrest --stanza=polaris --type=full backup"), tail)

    def test_a_stack_that_does_not_archive_skips_pgbackrest(self):
        r, calls = self.walk(STUB_ARCHIVING="0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(any(c.startswith("deploy") for c in calls), calls)
        self.assertFalse([c for c in calls if "pgbackrest" in c], calls)


class PgUpgradeDrillStateFailsClosed(_CutBlock):
    """The PostgreSQL upgrade drill compares each table's count and a digest of its rows before and after.
    Read inside printf's arguments, a failed count or copy went unseen by set -e, and a table never read
    hashed as empty input: both states compared equal and the drill passed. state() runs here, cut from
    the drill, with a stand-in database of 42 tables."""

    FN = _cut("scripts/polaris-pg-upgrade-drill.sh", "state() {")
    DB = r'''fail() { echo "FAIL: $*" >&2; exit 1; }
sql() {
    case "$*" in
      *"format('%I.%I'"*) for i in $(seq 10 51); do echo "public.t$i"; done ;;
      *"count(*) FROM public.t${STUB_COUNT_FAILS:-none}") return 2 ;;
      *"count(*) FROM"*) echo 2 ;;
      *) echo fact ;;
    esac
}
compose() {
    local q; q=$(cat)
    case "$q" in
      *"FROM public.t${STUB_COPY_FAILS:-none})"*) echo "ERROR:  could not read" >&2; return 3 ;;
      *"FROM public.t${STUB_COPY_EMPTY:-none})"*) return 0 ;;
      *) printf 'r1\nr2\n' ;;
    esac
}
'''

    def state(self, **env):
        out = self.dir / "state.txt"
        r = self.run_bash(self.DB + self.FN + '\nstate "%s"\necho "STATE WRITTEN"\n' % out, **env)
        return r, out

    def test_every_table_is_read(self):
        r, out = self.state()
        self.assertEqual(r.returncode, 0, r.stderr)
        rows = [line for line in out.read_text().splitlines() if line.startswith("rows ")]
        self.assertEqual(len(rows), 42)
        self.assertNotIn("e3b0c442", out.read_text())

    def test_a_failed_read_fails_and_names_its_table(self):
        for env, says in (({"STUB_COPY_FAILS": "23"}, "could not copy public.t23"),
                          ({"STUB_COUNT_FAILS": "11"}, "could not count public.t11"),
                          ({"STUB_COPY_EMPTY": "37"}, "public.t37 counts 2 rows, but its copy read none")):
            with self.subTest(**env):
                r, _ = self.state(**env)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(says, r.stderr)
                self.assertNotIn("STATE WRITTEN", r.stdout)


if __name__ == "__main__":
    unittest.main()
