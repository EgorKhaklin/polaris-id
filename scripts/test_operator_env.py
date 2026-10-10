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
import json
import os
import pathlib
import shutil
import sys
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


#: The secret files a production deploy requires: the app's (each secret_file setting in
#: config_schema.py the prod compose mounts) and Redis's users, the root password and the
#: pgBackRest fragment.
APP_SECRETS = ("polaris_db_password", "polaris_redis_password", "polaris_secret_key_fallbacks",
               "polaris_secret_key")
ALL_SECRETS = APP_SECRETS + ("redis_users.acl", "polaris_db_root_password", "pgbackrest_repo_creds.conf")
#: What a v1.0.0-rc.70 install holds: its polaris-generate-secrets.sh wrote neither the Redis
#: password nor its users file nor the fallback keys, and its deploy checked these four.
RC70_SECRETS = ("polaris_secret_key", "polaris_db_password", "polaris_db_root_password",
                "pgbackrest_repo_creds.conf")


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
  *" config --format json") cat "%(json)s"; exit $? ;;
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
        for name in ALL_SECRETS:
            (secrets / name).write_text("x\n")
        self.env_text = ("POLARIS_DOMAIN=polaris.example.org\nPOLARIS_SECRETS_BACKEND=file\n"
                         "POLARIS_SECRETS_DIR=%s\n" % secrets)
        # The postgres service as `compose config --format json` resolves it: no bucket.
        self.compose_json = self.tmp / "compose.json"
        self.compose_json.write_text(json.dumps({"name": self.project, "services": {"postgres": {
            "environment": {"POLARIS_PGBACKREST_S3_BUCKET": ""}}}}))
        (self.bin / "docker").write_text(self.DOCKER % {"log": self.docker_log, "nets": self.nets,
                                                        "project": self.project, "json": self.compose_json})
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


class DeployRefusesAnOffsiteRepoThePostgresImageWouldRefuse(_Base):
    """The postgres image refuses to start with a bucket and no repo2-cipher-pass (or one under 32
    characters, or a fragment still naming repo1-s3-* from before the bucket became repo2). Found
    there, that is the database down in the middle of a deploy, so polaris-deploy.sh runs the same
    renderer against the host's fragment and the postgres service's resolved settings first, and
    stops before it starts anything. The stand-in Docker is DeploysTakeTurns', which also answers
    `compose config --format json` with the postgres service as the test writes it."""

    FIXTURE_CIPHER_TEXT = "an-offsite-test-passphrase-0123456789"
    FULL = "[global]\nrepo2-s3-key=AKIATEST\nrepo2-s3-key-secret=test-secret\nrepo2-cipher-pass=%s\n" % FIXTURE_CIPHER_TEXT

    def setUp(self):
        super().setUp()
        self.nets = self.tmp / "networks"
        self.fixture_dir = self.tmp / "secrets"
        self.fixture_dir.mkdir()
        for name in ALL_SECRETS:
            if name != "pgbackrest_repo_creds.conf":
                (self.fixture_dir / name).write_text("x\n")
        self.compose_json = self.tmp / "compose.json"
        (self.bin / "docker").write_text(DeploysTakeTurns.DOCKER % {
            "log": self.docker_log, "nets": self.nets, "project": "offsite", "json": self.compose_json})
        (self.bin / "docker").chmod(0o755)

    def _deploy(self, fragment, bucket, mounted=None, compose_json=None):
        (self.fixture_dir / "pgbackrest_repo_creds.conf").write_text(fragment)
        env = dict([("POLARIS_PGBACKREST_ENABLED", "1"),
                    ("POLARIS_DB_PASSWORD_FILE", "/run/secrets/polaris_db_password"),
                    ("POLARIS_PGBACKREST_S3_BUCKET", bucket)])
        if bucket:
            env.update(POLARIS_PGBACKREST_S3_ENDPOINT="s3.eu-central-1.amazonaws.com",
                       POLARIS_PGBACKREST_S3_REGION="eu-central-1")
        volumes = [{"type": "bind", "source": str(self.fixture_dir / "pgbackrest_repo_creds.conf"),
                    "target": "/etc/pgbackrest/conf.d/repo-creds.conf", "read_only": True}]
        if mounted is not None:
            (self.tmp / "operator-repo.conf").write_text(mounted)
            volumes.append({"type": "bind", "source": str(self.tmp / "operator-repo.conf"),
                            "target": "/etc/pgbackrest/conf.d/repo.conf", "read_only": True})
        self.compose_json.write_text(compose_json if compose_json is not None else json.dumps(
            {"name": "offsite", "services": {"postgres": {"environment": env, "volumes": volumes}}}))
        self.env_file.write_text("POLARIS_DOMAIN=polaris.example.org\nPOLARIS_SECRETS_BACKEND=file\n"
                                 "POLARIS_SECRETS_DIR=%s\n" % self.fixture_dir)
        return subprocess.run(["bash", str(ROOT / "scripts" / "polaris-deploy.sh"), "prod", "--no-pull"],
                              capture_output=True, text=True, timeout=60,
                              env={"PATH": "%s:/usr/bin:/bin:/usr/sbin:/sbin" % self.bin, "HOME": str(self.tmp),
                                   "STUB_WD": str(ROOT / "polaris_web"), "STUB_EF": str(self.env_file)})

    def _started_nothing(self, r):
        calls = self.docker_log.read_text().splitlines() if self.docker_log.exists() else []
        acted = [c for c in calls if c.startswith(("tag", "inspect", "run")) or " pull" in c or " up" in c]
        self.assertFalse(acted, "the refused deploy acted: %s\n%s" % (acted, r.stdout + r.stderr))
        self.assertFalse(list(self.nets.iterdir()) if self.nets.is_dir() else [], "the refused deploy kept its lock")

    def test_a_bucket_without_a_passphrase_stops_the_deploy_before_anything_starts(self):
        r = self._deploy("[global]\nrepo2-s3-key=AKIATEST\nrepo2-s3-key-secret=test-secret\n", "polaris-dr")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("repo2-cipher-pass. The offsite repo", r.stderr)
        self.assertIn("nothing was started", r.stderr)
        self._started_nothing(r)

    def test_a_fragment_from_before_the_bucket_became_repo2_is_told_how_to_migrate(self):
        r = self._deploy("[global]\nrepo1-s3-key=AKIATEST\nrepo1-s3-key-secret=test-secret\n", "polaris-dr")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("rename those lines repo2-s3-*", r.stderr)
        self._started_nothing(r)

    def test_a_short_passphrase_stops_it_too(self):
        r = self._deploy(self.FULL.replace(self.FIXTURE_CIPHER_TEXT, "too-short"), "polaris-dr")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("At least 32 are required", r.stderr)
        self.assertNotIn("too-short", r.stdout + r.stderr)
        self._started_nothing(r)

    def test_a_mounted_repo_conf_off_this_host_without_a_cipher_stops_it(self):
        # The image does not rewrite a mounted repo.conf, and refuses one naming an S3 repo with no
        # cipher; the deploy reads which host file compose mounts there, and refuses it first.
        conf = "[global]\nrepo1-path=/var/lib/pgbackrest\nrepo2-type=s3\nrepo2-s3-bucket=b\nrepo2-path=/p\n"
        r = self._deploy(self.FULL, "", mounted=conf)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("configures repo2 (repo2-type=s3) with no cipher", r.stderr)
        self._started_nothing(r)
        r = self._deploy(self.FULL, "", mounted=conf + "repo2-cipher-type=aes-256-cbc\n")
        self.assertIn("is one the postgres image accepts", r.stdout, r.stdout + r.stderr)

    def test_a_resolved_configuration_that_cannot_be_read_stops_it(self):
        # A bucket set only in polaris_web/.env is in no shell's environment: a deploy that fell back
        # to its own environment would pass a configuration the image refuses.
        for what, text in (("compose failed", None), ("not json", "name: offsite\n"),
                           ("no postgres service", json.dumps({"services": {"app": {}}}))):
            with self.subTest(what=what):
                self.docker_log.unlink(missing_ok=True)
                if text is None:
                    self.compose_json.unlink(missing_ok=True)
                    (self.fixture_dir / "pgbackrest_repo_creds.conf").write_text(self.FULL)
                    self.env_file.write_text("POLARIS_DOMAIN=polaris.example.org\nPOLARIS_SECRETS_BACKEND=file\n"
                                             "POLARIS_SECRETS_DIR=%s\n" % self.fixture_dir)
                    r = subprocess.run(["bash", str(ROOT / "scripts" / "polaris-deploy.sh"), "prod", "--no-pull"],
                                       capture_output=True, text=True, timeout=60,
                                       env={"PATH": "%s:/usr/bin:/bin:/usr/sbin:/sbin" % self.bin,
                                            "HOME": str(self.tmp), "STUB_WD": str(ROOT / "polaris_web"),
                                            "STUB_EF": str(self.env_file)})
                else:
                    r = self._deploy(self.FULL, "polaris-dr", compose_json=text)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("could not read the postgres service's resolved configuration", r.stderr)
                self._started_nothing(r)

    def test_a_configuration_the_image_accepts_goes_on(self):
        for fragment, bucket in ((self.FULL, "polaris-dr"), ("# commented template\n", "")):
            with self.subTest(bucket=bucket or "none"):
                self.docker_log.unlink(missing_ok=True)
                r = self._deploy(fragment, bucket)
                self.assertIn("is one the postgres image accepts", r.stdout, r.stdout + r.stderr)
                # It goes on to step 3, where DeploysTakeTurns' stand-in pins the running image.
                self.assertIn("tag sha256:feed polaris-app:rollback-offsite", self.docker_log.read_text())
                self.assertNotIn(self.FIXTURE_CIPHER_TEXT, r.stdout + r.stderr)


class DeployRequiresEverySecretProductionValidates(_Base):
    """config_schema.py makes each app secret_file one production validates at boot, and an rc.70
    install has neither polaris_redis_password nor polaris_secret_key_fallbacks (nor redis_users.acl,
    which Redis reads). The deploy checked four names, so the upgrade OPERATIONS.md gave went on to
    pull, build and start a stack that could not start. It now refuses first, naming each missing
    file and the script that writes it. The stand-in Docker is DeploysTakeTurns'."""

    def setUp(self):
        super().setUp()
        self.nets = self.tmp / "networks"
        self.fixture_dir = self.tmp / "secrets"
        self.fixture_dir.mkdir()
        compose_json = self.tmp / "compose.json"
        compose_json.write_text(json.dumps({"name": "secrets", "services": {"postgres": {"environment": {}}}}))
        (self.bin / "docker").write_text(DeploysTakeTurns.DOCKER % {
            "log": self.docker_log, "nets": self.nets, "project": "secrets", "json": compose_json})
        (self.bin / "docker").chmod(0o755)
        self.env_file.write_text("POLARIS_DOMAIN=polaris.example.org\nPOLARIS_SECRETS_BACKEND=file\n"
                                 "POLARIS_SECRETS_DIR=%s\n" % self.fixture_dir)

    def _deploy(self, present, directory=None):
        for p in self.fixture_dir.iterdir():
            p.rmdir() if p.is_dir() else p.unlink()
        for name in present:
            (self.fixture_dir / name).write_text("# template\n" if name == "pgbackrest_repo_creds.conf" else "x\n")
        if directory:
            (self.fixture_dir / directory).mkdir()
        self.docker_log.unlink(missing_ok=True)
        r = subprocess.run(["bash", str(ROOT / "scripts" / "polaris-deploy.sh"), "prod", "--no-pull"],
                           capture_output=True, text=True, timeout=60,
                           env={"PATH": "%s:/usr/bin:/bin:/usr/sbin:/sbin" % self.bin, "HOME": str(self.tmp),
                                "STUB_WD": str(ROOT / "polaris_web"), "STUB_EF": str(self.env_file)})
        return r, r.stdout + r.stderr

    def _refused_before_docker(self, r, out):
        self.assertEqual(r.returncode, 1, out)
        self.assertIn("run: ./scripts/polaris-generate-secrets.sh", out)
        calls = self.docker_log.read_text().splitlines() if self.docker_log.exists() else []
        self.assertEqual(calls, ["compose version"], "the refused deploy went on: %s\n%s" % (calls, out))
        self.assertFalse(list(self.nets.iterdir()) if self.nets.is_dir() else [], "the refused deploy took the lock")

    def test_an_rc70_install_is_refused_naming_what_it_lacks(self):
        r, out = self._deploy(RC70_SECRETS)
        self._refused_before_docker(r, out)
        for name in ("polaris_redis_password", "redis_users.acl", "polaris_secret_key_fallbacks"):
            self.assertIn("missing secret: secrets/%s\n" % name, out)
        for name in RC70_SECRETS:
            self.assertNotIn("missing secret: secrets/%s\n" % name, out)

    def test_each_file_is_required_and_a_directory_is_not_one(self):
        for name in ALL_SECRETS:
            with self.subTest(missing=name):
                r, out = self._deploy([n for n in ALL_SECRETS if n != name])
                self._refused_before_docker(r, out)
                self.assertIn("missing secret: secrets/%s\n" % name, out)
        # A bind mount whose source is missing makes docker create a directory there.
        r, out = self._deploy([n for n in ALL_SECRETS if n != "polaris_redis_password"],
                              directory="polaris_redis_password")
        self._refused_before_docker(r, out)
        self.assertIn("missing secret: secrets/polaris_redis_password\n", out)

    def test_the_app_files_are_config_schemas_secret_files_the_compose_mounts(self):
        import importlib.util
        import re
        import sys
        spec = importlib.util.spec_from_file_location("config_schema", ROOT / "polaris_web" / "config_schema.py")
        schema = importlib.util.module_from_spec(spec)
        sys.modules.setdefault("config_schema", schema)  # the dataclass resolves its module by name
        spec.loader.exec_module(schema)
        compose = (ROOT / "polaris_web" / "docker-compose.prod.yml").read_text()
        mounted = {secret for name, secret in re.findall(r"(?m)^\s+(POLARIS_\w+_FILE): /run/secrets/(\w+)\s*$", compose)
                   if getattr(schema.lookup(name), "kind", None) == "secret_file"}
        self.assertEqual(mounted, set(APP_SECRETS))

    def test_the_full_set_goes_on(self):
        r, out = self._deploy(ALL_SECRETS)
        self.assertIn("all secrets present", out)
        self.assertIn("tag sha256:feed polaris-app:rollback-secrets", self.docker_log.read_text(), out)

    @unittest.skipIf(sys.platform.startswith("linux") and os.geteuid() == 0,
                     "as root on Linux the unseal mounts a tmpfs over the test's directory")
    def test_a_sealed_store_is_told_to_seal_only_what_is_missing(self):
        # The deploy unseals into POLARIS_SECRETS_DIR first, so a file missing there is missing from
        # the store; the generator writes plaintext, all of it when polaris_web/secrets is gone, and a
        # full seal would put new values over the live ones. A stand-in interpreter makes the unseal
        # a no-op over the directory the test fills.
        stub = self.bin / "unseal-noop"
        stub.write_text("#!/bin/sh\nexit 0\n")
        stub.chmod(0o755)
        self.env_file.write_text("POLARIS_DOMAIN=polaris.example.org\nPOLARIS_SECRETS_BACKEND=age\n"
                                 "POLARIS_SECRETS_DIR=%s\nPOLARIS_PYTHON=%s\n" % (self.fixture_dir, stub))
        r, out = self._deploy(RC70_SECRETS)
        self._refused_before_docker(r, out)
        self.assertIn("missing secret: secrets/polaris_redis_password\n", out)
        self.assertIn("./scripts/polaris-secrets.sh seal --only <name> for each one named", out)
        r, out = self._deploy(ALL_SECRETS)
        self.assertIn("all secrets present", out)

    def test_the_file_backend_is_not_told_to_seal(self):
        r, out = self._deploy(RC70_SECRETS)
        self._refused_before_docker(r, out)
        self.assertNotIn("seal --only", out)


class DeployRefusesWhenItCannotTellWhichSecretsProductionNeeds(_Base):
    """The app's secret files are read from config_schema.py and the prod compose. A list that comes
    out empty, or that cannot be read, is a refusal, never a pre-flight that checks nothing. The
    deploy runs from a copy of the tree whose two files the test changes."""

    def setUp(self):
        super().setUp()
        self.root = self.tmp / "tree"
        (self.root / "scripts").mkdir(parents=True)
        (self.root / "polaris_web").mkdir()
        for name in ("polaris-deploy.sh", "polaris-env.sh", "polaris-host-lock.sh"):
            shutil.copy(ROOT / "scripts" / name, self.root / "scripts" / name)
        self.compose = (ROOT / "polaris_web" / "docker-compose.prod.yml").read_text()
        self.fixture_dir = self.tmp / "secrets"
        self.fixture_dir.mkdir()
        for name in ALL_SECRETS:
            (self.fixture_dir / name).write_text("x\n")
        self.env_file.write_text("POLARIS_DOMAIN=polaris.example.org\nPOLARIS_SECRETS_BACKEND=file\n"
                                 "POLARIS_SECRETS_DIR=%s\n" % self.fixture_dir)
        (self.bin / "docker").write_text('#!/bin/sh\necho "$*" >> "%s"\n[ "$*" = "compose version" ] && exit 0\n'
                                         'exit 99\n' % self.docker_log)
        (self.bin / "docker").chmod(0o755)

    def _deploy(self, compose, schema=True):
        (self.root / "polaris_web" / "docker-compose.prod.yml").write_text(compose)
        target = self.root / "polaris_web" / "config_schema.py"
        if schema:
            shutil.copy(ROOT / "polaris_web" / "config_schema.py", target)
        elif target.exists():
            target.unlink()
        self.docker_log.unlink(missing_ok=True)
        r = subprocess.run(["bash", str(self.root / "scripts" / "polaris-deploy.sh"), "prod", "--no-pull"],
                           capture_output=True, text=True, timeout=60,
                           env={"PATH": "%s:/usr/bin:/bin:/usr/sbin:/sbin" % self.bin, "HOME": str(self.tmp),
                                "STUB_WD": str(self.root / "polaris_web"), "STUB_EF": str(self.env_file)})
        return r, r.stdout + r.stderr

    def test_an_empty_or_unreadable_list_is_refused(self):
        import re
        no_mounts = re.sub(r"(?m)^\s+POLARIS_\w+_FILE: /run/secrets/\w+\s*\n", "", self.compose)
        no_entry = self.compose.replace("  polaris_redis_password:\n    file:", "  polaris_redis_password_gone:\n    file:")
        self.assertNotEqual(no_mounts, self.compose)
        self.assertNotEqual(no_entry, self.compose)
        for what, compose, schema in (("no secret_file is mounted", no_mounts, True),
                                      ("a mounted secret the secrets section lacks", no_entry, True),
                                      ("no config_schema.py", self.compose, False)):
            with self.subTest(what):
                r, out = self._deploy(compose, schema)
                self.assertEqual(r.returncode, 1, out)
                self.assertIn("could not read the secret files production requires", out)
                calls = self.docker_log.read_text().splitlines() if self.docker_log.exists() else []
                self.assertEqual(calls, ["compose version"], out)
        r, out = self._deploy(self.compose)
        self.assertIn("all secrets present", out)


class GeneratorRefusesADirectoryWhereASecretBelongs(unittest.TestCase):
    """docker creates a directory at a bind source that is missing when the stack starts, and `-s`
    is true for a directory: the generator said the secret existed and never wrote it, so a host
    that started the stack before generating stayed broken. It now refuses and names the
    directory, and leaves it for the operator to remove. Runs the real generator in a copy of the
    tree, with a Docker that fails (so no signing key is minted)."""

    def _generate(self, directory=None):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-gen-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "scripts").mkdir()
        (tmp / "polaris_web").mkdir()
        (tmp / "bin").mkdir()
        shutil.copy(ROOT / "scripts" / "polaris-generate-secrets.sh", tmp / "scripts")
        (tmp / "bin" / "docker").write_text("#!/bin/sh\nexit 99\n")
        (tmp / "bin" / "docker").chmod(0o755)
        secrets = tmp / "polaris_web" / "secrets"
        if directory:
            (secrets / directory).mkdir(parents=True)
        r = subprocess.run(["bash", str(tmp / "scripts" / "polaris-generate-secrets.sh")], capture_output=True,
                           text=True, timeout=120,
                           env={"PATH": "%s:/usr/bin:/bin:/usr/sbin:/sbin" % (tmp / "bin"), "HOME": str(tmp)})
        return r, secrets

    def test_a_directory_at_a_secrets_path_is_refused_and_kept(self):
        for name in ("polaris_redis_password", "redis_users.acl", "polaris_secret_key_fallbacks",
                     "pgbackrest_repo_creds.conf", "postgres_server.key"):
            with self.subTest(name):
                r, secrets = self._generate(directory=name)
                self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("remove the directory %s," % (secrets / name), r.stderr)
                self.assertIn("created by docker for a missing secret, then rerun", r.stderr)
                self.assertTrue((secrets / name).is_dir(), "the generator removed the directory itself")

    def test_without_one_every_file_is_written(self):
        r, secrets = self._generate()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for name in ALL_SECRETS:
            self.assertTrue((secrets / name).is_file() and (secrets / name).stat().st_size > 0, name)


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
