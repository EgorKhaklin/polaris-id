# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_ship_tool.py — the triage tool's flake classifier (roadmap P1.16, v9.377).

`triage` exists so a red CI run gets one of two answers quickly: this is a known flake, rerun
it; or this is real, here are the first failing lines. Both answers are load-bearing, and the
expensive failure is the third one it used to give by accident, which is a confident
"investigate" over a log it never actually read.

These are unit tests over the pure classifier, so a new signature is verified against the log
line it was written for rather than by pushing and waiting twenty minutes to find out.
"""
import importlib.util
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load():
    spec = importlib.util.spec_from_file_location(
        "polaris_ship_tool", os.path.join(_HERE, "polaris-ship.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ship = _load()

# The real line, from the run that prompted the signature. Kept verbatim: a signature tested
# against a paraphrase of its log is a signature tested against nothing.
ALPINE_PIP = (
    'Docker image build\t\t2026-09-10T22:17:12.4862682Z ERROR: failed to build: failed to '
    'solve: process "/bin/sh -c apk add --no-cache python3     && apk add --no-cache '
    '--virtual .pip py3-pip     && pip3 install --no-cache-dir --break-system-packages -r '
    '/tmp/requirements-patroni.txt     && apk del .pip     && rm -f '
    '/tmp/requirements-patroni.txt     && patroni --version" did not complete successfully: '
    'exit code: 1')


#: Run 35110741726's rolling drill, verbatim: the preflight refused because
#: `docker compose config --services` listed no app-green, seconds after the boot step had
#: printed both colours healthy. The rerun passed unchanged.
COMPOSE_CONFIG_EMPTY = (
    'Rolling deploy under traffic drops zero requests (blue-green profile + control)\t'
    'Rolling deploy under traffic, then the negative control\t'
    '2026-09-16T14:55:06.6743947Z == preflight: both colours up and the edge answers ==\n'
    'Rolling deploy under traffic drops zero requests (blue-green profile + control)\t'
    'Rolling deploy under traffic, then the negative control\t'
    '2026-09-16T14:55:06.8123496Z ##[error]the blue-green overlay is not active (set POLARIS_COMPOSE_EXTRA)\n'
    'Rolling deploy under traffic drops zero requests (blue-green profile + control)\t'
    'Rolling deploy under traffic, then the negative control\t'
    '2026-09-16T14:55:06.8139171Z ##[error]Process completed with exit code 1.')

#: v9.446's DR drill, verbatim. The build died resolving the dockerfile FRONTEND from
#: Docker Hub, so it never read the Dockerfile and the tree had nothing to do with it.
BUILDKIT_FRONTEND = (
    'DR drill\t\t2026-09-12T19:01:12.0000000Z == 0. build the pgbackrest-enabled postgres image ==\n'
    'DR drill\t\t2026-09-12T19:01:13.0000000Z ERROR: failed to build: failed to solve: '
    'DeadlineExceeded: DeadlineExceeded: failed to resolve source metadata for '
    'docker.io/docker/dockerfile:1: failed to do request\n'
    'DR drill\t\t2026-09-12T19:01:13.6923120Z ##[error]Process completed with exit code 1.')

#: Run 35174791045, verbatim. Dependabot proposed ydiff==1.5 into requirements-patroni.txt;
#: patroni 4.1.5 forbids it; the postgres image stopped building and nine container jobs went
#: down. pip has answered here, so no rerun can help.
PIP_RESOLUTION_IMPOSSIBLE = (
    'Docker image build + boot smoke test\tpgBackRest archive + backup + restore round-trip\t'
    '2026-09-17T02:35:03.9593736Z #10 4.566 ERROR: Cannot install patroni and ydiff==1.5 '
    'because these package versions have conflicting dependencies.\n'
    'Docker image build + boot smoke test\tpgBackRest archive + backup + restore round-trip\t'
    '2026-09-17T02:35:03.9595255Z #10 4.566     patroni 4.1.5 depends on ydiff!=1.4.0, '
    '!=1.4.1, <1.5 and >=1.2.0')

#: The line BuildKit prints when it STARTS the caddy builder step, verbatim from the same run.
#: It is the RUN command's own text, and the retry loop inside it echoes the words
#: "checksum-database stream error". Nothing has failed at this point. The old
#: caddy-module-proxy pattern matched the bare words `stream error`, so this line alone made
#: every container log in the tree look like a known Caddy flake.
CADDY_RETRY_LOOP_ECHO = (
    'Linux server install (systemd on this host; Debian 12 + Rocky 9 package stages)\t'
    'full install on this host (real systemd) to a healthy stack through the TLS edge\t'
    '2026-09-17T02:35:19.0342028Z Sep 17 02:35:18 runnervmlun5p docker[10721]: '
    '#26 [caddy builder 2/2] RUN for attempt in 1 2 3 4; do         xcaddy build '
    '            --with github.com/mholt/caddy-ratelimit             --replace '
    'golang.org/x/crypto=golang.org/x/crypto@v0.55.0         && break;         '
    'if [ "$attempt" = 4 ]; then echo "xcaddy build failed 4 times; giving up" >&2; exit 1; '
    'fi;         echo "xcaddy build attempt $attempt failed (a module fetch or a '
    'checksum-database stream error); retrying in $((attempt * 20))s" >&2;         '
    'sleep $((attempt * 20));     done')


#: The same package-index failure in the pgbouncer image, which runs `apk upgrade && apk add`
#: with no pip. Its failure marker comes BEFORE the step text rather than after it, which is
#: why the pip-shaped pattern missed it: on 2026-09-19 it came back as "investigate" and cost a
#: hand investigation for a class this table already documented.
ALPINE_APK_NO_PIP = (
    'target pgbouncer: failed to solve: process "/bin/sh -c apk upgrade --no-cache     '
    '&& apk add --no-cache pgbouncer netcat-openbsd openssl" did not complete successfully: '
    'exit code: 1')

#: BuildKit ECHOES a RUN step when it starts. Matching the bare step text is how the Caddy
#: retry loop's own message made every container log look like a Caddy flake until 2026-09-16,
#: so the apk signature must require a real failure marker and this must NOT classify.
ALPINE_APK_ECHO_ONLY = '#8 [stage-1 3/7] RUN /bin/sh -c apk add --no-cache pgbouncer'


class FlakeClassifierTests(unittest.TestCase):
    def test_the_alpine_apk_layer_is_a_known_flake(self):
        verdict, name, advice = ship.classify_failure_log(ALPINE_PIP)
        self.assertEqual((verdict, name), ("flake", "alpine-apk-layer"))
        self.assertIn("docker build --no-cache", advice,
                      "the advice must say how to CONFIRM it is a flake, not just assert it")

    def test_the_apk_layer_classifies_in_an_image_that_does_not_pip(self):
        """The signature was scoped to the image somebody was looking at.

        It required `apk add ... pip3 install`, which is the postgres image's layer. The
        pgbouncer image installs no Python, so an identical package-index failure returned
        "investigate"."""
        verdict, name, _advice = ship.classify_failure_log(ALPINE_APK_NO_PIP)
        self.assertEqual((verdict, name), ("flake", "alpine-apk-layer"))

    def test_a_buildkit_echo_of_an_apk_step_is_not_a_flake(self):
        verdict, name, _advice = ship.classify_failure_log(ALPINE_APK_ECHO_ONLY)
        self.assertNotEqual(name, "alpine-apk-layer",
                            "BuildKit echoes a RUN step when it starts; classifying on the "
                            "step text rather than on a failure marker is how the Caddy "
                            "signature matched every container log until 2026-09-16")

    def test_a_curl_network_error_in_a_package_stage_is_a_known_flake(self):
        """Run 35510591888: the Linux server install job exited 35 on a commit that touched
        one drill script and nothing that job runs. Underneath was a TLS reset from a CDN
        during the Rocky Linux package stage."""
        verdict, name, advice = ship.classify_failure_log(
            "Importing GPG key 0x350D275D:\n"
            "curl: (35) OpenSSL SSL_connect: Connection reset by peer in connection to "
            "download.docker.com:443\n"
            "##[error]Process completed with exit code 35.\n")
        self.assertEqual((verdict, name), ("flake", "transient-fetch-network"))
        self.assertIn("rerun", advice)

    def test_a_tool_download_timeout_is_the_same_flake(self):
        """Run 35516415530, hours after the signature was written: the formal-specs step
        fetches tla2tools from github.com and curl timed out. Different host, different step,
        different curl code. A signature naming download.docker.com would have missed it."""
        verdict, name, _advice = ship.classify_failure_log(
            "curl: (28) Failed to connect to github.com port 443 after 135276 ms: "
            "Couldn't connect to server\ntla drill could not fetch tla2tools v1.7.4\n"
            "##[error]Process completed with exit code 3.\n")
        self.assertEqual((verdict, name), ("flake", "transient-fetch-network"))

    def test_the_curl_signature_is_not_scoped_to_one_host(self):
        """The alpine-apk entry above is here because a signature written for the image
        somebody was looking at missed the identical failure in a sibling. Every package
        stage in this tree fetches over curl from somewhere."""
        verdict, name, _advice = ship.classify_failure_log(
            "curl: (6) Could not resolve host: deb.debian.org\n")
        self.assertEqual((verdict, name), ("flake", "transient-fetch-network"))

    def test_an_http_error_from_curl_is_not_a_flake(self):
        """`curl: (22)` is a 4xx under --fail: a URL that moved or a credential that
        expired. Rerunning that fails forever, which is the whole distinction this table
        draws."""
        for line in ("curl: (22) The requested URL returned error: 404\n",
                     "curl: (22) The requested URL returned error: 403 Forbidden\n"):
            with self.subTest(line=line):
                _verdict, name, _advice = ship.classify_failure_log(line)
                self.assertNotEqual(name, "transient-fetch-network",
                                    "an HTTP status is not a dropped connection")

    def test_a_registry_5xx_during_a_pull_is_a_known_flake(self):
        """Run 35473066452: `docker compose up` got a 502 and created nothing.

        The commit touched two Markdown files under lab/strategy/. The commit after it,
        carrying the same content plus a package change, passed the same job.
        """
        for line in ("pg-router Error received unexpected HTTP status: 502 Bad Gateway",
                     "Error response from daemon: received unexpected HTTP status: 502 Bad Gateway",
                     "received unexpected HTTP status: 503 Service Unavailable"):
            with self.subTest(line=line[:40]):
                verdict, name, advice = ship.classify_failure_log(line)
                self.assertEqual((verdict, name), ("flake", "registry-5xx"))
                self.assertIn("rerun", advice)

    def test_a_missing_container_alone_is_not_a_registry_flake(self):
        """The signature is anchored on the HTTP status, not on the daemon's error prefix.

        `Error response from daemon:` also prefixes `No such container`, which is what a
        genuinely dead service prints. Matching the prefix would have classified every one
        of those as a registry flake and told the reader to rerun."""
        verdict, name, _advice = ship.classify_failure_log(
            "Error response from daemon: No such container: polaris-postgres")
        self.assertNotEqual(name, "registry-5xx",
                            "a container that is absent for any other reason must not be "
                            "answered 'known flake, rerun'")

    def test_a_registry_4xx_is_not_this_flake(self):
        """A definite answer from a registry that is up. Rerunning never clears it."""
        verdict, name, _advice = ship.classify_failure_log(
            "pull access denied for polaris/nope, repository does not exist")
        self.assertNotEqual(name, "registry-5xx")

    def test_a_docker_hub_rate_limit_is_a_known_flake(self):
        """Runs 37988431584 and 37988697783: every image build died on Docker Hub's 429.

        The BuildKit line is copied from the log; the daemon line is how `docker pull` and
        `docker compose` print the same refusal. Before the signature both said
        'investigate'."""
        for line in (
                "ERROR: failed to build: failed to solve: failed to copy: httpReadSeeker: failed "
                "open: unexpected status code https://registry-1.docker.io/v2/library/postgres/"
                "manifests/sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea"
                ": 429 Too Many Requests - Server message: toomanyrequests: You have reached your "
                "unauthenticated pull rate limit. https://www.docker.com/increase-rate-limit",
                "Error response from daemon: toomanyrequests: You have reached your "
                "unauthenticated pull rate limit. https://www.docker.com/increase-rate-limit",
                # An authenticated account's own limit: the same flake, another remedy.
                "Error response from daemon: toomanyrequests: You have reached your pull rate "
                "limit as 'polarisbot': 0123abcd. You may increase the limit by upgrading. "
                "https://www.docker.com/increase-rate-limit"):
            with self.subTest(line=line[60:100]):
                verdict, name, advice = ship.classify_failure_log(line)
                self.assertEqual((verdict, name), ("flake", "dockerhub-rate-limit"))
                self.assertIn("wait, then rerun", advice)
                self.assertIn("docker login", advice)
                self.assertIn("higher tier", advice)

    def test_a_removed_image_beats_the_rate_limit(self):
        """A log carrying both answers is the definite one: registry-removal, not a flake.

        One job's 429 must not turn another job's removed image into "wait and rerun"."""
        verdict, name, _advice = ship.classify_failure_log(
            "Error response from daemon: toomanyrequests: You have reached your "
            "unauthenticated pull rate limit. https://www.docker.com/increase-rate-limit\n"
            "pull access denied for minio/minio, repository does not exist or may require "
            "'docker login'")
        self.assertEqual((verdict, name), ("upstream", "registry-removal"))

    def test_the_apt_index_flake_still_classifies(self):
        for line in ("E: Failed to fetch http://azure.archive.ubuntu.com",
                     "Hash Sum mismatch",
                     "Some index files failed to download"):
            with self.subTest(line=line[:30]):
                self.assertEqual(ship.classify_failure_log(line)[1], "apt-index")

    def test_the_caddy_module_proxy_flake_still_classifies(self):
        self.assertEqual(
            ship.classify_failure_log("verifying sum.golang.org: stream error")[1],
            "caddy-module-proxy")

    def test_the_buildkit_frontend_timeout_is_a_known_flake(self):
        verdict, name, advice = ship.classify_failure_log(BUILDKIT_FRONTEND)
        self.assertEqual((verdict, name), ("flake", "buildkit-frontend"))
        self.assertIn("rerun", advice)

    def test_an_empty_compose_config_in_the_rolling_preflight_is_a_known_flake(self):
        verdict, name, advice = ship.classify_failure_log(COMPOSE_CONFIG_EMPTY)
        self.assertEqual((verdict, name), ("flake", "compose-config-empty"))
        self.assertIn("boot step", advice,
                      "the advice must say what to CONFIRM before calling it a flake")
        self.assertIn("rerun", advice)

    def test_the_drill_refusing_an_unhealthy_edge_is_still_investigated(self):
        """The preflight has two refusals. Only the compose-config one has been chased; the
        other is the edge not answering, which nobody has shown to be transient."""
        verdict, name, _ = ship.classify_failure_log(
            "Rolling deploy under traffic drops zero requests (blue-green profile + control)\t"
            "Rolling deploy under traffic, then the negative control\t"
            "2026-09-16T14:55:06.8123496Z ##[error]edge not healthy before the drill")
        self.assertEqual((verdict, name), ("investigate", None))

    def test_a_registry_REMOVAL_is_not_read_as_a_frontend_timeout(self):
        """The two look alike and the advice is opposite: rerunning clears a registry that
        did not answer and never clears a repository that is gone."""
        verdict, name, _ = ship.classify_failure_log(
            "ERROR: pull access denied for minio/minio, repository does not exist or may "
            "require 'docker login'")
        self.assertEqual((verdict, name), ("upstream", "registry-removal"))

    def test_a_real_failure_is_not_excused_as_a_flake(self):
        # The direction that matters most. A classifier that called real failures flakes
        # would turn a red build into a rerun loop, and the defect would ship.
        for line in ("AssertionError: the drill found a defect",
                     "✗ [some_check] the tree does not hold",
                     "FAIL: at least one case did not hold",
                     "psycopg2.errors.CheckViolation: token has zero active signatures",
                     "ModuleNotFoundError: No module named 'cbor2'"):
            with self.subTest(line=line[:30]):
                self.assertEqual(ship.classify_failure_log(line)[0], "investigate")

    def test_an_empty_log_is_not_a_flake(self):
        self.assertEqual(ship.classify_failure_log("")[0], "investigate")

    def test_a_pip_requirement_set_with_no_solution_is_upstream_not_a_flake(self):
        """pip has ANSWERED: these versions cannot be installed together. Rerunning cannot
        change that, so the verdict must not be the one that says to rerun."""
        verdict, name, advice = ship.classify_failure_log(PIP_RESOLUTION_IMPOSSIBLE)
        self.assertEqual((verdict, name), ("upstream", "pip-resolution-impossible"))
        self.assertIn("dependabot", advice.lower(),
                      "a bot-proposed bump comes back unless the bound is recorded; say so")

    def test_the_caddy_retry_loop_being_PRINTED_is_not_the_caddy_flake(self):
        """BuildKit echoes a RUN step's command text when the step starts, and this one
        contains the retry loop's own words "checksum-database stream error". Reading that as
        the flake made every container log in the tree look transient, which is how a hard
        dependency conflict was answered "rerun the failed jobs"."""
        verdict, name, _ = ship.classify_failure_log(CADDY_RETRY_LOOP_ECHO)
        self.assertEqual((verdict, name), ("investigate", None))

    def test_a_definite_failure_beats_a_flake_signature_in_the_same_log(self):
        """The failure that made this matter. A CI run is many jobs in one log: one job can
        hit a real network flake while another hits something no rerun will fix. The definite
        answer has to win whichever order they appear in, or the verdict is decided by which
        job happened to run first."""
        for label, log in (
                ("flake first", CADDY_RETRY_LOOP_ECHO + "\nsum.golang.org: stream error\n"
                                + PIP_RESOLUTION_IMPOSSIBLE),
                ("flake last", PIP_RESOLUTION_IMPOSSIBLE
                               + "\nsum.golang.org: stream error\n" + CADDY_RETRY_LOOP_ECHO)):
            with self.subTest(label):
                verdict, name, _ = ship.classify_failure_log(log)
                self.assertEqual((verdict, name), ("upstream", "pip-resolution-impossible"))

    def test_every_upstream_signature_says_not_to_rerun(self):
        """The whole point of the second table: its advice is the opposite of a flake's. A
        signature that landed here without saying so would read as a flake to the reader."""
        for name, pattern, advice in ship.UPSTREAM_SIGNATURES:
            with self.subTest(name=name):
                self.assertTrue(pattern, "%s has no pattern" % name)
                self.assertGreater(len(advice), 30, "%s: advice must say what to DO" % name)
                self.assertRegex(
                    advice, r"(?i)NOT a flake|will not clear|do not rerun",
                    "%s: say plainly that rerunning cannot help" % name)

    def test_every_signature_carries_advice(self):
        for name, pattern, advice in ship.FLAKE_SIGNATURES:
            with self.subTest(name=name):
                self.assertTrue(pattern, "%s has no pattern" % name)
                self.assertGreater(len(advice), 30,
                                   "%s: advice must say what to DO, not name the flake" % name)
                self.assertIn("rerun", advice.lower(),
                              "%s: a flake's advice is to rerun; say so" % name)


class TriageHonestyTests(unittest.TestCase):
    """The verdict a tool gives when it could not look at anything."""

    def test_triage_distinguishes_no_log_from_nothing_found(self):
        # gh refuses --log-failed while any job in the run is still going, so a run whose
        # failure has already landed returns a refusal string rather than a log. Reporting
        # "investigate (no known flake signature matched)" over that reads as a considered
        # verdict about evidence nobody saw.
        with open(os.path.join(_HERE, "polaris-ship.py")) as fh:
            source = fh.read()
        self.assertIn("still in progress", source,
                      "triage must recognise gh's refusal to hand over a log")
        self.assertIn("UNKNOWN, no log to read yet", source,
                      "and say so, rather than reporting a conclusion it did not reach")
        triage = source.split("def triage")[1]
        unknown_at = triage.find("UNKNOWN, no log to read yet")
        classify_at = triage.find("classify_failure_log(log)")
        self.assertGreater(classify_at, 0)
        self.assertLess(unknown_at, classify_at,
                        "the no-log case must be handled BEFORE classification, or the "
                        "classifier runs over a refusal string and reports on it")

    def _triage_with(self, jobs, log, annotations):
        """triage() against a stand-in for gh: the run's jobs, the failed-job log, annotations."""
        import io
        import json
        from unittest import mock
        calls = []

        def fake_gh(*args):
            calls.append(args)
            if args[:2] == ("run", "view"):
                return json.dumps(jobs)
            if args[0] == "api" and args[1].endswith("/annotations"):
                return json.dumps(annotations)
            raise AssertionError("unexpected gh call %r" % (args,))
        out = io.StringIO()
        with mock.patch.object(ship, "_gh", fake_gh), \
                mock.patch.object(ship.subprocess, "run", return_value=mock.Mock(stdout=log)):
            rc = ship.triage("123", out=out)
        return rc, out.getvalue(), calls

    def test_a_job_that_never_got_a_runner_is_named_not_left_unknown(self):
        # Run 36712294233, 2026-09-30: finished, one job failed without ever starting, no log.
        jobs = {"conclusion": "failure", "jobs": [
            {"name": "Full prod compose", "conclusion": "failure", "steps": [], "databaseId": 9}]}
        note = [{"message": "The job was not started because it repeatedly failed to be "
                            "acquired (5 attempts)."}]
        rc, text, _ = self._triage_with(jobs, "", note)
        self.assertIn("known flake [runner-not-acquired]", text)
        self.assertIn("gh run rerun 123 --failed", text)
        self.assertEqual(rc, 0)

    def test_a_finished_run_with_no_log_and_no_reason_stays_unknown(self):
        jobs = {"conclusion": "failure", "jobs": [
            {"name": "x", "conclusion": "failure", "steps": [], "databaseId": 9}]}
        rc, text, _ = self._triage_with(jobs, "", [])
        self.assertIn("UNKNOWN, no log to read yet", text)
        self.assertEqual(rc, 1)

    def test_a_run_still_going_reads_no_annotations_and_stays_unknown(self):
        jobs = {"conclusion": None, "jobs": [
            {"name": "x", "conclusion": "failure", "steps": [], "databaseId": 9}]}
        rc, text, calls = self._triage_with(jobs, "", [{"message": "was not started because it "
                                                          "repeatedly failed to be acquired"}])
        self.assertIn("UNKNOWN, no log to read yet", text)
        self.assertEqual([c for c in calls if c[0] == "api"], [])
        self.assertEqual(rc, 1)


def _write(path, text):
    with open(path, "w") as fh:
        fh.write(text)


class ShipBaselineTests(unittest.TestCase):
    """What the drill gate diffs against. 2026-09-23: a committed, unpushed change in a tree
    holding one unrelated untracked file read as "dirty", the baseline became HEAD, and the
    gate reported READY with the commit's drills unrun."""

    def setUp(self):
        # Run from a git hook, the environment names the repository being committed
        # (GIT_INDEX_FILE, GIT_DIR, GIT_WORK_TREE). Inherited by the git commands below and by
        # the ship tool's own, they act on THAT repository: from a linked worktree, where the
        # index path is absolute, `git add a.txt` in the scratch repository added a.txt to the
        # index of the commit being made, and the scratch commit failed (2026-09-28). The
        # scratch repositories must see none of it.
        self._git_env = {k: os.environ.pop(k) for k in list(os.environ) if k.startswith("GIT_")}

    def tearDown(self):
        os.environ.update(self._git_env)

    def _repo(self):
        import subprocess
        import tempfile
        root = tempfile.mkdtemp(prefix="polaris-ship-baseline-")
        remote, work = os.path.join(root, "remote.git"), os.path.join(root, "work")
        # The scratch identity rides in the environment and is never written to a config file.
        # Before setUp dropped GIT_*, a hook's GIT_DIR sent `git config user.name t` into the
        # real repository's config, and 69 commits were authored t <t@example.invalid>.
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
        git = lambda *a, cwd=work: subprocess.run(["git", *a], cwd=cwd, check=True, env=env,  # noqa: E731
                                                  capture_output=True, text=True).stdout.strip()
        subprocess.run(["git", "init", "--bare", "-q", remote], check=True)
        subprocess.run(["git", "clone", "-q", remote, work], check=True, capture_output=True)
        _write(os.path.join(work, "a.txt"), "1")
        git("add", "a.txt"); git("commit", "-q", "-m", "base"); git("push", "-q", "origin", "HEAD")
        git("branch", "--set-upstream-to=origin/%s" % git("rev-parse", "--abbrev-ref", "HEAD"))
        return work, git

    def _baseline(self, work):
        saved = ship.ROOT
        ship.ROOT = work
        try:
            return ship._ship_baseline()
        finally:
            ship.ROOT = saved

    def test_an_unpushed_commit_is_measured_against_the_upstream_even_with_a_stray_file(self):
        work, git = self._repo()
        upstream = git("rev-parse", "HEAD")
        _write(os.path.join(work, "a.txt"), "2")
        git("commit", "-q", "-am", "the change the gate must see")
        _write(os.path.join(work, "stray.png"), "x")
        self.assertEqual(self._baseline(work), upstream)

    def test_uncommitted_work_on_a_pushed_head_is_measured_against_head(self):
        work, git = self._repo()
        _write(os.path.join(work, "a.txt"), "2")
        self.assertEqual(self._baseline(work), "HEAD")

    # 2026-09-28: CI names the commit a push started from (POLARIS_CHANGED_BASE), because HEAD~1
    # sees only a push's last commit. A push of three commits whose procedure change was the
    # middle one ran the procedure drill as a no-op in under a second.

    def _push_of_three(self):
        work, git = self._repo()
        before = git("rev-parse", "HEAD")
        os.makedirs(os.path.join(work, "polaris_sql"))
        _write(os.path.join(work, "polaris_sql", "05_procedures.sql"), "-- a refusal moved")
        git("add", "polaris_sql"); git("commit", "-q", "-m", "the procedure change")
        _write(os.path.join(work, "CHANGELOG.md"), "a line")
        git("add", "CHANGELOG.md"); git("commit", "-q", "-m", "a changelog line")
        git("checkout", "-q", "--detach")          # CI checks out a commit, with no upstream
        return work, git, before

    def _named(self, value):
        from unittest import mock
        return mock.patch.dict(os.environ, {"POLARIS_CHANGED_BASE": value})

    def test_ci_measures_a_push_from_the_commit_it_started_from(self):
        import polaris_changed_base as cb
        work, git, before = self._push_of_three()
        parent = git("rev-parse", "HEAD~1")
        self.assertNotIn("05_procedures.sql", git("diff", "--name-only", parent),
                         "the miss this closes: HEAD~1 does not see the middle commit")
        with self._named(before):
            self.assertEqual(cb.changed_base(work), before)
            self.assertEqual(self._baseline(work), before)
        self.assertIn("polaris_sql/05_procedures.sql", git("diff", "--name-only", before))

    def test_unnamed_and_detached_is_head_parent(self):
        import polaris_changed_base as cb
        work, git, _ = self._push_of_three()
        saved = os.environ.pop("POLARIS_CHANGED_BASE", None)
        try:
            self.assertEqual(cb.changed_base(work), git("rev-parse", "HEAD~1"))
        finally:
            if saved is not None:
                os.environ["POLARIS_CHANGED_BASE"] = saved

    def test_a_named_commit_the_checkout_cannot_reach_is_not_nothing_changed(self):
        import polaris_changed_base as cb
        work, git, _ = self._push_of_three()
        with self._named("f" * 40):
            self.assertIsNone(cb.changed_base(work), "unreachable must read as 'could not tell'")
            self.assertNotEqual(self._baseline(work), git("rev-parse", "HEAD~1"),
                                "the ship tool must not fall back to the narrow baseline")

    def test_a_first_push_names_the_zero_commit_and_falls_back(self):
        import polaris_changed_base as cb
        work, git, _ = self._push_of_three()
        with self._named("0" * 40):
            self.assertEqual(cb.changed_base(work), git("rev-parse", "HEAD~1"))



class ClassSkipTests(unittest.TestCase):
    """A class skipped whole in setUpClass never counts in "Ran N tests"; run names it."""

    def test_a_whole_class_skip_is_named_with_its_reason(self):
        log = ("test_c (test_app.Fine.test_c) ... ok\n"
               "setUpClass (test_app.ZKSnarkTests) ... skipped 'polaris-zk binary not built at /x. "
               "Run `cargo build --release` in polaris_zk/ first.'\n\n"
               "Ran 1 test in 0.100s\n\nOK (skipped=1)\n")
        self.assertEqual(ship.class_skips(log), [
            ("ZKSnarkTests", "polaris-zk binary not built at /x. Run `cargo build --release` in polaris_zk/ first.")])

    def test_a_per_test_skip_is_not_a_class_skip(self):
        log = ("test_d (test_app.Fine.test_d) ... skipped 'per-test reason'\n\n"
               "Ran 1 test in 0.100s\n\nOK (skipped=1)\n")
        self.assertEqual(ship.class_skips(log), [])


if __name__ == "__main__":
    unittest.main()


class VerificationSelectionTests(unittest.TestCase):
    """`plan` decides what a ship has to verify. Until v9.379 that decision was untested.

    A classifier that mis-selects does not fail loudly: it prints a shorter list, the ship
    passes the checks it was told to run, and the suite that would have caught the defect was
    simply never named. That is the quiet half of a verification tool, and it is the half worth
    testing."""

    def test_a_changed_path_selects_its_verification(self):
        picked = ship.verification_for(["polaris_sql/01_schema.sql"])
        self.assertTrue(picked, "a schema change must select something to run")
        self.assertTrue(all("run" in entry and "why" in entry for entry in picked),
                        "every entry must say what to run and why")

    def test_an_unrelated_path_selects_nothing_spurious(self):
        # Over-selection is not harmless: a plan that names everything is one an operator
        # learns to skim, and then the entry that mattered is skimmed with it.
        picked = ship.verification_for(["README.md"])
        for entry in picked:
            self.assertIn("README", " ".join(entry["paths"]))

    def test_no_changes_selects_nothing(self):
        self.assertEqual(ship.verification_for([]), [])

    def test_each_package_names_the_drill_that_inverts_its_refusals(self):
        def runs(path):
            return " ".join(" ".join(e["run"]) for e in ship.verification_for([path]))
        for path in ("packages/polaris-verify/polaris_verify_cli/verifier.py",
                     "scripts/test_verify_refusals.py"):
            self.assertIn("polaris-sdk-mutation-drill.py", runs(path), path)
        for path in ("packages/polaris-oid4vp/polaris_oid4vp/status.py",
                     "packages/polaris-oid4vp/test_verifier.py"):
            self.assertIn("polaris-oid4vp-mutation-drill.py", runs(path), path)


class RouteChangeDetectionTests(unittest.TestCase):
    """`changed_routes` is how a ship learns which drills exercise what it touched."""

    BASE = (
        "@app.route('/a')\n"
        "def handler_a():\n"
        "    return helper()\n"
        "\n"
        "@app.route('/b')\n"
        "def handler_b():\n"
        "    return 2\n"
        "\n"
        "def helper():\n"
        "    return 1\n")

    def test_an_unchanged_module_changes_no_route(self):
        self.assertEqual(ship.changed_routes(self.BASE, self.BASE), [])

    def test_a_changed_handler_selects_its_own_route(self):
        now = self.BASE.replace("    return 2\n", "    return 3\n")
        self.assertEqual(ship.changed_routes(self.BASE, now), ["/b"])

    def test_a_changed_HELPER_selects_every_route_that_calls_it(self):
        # The case a naive diff misses, and the reason this function exists: the handler's own
        # source is untouched, so nothing about /a looks changed, and /a is exactly what broke.
        now = self.BASE.replace("def helper():\n    return 1\n",
                                "def helper():\n    return 99\n")
        self.assertEqual(ship.changed_routes(self.BASE, now), ["/a"])

    def test_a_new_route_is_selected(self):
        now = self.BASE + "\n@app.route('/c')\ndef handler_c():\n    return 3\n"
        self.assertIn("/c", ship.changed_routes(self.BASE, now))

    def test_top_level_defs_captures_decorators_and_bodies(self):
        defs = ship.top_level_defs(self.BASE)
        self.assertEqual(set(defs), {"handler_a", "handler_b", "helper"})
        self.assertEqual(defs["handler_a"]["routes"], ["/a"])
        self.assertEqual(defs["helper"]["routes"], [])


class DrillSelectionTests(unittest.TestCase):
    def test_a_drill_mentioning_a_route_is_selected(self):
        drills = {"d1.py": "client.get('/api/v1/thing')", "d2.py": "nothing here"}
        self.assertEqual(ship.drills_for_routes(["/api/v1/thing"], drills),
                         {"d1.py": ["/api/v1/thing"]})

    def test_a_parameterised_route_matches_a_concrete_call(self):
        # The route is declared with a placeholder and called with a value; a literal match
        # would select nothing and the drill that covers it would go unrun.
        drills = {"d.py": "client.get('/api/v1/epoch-checkpoint/7')"}
        self.assertEqual(
            ship.drills_for_routes(["/api/v1/epoch-checkpoint/<int:agency_id>"], drills),
            {"d.py": ["/api/v1/epoch-checkpoint/<int:agency_id>"]})

    def test_a_route_that_is_a_PREFIX_of_another_does_not_over_match(self):
        # '/api/v1/thing' must not match '/api/v1/thing-else', or every ship drags in drills
        # for routes it did not touch and the plan stops meaning anything.
        drills = {"d.py": "client.get('/api/v1/thing-else')"}
        self.assertEqual(ship.drills_for_routes(["/api/v1/thing"], drills), {})


class ShardingTests(unittest.TestCase):
    """`run` shards the suites across processes. A unit lost in sharding is a test that
    silently never ran, which is the one sharding bug that does not announce itself."""

    UNITS = [("test_app", "ClassA", 30), ("test_app", "ClassB", 20),
             ("test_app", "ClassC", 10), ("test_cli", "ClassD", 5),
             ("test_cli", "ClassE", 1)]

    def test_every_unit_lands_in_exactly_one_shard(self):
        shards = ship.distribute(self.UNITS, 3, serial=set())
        flat = [u for shard in shards for u in shard]
        self.assertEqual(sorted(flat), sorted(self.UNITS),
                         "no unit may be dropped or duplicated by sharding")

    def test_serial_classes_all_land_in_shard_zero(self):
        # Process-spawning classes must not run beside each other in parallel shards; the
        # convention is that shard 0 takes them and runs them serially.
        serial = {("test_app", "ClassA"), ("test_cli", "ClassD")}
        shards = ship.distribute(self.UNITS, 3, serial=serial)
        for unit in self.UNITS:
            if (unit[0], unit[1]) in serial:
                self.assertIn(unit, shards[0],
                              "%s is serial and must be in shard 0" % (unit,))

    def test_the_heaviest_units_are_spread_rather_than_stacked(self):
        # Heaviest-first onto the least-loaded shard. Without it the wall clock is the sum of
        # the two slowest classes landing together, which is the whole point of sharding.
        shards = ship.distribute(self.UNITS, 2, serial=set())
        loads = [sum(u[2] for u in shard) for shard in shards]
        self.assertLessEqual(max(loads) - min(loads), 30,
                             "the biggest class alone may dominate, but not stack with the next")

    def test_one_unit_and_many_shards_still_runs_that_unit(self):
        shards = ship.distribute([("test_app", "Only", 1)], 8, serial=set())
        flat = [u for shard in shards for u in shard]
        self.assertEqual(flat, [("test_app", "Only", 1)])


class FailureBlockTests(unittest.TestCase):
    """2026-09-24. A CI failure in a test with a docstring printed the test's name and its
    docstring and nothing else: _failure_blocks ended the block at the first dashed line,
    which in unittest's format separates the header from the TRACEBACK, so the assertion that
    says what went wrong never reached the log. A test without a docstring was unaffected,
    which is why it went unnoticed."""

    LOG = (
        "..F.\n"
        "======================================================================\n"
        "FAIL: test_race (test_app.ConcurrencyTests.test_race)\n"
        "Two concurrent calls must not both succeed.\n"
        "----------------------------------------------------------------------\n"
        "Traceback (most recent call last):\n"
        "  File \"test_app.py\", line 9, in test_race\n"
        "AssertionError: 2 != 1 : exactly one should win: {'success': 2}\n"
        "\n"
        "======================================================================\n"
        "ERROR: test_other (test_app.X.test_other)\n"
        "----------------------------------------------------------------------\n"
        "Traceback (most recent call last):\n"
        "RuntimeError: boom\n"
        "\n"
        "----------------------------------------------------------------------\n"
        "Ran 4 tests in 1.000s\n"
        "\n"
        "FAILED (failures=1, errors=1)\n")

    def test_a_block_carries_its_assertion_whether_or_not_the_test_has_a_docstring(self):
        blocks = ship._failure_blocks(self.LOG)
        self.assertEqual(len(blocks), 2)
        self.assertIn("Two concurrent calls", blocks[0])
        self.assertIn("AssertionError: 2 != 1", blocks[0])
        self.assertIn("RuntimeError: boom", blocks[1])

    def test_a_block_ends_before_the_summary(self):
        blocks = ship._failure_blocks(self.LOG)
        self.assertNotIn("Ran 4 tests", blocks[1])
        self.assertNotIn("FAIL: test_race", blocks[1])


class RunLockTests(unittest.TestCase):
    """One `run` per server (2026-09-30): two runs drop and reload the same shard databases, and a
    coverage run beside a gate lost its real-signer stage to "database does not exist". The lock
    is tested against the real server under its own key, because a gate running this suite holds
    the run's key; that run() refuses is tested with the lock's answer given and every process
    start forbidden, so a run that failed to refuse stops here instead of dropping databases."""

    KEY = ship.RUN_LOCK ^ 0x5EED

    def setUp(self):
        self.env = dict(os.environ, POLARIS_DB_HOST=os.environ.get("POLARIS_DB_HOST", "localhost"))

    def test_a_second_holder_is_refused_until_the_first_lets_go(self):
        first, why = ship.hold_run_lock(self.env, self.KEY)
        if first is None:
            self.skipTest("no PostgreSQL to hold the lock on: %s" % why)
        self.addCleanup(ship.release_run_lock, first)
        second, why = ship.hold_run_lock(self.env, self.KEY)
        self.assertIsNone(second, "a second holder must be refused while the first holds it")
        self.assertIn("another polaris-ship run holds the shard databases", why)
        ship.release_run_lock(first)
        third, why = ship.hold_run_lock(self.env, self.KEY)
        self.assertIsNotNone(third, "released with its session, the lock is free again: %s" % why)
        ship.release_run_lock(third)

    def test_a_run_refuses_before_it_starts_anything(self):
        import io
        from unittest import mock

        def no_process(*args, **kwargs):
            raise AssertionError("run() started a process while refused: %r" % (args[:1],))

        out = io.StringIO()
        refused = (None, "another polaris-ship run holds the shard databases (polaris_test_s*) on this server")
        with mock.patch.dict(os.environ, {"POLARIS_DB_USER": "drill"}), \
                mock.patch.object(ship, "_python", return_value="python3"), \
                mock.patch.object(ship, "hold_run_lock", return_value=refused), \
                mock.patch.object(ship.subprocess, "Popen", side_effect=no_process), \
                mock.patch.object(ship.subprocess, "run", side_effect=no_process):
            rc = ship.run(["--shards", "1"], out=out)
        self.assertEqual(rc, 75, out.getvalue())
        self.assertIn("run: refused: another polaris-ship run holds the shard databases", out.getvalue())
        self.assertNotIn("loading", out.getvalue())


class BoundedSuiteRunTests(unittest.TestCase):
    """scripts/polaris_bounded_run.py: a drill's suite run has a bound, and hitting it is reported.

    These assert the effect: the run returns inside the bound, it reads as not passing, and what
    the suite started is gone too, which subprocess.run(timeout=...) alone does not do."""

    def setUp(self):
        import tempfile
        self.dir = tempfile.mkdtemp(prefix="polaris-bounded-")
        self.saved = os.environ.pop("POLARIS_DRILL_SUITE_TIMEOUT", None)

    def tearDown(self):
        import shutil
        import polaris_bounded_run as br
        shutil.rmtree(self.dir, ignore_errors=True)
        if self.saved is not None:
            os.environ["POLARIS_DRILL_SUITE_TIMEOUT"] = self.saved
        br.TIMEOUTS.clear()      # these timeouts are the tests' own; the exit line is a drill's

    @staticmethod
    def _alive(pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        # A killed child of a reaped parent can linger as a zombie until init reaps it; a
        # zombie runs nothing.
        import subprocess
        state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True,
                               text=True).stdout.strip()
        return bool(state) and not state.startswith("Z")

    def test_a_suite_that_finishes_is_passed_through(self):
        import polaris_bounded_run as br
        r = br.run(["sh", "-c", "echo out; echo err >&2; exit 3"], capture_output=True, text=True,
                   timeout=30)
        self.assertEqual((r.returncode, r.stdout, r.stderr), (3, "out\n", "err\n"))
        r = br.run(["sh", "-c", "echo ok"], capture_output=True, timeout=30)
        self.assertEqual((r.returncode, r.stdout), (0, b"ok\n"))

    def test_a_hung_suite_comes_back_inside_the_bound_and_reads_as_not_passing(self):
        import time
        import polaris_bounded_run as br
        pidfile = os.path.join(self.dir, "grandchild.pid")
        # The shell starts a long sleep (what a suite starts: a server, a test binary) and
        # waits on it, as a hung suite would. The sleep writes nowhere, so the pipes close when
        # the shell dies and the only thing left to show a group-less kill is the sleep itself.
        script = "sleep 300 >/dev/null 2>&1 & echo $! > %s; echo started; wait" % pidfile
        t0 = time.monotonic()
        r = br.run(["sh", "-c", script], capture_output=True, text=True, timeout=2)
        took = time.monotonic() - t0
        self.assertLess(took, 20, "the bound did not bound the run")
        self.assertEqual(r.returncode, br.TIMED_OUT)
        self.assertNotEqual(r.returncode, 0, "a timed-out suite must never read as green")
        self.assertIn("started", r.stdout, "what the suite wrote before the bound is kept")
        self.assertIn("TIMED OUT after 2 s", r.stderr.splitlines()[-1])
        with open(pidfile) as fh:
            grandchild = int(fh.read().strip())
        for _ in range(50):
            if not self._alive(grandchild):
                break
            time.sleep(0.1)
        self.assertFalse(self._alive(grandchild),
                         "the suite's own child outlived the bound: only the direct child "
                         "was killed, which is what subprocess.run(timeout=...) does")

    def test_a_process_that_left_the_group_cannot_hold_the_run_open(self):
        import sys
        import time
        import polaris_bounded_run as br
        pidfile = os.path.join(self.dir, "escaped.pid")
        # A test that starts a server in a session of its own: the bound cannot kill it, and it
        # still holds the run's stdout, so reading to end-of-file would wait for it forever.
        child = ("import subprocess, time\n"
                 "p = subprocess.Popen(['sleep', '300'], start_new_session=True)\n"
                 "open(%r, 'w').write(str(p.pid))\n"
                 "time.sleep(300)\n" % pidfile)
        t0 = time.monotonic()
        try:
            r = br.run([sys.executable, "-c", child], capture_output=True, text=True, timeout=2)
            took = time.monotonic() - t0
        finally:
            if os.path.exists(pidfile):
                try:
                    os.kill(int(open(pidfile).read().strip()), 9)
                except (ProcessLookupError, ValueError):
                    pass
        self.assertEqual(r.returncode, br.TIMED_OUT)
        self.assertLess(took, 30, "a process outside the group held the run open")
        self.assertIn("TIMED OUT", r.stderr)

    def test_bytes_output_carries_the_note_too(self):
        import polaris_bounded_run as br
        r = br.run(["sh", "-c", "sleep 300"], capture_output=True, timeout=1)
        self.assertEqual(r.returncode, br.TIMED_OUT)
        self.assertIn(b"TIMED OUT after 1 s", r.stderr)

    def test_the_exit_line_names_every_run_that_hit_the_bound(self):
        """A drill's verdict counts mutants; this line is what says some were noticed by hanging."""
        import contextlib
        import io
        import polaris_bounded_run as br
        br.run(["sh", "-c", "exit 1"], capture_output=True, timeout=30)
        self.assertEqual(br.TIMEOUTS, [], "a run that ended is not a timeout")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            br._say_timeouts()
        self.assertEqual(buf.getvalue(), "", "nothing timed out, so nothing is said")
        br.run(["sh", "-c", "sleep 300"], capture_output=True, timeout=1)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            br._say_timeouts()
        self.assertIn("1 suite run(s) hit the time bound", buf.getvalue())
        self.assertIn("after 1 s: sh -c sleep 300", buf.getvalue())

    def test_the_environment_sets_the_bound_and_nonsense_does_not(self):
        import polaris_bounded_run as br
        from unittest import mock
        for raw, want in (("45", 45.0), ("0.5", 0.5), ("", br.DEFAULT_S), ("soon", br.DEFAULT_S),
                          ("0", br.DEFAULT_S), ("-3", br.DEFAULT_S)):
            with mock.patch.dict(os.environ, {"POLARIS_DRILL_SUITE_TIMEOUT": raw}):
                self.assertEqual(br.bound(), want, raw)
        with mock.patch.dict(os.environ, {"POLARIS_DRILL_SUITE_TIMEOUT": "1"}):
            r = br.run(["sh", "-c", "sleep 300"], capture_output=True)
            self.assertEqual(r.returncode, br.TIMED_OUT, "run() without timeout= must use bound()")

    def test_every_drill_suite_run_is_bounded(self):
        """Each subprocess call in a mutation drill that runs a suite goes through the helper or
        carries its own timeout=. A new drill written the old way fails here, by name."""
        import ast
        import glob
        suite_words = ("unittest", "pytest", "cargo", "polaris_checks.run", "--probe-route")
        unbounded = []
        drills = sorted(glob.glob(os.path.join(_HERE, "polaris-*-mutation-drill.py")))
        self.assertGreaterEqual(len(drills), 10, "the drill glob found almost nothing")
        seen = 0
        for path in drills:
            tree = ast.parse(open(path).read(), path)
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "subprocess"
                        and node.func.attr in ("run", "Popen", "call", "check_call",
                                               "check_output")):
                    continue
                text = ast.get_source_segment(open(path).read(), node) or ""
                # The interpreter probe (`-c` with __import__) only imports; it is not a suite.
                if "__import__" in text or not any(w in text for w in suite_words):
                    continue
                seen += 1
                if not any(k.arg == "timeout" for k in node.keywords):
                    unbounded.append("%s:%d" % (os.path.basename(path), node.lineno))
        self.assertGreater(seen, 0, "no suite call was recognised; the scan is broken")
        self.assertEqual(unbounded, [], "suite runs with no bound; use polaris_bounded_run.run")


class ReleaseNotesTests(unittest.TestCase):
    """scripts/polaris-release-notes.sh renders a GitHub release page from a CHANGELOG block. A
    release page resolves a relative link against .../releases/tag/vX, so the rc.66 page's links
    404ed (2026-09-28); its item list had lost the group headings; and a block with no intro
    paragraph printed its first heading as the summary."""

    BLOCK = ("# Changelog\n\n## v9.9.9 — 2026-01-02 (a plain subtitle)\n\n{intro}"
             "### Security\n\n- A fix; [its record](docs/x.md#part) and [a site](https://example.org).\n\n"
             "### Fixed\n\n- **Breaking**: a second fix.\n\n## v9.9.8 — 2026-01-01 (older)\n\n- old\n")

    def render(self, intro):
        import shutil
        import subprocess
        import tempfile
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, "scripts"))
            shutil.copy(os.path.join(_HERE, "polaris-release-notes.sh"), os.path.join(d, "scripts"))
            with open(os.path.join(d, "CHANGELOG.md"), "w", encoding="utf-8") as f:
                f.write(self.BLOCK.format(intro=intro))
            out = subprocess.run(["bash", os.path.join(d, "scripts", "polaris-release-notes.sh"), "9.9.9"],
                                 capture_output=True, text=True, timeout=60)
        finally:
            shutil.rmtree(d)
        self.assertEqual(out.returncode, 0, out.stderr)
        return out.stdout

    def test_links_point_at_the_tag_and_the_list_keeps_its_groups_folded(self):
        page = self.render("One sentence about the release.\n\n")
        self.assertIn("One sentence about the release.", page)
        self.assertIn("](https://github.com/EgorKhaklin/polaris-id/blob/v9.9.9/docs/x.md#part)", page)
        self.assertIn("](https://example.org)", page)
        self.assertNotIn("](docs/", page)
        details = page.split("### Details")[1]
        self.assertIn("<details>", details)
        self.assertIn("**Security**", details)
        self.assertIn("**Fixed**", details)
        self.assertIn("- **Breaking**: a second fix.", page.split("### Upgrade")[0])

    def test_a_block_with_no_intro_has_no_summary(self):
        head = self.render("").split("### Breaking changes")[0]
        self.assertNotIn("Security", head)
