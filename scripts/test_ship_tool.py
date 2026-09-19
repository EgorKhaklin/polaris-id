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
