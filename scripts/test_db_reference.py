# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""An upgraded database is compared with a fresh install of the same release, built beside it.

scripts/lib/polaris-db-reference.sh builds that reference in the database server's own container
with the image's own init, after checking the image's SQL and init are this tree's, and compares two
security states exactly or table by table, so the months two databases happen to hold do not matter
and a partition unlike its siblings still shows. These
tests source it under bash with a stand-in `pg_run` that records each command and fails the step
it is told to. They need no database and no Docker.

    python3 -m unittest test_db_reference      (from scripts/)
"""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIB = ROOT / "scripts" / "lib" / "polaris-db-reference.sh"

# One record line per call; STUB_FAIL names a step (a word its argv holds) whose call fails.
# STUB_IMAGE plays the image: a directory with sql/ and 00-init.sh; a `sh -c` call really runs,
# with the image's paths, in its script and its arguments, rewritten to the test's.
STUB = r"""
pg_run() {
    printf '%s\n' "$*" >> "$STUB_DIR/calls"
    if [ -n "${STUB_FAIL:-}" ]; then
        case "$*" in *"$STUB_FAIL"*) echo "stub: $STUB_FAIL failed" >&2; return 3 ;; esac
    fi
    if [ "$1" = sh ] && [ "$2" = -c ] && [ -n "${STUB_IMAGE:-}" ]; then
        local script
        script=$(printf '%s' "$3" | sed -e "s#/docker-entrypoint-initdb.d/sql#${STUB_IMAGE}/sql#g" \
                                        -e "s#/docker-entrypoint-initdb.d/00-init.sh#${STUB_IMAGE}/00-init.sh#g")
        shift 3
        sh -c "${script}" $(printf '%s\n' "$@" | sed "s#/docker-entrypoint-initdb.d/00-init.sh#${STUB_IMAGE}/00-init.sh#g")
        return
    fi
    echo "stub output of: $1"
}
"""

# A state as polaris_db_state prints it: two months of verificationevent, the default partition,
# a column of one month, and facts about relations that are not partitions.
STATE = [
    "owner public.verificationevent p postgres",
    "owner public.verificationevent_2026_10 r postgres",
    "owner public.verificationevent_2026_11 r postgres",
    "owner public.verificationevent_default r postgres",
    "partition public.verificationevent_2026_10 of public.verificationevent bound=FOR VALUES FROM ('2026-10-01 00:00:00+00') TO ('2026-11-01 00:00:00+00')",
    "partition public.verificationevent_2026_11 of public.verificationevent bound=FOR VALUES FROM ('2026-11-01 00:00:00+00') TO ('2026-12-01 00:00:00+00')",
    "partition public.verificationevent_default of public.verificationevent bound=DEFAULT",
    "role polaris_app super=false",
    "table public.enrollmentcode polaris_app SELECT",
    "table public.verificationevent polaris_app SELECT",
    "trigger public.verificationevent_2026_10 trg_verification_append_only enabled=O def=aa",
    "trigger public.verificationevent_2026_11 trg_verification_append_only enabled=O def=aa",
    "trigger public.verificationevent_default trg_verification_append_only enabled=O def=aa",
]


class _Base(unittest.TestCase):

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-db-reference-"))
        self.log = self.tmp / "reference.log"

    def bash(self, body, **env):
        full = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(self.tmp), "STUB_DIR": str(self.tmp)}
        full.update(env)
        script = "set -euo pipefail\nsource %s\n%s\n%s\n" % (LIB, STUB, body)
        return subprocess.run(["bash", "-c", script], env=full, capture_output=True, text=True, timeout=60)

    def calls(self):
        p = self.tmp / "calls"
        return p.read_text().splitlines() if p.exists() else []

    def state_file(self, name, lines):
        p = self.tmp / name
        p.write_text("".join(line + "\n" for line in lines))
        return p


class BuildTests(_Base):

    def test_the_reference_is_this_release_loaded_migrated_and_synced_in_order(self):
        r = self.bash('polaris_db_reference_build polaris_reference "%s"' % self.log)
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 5, calls)
        drop, create, init, up, sync = calls
        self.assertIn("-d postgres -c DROP DATABASE IF EXISTS polaris_reference WITH (FORCE)", drop)
        self.assertIn("-d postgres -c CREATE DATABASE polaris_reference", create)
        self.assertTrue(init.endswith("bash /docker-entrypoint-initdb.d/00-init.sh"), init)
        for call, mode in ((up, "--up"), (sync, "--sync-objects")):
            self.assertIn("POLARIS_DB_NAME=polaris_reference", call)
            self.assertIn("POLARIS_DB_HOST=/var/run/postgresql", call)
            self.assertTrue(call.endswith("/opt/polaris/scripts/polaris-migrate.sh " + mode), call)
        # Every step's output went to the log, none to the caller's stdout.
        self.assertEqual(r.stdout, "")
        self.assertEqual(self.log.read_text().count("stub output of:"), 5)

    def test_the_init_runs_on_the_reference_with_only_the_containers_polaris_env(self):
        # The image's init, played by a script that writes down the environment it was given.
        image = self.tmp / "image"
        (image / "sql").mkdir(parents=True)
        seen = self.tmp / "init-env"
        (image / "00-init.sh").write_text("env > %s\n" % seen)
        r = self.bash('polaris_db_reference_build polaris_reference "%s"' % self.log, STUB_IMAGE=str(image),
                      POLARIS_ENV="production", POLARIS_APP_PASSWORD_FILE="/run/secrets/polaris_db_password",
                      POLARIS_APP_PASSWORD="a-live-secret-0123456789", PGPASSWORD="superuser",
                      POLARIS_REPLICATOR_PASSWORD_FILE="/run/secrets/polaris_replicator_password",
                      POSTGRES_DB="polaris")
        self.assertEqual(r.returncode, 0, r.stderr)
        env = dict(line.split("=", 1) for line in seen.read_text().splitlines() if "=" in line)
        self.assertEqual(env.get("POSTGRES_DB"), "polaris_reference")
        self.assertEqual(env.get("POLARIS_INIT_MANAGED_BY"), "patroni")
        self.assertEqual(env.get("POLARIS_ENV"), "production")
        self.assertEqual(env.get("POSTGRES_USER"), "postgres")
        for name in ("POLARIS_APP_PASSWORD_FILE", "POLARIS_APP_PASSWORD", "PGPASSWORD",
                     "POLARIS_REPLICATOR_PASSWORD_FILE", "STUB_DIR"):
            self.assertNotIn(name, env, "the init was handed the container's %s" % name)
        # A container with no POLARIS_ENV gives the init none: a sample install, as its own boot would be.
        seen.unlink()
        r = self.bash('polaris_db_reference_build polaris_reference "%s"' % self.log, STUB_IMAGE=str(image))
        self.assertEqual(r.returncode, 0, r.stderr)
        env = dict(line.split("=", 1) for line in seen.read_text().splitlines() if "=" in line)
        self.assertEqual(env.get("POLARIS_ENV"), "")

    def test_a_name_that_is_not_a_reference_is_refused_before_anything_runs(self):
        for name in ("polaris", "postgres", "polaris_test", "polaris_reference;drop", "polaris_referencex",
                     "Polaris_reference", ""):
            for fn in ('polaris_db_reference_build "%s" "%s"' % (name, self.log),
                       'polaris_db_reference_drop "%s"' % name):
                with self.subTest(name=name, fn=fn.split()[0]):
                    r = self.bash(fn)
                    self.assertEqual(r.returncode, 2, r.stderr)
                    self.assertEqual(self.calls(), [], "a refused name reached pg_run")
        r = self.bash('polaris_db_reference_build polaris_reference_upgrade_1 "%s"' % self.log)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_build_without_a_log_is_misuse(self):
        r = self.bash("polaris_db_reference_build polaris_reference")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(self.calls(), [])

    def test_each_failed_step_fails_the_build_names_itself_and_stops_it(self):
        steps = [("DROP DATABASE", "could not drop", 1), ("CREATE DATABASE", "could not create", 2),
                 ("00-init.sh", "init did not complete", 3), ("--up", "--up failed", 4),
                 ("--sync-objects", "--sync-objects failed", 5)]
        for word, message, ran in steps:
            with self.subTest(step=word):
                (self.tmp / "calls").unlink(missing_ok=True)
                r = self.bash('polaris_db_reference_build polaris_reference "%s"' % self.log, STUB_FAIL=word)
                self.assertEqual(r.returncode, 1, r.stderr)
                self.assertIn(message, r.stderr)
                self.assertEqual(len(self.calls()), ran, "a step ran after %s failed" % word)


class ByParentTests(_Base):

    def by_parent(self, lines):
        r = self.bash('polaris_db_state_by_parent "%s"' % self.state_file("s", lines))
        return r, r.stdout.splitlines()

    def test_every_partition_is_written_as_its_table_and_duplicates_collapse(self):
        r, out = self.by_parent(STATE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(out, sorted(set(out)), "not sorted and unique")
        self.assertIn("owner @public.verificationevent r postgres", out)
        self.assertIn("partition @public.verificationevent of public.verificationevent", out)
        self.assertIn("trigger @public.verificationevent trg_verification_append_only enabled=O def=aa", out)
        self.assertEqual(len([x for x in out if x.startswith("trigger ")]), 1)
        # No month and no bound is left, and what is not a partition is untouched.
        self.assertFalse([x for x in out if "2026_1" in x or "bound=" in x or "_default" in x], out)
        for line in ("owner public.verificationevent p postgres", "role polaris_app super=false",
                     "table public.enrollmentcode polaris_app SELECT"):
            self.assertIn(line, out)

    def test_a_partition_unlike_its_siblings_still_shows(self):
        r, out = self.by_parent(STATE + ["table public.verificationevent_2026_11 polaris_app SELECT",
                                         "column public.verificationevent_2026_11.event_id polaris_app SELECT"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("table @public.verificationevent polaris_app SELECT", out)
        self.assertIn("column @public.verificationevent.event_id polaris_app SELECT", out)

    def test_a_state_with_no_partition_or_no_line_fails(self):
        r, _ = self.by_parent([x for x in STATE if not x.startswith("partition ")])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no partition fact", r.stderr)
        r = self.bash('polaris_db_state_by_parent "%s"' % self.state_file("empty", []))
        self.assertEqual(r.returncode, 2)


class SameByTableTests(_Base):

    def compare(self, a, b):
        return self.bash('polaris_db_state_same_by_table "%s" "%s"' % (self.state_file("a", a), self.state_file("b", b)))

    def test_states_that_differ_only_in_which_months_exist_agree(self):
        # The fresh install made December too; the upgraded database has only the default and October.
        fresh = STATE + [
            "owner public.verificationevent_2026_12 r postgres",
            "partition public.verificationevent_2026_12 of public.verificationevent bound=FOR VALUES FROM ('2026-12-01 00:00:00+00') TO ('2027-01-01 00:00:00+00')",
            "trigger public.verificationevent_2026_12 trg_verification_append_only enabled=O def=aa"]
        upgraded = [x for x in STATE if "2026_11" not in x]
        r = self.compare(fresh, upgraded)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_privilege_only_the_upgrade_holds_fails_and_is_named(self):
        r = self.compare(STATE, STATE + ["table public.enrollmentcode polaris_app DELETE"])
        self.assertEqual(r.returncode, 1)
        self.assertIn("> table public.enrollmentcode polaris_app DELETE", r.stderr)
        self.assertIn("1 fact(s) differ", r.stderr)

    def test_a_month_the_upgrade_left_unlocked_fails(self):
        r = self.compare(STATE, STATE + ["table public.verificationevent_2026_11 polaris_app DELETE"])
        self.assertEqual(r.returncode, 1)
        self.assertIn("> table @public.verificationevent polaris_app DELETE", r.stderr)

    def test_what_the_upgrade_lost_fails_too(self):
        r = self.compare(STATE, [x for x in STATE if x != "table public.verificationevent polaris_app SELECT"])
        self.assertEqual(r.returncode, 1)
        self.assertIn("< table public.verificationevent polaris_app SELECT", r.stderr)

    def test_an_unreadable_state_is_not_a_match(self):
        unreadable = [x for x in STATE if not x.startswith("partition ")]
        for a, b in ((STATE, unreadable), (unreadable, STATE)):
            with self.subTest(first_readable=a is STATE):
                r = self.compare(a, b)
                self.assertEqual(r.returncode, 2, r.stderr)
        r = self.bash('polaris_db_state_same_by_table "%s"' % self.state_file("a", STATE))
        self.assertEqual(r.returncode, 2)



class CarriesTests(_Base):
    """The reference is built from the image's SQL, so that SQL must be this tree's."""

    def setUp(self):
        super().setUp()
        # A tree (polaris_sql, polaris_web/docker-init.sh) and the image it built (sql/, 00-init.sh).
        self.tree = self.tmp / "tree" / "polaris_sql"
        self.image = self.tmp / "image"
        self.sql = self.image / "sql"
        for d in (self.tree, self.sql):
            (d / "migrations").mkdir(parents=True)
            (d / "00_load_all.sql").write_text("\\i 01_schema.sql\n")
            (d / "01_schema.sql").write_text("CREATE TABLE t (x int);\n")
            (d / "migrations" / "2026-10-10-001-x.up.sql").write_text("SELECT 1;\n")
        self.tree_init = self.tmp / "tree" / "polaris_web" / "docker-init.sh"
        self.tree_init.parent.mkdir()
        for init in (self.tree_init, self.image / "00-init.sh"):
            init.write_text("#!/bin/bash\necho init\n")

    def carries(self, **env):
        return self.bash('polaris_db_reference_carries "%s"' % self.tree, STUB_IMAGE=str(self.image), **env)

    def test_the_same_files_pass_and_what_is_not_sql_does_not_count(self):
        (self.tree / "README.md").write_text("the tree's notes, which the image need not carry\n")
        r = self.carries()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls()[0].split()[:2], ["sh", "-c"])

    def test_any_other_sql_fails(self):
        cases = {
            "a changed byte": lambda: (self.sql / "01_schema.sql").write_text("CREATE TABLE t (x bigint);\n"),
            "a file the tree lacks": lambda: (self.sql / "migrations" / "2026-10-10-002-y.up.sql").write_text("SELECT 2;\n"),
            "a file the image lacks": lambda: (self.sql / "migrations" / "2026-10-10-001-x.up.sql").unlink(),
            "a file moved": lambda: (self.sql / "01_schema.sql").rename(self.sql / "migrations" / "01_schema.sql"),
            "another init": lambda: (self.image / "00-init.sh").write_text("#!/bin/bash\necho other\n"),
        }
        for name, change in cases.items():
            with self.subTest(case=name):
                self.setUp()
                change()
                r = self.carries()
                self.assertEqual(r.returncode, 1, r.stderr)
                self.assertIn("not this tree's", r.stderr)

    def test_no_sql_on_either_side_fails_rather_than_matching_nothing(self):
        for side in ("image", "tree"):
            with self.subTest(empty=side):
                self.setUp()
                for f in sorted((self.tmp / side).rglob("*.sql")):
                    f.unlink()
                r = self.carries()
                self.assertEqual(r.returncode, 1, r.stderr)
                self.assertNotIn("not this tree's", r.stderr)

    def test_no_init_on_either_side_fails_rather_than_matching_nothing(self):
        for name in ("image", "tree"):
            with self.subTest(missing=name):
                self.setUp()
                (self.image / "00-init.sh" if name == "image" else self.tree_init).unlink()
                r = self.carries()
                self.assertEqual(r.returncode, 1, r.stderr)
                self.assertIn("could not be read", r.stderr)

    def test_hashes_of_no_file_fail_rather_than_matching(self):
        # An xargs that runs nothing: both sides would hash the same empty list and match.
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        (bin_dir / "xargs").write_text("#!/bin/sh\nexit 0\n")
        (bin_dir / "xargs").chmod(0o755)
        r = self.carries(PATH="%s:/usr/bin:/bin:/usr/sbin:/sbin" % bin_dir)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("could not be read", r.stderr)

    def test_an_image_that_cannot_be_read_fails(self):
        r = self.carries(STUB_FAIL="sh -c")
        self.assertEqual(r.returncode, 1)
        self.assertIn("could not be read", r.stderr)
        r = self.bash('polaris_db_reference_carries "%s"' % (self.tmp / "nowhere"))
        self.assertEqual(r.returncode, 2)


class SameTests(_Base):

    def test_exactly_the_same_or_the_lines_that_differ(self):
        a = self.state_file("a", STATE)
        r = self.bash('polaris_db_state_same "%s" "%s"' % (a, self.state_file("b", STATE)))
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.bash('polaris_db_state_same "%s" "%s"' % (a, self.state_file("c", STATE + ["role x super=false"])))
        self.assertEqual(r.returncode, 1)
        self.assertIn("> role x super=false", r.stderr)
        # Months are not forgiven here: this compare is for one database read twice.
        r = self.bash('polaris_db_state_same "%s" "%s"' % (a, self.state_file("d", [x for x in STATE if "2026_11" not in x])))
        self.assertEqual(r.returncode, 1)

    def test_an_empty_state_is_not_a_match(self):
        empty = self.state_file("e", [])
        r = self.bash('polaris_db_state_same "%s" "%s"' % (empty, empty))
        self.assertEqual(r.returncode, 2)



# A stand-in for polaris_db_state: each call prints the next canned state ($STUB_DIR/state-1, -2, ...)
# and records itself; a state file named fail-N makes the Nth read fail.
STATE_STUB = r"""
polaris_db_state() {
    local n
    n=$(( $(cat "$STUB_DIR/reads" 2>/dev/null || echo 0) + 1 ))
    echo "$n" > "$STUB_DIR/reads"
    echo "read $n" >> "$STUB_DIR/log"
    [ -e "$STUB_DIR/fail-$n" ] && { echo "stub: read $n fails" >&2; return 1; }
    cat "$STUB_DIR/state-$n"
}
cmd() { echo "cmd $*" >> "$STUB_DIR/log"; return "${STUB_CMD_RC:-0}"; }
"""


class UnchangedByTests(_Base):
    """A procedure that changes data only: the state before and after must be exactly the same."""

    def run_it(self, before, after, **env):
        self.state_file("state-1", before)
        self.state_file("state-2", after)
        (self.tmp / "out").mkdir(exist_ok=True)
        return self.bash(STATE_STUB + 'polaris_db_state_unchanged_by "%s" cmd rotate polaris_db_password'
                         % (self.tmp / "out"), **env)

    def events(self):
        return (self.tmp / "log").read_text().splitlines()

    def test_the_same_state_around_a_command_that_succeeds(self):
        r = self.run_it(STATE, STATE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.events(), ["read 1", "cmd rotate polaris_db_password", "read 2"])
        self.assertEqual((self.tmp / "out" / "state-before").read_text(), (self.tmp / "out" / "state-after").read_text())

    def test_a_changed_state_fails_and_names_the_change(self):
        r = self.run_it(STATE, [x if x != "role polaris_app super=false" else "role polaris_app super=true" for x in STATE])
        self.assertEqual(r.returncode, 1)
        self.assertIn("> role polaris_app super=true", r.stderr)
        self.assertIn("< role polaris_app super=false", r.stderr)
        self.assertIn("changed across: cmd rotate polaris_db_password", r.stderr)

    def test_a_failed_command_is_its_own_status_unless_the_state_changed_too(self):
        r = self.run_it(STATE, STATE, STUB_CMD_RC="7")
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn("the command failed (status 7)", r.stderr)
        r = self.run_it(STATE, STATE + ["role x super=false"], STUB_CMD_RC="7")
        self.assertEqual(r.returncode, 1)

    def test_a_state_that_cannot_be_read_fails_and_before_it_nothing_runs(self):
        (self.tmp / "fail-1").write_text("")
        r = self.run_it(STATE, STATE)
        self.assertEqual(r.returncode, 1)
        self.assertIn("could not be read before", r.stderr)
        self.assertEqual(self.events(), ["read 1"], "the command ran although the state before it was not read")
        for f in ("fail-1", "reads", "log"):
            (self.tmp / f).unlink()
        (self.tmp / "fail-2").write_text("")
        r = self.run_it(STATE, STATE)
        self.assertEqual(r.returncode, 1)
        self.assertIn("could not be read after", r.stderr)

    def test_misuse(self):
        for body in ('polaris_db_state_unchanged_by "%s"' % self.tmp, 'polaris_db_state_unchanged_by /nowhere cmd'):
            with self.subTest(body=body):
                self.assertEqual(self.bash(STATE_STUB + body).returncode, 2)


class SettingAbsentTests(_Base):
    """A transaction's setting (the purge's carve-out) is never one of the database or of a role."""

    SETTINGS = ["dbsetting this - polaris.default_window_days=30", "dbsetting all polaris_app search_path=public"]

    def absent(self, lines, name="polaris.purge_in_progress"):
        return self.bash('polaris_db_state_setting_absent "%s" "%s"' % (self.state_file("s", lines), name))

    def test_absent(self):
        r = self.absent(STATE + self.SETTINGS)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_set_for_the_database_or_a_role_in_any_case_fails_and_is_named(self):
        for line in ("dbsetting this - polaris.purge_in_progress=TRUE",
                     "dbsetting all polaris_app polaris.purge_in_progress=on",
                     "dbsetting this polaris_app Polaris.Purge_In_Progress=TRUE"):
            with self.subTest(line=line):
                r = self.absent(STATE + self.SETTINGS + [line])
                self.assertEqual(r.returncode, 1)
                self.assertIn(line, r.stderr)
        # And the name asked for, in any case.
        r = self.absent(STATE + self.SETTINGS + ["dbsetting this - polaris.purge_in_progress=TRUE"],
                        name="POLARIS.Purge_In_Progress")
        self.assertEqual(r.returncode, 1, r.stderr)

    def test_only_that_setting_and_only_a_setting_counts(self):
        r = self.absent(STATE + self.SETTINGS + ["dbsetting this - polaris.purge_in_progress_note=x",
                                                 "routine public.f() def=aa definer=true owner=postgres "
                                                 "config=polaris.purge_in_progress=TRUE"])
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_state_with_no_setting_read_is_not_absence(self):
        r = self.absent(STATE)
        self.assertEqual(r.returncode, 2)
        self.assertIn("no dbsetting fact", r.stderr)
        self.assertEqual(self.absent(STATE + self.SETTINGS, name="").returncode, 2)


if __name__ == "__main__":
    unittest.main()
