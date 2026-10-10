# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""An upgraded database is compared with a fresh install of the same release, built beside it.

scripts/lib/polaris-db-reference.sh builds that reference in the database server's own container
from the files its image carries, after checking those files are this tree's, and compares two
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
STUB = r"""
pg_run() {
    printf '%s\n' "$*" >> "$STUB_DIR/calls"
    if [ -n "${STUB_FAIL:-}" ]; then
        case "$*" in *"$STUB_FAIL"*) echo "stub: $STUB_FAIL failed" >&2; return 3 ;; esac
    fi
    # The image's SQL directory, played by a directory of the test's: the digest script really runs.
    if [ "$1" = sh ] && [ "$2" = -c ] && [ -n "${STUB_IMAGE_SQL:-}" ]; then
        sh -c "$(printf '%s' "$3" | sed "s#/docker-entrypoint-initdb.d/sql#${STUB_IMAGE_SQL}#g")"
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
        drop, create, load, up, sync = calls
        self.assertIn("-d postgres -c DROP DATABASE IF EXISTS polaris_reference WITH (FORCE)", drop)
        self.assertIn("-d postgres -c CREATE DATABASE polaris_reference", create)
        # The load runs from the image's own SQL directory (its \i paths are relative), into NAME.
        self.assertIn("cd /docker-entrypoint-initdb.d/sql && psql", load)
        self.assertIn("-d polaris_reference -f 00_load_all.sql", load)
        for call, mode in ((up, "--up"), (sync, "--sync-objects")):
            self.assertIn("POLARIS_DB_NAME=polaris_reference", call)
            self.assertIn("POLARIS_DB_HOST=/var/run/postgresql", call)
            self.assertTrue(call.endswith("/opt/polaris/scripts/polaris-migrate.sh " + mode), call)
        # Every step's output went to the log, none to the caller's stdout.
        self.assertEqual(r.stdout, "")
        self.assertEqual(self.log.read_text().count("stub output of:"), 5)

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
                 ("00_load_all.sql", "00_load_all.sql did not load", 3), ("--up", "--up failed", 4),
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
        self.tree = self.tmp / "tree"
        self.image = self.tmp / "image"
        for d in (self.tree, self.image):
            (d / "migrations").mkdir(parents=True)
            (d / "00_load_all.sql").write_text("\\i 01_schema.sql\n")
            (d / "01_schema.sql").write_text("CREATE TABLE t (x int);\n")
            (d / "migrations" / "2026-10-10-001-x.up.sql").write_text("SELECT 1;\n")

    def carries(self, **env):
        return self.bash('polaris_db_reference_carries "%s"' % self.tree, STUB_IMAGE_SQL=str(self.image), **env)

    def test_the_same_files_pass_and_what_is_not_sql_does_not_count(self):
        (self.tree / "README.md").write_text("the tree's notes, which the image need not carry\n")
        r = self.carries()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls()[0].split()[:2], ["sh", "-c"])

    def test_any_other_sql_fails(self):
        cases = {
            "a changed byte": lambda: (self.image / "01_schema.sql").write_text("CREATE TABLE t (x bigint);\n"),
            "a file the tree lacks": lambda: (self.image / "migrations" / "2026-10-10-002-y.up.sql").write_text("SELECT 2;\n"),
            "a file the image lacks": lambda: (self.image / "migrations" / "2026-10-10-001-x.up.sql").unlink(),
            "a file moved": lambda: (self.image / "01_schema.sql").rename(self.image / "migrations" / "01_schema.sql"),
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

    def test_hashes_of_no_file_fail_rather_than_matching(self):
        # An xargs that runs nothing: both sides would hash the same empty list and match.
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        (bin_dir / "xargs").write_text("#!/bin/sh\nexit 0\n")
        (bin_dir / "xargs").chmod(0o755)
        r = self.carries(PATH="%s:/usr/bin:/bin:/usr/sbin:/sbin" % bin_dir)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("no SQL file could be read", r.stderr)

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


if __name__ == "__main__":
    unittest.main()
