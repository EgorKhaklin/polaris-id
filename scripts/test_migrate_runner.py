# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The migration runner refuses a database whose registry it cannot read, and raises a production
database's anonymity floor from the notional sample's one.

Until 2026-10-07 polaris-migrate.sh answered "not applied" when its query of schema_version failed,
so an unreachable database, a wrong password or an unreadable registry put every migration on disk
in the pending list and --up set out to apply them all (the Helm upgrade drill met it as
"Pending: 110" against 93 recorded). These tests point the runner at a port nothing listens on and
require it to stop with EXIT_DB, planning nothing. They need no database.

A production database initialised before 2026-10-08 kept the sample's polaris.min_epoch_anonymity_set
of 1 through every upgrade, so uc11_close_epoch could close epochs smaller than 20; --sync-objects raises
exactly that 1 under POLARIS_ENV=production. Those tests run the runner with a stand-in psql.

    python3 -m unittest test_migrate_runner      (from scripts/)
"""
import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "polaris-migrate.sh"
EXIT_DB = 5


def closed_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]          # released on close: nothing listens there now


class RunnerRefusesAnUnreadableRegistry(unittest.TestCase):

    def run_runner(self, *args):
        env = dict(os.environ, POLARIS_DB_HOST="127.0.0.1", PGPORT=str(closed_port()),
                   POLARIS_DB_USER="postgres", PGCONNECT_TIMEOUT="3", PGPASSWORD="unused")
        return subprocess.run(["bash", str(RUNNER), *args], env=env, capture_output=True, text=True,
                              timeout=60)

    def test_up_stops_without_planning(self):
        r = self.run_runner("--up")
        self.assertEqual(r.returncode, EXIT_DB, r.stdout + r.stderr)
        self.assertNotIn("Pending:", r.stdout, "an unreadable registry must not read as nothing applied")
        self.assertIn("cannot read schema_version", r.stderr)

    def test_dry_run_stops_without_planning(self):
        r = self.run_runner("--dry-run", "--up")
        self.assertEqual(r.returncode, EXIT_DB, r.stdout + r.stderr)
        self.assertNotIn("Pending:", r.stdout)

    def test_down_stops_without_planning(self):
        r = self.run_runner("--down", "1")
        self.assertEqual(r.returncode, EXIT_DB, r.stdout + r.stderr)


# A stand-in psql: an object file (-f) applies; the floor is read from $STUB/floor; the raise sets a
# floor that reads 1 to 20, as its SQL does, unless STUB_STUCK is set; STUB_READ=fail fails the reads.
FLOOR_PSQL = r"""#!/bin/sh
sql=""; file=""
while [ $# -gt 0 ]; do
    case "$1" in
        -c) sql="$2"; shift ;;
        -f) file="$2"; shift ;;
    esac
    shift
done
if [ -n "$file" ]; then echo "file $(basename "$file")" >> "$STUB/psql.log"; exit 0; fi
echo "sql $(printf '%s' "$sql" | tr '\n' ' ')" >> "$STUB/psql.log"
case "$sql" in
    *"ALTER DATABASE"*)
        if [ -z "${STUB_STUCK:-}" ] && [ "$(cat "$STUB/floor")" = 1 ]; then echo 20 > "$STUB/floor"; fi
        exit 0 ;;
    *min_epoch_anonymity_set*)
        if [ "${STUB_READ:-}" = fail ]; then echo 'psql: error: connection to server failed' >&2; exit 2; fi
        cat "$STUB/floor"; exit 0 ;;
esac
exit 0
"""


class AProductionDatabaseLosesTheSamplesFloor(unittest.TestCase):
    """--sync-objects, run by every upgrade path, raises exactly the notional sample's floor of one to
    twenty on a production database and reads it back; a floor the authority set stays, and a
    database that is not production is never touched (measured on 2026-10-10: an upgraded rc.70
    production database read 1, a fresh install 20)."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-floor-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / "psql").write_text(FLOOR_PSQL)
        (self.tmp / "psql").chmod(0o755)

    def sync(self, floor, *args, **env):
        (self.tmp / "floor").write_text(floor + "\n")
        full = {"PATH": "%s:/usr/bin:/bin" % self.tmp, "HOME": str(self.tmp), "STUB": str(self.tmp),
                "POLARIS_ENV_FILE": ""}
        full.update(env)
        r = subprocess.run(["bash", str(RUNNER), *(args or ("--sync-objects",))], env=full,
                           capture_output=True, text=True, timeout=60)
        log = (self.tmp / "psql.log").read_text() if (self.tmp / "psql.log").exists() else ""
        return r, (self.tmp / "floor").read_text().strip(), log

    def test_production_raises_the_samples_floor_of_one_to_twenty(self):
        r, floor, log = self.sync("1", POLARIS_ENV="production")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(floor, "20")
        self.assertIn("the notional sample's 1 raised to 20", r.stdout)
        self.assertLess(log.index("file 09_grants.sql"), log.index("ALTER DATABASE"),
                        "the floor must be raised after 09_grants.sql has run")

    def test_production_keeps_a_floor_the_authority_set(self):
        r, floor, log = self.sync("12", POLARIS_ENV="production")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(floor, "12")
        self.assertIn("anonymity floor 12, below the default of 20: kept, as the authority set it", r.stderr)
        self.assertNotIn("ALTER DATABASE", log)

    def test_production_leaves_twenty_or_more_alone(self):
        for value in ("20", "50"):
            with self.subTest(value=value):
                (self.tmp / "psql.log").unlink(missing_ok=True)
                r, floor, log = self.sync(value, POLARIS_ENV="production")
                self.assertEqual((r.returncode, floor), (0, value), r.stdout + r.stderr)
                self.assertNotIn("ALTER DATABASE", log)
                self.assertNotIn("below the default", r.stderr)

    def test_a_database_that_is_not_production_is_never_touched(self):
        for env in ({}, {"POLARIS_ENV": "development"}, {"POLARIS_ENV": ""}, {"POLARIS_ENV": "Production"}):
            with self.subTest(env=env):
                (self.tmp / "psql.log").unlink(missing_ok=True)
                r, floor, log = self.sync("1", **env)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertEqual(floor, "1")
                self.assertNotIn("min_epoch_anonymity_set", log, "a sample database's floor was read or set")
                self.assertIn("file 09_grants.sql", log, "the objects were not synced at all")

    def test_a_floor_that_still_reads_below_twenty_is_refused(self):
        r, floor, _ = self.sync("1", POLARIS_ENV="production", STUB_STUCK="1")
        self.assertEqual(r.returncode, EXIT_DB, r.stdout + r.stderr)
        self.assertIn("the anonymity floor reads '1' after it was raised to 20", r.stderr)
        self.assertNotIn("raised to", r.stdout)

    def test_a_floor_that_cannot_be_read_is_refused(self):
        r, _, _ = self.sync("1", POLARIS_ENV="production", STUB_READ="fail")
        self.assertEqual(r.returncode, EXIT_DB, r.stdout + r.stderr)
        self.assertIn("cannot read this production database's anonymity floor", r.stderr)

    def test_a_dry_run_reads_and_changes_nothing(self):
        r, floor, log = self.sync("1", "--dry-run", "--sync-objects", POLARIS_ENV="production")
        self.assertEqual((r.returncode, floor), (0, "1"), r.stdout + r.stderr)
        self.assertIn("would raise a production anonymity floor of 1 to 20", r.stdout)
        self.assertEqual(log, "")

    def test_the_raise_is_the_statement_production_init_runs(self):
        stmt = "EXECUTE format('ALTER DATABASE %I SET polaris.min_epoch_anonymity_set = 20', current_database());"
        init = (ROOT / "polaris_web" / "docker-init.sh").read_text()
        self.assertIn(stmt, init, "docker-init.sh's production statement changed; keep the two the same")
        self.assertEqual(RUNNER.read_text().count(stmt), 1)


if __name__ == "__main__":
    unittest.main()
