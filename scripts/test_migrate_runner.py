# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The migration runner refuses a database whose registry it cannot read.

Until 2026-10-07 polaris-migrate.sh answered "not applied" when its query of schema_version failed,
so an unreachable database, a wrong password or an unreadable registry put every migration on disk
in the pending list and --up set out to apply them all (the Helm upgrade drill met it as
"Pending: 110" against 93 recorded). These tests point the runner at a port nothing listens on and
require it to stop with EXIT_DB, planning nothing. They need no database.

    python3 -m unittest test_migrate_runner      (from scripts/)
"""
import os
import pathlib
import socket
import subprocess
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


if __name__ == "__main__":
    unittest.main()
