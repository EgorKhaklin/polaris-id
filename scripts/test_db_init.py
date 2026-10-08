# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""A PostgreSQL Polaris does not ship is initialised by one script, or refused before a write.

On a managed service the database's owner is not a superuser, and PostgreSQL 15 and later let such
a role write the three polaris.* settings the schema keeps on the database only by a superuser's
grant: the schema stopped half-loaded with "permission denied to set parameter" (lab record 017).
`polaris-db-init.sh` checks every precondition first and then runs docker-init.sh in its external
mode. These tests run the real script from a copy of the tree in which `psql` is a stand-in that
answers the precondition queries and `polaris_web/docker-init.sh` records what it was given. No
database; CI's managed-postgres job runs the script against a real one.

    python3 -m unittest test_db_init      (from scripts/)
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "polaris-db-init.sh"
GRANT = ("GRANT SET ON PARAMETER polaris.min_epoch_anonymity_set, polaris.default_max_revoke_percent, "
         "polaris.default_window_days TO \"polaris_owner\";")

# psql: the version query answers STUB_VERSION; the facts query answers STUB_FACTS, in the
# script's column order: super|owns|createrole|app_exists|app_admin|tables|can_set.
PSQL = r'''#!%(python)s
import os, sys
sql = " ".join(sys.argv[1:])
if "server_version_num" in sql:
    if os.environ.get("STUB_DOWN"):
        sys.stderr.write("psql: error: connection refused\n"); sys.exit(2)
    print(os.environ.get("STUB_VERSION", "160014")); sys.exit(0)
if "rolsuper" in sql:
    print(os.environ.get("STUB_FACTS", "f|t|t|f|f|0|t")); sys.exit(0)
sys.stderr.write("stand-in psql: unexpected query\n"); sys.exit(99)
'''
# docker-init.sh: records its environment; STUB_INIT_FAIL makes it fail as a load would.
INIT = r'''#!/bin/bash
python3 -c 'import json, os, sys; json.dump(dict(os.environ), open(sys.argv[1], "w"))' "$STUB_INIT_LOG"
[ -z "$STUB_INIT_FAIL" ] || { echo "psql: ERROR: something" >&2; exit 3; }
echo "Polaris init complete."
'''


class DbInitTests(unittest.TestCase):

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-db-init-"))
        (self.tmp / "scripts").mkdir()
        (self.tmp / "polaris_web").mkdir()
        (self.tmp / "polaris_sql").mkdir()
        shutil.copy2(SCRIPT, self.tmp / "scripts" / SCRIPT.name)
        (self.tmp / "polaris_web" / "docker-init.sh").write_text(INIT)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        (self.bin / "psql").write_text(PSQL % {"python": sys.executable})
        (self.bin / "psql").chmod(0o755)
        self.app_pw = self.tmp / "app.pw"
        self.app_pw.write_text("a3f1" * 12)
        self.owner_pw = self.tmp / "owner.pw"
        self.owner_pw.write_text("owner-secret")
        self.log = self.tmp / "init.json"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_script(self, *args, drop=(), **env):
        full = {"PATH": "%s:%s:/usr/bin:/bin" % (self.bin, os.path.dirname(sys.executable)),
                "HOME": str(self.tmp), "STUB_INIT_LOG": str(self.log),
                "POLARIS_DB_HOST": "db.example.net", "POLARIS_DB_OWNER": "polaris_owner",
                "POLARIS_DB_OWNER_PASSWORD_FILE": str(self.owner_pw),
                "POLARIS_APP_PASSWORD_FILE": str(self.app_pw)}
        full.update(env)
        for name in drop:
            full.pop(name, None)
        return subprocess.run(["bash", str(self.tmp / "scripts" / SCRIPT.name), *args], env=full,
                              capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)

    def init_env(self):
        return json.loads(self.log.read_text()) if self.log.exists() else None

    def test_it_runs_docker_init_in_its_external_production_mode(self):
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        env = self.init_env()
        assert env is not None, "docker-init.sh never ran"
        for name, want in (("POLARIS_INIT_MANAGED_BY", "external"), ("POLARIS_ENV", "production"),
                           ("POLARIS_SQL_DIR", str(self.tmp / "polaris_sql")),
                           ("POSTGRES_USER", "polaris_owner"), ("PGUSER", "polaris_owner"),
                           ("POSTGRES_DB", "polaris"), ("PGDATABASE", "polaris"),
                           ("PGHOST", "db.example.net"), ("PGPORT", "5432"),
                           ("PGSSLMODE", "verify-full"), ("PGPASSWORD", "owner-secret"),
                           ("POLARIS_APP_PASSWORD_FILE", str(self.app_pw))):
            self.assertEqual(env.get(name), want, name)
        self.assertIn("initialised", r.stdout)

    def test_the_operators_tls_mode_is_kept(self):
        r = self.run_script(PGSSLMODE="verify-ca", POLARIS_DB_NAME="pid", POLARIS_DB_PORT="6432")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        env = self.init_env()
        assert env is not None, "docker-init.sh never ran"
        self.assertEqual((env["PGSSLMODE"], env["PGDATABASE"], env["PGPORT"]), ("verify-ca", "pid", "6432"))

    def test_each_missing_precondition_is_refused_before_a_write(self):
        cases = {
            "f|t|t|f|f|87|t": "not empty",
            "f|f|t|f|f|0|t": "does not own polaris",
            "f|t|t|f|f|0|f": GRANT,
            "f|t|f|f|f|0|t": "CREATEROLE",
            "f|t|t|t|f|0|t": "does not hold ADMIN on it",
        }
        for facts, said in cases.items():
            with self.subTest(facts):
                r = self.run_script(STUB_FACTS=facts)
                self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
                self.assertIn(said, r.stderr)
                self.assertIn("nothing was written", r.stderr)
                self.assertIsNone(self.init_env(), "docker-init.sh ran after a refusal")

    def test_every_missing_precondition_is_named_at_once(self):
        r = self.run_script(STUB_FACTS="f|f|f|f|f|3|f")
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        for said in ("not empty", "does not own", "GRANT SET ON PARAMETER", "CREATEROLE"):
            self.assertIn(said, r.stderr)

    def test_a_superuser_needs_no_grant(self):
        r = self.run_script(STUB_FACTS="t|f|f|t|f|0|f")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIsNotNone(self.init_env())

    def test_an_existing_app_role_the_owner_administers_is_kept(self):
        r = self.run_script(STUB_FACTS="f|t|f|t|t|0|t")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_server_older_than_sixteen_is_refused(self):
        r = self.run_script(STUB_VERSION="150008")
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("built and tested on 16", r.stderr)
        self.assertIsNone(self.init_env())

    def test_an_unreachable_server_is_an_error(self):
        r = self.run_script(STUB_DOWN="1")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("cannot reach", r.stderr)
        self.assertIsNone(self.init_env())

    def test_the_app_password_is_required_and_never_the_public_one(self):
        self.app_pw.write_text("polaris_dev_password")
        r = self.run_script()
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("public", r.stderr)
        r = self.run_script(drop=("POLARIS_APP_PASSWORD_FILE",))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        r = self.run_script(drop=("POLARIS_DB_HOST",))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIsNone(self.init_env())

    def test_a_failed_initialisation_says_to_start_again_from_an_empty_database(self):
        r = self.run_script(STUB_INIT_FAIL="1")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("drop and recreate polaris", r.stderr)


if __name__ == "__main__":
    unittest.main()
