# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Migration 2026-10-10-001: the application role keeps nothing on an event partition, detached ones too.

The authority policies on TokenLifecycleEvent and VerificationEvent live on their parents, and a partition
read directly carries none, so polaris_app holds no privilege on any partition. The migration revokes it on
every partition, and on tables detached before it ran, which kept the SELECT the lock used to leave: a
partition's name no longer in pg_inherits, a branch nothing else exercises. A database is built as
production builds it (00_load_all.sql, then polaris-migrate.sh --up); the migration and any after it are
reverted, a past month is detached the way the partition manager detached one then, and the migrations are
applied again. Needs PostgreSQL (POLARIS_DB_HOST, POLARIS_DB_USER, POLARIS_DB_PASSWORD, POLARIS_DB_PORT) and
a role that may create databases.

    python3 -m unittest test_event_partition_migration      (from scripts/)
"""
import os
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
MIGRATION = "2026-10-10-001-event-partitions-read-only-through-their-parent"
GRANTS = ("SELECT count(*) FROM information_schema.role_table_grants WHERE grantee = 'polaris_app' "
          "AND table_name ~ '^(tokenlifecycleevent|verificationevent|enrollmentstatusevent|authauditlog)_'")
DETACHED = "tokenlifecycleevent_2020_01"


def _env():
    env = dict(os.environ)
    env.setdefault("POLARIS_DB_HOST", "localhost")
    env.setdefault("POLARIS_DB_USER", "postgres")
    env["PGHOST"] = env["POLARIS_DB_HOST"]
    env["PGUSER"] = env["POLARIS_DB_USER"]
    if env.get("POLARIS_DB_PASSWORD"):
        env["PGPASSWORD"] = env["POLARIS_DB_PASSWORD"]
    if env.get("POLARIS_DB_PORT"):
        env["PGPORT"] = env["POLARIS_DB_PORT"]
    return env


def _run(cmd, env, cwd=None, timeout=900):
    return subprocess.run(cmd, env=env, cwd=cwd, capture_output=True, text=True, timeout=timeout)


class AMigratedDatabaseKeepsNothingOnAPartition(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.env = _env()
        if _run(["psql", "-X", "-At", "-d", "postgres", "-c", "SELECT 1"], cls.env).returncode != 0:
            if os.environ.get("CI"):
                raise RuntimeError("CI runs this suite against PostgreSQL, and none is reachable")
            raise unittest.SkipTest("no PostgreSQL reachable as POLARIS_DB_USER at POLARIS_DB_HOST")
        cls.db = "polaris_partmig_%d" % os.getpid()
        _run(["dropdb", "--if-exists", "--force", cls.db], cls.env)
        r = _run(["createdb", "-T", "template0", cls.db], cls.env)
        assert r.returncode == 0, r.stderr
        cls.addClassCleanup(cls._drop)
        load = _run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", cls.db, "-f", "00_load_all.sql"],
                    cls.env, cwd=ROOT / "polaris_sql")
        assert load.returncode == 0, load.stderr[-1500:]
        cls.migrate("--up")

    @classmethod
    def _drop(cls):
        r = _run(["dropdb", "--if-exists", "--force", cls.db], cls.env)
        assert r.returncode == 0, "the test database was left behind: %s" % r.stderr

    @classmethod
    def migrate(cls, *args):
        r = _run(["bash", str(SCRIPTS / "polaris-migrate.sh"), *args], dict(cls.env, POLARIS_DB_NAME=cls.db))
        assert r.returncode == 0, (r.stdout + r.stderr)[-1500:]

    def psql(self, sql):
        r = _run(["psql", "-X", "-At", "-v", "ON_ERROR_STOP=1", "-d", self.db, "-c", sql], self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def test_the_migration_revokes_on_every_partition_and_every_table_detached_before_it(self):
        self.assertEqual(self.psql(GRANTS), "0", "after --up, polaris_app holds a privilege on a partition")
        ups = sorted(p.name[:-len(".up.sql")] for p in (ROOT / "polaris_sql" / "migrations").glob("*.up.sql"))
        self.assertIn(MIGRATION, ups)
        self.migrate("--down", str(len(ups) - ups.index(MIGRATION)))
        self.assertGreater(int(self.psql(GRANTS)), 0, "reverted, the partitions did not get SELECT back")
        # A past month, made and detached the way the partition manager did before the migration: the
        # default privileges grant it, the lock of the time leaves SELECT, the detach of the time keeps it.
        self.psql("CREATE TABLE %s PARTITION OF tokenlifecycleevent FOR VALUES FROM ('2020-01-01') TO ('2020-02-01')"
                  % DETACHED)
        self.psql("SELECT polaris_lock_event_partitions()")
        self.psql("CALL uc_detach_event_partitions_before('2020-02-01'::timestamptz)")
        self.assertEqual(self.psql("SELECT EXISTS (SELECT 1 FROM pg_inherits WHERE inhrelid = '%s'::regclass)"
                                   % DETACHED), "f", "fixture: the past month was not detached")
        self.assertEqual(self.psql("SELECT has_table_privilege('polaris_app', '%s', 'SELECT')" % DETACHED), "t",
                         "fixture: the detached month did not keep SELECT")
        self.migrate("--up")
        self.assertEqual(self.psql("SELECT has_table_privilege('polaris_app', '%s', 'SELECT')" % DETACHED), "f",
                         "the migration left polaris_app SELECT on a table detached before it")
        self.assertEqual(self.psql(GRANTS), "0", "after the migration, polaris_app holds a privilege on a partition")


if __name__ == "__main__":
    unittest.main()
