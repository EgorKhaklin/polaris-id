# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris-restore.sh --verify-schema-version passes a good restore and refuses the three bad ones.

Until 2026-10-10 the cross-check selected a `version` column schema_version does not have and
discarded the error, so the documented command (docs/operator/OPERATIONS.md) exited 10 on every
good restore, with every migration on disk reported missing. polaris-migrate.sh had the same
silence about an unreadable registry until 2026-10-07 (test_migrate_runner.py).

The database is built the way production builds it, the migrations applied by polaris-migrate.sh
so that schema_version records them; a database loaded with bare psql -f has an empty registry.
Each case backs it up with polaris-backup.sh and restores the tarball into a fresh database with
polaris-restore.sh, the documented scripts end to end. Needs PostgreSQL (POLARIS_DB_HOST,
POLARIS_DB_USER, POLARIS_DB_PASSWORD, POLARIS_DB_PORT) and a role that may create databases.

    python3 -m unittest test_restore_schema_check      (from scripts/)
"""
import glob
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
EXIT_SCHEMA_MISMATCH = 10


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


class VerifySchemaVersionAfterRestore(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.env = _env()
        if _run(["psql", "-X", "-At", "-d", "postgres", "-c", "SELECT 1"], cls.env).returncode != 0:
            if os.environ.get("CI"):
                raise RuntimeError("CI runs this suite against PostgreSQL, and none is reachable")
            raise unittest.SkipTest("no PostgreSQL reachable as POLARIS_DB_USER at POLARIS_DB_HOST")
        cls.tmp = tempfile.mkdtemp(prefix="polaris-restore-check-")
        cls.prefix = "polaris_rsc_%d" % os.getpid()
        cls.dbs = []
        src = cls._createdb("src")
        load = _run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", src, "-f", "00_load_all.sql"],
                    cls.env, cwd=ROOT / "polaris_sql")
        assert load.returncode == 0, load.stderr[-1500:]
        menv = dict(cls.env, POLARIS_DB_NAME=src)
        up = _run(["bash", str(SCRIPTS / "polaris-migrate.sh"), "--up"], menv)
        assert up.returncode == 0, (up.stdout + up.stderr)[-1500:]
        applied = cls._psql(src, "SELECT count(*) FROM schema_version WHERE event_type = 'applied'")
        on_disk = len(glob.glob(str(ROOT / "polaris_sql" / "migrations" / "*.up.sql")))
        assert int(applied) == on_disk > 0, (applied, on_disk)
        cls.newest = sorted(pathlib.Path(p).name[:-len(".up.sql")]
                            for p in glob.glob(str(ROOT / "polaris_sql" / "migrations" / "*.up.sql")))[-1]
        # Four backups of the one database: as migrated; with its newest migration reverted
        # (a 'reverted' event after the 'applied' one); re-applied, then reverted again by a row
        # with the very same timestamp, which only event_id orders; with its registry unreadable.
        cls.good = cls._backup(src, "good")
        down = _run(["bash", str(SCRIPTS / "polaris-migrate.sh"), "--down", "1"], menv)
        assert down.returncode == 0, (down.stdout + down.stderr)[-1500:]
        cls.reverted = cls._backup(src, "reverted")
        reup = _run(["bash", str(SCRIPTS / "polaris-migrate.sh"), "--up"], menv)
        assert reup.returncode == 0, (reup.stdout + reup.stderr)[-1500:]
        cls._psql(src, "INSERT INTO schema_version (name, event_type, occurred_at, actor_user_id, file_sha256) "
                       "SELECT name, 'reverted', occurred_at, actor_user_id, file_sha256 FROM schema_version "
                       "WHERE name = '%s' AND event_type = 'applied' ORDER BY event_id DESC LIMIT 1" % cls.newest)
        cls.tied = cls._backup(src, "tied")
        cls._psql(src, "ALTER TABLE schema_version RENAME COLUMN name TO legacy_name")
        cls.unreadable = cls._backup(src, "unreadable")

    @classmethod
    def tearDownClass(cls):
        for db in getattr(cls, "dbs", []):
            _run(["dropdb", "--if-exists", db], cls.env)
        shutil.rmtree(getattr(cls, "tmp", ""), ignore_errors=True)

    @classmethod
    def _createdb(cls, suffix):
        db = "%s_%s" % (cls.prefix, suffix)
        _run(["dropdb", "--if-exists", db], cls.env)
        r = _run(["createdb", db], cls.env)
        assert r.returncode == 0, r.stderr
        cls.dbs.append(db)
        return db

    @classmethod
    def _psql(cls, db, sql):
        r = _run(["psql", "-X", "-At", "-v", "ON_ERROR_STOP=1", "-d", db, "-c", sql], cls.env)
        assert r.returncode == 0, r.stderr
        return r.stdout.strip()

    @classmethod
    def _backup(cls, db, name):
        dest = os.path.join(cls.tmp, name)
        os.makedirs(dest)
        r = _run(["bash", str(SCRIPTS / "polaris-backup.sh"), "--dest=%s" % dest],
                 dict(cls.env, POLARIS_DB_NAME=db))
        assert r.returncode == 0, (r.stdout + r.stderr)[-1500:]
        tarballs = glob.glob(os.path.join(dest, "polaris-*.tar.gz"))
        assert len(tarballs) == 1, tarballs
        return tarballs[0]

    def restore(self, tarball, case, scripts=SCRIPTS):
        target = self._createdb(case)
        return _run(["bash", str(pathlib.Path(scripts) / "polaris-restore.sh"), tarball,
                     "--target=%s" % target, "--verify-schema-version"], self.env)

    def test_a_good_restore_passes(self):
        r = self.restore(self.good, "good")
        self.assertEqual(r.returncode, 0, (r.stdout + r.stderr)[-2000:])
        self.assertIn("schema_version table matches migrations/ on disk", r.stdout)

    def test_a_reverted_migration_is_missing(self):
        """Its 'applied' row is still there; only the latest event says it is not applied."""
        r = self.restore(self.reverted, "reverted")
        self.assertEqual(r.returncode, EXIT_SCHEMA_MISMATCH, (r.stdout + r.stderr)[-2000:])
        self.assertIn("NOT in restored DB", r.stdout)
        self.assertIn(self.newest, r.stdout)

    def test_a_revert_tied_on_its_timestamp_is_ordered_by_event_id(self):
        """Two events in one transaction share now(); the later row is the later event."""
        r = self.restore(self.tied, "tied")
        self.assertEqual(r.returncode, EXIT_SCHEMA_MISMATCH, (r.stdout + r.stderr)[-2000:])
        self.assertIn("NOT in restored DB", r.stdout)
        self.assertIn(self.newest, r.stdout)

    def test_a_backup_from_a_newer_tree_is_refused(self):
        """Restored by a checkout that lacks the newest migration: the database has one more."""
        tree = os.path.join(self.tmp, "older-tree")
        os.makedirs(os.path.join(tree, "scripts"))
        for f in ("polaris-restore.sh", "polaris-env.sh"):
            shutil.copy2(SCRIPTS / f, os.path.join(tree, "scripts", f))
        shutil.copytree(ROOT / "polaris_sql" / "migrations", os.path.join(tree, "polaris_sql", "migrations"))
        os.remove(os.path.join(tree, "polaris_sql", "migrations", self.newest + ".up.sql"))
        r = self.restore(self.good, "newer", scripts=pathlib.Path(tree, "scripts"))
        self.assertEqual(r.returncode, EXIT_SCHEMA_MISMATCH, (r.stdout + r.stderr)[-2000:])
        self.assertIn("NOT on disk", r.stdout)
        self.assertIn(self.newest, r.stdout)

    def test_an_unreadable_registry_fails_closed(self):
        """A read that fails is an unverified restore, not a database with nothing applied."""
        r = self.restore(self.unreadable, "unreadable")
        self.assertEqual(r.returncode, EXIT_SCHEMA_MISMATCH, (r.stdout + r.stderr)[-2000:])
        self.assertIn("cannot read schema_version", r.stdout)
        self.assertNotIn("NOT in restored DB", r.stdout)


if __name__ == "__main__":
    unittest.main()
