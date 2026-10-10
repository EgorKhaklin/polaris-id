# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""A deploy changes nothing a migrated database holds.

Every deploy runs polaris-migrate.sh --sync-objects, which re-applies the schema's base files (views,
procedures, triggers, queries, the application role's grants) to a database already migrated. Until
2026-10-10 those files lagged the migrations: 09_grants.sql grants polaris_app SELECT, INSERT, UPDATE
and DELETE on every table and then revokes only what it names, so the DELETE on EnrollmentCode that
migration 2026-09-11-017 revoked came back on every deploy, and three routines' text differed from what
the migrations had installed. The database is built as production builds it (00_load_all.sql, then
polaris-migrate.sh --up); one sync must then change no view (or its options: CREATE OR REPLACE VIEW
replaces them, so a view that lost security_invoker would bypass row-level security), trigger (or whether it is enabled), routine
(its definition, settings, SECURITY DEFINER or owner), privilege of any role on any table, column,
sequence, routine or the public schema, default privilege, or database setting (09_grants.sql sets some). Needs PostgreSQL (POLARIS_DB_HOST,
POLARIS_DB_USER, POLARIS_DB_PASSWORD, POLARIS_DB_PORT) and a role that may create databases.

    python3 -m unittest test_sync_objects_parity      (from scripts/)
"""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

# Everything --sync-objects could change, one fact a line, for every role that is neither a superuser
# (which holds every privilege whatever the grants say) nor one of PostgreSQL's own. A routine is
# compared by its whole definition, comments included: the canonical files carry the migrations' text.
FACTS = r"""
WITH roles AS (SELECT oid, rolname FROM pg_roles WHERE NOT rolsuper AND rolname !~ '^pg_'),
     rels AS (SELECT c.oid, c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')),
     procs AS (SELECT p.oid, p.prokind FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'public')
SELECT 'view ' || c.oid::regclass::text || ' ' || md5(pg_get_viewdef(c.oid)) || ' options='
       || coalesce(array_to_string(pc.reloptions, ','), '')
  FROM rels c JOIN pg_class pc ON pc.oid = c.oid WHERE c.relkind IN ('v', 'm')
UNION ALL
SELECT 'trigger ' || t.tgrelid::regclass::text || ' ' || t.tgname || ' ' || t.tgenabled::text || ' ' || md5(pg_get_triggerdef(t.oid))
  FROM pg_trigger t JOIN rels c ON c.oid = t.tgrelid WHERE NOT t.tgisinternal
UNION ALL
SELECT 'routine ' || p.oid::regprocedure::text || ' ' || md5(pg_get_functiondef(p.oid)) || ' definer=' || pp.prosecdef::text
       || ' owner=' || pp.proowner::regrole::text || ' config=' || coalesce(array_to_string(pp.proconfig, ','), '')
  FROM procs p JOIN pg_proc pp ON pp.oid = p.oid WHERE p.prokind IN ('f', 'p')
UNION ALL
SELECT 'table ' || r.rolname || ' ' || c.oid::regclass::text || ' ' || priv
  FROM roles r CROSS JOIN rels c
  CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) v(priv)
 WHERE c.relkind <> 'S' AND has_table_privilege(r.oid, c.oid, priv)
UNION ALL
SELECT 'column ' || r.rolname || ' ' || c.oid::regclass::text || '.' || a.attname || ' ' || priv
  FROM roles r CROSS JOIN rels c JOIN pg_attribute a ON a.attrelid = c.oid
  CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('REFERENCES')) v(priv)
 WHERE c.relkind <> 'S' AND a.attnum > 0 AND NOT a.attisdropped AND has_column_privilege(r.oid, c.oid, a.attnum, priv)
UNION ALL
SELECT 'sequence ' || r.rolname || ' ' || c.oid::regclass::text || ' ' || priv
  FROM roles r CROSS JOIN rels c CROSS JOIN (VALUES ('USAGE'), ('SELECT'), ('UPDATE')) v(priv)
 WHERE c.relkind = 'S' AND has_sequence_privilege(r.oid, c.oid, priv)
UNION ALL
SELECT 'execute ' || r.rolname || ' ' || p.oid::regprocedure::text
  FROM roles r CROSS JOIN procs p WHERE has_function_privilege(r.oid, p.oid, 'EXECUTE')
UNION ALL
SELECT 'schema ' || r.rolname || ' public ' || priv
  FROM roles r CROSS JOIN (VALUES ('USAGE'), ('CREATE')) v(priv) WHERE has_schema_privilege(r.oid, 'public', priv)
UNION ALL
SELECT 'default ' || d.defaclrole::regrole::text || ' ' || coalesce(n.nspname, '-') || ' ' || d.defaclobjtype::text
       || ' ' || d.defaclacl::text
  FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
UNION ALL
SELECT 'dbsetting ' || coalesce(r.rolname, '-') || ' ' || array_to_string(s.setconfig, ',')
  FROM pg_db_role_setting s LEFT JOIN pg_roles r ON r.oid = s.setrole
 WHERE s.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database())
"""


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


class OneSyncChangesNothing(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.env = _env()
        if _run(["psql", "-X", "-At", "-d", "postgres", "-c", "SELECT 1"], cls.env).returncode != 0:
            if os.environ.get("CI"):
                raise RuntimeError("CI runs this suite against PostgreSQL, and none is reachable")
            raise unittest.SkipTest("no PostgreSQL reachable as POLARIS_DB_USER at POLARIS_DB_HOST")
        cls.dbs = []
        cls.tmp = tempfile.mkdtemp(prefix="polaris-syncparity-")
        cls.addClassCleanup(cls._drop)
        cls.db = cls._migrated("main")
        cls.view_db = cls._migrated("view")
        cls.grant_db = cls._migrated("grant")

    @classmethod
    def _migrated(cls, suffix):
        """A database built as production builds it: the canonical files, then every migration."""
        db = "polaris_syncparity_%d_%s" % (os.getpid(), suffix)
        _run(["dropdb", "--if-exists", "--force", db], cls.env)
        r = _run(["createdb", "-T", "template0", db], cls.env)
        assert r.returncode == 0, r.stderr
        cls.dbs.append(db)
        load = _run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-f", "00_load_all.sql"],
                    cls.env, cwd=ROOT / "polaris_sql")
        assert load.returncode == 0, load.stderr[-1500:]
        up = _run(["bash", str(SCRIPTS / "polaris-migrate.sh"), "--up"], dict(cls.env, POLARIS_DB_NAME=db))
        assert up.returncode == 0, (up.stdout + up.stderr)[-1500:]
        return db

    @classmethod
    def _drop(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        failed = [db for db in cls.dbs if _run(["dropdb", "--if-exists", "--force", db], cls.env).returncode != 0]
        assert not failed, "test databases left behind: %s" % failed

    def facts(self, db=None):
        r = _run(["psql", "-X", "-At", "-v", "ON_ERROR_STOP=1", "-d", db or self.db, "-c", FACTS], self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        facts = set(r.stdout.splitlines())
        for kind in ("view", "trigger", "routine", "table", "column", "sequence", "execute", "schema", "default", "dbsetting"):
            self.assertTrue(any(f.startswith(kind + " ") for f in facts), "no %s facts were read" % kind)
        self.assertTrue(any(f.startswith("table polaris_app ") for f in facts), "polaris_app holds no table privilege")
        return facts

    def test_a_deploys_sync_changes_nothing_a_migrated_database_holds(self):
        before = self.facts()
        sync = _run(["bash", str(SCRIPTS / "polaris-migrate.sh"), "--sync-objects"],
                    dict(self.env, POLARIS_DB_NAME=self.db))
        self.assertEqual(sync.returncode, 0, (sync.stdout + sync.stderr)[-1500:])
        after = self.facts()
        lost, gained = sorted(before - after), sorted(after - before)
        self.assertFalse(lost or gained, "one --sync-objects changed %d facts of a migrated database:\n%s"
                         % (len(lost) + len(gained), "\n".join(["- " + f for f in lost[:10]] + ["+ " + f for f in gained[:10]])))
        self.assertNotIn("table polaris_app enrollmentcode DELETE", after,
                         "polaris_app may delete enrollment codes after a deploy (revoked by migration 2026-09-11-017)")

    def sync_from_a_copy(self, db, rel, old, new):
        """One sync of DB from a copy of the tree whose REL has OLD replaced by NEW: the facts it changed."""
        tree = pathlib.Path(tempfile.mkdtemp(dir=self.tmp))
        shutil.copytree(ROOT / "polaris_sql", tree / "polaris_sql")
        (tree / "scripts").mkdir()
        for f in ("polaris-migrate.sh", "polaris-env.sh"):
            shutil.copy2(SCRIPTS / f, tree / "scripts" / f)
        path = tree / rel
        text = path.read_text()
        self.assertEqual(text.count(old), 1, "the control's anchor drifted: %r" % old)
        path.write_text(text.replace(old, new))
        before = self.facts(db)
        sync = _run(["bash", str(tree / "scripts" / "polaris-migrate.sh"), "--sync-objects"],
                    dict(self.env, POLARIS_DB_NAME=db))
        self.assertEqual(sync.returncode, 0, (sync.stdout + sync.stderr)[-1500:])
        after = self.facts(db)
        return sorted("- " + f for f in before - after) + sorted("+ " + f for f in after - before)

    def test_the_comparison_sees_a_view_that_lost_security_invoker(self):
        """CREATE OR REPLACE VIEW replaces a view's options: one that lost security_invoker would bypass
        row-level security after every deploy, and must be seen."""
        changed = self.sync_from_a_copy(self.view_db, "polaris_sql/03_view.sql",
                                        "CREATE OR REPLACE VIEW ActiveTokens WITH (security_invoker = true) AS",
                                        "CREATE OR REPLACE VIEW ActiveTokens AS")
        self.assertTrue(changed and all(f[2:].startswith("view activetokens ") for f in changed),
                        "the view's lost security_invoker went unseen, or something else changed: %s" % changed[:6])

    def test_without_its_revoke_a_deploy_grants_enrollment_code_delete(self):
        """09_grants.sql as it was before 2026-10-10: the comparison names what every deploy then granted."""
        changed = self.sync_from_a_copy(self.grant_db, "polaris_sql/09_grants.sql",
                                        "REVOKE DELETE ON EnrollmentCode FROM polaris_app;\n", "")
        self.assertEqual(changed, ["+ table polaris_app enrollmentcode DELETE"])

if __name__ == "__main__":
    unittest.main()
