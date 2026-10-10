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
import re
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


class _RestoreHarness(unittest.TestCase):
    """Databases, backups and psql for the cases below, against the PostgreSQL the environment names."""

    @classmethod
    def _connect(cls, prefix):
        cls.env = _env()
        if _run(["psql", "-X", "-At", "-d", "postgres", "-c", "SELECT 1"], cls.env).returncode != 0:
            if os.environ.get("CI"):
                raise RuntimeError("CI runs this suite against PostgreSQL, and none is reachable")
            raise unittest.SkipTest("no PostgreSQL reachable as POLARIS_DB_USER at POLARIS_DB_HOST")
        cls.tmp = tempfile.mkdtemp(prefix="polaris-%s-" % prefix)
        cls.prefix = "polaris_%s_%d" % (prefix, os.getpid())
        cls.dbs = []
        # A class cleanup runs when setUpClass fails too, which tearDownClass does not: the databases
        # named for this process would otherwise outlive it, since nothing reuses the name.
        cls.addClassCleanup(cls._drop_all)

    @classmethod
    def _drop_all(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        failed = []
        for db in cls.dbs:
            r = _run(["dropdb", "--if-exists", "--force", db], cls.env)
            if r.returncode != 0:
                failed.append("%s: %s" % (db, r.stderr.strip()))
        assert not failed, "test databases left behind: %s" % failed

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


class VerifySchemaVersionAfterRestore(_RestoreHarness):

    @classmethod
    def setUpClass(cls):
        cls._connect("rsc")
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


EXIT_PRIVILEGE_MISMATCH = 11

# polaris_app's effective privileges, one fact a line: on every table, view, sequence, column and
# routine of the public schema, and the default privileges.
APP_ROLE_FACTS = """
SELECT 'table ' || c.oid::regclass::text || ' ' || p.priv
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE')) p(priv)
 WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND has_table_privilege('polaris_app', c.oid, p.priv)
UNION ALL
SELECT 'sequence ' || c.oid::regclass::text || ' ' || p.priv
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  CROSS JOIN (VALUES ('USAGE'), ('SELECT'), ('UPDATE')) p(priv)
 WHERE n.nspname = 'public' AND c.relkind = 'S' AND has_sequence_privilege('polaris_app', c.oid, p.priv)
UNION ALL
SELECT 'column ' || c.oid::regclass::text || '.' || a.attname || ' ' || p.priv
  FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
  CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE')) p(priv)
 WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND a.attnum > 0 AND NOT a.attisdropped
   AND has_column_privilege('polaris_app', c.oid, a.attnum, p.priv)
UNION ALL
SELECT 'routine ' || p.oid::regprocedure::text || ' EXECUTE'
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname = 'public' AND has_function_privilege('polaris_app', p.oid, 'EXECUTE')
UNION ALL
SELECT 'default ' || d.defaclobjtype::text || ' in ' || coalesce(n.nspname, '-') || ' ' || d.defaclacl::text
  FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
"""


class RestoreKeepsTheBackupsPrivileges(_RestoreHarness):
    """A restore gives polaris_app the privileges the backup gave it, no more.

    09_grants.sql grants polaris_app SELECT, INSERT, UPDATE and DELETE on new tables and EXECUTE on new
    routines as default privileges, then narrows it: the append-only tables, the counts, the registers,
    AppUser to its four lockout columns, the owner-only routines. pg_restore --clean recreates every
    object, a new object takes the database's default privileges, and pg_dump writes grants as a
    difference from PostgreSQL's built-in default, so the narrowing was never replayed: restored into
    an initialised database (the stack's, after its first start; a host's after setup.sh), polaris_app
    could write all of them again and run the retention purge. Each case restores into a database
    initialised the way the stack is; the expectations are the source's own privileges, read when its
    backup was taken."""

    @classmethod
    def setUpClass(cls):
        cls._connect("rkp")
        src = cls._initialised("src")
        up = _run(["bash", str(SCRIPTS / "polaris-migrate.sh"), "--up"], dict(cls.env, POLARIS_DB_NAME=src))
        assert up.returncode == 0, (up.stdout + up.stderr)[-1500:]
        cls.source = cls._facts(src)
        cls.backup = cls._backup(src, "backup")

    @classmethod
    def _initialised(cls, suffix):
        """A database initialised as docker-init.sh initialises the stack's, its default privileges set."""
        db = cls._createdb(suffix)
        load = _run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-f", "00_load_all.sql"],
                    cls.env, cwd=ROOT / "polaris_sql")
        assert load.returncode == 0, load.stderr[-1500:]
        return db

    @classmethod
    def _facts(cls, db):
        return set(cls._psql(db, APP_ROLE_FACTS).splitlines())

    def restore_into(self, target):
        return _run(["bash", str(SCRIPTS / "polaris-restore.sh"), self.backup, "--target=%s" % target, "--force",
                     "--verify-schema-version"], self.env)

    def assertSameFacts(self, got, msg):
        lost, gained = sorted(self.source - got), sorted(got - self.source)
        self.assertEqual((lost[:8], gained[:8]), ([], []), "%s: %d lost, %d gained" % (msg, len(lost), len(gained)))

    def test_the_source_is_narrowed_as_the_schema_says(self):
        """The cases below mean something only if the source holds the narrowing they look for."""
        self.assertTrue(any(f.startswith("default r in public ") for f in self.source), "no default privileges")
        appuser_update = {f for f in self.source if f.startswith("column appuser.") and f.endswith(" UPDATE")}
        self.assertTrue(appuser_update, "polaris_app updates no AppUser column")
        self.assertNotIn("column appuser.password_hash UPDATE", self.source)
        self.assertNotIn("table appuser UPDATE", self.source)
        self.assertFalse([f for f in self.source if f.startswith("routine uc_archive_purge(")], "the purge is lent")
        self.assertNotIn("table schema_version INSERT", self.source)

    def test_a_restore_into_an_initialised_database_keeps_the_app_roles_privileges(self):
        target = self._initialised("restored")
        r = self.restore_into(target)
        self.assertEqual(r.returncode, 0, (r.stdout + r.stderr)[-2500:])
        self.assertIn("the backup's privileges, restored", r.stdout)
        got = self._facts(target)
        self.assertNotIn("column appuser.password_hash UPDATE", got, "polaris_app could reset a password")
        self.assertFalse([f for f in got if f.startswith("routine uc_archive_purge(")], "polaris_app may run the purge")
        self.assertSameFacts(got, "polaris_app's privileges after the restore are not the source's")

    def test_a_privilege_the_backup_does_not_hold_is_refused(self):
        """The public schema is not recreated by the restore, so a grant the target holds on it remains."""
        target = self._initialised("widened")
        self._psql(target, "GRANT CREATE ON SCHEMA public TO polaris_app")
        r = self.restore_into(target)
        self.assertEqual(r.returncode, EXIT_PRIVILEGE_MISMATCH, (r.stdout + r.stderr)[-2500:])
        self.assertIn("the restored privileges are not the backup's", r.stderr)
        self.assertIn("schema public", r.stderr)

    def restore_with(self, case, old, new):
        """The restore run by a copy of the script with OLD replaced by NEW: the check's own controls."""
        tree = os.path.join(self.tmp, "tree-" + case, "scripts")
        os.makedirs(tree)
        shutil.copy2(SCRIPTS / "polaris-env.sh", tree)
        text = (SCRIPTS / "polaris-restore.sh").read_text()
        self.assertEqual(text.count(old), 1, "the control's anchor drifted: %r" % old)
        pathlib.Path(tree, "polaris-restore.sh").write_text(text.replace(old, new))
        return _run(["bash", os.path.join(tree, "polaris-restore.sh"), self.backup,
                     "--target=%s" % self._initialised(case), "--force"], self.env)

    def test_without_the_clearing_the_check_names_what_the_restore_widened(self):
        r = self.restore_with("unclear", '    if ! clear_err=$(db_sql "${TARGET_DB}" "${CLEAR_DEFAULT_PRIVILEGES}" 2>&1); then',
                              '    if false; then')
        self.assertEqual(r.returncode, EXIT_PRIVILEGE_MISMATCH, (r.stdout + r.stderr)[-2500:])
        appended_only = sorted(f.split()[1] for f in self.source if f.startswith("table ") and f.endswith(" INSERT")
                               and "table %s UPDATE" % f.split()[1] not in self.source
                               and "table %s DELETE" % f.split()[1] not in self.source)
        self.assertTrue(appended_only, "the source has no table the application may only append to")
        self.assertIn("relation %s:" % appended_only[0], r.stderr, "an append-only table widened unnamed")
        self.assertIn("relation appuser:", r.stderr, "AppUser widened past its four columns unnamed")

    def test_privileges_that_cannot_be_read_are_an_unverified_restore(self):
        anchor = '\nSCRATCH_DB=""\n'
        for case, facts, says in (("empty", "SELECT '', '', '' WHERE false", "missing from its restored schema"),
                                  ("unreadable", "SELECT no_such_column FROM pg_class", "cannot read the backup's privileges")):
            with self.subTest(case):
                r = self.restore_with(case, anchor, anchor + 'PRIVILEGE_FACTS="%s"\n' % facts)
                self.assertEqual(r.returncode, EXIT_PRIVILEGE_MISMATCH, (r.stdout + r.stderr)[-2500:])
                self.assertIn(says, r.stderr)

    def test_contents_the_check_cannot_account_for_are_an_unverified_restore(self):
        """The reference must cover the dump: an object it lacks, contents that cannot be listed, or a
        listing that cannot be read, each leaves objects uncompared, and each is refused."""
        anchor = '\nSCRATCH_DB=""\n'
        real = 'pg_restore -U "${PGUSER:-postgres}" -l "$1"'
        for case, stub, says in (
                ("ghost", '{ %s; echo "9999; 1259 1 TABLE public ghost postgres"; }' % real, "relation ghost"),
                ("unlisted", '{ echo "pg_restore: error: not an archive" >&2; return 1; }', "cannot list the backup's contents"),
                ("unparsed", "{ %s | sed 's/ public / other /'; }" % real, "could not all be read"),
                ("partial", "{ %s | sed 's/ TABLE public agency / TABLE public \"agency x\" /'; }" % real,
                 "could not all be read")):
            with self.subTest(case):
                r = self.restore_with(case, anchor, anchor + "dump_contents() %s\n" % stub)
                self.assertEqual(r.returncode, EXIT_PRIVILEGE_MISMATCH, (r.stdout + r.stderr)[-2500:])
                self.assertIn(says, r.stderr)

    def test_database_wide_default_privileges_are_refused_before_anything_is_restored(self):
        target = self._initialised("database_wide")
        self._psql(target, "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO polaris_app")
        self._psql(target, "CREATE TABLE restore_marker (x int)")
        r = self.restore_into(target)
        self.assertEqual(r.returncode, EXIT_PRIVILEGE_MISMATCH, (r.stdout + r.stderr)[-2500:])
        self.assertIn("database-wide default privileges", r.stderr)
        self.assertIn("nothing was restored", r.stderr)
        self.assertEqual(self._psql(target, "SELECT to_regclass('public.restore_marker') IS NOT NULL"), "t")


class DockerExecUsesTheStackRole(unittest.TestCase):
    """Every `compose ... exec -T postgres <client> -U <role>` in scripts/ names the stack's POSTGRES_USER.

    The cross-check's docker branch above once named a `polaris` role the production stack does not
    have, so the documented docker-stack restore stopped at "role polaris does not exist" while the
    host-path tests passed (found in review, 2026-10-10). These calls need the stack to run, which
    the suite does not start, so their role is held to docker-compose.prod.yml here."""

    CLIENT = re.compile(r"exec\s+-T\s+(?:-u\s+\S+\s+)?postgres\s+"
                        r"(psql|pg_dump|pg_dumpall|pg_restore|createdb|dropdb)\b([^\n]*)")

    def test_every_docker_exec_client_uses_the_stack_role(self):
        compose = (ROOT / "polaris_web" / "docker-compose.prod.yml").read_text()
        m = re.search(r"^\s*POSTGRES_USER:\s*(\S+)\s*$", compose, re.M)
        self.assertIsNotNone(m, "docker-compose.prod.yml names no POSTGRES_USER")
        role = m.group(1)
        calls, wrong = [], []
        for path in sorted(SCRIPTS.glob("*.sh")):
            text = path.read_text(encoding="utf-8", errors="replace").replace("\\\n", " ")
            for c in self.CLIENT.finditer(text):
                u = re.search(r'(?:-U|--username[= ])\s*"?([^"\s]+)', c.group(2))
                calls.append((path.name, c.group(1)))
                if not u or u.group(1) != role:
                    wrong.append("%s: %s -U %s" % (path.name, c.group(1), u.group(1) if u else "(none)"))
        self.assertGreaterEqual(len(calls), 20, "the scan found too few calls to mean anything")
        self.assertIn(("polaris-restore.sh", "psql"), calls, "the restore cross-check's docker read was not seen")
        self.assertEqual(wrong, [], "docker exec clients must connect as %s" % role)

    def test_every_restore_client_call_uses_its_branch_role(self):
        """In polaris-restore.sh each psql or pg_restore command connects as its branch's helper does:
        the docker branch as the stack's POSTGRES_USER, the host branch as ${PGUSER:-postgres}.
        The cross-check's host read once ran with no -U, as the OS user, after a restore made as
        postgres (found in review, 2026-10-10)."""
        compose = (ROOT / "polaris_web" / "docker-compose.prod.yml").read_text()
        role = re.search(r"^\s*POSTGRES_USER:\s*(\S+)\s*$", compose, re.M).group(1)
        text = (SCRIPTS / "polaris-restore.sh").read_text().replace("\\\n", " ")
        docker, host, wrong, heredoc = [], [], [], None
        for line in text.split("\n"):
            if heredoc:
                heredoc = None if line.strip() == heredoc else heredoc
                continue
            code = line.strip()
            if not code or code.startswith("#") or re.match(r"(echo|printf)\b", code):
                continue
            h = re.search(r"<<-?\s*['\"]?(\w+)", code)
            if h:
                heredoc = h.group(1)
            for m in re.finditer(r"(?:^|[\s;{(|&])(psql|pg_restore)\s([^\n]*)", code):
                in_docker = "exec -T postgres" in code
                want = "-U %s" % role if in_docker else '-U "${PGUSER:-postgres}"'
                (docker if in_docker else host).append(code)
                if want not in m.group(2):
                    wrong.append(("docker" if in_docker else "host") + ": " + code[:90])
        self.assertGreaterEqual(len(docker), 3, docker)
        self.assertGreaterEqual(len(host), 3, host)
        self.assertEqual(wrong, [], "each client must connect as its branch's helper does")


if __name__ == "__main__":
    unittest.main()
