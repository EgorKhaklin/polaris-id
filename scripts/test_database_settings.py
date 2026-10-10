# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""A backup carries its database's own settings, and a restore puts them back or stops.

pg_restore applies ALTER DATABASE ... SET and ALTER ROLE ... IN DATABASE ... SET only with
--create, which polaris-restore.sh does not use, so until 2026-10-10 a restore into a new database
lost 09_grants.sql's settings and any an operator had changed, and one into an initialised database
kept that database's own. polaris-backup.sh now records them (database-settings.json, under the
manifest) and polaris-restore.sh replays them, reads them back and exits 12 otherwise.

These tests need no database: the file format, the SQL the replay writes (its quoting above all) and
the scripts' fail-closed paths, with a stand-in psql, pg_restore, pg_dump and docker on PATH. The
round trip through a real PostgreSQL is test_restore_schema_check.py's.

    python3 -m unittest test_database_settings      (from scripts/)
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
HELPER = SCRIPTS / "polaris_db_settings.py"
EXIT_MANIFEST_VERIFY_FAIL = 5
EXIT_SETTINGS_MISMATCH = 12

_spec = importlib.util.spec_from_file_location("polaris_db_settings", HELPER)
settings = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(settings)


def record(entries, database="polaris"):
    """A settings file as the backup writes it, from (role, name, value) triples."""
    return json.dumps({"format": settings.FORMAT, "database": database,
                       "settings": [{"role": r, "name": n, "value": v} for r, n, v in entries]})


# What 09_grants.sql and the notional sample give a database, an operator's own values, and a role's.
SOURCE = [
    (None, "TimeZone", "UTC"),
    (None, "polaris.default_max_revoke_percent", "2.50"),
    (None, "polaris.default_window_days", "30"),
    (None, "polaris.min_epoch_anonymity_set", "25"),
    ("polaris_app", "statement_timeout", "7s"),
]


def pg_literal(sql):
    """The value PostgreSQL's lexer reads from one string literal: '...' or E'...', the same whatever
    standard_conforming_strings is (a database may set it off). So a plain literal holds no
    backslash, and an E'' literal no escape but a doubled backslash."""
    escaped = sql.startswith("E'")
    body = sql[2:-1] if escaped else sql[1:-1]
    assert sql.endswith("'"), sql
    assert escaped or "\\" not in body, "read differently with standard_conforming_strings off: %r" % sql
    out, i = [], 0
    while i < len(body):
        c = body[i]
        if c == "'":
            assert body[i + 1:i + 2] == "'", "a lone quote ends the literal early: %r" % sql
            out.append("'")
            i += 2
        elif c == "\\" and escaped:
            assert body[i + 1:i + 2] == "\\", "an escape the replay must not write: %r" % sql
            out.append("\\")
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


class TheFile(unittest.TestCase):

    def test_a_record_loads_as_it_was_read(self):
        self.assertEqual(settings.load(record(SOURCE)), SOURCE)
        self.assertEqual(settings.load(record([])), [], "a database with no settings records none")

    def test_record_checks_what_it_writes(self):
        r = subprocess.run([sys.executable, str(HELPER), "record"], input=record(SOURCE),
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(settings.load(r.stdout), SOURCE)
        for bad in ("", "ERROR: relation does not exist", record(SOURCE).replace("/1", "/2")):
            with self.subTest(bad=bad[:30]):
                r = subprocess.run([sys.executable, str(HELPER), "record"], input=bad, capture_output=True, text=True)
                self.assertEqual(r.returncode, 1, "an unusable reading was written as a record")
                self.assertEqual(r.stdout, "")

    def test_a_record_that_cannot_be_trusted_is_refused(self):
        good = json.loads(record(SOURCE))
        cases = {
            "not JSON": "{",
            "another format": json.dumps(dict(good, format="polaris-database-settings/2")),
            "no format": json.dumps({k: v for k, v in good.items() if k != "format"}),
            "settings not a list": json.dumps(dict(good, settings={})),
            "no database": json.dumps({k: v for k, v in good.items() if k != "database"}),
            "an empty role": record([("", "work_mem", "1MB")]),
            "a role that is not text": json.dumps(dict(good, settings=[{"role": 7, "name": "a.b", "value": "1"}])),
            "no name": record([(None, "", "1")]),
            "a value that is not text": json.dumps(dict(good, settings=[{"role": None, "name": "a.b", "value": 1}])),
            "a NUL": record([(None, "a.b", "x\x00y")]),
            "a key too many": json.dumps(dict(good, settings=[{"role": None, "name": "a.b", "value": "1", "x": 1}])),
            "a setting twice": record([(None, "TimeZone", "UTC"), (None, "timezone", "Europe/Paris")]),
        }
        for case, text in cases.items():
            with self.subTest(case):
                with self.assertRaises(settings.SettingsError):
                    settings.load(text)

    def test_the_same_name_for_the_database_and_a_role_is_two_settings(self):
        both = [(None, "statement_timeout", "5s"), ("polaris_app", "statement_timeout", "7s")]
        self.assertEqual(settings.load(record(both)), both)

    def test_the_query_reads_this_databases_rows_and_both_scopes(self):
        q = settings.QUERY
        self.assertIn("d.datname = current_database()", q)
        self.assertIn("pg_db_role_setting", q)
        self.assertIn("CASE WHEN s.setrole = 0 THEN NULL", q, "a database setting must read as role NULL")
        self.assertIn(settings.FORMAT, q)


class TheReplay(unittest.TestCase):
    """The SQL polaris-restore.sh sends: every name and value quoted so that PostgreSQL reads back
    exactly the recorded text, whatever it holds."""

    def statements(self, entries, target="polaris"):
        sql = settings.replay_sql(entries, target)
        self.assertTrue(sql.startswith(settings.RESET), "the target's own settings must be reset first")
        return [line for line in sql[len(settings.RESET):].split(";\n") if line.strip()]

    def test_each_scope_has_its_statement(self):
        got = self.statements(SOURCE, target="polaris_restored")
        self.assertEqual(got[0], "\nALTER DATABASE \"polaris_restored\" SET \"TimeZone\" TO 'UTC'")
        self.assertEqual(got[3], "ALTER DATABASE \"polaris_restored\" SET \"polaris.min_epoch_anonymity_set\" TO '25'")
        self.assertEqual(got[4], "ALTER ROLE \"polaris_app\" IN DATABASE \"polaris_restored\" SET "
                                 "\"statement_timeout\" TO '7s'")
        self.assertEqual(len(got), len(SOURCE))

    def test_the_reset_covers_the_database_and_every_role_in_it(self):
        self.assertIn("ALTER DATABASE %I RESET ALL", settings.RESET)
        self.assertIn("ALTER ROLE %s IN DATABASE %I RESET ALL", settings.RESET)
        self.assertIn("s.setrole <> 0", settings.RESET)
        self.assertEqual(self.statements([]), [], "a record of none still resets the target")

    def test_identifiers_are_quoted_and_keep_their_case(self):
        sql = settings.replay_sql([('odd"role', "Polaris.Odd", "1")], 'db "x"')
        self.assertIn('ALTER ROLE "odd""role" IN DATABASE "db ""x""" SET "Polaris.Odd" TO \'1\';', sql)

    def test_every_value_reads_back_as_recorded(self):
        values = ["UTC", "", "it's", "''", "back\\slash", "\\'; DROP DATABASE polaris; --", "two\nlines",
                  "tab\there", "$$dollar$$", "E'x'", "\\\\", "unicode \u00e9\u4e2d", "\"quoted\"", "trailing\\"]
        for v in values:
            with self.subTest(v=v):
                stmt = self.statements([(None, "polaris.x", v)])[0]
                lit = stmt.split(" TO ", 1)[1]
                self.assertEqual(pg_literal(lit), v)

    def test_a_list_setting_is_replayed_element_by_element(self):
        """search_path is stored quoted, element by element; one literal of the whole would set a
        single schema named '"$user", public'."""
        stmt = self.statements([(None, "search_path", '"$user", public, "we""ird x"')])[0]
        self.assertTrue(stmt.endswith(" TO '$user', 'public', 'we\"ird x'"), stmt)
        stmt = self.statements([(None, "search_path", '""')])[0]
        self.assertTrue(stmt.endswith(" TO ''"), stmt)
        for broken in ('"$user', "a,", "a b", ",a", " "):
            with self.subTest(broken=broken):
                with self.assertRaises(settings.SettingsError):
                    settings.replay_sql([(None, "search_path", broken)], "polaris")

    def test_the_list_is_split_as_postgresql_splits_it(self):
        split = settings.split_guc_list
        self.assertEqual(split(""), [])
        self.assertEqual(split("  a ,  \"b c\"  "), ["a", "b c"])
        self.assertEqual(split('"a""b",c'), ['a"b', "c"])
        self.assertEqual(split('"x,y"'), ["x,y"])
        self.assertEqual(split("Mixed"), ["Mixed"], "an unquoted element keeps its case")

    def test_other_settings_are_one_literal_even_with_commas(self):
        stmt = self.statements([(None, "DateStyle", "ISO, MDY")])[0]
        self.assertTrue(stmt.endswith(" TO 'ISO, MDY'"), stmt)


class TheComparison(unittest.TestCase):

    def test_equal_settings_compare_equal(self):
        self.assertEqual(settings.compare(SOURCE, list(reversed(SOURCE))), [])

    def test_each_difference_is_named_both_ways(self):
        restored = [s for s in SOURCE if s[1] != "TimeZone"]
        restored = [(r, n, "1" if n == "polaris.min_epoch_anonymity_set" else v) for r, n, v in restored]
        restored.append((None, "work_mem", "1MB"))
        restored.append(("polaris_app", "TimeZone", "UTC"))
        self.assertEqual(settings.compare(SOURCE, restored), [
            "the database's polaris.min_epoch_anonymity_set: restored 1, the backup 25",
            "the database's TimeZone: missing after the restore (the backup: UTC)",
            "the database's work_mem: restored 1MB, the backup none",
            "role polaris_app's TimeZone: restored UTC, the backup none",
        ])

    def test_the_command_exits_one_on_a_difference_or_an_unreadable_reading(self):
        with tempfile.TemporaryDirectory() as d:
            f = pathlib.Path(d, "database-settings.json")
            f.write_text(record(SOURCE))
            same = subprocess.run([sys.executable, str(HELPER), "compare", str(f)], input=record(SOURCE),
                                  capture_output=True, text=True)
            self.assertEqual((same.returncode, same.stdout), (0, ""), same.stderr)
            other = subprocess.run([sys.executable, str(HELPER), "compare", str(f)], input=record(SOURCE[:-1]),
                                   capture_output=True, text=True)
            self.assertEqual(other.returncode, 1)
            self.assertIn("role polaris_app's statement_timeout: missing after the restore", other.stdout)
            unreadable = subprocess.run([sys.executable, str(HELPER), "compare", str(f)], input="",
                                        capture_output=True, text=True)
            self.assertEqual(unreadable.returncode, 1)
            self.assertIn("could not be read", unreadable.stderr)

    def test_a_usage_error_is_named_even_without_docstrings(self):
        """python -OO drops the module docstring; the usage must not depend on it."""
        for flags in ([], ["-OO"]):
            with self.subTest(flags=flags):
                r = subprocess.run([sys.executable, *flags, str(HELPER), "replay"], capture_output=True, text=True)
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn("usage: polaris_db_settings.py", r.stderr)
                self.assertNotIn("Traceback", r.stderr)
        r = subprocess.run([sys.executable, str(HELPER), "replay", os.devnull, ""], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1, "a replay without a target must be refused")


# A stand-in psql for the restore and the backup. It reads -d and -c as psql does, answers the
# queries those scripts send, and keeps the target's settings in $STUB/state.json: a replay applies
# $STUB/recorded.json (or $STUB/wrong.json, or fails), a read of the settings returns the state.
PSQL = r"""#!/bin/sh
db=""; sql=""
while [ $# -gt 0 ]; do
    case "$1" in
        -d) db="$2"; shift ;;
        -c) sql="$2"; shift ;;
    esac
    shift
done
printf '%s\t%s\n' "$db" "$(printf '%s' "$sql" | tr '\n\t' '  ' | cut -c1-80)" >> "$STUB/psql.log"
case "$sql" in
    *'DO $reset$'*)
        printf '%s' "$sql" > "$STUB/replay.sql"
        case "${STUB_APPLY:-ok}" in
            fail) echo 'ERROR:  role "no_such_role" does not exist' >&2; exit 1 ;;
            wrong) cp "$STUB/wrong.json" "$STUB/state.json" ;;
            *) cp "$STUB/recorded.json" "$STUB/state.json" ;;
        esac
        exit 0 ;;
    *polaris-database-settings/1*)
        [ "${STUB_READ:-ok}" = fail ] && { echo 'ERROR:  permission denied for table pg_db_role_setting' >&2; exit 1; }
        cat "$STUB/state.json"; exit 0 ;;
    *information_schema.tables*) echo 0; exit 0 ;;
    *to_regclass*) echo t; exit 0 ;;
    *relacl*) printf 'relation identitytoken\trelation identitytoken\t-\n'; exit 0 ;;
esac
exit 0
"""
PG_RESTORE = r"""#!/bin/sh
echo "$*" >> "$STUB/pg_restore.log"
case "$*" in *" -l "*) echo "1; 1259 16385 TABLE public identitytoken postgres" ;; esac
exit 0
"""
PG_DUMP = "#!/bin/sh\nprintf 'PGDMP stand-in dump'\n"
DOCKER = "#!/bin/sh\necho \"$*\" >> \"$STUB/docker.log\"\nexit 99\n"


class _Stubbed(unittest.TestCase):

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-settings-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.stub = self.tmp / "stub"
        self.bin = self.tmp / "bin"
        self.stub.mkdir()
        self.bin.mkdir()
        for name, text in (("psql", PSQL), ("pg_restore", PG_RESTORE), ("pg_dump", PG_DUMP), ("docker", DOCKER)):
            (self.bin / name).write_text(text)
            (self.bin / name).chmod(0o755)
        (self.bin / "python3").symlink_to(sys.executable)
        self.state(record([(None, "polaris.min_epoch_anonymity_set", "1"), (None, "work_mem", "1MB")]))

    def state(self, text):
        (self.stub / "state.json").write_text(text)

    def env(self, **extra):
        return dict({"PATH": "%s:/usr/bin:/bin:/usr/sbin:/sbin" % self.bin, "HOME": str(self.tmp),
                     "STUB": str(self.stub), "POLARIS_ENV_FILE": "", "PGUSER": "postgres"}, **extra)

    def tarball(self, settings_text=None, in_manifest=True, name="backup"):
        """A backup laid out as polaris-backup.sh lays it out: polaris-<ts>/ with the dump, the
        settings file when given, and a manifest of their hashes."""
        stage = self.tmp / name / "polaris-20261010T000000Z"
        stage.mkdir(parents=True)
        (stage / "polaris.dump").write_bytes(b"PGDMP stand-in dump")
        if settings_text is not None:
            (stage / "database-settings.json").write_text(settings_text)
            (self.stub / "recorded.json").write_text(settings_text)
        hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in stage.iterdir()
                  if in_manifest or p.name != "database-settings.json"}
        (stage / "MANIFEST.json").write_text(json.dumps({
            "timestamp_utc": "20261010T000000Z", "polaris_version": "8.77", "sha256": hashes,
            "size_bytes": {k: 1 for k in hashes}}))
        out = self.tmp / name / "polaris-20261010T000000Z.tar.gz"
        with tarfile.open(out, "w:gz") as tar:
            tar.add(stage, arcname=stage.name)
        return out

    def restore(self, tarball, *args, **env):
        return subprocess.run(["bash", str(SCRIPTS / "polaris-restore.sh"), str(tarball), "--target=polaris_t", *args],
                              capture_output=True, text=True, timeout=120, env=self.env(**env))

    def log(self, name):
        p = self.stub / name
        return p.read_text() if p.exists() else ""


class TheRestore(_Stubbed):

    def test_the_backups_settings_replace_the_targets_and_are_read_back(self):
        r = self.restore(self.tarball(record(SOURCE)))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("the backup's database settings, restored: 5", r.stdout)
        replay = self.log("replay.sql")
        self.assertIn("ALTER DATABASE \"polaris_t\" SET \"polaris.min_epoch_anonymity_set\" TO '25';", replay)
        self.assertIn("ALTER ROLE \"polaris_app\" IN DATABASE \"polaris_t\" SET \"statement_timeout\" TO '7s';", replay)
        self.assertIn("polaris_t\tDO $reset$", self.log("psql.log"), "the replay ran on another database")
        self.assertEqual(settings.load((self.stub / "state.json").read_text()), SOURCE)
        self.assertIn("the backup's privileges, restored", r.stdout, "the privilege check must still run after")
        self.assertLess(r.stdout.index("4.2/6"), r.stdout.index("4.5/6"))

    def test_settings_that_cannot_be_applied_stop_the_restore(self):
        before = (self.stub / "state.json").read_text()
        r = self.restore(self.tarball(record(SOURCE)), STUB_APPLY="fail")
        self.assertEqual(r.returncode, EXIT_SETTINGS_MISMATCH, r.stdout + r.stderr)
        self.assertIn("could not be applied to 'polaris_t', which keeps its own", r.stderr)
        self.assertIn('role "no_such_role" does not exist', r.stderr)
        self.assertNotIn("4.5/6", r.stdout, "a restore whose settings failed went on")
        self.assertEqual((self.stub / "state.json").read_text(), before)

    def test_settings_that_read_back_otherwise_stop_the_restore(self):
        (self.stub / "wrong.json").write_text(record(SOURCE[:3] + [(None, "polaris.min_epoch_anonymity_set", "1")]))
        r = self.restore(self.tarball(record(SOURCE)), STUB_APPLY="wrong")
        self.assertEqual(r.returncode, EXIT_SETTINGS_MISMATCH, r.stdout + r.stderr)
        self.assertIn("the restored database settings are not the backup's", r.stderr)
        self.assertIn("the database's polaris.min_epoch_anonymity_set: restored 1, the backup 25", r.stderr)
        self.assertIn("role polaris_app's statement_timeout: missing after the restore (the backup: 7s)", r.stderr)
        self.assertNotIn("4.5/6", r.stdout)

    def test_settings_that_cannot_be_read_back_are_an_unverified_restore(self):
        r = self.restore(self.tarball(record(SOURCE)), STUB_READ="fail")
        self.assertEqual(r.returncode, EXIT_SETTINGS_MISMATCH, r.stdout + r.stderr)
        self.assertIn("cannot read 'polaris_t's database settings, so the restore is unverified", r.stderr)

    def test_a_file_that_cannot_be_used_is_refused_before_the_target_is_touched(self):
        for case, text in (("another format", record(SOURCE).replace("/1", "/9")), ("not JSON", "{"),
                           ("a broken list", record([(None, "search_path", '"unbalanced')]))):
            with self.subTest(case):
                for f in ("psql.log", "replay.sql"):
                    (self.stub / f).unlink(missing_ok=True)
                r = self.restore(self.tarball(text, name=case.replace(" ", "-")))
                self.assertEqual(r.returncode, EXIT_SETTINGS_MISMATCH, r.stdout + r.stderr)
                self.assertIn("the backup's database settings cannot be read, so they were not restored", r.stderr)
                self.assertNotIn("DO $reset$", self.log("psql.log"))

    def test_a_record_of_no_settings_is_refused_before_the_target_is_touched(self):
        """Every Polaris database carries 09_grants.sql's settings: none is a reading that saw nothing,
        and replaying it would reset the target's to none."""
        before = (self.stub / "state.json").read_text()
        r = self.restore(self.tarball(record([])))
        self.assertEqual(r.returncode, EXIT_SETTINGS_MISMATCH, r.stdout + r.stderr)
        self.assertIn("the backup records no database settings, so the target's would be reset to none", r.stderr)
        self.assertNotIn("DO $reset$", self.log("psql.log"))
        self.assertEqual((self.stub / "state.json").read_text(), before)
        self.assertNotIn("4.5/6", r.stdout)

    def test_a_settings_file_the_manifest_does_not_cover_is_refused(self):
        r = self.restore(self.tarball(record(SOURCE), in_manifest=False))
        self.assertEqual(r.returncode, EXIT_MANIFEST_VERIFY_FAIL, r.stdout + r.stderr)
        self.assertIn("database-settings.json is not covered by the manifest", r.stdout)
        self.assertEqual(self.log("pg_restore.log"), "", "the restore went on")

    def test_an_older_backup_restores_as_before_and_says_so(self):
        before = (self.stub / "state.json").read_text()
        r = self.restore(self.tarball(None))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("this backup records no database settings (taken before 2026-10-10): 'polaris_t' keeps its own",
                      r.stdout)
        self.assertNotIn("DO $reset$", self.log("psql.log"))
        self.assertEqual((self.stub / "state.json").read_text(), before)

    def test_the_dry_run_says_what_it_would_do(self):
        r = self.restore(self.tarball(record(SOURCE)), "--dry-run")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("database settings (database-settings.json)  →  database 'polaris_t', replacing its own", r.stdout)
        old = self.restore(self.tarball(None, name="old"), "--dry-run")
        self.assertIn("no database settings recorded (an older backup): 'polaris_t' keeps its own", old.stdout)
        self.assertEqual(self.log("psql.log"), "")


class TheBackup(_Stubbed):

    def backup(self, *args, **env):
        dest = self.tmp / "dest"
        r = subprocess.run(["bash", str(SCRIPTS / "polaris-backup.sh"), "--dest=%s" % dest, *args],
                           capture_output=True, text=True, timeout=120,
                           env=self.env(POLARIS_DB_NAME="polaris_src", **env))
        return r, dest

    def test_the_settings_are_recorded_under_the_manifest_and_restore(self):
        self.state(record(SOURCE, database="polaris_src"))
        r, dest = self.backup()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("5 database settings recorded", r.stdout)
        self.assertIn("polaris_src\t", self.log("psql.log"), "the settings were read from another database")
        tarballs = list(dest.glob("polaris-*.tar.gz"))
        self.assertEqual(len(tarballs), 1)
        with tarfile.open(tarballs[0]) as tar:
            names = {pathlib.PurePath(m.name).name: m for m in tar.getmembers()}
            text = tar.extractfile(names["database-settings.json"]).read()
            manifest = json.loads(tar.extractfile(names["MANIFEST.json"]).read())
        self.assertEqual(settings.load(text.decode()), SOURCE)
        self.assertEqual(manifest["sha256"]["database-settings.json"], hashlib.sha256(text).hexdigest())
        # The file the backup wrote is the one the restore replays.
        (self.stub / "recorded.json").write_bytes(text)
        self.state(record([]))
        rr = self.restore(tarballs[0])
        self.assertEqual(rr.returncode, 0, rr.stdout + rr.stderr)
        self.assertEqual(settings.load((self.stub / "state.json").read_text()), SOURCE)
        verify = subprocess.run(["bash", str(SCRIPTS / "polaris-backup.sh"), "--verify-latest", "--dest=%s" % dest],
                                capture_output=True, text=True, timeout=120, env=self.env())
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
        self.assertIn("✓ database-settings.json", verify.stdout)

    def test_settings_that_cannot_be_read_write_no_backup(self):
        r, dest = self.backup(STUB_READ="fail")
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        self.assertIn("could not be recorded, so a restore of this backup would lose them; no backup was written",
                      r.stderr)
        self.assertIn("permission denied", r.stderr)
        self.assertEqual(list(dest.glob("polaris-*")), [])

    def test_a_reading_of_no_settings_writes_no_backup(self):
        self.state(record([], database="polaris_src"))
        r, dest = self.backup()
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        self.assertIn("the database records no settings of its own (09_grants.sql sets four); no backup was written",
                      r.stderr)
        self.assertEqual(list(dest.glob("polaris-*")), [])

    def test_an_unusable_reading_writes_no_backup(self):
        self.state("not a settings record")
        r, dest = self.backup()
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        self.assertEqual(list(dest.glob("polaris-*")), [])

    def test_verify_refuses_a_settings_file_the_manifest_does_not_cover(self):
        dest = self.tmp / "dest"
        dest.mkdir()
        shutil.copy(self.tarball(record(SOURCE), in_manifest=False), dest)
        r = subprocess.run(["bash", str(SCRIPTS / "polaris-backup.sh"), "--verify-latest", "--dest=%s" % dest],
                           capture_output=True, text=True, timeout=120, env=self.env())
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("database-settings.json is not covered by the manifest", r.stdout)


if __name__ == "__main__":
    unittest.main()
