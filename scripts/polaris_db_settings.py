# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""A database's own settings, carried from a backup into a restore.

09_grants.sql binds settings to the database (ALTER DATABASE ... SET): the revocation bound and its
window, the UTC clock, the zero-knowledge anonymity floor; an operator may have changed them, or set
others per role (ALTER ROLE ... IN DATABASE ... SET). They live in pg_db_role_setting, beside the
database rather than in it, and pg_restore applies them only with --create, which polaris-restore.sh
does not use: it restores into a database that exists. Until 2026-10-10 a restore into a new
database lost all of them, and one into an initialised database kept that database's own.

polaris-backup.sh records them beside the dump (database-settings.json, under the manifest);
polaris-restore.sh makes the target's settings exactly the recorded ones and reads them back.

    python3 polaris_db_settings.py query                       the SQL that reads them, one JSON row
    python3 polaris_db_settings.py record  < QUERY-OUTPUT      the file, checked, on stdout
    python3 polaris_db_settings.py count   FILE                how many settings the file records
    python3 polaris_db_settings.py replay  FILE TARGET_DB      the SQL that makes TARGET_DB's settings the file's
    python3 polaris_db_settings.py compare FILE < QUERY-OUTPUT each difference; exit 1 when there is one

Exit 0 on success, 1 when a file or a reading cannot be used or differs, 2 on a usage error.
"""
import json
import sys

FORMAT = "polaris-database-settings/1"
FILENAME = "database-settings.json"
# The usage stands on its own: under python -OO the module docstring is None.
USAGE = """usage: polaris_db_settings.py query
       polaris_db_settings.py record  < QUERY-OUTPUT
       polaris_db_settings.py count   FILE
       polaris_db_settings.py replay  FILE TARGET_DB
       polaris_db_settings.py compare FILE < QUERY-OUTPUT
"""

# This database's rows of pg_db_role_setting, the database's own (role NULL) and each role's in it.
# A role setting whose role cannot be named (impossible: DROP ROLE removes its settings) reads as an
# empty name, which load() refuses rather than take for a database setting.
QUERY = """SELECT json_build_object(
         'format', '%s',
         'database', current_database(),
         'settings', coalesce((
             SELECT json_agg(json_build_object(
                        'role', CASE WHEN s.setrole = 0 THEN NULL ELSE coalesce(r.rolname::text, '') END,
                        'name', o.option_name,
                        'value', o.option_value)
                    ORDER BY CASE WHEN s.setrole = 0 THEN NULL ELSE coalesce(r.rolname::text, '') END NULLS FIRST,
                             o.option_name)
               FROM pg_db_role_setting s
               JOIN pg_database d ON d.oid = s.setdatabase
               LEFT JOIN pg_roles r ON r.oid = s.setrole
              CROSS JOIN LATERAL pg_options_to_table(s.setconfig) o
              WHERE d.datname = current_database()), '[]'::json))""" % FORMAT

# The target's settings set aside first, so that it ends with the backup's and no others: the ones
# an initialised database was given, or a sample's floor of one, would otherwise survive a backup
# that never had them.
RESET = """DO $reset$
DECLARE r record;
BEGIN
    EXECUTE format('ALTER DATABASE %I RESET ALL', current_database());
    FOR r IN
        SELECT s.setrole::regrole::text AS role
          FROM pg_db_role_setting s JOIN pg_database d ON d.oid = s.setdatabase
         WHERE d.datname = current_database() AND s.setrole <> 0
    LOOP
        EXECUTE format('ALTER ROLE %s IN DATABASE %I RESET ALL', r.role, current_database());
    END LOOP;
END
$reset$;"""

# The settings PostgreSQL stores as a list of quoted elements (GUC_LIST_QUOTE); pg_dump's
# variable_is_guc_list_quote() names the same six. Each element is replayed as a literal of its own.
LIST_QUOTE = frozenset(("local_preload_libraries", "search_path", "session_preload_libraries",
                        "shared_preload_libraries", "temp_tablespaces", "unix_socket_directories"))
_SPACE = " \t\n\v\f\r"   # C isspace(), as SplitGUCList reads it


class SettingsError(Exception):
    pass


def load(text):
    """The file's settings as (role, name, value) triples, role None for the database's own."""
    try:
        doc = json.loads(text)
    except ValueError as e:
        raise SettingsError("not JSON: %s" % e)
    if not isinstance(doc, dict):
        raise SettingsError("not a settings record")
    if doc.get("format") != FORMAT:
        raise SettingsError("format %r, not %r: written by another version of Polaris"
                            % (doc.get("format"), FORMAT))
    if not isinstance(doc.get("database"), str) or not isinstance(doc.get("settings"), list):
        raise SettingsError("a settings record names its database and lists its settings")
    out, seen = [], set()
    for i, s in enumerate(doc["settings"]):
        if not isinstance(s, dict) or set(s) != {"role", "name", "value"}:
            raise SettingsError("setting %d is not a role, a name and a value" % i)
        role, name, value = s["role"], s["name"], s["value"]
        if role is not None and not (isinstance(role, str) and role):
            raise SettingsError("setting %d names no role" % i)
        if not (isinstance(name, str) and name) or not isinstance(value, str):
            raise SettingsError("setting %d has no name or no text value" % i)
        if any("\x00" in t for t in (role or "", name, value)):
            raise SettingsError("setting %d holds a NUL byte" % i)
        key = (role, name.lower())   # setting names are case-insensitive
        if key in seen:
            raise SettingsError("setting %d repeats %s" % (i, describe(role, name)))
        seen.add(key)
        out.append((role, name, value))
    return out


def describe(role, name):
    return ("the database's %s" % name) if role is None else ("role %s's %s" % (role, name))


def ident(s):
    """A quoted identifier, as pg_dump's fmtId writes a setting's name: case and dots kept."""
    return '"' + s.replace('"', '""') + '"'


def literal(s):
    """A string literal, as quote_literal() writes it: read the same whatever standard_conforming_strings is."""
    q = s.replace("'", "''")
    if "\\" in s:
        return "E'" + q.replace("\\", "\\\\") + "'"
    return "'" + q + "'"


def split_guc_list(raw):
    """SplitGUCList (src/fe_utils/string_utils.c): a stored list value into its elements."""
    out, i, n = [], 0, len(raw)
    while i < n and raw[i] in _SPACE:
        i += 1
    if i == n:
        return out
    while True:
        if i < n and raw[i] == '"':
            parts, j = [], i + 1
            while True:
                k = raw.find('"', j)
                if k < 0:
                    raise SettingsError("unbalanced quotes in %r" % raw)
                parts.append(raw[j:k])
                if k + 1 < n and raw[k + 1] == '"':
                    parts.append('"')
                    j = k + 2
                    continue
                break
            item, i = "".join(parts), k + 1
        else:
            j = i
            while i < n and raw[i] != "," and raw[i] not in _SPACE:
                i += 1
            if i == j:
                raise SettingsError("an empty element in %r" % raw)
            item = raw[j:i]
        while i < n and raw[i] in _SPACE:
            i += 1
        out.append(item)
        if i == n:
            return out
        if raw[i] != ",":
            raise SettingsError("not a list: %r" % raw)
        i += 1
        while i < n and raw[i] in _SPACE:
            i += 1


def value_sql(name, value):
    if name.lower() in LIST_QUOTE:
        items = split_guc_list(value)
        if not items:
            raise SettingsError("%s holds an empty list, which SET cannot write" % name)
        return ", ".join(literal(x) for x in items)
    return literal(value)


def replay_sql(settings, target):
    """One script, one transaction under psql -c: the target's settings reset, then the recorded ones set."""
    lines = [RESET]
    for role, name, value in settings:
        scope = "DATABASE %s" % ident(target) if role is None else \
            "ROLE %s IN DATABASE %s" % (ident(role), ident(target))
        lines.append("ALTER %s SET %s TO %s;" % (scope, ident(name), value_sql(name, value)))
    return "\n".join(lines) + "\n"


def compare(recorded, restored):
    """Each difference between two lists of settings, compared both ways."""
    want = {(r, n.lower()): (r, n, v) for r, n, v in recorded}
    got = {(r, n.lower()): (r, n, v) for r, n, v in restored}
    diffs = []
    for key in sorted(set(want) | set(got), key=lambda k: (k[0] is not None, k[0] or "", k[1])):
        if key not in got:
            r, n, v = want[key]
            diffs.append("%s: missing after the restore (the backup: %s)" % (describe(r, n), v))
        elif key not in want:
            r, n, v = got[key]
            diffs.append("%s: restored %s, the backup none" % (describe(r, n), v))
        elif got[key][2] != want[key][2]:
            r, n, v = got[key]
            diffs.append("%s: restored %s, the backup %s" % (describe(r, n), v, want[key][2]))
    return diffs


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ""
    try:
        if cmd == "query" and len(argv) == 2:
            print(QUERY)
        elif cmd == "record" and len(argv) == 2:
            text = sys.stdin.read()
            load(text)
            print(json.dumps(json.loads(text), indent=2, sort_keys=True, ensure_ascii=True))
        elif cmd == "count" and len(argv) == 3:
            print(len(load(_read(argv[2]))))
        elif cmd == "replay" and len(argv) == 4:
            if not argv[3]:
                raise SettingsError("no target database")
            sys.stdout.write(replay_sql(load(_read(argv[2])), argv[3]))
        elif cmd == "compare" and len(argv) == 3:
            recorded = load(_read(argv[2]))
            try:
                restored = load(sys.stdin.read())
            except SettingsError as e:
                raise SettingsError("the restored database's settings could not be read: %s" % e)
            diffs = compare(recorded, restored)
            for d in diffs:
                print(d)
            return 1 if diffs else 0
        else:
            sys.stderr.write(USAGE)
            return 2
    except (SettingsError, ValueError, OSError) as e:
        sys.stderr.write("polaris_db_settings: %s\n" % e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
