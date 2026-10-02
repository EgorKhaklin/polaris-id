# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris_web/athena_board.py -- Athena's constraint board (lab/strategy/009, step B1).

Each mechanism athena_rule_enforcement names is looked up in the catalogue of the database this
application is connected to, when the page is read. Until this board the console showed the
curated rows and called them live; the check behind them reads the repository, so a database
built from an older schema, a trigger switched off or an index left invalid showed the same page.

WHAT IT CAN SAY. A trigger is present, switched on, and fires at the time and on the events the
catalogue records; a CHECK constraint is present and validated; an index is present, valid and
unique; a routine is present. That is the catalogue's word for "in force", and the board shows
the definition the database holds beside it.

WHAT IT CANNOT. Present and switched on is not refusing: a trigger whose function was rewritten
to let writes through still reads as present here. Two rules live in the running application,
not the database (C5's script policy, C8's caps); the board reads those from this application
and labels them so. The rest are repository checks, which run on every change and read the
repository, not this database; the board names them and claims nothing about them.

It reads the catalogue and the curated rows only, never a table that holds a person;
check_athena_console holds this module to that.
"""
from flask import Response

import security

#: pg_trigger.tgtype bits (src/include/catalog/pg_trigger.h).
_ROW, _BEFORE, _INSERT, _DELETE, _UPDATE, _TRUNCATE, _INSTEAD = 1, 2, 4, 8, 16, 32, 64

#: A trigger fires in an ordinary session when it is enabled for origin ('O') or always ('A').
#: 'D' is disabled, and 'R' fires only under session_replication_role = replica.
_FIRES = ('O', 'A')


def _trigger_shape(tgtype):
    timing = 'INSTEAD OF' if tgtype & _INSTEAD else ('BEFORE' if tgtype & _BEFORE else 'AFTER')
    events = [name for bit, name in ((_INSERT, 'INSERT'), (_UPDATE, 'UPDATE'),
                                     (_DELETE, 'DELETE'), (_TRUNCATE, 'TRUNCATE')) if tgtype & bit]
    return '%s %s, %s' % (timing, ' OR '.join(events), 'each row' if tgtype & _ROW else 'each statement')


#: How each kind of mechanism is named on the page.
KIND_LABELS = {
    'TRIGGER': 'Trigger', 'CHECK_CONSTRAINT': 'CHECK constraint', 'INDEX': 'Unique index',
    'PROCEDURE': 'Routine', 'CHECK_FUNCTION': 'Repository check',
    'RESPONSE_POLICY': 'Response policy', 'APPLICATION_CAP': 'Application caps',
}


def _mechanism(row, status, source, detail=None, definition=None, reason=None):
    return dict(kind=row['mechanism_kind'], label=KIND_LABELS.get(row['mechanism_kind'], row['mechanism_kind']),
                name=row['mechanism_name'], note=row['note'], status=status, source=source,
                detail=detail, definition=definition, reason=reason)


def _triggers(query, names):
    """The triggers called one of `names`, or running a function called one of them."""
    if not names:
        return [], set()
    rows = query("""
        SELECT t.tgname, t.tgenabled::text AS tgenabled, t.tgtype, c.relname AS table_name,
               t.tgparentid <> 0 AS is_clone,
               p.proname AS function_name, pg_get_triggerdef(t.oid) AS definition
          FROM pg_trigger t
          JOIN pg_class c ON c.oid = t.tgrelid
          JOIN pg_proc  p ON p.oid = t.tgfoid
         WHERE NOT t.tgisinternal AND (t.tgname = ANY(%s) OR p.proname = ANY(%s))
         ORDER BY c.relname, t.tgname
    """, (names, names))
    functions = {r['proname'] for r in query(
        "SELECT proname FROM pg_proc WHERE proname = ANY(%s)", (names,))}
    return rows, functions


def _database_mechanism(row, catalog):
    kind, name = row['mechanism_kind'], row['mechanism_name']
    if kind == 'TRIGGER':
        # A partitioned table's trigger is cloned onto every partition, and a clone can be
        # switched off on its own: the line is the table's, the verdict covers every clone.
        named = [t for t in catalog['triggers'] if t['tgname'] == name]
        if named:
            tables = [t for t in named if not t['is_clone']] or named
            off = [t for t in named if t['tgenabled'] not in _FIRES]
            detail = '; '.join('%s on %s' % (_trigger_shape(t['tgtype']), t['table_name']) for t in tables)
            if len(named) > len(tables):
                detail += ' and its %d partition%s' % (len(named) - len(tables), '' if len(named) - len(tables) == 1 else 's')
            if off:
                return _mechanism(row, 'not_in_force', 'database', detail, tables[0]['definition'],
                                  'switched off on ' + ', '.join(t['table_name'] for t in off))
            return _mechanism(row, 'in_force', 'database', detail, tables[0]['definition'])
        if name in catalog['functions']:
            using = [t for t in catalog['triggers'] if t['function_name'] == name and not t['is_clone']]
            firing = [t for t in using if t['tgenabled'] in _FIRES]
            if not firing:
                return _mechanism(row, 'not_in_force', 'database', None, None,
                                  'the function is present and no switched-on trigger runs it')
            return _mechanism(row, 'in_force', 'database',
                              'runs %d switched-on trigger%s' % (len(firing), '' if len(firing) == 1 else 's'))
        return _mechanism(row, 'not_in_force', 'database', None, None, 'absent from this database')
    if kind == 'CHECK_CONSTRAINT':
        # A constraint on a partitioned table is inherited by every partition: the line names the
        # table it was declared on, and the verdict covers every copy.
        copies = catalog['constraints'].get(name, [])
        if not copies:
            return _mechanism(row, 'not_in_force', 'database', None, None, 'absent from this database')
        tables = [c for c in copies if c['inherited'] == 0] or copies
        detail = 'on ' + ', '.join(c['table_name'] for c in tables)
        if len(copies) > len(tables):
            detail += ' and its %d partition%s' % (len(copies) - len(tables), '' if len(copies) - len(tables) == 1 else 's')
        loose = [c['table_name'] for c in copies if not c['convalidated']]
        if loose:
            return _mechanism(row, 'not_in_force', 'database', detail, tables[0]['definition'],
                              'not validated on %s: rows already stored there were never checked' % ', '.join(loose))
        return _mechanism(row, 'in_force', 'database', detail, tables[0]['definition'])
    if kind == 'INDEX':
        ix = catalog['indexes'].get(name)
        if ix is None:
            return _mechanism(row, 'not_in_force', 'database', None, None, 'absent from this database')
        detail = 'on %s' % ix['table_name']
        broken = [why for ok, why in ((ix['indisvalid'], 'not valid'), (ix['indisready'], 'not ready'),
                                      (ix['indislive'], 'being dropped'), (ix['indisunique'], 'not unique'))
                  if not ok]
        if broken:
            return _mechanism(row, 'not_in_force', 'database', detail, ix['definition'], ', '.join(broken))
        return _mechanism(row, 'in_force', 'database', detail, ix['definition'])
    if kind == 'PROCEDURE':
        if name in catalog['routines']:
            return _mechanism(row, 'in_force', 'database', 'a routine in this database')
        return _mechanism(row, 'not_in_force', 'database', None, None, 'absent from this database')
    # CHECK_FUNCTION: a repository check. It runs on every change and reads the repository.
    return _mechanism(row, 'repository', 'repository')


def _script_policy():
    """C5, from the response policy this application attaches to every page."""
    probe = Response()
    security.apply_security_headers(probe)
    csp = probe.headers.get('Content-Security-Policy', '')
    script = next((d.strip() for d in csp.split(';') if d.strip().startswith('script-src')), '')
    sources = script.split()[1:]
    loose = [s for s in sources if s in ("'unsafe-inline'", "'unsafe-eval'", '*', 'data:', 'http:', 'https:')]
    row = {'mechanism_kind': 'RESPONSE_POLICY', 'mechanism_name': 'Content-Security-Policy',
           'note': 'the header this application sends with every response'}
    if not script or loose:
        return _mechanism(row, 'not_in_force', 'application', script or None, csp or None,
                          'allows ' + ', '.join(loose) if loose else 'no script-src directive')
    return _mechanism(row, 'in_force', 'application', script, csp)


def _atlas_caps():
    """C8, from the clamps the Atlas routes of this application apply."""
    import atlas_routes   # registered by app.py at import; read at use time, never copied
    caps = sorted((k, v) for k, v in vars(atlas_routes).items() if k.startswith('_ATLAS_MAX_'))
    row = {'mechanism_kind': 'APPLICATION_CAP', 'mechanism_name': '_ATLAS_MAX_*',
           'note': 'the most rows any Atlas response carries, applied before the SQL runs'}
    bad = [k for k, v in caps if not isinstance(v, int) or v <= 0]
    detail = ', '.join('%s %s' % (k[len('_ATLAS_MAX_'):].lower(), '{:,}'.format(v) if isinstance(v, int) else v)
                       for k, v in caps)
    if not caps or bad:
        return _mechanism(row, 'not_in_force', 'application', detail or None, None,
                          'no cap is set' if not caps else 'not a positive limit: ' + ', '.join(bad))
    return _mechanism(row, 'in_force', 'application', detail)


#: The rules the running application enforces itself, read from it rather than from the database.
_APPLICATION = {'C5': _script_policy, 'C8': _atlas_caps}


def read_board(query):
    """The constitution as this database and this application hold it now.

    `query` is app.query: the reads go where the console's reads go, under the same scope."""
    rules = query(
        "SELECT rule_code, title, statement, layer FROM athena_constitutional_rule "
        "ORDER BY CASE layer WHEN 'CONSTITUTIONAL' THEN 1 WHEN 'ENGINEERING' THEN 2 ELSE 3 END, "
        "CASE WHEN rule_code = 'VOCATION' THEN 999 ELSE CAST(substring(rule_code FROM 2) AS INTEGER) END")
    rows = query("SELECT rule_code, mechanism_kind, mechanism_name, note FROM athena_rule_enforcement "
                 "ORDER BY rule_code, mechanism_kind, mechanism_name")
    def names(kind):
        return sorted({r['mechanism_name'] for r in rows if r['mechanism_kind'] == kind})
    triggers, functions = _triggers(query, names('TRIGGER'))
    catalog = {
        'triggers': triggers,
        'functions': functions,
        'constraints': {},
        'indexes': {r['index_name']: r for r in query("""
            SELECT ic.relname AS index_name, i.indisvalid, i.indisready, i.indislive, i.indisunique,
                   c.relname AS table_name, pg_get_indexdef(i.indexrelid) AS definition
              FROM pg_index i JOIN pg_class ic ON ic.oid = i.indexrelid
              JOIN pg_class c ON c.oid = i.indrelid
             WHERE ic.relname = ANY(%s)""", (names('INDEX'),))},
        'routines': {r['proname'] for r in query(
            "SELECT proname FROM pg_proc WHERE proname = ANY(%s)", (names('PROCEDURE'),))},
    }
    for r in query("""
            SELECT con.conname, con.convalidated, con.coninhcount AS inherited, c.relname AS table_name,
                   pg_get_constraintdef(con.oid) AS definition
              FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid
             WHERE con.conname = ANY(%s)
             ORDER BY con.coninhcount, c.relname""", (names('CHECK_CONSTRAINT'),)):
        catalog['constraints'].setdefault(r['conname'], []).append(r)
    at = query("SELECT now() AS at, current_database() AS database", fetch='one')

    by_rule = {}
    for r in rows:
        by_rule.setdefault(r['rule_code'], []).append(_database_mechanism(r, catalog))
    board, summary = [], {'in_force': 0, 'not_in_force': 0, 'application': 0, 'repository': 0}
    for rule in rules:
        mechanisms = by_rule.get(rule['rule_code'], [])
        if rule['rule_code'] in _APPLICATION:
            mechanisms = [_APPLICATION[rule['rule_code']]()] + mechanisms
        mechanisms.sort(key=lambda m: ({'database': 0, 'application': 1, 'repository': 2}[m['source']],
                                        m['status'] != 'not_in_force', m['name']))
        checked = [m for m in mechanisms if m['source'] != 'repository']
        if any(m['status'] == 'not_in_force' for m in checked):
            state = 'not_in_force'
        elif checked:
            state = 'in_force'
        else:
            state = 'repository'
        for m in mechanisms:
            key = 'application' if m['source'] == 'application' and m['status'] == 'in_force' else m['status']
            summary[key] += 1
        # A rule guarded table by table (C1: one trigger per audit-of-record table) reads as one
        # line with its list beneath, not as thirty rows; a table that lost its guard still
        # shows, first, in that list.
        guards = [m for m in mechanisms if m['kind'] == 'TRIGGER' and m['name'] not in functions]
        if len(guards) <= 3:
            guards = []
        guards.sort(key=lambda m: (m['status'] == 'in_force', m['name']))
        board.append(dict(rule, mechanisms=[m for m in mechanisms if m not in guards], guards=guards,
                          guards_held=sum(m['status'] == 'in_force' for m in guards), state=state,
                          checked=len(checked), held=sum(m['status'] == 'in_force' for m in checked)))
    return {'rules': board, 'summary': summary, 'verified_at': at['at'], 'database': at['database']}
