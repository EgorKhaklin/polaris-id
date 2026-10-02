# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris_web/athena_selftest.py -- Athena's self-test (lab/strategy/009, step B2).

The constraint board (athena_board.py) says what the catalogue holds. It cannot say that a
mechanism refuses: a trigger whose function had been rewritten to let writes through still reads
as present. This attempts the forbidden writes themselves and shows what refused each one.

HOW IT CANNOT WRITE. Every probe runs on the application's own connection, the role this
application uses for everything, inside one transaction that is always rolled back, each probe
inside a SAVEPOINT that is rolled back too, whether the database refused it or accepted it. A
probe aims at a row that already exists, changed to a value that is wrong only because a rule
forbids it, or inserts a row a rule must refuse. What survives the rollback: a sequence a refused
insert advanced (sequences are not transactional), and the database's log lines for the refusals,
written under application_name polaris-athena-selftest. Nothing else.

WHAT A RESULT MEANS. "Refused" names what refused (the privilege boundary, a constraint, an
index or a trigger function, read from the error the database raised) beside what was expected.
"Accepted" means the database let the forbidden write through. Some rules deliberately do not bind
the schema owner (the owner runs the issuance and recovery procedures and the migrations); when
this application connects as the owner, those probes are accepted and say why, which is itself
the finding: in production the application connects as polaris_app.

What leaves this module: each probe's name, its expectation, the SQLSTATE, what refused it and the
database's message with every number masked. No row value is read back.
"""
import re

import psycopg2

#: A probe: the rule it tests, what it attempts, how it finds its target (a query returning one
#: row of parameters, or nothing), the forbidden statement, what should refuse it, and whether the
#: rule binds the schema owner.
PROBES = (
    {
        'rule': 'C1',
        'attempt': 'Change a recorded verification',
        'target': "SELECT max(event_id) AS id FROM VerificationEvent",
        'sql': "UPDATE VerificationEvent SET outcome = outcome WHERE event_id = %(id)s",
        'expected': ('privilege', 'reject_audit_modification'),
        'expected_text': 'the privilege boundary or reject_audit_modification',
        'owner_exempt': False,
    },
    {
        'rule': 'C2',
        'attempt': 'Record a zero-knowledge verification that names a credential',
        'target': ("SELECT (SELECT max(token_id) FROM IdentityToken) AS token, "
                   "(SELECT min(agency_id) FROM Agency) AS agency, "
                   "(SELECT min(context_id) FROM VerificationContext) AS context"),
        'sql': ("INSERT INTO VerificationEvent (token_id, requesting_agency_id, context_id, outcome, "
                "disclosure_level) VALUES (%(token)s, %(agency)s, %(context)s, 'FAILURE', 'ZERO_KNOWLEDGE')"),
        'expected': ('chk_disclosure_token_consistency',),
        'expected_text': 'chk_disclosure_token_consistency',
        'owner_exempt': False,
    },
    {
        'rule': 'C3',
        'attempt': 'Make a second credential ACTIVE for one person',
        'target': ("SELECT r.token_id AS token FROM IdentityToken r "
                   "WHERE r.status = 'RESERVE' AND (r.expiration_date IS NULL OR r.expiration_date > now()) "
                   "AND EXISTS (SELECT 1 FROM IdentityToken a WHERE a.individual_id = r.individual_id "
                   "AND a.status = 'ACTIVE') ORDER BY r.token_id LIMIT 1"),
        'sql': "UPDATE IdentityToken SET status = 'ACTIVE', activated_date = now() WHERE token_id = %(token)s",
        'expected': ('uq_one_active_per_person',),
        'expected_text': 'uq_one_active_per_person',
        'owner_exempt': False,
    },
    {
        'rule': 'Success rules',
        'attempt': 'Record a SUCCESS for a revoked credential',
        'target': ("SELECT (SELECT max(token_id) FROM IdentityToken WHERE status = 'REVOKED') AS token, "
                   "(SELECT min(agency_id) FROM Agency) AS agency, "
                   "(SELECT min(context_id) FROM VerificationContext) AS context"),
        'sql': ("INSERT INTO VerificationEvent (token_id, requesting_agency_id, context_id, outcome, "
                "disclosure_level) VALUES (%(token)s, %(agency)s, %(context)s, 'SUCCESS', 'SELECTIVE')"),
        'expected': ('enforce_verification_success_rules',),
        'expected_text': 'enforce_verification_success_rules',
        'owner_exempt': True,
    },
    {
        'rule': 'Binding',
        'attempt': 'Move a credential to another holder',
        'target': ("SELECT t.token_id AS token, (SELECT min(i.individual_id) FROM Individual i "
                   "WHERE i.individual_id <> t.individual_id) AS other "
                   "FROM IdentityToken t ORDER BY t.token_id DESC LIMIT 1"),
        'sql': "UPDATE IdentityToken SET individual_id = %(other)s WHERE token_id = %(token)s",
        'expected': ('privilege', 'enforce_token_binding_owner_only'),
        'expected_text': 'enforce_token_binding_owner_only',
        'owner_exempt': True,
    },
    {
        'rule': 'Privilege',
        'attempt': 'Write a duress record directly, outside its procedure',
        'target': ("SELECT (SELECT max(token_id) FROM IdentityToken) AS token, "
                   "(SELECT min(agency_id) FROM Agency) AS agency, "
                   "(SELECT min(context_id) FROM VerificationContext) AS context"),
        'sql': ("INSERT INTO DuressEvent (token_id, context_id, requesting_agency_id) "
                "VALUES (%(token)s, %(context)s, %(agency)s)"),
        'expected': ('privilege',),
        'expected_text': 'the privilege boundary',
        'owner_exempt': True,
    },
)

#: How long one probe may take, and how long it may wait for a lock another session holds: a probe
#: that would wait gives up rather than queue behind real work.
_STATEMENT_TIMEOUT_MS = 3000
_LOCK_TIMEOUT_MS = 500


def _mask(text):
    """The database's message with every standalone number masked: a credential number in a
    trigger's message is a value a probe read, and the page shows no value. A number inside a name
    (a partition's verificationevent_2026_10, "Phase 2b") is not a value and is kept."""
    return re.sub(r'\b\d+\b', '#', (text or '').strip())[:220]


def _refused_by(error):
    """What refused a statement, from the error the database raised."""
    diag = error.diag
    function = re.search(r'PL/pgSQL function (\w+)\(', diag.context or '')
    if function:
        return function.group(1)
    if diag.constraint_name:
        return diag.constraint_name
    if error.pgcode == '42501':
        return 'privilege'
    return error.pgcode or 'unknown'


def _run_probe(cur, probe, is_owner):
    out = {'rule': probe['rule'], 'attempt': probe['attempt'], 'expected': probe['expected_text'],
           'sqlstate': None, 'refused_by': None, 'message': None}
    cur.execute("SAVEPOINT athena_probe")
    try:
        try:
            cur.execute(probe['target'])
            params = cur.fetchone()
        except psycopg2.Error as error:
            out.update(status='inconclusive', message='its target could not be read: ' + _mask(
                error.diag.message_primary))
            return out
        if params is None or any(v is None for v in params.values()):
            out.update(status='inconclusive', message='there is no row for it to aim at in this database')
            return out
        try:
            cur.execute(probe['sql'], params)
        except psycopg2.Error as error:
            by = _refused_by(error)
            out.update(sqlstate=error.pgcode, refused_by='the privilege boundary' if by == 'privilege' else by,
                       message=_mask(error.diag.message_primary),
                       status='refused' if by in probe['expected'] else 'refused_otherwise')
            return out
        out.update(status='owner_exempt' if (is_owner and probe['owner_exempt']) else 'accepted')
        return out
    finally:
        # Whatever happened, the probe's effect goes: the savepoint is rolled back here, and the
        # transaction it sits in is rolled back by run().
        cur.execute("ROLLBACK TO SAVEPOINT athena_probe")


def run(conn):
    """Run every probe on `conn` and roll everything back. `conn` is the application's own
    connection (app.get_db()); this function closes it."""
    try:
        with conn.cursor() as cur:
            cur.execute("SET LOCAL statement_timeout = %s", (str(_STATEMENT_TIMEOUT_MS),))
            cur.execute("SET LOCAL lock_timeout = %s", (str(_LOCK_TIMEOUT_MS),))
            cur.execute("SET LOCAL application_name = 'polaris-athena-selftest'")
            cur.execute("SELECT current_user::text AS role, "
                        "pg_get_userbyid((SELECT relowner FROM pg_class WHERE oid = 'verificationevent'::regclass))::text "
                        "AS owner, now() AS at")
            who = cur.fetchone()
            is_owner = who['role'] == who['owner']
            probes = [_run_probe(cur, p, is_owner) for p in PROBES]
    finally:
        conn.rollback()
        conn.close()
    def count(status):
        return sum(p['status'] == status for p in probes)
    return {'role': who['role'], 'is_owner': is_owner, 'at': who['at'], 'probes': probes,
            'held': count('refused'), 'failed': count('accepted'), 'exempt': count('owner_exempt'),
            'otherwise': count('refused_otherwise'), 'not_run': count('inconclusive')}
