#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""run_rp_as_polaris_rp.py - the relying-party test classes with the relying-party API connected
as polaris_rp (lab/strategy/002-relying-party-api-compartment.md, section 9, step 2).

LAB ONLY. Changes no product file; patches the imported modules in this process.

HOW IT MIRRORS scripts/polaris-app-role-suite.py. That script imports test_app, leaves the test
module's own helpers (fixtures, reloads, assertions) on the owner's configuration, and switches
the APPLICATION to polaris_app. This does the same, with one difference forced by the question:
the relying-party classes also drive operator routes (they log in, issue, revoke, close epochs
through /login, /tokens, /api/...), and in the split deployment those are served by the
operator service, not by the compartment. So the database login is chosen per request:

  * a request whose path starts with /api/v1/ is the relying-party service: polaris_rp;
  * every other request, and every fixture outside a request, keeps the owner, exactly as the
    ordinary suite runs it; so any new failure is attributable to polaris_rp.

get_db is replaced in app.py, rp_api.py and auth_routes.py (they bind it by name). A duress
recording spawned on a background thread from an /api/v1 request inherits polaris_rp (the
thread carries the role it was spawned under).

MODES
  --mode owner   baseline: every request as the owner (what the ordinary suite does).
  --mode asis    every /api/v1/* request as polaris_rp, code as it stands. Measures the surface.
  --mode split   the deployment the strategy proposes: the two login-gated /api/v1 routes
                 (POST /api/v1/exchange-receipt/<id> and POST /api/v1/sign/<id>, which require
                 an operator session) are routed to the operator service (owner), and the
                 relying-party service honours no operator session cookie (the session hook
                 is a no-op for requests it serves, as it would be for a service that does not
                 hold the operator session secret).

INSTRUMENT. Every statement refused with SQLSTATE 42501 (insufficient_privilege) on a polaris_rp
connection is recorded with the test, endpoint, method, path and statement, INCLUDING refusals
the application swallows (security._audit, the duress thread). That list, not the test verdict,
is the measurement: a swallowed refusal passes its test and fails in the deployment.

    POLARIS_DB_HOST=localhost POLARIS_DB_NAME=polaris_rpcomp POLARIS_DB_USER=vanta \\
    POLARIS_TEST_RELOAD_USER=vanta POLARIS_SECRET_KEY=local-test-secret-key-32-bytes-long \\
    POLARIS_STATE_DIR=/tmp/polaris-state-rpcomp POLARIS_PQC_PROFILE=placeholder \\
    ~/.local/share/polaris-venv312/bin/python lab/strategy/002/run_rp_as_polaris_rp.py --mode split

Writes lab/strategy/002/out/<mode>.json (per-test verdicts and every refusal).
"""
import argparse
import json
import os
import subprocess
import sys
import threading
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
WEB = os.path.join(REPO, 'polaris_web')

#: Every class in test_app.py whose tests call an /api/v1/... route (grep of the literal path,
#: 2026-09-27). Some also drive operator routes; those requests stay on the owner.
RP_CLASSES = [
    'ExchangeReceiptSignedTests', 'ExchangeReceiptLogTests', 'TimestampLogTests', 'RegistryTests',
    'ExchangeGatewayTests', 'DocumentSigningTests', 'AuthBrokerTests', 'ZKSnarkTests',
    'TransparencyProofBoundsTests', 'F03_RateLimitingTests', 'JsonRouteTotalityTests',
    'RouteGuardMatrixTests', 'CrossSiteDefenceMatrixTests', 'EndToEndFlowTests',
    'RelyingPartyApiTests', 'HolderKeyBindingTests', 'OfflineStatusAssertionTests',
    'FederationManifestTests', 'EpochRevocationTests', 'StatusBundleTests',
    'OperatorAuthorityScopeTests', 'RefusalsTheAppMutationDrillFound',
]

#: The two /api/v1 routes that require an operator session (login_required + csrf_protect).
OPERATOR_ENDPOINTS = {'api_v1_exchange_receipt', 'api_v1_sign'}

RP_ROLE = dict(user='polaris_rp', password=os.environ.get('POLARIS_RP_PASSWORD', 'polaris_rp_lab'))


def snapshot():
    out = subprocess.run(
        ['psql', '-h', os.environ.get('POLARIS_DB_HOST', 'localhost'), '-U',
         os.environ.get('POLARIS_TEST_RELOAD_USER', 'vanta'), '-d', os.environ['POLARIS_DB_NAME'],
         '-Atf', os.path.join(HERE, 'privilege_snapshot.sql')],
        capture_output=True, text=True, check=True)
    return out.stdout.splitlines()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--mode', choices=('owner', 'asis', 'split'), default='split')
    ap.add_argument('--only', help='comma-separated class names (default: every RP class)')
    args = ap.parse_args()

    if os.environ.get('POLARIS_DB_NAME') != 'polaris_rpcomp':
        print('refusing: POLARIS_DB_NAME must be polaris_rpcomp (reload_sample_data reloads it)')
        return 2

    os.chdir(WEB)
    sys.path.insert(0, WEB)
    import psycopg2
    import psycopg2.errors
    from psycopg2.extras import RealDictCursor
    from flask import has_request_context, request
    import test_app as T
    import app as A
    import rp_api
    import auth_routes

    owner_cfg = dict(A.DB_CONFIG)
    rp_cfg = dict(owner_cfg, **RP_ROLE)
    psycopg2.connect(**rp_cfg).close()           # fail early if the role cannot connect

    # The test module's helpers keep the owner's configuration (a private copy, as the
    # app-role suite does), whatever the application does.
    T.DB_CONFIG = dict(owner_cfg)

    refusals = []
    rp_connections = {}
    state = {'test': None}
    tls = threading.local()

    def request_role():
        forced = getattr(tls, 'role', None)
        if forced:
            return forced
        if args.mode == 'owner' or not has_request_context():
            return 'owner'
        if not request.path.startswith('/api/v1/'):
            return 'owner'
        if args.mode == 'split' and request.endpoint in OPERATOR_ENDPOINTS:
            return 'owner'
        return 'rp'

    def where():
        if has_request_context():
            return dict(endpoint=request.endpoint, method=request.method, path=request.path)
        return dict(endpoint=getattr(tls, 'endpoint', None), method=None, path='(background thread)')

    class RecordingCursor(RealDictCursor):
        def execute(self, sql, vars=None):
            try:
                return super().execute(sql, vars)
            except psycopg2.errors.InsufficientPrivilege as e:
                if getattr(self.connection, '_polaris_role', None) == 'rp':
                    refusals.append(dict(test=state['test'], statement=' '.join(str(sql).split())[:300],
                                         error=str(e).strip().splitlines()[0], **where()))
                raise

    # A plain psycopg2 connection takes no new attributes; a subclass can carry the role tag.
    class _Conn(psycopg2.extensions.connection):
        pass

    def get_db(readonly=False):
        role = request_role()
        cfg = rp_cfg if role == 'rp' else owner_cfg
        conn = psycopg2.connect(connection_factory=_Conn, cursor_factory=RecordingCursor, **cfg)
        conn._polaris_role = role
        if role == 'rp':
            ep = request.endpoint if has_request_context() else getattr(tls, 'endpoint', None)
            rp_connections[ep] = rp_connections.get(ep, 0) + 1
        A._apply_operator_scope(conn)
        return conn

    if args.mode != 'owner':
        A.get_db = get_db
        rp_api.get_db = get_db
        auth_routes.get_db = get_db

        # A thread spawned during a request (the duress recording) carries its spawner's role.
        real_threading = A.threading

        class Thread(real_threading.Thread):
            def __init__(self, *a, target=None, **kw):
                role = request_role()
                ep = request.endpoint if has_request_context() else None

                def run_as(*ta, **tk):
                    tls.role, tls.endpoint = role, ep
                    return target(*ta, **tk)
                super().__init__(*a, target=run_as, **kw)

        shim = types.ModuleType('threading_shim')
        shim.__dict__.update({k: getattr(real_threading, k) for k in dir(real_threading)
                              if not k.startswith('__')})
        shim.Thread = Thread
        A.threading = shim

    if args.mode == 'split':
        real_validate = A.security.validate_session

        def validate_session(get_conn):
            if request_role() == 'rp':
                return None       # the relying-party service holds no operator session secret
            return real_validate(get_conn)
        A.security.validate_session = validate_session

    before = snapshot()

    names = args.only.split(',') if args.only else RP_CLASSES
    suite = unittest.TestSuite()
    for n in names:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(getattr(T, n)))

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            state['test'] = test.id().split('.', 1)[-1]
            super().startTest(test)

    with open(os.devnull, 'w') as sink:
        result = unittest.TextTestRunner(verbosity=0, stream=sink, resultclass=Result).run(suite)

    after = snapshot()

    per_class = {}
    bad_ids = {t.id(): tb for t, tb in result.failures + result.errors}
    skipped = {t.id() for t, _ in result.skipped}
    for n in names:
        for t in unittest.defaultTestLoader.loadTestsFromTestCase(getattr(T, n)):
            c = per_class.setdefault(n, {'pass': 0, 'fail': 0, 'skip': 0})
            if t.id() in bad_ids:
                c['fail'] += 1
            elif t.id() in skipped:
                c['skip'] += 1
            else:
                c['pass'] += 1

    failures = []
    for tid, tb in bad_ids.items():
        last = [line for line in tb.strip().splitlines() if line.strip()][-1]
        failures.append(dict(test=tid.split('.', 1)[-1], last=last[:300]))

    os.makedirs(os.path.join(HERE, 'out'), exist_ok=True)
    out = dict(mode=args.mode, tests_run=result.testsRun, failed=len(bad_ids), skipped=len(skipped),
               per_class=per_class, failures=sorted(failures, key=lambda f: f['test']),
               refusals=refusals, rp_connections_by_endpoint=rp_connections, grants_unchanged_by_reloads=(before == after),
               grant_lines=len(after))
    with open(os.path.join(HERE, 'out', '%s.json' % args.mode), 'w') as f:
        json.dump(out, f, indent=1, default=str)

    print('mode=%s: %d tests, %d failed, %d skipped; %d privilege refusals on polaris_rp; '
          'grants unchanged by reloads: %s'
          % (args.mode, result.testsRun, len(bad_ids), len(skipped), len(refusals), before == after))
    print('  polaris_rp connections: %d, across %d endpoints' % (sum(rp_connections.values()), len(rp_connections)))
    for n, c in per_class.items():
        print('  %-36s pass %3d  fail %3d  skip %3d' % (n, c['pass'], c['fail'], c['skip']))
    for f in out['failures']:
        print('  FAIL %s\n       %s' % (f['test'], f['last'][:200]))
    distinct = {}
    for r in refusals:
        distinct.setdefault((r['endpoint'], r['statement'][:120], r['error']), []).append(r['test'])
    for (ep, st, err), tests in sorted(distinct.items(), key=lambda kv: str(kv[0])):
        print('  REFUSED endpoint=%s (%d times, e.g. %s)\n      %s\n      %s' % (ep, len(tests), tests[0], err, st))
    return 0 if not bad_ids and not refusals else 1


if __name__ == '__main__':
    sys.exit(main())
