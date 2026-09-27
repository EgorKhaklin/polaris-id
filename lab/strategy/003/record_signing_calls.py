#!/usr/bin/env python3
"""record_signing_calls.py - every signing call the test suite makes, with the statement format
it signs and the surface that reached it (lab/strategy/003-signing-custody-compartment.md,
section 9, step 1 checked dynamically).

LAB ONLY. Changes no product file; wraps the signing entry points in this process.

WHAT IT WRAPS. pqc_signing.signature_over_message, signature_with_key_for_token,
signature_bytes_for_token, signature_for_migration and sign (the module is also imported as
polaris_web.pqc_signing by migration.py, so both module objects are patched), and every custody
driver's sign() (a signing path that bypassed pqc_signing would show up there). Under the
placeholder profile no custody driver signs, so the custody wrap can only show a path that
signs with a key even in development.

FORMAT. The `format` field when the message parses as a JSON object; `raw-token-value` for the
issuance and migration entry points (they sign SHA3-256(token_value), no format at all);
`bare-32-byte-digest` when signature_over_message is handed 32 opaque bytes (the verifiable
credential and mdoc call sites hash their document first); otherwise `unparsed`.

SURFACE, from the request that reached the call:
  rp          a request under /api/v1/ other than the two login-gated routes
  operator    any other request, and the two login-gated /api/v1 routes
  no-request  outside a request (a test calling a helper directly, the migration library)

    POLARIS_DB_HOST=localhost POLARIS_DB_NAME=polaris_signer POLARIS_DB_USER=vanta \\
    POLARIS_TEST_RELOAD_USER=vanta POLARIS_SECRET_KEY=local-test-secret-key-32-bytes-long \\
    POLARIS_STATE_DIR=/tmp/polaris-state-signer POLARIS_PQC_PROFILE=placeholder \\
    ~/.local/share/polaris-venv312/bin/python lab/strategy/003/record_signing_calls.py

Writes lab/strategy/003/out/recorded_calls.json.
"""
import collections
import json
import os
import sys
import traceback
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
WEB = os.path.join(REPO, 'polaris_web')

OPERATOR_ENDPOINTS = {'api_v1_exchange_receipt', 'api_v1_sign'}


def classify_message(msg):
    if isinstance(msg, (bytes, bytearray)) and len(msg) == 32:
        try:
            json.loads(bytes(msg))
        except Exception:
            return 'bare-32-byte-digest'
    try:
        obj = json.loads(bytes(msg))
        if isinstance(obj, dict) and isinstance(obj.get('format'), str):
            return obj['format']
    except Exception:
        pass
    return 'unparsed'


def main():
    if os.environ.get('POLARIS_DB_NAME') != 'polaris_signer':
        print('refusing: POLARIS_DB_NAME must be polaris_signer (the suite reloads it)')
        return 2
    os.chdir(WEB)
    sys.path.insert(0, WEB)
    sys.path.insert(0, REPO)
    from flask import has_request_context, request
    import pqc_signing
    import custody
    import test_app as T  # noqa: F401  (imports app and every route module)

    mods = [pqc_signing]
    try:
        import polaris_web.pqc_signing as pw_pqc
        if pw_pqc is not pqc_signing:
            mods.append(pw_pqc)
    except Exception:
        pass

    calls = []
    state = {'test': None}

    def surface():
        if not has_request_context():
            return 'no-request', None, None
        if request.path.startswith('/api/v1/') and request.endpoint not in OPERATOR_ENDPOINTS:
            return 'rp', request.endpoint, request.path
        return 'operator', request.endpoint, request.path

    def caller_chain():
        frames = traceback.extract_stack()[:-3]
        out = []
        for fr in reversed(frames):
            fn = os.path.basename(fr.filename)
            if fn in ('record_signing_calls.py', 'pqc_signing.py', 'custody.py'):
                continue
            if fn.startswith('test_') or 'unittest' in fr.filename or 'site-packages' in fr.filename:
                break
            out.append('%s:%s' % (fn, fr.name))
            if len(out) == 4:
                break
        return out

    def record(entry, fmt):
        s, ep, path = surface()
        calls.append(dict(test=state['test'], entry=entry, format=fmt, surface=s, endpoint=ep,
                          path=path, chain=caller_chain()))

    for m in mods:
        real_som = m.signature_over_message
        real_swk = m.signature_with_key_for_token
        real_sfm = m.signature_for_migration
        real_sign = m.sign

        def som(message, agency_id=None, _r=real_som):
            record('signature_over_message', classify_message(message))
            return _r(message, agency_id=agency_id)

        def swk(token_value, agency_id=None, _r=real_swk):
            record('signature_with_key_for_token', 'raw-token-value')
            return _r(token_value, agency_id=agency_id)

        def sfm(token_value, algorithm, agency_id=None, _r=real_sfm):
            record('signature_for_migration', 'raw-token-value')
            return _r(token_value, algorithm, agency_id=agency_id)

        def sgn(message, agency_id=None, _r=real_sign):
            record('sign', classify_message(message))
            return _r(message, agency_id=agency_id)

        m.signature_over_message, m.signature_with_key_for_token = som, swk
        m.signature_for_migration, m.sign = sfm, sgn

    for cls_name in dir(custody):
        cls = getattr(custody, cls_name)
        if isinstance(cls, type) and hasattr(cls, 'sign') and cls_name.endswith('Custody'):
            real = cls.sign

            def csign(self, digest, _r=real, _n=cls_name):
                record('custody.%s.sign' % _n, 'digest')
                return _r(self, digest)
            cls.sign = csign

    suite = unittest.defaultTestLoader.loadTestsFromModule(T)

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            state['test'] = test.id().split('.', 1)[-1]
            super().startTest(test)

    with open(os.devnull, 'w') as sink:
        result = unittest.TextTestRunner(verbosity=0, stream=sink, resultclass=Result).run(suite)

    agg = collections.Counter((c['entry'], c['format'], c['surface'], c['endpoint'] or '-',
                               ' < '.join(c['chain'][:2])) for c in calls)
    rows = [dict(entry=k[0], format=k[1], surface=k[2], endpoint=k[3], chain=k[4], count=v)
            for k, v in sorted(agg.items())]
    fails = [dict(test=t.id(), last=[x for x in tb.strip().splitlines() if x.strip()][-1][:300])
             for t, tb in result.failures + result.errors]
    os.makedirs(os.path.join(HERE, 'out'), exist_ok=True)
    with open(os.path.join(HERE, 'out', 'recorded_calls.json'), 'w') as f:
        json.dump(dict(tests_run=result.testsRun, failed=len(fails), skipped=len(result.skipped),
                       failures=fails, total_calls=len(calls), distinct=rows), f, indent=1)
    print('%d tests, %d failed/errored, %d skipped; %d signing calls'
          % (result.testsRun, len(fails), len(result.skipped), len(calls)))
    for r in rows:
        print('  %-30s %-36s %-10s %-34s %5d  %s' % (r['entry'], r['format'], r['surface'],
                                                    r['endpoint'], r['count'], r['chain']))
    for f in fails:
        print('  FAIL', f['test'], '|', f['last'][:160])
    return 0


if __name__ == '__main__':
    sys.exit(main())
