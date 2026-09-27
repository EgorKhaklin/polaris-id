#!/usr/bin/env python3
"""probe_rate_limit_audit.py - does the /api/v1 path write the operator's audit table?

LAB ONLY. app._security_before_request audits every state-changing request past the per-IP write
limit with security._audit(get_db, 'RATE_LIMITED', ...), an INSERT into AuthAuditLog, before any
route runs. No test class drives an /api/v1 POST past that limit, so the run cannot see it. This
drives POST /api/v1/timestamp/1 past the limit with the application connected as polaris_rp and
records what the audit write does. security._audit swallows its own failure (stderr only), so
the response is 429 either way; the refusal is the finding.

    POLARIS_DB_HOST=localhost POLARIS_DB_NAME=polaris_rpcomp POLARIS_DB_USER=vanta \\
    POLARIS_SECRET_KEY=local-test-secret-key-32-bytes-long POLARIS_STATE_DIR=/tmp/polaris-state-rpcomp \\
    POLARIS_PQC_PROFILE=placeholder ~/.local/share/polaris-venv312/bin/python lab/strategy/002/probe_rate_limit_audit.py
"""
import contextlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.abspath(os.path.join(HERE, '..', '..', '..', 'polaris_web'))


def main():
    if os.environ.get('POLARIS_DB_NAME') != 'polaris_rpcomp':
        print('refusing: POLARIS_DB_NAME must be polaris_rpcomp')
        return 2
    os.chdir(WEB)
    sys.path.insert(0, WEB)
    import psycopg2
    from psycopg2.extras import RealDictCursor
    import app as A
    import rp_api

    rp_cfg = dict(A.DB_CONFIG, user='polaris_rp', password=os.environ.get('POLARIS_RP_PASSWORD', 'polaris_rp_lab'))

    def get_db(readonly=False):
        return psycopg2.connect(cursor_factory=RealDictCursor, **rp_cfg)
    A.get_db = rp_api.get_db = get_db

    owner = psycopg2.connect(**dict(A.DB_CONFIG))
    owner.autocommit = True
    with owner.cursor() as c:
        c.execute("SELECT count(*) FROM AuthAuditLog WHERE event_type = 'RATE_LIMITED'")
        before = c.fetchone()[0]

    A.app.config['TESTING'] = True
    A.security.rate_limiter.reset()
    client = A.app.test_client()
    statuses = {}
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        for _ in range(A.security.RATE_LIMIT_WRITE_MAX + 3):
            r = client.post('/api/v1/timestamp/1', json={'digest_hex': 'ab' * 32})
            statuses[r.status_code] = statuses.get(r.status_code, 0) + 1
    with owner.cursor() as c:
        c.execute("SELECT count(*) FROM AuthAuditLog WHERE event_type = 'RATE_LIMITED'")
        after = c.fetchone()[0]
    audit_lines = [ln for ln in err.getvalue().splitlines() if '[audit]' in ln]
    out = dict(statuses=statuses, rate_limited_rows_before=before, rate_limited_rows_after=after,
               audit_failures=audit_lines[:3], audit_failure_count=len(audit_lines))
    os.makedirs(os.path.join(HERE, 'out'), exist_ok=True)
    with open(os.path.join(HERE, 'out', 'rate_limit_audit.json'), 'w') as f:
        json.dump(out, f, indent=1)
    print(json.dumps(out, indent=1))
    return 0


if __name__ == '__main__':
    sys.exit(main())
