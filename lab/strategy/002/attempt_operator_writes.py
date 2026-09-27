#!/usr/bin/env python3
"""attempt_operator_writes.py - section 9 step 4: as polaris_rp, attempt the operator's writes
directly in SQL and require each refused with insufficient_privilege (SQLSTATE 42501).

LAB ONLY, scratch database polaris_rpcomp. Every attempt runs in its own transaction and is
ROLLED BACK whatever happens, so a write that succeeds is reported and not kept. One fixture
(a duress code on token 1, needed to test uc12_record_duress honestly) is written as the owner
and removed at the end.

Also attempts the compartment's OWN rights in the ways an attacker holding polaris_rp would use
them (update or delete a register row, widen a relying party, read what the surface does not
need), and every SECURITY DEFINER routine the role can EXECUTE.

    POLARIS_DB_HOST=localhost POLARIS_DB_NAME=polaris_rpcomp \\
    ~/.local/share/polaris-venv312/bin/python lab/strategy/002/attempt_operator_writes.py

Exit 0 when every operator write is refused with 42501; 1 otherwise. Writes out/attempts.json.
"""
import json
import os
import sys

import psycopg2

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = os.environ.get('POLARIS_DB_HOST', 'localhost')
DB = os.environ.get('POLARIS_DB_NAME', 'polaris_rpcomp')
OWNER = os.environ.get('POLARIS_TEST_RELOAD_USER', 'vanta')
RP = dict(host=HOST, dbname=DB, user='polaris_rp', password=os.environ.get('POLARIS_RP_PASSWORD', 'polaris_rp_lab'))

KEY = 'ab' * 1952   # an ML-DSA-65-length public key the attacker holds

# (label, kind, sql). kind 'operator' = an operator write that MUST be refused with 42501;
# kind 'own' = the compartment's own tables used against their purpose; kind 'read' = a read the
# surface does not need.
ATTEMPTS = [
    # --- issue a token -------------------------------------------------------------------------
    ('issue: INSERT IdentityToken', 'operator',
     "INSERT INTO IdentityToken (token_value, physical_serial, biometric_binding_type, individual_id, "
     "issuing_agency_id, algorithm_id, status) VALUES ('rp-forged', 'rp-forged', 'FINGERPRINT', 1, 1, 1, 'ACTIVE')"),
    ('issue: uc1_issue_and_activate (a function, SECURITY DEFINER)', 'operator',
     "SELECT uc1_issue_and_activate('rp-forged-2'::varchar, CURRENT_DATE, 'SN-RP'::varchar, 1, 1, "
     "'FINGERPRINT'::varchar, 1, NULL::varchar, NULL::varchar, NULL::varchar, NULL::varchar, ARRAY[1], "
     "NULL::bytea, NULL::text)"),
    ('issue: CALL uc_bulk_issue', 'operator', "CALL uc_bulk_issue(1, 1)"),
    ('issue: INSERT TokenSignature', 'operator',
     "INSERT INTO TokenSignature (token_id, signature_bytes, signing_public_key_hex) VALUES (1, '\\x00', '%s')" % KEY),
    ('issue: INSERT TokenPermission', 'operator', "INSERT INTO TokenPermission (token_id, context_id) VALUES (1, 1)"),
    # --- revoke --------------------------------------------------------------------------------
    ('revoke: UPDATE IdentityToken.status', 'operator', "UPDATE IdentityToken SET status = 'REVOKED' WHERE token_id = 1"),
    ('revoke: CALL uc8_revoke_token', 'operator', "CALL uc8_revoke_token(1, 1, 'rp compartment test', 'admin', NULL)"),
    ('revoke: INSERT RevocationList', 'operator',
     "INSERT INTO RevocationList (token_id, revoked_by_agency_id, effective_date, reason_code) "
     "VALUES (1, 1, CURRENT_DATE, 'COMPROMISED')"),
    ('un-revoke: DELETE RevocationList', 'operator', "DELETE FROM RevocationList"),
    # --- re-point an agency signing key --------------------------------------------------------
    ('re-point: UPDATE Agency.signing_public_key_hex', 'operator',
     "UPDATE Agency SET signing_public_key_hex = '%s' WHERE agency_id = 1" % KEY),
    ('authority key event: INSERT AuthorityKeyEvent', 'operator',
     "INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, event) VALUES (1, '%s', 'registered')" % KEY),
    ('trust edge: CALL uc10_attest_trust', 'operator', "CALL uc10_attest_trust(1, 2, 1, CURRENT_DATE + 30, 1)"),
    ('trust edge: INSERT AgencyTrustAttestation', 'operator',
     "INSERT INTO AgencyTrustAttestation (attesting_agency_id, attested_agency_id, context_id) VALUES (1, 2, 1)"),
    # --- accounts and sessions -----------------------------------------------------------------
    ('account: INSERT AppUser', 'operator',
     "INSERT INTO AppUser (username, password_hash, role) VALUES ('rp_admin', 'x', 'admin')"),
    ('account: UPDATE AppUser.role', 'operator', "UPDATE AppUser SET role = 'admin'"),
    ('session: INSERT OperatorSession', 'operator',
     "INSERT INTO OperatorSession (session_id, user_id, role) VALUES ('rp', 1, 'admin')"),
    # --- verification and audit ----------------------------------------------------------------
    ('verification event: INSERT VerificationEvent', 'operator',
     "INSERT INTO VerificationEvent (token_id, requesting_agency_id, context_id, outcome, disclosure_level) "
     "VALUES (1, 1, 1, 'APPROVED', 'ZERO_KNOWLEDGE')"),
    ('audit: DELETE TokenLifecycleEvent', 'operator', "DELETE FROM TokenLifecycleEvent"),
    ('audit: DELETE VerificationEvent', 'operator', "DELETE FROM VerificationEvent"),
    ('audit: DELETE AuthAuditLog', 'operator', "DELETE FROM AuthAuditLog"),
    ('audit: DELETE DuressEvent', 'operator', "DELETE FROM DuressEvent"),
    ('audit: INSERT AuthAuditLog', 'operator',
     "INSERT INTO AuthAuditLog (event_type, detail) VALUES ('LOGIN_SUCCESS', 'forged')"),
    ('audit: TRUNCATE TokenLifecycleEvent', 'operator', "TRUNCATE TokenLifecycleEvent"),
    ('epoch: CALL uc11_close_epoch', 'operator', "CALL uc11_close_epoch('rp', NULL, 1, NULL)"),
    ('recovery: CALL uc9_initiate_recovery', 'operator', "CALL uc9_initiate_recovery(1, 1, 1, 1)"),
    ('erasure: CALL uc_pseudonymize_individual', 'operator', "CALL uc_pseudonymize_individual(1, 1, 'admin')"),
    ('purge: CALL uc_archive_purge', 'operator',
     "CALL uc_archive_purge(now(), 'admin', 'rp compartment test', 1, 'x', ARRAY[]::timestamptz[], 0)"),
    ('DDL: CREATE TABLE', 'operator', "CREATE TABLE rp_owned (x int)"),
    # --- the compartment's own registers, against their purpose --------------------------------
    ('own: UPDATE HolderKeyEvent', 'own', "UPDATE HolderKeyEvent SET public_key_hex = '%s'" % KEY),
    ('own: DELETE HolderKeyEvent', 'own', "DELETE FROM HolderKeyEvent"),
    ('own: DELETE ExchangeReceiptLog', 'own', "DELETE FROM ExchangeReceiptLog"),
    ('own: DELETE TimestampLog', 'own', "DELETE FROM TimestampLog"),
    ('own: DELETE AuthCodeConsumed', 'own', "DELETE FROM AuthCodeConsumed"),
    ('own: DELETE ExchangeNonce', 'own', "DELETE FROM ExchangeNonce"),
    ('own: DELETE ZkVerificationNonce', 'own', "DELETE FROM ZkVerificationNonce"),
    ('own: UPDATE RelyingParty.scope', 'own', "UPDATE RelyingParty SET scope = 'verify authenticate'"),
    ('own: UPDATE RelyingParty.client_secret_hash', 'own', "UPDATE RelyingParty SET client_secret_hash = 'x'"),
    ('own: UPDATE RelyingParty.require_zk', 'own', "UPDATE RelyingParty SET require_zk = FALSE"),
    ('own: INSERT RelyingParty', 'own',
     "INSERT INTO RelyingParty (client_id, client_secret_hash, org_name, scope) VALUES ('rp-x', 'x', 'x', 'verify')"),
    # --- reads the surface does not need -------------------------------------------------------
    ('read: AppUser.password_hash', 'read', "SELECT password_hash FROM AppUser"),
    ('read: OperatorSession', 'read', "SELECT * FROM OperatorSession"),
    ('read: Individual.date_of_birth', 'read', "SELECT date_of_birth FROM Individual"),
    ('read: VerificationEvent', 'read', "SELECT * FROM VerificationEvent"),
    ('read: DuressEvent', 'read', "SELECT * FROM DuressEvent"),
    ('read: IdentityToken.physical_serial', 'read', "SELECT physical_serial FROM IdentityToken"),
]


def main():
    owner = psycopg2.connect(host=HOST, dbname=DB, user=OWNER)
    owner.autocommit = True
    with owner.cursor() as c:
        c.execute("SELECT duress_code_hash FROM IdentityToken WHERE token_id = 1")
        saved_hash = c.fetchone()[0]
        c.execute("UPDATE IdentityToken SET duress_code_hash = 'scrypt:32768:8:1$x$y' WHERE token_id = 1")
        c.execute("SELECT count(*) FROM DuressEvent")
        duress_before = c.fetchone()[0]

    # The definer routines this role can run, from the catalog: each is the owner's rights, lent.
    rp = psycopg2.connect(**RP)
    with rp.cursor() as c:
        c.execute("SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                  "WHERE n.nspname = 'public' AND p.prosecdef AND has_function_privilege(p.oid, 'EXECUTE') ORDER BY 1")
        definer = [r[0] for r in c.fetchall()]
    rp.rollback()
    attempts = list(ATTEMPTS) + [
        ('definer: CALL uc12_record_duress on a token with a duress code enrolled', 'definer',
         "CALL uc12_record_duress(1, 1, 1, 'AUDIT_TABLE')"),
        ('own: INSERT HolderKeyEvent binding an attacker key to token 1 (no possession proof)', 'own-insert',
         "INSERT INTO HolderKeyEvent (token_id, public_key_hex, algorithm, event) VALUES (1, '%s', 'ML-DSA-65', 'bound')" % KEY),
        ('own-read: every credential pack (token_value + stored signature) in one query', 'own-read',
         "SELECT it.token_value, ts.signature_bytes FROM IdentityToken it JOIN TokenSignature ts USING (token_id)"),
        ('own-read: which credentials have a duress code enrolled, and the hashes', 'own-read',
         "SELECT token_id, duress_code_hash FROM IdentityToken WHERE duress_code_hash IS NOT NULL"),
        ('own-read: every holder legal name', 'own-read', "SELECT individual_id, legal_name FROM Individual"),
        ('own: INSERT ZkVerificationNonce (burn a nonce a holder has not used)', 'own-insert',
         "INSERT INTO ZkVerificationNonce (epoch_id, context_id, nonce) VALUES "
         "((SELECT max(epoch_id) FROM TokenStateEpoch), 1, 424242)"),
    ]

    results = []
    for label, kind, sql in attempts:
        try:
            with rp.cursor() as c:
                c.execute(sql)
                n = c.rowcount
            outcome, code, msg = 'SUCCEEDED', None, 'rowcount=%s' % n
        except psycopg2.Error as e:
            outcome = 'refused-42501' if e.pgcode == '42501' else 'refused-other'
            code, msg = e.pgcode, (e.pgerror or str(e)).strip().splitlines()[0]
        finally:
            rp.rollback()
        results.append(dict(label=label, kind=kind, outcome=outcome, sqlstate=code, message=msg))

    with owner.cursor() as c:
        c.execute("UPDATE IdentityToken SET duress_code_hash = %s WHERE token_id = 1", (saved_hash,))
        c.execute("SELECT count(*) FROM DuressEvent")
        duress_after = c.fetchone()[0]

    os.makedirs(os.path.join(HERE, 'out'), exist_ok=True)
    with open(os.path.join(HERE, 'out', 'attempts.json'), 'w') as f:
        json.dump(dict(definer_routines_executable=definer, results=results,
                       duress_rows_before=duress_before, duress_rows_after=duress_after), f, indent=1)

    print('SECURITY DEFINER routines polaris_rp can EXECUTE: %s' % (', '.join(definer) or 'none'))
    bad = 0
    for r in results:
        flag = ''
        if r['kind'] == 'operator' and r['outcome'] != 'refused-42501':
            flag, bad = '  <-- NOT REFUSED WITH 42501', bad + 1
        print('%-15s %-8s %s | %s %s%s' % (r['outcome'], r['kind'], r['label'], r['sqlstate'] or '', r['message'][:110], flag))
    print('DuressEvent rows before/after (every attempt rolled back): %s / %s' % (duress_before, duress_after))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
