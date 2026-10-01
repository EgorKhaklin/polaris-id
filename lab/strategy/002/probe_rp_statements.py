#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""probe_rp_statements.py - every SQL statement on the relying-party path, run AS polaris_rp.

LAB ONLY. The test classes do not reach every statement under the test profile: the exchange
gateway and service-to-service receipt minting refuse without real ML-DSA-65, and no test drives
a zero-knowledge step-up with a proof that verifies. So the grant list is also checked statement
by statement: each statement below is copied from polaris_web/rp_api.py or the app.py helper it
calls (same text, sample parameters), executed as polaris_rp inside a transaction that is always
rolled back. A statement refused here is a right the grant list is missing.

    POLARIS_DB_HOST=localhost POLARIS_DB_NAME=polaris_rpcomp \\
    ~/.local/share/polaris-venv312/bin/python lab/strategy/002/probe_rp_statements.py
"""
import json
import os
import sys

import psycopg2

HERE = os.path.dirname(os.path.abspath(__file__))
RP = dict(host=os.environ.get('POLARIS_DB_HOST', 'localhost'), dbname=os.environ.get('POLARIS_DB_NAME', 'polaris_rpcomp'),
          user='polaris_rp', password=os.environ.get('POLARIS_RP_PASSWORD', 'polaris_rp_lab'))
H = 'ab' * 32

# (route or helper, statement, params)
STATEMENTS = [
    ('_rp_authenticate_client (oauth/token, auth/token)',
     "SELECT rp_id, client_secret_hash, enabled, scope FROM RelyingParty WHERE client_id = %s", ('x',)),
    ('POST /api/v1/oauth/token', "UPDATE RelyingParty SET last_used_at = now() WHERE rp_id = %s", (1,)),
    ('POST /api/v1/verify', "SELECT rate_limit_per_min FROM RelyingParty WHERE rp_id = %s AND enabled = TRUE", (1,)),
    ('POST /api/v1/verify', """
        SELECT it.token_id, it.issuing_agency_id, it.token_value, it.status, it.expiration_date,
               ts.signature_bytes, ts.signing_public_key_hex, ag.signing_public_key_hex AS agency_key, now() AS as_of
        FROM IdentityToken it
        JOIN TokenSignature ts ON ts.token_id = it.token_id AND ts.deprecation_date IS NULL
        JOIN Agency ag ON ag.agency_id = it.issuing_agency_id
        WHERE it.token_value = %s ORDER BY ts.signed_at DESC""", ('x',)),
    ('_issuer_key_facts (verify)', """
        SELECT k.status, k.registered_at, k.retired_at, k.compromised_at,
               (SELECT min(event_timestamp) FROM TokenLifecycleEvent WHERE token_id = %s AND event_type = 'ISSUED') AS signed_at
          FROM AuthorityKeyCurrent k WHERE k.agency_id = %s AND lower(k.public_key_hex) = lower(%s)""", (1, 1, H)),
    ('_possession_authenticated (holder routes, mdoc, vc, sign/holder, auth/authorize)', """
        SELECT it.token_id, it.individual_id, it.token_value, it.status, it.issuing_agency_id, it.expiration_date,
               ts.signature_bytes, ts.signing_public_key_hex
        FROM IdentityToken it
        JOIN TokenSignature ts ON ts.token_id = it.token_id AND ts.deprecation_date IS NULL
        WHERE it.token_value = %s ORDER BY ts.signed_at DESC""", ('x',)),
    ('GET /api/v1/epoch/<id>/leaves', "SELECT e.epoch_id, e.merkle_root, e.committed_count, e.valid_until FROM TokenStateEpoch e WHERE e.epoch_id = %s", (1,)),
    ('GET /api/v1/epoch/<id>/leaves', "SELECT leaf_hash FROM TokenStateEpochLeaf WHERE epoch_id = %s ORDER BY leaf_id", (1,)),
    ('GET /api/v1/epoch/<id>/leaves', "SELECT agency_id, name FROM Agency ORDER BY agency_id LIMIT 1", ()),
    ('_holder_binding_for', "SELECT public_key_hex, algorithm, event, effective_at FROM HolderKeyCurrent WHERE token_id = %s", (1,)),
    ('POST /api/v1/holder-key', "SELECT public_key_hex, algorithm FROM HolderKeyCurrent WHERE token_id = %s", (1,)),
    ('POST /api/v1/holder-key', "INSERT INTO HolderKeyEvent (token_id, public_key_hex, algorithm, event) VALUES (%s, %s, %s, %s)",
     (1, 'cd' * 1952, 'ML-DSA-65', 'bound')),
    ('POST /api/v1/mdoc', "SELECT current_status FROM IndividualCurrentEnrollment WHERE individual_id = "
                          "(SELECT individual_id FROM IdentityToken WHERE token_value = %s)", ('x',)),
    ('POST /api/v1/mdoc, /verifiable-credential', "SELECT c.context_type FROM VerificationContext c "
     "JOIN TokenPermission p ON p.context_id = c.context_id JOIN IdentityToken t ON t.token_id = p.token_id "
     "WHERE t.token_value = %s ORDER BY c.context_id LIMIT 1", ('x',)),
    ('_authority_keys (federation-manifest, trust-list)', """
        SELECT public_key_hex, algorithm, status, registered_at, retired_at, compromised_at
        FROM AuthorityKeyCurrent WHERE agency_id = %s ORDER BY registered_at NULLS LAST, public_key_hex""", (1,)),
    ('_key_status', "SELECT status FROM AuthorityKeyCurrent WHERE agency_id = %s AND public_key_hex = %s", (1, H)),
    ('_federation_manifest_body', """
        SELECT att.attested_agency_id, att.context_id, att.attested_date, att.valid_until, att.attestation_format,
               att.attestation_signature_hex, att.attestation_public_key_hex, ag2.signing_public_key_hex AS attested_public_key_hex
        FROM AgencyTrustAttestation att JOIN Agency ag2 ON ag2.agency_id = att.attested_agency_id
        WHERE att.attesting_agency_id = %s AND att.revocation_date IS NULL AND att.valid_until >= polaris_utc_date()
        ORDER BY att.attested_agency_id, att.context_id""", (1,)),
    ('_federation_manifest_body, _revocation_feed_body', "SELECT epoch_id, merkle_root FROM TokenStateEpoch ORDER BY epoch_id DESC LIMIT 1", ()),
    ('_epoch_checkpoint_body', "SELECT epoch_id, merkle_root, committed_count, valid_until FROM TokenStateEpoch ORDER BY epoch_id DESC LIMIT 2", ()),
    ('_revocation_feed_body', "SELECT it.token_value FROM RevocationList rl JOIN IdentityToken it ON it.token_id = rl.token_id "
                              "WHERE it.issuing_agency_id = %s", (1,)),
    ('_federated_agency and every per-agency route', "SELECT agency_id, name, signing_public_key_hex FROM Agency WHERE agency_id = %s", (1,)),
    ('_exchange_attestation', """
        SELECT ag.agency_id AS authority_id, ag.name AS authority_name
        FROM AgencyTrustAttestation att JOIN Agency ag2 ON ag2.agency_id = att.attested_agency_id
        JOIN Agency ag ON ag.agency_id = att.attesting_agency_id
        WHERE att.attesting_agency_id = %s AND lower(ag2.signing_public_key_hex) = %s AND att.context_id = %s
          AND att.revocation_date IS NULL AND att.valid_until >= polaris_utc_date()
        ORDER BY att.attestation_id LIMIT 1""", (1, H, 1)),
    ('GET /api/v1/registry/<id>', """
        SELECT va.agency_id, va.name, va.agency_type, va.jurisdiction, va.authorization_level, ag.signing_public_key_hex
        FROM v_athena_agency va JOIN Agency ag ON ag.agency_id = va.agency_id
        WHERE ag.signing_public_key_hex IS NOT NULL ORDER BY va.agency_id""", ()),
    ('GET /api/v1/registry/<id>', "SELECT context_id, context_type, requires_biometric, min_security_level FROM v_athena_proof_policy ORDER BY context_id", ()),
    ('GET /api/v1/registry/<id>', "SELECT disclosure_level FROM v_athena_disclosure_policy ORDER BY ordinal", ()),
    ('GET /api/v1/registry/<id>', """
        SELECT ta.attesting_agency_id, ta.attested_agency_id, ta.context_id, ta.valid_until, ab.signing_public_key_hex AS attested_public_key_hex
        FROM v_athena_trust_agreement ta JOIN Agency ab ON ab.agency_id = ta.attested_agency_id
        WHERE ab.signing_public_key_hex IS NOT NULL""", ()),
    ('GET /api/v1/registry/<id>', "SELECT org_name, scope FROM RelyingParty WHERE enabled = TRUE ORDER BY org_name", ()),
    ('_consume_exchange_nonce (POST /api/v1/exchange/<id>)', "INSERT INTO ExchangeNonce (requester_key_hash, nonce) VALUES (%s, %s)", (H, 'n-1')),
    ('POST /api/v1/exchange/<id>', "SELECT agency_id FROM Agency WHERE lower(signing_public_key_hex) = %s", (H,)),
    ('POST /api/v1/auth/authorize', "SELECT rp_id, client_id, scope, enabled, require_zk, required_enrollment, required_context_id "
                                    "FROM RelyingParty WHERE client_id = %s", ('x',)),
    ('_check_and_record_duress (auth/authorize)', "SELECT duress_code_hash FROM IdentityToken WHERE token_id = %s", (1,)),
    ('POST /api/v1/auth/authorize', "SELECT 1 FROM TokenPermission WHERE token_id = %s AND context_id = %s", (1, 1)),
    ('POST /api/v1/auth/authorize', "SELECT current_status FROM IndividualCurrentEnrollment WHERE individual_id = %s", (1,)),
    ('_zk_verify_and_consume (auth/authorize step-up)', """
        SELECT merkle_root, valid_until, committed_count,
               COALESCE(NULLIF(polaris_database_setting('polaris.min_epoch_anonymity_set'), ''), '20')::INTEGER AS min_anonymity_set
          FROM TokenStateEpoch WHERE epoch_id = %s""", (1,)),
    ('_db_now (zk step-up)', "SELECT LOCALTIMESTAMP AS t", ()),
    ('_zk_verify_and_consume (auth/authorize step-up)', """
        INSERT INTO ZkVerificationNonce (epoch_id, context_id, nonce) VALUES (%s, %s, %s)
        ON CONFLICT ON CONSTRAINT pk_zk_verification_nonce DO NOTHING RETURNING consumed_at""", None),
    ('POST /api/v1/auth/token', "INSERT INTO AuthCodeConsumed (code_hash) VALUES (%s)", (H,)),
    ('POST /api/v1/auth/token', "SELECT agency_id, name FROM Agency WHERE agency_id = %s", (1,)),
    ('POST /api/v1/trust-list/<id>', "SELECT agency_id, name, signing_public_key_hex FROM Agency WHERE signing_public_key_hex IS NOT NULL ORDER BY agency_id", ()),
    ('_transparency_entries receipts', "SELECT receipt_hash FROM ExchangeReceiptLog ORDER BY seq", ()),
    ('_transparency_entries timestamps', "SELECT timestamp_hash FROM TimestampLog ORDER BY seq", ()),
    ('_transparency_entries anchors', "SELECT merkle_root FROM AnchorBatch ORDER BY batch_id", ()),
    ('_receipt_log_append', "INSERT INTO ExchangeReceiptLog (receipt_hash) VALUES (%s) ON CONFLICT (receipt_hash) DO NOTHING", (H,)),
    ('_receipt_log_append', "SELECT (SELECT count(*) FROM ExchangeReceiptLog b WHERE b.seq < a.seq) AS idx "
                            "FROM ExchangeReceiptLog a WHERE a.receipt_hash = %s", (H,)),
    ('_timestamp_log_append', "INSERT INTO TimestampLog (timestamp_hash) VALUES (%s) ON CONFLICT (timestamp_hash) DO NOTHING", (H,)),
    ('_timestamp_log_append', "SELECT (SELECT count(*) FROM TimestampLog b WHERE b.seq < a.seq) AS idx "
                              "FROM TimestampLog a WHERE a.timestamp_hash = %s", (H,)),
]


def main():
    conn = psycopg2.connect(**RP)
    results, bad = [], 0
    for where, sql, params in STATEMENTS:
        if params is None:      # the ZK nonce: needs a real epoch id
            with conn.cursor() as c:
                c.execute("SELECT max(epoch_id) FROM TokenStateEpoch")
                params = (c.fetchone()[0], 1, 987654321)
            conn.rollback()
        try:
            with conn.cursor() as c:
                c.execute(sql, params)
            outcome, msg = 'ok', ''
        except psycopg2.Error as e:
            outcome, msg = ('REFUSED' if e.pgcode == '42501' else 'error-%s' % e.pgcode), str(e).strip().splitlines()[0]
            bad += outcome == 'REFUSED'
        finally:
            conn.rollback()
        results.append(dict(where=where, statement=' '.join(sql.split())[:160], outcome=outcome, message=msg))
        print('%-9s %-55s %s %s' % (outcome, where[:55], ' '.join(sql.split())[:70], msg[:80]))
    os.makedirs(os.path.join(HERE, 'out'), exist_ok=True)
    with open(os.path.join(HERE, 'out', 'probe.json'), 'w') as f:
        json.dump(results, f, indent=1)
    print('%d statements, %d refused' % (len(results), bad))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
