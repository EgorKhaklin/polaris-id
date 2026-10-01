-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Egor Khaklin and the Polaris contributors
-- Synthetic population for the console scale bench (lab/strategy/008). Run as the schema owner,
-- a superuser, against a database loaded from polaris_sql/00_load_all.sql and the migrations:
--   psql -v n=2000000 -v v=10000000 -d polaris_scale -f lab/strategy/008/gen.sql
-- Triggers are bypassed for the bulk load (session_replication_role = replica); the rows are built
-- consistent by construction: one ACTIVE credential per person (C3), a signature per credential,
-- ZERO_KNOWLEDGE verifications carry no token id (C2). Timestamps fall between 2026-09-01 and the
-- moment of loading, so they land in the monthly partitions, not the default one.
\set ON_ERROR_STOP on
\timing on
SET session_replication_role = replica;
SET synchronous_commit = off;
SET maintenance_work_mem = '1GB';
SET work_mem = '256MB';

SELECT COALESCE(max(individual_id), 0) AS base_person FROM Individual \gset
SELECT COALESCE(max(token_id), 0) AS base_token FROM IdentityToken \gset

-- People
INSERT INTO Individual (individual_id, legal_name, date_of_birth, jurisdiction, enrollment_date)
SELECT :base_person + g,
       'Person ' || g,
       date '1940-01-01' + (g % 29000),
       (ARRAY['US-PA','US-CA','US-NY','US-TX','US-FL','US-OH','US-WA','US-IL'])[1 + g % 8],
       timestamp '2026-09-01' + ((g % 2500000) * interval '1 second')
  FROM generate_series(1, :n) g;
SELECT setval(pg_get_serial_sequence('individual', 'individual_id'), (SELECT max(individual_id) FROM Individual));

-- Credentials: every person one ACTIVE; half also a RESERVE; a quarter a REVOKED one; 5% an
-- EXPIRED one; 2% a LOST one. Token ids are dense per kind so they are computable below.
CREATE TEMP TABLE kinds(k int, status text, every int);
INSERT INTO kinds VALUES (0,'ACTIVE',1),(1,'RESERVE',2),(2,'REVOKED',4),(3,'EXPIRED',20),(4,'LOST',50);
INSERT INTO IdentityToken (token_id, token_value, physical_serial, hardware_model, biometric_binding_type,
                           individual_id, issuing_agency_id, algorithm_id, activation_sequence, status,
                           issued_date, activated_date, expiration_date)
SELECT :base_token + row_number() OVER (),
       'TKN-SC-' || k.k || '-' || g,
       'SN-SC-' || k.k || '-' || g,
       'BENCH-1',
       'NONE',
       :base_person + g,
       1 + (g % 3),
       CASE WHEN g % 100 = 0 THEN 5 ELSE 1 END,
       1,
       k.status,
       timestamp '2026-09-01' + ((g % 2500000) * interval '1 second'),
       CASE WHEN k.status = 'ACTIVE' THEN timestamp '2026-09-01' + ((g % 2500000) * interval '1 second') + interval '1 hour' END,
       date '2031-09-01' + (g % 365)
  FROM kinds k
  CROSS JOIN LATERAL generate_series(1, :n) g
 WHERE g % k.every = 0;
SELECT setval(pg_get_serial_sequence('identitytoken', 'token_id'), (SELECT max(token_id) FROM IdentityToken));

-- One live signature per credential under its algorithm (64 bytes here; a real ML-DSA-65
-- signature is 3,309 bytes, which the bench notes when it reports storage).
INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes, signing_public_key_hex, signed_at)
SELECT token_id, algorithm_id, decode(repeat('ab', 64), 'hex'), NULL, issued_date
  FROM IdentityToken WHERE token_id > :base_token;

-- Lifecycle: ISSUED for every credential, ACTIVATED for the active, REVOKED for the revoked.
INSERT INTO TokenLifecycleEvent (token_id, actor_agency_id, event_type, event_timestamp, reason_code)
SELECT token_id, issuing_agency_id, 'ISSUED', issued_date, 'INITIAL_ENROLLMENT'
  FROM IdentityToken WHERE token_id > :base_token;
INSERT INTO TokenLifecycleEvent (token_id, actor_agency_id, event_type, event_timestamp, reason_code)
SELECT token_id, issuing_agency_id, 'ACTIVATED', activated_date, 'POST_BIOMETRIC_ENROLLMENT'
  FROM IdentityToken WHERE token_id > :base_token AND status = 'ACTIVE';
INSERT INTO TokenLifecycleEvent (token_id, actor_agency_id, event_type, event_timestamp, reason_code)
SELECT token_id, issuing_agency_id, 'REVOKED', issued_date + interval '2 hours', 'ADMINISTRATIVE_PAPERWORK_ERROR'
  FROM IdentityToken WHERE token_id > :base_token AND status = 'REVOKED';

-- Enrollment status: the seeded NOT_ENROLLED, then ENROLLED.
INSERT INTO EnrollmentStatusEvent (individual_id, status, transition_reason, recorded_by_agency_id, event_timestamp)
SELECT individual_id, 'NOT_ENROLLED', 'INDIVIDUAL_ROW_CREATED', NULL, enrollment_date
  FROM Individual WHERE individual_id > :base_person;
INSERT INTO EnrollmentStatusEvent (individual_id, status, transition_reason, recorded_by_agency_id, event_timestamp)
SELECT individual_id, 'ENROLLED', 'BENCH_ENROLLMENT', 1, enrollment_date + interval '30 minutes'
  FROM Individual WHERE individual_id > :base_person;

-- Verifications over the month: ZERO_KNOWLEDGE (no token id), SELECTIVE, FULL; 3% not successful.
SELECT EXTRACT(EPOCH FROM (now()::timestamp - timestamp '2026-09-01'))::bigint AS span \gset
INSERT INTO VerificationEvent (token_id, requesting_agency_id, context_id, event_timestamp, outcome,
                               disclosure_level, proof_commitment)
SELECT CASE WHEN g % 3 = 0 THEN NULL ELSE :base_token + 1 + (g::bigint * 7919) % (:n) END,
       1 + g % 6,
       1 + g % 7,
       timestamp '2026-09-01' + (((g::bigint * 104729) % :span) * interval '1 second'),
       CASE WHEN g % 33 = 0 THEN 'FAILURE' WHEN g % 97 = 0 THEN 'EXPIRED' ELSE 'SUCCESS' END,
       CASE g % 3 WHEN 0 THEN 'ZERO_KNOWLEDGE' WHEN 1 THEN 'SELECTIVE' ELSE 'FULL' END,
       CASE WHEN g % 3 = 0 THEN md5(g::text) END
  FROM generate_series(1, :v) g;

RESET session_replication_role;
-- The triggers that keep PopulationCount were off for the load: recount.
SELECT uc_rebuild_population_counts();
ANALYZE;
SELECT relname, n_live_tup FROM pg_stat_user_tables
 WHERE relname IN ('individual','identitytoken','tokensignature','tokenlifecycleevent_2026_09',
                   'tokenlifecycleevent_2026_10','verificationevent_2026_09','verificationevent_2026_10',
                   'enrollmentstatusevent_2026_09','enrollmentstatusevent_2026_10')
 ORDER BY relname;
SELECT pg_size_pretty(pg_database_size(current_database())) AS database_size;
