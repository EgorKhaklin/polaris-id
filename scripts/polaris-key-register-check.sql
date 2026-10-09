-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Egor Khaklin and the Polaris contributors
--
-- scripts/polaris-key-register-check.sql: which credentials signed for real every relying party
-- refuses for their key, read by scripts/polaris-doctor.sh and scripts/polaris-deploy.sh.
--
-- Every route that takes a presented credential accepts a real signature only under a key its
-- authority had registered at the signature's instant (rp_api.py, _issuer_key_facts in app.py):
-- the instant is the later of the signature's signed_at and the credential's protected ISSUED
-- instant, and no ISSUED row is no instant. This judges every real signature in force the same way
-- and prints one line, four fields:
--
--   unregistered  agencies with such a signature under a key they had not registered at its instant
--                 (never, or later): registering fixes them
--   first         those of them with no key event at all: `polaris-key-event.sh register <agency>
--                 --current` registers the key from its first signature
--   ended         agencies holding an ACTIVE credential signed under a key they had already retired
--                 or declared compromised at its instant: refused by design; re-issue
--   registered    how many registrations the register holds (0: no authority key is registered)
--
-- polaris_web/test_app.py (KeyRegisterScriptTests) holds this to _issuer_key_facts, signature by signature.
WITH sig AS (
    SELECT t.issuing_agency_id AS agency_id, t.status, lower(s.signing_public_key_hex) AS key_hex,
           s.signed_at,
           (SELECT min(e.event_timestamp) FROM TokenLifecycleEvent e
             WHERE e.token_id = t.token_id AND e.event_type = 'ISSUED') AS issued_at
      FROM IdentityToken t
      JOIN TokenSignature s ON s.token_id = t.token_id
                           AND (s.deprecation_date IS NULL OR s.deprecation_date > now())
     WHERE s.signing_public_key_hex IS NOT NULL
), judged AS (
    SELECT sig.agency_id, sig.status, GREATEST(sig.issued_at, sig.signed_at) AS at, sig.issued_at,
           k.registered_at, k.retired_at, k.compromised_at
      FROM sig
      LEFT JOIN AuthorityKeyCurrent k ON k.agency_id = sig.agency_id AND lower(k.public_key_hex) = sig.key_hex
), unregistered AS (
    SELECT DISTINCT agency_id FROM judged
     WHERE issued_at IS NULL OR registered_at IS NULL OR registered_at > at
), ended AS (
    SELECT DISTINCT agency_id FROM judged
     WHERE status = 'ACTIVE' AND issued_at IS NOT NULL AND registered_at <= at
       AND (retired_at <= at OR compromised_at <= at)
)
SELECT COALESCE((SELECT string_agg(agency_id::text, ' ' ORDER BY agency_id) FROM unregistered), '')
       || '|' ||
       COALESCE((SELECT string_agg(u.agency_id::text, ' ' ORDER BY u.agency_id) FROM unregistered u
                  WHERE NOT EXISTS (SELECT 1 FROM AuthorityKeyEvent e WHERE e.agency_id = u.agency_id)), '')
       || '|' ||
       COALESCE((SELECT string_agg(agency_id::text, ' ' ORDER BY agency_id) FROM ended), '')
       || '|' ||
       (SELECT count(*) FROM AuthorityKeyEvent WHERE event = 'registered');
