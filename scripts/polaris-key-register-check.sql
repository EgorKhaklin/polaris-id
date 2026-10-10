-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Egor Khaklin and the Polaris contributors
--
-- scripts/polaris-key-register-check.sql: which active credentials signed for real every relying
-- party refuses for their key, and what fixes each, read by scripts/polaris-doctor.sh and
-- scripts/polaris-deploy.sh.
--
-- Every route that takes a presented credential accepts a real signature only under a key its
-- authority had registered at the signature's instant and had not retired or declared compromised
-- by then (rp_api.py, _issuer_key_facts in app.py): the instant is the later of the signature's
-- signed_at and the credential's protected ISSUED instant, or its earliest signed_at where it has no
-- ISSUED row (retention purged it, or a recovery made the credential; each signature is written in the
-- transaction that made it). This
-- judges every real signature in force on an ACTIVE, unexpired credential the same way and prints
-- one line, five fields:
--
--   unregistered  agencies with such a signature under a key they had not registered at its instant
--                 and have never ended: a registration fixes them, if the key is theirs
--   first         those of them `polaris-key-event.sh register <agency> --current` fixes: no key
--                 history at all, or a signature under the agency's current key, whose history holds
--                 that key's registrations only (--current extends it back to its first signature)
--   reissue       agencies whose refused signature no registration can fix: its key has been retired
--                 or declared compromised
--   registered    how many registrations the register holds (0: no authority key is registered)
--   keys          agency:key-prefix for each unregistered key, so an operator can tell the key the
--                 install signs with from one nobody minted (a planted signature row)
--
-- polaris_web/test_app.py (KeyRegisterScriptTests) holds this to _issuer_key_facts, signature by signature.
WITH sig AS (
    SELECT t.issuing_agency_id AS agency_id, lower(s.signing_public_key_hex) AS key_hex, s.signed_at,
           COALESCE((SELECT min(e.event_timestamp) FROM TokenLifecycleEvent e
                      WHERE e.token_id = t.token_id AND e.event_type = 'ISSUED'),
                    (SELECT min(f.signed_at) FROM TokenSignature f WHERE f.token_id = t.token_id)) AS issued_at
      FROM IdentityToken t
      JOIN TokenSignature s ON s.token_id = t.token_id
                           AND (s.deprecation_date IS NULL OR s.deprecation_date > now())
     WHERE s.signing_public_key_hex IS NOT NULL
       AND t.status = 'ACTIVE'
       AND (t.expiration_date IS NULL OR t.expiration_date >= (now() AT TIME ZONE 'UTC')::date)
), refused AS (
    SELECT sig.agency_id, sig.key_hex,
           (sig.issued_at IS NULL OR k.retired_at IS NOT NULL OR k.compromised_at IS NOT NULL) AS reissue
      FROM sig
      LEFT JOIN AuthorityKeyCurrent k ON k.agency_id = sig.agency_id AND lower(k.public_key_hex) = sig.key_hex
     WHERE sig.issued_at IS NULL OR k.registered_at IS NULL
        OR k.registered_at > GREATEST(sig.issued_at, sig.signed_at)
        OR k.retired_at <= GREATEST(sig.issued_at, sig.signed_at)
        OR k.compromised_at <= GREATEST(sig.issued_at, sig.signed_at)
), unregistered AS (
    SELECT DISTINCT agency_id, key_hex FROM refused WHERE NOT reissue
), first AS (
    SELECT DISTINCT u.agency_id FROM unregistered u JOIN Agency a ON a.agency_id = u.agency_id
     WHERE NOT EXISTS (SELECT 1 FROM AuthorityKeyEvent e WHERE e.agency_id = u.agency_id)
        OR (u.key_hex = lower(a.signing_public_key_hex)
            AND NOT EXISTS (SELECT 1 FROM AuthorityKeyEvent e WHERE e.agency_id = u.agency_id
                              AND (lower(e.public_key_hex) <> u.key_hex OR e.event <> 'registered')))
)
SELECT COALESCE((SELECT string_agg(agency_id::text, ' ' ORDER BY agency_id)
                   FROM (SELECT DISTINCT agency_id FROM unregistered) x), '')
       || '|' ||
       COALESCE((SELECT string_agg(agency_id::text, ' ' ORDER BY agency_id) FROM first), '')
       || '|' ||
       COALESCE((SELECT string_agg(agency_id::text, ' ' ORDER BY agency_id)
                   FROM (SELECT DISTINCT agency_id FROM refused WHERE reissue) x), '')
       || '|' ||
       (SELECT count(*) FROM AuthorityKeyEvent WHERE event = 'registered')
       || '|' ||
       COALESCE((SELECT string_agg(agency_id || ':' || left(key_hex, 16), ' ' ORDER BY agency_id, key_hex)
                   FROM unregistered), '');
