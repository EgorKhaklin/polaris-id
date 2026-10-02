-- 2026-10-02-002: the duress page's count of active credentials with a duress code, bounded
-- (lab/strategy/008, step 4).
--
-- ADD: idx_identitytoken_duress_enrolled, IdentityToken (status) WHERE duress_code_hash IS NOT
-- NULL. Few credentials carry a duress code, so counting them read every credential; through the
-- index a capped count reads at most its cap.
--
-- EXPAND: an index; the previous release's queries are unchanged by it.
-- LOCK: a plain CREATE INDEX blocks writes to IdentityToken while it builds; on a large
-- population build it CONCURRENTLY by hand first (this file then finds it and skips).
-- REVERSIBLE: yes.
CREATE INDEX IF NOT EXISTS idx_identitytoken_duress_enrolled
    ON IdentityToken (status)
    WHERE duress_code_hash IS NOT NULL;
