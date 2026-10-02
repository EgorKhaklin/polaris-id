-- 2026-10-01-006: the index a person lookup needs at any population (lab/strategy/008).
--
-- ADD:
--   idx_individual_birth_name   Individual (date_of_birth, lower(legal_name) COLLATE "C", individual_id)
--     The operation forms find a person by date of birth and the beginning of the name as
--     recorded, instead of listing every person in a dropdown. The C collation lets a LIKE prefix
--     be an index range and lets the index give the order, so the lookup stops after its limit
--     however many people share a birthday.
--
-- REVERSIBLE: yes (the .down.sql drops it).
-- ADDITIVE:   yes; an expand step. Code that does not use it is unaffected.
-- LOCK:       CREATE INDEX, not CONCURRENTLY: the runner applies a migration in one transaction.
--             On a populated database, build it first outside the runner with CONCURRENTLY, and
--             IF NOT EXISTS makes this a no-op.

CREATE INDEX IF NOT EXISTS idx_individual_birth_name
    ON Individual (date_of_birth, (lower(legal_name)) COLLATE "C", individual_id);
