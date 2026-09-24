-- 2026-09-24-005: the database's clock is UTC.
--
-- CURRENT_DATE answers in the session's timezone. Attestation validity is judged against it in
-- SQL, while credential expiry (rc.27), the signed status assertion and the standalone
-- verifiers read the UTC date, so a database initialised outside UTC judged one date and signed
-- another for hours of every day. New sessions of this database now run UTC; 09_grants.sql
-- carries the same setting for a fresh install. Already-open sessions keep their timezone until
-- they reconnect.
DO $$
BEGIN
    EXECUTE format('ALTER DATABASE %I SET timezone = %L', current_database(), 'UTC');
END$$;
