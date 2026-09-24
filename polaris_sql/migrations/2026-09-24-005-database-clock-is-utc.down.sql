-- Reverts 2026-09-24-005: the database's timezone falls back to the server default.
DO $$
BEGIN
    EXECUTE format('ALTER DATABASE %I RESET timezone', current_database());
END$$;
