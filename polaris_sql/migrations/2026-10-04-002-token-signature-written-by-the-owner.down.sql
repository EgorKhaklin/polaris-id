-- 2026-10-04-002 down: the application role regains INSERT, UPDATE and DELETE on TokenSignature,
-- as the blanket grant in 09_grants.sql gave it before this change. The possession gate still
-- refuses a planted row under real signing; the write is open again.

GRANT INSERT, UPDATE, DELETE ON TokenSignature TO polaris_app;
