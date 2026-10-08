-- Reverts 2026-10-08-001. The application asks for the function only when received and replayed WAL
-- differ, and keeps its earlier answer when the function is absent.

DROP FUNCTION IF EXISTS replica_replay_caught_up();
