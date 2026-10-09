-- 2026-10-08-001: replica_replay_caught_up() (lab record 017, gate row OP-6).
--
-- An idle primary can leave its newest WAL page partly unwritten. Its replica then receives the page
-- up to its boundary and cannot replay the record that straddles it, so received and replayed WAL
-- differ, and the application read that as the time since the last replayed commit: a caught-up
-- replica on a quiet cluster read as lagging (and PolarisReplicaBehind would page). This function
-- reads the startup process, which only pg_read_all_stats can see: waiting for WAL, it has replayed
-- everything complete it received.
--
-- phase: expand. A new function; nothing existing changes. The canonical copy lives in
-- 05_procedures.sql, and 09_grants.sql's loop gives it to the application role as it does every
-- definer routine. REVERSIBLE: the .down.sql drops it, and the application keeps its earlier answer.

-- Lab record 017 (gate row OP-6): whether this server is a replica with nothing complete left to
-- replay. The application's replica-lag check compares received and replayed WAL, and an idle
-- primary can leave its newest WAL page partly unwritten: the replica then holds the page up to its
-- boundary and cannot replay the record that straddles it, so the two differ while every commit is
-- applied. The startup process says which: waiting for WAL, it has replayed everything complete it
-- received. Only pg_read_all_stats sees that process, so the function runs as its owner and answers
-- only this.
CREATE OR REPLACE FUNCTION replica_replay_caught_up() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
    SELECT pg_is_in_recovery()
       AND coalesce(bool_or(wait_event IN ('RecoveryWalStream', 'RecoveryRetrieveRetryInterval')), false)
      FROM pg_stat_activity
     WHERE backend_type = 'startup'
$$;

COMMENT ON FUNCTION replica_replay_caught_up() IS
  'True on a replica whose startup process waits for WAL: it has replayed every complete record it '
  'received (lab record 017, gate row OP-6). The application asks when received and replayed WAL '
  'differ. False on a primary.';

REVOKE EXECUTE ON FUNCTION replica_replay_caught_up() FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT EXECUTE ON FUNCTION replica_replay_caught_up() TO polaris_app;
    END IF;
END$$;
