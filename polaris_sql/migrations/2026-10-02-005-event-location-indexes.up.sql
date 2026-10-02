-- 2026-10-02-005: the event tables' location indexes, withdrawn (lab/strategy/009, step 4c).
--
-- DROP: idx_verificationevent_geo, idx_verificationevent_geo_time and
-- idx_tokenlifecycleevent_geo, B-trees on (latitude, longitude) built in v6 for the Atlas's
-- bounding-box layers. Since step 4 the Atlas sums the activity rollups and nothing reads a
-- coordinate: the verification log projects explicit columns and filters by none. Each index
-- cost every located insert a B-tree update and grew with the population.
--
-- EXPAND: dropping an index changes no query's result; a previous release still serving during
-- a rolling deploy reads the same answers, more slowly.
-- LOCK: DROP INDEX holds an ACCESS EXCLUSIVE lock on the table for as long as the catalog change
-- takes, and builds nothing; an index on a partitioned table cannot be dropped CONCURRENTLY.
-- REVERSIBLE: yes; the down file rebuilds the three, a full scan of each table.
DROP INDEX IF EXISTS idx_verificationevent_geo;
DROP INDEX IF EXISTS idx_verificationevent_geo_time;
DROP INDEX IF EXISTS idx_tokenlifecycleevent_geo;
