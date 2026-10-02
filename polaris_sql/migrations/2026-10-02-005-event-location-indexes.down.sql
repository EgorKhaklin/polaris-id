-- 2026-10-02-005 down: rebuild the event tables' location indexes as 02_indexes.sql built them
-- before step 4c. A plain CREATE INDEX blocks writes to each table while it scans it.
CREATE INDEX IF NOT EXISTS idx_verificationevent_geo
    ON VerificationEvent (latitude, longitude)
    WHERE latitude IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_verificationevent_geo_time
    ON VerificationEvent (event_timestamp DESC, latitude, longitude)
    WHERE latitude IS NOT NULL;
COMMENT ON INDEX idx_verificationevent_geo IS
  'Bbox queries from atlas_clusters_verifications(). Predicate excludes '
  'NULL latitude rows (legacy / unrecorded location) so the index stays small.';
CREATE INDEX IF NOT EXISTS idx_tokenlifecycleevent_geo
    ON TokenLifecycleEvent (latitude, longitude)
    WHERE latitude IS NOT NULL;
