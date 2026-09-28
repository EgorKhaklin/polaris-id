-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Egor Khaklin and the Polaris contributors
\echo Generating 2M synthetic verification events...
\timing on

INSERT INTO VerificationEvent (
    token_id, requesting_agency_id, context_id, event_timestamp,
    outcome, disclosure_level, requestor_location, latitude, longitude
)
SELECT
    CASE WHEN (i % 100) < 40 THEN NULL ELSE ((i % 5) + 1) END,
    ((i % 6) + 1),
    ((i % 7) + 1),
    (CURRENT_TIMESTAMP - (random() * INTERVAL '90 days')),
    (ARRAY['SUCCESS','SUCCESS','SUCCESS','SUCCESS','SUCCESS','SUCCESS','SUCCESS','SUCCESS','SUCCESS','SUCCESS','SUCCESS','SUCCESS','SUCCESS','SUCCESS','SUCCESS','SUCCESS','SUCCESS','SUCCESS','SUCCESS','SUCCESS','SUCCESS','SUCCESS','FAILURE','FAILURE','EXPIRED'])[((i % 25) + 1)],
    CASE WHEN (i % 100) < 40 THEN 'ZERO_KNOWLEDGE' WHEN (i % 100) < 75 THEN 'SELECTIVE' ELSE 'FULL' END,
    'synthetic-' || (i / 1000),
    CASE (i % 30)
        WHEN  0 THEN 40.7128 + (random() - 0.5) * 0.3 WHEN  1 THEN 34.0522 + (random() - 0.5) * 0.3
        WHEN  2 THEN 41.8781 + (random() - 0.5) * 0.3 WHEN  3 THEN 29.7604 + (random() - 0.5) * 0.3
        WHEN  4 THEN 39.9526 + (random() - 0.5) * 0.3 WHEN  5 THEN 33.4484 + (random() - 0.5) * 0.3
        WHEN  6 THEN 32.7157 + (random() - 0.5) * 0.3 WHEN  7 THEN 47.6062 + (random() - 0.5) * 0.3
        WHEN  8 THEN 25.7617 + (random() - 0.5) * 0.3 WHEN  9 THEN 38.9072 + (random() - 0.5) * 0.3
        WHEN 10 THEN 51.5074 + (random() - 0.5) * 0.3 WHEN 11 THEN 48.8566 + (random() - 0.5) * 0.3
        WHEN 12 THEN 52.5200 + (random() - 0.5) * 0.3 WHEN 13 THEN 41.9028 + (random() - 0.5) * 0.3
        WHEN 14 THEN 40.4168 + (random() - 0.5) * 0.3 WHEN 15 THEN 35.6762 + (random() - 0.5) * 0.3
        WHEN 16 THEN 31.2304 + (random() - 0.5) * 0.3 WHEN 17 THEN 22.3193 + (random() - 0.5) * 0.3
        WHEN 18 THEN  1.3521 + (random() - 0.5) * 0.3 WHEN 19 THEN 28.6139 + (random() - 0.5) * 0.3
        WHEN 20 THEN 19.0760 + (random() - 0.5) * 0.3 WHEN 21 THEN -33.8688+ (random() - 0.5) * 0.3
        WHEN 22 THEN -23.5505+ (random() - 0.5) * 0.3 WHEN 23 THEN -34.6037+ (random() - 0.5) * 0.3
        WHEN 24 THEN 19.4326 + (random() - 0.5) * 0.3 WHEN 25 THEN 55.7558 + (random() - 0.5) * 0.3
        WHEN 26 THEN 30.0444 + (random() - 0.5) * 0.3 WHEN 27 THEN -1.2921 + (random() - 0.5) * 0.3
        WHEN 28 THEN -26.2041+ (random() - 0.5) * 0.3 ELSE 43.6532 + (random() - 0.5) * 0.3
    END,
    CASE (i % 30)
        WHEN  0 THEN -74.0060+ (random() - 0.5) * 0.3 WHEN  1 THEN -118.2437+ (random() - 0.5) * 0.3
        WHEN  2 THEN -87.6298+ (random() - 0.5) * 0.3 WHEN  3 THEN -95.3698+ (random() - 0.5) * 0.3
        WHEN  4 THEN -75.1652+ (random() - 0.5) * 0.3 WHEN  5 THEN -112.0740+ (random() - 0.5) * 0.3
        WHEN  6 THEN -117.1611+ (random() - 0.5) * 0.3 WHEN  7 THEN -122.3321+ (random() - 0.5) * 0.3
        WHEN  8 THEN -80.1918+ (random() - 0.5) * 0.3 WHEN  9 THEN -77.0369+ (random() - 0.5) * 0.3
        WHEN 10 THEN  -0.1278+ (random() - 0.5) * 0.3 WHEN 11 THEN   2.3522+ (random() - 0.5) * 0.3
        WHEN 12 THEN  13.4050+ (random() - 0.5) * 0.3 WHEN 13 THEN  12.4964+ (random() - 0.5) * 0.3
        WHEN 14 THEN  -3.7038+ (random() - 0.5) * 0.3 WHEN 15 THEN 139.6503+ (random() - 0.5) * 0.3
        WHEN 16 THEN 121.4737+ (random() - 0.5) * 0.3 WHEN 17 THEN 114.1694+ (random() - 0.5) * 0.3
        WHEN 18 THEN 103.8198+ (random() - 0.5) * 0.3 WHEN 19 THEN  77.2090+ (random() - 0.5) * 0.3
        WHEN 20 THEN  72.8777+ (random() - 0.5) * 0.3 WHEN 21 THEN 151.2093+ (random() - 0.5) * 0.3
        WHEN 22 THEN -46.6333+ (random() - 0.5) * 0.3 WHEN 23 THEN -58.3816+ (random() - 0.5) * 0.3
        WHEN 24 THEN -99.1332+ (random() - 0.5) * 0.3 WHEN 25 THEN  37.6173+ (random() - 0.5) * 0.3
        WHEN 26 THEN  31.2357+ (random() - 0.5) * 0.3 WHEN 27 THEN  36.8219+ (random() - 0.5) * 0.3
        WHEN 28 THEN  28.0473+ (random() - 0.5) * 0.3 ELSE -79.3832+ (random() - 0.5) * 0.3
    END
FROM generate_series(1, 2000000) AS i;

ANALYZE VerificationEvent;
SELECT count(*) FROM VerificationEvent;
