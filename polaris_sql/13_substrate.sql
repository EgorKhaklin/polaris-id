-- AI-context: M2-3 / R10-3 — substrate-dependency manifest, queryable form.
-- The prose form is docs/design/substrate.md; this SQL view is its mirror so
-- the manifest is machine-readable. The two MUST stay in sync — if a row
-- is added or removed here, mirror it in the prose, and vice versa.
-- Updates to this file should be reflected in 00_load_all.sql's load order.
-- ============================================================================
-- POLARIS — IDENTITY TOKEN SYSTEM
-- 13_substrate.sql : Substrate-dependency manifest (M2-3 / R10-3)
--
-- Operationalizes the architectural argument from Appendix E of
-- docs/paper/polaris_project_report.pdf: "every higher-level property of an identity
-- system is derivative of the primitives it sits on top of." Each row in
-- the SystemDependency view names one primitive Polaris depends on; the
-- columns capture what fails if that primitive is compromised, the path
-- off the broken primitive, and how Polaris detects the failure.
--
-- The view is read-only by construction (VALUES-backed). DDL is the only
-- way to amend it — which means changes are reviewable and require a
-- schema-load run. The prose form (docs/design/substrate.md) is the longer
-- explanation; this view is the indexable form. Both must stay in sync.
-- ============================================================================

DROP VIEW IF EXISTS SystemDependency;

CREATE VIEW SystemDependency AS
SELECT
    primitive,
    layer,
    authority,
    role,
    fail_mode,
    replacement,
    detection
FROM (VALUES

    -- ------------------------------------------------------------------------
    -- Cryptographic primitives
    -- ------------------------------------------------------------------------
    ('ML-DSA-65 / ML-DSA-87', 'crypto', 'NIST FIPS 204',
     'Primary signing algorithm; CryptographicAlgorithm rows; bound to IdentityToken.algorithm_id',
     'Token signatures forgeable; authenticity claim has no referent',
     'Multi-signature transitional state (M2-6 / R11-1) — accept any in active set during migration',
     'CryptographicAlgorithm.deprecation_date column; external cryptanalysis publication'),

    ('SLH-DSA',              'crypto', 'NIST FIPS 205',
     'Hedge against ML-DSA cryptanalysis; hash-based, distinct mathematical assumption',
     'Hedge gone; if ML-DSA also broken, the diversity assumption itself has failed',
     'Same multi-sig path as ML-DSA',
     'CryptographicAlgorithm.deprecation_date'),

    ('ECDSA / RSA',          'crypto', 'NIST legacy',
     'Migration semantics only; new tokens NOT issued under classical algorithms',
     'Already known quantum-broken (Shor 1994); harvest-now-decrypt-later applies',
     'N/A — these are the algorithms being replaced',
     'CryptographicAlgorithm.quantum_resistant = FALSE flags every classical row'),

    ('SHA-3 / BLAKE3 / BLAKE2b', 'crypto', 'NIST FIPS 202; IETF',
     'Hash functions for AnchorBatch.merkle_root (R10-2), the ZK-SNARK Fiat-Shamir transform, CSRF HMAC, scrypt internals',
     'Password hash collision resistance lost; CSRF forgeable; Merkle root forgeable',
     'werkzeug method= parameter; anchoring.py SUPPORTED_HASHES extensible',
     'Cryptanalysis publication'),

    ('Merkle commitment (in-tree)', 'crypto', 'Polaris polaris_web/anchoring.py',
     'Per-batch commitment to BlockchainAnchor leaves (R10-2 / M2-2); AnchorBatch.merkle_root + per-leaf inclusion proofs',
     'Hash compromise voids batches under that hash; root forgery detectable via /api/anchor/verify',
     'New hash entry in SUPPORTED_HASHES; existing batches keep their original hash',
     'Operator NIST/hash-status monitoring'),

    ('Plonky2 SNARK (in-tree)', 'crypto', 'Polaris polaris_zk/ Rust crate using mir-protocol/plonky2',
     'Real ZK-SNARK for ZERO_KNOWLEDGE verifications (R10-1 / M2-1); FRI-based, post-quantum-comfortable; proves Merkle inclusion in TokenStateEpoch.merkle_root',
     'Circuit soundness bug accepts invalid witnesses silently; upstream library breaking changes force re-port',
     'B3 epoch-bounded architecture allows re-port to Halo2 without changing schema',
     'Cryptographic audits of circuit code; Plonky2 upstream advisories; in-tree adversary tests'),

    ('Rust toolchain', 'runtime', 'Rust language team',
     'Compiles polaris_zk/ crate; Plonky2 0.2 requires nightly channel',
     'Operator cannot rebuild binary; existing pre-built binary continues to verify',
     'Pin to rust-toolchain.toml; ship pre-built binaries for common platforms',
     'cargo build failures; CI on toolchain upgrades'),

    ('scrypt (Werkzeug)',    'crypto', 'RFC 7914',
     'AppUser.password_hash encoding; CWE-916 mitigation',
     'Password hashes lose pre-image resistance under realistic attacker compute',
     'Argon2id — single string change in security.py:hash_password + re-hash on next login',
     'OWASP cost-parameter guidance update'),

    ('HMAC-SHA256',          'crypto', 'RFC 2104; FIPS 180-4',
     'CSRF token signing in security.py:_csrf_sign',
     'CSRF tokens forgeable; cross-site requests defeat the body-based protection',
     'HMAC-SHA3 / HMAC-BLAKE3 — single hmac module parameter',
     'Cryptanalysis of SHA-256 (extremely unlikely near-term)'),

    ('secrets / OS PRNG',    'crypto', 'Python stdlib; Linux kernel',
     'Session tokens, CSRF salt, future ZK commitment randomness, Redis Lua nonces',
     'If predictable, every secret produced post-boot is predictable; full session forgery',
     'Hardware RNG fallback (RDRAND / TPM); user-space entropy mixing — operator concern',
     'OS-level audit; Polaris cannot detect from inside the application'),

    -- ------------------------------------------------------------------------
    -- Network primitives
    -- ------------------------------------------------------------------------
    ('TLS 1.3',              'network', 'IETF RFC 8446; CA infra',
     'Wire protection; required in production via POLARIS_COOKIE_SECURE / POLARIS_HSTS',
     'Wire transcripts harvestable; harvest-now-decrypt-later on login transcripts and cookies',
     'TLS 1.3 with PQ-hybrid key exchange (e.g. X25519+Kyber768) at the reverse proxy',
     'Operator-level TLS configuration audit'),

    ('HTTP/HTTPS framing',   'network', 'IETF RFC 7230 / RFC 7540',
     'Request layer; CSRF tokens, session cookies, rate-limit headers all live here',
     'Implementation-level desync / Host-confusion bugs (covered by docs/operator/SECURITY-CONTROLS.md)',
     'N/A — application-layer concern',
     'App-layer testing'),

    -- ------------------------------------------------------------------------
    -- Storage primitives
    -- ------------------------------------------------------------------------
    ('PostgreSQL 14+',       'storage', 'PostgreSQL Global Development Group',
     'Every CHECK / trigger / partial-unique index; C1 audit invariant lives here',
     'Trigger-bypass CVE silently violates C1; DDL escalation drops triggers / alters tables',
     'Same-family migration (Aurora / CockroachDB / EnterpriseDB); state-machine triggers may need port-specific work',
     'PostgreSQL CVE feed; pg_audit on production tables (BACKLOG)'),

    ('Filesystem (data + WAL + secrets)', 'storage', 'Linux kernel; underlying volume',
     'Data pages, WAL, /etc/polaris/secret_key',
     'Data-at-rest exposure — Polaris does NOT do app-level encryption-at-rest',
     'Operator policy: LUKS / dm-crypt / cloud-native envelope encryption',
     'Outside Polaris purview'),

    ('Redis (rate limiter)', 'storage', 'Redis Ltd.',
     'Atomic sliding-window per-IP rate counters when POLARIS_REDIS_URL set; Lua script',
     'Unreachable → allow() fails closed (denies); 429s until recovery',
     'Auto-fallback to InMemoryRateLimiter via POLARIS_RATE_LIMIT_BACKEND=memory (cap multiplication caveat)',
     '/api/health rate_limiter.ok; sustained false > 60s = paging'),

    -- ------------------------------------------------------------------------
    -- Runtime
    -- ------------------------------------------------------------------------
    ('Python 3.10+',         'runtime', 'Python Software Foundation',
     'Every line of polaris_web/; CPython GIL is load-bearing for InMemoryRateLimiter atomicity',
     'Interpreter CVE; PEP-703 free-threaded Python invalidating GIL-derived atomicity',
     'Pin to GIL-d Python until atomicity audit completes',
     'CPython release notes'),

    ('Flask + Werkzeug',     'runtime', 'Pallets Projects',
     'Web framework; session signing; password hashing; constant-time compare in check_password_hash',
     'Framework-level CVE (e.g. session-decoding bug)',
     'Werkzeug → Starlette / pure ASGI mechanical; Flask → Quart preserves API',
     'Pallets security advisories'),

    ('psycopg2',             'runtime', 'psycopg2 maintainers',
     'PostgreSQL driver; parameterized queries are the SQL-injection defense',
     'Driver-level CVE',
     'psycopg3 — drop-in for the API surface Polaris uses',
     'psycopg2 advisories'),

    ('gunicorn',             'runtime', 'Benoit Chesneau',
     'WSGI server; worker model defines whether rate limiter needs Redis',
     'Pre-fork model bug; worker isolation breach',
     'uWSGI / Hypercorn / direct ASGI — mechanical given the WSGI app object',
     'gunicorn release notes'),

    -- ------------------------------------------------------------------------
    -- Standards (external authority)
    -- ------------------------------------------------------------------------
    ('NIST FIPS 203/204/205','standards', 'NIST (US Department of Commerce)',
     'PQ standards defining ML-KEM, ML-DSA, SLH-DSA; sovereignty stance per Appendix E',
     'Standards withdrawal or revision; political capture of NIST collapses sovereignty argument',
     'Cryptographic-diversity stance — multi-source standards (NIST + ETSI + KCMVP); extends M2-6',
     'Public standards process; NIST publication of withdrawal'),

    ('W3C DID',              'standards', 'W3C',
     'BlockchainAnchor.did references the DID specification',
     'Standards revision invalidates did column format',
     'Schema migration (column type change); anchor mechanism (M2-2) is independent',
     'W3C-DID working group publications'),

    ('ISO 3166-2',           'standards', 'ISO',
     'Individual.jurisdiction / Agency.jurisdiction codes',
     'Code reassignment makes existing rows ambiguous',
     'One-time UPDATE per published reassignment',
     'ISO publishes amendments quarterly'),

    -- ------------------------------------------------------------------------
    -- Hardware (assumed but not in repo)
    -- ------------------------------------------------------------------------
    ('Token hardware enclave', 'hardware', 'Token vendor',
     'Biometric template storage; signing operation; local-match-required-for-sign',
     'Enclave compromise → biometric template extractable → the token''s hardware binding defeated',
     'Hardware refresh; hardware-backed key custody (PKCS#11 / KMS)',
     'Vendor disclosure; cryptographic side-channel research'),

    ('Server hardware (TPM)', 'hardware', 'Server vendor; TCG',
     'Key sealing; secret_key at-rest protection',
     'Server compromise → secret_key extractable → all active sessions forgeable',
     'Operator policy: secret rotation; HSM custody',
     'Outside Polaris'),

    -- ------------------------------------------------------------------------
    -- Human / operational substrate (Appendix E §3 implication 3)
    -- ------------------------------------------------------------------------
    ('Credentialed operators', 'human', 'Issuing-agency personnel processes',
     'Perform UC-1 enrollment, UC-4 reserve activation, UC-7 warrant audits',
     'Insider-threat issuance (rogue token) or mass revocation (denaturalization-style)',
     'Personnel vetting; M2-11 (R11-6) issuer-discretion bounds; M2-8 cross-issuer trust',
     'AuthAuditLog records every administrative action'),

    ('Out-of-band identity verification', 'human', 'Operator policy',
     'UC-4 reserve activation today; M2-7 catastrophic-loss recovery (R11-2)',
     'Compromised out-of-band channels enable reissuance attacks',
     'Layered verification (multi-factor including human witness)',
     'UC-7 audit trail review'),

    -- ------------------------------------------------------------------------
    -- Hardware substrate
    -- ------------------------------------------------------------------------
    ('Hardware key custody (PKCS#11 HSM / KMS)', 'hardware', 'PKCS#11; cloud KMS',
     'M2-6 signing keys held in hardware where deployed; the custody interface drives file, PKCS#11 and KMS backends (polaris_web/custody.py)',
     'Key extraction if a custody backend is compromised or misconfigured',
     'The custody interface abstracts the backend; a signature that cannot be produced by the custodied key never degrades to an ephemeral one',
     'Custody driver configuration; public-key fingerprint pinning')

) AS d (primitive, layer, authority, role, fail_mode, replacement, detection);

COMMENT ON VIEW SystemDependency IS
  'Substrate-dependency manifest (M2-3 / R10-3). Operationalizes Appendix E '
  'of docs/paper/polaris_project_report.pdf: every higher-level property of the system '
  'is derivative of the primitives listed here. Mirror of docs/design/substrate.md '
  '(prose form). The two must stay in sync. Read-only by construction (VALUES-'
  'backed view); changes are DDL and reviewable.';

-- ----------------------------------------------------------------------------
-- Quick sanity tests — these run when 13_substrate.sql is loaded directly
-- (no-ops when included via 00_load_all.sql since the same checks are in
-- 12_v7_constraints.sql or run by test_app.py).
-- ----------------------------------------------------------------------------
DO $$
DECLARE
    v_count INTEGER;
BEGIN
    SELECT count(*) INTO v_count FROM SystemDependency;
    IF v_count < 15 THEN
        RAISE EXCEPTION
            'SystemDependency view returned % rows; manifest looks incomplete',
            v_count;
    END IF;

    -- Every row should have non-NULL fail_mode and replacement.
    SELECT count(*) INTO v_count FROM SystemDependency
        WHERE fail_mode IS NULL OR replacement IS NULL OR detection IS NULL;
    IF v_count > 0 THEN
        RAISE EXCEPTION
            'SystemDependency has % rows with NULL fail_mode / replacement / detection',
            v_count;
    END IF;

    -- Every layer label should be one of the canonical set.
    SELECT count(*) INTO v_count FROM SystemDependency
        WHERE layer NOT IN ('crypto','network','storage','runtime','standards','hardware','human');
    IF v_count > 0 THEN
        RAISE EXCEPTION
            'SystemDependency has % rows with invalid layer label',
            v_count;
    END IF;

    RAISE NOTICE 'SystemDependency view OK: % rows, all layer labels valid',
        (SELECT count(*) FROM SystemDependency);
END$$;

-- ============================================================================
-- END OF 13_substrate.sql
-- One read-only view (SystemDependency). The prose companion is
-- docs/design/substrate.md and the test mirror is in test_app.py
-- (SubstrateManifestTests).
-- ============================================================================
