# The substrate

**Reader:** an engineer or an assessor. **Job:** Every primitive Polaris depends on, and which are reserved rather than built.

Every higher-level property of an identity system is derivative of the
primitives it sits on. Change a primitive and the property changes;
compromise one and the property has no referent. This is the manifest that
takes that seriously: for every primitive Polaris stands on, what stops being
true if it is compromised, what the replacement would be, and how the
compromise would be noticed.

The same manifest is mirrored in SQL as the `SystemDependency` view
(`polaris_sql/13_substrate.sql`) so the inventory is queryable. The two
representations must agree; a row in one without a row in the other is
considered the manifest being out of sync.

## How to read this document

Each row records:

- **Primitive**: the named dependency.
- **Layer**: `crypto` / `network` / `storage` / `runtime` / `standards`
  / `hardware` / `human`.
- **Authority**: who governs this primitive (NIST, IETF, the kernel,
  ourselves, etc.). When the primitive is governed by an external body,
  that body's stance is load-bearing for Polaris.
- **Role**: where Polaris uses it. Specific column/file/function
  references where applicable.
- **Fail mode**: what is no longer true if this primitive is compromised
  or withdrawn. Stated as a positive claim that becomes false.
- **Replacement**: the path off the broken primitive. Sometimes a
  scheduled migration; sometimes a reissuance of every credential.
- **Detection**: the signal Polaris (or its operator) sees when this
  primitive starts to fail. Where the schema can detect, that's named;
  where only operational policy can, the policy is named.

## Manifest

### Cryptographic primitives

#### ML-DSA-65 / ML-DSA-87
- **Layer:** crypto
- **Authority:** NIST (FIPS 204, finalized August 2024)
- **Role:** Primary signing algorithm for token credentials. Encoded as
  `CryptographicAlgorithm` rows; bound to `IdentityToken.algorithm_id`;
  bounded by `AgencyAlgorithmAuth` for who may issue under what.
- **Fail mode:** Token signatures forgeable; every signed binding (token
  ↔ holder, token ↔ algorithm) becomes asserted by whoever recovers the
  signing key, not the original issuer. The schema's authenticity claim
  has no referent.
- **Replacement:** Multi-signature transitional state:
  each token carries signatures from N algorithms during the migration
  window; verification accepts any in the active set. Without,
  replacement requires simultaneous mass reissuance of every token.
- **Detection:** `CryptographicAlgorithm.deprecation_date` is the
  proactive signal: set when a cryptanalytic advance becomes public,
  before the substrate transitions. Reactive signal: third-party
  cryptanalysis publication.

#### SLH-DSA
- **Layer:** crypto
- **Authority:** NIST (FIPS 205)
- **Role:** Hedge against ML-DSA cryptanalysis. Stateless hash-based
  signature; security reduces to the hash function rather than algebraic
  hardness, so it survives breaks that do not also break SHA-3.
- **Fail mode:** If SLH-DSA breaks, the hedge is gone, but only ML-DSA
  tokens issued under the same hedge assumption are at risk. SLH-DSA
  itself is not the operational default.
- **Status at v9.232:** registry rows only. No SLH-DSA signer is wired, which
  `docs/reference/PQC-POSTURE.md` records as registered and not wired.
- **Replacement:** Same multi-signature path as ML-DSA. The whole
  rationale for keeping SLH-DSA in the schema is that it was vetted
  under different mathematical assumptions; if both break together,
  the assumption-diversity hedge has failed and the response is
  qualitatively the same as ML-DSA-only failure.
- **Detection:** Same as ML-DSA, `deprecation_date` and external
  cryptanalysis.

#### ECDSA / RSA
- **Layer:** crypto
- **Authority:** NIST (legacy)
- **Role:** Present in `CryptographicAlgorithm` only for migration
  semantics. NEW tokens are not issued under classical algorithms (this
  is a sovereignty stance rather than a technical preference: see the report's
  §3 "second implication").
- **Fail mode:** Already known to be quantum-broken (Shor 1994). Any
  token issued under classical algorithms is in a latent pre-collapse
  state per Mosca's inequality.
- **Replacement:** N/A, these are the algorithms being replaced.
- **Detection:** `CryptographicAlgorithm.quantum_resistant = FALSE`
  flags every classical row; `idx_identitytoken_individual` lets a
  query identify every token bound to a non-PQ algorithm in O(log n)
  per holder.

#### SHA-3 / BLAKE3 / BLAKE2b
- **Layer:** crypto
- **Authority:** NIST (FIPS 202 for SHA-3); IETF / academic for the
  BLAKE family
- **Role:** Hash functions for `AnchorBatch.merkle_root`, the ZK-SNARK Fiat-Shamir transform,
  CSRF-token integrity (HMAC-SHA256 in `security.py`), and password
  scrypt's internal hash (Werkzeug default).
- **Fail mode:** Merkle roots become forgeable, breaking the anchor-
  inclusion invariant. Password hashes lose collision resistance.
  CSRF-token signatures forgeable.
- **Replacement:** Migrate the hash choice to a stronger primitive
  (`anchoring.py` SUPPORTED_HASHES is extensible).
  `werkzeug.security.generate_password_hash(method=...)` accepts the
  replacement; CSRF token construction is a single function in
  `security.py`.
- **Detection:** Cryptanalysis publication. SHA-3's wide security margin
  makes near-term failure unlikely; BLAKE3 is younger but the design
  draws on better-vetted primitives.

#### scrypt (Werkzeug default)
- **Layer:** crypto
- **Authority:** RFC 7914
- **Role:** `AppUser.password_hash` is scrypt-encoded by
  `werkzeug.security.generate_password_hash(method='scrypt')`. CWE-916
  mitigation.
- **Fail mode:** Password hashes lose pre-image resistance under
  realistic attacker compute budgets. Stolen hashes become recoverable
  passwords.
- **Replacement:** Argon2id is the canonical successor, Werkzeug supports
  it; switching is a single string change in `security.py:hash_password`
  plus a re-hash-on-next-login migration window.
- **Detection:** When the OWASP-recommended cost parameter for scrypt
  exceeds what's tractable for routine login, that's the signal.

#### HMAC-SHA256
- **Layer:** crypto
- **Authority:** RFC 2104; SHA-256 from FIPS 180-4
- **Role:** CSRF token signing in `security.py:_csrf_sign`. Signs
  `(session_id, salt)` so a stolen CSRF cookie can't be replayed
  cross-session.
- **Fail mode:** CSRF token forgeability, any cross-site request can
  forge a valid token. C-tier defense reduces to body-based protections
  alone.
- **Replacement:** HMAC-SHA3 / HMAC-BLAKE3, algorithm is a single
  parameter to Python's `hmac` module.
- **Detection:** Cryptanalysis of SHA-256 specifically (extremely
  unlikely near-term).

#### `secrets` module / OS PRNG
- **Layer:** crypto
- **Authority:** Python stdlib; OS kernel
- **Role:** Session token generation, CSRF salt, ZK proof-commitment
  randomness, Redis
  rate-limiter Lua-script nonces.
- **Fail mode:** If the OS PRNG is predictable (compromised entropy
  source), every secret produced post-boot is predictable. The
  attacker can forge sessions, CSRF tokens, and ZK commitments.
- **Replacement:** Hardware RNG fallback (RDRAND / TPM); user-space
  entropy mixing. This is a kernel-level concern, not a Polaris
  concern: but Polaris depends on it.
- **Detection:** OS-level audit. Polaris can't detect a compromised
  PRNG from inside the application.

### Network primitives

#### TLS 1.3 (deployment-layer)
- **Layer:** network
- **Authority:** IETF (RFC 8446); CA infrastructure
- **Role:** Wire protection between client browser and Polaris reverse
  proxy. Required in production (`POLARIS_COOKIE_SECURE=1`,
  `POLARIS_HSTS=1`).
- **Fail mode:** Wire transcripts harvestable; harvest-now-decrypt-later
  applies to login transcripts (passwords) and authenticated session
  cookies. PQ-ready TLS (Kyber-based key exchange) is the migration
  target.
- **Replacement:** TLS 1.3 with PQ-hybrid key exchange (e.g.,
  X25519+Kyber768): already deployable in modern reverse proxies.
- **Detection:** Operator-level (TLS configuration audit).

#### HTTP/HTTPS framing, cookies, headers
- **Layer:** network
- **Authority:** IETF (HTTP/1.1 RFC 7230, HTTP/2 RFC 7540)
- **Role:** Polaris is HTTP-shaped. CSRF tokens, session cookies,
  rate-limit headers all live in HTTP semantics.
- **Fail mode:** Generally these don't fail; specific implementation
  bugs (HTTP/2 desync, Host-header confusion) are application-layer
  concerns covered in `docs/operator/SECURITY-CONTROLS.md`.
- **Replacement:** N/A.
- **Detection:** App-layer testing.

### Storage primitives

#### PostgreSQL 14+
- **Layer:** storage
- **Authority:** PostgreSQL Global Development Group
- **Role:** Every CHECK constraint, every trigger, every partial unique
  index is the schema's enforcement mechanism. The append-only audit
  invariant (C1) is enforced by `reject_audit_modification`:
  PostgreSQL is the place that enforcement lives.
- **Fail mode:** A PostgreSQL bug that allows trigger bypass would
  silently violate C1. A privilege escalation (rare but possible:
  CVE history exists) gives the attacker DDL, which can DROP the
  triggers and ALTER the table. Both compromise the audit invariant
  (the load-bearing security claim per MISSION.md).
- **Replacement:** Polaris is portable PostgreSQL, the dialect is
  standard enough that migration to a same-family replacement (Aurora,
  CockroachDB, EnterpriseDB) is mechanical. The schema-level
  enforcement of state-machine triggers is the part most likely to
  need port-specific work.
- **Detection:** PostgreSQL CVE feed. Read-only replicas plus
  `pg_audit` would surface DDL on production tables; not currently
  configured but listed in `docs/BACKLOG.md`.

#### Filesystem (data + WAL + secrets)
- **Layer:** storage
- **Authority:** Linux kernel; underlying volume
- **Role:** Data pages, write-ahead log, `/etc/polaris/secret_key`.
- **Fail mode:** Data-at-rest exposure. There is no application-level
  encryption at rest; the operator's filesystem encryption, LUKS or dm-crypt,
  is the layer that matters, and choosing it is one of the operator decisions
  in the readiness ledger.
- **Replacement:** Operator policy (LUKS + key in TPM; cloud-native
  envelope encryption).
- **Detection:** Outside Polaris's purview.

#### Redis: multi-process rate limiter)
- **Layer:** storage
- **Authority:** Redis Ltd.
- **Role:** Atomic sliding-window per-IP rate counters when
  `POLARIS_REDIS_URL` is set and `POLARIS_RATE_LIMIT_BACKEND=redis`.
  Backed by a Lua script for atomicity (see `docs/design/rate-limiter.md`).
- **Fail mode:** Redis unreachable → `RedisRateLimiter.allow()` fails
  closed (returns False) per OWASP "fail securely". Result: every
  rate-limited request returns 429 until Redis recovers. The app stays
  up; new logins and writes do not.
- **Replacement:** Auto-fallback to `InMemoryRateLimiter` is configured
  if `POLARIS_RATE_LIMIT_BACKEND=memory` is set as an emergency
  override. Remember the cap multiplication (workers × configured) when
  you do.
- **Detection:** `/api/health` reports `{rate_limiter: {ok}}`; sustained
  `ok: false` for over 60s is a paging condition.

### Runtime

#### Python 3.10+
- **Layer:** runtime
- **Authority:** Python Software Foundation
- **Role:** Every line of `polaris_web/`. CPython's GIL provides
  structural guarantees that `InMemoryRateLimiter` relies on (deque
  popleft + append are atomic at the bytecode level). A move to a
  GIL-free Python interpreter would force a re-audit of every
  shared-state structure.
- **Fail mode:** Interpreter security bug (rare); PEP-703 free-threaded
  Python invalidating GIL-derived atomicity.
- **Replacement:** Pin to GIL'd Python until atomicity audit completes.
- **Detection:** CPython release notes; `sys.version`.

#### Flask + Werkzeug
- **Layer:** runtime
- **Authority:** Pallets Projects
- **Role:** Web framework, request parsing, session signing, password
  hashing.
- **Fail mode:** Framework-level CVE (e.g., session-decoding bug). The
  `werkzeug.security.check_password_hash` constant-time comparison is
  load-bearing for the timing-attack resistance of `authenticate()`.
- **Replacement:** Werkzeug → Starlette or pure ASGI is mechanical but
  significant; Flask → Quart preserves API. No imminent migration
  driver.
- **Detection:** Pallets security advisories.

#### psycopg2
- **Layer:** runtime
- **Authority:** psycopg2 maintainers
- **Role:** PostgreSQL driver. Parameterized-query enforcement (no
  string concatenation) is what makes Polaris SQL-injection-safe.
- **Fail mode:** Driver-level CVE.
- **Replacement:** psycopg3, drop-in for the API surface Polaris uses.
- **Detection:** psycopg2 advisories.

#### gunicorn
- **Layer:** runtime
- **Authority:** Benoit Chesneau
- **Role:** WSGI server in production; worker model defines whether
  the rate limiter needs Redis (see docs/operator/DEPLOYMENT.md).
- **Fail mode:** Pre-fork model bug; worker isolation breach.
- **Replacement:** uWSGI / Hypercorn / direct ASGI, mechanical given
  the WSGI app object.
- **Detection:** gunicorn release notes.

### Standards (external authority)

#### NIST FIPS 203 / 204 / 205
- **Layer:** standards
- **Authority:** NIST (US Department of Commerce)
- **Role:** The PQ standards that define ML-KEM, ML-DSA, SLH-DSA. The
  schema's commitment to FIPS-finalized primitives is "a sovereignty
  stance rather than a technical preference.
- **Fail mode:** Standards withdrawal or revision. NIST's authority
  itself is the load-bearing assumption: if NIST were politically
  captured to mandate adversary-authored algorithms, the sovereignty
  argument collapses regardless of the schema's local enforcement.
- **Replacement:** Cryptographic-diversity stance, issue under
  multiple PQ algorithms from different national standards bodies
  (NIST + ETSI + Korean KCMVP). Not currently modeled; would extend to include source-of-standard.
- **Detection:** Public standards process; NIST publication of
  withdrawal notice.

#### W3C Decentralized Identifiers (DID)
- **Layer:** standards
- **Authority:** W3C
- **Role:** `BlockchainAnchor.did` references the DID specification.
  The optional ledger-anchoring path depends on it.
- **Fail mode:** Standards revision invalidates the `did` column
  format. The current `VARCHAR(200)` is permissive enough to survive
  most revisions; a complete rewrite would force schema migration.
- **Replacement:** Schema migration (column type change). The
  underlying anchor mechanism is independent of the
  DID standard, DID is the naming convention, not the cryptographic
  primitive.
- **Detection:** W3C-DID working group publications.

#### Merkle tree commitment (in-tree)
- **Layer:** crypto
- **Authority:** in-tree primitive, `polaris_web/anchoring.py`
  (`compute_batch`, `merkle_root`, `inclusion_proof`, `verify_proof`).
- **Role:** Per-batch commitment to one or more `BlockchainAnchor`
  leaves under a per-algorithm advisory lock. The batch is one of the
  audit-of-record instances; see [audit-of-record.md](audit-of-record.md).
- **Fail mode:** Hash-function compromise voids every batch closed
  under that algorithm. Detection is via `GET /api/anchor/verify/<id>`
  (server-side proof reconstruction): a tampered log fails
  verification, so root compromise is detectable but not preventable
  retroactively.
- **Replacement:** Add the new hash name to `SUPPORTED_HASHES` in
  `anchoring.py`; thereafter `close_anchor_batch` calls under the new
  algorithm pick it up. Existing batches keep their original hash:
  the audit is per-batch, not global.
- **Detection:** Operator must monitor NIST hash-function status; SHA3
  has no known weakness as of 2026 but is on a 20-year radar.
- **See also:** `docs/design/anchoring.md` for the full write-up.

#### Plonky2 SNARK (in-tree)
- **Layer:** crypto
- **Authority:** in-tree dependency, `polaris_zk/` Rust crate using
  `plonky2 = "0.2"` from crates.io (upstream: `mir-protocol/plonky2`).
- **Role:** Real ZK-SNARK for ZERO_KNOWLEDGE verifications. The
  Plonky2 circuit (`polaris_zk/src/lib.rs`) proves Merkle inclusion
  in `TokenStateEpoch.merkle_root` bound to `(epoch_id, context_id,
  nonce)` public inputs. FRI-based, hash-only: post-quantum-
  comfortable. The C3+A4+B3 pick from the alignment-exploration
  Sanctum. Closes Substrate-D arc to 5/5.
- **Fail mode:** A circuit soundness bug accepts invalid witnesses
  silently. A breaking change in upstream Plonky2 forces a re-port
  (B3 architecture keeps the schema stable across SNARK migrations).
- **Replacement:** B3 epoch-bounded design lets us re-port to Halo2
  in a future migration without changing the schema; the
  `TokenStateEpoch.merkle_root` column is hash-family-agnostic.
- **Detection:** Operator monitors upstream Plonky2 advisories;
  Cryptographic audits of the circuit code; in-tree unit tests
  (`cargo test`) include malicious-prover, replay, and cross-epoch
  scenarios.
- **See also:** `docs/design/zk-snark.md` for the full write-up.

#### Rust toolchain (assumed, and required to build)
- **Layer:** runtime
- **Authority:** Rust language team + nightly channel.
- **Role:** Compiles `polaris_zk/` crate. Required at build time;
  not required at runtime if the pre-built binary is distributed.
  Plonky2 0.2 requires Rust *nightly* (uses
  `#![feature(specialization)]`).
- **Fail mode:** Operator cannot rebuild the binary; existing
  pre-built binary continues to verify proofs. A Rust major-version
  breaking change could force the crate to migrate.
- **Replacement:** Pin to a known-good `rust-toolchain.toml`
  (`polaris_zk/rust-toolchain.toml` specifies nightly); ship pre-built
  binaries for common platforms (macOS arm64, Linux x86_64) so
  end-users don't need a Rust install.
- **Detection:** Build failures on `cargo build` surface immediately;
  CI catches breakage on toolchain upgrades.

#### ISO 3166-2
- **Layer:** standards
- **Authority:** ISO
- **Role:** `Individual.jurisdiction` and `Agency.jurisdiction` use
  ISO 3166-2 codes (e.g., `US-PA`).
- **Fail mode:** Code reassignment (rare but happens, e.g., `RS-CS`
  reassigned). A Polaris row with the old code becomes ambiguous.
- **Replacement:** Operator policy: when ISO publishes a reassignment,
  run a one-time UPDATE.
- **Detection:** ISO publishes amendments quarterly; subscribe.

### Hardware (assumed but not in repo)

#### Token hardware secure enclave
- **Layer:** hardware
- **Authority:** token vendor
- **Role:** Stores biometric template; performs the signing operation;
  enforces the local biometric-match-required-for-sign property.
  Polaris records `IdentityToken.biometric_binding_type`: the
  enclave is the substrate that makes that field meaningful.
- **Fail mode:** Enclave compromise → biometric template extractable
  → the token's hardware binding partially defeated.
- **Replacement:** Hardware refresh; hardware-backed key custody
  (PKCS#11 / KMS).
- **Detection:** Vendor disclosure; cryptographic side-channel
  research publication.

#### Server hardware (TPM, secure boot)
- **Layer:** hardware
- **Authority:** server vendor; TCG (TPM)
- **Role:** Server-side key sealing; secret_key at-rest protection.
- **Fail mode:** Server compromise → secret_key extractable → all
  active sessions forgeable.
- **Replacement:** Operator policy, secret rotation; HSM custody.
- **Detection:** Outside Polaris.

### The human and operational substrate

#### Credentialed operators
- **Layer:** human
- **Authority:** issuing agencies' personnel processes
- **Role:** Issuing-agency staff perform UC-1 enrollment, UC-4 reserve
  activation, UC-7 warrant audits. The schema records WHAT they do;
  WHO they are is a personnel-vetting concern outside the schema.
- **Fail mode:** Insider-threat issuance (rogue token) or insider-threat
  revocation (denaturalization-style mass revocation). The schema
  defends against the second through issuer-discretion
  bounds; against the first only through audit (UC-7) plus
  cryptographic-diversity-across-issuers.
- **Replacement:** Personnel-vetting policy; periodic key ceremony
  re-attestation.
- **Detection:** `AuthAuditLog` records every administrative action.

#### Out-of-band identity verification
- **Layer:** human
- **Authority:** operator policy
- **Role:** UC-4 reserve activation (today) and catastrophic-loss
  recovery, future) both require identity verification by
  channels other than the token itself: biometric + sworn statement
  + secondary identification. Polaris records the result; the
  verification process is human.
- **Fail mode:** Compromised out-of-band channels enable reissuance
  attacks.
- **Replacement:** Layered verification (multi-factor including human
  witness).
- **Detection:** UC-7 audit trail review.

### Hardware key custody

#### Hardware key custody (PKCS#11 HSM / KMS)
- **Layer:** hardware
- **Authority:** PKCS#11 (OASIS); cloud KMS providers
- **Role:** M2-6 signing keys held in hardware where deployed. The
  custody interface (`polaris_web/custody.py`) drives file, PKCS#11 and
  KMS backends behind one signing API, so a key can live in an HSM or a
  managed KMS without changing the issuance path.
- **Fail mode:** Key extraction if a custody backend is compromised or
  misconfigured; a backend that cannot produce a signature at all.
- **Replacement:** The custody interface abstracts the backend; a
  signature that cannot be produced by the custodied key never degrades
  to an ephemeral one (the signing path fails closed).
- **Detection:** Custody driver configuration; public-key fingerprint
  pinning surfaces an unexpected key.

## Re-evaluation triggers

This manifest must be revisited when:

- **A new external dependency is introduced** (new Python package, new
  hash function, new standard). The PR adding the dependency must add
  the row here.
- **An external authority publishes a withdrawal or deprecation
  notice** (NIST FIPS 204 successor, RFC obsolescence, vendor EOL).
- **A primitive moves between layers**: e.g., if hardware-binding
  becomes a software emulation, that's a layer demotion that changes
  the fail-mode analysis.
- **A new substrate-relevant capability ships.** The ZK layer added Plonky2
  and the Rust toolchain; the anchoring layer added the Merkle commitment.
  Both are rows above, added in the change that introduced them.

## Browser dependencies

- **MapLibre GL** (`polaris_web/static/vendor/maplibre-gl.js` and its
  stylesheet), vendored rather than loaded from a content delivery network,
  which is what lets the content security policy stay `script-src 'self'`. It
  renders the Atlas. A replacement would be any GL map library taking a
  GeoJSON source; there is no equivalent in the standard browser stack. The
  basemap tiles it fetches are a separate dependency, on an external tile
  service, and the Atlas degrades to markers without a basemap rather than
  failing if that service is unreachable.

## Cross-references

- `docs/paper/polaris_project_report.pdf`: the architectural argument this
  manifest operationalises, in its appendix on substrate.
- `MISSION.md` C7: `CryptographicAlgorithm` table is the proximate
  schema-level expression of "primitives are queryable".
- `docs/design/threat-model.md`: STRIDE threats; this manifest enumerates
  the substrate behind those threats.
- `docs/design/rate-limiter.md`: Redis dependency detail.
- `meta/redaction-proof.md`: the privacy claim built on top of the
  cryptographic primitives listed here.
- `polaris_sql/13_substrate.sql`: the queryable mirror
  (`SystemDependency` view).
