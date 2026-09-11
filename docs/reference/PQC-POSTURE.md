# PQC Posture

This document states precisely which Polaris primitives are post-quantum and
which are still classical. It is an honest audit, not a marketing claim. Where a
primitive is classical, it says so plainly. Polaris is a notional, educational
reference system; see [../../MISSION.md](../../MISSION.md) for scope and
[../PRODUCTION-READINESS.md](../PRODUCTION-READINESS.md) for the operational gap
ledger. Nothing here asserts production-readiness.


> **Key custody (v9.178, roadmap P1.2).** The issuer's ML-DSA-65 private key sits
> behind `polaris_web/custody.py`: a `file` driver (development), a `pkcs11`
> driver (HSM or PKCS#11 v3.2 software token; the key is generated in-token and
> never leaves it), and an `awskms` driver (KMS `ML_DSA_65`). The two-witness
> verification is unchanged and checks every driver's output. Ceremony and
> rotation: [`docs/operator/KEY-CEREMONY.md`](../operator/KEY-CEREMONY.md).

## Scope

Polaris's thesis is a "post-quantum identity system." That thesis holds for the
identity TOKEN and its proofs, and as of v9.136 for the client-to-edge TRANSPORT
key exchange with modern clients (hybrid X25519MLKEM768, proven off a real
handshake), and as of v9.404 for the app-to-pooler INTERNAL hop (measured the
same way). It does not yet hold for the pooler-to-database hop, for the
certificate signatures, or for the OPERATOR-AUTH that gates the console. This
document separates those layers without softening either side.

The reference standards are NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS
205 (SLH-DSA), all final as of 2024-08-13, and the NIST IR 8547 transition draft
(deprecate classical public-key after 2030, disallow after 2035). CNSA 2.0 is NSA
policy for National Security Systems and is reference context only; Polaris is a
civilian educational system.

## What is post-quantum today

The core artifact and its supporting hashing and proof primitives are genuinely
post-quantum or post-quantum-acceptable.

- **Identity token signature: ML-DSA-65 (FIPS 204, Category 3, ~AES-192).** The
  authenticity proof over `token_value` is a real lattice-based PQC signature
  when `POLARIS_USE_REAL_PQC=1` (the production default) and liboqs is present.
  The verify path is two-witnessed (v9.133): the liboqs verdict is cross-checked
  against an independent OpenSSL-backed MLDSA65 witness, and the two must agree or
  the signature is refused. The algorithm is pinned in `CryptographicAlgorithm`
  per invariant C7. When the flag is off or liboqs is absent, the path falls back
  to a deterministic SHA3-256 placeholder, which is NOT a cryptographic signature;
  that fallback is the non-production default and is labelled as such.
- **Token binding digest: SHA3-256 (FIPS 202).** The digest input to the ML-DSA-65
  signature. A hash retains roughly half its bit-length against Grover, so
  SHA3-256 keeps about 128-bit quantum preimage security. No quantum deprecation
  deadline applies.
- **Anchor and Merkle hashing: SHA3-256 and SHA3-512.** Blockchain-anchor batch
  attestation hashes the Merkle tree with SHA3-256 or SHA3-512 (`anchoring.py`).
  The `BLAKE3-256` label is accepted at the API but currently maps to SHA3-256 as
  a fallback, because no BLAKE3 dependency is installed; it is honest to call the
  implemented anchor hash SHA3, not BLAKE3. Both are post-quantum acceptable
  hashes.
- **Zero-knowledge inclusion proof: Plonky2 over Goldilocks with Poseidon.** The
  proof system is a PLONK protocol with a FRI-based polynomial commitment, which
  is hash-based and transparent (no trusted setup). Its soundness reduces to
  collision-resistance of the Poseidon hash with no discrete-log, pairing, or
  factoring assumption. This makes it PLAUSIBLY post-quantum. It is NOT
  NIST-certified: there is no FIPS for ZK proof systems, so the correct claim is
  the hash reduction, stated explicitly, not a certification. This posture is
  strictly stronger than pairing or discrete-log SNARKs such as Groth16 or
  KZG-Plonk, whose soundness is quantum-broken.
- **Operator password hashing: scrypt.** Memory-hard KDFs are effectively
  unaffected by quantum computers in practice; Grover does not cheaply parallelize
  the memory cost. No PQC deadline applies.
- **Session, CSRF, and nonce material: `secrets.token_urlsafe` / `token_hex`,
  HMAC-SHA3-256.** Symmetric and hash primitives at adequate bit-width. The only
  PQC-sensitive part of a session is how a symmetric key is established over the
  wire, which is a transport concern, addressed below.
- **Client-to-edge TLS key exchange: X25519MLKEM768 hybrid, for modern clients
  (v9.136).** The self-built Caddy edge (v9.135), built with a Go 1.24+ TLS stack
  (the version where X25519MLKEM768 is offered by default), negotiates the hybrid
  post-quantum group X25519MLKEM768 with any client that offers it. What is
  PROVEN: a real TLS 1.3 handshake against the edge negotiates
  `Negotiated TLS1.3 group: X25519MLKEM768`, both when the client forces the group
  AND with the client's default groups; this is read off the wire locally and
  asserted by the `caddy-edge` CI job on every push. So the SERVER offers and
  selects the hybrid by default. Whether a given real browser gets it is then a
  grounded inference: any client whose default supported_groups include
  X25519MLKEM768 (current Chrome and Firefox, OpenSSL 3.5+, Go 1.24+) negotiates
  post-quantum key exchange with no special configuration. A client offering only
  classical X25519 still completes the handshake (verified), so by TLS group
  selection it necessarily negotiates classical X25519, with no post-quantum
  protection. The negotiated KEX group is independent of the certificate, so the
  production Let's Encrypt path negotiates the same group as the `tls internal`
  test in CI. This closes harvest-now-decrypt-later for connections from modern
  (ML-KEM-capable) clients, on the only hop that carries live external content.
  The hybrid is safe if EITHER X25519 or ML-KEM-768 holds. Caveat: the group is
  negotiated OPPORTUNISTICALLY and cannot be required without breaking pre-ML-KEM
  clients, so harvest-now-decrypt-later exposure persists for any connection that
  does not negotiate ML-KEM (old clients, or an active downgrade of the offered
  groups).
- **App-to-pooler TLS key exchange: X25519MLKEM768 hybrid (v9.404).** The app's
  connection to pgbouncer negotiates the hybrid post-quantum group with the
  driver's default offer, and accepts it when forced. What is PROVEN:
  `scripts/polaris-internal-kex-drill.sh` boots the repo's own pgbouncer image,
  speaks the PostgreSQL SSLRequest preamble, and reads
  `SSL_get0_group_name()` off the finished handshake using THE SAME OpenSSL the
  driver links. That last part is the whole point. This document previously said
  this hop was classical, held back by "the app's libpq 3.0.20 (Debian Bookworm
  base)". The app does not use the base image's libpq: `psycopg2-binary` ships a
  manylinux wheel that vendors its own libpq and its own OpenSSL 3.5.6 beside it,
  and that vendored pair is what every database connection speaks TLS with. The
  base image's OpenSSL 3.0.20 never enters the path. On the server side pgbouncer
  had moved from Alpine 3.20 to 3.24 (OpenSSL 3.3.7 to 3.5.8) without the document
  following. Both ends had been ML-KEM-capable for some time; nothing measured it,
  because the claim was derived from version numbers in Dockerfiles rather than
  from a handshake. The drill runs in CI now, so the hop is asserted rather than
  asserted about.

## What is still classical

These surfaces are classical and quantum-vulnerable today. The threat differs by
surface, and the realistic exposure is bounded but real.

- **TLS key exchange on the INTERNAL pooler-to-database hop: classical ECDHE
  (secp256r1), no hybrid ML-KEM.** Measured, not inferred:
  `scripts/polaris-internal-kex-drill.sh` boots the repo's own postgres image and
  reads the group off a finished handshake. Both ends already link OpenSSL 3.5
  (postgres:16-alpine carries 3.5.6, pgbouncer 3.5.8), so the library is not the
  limiter. The limiter is postgres itself: through PostgreSQL 17 the server clamps
  its TLS group list to `ssl_ecdh_curve`, a SINGLE named EC curve, which cannot
  express a hybrid group. A client that forces X25519MLKEM768 is refused with a
  handshake-failure alert, and the drill asserts that refusal, because the refusal
  is what identifies the real blocker. PostgreSQL 18 replaces that setting with
  `ssl_groups`, which takes a list; with `ssl_groups='X25519MLKEM768:...'` the same
  client and the same driver negotiate X25519MLKEM768 (measured against
  postgres:18-alpine). So this hop is gated on the postgres major, not on any
  image's OpenSSL. Threat: harvest-now-decrypt-later. Exposure: notional data
  inside the deployment trust boundary, so the payoff is near nil.
- **Edge certificate signature (Let's Encrypt CA, RSA 2048 or ECDSA P-256):
  classical, Shor-breakable forgery.** Exposure: the standard public-PKI gap
  shared by most of the classical web. The algorithm is chosen by the CA, not the
  operator, so migration is gated on the CA-Browser ecosystem.
- **Internal certificate signatures (self-signed RSA 2048 with SHA-256 for
  postgres and pgbouncer): classical, Shor-breakable forgery.** Exposure:
  infrastructure certs pinned via `sslmode=verify-ca`, reachable only inside the
  deployment trust boundary. These are operator-generated, so they are the most
  self-controllable cert gap. Note the threat here is future forgery and
  impersonation, not harvest-now-decrypt-later: a signature carries no
  confidentiality to record, and the ECDHE handshake, not the cert key, derives
  the session secret.
- **WebAuthn operator-MFA signatures (ES256/ECDSA P-256, EdDSA/Ed25519,
  RS256/RSA): classical, Shor-breakable forgery.** Critical nuance: the signing
  key is the authenticator's, held client-side in operator hardware, and is never
  transmitted, so harvest-now-decrypt-later does NOT apply to the credential. The
  threat is future signature forgery. Migration is gated on the FIDO Alliance,
  browsers, and authenticator hardware, not on Polaris as the relying party. No
  PQC COSE authenticators ship as of 2026-09. Since v9.189 (webauthn 3.0.0)
  the relying party offers ML-DSA-65 (COSE -49) FIRST in the registration
  options and verifies it through cryptography's ML-DSA implementation, with
  the classical three behind it, so the day an authenticator implements
  ML-DSA its credential enrolls post-quantum with no Polaris change; the
  ceremony is proven in `WebAuthnCeremonyTests` with a synthetic ML-DSA-65
  authenticator. Every credential enrolled today is still classical, and
  this surface stays in this section until the hardware exists.
- **Recovery-code mnemonic digest (SHA-256): classical SHA-2.** This is a hash,
  not a public-key primitive, so it is NOT Shor-breakable and carries NO
  deprecation deadline. Grover leaves about 128-bit quantum preimage security on
  the 128-bit-entropy mnemonic. It is listed here only for transparency about the
  algorithm family; it is acceptable as-is.

## Gap table

Status maps to the NIST IR 8547 timeline (deprecate classical public-key after
2030, disallow after 2035).

| Primitive | Category | Status | Rationale |
|---|---|---|---|
| ML-DSA-65 (token signature) | signing | PQ_SECURE | FIPS 204 Cat 3, real signature under the production default, two-witnessed, algorithm pinned per C7. |
| ML-DSA-87 (accepted parameter set) | signing | PQ_SECURE | v9.329 (P8.8a): NIST level 5, accepted by every verifier (the detached verifier, both SDKs, the app's two witnesses) and signed by the file custody driver when the key file names it. Migration is a key-lifecycle event: register the ML-DSA-87 key (it becomes current), retire the ML-DSA-65 key from an instant; proven by conformance vectors under both sets and a mixed-algorithm two-instance drill. ML-DSA-44 is refused everywhere (below the floor). The PKCS#11 and KMS drivers remain ML-DSA-65 in this version. |
| SLH-DSA-128s / SLH-DSA-256s (algorithm registry rows) | signing | REGISTERED_NOT_WIRED | FIPS 205 hash-based parameter sets are rows in `CryptographicAlgorithm`, so a rotation away from lattices is a row update (C7). No SLH-DSA signer is wired: `pqc_signing.py` signs ML-DSA-65 or ML-DSA-87 (v9.329), so the seed token filed under SLH-DSA-128s cannot be re-signed (every seed signature row is a placeholder; real signatures appear at issuance). Wiring one is not yet scheduled; it would sit behind the same custody interface as ML-DSA-65. |
| SHA3-256 (token binding digest) | hashing | PQ_SECURE | FIPS 202; ~128-bit quantum preimage resistance. No deadline. |
| SHA3-256/512 (blockchain anchor Merkle) | hashing | PQ_SECURE | Server-computed Merkle hashing; the BLAKE3-256 label falls back to SHA3-256. Grover quadratic only. No migration. |
| Plonky2 + Poseidon (ZK proof) | zk | PQ_SECURE | Plausibly PQ: PLONK with a FRI (hash-based) commitment; soundness reduces to hash collision-resistance, no number-theoretic assumption. NOT NIST-certified; the claim is the reduction, not a certification. |
| scrypt (operator password) | password | PQ_SECURE | Memory-hard KDF; unaffected in practice. No deadline. |
| secrets.token_* (session/CSRF/nonce RNG) | session | PQ_SECURE | CSPRNG, 256/64-bit entropy. Symmetric; acceptable. |
| HMAC-SHA3-256 (CSRF compare) | session | PQ_SECURE | Inherits hash security; constant-time compare. No item. |
| SHA-256 (recovery-code digest) | hashing | REDUCED_BUT_OK | Classical SHA-2 but a hash, not public-key; ~128-bit quantum preimage. No deadline. Acceptable as-is. |
| ECDSA/EdDSA/RSA (WebAuthn MFA) | webauthn | MIGRATE_BY_2035 | Classical, Shor-breakable. Key is client-side authenticator, never sent, so no HNDL. Migration gated on FIDO/hardware, not Polaris; the relying party already offers and verifies ML-DSA-65 (v9.189), so no Polaris change is needed when authenticators ship it. |
| X25519MLKEM768 hybrid (client to edge) | kex_transport | PQ_SECURE (modern clients) | Hybrid PQ KEX, server offers + selects it by default (proven off a real handshake, forced + default; asserted by the caddy-edge CI job). Closes HNDL for connections from modern (ML-KEM-capable) clients; old clients negotiate classical X25519 (no PQ). Opportunistic, not required. Safe if either X25519 or ML-KEM-768 holds. |
| X25519MLKEM768 hybrid (app to pgbouncer) | kex_transport | PQ_SECURE | Hybrid PQ KEX, negotiated by default and accepted when forced. Measured off a real handshake with the driver's own vendored OpenSSL 3.5.6 (psycopg2-binary) against the repo's pgbouncer image (OpenSSL 3.5.8); asserted by `polaris-internal-kex-drill.sh` in CI. Closes HNDL on this hop. Safe if either X25519 or ML-KEM-768 holds. |
| TLS ECDHE, secp256r1 (pgbouncer to postgres) | kex_transport | MIGRATE_BY_2030 | Classical KEX, HNDL. Internal hop, notional data. Measured, and the forced-hybrid refusal measured with it: both ends link OpenSSL 3.5, so the limiter is postgres clamping its group list to `ssl_ecdh_curve` (one EC curve) through PG 17. Gated on PostgreSQL 18's `ssl_groups`, not on any image's OpenSSL. |
| RSA 2048 + SHA-256 (internal self-signed certs) | cert_signature | MIGRATE_BY_2035 | Classical, Shor-breakable forgery, ~112-bit. Pinned, inside trust boundary. Migrate to ML-DSA or SLH-DSA when the stack verifies PQC chains. |
| RSA 2048 / ECDSA P-256 (Let's Encrypt CA) | cert_signature | MIGRATE_BY_2035 | Classical, Shor-breakable forgery. CA chooses the algorithm; gated on public-PKI rollout. |

## Migration roadmap

Prioritized and aligned to the NIST clock. Items below P1 are operator-gated or
third-party-gated and are future work, not current defects.

1. **P1, client-to-edge TLS hybrid KEX. DONE (v9.135 + v9.136).** The self-built
   Caddy edge (Go 1.24+ TLS stack) negotiates X25519MLKEM768 with modern clients,
   proven off a real handshake and asserted by the caddy-edge CI job. Hybrid runs
   classical and ML-KEM-768 concurrently so the session is safe if either holds.
   This closed harvest-now-decrypt-later for modern clients on the only hop with
   live content. Old clients still fall back to classical X25519 (opportunistic,
   not required).
2. **P2, internal-hop TLS hybrid KEX. HALF DONE (v9.404).** The app-to-pooler
   hop negotiates X25519MLKEM768 today, measured off a real handshake with the
   driver's own OpenSSL and asserted by `polaris-internal-kex-drill.sh` in CI. It
   got there without anyone enabling it: `psycopg2-binary` vendors OpenSSL 3.5.6
   and the pgbouncer image moved to Alpine 3.24 (OpenSSL 3.5.8), and this document
   went on describing the hop from the base-image versions in the Dockerfiles,
   which were never the versions in the path. The remaining half, pooler to
   database, is NOT gated on OpenSSL: both ends already link 3.5, and the drill
   measures postgres refusing a forced hybrid anyway, because through PostgreSQL
   17 the server clamps its groups to `ssl_ecdh_curve`, a single EC curve.
   PostgreSQL 18's `ssl_groups` takes a list and negotiates the hybrid with the
   same client, measured. So the gate is a postgres major upgrade. Lower urgency:
   notional data, inside the trust boundary.

## Closing note

This is an audit of a notional, educational reference system. The data is
non-real. The honest summary is that the identity token at the center of Polaris
is post-quantum, and as of v9.136 so is the client-to-edge transport key exchange
for modern clients (hybrid X25519MLKEM768, proven off a real handshake and
asserted by the caddy-edge CI job) and, as of v9.404, the app-to-pooler internal
hop (measured the same way, asserted by the internal-kex drill). The
pooler-to-database hop, the certificate signatures, and the operator
authentication that gates the console are still classical, and the
pooler-to-database hop waits on a postgres major, not on an image
rebuild. The realistic exposure of those classical
surfaces is bounded by the notional data, the internal-only reach of the internal
hops, the client-side custody of the WebAuthn key, and the third-party gating of
WebAuthn and public-PKI migration. Nothing here claims production-readiness; for
the operational ledger see [../PRODUCTION-READINESS.md](../PRODUCTION-READINESS.md),
and for the constitutional scope see [../../MISSION.md](../../MISSION.md).
