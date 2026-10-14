# Project record

**Reader:** anyone tracing how Polaris reached its current shape; a
maintainer checking whether a piece of scope was shipped, retired or
reopened. **Job:** the historical record that used to live at the end of
[MISSION.md](../MISSION.md): the v1 and v2 done-lists, the retired
cognitive-apparatus arcs, and the production-deployment phase log. It was
moved here on 2026-09-02 (v9.195) so the constitution carries only the
constitution. The text is the record as written at the time, kept
verbatim apart from two citations of files that no longer exist and the
maintainer's name, now written as Egor Khaklin; ticket
labels such as M2-1 or R11-3 are the labels the CHANGELOG and the
per-ship notes in [ships/](../docs/design/) still use. Where this record and the
running code disagree, the code and [CHANGELOG.md](../CHANGELOG.md) are
authoritative.

---

## What "done" looks like for Polaris

The done-list has two epochs. The v1 done-list (the SCS-230 deliverable
arc) closed on 2026-05-09 with 12 of 15 items shipped and 3 retired
(items 13–15, v8.27). The v2 done-list extended Polaris from "the
schema implements the design" to "the system stands behind the
design's claims" — the combination of substrate-level demonstrations
(PDF Appendices E and F as code) and the open problems the report
itself names as deferred (PDF §9). **v2 closed 2026-05-12 at 12/12 ✅
with the v8.28 UI graduation phase** (Option 3 close-out: dashboard
substrate tiles, `/anchors` / `/epochs` / `/federation` viewers, token
detail v2 state section). Both epochs are listed below: v1 as the
historical record, v2 as the closed mission.
### v1 done-list (closed 2026-05-09)

1. ✅ Schema models the full lifecycle of an identity token (achieved v1)
2. ✅ Stored procedures cover UC-1 through UC-7 (achieved v1)
3. ✅ Application layer enforces context-scoped verification (achieved v3)
4. ✅ Cybersecurity controls: CSP, CSRF, rate-limit, role-based auth (achieved v4)
5. ✅ Concurrency hazards identified and sealed with tests (achieved v6)
6. ✅ Scales to 2M+ events with bounded API responses (achieved v6)
7. ✅ Test coverage: 1077 Python (12 test classes incl. property + redaction-property) + 171 SQL self-tests (achieved v6/v7; growing each release)
8. ✅ Threat model: STRIDE-categorized, every threat mapped to a control (docs/design/threat-model.md)
9. ✅ Antimeridian-spanning bbox queries (wrap-aware predicate; 11_atlas.sql)
10. ✅ Cursor pagination on list pages (achieved v7.4 — keyset cursors on /tokens and /verifications)
11. ✅ Property-based tests for invariants (19 Hypothesis tests on C1, C2, C3 in test_invariants_property.py)
12. ✅ Multi-process rate limiter (Redis-backed) (achieved v7.5 — `InMemoryRateLimiter` + `RedisRateLimiter` with auto-selection)
13. ✗ External IdP integration (OIDC) — RETIRED 2026-05-09 (out of v1 scope; not on v2; do not auto-propose)
14. ✗ Banking-on-Polaris reference architecture (separate repo) — RETIRED 2026-05-09 (correct answer is a separate repo consuming Polaris over HTTP; not on v2)
15. ✗ Linux + Windows variant of the launcher — RETIRED 2026-05-09 (macOS launcher is the SCS-230 deliverable surface; cross-platform is an operational concern, not a mission item)

**Note on retirement.** Items 13–15 were marked `⏸ DEFERRED` from
2026-05-09 to v8.26, then re-classified as `✗ RETIRED` once it
became clear (after the v2 close-out) that they were not paused
pending a future epoch — they were outside the mission scope.
They stay
skipped. Audit-of-record: the `DEFERRED 2026-05-09` history is
preserved in this annotation; nothing was deleted.

### v2 done-list (closed 2026-05-12 at 12/12 ✅, opened 2026-05-09)

The v2 arc is **D + A** (substrate-level demonstrations + the report's
open problems).

**Substrate-level demonstrations (D — make Appendices E and F concrete):**

M2-1. ✅ **Real ZK-SNARK for ZERO_KNOWLEDGE verifications** (achieved
       v8.23 / R10-1 — `TokenStateEpoch` table is the 7th audit-of-record;
       Plonky2 SNARK (FRI-based, post-quantum-comfortable) proves Merkle
       inclusion bound to `(epoch_id, context_id, nonce)` public inputs;
       Rust crate `polaris_zk/` provides the prover/verifier CLI;
       `polaris_web/zk.py` is the subprocess wrapper; `uc11_close_epoch`
       procedure with per-procedure advisory lock (6th catalog entry);
       three `/api/zk/*` routes (epoch close, get, verify); 5 SQL self-
       tests in section P, 15+ Python `ZKSnarkTests`, 3 Rust unit tests
       (honest prover, replay, cross-epoch), 2 concurrency tests. C3+A4+B3
       picked by Egor Khaklin at the M2-1 exploration Sanctum: transparent setup,
       Plonky2, hybrid-Merkle reusing R10-2. **Substrate-D arc closed
       5/5** — every primitive named in PDF Appendices E and F is now
       in-tree or scaffolded.).

M2-2. ✅ **Functional DID anchoring** (achieved v8.21 / R10-2 —
       `AnchorBatch` table is the off-chain audit-of-record;
       `close_anchor_batch(algorithm_id, root, proofs)` procedure
       groups pending `BlockchainAnchor` rows by signature algorithm
       under a per-algorithm advisory-lock (4th entry in the catalog);
       `polaris_web/anchoring.py` Merkle helper (SHA3-256 default, sort
       by anchor_id for publish-then-fork resistance); three Flask
       routes (`/api/anchor/batch`, `/api/anchor/<token_id>`,
       `/api/anchor/verify/<token_id>`) — the last one server-side
       reconstructs the Merkle root from leaf + proof and rejects
       tampered logs; 5 SQL self-tests in section O, 15 Python tests in
       `AnchorBatchTests`, 2 concurrency tests for the lock contract.
       Substrate-D arc closed 5/5 — M2-1 ZK-SNARK delivered v8.23).

M2-3. ✅ **Substrate-dependency manifest** (achieved v8 —
       `docs/design/substrate.md` is the prose form; `SystemDependency` view
       in `polaris_sql/13_substrate.sql` is the queryable mirror; 27 rows
       across 7 layers (crypto, network, storage, runtime, standards,
       hardware, human); `SubstrateManifestTests` confirms the prose and
       SQL forms agree).

M2-4. ✅ **GenomicAnchor schema (Appendix F.1)** (achieved v8 — table with
       three CHECK constraints: hex-only, algorithm-specific length, and
       genomic-alphabet refusal; 11 tests in `GenomicAnchorTests`).

M2-5. ✅ **QuantumObserverBinding scaffold (Appendix F.2).** Schema
       scaffold with explicit DEFERRED markers on functional fields, and
       a rationale doc explaining what the binding becomes when
       quantum-observer hardware is real. Acceptance: table exists,
       comments explain the deferred state, schema does not block the
       eventual functional implementation.

**The PDF's open problems (A — close the loops §9 explicitly opens):**

M2-6. ✅ **Multi-signature transitional state** (achieved v8.18 /
       R11-1 — `TokenSignature` M:N table with UNIQUE composite key
       and deprecation_after_signed CHECK; partial index on active
       set; two triggers — `enforce_token_has_active_signature`
       (≥ 1 active per token) and `enforce_token_signature_immutability`
       (write-once except for one-way deprecation_date);
       `uc6_migrate_algorithm` procedure with `pg_advisory_xact_lock`
       on token_id for C9 correctness; UC-1 and UC-9 extended to
       insert TokenSignature alongside the new IdentityToken; backfill
       block for v1 sample tokens; verification path + dashboard
       Post-Quantum panel read from TokenSignature; 16 tests in
       `MultiSignatureTests` + 3 in `ConcurrencyTests` (per-token race,
       verify+migrate snapshot consistency, cross-token parallelism)
       + 5 SQL self-tests in section N; `docs/design/multi-sig-migration.md`
       documents the adversary walk, the verification consistency
       model, the no-auto-derivation argument, and the
       issuer-trust-concentration triad positioning. Closes the
       cryptographic-diversity leg of PDF §9 alongside R11-6 ✅;
       M2-8 federation remains the unbuilt third leg.)

M2-7. ✅ **Catastrophic-loss recovery — UC-9** (achieved v8.17 /
       R11-2 — `RecoveryRequest` table with four CHECK constraints
       encoding the mechanism: 48h cool-down minimum, three-channel
       OOB verification required for APPROVED, decided_at after
       cool-down, approver ≠ requester; partial unique index
       `uq_one_pending_recovery_per_individual` for one PENDING per
       individual; two-phase procedures `uc9_initiate_recovery`
       (operator) + `uc9_complete_recovery` (admin only, RAISE
       EXCEPTION enforced); `pg_advisory_xact_lock` on
       claimed_individual_id for C9 correctness; APPROVED branch
       transitions non-terminal tokens to LOST + publishes each to
       RevocationList + issues new ACTIVE token with
       predecessor_token_id=NULL + tags all lifecycle rows with
       `[RECOVERY:<id>]`; three Flask routes + templates;
       15 CatastrophicLossRecoveryTests + 2 ConcurrencyTests; 5 SQL
       self-tests in section M; `docs/design/recovery-ceremony.md`
       documents the adversary walk, mechanism design, and the
       administrative-vs-operational grace-period framing. The third
       leg of the "schema doesn't weaponize itself against the
       holder" triad (entry R11-4, exit R11-6, recovery this).)

M2-8. ✅ **Issuer federation model** (achieved v8.22 / R11-3 —
       `AgencyTrustAttestation` table is the 6th audit-of-record;
       `enforce_attestation_immutability` trigger enforces one-way
       revocation; `uc10_attest_trust` + `uc10_revoke_attestation`
       procedures with per-attesting-agency advisory lock (5th catalog
       entry); explicit-only federation (NO transitive trust);
       verification flow gates SUCCESS outcomes by `_federation_trust_holds`
       check; `/api/federation/attest` + `/api/federation/revoke`
       routes (admin); 6-row seed graph explains existing demo
       verifications; 15 `IssuerFederationTests` + 2 concurrency tests
       + 5 SQL self-tests in section P. Closes the issuer-trust-
       concentration triad to 3/3 (after R11-1 cryptographic diversity
       and R11-6 constitutional limits).

M2-9. ✅ **Tiered enrollment / population coverage** (achieved v8.16 /
       R11-4 — `EnrollmentStatusEvent` table with 5-status CHECK enum;
       `IndividualCurrentEnrollment` view returns latest event per
       individual with COALESCE fallback to `NOT_ENROLLED`;
       `seed_default_enrollment_status` trigger materializes the
       default state on every new Individual; append-only invariant
       extended to the new table; `civic_enrollment_summary` function
       returns per-jurisdiction × status counts only — per-individual
       NOT_ENROLLED enumeration deliberately not first-class;
       10 tests in `TieredEnrollmentTests` + 5 SQL self-tests in
       section L; `docs/design/tiered-enrollment.md` documents the
       asymmetric design (EXEMPT frictionless, mass-NOT_ENROLLED
       enumeration deliberate) and the PDF §9 anchoring.)

M2-10. ✅ **Compulsion resistance — duress codes (§9.5)** (achieved
       v8.24 / R11-5 — `IdentityToken.duress_code_hash` Werkzeug scrypt
       commitment; `DuressEvent` table is the 8th audit-of-record
       (append-only via `reject_audit_modification`);
       `uc12_record_duress` procedure with no advisory lock (pure
       append, no contention); `_check_and_record_duress` helper uses
       `werkzeug.security.check_password_hash` for constant-time
       comparison; the verification flow proceeds identically to the
       coercer (R2 audit refinement) while silently writing the
       DuressEvent; `/api/duress/events` (admin/auditor) is the OOB
       dashboard; `/verifications` operator list does NOT join to
       DuressEvent (R6 anti-revealing posture); 5 SQL self-tests in
       section R + 13 `DuressCodeTests`. **The v2 mission-closer —
       v2 done-list = 12/12 ✅.**).

M2-11. ✅ **Issuer-discretion bounds** (achieved v8.15 / R11-6 —
       `IssuerDiscretionPolicy` table for per-agency overrides;
       `uc8_revoke_token` stored procedure enforces a rolling N%/W-day
       cap with optional higher-authority co-signer; system defaults
       N=5.00% / W=30 days set via `ALTER DATABASE` GUCs;
       `enforce_revocation_velocity_bound` belt-and-suspenders trigger
       rejects raw UPDATEs; `pg_advisory_xact_lock` per agency_id
       serializes concurrent boundary races for C9 correctness;
       11 tests in `IssuerDiscretionBoundsTests` + 2 in
       `ConcurrencyTests` + 7 SQL self-tests in section K;
       `docs/design/issuer-discretion.md` documents the policy choices,
       adversary walk, and PDF §9 anchoring).

M2-12. ✅ **Verification-graph redaction proof** (achieved v8 —
       `meta/redaction-proof.md` documents the adversary model and the
       five enumerated side-channels; `test_redaction_property.py`
       instantiates a `UniformGuessAdversary` against ZK-only sequences
       and confirms the privacy bound, plus a `TemporalCorrelationAdversary`
       and `SpatialUniquenessAdversary` that prove CE-1 and CE-2 succeed
       — the documented operational limitations the schema cannot
       mitigate; 6 tests in `RedactionPropertyTests`).

Items M2-1..M2-5 are the substrate arc (D); M2-6..M2-12 are the open-
problems arc (A). Roadmap sequencing in `ROADMAP.md` (R10-* for D items,
R11-* for A items). Risk classes range from LOW (M2-3, M2-5, M2-12) to
HIGH (M2-1: cryptographic rabbit hole; M2-8: cross-jurisdiction trust
model). The agent should treat MEDIUM/HIGH items as propose-and-wait
unless the user has explicitly authorized autonomous execution for the
specific item.

### Arcs D / E / F / G — the cognitive apparatus (RETIRED v9.55)

Between 2026-05-12 and 2026-05-14, Polaris grew a large self-monitoring
apparatus: **Arc D** (the "HYDRA" host + a cohort of read-only
watchers), **Arc E** (the "Mycelium" pheromone swarm plus a Roman
"legion" / "Civitas" organizational metaphor), **Arc F** (the
"Denarius" swarm-internal economy), and **Arc G** (a "Roman Empire"
expansion). It was roughly 18k lines of code plus a comparable mass of
narrative, and it observed C1-C10 without ever being imported by the
product.

**v9.55 cut all four arcs wholesale** (CHANGELOG v9.50–v9.55). The job
they nominally did — confirming the constitutional invariants hold — is
now done by the flat, tested `polaris_checks/` layer in ~350 legible
lines. The apparatus packages (`polaris_swarm/`, `polaris_hydra/`,
`polaris_foresight/`), their scripts, their mythology docs, and the
`Pheromone` schema were all deleted. This was authorized as a
de-larping pass: the apparatus had become a self-referential web that
made Polaris read as theater rather than as the serious reference
implementation it is. Legibility is itself an anti-coercion property —
a system whose guarantees you can read in an afternoon is one you can
trust without taking it on faith — so the cut strengthens the Vocation
rather than weakening it.

### Arc B — Production deployment (active multi-phase, opened 2026-05-14)

Production-readiness arc. Polaris was, before v8.77,
**architecturally rich but productionally thin**: cryptography,
schema, and audit-of-record were production-grade, but the
deployment story was the dev launcher.
A reference implementation that no operator can deploy is not
actually a reference. Arc B closes that gap.

**Phase 1 (✅ shipped 2026-05-14 as v8.77):** TLS via Caddy
(Let's Encrypt auto), file-mounted secrets (Docker secrets at
`/run/secrets/`), structured `/api/health` JSON with per-component
checks, multi-stage non-root Dockerfile.prod, idempotent
`polaris-deploy.sh` with rollback-on-fail, manifest-verified
`polaris-backup.sh`, secret-rotation tooling, and the operator
runbook + secrets primer. **G27** (TLS required), **G28** (no
sensitive env-var literals in prod compose), **G29** (structured
health JSON) added.

**Phase 2 (⬜ deferred):** WebAuthn + hardware-token operator auth;
audit-log archive policy (S3 / Glacier rotation); multi-instance
scaling (pgbouncer + gunicorn tuning + Redis cluster);
`polaris-restore.sh` recovery-from-backup with validation.

**Phase 3 (⬜ deferred):** Multi-region deployment patterns;
disaster-recovery runbook (RPO/RTO targets); SOC 2 readiness
checklist.

**Done-list:** R16-1..R16-10 (Phase 1) all ✅. R16-* sequence in
`ROADMAP.md`.

Phases 2 and 3 above were written as deferred; every item in them has
since shipped (WebAuthn at v8.97, restore and DR runbooks, PgBouncer and
Redis scaling, the monthly DR drill at v9.192). The current plan is
[ROADMAP.md](../ROADMAP.md); the operator runbooks are under
[docs/operator/](../docs/operator/README.md).

