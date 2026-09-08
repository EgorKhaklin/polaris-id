# ROADMAP.md - from reference implementation to national deployment

This is the build plan. It is written to be executed: an agent (or a human) in a
fresh session reads [CLAUDE.md](CLAUDE.md), then this file, picks the first
unblocked item in the active phase, and ships it under the standing ship
discipline. Shipped history lives in [CHANGELOG.md](CHANGELOG.md), not here.

**Decision record.** MISSION.md's freeze line defined when the core was done,
limited the work that followed to hardening, measurement and thesis evidence,
and required a named operator trigger to open a new arc. Its six conditions
are met and it is recorded closed (MISSION.md's amendment log, 2026-09-04).
The trigger it required occurred on 2026-08-31, when the project owner
directed a complete plan to real national deployment; this roadmap is that
recorded decision. The constitution (C1 to C10 and the vocation) is not
softened by it: every phase below carries the constitution as a hard gate,
what a deployment may not yet claim is bounded by
[docs/PRODUCTION-READINESS.md](docs/PRODUCTION-READINESS.md), and several
previously retired scope decisions are reopened here with reasons, rather
than silently.

**Status marks:** `[ ]` pending · `[>]` in progress · `[x]` done ·
`[EXT]` blocked on an external actor (funding, law, vendor, institution).
Update marks in place as part of each ship; never delete rows.

**Sizing:** S (under one session) · M (1-3 sessions) · L (an arc, 3-10) ·
XL (multi-arc). Risk is delivery risk, not security risk.

---

## Where we are (inventory at v9.236)

**Have, working, CI-proven:** a 30-table constraint-enforced schema (37 tables
in a migrated deployment) with append-only audit; an 87-route application with
WebAuthn operator MFA, a server-side session registry, per-role network policy,
per-agency quotas and the Atlas; an operator CLI; Plonky2 ZK Merkle inclusion
with an independent Python second witness and a parameterized tree depth; real
ML-DSA-65 signing two-witnessed (liboqs and OpenSSL) behind a custody interface
with file, PKCS#11 and KMS drivers; a five-service hardened production stack
behind a post-quantum TLS edge (X25519MLKEM768, proven in CI), deployable by
compose, by blue-green rolling deploy, by a scripted Linux install under
systemd, or by the Helm reference profile; pgBackRest backup and restore,
off-site to S3, streaming replication, and a monthly DR drill that measures
RPO and RTO; a retention engine that holds the retention decision as data with
a floor no configuration reaches, per class and per jurisdiction, enforced by
the purge and drilled end to end in CI; a sealed secrets store; opt-in
distributed tracing with dashboards as code; SBOMs and SLSA provenance on every
release; CVE gates on dependencies and images; a coverage floor; 138 invariant
checks (v9.262) each with a detection test; eighteen operator runbooks and ledgers; and the bound on
every claim in [docs/PRODUCTION-READINESS.md](docs/PRODUCTION-READINESS.md).

**Do not have:** hardware tokens (the physical artifact is modeled, not built);
holder-facing surfaces (everything today is operator-facing); identity-proofing
evidence flows mapped to NIST 800-63; scale beyond a single node (no
partitioning, no HA automation, no multi-region; the Helm profile runs one
postgres replica); a relying-party ecosystem (no stable public API contract, no
SDKs, no conformance suite); offline verification; status and revocation
distribution at scale; inter-authority federation as deployed topology (the
schema supports it; no protocol spec or second instance exists); a hardware
HSM in CI (the PKCS#11 driver is proven against a software token); certified
cryptography (liboqs is not FIPS-validated); published registry images and
image signing (deferred from P0.6 until images are published); accessibility
conformance; any external audit, pen test, or pilot; and every institutional
prerequisite of a national system (statute, funding, enrollment workforce,
manufacturing, authorization to operate).

**Carrying debts:** none from the P0 list; that paragraph closed with P0
(v9.160 to v9.175). One engineering limit is carried openly in the readiness
ledger: edge and database recreation are window operations, measured against
ceilings on every push since v9.240 (edge configuration changes are live
reloads). Closing it is P2.7. The Caddy edge became fully non-root at v9.239. P0.11 (internal-hop hybrid KEX) stays `[EXT]` on
OpenSSL 3.5 reaching the pgbouncer and postgres images.

---

## Phase map

| Phase | Objective | Scale target | Exit gate |
|---|---|---|---|
| P0 | Foundation closure | n/a | Every claim reproducible by command; supply chain signed; zero known debts |
| P1 | Single-authority production | 10k-100k persons, one org | A non-author operator runs it from docs alone; pen test closed; SLOs met |
| P2 | Scale architecture | 1-10M persons (state) | 10M load profile green on HA topology through a rolling deploy and a failover |
| P3 | Federation and relying parties | Many authorities, third-party verifiers | Two instances interoperate in CI; an external team integrates docs-only |
| P4 | Hardware token and enrollment | Field-ready issuance kit | Enroll, personalize, verify online+offline, revoke, recover: end to end on AoR |
| P5 | Pilots | Real, consenting users | Two completed pilots with public reports, zero constitutional violations |
| P6 | Certification and assurance | Authorization-ready | Validated crypto option, 800-63 mapping, audit and red team published |
| P7 | National rollout | 350M persons | First state live; a national program office assumes ownership |

P4 runs in parallel from P1 onward. P5-P7 are gated on external actors; the
buildable machinery for each is listed so no external gate is ever waiting on
us.

---

## P0 - Foundation closure

Objective: a stranger can clone the repo, verify every stated claim with a
command, and reproduce every artifact. Nothing on the known-debt list survives.

| ID | Item | Size | Risk | Blocked by | Definition of done |
|---|---|---|---|---|---|
| [x] P0.1 | Pin the Rust toolchain to a dated nightly (v9.160) | S | low | - | Pinned by `check_rust_toolchain_pinned` |
| [x] P0.2 | Wire `test_e2e_atlas.py` into CI (v9.160) | S | low | - | Pinned by `check_ci_runs_atlas_e2e` |
| [x] P0.3 | Clear the Dependabot backlog and set policy (v9.161) | M | low | - | Policy in `.github/dependabot.yml`; the record is CHANGELOG v9.161 to v9.165 |
| [x] P0.4 | Exercise the un-swept operator tools: rotate-secret, chaos-test, load-test, ct-monitor (v9.166) | L | med | - | Four defects found by running the tools, each pinned: `check_load_gen_single_ledger`, `check_chaos_probe_reaches_wrapper`, `check_ct_monitor_testable_and_guarded`, `check_rotate_secret_preserves_mode` |
| [x] P0.5 | SBOM per release (pip + all four images) (v9.167) | M | low | - | Pinned by `check_sbom_workflow` and `check_sbom_trivy_matches_scan` |
| [x] P0.6 | Signed artifacts and provenance (v9.168) | M | med | P0.5 | Pinned by `check_release_provenance`. Deferred: image signing at a registry digest waits until the four images are published to a registry, since there is no ref to sign today |
| [x] P0.7 | ZK production profile + plonky2 major (v9.169 + v9.170) | M | med | - | Pinned by `check_zk_tree_depth_synced`. Follow-up: a national-scale (depth 24+) anonymity set is verify- and size-viable but gated on the sibling-path witness optimization |
| [x] P0.8 | Coverage measured and gated (v9.171) | M | low | - | Pinned by `check_coverage_gated` |
| [x] P0.9 | Offsite backup, one command (v9.173) | M | low | - | Pinned by `check_offsite_backup_env_driven` |
| [x] P0.10 | Pager integration for alerts (v9.175) | S | low | - | Pinned by `check_pager_integration` |
| [ ] P0.11 | Internal-hop hybrid PQ KEX | M | ext | OpenSSL 3.5 in the pgbouncer/postgres images | Both internal hops negotiate hybrid KEX; the CI handshake proof extends to them; PQC-POSTURE updated |

Exit gate, met at v9.175 with P0.11 `[EXT]`: every other P0 row `[x]`; the
carrying-debts paragraph in the inventory is empty of P0 items.

---

## P1 - Single-authority production

Objective: one real issuing authority (a university, a county office) could run
Polaris for its population, on Linux, around the clock, without the author.

| ID | Item | Size | Risk | Blocked by | Definition of done |
|---|---|---|---|---|---|
| [x] P1.1 | First-class Linux server deployment (v9.176) | L | med | P0 | Pinned by `check_linux_server_deployment` |
| [x] P1.2 | Key custody abstraction (HSM/KMS) (v9.178) | L | high | - | Pinned by `check_key_custody_abstraction`. Scope: epoch anchors are hash-chained, not signed, so the issuer key is the only key under custody. Limits: no hardware HSM in CI (the PKCS#11 driver is proven against a Kryoptic software token); GCP and Azure ML-DSA drivers wait on their preview APIs |
| [x] P1.3 | Secrets lifecycle to KMS (v9.180) | M | med | P1.2 | Pinned by `check_secrets_lifecycle_sealed` |
| [x] P1.4 | Zero-downtime deploys (v9.183) | L | med | - | Pinned by `check_zero_downtime_deploy` and `check_migrations_expand_contract`. Limit: edge and database recreation are still window operations |
| [x] P1.5 | Kubernetes/Helm reference profile (v9.186) | L | med | P1.4 | Pinned by `check_helm_reference_profile`. Limits: one postgres replica (HA is P2), `tls: internal` in CI, no registry images published |
| [x] P1.6 | Distributed tracing and dashboards-as-code (v9.187) | M | low | - | Pinned by `check_distributed_tracing` |
| [x] P1.7 | Session and origin hardening pass (v9.189) | M | low | - | Pinned by `check_session_origin_hardening` |
| [x] P1.8 | Abuse controls (v9.190) | M | med | - | Pinned by `check_abuse_controls` |
| [x] P1.9 | Performance baseline v1, published (v9.191) | M | low | P0.4 | Pinned by `check_performance_baseline` |
| [x] P1.10 | DR to targets, on a schedule (v9.192) | M | low | P0.9 | Pinned by `check_dr_drill_scheduled` |
| [x] P1.11 | Retention and lifecycle engine (v9.234-v9.236) | M | med | - | Per-table-class retention as data with a 365-day CHECK floor and jurisdiction templates, append-only with one-way supersession; the archive/purge chain drives it per class and verifies the archive against its manifest before deleting; the checkpoint records which cutoff applied to which class; `polaris-retention-drill.sh` runs the whole chain in CI; `polaris-id retention-show` / `retention-set` are the operator surface. The C1 carve-out rules are unchanged. [retention.md](docs/design/retention.md) |
| [ ] P1.12 | External penetration test | M | ext | P1.1-P1.8 | [EXT: funding, firm] The readiness pack is ours to build; findings triaged, fixed, and pinned; a summary published |
| [x] P1.13 | Human-facing documentation, reworked for the national-deployment reader (v9.194-v9.200) | L | med | - | [OWNER-AUTHORIZED REWORK, 2026-09-02] Every document a person reads (README, `docs/`, the operator runbooks, the reference set, the in-code docstrings and comments that face an operator or assessor) is rewritten or removed against one standard: a named reader (operator, integrator, assessor, contributor), one job per document, one voice (declarative, no version archaeology in the body, no em-dashes), stamps only where a number lives, and nothing stale, internal, or ambiguous to a first-time assessor of a national identity system. Duplicated and superseded documents are merged or deleted, not annotated. `docs/README.md` and `SYSTEM-MAP.md` match the tree exactly. An observer-confusion audit (a read-through as a first-time assessor, recorded) finds nothing to ask. Pinned by a check on the doc index and the stamp discipline Ship by ship per [DEVNOTES/presentation-plan.md](DEVNOTES/presentation-plan.md) |
| [x] P1.14 | The GitHub presence as the front door (v9.201-v9.205) | M | med | P1.13 | [OWNER-AUTHORIZED REWORK] The repository's About, topics, README above the fold, SECURITY.md, CONTRIBUTING.md, release notes, and the Pages site present one accurate, professional story of what Polaris is, what it proves, and what it is not; templates and community files that a national-deployment reader expects exist and nothing demo-era or internal remains visible. Pinned by a check Ship by ship per [DEVNOTES/presentation-plan.md](DEVNOTES/presentation-plan.md) |
| [x] P1.15 | The demo website, accurate and professional (v9.216-v9.219) | M | med | P1.13 | [OWNER-AUTHORIZED REWORK] `site/` (egorkhaklin.github.io/polaris-id) mirrors the product's current state and the honesty ledger, in the intelligence-report visual system, with no claim the repository does not prove; built and link-checked in CI Ship by ship per [DEVNOTES/presentation-plan.md](DEVNOTES/presentation-plan.md) |
| [x] P1.16 | Repository organization, matched to reality (v9.218-v9.225) | M | med | - | [OWNER-AUTHORIZED REWORK] Directory layout, script names, `DEVNOTES/`, `meta/`, `site/`, and every committed artifact are triaged: kept with a stated reader, moved, or deleted; dead scripts and historical apparatus are gone; the tree a first-time reader opens explains itself. `SYSTEM-MAP.md` and the checks that pin file locations are updated in the same ship Ship by ship per [DEVNOTES/presentation-plan.md](DEVNOTES/presentation-plan.md) |
| [x] P1.17 | The software's own presentation, visually and structurally (v9.206-v9.213) | L | med | P1.13 | [OWNER-AUTHORIZED REWORK] The web application (templates, CSS, navigation, copy, error and flash messages), the CLI's output and help, the health and metrics naming, and the log stream present one restrained, consistent, national-deployment tone; demo-only surfaces are removed or gated behind an explicit demo mode; the test-pinned markup contract is honoured so the rework is safe; nothing an operator sees is internal jargon or leftover scaffolding. Pinned by checks and the existing UI tests Ship by ship per [DEVNOTES/presentation-plan.md](DEVNOTES/presentation-plan.md) |
| [>] P1.18 | Consolidation and external-validation readiness | L | med | - | A short, SEQUENCED "claim-and-proof season" (assessment: [DEVNOTES/production-readiness-review.md](DEVNOTES/production-readiness-review.md)) — eight items, not a backlog of thirty-six virtues; less public machinery, more externally-checkable evidence; on the standing acceptance test (ship only if it keeps people no more legible or coercible and the authority more inspectable). In order: (1) public claim pass — ban "zero-knowledge identity system" from the README title, split into unlinkable-verification-records / Merkle-membership-proof / selective-disclosure-not-implemented, stop calling extrapolation "certification" (rename P2.9 to a capacity model), label every claim measured/simulated/projected/aspirational, cut the README to three claims and demote mythology + "350M" off the first screen; (2) quarantine the sci-fi schema (GenomicAnchor/QuantumObserverBinding, wired so deprecate properly) with a check they cannot return; (3) split C1-C10 into constitutional vs engineering-invariant ONCE (two levels, not a four-tier hierarchy); (4) semantic checks (a signature must VERIFY under its declared algorithm, not merely exist) + THE key backend change: split verify into signature_valid (replica-safe) vs currently_authoritative (primary / bounded-staleness with as_of+max_lag); (5) finish the two-witness contract with the availability clause (single-witness verify-at-use only if the fast path cannot change authz state, sampling is mandatory + paging, disagreement is a SEV, responses name the witness set); (6) ONE measured HA/verification report on the real topology (real p50/p95/p99, no one-core x8), synthetic nation as harness; (7) proof-of-life 15-minute demo + the non-author operator session (above most of P3); (8) external-review packet (threat matrix for existing subsystems, blunt known-limitations, guarantee-attack prompts). Freeze product surface after (7). Ecosystem anti-coercion (right-to-alternate-path etc.) is a one-page posture note + refusing exclusivity-enabling APIs, NOT C11-C18; founder-governance overrule mechanism is a known limitation now, designed before P5. Pairs with P1.12 (pentest) and P6.6 (independent red team). Already shipped and credited: two-witness fail-closed issuance + authenticity/authorization split (v9.264), Athena person-prohibition (v9.266) |

Exit gate: a non-author operator performs a witnessed clean install and a
simulated month of operations (issuance, revocation, recovery, backup, restore,
failover, rotation) using only the docs, and the
[SLOs](docs/operator/SLOS.md) hold on reference hardware.

---

## P2 - Scale architecture

Objective: a state-scale deployment (1-10M persons) with high availability,
horizontal read scaling, and operational headroom, proven by load.

Planning targets (to be validated by P2.9, not asserted): 10M persons;
sustained 1,000 verifications/s with 10x peak headroom; 50 issuances/s
sustained during enrollment surge; p95 online verification under 150ms
server-side; 99.95% availability.

| ID | Item | Size | Risk | Blocked by | Definition of done |
|---|---|---|---|---|---|
| [x] P2.1 | Event-table partitioning (v9.245) | L | high | P1.4 | The four append-only event tables are monthly range-partitioned on `event_timestamp` (composite PK, DEFAULT catch-all); `uc_ensure_event_partitions` premakes months and `uc_detach_event_partitions_before` detaches old ones (re-adding the append-only trigger so C1 holds across the detach); the online migration converts a pre-v9.245 database in place by attaching its table as DEFAULT (no copy) and reverts by departitioning; `polaris-partition-drill.sh` proves append-only across a partition, an attach and a detach on every push. [partitioning.md](docs/design/partitioning.md), pinned by `check_event_table_partitioning` |
| [x] P2.2 | Read-replica routing (v9.246) | M | med | P2.1 | The read-only surfaces (the atlas API, the verification list, the token export) route to a streaming replica under an explicit staleness contract (`POLARIS_REPLICA_MAX_LAG_S`, the `X-Polaris-Data-Source` / lag headers, a health component) with failback to the primary; correctness-critical reads stay on the primary; on the HA profile the app dials the pooler's `polaris_ro` -> `pg-router:5433`. Single node is unaffected. `polaris-failover-drill.sh` proves it. Pinned by `check_read_replica_routing` |
| [>] P2.3 | Atlas v2: the analytical console | L | med | P2.1 | The Atlas is rebuilt from a globe-first canvas into a tabbed analytical console: an Overview of bounded, non-geographic charts is the default, the globe is a tab (kept for the per-subject investigation and region drill), and every view stays O(buckets/categories/regions) so it survives the stress set (C8 extended, C6 counts zero-knowledge but never locates it, C5 keeps charts as self-hosted SVG). Ship 1 (v9.248): the console shell + Overview + `atlas_volume_series`/`atlas_breakdown` + `check_atlas_console`. Later ships: Breakdown, the map redesign (region choropleth + drill), Trends, and the subject-investigation promotion; PostGIS at 10M remains a sub-item gated on a PostGIS env + a 10M dataset. Plan in [DEVNOTES/atlas-redesign.md](DEVNOTES/atlas-redesign.md) |
| [x] P2.4 | Bulk enrollment pipeline (v9.247) | L | med | P2.1 | An authority's population stages with `COPY` into `BulkEnrollmentStaging` and issues SET-BASED in one transaction through `uc_bulk_issue`: the `uc1` authorization gate once per batch (one agency, one algorithm), the keys pre-assigned, then one `INSERT ... SELECT` per table through the full constraint set and one `UPDATE` to activate, so every imported row passes exactly what a single issuance passes and a single violation rolls the whole batch back (all issued, or none). A staged `individual_id` correlates a re-card to an existing person, which is what makes C3 reachable across a batch. The `bulk-enroll` CLI runs it from a pipe-delimited extract; `polaris-bulk-drill.sh` proves throughput (~4500 rows/s local at v9.247, floored in CI), all-or-none atomicity, C3 across the batch, and the issue/auth/empty refusals on every push. [bulk-enrollment.md](docs/design/bulk-enrollment.md), pinned by `check_bulk_enrollment` |
| [ ] P2.5 | Epoch pipeline at scale | L | high | P0.7 | Incremental Merkle maintenance, parallel proving, witness parity at production depth; an epoch cadence spec published |
| [ ] P2.6 | Status distribution v1 | L | high | P2.5 | Signed, versioned, short-lived status artifacts (revocation and validity) distributable via CDN and verifiable offline; freshness rules specified; this is the backbone of P3.6 |
| [x] P2.7 | HA automation (v9.243) | L | high | P1.10 | The HA profile (`docker-compose.ha.yml`) runs the database under Patroni with a leader lease in a three-member etcd and HAProxy routing on the role endpoints; `polaris-failover-drill.sh` loses the leader, cuts it off from the lease store, switches over and crashes an etcd member under a live write stream on every push; [FAILOVER.md](docs/operator/FAILOVER.md) carries the measured numbers and the split-brain analysis. The member hosts are the operator's placement. Pinned by `check_ha_automation` |
| [x] P2.13 | HA on Kubernetes (v9.244) | M | med | P2.7 | The chart runs the same Patroni members under the same entrypoint with the Kubernetes API as the lease store (no etcd): a Role for exactly what Patroni needs, a selector-less leader Service whose endpoints follow the lease, a replica Service on the role label; the kind drill deletes the leader pod, switches over, and asserts every acknowledged insert present. Pinned by `check_helm_reference_profile` |
| [ ] P2.8 | Multi-region DR | L | med | P2.7 | An async standby region and a region-evacuation drill with measured RTO/RPO |
| [x] P2.9 | 10M-profile capacity model (single-node measured, multi-node projected) | L | med | P2.1-P2.7 | Done in three parts. SINGLE-NODE load (v9.257): the P2.14 harness drives the nation at scale and commits throughput, latency percentiles and invariants-under-load ([docs/reference/BENCHMARK.md](docs/reference/BENCHMARK.md)). THROUGHPUT lever (v9.258): single-witness verify-at-use takes real ML-DSA-65 verification from ~745 to ~7,848/s per core (~62,783/s projected fleet) via `GET /api/tokens/<id>/verify`, sound because issuance still two-witnesses every signature ([docs/design/verification-scaling.md](docs/design/verification-scaling.md)). HA transitions under load (v9.259): both CI drills now hold a real authenticated verification load across the transition — the rolling deploy drops ZERO verifications; the failover induces four failures and demonstrates verification RECOVERS after each and keeps serving at rate (`scripts/polaris-verify-load.py`). The 10M-RECORD scale on a real multi-node cluster is extrapolated from these single-node numbers (P2.10 cost model, P7.3 capacity model); CI hardware runs the two-member HA topology, not multi-region |
| [>] P2.14 | National simulation and benchmark harness | XL | med | P2.4 | A seeded, deterministic simulation of a synthetic United States driven through the REAL procedures/constraints/ZK-path/Atlas: all states with ID bureaus scaled by population, life events (verification + token lifecycle) streaming over a simulated clock, measured for throughput, latency percentiles, contention, Atlas query time at scale, and C1-C10 behavior under load, so findings become targeted hardening ships. Notional and isolated; every report states its scale factor and hardware. Realizes and expands P2.9 (the benchmark run is the capacity-model measurement). Multi-ship arc, plan in [DEVNOTES/national-simulation.md](DEVNOTES/national-simulation.md) |
| [ ] P2.10 | Cost model | S | low | P2.9 | Infrastructure cost per 1M persons per year, derived from P2.9, committed |
| [x] P2.11 | Standing chaos program (v9.242) | M | low | P0.4 | The fail-closed harness runs on every push; `polaris-chaos-drill.sh` runs weekly against the booted blue-green stack under traffic (one colour killed with zero drops, both stopped until `PolarisAppDown` reaches a webhook through real Prometheus and Alertmanager, redis and postgres killed, pgbouncer partitioned, every recovery against a ceiling) with the row committed to [CHAOS-DRILLS.md](docs/operator/CHAOS-DRILLS.md); findings become checks. Pinned by `check_chaos_program` |
| [ ] P2.12 | Evaluate Plonky2 to Plonky3 migration | L | med | P2.5 | An EVALUATION SPIKE with a decision record, not a committed migration. Plonky3 is NOT a version bump: it ships as modular `p3-*` component crates (a STARK/AIR toolkit), not a drop-in for Plonky2's ready-made recursive-SNARK `CircuitBuilder`, so adopting it is a rewrite of `polaris_zk` (circuit as an AIR) plus a full two-witness re-anchor, not a `cargo` bump. As of 2026-09 Plonky3 is `0.7.0-rc.1` (a release candidate) while Plonky2 is stable at 1.1.0 but 16 months without a release. This row exists because that staleness-vs-momentum gap is a real long-term supply-chain question for a national system; it is timed to P2 because you do not rewrite a prover before (a) Plonky3 stabilizes past RC and (b) the scale requirements (P2.5 epoch pipeline) actually justify the cost. DoD: a written comparison (perf at production depth, proof size, audit status, maintenance trajectory, rewrite cost, two-witness feasibility) ending in a recorded keep-or-migrate decision. The nearer-term ZK step remains the sibling-path witness optimization named in P0.7 |

Exit gate: P2.9 (the capacity model, single-node measured and multi-node projected) green and published.

---

## P3 - Federation and the relying-party ecosystem

Objective: multiple independent issuing authorities interoperate, and third
parties verify against Polaris without talking to us.

| ID | Item | Size | Risk | Blocked by | Definition of done |
|---|---|---|---|---|---|
| [ ] P3.1 | Topology decision record | M | low | - | An ADR choosing federated per-authority instances (the schema's explicit-attestation model) over a central instance; the threat-model delta documented |
| [ ] P3.2 | Inter-authority protocol v1 | L | high | P3.1 | A versioned spec: attestation exchange, anchor cross-publication, epoch alignment, revocation propagation; conformance vectors included |
| [ ] P3.3 | Transparency service | L | med | P3.2 | A public append-only anchor log, mirrored; `ct-monitor` productized as an independent daemon anyone can run; a tampering drill proves detection |
| [ ] P3.4 | Relying-party API v1 | M | med | P2.6 | A stable versioned verification API; RP organizations authenticate via mTLS or OAuth2 client credentials. This is API access auth only: identity never becomes a login product, per the vocation. Deliberately reopens the retired "OIDC" scope in that narrow form |
| [ ] P3.5 | RP SDKs and conformance suite | L | med | P3.4 | Server-side verify SDKs (Python, TypeScript) with a public conformance suite; passing it is the integration contract |
| [ ] P3.6 | Offline verification protocol v1 | L | high | P2.6 | A short-lived signed presentation plus status bundle verifiable with no connectivity; replay and freshness bounds specified; a reference verifier CLI ships |
| [ ] P3.7 | mDL / ISO 18013-5 bridge | L | med | P3.4 | Read-only derived mdoc presentment from a Polaris token for mDL-reader interop; no new trust semantics |
| [ ] P3.8 | W3C VC issuance endpoint | M | low | P3.4 | An optional VC representation of a verification result; explicitly a format, not a trust model |
| [ ] P3.9 | Per-authority isolation review | L | med | P3.1 | Operator RBAC and data isolation reviewed for the federated topology; row-level security added where the review demands it |
| [ ] P3.10 | Federation proven in CI | M | med | P3.2 | A CI job boots two instances as two authorities and proves cross-verification, attestation revocation, and anchor cross-checks end to end |

Exit gate: P3.10 green, plus one external team completing an SDK integration
using only the public docs and the conformance suite.

---

## P4 - Hardware token and enrollment field kit

Objective: the physical layer. Runs in parallel from P1. The schema already
models the card (serials, biometric binding type, duress hash, succession);
this phase makes the card real.

An honest constraint, stated up front: ML-DSA on secure elements is
bleeding-edge silicon. The card profile therefore targets the schema's own
UC-6 dual-signature model: a classical signature on today's certified silicon
plus a post-quantum binding, migrating on-card as FIPS 204 hardware certifies.
That is exactly the migration the database was built to express.

| ID | Item | Size | Risk | Blocked by | Definition of done |
|---|---|---|---|---|---|
| [ ] P4.1 | Card profile spec v0 | L | high | - | The on-card data model, dual-signature layout, PIN and duress semantics, and succession handling, reviewed against the threat model |
| [ ] P4.2 | Software token emulator and vectors | L | med | P4.1 | An emulator implementing the profile plus published test vectors; everything downstream develops against it |
| [ ] P4.3 | Personalization service | L | high | P4.2, P1.2 | A secure key-injection flow bound to the audit-of-record; every personalization is an AoR event |
| [ ] P4.4 | Enrollment station reference | XL | high | P4.3 | A kiosk build: locked-down browser, vendor-neutral biometric capture abstraction, document authentication hooks, and the 800-63A evidence flow; produces a complete IAL-mapped enrollment record |
| [ ] P4.5 | Verifier device reference | L | med | P4.2, P3.6 | An NFC/QR read path with online and offline verification, running the P3.6 protocol |
| [ ] P4.6 | Silicon tracking and eval | M | ext | - | [EXT: vendor availability] A FIPS 140-3 SE vendor matrix, ML-DSA-on-SE status, and eval-kit results as they exist; refreshed quarterly |
| [ ] P4.7 | Duress-on-card interaction spec | M | med | P4.1 | The duress entry method specified with a safety review; indistinguishability preserved end to end at the physical layer |

Exit gate: enroll a person, personalize a token (emulator or eval silicon),
verify online and offline, revoke, and recover, with every step on the AoR and
every guarantee holding.

---

## P5 - Pilots [EXTERNAL GATES]

Objective: real, consenting users. Institutions decide; our job is to make
saying yes cheap and safe.

| ID | Item | Size | Risk | Blocked by | Definition of done |
|---|---|---|---|---|---|
| [ ] P5.1 | Pilot-in-a-box | L | med | P1, P4.2 | A one-command pilot deployment profile: ops pack, metrics and reporting bundle, DPIA template, consent flow, and a rollback-and-erasure plan |
| [ ] P5.2 | Campus pilot | M | ext | P5.1 | [EXT: university MOU, IRB] An opt-in campus credential shadow pilot; our part is support engineering and the public exit report |
| [ ] P5.3 | Agency pilot | L | ext | P5.2 | [EXT: county or agency MOU] Shadow verification alongside an existing credential at a real agency, to the same reporting bar |
| [ ] P5.4 | Post-pilot fix arcs | L | med | each pilot | Every pilot finding triaged, fixed, and pinned; the report published |

Exit gate: two completed pilots, public reports, zero constitutional
violations under real use, and erasure honored on request and proven.

---

## P6 - Certification and assurance [EXTERNAL-HEAVY]

Objective: the assurance envelope a government sponsor requires. External
certifications are theirs to grant; readiness is ours to build.

| ID | Item | Size | Risk | Blocked by | Definition of done |
|---|---|---|---|---|---|
| [ ] P6.1 | Validated-crypto option | M | ext | P1.2 | [EXT: module certification] The custody interface drives a FIPS 140-3 validated module; the two-witness discipline is retained; the toggle documented |
| [ ] P6.2 | NIST 800-63-4 mapping | L | med | P4.4 | An IAL/AAL/FAL mapping with evidence per control; gaps closed or explicitly waived with reasons |
| [ ] P6.3 | FedRAMP/StateRAMP-ready profile | L | ext | P1.5 | [EXT: authorization] A GovCloud IaC reference, a control-mapping SSP skeleton, inheritance documented |
| [ ] P6.4 | SOC 2 evidence automation | M | ext | P1 | [EXT: audit] Continuous evidence collection wired to the ops stack |
| [ ] P6.5 | Accessibility to WCAG 2.2 AA / Section 508 | L | med | - | Every surface audited and conformant; automated accessibility checks added to CI |
| [ ] P6.6 | Independent audit, public red team, bug bounty | M | ext | P1.12 | [EXT: funding] Scoped from [RED-TEAM-SCOPE](docs/RED-TEAM-SCOPE.md); results published unredacted where safe |
| [ ] P6.7 | Formal-methods expansion | L | med | P0.7 | Specs for C1, C2, and the epoch/status protocol; the purge coverage property proven; [meta/tla](meta/tla/README.md) graduates from demonstrator to maintained |
| [x] P6.8 | Athena: the authority-and-constitution ontology (v9.266) | M | med | - | A read-only semantic + provenance layer ([`polaris_sql/16_athena.sql`](polaris_sql/16_athena.sql), [athena.md](docs/design/athena.md)) over the EXISTING authority tables (agency/algorithm/context/trust/retention) plus C1-C10 + the Vocation modelled as first-class queryable rows linked to the exact live mechanism that enforces each — so "why is this authorized / what enforces it / what breaks if this key or algorithm is retired" is mechanical, with provenance. 10 object + 8 edge views and four functions (`athena_authority_chain`, `athena_explain_proof`, `athena_affected_by_algorithm`, `athena_rule_enforcement`); `athena_rule_enforcement` maps every rule to a trigger/index/CHECK/`check_*`/procedure and `check_athena_rule_enforcement_resolves` fails the build if one drifts (closing the prose-drift gap in [constraint-lattice.md](meta/constraint-lattice.md)). Assessed and endorsed (constrained version): [DEVNOTES/athena-ontology-assessment.md](DEVNOTES/athena-ontology-assessment.md). Person-legibility is structurally impossible, five checks each with a detection test: NO natural-person node/column, NO globally-linkable subject surrogate, NO ZK-subject traversal, bounded event access under the Atlas C8 ceilings, and NON-SOVEREIGN (describes/orchestrates authority; the DB constitution stays the source). The same ship removed the existing `v_ontology_individual`/`_tokens` person views (their single-entity data now lives only on the audited Investigate route). Plain PostgreSQL (no graph DB/RDF); read-only. The operator-facing four-tab Athena console (`/athena`: Constitution / Authority / Proof / Trust) shipped at v9.267 |
| [ ] P6.9 | Operational-learning subsystem (assessment first) | L | high | P6.8, P2.14 | A future, advisory-only ML subsystem that learns **Polaris itself** (infrastructure, authorities, system behaviour) for anomaly detection, capacity forecasting, regression and root-cause help, and AGGREGATE institutional-abuse patterns — never natural persons. Central hypothesis to be falsified: ML may infer properties of the system, never rank/score/predict the rights of people. Captured brief (NOT started, needs assessment on the Athena model): [DEVNOTES/operational-learning-assessment-brief.md](DEVNOTES/operational-learning-assessment-brief.md). Advisory only (OBSERVE->…->RECOMMEND, never PREDICT->REVOKE); pairs with Athena for root-cause explainability; a candidate new constitutional rule; synthetic-nation ground truth for evaluation. Naming open (proposed "Metis", not "Prometheus" — that name already belongs to the metrics stack). Do the 23-section assessment before any code |

Exit gate: a sponsoring authority accepts the authorization package [EXT].

---

## P7 - National rollout [EXTERNAL-DOMINATED]

Objective: the machinery of scale-out. Statute, funding, and program authority
belong to government; every buildable artifact is ready before it is asked for.

Planning targets (to be validated, not asserted): 350M persons; 5,000
sustained and 50,000 peak verifications/s nationally across federated
instances; an enrollment surge of 200,000/day sustained during rollout years;
99.99% availability on the verification path.

| ID | Item | Size | Risk | Blocked by | Definition of done |
|---|---|---|---|---|---|
| [ ] P7.1 | Institutional prerequisites register | M | ext | - | [EXT: statute, SORN, funding] The complete list of legal instruments and decisions national operation requires, maintained as a living document |
| [ ] P7.2 | Authority onboarding factory | L | med | P3, P6.3 | Instance-per-authority provisioning automation plus an onboarding playbook; a new authority reaches interoperating-live in days |
| [ ] P7.3 | National capacity model | L | med | P2.9 | The targets above validated by extrapolation from measured P2 numbers plus staged federation load tests; published |
| [ ] P7.4 | 24/7 operations design | M | ext | P2.11 | [EXT: staffing] SOC integration, on-call structure, public status and incident communications, all specified and tool-ready |
| [ ] P7.5 | Coexistence and migration spec | M | med | P3.7 | Phased coexistence with Real ID and legacy credentials, cutover and sunset criteria, no flag-day |
| [ ] P7.6 | Quantum-event readiness | L | med | P2.5 | A mass UC-6 migration drill at scale: the measured time to re-sign a population when an algorithm falls; runbook committed |
| [ ] P7.7 | Public transparency program | M | low | P3.3 | Anchors, availability, audit results, and aggregate warrant-audit statistics published on a standing cadence |

Exit gate: the first state authority live at scale on its own instance; a
national program office assumes ownership; the project transitions to steward
of the reference implementation.

---

## Standing rules (every phase, every ship)

1. **The constitution gates everything.** No item ships if it erodes C1-C10 or
   the vocation. Anything touching them carries a constitutional note in its
   CHANGELOG entry.
2. **The ship discipline is unchanged** (see [CLAUDE.md](CLAUDE.md)): edit,
   test, check, bump, CHANGELOG, gate READY.
3. **Every new capability ships with its checks.** A capability without a
   detection-tested check is not done.
4. **Exercise, never just read.** Ten of ten defects found in the 2026-08-31
   sweeps were invisible to reading. Anything operational is run against a
   scratch stack before it is called done.
5. **Numbers carry stamps.** Any stated count or benchmark names the version
   it was measured at.
6. **External gates never wait on us.** For every [EXT] row, the buildable
   readiness artifact is listed and built before the external actor is
   engaged.
7. **Reopened decisions are recorded.** This file reopens Linux deployment
   (P1.1) and narrow RP API authentication (P3.4) against earlier
   retirements, with reasons inline. Banking and payments stay out
   permanently: C10 is not a phase.
8. **Presentation is a deliverable, and its rework is pre-authorized.** On
   2026-09-02 the owner authorized wholesale rework of any human-facing
   surface (documentation, the GitHub presence, the demo site, the
   repository's organization, the software's own UI, CLI, and messages)
   wherever that serves national-deployment readiness, including removal of
   bloat, unneeded material, and anything that could confuse an observer.
   Rows P1.13-P1.17 are therefore autonomous-eligible despite their medium
   risk; the constitution (rule 1) and the honesty ledger still bound them.
   Those five rows closed at v9.225, twenty-nine ships in all; the record is
   [DEVNOTES/presentation-plan.md](DEVNOTES/presentation-plan.md). The
   authorization does not expire with them: a human-facing surface that drifts
   again is reworked under this rule, not re-authorized.

## Permanent non-goals

No payment rails or monetary claims (C10). No central biometric database. No
population-scale attribute filtering or analytics. No social scoring. No
commercial or advertising use of verification data. No real personal data
before the P5 consent framework exists. These do not expire with any phase.

## Execution protocol for the next session

1. Read [CLAUDE.md](CLAUDE.md), then this file. The active phase is the lowest
   phase with pending rows.
2. Pick the first row whose Blocked-by column is satisfied; prefer S and M
   rows when resuming cold.
3. One row is one ship (S rows may batch). Mark `[>]` on start; mark `[x]`
   with a version stamp when the definition of done is verifiably true.
4. If a definition of done proves wrong or underspecified, amend the row in
   the same ship and say so in the CHANGELOG entry.
5. When a phase's exit gate is met, record it in the CHANGELOG and move to
   the next phase.
