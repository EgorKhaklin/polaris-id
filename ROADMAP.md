# ROADMAP.md - from reference implementation to national deployment

This is the build plan. It is written to be executed: an agent (or a human) in a
fresh session reads [CLAUDE.md](CLAUDE.md), then this file, picks the first
unblocked item in the active phase, and ships it under the standing ship
discipline. Shipped history lives in [CHANGELOG.md](CHANGELOG.md), not here.

**Decision record.** The project's core was declared done at v9.27, and the
work that followed was limited to hardening, measurement and thesis evidence
until a named owner trigger opened a new arc. That trigger occurred on
2026-08-31, when the project owner directed a complete plan to real national
deployment; this roadmap is that recorded decision, and the definition-of-done
freeze that preceded it has since been retired from the constitution as no
longer the operating frame. The constitution (C1 to C10 and the vocation) is not
softened by it: every phase below carries the constitution as a hard gate,
what a deployment may not yet claim is bounded by
[docs/PRODUCTION-READINESS.md](docs/PRODUCTION-READINESS.md), and several
previously retired scope decisions are reopened here with reasons, rather
than silently.

**Engine before wrap (2026-09-08).** The owner directed a hard reprioritization:
too much effort had gone into the *wrap* (consoles, ontology, presentation) and
too little into the *engine* (the cryptographic primitives as things that run
detached, for real, under attack). The test of engine work is **displacement** —
a path that exists and runs without anyone watching, not another document saying
the path exists. Phase E below is that engine work, and it is the active phase:
it precedes the numbered deployment phases, and the wrap is frozen behind it (see
"Frozen behind the engine" in Phase E). This reopens no non-goal and does not
soften the constitution.

**The holder before the deployment (2026-09-10).** The owner directed a second
reprioritization. Version 2 of the paper was written from the tree rather than from
this plan, and it found five load-bearing absences in the system itself; four of them
had no row here at all, and a fifth existed only as a sentence inside a completed row.
The cause was the ordering principle: phases were ordered by distance to national
deployment, which is gated on institutions, rather than by what can be built without
one. **Phase P9 below is that work and it is the active phase.** Every row in it is
buildable by the maintainer alone and every row retires a stated limitation. The rows
that wait on an external actor are gathered under "Waiting on the world" so the
execution protocol cannot select one. This reopens no non-goal and does not soften the
constitution; P9.1 carries a constitutional note against the vocation.

**P9 is COMPLETE at v9.354 (2026-09-10).** All eight rows shipped. The holder now has a
key of their own (P9.1), proves membership on their own device against a published
anonymity set (P9.2), carries a per-verifier nullifier so one relying party can refuse a
second claim without learning who (P9.3), hands out no identifier stable across relying
parties (P9.4), and can delegate to an agent with a bounded, expiring grant they alone can
revoke (P9.8), while federation trust rests on a signature rather than an operator's word
(P9.5), long-term validation is decidable by an SDK that imports no Polaris code (P9.6),
and the last audit-of-record instance resting on procedure is enforced at the schema
(P9.7). Two limitations were restated rather than closed, in the code and on every outward
surface: cross-verifier correlation is bounded, not eliminated, because a full credential
still shows a verifier stable material; and neither the nullifier nor the pairwise handle
hides a holder from the ISSUER, which derives every leaf to build the tree.

By rule 5 the numbered deployment phases resume. P0.11 and P1.12 are the only rows left in
those phases and both read `ext`, which rule 2 forbids selecting, so the first selectable
row is **P2.5** and the active phase is **P2**.

**Status marks:** `[ ]` pending · `[>]` in progress · `[x]` done ·
`[EXT]` blocked on an external actor (funding, law, vendor, institution).
Update marks in place as part of each ship; never delete rows.

**Sizing:** S (under one session) · M (1-3 sessions) · L (an arc, 3-10) ·
XL (multi-arc). Risk is delivery risk, not security risk.

---

## Where we are (inventory at v9.311)

**Have, working, CI-proven:** a 37-table constraint-enforced schema (44 tables
in a migrated deployment) with append-only audit; a 122-route application with
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
release; CVE gates on dependencies and images; a coverage floor; 202 invariant
checks (v9.350) each with a detection test; eighteen operator runbooks and ledgers; the protocol layer
(P8, complete and released): a signed registry, trust lists, the exchange gateway with
receipts, a timestamp authority, document signing with long-term validation, an auth broker,
offline wallet presentations, algorithm agility and versioning, frozen at version 1 with a
cross-version suite in CI; and the bound on
every claim in [docs/PRODUCTION-READINESS.md](docs/PRODUCTION-READINESS.md).

Since the v9.236 base, and CI-proven: HA automation (Patroni with an etcd leader
lease and an automated failover drill under a live write stream); monthly table
partitioning holding C1 across attach and detach; a read replica under a staleness
contract; a holder credential wallet; a versioned relying-party API (`/api/v1`) with
Python and TypeScript verify SDKs and a language-agnostic conformance suite; offline
verification via short-lived issuer-signed status assertions; an inter-authority
federation protocol (signed federation manifests, epoch checkpoints, revocation
feeds, and an aggregate status bundle) whose trust is decided OFFLINE by a standalone
detached verifier, proven across two INDEPENDENT instances over HTTP in CI; a public
RFC-6962-style transparency log with independent witnesses, an equivocation proof, and
external-ledger publication; and that detached verifier held TOTAL against hostile
input by a metamorphic fuzzer.

**Do not have:** hardware tokens (the physical artifact is modeled, not built);
identity-proofing evidence flows mapped to NIST 800-63; multi-region scale
(monthly partitioning, HA automation and a read replica now ship; the profile
is still single-region); status and revocation distribution at production CDN
scale (the signed artifacts and the aggregate bundle ship, P3.2b/P3.2c; a
distribution deployment does not); a hardware HSM in CI (the PKCS#11 driver is
proven against a software token); certified cryptography (liboqs is not
FIPS-validated); published registry images and image signing (deferred from P0.6
until images are published); accessibility conformance; any external audit, pen
test, or pilot; an external team's docs-only integration against the wire specification
(the conformance suite is the contract; the integration itself has not happened); anchor
verification in the SDKs (P8.5c; the detached verifier has it); a relying-party-signed
authorization request; native wallet applications (the wallet is a protocol and a reference
script); a holder-side key (the model is issuer-centric, which is why document signing is
notarial, login is by possession, and no delegation exists); a scoped nullifier, without
which a membership proof cannot enforce one human once per scope; a presentation that
carries no handle stable across verifiers; attestations signed by the attesting agency
rather than recorded by an operator; a schema-enforced `RecoveryRequest`; and every
institutional prerequisite of a national system (statute,
funding, enrollment workforce, manufacturing, authorization to operate).

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
| **E** | **The engine: real, detached, adversarial** (COMPLETE, v9.280) | n/a | A relying party verifies offline with no Polaris code; two issuers interoperate; the HSM is the only prod signer; attacks run every release and fail; a person holds a credential; numbers are published |
| P0 | Foundation closure | n/a | Every claim reproducible by command; supply chain signed; zero known debts |
| P1 | Single-authority production | 10k-100k persons, one org | A non-author operator runs it from docs alone; pen test closed; SLOs met |
| P2 | Scale architecture | 1-10M persons (state) | 10M load profile green on HA topology through a rolling deploy and a failover |
| P3 | Federation and relying parties | Many authorities, third-party verifiers | Two instances interoperate in CI; an external team integrates docs-only |
| P4 | Hardware token and enrollment | Field-ready issuance kit | Enroll, personalize, verify online+offline, revoke, recover: end to end on AoR |
| P5 | Pilots | Real, consenting users | Two completed pilots with public reports, zero constitutional violations |
| P6 | Certification and assurance | Authorization-ready | Validated crypto option, 800-63 mapping, audit and red team published |
| P7 | National rollout | 350M persons | First state live; a national program office assumes ownership |
| P8 | The exchange fabric, the Polaris way | Many independent organizations | A non-Polaris implementation interoperates from the spec alone; an institutional exchange is provable to a third party WITHOUT retaining the payload |
| **P9** | **The holder: the key, the proof and the grant** (ACTIVE) | n/a | A holder proves on their own device, once per scope, unlinkable across scopes; an agent acts under a signed, expiring, separately revocable grant |

Phase E is COMPLETE (v9.280): all of PE.1-PE.8 shipped. The engine was built before
more deployment machinery was wrapped around it; the numbered phases below resume as
the active work. P4 runs in parallel from P1 onward.
P8 is a SOFTWARE arc, buildable now: it extends P3's federation and relying-party work
into the "digital society" layer (the exchange-fabric piece Polaris lacks), and it is NOT
gated on the P4-P7 deployment or institutional phases. Its defining constraint is the
anti-surveillance inversion of an evidentiary message log: evidence that an exchange occurred and was
authorized, without retaining the underlying personal data.
P9 is the ACTIVE phase (2026-09-10): a software arc, buildable now, that closes the
system's own gaps rather than the deployment's. It precedes the numbered deployment
phases in priority, not in numbering.
P5-P7 are gated on external actors; the buildable machinery for each is listed so
no external gate is ever waiting on us.

---

## PE - The engine: real, detached, adversarial  [COMPLETE at v9.280]

Objective: the cryptographic core is not a thing the app does behind a login; it
is a set of primitives that run **detached, for real, and under attack**. Each
row is measured by displacement — a path that runs without anyone watching — not
by a document that says it does. This phase is active; it precedes the numbered
deployment phases below.

| ID | Item | Size | Risk | Blocked by | Definition of done |
|---|---|---|---|---|---|
| [x] PE.1 | The default boot is the real motor (v9.280) | M | med | - | Production FAILS CLOSED at boot unless real ML-DSA-65 signing is actually available (`pqc_signing.is_enabled()` — POLARIS_USE_REAL_PQC=1 AND liboqs), so a deployment can never silently issue tokens signed with the SHA3-256 placeholder; the placeholder becomes a NAMED dev profile (`POLARIS_PQC_PROFILE=placeholder`) that the canonical test/dev paths (CI test job, polaris-test.sh, dev compose) declare and that WARNS loudly when used unnamed, with the active profile announced at boot (`boot.pqc_profile`). Pinned by `check_real_pqc_default_boot`; the boot refusal is exercised by `RealPqcDefaultBootTests`. Scoped to production fail-closed rather than a global default flip so the many app-booting CI jobs keep running |
| [x] PE.2 | A detached verifier a relying party runs with no Polaris code (v9.274) | M | med | - | `scripts/polaris-verify.py` verifies an ML-DSA-65 authenticity pack OFFLINE with only a standard ML-DSA library, no Polaris code and no database; `GET /api/tokens/<id>/authenticity-pack` exports the pack; the published `vectors/` are re-verified in CI under liboqs AND cryptography/OpenSSL (three independent implementations agree). Pinned by `check_detached_verifier`; the pack round-trip is a DB test; CI's `pqc-real` job runs `--selftest` and `--verify-dir` |
| [x] PE.3 | Two issuers on one machine — real federation (v9.276) | L | med | PE.2 | `scripts/polaris-federation-drill.py` stands up two issuers on one box with DISTINCT ML-DSA-65 roots plus a third outsider, issues a genuine token under each through the real signing path, and proves with the detached verifier that each relying party accepts its own issuer, REJECTS a foreign issuer, and rejects the outsider — decided against published KEYS via `issuer_trusted`, not the DB trust graph. CI runs it under real ML-DSA-65; `check_federation_real` pins it; a `federation` adversary is in attacks/. PE.3b SHIPPED (v9.286): federation IN the running app — each Agency registers `signing_public_key_hex`, custody selects the issuing agency's own key (`POLARIS_AGENCY_KEYS_DIR/<id>.json`, falling back to the global key), `/uc1/issue` signs with it and REFUSES a cross-key token, and `/verify` reports `issuer_authentic`; per-agency signing tested under real ML-DSA (`PerAgencyCustodyTests`) + the issuer-binding field (`FederationInAppTests`), pinned by `check_federation_in_app` |
| [x] PE.4 | The HSM is the only production signing path (one profile) + rotation (v9.277) | L | med | - | `POLARIS_REQUIRE_HSM_SOLE_SIGNER=1` makes the app FAIL CLOSED at boot unless the PKCS#11/HSM driver is the sole signer, no file key is in the environment, and real PQC is on (guard pinned by `check_prod_fail_closed`, boot refusal tested by `HsmSoleSignerBootTests`). Key rotation is drilled IN-TOKEN against a real PKCS#11 token: a second key is minted inside the token under a new label, a token signed under the old in-token key STILL verifies after the switch while the new key signs, and dropping the old anchor completes retirement (`test_in_token_rotation_...`, run by the `custody-pkcs11` job; pinned by `check_key_rotation_drilled`). Software token: Kryoptic (the ML-DSA-capable PKCS#11 v3.2 module; SoftHSMv2 lacks ML-DSA). Unblocked from PE.1: the profile enforces real PQC itself |
| [x] PE.5 | Attacks that must fail, run every release (v9.275) | M | med | PE.2 | An `attacks/` folder of executable adversaries (forge a signature, tamper a pack, present a revoked token, replay, wrong key), each of which MUST fail against the real code; CI runs them every release and goes red if any SUCCEEDS. Running attacks, not greps |
| [x] PE.6 | An offline authenticity pack, re-verifiable with the network off (v9.274) | S | low | - | Folded into PE.2: the authenticity pack is one self-contained file, and `polaris-verify.py --pack file.json` verifies it with no network and no database. The published `vectors/` are exactly such files |
| [x] PE.7 | One held-in-hand flow, even ugly — a holder CLI (v9.278) | L | med | PE.2 | `scripts/polaris-wallet.py` is the first NON-operator surface: a person holds a credential as a file (`enroll`, optionally a duress code), sees it offline (`show`), verifies it offline through the detached verifier (`verify`), presents it to a relying party (`present`; a duress presentation is byte-identical in structure to a normal one — the holder-side of the anti-coercion vocation), and proves membership in ZERO KNOWLEDGE against a published epoch (`prove-membership`, via the polaris-zk binary — a real proof that round-trips through `polaris-zk verify`). Standalone: no server code, no database. Pinned by `check_holder_wallet`; `test_wallet.py` (in the coverage suite) proves the deniability property and the ZK round-trip |
| [x] PE.8 | Publish real numbers from this box (v9.279) | M | low | PE.2 | `scripts/polaris-dyno.py` measures the real primitives on the box it runs on — ML-DSA-65 sign and verify (single-witness verify-at-use AND two-witness issuance-grade) and ZK membership prove/verify at the configured tree depth — and prints them with the box spec and a version stamp. A committed run is published in [docs/reference/DYNO.md](docs/reference/DYNO.md) (Apple Silicon, 8 cores: ~2,110 sign/s, ~7,840 single-verify/s, ~740 two-witness/s, ZK prove ~35 ms / verify ~13 ms at depth 14), cross-checking the national-sim numbers in BENCHMARK.md. The numbers are MEASURED, single-core, and NOT extrapolated (a fleet number stays a separate labelled projection); CI re-measures every release (ML-DSA in pqc-real, ZK in the test job). Pinned by `check_dyno_published` |

Exit gate: a relying party verifies a Polaris credential offline with no Polaris
code (met at PE.2); two issuers interoperate with correct accept and reject; the
HSM is the only signer in one profile with a drilled rotation; the attack suite
runs every release and is green (every attack fails); a person holds and presents
a credential; and the published numbers come from a reproducible bench on a named
box. **Met at v9.280: all of PE.1-PE.8 are done — Phase E is COMPLETE.** Composed
end to end at v9.287: `scripts/polaris-relying-party.py` is the relying party the
exit gate implies — it decides ACCEPT/REJECT for a holder's presentation by combining
offline authenticity (PE.2) with online status (`/verify`), refusing a revoked, tampered,
or foreign-issuer credential and staying blind to duress; `scripts/polaris-e2e-drill.py`
runs the whole wallet-to-relying-party matrix under real ML-DSA every release, pinned by
`check_holder_verifier_flow`. The vinyl frozen behind it (further Atlas/Athena/ontology/constitution-tiers, file-only invariants, SLH-DSA-before-HSM, 'national' scope) can now be reconsidered with the owner.

**Frozen behind the engine.** These add surface, not displacement, and are frozen
until PE's exit gate is met: further Atlas ships (Investigate, Alerts) and any
Athena / ontology / foresight / "constitution tiers" expansion; any invariant
that only reads a file rather than exercising a path; wiring a second signature
algorithm (SLH-DSA) before the HSM is the sole production signer (PE.4); and any
"national"-scale expansion of scope. The permanent non-goals below hold
independently of this freeze.

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
| [x] P2.5 | Epoch pipeline at scale (v9.357) | L | high | P0.7 | DONE (v9.357), with the middle term of the definition AMENDED (rule 4). INCREMENTAL MERKLE MAINTENANCE: an epoch tree is fixed-depth and was padded to 2^depth before anything was hashed, which at the national depth of 24 cost 10.8s and 2.9GB to root a THOUSAND members and did not move with the population at all. The padding is one repeated value, so every subtree above the real members is an all-zero subtree with one hash per level; folding those in makes a root O(members + depth) and a single-member repair O(depth). Measured: 0.01s/27MB for a thousand, 0.24s for 100k, 2.10s for 1M, all at depth 24. The padded construction is KEPT as the reference the sparse root is asserted element-for-element equal to, so no published epoch becomes unverifiable. WITNESS PARITY AT PRODUCTION DEPTH: the Python second witness folds the padding the same way and agrees at depth 24, where the padded form (16.7M entries of pure-Python Poseidon) could not run at all. PARALLEL PROVING is amended away: P9.2 moved proving to the HOLDER's device, so the authority no longer proves, and the authority-side batch that remained was one inclusion path per member. Measuring it found the real wall was not compute but storage: 1,718 bytes per member, roughly 17GB of JSON to close a ten-million-member epoch, written on every close and READ BY NOTHING, and flagged by the schema as plaintext at rest. The answer at scale is not to parallelise it but not to materialise it, so since migration 011 `proof_path` is nullable and an epoch close stores none; a holder derives their own path from the published set. EPOCH CADENCE SPEC published at [epoch-cadence.md](docs/design/epoch-cadence.md): the cadence sets revocation freshness, the size of the anonymity crowd and how often a relying party's one-human-once ledger resets, and those pull against each other. `check_epoch_pipeline_scale` with a twelve-fixture detection test and `scripts/polaris-epoch-scale-drill.py` gating parity, two-witness agreement at depth 24, and wall-clock and memory ceilings on every push. The 10,000-member epoch cap in `uc11_close_epoch` and the bounded published set are UNCHANGED and are now the binding national-scale constraint; the spec says why raising them is a deployment decision, not a number to bump |
| [x] P2.6 | Status distribution v1 (v9.358) | L | high | P2.5 | DONE (v9.358): The artifacts were already signed, versioned and short-lived, and the detached verifier already decides them offline; what was missing was the property that makes an untrusted intermediary SAFE to put in front of the origin. Every public status artifact now carries cache directives derived from its OWN signed `expires_at`, never a constant, so a cache physically cannot outlive the window the issuer committed to; an expired or unparseable window is `no-store` rather than cached for a guessed interval; `stale-while-revalidate` and `stale-if-error` are refused, because serving a known-stale revocation feed when the origin is unreachable is the cheapest attack on the design, not a resilience feature; and each carries a strong ETag over its canonical bytes so an intermediary revalidates without the origin re-signing. The split that matters is pinned in both directions: the seven artifacts identical for every consumer are `public`, and the three that NAME ONE CREDENTIAL (status assertion, holder binding, timestamp) are `no-store` rather than `private`, because a shared cache holding one would serve one holder's credential to another and `private` still lets a holder's own device keep it on disk. Freshness rules published at [status-distribution.md](docs/design/status-distribution.md); `check_status_distribution` with a twelve-fixture detection test and `scripts/polaris-status-distribution-drill.py` on every push. NOT done here and stated as such: CDN placement, origin-shield topology and a measured hit rate at national volume are the operator's deployment, not the repository's |
| [x] P2.7 | HA automation (v9.243) | L | high | P1.10 | The HA profile (`docker-compose.ha.yml`) runs the database under Patroni with a leader lease in a three-member etcd and HAProxy routing on the role endpoints; `polaris-failover-drill.sh` loses the leader, cuts it off from the lease store, switches over and crashes an etcd member under a live write stream on every push; [FAILOVER.md](docs/operator/FAILOVER.md) carries the measured numbers and the split-brain analysis. The member hosts are the operator's placement. Pinned by `check_ha_automation` |
| [x] P2.13 | HA on Kubernetes (v9.244) | M | med | P2.7 | The chart runs the same Patroni members under the same entrypoint with the Kubernetes API as the lease store (no etcd): a Role for exactly what Patroni needs, a selector-less leader Service whose endpoints follow the lease, a replica Service on the role label; the kind drill deletes the leader pod, switches over, and asserts every acknowledged insert present. Pinned by `check_helm_reference_profile` |
| [x] P2.8 | Multi-region DR (v9.359) | L | med | P2.7 | DONE (v9.359): The HA profile survives a NODE dying; it does not survive the region, and the tempting fix of a third Patroni member 'in region B' puts the wide-area network inside region A's quorum in three places (the lease store must be reachable across it, so a partition between regions partitions the consensus; write latency includes it; and a member of A's cluster in B is still A's problem when A's lease store is gone). So region B is a Patroni STANDBY CLUSTER: a different scope, its OWN lease store, streaming ASYNCHRONOUSLY from region A's router so a failover inside A does not break replication to B, and electing no primary of its own so the two can never both accept writes. `polaris_web/docker-compose.dr.yml` plus standby support in the Patroni entrypoint. `scripts/polaris-region-evacuation-drill.sh` runs the whole evacuation on every push: it cuts the region the way a region goes dark (members, router AND lease store at once), promotes region B, and MEASURES the recovery time and the recovery point rather than asserting them, having recorded every acknowledged write as it went because once the region is gone nobody can ask it what it acknowledged. Measured locally: RTO 5s, RPO 0 rows at the drill's write rate, against ceilings of 90s and 50 rows. Two properties matter more than either number and are asserted: region B holds NO row region A never acknowledged (a recovery point is a stated cost, divergence is a correctness failure), and what crossed is a CONTIGUOUS prefix (a standby missing rows below its high-water mark skipped rather than lagged, which counting would not catch). `docs/operator/DR.md` carries the procedure and states the non-zero recovery point BEFORE it, plus the rule that a returned region A is rebuilt as a standby and never brought back as a primary; `docs/design/multi-region.md` is the design record. `check_multi_region_dr` with a fourteen-fixture detection test. NOT done and stated: placement is the operator's, promotion is deliberate rather than automatic (an automatic cross-region promotion would have to distinguish 'region A is gone' from 'region A is unreachable from here', and getting that wrong makes two primaries on two timelines), and zero data loss would need synchronous replication with the WAN on every commit |
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
| [x] P3.1 | Topology decision record (v9.292) | M | low | - | SHIPPED. [docs/design/federation-topology.md](docs/design/federation-topology.md) is the ADR: Polaris is FEDERATED per-authority (each authority its own ML-DSA root, explicit NON-TRANSITIVE cross-attestation via AgencyTrustAttestation, a relying party verifying against published keys with NO central service), chosen over a central instance. The choice is derived from the constitution (the anti-monopoly + anti-surveillance vocation), not taste: a central instance is a monopoly and a population-scale aggregation the vocation refuses. The threat-model delta (blast radius, aggregation, coercion, trust semantics, cost) is documented. `check_federation_topology` keeps the ADR HONEST against the code: it may not claim the federated model unless AgencyTrustAttestation, _federation_trust_holds, per-authority keys, and the detached verifier are all present. Grounded in what already runs (PE.2/PE.3/PE.3b). |
| [x] P3.2 | Inter-authority protocol v1 (v9.296) | L | high | P3.1 | SHIPPED (v1: anchor cross-publication + attestation exchange; epoch alignment + revocation propagation named + deferred to P3.2b). An authority publishes a SIGNED federation manifest (`polaris-federation-manifest/1`) at `GET /api/v1/federation-manifest/<id>`: its own anchors (roots) + the AgencyTrustAttestation rows it has made (who it accepts, per context, with the attested key). The detached verifier decides cross-authority trust OFFLINE (`scripts/polaris-verify.py` verify_manifest + verify_cross_authority): a manifest must be self-consistent (signed by one of its own declared active anchors), authentic (two-witness), fresh (window-bounded), and trusted; a FOREIGN credential is accepted iff a trusted authority attests to its signing key IN THE PRESENTED CONTEXT (non-transitive). `scripts/polaris-federation-manifest-drill.py` runs the two-authority accept/reject matrix under real ML-DSA every release (pqc-real); spec in [inter-authority-protocol.md](docs/design/inter-authority-protocol.md); `check_inter_authority_protocol`; `FederationManifestTests`. Unblocks P3.10 (two instances in CI). |
| [x] P3.2b | Epoch alignment + revocation propagation (v9.298) | L | high | P3.2 | SHIPPED. The two references the manifest carried are now consumable, as two more signed objects an authority publishes and the standalone verifier consumes OFFLINE, both views over the append-only `TokenStateEpoch` and `RevocationList` (no new mutation path). **Epoch checkpoint** (`polaris-epoch-checkpoint/1` at `GET /api/v1/epoch-checkpoint/<id>`): the authority's commitment to the latest point on its epoch chain (number + Merkle root + the prior epoch it extends). Two checkpoints prove MONOTONICITY and catch a FORK (two roots signed at one epoch number is equivocation); `verify_epoch_checkpoint` + `check_epoch_chain` + `epoch_aligned` (cross-checks a checkpoint against the epoch the authority's own manifest commits to). **Revocation feed** (`polaris-revocation-feed/1` at `GET /api/v1/revocation-feed/<id>`): the sorted revoked-credential leaves (`SHA3-256(token_value)`) it issued + a commitment. A relying party checks a FOREIGN credential's non-revocation OFFLINE with no issuer contact: `verify_cross_authority` folds in the feed FAIL-CLOSED (genuine + fresh + bound to the issuer key, else reject); `verify_revocation_feed` + `is_revoked`; `check_revocation_progression` catches a ROLLBACK (a newer feed that drops a published revocation), monotone because RevocationList is append-only. A CRL of revoked leaves, NOT the active population (a leaf is derivable only by a holder; no `token_value` published). `scripts/polaris-epoch-revocation-drill.py` runs the two-authority fork/rollback/cross-revocation matrix under real ML-DSA every release (pqc-real); `check_epoch_revocation_propagation`; `EpochRevocationTests`. Deferred to P3.2c (the aggregate mirrored status feed, the P2.6 backbone at federation scale) and P3.2d (epoch-bound ZK presentation across authorities). |
| [x] P3.2c | Aggregate mirrored status feed (v9.308) | L | high | P3.2b | SHIPPED (v1: the mirror + the untrusted-aggregator proof; epoch-bound cross-authority ZK deferred to P3.2d). At federation scale a relying party checking foreign credentials from many authorities would fetch one revocation feed + epoch checkpoint per authority. P3.2c aggregates them into ONE short-lived, CDN-distributable, signed STATUS BUNDLE (`polaris-federation-status-bundle/1` at `GET /api/v1/federation-status-bundle/<id>`) that MIRRORS each member authority's own signed feed and checkpoint VERBATIM. The publisher is UNTRUSTED for correctness: trust roots in each member's ML-DSA signature, never the aggregator's; the publisher's own signature is only a freshness + set-integrity envelope (the member set committed by `members_root_hex`, so it cannot be tampered after signing). The detached verifier decides a foreign credential OFFLINE (`scripts/polaris-verify.py` `verify_status_bundle` + `verify_cross_authority_via_bundle`): the envelope must be authentic + fresh, the issuer must be PRESENT (an omitted authority is FAIL-CLOSED, not verifiable), and the trust + revocation decision DELEGATES to the P3.2b `verify_cross_authority` against the member's OWN feed, so a forged/tampered/stale member feed rejects there. The headline property, proven in the drill: an aggregator in FULL control of the bundle (recomputing the commitment and re-signing the envelope) STILL cannot forge a member's status, because it cannot re-sign as the member. A view over the append-only feeds (no new mutation path); the app builder and the verifier are byte-identical (pinned by the canonical-equivalence oracle, the sixth signed type). `scripts/polaris-federation-status-bundle-drill.py` runs the two-authority accept/reject/forge-resistance matrix under real ML-DSA every release (pqc-real); spec in [federation-status-bundle.md](docs/design/federation-status-bundle.md); `check_federation_status_bundle`; `StatusBundleTests`. |
| [x] P3.2d | Offline cross-authority epoch-bound ZK (v9.312) | L | high | P3.2c | SHIPPED, ZERO circuit changes. A holder proves in ZERO KNOWLEDGE that its credential is included in an issuing authority's epoch tree, and a relying party that trusts that authority through the graph accepts it OFFLINE, learning nothing about which credential. Composes two things that already existed: the Plonky2 circuit already binds the proof to the epoch's Merkle ROOT (a public input), which is exactly `TokenStateEpoch.merkle_root`, and that root already travels the federation SIGNED in the epoch checkpoint. `scripts/polaris-verify.py` `verify_cross_authority_zk`: (1) TRUST -- `verify_epoch_checkpoint` + a trusted in-context attestation (the hardened `verify_cross_authority` path) yield the trusted epoch root; (2) BIND -- the proof's public inputs must match that root, epoch number and context (and a challenge nonce); (3) PROOF -- the Plonky2 FRI proof is checked by shelling to the `polaris-zk` binary as a LOCAL subprocess (no network, still offline). If the binary is absent the decision ABSTAINS (trust and binding established, proof unverifiable here), NEVER a false accept. The verdict carries NO credential. The verifier stays import-standalone (a subprocess is not an import). `--zk-proof` CLI. `scripts/polaris-cross-authority-zk-drill.py` verifies a committed real-proof fixture (`polaris_zk/fixtures/cross-authority-zk.json`, like the ML-DSA `vectors/`) every release in the test job (which has the binary and the cryptography ML-DSA witness): accept the genuine foreign proof, reject wrong-root / forged-checkpoint / untrusted-issuer / wrong-context / tampered-proof, abstain with no binary. Spec in [cross-authority-zk.md](docs/design/cross-authority-zk.md); `check_cross_authority_zk`. Deferred: single-use offline replay (the stateless verifier keeps no state; a relying party issues a challenge nonce or verifies online) and binding issuer identity INSIDE the circuit (needs a circuit change). |
| [x] P3.3 | Transparency service (v9.301) | L | med | P3.2 | SHIPPED (v1: the append-only log, the monitor, and the tampering drill; cross-monitor gossip + external-ledger publication are P3.3b). The append-only `AnchorBatch` root sequence is exposed as a PUBLIC, independently verifiable transparency log in the style of RFC 6962 (SHA3-256): `GET /api/v1/transparency/sth` publishes a signed tree head (`polaris-transparency-sth/1`), `/consistency/<m>/<n>` an append-only consistency proof, `/proof/<index>` an inclusion proof, `/entries` the entries for replication. A signed view over the append-only table; no new mutable state. The detached verifier (`scripts/polaris-verify.py` merkle_tree_head / verify_consistency / verify_inclusion / verify_sth / verify_log_consistency) proves an append-only extension and rejects a rewrite, FORK (two roots at one size), shrink, or wrong-key head, standalone. `scripts/polaris-transparency-monitor.py` is the independent monitor daemon anyone runs: it caches the last head and ALERTS (non-zero) on any tampering. `scripts/polaris-transparency-drill.py` proves it end to end under real ML-DSA every release (pqc-real): the detection matrix, AND the actual monitor run over HTTP against a live log that is then tampered. Spec in [transparency-log.md](docs/design/transparency-log.md); `check_transparency_log`; the STH is also in the canonical-equivalence oracle. |
| [x] P3.3b | Transparency witnesses + split-view defence (v9.302) | M | med | P3.3 | SHIPPED. A lone monitor catches a log that rewrites its own history; it cannot catch a SPLIT VIEW (different heads shown to different observers). This adds the witness layer. The detached verifier gains witness COSIGNATURES (`polaris-transparency-cosignature/1`; `verify_cosignature`), a WITNESSED-CHECKPOINT threshold (`verify_witnessed_checkpoint`: a head must carry >=K distinct trusted-witness cosignatures, so a split view needs K witnesses to equivocate, not just the log), and a non-repudiable EQUIVOCATION PROOF (`verify_equivocation`: two log-signed heads at one size with different roots). `scripts/polaris-transparency-witness.py` is the independent witness daemon anyone runs: it cosigns consistent heads, refuses a fork, gossips the head it saw into a shared pool, and ALERTS with a written equivocation proof on a rewrite or a gossip-detected split view. `scripts/polaris-transparency-gossip-drill.py` proves it under real ML-DSA every release (pqc-real): threshold cosigning accepts, and a split view is caught both by a witness refusing a fork and by two witnesses gossiping. `check_transparency_gossip`; the split-view section of [transparency-log.md](docs/design/transparency-log.md). External-ledger publication is P3.3c. |
| [x] P3.3c | Transparency external-ledger publication (v9.303) | M | med | P3.3 | SHIPPED. Witnesses attest heads they saw; an external LEDGER is the complete, ordered, public record. A log publishes each head into an independent APPEND-ONLY ledger and gets a RECEIPT (`polaris-transparency-publication/1`): the ledger's own signed tree head + an inclusion proof that the head's entry is a leaf in it. The detached verifier (`scripts/polaris-verify.py` `verify_publication`, standalone) confirms it -- so the log cannot use a head it has not publicly committed, and the ledger (append-only, monitored the same way) cannot later drop it; the full set of published heads is publicly enumerable. A ledger IS an append-only log, so this reuses the P3.3 Merkle machinery. `scripts/polaris-transparency-ledger.py` is the append-only ledger with a BACKEND DRIVER abstraction (`POLARIS_LEDGER_BACKEND`: `file` implemented + CI-tested; `algorand-pq`/`hyperledger-indy` declared, waiting on their APIs -- the same honest shape as key custody and the audit anchor's external chain). `scripts/polaris-transparency-publication-drill.py` proves it under real ML-DSA every release (pqc-real): the ledger records heads and the verifier confirms; a forged/wrong-key/unrecorded-head receipt is rejected; and the ledger dropping a recorded head is caught. `check_transparency_publication`; the external-publication section of [transparency-log.md](docs/design/transparency-log.md). |
| [x] P3.4 | Relying-party API v1 (v9.288) | M | med | P2.6 | SHIPPED. `RelyingParty` (scope CHECK-constrained to `'verify'` at the schema, scrypt `client_secret_hash`) + `POST /api/v1/oauth/token` (OAuth2 client-credentials, RFC 6749 §4.4, stateless bearer salted distinctly from the session, constant-time so it is not a client-id oracle) + `POST /api/v1/verify` (a relying party presents the held credential and gets an authentic/authoritative verdict with NO personal data). API-access auth ONLY: the schema CHECK makes "identity never becomes a login product" a database constraint. No enumeration / no existence oracle: a constant-time possession proof against the stored signature, a uniform "not a verifiable presentation" verdict on not-found/mismatch, and the sequential `token_id` is never accepted; no who-verified-whom record is kept. The verify-only bound and the no-PII verdict RUN as fail-closed adversaries every release (`attack_controls.py`, AC-6). Registration via `polaris rp-register`; `scripts/polaris-relying-party.py` gains an `--oauth` mode and authenticates as an org end to end. `check_relying_party_api`; `RelyingPartyApiTests`. **mTLS (the other option) is deferred to a P3.4b at the Caddy edge; OAuth2 client-credentials is the CI-testable first cut.** |
| [x] P3.5 | RP SDKs and conformance suite | L | med | P3.4 | Python reference SDK + the public conformance suite SHIPPED (v9.289, P3.5a). `conformance/` is the language-agnostic contract: `run_conformance.py` drives ANY verifier (stdin->stdout: `{pack, anchors}` -> `{authentic, issuer_trusted}`) over the published authenticity cases (`cases.json`, built on `vectors/`), covering authentic / tampered / placeholder / genuine-but-untrusted-issuer; `SPEC.md` is the published contract; passing it is what "conformant" means. `sdk/python/` (`polaris-verify`) is the standalone reference SDK: offline ML-DSA-65 authenticity (cryptography + liboqs) plus the OAuth2 `/api/v1` online check, proven live. Runs `--self` in the pqc-real CI job; `check_conformance_suite`; `test_sdk.py`. **P3.5b SHIPPED (v9.290): the TypeScript SDK (`sdk/typescript/`, `@polaris/verify`) is the second implementation — real ML-DSA-65 via `@noble/post-quantum` (a third impl agreeing with liboqs and OpenSSL), the OAuth2 `/api/v1` online check, standalone, type-checked (tsc), unit-tested. It passes the SAME language-agnostic conformance runner in the repo's first Node CI job (`sdk-typescript`); `check_typescript_sdk`. P3.5 is complete across both languages.** |
| [x] P3.6 | Offline verification protocol v1 (v9.291) | L | high | P2.6 | SHIPPED. Authorization is verifiable with NO connectivity via a short-lived issuer-signed STATUS ASSERTION. `POST /api/v1/status-assertion` (possession-authenticated, no bearer, no PII) mints the assertion -- the issuing agency's ML-DSA-65 signature over `SHA3-256(canonical {format,token_value,status,issued_at,expires_at})`, reflecting current status. The reference verifier `scripts/polaris-verify.py --pack --status-assertion` decides the whole flow OFFLINE: accept iff the credential is authentic AND the assertion is authentic, bound, ACTIVE, and fresh (now in [issued_at,expires_at) AND window <= a verifier-set ceiling `--max-window`). Freshness + replay bounds specified in [docs/design/offline-verification.md](docs/design/offline-verification.md); `scripts/polaris-offline-status-drill.py` runs the accept/reject matrix under real ML-DSA every release (pqc-real). `check_offline_verification`; `OfflineStatusAssertionTests`. Because verification touches no issuer, the issuer never learns it happened -- offline is MORE private than online. **P3.6b (deferred): an aggregate signed status bundle, wallet stapling + SDK offline-status methods, epoch binding.** |
| [ ] P3.7 | mDL / ISO 18013-5 bridge | L | med | P3.4 | Read-only derived mdoc presentment from a Polaris token for mDL-reader interop; no new trust semantics |
| [ ] P3.8 | W3C VC issuance endpoint | M | low | P3.4 | An optional VC representation of a verification result; explicitly a format, not a trust model |
| [ ] P3.9 | Per-authority isolation review | L | med | P3.1 | Operator RBAC and data isolation reviewed for the federated topology; row-level security added where the review demands it |
| [x] P3.10 | Federation proven in CI (v9.299) | M | med | P3.2 | SHIPPED. The `federation-two-instances` CI job (the first with BOTH a database and real liboqs) boots two independent instances as two authorities, each its own database and its own real ML-DSA-65 root, talking only over HTTP. `scripts/polaris-federation-instances-drill.py` launches an instance (gunicorn) against each of two loaded databases and drives the cross-authority matrix over the wire: cross-verification (B publishes a manifest attesting to A's key in a context; a relying party that trusts B accepts A's credential in that context, from B's manifest fetched over HTTP), attestation revocation (B revokes the attestation; the re-fetched manifest no longer accepts A), and anchor cross-checks (A's signed epoch checkpoint and revocation feed are fetched over HTTP and verified; A's feed rejects a revoked credential), with the adversarial cases (wrong context, forged credential) rejecting throughout. Red on any wrong decision. `check_federation_two_instances`. Completes the P3 exit gate's first clause (two instances interoperate in CI); the second clause (an external team integrating docs-only) is `[EXT]`. |

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

## P8 - The exchange fabric, the Polaris way [SOFTWARE ARC, BUILDABLE NOW]

Objective: the "digital society" layer around the identity core, which is the
exchange-fabric piece Polaris lacks. This is not more identity crypto; it is a general
authenticated, signed, evidenced exchange between ARBITRARY institutions, built as the
anti-surveillance INVERSION of an evidentiary message log: an exchange is provable to a third party WITHOUT
retaining the underlying personal data (a signed cryptographic receipt plus a
transparency commitment, not a logged message body). Every primitive already exists (the
detached verifier, the transparency log with witnesses, status bundles, ML-DSA signing,
ZK inclusion); P8 composes them into the fabric. It is buildable now, extends P3, and is
not gated on the P4-P7 deployment or institutional phases.

Order by leverage and dependency (the build plan, fixed at v9.319). P8.1 (the normative
spec + conformance) came first and is done: it is what makes everything already built a
substrate that independent implementations can target, and it is exactly the P3 exit gate
("an external team integrates docs-only"). Then, in order: P8.2b/c (the receipt gains
service-to-service auth and a transparency anchor) -> P8.7a (a timestamp authority, which
signing needs and which gives every receipt independent time evidence) -> P8.3 (the signed
registry the gateway routes through) -> P8.2d (the mediating gateway, the flagship) -> P8.5
(document signing, on timestamps) -> P8.4 (the auth broker's protocol core) -> P8.6 (the
wallet PROTOCOL surface) -> P8.7b (trust-service lifecycle: trust list, compromise recovery,
algorithm migration) -> P8.8 (versioning and cross-version compatibility); complete at v9.330, with v9.331 the
sweep that certified the exchange receipt and mint in both SDKs and the conformance suite and
brought the reference documents up to the protocol layer. Two scope
decisions are deliberate: the wallet ships as a protocol the detached verifier checks, not
as native mobile or desktop clients (a product mountain, not a reference-implementation
concern), and a unified operator control-plane console is wrap that stays behind the
engine. Every new signed artifact enters through the same machinery: the
canonical-equivalence oracle, the wire spec, conformance vectors in both SDKs, the
metamorphic fuzzer, a real-ML-DSA drill, and a check with a detection test.

| ID | Item | Size | Risk | Blocked by | Definition of done |
|---|---|---|---|---|---|
| [x] P8.1 | Normative wire specification + conformance for independent implementations | L | med | P3 | DONE (v9.313 spec, v9.314-v9.316 conformance). An implementation importing NO Polaris code is now certified against the FULL protocol -- all seven signed artifacts AND the federation trust decision -- in both Python and TypeScript. The normative SPEC shipped (v9.313): `docs/reference/WIRE-SPEC.md` (RFC-2119) specifies the signature envelope + the canonical-signing discipline, all seven app-signed artifacts (each with its exact signed-field list + canonical construction + verification MUSTs), the authenticity pack's special construction, the federation trust decision (non-transitive, in-context), the three transparency-infra artifacts, and the `format /N` versioning + algorithm-agility rule. `check_wire_spec_matches_code` (#170) fails CI when a documented format string or signed-field list diverges from the signer -- and closes the canonical-pinning gap the oracle left for the bundle, the pack, and the transparency-infra types (also un-vacuum-ing `_signed_statement_keys`, whose multi-line regex silently returned nothing so the oracle's static key-list pin was a no-op). P8.1b IN PROGRESS (v9.314 status assertion; v9.315 the rest): the conformance harness is typed (a case names its `artifact`; the runner checks every constrained key), and the AUTHENTICITY of ALL SEVEN app-signed artifacts is now certified end to end in BOTH SDKs -- the pack, the status assertion, and (through one generic `verify_signed_artifact` / `verifySignedArtifact`) the epoch checkpoint, revocation feed, federation manifest, status bundle, and transparency STH, each with signature + freshness + commitment/self-consistency. Twelve published vectors under `conformance/vectors/`; both SDKs pass all twenty cases, incl. an independent TS verifier accepting Python-signed NESTED-object artifacts (the recursive canonical JSON matches byte-for-byte). v9.316 added the composite federation TRUST DECISION (`artifact: cross-authority`): pack + trusted manifests + trusted anchors + context (+ optional revocation feed) -> accept/reject, via `verify_cross_authority` / `verifyCrossAuthority` in both SDKs; four cases (accept / untrusted issuer / wrong context / revoked) and both SDKs pass all TWENTY-FOUR cases. `check_conformance_suite` + `check_typescript_sdk` require every artifact type + the trust decision. P8.1 COMPLETE: the docs-only integration path the P3 exit gate's second clause needs now exists (spec + full conformance in two languages); an ACTUAL external-team integration remains `[EXT]`. Next in P8: P8.2 (the evidence-without-retention gateway). |
| [x] P8.2 | Polaris Gateway: an evidence-without-retention service-to-service fabric | XL | high | P8.1 | DONE (the receipt v9.317, service-to-service minting v9.320, the transparency anchor v9.322, the mediating gateway v9.324, directional trust v9.333). The EVIDENCE PRIMITIVE shipped (v9.317): the exchange receipt (`polaris-exchange-receipt/1` at `POST /api/v1/exchange-receipt/<id>`) -- a responder signs a commitment to the SHA3-256 of the request and response (never the bodies), the parties, the context, and which attestation authorized the requester. The mint endpoint accepts ONLY hashes (the retention rule at the door). `scripts/polaris-verify.py` `verify_exchange_receipt` proves offline, from the receipt alone, that the exchange occurred and the requester was authorized (a trusted manifest attests its key in-context), WITHOUT the payload; a party holding a body confirms the commitment binds. In the wire spec, the canonical-equivalence oracle, and a real-ML-DSA drill (`scripts/polaris-exchange-receipt-drill.py`); `check_exchange_receipt`. This is the anti-surveillance inversion of an evidentiary message log. P8.2b DONE (v9.320): service-to-service minting at `/signed` -- the responder's own service authenticates by signing the mint statement under its registered ML-DSA-65 key (no session, no shared secret, no nonce store; the signed time is carried into the receipt and freshness-bounded, so a replay can only duplicate), proven over HTTP by the two-instance drill and fail-closed without real PQC. P8.2c DONE (v9.322): the receipt SET is a transparency log -- every minted receipt's SHA3-256 (never the receipt) joins the strictly append-only `ExchangeReceiptLog`, published as a second RFC-6962 log with per-receipt inclusion evidence, proven offline by `verify_receipt_inclusion`, watched by the monitor/witness (`--log receipts`), driven over HTTP by the two-instance drill. P8.2d DONE (v9.324): the gateway itself -- `POST /api/v1/exchange/<id>` takes a requester-signed `polaris-exchange-request/1` envelope + body, authenticates the requester by a KNOWN key, authorizes it through the in-context trust graph BEFORE forwarding, consumes the nonce in the append-only `ExchangeNonce` replay register, forwards only to an operator-configured upstream, and returns the response with a receipt carrying the envelope's signed time; (envelope, receipt) is the offline-verifiable evidence chain and no body is ever persisted or logged; proven across two independent instances with an echo upstream (replay 409, stranger 401, unbound body 400, tampered 401, unknown kind 404, stale 401). P8.2 COMPLETE. Definition of done: arbitrary institutions exchange authenticated signed requests mediated by Polaris trust, each yielding a receipt an independent party verifies offline, WITHOUT retaining the payload. |
| [x] P8.3 | Service-and-authority registry | L | med | P8.1 | DONE (v9.323): `GET /api/v1/registry/<id>` publishes `polaris-registry/1` -- protocol formats (pinned to the wire spec by `check_registry`) and algorithms, services with path templates and auth, transparency logs, federated authorities with keys, contexts and required proof, the in-context trust graph, relying parties (name + scope only) -- every fact a view over Athena, signed by a publisher that must list itself (a stranger cannot publish in an authority's name), verified offline (`verify_registry`) and read for DISCOVERY (`registry_service`/`registry_authority`/`registry_trusts`). In the oracle, the spec (3.10), both SDKs' conformance (incl. the impostor case), the fuzzer, a real-ML-DSA drill; the two-instance drill calls a service at a path it read out of B's fetched registry and watches the trust graph drop a revoked attestation |
| [x] P8.4 | Auth/SSO broker across credential types | L | med | P3.4 | DONE (v9.326), the protocol core: authorization code + PKCE (`POST /api/v1/auth/authorize` by possession, `POST /api/v1/auth/token` by client credentials) yielding an issuing-agency-signed `polaris-id-token/1` whose subject is the credential hash (cross-RP correlatable by design), carrying context, disclosure level, `acr` (possession, or possession + a verified ZK proof for step-up), enrollment status and instants -- no claim beyond the vocabulary; the relying-party scope bound widened at the schema to exactly `verify | authenticate | verify authenticate`; the authority writes nothing but consumed code hashes (no record of who logged in where); duress served identically; the wallet's `login` command; verified offline in the detached verifier and both SDKs; the flow proven over HTTP across two instances. The session/SSO product surface remains wrap |
| [x] P8.5 | Polaris Sign: general document signing | L | med | P8.1 | DONE (v9.325): `polaris-signed-document/1` -- a digest-bound, portable container signed by the institution (`POST /api/v1/sign/<id>`) or, on behalf of a holder who proved possession of an ACTIVE credential and is recorded by credential HASH, by its issuing authority (`/sign/<id>/holder`; the wallet's `sign` command hashes the file locally). Long-term validation: a timestamp over the statement AND signature plus the signer's manifest, checkpoint and feed at the instant, attached at signing, so `verify_signed_document` decides validity at that instant and the signature survives key retirement (drilled: re-signed, retired-at-instant, revoked, tampered all fail). Oracle, spec 3.12, both SDKs' conformance, fuzzer, real-ML-DSA drill, two-instance HTTP proof incl. the wallet |
| [x] P8.6 | Wallet protocol surface (clients follow it) | L | med | P8.1, PE.7, P8.5 | DONE (v9.327): `polaris-presentation/1` (credential + stapled status assertion so authorization is decidable OFFLINE, optional ZK proof, context/disclosure, an opaque code the verifier never interprets) decided by `verify_presentation`; `polaris-qr/1` compressed, digest-tied, any-order framing for QR/NFC, refused when mixed/missing/altered; the wallet's `present --qr --status-assertion --zk-proof` plus its `sign` (P8.5) and `login` (P8.4); the verifier's `--presentation`/`--qr-frames`; drilled through the wallet under real ML-DSA. The WebAuthn browser bridge waits on a holder-key binding the issuer-centric model does not have (recorded, not claimed); native clients remain out of scope |
| [x] P8.7 | Trust-service lifecycle as one subsystem | L | med | P3.2b | (b) DONE (v9.328): the append-only, one-way `AuthorityKeyEvent` register (registered / retired / compromised from an instant) derived into `AuthorityKeyCurrent`; manifests and the registry report REAL key statuses; `polaris-trust-list/1` at `GET /api/v1/trust-list/<id>` signed by a key it lists active for its publisher; `key_status_at` decides a key's status at an instant, so the cross-authority decision rejects a compromised issuer key and long-term validation checks the signer key independently of the signer; CLI `key-register`/`key-retire`/`key-compromise`; compromise recovery drilled under real ML-DSA and across two instances (B records A's key compromised; the decision flips with no change to A). Algorithm-migration compatibility moves to P8.8. (a) DONE (v9.321): the timestamp authority -- `POST /api/v1/timestamp/<id>` binds any SHA3-256 digest to an instant under the agency's registered key (`polaris-timestamp/1`), digest-only and unlogged so it learns and retains nothing, verified offline by `verify_timestamp` + `timestamp_binds`, in the oracle, the wire spec, both SDKs' conformance, the fuzzer, and a real-ML-DSA drill (which also timestamps a receipt at a second authority: independent time evidence); (b) a signed, versioned trust list of authority roots with status (active / retired / compromised), the root's status governing every downstream decision; a compromise-recovery drill under real ML-DSA (a root is declared compromised -> the trust list, revocation feed and epoch checkpoint update -> verifiers reject artifacts under the old root after the compromise time and accept re-issued ones -> monitors and witnesses see it); algorithm-migration compatibility proven by vectors signed under two algorithms verifying in both SDKs |
| [x] P8.5b | Timestamp transparency: anchor each timestamp's digest in an append-only log | M | low | P8.5, P8.2c | DONE (v9.341), as the maintainer decided: anchoring is the CALLER's choice (`anchor: true`), so the default request still retains nothing; an anchored timestamp's SHA3-256 joins `TimestampLog` (migration 007, append-only, published as `polaris-timestamp-log` with signed heads, watched by the same monitor and witnesses) and the inclusion evidence comes back stapled; `verify_timestamp_anchor` decides it offline, witnessed when the relying party names witnesses; long-term validation takes `require_anchored`, a `timestamp_quorum` of independent authorities (the no-retention alternative) and the authority's key status per the trust list; drilled under a stolen key (a backdated forgery has no witnessed inclusion, a forged head is a caught split view) and across two instances. Follow-up P8.5c: anchor verification in both SDKs (today the detached verifier only). |
| [x] P8.8 | Protocol versioning, negotiation and cross-version compatibility | M | low | P8.3 | (a) DONE (v9.329): algorithm agility and migration. ML-DSA-65 and ML-DSA-87 are accepted by the signer (the key file names its parameter set), the detached verifier, both SDKs and the app's two witnesses; ML-DSA-44 is refused as below the floor; no signed body hardcodes its algorithm (the custodied key decides it before signing, since `algorithm` is a signed field); the registry advertises the accepted set and its own; migration is a key-lifecycle event (`key-register --algorithm`); six two-algorithm conformance vectors (both SDKs pass all 44 cases), the fuzzer under both sets in CI, and the two-instance drill federating a mixed pair (A under ML-DSA-87, B under ML-DSA-65). (b) DONE (v9.330): majors in the format string, minors advertised by the registry as `instance.protocol.versions` (the registry itself at 1.3) and never needed to verify; the normative negotiation rule (reject an unknown major, accept any minor, never emit or send an unadvertised version; `400 unsupported_format_version` with the supported list at the interactive routes through one `_format_check`, `registry_speaks` on the consumer side, drilled over HTTP across two instances); version 1 FROZEN under `conformance/frozen/v1` (44 cases, 43 files pinned by SHA256SUMS recomputed by check #184, the v9.317 detached verifier vendored) and `scripts/polaris-compat-suite.py` proving both directions on every CI run (current detached verifier and both SDKs: 44/44 frozen cases; the pinned v9.317 verifier: 26 agreed, 16 predated, 2 declined fail-closed, 0 violations); every case carries `since`. Original scope: Capability and version advertisement in the registry; a normative negotiation rule (reject an unknown major, accept a higher minor, never emit an unadvertised version); a compatibility suite run in CI that verifies the frozen v1 vectors under the current SDKs and current vectors under a pinned older verifier, old and new in both directions |

Exit gate: a non-Polaris implementation interoperates from P8.1 alone; an institutional
exchange over P8.2 is provable to a third party with the payload never retained. This
phase is where Polaris's architecture reaches the same broad class as a mature national
digital-identity and exchange ecosystem while keeping a stronger privacy and post-quantum
posture; it deliberately does not reproduce an exchange fabric's message-body logging,
which the vocation forbids.

---

## P9 - The holder: the key, the proof and the grant [COMPLETE at v9.354]

Objective: close the gaps Version 2 of the paper found in the tree. Polaris is
issuer-centric: a holder holds a credential, not a key pair, and that single absence is
the common cause under four separate limitations (document signing is notarial, login is
by possession, no agent can be delegated to, and a presentation carries a value stable
across the verifiers it is shown to). This phase supplies the missing primitive and the
capabilities it unblocks, plus three smaller closures the paper named. Nothing here is
gated on an external actor, and every row retires a sentence from the paper's limitations
section or from [docs/PRODUCTION-READINESS.md](docs/PRODUCTION-READINESS.md).

**Constitutional note (rule 1).** A key the holder controls is also a key the holder can
be compelled to use. P9.1 is not done until the duress path is re-drilled under
holder-key presentation and a coerced presentation remains byte-indistinguishable from a
consenting one. A holder key that weakens the duress path is a regression against the
vocation and is refused on that ground, not deferred.

Order by dependency: P9.1 -> P9.2 -> P9.3 -> P9.4 -> P9.8, with P9.5, P9.6 and P9.7
independent and shippable in any gap. P9.6 was carried as a follow-up sentence inside
P8.5b and becomes a row here so the execution protocol can select it.

| ID | Item | Size | Risk | Blocked by | Definition of done |
|---|---|---|---|---|---|
| [x] P9.1 | Holder-side key binding (v9.349) | L | high | - | DONE (v9.349): An optional holder public key binds to a credential at issuance or by a possession-proved rotation, recorded in an append-only register under the same lifecycle discipline as `AuthorityKeyEvent`; a presentation carries a holder signature over the context, the verifier's nonce and the instant; `verify_presentation` and both SDKs check it; the wire spec gains the signed-field list and the conformance suite its vectors; the duress drill re-runs under holder-key presentation and the coerced and consenting shapes stay identical; `check_holder_key_binding` with a detection test |
| [x] P9.2 | Holder-side proving (v9.350) | L | high | P9.1 | DONE (v9.350): The membership prover runs on the holder's device from a Merkle path served out of the published epoch tree; the authority learns only that a path was fetched, the fetch is bounded (C8) and not keyed by holder; the wallet proves locally and the two-witness differential still decides the verdict; retires "the prover runs on the Polaris host" from the soundness ledger; `check_holder_side_prover` |
| [x] P9.3 | Scoped nullifier (v9.352) | L | high | P9.2 | DONE (v9.352): The epoch leaf moved from an opaque `SHA3-256` seed to `Poseidon(secret || context_id)`, a commitment the circuit OPENS, which is what lets a nullifier be constrained to the same secret as the leaf; the SHA3-256 derivation became the holder secret. The circuit gains `scope` and a `nullifier` public input, `Poseidon(secret || scope || epoch_id)`, and `verify` binds both. One person proving twice in one relying party's scope and epoch presents the same nullifier and is refused; the same person at a second relying party presents a value the two cannot correlate; a member cannot prove against another member's leaf and a proof cannot be relabelled into another scope. The independent Python second witness re-derives both commitments (`witness2/commitment.py`) rather than taking the bundle's word, and the cross-language differential pins them bit for bit. Both SDKs carry the comparison rule; Plonky2 proof verification stays crate-only and abstains elsewhere, as before. NOT backward compatible: epochs closed before v9.352 are re-closed, not migrated. `check_scoped_nullifier` with a nine-fixture detection test and `scripts/polaris-scoped-nullifier-drill.py` proving it end to end under the real circuit. Bounds stated in `docs/design/zk-snark.md`: the nullifier does not hide the holder from the ISSUER, which derives every secret to build the tree, and it resets each epoch so membership never becomes a permanent identifier |
| [x] P9.4 | Pairwise presentation (v9.353) | L | high | P9.3 | DONE (v9.353): The login token's subject was `SHA3-256(token_value)`, the same value at every relying party, so two of them comparing user tables matched people exactly and forever without either doing anything wrong. It is now `SHA3-256("polaris-pairwise/1" || token_value || client_id)`: stable at one relying party so an account works, unrecognisable at the next. The same derivation gives the presentation layer its handle, from the holder key; the wallet emits it under `--verifier-scope` and the verifier RECOMPUTES it from the binding rather than trusting the holder. A handle with no scope is refused, not globalised, because that would be a global identifier wearing the word pairwise. The issuer's own records are unchanged. The bound is stated rather than glossed: `verify_presentation` reports `correlation` as `exposed` for a plain credential, which still shows a stable token value, issuer signature and holder key, and `bounded` only for the zero-knowledge form, whose handle is P9.3's scoped nullifier. The README, the paper's privacy section and the status ledger now say bounded rather than permanent, and the paper is rebuilt and restamped. Both SDKs derive the handle identically, pinned by a cross-language anchor. BREAKING for relying parties: every existing account subject changes once. `check_pairwise_presentation` with a ten-fixture detection test and `scripts/polaris-pairwise-drill.py`, which asserts the bound as well as the benefit |
| [x] P9.5 | Attestations signed by the attesting agency (v9.348) | M | med | - | DONE (v9.348): An `AgencyTrustAttestation` carries a signature by the attesting agency over the attested key, the context and the window, so cross-authority trust rests on a signature rather than on an operator's word; the federation manifest publishes it; the detached verifier and both SDKs require it; existing rows stay verifiable as legacy for one major; `check_attestation_signed`. Closes the last joint in federation held up by procedure |
| [x] P9.6 | Anchor verification in both SDKs (was P8.5c) (v9.346) | S | low | - | DONE (v9.346): `verify_timestamp_anchor` and its witnessed and quorum forms exist in the Python and TypeScript SDKs with conformance vectors, so long-term validation is decidable by an implementation that imports no Polaris code; `check_conformance_suite` requires the artifact |
| [x] P9.7 | `RecoveryRequest` enforced at the schema (v9.347) | M | med | - | DONE (v9.347): The one audit-of-record instance resting on procedure discipline gains what the other twelve have: the decision fields move one way, a raw update from a database session is refused, and the readiness ledger's "not fully enforced" sentence is retired; `check_aor_append_only_triggers` covers thirteen of thirteen |
| [x] P9.8 | Delegated agent grant (v9.354) | L | high | P9.1 (v9.349), P9.4 (v9.353) | DONE (v9.354): The thing this replaces is what people actually do, which is hand the agent the credential: everything the person can do, forever, revocable only by revoking the person. A `polaris-agent-grant/1` is the opposite of each. Signed by the HOLDER key, it names its actions, states its limits, expires on its own and carries `grant_id` as a revocation handle scoped to itself. `actions` and `limits` are INSIDE the signed statement, so a grant widened in transit fails rather than passing invisibly, and an empty `actions` grants nothing rather than everything. A `polaris-grant-revocation/1` is signed by the same holder key: anyone may publish bytes, only the holder may end the grant, the ISSUER is never contacted and the human's credential is untouched. A `polaris-agent-proof/1` is signed by the AGENT key over the action and the service's own nonce, so a grant is not a bearer token and a captured proof replays neither to a second service nor to a second action. A revocation carries NO reason field, because a place to record why a grant ended is a place a coercer can demand be filled in or left empty. Unknown limit keys are refused rather than ignored. The bound is stated: under a plain holder binding the service still sees the credential's token value, so the verdict reports `correlation: exposed`, exactly as a presentation does. Wire spec, canonical oracle, both SDKs, six conformance vectors passing in all three implementations (71 cases), three artifacts added to the metamorphic fuzzer (2072 cases), `check_agent_grant` with a twelve-fixture detection test, and `scripts/polaris-agent-grant-drill.py` proving twenty-four cases under real ML-DSA-65 |

Exit gate: a holder proves membership on their own device, once per scope, without
becoming linkable across scopes; an agent acts inside a signed, expiring, separately
revocable grant; federation trust rests on signatures end to end; and every claim above is
pinned by an invariant check with a detection test. Seven sentences leave the paper's
limitations section.

---

## Waiting on the world [NEVER SELECT FROM THIS LIST]

These rows are blocked on an actor Polaris does not control. Standing rule 6 applies to
each: the buildable readiness artifact is listed in the row and is built before the actor
is engaged, so no external gate is ever waiting on us. The execution protocol must not
select from here.

| Row | Waiting on |
|---|---|
| P0.11 | OpenSSL 3.5 reaching the pgbouncer and postgres images |
| P1.12 | A penetration-testing firm |
| P4.6 | Secure-element vendors and silicon availability |
| P5.2, P5.3 | An institution willing to run a pilot with consenting users |
| P6.1 | A FIPS-validated lattice implementation |
| P6.3 | A sponsoring agency and an authorizing official |
| P6.4 | An audit firm |
| P6.6 | An auditor, a red team and a bounty budget |
| P7.1 | Statute, funding and a program office |
| P7.4 | A staffed operations organisation |

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

1. Read [CLAUDE.md](CLAUDE.md), then this file. **The active phase is named in the
   decision record at the top of this file. It is P2.** Phases E, P8 and P9 are COMPLETE;
   the numbered deployment phases resumed after P9, and P0 and P1 hold only `ext` rows,
   which rule 2 forbids selecting. Do not derive the active phase from the lowest number:
   that rule selected a row blocked on a vendor's container image.
2. Pick the first row in the active phase whose Blocked-by column is satisfied and whose
   Risk column does not read `ext`; prefer S and M rows when resuming cold. Never select
   a row listed under "Waiting on the world".
3. One row is one ship (S rows may batch). Mark `[>]` on start; mark `[x]`
   with a version stamp when the definition of done is verifiably true.
4. If a definition of done proves wrong or underspecified, amend the row in
   the same ship and say so in the CHANGELOG entry.
5. When a phase's exit gate is met, record it in the CHANGELOG and move to
   the next phase.
