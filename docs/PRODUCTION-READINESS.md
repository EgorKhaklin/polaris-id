# PRODUCTION-READINESS.md: what stands between this repository and real identity data

**Reader:** the operator or assessor deciding whether Polaris can hold real
national-identity data. **Job:** the bound on every claim in this repository.
Status first, then the decisions only a deploying organization can make, then
the engineering record with the check that pins each closed item.

**Status (v9.458): not production-ready for real identity data.** Every
engineering gap this ledger enumerated is closed and pinned by a check (the
table at the end). The protocol layer (P8, v9.320 to v9.331: the registry, the
trust list, the exchange gateway and its receipts, the timestamp authority,
document signing, the auth broker, wallet presentations, algorithm agility and
versioning) is complete, certified in two SDKs and frozen at version 1; it
changes nothing about this status. One retention fact to know (v9.341): the
timestamp authority keeps no per-request record, except one digest and one
instant per anchored timestamp, and only when the caller asked for the anchor.
Two holder-side facts to know (v9.349 to v9.352): a credential may carry a
holder key, so possession of the file is no longer possession of the
credential; and an epoch's leaves are Poseidon commitments a holder opens on
their own device, carrying a per-relying-party nullifier, so one relying party
can refuse a second claim from the same person without learning who they are
and without being able to compare notes with another. Neither hides a holder
from the ISSUER, which derives every leaf to build the tree.

Four facts to know from v9.374 to v9.394, each of which is easy to read as more than
it is. **The throughput targets were met and the system could not have run for a week
at them**, because an identifier column was 32 bits: five days at the stated sustained
verification rate, twelve hours at the peak one. Nothing was slow. The columns are
64-bit now and `check_capacity_model` recomputes the arithmetic from the live schema on
every push, but the lesson is the one to carry -- a capacity question answered in cores
and seconds is the easy half. **Three tools reported results they had not established.**
With no post-quantum library installed, the conformance runner scored 35 of 71 cases as
passes and the compat suite reported 24 of 44 holding, every one of them a rejection
case answered by a verifier that rejects everything; a third drill closed with a summary
asserting a property it had skipped. All three now refuse to report, and the rule names
no cause, because a missing library, a misconfigured backend and a future regression
produce the same false green. **The authority's most invasive power left no record of
its own use** until v9.382: the warrant-audit read went unlogged for as long as it
existed, because the read sits behind a stored procedure and nothing looking for a
SELECT found it. **And somebody with no documents can now be enrolled** through a
trusted referee -- bounded, co-signed past a threshold, and invisible on the credential
itself, because a person who needed one should not carry a mark for it at every counter.

Three facts from v9.403 to v9.415, all of them about the tests rather than the system, which is
the point. **The verification layer was asked the question it asks everything else**: not "does
it pass" but "would it notice". It often would not. Twenty-two drills printed their whole verdict
paragraph from zero recorded cases. Fourteen of the 37 database triggers, and twelve of the 17
non-primary-key unique indexes, could be dropped from the schema with the entire suite green,
including the index that stops two people holding the same token value. All three mechanisms
MISSION names are now mutation-tested on every push, and the triggers' full sweep runs weekly.
**The suite that proves C3 was the thing violating it.** Every negative property test did the
forbidden thing, COMMITTED, and then failed; with the one-active-token index absent that left a
permanent duplicate and the index could not be rebuilt. The same tests ended `except
psycopg2.Error`, which accepts any database error as proof, so a refusal for a missing column read
exactly like the invariant holding. **And a security claim was inferred rather than measured**:
PQC-POSTURE stated the internal hops' key exchange from base-image OpenSSL versions, and one hop
had been post-quantum for some time while the document called it classical. It is read off a real
handshake now.

Four more facts from v9.416 to v9.436, still about the verification layer rather than the system.
**The published conformance contract asked less than it appeared to.** Three artifact types --
agent-proof, grant-revocation, holder-proof -- had no case in which the signature was bad, so a
verifier that never checked theirs conformed; five of the published "valid" vectors had expired
months earlier and no case noticed, because none asserted freshness. Asking about freshness then
surfaced two divergences between the shipped reference verifiers: neither SDK bounded a holder
proof's age, so an integrator following one got no replay protection on presentations, and
neither could report whether an artifact's issuer was trusted at all. Both are fixed and all
three verifiers now agree on 118 cases.

**What conformance still does not prove is now stated where an integrator will read it.** 43
verdict fields are unconstrained by the published cases, and none of them can be closed by
writing a case: each needs a conforming verifier to compute something it does not. The contract
constrains what its WEAKEST conforming implementation computes, which is a property of the suite
worth knowing before relying on it. SECURITY.md says so.

**The stored procedures were the last part of the security boundary with no mutation test.** 59
refusals across 16 procedures; 27 could be deleted with the whole suite green. They concentrate
where the invariants are multi-step and a trigger cannot see them: the four-eyes rule, the
cool-down, the three out-of-band channels and the third-person witness in
`uc9_complete_recovery`, the preconditions on an irreversible erasure, and the only sanctioned
DELETE path against the audit tables. **All 27 are covered as of v9.437**, and the drill runs on
every push that touches a procedure with its declared-survivor list empty and checked in both
directions, so one that stops being covered fails rather than going quiet.

Three more facts from v9.437 to v9.458, all of them about the reference SDKs an integrator
actually builds against. **Both shipped verifiers could be made to accept what they exist to
reject.** Every refusal in each SDK was inverted in turn and the suites re-run: 18 of 18 in the
Python reference implementation, 9 of 14 in the TypeScript one, accepted with both that SDK's own
tests and the conformance runner green. The two that matter most to a relying party are an agent
grant's exhausted use count and an amount over its ceiling, which is the bound that makes P9.8
delegation something other than a bearer token, and the TypeScript SDK's constant-time comparison,
whose length guard inverted makes a five-byte value compare EQUAL to a 32-byte Merkle root. All are
closed in the SDKs' own tests, and the drill now inverts all 32 refusals on every push with a
per-SDK negative control, so a result of zero survivors is distinguishable from a harness that
never ran.

**That is not the conformance suite being broken, and the distinction bounds what conformance
means.** An SDK whose signature backends accept anything IS caught by the published cases. These
guards sit on inputs no case contains, so the contract certified what it exercised and these
refusals were outside it. An integrator relying on conformance alone should read it as the floor
it is.

**A drill can be wired into CI and still not run.** The two-SDK drill was added to a job that has
Python and a built liboqs and no Node dependency tree. It refused to report rather than calling an
unverifiable tree clean, which is the correct refusal, but the job then failed on its own setup
rather than on a finding. A red build that says nothing about the tree is how a real finding gets
waved through. The job installs what it runs now, and a check holds every job to that.

**And the measurement instruments were wrong three times in ways that flattered them.** The
conformance drill counted 22 fields that were not fields and misclassified what fixing the rest
would take, twice. Of a 45-point fall in its headline number, 18 was work and 27 was correcting
the instrument. Every intermediate figure had been reported as if it measured the contract. The
lesson this ledger already carried -- ask whether it would notice, not whether it passes -- turns
out to apply to the things doing the asking.

**One fact about the cryptography, which the outward surfaces have been stating as more than it
is.** Polaris is described as post-quantum. What is defensible is narrower and more useful:
**algorithm agility under an audited migration path**. The distinction is not pedantry, because
the two fail differently.

ML-DSA-65's security does not rest on a prediction about how large quantum computers will get. It
rests on the hardness of Module-LWE and Module-SIS against the best known classical AND quantum
algorithms. So the argument "post-quantum is unprovable because the hardware is unpredictable"
attacks the wrong thing. The two ways this breaks are a **cryptanalytic advance against the lattice
assumptions** and an **implementation flaw**, and the design answers each: SLH-DSA-128s and
SLH-DSA-256s are registered with no signer precisely because they rest on hash functions alone
rather than on lattices, and issuance requires two independent ML-DSA implementations (liboqs and
OpenSSL through `cryptography`) that must agree.

What a break in Module-LWE would cost, stated plainly. It would **not** require a schema change, a
code change on the verification path, or a new trust model: the algorithm is a row in
`CryptographicAlgorithm`, not a constant, which is C7. Registering a replacement, authorizing it
per authority through `AgencyAlgorithmAuth`, and migrating credentials through `uc6_migrate` is a
path that RUNS and is exercised on every push, not a plan. It **would** cost every credential
already issued under the broken algorithm, and here is the part no agility buys back: a credential
carries classical and post-quantum signatures during a cutover, and the classical half is
protected by nothing this design provides. A holder's credential that was harvested today is
readable on the day its classical signature falls, whatever Polaris migrates to afterwards. That is
the asymmetry that makes signing post-quantum now worth doing, and it is also the limit of what
doing it achieves.

And the exposure a reader should know before believing the word. **The default signing path is not
post-quantum.** Without `POLARIS_USE_REAL_PQC=1` and liboqs present,
`TokenSignature.signature_bytes` holds a 32-byte deterministic SHA3-256 value labelled
`DETERMINISTIC-PLACEHOLDER-SHA3-256` that verifies against no key; real ML-DSA-65 produces 3,309
bytes. That is the default in CI. It is guarded -- production fails closed at boot without real
signing, the placeholder is a named development profile, and it warns loudly when used unnamed --
but a repository whose default path signs with a placeholder should not call itself post-quantum
without saying so in the same breath. `check_post_quantum_claims_are_agility` refuses an outward
surface that asserts post-quantum SECURITY rather than post-quantum AGILITY, and refuses one that
claims either without pointing here.

None of that changed what the system does. All of it changed what is known about it, which is the
only thing this ledger is for.

Four earlier facts, still true. **The physical layer is a specification, an emulator and published
vectors, not a card.** `polaris_card/` defines the on-card object, speaks ISO
7816-4, personalizes a token whose keys it generates itself, and drives a
reference verifier device; no card is manufactured and no silicon is certified,
and the profile states which of its properties an emulator cannot establish.
**An enrollment now records what it rested on**, and the assurance level is
derived from that evidence rather than entered, with no column anywhere for the
document itself; that is a mechanism, and no proofing has been performed with
it. **The NIST 800-63 mapping is machine-checked and is not a conformance
claim**: every row cites an artifact that CI resolves and runs, no assessment
has taken place, and a deployment does not inherit any of it. **Accessibility is
enforced for the third that automation covers**, which is why accessibility
conformance is still in the list below rather than out of it. What remains is
not buildable here: nine decisions that
belong to the deploying organization, two engineering limits carried openly,
and the deployment-scale work that [ROADMAP.md](../ROADMAP.md) tracks phase by
phase. [MISSION.md](../MISSION.md) still governs every change, and
[THESIS.md](THESIS.md) records why this project refuses to overclaim.

---

## Decisions only the operator can make

Production with real identity data cannot proceed until each of these is
recorded as made for a named deployment.

| Decision | What ships today | What the deploying organization supplies |
|---|---|---|
| **Legal basis, DPIA, regulator approval** | Nothing; this is not an engineering task. | A named controller, the jurisdiction, a counsel-drafted DPIA, regulatory sign-off. |
| **Signing-key custody** | `polaris_web/custody.py` with `file`, `pkcs11` (proven in CI against a Kryoptic token) and `kms` drivers; [KEY-CEREMONY.md](operator/KEY-CEREMONY.md). | Which custody driver, the HSM or KMS itself, who holds the key, and the rotation authority. |
| **Postgres HA topology** | The HA profile (v9.243): the database under Patroni with a leader lease in etcd and HAProxy routing, automated failover drilled on every push under a live write stream, the split-brain analysis in [FAILOVER.md](operator/FAILOVER.md); the Helm profile runs the same members with the cluster's API as the lease store (v9.244). | The hosts the two members and the three etcd members run on, and whether to trade commit latency for zero data loss (synchronous replication). |
| **Encryption at rest** | [ENCRYPTION-AT-REST.md](operator/ENCRYPTION-AT-REST.md) names the plaintext surfaces; backups and every transit hop are encrypted. | The host volume encryption (LUKS, TDE or fscrypt) and its key custodian. |
| **Offsite backup target** | pgBackRest to an S3-compatible bucket by environment variable (v9.173); the monthly DR drill (v9.192) measures RPO and RTO against the 300 s and 4 h targets in [DR-DRILLS.md](operator/DR-DRILLS.md). | The bucket, its retention, and the schedule. |
| **Alerting backend and on-call** | Alert rules, Alertmanager routing with the duress page at no delay, a pager webhook read from a secret file, a CI drill that proves a duress event reaches the webhook (v9.175), and a weekly chaos drill that stops both app colours until the outage page reaches it (v9.242, [CHAOS-DRILLS.md](operator/CHAOS-DRILLS.md)). | The pager product and its URL, and the named rotation, including who receives the duress page. |
| **Right-to-erasure policy** | The pseudonymization mechanism: `uc_pseudonymize_individual` and the append-only `IndividualErasureEvent` (v9.125). | Which erasures to honor and crypto-shred versus pseudonymize against the append-only audit. |
| **Retention schedule** | The engine: `RetentionPolicy` holds the decision per table class and jurisdiction with a 365-day CHECK floor, append-only with one-way supersession, and `uc_archive_purge` refuses a cutoff inside the window (v9.234, [retention.md](design/retention.md)). Ships at five years for every class. | The days each class is kept in this jurisdiction, and the counsel who says the number satisfies the statute. Polaris records the decision and its justification; it does not know the law. |
| **Independent penetration test and threat-model sign-off** | The readiness pack in [RED-TEAM-SCOPE.md](RED-TEAM-SCOPE.md); roadmap row P1.12. | The firm, the funding, and an accountable human signature. |

One engineering limit is carried openly, and since v9.243 only its edge half
remains (every latency below is measured by the CI drills on an ephemeral single
host or a kind cluster, not on production multi-node hardware): recreating the edge on a single host is a 0.3 s window, measured
under traffic on every push by `scripts/polaris-window-drill.sh` against a
30 s ceiling (v9.240), and an edge configuration change is a live reload
with a near-zero window (Caddy occasionally restarts a listener and drops a
single in-flight request at the swap; the drill asserts a small transient budget). The database half closed with the HA profile
(v9.243, [FAILOVER.md](operator/FAILOVER.md)): under Patroni a lost leader
is replaced within its 20 s lease (20.0 s measured at v9.244; queries in
flight fail fast at the pooler's 15 s query timeout and the app retries,
none lost), a planned switchover is a 3.4 s outage, and a leader that loses
its lease store stands down in 7 s; the hosts the members run on are the operator's
placement. A single-host database restart without the profile remains
latency the pooler absorbs (v9.240), and a database crash a 0.6 s window
(v9.242). Closing the edge half means a second edge with an address that
moves, which is placement and DNS, not code. The other limit the ledger
carried, a Caddy edge that ran as root with `NET_BIND_SERVICE`, closed at
v9.239: the edge runs as uid 1000 with no capability on every substrate, and
`check_container_hardening` fails the build if a capability or a root user
comes back.

---

## Deployment-scale gaps

This ledger tracks one authority on one host or one cluster. Everything
beyond that is in [ROADMAP.md](../ROADMAP.md): the external penetration
test (P1.12), partitioning and HA automation and
multi-region (P2), the relying-party API and federation protocol (P3), the
hardware token and enrollment kit (P4), pilots (P5), certification (P6) and
national rollout (P7). Do not read a closed ledger here as readiness for those.

---

## What is already production-grade

- **The ZK stack is real**, not a mock: a Plonky2 transparent-setup
  Merkle-inclusion circuit, verified at use on `/api/zk/verify` with single-use
  nonce anti-replay, plus an independent second-witness Poseidon/Merkle
  verifier in Python.
- **Authentication and access control**: scrypt password hashing, atomic
  failed-login counting, username-enumeration resistance, per-session CSRF with
  constant-time compare, session-fixation regeneration, role-based
  authorization with 403 and audit, a CSP with no `unsafe-inline` for scripts,
  a server-side session registry with per-role caps and revocation, per-role
  network allow-lists, a WebAuthn attestation policy with ML-DSA-65 offered
  first, and opt-in per-agency quotas enforced by trigger.
- **The C1-C10 invariants are enforced at the database**, not in policy: the
  grant boundary revokes UPDATE and DELETE on append-only audit tables from
  `polaris_app`, the only DELETE path is SECURITY DEFINER, and `polaris_app`
  has no DDL.
- **Secrets** are file-mounted under `/run/secrets/`, the app refuses to boot
  in production on the default secret key, and the database role password is
  rotated off its development default at first boot.
- **Algorithm-as-data (C7)**, `TokenSignature` immutability, and the duress
  machinery are real and enforced in the schema.
- **Retention is a recorded decision with a floor**: `RetentionPolicy` holds
  the days per table class and jurisdiction behind a 365-day CHECK, the purge
  refuses a cutoff inside the window, and the archive chain runs per class
  and is drilled in CI (v9.234 to v9.236).

---

## The engineering record

Every gap the ledger enumerated, the version that closed it, and the check that
fails if it stops being true. Each landed as its own CI-green ship; the
CHANGELOG entry for the version carries the detail.

| Claim | Shipped | Pinned by |
|---|---|---|
| Demo accounts never reach a production database; the first admin is bootstrapped by script | v9.101 | `check_prod_hardening` |
| The rate limiter uses Redis in production, so per-IP limits are shared across workers | v9.101 | `check_prod_hardening` |
| Real ML-DSA-65 signing runs end to end in CI (liboqs) | v9.103 | the `pqc-real` CI job |
| A persistent signing key is the published trust anchor; a malformed key fails loud | v9.103 | `check_pqc_real_signing` |
| Every produced signature is self-verified before it is stored; stored signatures verify against the trust anchor | v9.113 | `check_verify_enforced` |
| The secrets generator mints a loadable key (the liboqs banner no longer corrupts it) | v9.139 | `check_signing_key_generation` |
| Real PQC is the production default; liboqs ships in the image; CI signs inside it | v9.116 | `check_prod_real_pqc` |
| Each signature row stores the issuer public key, so verification survives rotation | v9.117 | `check_signature_self_contained_verify` |
| Algorithm migration (UC-6) signs through the same module as issuance | v9.119 | `check_pqc_signing_wired` |
| Two independent FIPS 204 implementations must agree on every verdict | v9.133 | `check_pqc_second_witness` |
| The full crypto surface is audited against the NIST 2030/2035 timeline | v9.134 | `check_pqc_posture` |
| The public edge negotiates X25519MLKEM768, proven off a real handshake | v9.136 | `check_edge_pq_kex` |
| Backups are encrypted at rest and restore fails closed without the key | v9.102 | `check_backup_encryption` |
| RPO and RTO are measured, not asserted: the drill kills a primary and restores it | v9.192 | `check_dr_drill_scheduled` |
| Both database hops are TLS with pinned certificates | v9.121, v9.131 | `check_app_db_tls` |
| The at-rest posture names every plaintext surface | v9.124 | `check_encryption_at_rest_posture` |
| Continuous WAL archiving ships in the image and round-trips in CI | v9.127 | `check_pgbackrest_scaffolding` |
| Every production container drops all capabilities and forbids privilege escalation | v9.141 | `check_container_hardening` |
| The full production compose boots and serves through the TLS edge in CI | v9.140 | `check_prod_stack_boot` |
| Migrations bound their lock and statement time | v9.106 | `check_migration_timeouts` |
| `WEB_CONCURRENCY` is honored | v9.107 | `check_web_concurrency_honored` |
| Liveness and readiness are distinct endpoints | v9.108 | `check_health_liveness_readiness_split` |
| Every service has resource limits and log rotation | v9.109 | `check_compose_resource_limits` |
| The pooler is self-built from the distro package | v9.110 | `check_pgbouncer_self_built` |
| The edge is self-built with its rate-limit plugin compiled in | v9.135 | `check_caddy_self_built` |
| Third-party images are digest-pinned | v9.114 | `check_prod_images_digest_pinned` |
| Alert rules ship and validate | v9.115 | `check_alert_rules` |
| The Kubernetes reference profile boots on kind with restricted policies | v9.186 | `check_helm_reference_profile` |
| A deploy drops zero requests under traffic | v9.183 | `check_zero_downtime_deploy`, `check_migrations_expand_contract` |
| A duress event reaches the pager webhook, proven in CI | v9.175 | `check_pager_integration` |
| Metrics aggregate across all workers | v9.120 | `check_prometheus_multiprocess` |
| Every request carries a correlation id that never touches the audit of record | v9.122 | `check_correlation_id` |
| SLO targets and one runbook per alert | v9.123 | `check_alert_runbooks` |
| The duress signal is a scrapeable counter with a SEV-1 alert | v9.128 | `check_duress_alertable` |
| Dependency CVEs and SAST gate the build; the production image ships no test framework | v9.105, v9.112 | `check_cve_scanning`, `check_prod_image_no_test_deps`, `check_sast_scanning` |
| Container image CVEs gate the build | v9.138 | `check_image_cve_scanning` |
| The SQL console is read-only at the engine | v9.104 | `check_sql_console_readonly` |
| A fresh Linux host reaches a healthy stack by one script, exercised on Debian and Rocky in CI | v9.176 | `check_linux_server_deployment` |
| The signing key sits behind a custody interface with file, PKCS#11 and KMS drivers | v9.178 | `check_key_custody_abstraction` |
| Secrets are sealed and rotated through the same lifecycle | v9.180 | `check_secrets_lifecycle_sealed` |
| The Kubernetes profile boots on kind with restricted policies | v9.186 | `check_helm_reference_profile` |
| Tracing and dashboards ship as code | v9.187 | `check_distributed_tracing` |
| Sessions are registered server-side with per-role caps and origin checks | v9.189 | `check_session_origin_hardening` |
| Per-agency quotas refuse writes under real load, proven in CI | v9.190 | `check_abuse_controls` |
| The performance baseline is published and re-run on every push | v9.191 | `check_performance_baseline` |
| Retention is data with a floor, purged per class, drilled in CI | v9.234 to v9.236 | `check_retention_engine` |
| Every base image under the self-built containers is digest-pinned | v9.237 | `check_prod_images_digest_pinned` |
| The TLS edge runs as a non-root user with no capability on every substrate | v9.239 | `check_container_hardening` |
| Edge configuration changes are live reloads; edge and database recreation windows are measured against ceilings on every push | v9.240 | `check_zero_downtime_deploy` |
| The SLIs and the error budget are recorded series, unit-tested, and on the overview dashboard | v9.241 | `check_alert_rules` |
| The fail-closed harness runs on every push; a weekly drill kills one colour, stops both until the outage pages through real Prometheus and Alertmanager, kills redis and postgres, partitions pgbouncer, and commits every recovery time to a ledger | v9.242 | `check_chaos_program` |
| The HA profile runs the database under Patroni with a leader lease in etcd and HAProxy routing on the role endpoints; the failover drill loses the leader, cuts it off from the lease store, switches over and crashes an etcd member under a live write stream against ceilings on every push; the split-brain analysis is written | v9.243 | `check_ha_automation` |
| The Helm profile runs the same Patroni members with the cluster's API as the lease store and the same router; the kind drill deletes the leader pod, freezes the leader's container and switches over under a live write stream, and asserts every acknowledged insert present | v9.244 | `check_helm_reference_profile` |
| The four append-only event tables are monthly range-partitioned; a manager premakes and detaches months (re-adding the append-only trigger so C1 holds across the detach), an online migration converts a pre-v9.245 database in place, and a drill proves append-only across a partition, an attach and a detach on every push | v9.245 | `check_event_table_partitioning` |
| The read-only surfaces (the atlas API, the verification list, the token export) route to a streaming replica under an explicit staleness contract with failback to the primary; correctness-critical reads stay on the primary; the failover drill proves the app serves reads from the replica | v9.246 | `check_read_replica_routing` |
| A whole population stages with `COPY` and issues set-based in one transaction through `uc_bulk_issue`, every row through the full constraint set and a single violation rolling the batch back; a drill proves throughput, all-or-none atomicity, and C3 across the batch on every push | v9.247 | `check_bulk_enrollment` |

---

## The rule

The status line at the top changes only when the nine decisions above are
recorded as made for a named deployment and the roadmap's P1 exit gate is met.
No document in this repository claims a protection the code does not
implement, and every row above names the check that fails if it stops being
true.
