# PRODUCTION-READINESS.md: what stands between this repository and real identity data

**Reader:** the operator or assessor deciding whether Polaris can hold real
national-identity data. **Job:** the bound on every claim in this repository.
Status first, then the decisions only a deploying organization can make, then
the engineering record with the check that pins each closed item.

**Status (v9.293): not production-ready for real identity data.** Every
engineering gap this ledger enumerated is closed and pinned by a check (the
table at the end). What remains is not buildable here: nine decisions that
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
