# Production readiness

The bound on every claim in this repository, for the operator or assessor deciding whether
Polaris could hold real identity data. Status, the facts to plan around, the operator's decisions.

**Status (v1.0.0): not production-ready for real identity data.** Every engineering gap
this ledger enumerated is closed and pinned by a check; what remains is the operator decisions
below and the deployment-scale work in [ROADMAP.md](../ROADMAP.md). Operating it is a separate question, tracked criterion by criterion in the [operability gate](#operability-gate).

## Facts to plan around

**Certification and evidence**

- Every number here was measured on notional data, on CI hosts or a kind cluster.
- `polaris-oid4vp 1.0.0rc7` is OpenID Certified to the OpenID4VP 1.0 + HAIP 1.0 Verifier profile (2026-09-24): a self-certification, not an endorsement or an independent verification.
- The protocol layer (registry, trust list, exchange gateway and receipts, timestamp authority, document signing, auth broker, wallet presentations, algorithm versioning) passes the repository's conformance suite in both SDKs and is frozen at version 1.
- The physical layer is a specification, an emulator and published vectors.
- Enrollment records the evidence it rested on and derives the assurance level from it; document authenticity is the operator's attestation.

**Cryptography**

- Polaris offers **algorithm agility under an audited migration path**. ML-DSA-65 rests on the hardness of Module-LWE and Module-SIS. SLH-DSA-128s and SLH-DSA-256s are registered as rows for a hash-based fallback, and issuance requires two independent ML-DSA implementations (liboqs and OpenSSL through `cryptography`) to agree.
- A break in Module-LWE needs no schema change or new trust model. The response is code, then data: write the signer and the `polaris-verify` verifier for the replacement (ML-DSA-87 rests on the same assumptions as ML-DSA-65), authorize it per authority through `AgencyAlgorithmAuth`, provision a key under it, and migrate every credential issued under the broken algorithm through `uc6_migrate` or the population runner. Those paths run on every push, record the algorithm of the key that signed, and refuse a target no key is provisioned for (until 2026-10-02 the per-credential path recorded the algorithm it was asked for).
- During a cutover a credential carries classical and ML-DSA signatures. Stop accepting the **classical half** when the cutover ends: a signature encrypts nothing, so harvest-now-decrypt-later does not apply to the credential, and once the classical algorithm falls anyone can forge that half ([reference/PQC-POSTURE.md](reference/PQC-POSTURE.md)).
- The production profile (`POLARIS_USE_REAL_PQC=1` with liboqs) signs with ML-DSA-65 (3,309 bytes). The default in development and CI writes a 32-byte SHA3-256 placeholder labelled `DETERMINISTIC-PLACEHOLDER-SHA3-256` that verifies against no key; production fails closed at boot without real signing, and unnamed placeholder use warns loudly.
- The zero-knowledge layer (a Plonky2 transparent-setup Merkle-inclusion circuit verified at use on `/api/zk/verify` with single-use nonces, plus an independent Python Poseidon/Merkle witness) rests its proof soundness on the `plonky2` 1.x crate. Do not protect real identities with it as shipped ([zk-soundness.md](design/zk-soundness.md)).

**Algorithm migration**

- Relying parties take a new or retired algorithm by a software release: the detached verifier's accepted set is in its code, the registry publishes names, and the trust list carries per-key status.
- Plan a spare algorithm. `one_signature_per_algorithm_per_token` forbids returning a token to an algorithm it already used, so a migration moves to an algorithm that already exists, is keyed and is not deprecated (see [design/multi-sig-migration.md](design/multi-sig-migration.md)).

**Unlinkability and correlation**

- Against colluding verifiers pooling full transcripts, a withheld-credential presentation gives no advantage beyond the anonymity set, and N is the epoch's membership. The application role writes an epoch only through `uc11_close_epoch`, which refuses an epoch below `polaris.min_epoch_anonymity_set` (20 unless set; the notional sample sets 1), and the online verifier and `verify_cross_authority_zk` answer a proof against a smaller epoch "privacy unavailable".
- The measuring adversary matches exact equality: its result is that no field is identical across verifiers.
- Keep the wallet's authenticity pack (free-text issuer name, unpadded token id) apart from a withheld credential: a bounded presentation sits at chance while it carries no per-holder variable-length field.
- Relying-party correlation is bounded, not eliminated: a full presentation shows a stable token value.
- The issuer derives every epoch leaf. A credential may carry a holder key, and a leaf is a Poseidon commitment opened on the holder's device with a per-relying-party nullifier.

**Duress**

- The mechanism is duress-aware: it acts against a coercer who does not know it exists, and its record is append-only (`lab/duress/`).

**Retention and records**

- The timestamp authority keeps one digest and one instant per anchored timestamp, when the caller asked for the anchor, and no other per-request record.
- Retention ships at five years for every class: set each class to the jurisdiction's law, and Polaris records the decision and its justification.
- Warrant-audit statistics are computed from the authority's own append-only log, which defends them against revision.

**Authorization and operators**

- Procedures enforcing rules about people (four-eyes, the recovery ceremony's distinct roles) take the actor as a user id parameter from the application, which reaches the database through one role. Guard that database credential as the root of those rules, and hold evidence outside the database as the defence against a compromised application.
- `investigate_individual` and `investigate_token` serve any signed-in operator: they return a holder's tokens and non-zero-knowledge verification history, including textual `requestor_location`, audit every access, and return no zero-knowledge event or coordinates. Whether investigation is an oversight or operational function is the deploying organization's call.
- Run `scripts/polaris-set-webauthn-deadline.sh` for admin accounts created before both provisioning paths set a WebAuthn deadline; [OPERATIONS.md](operator/OPERATIONS.md) lists who is affected.

**Verifiers and SDKs**

- A relying party that depends on them reads six signed fields itself: `epoch_number` on a revocation feed (require it to advance with `as_of`), `purpose` on a signed document (require the purpose it expects), `auth_time`, `authorized_via`, `bound_at` and `revoked_at`.
- Where each security decision is made is in [reference/SECURITY-DECISIONS.md](reference/SECURITY-DECISIONS.md).

**Capacity and availability**

- `Individual.individual_id` and `IdentityToken.token_id` are 32-bit, about 29 years at the stated enrollment rate; widening them touches foreign keys across the schema, and `check_capacity_model` recomputes the arithmetic from the live schema on every push.
- On one core ([lab/evaluation](../lab/evaluation/README.md), 2026-09-27) the liboqs witness verifies in 122 us at p50 (about 8,200/s, the path the application uses) and the Python SDK's OpenSSL witness, all a plain install gets, in 1.21 ms (about 826/s). End to end, `POST /api/v1/verify` served 155 to 165 per second on one 8-core machine with 4 or 8 workers; the signature was under 1% of each request, and a new database connection per statement (three per verification) was most of it.
- The HA drills run a two-member topology on CI hardware.
- The edge is one host: recreating it is a 0.3 s window, and a configuration reload may drop one in-flight request.
- Under the HA profile a lost database leader is replaced within its 20 s lease, a planned switchover is a 3.4 s outage and a leader that loses its lease store stands down in 7 s. Without the profile a database crash is a 0.6 s window.

## Decisions only the operator can make

Production with real identity data cannot proceed until each is recorded as made for a named deployment.

| Decision | Options | Where documented |
|---|---|---|
| Legal basis, DPIA, regulator approval | Named controller, jurisdiction, counsel-drafted DPIA, regulatory sign-off | Not an engineering task |
| Signing-key custody | `file`, `pkcs11` (CI-tested against a PKCS#11 v3.2 software token, Kryoptic) or `kms` driver; the HSM or KMS; key holder; rotation authority | [KEY-CEREMONY.md](operator/KEY-CEREMONY.md) |
| Wallet copies | Whether to offer them at all (each is a classical ES256 credential that relying parties can link across presentations, with no duress path); per agency, the CA that issues the wallet-copy leaf, the leaf's lifetime, and the key's custodian (a file in this version, which the HSM-sole-signer profile refuses) | [oid4vci-issuer.md](design/oid4vci-issuer.md), [KEY-CEREMONY.md](operator/KEY-CEREMONY.md#wallet-copy-keys-es256) |
| Postgres HA topology | Hosts for the two members and three etcd members; synchronous replication (zero loss) or lower commit latency | [FAILOVER.md](operator/FAILOVER.md) |
| Encryption at rest | Host volume encryption (LUKS, TDE or fscrypt) and its key custodian | [ENCRYPTION-AT-REST.md](operator/ENCRYPTION-AT-REST.md) |
| Offsite backup target | The S3-compatible bucket, retention and schedule (RPO 300 s, RTO 4 h targets) | [DR-DRILLS.md](operator/DR-DRILLS.md) |
| Alerting and on-call | Pager product and URL, named rotation, who receives the duress page | [CHAOS-DRILLS.md](operator/CHAOS-DRILLS.md) |
| Right-to-erasure policy | Which erasures to honor; crypto-shred or pseudonymize against the append-only audit | `uc_pseudonymize_individual` |
| Retention schedule | Days per table class in this jurisdiction (365-day floor), and the counsel who signs off | [retention.md](design/retention.md) |
| Operator MFA | Recovery path for a lost admin key; handling of admins that predate the deadline | [OPERATIONS.md](operator/OPERATIONS.md) |
| Penetration test and threat-model sign-off | The firm, the funding, an accountable signature | [RED-TEAM-SCOPE.md](RED-TEAM-SCOPE.md) |
| What may leave the database and be joined to it | A written export and join rule and an audit that checks it. The constraints bind this schema only; a side store can rebuild the correlation C2 prevents with every check passing | [MISSION.md](../MISSION.md) |
| A holder whose one live token is gone | Service level on the UC-9 recovery ceremony, and what the person is entitled to meanwhile. C3 means a revoked or lost token leaves them unable to present anywhere until it completes | [MISSION.md](../MISSION.md) |

## Operability gate

Whether an operator who is not the author can install, run, upgrade and recover Polaris, one criterion per row ([lab record 017](../lab/strategy/017-production-operability.md)). A PASS row cites evidence that `check_operability_gate` resolves: a check, a test, a drill or a file. This gate is about operating the software; it is not readiness for real identity data, which the status line above and the last row keep separate.

29 criteria: 22 PASS, 6 PARTIAL, 1 FAIL, 0 UNKNOWN.

| ID | Criterion | Status | Evidence |
|---|---|---|---|
| OP-1 | Installed from published, signed release artifacts, with no source build | PARTIAL | v1.0.0's five images and its chart are published, signed and verified from outside the run, anonymously (`check:release_images_signed`; the digests and runs in `file:docs/RELEASING.md`). Nothing has been installed from them yet: PASS needs an install from `oci://ghcr.io/egorkhaklin/charts/polaris` 1.0.0 that reaches a verified credential with no source build. |
| OP-2 | A fresh host reaches HTTPS and a verified credential in 15 minutes or less, with five operator inputs or fewer | PASS | `check:fresh_host_reaches_online_verification`: on a fresh host with real systemd (CI's linux-install job), the documented commands reach a credential that `polaris-verify` from PyPI verifies offline, with five operator inputs (the domain; the first administrator's name, password and reason; the key registration), and a relying party then verifies it online after its own registration (two more: its name and the reason). The job fails past 15 minutes from the install's start to the online accept, a span that also holds the backup, upgrade and rotation it runs on the way; in ten CI runs on 2026-10-09 it took 6 to 10 minutes, the install 5 min 10 s to 8 min 43 s of it with every image built from source (an upper bound until OP-1 publishes them); `test:scripts/test_key_event.py`; `drill:lab/strategy/006/try.sh` reaches one offline. No operator outside the project has done it yet. |
| OP-3 | Every setting is validated at boot, and a wrong one stops it by name | PASS | `check:config_schema_covers_env`, `test:polaris_web/test_app.py::ConfigSchemaTests`, `test:polaris_web/test_app.py::F05_ProductionSecretGuardTests` |
| OP-4 | Readiness reflects what this instance can serve, and a shared failure does not empty the pool | PASS | `check:health_liveness_readiness_split`, `test:polaris_web/test_app.py::HealthEndpointTests` |
| OP-5 | An instance crash costs no request | PASS | `drill:scripts/polaris-rolling-drill.sh` |
| OP-6 | A database failover loses no acknowledged write | PASS | `drill:scripts/polaris-failover-drill.sh`, on the HA profile with its default `synchronous_mode` on, which CI requires the drill to find: after the leader lost past its lease, the leader cut off from the lease store, a planned switchover and the replica lost, every insert acknowledged since the drill began is in the surviving history (CI, 2026-10-09: 49, 171, 193 and 464 acknowledged by then, none lost). The first three cost a write outage of 4.7 to 25.4 s; the fourth no failed write, its longest stall 0.7 s. `synchronous_mode_strict` is off: with the replica gone the leader writes alone, and losing it too before the replica returns stops writes until it does, an outage, not a lost write: Patroni's synchronous mode promotes no replica that missed them (its documented behaviour; no drill here fails both). Not covered: the documented opt-out (`POLARIS_PATRONI_SYNCHRONOUS_MODE=off`, or the chart's `synchronousMode: false`), the DR overlay's standby region, asynchronous by design (the region-evacuation drill measures what its promotion loses), and a cluster bootstrapped before this default, which stays asynchronous until `patronictl edit-config` turns it on (FAILOVER.md section 1). |
| OP-7 | The loss of a host or zone is tolerated | PARTIAL | `check:failure_domains`: on Kubernetes the chart spreads every replicated component across nodes and zones, runs two pods of each hop on the data path, moves pods off an unanswering node after 30 s and Redis with them; `drill:scripts/polaris-zone-loss-drill.sh` kills the leader's node, then Redis's, on a three-zone kind cluster, and passes in CI: the chart serves on after each. The Compose profiles run on one host, where a host's loss is a restore (DR.md section 4.3). |
| OP-8 | Internal services authenticate one another | PASS | `check:redis_authenticated`: the cache refuses unauthenticated clients and scopes the app's user; `check:ha_internal_auth`, `drill:scripts/polaris-failover-drill.sh`, `drill:scripts/polaris-region-evacuation-drill.sh`: the HA lease store (etcd) authenticates its clients and fences Patroni's user to its keys, and Patroni's REST API refuses unauthenticated writes from the app's network, in both regions of the DR overlay. The database, its pooler and replication take passwords. |
| OP-9 | Secrets are least-privilege and sealed at rest | PARTIAL | `check:secrets_reach_only_their_readers`, `drill:scripts/polaris-helm-drill.sh`: each container and pod mounts only the secrets it reads, the chart's at 0440; `check:secrets_lifecycle_sealed`: an age or KMS sealed store, unsealed into a tmpfs at start, is drilled in CI, and on a systemd host through `polaris.service`, which refuses a sealed store without `POLARIS_SECRETS_DIR` (`check:operator_scripts_read_the_unit_env`); but the default backend keeps the secrets in a 0700 directory on disk, which the doctor and every start now state, and an age identity kept on the same host travels with its disk. |
| OP-10 | Signing keys can live in hardware or a KMS, shown on a real device | PARTIAL | `test:polaris_web/test_custody.py` runs PKCS#11 against a software token and KMS against a stand-in. |
| OP-11 | Restores are verified on a schedule and the evidence is current | PASS | `check:restore_verified_on_schedule`, `drill:lab/strategy/006/restore.sh`: on a Compose or host install, the deployment's newest backup is restored into a scratch copy and proven against the live database, at the first deploy and weekly by timer. Each verified restore is recorded, and `PolarisRestoreUnverified` pages at 8 days. CI proves the refusals: an archive that is not current, a copy that differs, a damaged repository. The chart schedules no such check yet (its archiving is opt-in, OP-14). `drill:scripts/polaris-dr-drill.sh` measures RPO and RTO monthly; its ledger reaches `main` by pull request. |
| OP-12 | A restore to a chosen point in time is tested | PASS | `drill:scripts/polaris-pitr-drill.sh`, `check:pitr_drilled` |
| OP-13 | Revocations made after a restore point are re-applied after the restore | PASS | `drill:scripts/polaris-pitr-drill.sh` (`--reconcile`), `file:scripts/polaris-reconcile-restore.py`, `check:restore_reconciled` |
| OP-14 | Continuous archiving is on by default, with an offsite copy | PARTIAL | `check:pgbackrest_scaffolding`: archiving on by default, the stanza made at the first init, a first full backup at deploy and scheduled ones after; `drill:scripts/polaris-offsite-drill.sh` round-trips the offsite repository, which needs the operator's bucket: by default the repository is local, and `test:scripts/test_doctor.py` shows the doctor warning until it is offsite. |
| OP-15 | Backup age, archive failure, replication lag, disk, certificate expiry and clock skew alert | PASS | `drill:lab/strategy/006/alerts.sh` fires the certificate, backup and archive alerts on their real conditions and clears them on repair; `check:infra_alerts` pins all six rules and their promtool tests. |
| OP-16 | Application metrics, alerts and traces are tested | PASS | `drill:scripts/polaris-page-drill.sh`, `drill:scripts/polaris-trace-drill.sh` |
| OP-17 | One command names the failing component | PASS | `drill:lab/strategy/006/doctor.sh`, `check:doctor_names_failures` |
| OP-18 | Schema migrations run on every upgrade path | PASS | The host deploy script runs them (`check:upgrade_drilled`); a Helm upgrade runs them in a pre-upgrade Job (`check:helm_upgrade_migrates`, `drill:scripts/polaris-helm-upgrade-drill.sh`). |
| OP-19 | An upgrade from the previous release is drilled | PASS | `drill:scripts/polaris-upgrade-drill.sh` upgrades the previous release's Compose stack as OPERATIONS.md says (`check:upgrade_drilled`); `drill:scripts/polaris-helm-upgrade-drill.sh` upgrades its chart on kind (`check:helm_upgrade_migrates`); on a systemd host, CI runs the documented `sudo scripts/polaris-deploy.sh prod`, which reads `polaris.env` as the unit does (`check:operator_scripts_read_the_unit_env`). |
| OP-20 | The data-integrity rules (C1 to C10) are enforced in the schema and mutation-tested | PASS | `check:aor_append_only_triggers`, `check:one_active_token_index`, `drill:scripts/polaris-constraint-mutation-drill.py` |
| OP-21 | Two independent ML-DSA implementations agree at issuance | PASS | `check:pqc_second_witness` |
| OP-22 | A signature-algorithm migration is drilled | PASS | `drill:scripts/polaris-quantum-event-drill.py` |
| OP-23 | A same-algorithm signing-key rotation is drilled end to end | PASS | `drill:lab/strategy/006/rotate.sh`, `check:key_rotation_drilled` |
| OP-24 | Throughput is measured and a sizing guide is published | PASS | `drill:scripts/polaris-throughput-measure.sh`, `check:throughput_measured`: online verifications a second through the production path, every answer read, per app vCPU and across replicas, with each tier's CPU per verification, weekly on a CI runner; `file:docs/reference/SCALING.md` sizes a deployment from it and names what is not measured (a database on its own host, more than two replicas, other hardware). `file:docs/reference/BENCHMARK.md` measures the cryptography. |
| OP-25 | Horizontal scaling is measured | PARTIAL | `drill:scripts/polaris-throughput-measure.sh`: on one host, two app replicas served 1.93 times one while the app tier bound, and a second replica added 13% once the database had taken the rest of the host; scaling across hosts is not measured. |
| OP-26 | The client address is correct behind load balancers and NAT | PASS | `drill:scripts/polaris-client-ip-drill.sh`, `check:client_ip_behind_proxies`, `check:edge_settings_reach_the_edge`: the client's own address behind an L7 balancer the operator names, and behind an L4 balancer that rewrites source addresses and sends a PROXY protocol header; forged headers and forged PROXY lines refused, directly and through the balancer. The metrics surfaces and the health answers are refused through an SNAT hop (`drill:scripts/polaris-metrics-edge-drill.sh`). |
| OP-27 | Contributors need no Kubernetes | PASS | `file:Polaris.command` |
| OP-28 | Real identity data | FAIL | Needs an external security review, the operator's DPIA and a pilot (above). |
| OP-29 | A PostgreSQL major-version upgrade is drilled, there and back | PASS | `drill:scripts/polaris-pg-upgrade-drill.sh` runs OPERATIONS.md's upgrade from 16 to 17 and its rollback as written, and requires the same rows, sequences, catalogue, roles and privileges on each side, a credential issued before still valid, pgBackRest healthy after both, and the deploy to refuse another major's cluster both ways; its control must name one changed audit row (`check:pg_upgrade_drilled`); `.github/workflows/pg-upgrade.yml` runs both on CI's Docker Compose nightly, on main, and for every change to the procedure |

## What is already production-grade

- **Authentication and access control**: scrypt hashing, atomic failed-login counting, enumeration resistance, per-session CSRF, session-fixation regeneration, audited role checks, a CSP with no inline scripts, a server-side session registry, per-role network allow-lists, a WebAuthn attestation policy and per-agency quotas enforced by trigger.
- **Database constraints**: C1 revokes UPDATE and DELETE on every audit partition from `polaris_app`, whose only DELETE path is SECURITY DEFINER and which has no DDL; C2 is a CHECK, C3 a partial unique index, C7 a registry table, C10 an absence. C4, C5, C6, C8 and C9 live in the application, response policy and threaded tests, and all ten are pinned by a check.
- **Credential expiry** is enforced at read time by one predicate on both endpoints: valid through the expiry date, a null expiry never expires, an unreadable one counts as expired.
- **Secrets** are file-mounted; production refuses to boot on the default secret key; the database role password rotates at first boot.
- **Algorithm-as-data (C7)**, `TokenSignature` immutability and the duress machinery are enforced in the schema.
- **Retention** is a recorded decision with a 365-day CHECK floor; the purge refuses a cutoff inside the window.
- **Referee enrollment**: a person with no documents can be enrolled through a trusted referee, bounded, co-signed past a threshold and invisible on the credential.

## The rule

The status line changes only when every decision above is recorded as made for a named deployment
and the roadmap's P1 exit gate is met. No document here claims a protection the code does not
implement. [MISSION.md](../MISSION.md) governs every change, and [THESIS.md](THESIS.md) records why
this project refuses to overclaim.
