# Production readiness

The bound on every claim in this repository, for the operator or assessor deciding whether
Polaris could hold real identity data. Status, known limitations, the operator's decisions, the gaps.

**Status (v1.0.0-rc.70): not production-ready for real identity data.** Every engineering gap
this ledger enumerated is closed and pinned by a check; what remains is the limitations and
operator decisions below and the deployment-scale work in [ROADMAP.md](../ROADMAP.md). Operating it is a separate question, tracked criterion by criterion in the [operability gate](#operability-gate).

## Known limitations

**Scope and evidence**

- It has never held real identity data; every number here was measured on notional data, on CI hosts or a kind cluster, not production multi-node hardware.
- No external party has audited it. The one certification is narrow: `polaris-oid4vp 1.0.0rc7` is OpenID Certified to the OpenID4VP 1.0 + HAIP 1.0 Verifier profile (2026-09-24), which says nothing about readiness for real identity data.
- The protocol layer (registry, trust list, exchange gateway and receipts, timestamp authority, document signing, auth broker, wallet presentations, algorithm versioning) is conformant in both SDKs under the repository's own suite only, and frozen at version 1.
- Conformance is a floor. It constrains what its weakest conforming verifier computes: 28 verdict fields are unconstrained by any case (`polaris-conformance-mutation-drill.py`), and SDK refusals on inputs no case contains are covered by the SDKs' own tests, not by conformance.
- The physical layer is a specification, an emulator and published vectors, not a card. No card is manufactured, no silicon is certified, and the profile states which properties an emulator cannot establish.
- Enrollment records the evidence it rested on and derives the assurance level from it, but no proofing has been performed with it, and document authenticity is taken on the operator's word.
- The NIST 800-63 mapping is machine-checked and is not a conformance claim. No assessment has taken place and a deployment inherits none of it.
- Accessibility is enforced only for the third that automation covers; accessibility conformance is not established.

**Cryptography**

- What is defensible is **algorithm agility under an audited migration path**, not a security claim against quantum adversaries. ML-DSA-65 rests on the hardness of Module-LWE and Module-SIS; the failure modes are a cryptanalytic advance against those assumptions or an implementation flaw. SLH-DSA-128s and SLH-DSA-256s are registered with no signer as a hash-based fallback, and issuance requires two independent ML-DSA implementations (liboqs and OpenSSL through `cryptography`) to agree.
- A break in Module-LWE needs no schema change or new trust model, but it does need code: ML-DSA-87 rests on the same assumptions, and the hash-based SLH-DSA rows have no signer here and no verifier in `polaris-verify`. With those written, authorize the replacement per authority through `AgencyAlgorithmAuth`, provision a key under it, and migrate through `uc6_migrate` or the population runner, paths exercised on every push that record the algorithm of the key that signed and refuse a target no key is provisioned for (until 2026-10-02 the per-credential path recorded the algorithm it was asked for). It still costs every credential issued under the broken algorithm.
- During a cutover a credential carries classical and ML-DSA signatures, and the **classical half** is protected by nothing here. The risk is forgery, not disclosure: a signature encrypts nothing, so harvest-now-decrypt-later does not apply to the credential, but once the classical algorithm falls anyone can forge that half, and a verifier that still accepts it accepts forgeries. Migration protects only verifiers that stop accepting it ([reference/PQC-POSTURE.md](reference/PQC-POSTURE.md)).
- The default signing path, without `POLARIS_USE_REAL_PQC=1` and liboqs, writes a 32-byte SHA3-256 placeholder labelled `DETERMINISTIC-PLACEHOLDER-SHA3-256` that verifies against no key (real ML-DSA-65 is 3,309 bytes). This is the default in CI. Production fails closed at boot without real signing, and unnamed placeholder use warns loudly.

**Algorithm migration**

- A verifier cannot learn that an algorithm is deprecated. `deprecation_date` reaches none of the twenty signed formats; the registry publishes bare names, the trust list carries per-key status only, and the detached verifier's accepted set is hardcoded, so retiring or adding an algorithm is a software release to every relying party.
- Key revocation does not substitute: if the assumption breaks, an attacker forges under any key the trust list calls active, and there is no algorithm-level lever.
- Mid-migration, a relying party that drops the old algorithm at 90 percent re-signed locks out one holder in ten, and no signed artifact tells it which fraction it is at (`lab/crypto-migration/algorithm_status.py`).
- There is no rollback. `one_signature_per_algorithm_per_token` forbids returning a token to an algorithm it already used; the only move is sideways to a third algorithm that must already exist, be keyed and not be deprecated, so a spare algorithm is a planning prerequisite (see [design/multi-sig-migration.md](design/multi-sig-migration.md)).
- A real population's migration rate and the cost of re-signing at scale are deployment facts this repository cannot measure.

**Unlinkability and correlation**

- Against colluding verifiers pooling full transcripts, a withheld-credential presentation gives no advantage beyond the anonymity set, and N is the epoch's membership. `committed_count` may be anywhere from 1 to 10,000, so a three-member epoch gives a one-in-three guess and a one-member epoch identifies the holder; nothing requires a relying party to read the count and no verdict mentions it.
- Timing, repeat-visit patterns and network metadata are not modelled, and the measuring adversary matches exact equality only: the result says no field is identical across verifiers, not that none is correlated.
- Transcript length is a channel. A bounded presentation sits at chance only while it carries no per-holder variable-length field; the wallet's authenticity pack (free-text issuer name, unpadded token id) reaches 5.6 times chance, which matters once a pack rides alongside a withheld credential.
- The OpenID4VP path discloses attribute values: over 200 holders an SD-JWT VC presentation falls into 16 holder-stable lengths, and one observation narrows 200 holders to about 23.
- Relying-party correlation is bounded, not eliminated: a full presentation shows a stable token value.
- Holder-side mechanisms do not hide a holder from the ISSUER. A credential may carry a holder key, and epoch leaves are Poseidon commitments opened on the holder's device with a per-relying-party nullifier, but the issuer derives every leaf.

**Duress**

- The mechanism is duress-aware only. It works against a coercer who does not know it exists, not one watching the holder, and against lawful or institutional access it is net-negative because the duress record is append-only (`lab/duress/`).

**Retention and records**

- The timestamp authority keeps no per-request record except one digest and one instant per anchored timestamp, and only when the caller asked for the anchor.
- Retention ships at five years for every class. Polaris records a jurisdiction's decision and its justification; it does not know the law.
- Warrant-audit statistics rest on the authority's own append-only log, which defends against revision, not omission; no outside reader can detect an access that was never recorded.
- Edits to a person's non-credential fields (legal name, date of birth, jurisdiction) are not recorded: an admin can rectify them through the operator UI and nothing keeps the prior value ([PRIVACY.md](operator/PRIVACY.md)).

**Authorization and operators**

- The operator a rule names is the operator the application names. Procedures enforcing rules about people (four-eyes, the recovery ceremony's distinct roles) take the actor as a user id parameter, because every operator reaches the database through one application role; a holder of that database credential can name any operator and satisfy a four-eyes rule alone.
- Closing that needs a per-operator database identity or operator-signed decisions checked outside the application; neither is built. The defence against a compromised application is its audit record and evidence held outside the database.
- Role reach: `investigate_individual` and `investigate_token` need a session but no role, so an `operator` can retrieve a holder's tokens and non-zero-knowledge verification history, including textual `requestor_location`. Every access is audited and no zero-knowledge event or coordinates are returned; whether investigation is an oversight or operational function is the deploying organization's call.
- Admin accounts created before both provisioning paths set a WebAuthn deadline carry none; `scripts/polaris-set-webauthn-deadline.sh` sets one and [OPERATIONS.md](operator/OPERATIONS.md) lists who is affected.

**Verifiers and SDKs**

- Six signed fields are verified but not surfaced or acted on: `epoch_number` on a revocation feed (a regressing `epoch_number` with advancing `as_of` is accepted), `purpose` on a signed document (a signature made for one purpose can be read as authorization for another), `auth_time` (no `max_age` can be derived), `authorized_via`, `bound_at` and `revoked_at`.
- The canonical form distinguishes `4` from `4.0` and JavaScript has one number type, so the TypeScript SDK cannot check a grant whose monetary limit is signed as a float; its verdict says so.
- Where each security decision is made is in [reference/SECURITY-DECISIONS.md](reference/SECURITY-DECISIONS.md).

**Application surface**

- The 400/404 surface is measured and open: 35 of 76 malformed-input and not-found refusals survive mutation. Of 32 probed, 27 are masked by a later guard; cases the probe cannot reach while signed in report as unprobed.
- Of fourteen rate limiters, the login and five holder-facing ones are driven by tests; the coarse velocity bounds (120 to 600 per minute) are pinned structurally, which proves the guard is written, not that it fires.

**Capacity and availability**

- `Individual.individual_id` and `IdentityToken.token_id` remain 32-bit, about 29 years at the stated enrollment rate, and widening them touches foreign keys across the schema; `check_capacity_model` recomputes the arithmetic from the live schema on every push.
- Every core count is extrapolated from one core; linear fan-out has never been run. On one core ([lab/evaluation](../lab/evaluation/README.md), 2026-09-27) the liboqs witness verifies in 122 us at p50 (about 8,200/s, the path the application uses) and the Python SDK's OpenSSL witness, all a plain install gets, in 1.21 ms (about 826/s). End to end, `POST /api/v1/verify` served 155 to 165 per second on one 8-core machine with 4 or 8 workers; the signature was under 1% of each request, and a new database connection per statement (three per verification) was most of it.
- 99.99% availability is not validated. The HA drills run a two-member topology on CI hardware, and latency on that topology supports a p50, not a p99.
- The edge is a single host: recreating it is a 0.3 s window and a configuration reload may drop one in-flight request. Closing this needs a second edge with a moving address, which is placement and DNS.
- Under the HA profile a lost database leader is replaced within its 20 s lease, a planned switchover is a 3.4 s outage and a leader that loses its lease store stands down in 7 s. Without the profile a database crash is a 0.6 s window.

## Decisions only the operator can make

Production with real identity data cannot proceed until each is recorded as made for a named deployment.

| Decision | Options | Where documented |
|---|---|---|
| Legal basis, DPIA, regulator approval | Named controller, jurisdiction, counsel-drafted DPIA, regulatory sign-off | Not an engineering task |
| Signing-key custody | `file`, `pkcs11` (CI-tested against a real token) or `kms` driver; the HSM or KMS; key holder; rotation authority | [KEY-CEREMONY.md](operator/KEY-CEREMONY.md) |
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

## Deployment-scale gaps

This ledger covers one authority on one host or one cluster. [ROADMAP.md](../ROADMAP.md) tracks the rest; a closed ledger here is not readiness for any of it:

- External penetration test (P1.12).
- Partitioning, HA automation and multi-region (P2).
- Relying-party API and federation protocol (P3).
- Hardware token and enrollment kit (P4).
- Pilots (P5), certification (P6) and national rollout (P7).

## Operability gate

Whether an operator who is not the author can install, run, upgrade and recover Polaris, one criterion per row ([lab record 017](../lab/strategy/017-production-operability.md)). A PASS row cites evidence that `check_operability_gate` resolves: a check, a test, a drill or a file. This gate is about operating the software; it is not readiness for real identity data, which the status line above and the last row keep separate.

28 criteria: 19 PASS, 7 PARTIAL, 2 FAIL, 0 UNKNOWN.

| ID | Criterion | Status | Evidence |
|---|---|---|---|
| OP-1 | Installed from published, signed release artifacts, with no source build | FAIL | The signed release workflow exists (`check:release_images_signed`); no image or chart is published yet. |
| OP-2 | A fresh host reaches HTTPS and a verified credential in 15 minutes or less, with five operator inputs or fewer | PARTIAL | `drill:lab/strategy/006/try.sh` reaches a verified credential, building from source on localhost. |
| OP-3 | Every setting is validated at boot, and a wrong one stops it by name | PASS | `check:config_schema_covers_env`, `test:polaris_web/test_app.py::ConfigSchemaTests`, `test:polaris_web/test_app.py::F05_ProductionSecretGuardTests` |
| OP-4 | Readiness reflects what this instance can serve, and a shared failure does not empty the pool | PASS | `check:health_liveness_readiness_split`, `test:polaris_web/test_app.py::HealthEndpointTests` |
| OP-5 | An instance crash costs no request | PASS | `drill:scripts/polaris-rolling-drill.sh` |
| OP-6 | A database failover loses no acknowledged write | PARTIAL | `drill:scripts/polaris-failover-drill.sh` measures a 3.3 to 20 s write outage; replication is asynchronous by default. |
| OP-7 | The loss of a host or zone is tolerated | PARTIAL | `check:failure_domains`: on Kubernetes the chart spreads every replicated component across nodes and zones, runs two pods of each hop on the data path, moves pods off an unanswering node after 30 s and Redis with them; `drill:scripts/polaris-zone-loss-drill.sh` kills the leader's node, then Redis's, on a three-zone kind cluster, and has yet to pass in CI. The Compose profiles run on one host, where a host's loss is a restore (DR.md section 4.3). |
| OP-8 | Internal services authenticate one another | PASS | `check:redis_authenticated`: the cache refuses unauthenticated clients and scopes the app's user; `check:ha_internal_auth`, `drill:scripts/polaris-failover-drill.sh`, `drill:scripts/polaris-region-evacuation-drill.sh`: the HA lease store (etcd) authenticates its clients and fences Patroni's user to its keys, and Patroni's REST API refuses unauthenticated writes from the app's network, in both regions of the DR overlay. The database, its pooler and replication take passwords. |
| OP-9 | Secrets are least-privilege and sealed at rest | PARTIAL | `check:secrets_reach_only_their_readers`, `drill:scripts/polaris-helm-drill.sh`: each container and pod mounts only the secrets it reads, the chart's at 0440; `check:secrets_lifecycle_sealed`: an age or KMS sealed store, unsealed into a tmpfs at start, is drilled in CI, but the default backend keeps the secrets in a 0700 directory on disk. |
| OP-10 | Signing keys can live in hardware or a KMS, shown on a real device | PARTIAL | `test:polaris_web/test_custody.py` runs PKCS#11 against a software token and KMS against a stand-in. |
| OP-11 | Restores are verified on a schedule and the evidence is current | PASS | `check:restore_verified_on_schedule`, `drill:lab/strategy/006/restore.sh`: on a Compose or host install, the deployment's newest backup is restored into a scratch copy and proven against the live database, at the first deploy and weekly by timer. Each verified restore is recorded, and `PolarisRestoreUnverified` pages at 8 days. CI proves the refusals: an archive that is not current, a copy that differs, a damaged repository. The chart schedules no such check yet (its archiving is opt-in, OP-14). `drill:scripts/polaris-dr-drill.sh` measures RPO and RTO monthly; its ledger reaches `main` by pull request. |
| OP-12 | A restore to a chosen point in time is tested | PASS | `drill:scripts/polaris-pitr-drill.sh`, `check:pitr_drilled` |
| OP-13 | Revocations made after a restore point are re-applied after the restore | PASS | `drill:scripts/polaris-pitr-drill.sh` (`--reconcile`), `file:scripts/polaris-reconcile-restore.py`, `check:restore_reconciled` |
| OP-14 | Continuous archiving is on by default, with an offsite copy | PARTIAL | `check:pgbackrest_scaffolding`: archiving on by default, the stanza made at the first init, a first full backup at deploy and scheduled ones after; `drill:scripts/polaris-offsite-drill.sh` round-trips the offsite repository, which needs the operator's bucket: by default the repository is local. |
| OP-15 | Backup age, archive failure, replication lag, disk, certificate expiry and clock skew alert | PASS | `drill:lab/strategy/006/alerts.sh` fires the certificate, backup and archive alerts on their real conditions and clears them on repair; `check:infra_alerts` pins all six rules and their promtool tests. |
| OP-16 | Application metrics, alerts and traces are tested | PASS | `drill:scripts/polaris-page-drill.sh`, `drill:scripts/polaris-trace-drill.sh` |
| OP-17 | One command names the failing component | PASS | `drill:lab/strategy/006/doctor.sh`, `check:doctor_names_failures` |
| OP-18 | Schema migrations run on every upgrade path | PASS | The host deploy script runs them (`check:upgrade_drilled`); a Helm upgrade runs them in a pre-upgrade Job (`check:helm_upgrade_migrates`, `drill:scripts/polaris-helm-upgrade-drill.sh`). |
| OP-19 | An upgrade from the previous release is drilled | PASS | `drill:scripts/polaris-upgrade-drill.sh` upgrades the previous release's Compose stack as OPERATIONS.md says (`check:upgrade_drilled`); `drill:scripts/polaris-helm-upgrade-drill.sh` upgrades its chart on kind (`check:helm_upgrade_migrates`). |
| OP-20 | The data-integrity rules (C1 to C10) are enforced in the schema and mutation-tested | PASS | `check:aor_append_only_triggers`, `check:one_active_token_index`, `drill:scripts/polaris-constraint-mutation-drill.py` |
| OP-21 | Two independent ML-DSA implementations agree at issuance | PASS | `check:pqc_second_witness` |
| OP-22 | A signature-algorithm migration is drilled | PASS | `drill:scripts/polaris-quantum-event-drill.py` |
| OP-23 | A same-algorithm signing-key rotation is drilled end to end | PASS | `drill:lab/strategy/006/rotate.sh`, `check:key_rotation_drilled` |
| OP-24 | Throughput is measured and a sizing guide is published | PASS | `drill:scripts/polaris-throughput-measure.sh`, `check:throughput_measured`: online verifications a second through the production path, every answer read, per app vCPU and across replicas, with each tier's CPU per verification, weekly on a CI runner; `file:docs/reference/SCALING.md` sizes a deployment from it and names what is not measured (a database on its own host, more than two replicas, other hardware). `file:docs/reference/BENCHMARK.md` measures the cryptography. |
| OP-25 | Horizontal scaling is measured | PARTIAL | `drill:scripts/polaris-throughput-measure.sh`: on one host, two app replicas served 1.93 times one while the app tier bound, and a second replica added 13% once the database had taken the rest of the host; scaling across hosts is not measured. |
| OP-26 | The client address is correct behind load balancers and NAT | PASS | `drill:scripts/polaris-client-ip-drill.sh`, `check:client_ip_behind_proxies`, `check:edge_settings_reach_the_edge`: the client's own address behind an L7 balancer the operator names, and behind an L4 balancer that rewrites source addresses and sends a PROXY protocol header; forged headers and forged PROXY lines refused, directly and through the balancer. The metrics surfaces are refused through an SNAT hop (`drill:scripts/polaris-metrics-edge-drill.sh`). |
| OP-27 | Contributors need no Kubernetes | PASS | `file:Polaris.command` |
| OP-28 | Real identity data | FAIL | Needs an external security review, the operator's DPIA and a pilot (above). |

## What is already production-grade

- **ZK stack**: a Plonky2 transparent-setup Merkle-inclusion circuit verified at use on `/api/zk/verify` with single-use nonces, plus an independent Python Poseidon/Merkle witness.
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
