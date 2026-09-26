# Production readiness

The bound on every claim in this repository, for the operator or assessor deciding whether
Polaris could hold real identity data. Status, known limitations, the operator's decisions, the gaps.

**Status (v1.0.0-rc.62): not production-ready for real identity data.** Every engineering gap
this ledger enumerated is closed and pinned by a check; what remains is the limitations and
operator decisions below and the deployment-scale work in [ROADMAP.md](../ROADMAP.md).

## Known limitations

**Scope and evidence**

- It has never held real identity data; every number here was measured on notional data, on CI hosts or a kind cluster, not production multi-node hardware.
- No external party has audited it. The one certification is narrow: `polaris-oid4vp 1.0.0rc7` is OpenID Certified to the OpenID4VP 1.0 + HAIP 1.0 Verifier profile (2026-09-24), which says nothing about readiness for real identity data.
- The protocol layer (registry, trust list, exchange gateway and receipts, timestamp authority, document signing, auth broker, wallet presentations, algorithm versioning) is conformant in both SDKs under the repository's own suite only, and frozen at version 1.
- Conformance is a floor. It constrains what its weakest conforming verifier computes: 43 verdict fields are unconstrained by any case, and SDK refusals on inputs no case contains are covered by the SDKs' own tests, not by conformance.
- The physical layer is a specification, an emulator and published vectors, not a card. No card is manufactured, no silicon is certified, and the profile states which properties an emulator cannot establish.
- Enrollment records the evidence it rested on and derives the assurance level from it, but no proofing has been performed with it, and document authenticity is taken on the operator's word.
- The NIST 800-63 mapping is machine-checked and is not a conformance claim. No assessment has taken place and a deployment inherits none of it.
- Accessibility is enforced only for the third that automation covers; accessibility conformance is not established.

**Cryptography**

- What is defensible is **algorithm agility under an audited migration path**, not a security claim against quantum adversaries. ML-DSA-65 rests on the hardness of Module-LWE and Module-SIS; the failure modes are a cryptanalytic advance against those assumptions or an implementation flaw. SLH-DSA-128s and SLH-DSA-256s are registered with no signer as a hash-based fallback, and issuance requires two independent ML-DSA implementations (liboqs and OpenSSL through `cryptography`) to agree.
- A break in Module-LWE needs no schema change, verification-path code change or new trust model: register a replacement, authorize it per authority through `AgencyAlgorithmAuth`, and migrate through `uc6_migrate`, a path exercised on every push. It still costs every credential issued under the broken algorithm.
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
- Every core count is extrapolated from a one-core measurement (about 7,848 verifications per second); linear fan-out has never been run.
- 99.99% availability is not validated. The HA drills run a two-member topology on CI hardware, and latency on that topology supports a p50, not a p99.
- The edge is a single host: recreating it is a 0.3 s window and a configuration reload may drop one in-flight request. Closing this needs a second edge with a moving address, which is placement and DNS.
- Under the HA profile a lost database leader is replaced within its 20 s lease, a planned switchover is a 3.4 s outage and a leader that loses its lease store stands down in 7 s. Without the profile a database crash is a 0.6 s window.

## Decisions only the operator can make

Production with real identity data cannot proceed until each is recorded as made for a named deployment.

| Decision | Options | Where documented |
|---|---|---|
| Legal basis, DPIA, regulator approval | Named controller, jurisdiction, counsel-drafted DPIA, regulatory sign-off | Not an engineering task |
| Signing-key custody | `file`, `pkcs11` (CI-tested against a real token) or `kms` driver; the HSM or KMS; key holder; rotation authority | [KEY-CEREMONY.md](operator/KEY-CEREMONY.md) |
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
