# docs/design/: why it is built this way

**Reader:** an engineer or an assessor who has read what Polaris does and now
wants to know how a specific guarantee is actually held up.
**Job:** one record per mechanism, written when the mechanism was designed and
kept beside the code it describes.

These documents were filed under `DEVNOTES/` until v9.224, where an assessor
would not have looked for them. Nothing here is a runbook: for operating a
deployment see [operator/](../operator/README.md), and for the API, the schema
and the posture documents see [reference/](../reference/README.md).

## Cross-cutting

| Document | What it answers |
|---|---|
| [threat-model.md](threat-model.md) | Which adversaries, reaching which surfaces, and what is deliberately out of scope |
| [audit-of-record.md](audit-of-record.md) | Why the audit tables are append-only at the database, and what that costs |
| [concurrency.md](concurrency.md) | Every race-prone path, the lock that serialises it, and the test that proves it |
| [substrate.md](substrate.md) | Every primitive Polaris depends on, across its cryptographic, storage, network, runtime, hardware and human layers |
| [two-witness-principle.md](two-witness-principle.md) | Why no cryptographic verdict is trusted from a single implementation |
| [zk-soundness.md](zk-soundness.md) | What the words proof and zero-knowledge are allowed to mean here |
| [observability.md](observability.md) | What a running deployment tells its operator, and through which surface |
| [rasp-rules.md](rasp-rules.md) | The runtime self-protection rules, implemented and gaps alike |
| [rate-limiter.md](rate-limiter.md) | The per-IP defence, its backend, and its failure mode |
| [atlas-scaling.md](atlas-scaling.md) | How the map stays bounded as the event log grows |
| [athena.md](athena.md) | The read-only authority-and-constitution layer: why an agency may issue, what enforces each rule, what breaks if a key is retired, and why person-legibility is structurally impossible |
| [retention.md](retention.md) | How long the record is kept, who decided that, and why the purge obeys it |
| [partitioning.md](partitioning.md) | Why the event tables are monthly-partitioned, how C1 holds across attach and detach, and the online conversion |
| [bulk-enrollment.md](bulk-enrollment.md) | How a whole population is issued set-based in one atomic transaction, every row still through the full constraint set |
| [verification-scaling.md](verification-scaling.md) | Taking real ML-DSA-65 verification from hundreds to thousands/sec: single-witness verify-at-use, why it is sound, and how it fans out across workers and HA replicas |
| [offline-verification.md](offline-verification.md) | Verifying authorization with no connectivity (P3.6): the short-lived signed status assertion, what a verifier MUST check, and the freshness and replay bounds |

## One mechanism each

| Document | The mechanism |
|---|---|
| [duress-codes.md](duress-codes.md) | The compulsion-resistant verification path |
| [recovery-ceremony.md](recovery-ceremony.md) | Recovering an identity without a single point of compromise |
| [federation.md](federation.md) | Cross-agency trust, recorded explicitly, never transitive |
| [federation-topology.md](federation-topology.md) | The topology decision record (ADR, P3.1): federated per-authority instances over a central instance, why the constitution forces it, and the threat-model delta |
| [inter-authority-protocol.md](inter-authority-protocol.md) | The inter-authority protocol v1 (P3.2): the signed federation manifest (anchor cross-publication + attestation exchange), how a relying party accepts a foreign credential offline, and what is deferred |
| [issuer-discretion.md](issuer-discretion.md) | The ceiling on what an issuing agency can do at scale |
| [multi-sig-migration.md](multi-sig-migration.md) | Moving a token to a new signature algorithm with no gap |
| [token-signature.md](token-signature.md) | How a signature is produced, stored, and verified across rotation |
| [zk-snark.md](zk-snark.md) | What the Plonky2 circuit proves, and the witness that checks it |
| [anchoring.md](anchoring.md) | Committing a batch of audit rows to an external anchor |
| [tiered-enrollment.md](tiered-enrollment.md) | The evidence tiers behind an issued token |
| [webauthn.md](webauthn.md) | Operator credentials, enforcement, and the grace period |
| [abuse-controls.md](abuse-controls.md) | The per-agency quotas and what a refusal looks like |

The proof that the zero-knowledge redaction holds against an explicit
adversary, rather than merely storing a NULL, is
[meta/redaction-proof.md](../../meta/redaction-proof.md).

**On accuracy.** These were working notes before they were documentation, and
rewriting them found drift as well as tone: a second witness one document said
did not exist, a table shape another described that never existed, a rule
catalogue built on apparatus removed at v9.55, and a dependency manifest
listing a library deleted three versions ago. Every SQL object, test, route
and environment variable cited here was checked against the tree at the time
of writing. Where a record states a limit, the limit is real; where it states
a gap, the gap is open.
