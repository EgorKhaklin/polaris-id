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
| [verifier-fuzz.md](verifier-fuzz.md) | How the detached verifier is held total against hostile input: the metamorphic fuzzer, what it found, and the fail-closed hardening it drove |
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
| [verifier-device.md](verifier-device.md) | The thing at the counter: what it reads over NFC and QR, the three facts it keeps apart, the replay a signature cannot refuse, the linkability an offline authorization check costs, and the measured QR ceiling |
| [card-profile.md](card-profile.md) | The physical card as an object somebody else can implement: the on-card data model, the dual-signature layout, PIN and duress semantics, succession, and the limits each of those has |
| [duress-codes.md](duress-codes.md) | The compulsion-resistant verification path |
| [recovery-ceremony.md](recovery-ceremony.md) | Recovering an identity without a single point of compromise |
| [federation.md](federation.md) | Cross-agency trust, recorded explicitly, never transitive |
| [federation-topology.md](federation-topology.md) | The topology decision record (ADR, P3.1): federated per-authority instances over a central instance, why the constitution forces it, and the threat-model delta |
| [inter-authority-protocol.md](inter-authority-protocol.md) | The inter-authority protocol v1 (P3.2): the signed federation manifest (anchor cross-publication + attestation exchange), how a relying party accepts a foreign credential offline, and what is deferred |
| [federation-status-bundle.md](federation-status-bundle.md) | The aggregate mirrored status feed (P3.2c): one short-lived signed artifact mirroring many authorities' feeds, why the aggregator is untrusted for correctness, and how a lying aggregator is defeated |
| [cross-authority-zk.md](cross-authority-zk.md) | Offline cross-authority epoch-bound ZK (P3.2d): a holder's zero-knowledge inclusion proof decided against a foreign authority's epoch through the trust graph, why the verifier shells to the polaris-zk binary, and why it abstains rather than false-accepts |
| [timestamp-transparency.md](timestamp-transparency.md) | Timestamp transparency (P8.5b): anchoring as the caller's choice into an append-only, witnessed timestamp log, so time evidence survives the authority's key being stolen; a quorum of independent authorities as the no-retention alternative; the retention trade-off stated |
| [protocol-versioning.md](protocol-versioning.md) | Protocol versioning, negotiation and cross-version compatibility (P8.8b): majors in the format string, minors advertised by the registry and never needed to verify, `400 unsupported_format_version` instead of guessing, version 1 frozen under checksums with a pinned older verifier, both directions proven on every CI run |
| [algorithm-migration.md](algorithm-migration.md) | Algorithm agility and migration (P8.8a): ML-DSA-65 and ML-DSA-87 accepted everywhere, ML-DSA-44 refused, the signing key decides each body's algorithm, migration as a key-lifecycle event, proven by two-algorithm vectors and a mixed-algorithm two-instance drill |
| [trust-lifecycle.md](trust-lifecycle.md) | The trust-service lifecycle (P8.7b): an append-only, one-way authority key register, honest statuses in manifests and the registry, a signed trust list a verifier decides key status at an instant from, and compromise recovery that rejects after and keeps before |
| [wallet-protocol.md](wallet-protocol.md) | The wallet protocol surface (P8.6): the offline-decidable presentation (credential + stapled status assertion, optional ZK proof, opaque code never interpreted) and digest-tied QR/NFC framing, with native clients and the browser bridge recorded as boundaries |
| [per-authority-isolation.md](per-authority-isolation.md) | The review of what one authority's operators can see of another's: sixteen of 74 operator routes read credential data unscoped, the row-level policies added where authority ownership is well-defined, and the part that cannot be fixed by adding policies, because a person is not owned by an authority |
| [vc-format.md](vc-format.md) | A verification RESULT in the W3C Verifiable Credentials data model: why it attests a result rather than an identity, why the cryptosuite names Polaris instead of falsely claiming a registered classical one, and why the canonicalisation is JCS rather than RDF |
| [mdoc-bridge.md](mdoc-bridge.md) | Rendering a credential in the ISO 18013-5 mdoc structure: what crosses (the format and selective disclosure) and what does not (the issuer signature, because it is ML-DSA and the standard does not list it), why signing classically to fix that would defeat the point, and why the document never claims the mDL docType |
| [plonky2-to-plonky3.md](plonky2-to-plonky3.md) | The proof-library question, evaluated and decided: measured proving and proof size at national depth, why a migration is a rewrite of the soundness core rather than a version bump, why the two-witness model would largely survive it, what was deliberately NOT verified, and the triggers that would re-open the decision |
| [multi-region.md](multi-region.md) | The second region as a Patroni standby cluster rather than another member: why a cross-region member puts the WAN inside the quorum, what the standby shape buys, and the recovery point asynchronous replication does not eliminate, measured on every push rather than asserted |
| [status-distribution.md](status-distribution.md) | Serving a signed status through an untrusted network: why a cache directive is the artifact's own remaining life and never a constant, why stale-while-revalidate is refused, and which artifacts may be cached publicly versus which name one credential and are never stored anywhere |
| [epoch-cadence.md](epoch-cadence.md) | How often an authority closes an epoch and what the number costs: it sets revocation freshness, the size of the anonymity crowd and how often a relying party's one-human-once ledger resets, and those pull against each other; plus the measured cost of closing at the national tree depth, and why an epoch stores no inclusion path |
| [holder-side-keys.md](holder-side-keys.md) | The holder side (P9): the optional holder key and why its proof must not cover the presented code, proving locally against a published anonymity set, the scoped nullifier that lets one relying party refuse a second claim without learning who, the per-verifier handle that stops relying parties pooling what they store, and the delegated agent grant a person can revoke alone; each with the bound it does NOT clear |
| [auth-broker.md](auth-broker.md) | The auth broker (P8.4): authorization code + PKCE, a holder authenticating by possession, an issuing-agency-signed ID token whose subject is derived per relying party, ZK step-up, duress served identically, and the guards that keep the authority from holding a record of who logged in where |
| [document-signing.md](document-signing.md) | Document signing with long-term validation (P8.5): a digest-bound container signed by an institution or, on behalf of a possession-authenticated holder recorded by credential hash, by its issuing authority, with evidence fixed at the instant of signing so validity survives key retirement |
| [exchange-gateway.md](exchange-gateway.md) | The exchange gateway (P8.2d): how one institution's signed request is authenticated by key, authorized through the trust graph before forwarding, replay-guarded by an append-only nonce register, forwarded only to an operator-configured upstream, and receipted with the signed time, leaving no body behind |
| [registry.md](registry.md) | The signed registry (P8.3): what an instance offers and trusts as one artifact over the Athena authority layer, why it must be signed by the key it lists for its own publisher, and how a consumer discovers services and the in-context trust graph from it instead of configuration |
| [timestamp-authority.md](timestamp-authority.md) | The timestamp authority (P8.7a): an arbitrary digest bound to an instant under an authority's registered key, digest-only and unlogged so it learns and retains nothing, verified offline; the time primitive signing builds on and independent time evidence for any artifact |
| [exchange-receipt.md](exchange-receipt.md) | The exchange receipt (P8.2): signed evidence that an authorized institutional exchange occurred, committing to request/response by hash not content, why it is the anti-surveillance inversion of a message log, and how a third party verifies it without the payload |
| [issuer-discretion.md](issuer-discretion.md) | The ceiling on what an issuing agency can do at scale |
| [multi-sig-migration.md](multi-sig-migration.md) | Moving a token to a new signature algorithm with no gap |
| [token-signature.md](token-signature.md) | How a signature is produced, stored, and verified across rotation |
| [zk-snark.md](zk-snark.md) | What the Plonky2 circuit proves, and the witness that checks it |
| [anchoring.md](anchoring.md) | Committing a batch of audit rows to an external anchor |
| [transparency-log.md](transparency-log.md) | The public, append-only, RFC-6962-style log over the anchor roots (P3.3): the signed tree head and consistency proofs, what an independent monitor proves and what it does not, and the tampering drill |
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
