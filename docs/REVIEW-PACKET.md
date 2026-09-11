# External review packet

**Reader:** the reviewer, assessor or red teamer who has been handed this repository and has to
decide where to spend their attention. **Job:** say what each subsystem is supposed to guarantee
and what holds it, state the limitations bluntly enough to be useful, and hand over the specific
attacks the maintainers would most like to see attempted.

**Status:** a packet, not a certificate. Every mechanism cited below exists and passes CI today;
none of it has been reviewed by anybody outside this repository. That is the gap this document
is written to close, and until it closes the honest summary is that a system has checked itself.

This is the **what to attack** companion to [RED-TEAM-SCOPE.md](RED-TEAM-SCOPE.md), which
defines the engagement, and to [design/threat-model.md](design/threat-model.md), which is
organised by STRIDE category rather than by subsystem.

Every citation here resolves and every cited check runs, verified on every push by
[`scripts/polaris-review-packet-drill.py`](../scripts/polaris-review-packet-drill.py). The
limitations are checked in the other direction too: each carries a WITNESS, and if a limitation
stops being true the drill fails and the entry has to be removed. A limitations list that can
only grow is a confession; one that is checked both ways is a record.

---

## 1. Threat matrix by subsystem

Each row: what an attacker wants from this subsystem, what stands in the way, and what does
not. The last column is the one worth reading.

| Subsystem | What an attacker wants | What stands in the way | What does NOT |
| --- | --- | --- | --- |
| Issuance | a credential that verifies under the authority's key without the authority having issued it | Two independent implementations must agree on every signature before it persists, and a disagreement fails closed rather than picking a winner: `check:pqc_second_witness`, `check:pqc_real_signing`, `check:signature_self_contained_verify` | Nothing here stops an authority issuing a credential it should not have. The two-witness rule is about correctness of the signature, not legitimacy of the decision. |
| Verify-at-use | acceptance of a revoked, expired or forged credential | Signature verification under the declared algorithm, status checked against a published epoch, and an anti-replay binding: `check:verify_enforced`, `check:zk_verify_anti_replay`, `check:offline_verification` | A verifier holding a stale epoch accepts a credential revoked since. Freshness is a distribution problem, and the bound is the publication cadence, not a cryptographic one. |
| The audit-of-record | to erase the evidence that the system did something | `UPDATE` and `DELETE` are revoked at the database and a trigger refuses them, with a single GUC-gated carve-out for the archive path: `check:aor_append_only_triggers`, `check:aor_privilege_boundary`, `check:purge_binds_archive_to_database` | A superuser on the database host is outside this boundary entirely. The guarantee is that the APPLICATION cannot erase, not that nobody can. |
| Warrant-authorized history (UC-7) | one named person's whole verification history, without leaving a trace | The read now writes an `AuditAccessLog` row, and a structural rule extends that to any read hidden behind a stored procedure: `check:audited_reads_are_logged`, `check:transparency_program` | Nobody outside the authority can detect an access that was never recorded. The append-only log makes tampering hard; it cannot make omission visible. |
| Revocation | to revoke a population, as coercion or sabotage | A per-agency rolling rate bound, with a second authority required to co-sign past it: `check:abuse_controls`, `drill:scripts/polaris-pilot-winddown-drill.py` | Two colluding authorities clear the bound. The control raises the cost of coercion and does not remove it. |
| Zero-knowledge verification | to link a ZK verification back to the person who presented | A ZK event carries `token_id = NULL`, so it joins to no individual by construction, and the Atlas cannot locate one: `check:c2_zk_token_null`, `check:c6_atlas_redacts_zk_location`, `check:scoped_nullifier` | Traffic analysis outside the database is untouched: who connected, from where, and when is a network property this schema has no opinion about. |
| The transparency log | to show two different histories to two different observers | Append-only proofs, independent monitors, witness cosignatures over a threshold, and a non-repudiable equivocation proof: `check:transparency_log`, `check:transparency_gossip`, `check:transparency_publication` | A split view needs K witnesses to equivocate rather than one log. That raises the bar; it does not make equivocation impossible, and K is a deployment choice. |
| Key custody | the authority's private signing key | The key never leaves the custody boundary, and the PKCS#11 path signs in-token: `check:key_custody_abstraction`, `check:signing_key_generation`, `check:secrets_lifecycle_sealed` | The default file backend is a reference convenience, and the KMS is a stand-in. See limitation L-5. |
| Duress | to learn that a holder entered a duress code | The duress comparison is unconditional and the response is byte-identical in shape and length: `check:duress_on_card`, `check:duress_alertable`, `drill:scripts/polaris-duress-timing-drill.py` | A coercer who can observe the ALARM's downstream effects (a police response) learns what the card would not tell them. The indistinguishability is local to the exchange. |
| Federation and the trust list | to impersonate another authority to a verifier | Signed trust lists, an append-only key register with honest statuses, and directional trust: `check:trust_lifecycle`, `check:federation_real`, `check:exchange_trust_directional` | A verifier that does not check the trust list gets no protection from it. This is a protocol guarantee, not an enforcement one. |
| Enrollment proofing | a credential at a higher assurance level than the evidence supports | The IAL is DERIVED from the evidence rather than claimed, and a named set of fields is refused outright: `check:enrollment_proofing`, `check:assurance_mapping` | Nothing here validates that the evidence presented was genuine. Document authenticity is the enrolling operator's problem and this system takes their word. |
| The card | to clone a card, or to correlate two readings of one | On-card key generation, fixed-length responses, and per-verifier pairwise handles: `check:card_profile`, `check:card_emulator`, `check:pairwise_presentation` | A reading that checks AUTHORIZATION becomes credential-linkable, because a status assertion names the token. Only handle-only reads stay pairwise, and `check:verifier_device` reports which happened. |

---

## 2. Known limitations

Each carries a `witness:` -- a file and a string that must still be present for the limitation to
be true. When the limitation is fixed the witness fails, the drill fails, and the entry has to be
removed. That is the point: a list of limitations nobody can forget to update.

| # | Limitation | Witness |
| --- | --- | --- |
| L-1 | **It has never held real identity data, and the physical token it models is not manufactured.** Every number in this repository was measured on notional data. | `witness:README.md::never held real identity data` |
| L-2 | **99.99% availability is not validated and cannot be, from what is measured here.** What exists is a rolling deploy that drops zero verifications and a failover that induces four failures and recovers, on a TWO-MEMBER topology on CI hardware. A four-nines figure extrapolated from that would be an assertion wearing a measurement's clothes. | `witness:polaris_web/capacity.py::UNVALIDATED_LINKS` |
| L-3 | **Every core count is extrapolated from a one-core measurement.** Verification is measured at ~7,848/s on one core; that verification fans out linearly across cores and replicas is plausible, and the multiplication has never been run. | `witness:polaris_web/capacity.py::LINEAR_FANOUT` |
| L-4 | **Warrant-audit statistics rest on the authority's own log.** No reader outside the authority can derive them, and none can detect an access that was never recorded. The log is append-only, which defends against revision and not against omission. | `witness:polaris_web/transparency.py::SOURCE_OPERATOR_ATTESTED` |
| L-5 | **Key custody's production backends are abstractions over a stand-in.** The PKCS#11 path is exercised against a real token in CI; the KMS is a stand-in whose envelope cryptography is real and whose service is not. | `witness:polaris_web/kms_standin.py::stand-in` |
| L-6 | **The external transparency ledger backends are declared, not implemented.** The file backend is real and CI-tested; `algorand-pq` and `hyperledger-indy` are named and wait on their APIs. | `witness:scripts/polaris-transparency-ledger.py::declared but not implemented` |
| L-7 | **A sunset verdict refuses to be computed from what the issuer can see.** Whether relying parties accept the credential, and whether an alternate path exists and is usable, are operator attestations this system cannot verify. It refuses rather than guessing, which is correct and is still a gap in what can be checked. | `witness:polaris_web/coexistence.py::OPERATOR_ATTESTATIONS` |
| L-8 | **Verification latency on a real topology is a p50, not a p99.** The HA drill offers ~2 rps by design, so the sample supports a median and not a tail. The harness withholds percentiles the sample cannot carry rather than computing them anyway. | `witness:scripts/polaris-verify-load.py::PERCENTILE_FLOORS` |
| L-9 | **Two identifier columns remain 32-bit.** `Individual.individual_id` and `IdentityToken.token_id` last about 29 years at the stated enrollment rate -- outside the capacity model's horizon rather than comfortably beyond it -- and both are referenced by foreign keys across the schema, so widening them is a wider change than widening a surrogate. | `witness:polaris_sql/01_schema.sql::individual_id   SERIAL` |
| L-10 | **Document authenticity at enrollment is taken on the operator's word.** The assurance level is derived from what evidence was presented; nothing here establishes that the evidence was genuine. | `witness:polaris_web/proofing.py::FORBIDDEN_EVIDENCE_FIELDS` |
| L-11 | **No external party has reviewed any of this.** Every guarantee below is checked by machinery written by the same author as the guarantee. | `witness:docs/RED-TEAM-SCOPE.md::No engagement has been commissioned` |

---

## 3. Guarantee-attack prompts

The attacks the maintainers would most like to see attempted, each naming the guarantee, the
mechanism that is supposed to hold it, and what a successful attack would look like. A reviewer
who breaks any of these has found something worth the engagement.

| # | Guarantee | Mechanism | A successful attack produces |
| --- | --- | --- | --- |
| A-1 | A credential that verifies was issued by the authority whose key it names | two-witness signing, `check:pqc_second_witness` | a credential accepted by `verify_enforced` that the authority never issued, or a signature both witnesses accept that is not valid ML-DSA |
| A-2 | Nobody, including the operator, can erase what the system recorded | `check:aor_append_only_triggers`, `check:aor_privilege_boundary` | any application-reachable path that removes or alters an audit row without the GUC carve-out |
| A-3 | A zero-knowledge verification cannot be attributed to the holder | `check:c2_zk_token_null`, `check:scoped_nullifier` | a query, join or side channel inside the database that links a ZK event to an individual |
| A-4 | The log cannot show different histories to different observers undetectably | `check:transparency_gossip`, `drill:scripts/polaris-transparency-gossip-drill.py` | a split view that a threshold of witnesses accepts, or a rewrite that produces no equivocation proof |
| A-5 | One authority cannot revoke a population alone | `check:abuse_controls` | a path to mass revocation that does not cross the rate bound or the co-signer requirement |
| A-6 | A card tells a coercer nothing about a duress entry | `check:duress_on_card`, `drill:scripts/polaris-duress-timing-drill.py` | any observable difference -- timing, length, structure, error -- between a normal and a duress response |
| A-7 | Two verifiers cannot tell they read the same card | `check:pairwise_presentation`, `check:verifier_device` | correlation of two handle-only readings, or a linkable field the pairwise derivation fails to cover |
| A-8 | Every read of a person's history leaves a record | `check:audited_reads_are_logged` | a route that reads an audited table -- directly, through a procedure, or through a view -- and writes no `AuditAccessLog` row |
| A-9 | A published statistic does not disclose a small count | `check:transparency_program`, `drill:scripts/polaris-transparency-report-drill.py` | recovery of a withheld cell from a published report, or a series of reports whose combination recovers one |
| A-10 | The system cannot reach a state where a holder has no verifiable credential | `check:quantum_event_readiness`, `drill:scripts/polaris-quantum-event-drill.py` | a window, however brief, in which an ACTIVE credential verifies under nothing |
| A-11 | An offline verifier refuses a credential revoked before its epoch | `check:offline_verification`, `check:status_distribution` | acceptance of a credential whose revocation was published before the verifier's epoch |
| A-12 | The check layer detects its own violations | `check:controls_as_attacks`, `check:attacks_run`, `drill:scripts/polaris-check-mutation-drill.py` | a check that passes against a tree where the property it names is false. Part of this is now machine-checked: the mutation drill comments out every line carrying a check's own search strings and re-runs it. 71 of 75 checks survived that when it was written; **none do now**, and the drill gates at zero |

A-12 is still the one to start with. Every other guarantee on this page is believed because a
check says so, and the checks are written by the same hand as the code. If a check can be made
to pass on a broken tree, everything above it is worth less than it looks.

That was not rhetorical. Running the attack found that **71 of 75 checks passed on a tree where
the property they name had been commented out.** The cause was one line: the helper every check
reads files through handed them the comments along with the code, so the words survived where
the code did not. Stripping there fixed all 71, and the 58 detection-test fixtures that carried
their own property in a comment were repaired in the same ship -- a fixture that states its
property in a comment is testing the thing the drill forbids.

The drill now gates at zero on every push. **Its limits are where a reviewer should look
next:** nine checks read files the drill cannot enumerate, so they are skipped rather than
counted; it only mutates strings a check GREPS for, so a check that computes rather than greps
is untested by it; and it cannot tell a check that is vacuously true from one that is watching
something. Two checks were found passing because the mutation removed their subject entirely,
and there is no reason to think those were the last two.
