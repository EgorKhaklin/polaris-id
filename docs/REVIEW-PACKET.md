# External review packet

**Reader:** the reviewer, assessor or red teamer who has been handed this repository and has to
decide where to spend their attention. **Job:** say what each subsystem is supposed to guarantee
and what holds it, and hand over the specific attacks the maintainers would most like to see
attempted.

**Status:** a packet, not a certificate. Every mechanism cited below exists and passes CI today.

This is the **what to attack** companion to [RED-TEAM-SCOPE.md](RED-TEAM-SCOPE.md), which
defines the engagement, and to [design/threat-model.md](design/threat-model.md), which is
organised by STRIDE category rather than by subsystem.

Every citation here resolves and every cited check runs, verified on every push by
[`scripts/polaris-review-packet-drill.py`](../scripts/polaris-review-packet-drill.py).

---

## 1. Threat matrix by subsystem

Each row: what an attacker wants from this subsystem, what stands in the way, and what does
not. The last column is the one worth reading.

| Subsystem | What an attacker wants | What stands in the way | What does NOT |
| --- | --- | --- | --- |
| Issuance | a credential that verifies under the authority's key without the authority having issued it | Two independent implementations must agree on every signature before it persists, and a disagreement fails closed rather than picking a winner: `check:pqc_second_witness`, `check:pqc_real_signing`, `check:signature_self_contained_verify` | Nothing here stops an authority issuing a credential it should not have. The two-witness rule is about correctness of the signature, not legitimacy of the decision. |
| Verify-at-use | acceptance of a revoked, expired or forged credential | Signature verification under the declared algorithm, status checked against a published epoch, and an anti-replay binding: `check:verify_enforced`, `check:zk_verify_anti_replay`, `check:offline_verification` | A verifier holding a stale epoch accepts a credential revoked since. Freshness is a distribution problem, and the bound is the publication cadence, not a cryptographic one. |
| The audit-of-record | to erase the evidence that the system did something | `UPDATE` and `DELETE` are revoked at the database and a trigger refuses them, with a single GUC-gated carve-out for the archive path: `check:aor_append_only_triggers`, `check:aor_privilege_boundary`, `check:purge_binds_archive_to_database` | A superuser on the database host is outside this boundary entirely. The guarantee is that the APPLICATION cannot erase, not that nobody can. |
| Warrant-authorized history (UC-7) | one named person's whole verification history, without leaving a trace | The read now writes an `AuditAccessLog` row, and a structural rule extends that to every route returning a tracked table's rows, directly, through a stored procedure or through a view, while the SQL console reads as a role that holds none of those tables: `check:audited_reads_are_logged`, `check:transparency_program` | Nobody outside the authority can detect an access that was never recorded. The append-only log makes tampering hard; it cannot make omission visible. |
| Revocation | to revoke a population, as coercion or sabotage | A per-agency rolling rate bound, with a second authority required to co-sign past it: `check:abuse_controls`, `drill:scripts/polaris-pilot-winddown-drill.py` | Two colluding authorities clear the bound. The control raises the cost of coercion and does not remove it. |
| Zero-knowledge verification | to link a ZK verification back to the person who presented | A ZK event carries `token_id = NULL`, so it joins to no individual by construction, and the Atlas cannot locate one: `check:c2_zk_token_null`, `check:c6_atlas_redacts_zk_location`, `check:scoped_nullifier` | Traffic analysis outside the database is untouched: who connected, from where, and when is a network property this schema has no opinion about. |
| The transparency log | to show two different histories to two different observers | Append-only proofs, independent monitors, witness cosignatures over a threshold, and a non-repudiable equivocation proof: `check:transparency_log`, `check:transparency_gossip`, `check:transparency_publication` | A split view needs K witnesses to equivocate rather than one log. That raises the bar; it does not make equivocation impossible, and K is a deployment choice. |
| Key custody | the authority's private signing key | The key never leaves the custody boundary, and the PKCS#11 path signs in-token: `check:key_custody_abstraction`, `check:signing_key_generation`, `check:secrets_lifecycle_sealed` | The default file backend is a reference convenience, and the KMS is a stand-in. |
| Duress | to learn that a holder entered a duress code | The duress comparison is unconditional and the response is byte-identical in shape and length: `check:duress_on_card`, `check:duress_alertable`, `drill:scripts/polaris-duress-timing-drill.py` | A coercer who can observe the ALARM's downstream effects (a police response) learns what the card would not tell them. The indistinguishability is local to the exchange. |
| Federation and the trust list | to impersonate another authority to a verifier | Signed trust lists, an append-only key register with honest statuses, and directional trust: `check:trust_lifecycle`, `check:federation_real`, `check:exchange_trust_directional` | A verifier that does not check the trust list gets no protection from it. This is a protocol guarantee, not an enforcement one. |
| Enrollment proofing | a credential at a higher assurance level than the evidence supports | The IAL is DERIVED from the evidence rather than claimed, and a named set of fields is refused outright: `check:enrollment_proofing`, `check:assurance_mapping` | Nothing here validates that the evidence presented was genuine. Document authenticity is the enrolling operator's problem and this system takes their word. |
| The card | to clone a card, or to correlate two readings of one | On-card key generation, fixed-length responses, and per-verifier pairwise handles: `check:card_profile`, `check:card_emulator`, `check:pairwise_presentation` | A reading that checks AUTHORIZATION becomes credential-linkable, because a status assertion names the token. Only handle-only reads stay pairwise, and `check:verifier_device` reports which happened. |

---

## 2. Guarantee-attack prompts

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
| A-8 | Every read of a person's history leaves a record: a page or API that returns rows of `TokenLifecycleEvent`, `VerificationEvent`, `AuthAuditLog` or `DuressEvent` writes an `AuditAccessLog` row, and the SQL console reads none of the four and no count table, since a count cell can be one event (the Atlas withholds a count below five). A count over the four that a page shows returns no one's rows and is not recorded; tables outside the four that hold one person's rows, `TokenStateEpochLeaf` (which `/epochs` returns) among them, are outside this record | `check:audited_reads_are_logged`, `check:sql_console_readonly` | a route that returns rows of one of the four -- directly, through a procedure, or through a view -- and writes no `AuditAccessLog` row, or a console query that returns one of their rows or a count cell |
| A-9 | A published statistic does not disclose a small count | `check:transparency_program`, `drill:scripts/polaris-transparency-report-drill.py` | recovery of a withheld cell from a published report, or a series of reports whose combination recovers one |
| A-10 | The system cannot reach a state where a holder has no verifiable credential | `check:quantum_event_readiness`, `drill:scripts/polaris-quantum-event-drill.py` | a window, however brief, in which an ACTIVE credential verifies under nothing |
| A-11 | An offline verifier refuses a credential revoked before its epoch | `check:offline_verification`, `check:status_distribution` | acceptance of a credential whose revocation was published before the verifier's epoch |
| A-12 | The check layer detects its own violations | `check:controls_as_attacks`, `check:attacks_run`, `drill:scripts/polaris-check-mutation-drill.py` | a check that passes against a tree where the property it names is false. Part of this is now machine-checked: the mutation drill runs three mutations, commenting out a check's own search strings, deleting the files it names, and deleting the sentences it greps for from the documents it reads. 71 of 75 checks survived the first when it was written; **none survive the first two now**, the third fails any check that cannot tell a document it names from an empty file, and the drill gates on every push. What it cannot reach it counts, by cause, every run |

A-12 is the one to start with: every other guarantee on this page is held by a check, so a check
that passes on a broken tree is the finding worth most.

Running that attack found that **71 of 75 checks passed on a tree where
the property they name had been commented out.** The cause was one line: the helper every check
reads files through handed them the comments along with the code, so the words survived where
the code did not. Stripping there fixed all 71, and the 58 detection-test fixtures that carried
their own property in a comment were repaired in the same ship -- a fixture that states its
property in a comment is testing the thing the drill forbids.

The drill gates on every push, across THREE mutations. The first comments out every line carrying a
check's own search strings: none survive. The second deletes every file a check names and requires
it to notice, which is what reaches the ones that compute rather than grep: none survive, and it
found four passing vacuously when it was written, two of them constitutional. C10's money-table
prohibition and the canonical-version rule were both perfectly true of a schema and an `app.py` that
did not exist.

The third is aimed at the gap this paragraph used to send a reviewer to. A check that computes over
a file which is PRESENT but wrong was caught by neither of the first two, since one only removes
lines it can name and the other removes the file entirely. For DOCUMENTS the third mutation reaches
it: `#` in Markdown is a heading rather than a comment, so the first mutation had to skip every
check that reads one, and the third deletes the matching sentences and leaves the file there.

---

## 3. Broken on purpose

Each drill deletes or inverts one security control at a time and requires a test to go red. A
**survivor** is a control nothing noticed; a **declared** survivor is one the drill's source
names with the reason it is acceptable (a twin check refuses the same case, or a drill outside
the suites covers it). An undeclared survivor, or a declaration nothing needs any more, fails
the drill. Each row names the run its numbers were read from, a CI run unless it says otherwise;
they move as the tree does.

| Drill | What is broken, one at a time | Broken | Noticed | Declared survivors | Runs | Measured |
| --- | --- | --- | --- | --- | --- | --- |
| [constraint](../scripts/polaris-constraint-mutation-drill.py) | a named constraint or row-level security policy, dropped | 50 | 50 | 0 | every push | [36661832758](https://github.com/EgorKhaklin/polaris-id/actions/runs/36661832758) |
| [trigger](../scripts/polaris-trigger-mutation-drill.py) | a whole trigger, dropped | 54 | 54 | 0 | every push; exhaustive weekly | [36661832758](https://github.com/EgorKhaklin/polaris-id/actions/runs/36661832758) |
| [trigger `--refusals`](../scripts/polaris-trigger-mutation-drill.py) | one refusal inside a trigger function, deleted | 65 | 56 | 9: masked, a later check in the same function refuses the case | every push | [36661832758](https://github.com/EgorKhaklin/polaris-id/actions/runs/36661832758) |
| [procedure](../scripts/polaris-procedure-mutation-drill.py) | one refusal inside a stored procedure, deleted | 90 | 88 | 2: pre-lock copies whose twins under the row lock refuse | changed procedures per push; all weekly | [36269239522](https://github.com/EgorKhaklin/polaris-id/actions/runs/36269239522), the full sweep |
| [constitution](../scripts/polaris-constitution-mutation-drill.py) | the enforcement of one of C1 to C10, deleted | 10 | 10 | 0 | every push | [36661832758](https://github.com/EgorKhaklin/polaris-id/actions/runs/36661832758) |
| [application](../scripts/polaris-app-mutation-drill.py) | one 4xx/5xx refusal in the web application, switched off | 116 | 94 | 22: coarse rate limiters pinned structurally, gateway checks covered by the two-instance drill | weekly | a local run, 2026-09-27; the weekly sweep first runs 2026-10-01 |
| [SDK](../scripts/polaris-sdk-mutation-drill.py) | one refusal in either SDK or the detached verifier, inverted to accept | 178 | 162 | 16 | changed files per push | [36661944211](https://github.com/EgorKhaklin/polaris-id/actions/runs/36661944211) |
| [OpenID4VP](../scripts/polaris-oid4vp-mutation-drill.py) | one refusal in the OpenID4VP verifier, inverted to accept | 107 | 102 | 5 | every push to main; pull requests that touch the package | [36666780941](https://github.com/EgorKhaklin/polaris-id/actions/runs/36666780941) |
| [ZK](../scripts/polaris-zk-mutation-drill.py) | a ZK witness, disabled or weakened | 3 | 3 | 0 | every push | [36661832758](https://github.com/EgorKhaklin/polaris-id/actions/runs/36661832758) |
| [check layer](../scripts/polaris-check-mutation-drill.py) | an invariant check's search strings, commented out | 134 | 134 | 0 | every push | [36661832758](https://github.com/EgorKhaklin/polaris-id/actions/runs/36661832758) |

Across the nine rows measured in CI, 691 controls were broken one at a time: 659 turned a test
red and 32 are declared survivors; none is undeclared. Beside the drills, three attack suites
attempt 21 attacks that must fail (cryptography 9, access and audit controls 11, database 1), and
all 21 held in [run 36661832758](https://github.com/EgorKhaklin/polaris-id/actions/runs/36661832758). The attack runner refuses a suite without a positive
control, a defense defeated on purpose that must be reported broken, so a clean sweep is a result
the harness could have failed to give.

What this does and does not say:

- Every drill carries a negative control, a tree it must fail on, so a drill that could never
  report a survivor is itself caught.
- A control no drill mutates is not in this table: the mutations are the ones written down.
- "Noticed" means some test went red, not that the right test went red for the right reason.
- The application row was 116 examined, 44 survived, 25 of them undeclared, until 2026-09-27:
  no workflow ran that drill. Tests now cover the 25 and a weekly sweep keeps them covered.

## 4. Verified, not asserted

Counts of checks, tables, routes and CI jobs are re-measured by `polaris_checks` on every run; test counts are measured per release.

| Layer | Scale | What it proves |
|---|---|---|
| Product tests (live database) | 1245 | Constraints, use cases, routes, redaction, real-thread concurrency, the secret store |
| Crypto witnesses | 126 passing of 131 collected | ML-DSA across both witnesses and a software PKCS#11 module; Rust and Python epoch roots agree |
| Invariant checks | 344 | C1-C10 plus production posture, each with a detection test |
| CI jobs | 23 | Below |

Test counts: reference machine, v1.0.0-rc.62 (`pytest -q` per suite, 2026-09-26). The five skipped crypto tests need a PKCS#11 module or a real KMS key.

On every push, CI also boots the five-service production-profile stack, round-trips backups,
fails over the HA profile under writes, proves the post-quantum TLS handshake and real ML-DSA-65
signing, runs the federation and compatibility drills and the mutation drills, and gates on CVE
scans ([ci.yml](../.github/workflows/ci.yml)). What the mutation drills broke, what noticed and which run each number
is from: [the review packet](#3-broken-on-purpose).

```bash
python3 -m polaris_checks.run        # the invariant layer, no database needed
python3 scripts/polaris-ship.py run  # the full local gate, matching CI
```
