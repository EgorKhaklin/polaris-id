# Version 2 of the Polaris paper: what changed from Version 1

**Files.** `polaris_project_report_v2.tex` (the main document), `v2-sections/` (one file per
section and appendix), `v2-figures/` (one TikZ file per diagram plus the shared style
vocabulary), and the rendered `polaris_project_report_v2.pdf`. Version 1
(`polaris_project_report.tex` and its PDF) is preserved byte for byte.

**Source of truth.** The tree at tag `v9.345` (commit `c20a3d4`, 9 September 2026): the
schema, the checks, the design records under `docs/design/`, the reference set under
`docs/reference/`, MISSION.md, ROADMAP.md, PRODUCTION-READINESS.md, THESIS.md, and the
CHANGELOG entries of the self-correction episodes. Every count was re-measured by the
commands listed in the paper's Appendix C.

## Revision at v9.355: the holder-side sections

The body was written from `v9.345`. Between that tag and `v9.355` the repository shipped
Phase P9, which closed five absences this paper had recorded as open. Leaving the sections
as written would have made the paper a description of a system that no longer exists, so
these parts were rewritten and the rest was not:

| Rewritten | Why |
|---|---|
| §8.3, the membership proof | Said the prover runs on the Polaris host and there is no per-verifier nullifier. Both are now false. |
| §8.4, replacing "The thing that does not exist" | Called cross-verifier correlation a permanent, documented property. It is bounded now, and the section states both what changed and what did not. |
| §17, AI agents and proof of personhood | Opened "Nothing in this section is solved" and marked the nullifier, local proving, the pairwise handle and the agent grant as proposals. All four run. |
| `v2-figures/delegation.tex` | Drew the whole chain dashed as a proposal. Redrawn as built, with one dashed box for the residue that is not closed. |
| `v2-figures/present-future.tex` | Put the agent grant and proof of personhood in the "not implemented" panel. |
| Appendix A, the capability ledger | Four rows moved from proposal to running, each with the limit it still carries; a new row names the residue. |
| §20's closing sentence, §0's front matter | Both now state the two dates rather than one. |

**What was deliberately not done.** The counts elsewhere in the paper are still the `v9.345`
measurements and are labelled as such where they appear. Re-measuring the whole document at
`v9.355` would have been a different piece of work, and a partial re-measurement is worse
than an honestly labelled old one. A reader checking a count against the current tree should
expect it to have grown.

**What the rewrite refused to claim.** Every closed absence is paired with the bound it does
not clear. The nullifier does not hide the holder from the issuer, which derives every leaf
to build the tree. The pairwise handle bounds what a verifier *stores*, not what it is
*shown*, because a full credential still carries a stable token value. And the agent grant
hides the human from the agent's actions, not the credential from the service. The verifier
reports which of the two guarantees a given presentation actually gave, so a reader of the
code cannot assume the stronger one either.

## Structure: one coherent document, not an appendix of updates

Version 1 followed a database-design pipeline (requirements, ER model, relational model, SQL,
relational algebra, appendices). Version 2 is organised as a zoom from the credential core
outward, one ring per section, each ring introduced by the failure of the ring inside it:

1. The problem
2. How to read this map (the concentric model, the town analogy, the four status marks, the
   per-layer questions)
3. The core: one credential, one signature, one person
4. The walls: the schema as the security boundary
5. Authenticating truth: signatures, custody and two witnesses
6. Verification without the issuer: the detached verifier, the SDKs, the conformance contract
7. Verification is not authorization: status, revocation and the offline trade
8. The privacy boundary: what a verifier is allowed to learn
9. Using the credential: holders, relying parties and the login that keeps no record
10. Federation: independent authorities that recognise one another
11. Watching the watchers: logs, witnesses and the split view
12. Institutions: exchange, time and signatures without a message log
13. Surviving reality: the stack, failure, load and the standing witness
14. How Polaris observes and understands itself (Atlas, Athena, Metis, Themis)
15. Errors become new senses: the history of self-correction
16. What Polaris refuses to become
17. AI agents, proof of personhood and the future internet
18. Future research and engineering (presentation technologies, the holder key, Metis, Myrmex)
19. Current limitations and the external validation still required
20. Conclusion: the whole organism

Appendices: A, capability status at v9.345; B, the metacognitive map; C, counts and their
methods; D, glossary; E, from Version 1 to Version 2.

## Kept from Version 1

- The token-centred entity geometry, reproduced unchanged as `v2-figures/nucleus.tex` and used
  as the centre of the districts figure and the concentric map. The geometry is treated as the
  constant of the paper; rings are drawn around it, never through it.
- The lifecycle state machine, reproduced unchanged as `v2-figures/lifecycle.tex`.
- The disclosure-level argument, the post-quantum-from-day-one argument (Mosca's inequality)
  and the substrate argument, summarised with pointers to Version 1.
- The palette, typography and page design.

## Corrected against Version 1

- Twelve tables became thirty-six canonical tables (forty-three in a migrated deployment).
- The audit tables are append-only by trigger, not "by convention and tooling"; the lifecycle
  transitions are enforced by a trigger, which Version 1 recommended as future work.
- The ledger anchor is an off-chain commitment monitored as a transparency log; publication to
  an external chain remains an operator action with declared, unwired drivers.
- The physical token remains modelled and not manufactured and is marked as a proposal.
- The two speculative binding appendices (genomic and quantum-observer) are not carried forward
  as design; the repository quarantined the speculative schema.

## New diagrams (all TikZ, in `v2-figures/`)

core-to-shell (the concentric map), districts (36 tables as rings around the nucleus), town-map
(the walled town with the real component beside every civic name), holder-flow, offline-status,
federation, transparency, gateway, signing-chain, cognition, senses-loop, layer-ladder,
delegation, stigmergy, present-future; plus the two figures carried from Version 1.

## Vocabulary introduced

Four status marks on every capability: implemented, experimental, external validation required,
proposed. A layer card per ring answering the same eleven questions. A shaded "in the town"
paragraph for the analogy, always followed by the mechanism. A "therefore" step at the end of
each ring naming why the next ring exists.

## Claims deliberately qualified

The following stronger wordings were available in prose somewhere and were not used, because
the implementation at v9.345 does not support them.

| Stronger wording avoided | What the paper says instead | Why |
|---|---|---|
| "Unlinkable" or "anonymous" presentations | Issuer-side unlinkable verification records, scoped to zero-knowledge mode; cross-verifier correlation is a permanent documented property | A presentation carries a stable `token_value`; the login token's subject is the credential hash; no pairwise, blinded or one-time presentation exists |
| "A zero-knowledge identity system" | Two uses of zero knowledge (unlinkable records, a membership proof) and one thing that does not exist (selective disclosure at presentation) | The repository's own readiness pass split the claim the same way |
| "Proof of personhood" | Three ingredients exist (C3 uniqueness, membership proof, epoch revocation); the scoped nullifier, holder-side key and presentation layer do not | No nullifier is a public input; the prover runs on the host |
| "Decentralised" | Federated per authority, with no central store, root or verification service | Decentralisation of institutions is a deployment fact; two instances are run by one author |
| "Independent witnesses" | The witness protocol is built and drilled; the witnesses today are three processes in a drill | Institutional independence requires deployment |
| "An external implementation interoperates" | The specification and conformance suite exist; the integration has not happened | Marked as blocked on an external actor in the roadmap |
| "Production-ready", "nationally deployed" | Not production-ready for real identity data; notional data only; never deployed | The readiness ledger's own status line |
| "Audited cryptography" | Two-witnessed verdicts; no external cryptographic audit; the shipped proof configuration's bit security not independently derived | The soundness ledger says so |
| "Hardware-backed custody" | PKCS#11 proven against a software token in CI; no hardware module used | The readiness ledger and PQC posture |
| "Post-quantum throughout" | Post-quantum for the token, digests, proofs and the client-to-edge exchange; classical on two internal hops, the certificates and today's authenticators | The PQC posture ledger |
| "Verifications per second" | Three separate numbers: event ingestion, two-witness verification, single-witness verification; fleet numbers marked as projections | The v9.257 correction |
| "The duress path is undetectable" | A tested property of the modelled flow, not an audited side-channel guarantee; long-run frequency analysis accepted | The duress design record |
| "The recovery ceremony is fully enforced at the schema" | `RecoveryRequest` rests on procedure discipline for the decision fields | The audit-of-record record names it |
| "Attestations are signed by the attesting agency" | Attestations are recorded by an operator; agency-level signing is a future migration | The federation design record |
| "Formally proven" | Machine-checked invariants with detection tests; a TLA+ model of C3 as a demonstrator; the cold-read thesis inconclusive | THESIS.md and the roadmap's formal-methods row |
| "Anchored timestamps are verified by the SDKs" | Anchor verification lives in the detached verifier only | Roadmap P8.5c |
| "Metis", "Themis", "Myrmex" as components | Metis is a captured assessment brief; Themis is a reading aid for the constitution; Myrmex is proposed in this paper | None is code |
| National capacity numbers | Planning targets to be validated; a simulation at a scale factor; single-node measurements on one laptop | BENCHMARK.md and the roadmap say so |
