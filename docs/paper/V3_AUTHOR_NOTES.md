# Version 3 author notes: what the research found in the repository

These are places where a repository document is behind its code or its own history, found while
writing Version 3 against the tree at `1.0.0-rc.1`. None was changed for the paper; the paper
follows the code. Each is small and each is recorded so it is not lost. Version 2's notes
(`V2_AUTHOR_NOTES.md`) are kept beside this file; several of them are still open.

| Where | What it says | What the tree shows | Paper's choice |
|---|---|---|---|
| `ROADMAP.md`, "Do not have" | Lists "a holder-side key", "a scoped nullifier", "a presentation that carries no handle stable across verifiers", "a schema-enforced `RecoveryRequest`", "anchor verification in the SDKs" and "no delegation exists" as absent | All were built between `v9.346` and `v9.353` (P9) and `RecoveryRequest` is trigger-enforced since `v9.347`; the same file's "Have" paragraph describes them as shipped | The paper follows the code; the paragraph reads as a snapshot the later ships did not update |
| `ROADMAP.md`, inventory heading | "Where we are (inventory at v9.371)" | The paragraph carries `1.0.0-rc.1` stamps | Cosmetic; noted only |
| `docs/design/audit-of-record.md` | "The fourteen instances" | `docs/design/identity-proofing.md` calls `EnrollmentProofing` and `EnrollmentEvidence` "the 16th and 17th audit-of-record instances"; the schema carries thirty-one tables under an append-only trigger | The paper says fourteen named, thirty-one measured, and cites both |
| `meta/README.md`, the `tla/` row | "checked once as a demonstrator rather than maintained" | `meta/tla/README.md` says the four specs are model-checked in CI on every push since `v9.374`, three with a counterpart configuration they must fail | Four checked models |
| `README.md`, the documentation table | "The project report" links `docs/paper/polaris_project_report.pdf`, the Version 1 file | Versions 2 and 3 exist beside it | Updated with this version to link Version 3 |
| `NOTICE` | Names `polaris_project_report.pdf` and `.tex` as the academic report | Three versions exist | Updated with this version to name all three |
| `docs/paper/README.md` | "Version 2 is the current map of the whole system" | Version 3 supersedes it | Updated with this version |
| `docs/PRODUCTION-READINESS.md`, the status paragraph | "The protocol layer (P8, v9.320 to v9.331) ... is complete, certified in two SDKs" | "Certified" means conformant to the repository's own suite; nothing is certified by an outside party, as the same document's later paragraphs and the scoreboard state | The paper uses "conformant" for the suite and reserves "certified" for a Foundation decision that has not happened |
| `docs/reference/DYNO.md` and `PERFORMANCE-BASELINE.md` | Stamped `v9.278` and `v9.191` | Not re-run since; the reference machine has since changed Python and liboqs versions | Cited with their stamps and marked as not re-measured |
| `V2_AUTHOR_NOTES.md`, row 1 | `docs/ARCHITECTURE-OVERVIEW.md` says "30 in `01_schema.sql`, 37 migrated" | The file declares 45 canonical tables; the front page says 45 and 52 | Still open from Version 2; the paper says 45 and 52 |

Two observations that are not contradictions but are worth a maintainer's eye:

- The scoreboard (`lab/EXTERNAL-NOUNS.md`) still records the four packages at `0.1.0`, which
  was true when it was written; the tree is at `1.0.0-rc.1` and the republish is the release
  step that follows this paper. The paper says "on public registries" without a version where
  the version is about to change, and names `1.0.0-rc.1` as the tree's version.
- The linkability measurement's harness was made reproducible (a seeded generator) after its
  first numbers were recorded; the numbers in the record were not re-run afterwards. The paper
  reports them as the record does, with the lab's own caveat that the effect is small.

## Status on 23 September 2026

Every row above was re-read against the tree at `537f1ac`.

| Row | Status |
|---|---|
| `ROADMAP.md`, "Do not have" and the inventory heading | Closed: the inventory is restated at `1.0.0-rc.3` and the list no longer names what has since been built |
| `docs/design/audit-of-record.md`, "the fourteen instances" | Closed: the record now says why it said fourteen and what the count is |
| `meta/README.md`, the `tla/` row | Closed: it says the four specifications are model-checked in CI on every push since `v9.374` |
| `README.md`, the documentation table | Closed at Version 3, and again today: it said "the system at 1.0.0-rc.1" after the paper was re-pinned to `1.0.0-rc.7`, and did not link the Russian edition. Both fixed |
| `NOTICE` | Closed at Version 3; today it also names the Russian edition |
| `docs/paper/README.md` | Closed; today it also lists the Russian edition and restamps both editions |
| `docs/PRODUCTION-READINESS.md`, "certified in two SDKs" | Closed: the word is gone |
| `DYNO.md`, `PERFORMANCE-BASELINE.md` | Open by design: not re-run, cited with their stamps |
| `V2_AUTHOR_NOTES.md` row 1, `docs/ARCHITECTURE-OVERVIEW.md` "30 in `01_schema.sql`, 37 migrated" | Closed today, open since Version 2: it now says 45 and 52, the counts Appendix C measures |
| The scoreboard's package versions | Unchanged and correct: the scoreboard records what a plain install resolves, `0.1.0`, because `1.0.0-rc.3` is a pre-release |
| The linkability numbers from before the seeded harness | Open: not re-run |
