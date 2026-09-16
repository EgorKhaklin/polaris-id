# Version 3 of the Polaris paper: what changed from Version 2

**Files.** `polaris_project_report_v3.tex` (the main document), `v3-sections/` (one file per
section and appendix), `v3-figures/` (one TikZ file per diagram plus the shared style
vocabulary), and the rendered `polaris_project_report_v3.pdf`. Version 2
(`polaris_project_report_v2.tex`, `v2-sections/`, `v2-figures/` and its PDF) and Version 1 are
preserved byte for byte.

**Source of truth.** The tree at version `1.0.0-rc.1` (commit `7019bcf`, 16 September 2026):
the schema, the checks, the design records under `docs/design/`, the reference set under
`docs/reference/`, MISSION.md, ROADMAP.md, PRODUCTION-READINESS.md, REVIEW-PACKET.md, the
scoreboard `lab/EXTERNAL-NOUNS.md`, the lab records under `lab/`, and the CHANGELOG entries
from `v9.357` to `1.0.0-rc.1`. Every count was re-measured by the commands listed in the paper's
Appendix C. Nothing was carried forward from Version 2's measurements except the two performance
rows the repository has not re-run (the dyno at `v9.278`, the application baseline at `v9.191`),
which carry their original stamps.

## Why a whole re-measurement rather than a revision

Version 2 was written at `v9.345` and revised at `v9.355` for the holder-side sections only,
with every other count left at its old stamp and labelled. Between `v9.355` and `1.0.0-rc.1`
the repository shipped 112 versions, adopted an operating contract that changed what progress
means, put four packages on public registries, was exercised by an outside wallet and by the
OpenID Foundation's hosted suite, mutation-tested its own verification layer, and weakened two
words on its front door. A partial revision would have left most of the paper describing a
system that no longer exists. So every section was rewritten against the tree, every count
re-measured, and every mark re-decided.

## What Version 3 keeps

- The structure: a zoom from the credential core outward, one ring per section, each ring
  introduced by the failure of the ring inside it, with the same twenty sections and the same
  layer card, analogy box and "therefore" step.
- The Version 1 nucleus geometry and lifecycle machine, unchanged.
- The four status marks of Version 2, with their definitions.
- The corrections table of Version 2 (Section 15), kept in full as history.
- Fourteen of the seventeen Version 2 figures, unchanged: nucleus, lifecycle, town-map,
  holder-flow, offline-status, federation, transparency, gateway, signing-chain, cognition,
  senses-loop, delegation, stigmergy, and the shared styles. `present-future.tex` is carried
  with its annotations updated though no section places it.

## What Version 3 adds

- **A fifth mark, "externally exercised".** Given only where the scoreboard has a filled row:
  a named outside party, a date, a pointable result. It never means audited, certified or
  piloted. Three things carry it: the OpenID4VP verifier (walt.id's wallet), the conformance
  profile (the Foundation's hosted suite), and ML-DSA-65 verification (Project Wycheproof).
- **A new figure**, `outside-witnesses.tex`: the three outside witnesses and the two controls
  without which the first would mean nothing.
- **A thirteenth rung** on the ladder (Appendix B and `layer-ladder.tex`): other people's
  software, checked by nothing in the tree, recorded by the scoreboard.
- **Appendix F**, from Version 2 to Version 3, with the table of Version 2 sentences this
  version does not repeat.
- **Section 15's second table**, the corrections since Version 2: the instruments asked whether
  they would notice.
- New material in nearly every section: what an enrolment rests on, the trusted referee, the
  card as an object, the duress assessment, decisions kept as records, the mutation drills,
  the formal models, the population migration, the cache rules, the depth-24 epoch pipeline,
  the linkability measurement, the standby region, the capacity and cost models, the public
  transparency report, the pilot wind-down, the coexistence plan, the assurance mapping, the
  format bridges, the packaged verifiers, the OpenID4VP verifier, the stranger's path, and the
  operating contract that governs Section 18.

## Claims of Version 2 withdrawn or narrowed

The full table is Appendix F of the paper. The ones that change the cover:

| Version 2 | Version 3 | Why |
|---|---|---|
| "post-quantum, issuer-unlinkable, compulsion-resistant" | "issuer-unlinkable, duress-aware, signed with ML-DSA-65 under an audited algorithm-migration path" | `v9.452` and the duress assessment of 2026-09-13; both strong words are refused on outward surfaces by a check |
| "an external implementation has not interoperated" | one unmodified outside wallet has, over OpenID4VP; none on the native protocol | the scoreboard's wallet row |
| "the conformance suite is the contract; the integration is unproven" | the Foundation's hosted suite ran the profile: 7 passed, 4 in review, not certified | the Foundation's signed exports |
| cross-verifier correlation "bounded" as a property of the mechanism | bounded as measured, within the epoch's crowd, against an equality adversary; exposed on plain and SD-JWT presentations | `lab/linkability/` |
| 36 tables, 26 triggers, 191 checks, 48 cases, 18 jobs | 45, 42, 272, 118, 20 | Appendix C |

## Claims deliberately qualified

Version 2's table of stronger wordings avoided still applies, with these rows changed:

| Stronger wording avoided | What the paper says instead | Why |
|---|---|---|
| "Post-quantum identity system" | Algorithm agility under an audited migration path; ML-DSA-65 by default; the development path signs a placeholder | The readiness ledger's cryptography paragraph; `check_post_quantum_claims_are_agility` |
| "Compulsion-resistant" | Duress-aware: resists the casual coercer, not the informed one, net-negative against lawful access | `lab/duress/`; `check_duress_claims_are_aware` |
| "Interoperable" | One wallet, one format, one path, ES256 throughout | The scoreboard's own qualification |
| "Conformant" or "certified" | Eleven hosted modules clean; seven passed by the service, four in review; REVIEW is not PASSED | The scoreboard's status vocabulary |
| "An external implementation interoperates" (native protocol) | The specification, the cases and two SDKs exist; nobody outside has implemented them | Unchanged from Version 2 |
| "Verified in production", "99.99% availability" | A median at two requests per second on a two-member cluster, tail withheld; availability not validated | REVIEW-PACKET L-2, L-8 |
| "Multi-region" | A standby cluster with a measured, non-zero recovery point | `docs/design/multi-region.md` |
| "Unlinkable" | Issuer-side, zero-knowledge mode; bounded on the native presentation path within the anonymity set; nine handles on the interoperable path | `lab/linkability/`, `lab/benchmark/` |

## Build

```bash
cd docs/paper
docker run --rm -v "$(pwd)/../..:/polaris" -w /polaris/docs/paper texlive/texlive:latest \
  pdflatex -interaction=nonstopmode -halt-on-error polaris_project_report_v3.tex   # three times
shasum -a 256 *.tex v2-sections/*.tex v2-figures/*.tex v3-sections/*.tex v3-figures/*.tex > rendered-from.txt
```

79 pages, zero overfull boxes, zero undefined references at the stamp above.
