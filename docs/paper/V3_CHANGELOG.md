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

**Re-pinned.** On 22 September 2026 the paper was re-measured whole at `1.0.0-rc.7` (commit
`4e74376`) by re-running each method Appendix C states; that commit is now its source of truth, and
what moved is listed under "Revisions after publication" below.

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
docker run --rm -v "$(pwd)/../..:/polaris" -w /polaris/docs/paper texlive/texlive:latest \
  pdflatex -interaction=nonstopmode -halt-on-error polaris_project_report_v3_ru.tex   # three times
rm -f *.aux *.out *.log *.toc
shasum -a 256 *.tex *sections*/*.tex *figures*/*.tex > rendered-from.txt
```

85 pages, zero overfull boxes, zero undefined references at the stamp above. At the corrections of
23 September 2026: English 91 pages, Russian 107, zero overfull boxes in either.

## Layout, 16 September 2026: readability over page count

The paper is dense, and the first Version 3 build kept the page count down by floating every
figure to the foot of a text page, which cut every paragraph and table that ran on to the next page.
The rule is now the opposite, and the build grew from 79 pages to 85 for it.

- A figure is placed exactly where the text introduces it (`\figfile`, `[H]`): after the paragraph
  that names it, or under the heading of the subsection it opens. When it does not fit the rest of
  the page it moves whole to the next, and the space it leaves stays empty. No figure sits between
  the lines of a paragraph, at the top of a page above a continuing table, or on the far side of a
  page break from its caption.
- The two figures too tall to share a page, the layer ladder and the walled town, have a page each:
  the ladder a float page (`[p]`) after its table, the town a page turned on its side
  (`\figside`, `rotating`) so that it is read at its natural size rather than at the three quarters
  the upright page allowed. The districts figure carries a three per cent height cap, the one
  reduction in the document, so that it lands on the page of the paragraph that introduces it.
- A layer card is one object: a `tabular` in a `minipage` rather than a `longtable`, so it never
  splits across a page. The card steps the table counter as the longtable did, so every captioned
  table keeps the number it carried when Version 3 was published.
- The town analogy box is unbreakable again: a few lines split across a page read worse than the
  space a whole box leaves behind.
- `\FloatBarrier` at every section, every subsection and every layer card: a figure never leaves
  the subsection that introduces it. Four figures moved from the end of their subsection to its
  head (the outside witnesses, the offline trade, the holder flow, the transparency machinery) and
  two from before to after the paragraph that explains them (the gateway, the delegation chain);
  the space a heading and its figure need together is reserved before the heading, so a page that
  cannot hold both breaks before the heading rather than between them.
- Figure and table numbering, cross-references, section order and every sentence are unchanged.

## Revisions after publication

Each revision re-ran the measurement behind the sentence it changed; each was made to both editions
in the same commit.

- **22 September 2026: re-measured at `1.0.0-rc.7`** (`7ec156f`). Fourteen of twenty-six counts did
  not move. Checks 272 to 313, mutation drills 8 to 12, test functions 1,755 to 2,189, tags 295 to 3
  (a tag marks a release, not a ship). The same day the Russian edition began (`d33ec6f`).
- **23 September 2026: the English edition took everything the Russian one added** (`d6e1613`):
  the redrawn radial figures with text set along their curves, the closing owl, the abbreviations
  list, the layout fixes.
- **23 September 2026: corrections.** Each is a sentence the evidence did not support.
  - Every check the paper cites must exist, and a check now fails the build if one does not
    (`ca56814`); two drill counts were stale.
  - What a plain install from the registries resolves: `0.1.0`, because `1.0.0-rc.3` is a
    pre-release (`95afa90`).
  - The ninety-day objective, item by item and dated; two fixes caused by outside findings, not one
    (`975d34c`).
  - The 32-bit limitation names its two columns and the arithmetic at the planning rate
    (`6179fff`).
  - Thirty-one append-only tables are 24 strict and 7 bounded, and every guard must be classified
    (`0f942b6`).
  - The procedure drill measured procedures only; the use-case functions' eleven refusals were
    measured by nothing. Nine are covered now, one by a test that forces the lock interleaving
    (`ceb1f30`, `3a85a7e`, and a row in Table 16, `8174a65`).
  - The schema has 46 triggers; 42 is the trigger file's own count (`796fa42`).
  - 142 package tests passed over the certificate the outside wallet refused, not 143, which is
    the count after the fix (`dbb66f4`).
  - 44 verdict fields are unconstrained at `1.0.0-rc.7`, not 43, which was the count at `v9.433`;
    Appendix C now carries the number with its method (`8470f9e`, `68d9f49`).
  - The dyno, cited at `v9.278`, was re-run at `1.0.0-rc.7`. Its proof half had sent the
    prover a pre-`v9.354` input since that version, printed "not measured here" and exited 0,
    so its CI step was green while measuring nothing. Fixed; `--require` makes a half that does
    not measure fail, and `check_dyno_published` requires it of every CI run. Table 12's
    signature rows moved a few per cent; the proof fell from 35 ms to 25 ms (a different
    statement since `v9.354`, so not like for like).
  - Appendix E said a check fails the build if the token state machine's trigger stops being.
    Deleting each of the 42 triggers in turn, seven left every check green, the state machine
    and the active-signature guard among them, and one check was satisfied by a trigger's comment.
    `check_token_core_triggers_are_bound` now pins both core triggers and the six legal
    transitions; the section 4 card states the measured split (a check notices 38 of 42, the
    trigger drill all 42), and Table 16 gains the row.
  - Two layer cards said a person reference in Athena "fails five checks"; measured, it fails
    one, `check_athena_no_person`.
  - The Atlas returns at most 5,000 cluster summaries, not "a few hundred".
  - The checks behind C1, C3 and C10 each accepted a mention for the mechanism: C1's the
    append-only error code anywhere in the schema, C3's (through the two drift checks) a
    deleted index by its `COMMENT ON`, C10's six words in table names, so a money column on
    the credential passed. Each now requires the defining statement and was shown red on the
    real tree; Table 16 gains the row.

