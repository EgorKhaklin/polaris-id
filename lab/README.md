# lab/: research that tries to falsify Polaris's own claims

**Reader:** anyone deciding whether a differentiating claim of the product holds up. **Job:**
the arm of the [operating contract](../docs/OPERATING-CONTRACT.md) that attacks the claims
rather than expanding the architecture, and the scoreboard that records what the outside
world has done with Polaris.

| Entry | What it holds |
|---|---|
| [EXTERNAL-NOUNS.md](EXTERNAL-NOUNS.md) | The scoreboard: every named outside party that has exercised Polaris, on a date, with a result; zero and blank are valid; invented evidence is prohibited. |
| [linkability/](linkability/README.md) | The colluding-verifier question: given two presentation transcripts, what advantage at "same holder?"; two adversaries (`adversary.py` on equal values, `transcript_size.py` on byte count alone), the measured bounds, and the blind spots of each. |
| [duress/](duress/README.md) | The three coercers (casual, informed, post-hoc institutional) against the duress mechanism, the vocabulary the result allows (duress-aware), and `enrolment_timing.py`, which found the front of house could time out who had enrolled. |
| [crypto-migration/](crypto-migration/README.md) | The algorithm-migration path under measurement: what a break would and would not cost, and `algorithm_status.py`, which found that no signed artifact tells a verifier an algorithm is deprecated and measured what the mixed window costs. |
| [interop/](interop/README.md) | The outside wallet probe: an unmodified walt.id wallet presenting to `polaris-oid4vp`, reproduced end to end, with its controls. |
| [benchmark/](benchmark/README.md) | Measured performance and the scale factor, kept apart from projection. |
| [strategy/](strategy/README.md) | The bets: a decision record per capability admitted on a prediction rather than on evidence, each carrying the falsifier that was written before the work started. |

Lab work needs no external reason to exist; product behaviour does. A lab finding becomes
product work only as a CORE-BUG against something already promised, or when a named outside
party trips over it.
