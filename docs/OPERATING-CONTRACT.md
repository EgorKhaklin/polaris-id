# The operating contract

**Reader:** anyone deciding whether a piece of work on Polaris should exist. **Job:** the rule
that decides it, written down in one place. Adopted on 13 September 2026 by the owner's
direction; carried until 16 September 2026 by the paper, the scoreboard and the release record
in parts, and recorded here whole on that date. It sits below [MISSION.md](../MISSION.md) and
above everything else: then the published contracts, then the machine-enforced checks, then the
admitted task, and implementation convenience last. It is amended
only by the owner's recorded direction, logged in [CHANGELOG.md](../CHANGELOG.md).

## 1. The unit of progress

The unit of progress is **a new external dependency survived**: a named outside party did
something with Polaris, on a date, with a result that can be pointed at. Internal feature
count, invariant count, lines of code, version count and roadmap breadth are not product
progress and are not presented as such. The scoreboard that records progress is
[lab/EXTERNAL-NOUNS.md](../lab/EXTERNAL-NOUNS.md).

## 2. Product and lab

**Product artifacts** are the things a stranger installs: `packages/polaris-verify`,
`packages/polaris-oid4vp`, `sdk/python` (`polaris-sdk-python`) and `sdk/typescript`
(`polaris-sdk-ts`). Everything else, the issuer, the schema, the application, the consoles,
the simulation, is the core, and `lab/` is research. (The contract as adopted named a `core/`
directory; the tree kept its `polaris_*` layout and gained `packages/` and `lab/` instead. The
boundary is the same.)

`polaris-verify` is the primary external door. It may depend on cryptographic providers and
on the published trust-root, trust-list, status and protocol formats. It must never require,
at runtime, the Atlas, Athena, the simulator, the check layer, the operator application or
PostgreSQL in order to verify a presentation. The required install test: a fresh machine,
install `polaris-verify`, configure a trust root, verify a fixture. If the full system must be
installed first, the product boundary has failed.

## 3. The merge rule

A product **behaviour** change needs exactly one qualifying reason, named in the change:

- **EXT-INTEROP.** A named external conformance suite, wallet, verifier, client or protocol
  implementation requires it.
- **EXT-USER.** A named relying party, operator or holder who is not the author requires it.
- **EXT-SECURITY.** A finding that originated outside the repository.
- **CORE-BUG.** An executable counterexample against behaviour Polaris already publicly
  promises, citing both the existing promise and the failing test. No existing promise means
  it is not a CORE-BUG.

- **STRATEGIC-BUILD.** Added 2026-09-19 by the owner, and the only reason here that does not
  answer to evidence that already exists. It admits a capability nothing outside has yet asked
  for, when a written analysis predicts the capability materially raises Polaris's long-term
  interoperability or assurance position. It is admitted **only** with a decision record under
  [`lab/strategy/`](../lab/strategy/README.md) answering all ten of that directory's questions,
  the last of which is the one that keeps this from becoming a licence: *what evidence would
  prove the bet wrong*, written before the work starts. No record, no STRATEGIC-BUILD.

Cleanliness, completeness, elegance, architectural expansion and "a desirable new guarantee"
still do not qualify, and a roadmap row, a paper or a competitor's feature list is not an
analysis. Everything else goes to `lab/`. Do not invent a sixth justification.

**Why the count changed.** The first four reasons are all reactive: each waits for somebody
outside to act. That is the right default for a reference implementation and it has a failure
mode, which is that Polaris can only ever answer questions it has already been asked. The
owner's judgement on 2026-09-19 was that the passivity now costs more than the discipline
buys. The decision record is what keeps the fifth reason from swallowing the other four: it
forces the alternatives, the cost, the thing delayed, and the falsifier to be written down
where a reader can hold the work to them later.

**Housekeeping** (documentation, dependency upgrades, refactors, CI cleanup, formatting,
citation repairs) may not create a new product guarantee, expand behaviour, bump a product
version or delay an external milestone. A prose or Markdown check is not a release blocker;
a claim guard stays only while it protects a falsifiable technical or security property.

**The decision test for every new idea.** Does a named external dependency require this?
Did a real external user require it? Did an external reviewer find it? Does it repair an
executable violation of an existing product promise? Is there a decision record under
`lab/strategy/` whose falsifier is written down? Five times no: it goes to `lab/`, or it
is not done.

## 4. Versioning

The tree version is not the product progress indicator; it moves only for an externally
observable change. The product artifacts are versioned independently, each under its own
semantic version. 1.0.0 requires all of:

1. a clean-machine install;
2. the real cryptographic mode explicit and safe (Section 5);
3. one named external client completed a presentation;
4. a named external conformance suite has been run;
5. the conformance result is published, even where it is not green.

All five held on 15 September 2026 and the four artifacts moved to `1.0.0-rc.1`. The
candidate holds until an operator who is not the author reaches a verified result without
help; a defect found in the candidate makes the NEXT candidate, which is how rc.1 became
rc.2 on 2026-09-17; nothing else moves the number.

## 5. Cryptographic mode

`polaris-verify` refuses to start unless the run declares its cryptography, `--pqc-provider`
naming a backend or `--dev-placeholder`. There is no default and no environment-variable
downgrade on that path. Under the development placeholder every relevant log line and every
verification response carries `"crypto": "DEV-PLACEHOLDER"`, so a development verdict can
never be mistaken for a real one.

## 6. The first interoperability target

OpenID4VP 1.0 under the High Assurance Interoperability Profile, exactly one credential
format, chosen from the first real use. Not, at the same time, a full mdoc stack, a native
transport, or several proximity transports. EXT-INTEROP success means a **named** external
implementation exchanged a presentation with Polaris; Polaris's own SDK talking to Polaris
does not count, and Polaris's own conformance suite is not external evidence. This target was
met on 15 September 2026 by an unmodified walt.id wallet; the scoreboard carries the row and
its two controls.

## 7. The scoreboard

[lab/EXTERNAL-NOUNS.md](../lab/EXTERNAL-NOUNS.md) records: the wallet (name, version, contact
or run date, result); the external conformance profile and its score; the external relying
party or operator; unique outside users; presentations outside CI; distinct days used; bugs or
ambiguities filed by non-authors; fixes caused by external findings. Zero and blank are valid
entries. Invented external evidence is prohibited. The invariant count is never displayed as
the primary progress metric.

## 8. The lab

The lab's job is to falsify the differentiating claims, not to expand the architecture.
Priority: `lab/linkability/`, `lab/duress/`, `lab/crypto-migration/`.

The linkability question: given complete transcripts of presentations A and B, what advantage
does a colluding verifier have at deciding "same holder?", considering pairwise identifiers,
issuer metadata, presentation size, timing, status artifacts and every other structure in the
transcript. Publish the threat model, the adversary implementation, the dataset and harness,
the measured result and its limitations. The existence of a mechanism is not proof of
unlinkability.

The duress question: model a casual coercer, an informed coercer observing the interaction,
and post-hoc lawful or institutional access; state what Polaris does and does not protect.
**If the evidence does not support the stronger word, the product vocabulary is weakened.**
It was: the front door says duress-aware.

Lab work cannot block a scheduled product milestone unless it produces a CORE-BUG against
already-promised behaviour. New tables, operator consoles, ontology layers, simulator
dimensions and unrelated protocol surfaces default to the lab and get no product version.
The architecture is not expanded because expansion is possible.

## 9. The ninety-day objective

`polaris-verify` independently installable; real cryptographic behaviour explicit; one named
external wallet or client completes a presentation; an external OpenID conformance suite
running; one relying party or operator who is not the author has used the verifier; repeated
outside presentations; external failures entering the development loop. The scoreboard says
which of these hold.

## 10. The 180-day line

At 180 days the external fields are read. If they remain effectively empty while internal
versions, lines, invariants or architecture kept growing: the core is frozen, the
national-scale architecture stops expanding, `polaris-verify` is kept only if external use
exists, and otherwise the project is archived as a reference implementation and a lab. The
right response to this clause is not to fill the fields oneself.

## 11. The change this contract makes

The old loop was owner to Polaris to internal tests to owner. The target loop is owner to
Polaris to a stranger, with failure flowing back. The next meaningful result is a wallet
name, a conformance score, an external presentation, an external operator, or an externally
discovered defect. Not another internal version number.
