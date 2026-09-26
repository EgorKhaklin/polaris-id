# Polaris: identity cannot outrun its primitives

**Status:** INCONCLUSIVE, the strong claim is permanently retired (the
v9.40 terminus passed with no external cold read).
**Author:** Egor Khaklin (VANTA)
**Reading time:** 8 minutes.

This page states the thesis behind Polaris, the test that would have
confirmed or refuted it, and an honest account of the evidence in hand.
It is a documented experiment whose falsification window has closed
unactioned, not a victory lap. The test below remains specified for
anyone who later chooses to run it.

---

## The thesis

A national identity-token system is only as trustworthy as the
primitives underneath it. Policy promises ("we will not aggregate," "we
will not retain forever," "we will enforce one identity per person") are
worthless if the only thing holding them up is policy. They have to be
enforced where they cannot be talked around: in the schema, in the
triggers, in the partial unique indexes, in the CHECK constraints.

Polaris is the claim made concrete. The ten constitutional invariants
(C1-C10 in `MISSION.md`) are each enforced at the database level, not
the policy level. The Vocation (anti-coercion) sits above them: changes
toward surveillance, centralized aggregation, or unbounded retention are
refused on sight. The schema does what identity-token schemas do
(tokens, individuals, agencies, signatures, audit trails, revocations),
but the security boundary is the database, and the invariants are
machine-checked by `polaris_checks/` before any change ships.

The strong form of the thesis: **a reference implementation can make its
own constraints legible enough that a stranger can read the repository
and correctly infer what it needs.** If the primitives are honest, the
system explains itself. That is the claim this page retired unproven: the
window to test it (the v9.40 terminus set in `MISSION.md`) passed with no
external cold read, so under the constitution the strong claim is retired
as inconclusive. It was not refuted. It was never independently tested,
and the deadline to test it lapsed.

---

## What would count as evidence

**The cold-read test.** An engineer who has never seen Polaris is given:

- The repository (read-only)
- The prompt "what does this need to ship a small contained feature?"
- No further guidance

They have ONE HOUR. At the end of the hour:

- If they correctly identify a coherent next step that the maintainer
  would also have produced, the repository is legible enough for cold
  reads.
- If they identify a step that violates a known invariant the maintainer
  would have refused, the documentation is INCOMPLETE; `CONTRIBUTING.md` and
  `MISSION.md` need the rules the engineer needed but did not find.
- If they produce no coherent answer, the repository is illegible to
  cold readers and the strong claim is false.

This is the falsification test. It requires an actual cold read by an
actual external engineer to count as evidence.

**The terminus.** `MISSION.md`'s abandonment clause set v9.40 as the
deadline: if no cold-read attempt occurred by then, the thesis is
documented inconclusive and the strong claim is retired permanently, with
the system kept as good tooling. That clause is mechanical, not
aspirational. No such cold read was conducted, and the repository is now
many minor versions past the v9.40 deadline. The window therefore closed
unactioned, which is why the status above is INCONCLUSIVE and the strong
claim is retired rather than left open.

---

## What evidence currently exists

Honestly, the standing evidence is internal and limited:

- **The invariants are enforced where it matters.** C1-C10 live in the
  schema and triggers (`polaris_sql/`), and `polaris_checks/` gates CI
  on them with tested detection correctness. This is evidence that the
  primitives are real, not that a stranger can read them cold.
- **A self-evaluation walkthrough** found intervention points where
  session context filled gaps the docs did not. A walkthrough by the
  person who built the system is not a cold read; it is self-evaluation
  by someone who already has full context. It can only surface
  candidate gaps, never prove legibility.

None of the above constitutes evidence for the strong claim. Elevating
"internal review by the author" to "a stranger can read this cold and
get it right" is exactly the inference this page refuses to make.

---

## How to replicate or refute

The repository is the experiment's substrate. To attempt the cold-read
test:

```bash
git clone <polaris repo>
cd polaris
cat CONTRIBUTING.md  # the document you should read first
# Then attempt: "ship a small contained feature, X"
# Log every moment you needed knowledge that wasn't in the docs
# Compare your trajectory to CONTRIBUTING.md + MISSION.md
```

If you conduct this experiment, send the results (publicly or privately
to the maintainer). The strong claim is retired by default, so a positive
result plus your methodology would not flip it automatically: it would be
the evidence a maintainer needs to reopen the claim through an explicit,
recorded decision. A negative result is equally valuable: it documents
the specific failure mode for future work.

---

## Why the strong claim is retired

The argument, condensed:

1. Publishing "this works" requires evidence it works.
2. The evidence required is an independent cold read.
3. No independent cold read was conducted before the v9.40 terminus.
4. Self-evaluation by the author is structurally compromised by full
   context; it cannot stand in for the test.
5. Therefore, per `MISSION.md`'s abandonment clause, the strong claim is
   retired as inconclusive and the system is kept as good tooling.

The thesis was not refuted; it was never independently tested, and the
deadline to test it lapsed. The distinction still matters: "retired as
inconclusive" is an honest terminal state, whereas an untested hypothesis
published as a verified result is the failure mode this whole project
exists to avoid. The disposition is closed by default: a later cold read
could reopen it only through an explicit, recorded maintainer decision
(see `ROADMAP.md`), never by an automatic flip when evidence appears.

---

## What this page is NOT

- A claim that the system has been independently validated.
- A claim that reading the repository cold is proven to work.
- A claim that the schema is novel.

What this page IS:

- An honest statement that identity has to be enforced at its
  primitives, and that Polaris tries to do exactly that.
- An invitation to test the repository's legibility against an explicit
  falsification criterion.
- A commitment to keep the status honest: the cold-read window closed
  unactioned at the v9.40 terminus, so the strong claim is retired as
  inconclusive rather than held open. A future cold read could reopen it
  only through an explicit, recorded maintainer decision (`ROADMAP.md`).

That is the thesis. That is the evidence that was available. That is the
terminal disposition the constitution mandates.
