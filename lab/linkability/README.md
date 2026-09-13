# lab/linkability: what advantage does a colluding verifier actually have?

**The lab's job is to falsify Polaris's differentiating claims, not to expand the
architecture.** The front door says *issuer-unlinkable*. That is a claim about the issuer.
This directory is about the other side: two verifiers who kept what they were shown.

**Status: one finding, the study not yet run.** The finding below came from reading the
question carefully enough to build a counterexample. The measured study, with a dataset and
an adversary, is not done, and nothing here should be read as evidence that the remaining
threat model holds.

---

## The question (from the operating contract)

> Given complete transcripts from presentations A and B, what advantage does a colluding
> verifier have at deciding: same holder?

Threat model to consider: pairwise/scoped identifier, issuer metadata, presentation size,
timing, status artifacts, other observable transcript structure.

> Mechanism existence is not proof of unlinkability.

---

## Finding 1: `correlation: bounded` did not mean what it said

**2026-09-13. Fixed the same day.**

`verify_presentation` reports a `correlation` field, whose two values the code documents as:

- `bounded` — "the verifier holds a value derived under its own scope from a secret it
  never sees, and the presentation showed it no stable credential"
- `exposed` — the weaker, honest form

The verdict was set to `bounded` **whenever a scoped nullifier was present**. It never
checked the premise its own comment stated.

The counterexample, which runs:

```python
pres = {
  "format": "polaris-presentation/1",
  "credential": {"token_value": "STABLE-TOKEN-0001",
                 "public_key_hex": "aa"*1952, "signature_hex": "bb"*3309},
  "zk_proof": {"public_inputs": {"nullifier_hex": "cc"*32}},
}
verify_presentation(pres, verifier_scope="verifier-A")["correlation"]
# -> "bounded"
```

The verifier is holding `STABLE-TOKEN-0001`, the issuer's public key, and the issuer's
signature over this credential. Every one of those is **the same value at every verifier**.
Two verifiers who kept their transcripts link on any one of them in a single string
comparison, and both of their verifiers had told them the correlation was bounded.

This is the shape the lab exists to catch. A mechanism was present, so the property was
assumed. The nullifier bounds what a verifier should **store**; it says nothing about what
it was **shown**, and only the second one is a fact about the transcript.

**The fix.** `bounded` now requires a scoped nullifier *and* the absence of any field that
is identical across verifiers: the credential's token value, issuer public key or issuer
signature, and the holder's public key. The holder key is on that list for the reason that
makes it easy to miss: it is stable across verifiers by construction, which is precisely
why the pairwise handle is derived from it and why showing it defeats the derivation.
Regression tests in `scripts/test_verify_p9.py`.

**What the fix does not do.** It corrects a verdict. It does not make any presentation more
private than it was, and no deployed behaviour changed. A relying party reading
`correlation` now gets an answer about the transcript in front of it.

---

## What has NOT been measured

Everything in the threat model except the stable-field case above. In particular, for a
transcript that now legitimately reports `bounded`:

- **Presentation size.** Does byte length vary with anything holder-specific?
- **Timing.** Does the interval between presentations, or proving time, carry a signal?
- **Issuer metadata.** Agency id, algorithm, epoch id and epoch root each narrow the
  anonymity set to a subpopulation. How small does that set get in practice?
- **Status artifacts.** A stapled status assertion is signed material with its own
  timestamps and identifiers.
- **Transcript structure.** Field ordering, optional-field presence, format minor version.

The honest statement today: **`bounded` now means no field in the transcript is trivially
identical across verifiers. It does not mean an adversary has no advantage.** The advantage
has not been measured, and claiming it is zero would repeat exactly the mistake above.

---

## The study, when it runs

Per the contract, publish all five: the threat model T, the adversary implementation, the
dataset/harness, the measured result, and the limitations. An adversary that is never shown
to succeed at anything is not evidence, so it needs a positive control: a population where
linking IS possible, which the adversary must solve, before a null result on the bounded
population means anything.
