# Coexistence, cutover, and the sunset

**Reader:** the authority planning how a Polaris credential lives beside the one it is meant to
replace, and the assessor asking what happens to people who do not hold it. **Job:** the
phases, what each requires, and the one decision in the sequence that is not really an
engineering decision at all.

The mechanism is [`polaris_web/coexistence.py`](../../polaris_web/coexistence.py).

---

## 1. The dangerous moment is not the cutover

A new national credential does not arrive into an empty field. It arrives beside a driving
licence, a passport, a legacy card, and for some years it has to be the second thing somebody
carries rather than the first. Cutover, in that picture, is undramatic: one more accepted
credential at the counter.

**The sunset is the moment an identity system becomes compulsory.** Until the old credential
stops being accepted, a person who cannot or will not hold the new one still has a way through
the door. Afterwards they do not, and nobody had to decide to make it mandatory. It happened
because a migration reached its last milestone.

So the sunset is treated here as a decision with a floor under it, not as a phase that arrives.

## 2. The phases

| Phase | What it means |
|---|---|
| `NOT_ISSUING` | The credential exists; nobody holds one. |
| `PILOT` | A consenting cohort holds one. The legacy credential does everything. |
| `ISSUING_ALONGSIDE` | Anyone may obtain one. The legacy credential still does everything. |
| `PREFERRED` | Relying parties accept both; the new one is the default offered. |
| `SOLE` | The legacy credential is no longer accepted. |

**No flag-day** means every phase is entered while the previous one still works, and `SOLE` is
never entered from anywhere but `PREFERRED`. Skipping a phase is the flag-day, whatever the
announcement calls it, and `sunset_readiness` refuses a verdict for any other phase.

## 3. What the issuer can measure, and what it cannot

This is the whole shape of the module.

**Measurable here** (`supply_side`): how many enrolled people hold an active credential, the
health of those credentials by status, how far the trust list reaches, whether epochs are
actually being published so offline verification has something to check against. All of it is
about the *authority's own* readiness.

**Not measurable here, at all:**

- what share of relying parties that accept the legacy credential also accept this one;
- whether a person without one can still obtain every service the old credential opened;
- whether that alternate path is usable by somebody with no smartphone, no fixed address and
  no appetite for a government website, *without them having to explain themselves*;
- whether somebody arriving tomorrow can still get the legacy credential.

None of that is in any table. **An authority that computed "ready to sunset" from issuance
numbers would be computing it from the half of the picture that flatters it**, and the half it
skipped is the half that decides whether anyone is harmed.

So `sunset_readiness` takes those four as arguments and **refuses without them**. Not as a
formality: the refusal is the mechanism, because an operator who has to type the answer has to
have asked the question. The refusal quotes the questions rather than naming the fields, since
a field gets filled in and a question gets considered.

### The denominator nobody mentions

`enrolled_holding_share` counts people this authority has **already enrolled**. It is not
coverage of the population. Everyone the authority has never met sits outside the denominator,
and they are exactly the people a sunset strands. The figure carries that warning in its own
output, because a number this reassuring will otherwise be quoted without it.

## 4. The floor under the sunset

Two blockers are checked before any adoption figure, because no percentage overrides them:

1. **No alternate path.** Withdrawing the old credential does not complete a migration; it
   removes somebody's way through the door.
2. **A path that exists on paper.** One requiring a smartphone, a fixed address or an
   explanation excludes the people most likely to need it, and counting it is how an exclusion
   gets recorded as a success.

Then: every relying party accepting the legacy credential must accept this one, the deployment
must be in `PREFERRED`, and an epoch must have been published, because a credential that only
works online is not a replacement for one that works in a power cut.

## 5. What a clear verdict is not

`may_sunset: true` means the engineering facts raise no objection. It is **not** permission
from the people affected, and the verdict says so in its own text. Sunset remains a decision
somebody makes and answers for, and this module exists to make sure they make it with the
second half of the picture in front of them.

## Proven by

`polaris_web/test_app.py::CoexistenceSunsetTests` on every push: the refusal without
attestations, the two floor blockers, partial relying-party acceptance, every skipped phase,
an unknown phase, the denominator warning, and that a clear verdict still disclaims itself.
`check_coexistence_plan` pins them and this document's statement of the limits.
