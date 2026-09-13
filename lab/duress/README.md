# lab/duress: what does the duress path actually resist?

**The lab's job is to falsify Polaris's differentiating claims.** The front door said
*compulsion-resistant*. This is the assessment the operating contract asked for, against the
three coercers it names, and its conclusion is that the word had to change.

**Result: the vocabulary is weakened to "duress-aware".** The mechanism is real and it works
against the coercer it was designed for. It does not resist compulsion, and against one
adversary it is worse than nothing.

---

## The mechanism

A holder enrols an optional second secret, stored as `IdentityToken.duress_code_hash`. Typed
during a verification, it is compared in constant time; the verification then **succeeds
exactly as an ordinary one does**, and `uc12_record_duress` appends a row to `DuressEvent`
that no operator surface displays. Only an auditor with an explicit role sees the queue.

Three structural safeguards hold it up: constant-time comparison with matched work on both
paths, omission from every operator-visible surface, and a role gate on the queue.
`docs/design/duress-codes.md` is accurate about all of this.

---

## Coercer 1: the casual coercer

Someone compelling a verification who does not know duress codes exist.

**Resisted.** The verification succeeds, the operator's screen is identical, the verification
list does not join `DuressEvent`, and the form field is labelled neutrally. The coercer
observes a successful verification and learns nothing. A silent alert is raised.

This is the adversary the mechanism was built for, and against this adversary it works.

---

## Coercer 2: the informed coercer, observing the interaction

Someone who knows Polaris has duress codes and is standing next to the holder.

**Not resisted, and the design says why without drawing the conclusion.** From
`docs/design/duress-codes.md`: *"No holder-side panic button. The code is typed on the
verifier's terminal."*

Every defence in that document protects the **operator's** surface. None of them protects the
holder from the person beside them:

- The coercer watches the code being typed. Keystrokes are not constant-time.
- A coercer who demanded the real code first can see a different one entered.
- Enrolment is per-token opt-in, so *"I have no duress code"* is a claim a coercer can press
  on, and the holder cannot prove it. An opt-in defence makes its absence interrogable.

The threat model in the design document ends at *"the attacker must attack the back: an admin
or auditor session, or the database directly."* That is true of an attacker attacking the
system. It is not true of an attacker attacking the person, who never needs the back at all.

---

## Coercer 3: post-hoc lawful or institutional access

A court order, a subpoena, a lawful-access request, or an auditor with the role the mechanism
grants.

**Not resisted. Against this adversary the mechanism is net-negative.**

`DuressEvent` is append-only by construction: `trg_duress_event_append_only` rejects UPDATE
and DELETE, it appears in no archive-or-purge path, and `polaris_sql/08_tests.sql` asserts
the DELETE is refused. That is C1 working exactly as intended, and it is the problem.

Without duress codes there is no durable record that a holder signalled coercion. With them
there is: permanent, un-erasable, naming the token and the moment. Lawful access is not a
privilege escalation; it is the authorised path, and it returns every row.

So where the coercing party *is* the institution, or can later compel the institution, the
mechanism does not protect the holder. It manufactures evidence that the holder resisted, and
the system's own integrity guarantee ensures that evidence cannot be destroyed.

That is the opposite of compulsion resistance, and it is the case the word most strongly
implies. "Anti-coercion" as a vocation points at exactly the adversary the mechanism is
weakest against.

---

## The vocabulary

| Claim | Supported? |
|---|---|
| A duress signal is invisible to a coercer at the counter | **Yes** |
| A duress signal is invisible to a coercer watching the holder | **No** |
| A duress signal is invisible to lawful or institutional access | **No**, and the record is indelible |
| "compulsion-resistant" | **Not supported** |
| "duress-aware" | Supported |

The contract: *"If evidence does not support 'compulsion-resistant', product vocabulary MUST
be weakened, e.g.: 'duress-aware'."* It does not, so it is.

`check_duress_claims_are_aware` refuses the strong word on any outward surface, the same
shape as the post-quantum agility guard, so a future README cannot quietly restore it.

---

## What is NOT proposed here

No mechanism changes. A holder-side panic signal, a deniable enrolment that makes absence
uninterrogable, or a duress record that degrades rather than persists are each a different
system, and lab work does not get to create a product guarantee. What changed is the claim,
which was wrong, and claims are free to fix.

## What is still unmeasured

- **Long-run frequency analysis.** The design document accepts it rather than solving it. No
  measurement of how much an attacker learns from aggregate rates.
- **The operator as coercer.** Every safeguard assumes the operator is neutral. An operator
  who is the coercer sees the terminal the code is typed on.
- **Enrolment-rate inference.** If few holders enrol, a `DuressEvent` is more identifying,
  which is the same anonymity-set problem measured in `lab/linkability/`.
