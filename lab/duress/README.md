# lab/duress: what does the duress path actually resist?

**The lab's job is to falsify Polaris's differentiating claims.** The front door said
*compulsion-resistant*. This is the assessment the operating contract asked for, against the
three coercers it names, and its conclusion is that the word had to change.

**Result: the vocabulary is weakened to "duress-aware".** The mechanism is real and it works
against the coercer it was designed for. It does not resist compulsion, and against one
adversary it is worse than nothing.

**And one measured finding, 2026-09-17.** Until this directory had an instrument, the claim
that the front of house cannot distinguish had never been tested. It was false on one axis:
the response time said whether a holder had enrolled a duress code at all. Fixed the same
day; see the finding below.

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

## Finding: weakening the claim nearly broke the one defence that works

**2026-09-13, caught by CI the same day.**

Replacing "compulsion-resistant by design" with "duress-aware by design" in the console's
`base.html` meta description put the literal word **duress** into every operator page.
`test_anti_revealing_verifications_list_excludes_duress` went red immediately.

The mechanism's single working defence is that an operator surface reveals nothing, and the
edit that weakened the *claim* damaged the *property*. The nav entry to the duress queue is
role-gated to admin and auditor for exactly this reason; an unconditional meta tag is not
gated by anything. The console now names no duress property in any wording, which is
correct: it is a surface a coercer reads over an operator's shoulder, not a place to state
what the system does.

The test caught it by luck rather than by design. It read one page, `/verifications`, and
found the leak only because `base.html` is inherited by all of them. A leak on any single
other page would have passed. It now sweeps every operator-reachable page, because the
property is "an operator never sees the word", not "one page does not show it".

## What is NOT proposed here

No mechanism changes. A holder-side panic signal, a deniable enrolment that makes absence
uninterrogable, or a duress record that degrades rather than persists are each a different
system, and lab work does not get to create a product guarantee. What changed is the claim,
which was wrong, and claims are free to fix.

## Finding: the front of house could read out who had enrolled, by timing

**2026-09-17. Measured and fixed the same day. `enrolment_timing.py`.**

Everything above is analysis. This directory had no instrument until now, and the first
thing one found was that the design record's own conclusion was false as written:

> *"Where it settles. The front of house cannot distinguish, so the attacker must attack the
> back: an admin or auditor session, or the database directly. Both need a privilege
> escalation the verification surface does not provide."*

`_check_and_record_duress` read:

```python
row = query("SELECT duress_code_hash FROM IdentityToken WHERE token_id = %s", ...)
if not row or not row['duress_code_hash']:
    return                                            # no hash, no work
if not check_password_hash(row['duress_code_hash'], duress_input):
    return                                            # a hash, and the full scrypt cost
```

The enrolled hashes are `scrypt:32768:8:1`, measured at **287 ms** on the machine this was
run on. So typing anything at all into the duress field and timing the response separated
*this holder enrolled a duress code* from *this holder did not*. No privilege, no escalation,
nothing but the verification surface. A third of a second is not a laboratory side channel.

**It reveals enrolment, not a code and not a signal.** That distinction matters and does not
rescue the claim. The three safeguards were stated as "the constant-time comparison with
matched work on both paths"; matched work was true of match versus no-match and had never
been true of enrolled versus not-enrolled. And this section already recorded that enrolment
is opt-in, so *"I have no duress code"* is a claim a coercer can press on and the holder
cannot disprove: **a coercer who can measure it does not have to press.** Against the
operator-as-coercer named below, it is cleaner still, because they type the field and read
the latency off their own screen.

**The fix.** The comparison runs against `_DURESS_TIMING_BALLAST`, a real scrypt hash at the
same parameters, when nothing is enrolled; both paths pay one comparison and the standin's
result is discarded. `check_duress_timing_ballast` fails the build if the standin
disappears, stops being a well-formed hash, drifts to cheaper parameters, or if the early
return comes back.

**The harness got this wrong first, in the way this repository keeps rediscovering.** Its
initial version split the source on the text `check_password_hash` and searched what came
before. The comment explaining the defect names that function, so the split landed inside the
comment, the check saw none of the code, and it reported the channel CLOSED against the
pre-fix source. It was caught by mutating the fix away and watching the harness not notice.
It reads an abstract syntax tree now, and so does the check. Match what the code does, never
text that also appears in a comment.

**What this does not say.** It measures the comparison cost, not a live request: the
surrounding query, template render and network dominate the variance and are not modelled.
It closes one channel on one axis. It says nothing about the three coercers above, and
nothing about the three items below.

---

## Finding: the timing channel was closed while a label said the same thing

**2026-09-17. Found on unmutated code, the same day as the timing fix above.**

`docs/design/duress-codes.md` has a section called "Keeping it off the operator's screen",
and it states a property rather than a preference:

> The operator is the surface a coercer can observe, so it is the surface that must be
> blind ... The word duress does not appear on the operator's screen.

It appeared on four of them. Logged in as an OPERATOR, with no escalation:

    /tokens/<id>                     a card headed "Duress Code", reading ENROLLED
                                     or NOT ENROLLED
    /api/tokens/<id>/export          `duress_enrolled` in the JSON
    /investigate/token/<id>          a DURESS-ENROLLED badge, and a "Has Duress Code" row
    /investigate/individual/<id>     a "Duress" column, one cell per token

The finding above this one closed a **287 millisecond** timing channel whose entire reason
for mattering was that an operator-coercer could learn enrolment: "against the
operator-as-coercer named below, it is cleaner still, because they type the field and read
the latency off their own screen". **That fix was defeated by a label.** Measuring a third of
a second is harder than reading a page, and the page was already open.

This is worth stating plainly because it is the recurring shape in this repository, not a
one-off: a subtle channel gets careful, instrumented work while the obvious one beside it
stays open, because the subtle one is the interesting problem. The audit below is what found
it, and only because it went surface by surface instead of reasoning about the mechanism.

**Both halves of the gate are tested, and the second half is the one that is easy to skip.**
Admin and auditor still see enrolment: the duress queue is already theirs and the design says
so, and a fix that deleted the field would also have passed a test that only checked the
operator. The label goes with the value, too. A card headed "Duress Code" reading NOT
ENROLLED tells a coercer this holder has nothing to fall back on, so hiding only the ENROLLED
case would have left the channel open for exactly the people with no protection. The view
passes `None` rather than `False` to a role that may not be told, so an absent card is
absence of permission and never absence of enrolment.

`test_the_word_duress_is_absent_from_every_operator_surface` asserts all four surfaces for
the operator and all four for admin and auditor. Opening the gate to everyone turns four
assertions red; closing it to nobody turns the control red.

---

## Finding: the operator as coercer, audited surface by surface

**2026-09-17. Audited against the code, not argued.** This was on the unmeasured list as
"every safeguard assumes the operator is neutral". Enumerating what an OPERATOR-role account
can actually reach found the premise mostly wrong, and saying so is more useful than leaving
the bullet to imply an open hole.

Every surface that touches `DuressEvent`, with its guard:

| Surface | Guard | Covered by |
|---|---|---|
| `/duress`, `/api/duress/events`, `/api/duress/record` | `require_role('admin')` | `test_duress_dashboard_blocked_for_operator`, `test_api_duress_events_operator_rejected` |
| `/dashboard` duress panel and 24-hour count | `privileged_view = role in (admin, auditor)`, in the template | `test_duress_is_visible_to_admin_and_auditor_only` |
| `/verifications` | operator-reachable, and shows nothing | a test asserting the operator view does not reveal duress |
| `/metrics`, `/api/metrics` | unauthenticated BY DESIGN, restricted at the edge | `check_metrics_edge_acl`, plus a CI job that scrapes from outside |

The metrics row is the interesting one and the tree already says so in the route's own
docstring: `polaris_duress_events_total` is a page-able alarm, whoever can scrape it learns
that a duress alarm fired and roughly when, and the control is **access to the surface, not
suppression of the metric**, because the audience that needs to page is the audience that
would learn it. That control is enforced at two substrates, the Caddyfile and the Helm
configmap, each requiring a named matcher and a `respond 404`, and
`check_metrics_edge_acl` fails the build if either loses it or if CI stops exercising it.

**One real gap, and it was in a test rather than the system.**
`test_duress_is_visible_to_admin_and_auditor_only` logged in as admin and as operator and
never as an AUDITOR. Narrowing the template guard to `role == 'admin'` passed it while its
name still claimed otherwise. The auditor leg is there now, and the mutation turns it red.

**What remains, and it is narrower than the bullet was.** The guards separate OPERATOR from
admin and auditor. An admin or auditor who is the coercer sees everything, and no guard in
this table helps: that person is the authority. That is not a new finding, it is Coercer 3
above, where this directory's conclusion is already that the mechanism is **net-negative**,
because the duress record is append-only and institutional access reads it. The honest
statement is that the operator-as-coercer question decomposes into a part that is handled and
tested, and a part that is Coercer 3 and was never claimed to be solved.

**One structural note for whoever changes the dashboard.** The duress query in
`_dashboard_model` runs for every role; only the template withholds it. There is exactly one
caller today and it renders HTML, so nothing leaks. A JSON variant of that model, added
later, would carry the duress counts and the latest instant with it unless its author
remembered. The defence is at the render layer, not the query.

---

## What is still unmeasured

- **Long-run frequency analysis.** The design document accepts it rather than solving it. No
  measurement of how much an attacker learns from aggregate rates.
- **Enrolment-rate inference.** If few holders enrol, a `DuressEvent` is more identifying,
  which is the same anonymity-set problem measured in `lab/linkability/`.
