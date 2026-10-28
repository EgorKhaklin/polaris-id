# lab/duress: the coercer the duress path is built for

**The lab's job is to falsify Polaris's differentiating claims.** This page records the result
and findings of the assessment the operating contract asked for.

**Result: the vocabulary is "duress-aware".** The mechanism is real and it works against the
coercer it was designed for: one who does not know duress codes exist.

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

`DuressEvent` is append-only by construction: `trg_duress_event_append_only` rejects UPDATE
and DELETE, it appears in no archive-or-purge path, and `polaris_sql/08_tests.sql` asserts
the DELETE is refused. That is C1 working exactly as intended.

---

## The casual coercer

Someone compelling a verification who does not know duress codes exist.

**Resisted.** The verification succeeds, the operator's screen is identical, the verification
list does not join `DuressEvent`, and the form field is labelled neutrally. The coercer
observes a successful verification and learns nothing. A silent alert is raised.

This is the adversary the mechanism was built for, and against this adversary it works.

---

## The vocabulary

| Claim | Supported? |
|---|---|
| A duress signal is invisible to a coercer at the counter who does not know duress codes exist | **Yes** |
| "duress-aware" | Supported |

`check_duress_claims_are_aware` refuses "compulsion-resistant" and its variants on any outward
surface, the same shape as the post-quantum agility guard, so a future README cannot quietly
restore them.

---

## Finding: weakening the claim nearly broke the operator-surface defence

**2026-09-13, caught by CI the same day.**

Replacing "compulsion-resistant by design" with "duress-aware by design" in the console's
`base.html` meta description put the literal word **duress** into every operator page.
`test_anti_revealing_verifications_list_excludes_duress` went red immediately.

The mechanism's defence at the counter is that an operator surface reveals nothing, and the
edit that weakened the *claim* damaged the *property*. The nav entry to the duress queue is
role-gated to admin and auditor for exactly this reason; an unconditional meta tag is not
gated by anything. The console now names no duress property in any wording, which is correct:
it is a surface a coercer reads over an operator's shoulder, not a place to state what the
system does.

The test caught it by luck rather than by design. It read one page, `/verifications`, and
found the leak only because `base.html` is inherited by all of them. A leak on any single
other page would have passed. It now sweeps every operator-reachable page, because the
property is "an operator never sees the word", not "one page does not show it".

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

**It reveals enrolment, not a code and not a signal.** The three safeguards were stated as
"the constant-time comparison with matched work on both paths"; matched work was true of
match versus no-match and had never been true of enrolled versus not-enrolled.

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
for mattering was that an operator-coercer could learn enrolment. **That fix was defeated by
a label.** Measuring a third of a second is harder than reading a page, and the page was
already open.

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

**And then the same question was asked of the whole surface, which found five more pages and
corrected the design record.** Four surfaces found by grepping a column name is four
surfaces, not a property. Walking every GET an operator may reach turned up `/metrics`,
`/api/metrics`, `/demo`, `/athena` and `/verifications/new`, and none of them is the same
kind of thing as a token card reading ENROLLED:

- `/metrics` and `/api/metrics` carry `polaris_duress_events_total`, the page-able alarm,
  under an edge ACL. They name no holder.
- `/demo` and `/athena` describe the MECHANISM. Its existence is public, in the README, the
  paper and `docs/design/`. They name no holder.
- `/verifications/new` ships the input as `name="duress_code"` behind a visible label reading
  "Holder verification code (optional)". A coercer glancing at the screen sees the neutral
  label, which is the standard the template itself states.

So the design record's sentence, "the word duress does not appear on the operator's screen",
was not true and could not be. It now states the property that IS enforced and that a coercer
actually cares about: **no page an operator can open says that a particular holder enrolled.**
`test_no_operator_reachable_page_reveals_that_a_HOLDER_enrolled` walks the route table and
asserts it, with every legitimate appearance declared beside its reason, because a regex
exclusion would have swallowed the original four in silence. It also fails when a declared
page stops being reachable, so the reasons cannot rot unread.

---

## Finding: the operator as coercer, audited surface by surface

**2026-09-17. Audited against the code, not argued.**

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
