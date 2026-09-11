# The trusted referee

**Reader:** the authority designing an enrollment path that does not strand people, and the
assessor asking how an assurance level can rest on somebody's word without becoming a forgery
channel. **Job:** say what a vouching can and cannot produce, where each limit lives, and why
the bound asks for a second signature instead of refusing.

The mechanism is [`polaris_web/referee.py`](../../polaris_web/referee.py) over
`RefereeVouching`. The proofing engine it extends is
[identity-proofing.md](identity-proofing.md).

---

## 1. One mechanism, not two features

Every combination in NIST SP 800-63A starts from documents. A person with none fails all of
them: no fixed address, a care leaver, somebody who left a household in a hurry, a refugee, an
adult who never held a passport. An enrollment path that stops there has decided that the people
with least are the people who go without, and it will have decided it by omission rather than
by anybody choosing it.

The trusted referee is the answer to that. It is also the easiest way to mint an assurance level
out of nothing: find one corruptible caseworker and the documents stop mattering.

**Those are not two things to balance. They are the same table.** Every rule below exists
because the second sentence is true of the first, and the reason none of them is "refuse more"
is that refusing is the exclusion the mechanism exists to prevent.

---

## 2. What a vouching can produce

| Rule | Where it lives | Why |
| --- | --- | --- |
| A referee must be proofed at IAL2 or above | `MINIMUM_REFEREE_IAL`, and `cannot_vouch_above_own_level` in the schema | An unproofed person vouching for an unproofed person is two strangers agreeing |
| A vouching cannot exceed the referee's own level | `vouching_ceiling`, `cannot_vouch_above_own_level` | You cannot give what you do not have |
| **A vouching never reaches IAL3** | `VOUCHING_CEILING`, `vouching_never_reaches_ial3` | IAL3 needs the APPLICANT's live biometric in a supervised session. A referee can attest to who somebody is; a referee cannot be that person's face |
| Nobody vouches for themselves | `referee_is_not_the_applicant` | |
| A co-signer is a third person | `co_signer_is_a_third_person` | Past the bound the point is a second pair of eyes, and the referee's own are already on it |
| The relationship comes from a closed vocabulary | `RELATIONSHIPS`, and a `CHECK` | "Knows the applicant" covers a social worker and a stranger paid fifty pounds, and the difference is the whole control |

Note the second column. **Every limit is a database constraint, not only a module check.** The
module refuses earlier and with a reason, which is a different job: a refusal an operator cannot
act on sends them back to re-run the identical session and get the identical answer. But the
floor is in the schema, because a rule only the application enforces is a rule the next caller
does not meet, and this is the table where an assurance level gets minted from somebody's word.

The IAL3 cap is the one worth restating. A referee proofed at IAL3 is **still** capped at IAL2:
the ceiling is about what a third party can establish, not about how well the referee was
proofed. A system that let an attestation substitute for a biometric would have made its highest
assurance level the easiest one to forge.

---

## 3. The bound asks for a co-signer and never refuses

A referee who has vouched forty times this month is either a shelter worker doing exactly what
this path exists for, or a compromised channel. **Nothing in the database can tell those apart.**

- Refusing breaks the legitimate case, which is the exclusion this mechanism exists to prevent.
- Allowing silently makes the volume invisible, which is how a compromised referee stays one.

So past `VOUCHING_BOUND` vouchings in `VOUCHING_WINDOW_DAYS`, a vouching requires a **co-signer**:
a third proofed person who also puts their name to it. With one, it stands at any volume. This
is the same shape as the mass-revocation bound in UC-8, for the same reason: the answer to an
action that might be coercion is to make one person unable to take it alone.

The threshold is a judgment and is stated as one. What must not change is that crossing it asks
for a signature rather than closing the door.

---

## 4. What the credential does not say

`IdentityToken` gains no column, no flag and no reference to a vouching. The check and the drill
both verify this as an **absence** -- the drill asks the live catalog, because absences are the
kind of property that gets added back by accident.

A credential asserts an assurance **level**. It does not assert the circumstances its holder was
in when they got it. A person who enrolled through a referee has usually been through enough
without carrying a mark for it at every counter for the rest of their life, and a relying party
that needs to know the assurance level already has it.

The authority keeps the entire record, because a referee found to have vouched falsely makes
every credential they touched a question that has to be answerable. `vouchings_by()` is an index
scan, and `RefereeVouching` is the eighteenth audit-of-record instance, append-only: the list
cannot be shortened after the fact by the authority that would most want to shorten it.

**Accountability sits with the authority; the holder carries something that looks like everybody
else's.** Those are separable, and separating them is the whole design.

---

## 5. What is checked

| Mechanism | What it holds |
| --- | --- |
| `check_trusted_referee` | Every floor is in the schema; the surrogate id is 64-bit; `IdentityToken` mentions neither vouching nor referee; and the rules are EXERCISED -- the ceiling, self-vouching, the IAL3 cap, and the bound asking for a co-signer rather than refusing |
| `scripts/polaris-referee-drill.py` | Fourteen cases against a real PostgreSQL. Every refusal attempted as a DIRECT INSERT, append-only proven by trying to UPDATE and DELETE a recorded vouching, the bound checked in both directions, the compromise query answered, and the credential's own catalog asked for any trace of a vouching |
| `polaris_web/test_referee.py` | 23 measured tests, including that a referee may vouch BELOW their own level (an authority may hold itself to less than it could assert) and that the bound's refusal says in its own text that it is not a refusal |

---

## 6. What this does not do

- **It does not check that the referee is who they say they are at vouching time.** It records
  their proofed level, copied rather than joined, so a later downgrade does not silently rewrite
  what the vouching was worth. Whether the person in the room is the referee is the session's
  problem, and IAL2 is what that session was worth.
- **It does not detect collusion rings.** A refuses for B, B refuses for C, C for A: each is a
  valid vouching by a proofed referee. The bound and the enumerable record make a ring
  expensive and visible after the fact; nothing here prevents one.
- **It does not cover the enrollment code.** `ENROLLMENT_CODE` exists as a verification method
  and the process around it -- issuing a code to an address, a supervised redemption -- is still
  open under P4.4, alongside the kiosk build.
