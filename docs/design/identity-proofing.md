# Identity proofing, and the assurance it supports

**Reader:** an engineer building an enrollment station, or an assessor asking what an assurance
claim rests on. **Job:** what is recorded when a person is proven to be who they claim, how the
level is derived from it, and why the record deliberately cannot reconstruct their documents.

The implementation is [`polaris_web/proofing.py`](../../polaris_web/proofing.py) and
[`scripts/polaris-enrollment-proofing-drill.py`](../../scripts/polaris-enrollment-proofing-drill.py)
runs the whole evidence table against a real database on every push.

---

## 1. The gap this closes

Polaris could issue a credential and had no way to say how the person was proven to be who they
claimed. `EnrollmentStatusEvent` recorded *that* enrollment happened; nothing recorded what it
rested on. No assurance level could be asserted honestly, and the NIST 800-63-4 mapping
(roadmap P6.2) was blocked on exactly that.

`EnrollmentProofing` is one proofing event; `EnrollmentEvidence` is what it rested on. They are
the 16th and 17th audit-of-record instances and are append-only by trigger, because an
assurance level rests on the evidence recorded beside it and a record of that evidence which
can be edited afterwards is not evidence.

## 2. The level is derived, never asserted

An enrollment does not get to claim IAL2 because someone typed IAL2. `derive_ial` takes the
evidence actually recorded and returns the level that evidence supports.

| Level | What it takes |
|---|---|
| **IAL1** | The floor. Self-asserted, and not a failure: it is what a person gets when the evidence does not support more. |
| **IAL2** | One SUPERIOR piece, **or** two STRONG, **or** one STRONG and two FAIR. |
| **IAL3** | Two SUPERIOR, **or** one SUPERIOR and one STRONG, **or** two STRONG and one FAIR; **and** an in-person or supervised-remote session; **and** a live biometric. |

These are the combinations from the published NIST SP 800-63A evidence table. They are a
reading of a public standard rather than an authority's policy: an authority may require more,
never less, and the control-by-control mapping is P6.2.

**Claiming more than the evidence supports is refused, with the reason.** Claiming *less* is
allowed: an authority may hold itself to less than it could assert, and refusing that would
push operators to overstate in order to record anything at all. A refusal that only said "no"
would send the operator back to run the same session again, so `why_not_higher` says what is
missing rather than what is wrong.

**Returning IAL1 rather than raising** matters for the same reason. An authority that must
record *something* will otherwise record the level it wanted.

## 3. Evidence nobody checked is not evidence

Two different questions, and a piece of evidence has to pass both:

- **Validation**: is this document genuine?
- **Verification**: does it belong to the person in front of you?

A piece that fails either contributes **nothing**, whatever its nominal strength. The second is
the sharper one: **a genuine passport belonging to somebody else passes validation and fails
verification**, and counting it anyway is how an IAL2 enrollment ends up resting on a theft.
The nominal strength is still recorded, because an authority that looked at something and
rejected it has made a finding, and a record that silently omits rejected evidence cannot be
audited for what was considered.

## 4. Biometrics: a modality, never a template

`BiometricCapture` is the only shape the enrollment path accepts: a modality, a quality score,
a liveness result. There is no field for a template, so a vendor SDK is adapted at the edge and
its own types never reach the record. That is vendor-neutrality by construction; letting each
vendor's blob through and promising not to store it is a promise rather than a boundary.

**Liveness is not optional.** A photograph of a face and a lifted fingerprint both produce
excellent quality scores. A pipeline that scored them without checking liveness would raise the
recorded assurance of exactly the enrollments an attacker controls, so a capture that fails
liveness does not count toward IAL3, and the database refuses an IAL3 row whose liveness is not
true even on a direct `INSERT` that skips the application.

**Matching later is a different system.** An authority that needs to match a biometric needs a
template, with different retention, a different threat model and a different legal posture.
Polaris binds a credential to a modality and records that a live capture met a quality bar; it
does not become a biometric database in order to do it.

## 5. What has no column

No document number. No scan or image. No expiry date. No biometric template. No date of birth,
address, or knowledge-based answers. These are refused **by name** by the encoder and have
**no column** in either table: not "we do not write one", but nowhere to write it.

A row says that a STRONG piece of evidence of type PASSPORT was validated by a digital
signature check and bound to the applicant by biometric comparison. That is enough to justify a
level and not enough to reconstruct somebody's documents. **The difference is what keeps an
enrollment archive from being a second identity database sitting behind the first**, which is
the single most attractive target any identity system builds.

## 6. The current level is the latest, not the highest

`current_ial` returns the most recent proofing event's level, deliberately not the highest ever
reached. An authority that re-proofs someone and finds less than it found before has learned
something, and a record that kept the old high-water mark would be reporting a level nothing
currently supports.

## 7. What this row does not cover

- **The kiosk build.** A locked-down browser, its supervision model and its physical siting are
  deployment packaging, and remain open under P4.4.
- **Document authentication itself.** `validation_method` records *how* a document was checked;
  the checking is a vendor integration behind that interface.
- **The 800-63-4 control mapping.** This provides the mechanism and the record. The
  control-by-control mapping with evidence per control is P6.2, and it is unblocked by this.
- **The kiosk build.** Covered above: deployment packaging, still open under P4.4.

## How it was verified caps what it contributes

Validation asks whether a document is genuine. Verification asks whether it is **this
person's**, and the methods are not interchangeable at that job.

Until v9.395 they were treated as if they were. Any verification method that was not `NONE`
let evidence contribute its full nominal strength, so a passport "verified" by posting a code
to the address printed on it counted exactly as much as one verified against the face of the
person holding it. One `SUPERIOR` piece reaches IAL2, so that single record produced an IAL2
enrollment.

| Verification method | Ceiling | Why |
| --- | --- | --- |
| `BIOMETRIC_COMPARISON` | none | The binding the step exists for |
| `PHYSICAL_COMPARISON` | none | A trained operator comparing the document to the person |
| `ENROLLMENT_CODE` | `FAIR` | Proves somebody at that address opened a letter. An attacker needs physical control of a channel, which is real -- and it is not evidence that the applicant is the document's holder |
| `KNOWLEDGE_BASED` | `WEAK` | The answers live in credit files and breach dumps, so the barrier is a database rather than a mailbox |

The ceiling never raises anything: `FAIR` evidence verified by a posted code stays `FAIR`.
And the strong methods carry no ceiling on purpose, because capping the method that actually
binds a document to a person would push operators toward the weaker paths.

**The address is the part worth dwelling on.** A code sent to somebody's home proves whoever
opens that post controls the enrollment. For most people that is them. For a person in a
controlling household, a care setting, or a shelter with shared post, it is not -- and that is
the same population the [trusted referee](trusted-referee.md) path exists for. The cap does not
solve that. It stops the system recording a high assurance level on the strength of it.

Both capped methods were in the vocabulary from v9.371 and **no test used either**, which is
where an overstatement hides: a vocabulary entry nothing exercises.

---

## The enrollment code

A code is a secret sent to a channel the applicant nominated, which they return. What it
establishes is narrow and worth stating before the mechanism: **somebody who could reach that
channel returned the secret.** Not that they are the applicant. That is the whole reason
`ENROLLMENT_CODE` is capped at `FAIR` above; `EnrollmentCode` is the lifecycle under the cap
rather than an argument for raising it.

| Property | Where it lives |
| --- | --- |
| The code is never stored, only a SHA-256 of it | No column could hold one, checked as an absence |
| Validity is at most 30 days | `validity_is_bounded` |
| Redeemed only inside its validity | `redeemed_inside_its_validity` |
| At most 5 wrong guesses | `attempts_are_bounded`, and the module counts them |
| A redemption names the proofing it fed | `a_redeemed_code_names_its_proofing` |
| Single use, and never un-redeemed | `enrollment_code_one_way_door` |

**This is not an audit-of-record table**, and the difference is the design. A code is live
state: it gets redeemed and its attempts counted, so an append-only rule would make redemption
itself impossible. What it has instead is a **one-way door**. The hash, channel, holder,
issuing agency, issuance and expiry are fixed once written; `redeemed_at` leaves `NULL` exactly
once; `attempts` only climbs. Re-pointing a code at another person, extending a passed expiry
and resetting a counter about to lock all look administrative, and all three are refused.

**The attempt counter climbs on a wrong guess**, which is why redemption finds the code by *who
it was issued to* rather than by the hash of what was presented. Looking it up by the presented
hash would be simpler and would count nothing: a wrong guess matches no row, the counter never
moves, and the bound never sees the brute force it exists for.

`issue()` returns the plaintext exactly once and nothing stores it. That is what makes "never
stored" true rather than aspirational: there is nowhere to read it back from.

**None of this addresses whose mailbox it is.** A posted code proves whoever opens that post
controls the enrollment, and for a person in a controlling household, a care setting or a
shelter with shared post, that is not them. The channel is recorded because the coercion
properties differ and nothing downstream can reconstruct it, and the cap stops a high assurance
level resting on it -- but the honest position is that this mechanism helps most people and
fails the same population the [trusted referee](trusted-referee.md) exists for.

---

## Proven by

`scripts/polaris-enrollment-proofing-drill.py` on every push: eleven combinations across the
evidence table, evidence that was not validated or not verified, a spoofed biometric, a claimed
level above and below what the evidence supports, the append-only refusals on both tables, a
re-proofing that lowers the level, the database's own floor under IAL3 on a direct `INSERT`,
and the absence of any column for the document itself. `check_enrollment_proofing` pins them.
