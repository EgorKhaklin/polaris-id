# PRODUCTION-READINESS.md: what stands between this repository and real identity data

**Reader:** the operator or assessor deciding whether Polaris can hold real
national-identity data. **Job:** the bound on every claim in this repository.
Status first, then the decisions only a deploying organization can make, then
the engineering record with the check that pins each closed item.

**Status (v1.0.0-rc.31): not production-ready for real identity data.** Every
engineering gap this ledger enumerated is closed and pinned by a check (the
table at the end). The protocol layer (P8, v9.320 to v9.331: the registry, the
trust list, the exchange gateway and its receipts, the timestamp authority,
document signing, the auth broker, wallet presentations, algorithm agility and
versioning) is complete, conformant in both SDKs under the repository's own suite
(the one certification is of the OpenID4VP verifier, not of this layer: `polaris-oid4vp
1.0.0rc7` is OpenID Certified to the OpenID4VP 1.0 + HAIP 1.0 Verifier profile, 2026-09-24,
which says nothing about readiness for real identity data) and frozen at version 1; it changes nothing about this status. One retention fact to know (v9.341): the
timestamp authority keeps no per-request record, except one digest and one
instant per anchored timestamp, and only when the caller asked for the anchor.
Two holder-side facts to know (v9.349 to v9.352): a credential may carry a
holder key, so possession of the file is no longer possession of the
credential; and an epoch's leaves are Poseidon commitments a holder opens on
their own device, carrying a per-relying-party nullifier, so one relying party
can refuse a second claim from the same person without learning who they are
and without being able to compare notes with another. Neither hides a holder
from the ISSUER, which derives every leaf to build the tree.

Four facts to know from v9.374 to v9.394, each of which is easy to read as more than
it is. **The throughput targets were met and the system could not have run for a week
at them**, because an identifier column was 32 bits: five days at the stated sustained
verification rate, twelve hours at the peak one. Nothing was slow. The columns are
64-bit now and `check_capacity_model` recomputes the arithmetic from the live schema on
every push, but the lesson is the one to carry -- a capacity question answered in cores
and seconds is the easy half. **Three tools reported results they had not established.**
With no post-quantum library installed, the conformance runner scored 35 of 71 cases as
passes and the compat suite reported 24 of 44 holding, every one of them a rejection
case answered by a verifier that rejects everything; a third drill closed with a summary
asserting a property it had skipped. All three now refuse to report, and the rule names
no cause, because a missing library, a misconfigured backend and a future regression
produce the same false green. **The authority's most invasive power left no record of
its own use** until v9.382: the warrant-audit read went unlogged for as long as it
existed, because the read sits behind a stored procedure and nothing looking for a
SELECT found it. **And somebody with no documents can now be enrolled** through a
trusted referee -- bounded, co-signed past a threshold, and invisible on the credential
itself, because a person who needed one should not carry a mark for it at every counter.

Three facts from v9.403 to v9.415, all of them about the tests rather than the system, which is
the point. **The verification layer was asked the question it asks everything else**: not "does
it pass" but "would it notice". It often would not. Twenty-two drills printed their whole verdict
paragraph from zero recorded cases. Fourteen of the 37 database triggers, and twelve of the 17
non-primary-key unique indexes, could be dropped from the schema with the entire suite green,
including the index that stops two people holding the same token value. All three mechanisms
MISSION names are now mutation-tested on every push, and the triggers' full sweep runs weekly.
**The suite that proves C3 was the thing violating it.** Every negative property test did the
forbidden thing, COMMITTED, and then failed; with the one-active-token index absent that left a
permanent duplicate and the index could not be rebuilt. The same tests ended `except
psycopg2.Error`, which accepts any database error as proof, so a refusal for a missing column read
exactly like the invariant holding. **And a security claim was inferred rather than measured**:
PQC-POSTURE stated the internal hops' key exchange from base-image OpenSSL versions, and one hop
had been post-quantum for some time while the document called it classical. It is read off a real
handshake now.

Four more facts from v9.416 to v9.436, still about the verification layer rather than the system.
**The published conformance contract asked less than it appeared to.** Three artifact types --
agent-proof, grant-revocation, holder-proof -- had no case in which the signature was bad, so a
verifier that never checked theirs conformed; five of the published "valid" vectors had expired
months earlier and no case noticed, because none asserted freshness. Asking about freshness then
surfaced two divergences between the shipped reference verifiers: neither SDK bounded a holder
proof's age, so an integrator following one got no replay protection on presentations, and
neither could report whether an artifact's issuer was trusted at all. Both are fixed and all
three verifiers now agree on 118 cases.

**What conformance still does not prove is now stated where an integrator will read it.** 43
verdict fields are unconstrained by the published cases, and none of them can be closed by
writing a case: each needs a conforming verifier to compute something it does not. The contract
constrains what its WEAKEST conforming implementation computes, which is a property of the suite
worth knowing before relying on it. SECURITY.md says so.

**The stored procedures were the last part of the security boundary with no mutation test.** 59
refusals across 16 procedures; 27 could be deleted with the whole suite green. They concentrate
where the invariants are multi-step and a trigger cannot see them: the four-eyes rule, the
cool-down, the three out-of-band channels and the third-person witness in
`uc9_complete_recovery`, the preconditions on an irreversible erasure, and the only sanctioned
DELETE path against the audit tables. **All 27 are covered as of v9.437**, and the drill runs on
every push that touches a procedure with its declared-survivor list empty and checked in both
directions, so one that stops being covered fails rather than going quiet.

Three more facts from v9.437 to v9.458, all of them about the reference SDKs an integrator
actually builds against. **Both shipped verifiers could be made to accept what they exist to
reject.** Every refusal in each SDK was inverted in turn and the suites re-run: 18 of 18 in the
Python reference implementation, 9 of 14 in the TypeScript one, accepted with both that SDK's own
tests and the conformance runner green. The two that matter most to a relying party are an agent
grant's exhausted use count and an amount over its ceiling, which is the bound that makes P9.8
delegation something other than a bearer token, and the TypeScript SDK's constant-time comparison,
whose length guard inverted makes a five-byte value compare EQUAL to a 32-byte Merkle root. All are
closed in the SDKs' own tests, and the drill now inverts all 32 refusals on every push with a
per-SDK negative control, so a result of zero survivors is distinguishable from a harness that
never ran.

**That is not the conformance suite being broken, and the distinction bounds what conformance
means.** An SDK whose signature backends accept anything IS caught by the published cases. These
guards sit on inputs no case contains, so the contract certified what it exercised and these
refusals were outside it. An integrator relying on conformance alone should read it as the floor
it is.

**A drill can be wired into CI and still not run.** The two-SDK drill was added to a job that has
Python and a built liboqs and no Node dependency tree. It refused to report rather than calling an
unverifiable tree clean, which is the correct refusal, but the job then failed on its own setup
rather than on a finding. A red build that says nothing about the tree is how a real finding gets
waved through. The job installs what it runs now, and a check holds every job to that.

**One fact about unlinkability that a deploying organisation has to decide about (2026-09-13).**
Against a colluding pair of verifiers who pool complete transcripts, a presentation that
withholds the credential gives no advantage beyond the anonymity set: measured top-1 accuracy
tracks 1/N at every population size from 2 to 200, with a positive control that links the
exposed population at 1.0. **N is the epoch's membership.** `TokenStateEpoch` constrains
`committed_count > 0` and `<= 10000`, so there is no floor above one: an epoch that closes with
three members gives a colluding pair a one-in-three guess, and an epoch that closes with one
member identifies the holder outright. The verifier would still report that presentation's
correlation as bounded, correctly, because the verdict is about the transcript and the anonymity
set is about the population. `committed_count` is readable off the signed epoch checkpoint;
nothing requires a relying party to look at it, and no verdict mentions it. Timing, repeat-visit
patterns and network metadata are not modelled at all, and the adversary that produced that
result matches on EXACT EQUALITY only: shown a population that is perfectly linkable with no
equal field in it, it stays at chance, so the measurement says no field is identical across
verifiers and not that none is correlated. One channel it can read is transcript LENGTH, which
carried the entire above-chance residue in that control. This ledger used to add that nothing
in a bounded presentation varies in size per holder; that had never been measured, and the
harness that appeared to support it builds every holder from fixed-width values, so it would
have returned the same answer whether or not a leak existed. It has now been measured against
the shipped serializer, with a positive control the matcher solves at 1.0000
(`lab/linkability/transcript_size.py`): over 200 holders, a matcher reading nothing but the
byte count sits at chance on a bounded presentation (0.0040 against 0.0050), and reaches
**5.6 times chance on the presentation the wallet actually emits** (0.0280), because the
authenticity pack carries a free-text issuer name and an unpadded integer token id. That
transcript is already `exposed` on its token value, so size gives a colluding pair nothing
further there; the two facts come apart the moment a pack rides alongside a withheld
credential. The bounded result holds only while a bounded presentation carries no per-holder
variable-length field: disclosed attribute values, optional elements or a variable-length
status assertion would each open the channel. **The OpenID4VP path is a different answer and
is now measured too**: an SD-JWT VC presentation discloses the holder's own attribute values,
so over the same 200 people it falls into 16 distinct lengths rather than 3, those lengths are
holder-STABLE because a person's name is the same length at every verifier, and one
observation requiring no field to be read narrows 200 holders to about 23. Nothing there is
broken: selective disclosure means disclosing, and a name is not a fixed-width field in any
country. It is recorded because a deploying organisation choosing that door is choosing this
with it. `lab/linkability/`.

**Eleven defects on the authentication surface (2026-09-17).** MISSION names the operator
password as "the compulsion surface that matters most: a coerced or phished operator password
reaches every use case", and an adversarial review of it found eleven, all reproduced by
running code. **An account could be locked exactly once, ever**: the lock statement held only
while the account had never been locked, and nothing clears that field when a lock expires, so
after the first fifteen minutes lapsed thirty-five further wrong passwords moved nothing and
the account accepted unlimited online guessing until the legitimate operator next signed in.
**The lock deadline was compared against the wrong machine's clock**, the application process
against a value the database wrote, so a database six hours behind made the lock a no-op from
the moment it was written and six hours ahead turned fifteen minutes into six. **The failure
window was published and compared nowhere**: the control says five failures within ten minutes
and the counter decayed only on a successful sign-in, so failures a fortnight apart
accumulated. **A demoted administrator kept their rights** for up to the eight-hour session
lifetime, because the per-request check re-read whether the account was active and never its
role, while deactivation took effect immediately. **A successful-authentication event was
recorded for sign-ins that never completed**, so the append-only audit could not tell an
authentication that finished from one that only proved a password, which is the exact
distinction that framing turns on. The rest: the authenticator allow-list applied at enrolment
and never again, so narrowing it on a running deployment left every enrolled model working; a
rate-limit window of zero silently removed the flood bound on every state-changing route; a
session setting beyond the database's range passed the boot the validator promises it would
fail and then broke every request; an exempt role could enrol a second factor the sign-in
discarded; a non-finite number reached an unhandled error on a relying-party endpoint; and an
applicant typing an accented character crashed the enrolment-code path instead of being
refused. All eleven are fixed with tests, two schema migrations and a new invariant check, and
each mechanism is shown to fail when removed.

**A credential past its own expiry stayed usable, and the dashboard was counting them
(2026-09-17).** `IdentityToken.expiration_date` is written at issuance, `ACTIVE -> EXPIRED` is
a legal transition in the credential state machine, and the operator dashboard has a counter
for active credentials past their expiry. Nothing drove that transition: no sweeper exists,
and **no verification path compared the column at all**. Both endpoints decided
`currently_authoritative` on the status column alone, which `docs/reference/API.md` describes
as "the usable right now authorization verdict". So the count on the dashboard grew and every
credential in it answered usable. Found by mapping where each security decision is made, which
is the other half of why that map now exists. Both endpoints share one predicate, enforced at
read time rather than by a background job, because a sweeper that stops running silently
restores the defect and a predicate cannot stop running. A credential is valid through its
expiry date; a null expiry never expires; an unreadable one counts as expired. The schema will
not allow an already-expired credential to be issued, so that state was only ever reachable by
the passage of time, which is why it went unnoticed for as long as it did.

**Where each security decision is made is now written down**
(`docs/reference/SECURITY-DECISIONS.md`). It names the file and the symbol for issuance
authorization, authority binding, expiry, revocation, proof verification, replay protection,
trust-edge validity, primary-database reads, audit writing, the database invariants that are
load-bearing, key selection and administrative authorization, says which layer is
authoritative where a decision is split across several, and names the check that pins each. It
exists because an outside review asked whether a reviewer could find any of this in a
nine-thousand-line module, and the answer was no.

**The two reference SDKs disagreed with each other, and one of them with the wire
specification (2026-09-17).** `polaris-sdk-python` and `polaris-sdk-ts` exist so an integrator
can build against either and get the same security answer. A differential review found them
giving different answers on inputs a federation of national agencies produces every day. **The
TypeScript SDK's canonicalisation was not the wire format's**: it emitted raw UTF-8 where the
specification pins Python's escaped form, so an artifact whose signer carries an accent, or
whose purpose is written in Japanese, verified in Python and was REJECTED as a forgery in
TypeScript. Its own comment claimed the two matched byte for byte. No JSON fixture in the tree
carries a non-ASCII byte, which is why nothing caught it. **And it read an instant with no UTC
offset as LOCAL time**, where the reference stamps it UTC, so an artifact whose window closed
three hours earlier verified as fresh for every verifier west of Greenwich and stale for every
one east of it; the two sides disagreed on twelve of thirty-three freshness cases. Three more
were the same non-finite-number class found elsewhere that day, one in each SDK, each a hole
the other did not have. One let a Merkle inclusion proof report a leaf INCLUDED when the
caller passed hex strings instead of bytes, which is the form those values arrive in. All are
fixed, with a differential test comparing the canonical forms byte for byte and the instants
across five offset shapes. **One divergence cannot be fixed at this layer and is now stated in
the verdict rather than silently rejected**: the canonical form distinguishes `4` from `4.0`
and JavaScript has one number type, so a grant signing a monetary limit as a float cannot be
checked by the TypeScript SDK, which now says so instead of reporting a forgery.

**Eleven defects in the detached verifier, from the same day's review of the PRIMARY external
door (2026-09-17).** `polaris-verify` is the package a stranger installs, and every finding
below was reproduced by running code before anything was changed. **A trust attestation's
`valid_until` is in the signed statement and was compared to nothing**: the word appeared
exactly once in the file, inside the canonicaliser, and no consumer read it, so a trust edge an
authority time-boxed to one year kept granting cross-authority acceptance six years past its
end, and so did one whose window said "not-a-date". That contradicts the wire specification's
own sentence about the attestation binding "the window, so it cannot be extended". **An agent
grant's spending limit was defeated by a single non-numeric value**: `limits` is inside the
signed statement, so a grant signed with a non-finite `max_amount` was a signed UNLIMITED grant
wearing a limit field, and the infinite case crashed rather than refusing. **The epoch fork
detector was defeated the same way**: every comparison against a non-finite number is false, so
two checkpoints with different roots at the same epoch reported agreement instead of a fork.
**A key-revocation lookup defaulted to "active"** for every status it did not recognise, so a
capitalised `COMPROMISED` read as a usable key. Five entry points raised instead of returning a
verdict, one of them the pack verifier itself, which came out of the shipped command as a
traceback with empty output and an exit code the documentation does not define. The mdoc CBOR
decoder had no depth limit and segmentation-faulted the process on a thousand nested arrays.
The QR decoder raised on one non-ASCII byte. Two hand-rolled freshness caps failed OPEN where
the shared one failed closed. All eleven are fixed with tests, each shown to fail when its
mechanism is removed, and the totality battery that missed five of them now carries
wrong-typed and non-finite values.

**The same defect, found a fourth time, and moved to the door (2026-09-17).** Non-finite
numbers had by then been repaired at four call sites in three products, each repair correct and
each local. A mechanical sweep of every `int()` and `float()` in the tree found four more in the
detached verifier, all of them inclusion-proof or public-input reads whose docstrings promise a
verdict on hostile input: a proof carrying `"index": Infinity` raised `OverflowError` out of
`verify_timestamp_anchor`, `verify_receipt_inclusion`, `verify_zk_against_root` and
`verify_publication`, because `int(float('inf'))` raises an exception that
`except (TypeError, ValueError)` does not catch. The Python SDK had a fifth of its own, and a
worse shape: it believed whatever `expires_in` the issuer sent, so `1e308` converted cleanly and
pinned a cached bearer token past the life of the process, which is a client that keeps
presenting a token after its credentials are revoked. The lifetime is now finite, positive and
capped at 24 hours.

The Flask application had the same hole on every handler that reads a JSON body, and
fixing them one call site at a time leaves
the 22nd to be written, so the refusal moved to the one place there is: a JSON provider that
refuses `NaN`, `Infinity`, `-Infinity` **and** overflowing exponents before any handler sees the
body. The exponent leg is the half that looks unnecessary and is not: `1e400` is ordinary JSON
grammar that never reaches `parse_constant` and overflows to infinity inside `float()`, so a
door built only on `parse_constant` reads as complete and admits it. `check_json_door_refuses_non_finite`
fails the build for either half missing, and its detection test asserts exactly that shape.

**A second field the holder signs and the verifier ignored (2026-09-17).** `valid_until` was
found by hand. Asking the same question mechanically, of every canonicaliser in the detached
verifier, found `agent_algorithm`: an agent grant names the algorithm the agent's key is for,
inside the statement the HOLDER signs, and `verify_agent_grant` verified the agent's proof under
the algorithm the PROOF declared, which is the agent's own unsigned word about itself. The wire
specification's sentence about grants is that a scope editable in transit "would be the unbounded
credential hand-over that grants exist to replace"; an algorithm the agent chooses is that, one
field over. A proof that names an algorithm the grant did not authorize is now refused rather
than verified. `scripts/polaris-unread-signed-fields.py` is the sweep, kept so the question can be
asked again, and it fails on any signed field nobody has declared a reason for.

The other eleven it reports were triaged field by field and none of them is fixed here, which is
a decision worth stating rather than leaving as a gap in a list. Five are **bound by something
stronger**: `attested_agency_id` because the edge is bound by the attested KEY rather than a
number naming its owner, `iss` because issuer trust is decided against the anchor keys,
`attested_date` because `valid_until` now bounds the edge, and the registry's `contexts` and
`relying_parties` because they are directory data no decision is taken on. Six are **signed,
and not surfaced**: the verifier does not act on them, no published contract says it must, and
a relying party cannot see them in the verdict. The two an assessor should weigh are
`epoch_number` on a revocation feed, where `as_of` is the monotonic field the specification
names and two feeds whose `as_of` advances while `epoch_number` regresses are accepted as
legitimate progression; and `purpose` on a signed document, which means an operator cannot see
whether a signature made for one purpose is being read as authorization for another. The
remaining four are `auth_time` (so no OIDC-style `max_age` can be derived), `authorized_via`,
`bound_at` and `revoked_at`.

None of the six is changed, because the operating contract admits a product change for a named
external requirement or an executable counterexample against an existing promise, and these are
neither: no contract promises them and no test can be written that shows one broken. The reasons
live in the script's own declared list, so the next person to read this does not have to derive
them again.

**The ten constraints themselves had never been mutation-tested, and one of them was not
enforced (2026-09-17).** CHECK constraints, triggers, the ZK witnesses, the conformance
contract, the stored procedures, both SDKs and the Flask application all have a drill that
inverts a mechanism and requires something to go red. Every one of those asks the question of
a MECHANISM. Nothing asked it of C1 to C10, which are the claims the mechanisms exist to
serve. `scripts/polaris-constitution-mutation-drill.py` now does: it deletes each
constraint's enforcement in turn and requires that constraint's OWN named check to fail.

First run: **nine of ten held, C8 did not.** The clamp on `/api/atlas/points` could be
deleted, leaving a caller-controlled result-set size unbounded, while `check_c8_atlas_caps`
reported "all 10 caller-controlled counts across 17 atlas routes are clamped". Its regex
accepted `limit <= 0` as a cap, which is a LOWER bound; C8 bounds a result set from above, and
rejecting zero is not a cap. A bare `_ATLAS_MAX` unbound to the parameter did the rest, so a
constant named anywhere in a route vouched for every count in it. The application suite and
the check's own detection tests passed throughout. The check's own comment says it was
written because "the constants existing is not the invariant ... Mechanism present, property
assumed"; the regex did that one level down, which is worth recording as a thing that happens
to checks and not only to code.

A file-level audit ran first and came back clean: all ten constraints have pinning checks that
read every file their claim names. That was not enough, and the gap between "reads the right
file" and "would notice the enforcement leaving" is the whole reason this drill exists.

**Thirty-one of thirty-seven refusals the application makes were untested, and the login rate
limiter was the only one of fourteen that anything exercised (2026-09-17).** CHECK constraints
have been mutation-tested since v9.407, triggers since v9.413, the ZK witnesses since v9.419,
the conformance contract since v9.429, the stored procedures since v9.437 and both SDKs since
v9.458. The Flask application was the member of that family nobody had measured, and three of
the ten constraints are enforced there and nowhere else.
`scripts/polaris-app-mutation-drill.py` replaces one refusal's condition with `False` at a time
and asks whether any test turns red. Of the 37 refusals answering 401, 403, 409, 413 or 429,
**31 survived**: the suite stayed green without them.

They are not all equal, and the drill's declared list says which is which. Seven are covered by
`scripts/polaris-federation-instances-drill.py`, which stands up two instances and speaks HTTP
because a mediated exchange needs real ML-DSA; what the survivor means there is that a developer
running the SUITE gets no signal, so the drill has to actually run. Three are defence-in-depth
assertions behind `login_required` that no test can reach. The rest were genuinely untested, and
five of them are authentication decisions: an authenticator model refused by policy could still
complete a login (the assertion path never consulted the policy that registration did, and the
commit that added that policy claimed the existing tests covered it, which this drill disproved);
any enrolled credential could finish any admin's second factor; an admin past the enrolment
deadline with no credential was refused by code no test exercised; one authority could sign for
another authority's credential; and a credential that was no longer ACTIVE could still authorize
a signature. All five now have tests, each shown to fail when its refusal is switched off.

The drill now exits clean on those 37: every survivor carries a stated reason, and the six that
remain uncovered by a test are the coarse velocity bounds, pinned structurally instead. Two of
the reasons are worth reading. One refusal is **dead code behind a stronger layer**: the epoch
leaves route answers 413 above ten thousand leaves, and the schema's `epoch_committed_count_cap`
refuses to store such an epoch at all, so the application's branch cannot fire. Writing the test
found that rather than the other way round, and the test that stands there now pins the two caps
to each other, because raising the schema's alone would make the 413 reachable, untested, and
the only thing between a caller and an unbounded body. The other is that a **bearer token
outlived the relying party's standing to use it**: the lookup on every verification is what makes
withdrawing a relying party take effect immediately rather than when its token happens to expire.

**The 400 and 404 surface is measured and OPEN.** The same drill run with `--all` covers the
other 76 refusals, the ones answering "that request is malformed" or "there is no such thing"
rather than "you may not", and 35 of them survive. That is not 35 defects. Most are
input-validation guards with another guard behind them, so switching one off does not make the
route accept the input, and what actually matters there is the property `JsonRouteTotalityTests`
asserts: that no body shape reaches a raise. Asserting it found a real defect nobody had
mutated, in `request.get_json(silent=True) or {}`, which is truthy for a JSON string, number or
list, so an anonymous caller could make the unauthenticated authorization endpoint raise by
sending `"a string"`. Twenty-one routes carried that idiom and now go through one helper, pinned
by `check_json_body_must_be_an_object`.

Which of those refuse for their own reason and which are masked by a neighbour is now
**measured rather than assumed**, which was the open item. The drill's `--probe` mode asks each
route what it ANSWERS with the refusal switched off, against the same bodies before and after:
27 of 32 answer identically, so something after them refuses the same input, and **three accept
input they used to turn away**. All three are on the timestamp authority, and they are the
reason that route can call itself one.

**The timestamp authority signed whatever it was handed (2026-09-17).** Its docstring promises
that "the content itself is never sent, so the authority learns nothing"; the `digest_hex` shape
check is the entirety of that promise. With it switched off the route ACCEPTS, so a caller puts
arbitrary text where a digest belongs and receives the authority's signature over it inside a
`polaris-timestamp/1` that an independent party verifies offline. The other two are the same
shape one field over: an unchecked `digest_algorithm` lets the signed statement name an
algorithm the authority did not compute, and an unbounded `nonce` is echoed into the signed
statement whatever it is. All three now have tests; switching the three off turns 21 assertions
red.

Two further ACCEPTS that run reported were **artifacts of the probe, not defects**, and the
distinction was worth chasing down rather than writing up. The test classes for the two guarded
WebAuthn routes enrol a credential for the seeded admin, so every probe after them lands on the
second factor instead of the dashboard, and an unauthenticated `302` is below 400 and reads as
acceptance. The probe now refuses to report when it is not signed in, and those cases come back
as "unprobed", which is a third thing from "masked" and from "a hole".

Separately, of the fourteen rate limiters the application installs, **the login one was the only
one any test drove**. `F03_RateLimitingTests` now drives the five holder-facing limiters past
their bounds; the rest are coarse velocity bounds of 120 to 600 per minute, which a unit test
cannot drive for less than it would cost, so `check_rate_limits_are_enforced` pins them
structurally: each must sit inside a negated guard that answers 429, so a limiter whose answer
stops being acted on fails the build. A structural pin proves the guard is written, not that it
fires, and the check's message says so.

**The local gate was narrower than CI in nine places, and the check that existed to prevent
that reported OK (2026-09-17).** `check_local_gate_covers_ci` was written so that a suite CI
runs cannot be one the ship tool has never heard of. It compared the ship tool against
`scripts/polaris-coverage.sh` and called that CI. The workflow that gates the push is
`.github/workflows/ci.yml`, and it ran nine suites coverage.sh does not mention, among them
`sdk/python/test_sdk.py` and all six polaris-oid4vp suites. The consequence arrived the same
day: a refusal note in `grant_within_limits` was reworded, `test_sdk` held the old phrase, the
local gate reported READY, and CI went red on a commit that had passed it. The check now reads
the workflow, the nine suites are named in `UNSHARDED_SUITES`, and `polaris-preflight.sh` RUNS
the eight that need no database, network or ML-DSA rather than only naming them. A check that
reads a proxy for the thing it checks is measuring the proxy.

**Fifteen defects in the OpenID4VP verifier, found by adversarial review (2026-09-17).**
`polaris-oid4vp` is the newest external door: unmodified third-party wallets present to it
over the network. An adversarial review ran code against the shipped module rather than
reading it, and every finding below was reproduced before anything was changed. Five let a
presentation through that should have been refused: neither `exp` nor `nbf` appeared anywhere
in the file, so a credential its own issuer stamped as expired ten years ago verified as
authentic, and the capture from the hosted conformance suite carries a fourteen-day expiry
this verifier was ignoring; a key binding `iat` of `NaN` defeated the freshness window
completely, because every comparison against NaN is false, and the presentation verified with
the clock a year ahead; a disclosure could overwrite a signed claim, so one named `cnf`
returned a key that was not the key the binding had been checked against; the credential type
the DCQL query asked for was built into the request and never compared, so a loyalty card's
`given_name` came back as though it were a personal identification credential's; and the
issuer certificate check was a signature plus an issuer/subject match, which promoted every
end-entity certificate the trust anchor had ever issued, TLS server certificates included.
Four were denial of service with no credential: a single packet declaring a negative
Content-Length took the listener off the air for every wallet; 2.7 KB of nested JSON raised
`RecursionError` out of a verifier documented never to raise; a 6 KB credential cost the
disclosure resolver 2^30 node visits; and there was no input-size bound anywhere, so a 117 MiB
presentation verified as authentic. Five more raised instead of returning a verdict. One was
interoperability in the other direction: recursive disclosures, which the specification
requires and the European digital identity wallet's personal identification credential uses
for `address`, were rejected as uncommitted. All fifteen are fixed with tests, each shown to
fail when its mechanism is removed. Two things to carry from it. **The certificate finding is
the mirror of the walt.id result**: that wallet refused Polaris for emitting a certificate
with no `digitalSignature` key usage, and this verifier was not reading that field on the way
in. **And nothing in this repository had caught any of them**: eleven conformance modules, the
package's own tests and every invariant check passed over all fifteen, because a conformance
suite constrains what it exercises and none of these was on its list.

**Two facts about the migration path, for the same reader (2026-09-13).** The agility is real
issuer-side: the algorithm is a row with a `deprecation_date`, `uc6_migrate_algorithm` re-signs a
token under a new one, and CI re-signs a whole population under real ML-DSA-87 on every push.
**A verifier cannot learn that an algorithm has been deprecated.** `deprecation_date` reaches no
signed artifact: the registry publishes `protocol.algorithms` as a bare name list, the trust list
carries per-KEY status only, and the detached verifier's accepted set is a hardcoded dict. So
retiring an algorithm is a software release to every relying party, not a migration, and adding
one is too. **Key revocation does not substitute:** if the assumption breaks an attacker forges
under any key the trust list calls active, so revoking one stops nothing and revoking all of them
is how "every credential issued under the broken algorithm is lost" is actually reached, one
`key-compromise` at a time with no algorithm-level lever. Rollback and the mixed window during a
partial migration are unmeasured. `lab/crypto-migration/`.

**And a third, measured 2026-09-17** (`lab/crypto-migration/algorithm_status.py`). `CryptographicAlgorithm` carries a `deprecation_date` and it reaches NO signed artifact: across the twenty signed formats the wire specification defines, none carries an algorithm's standing. An issuer can record that an algorithm is deprecated and no verifier will ever find out. The only lever a relying party has is its accepted-algorithm set, which is a hardcoded dict in the shipped verifier, so retiring an algorithm is a software release to every integrator rather than a migration. What that costs mid-migration is now measured against the verifier's own predicate: at 90 per cent re-signed, a relying party that drops the old algorithm turns away one holder in ten, and **no artifact tells it which fraction it is at**, so it cannot choose the moment. Rollback and the cost of re-signing at scale remain unmeasured.

**And a fourth, measured 2026-09-18** (`lab/crypto-migration/rollback.py`). The 2026-09-13
entry above lists rollback as unmeasured. It is not any more, and the answer is sharper than
"unmeasured" suggested: there is no rollback at all.
`one_signature_per_algorithm_per_token` means a token can never hold a second signature under an
algorithm it has already used, so an authority that migrates a population A to B and then learns
B is the problem cannot return it to A. Not by un-setting a `deprecation_date`, which the
immutability trigger refuses, and not by calling the procedure again, which the unique constraint
refuses whether or not anything was deprecated. The only move is sideways, to a third algorithm
that must already exist, be keyed, and not itself be deprecated on the day. That is intended
rather than a defect, because TokenSignature is the audit of record for migrations and a record
you can walk back is not one, but it makes provisioning a spare algorithm a migration-planning
prerequisite the schema cannot supply in the emergency. Stated in
[design/multi-sig-migration.md](design/multi-sig-migration.md) and carried as L-13 on the review
packet.

**Which closes that sentence, and the correction is worth keeping.** This entry first said the
mixed window was still unmeasured. It is not, and had not been since the day before the sentence
was written: `algorithm_status.py` measured it on 2026-09-17 and `lab/crypto-migration/README.md`
carries the table under a heading that says so. Over 10,000 holders, a relying party that drops
the old algorithm locks out the fraction not yet re-signed, one in ten at 90 per cent re-signed,
and **no signed artifact tells it which row it is on**. That is the finding rather than the
curve, and it is L-12. What is left is not a measurement anybody here can take: a real
population's migration rate is a deployment fact, and the ledger should say that rather than
calling it unmeasured, which implies somebody could go and measure it in this repository.

**And the measurement instruments were wrong three times in ways that flattered them.** The
conformance drill counted 22 fields that were not fields and misclassified what fixing the rest
would take, twice. Of a 45-point fall in its headline number, 18 was work and 27 was correcting
the instrument. Every intermediate figure had been reported as if it measured the contract. The
lesson this ledger already carried -- ask whether it would notice, not whether it passes -- turns
out to apply to the things doing the asking.

**One fact about the cryptography, which the outward surfaces have been stating as more than it
is.** Polaris is described as post-quantum. What is defensible is narrower and more useful:
**algorithm agility under an audited migration path**. The distinction is not pedantry, because
the two fail differently.

ML-DSA-65's security does not rest on a prediction about how large quantum computers will get. It
rests on the hardness of Module-LWE and Module-SIS against the best known classical AND quantum
algorithms. So the argument "post-quantum is unprovable because the hardware is unpredictable"
attacks the wrong thing. The two ways this breaks are a **cryptanalytic advance against the lattice
assumptions** and an **implementation flaw**, and the design answers each: SLH-DSA-128s and
SLH-DSA-256s are registered with no signer precisely because they rest on hash functions alone
rather than on lattices, and issuance requires two independent ML-DSA implementations (liboqs and
OpenSSL through `cryptography`) that must agree.

What a break in Module-LWE would cost, stated plainly. It would **not** require a schema change, a
code change on the verification path, or a new trust model: the algorithm is a row in
`CryptographicAlgorithm`, not a constant, which is C7. Registering a replacement, authorizing it
per authority through `AgencyAlgorithmAuth`, and migrating credentials through `uc6_migrate` is a
path that RUNS and is exercised on every push, not a plan. It **would** cost every credential
already issued under the broken algorithm, and here is the part no agility buys back: a credential
carries classical and post-quantum signatures during a cutover, and the classical half is
protected by nothing this design provides. A holder's credential that was harvested today is
readable on the day its classical signature falls, whatever Polaris migrates to afterwards. That is
the asymmetry that makes signing post-quantum now worth doing, and it is also the limit of what
doing it achieves.

And the exposure a reader should know before believing the word. **The default signing path is not
post-quantum.** Without `POLARIS_USE_REAL_PQC=1` and liboqs present,
`TokenSignature.signature_bytes` holds a 32-byte deterministic SHA3-256 value labelled
`DETERMINISTIC-PLACEHOLDER-SHA3-256` that verifies against no key; real ML-DSA-65 produces 3,309
bytes. That is the default in CI. It is guarded -- production fails closed at boot without real
signing, the placeholder is a named development profile, and it warns loudly when used unnamed --
but a repository whose default path signs with a placeholder should not call itself post-quantum
without saying so in the same breath. `check_post_quantum_claims_are_agility` refuses an outward
surface that asserts post-quantum SECURITY rather than post-quantum AGILITY, and refuses one that
claims either without pointing here.

None of that changed what the system does. All of it changed what is known about it, which is the
only thing this ledger is for.

Four earlier facts, still true. **The physical layer is a specification, an emulator and published
vectors, not a card.** `polaris_card/` defines the on-card object, speaks ISO
7816-4, personalizes a token whose keys it generates itself, and drives a
reference verifier device; no card is manufactured and no silicon is certified,
and the profile states which of its properties an emulator cannot establish.
**An enrollment now records what it rested on**, and the assurance level is
derived from that evidence rather than entered, with no column anywhere for the
document itself; that is a mechanism, and no proofing has been performed with
it. **The NIST 800-63 mapping is machine-checked and is not a conformance
claim**: every row cites an artifact that CI resolves and runs, no assessment
has taken place, and a deployment does not inherit any of it. **Accessibility is
enforced for the third that automation covers**, which is why accessibility
conformance is still in the list below rather than out of it. What remains is
not buildable here: ten decisions that
belong to the deploying organization, one engineering limit carried openly,
and the deployment-scale work that [ROADMAP.md](../ROADMAP.md) tracks phase by
phase. [MISSION.md](../MISSION.md) still governs every change, and
[THESIS.md](THESIS.md) records why this project refuses to overclaim.

---

## Decisions only the operator can make

Production with real identity data cannot proceed until each of these is
recorded as made for a named deployment.

| Decision | What ships today | What the deploying organization supplies |
|---|---|---|
| **Legal basis, DPIA, regulator approval** | Nothing; this is not an engineering task. | A named controller, the jurisdiction, a counsel-drafted DPIA, regulatory sign-off. |
| **Signing-key custody** | `polaris_web/custody.py` with `file`, `pkcs11` (proven in CI against a Kryoptic token) and `kms` drivers; [KEY-CEREMONY.md](operator/KEY-CEREMONY.md). | Which custody driver, the HSM or KMS itself, who holds the key, and the rotation authority. |
| **Postgres HA topology** | The HA profile (v9.243): the database under Patroni with a leader lease in etcd and HAProxy routing, automated failover drilled on every push under a live write stream, the split-brain analysis in [FAILOVER.md](operator/FAILOVER.md); the Helm profile runs the same members with the cluster's API as the lease store (v9.244). | The hosts the two members and the three etcd members run on, and whether to trade commit latency for zero data loss (synchronous replication). |
| **Encryption at rest** | [ENCRYPTION-AT-REST.md](operator/ENCRYPTION-AT-REST.md) names the plaintext surfaces; backups and every transit hop are encrypted. | The host volume encryption (LUKS, TDE or fscrypt) and its key custodian. |
| **Offsite backup target** | pgBackRest to an S3-compatible bucket by environment variable (v9.173); the monthly DR drill (v9.192) measures RPO and RTO against the 300 s and 4 h targets in [DR-DRILLS.md](operator/DR-DRILLS.md). | The bucket, its retention, and the schedule. |
| **Alerting backend and on-call** | Alert rules, Alertmanager routing with the duress page at no delay, a pager webhook read from a secret file, a CI drill that proves a duress event reaches the webhook (v9.175), and a weekly chaos drill that stops both app colours until the outage page reaches it (v9.242, [CHAOS-DRILLS.md](operator/CHAOS-DRILLS.md)). | The pager product and its URL, and the named rotation, including who receives the duress page. |
| **Right-to-erasure policy** | The pseudonymization mechanism: `uc_pseudonymize_individual` and the append-only `IndividualErasureEvent` (v9.125). | Which erasures to honor and crypto-shred versus pseudonymize against the append-only audit. |
| **Retention schedule** | The engine: `RetentionPolicy` holds the decision per table class and jurisdiction with a 365-day CHECK floor, append-only with one-way supersession, and `uc_archive_purge` refuses a cutoff inside the window (v9.234, [retention.md](design/retention.md)). Ships at five years for every class. | The days each class is kept in this jurisdiction, and the counsel who says the number satisfies the statute. Polaris records the decision and its justification; it does not know the law. |
| **Operator MFA enforcement** | The whole WebAuthn mechanism: registration, assertion bound to the partially-authenticated user, a per-account enrollment deadline, second-admin recovery pairing and a printed recovery code. Once an admin enrolls a credential, MFA is mandatory on every login and cannot be skipped. | Which recovery path a deployment will honour when an admin loses their key, and what it does about admins that predate the policy. This row said something false until 2026-09-17: that no provisioning path set `AppUser.webauthn_required_after`. `scripts/polaris-create-operator.sh --role admin` had always set it to thirty days; `polaris-id user-create NAME admin` had always left it NULL, which the design record reads as "the password is sufficient". Two documented doors onto the same account type, different second-factor defaults, and nothing saying so. Both now give thirty days and `check_admin_mfa_deadline` fails the build if they diverge again. An account created BEFORE that fix still carries no deadline; `scripts/polaris-set-webauthn-deadline.sh` sets one, and the query in OPERATIONS.md lists who is affected. |
| **Independent penetration test and threat-model sign-off** | The readiness pack in [RED-TEAM-SCOPE.md](RED-TEAM-SCOPE.md); roadmap row P1.12. | The firm, the funding, and an accountable human signature. |
| **What may leave the database, and what may be joined to it** | Nothing, and nothing here can. Every constraint in this repository binds THIS schema and THIS application: C1's append-only triggers, C2's CHECK that a zero-knowledge event carries no token id, C8's bounded aggregates, the audit of record. A verification event copied into a fraud-analytics store, a nightly extract, or a support tool is outside all of them. | A written rule on what may be exported and what may be joined to it, and an audit that checks. This is the decision most able to make the rest of the list pointless: an organisation can satisfy every constraint here, pass every check, and keep a parallel store next door that reconstructs exactly the correlation C2 exists to prevent, at which point the side system is the identity system and nothing in this repository fails. The constraints are strongest where the data is, and they say nothing about where it goes. |
| **What a holder does when their one live token is gone** | C3 permits at most one ACTIVE token per person, enforced by a partial unique index, and UC-9 is the route back: a two-phase ceremony with a cooldown, operator MFA and a second human. Both are real and both are measured. | The service level on that ceremony, and what a person is entitled to in the meantime. C3 is stated in MISSION.md for its security rationale, which is that two active tokens let one authorize what the other repudiates. Its cost to the holder is not stated anywhere and is this: a person whose token is revoked, lost or destroyed cannot present anything at any door until the ceremony completes, and the cleanliness of that is the hazard. Unpersoning used to need a thousand offices and leave a thousand traces; here it needs one write, which cannot be quietly undone but does not need to be. The audit trail makes it loud, not slow. How long a person may be left in that state, and who is accountable for it, is a policy decision no schema can make. |

One engineering limit is carried openly, and since v9.243 only its edge half
remains (every latency below is measured by the CI drills on an ephemeral single
host or a kind cluster, not on production multi-node hardware): recreating the edge on a single host is a 0.3 s window, measured
under traffic on every push by `scripts/polaris-window-drill.sh` against a
30 s ceiling (v9.240), and an edge configuration change is a live reload
with a near-zero window (Caddy occasionally restarts a listener and drops a
single in-flight request at the swap; the drill asserts a small transient budget). The database half closed with the HA profile
(v9.243, [FAILOVER.md](operator/FAILOVER.md)): under Patroni a lost leader
is replaced within its 20 s lease (20.0 s measured at v9.244; queries in
flight fail fast at the pooler's 15 s query timeout and the app retries,
none lost), a planned switchover is a 3.4 s outage, and a leader that loses
its lease store stands down in 7 s; the hosts the members run on are the operator's
placement. A single-host database restart without the profile remains
latency the pooler absorbs (v9.240), and a database crash a 0.6 s window
(v9.242). Closing the edge half means a second edge with an address that
moves, which is placement and DNS, not code. The other limit the ledger
carried, a Caddy edge that ran as root with `NET_BIND_SERVICE`, closed at
v9.239: the edge runs as uid 1000 with no capability on every substrate, and
`check_container_hardening` fails the build if a capability or a root user
comes back.

**One role-reach limit is carried openly**, recorded by a security review of the authorization
surface on 2026-09-16 rather than decided by it. The Atlas subject view is gated to `admin` and
`auditor`, with the reason stated in its own comment: an operator must not be able to pull a
holder's movement map. A neighbouring surface is reachable from a lower gate.
`investigate_individual` and `investigate_token` require a session but no role, so an `operator`
can retrieve a holder's tokens and their non-zero-knowledge verification history, including the
textual `requestor_location` recorded against each verification. This is not a C6 break: a
zero-knowledge verification carries no token identifier and cannot be attributed, no coordinates
are returned on this path, and every access writes an `AuditAccessLog` row. It is an asymmetry,
two doors onto a holder's activity with different locks, and the narrower one was chosen
deliberately. Closing it means deciding that investigating a credential is an oversight function
rather than an operational one, which removes a capability an operator may legitimately need
during an incident. That is a decision for the deploying organization, so it is stated here
rather than taken.

---

## Deployment-scale gaps

This ledger tracks one authority on one host or one cluster. Everything
beyond that is in [ROADMAP.md](../ROADMAP.md): the external penetration
test (P1.12), partitioning and HA automation and
multi-region (P2), the relying-party API and federation protocol (P3), the
hardware token and enrollment kit (P4), pilots (P5), certification (P6) and
national rollout (P7). Do not read a closed ledger here as readiness for those.

---

## What is already production-grade

- **The ZK stack is real**, not a mock: a Plonky2 transparent-setup
  Merkle-inclusion circuit, verified at use on `/api/zk/verify` with single-use
  nonce anti-replay, plus an independent second-witness Poseidon/Merkle
  verifier in Python.
- **Authentication and access control**: scrypt password hashing, atomic
  failed-login counting, username-enumeration resistance, per-session CSRF with
  constant-time compare, session-fixation regeneration, role-based
  authorization with 403 and audit, a CSP with no `unsafe-inline` for scripts,
  a server-side session registry with per-role caps and revocation, per-role
  network allow-lists, a WebAuthn attestation policy with ML-DSA-65 offered
  first, and opt-in per-agency quotas enforced by trigger.
- **The constraints that can live in the database do**, not in policy: C1's
  grant boundary revokes UPDATE and DELETE on append-only audit tables from
  `polaris_app`, the only DELETE path is SECURITY DEFINER, and `polaris_app`
  has no DDL; C2 is a CHECK constraint, C3 a partial unique index, C7 a
  registry table, C10 an absence. C4, C5, C6 and C9 are enforced in the
  application, the response policy and the threaded tests, as the table in
  [MISSION.md](../MISSION.md) records, and every one of the ten is pinned by a
  check with a detection test.
- **Secrets** are file-mounted under `/run/secrets/`, the app refuses to boot
  in production on the default secret key, and the database role password is
  rotated off its development default at first boot.
- **Algorithm-as-data (C7)**, `TokenSignature` immutability, and the duress
  machinery are real and enforced in the schema.
- **Retention is a recorded decision with a floor**: `RetentionPolicy` holds
  the days per table class and jurisdiction behind a 365-day CHECK, the purge
  refuses a cutoff inside the window, and the archive chain runs per class
  and is drilled in CI (v9.234 to v9.236).

---

## The engineering record

Every gap the ledger enumerated, the version that closed it, and the check that
fails if it stops being true. Each landed as its own CI-green ship; the
CHANGELOG entry for the version carries the detail.

| Claim | Shipped | Pinned by |
|---|---|---|
| Demo accounts never reach a production database; the first admin is bootstrapped by script | v9.101 | `check_prod_hardening` |
| The rate limiter uses Redis in production, so per-IP limits are shared across workers | v9.101 | `check_prod_hardening` |
| Real ML-DSA-65 signing runs end to end in CI (liboqs) | v9.103 | the `pqc-real` CI job |
| A persistent signing key is the published trust anchor; a malformed key fails loud | v9.103 | `check_pqc_real_signing` |
| Every produced signature is self-verified before it is stored; stored signatures verify against the trust anchor | v9.113 | `check_verify_enforced` |
| The secrets generator mints a loadable key (the liboqs banner no longer corrupts it) | v9.139 | `check_signing_key_generation` |
| Real PQC is the production default; liboqs ships in the image; CI signs inside it | v9.116 | `check_prod_real_pqc` |
| Each signature row stores the issuer public key, so verification survives rotation | v9.117 | `check_signature_self_contained_verify` |
| Algorithm migration (UC-6) signs through the same module as issuance | v9.119 | `check_pqc_signing_wired` |
| Two independent FIPS 204 implementations must agree on every verdict | v9.133 | `check_pqc_second_witness` |
| The full crypto surface is audited against the NIST 2030/2035 timeline | v9.134 | `check_pqc_posture` |
| The public edge negotiates X25519MLKEM768, proven off a real handshake | v9.136 | `check_edge_pq_kex` |
| Backups are encrypted at rest and restore fails closed without the key | v9.102 | `check_backup_encryption` |
| RPO and RTO are measured, not asserted: the drill kills a primary and restores it | v9.192 | `check_dr_drill_scheduled` |
| Both database hops are TLS with pinned certificates | v9.121, v9.131 | `check_app_db_tls` |
| The at-rest posture names every plaintext surface | v9.124 | `check_encryption_at_rest_posture` |
| Continuous WAL archiving ships in the image and round-trips in CI | v9.127 | `check_pgbackrest_scaffolding` |
| Every production container drops all capabilities and forbids privilege escalation | v9.141 | `check_container_hardening` |
| The full production compose boots and serves through the TLS edge in CI | v9.140 | `check_prod_stack_boot` |
| Migrations bound their lock and statement time | v9.106 | `check_migration_timeouts` |
| `WEB_CONCURRENCY` is honored | v9.107 | `check_web_concurrency_honored` |
| Liveness and readiness are distinct endpoints | v9.108 | `check_health_liveness_readiness_split` |
| Every service has resource limits and log rotation | v9.109 | `check_compose_resource_limits` |
| The pooler is self-built from the distro package | v9.110 | `check_pgbouncer_self_built` |
| The edge is self-built with its rate-limit plugin compiled in | v9.135 | `check_caddy_self_built` |
| Third-party images are digest-pinned | v9.114 | `check_prod_images_digest_pinned` |
| Alert rules ship and validate | v9.115 | `check_alert_rules` |
| The Kubernetes reference profile boots on kind with restricted policies | v9.186 | `check_helm_reference_profile` |
| A deploy drops zero requests under traffic | v9.183 | `check_zero_downtime_deploy`, `check_migrations_expand_contract` |
| A duress event reaches the pager webhook, proven in CI | v9.175 | `check_pager_integration` |
| Metrics aggregate across all workers | v9.120 | `check_prometheus_multiprocess` |
| Every request carries a correlation id that never touches the audit of record | v9.122 | `check_correlation_id` |
| SLO targets and one runbook per alert | v9.123 | `check_alert_runbooks` |
| The duress signal is a scrapeable counter with a SEV-1 alert | v9.128 | `check_duress_alertable` |
| Dependency CVEs and SAST gate the build; the production image ships no test framework | v9.105, v9.112 | `check_cve_scanning`, `check_prod_image_no_test_deps`, `check_sast_scanning` |
| Container image CVEs gate the build | v9.138 | `check_image_cve_scanning` |
| The SQL console is read-only at the engine | v9.104 | `check_sql_console_readonly` |
| A fresh Linux host reaches a healthy stack by one script, exercised on Debian and Rocky in CI | v9.176 | `check_linux_server_deployment` |
| The signing key sits behind a custody interface with file, PKCS#11 and KMS drivers | v9.178 | `check_key_custody_abstraction` |
| Secrets are sealed and rotated through the same lifecycle | v9.180 | `check_secrets_lifecycle_sealed` |
| The Kubernetes profile boots on kind with restricted policies | v9.186 | `check_helm_reference_profile` |
| Tracing and dashboards ship as code | v9.187 | `check_distributed_tracing` |
| Sessions are registered server-side with per-role caps and origin checks | v9.189 | `check_session_origin_hardening` |
| Per-agency quotas refuse writes under real load, proven in CI | v9.190 | `check_abuse_controls` |
| The performance baseline is published and re-run on every push | v9.191 | `check_performance_baseline` |
| Retention is data with a floor, purged per class, drilled in CI | v9.234 to v9.236 | `check_retention_engine` |
| Every base image under the self-built containers is digest-pinned | v9.237 | `check_prod_images_digest_pinned` |
| The TLS edge runs as a non-root user with no capability on every substrate | v9.239 | `check_container_hardening` |
| Edge configuration changes are live reloads; edge and database recreation windows are measured against ceilings on every push | v9.240 | `check_zero_downtime_deploy` |
| The SLIs and the error budget are recorded series, unit-tested, and on the overview dashboard | v9.241 | `check_alert_rules` |
| The fail-closed harness runs on every push; a weekly drill kills one colour, stops both until the outage pages through real Prometheus and Alertmanager, kills redis and postgres, partitions pgbouncer, and commits every recovery time to a ledger | v9.242 | `check_chaos_program` |
| The HA profile runs the database under Patroni with a leader lease in etcd and HAProxy routing on the role endpoints; the failover drill loses the leader, cuts it off from the lease store, switches over and crashes an etcd member under a live write stream against ceilings on every push; the split-brain analysis is written | v9.243 | `check_ha_automation` |
| The Helm profile runs the same Patroni members with the cluster's API as the lease store and the same router; the kind drill deletes the leader pod, freezes the leader's container and switches over under a live write stream, and asserts every acknowledged insert present | v9.244 | `check_helm_reference_profile` |
| The four append-only event tables are monthly range-partitioned; a manager premakes and detaches months (re-adding the append-only trigger so C1 holds across the detach), an online migration converts a pre-v9.245 database in place, and a drill proves append-only across a partition, an attach and a detach on every push | v9.245 | `check_event_table_partitioning` |
| The read-only surfaces (the atlas API, the verification list, the token export) route to a streaming replica under an explicit staleness contract with failback to the primary; correctness-critical reads stay on the primary; the failover drill proves the app serves reads from the replica | v9.246 | `check_read_replica_routing` |
| A whole population stages with `COPY` and issues set-based in one transaction through `uc_bulk_issue`, every row through the full constraint set and a single violation rolling the batch back; a drill proves throughput, all-or-none atomicity, and C3 across the batch on every push | v9.247 | `check_bulk_enrollment` |

---

## The rule

The status line at the top changes only when the ten decisions above are
recorded as made for a named deployment and the roadmap's P1 exit gate is met.
No document in this repository claims a protection the code does not
implement, and every row above names the check that fails if it stops being
true.
