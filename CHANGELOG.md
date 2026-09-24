# Changelog (recent ships)

This file holds the entries since the front door was rewritten at v9.453 (12 September
2026), the point from which the operating contract governs what is worth shipping.
Everything before it, v9.44 (3 June 2026) through v9.452, is in
[docs/history/CHANGELOG-v9.md](docs/history/CHANGELOG-v9.md), moved there unchanged on
16 September 2026 so that this file stays readable; the complete ship-by-ship history is
also in the git log. Entries are never edited retroactively: a correction is a later
entry. When this file grows past a reader's patience, its oldest entries move to the
archive, and `scripts/polaris-release-notes.sh` renders a moved entry from there.

---

## v1.0.0-rc.8 — 2026-09-23 (the offline answer agrees with the online one about expiry)

CORE-BUG against rc.7. Externally observable: what `POST /api/v1/status-assertion` signs.
Nothing is published.

Authorization, whether a credential is authoritative right now, is answered two ways: online
by `/api/v1/verify`, and offline by a short-lived signed status assertion that a holder staples
to a presentation. The two must give the same answer. On 2026-09-17 `/verify` learned to read
`expiration_date`, because nothing moves a credential from `ACTIVE` to `EXPIRED` when its date
passes and the endpoint had been answering `currently_authoritative: true` for credentials past
their stated end. The status-assertion route was the sibling path and was not changed: it
signed the stored status alone. So a credential past its expiry date got a freshly signed
`ACTIVE` assertion, and every offline verifier, the published one included, accepted it. The
online answer said no; the offline answer said yes.

Now an `ACTIVE` credential past its `expiration_date` is asserted `EXPIRED`, by the same
`_not_expired` rule `/verify` uses, and an `ACTIVE` assertion's `expires_at` is capped at the end
of the credential's expiration date (00:00Z the day after it), so an assertion minted on the
last valid day does not outlive the credential by up to its TTL.

Found by reading the route while mutation-testing the relying-party endpoint around it: the
held-out round had just shown that endpoint's own expiry check was untested, and the question
was which other path answers the same question. The test
(`RelyingPartyApiTests.test_a_status_assertion_never_says_active_for_an_expired_credential`)
failed on rc.7 on the `ACTIVE` assertion, and fails with the cap removed on an assertion ten
days past the credential; it passes with both.

The promise: CLAUDE.md section 1 and docs/reference/API.md (authorization answered online or by
the offline assertion); API.md's `status` row now states the expiry rule and the cap.

The same commit carries tests only, no behaviour, for held-out rounds on the SDKs' grant
coverage, the OpenID4VP status-list authority and HTTP framing, and the published verifier's
QR frame decoder.

## v1.0.0-rc.7 — 2026-09-19 (total on hostile input, this time actually)

CORE-BUG against rc.5. Externally observable. One package: `polaris-oid4vp`. Nothing is
published.

`status.py`'s `decide` says "Total on hostile input" on its first line and raised
`RecursionError` on a status list token nesting 30,000 arrays. `RecursionError` is not a
`ValueError`, so the `except (ValueError, UnicodeDecodeError)` around the parse never saw it.
The body is fetched from a URI named inside somebody else's credential, which is exactly the
input an attacker controls, and a verifier that dies on one credential has failed open for
every other credential in the queue.

**`sdjwt.py`, in the same package, has bounded JSON size, nesting depth and the bare constants
since 2026-09-17**, after 2,780 bytes of `[[[[...]]]]` raised out of it for the same reason.
I promoted this module out of `lab/` into a published package without carrying that lesson
across, so it shipped in rc.5 with a defect its sibling had already fixed. Found by asking
what the file next door protects against that this one does not.

`_json_bounded` now applies all three: 64 KiB, 64 levels, and `parse_constant` refusing NaN
and Infinity. Refusing the shape before parsing rather than catching `RecursionError`, because
that fires at a point depending on how much stack the caller already used, so the same input
is accepted from one call site and raises from another.

**Two copies of a security decision function is how they stop agreeing**, and it nearly
happened inside a day: the lab original would have kept the defect while its own adversaries
reported all clear. The lab copy is deleted and its 24 adversaries now import from the
package, so they attack what a relying party installs.

244 tests across seven suites; four mutations confirm each bound. One of those four found a
weak test rather than weak code: the first depth fixture used `{"a":` nesting at six bytes a
level, so 20,000 levels was 120 KB and the SIZE bound refused it. Removing the depth bound
changed nothing and the test did not notice. Nested arrays at two bytes a level keep 30,000
levels inside the size budget, where only the depth bound can refuse them.

That is the third time in one day a test passed because a mechanism other than the one it
named satisfied it.

---

## v1.0.0-rc.6 — 2026-09-19 (the capability rc.5 shipped, reachable from the thing you use)

A correction to rc.5, as a later entry rather than an edit to it. Externally observable. One
package: `polaris-oid4vp`. Nothing is published by this entry.

rc.5 added `status_resolver` to `verify_presentation` and did not thread it through
`Verifier`. `Verifier` is the class an operator constructs, the one that answers the wallet,
and the one the README's own run instructions show. So the capability existed in the package
and not in the product: a relying party using the documented entry point could not supply a
resolver at all, and nothing said so.

`Verifier(..., status_resolver=...)` now takes it and hands it down. The default is unchanged
in both places: no resolver means `not_evaluated`.

**The test written for this first did not catch it, and that is the more useful half.** It
asserted `assertIs(verifier.status_resolver, resolver)` against a fixture credential carrying
no status claim. Both were true with the resolver held in `__init__` and never passed on: the
object had it, nothing used it, and the assertion could not tell the difference. Removing the
threading left the suite green.

The credential has to NAME a status list, and the assertion has to be that the resolver's
answer reached the verdict. It does now, and two mutations confirm it: dropping the resolver
in `__init__` and failing to thread it past there both turn the suite red.

That is the second time today a test asserted the shape of a mechanism rather than its effect,
after a status-list adversary that checked a verdict was "not accepted" without checking which
refusal it was. Both passed against code that did not work.

240 tests across seven suites.

---

## v1.0.0-rc.5 — 2026-09-19 (asking is opt-in, and the answer can be absent)

Externally observable, so it is a version. One package moved: `polaris-oid4vp`. Nothing is
published by this entry; `docs/RELEASING.md` still records rc.3 on the registry.

rc.4 made the verdict say what it had NOT established about revocation. This adds the way to
establish it, and keeps the default exactly where rc.4 left it.

**`polaris_oid4vp.status` decides a Token Status List token.** `draft-ietf-oauth-status-list`
is the mechanism SD-JWT VC, CWT and ISO mdoc all reference, so one implementation reaches all
three. It is pure: `decide` is handed a token, `decide_by_fetching` is handed a `fetch`
callable. Nothing in it opens a socket, because timeouts, retries, connection limits and
caching are policy and belong to the caller.

**Asking is opt-in.** `verify_presentation(..., status_resolver=...)` takes a callable the
relying party supplies. With no resolver the verdict is `not_evaluated`, unchanged from rc.4,
which is the honest thing to say about a list nobody read. It is opt-in rather than automatic
because a status check couples your verification path to somebody else's uptime, and a library
that made that choice silently would be deciding, on the relying party's behalf, that their
traffic stops when a third party's endpoint does.

**Two states that must not be confused, and the reason this is a version and not a
refactor.** `not_evaluated` says nobody looked. `unreachable` says somebody looked and no
answer came back. A verifier that reports them identically has decided, without being asked,
that an unreachable status endpoint is as good as a credential whose issuer publishes none.
"I could not reach the list" is not "not revoked", and it is the state implementations lose
first, because refusing traffic when a third party is down is expensive and the pressure to
shrug is real.

**Who may publish status for whom is stated, not inferred.** The draft does not settle it:
section 11.3 says the Status Issuer MAY reuse the credential issuer's key when they are the
same entity and SHOULD share a Certificate Authority when they differ, both recommendations,
and `iss` is not even a required claim of a Status List Token. So a fetched list is signed by
a key the token often does not name, and the only binding it carries is `sub` equal to the
`uri` the credential gave. Fetch that URI and believe whatever signed the response and you
have asked DNS an authorization question. `StatedAuthority` requires an operator to record
that a named key may publish status for a named issuer at a named URI, and why; anything else
is `no_authority`. Authority is established BEFORE any fetch, so a URI inside an unvetted
credential is never a place a request is sent.

**What is refused, and what a refusal means.** A list published for another URI, a plain JWT
offered as a status list, an expired list, an index past the end of the array, a signature
that does not verify, a decompression bomb, an application-specific status value folded into
VALID, and a stale-but-unexpired list used to roll a revocation back: that last one is only
visible as age, so the verdict carries it and a caller can bound it. A 404 page is
`unreachable`, not a malformed list, because the endpoint failing is not the issuer publishing
something broken.

22 tests in `test_status.py`, and five more in `test_sdjwt.py` for the resolver hook, each
confirmed by mutation: a raising resolver reported as "nobody looked", a nonsense return
trusted, and the resolver ignored entirely all turn tests red.

The research, the twenty-two adversaries and the decision record that admitted this work are
in [lab/strategy/001-token-status-list.md](lab/strategy/001-token-status-list.md).

---

## v1.0.0-rc.4 — 2026-09-19 (a credential that might be revoked)

Externally observable, so it is a version and not housekeeping. One package moved:
`polaris-oid4vp`. Nothing else changed and nothing is published by this entry.

**The verdict now says what it did not establish about revocation.** `polaris-oid4vp`
verifies a presentation from a wallet that has never heard of Polaris: issuer signature,
`vct`, disclosure digests, `exp`, `nbf`, holder key binding, nonce, audience. Its verdict
was `{authentic, code, reason, claims}`, and there was no field about revocation anywhere
in it.

An SD-JWT VC's `status` claim is issuer-signed and, by the specification, MUST NOT be
selectively disclosable. This verifier already knew that: `status` sits in the list of
claim names a disclosure may never carry. So it parsed the claim, protected it, handed it
back inside `claims`, and said nothing about it. A relying party reading `authentic: true`
was being told the strongest thing this code can say, while the second question a relying
party actually has went unasked and unmentioned.

That is the principle rc.3 published, one surface over. rc.3 added `trust_evaluated` to
the detached verifier so three states would be distinguishable rather than collapsed, and
said of the two issuer fields that either is null when it cannot be established, "which is
not the same as false". Revocation had no field at all, so it did not have two states to
confuse: it had silence.

The verdict carries `revocation` now, in one of three states, and a relying party that
cannot tell them apart cannot make a decision about any of them:

- `no_status_claim`: the credential names no revocation list, so there is none to read.
- `not_evaluated`: it names a Token Status List at a URI and an index, and this verifier
  did not fetch it. Whether the issuer has revoked this credential is UNKNOWN, not false.
- `unsupported_status`: it carries a status claim in a form this verifier cannot read,
  which is not evidence that the credential is current.

**No status list is fetched, and that is the point of the change rather than a gap in it.**
Fetching is an online operation with a timeout, a cache and its own failure semantics, and
this package does not do it today. Saying so costs nothing. Claiming otherwise, or staying
quiet and letting `authentic: true` carry the weight, is the overstatement being removed.

`authentic` is unchanged and still means what it meant: the issuer signed this, the
disclosures match what was signed, the holder proved possession, the credential is inside
its own validity window. It was never a statement about revocation.

Six tests pin the states apart, including one whose only job is to fail if an
implementation returns a single constant, and one that fails if any path ever reports a
revocation as checked while the package opens no socket. All three were confirmed by
mutation: making the state constant, reporting the unfetched list as checked, and reading
an unsupported claim as absent each turn tests red.

The research behind it, the Token Status List decision function and the sixteen
adversaries against it, stays in `lab/strategy/` and is not part of this version. See
[lab/strategy/001-token-status-list.md](lab/strategy/001-token-status-list.md) for what is
settled and what is not.

---

## v1.0.0-rc.3 — 2026-09-17 (a genuine signature is not a trusted issuer)

Two published-contract ambiguities, found by an outside design-intent review and
resolved against the owner's stated principles: signature validity must not silently
imply issuer trust, historical authorization and current-key status are separate facts,
and where a fact cannot be established safely the answer is UNKNOWN rather than a guess.

Both are externally observable, so this is a version and not housekeeping.

**The detached verifier abstains instead of implying trust.** `polaris-verify` computed
`accept` as `signature_valid and issuer_trusted in (None, True)`, and `None` is what you
get when the caller passes no `--issuer-anchor`. So a credential signed by any key at all
exited 0, indistinguishable, to anything branching on exit status, from a verification
against a trust root that matched. The JSON was honest (`issuer_trusted: null` was right
there); the exit code was not.

A run with no trust root now abstains with exit 2 and says why. `--signature-only` is how
a caller states that cryptographic validity alone is the question, and that run exits 0
while reporting `trust was NOT evaluated`. The verdict carries a new `trust_evaluated`
field so the three states are distinguishable in JSON as well as by exit code. This is the
same discipline the package already applied to `--pqc-provider`: the mode a run uses is
something the caller states, not something the machine decides for them.

Measured before and after in `lab/interop/verifier_trust_default.py`, which now stands as
the guard: it fails if the three states are collapsed back onto one exit code, and fails
equally if `--signature-only` stops working, because a verifier that cannot answer "does
this signature verify" has lost a use case rather than gained a guarantee.

**`issuer_authentic` is replaced by two fields, because it was answering two questions and
getting the common one wrong.** It compared the signing key against
`Agency.signing_public_key_hex`, the authority's CURRENT key. Since a signature row is
immutable and `polaris key-event ... registered` moves that column, the two diverge the
moment an authority rotates: every credential issued before the last rotation reported
`issuer_authentic = false` while being perfectly legitimate. The field fired on good
credentials, which teaches an integrator to ignore it.

`/verify` and the relying-party API now report:

- `issuer_authorized_at_signing`: was this key authorized for this authority at the
  instant the credential was signed? Survives an ordinary rotation.
- `issuer_key_current`: is that key still active for the authority today? A rotation makes
  this false, which is a fact about the key and not a verdict on the credential.

Either is `null` when it cannot be established, which is not the same as false.

**The instant is the one that cannot be moved.** Historical authorization is only
meaningful if the time it compares against is integrity-protected.
`IdentityToken.issued_date` cannot serve: IdentityToken carries a state machine and an
audit trigger but no immutability guard, and a database session can UPDATE it freely
(measured). The instant used is the `ISSUED` row in `TokenLifecycleEvent`, an audit of
record under C1, where the same edit is refused. With no `ISSUED` row there is no
trustworthy instant and the answer is `null` rather than a guess.

What this does not survive, stated rather than discovered later:
`AuthorityKeyEvent.effective_at` is operator-supplied, so an authority that writes its own
key history can backdate an authorization. This answers against the recorded history; it
does not defend against the operator who writes it, which is the operator-as-adversary
`lab/duress/` already names.

**Six cases pin the new semantics**, in `FederationInAppTests`: a credential surviving an
ordinary rotation (the case the single boolean got wrong), a key never authorized for that
authority, a key authorized at signing and retired later, a credential signed *after* its
key was retired (the one case that must answer false rather than null), no protected
issuance instant, and a placeholder signature that decides neither.

`check_federation_in_app` requires both field names, requires the rotation case by name,
and now fails if `issuer_authentic=` reappears in the application.

**Not changed**, deliberately: the mdoc bridge's own `issuer_authentic` is a different
field answering a different question about an ISO 18013-5 document, and is untouched.
`polaris_card`'s pairwise handle, the other finding from the same review, is recorded in
`lab/linkability/pairwise_constructions.py` and left for a decision rather than swept in
here.

---

## v1.0.0-rc.2 — 2026-09-17 (a defect found in the candidate)

The contract says a defect found in the candidate makes rc.2 and nothing else moves the
number. The trigger fired twenty-two times in two days, across all four external doors and
the application, so this is that release and not a larger one.

**What a stranger installing rc.1 has.** Measured inside the downloaded wheels rather than
inferred from a changelog, on 2026-09-17: `polaris-oid4vp` 1.0.0rc1 never reads `exp` (the
string appears zero times in its `sdjwt.py`, against three here), so it accepts a credential
whose validity has ended. `polaris-verify` 1.0.0rc1 reads a trust attestation's `valid_until`
exactly once, inside its canonicaliser, so a time-boxed trust edge never expires; it has no
finite-number guards, so an agent grant signed with a non-finite `max_amount` is a signed
unlimited grant wearing a limit field. `polaris-sdk-python` has neither guard either. The npm
`polaris-sdk-ts` is still 0.1.0 and predates rc.1 entirely.

And the reason that matters rather than merely being true: `docs/STRANGER-PATH.md` was walked
end to end from PyPI the same day, and a stock walt.id wallet presented to the published
verifier and was ACCEPTED. The happy path works. Somebody evaluating Polaris against their
own wallet watches it succeed and has no way to learn their copy does not check expiry.
SECURITY.md now carries that, at the top, where a person who installed from a registry will
reach it instead of only a maintainer.

**The four external doors.** Fifteen defects in the OpenID4VP verifier, among them expired
credentials accepted, a key-binding `iat` of NaN defeating the replay window, a disclosure
able to overwrite the issuer or the key-binding key in the returned claims, and four
denial-of-service paths needing no credential. Sixteen in the detached verifier, including
the trust edge above, an agent grant whose algorithm the verifier ignored while the holder
had signed it, and four totality escapes where an inclusion proof carrying `Infinity` raised
instead of returning a verdict. Thirteen across the two reference SDKs, including a cached
bearer token that outlived the client's standing to use it.

**The application.** A credential past its own expiry stayed usable and the dashboard counted
it. An operator bound to one authority could make another authority sign. An operator account
could be locked exactly once, ever. Eleven refusals on the authentication surface were not
being made, among them an authenticator model refused by policy that could still complete a
login. A timestamp authority signed whatever it was handed: its docstring promises the content
itself is never sent, and the `digest_hex` shape check is the whole of that promise.

**Non-finite numbers, moved to the door.** `NaN` and `Infinity` survive `json.loads`, every
comparison against NaN is false, and `int(float('inf'))` raises an exception the usual
`except (TypeError, ValueError)` does not catch. After repairing five call sites individually
the refusal moved to one JSON provider, because fixing the twenty-first call site leaves the
twenty-second to be written. The same shape produced `_json_object()`: `get_json(silent=True)
or {}` is truthy for a JSON string, so an anonymous caller could make an unauthenticated
endpoint raise by sending `"a string"`.

**How the tests were found wanting, which is most of what changed.** The Flask application
was the one member of the mutation-drill family nobody had measured, and three of the ten
constraints are enforced there and nowhere else. Of 37 refusals answering 401, 403, 409, 413
or 429, **31 survived being switched off with the whole suite green**. Of fourteen rate
limiters, the login one was the only one any test drove. `check_local_gate_covers_ci` existed
to stop the local gate being narrower than CI and compared the ship tool against the wrong
file, so nine suites ran in CI that nothing local knew about.

**The lab.** Linkability went from five findings to eight. Two of the four fields its
issuer-metadata question named are not in a presentation at all; the anonymity set is the
(epoch, context) cell and the metadata gives an adversary nothing beyond it. A wallet whose
`holder-keygen` was interrupted by a network failure presents `holder_proof` with no
`holder_binding` beside it, identically at every verifier, which is a stable one-bit
fingerprint, and the cause was an uncaught `URLError`. A status assertion trimmed to its
timestamps reported `bounded` while handing over an instant to the second.

**What has not changed.** Polaris remains a reference implementation on notional data, not
production-ready, not audited, not certified, not deployed. The five conditions for 1.0.0 still
hold and the sixth still does not: an operator who is not the author has not reached a verified
result, and that row of the scoreboard is what makes 1.0.0 rather than another candidate.

---

## v1.0.0-rc.1 — 2026-09-15 (a version a stranger can read)

The tree version moves from 9.467 to 1.0.0-rc.1, and the four standalone packages from 0.1.0 to
1.0.0-rc.1. What changed is what the number means; the two defects found on the way are below.

**Why 1.0, and why a candidate.** The go-forward contract names five conditions for calling
anything 1.0.0, and all five hold: a clean-machine install works, the cryptographic mode is
explicit and safe, a named external client (walt.id's wallet, unmodified) completed a
presentation, a named external conformance suite (the OpenID Foundation's hosted suite) has
been run, and its result is published where it is not green (7 PASSED, 4 REVIEW). What is
still missing is not one of the five. The contract's 90-day objective also asks for an operator
who is not the author to have used the verifier, and that row of the scoreboard is blank. A
release candidate says both things at once. That operator makes 1.0.0; a defect found in the
candidate makes rc.2. Nothing else does.

**The maturity classifier moves from Alpha to Beta.** PyPI has no classifier for a candidate,
and Production/Stable would say more than has happened.

**Why the tree version stops moving.** 9.467 was a count of ships, bumped by the one that added a
check and the one that fixed a comment alike. Under the contract a version marks an externally
observable change, which is rare, so the tree number stops tracking internal activity. Standalone
packages keep their own semver, independently.

**What had to move with it.** Four invariant checks parsed the version as MAJOR.MINOR and judged
a document stamp stale when more than twenty minors behind the tree. That proxy dies the moment
the version stops bumping per ship: everything is forever within twenty minors of a number that
does not move. The stamps in SECURITY.md, CONTRIBUTING.md, PRODUCTION-READINESS.md and ROADMAP.md
must now equal the tree version exactly, so a version bump forces every outward document to be
re-read, which is when a document is most likely to have drifted. The thesis-terminus check
compared against (9, 40); it now treats that terminus as the permanent fact it is, since a reset
to 1.0 would otherwise have read as "before v9.40" and reopened a claim retired by recorded
decision.

**One latent defect surfaced by the move.** `check_roadmap_consistent` guarded its version
comparison with `if vm and ...`, so a version its regex could not parse skipped the comparison
and passed. On the first run against 1.0.0-rc.1 it would have gone green over a stamp it never read.
It now fails when the version cannot be read.

**A second, found by re-measuring.** Restating the README's test counts meant running the
product suites the way the README says they were measured, `pytest -q` per suite, and
`test_check_constraints` failed once: a relying party registered with no actor declared came
back recorded `by vanta`. The seed that reloads the sample database restarts every reached
table's ids from 1 (`TRUNCATE ... RESTART IDENTITY CASCADE`), and CASCADE reaches
`RelyingParty` through its key to `VerificationContext`. `RelyingPartyEvent` deliberately
carries no foreign key, so that ending a party's contract cannot erase its history, which also
means the reload never reaches it: its rows survived every reload, and the first party
registered after each one inherited every event of whichever party had held `rp_id` 1 in the
previous life. The test that caught it was reading the oldest event under its new id and finding
a dead party's. `04_data.sql` now names the record in the same statement, as `10_auth.sql` has
done for `AppUserEvent` since it was written, and `check_seed_restart_resets_dependent_records`
computes what the reload restarts from the schema's own foreign keys, migrations included, and
fails on the next record left behind. Its closure was compared with what Postgres actually
cascades to on the loaded database; they agree on every table.

**Installing a candidate.** pip skips pre-releases unless told, and 0.1.0 remains available as
the prior release, so the pip lines read `pip install --pre`. npm refuses to publish a
prerelease without a dist-tag (the first rc.1 run was refused on exactly that, and uploaded
nothing), so the candidate goes out under `next`: `npm install polaris-sdk-ts@next`, while plain
`npm install` keeps 0.1.0. The republish replaced the frozen 0.1.0 descriptions on PyPI,
one of which still said "Not on PyPI yet" from a page that was, literally, on PyPI. The GitHub release for this
version is a full release, not a pre-release: GitHub will not put its Latest marker on a
pre-release, and leaving that marker on v9.466 kept a retired numbering on the front door. The
tag says what the release is. The badge includes pre-releases, so it reads the tag rather than
the marker. The 295 v9 tags and their 294 GitHub releases were removed the same day: a series
that numbered ships rather than observable change, cleared from the front door instead of left
as 294 entries under the one that matters. Every one of those numbers still maps to its commit,
date and subtitle in [docs/history/RELEASES-v9.md](docs/history/RELEASES-v9.md), and every entry
is still in the changelog archive. The SBOM attachments went with the releases; the author holds
an archive of them, and nothing published depends on one.

**The README, rewritten.** The front door had grown by accretion: a three-hundred-word opening
paragraph, the wallet and conformance results told twice, the cryptographic claim made four times,
and the honest counterweight scattered across three sections. Rewritten from a blank page on
2026-09-16 in the order a stranger needs: what it is, its status with the two outside results and
the counterweight in one place, a two-minute try, the ten guarantees, the threats, the architecture,
the cryptography with its limits, what is verified and how, how to run it, where it sits, and where to
read next. Every pinned claim, count and vocabulary rule the checks hold the README to survived
unchanged; the checks and the link checker gate the result as before.

**The runbook, rewritten.** `CLAUDE.md` was a v9-era onboarding note that still called the system
national on its first line, described all ten constraints as database objects, named a Python
3.9 venv that does not exist, wrote the CHANGELOG header with a comma, counted five flake
signatures where the tool knows six, and never mentioned the operating contract, the
scoreboard, the four standalone products or the release candidate. Rewritten for 1.0.0-rc.1
in the order a fresh agent needs: what Polaris is and is not, what governs when instructions
conflict, the operating contract as a first-class section, the five evidence marks and the rules
that keep one from being upgraded into the next, C1-C10 at the level each is actually enforced,
how to work, how a change earns admission, how to test and falsify it, shipping and versioning,
where things live, the operational gotchas as symptom, cause, distinction and action, the style
rules, and engine over wrapper subordinated to the contract. Every command and path in it was
verified against the tree; the documentation disagreements found on the way are recorded in the
commit rather than reconciled silently.

The two test-count stamps in the README, last measured at v9.332, are re-measured at this
version and restated: 992 product tests passing (was 755) and 107 of 112 crypto witnesses (was
84 of 89), on the reference machine, `pytest -q` per suite. The growth is the suites' ordinary
accretion since v9.332, not anything this ship did; the three product tests and five crypto
witnesses skipped need real ML-DSA, a PKCS#11 module or a real KMS key.

## v9.467 — 2026-09-15 (a privacy promise kept by discipline alone)

A data-protection audit of the repository. Most of it came back clean, and the one finding is
the shape this project keeps finding in itself.

**Clean, and checked rather than assumed.** No credentials or API keys are committed. The one
`BEGIN PRIVATE KEY` in the tree is a fixture with `xyz` between the headers, used to assert file
permissions. `.gitignore` carries 13 secret patterns. Retention, erasure, the secret store's
lifecycle, redaction and the duress paths each already have a check with a detection test.
`docs/operator/PRIVACY.md` runs to 488 lines and states its own boundary honestly: it disclaims
GDPR and CCPA as deployment-specific, says Polaris has no special handling for minors, and says
outright that it is an architectural posture and not a legal privacy notice drafted by counsel.
That boundary is correct for a reference implementation on notional data and was left alone.

**The finding.** PRIVACY.md tells an operator, in as many words, that the application log does
NOT record form bodies, cookie values or token values. It is a sentence somebody reads before
deciding what a deployment may hold. It was true: none of the 21 logging call sites in the
application interpolates a request body, a credential or a holder attribute, and the structured
logger names no such field. But nothing enforced it and nothing tested it. A debugging line that
logged `request.form` could have landed and stayed, and the document would have gone on promising
otherwise.

`check_logs_exclude_pii` (271) reads the logging call sites and fails if one names a request
body, a cookie, a credential or a holder attribute, including across a call wrapped over several
lines. It also fails if PRIVACY.md stops making the promise, because a check that exists to keep
a published sentence true must not read as compliance once the sentence is gone. Six failure
modes are covered by its detection test, including the empty room.

What this does not do: it reads call sites, so it cannot prove a log is clean at runtime, and it
says nothing about what a deployment's own logging configuration adds. The document already tells
an operator to revert debug logging immediately and record it; that instruction is still theirs
to follow.

## v9.466 — 2026-09-15 (you can install it now)

A version because installation changed, which is externally observable and is the only kind of
change that earns one. Nothing else here alters product behaviour.

**All four standalone products are published.**

    pip install polaris-verify
    pip install polaris-oid4vp
    pip install polaris-sdk-python
    npm install polaris-sdk-ts

All at 0.1.0. The three PyPI packages went out by GitHub Actions trusted publishing over OIDC and
no API token was created for them at any point. npm needed one, because it cannot use trusted
publishing for a package's first publish (npm/cli#8544); that token covered one publish and was
revoked within the hour. The publish workflow now contains no `secrets.` reference at all.

Each was checked by installing from the live registry into a clean environment and running it
there. `polaris-oid4vp keygen` produces a working HAIP certificate set from a fresh venv, which
is the one that matters, because it is the package an outside verifier operator reaches for.

**The stranger's path no longer needs a clone.** [docs/STRANGER-PATH.md](docs/STRANGER-PATH.md)
goes from a clean machine to one accepted presentation from an external wallet in about ten
minutes: `pip install polaris-oid4vp`, two helper files by curl, then keygen, serve, present. It
was executed from an empty directory before it was written down, and it ends:

    <- 200 authentic, claims ['cnf', 'family_name', 'given_name', 'iat', 'iss', 'vct']

**Hosted conformance: 7 PASSED, 4 REVIEW.** The OpenID Foundation's hosted suite ran
`oid4vp-1final-verifier-haip-test-plan` against the verifier across the open internet. Eleven
modules, zero FAILURE, zero WARNING. Seven negative modules carry the service's own
`result: PASSED`. Four positive modules are FINISHED / REVIEW with screenshot evidence attached,
awaiting a Foundation reviewer, which only a certification submission triggers.

**REVIEW is not PASSED. Polaris is not certified. Publication is distribution, not validation.**

What is still absent, unchanged by any of the above: no independent security review by anyone who
did not build this, no operator other than the author has run it, no pilot, no real identity data.
A constraint lattice and a verifier that an unmodified wallet already spoke to is the whole of
what is demonstrated.

## v9.465 — 2026-09-15 (a wallet nobody here wrote said no, and it was right)

First named independent implementation on the board. An unmodified walt.id Wallet API v2
(`waltid/wallet-api2:1.0.0`) presented an SD-JWT VC to `polaris-oid4vp` over OpenID4VP 1.0 and
Polaris accepted it.

    <- 200 authentic, claims ['cnf', 'family_name', 'given_name', 'iat', 'iss', 'vct']

walt.id fetched the signed request object over `request_uri_method=post`, verified it under
`client_id_prefix=x509_hash` against the registered trust anchor, matched the credential with the
`dcql_query`, signed a key binding JWT with a P-256 key **it generated and this repository has
never held**, encrypted the response as `direct_post.jwt`, and Polaris verified the chain.

**And it refused Polaris first, correctly.** `polaris-oid4vp keygen` produced a request-signing
leaf certificate with no KeyUsage extension at all:

    Certificate does not contain client Key Usage 'digitalSignature'

The CA carried `keyCertSign`/`cRLSign`; the leaf carried nothing. Eleven of eleven HAIP verifier
modules in the OpenID Foundation conformance suite had run clean against that certificate, and
`test_cli.py` already asserted four separate properties of the same leaf without asserting this
one. The certificate whose entire job is signing request objects was not marked as usable for
signing, and it took an implementation from outside this repository to say so. Fixed here, with a
test that is red on a leaf missing it.

The exchange stands on two negative controls, because a verifier that accepts everything prints
the same success line. Same wallet, same credential, same path, verifier trusting a different
issuer key: `400 refused: issuer_signature`, and walt.id told only "the presentation was not
accepted". Re-presenting against an answered `state`: refused at the request stage.

Recorded in [lab/EXTERNAL-NOUNS.md](lab/EXTERNAL-NOUNS.md) with the image digest, the release tag, the
Polaris commit, the transcript and every incompatibility found, including two that are not
Polaris's: walt.id's `/credentials/present/resolve-request` is the only route in its handler file
not passed `clientIdTrustConfiguration`, so it reports `MissingX509TrustAnchors` whatever is
configured; and its `x509TrustAnchors` wants PEM though the type comment says base64 DER.

One wallet, one credential format, one presentation path, ES256 throughout. No claim is made that
`polaris-oid4vp` is interoperable in general.

## v9.464 — 2026-09-14 (the design doc described the defect as the technique)

Closing sweep over `docs/design/concurrency.md`, which had not moved while five ships rewrote what
it describes. Three passages were wrong and one of them was instructive.

The instructive one, on `uc10_same_attesting_agency_serializes`: *"The test manually holds the lock
to make the serialization timing observable; the procedure's lock acquisition inside is a no-op
reacquire on the same transaction."* That is the defect written down as a technique, and it reads
entirely reasonable. It is also exactly why the test proved nothing: both threads serialized on the
TEST's lock, so the procedure's own locking never entered the measurement. The replacement quotes
the old sentence rather than deleting it, because the sentence is the clearest statement of the
trap anyone will find.

The other two described mechanisms that no longer exist: `test_uc6_cross_token_migrations_run_in_parallel`
"confirms the wall-clock parallelism", and the cross-algorithm close "completes in ~0.3s (the held
lock duration), not ~0.6s (serialized)". Both now hold a lock through the procedure and probe under
`lock_timeout`.

The catalog summary gained the one fact it could not have carried before today: which of the six
locks the suite can actually see. Four go red when their `pg_advisory_xact_lock` line is deleted.
Two cannot be observed at all, and for those, dropping either mechanism leaves 866 tests green
while dropping both turns the suite red.

A design doc that describes a verification approach is making a claim about the code, and this one
had been making three false ones since this morning.

## v9.463 — 2026-09-14 (a surviving mutation that was the right answer)

Four ships today treated a surviving mutation as a defect. This one did not, and the difference is
worth writing down because the reflex that found the first four would have produced a false finding
here.

The procedure mutation drill mutates `RAISE EXCEPTION` and nothing else, so the six `FOR UPDATE`
clauses in `05_procedures.sql` had never been mutated. Dropping them one at a time:

  * `uc4_activate_reserve` holds three, and removing them turns
    `test_uc4_concurrent_same_tokens_one_winner_no_duplicate_crl` red. Load-bearing and watched.
  * `uc9_complete_recovery` and `uc10_revoke_attestation` hold one each, and removing either leaves
    **all 866 tests green**.

By the pattern of the last four ships that reads as two unwatched clauses. It is not. Each sits
after an advisory lock keyed on an entity that already covers the same row, so the experiment that
settles it is the one that removes BOTH. Run for each procedure:

    drop the FOR UPDATE      866 pass
    drop the advisory lock   866 pass
    drop both                the suite FAILS

That is defense-in-depth seen from outside: two sufficient mechanisms, and a test asserting the
PROPERTY rather than either implementation. Neither clause is dead and neither is untested. Adding
a test to "close" either gap would have pinned an implementation detail and made the pair harder to
change, for a defect that does not exist.

Recorded where someone would be standing when they consider deleting a line: a comment beside each
clause with the three measurements, and a note in `_UNOBSERVABLE_LOCKS` that an entry there means
"no test can tell these apart", never "nothing tests this". The list already named two advisory
locks as unobservable, and read as though the property behind them went unchecked. It does not.

No behaviour changed in this ship. The tree is byte-identical apart from comments, a version and
this entry.

## v9.462 — 2026-09-14 (a claim that lived in a comment)

The last thing in this family, and the smallest. Above the federation lock tests sits a comment
that has said since R11-3: "Same-attesting-agency attest + concurrent revoke serialize". No test
drove `uc10_revoke_attestation` concurrently. The claim lived in a comment.

It is not a trivial claim. The two procedures reach the same lock key by different routes.
`uc10_attest_trust` hashes its `p_attesting_id` PARAMETER; `uc10_revoke_attestation` SELECTs
`attesting_agency_id` out of the attestation row and hashes that. Nothing checked the routes
agree, and `AgencyTrustAttestation` carries `attested_agency_id` right beside it.

Now measured, and the rows are disjoint on purpose: the attest INSERTs a new attestation while the
revoke UPDATEs an existing one, so the key is the only thing they share. The claim held. The
mutation is the one a person would actually make, deriving the key from `attested_agency_id`
instead, and the test goes red against it while the comment would have stayed true.

`check_advisory_locks_have_a_contention_test` now requires every procedure that takes a lock to be
exercised in one direction or the other, not just one procedure per domain. That is the rule that
would have found this gap: `uc10_revoke_attestation` joined an existing lock domain and no test
ever drove it.

Four ships, one question. v9.459 found five tests measuring a sleep instead of a lock; v9.460 found
two substituting their own lock for the procedure's, and two locks that cannot be watched at all;
v9.461 found the local runner reading half its file; and this one found a claim nothing had ever
checked. The question was the same each time, and it was never whether the suite passes.

## v9.461 — 2026-09-14 (the local runner was reading half the file)

Found while verifying v9.459, and worth its own ship because it is about the instrument a person
checks a change with rather than about any particular test.

`scripts/polaris-test.sh app` runs `python test_app.py`. Python executes a file top to bottom, and
`test_app.py` had its `if __name__ == '__main__':` block at line 10269 with **27 top-level
definitions after it**. The block calls `loadTestsFromModule(sys.modules[__name__])` on the module
as it stands at that moment and then `sys.exit()`s, so the last 2,497 lines were never executed,
never defined, and never collected. The command reported 566 tests. With the runner moved to the
end it reports 704, so 138 were never running locally.

Two of the 566 it did run raised `NameError: name '_sql' is not defined`, because `_sql` is a
module-level helper defined at line 10252, below the block. Run the same tests through the module
path and they pass: the whole file loads because `__name__` is not `__main__`.

**CI never saw any of it,** which is the worst shape this defect can take. CI loads the module
rather than executing it, so the block never runs and all the classes are collected. The local
command a person checks a change with was the broken one, and the remote that would have caught it
is the one that works. A local suite that silently skips a fifth of a file and reports two
failures that do not exist is worse than one that refuses to start.

The runner is now the last thing in the file.

`check_test_runners_are_last_in_their_file` (270) holds it there across four test files. It found a
second instance on its first run, and the second instance turned out not to be a defect:
`polaris_checks/test_checks.py` has 186 definitions below its guard, but that guard delegates with
`pytest.main([__file__])`, which starts a fresh session and imports the file as a module. So the
check had to tell a runner that collects from the half-built `__main__` apart from one that
re-imports. That distinction was measured rather than reasoned: a two-test file of each shape, run
both ways. The unittest form collected 1 of 2; the pytest form collected 2 of 2. The check now
matches on `sys.modules[__name__]` and bare `unittest.main()`, and the detection test asserts the
delegating form stays OK, because otherwise the check is a style rule about where a block sits
rather than a statement about what runs.

## v9.460 — 2026-09-14 (the other direction, and two locks that cannot be watched)

v9.459 fixed five tests that claimed two operations on DIFFERENT entities do not serialize. Two
tests in the same class claim the opposite, that operations on the SAME entity do, and they were
worse.

Both took the advisory lock BY HAND. The test computed
`hashtext('polaris.federation.attest.4')` itself, acquired it, slept inside the transaction, and
then called the procedure. Both threads serialized on the TEST's lock, so the procedure's locking
never entered the measurement. Measured rather than argued: `uc10_attest_trust` and
`uc11_close_epoch` were reinstalled with their `PERFORM pg_advisory_xact_lock(...)` line **deleted
outright**, and both tests passed.

Taken with v9.459 that is the whole picture. The cross-entity tests prove a key SEPARATES and pass
happily against a procedure holding no lock at all, because two calls that never contend are
exactly what no lock looks like. The serialization tests were supposed to be the other half.
**Nothing in the suite would have noticed any of these six procedures giving up its lock.**

`assertContends` is the mirror of `assertDoesNotContend` and holds through the PROCEDURE. Four
domains are now proven to take their lock: `uc6_migrate_algorithm`, `uc8_revoke_token`,
`uc10_attest_trust`, `uc11_close_epoch`, each red against its own lockless build.

**Two are not observable, and the honest answer was to say so rather than ship a green test.** Both
were written first and both passed against a lockless procedure, which is how they were caught:

  * `uc9_complete_recovery` locks on `claimed_individual_id`, and
    `uq_one_pending_recovery_per_individual` allows one PENDING recovery per individual. Any two
    calls sharing the key target the same row and serialize on its `FOR UPDATE` regardless.
  * `close_anchor_batch` locks on `algorithm_id` and batches every pending row under it. Holding
    the first open does not help: under READ COMMITTED the probe cannot see the holder's
    uncommitted batching, reads the same set, and blocks on the UPDATE either way.

Neither lock is redundant. Each closes a window before its own SELECT. But from outside the
procedure they cannot be told from the row locks beside them, and `_UNOBSERVABLE_LOCKS` records
that with the reason rather than leaving a test that cannot tell.

**Three of the four lock-presence tests were wrong on their first draft, in the way this ship is
about.** They probed with the same entity as the holder, so they blocked on a unique index or a
row lock and passed against lockless builds. `uc6` was repaired by migrating to a DIFFERENT target
algorithm, which shares `token_id` with the holder but not `TokenSignature`'s
`(token_id, algorithm_id)`. The other two could not be repaired and became the two declarations
above. The helper now separates "blocked at the lock" from "reached its own validation and
objected there", because those look identical if you only watch whether the call returned.

`check_advisory_locks_have_a_contention_test` gained both rules: a test may not execute
`pg_advisory_xact_lock` itself and then call a procedure that takes one, and every domain needs a
holding-direction test or a declared reason. Its first version failed on the tree by matching its
own explanatory docstrings, which is the same error one level up, and it now matches a quoted SQL
literal instead of the word.

## v9.459 — 2026-09-14 (five concurrency tests, none of which could fail)

CI went red on a timing test by 7 milliseconds: `elapsed=0.557s not less than 0.55`. The obvious
repair is to move the number. Reading the test first was better.

`test_close_anchor_batch_cross_algorithm_parallel` existed to prove that two batch closes under
DIFFERENT algorithms do not serialize, because `close_anchor_batch` locks
`hashtext('polaris.anchor.close-batch.' || algorithm_id)` and the algorithm is what separates
them. It ran two threads, each sleeping 0.3s, and required the pair to finish in under 0.55s on
the reasoning that a shared lock would cost 0.6s.

**The sleep came before the CALL.** The procedure takes its advisory lock as its first statement
and holds it until commit, so at the moment both threads were sleeping neither held anything. Two
threads sleeping concurrently take 0.3s whether or not their keys collide. The stopwatch was
measuring the sleep.

Proven rather than argued. The procedure was rewritten with the lock key
`hashtext('polaris.anchor.close-batch.GLOBAL')` -- one key for every algorithm in the system --
installed into the test database, and the test passed. Then the same question was put to the rest
of the family, and the same mutation was applied to `uc8_revoke_token`, `uc9_complete_recovery`,
`uc6_migrate_algorithm` and `uc10_attest_trust`, dropping agency, individual, token and attesting
agency from their keys. **All five tests passed against lock keys that ignored the entity they
were keyed on.** Five tests, one defect, and it was in every one of them.

All five now ask Postgres instead of a clock. One worker calls the procedure and holds its
transaction open, so its advisory lock is genuinely held; the other runs under `lock_timeout`, so a
shared key raises `lock_not_available` rather than merely taking longer. There is no threshold and
no calibration, the answer does not move when the runner is busy, and the failure message carries
the offending key expression verbatim from Postgres:

    canceling statement due to lock timeout
    CONTEXT: SQL statement "SELECT pg_advisory_xact_lock(
            hashtext('polaris.anchor.close-batch.GLOBAL'))"

Each one also now asserts its own effect landed: both tokens REVOKED, both recoveries APPROVED with
a token issued, both migrations signed, both batches closed, both attestations recorded. A lock test
that never checks the work happened can be satisfied by two operations that both did nothing.

**A timing helper that told you to re-run a real regression.** `_assertRanInParallel` treated any
reading above `baseline + PARALLEL_SLEEP` as an unusable measurement, on the reasoning that two
workers cannot be slower than two run in sequence. The reasoning holds; the estimate it was applied
to does not. `baseline` timed one BARE round trip while each worker also ran the procedure under
test, so a genuinely serialized pair costs more than the estimate and lands in the band labelled
impossible. Measured against the global-key mutant: elapsed=0.643s versus a serialized estimate of
0.606s. A real shared-key regression would have been reported as "the machine stalled
mid-measurement; re-run this job." The helper is gone along with the approach.

`check_advisory_locks_have_a_contention_test` (269) keeps it that way. Every advisory-lock domain
in `05_procedures.sql` that carries a parameter must be driven by a test calling
`assertDoesNotContend`; a domain with a single global key must be declared with its reason
(`polaris.zk.close-epoch` is, because epoch_id comes from a SERIAL and closures must not skip a
gap). It also fails if the helper stops setting `lock_timeout`, since without one a shared key is
not an error but a slow pass, and if a parallelism claim is ever again decided by comparing elapsed
time against a constant. The check found one more thing on its first run: the batch-close test had
been rewritten inline before the shared helper existed and was not using it.

The five tests run in 9.3s where they took 11.6s, because none of them sleeps any more. That is the
smallest thing about this ship. The finding is that this family went red, was repaired twice in
three days, and neither repair touched the reason it could not fail. v9.397 replaced the absolute
thresholds with a measured baseline after a parallel run clocked 0.616s and was called serialized.
v9.456 added the unusable-measurement branch. Both were repairs to the calibration, which had never
been the problem. And v9.397 migrated three of the five call sites: the two left on the original
hardcoded 0.55 were `close_anchor_batch` and `uc10_attest_trust`, and the one that went red
yesterday was the first of those two.

## v9.458 — 2026-09-13 (the license was right and nothing held it there)

A question worth asking directly: keep Apache 2.0, or change it. Measured first, then answered.

**Keep it.** The reason is section 3, the express and irrevocable patent grant, with a clause
that terminates it for anyone who brings a patent suit over the work. MIT and BSD grant copyright
permission and say nothing about patents. For a reference implementation of a lattice signature
scheme that is the wrong silence to ship: the patent landscape around post-quantum cryptography is
younger than the algorithms, and an integrator building a production verifier out of this code
would be carrying that risk with nothing from the license. Copyleft would defeat the purpose,
which is to be built on, including by the deployments this models.

Nothing in the dependency tree argues otherwise, and that was checked rather than assumed. Every
Python, Rust and npm dependency is permissive (Apache-2.0, MIT, BSD-2/3-Clause, PSF-2.0, or dual
MIT/Apache-2.0) with one exception: psycopg2, LGPL 3 with an OpenSSL exception, used as an
unmodified library through its public API. Its obligations attach to psycopg2, not to this work.
NOTICE now says so by name instead of listing it among four dependencies that "each retain their
own license", which is true and useless to anyone doing a review.

**What was actually missing was enforcement.** All five package manifests already declared
Apache-2.0, the LICENSE appendix was filled in, NOTICE existed. Nothing held any of it there. A
package added later with no `license` field renders on npm and crates.io as no permission granted,
and the tree would have been green. `check_license_is_pinned` globs for manifests rather than
listing them, so a package added tomorrow is in scope without anyone remembering, and it holds
LICENSE, NOTICE, the README badge and the README's License section to one identifier. A tree where
it finds no manifest FAILS rather than reporting clean.

**And NOTICE was outside every honesty check.** It is the furthest-travelling surface the project
has, because section 4 requires a redistributor to carry it, and it said the project was
"maintained as a working system prepared for national deployment" while every checked surface said
reference implementation on notional data. It now says what the others say, and it is in
`_OUTWARD_SURFACES`, so the post-quantum agility rule holds it too: it points at the readiness
ledger rather than leaving the word unqualified.

---

## v9.457 — 2026-09-13 (a job that could not run what it was asked to run)

v9.456 wired the two-SDK mutation drill into the `pqc-real` CI job. That job has Python and a
built liboqs. It has no Node dependency tree, and the drill's TypeScript half runs `node --test`
inside `sdk/typescript`.

The drill behaved exactly as designed: before believing any mutation result it checks that the
UNMUTATED tree passes both suites, found that it did not, and refused to report. That is the right
refusal. But the job then died on its own setup rather than on a finding, which is a red build
that says nothing about the tree, and a red build that says nothing is how a real finding gets
waved through as "that job is flaky again".

`pqc-real` now sets up Node 24 and runs `npm ci` for the TypeScript SDK before the drill.

**The check that would have caught it.** `check_ci_jobs_install_what_they_run` asks, for every job
in `ci.yml`, whether it reaches the TypeScript SDK's suite, and if so whether it installs the
SDK's dependencies and pins the Node version. The version is not cosmetic: the suite executes
`.ts` sources directly under Node's type stripping, which older Node does not do.

**The need is one hop from the step.** The job runs a PYTHON script; the Python script runs
`node --test` inside `sdk/typescript`. Nothing in the job's own commands mentions Node at all, so
the check follows any repository script a step invokes and reads its source too. Both jobs that
reach the SDK are found that way, and a tree where none is found FAILS rather than reporting
clean.

**The first version of that check found the right job for the wrong reason.** It matched
`node --test` as a literal, which does not appear in the drill, whose invocation is the argv list
`["node", "--test"]`; it found `pqc-real` only through a second, incidental spelling in the
conformance arguments. Delete that one string and the check would have gone quietly blind. The
signal is now structural, naming the directory and an invocation of the runtime, which survives
both spellings and the next one.

---

## v9.456 — 2026-09-13 (the other reference implementation)

v9.455 inverted every refusal in the Python SDK and closed eighteen of eighteen. It asked the
question of one implementation. Polaris ships **two** reference verifiers, both certified by the
same conformance suite, and an integrator picks whichever matches their stack. The TypeScript one
had never been asked.

**Nine of fourteen.** Fourteen refusals in `sdk/typescript/src/index.ts`, nine of them able to
accept what they exist to reject with `node --test` and the conformance runner both green. The one
worth naming:

- **`sameBytes`, the constant-time comparison.** Its first act is a length guard. Inverted, arrays
  of different lengths fall through to a loop over the shorter one and compare EQUAL. A five-byte
  value matches a 32-byte Merkle root. That is the comparison every signature, root and digest
  check in the TypeScript SDK funnels through, and nothing in either suite noticed it was gone.
- `verifyInclusion`'s bounds check on the leaf index, and its node-shape check.
- `grantWithinLimits`' use-count ceiling and amount ceiling, the same pair the Python SDK had open.
- `grantCovers`' empty-action-list guard, `revocationEndsGrant`'s id match.

Six tests close them. The drill now runs both SDKs: **32 refusals, 4 declared survivors with
stated reasons, and a per-SDK negative control** that inverts every refusal at once and confirms
the harness can produce a survivor at all. Without that control, "0 survivors" and "the suite
never ran" print the same number.

**Three harness errors, each caught by the harness.** The TypeScript refusal regex was anchored to
a line start, so it matched nothing in a file that writes `if (cond) return false;` -- a vacuous
"0 of 0" that looked like a pass. The labeller only recognised top-level functions, so class
methods were all attributed to whichever function preceded them. And the sandbox copy excluded
`node_modules`, so the baseline could not resolve its own imports; the drill refused to report
rather than calling an unbuildable tree clean. The declared-survivor list is checked in both
directions, which is what caught the mislabelled names: a declared survivor that no longer
survives fails the drill just as a new survivor does.

`check_sdk_refusals_are_mutation_tested` now requires both SDKs to be in the drill's reach and the
TypeScript suite to exercise the length guard by name.

**A timing test that could not say what it measured.** `_assertRanInParallel` compared elapsed
time against a serialized estimate; when the sample was unusable (the runner stalled and elapsed
exceeded the estimate despite real parallelism) it reported a plain assertion failure that read as
a concurrency regression. It now names the case: the measurement is unusable, not the property.
`polaris-ship.py triage` carries a `concurrency-measurement-stall` signature so a rerun is the
named response rather than an investigation.

---

## v9.455 — 2026-09-13 (every refusal in the reference verifier could be made to accept)

Six mutation drills existed -- checks, constraints, procedures, triggers, the ZK circuit, the
conformance contract. None of them asked the question of `sdk/python/polaris_verify`, which is the
implementation an integrator builds against and the thing the conformance suite certifies: if a
refusal inside the SDK stopped refusing, would anything go red?

**Eighteen of eighteen.** Every `return False` in the reference verifier could be turned into
`return True` -- made to ACCEPT what it exists to reject -- with the SDK's own tests and
`run_conformance.py --self` both green. Among them:

- `grant_within_limits`: a grant's **exhausted use count**, and a **requested amount over the
  grant's ceiling**. Invert either and the reference verifier authorizes a delegated action
  beyond the authority the grant states, which is the whole point of P9.8 being bounded.
- `verify_inclusion`: a **leaf index outside the tree**, and a malformed proof node. Invert and a
  bogus Merkle proof verifies.
- `revocation_ends_grant`: the format check and the grant-id match.
- `grant_covers`: an empty action list treated as "all actions".

**This is not the conformance suite being broken**, and the distinction matters. An SDK whose
signature backends accept anything IS caught, by both suites -- that is the drill's negative
control. The published cases reach the happy path and a tampered-signature path; these guards sit
on inputs no case contains. So the contract certifies what it exercises, and these refusals were
outside it. They are closed in the SDK's own tests rather than by changing a frozen contract.

Eighteen tests later the drill reports **0 of 18**, and two of them were only reachable once the
inputs were found: a signature that is not bytes at all, which raises something other than
`InvalidSignature` and lands in the catch-all arm. Inverting that arm turns every unexpected error
during verification into an accept, which is the worst direction a failure nobody anticipated can
take.

**The mutation inverts rather than deletes, and that was learned the hard way.** The first version
replaced a refusal with `pass`; a function that then falls through returns None, which is falsy
too, so the mutation can be inert. It reported 17 of 18 -- UNDER-stating the gap -- and the
eighteenth appeared protected when it was not. `return False` becomes `return True` now, and
`check_sdk_refusals_are_mutation_tested` refuses a drill that deletes instead.

One thing the tests found on the way: the two signature backends answer an unaccepted algorithm
differently and both are right. `_verify_liboqs` returns False (refused); `_verify_cryptography`
returns None (this backend cannot answer, so the caller falls through to the other). The first
version of the test asserted both return False and was wrong about the contract. What neither may
do is return True, which is what the assertion says now.

**261 invariant checks. 45 tables.**

---

## v9.454 — 2026-09-13 (the headline rested on prose; now it rests on a rule)

v9.453 rewrote the front door to say what is true -- signed with ML-DSA-65 under an audited
algorithm-migration path -- and that left a gap worth naming rather than leaving implied. The
rules `check_post_quantum_claims_are_agility` pinned were the denylist of settled-security
phrasing and the requirement to point at the limitation. It deliberately permitted the words
"post-quantum", because they are accurate about ML-DSA-65, about the SLH-DSA hedge and about the
X25519MLKEM768 edge, and a check that refused a true statement gets routed around. So a future
headline could have gone back to "a post-quantum identity-token system" and still passed.

The overstatement is separable from the accurate use, and the separating line is grammatical.
"The TLS edge negotiates post-quantum key exchange" is a fact about a protocol. "Post-quantum
signatures (ML-DSA-65 by default)" is a fact about an algorithm. "A post-quantum credential
verification engine" is a claim that the SYSTEM cannot be broken by a quantum adversary, which is
a claim about Module-LWE staying hard. The check now refuses post-quantum used as an adjective on
the system, engine or platform, and permits every use that names the thing which actually is one.

Writing that rule immediately found what the v9.453 pass had missed: `site/index.html` still
opened its lede with "Polaris is a post-quantum credential verification engine", because that
rewrite corrected the README's version of the sentence and not the site's. The site now carries
the same framing as everything else, and says why -- ML-DSA-65 rests on Module-LWE hardness, which
is mathematics rather than a property of this repository, while the algorithm being a row in the
schema rather than a constant is.

One detection case from v9.452 had to be corrected rather than kept. It asserted that "a
post-quantum credential engine" must PASS, as the example of an accurate use the check must not
refuse -- and that is precisely the construction now refused. The fixture was asserting the wrong
thing was accurate; it now uses a statement about the SIGNATURE, which is one.

**260 invariant checks. 45 tables.**

---

## v9.453 — 2026-09-12 (forty-six citations to a document that is not in the repository)

v9.55 deleted the apparatus wholesale -- about 18,150 lines and the mythology docs with it.
Three hundred and ninety-seven versions later, **46 references across 24 live files still cited
it as the authority for a rule**, and one of them was an error message an operator reads:

    error: migration 'X' missing .down.sql (Sanctum §IV.2 requires bidirectional)

Somebody who hits that, goes looking for §IV.2 and finds no such document in the repository has
been sent after something that is not there. The rules those citations stood for are real and
worth stating; the pointers are not. Each is now the reason it encoded -- a migration that cannot
be reversed is one you can only go forward from; `schema_version` is append-only so a revert is a
new row rather than an edit -- which is both true and more useful than a section number.

Two were worse than dangling. `01_schema.sql` counted the deleted apparatus's session table among
the audit-of-record instances, so AnchorBatch was the FIFTH and AgencyTrustAttestation the SIXTH
by a tally that included a table the catalog does not have. They are the fourth and fifth.

And one was in the module this matters most for. `pqc_signing.py` explained the placeholder by
citing a deleted tier list, including in `availability_report()["notes"]`, which is
runtime-visible. It now states what the module actually does: real signing behind
`POLARIS_USE_REAL_PQC=1`, a labelled 32-byte placeholder without it, and where the limits are
written down.

`check_no_citations_to_deleted_apparatus` holds it. What it does NOT refuse is a sentence
recording that the apparatus was removed -- MISSION.md carries one, explaining that the owner's
recorded direction authorizes an amendment now, and that is the honest treatment rather than a
violation. Any retired name is allowed within 200 characters of "removed", "retired", "deleted" or
"no longer". The CHANGELOG, the migrations and DEVNOTES are exempt outright: they record what
happened, and rewriting them to satisfy a check would be editing the past. The check's own
docstring paraphrases its examples rather than quoting them, because this file is live and a
verbatim citation in it would be one.

**Two documents were also past their re-read window**, which `check_presentation_surface` caught
on the same push, and both needed more than a stamp.

SECURITY.md had no mention of the placeholder. A researcher reading its in-scope list would
reasonably report that credential signatures do not verify on a default checkout -- which is the
named development profile, already known, and now said so, along with what IS in scope there: the
guard failing, a placeholder that is not labelled, or a verifier that accepts one as a signature.

CONTRIBUTING.md told a contributor that `polaris-test.sh` passing is one of the conditions for a
merge, without saying that it runs **four of the eighteen suites CI runs**. v9.443 passed every
suite that document names and broke `polaris_sim.test_sim` in CI twice. It says so now.

**And the front door stopped calling itself post-quantum.** v9.452 established that the
defensible claim is agility rather than settled security; the headline had not caught up, and the
GitHub About box had reached the point of putting "post-quantum" in scare quotes -- which signals
doubt without explaining it, and is worse than either saying it plainly or not saying it.

The headline now reads the same on all five surfaces it appears on (README, the site title,
description, og:title and subtitle, CLAUDE.md, CITATION.cff and the repository description):
**an issuer-unlinkable, compulsion-resistant identity-token system signed with ML-DSA-65 under an
audited algorithm-migration path.** Every clause of that is a fact about this repository. The
system IS signed with ML-DSA-65; the migration path IS audited and runs in CI; and nothing there
asserts that Module-LWE stays hard, which is the part no repository can assert about itself.

"What Polaris is" now says so in the first sentence rather than leaving a reader to find the
limitation four documents away, and links to it.

**260 invariant checks. 45 tables.**

---

