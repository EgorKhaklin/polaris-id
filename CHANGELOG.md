# Changelog

Externally observable changes to Polaris, pre-pilot software on notional data.
Entries before v9.453 are in [docs/history/CHANGELOG-v9.md](docs/history/CHANGELOG-v9.md).
The full reasoning for each change, with its tests and measurements, is in its commit message.
Entries use the [Keep a Changelog](https://keepachangelog.com/) groups: Security, Fixed, Added, Changed.

---

## Unreleased

### Security

- A holder key rotation or revocation is refused unless its signer is still the live key under the per-token lock, closing a read-before-lock race a stolen-but-live key could ride.
- The Atlas answered a refused parameter with the exception's text, which could carry the request back; it states a fixed sentence.
- An operator bound to one authority could be served other authorities' Atlas counts from its response cache.
- The database refuses a successful verification of a dead credential, outside its permitted contexts, or across an untrusted edge.
- An operator bound to one authority can no longer activate a reserve another authority issued (UC-4).
- The Atlas no longer returns events naming their holders; the access check reads every SQL source.

### Fixed

- Every documented install reaches the current candidate; a bare `pip install` gets 0.1.0, which predates every fix in SECURITY.md.
- The plug-and-play matrix tests the SDKs' current candidates on a genuine and a tampered credential, not npm's `latest`.
- The EU-library lab wallet's lockfile carried nine OSV advisories (Bouncy Castle 1.83, Kotlin 2.2.21); it pins fixed releases.
- polaris-sdk-ts requires Node >= 20.19.0 for its post-quantum dependencies; rc.8 declared >= 18 but does not load there.
- polaris-oid4vp decides status lists the draft sizes as ordinary; a 2^20-entry list with 10% revoked was refused as malformed.
- polaris-oid4vp keygen marks the listener certificate for server authentication; Apple's TLS policy refused it.
- polaris-oid4vp refuses a presentation disclosing claims the request did not select, which OpenID4VP 1.0 section 6.4 forbids; it accepted one.
- polaris-oid4vp keygen gives its CA and leaf the key identifiers RFC 5280 asks for; Multipaz's trust manager skipped the CA without them.
- The checks layer skips other checkouts nested in the tree (agent worktrees); four checks failed on their stale copies.
- polaris-oid4vp serves the request object with `Cache-Control: no-store`, as the German EUDI wallet guide's request_uri response does.
- The record 007 Pomerium demo maps `*.localhost.pomerium.io` to loopback itself; public DNS stopped resolving it.

### Added

- polaris-oid4vp asks for a nested claim and its value (`--claim age_equal_or_over.18=true`): one statement of an EUDI PID, not all of them.
- polaris-oid4vp verifies an issuer `x5c` through the intermediate CAs it carries, link by link in order, as eudi-dev v2.5.0's PID Provider sends.
- An issuance tunnel serves only the wallet's OpenID4VCI endpoints over your own tunnel, so a wallet can be issued a demo copy.
- A one-command helper mints an OpenID4VCI wallet-copy offer through the operator route, for the issuance-tunnel demo.
- A README badge for the pre-pilot status; the outside implementations are listed under Tested against.
- A Discord server for questions and conversation, linked from the README, CONTRIBUTING, SUPPORT.md and the issue chooser.
- Exact credential and live-signature counts by authority, kept by triggers that only append (`PopulationCount`).
- Indexes for expiring credentials, credentials by status, issuance in a window and one credential's verifications.
- Find a credential by number, token value or card serial, or a person by name and date of birth; the text stays out of URLs.
- An index for finding a person by date of birth and the beginning of the name.
- A credential's page offers the operations its state admits; a person's page offers recovery and the warrant audit.
- The verification log filters by credential, and a credential's page links its every verification there.
- An index on every foreign key between tables that grow with the population, and a test that reads the catalogue for one missing.
- Exact enrolment counts by jurisdiction and status (`EnrollmentCount`), kept by triggers; the application role cannot read the per-person row.
- An index for counting the active credentials that carry a duress code.
- Hourly and daily activity counts by authority, context and outcome, kept by triggers; no person, place or minute.
- The Atlas Overview shows the latest state epoch and anchor batch, and the Athena board's verdict on the database.
- Atlas breakdowns and cross-tabs compare with the window before; a change shows only where both counts do.
- polaris-oid4vp runs behind a proxy or tunnel: `--public-base-url` sets the wallet-facing HTTPS origin, `--no-local-tls` serves plain HTTP.
- The README and polaris-oid4vp's page list every outside implementation the verifier is walked against: maintainer, language, last walk.
- The wallet canary walks the EU reference OpenID4VP library too, so all five implementations are re-run weekly.
- A sixth implementation, vck (A-SIT Plus, Kotlin), presents to the published verifier a credential it issued; re-run weekly.
- A lab walk decides outside status lists: the draft's test vectors, its signed example and the OpenWallet Foundation's tokens.
- The wallet canary runs the OpenID Foundation's conformance suite weekly against the published verifier, with both controls.
- Four more walks against the published verifier, re-run weekly: the EU iOS OpenID4VP library, irmago (Yivi), SpruceID's adapter and Procivis One Core.
- ProtocolSoup v4.0.0, a wallet the OpenID Foundation lists as certified, presents to the published verifier; re-run weekly.
- ERICA, the German EUDI Wallet programme's verifier testing tool, presents and runs its negative modes; it passes 48 of 49 request checks.
- Multipaz 0.101.0 (OpenWallet Foundation) presents to the published verifier; re-run weekly.
- The EU reference PID issuer issues a PID that the published verifier accepts, trusting only the issuer's test root; re-run weekly.
- A credential issued under a `did:cheqd` on a local cheqd ledger, its status list on the ledger, is accepted and its status decided; re-run weekly.
- The weekly canary also runs ERICA, and the EU iOS library with the wallet kit's own request-object encryption.
- polaris-oid4vp encrypts the request object to the wallet's key when its `wallet_metadata` asks, as the EU iOS wallet kit requires.
- polaris-oid4vp `serve --verifier-info` adds attestations such as a registration certificate to the request, as the German wallet requires.

### Changed

- The scoreboard records the IETF SD-JWT repository listing polaris-oid4vp among its implementations.
- MISSION.md's second item reads "ML-DSA-65 by default", not "Post-quantum by default", by the owner's direction (2026-10-03).
- The operator console is rethought around what Polaris is now: grouped, role-gated navigation; new sign-in, landing and Overview.
- The Atlas shows counts only: its map points, event feed, records grid and person focus are withdrawn.
- The Atlas reads hourly and daily totals, never an event: the page from 6.7 s to 31 ms at ten million verifications.
- The Atlas withholds every count below five and any figure that would give one back; a narrow question is logged.
- The Atlas map draws counts per jurisdiction only; its cluster, hexagon and timeline layers are withdrawn.
- An Atlas filter takes one context and one authority at a time, and every Atlas figure counts any non-success as a failure.
- No event coordinate is indexed or written: five indexes go, and the optional PostGIS path is withdrawn.
- The token export carries no coordinate, as no page shows one; its events name their fields.
- Athena's Constitution tab reads each mechanism from the connected database's catalogue when opened.
- Athena's self-test attempts six forbidden writes, rolled back, and shows on each rule what refused it.
- The Overview costs the same at any population: 10.4 s to 0.12 s at two million persons.
- Console counts read to thirteen digits and beyond; a capped count says "or more".
- The seven operation forms start from one record found by lookup instead of listing every credential or person.
- Lists page by key by default; an old page number answers while its offset stays within 10,000 rows.
- A filtered verification log reads at most 20,000 events for a page and says how far it looked.
- A credential's page and the investigation pages show the latest rows and cap their lifetime counts.
- The wording checks read the three pages served without sign-in: landing, sign-in and walkthrough.
- The enrolment summary reads the maintained counts: 7.2 s to 14.5 ms at two million people, in 64-bit counts.
- The credential page is rebuilt: facts beside proofs, one table per kind of row, empty kinds in one line.
- On a phone, each list keeps a row's identifier, state and holder; the rest is on the record's page.
- A status change is offered only where the database makes it; revocation keeps its own operation.
- The SQL console shows at most 500 rows of a query, read from a server-side cursor, and says when there are more.
- A web request's statements end two seconds before its worker's timeout, so no query outlives its request.
- The landing emblem has no ring; a soft gold halo sits behind it.
- `polaris-id migrate-algorithm` signs as the route does; `--signature-hex` and `--signature-file` are withdrawn.

### Fixed

- The README's OpenID Certified badge now names what it covers: the polaris-oid4vp verifier, not Polaris.
- The SQL console runs one statement per query; a second statement could lift its five-second limit.
- SECURITY.md called PyPI's publish attestation the same kind of provenance as build provenance; it says what each is.
- A credential's page and both investigation pages read its verifications through an index, not a full scan.
- Release SBOMs failed the NTIA minimum elements and four were invalid SPDX; the release checks both before publishing.
- The advisory-lock check reads locks taken in functions; the holder key register's lock gains contention tests.
- The migration page and API.md no longer say a migration always writes a placeholder; it signs with the signing module in force.
- The warrant audit page no longer says zero-knowledge events come back redacted; they are never returned.
- The Atlas marked every withheld count "<5", false for one withheld for its whole's sake; it shows a neutral mark.
- A person's investigation page takes its colours from the theme; a credential value read at 3.48:1 in light.
- A credential's investigation page found its successor by scanning every credential: 904 ms at 3.6 million.
- A credential's page read its device bindings and revocations by scanning those tables.
- Record pages' tables scroll at phone width, and their hard-coded pill colours (3.49:1) take the theme.
- The public walkthrough said post-quantum signing protects against coercion; it now marks where each rule is enforced.
- An Atlas series could carry one bucket more than asked, and its authority filter took non-ASCII digits.
- The simulator stamped events on the host's clock, so on a host off UTC the Atlas's hour windows missed them.
- The UI drill and the performance baseline refuse a port another server holds; the drill's app no longer outlives it.
- In the Atlas, a hovered tab keeps its label and a lone interval is drawn; a stacked chart no longer reads a withheld value as zero.
- Public pages: no empty band above the first line, a visible secondary action, a four-column feature grid.
- Every page showing the OpenID® Certified™ mark names the OpenID Foundation as its owner, as its trademark policy (2.2) asks.
- SPEC-COMPLIANCE.md said `vc+sd-jwt` credentials are verified; the verifier refuses them (`issuer_typ`), as its README says.
- The EU-library lab walk failed its dependency check on a clean machine: its verification metadata missed one BOM a cold cache fetches.
- The duress wording check passed the noun "compulsion resistance"; API.md and DATA-MODEL.md named the mechanism with it.
- API.md pointed at `app.py` for the federation check; it is in `verification_routes.py`.
- The signals queue said "N of M active" while counting every credential with a duress code, in 923 ms.
- Delete buttons for a person, a credential and an authority, which the database always refuses, are gone.
- A credential issued by recovery carried a placeholder for a signature and verified under nothing; approval now signs it.
- Issuance and migration recorded the algorithm a request named, not the one that signed; now the signing key's set.
- The readiness ledger said a Module-LWE break needs no verification code; the hash-based fallback has no signer or verifier.
- A status change to a number that is no credential reported success.
- A refused deep page number now says what to do instead and offers the list back.
- The population recount's lock test passed with the lock deleted; it now holds a fold that touches no row.

## v1.0.0-rc.70 — 2026-10-01 (the three verifiers read every input alike)

The three verifiers read instants, ids, keys, grant actions and status answers alike, and `polaris-verify` refuses a flag its mode would not read; `polaris-oid4vp` verifies only under keys meant for ES256 signatures; the application's database role no longer writes the holder key register directly. 10 security changes, 12 fixes.

### Security

- The application's database role no longer writes the holder key register directly; the route has recorded events only through its routine since rc.69.
- All three verifiers read one instant grammar: ASCII digits, no surrounding whitespace, offsets below 24 hours, years 1 to 99 as written.
- An agency or context id matches only the same string or integer in all three verifiers; Python's `==` read `true` as 1 and a missing id as a null one.
- Both SDKs read only the JSON `true` as currently authoritative; both read a status answer of `"false"` as current.
- All three verifiers refuse an agent grant whose `grant_id` is not text; it is the grant's only revocation handle (WIRE-SPEC 3.17).
- All three verifiers read a key or a digest only as a hex string; the TypeScript SDK read a signed `[K]` as K, and two missing keys matched in Python.
- `polaris-oid4vp` verifies an issuer signature or a key binding JWT only under a JWK meant for ES256 signatures; an encryption key verified either.
- `polaris-verify --zk-proof` reads `--issuer-anchor` and abstains without a trust root or a `--nonce`; it accepted with neither.
- `polaris-verify` refuses a flag the chosen mode would not read; `--presentation` ignored `--status-assertion`.
- `polaris-verify` refuses a value flag given twice; a second `--issuer-anchor` replaced the first.

### Fixed

- The TypeScript SDK writes a small number and orders keys as the signer does, so a genuine artifact with `1.5e-05` or an emoji key verifies.
- All three verifiers read the ids, nonces, actions and credentials that grants, proofs, bindings and revocations name as text; a value with none matches nothing.
- An id, nonce or action beyond 2**53 is not one any verifier reads; JavaScript reads the nearest double there.
- All three verifiers trim only ASCII whitespace from a pairwise handle or nullifier; other Unicode spaces split the SDKs.
- The TypeScript SDK refuses a credential that is not an object instead of throwing, and checks each grant limit and the use count alone.
- The Python SDK reports no nonce match for a holder proof it cannot check, as the TypeScript SDK does.
- A trusted anchor, witness or log key that is not text matches nothing in all three verifiers; each raised on it.
- `polaris-wallet grant --max-amount 100` signs 100, not 100.0, which the TypeScript SDK could not verify.
- `polaris-oid4vp serve` refuses an `--issuer-jwks` file it cannot read or use; one raised, and one with no usable key started silently.
- `polaris-verify --json` prints `abstain` for a zero-knowledge or stapled accept that exits 2; it printed `accept`.
- `polaris-verify` reads zero-knowledge public inputs as `polaris-zk` does: integers below 2**64 and a 64-digit nullifier; it read `"7"` and `true`.
- Both SDKs' conformance adapters report no pairwise handle for an object that is not a holder binding, as the detached verifier and the contract do.

### Added

- Ten conformance cases pin where the two SDKs disagreed on signed bytes.
- Twenty-two more pin nonces, contexts, agencies, grant ids, actions and ids beyond 2**53, from three reviews of that fix.
- Six conformance cases pin keys and digests as hex text; the suite has 281 cases.
- `scripts/polaris-hostile-agreement-drill.py` has all three verifiers decide every published case with each presenter-supplied node retyped or deleted, 184,331 inputs from 281 cases; CI runs a third.
- `lab/interop/oid4vcgo` runs OID4VCgo v0.23.0, which holds the verifier's leaf to HAIP; accepted, and all four controls refused.

### Changed

- Published: `polaris-oid4vp` 1.0.0rc12 on PyPI (not certified; 1.0.0rc7 is), built before #157 and #168; 1.0.0rc13 carries them.
- `polaris-verify` exits 4 on an unknown flag or a mistyped value, and 3 without `polaris-zk`; each exited 2.
- `polaris-verify --pack` names another signed artifact as such, and its README separates the command from the library.
- Lab and drill scripts install their dependencies by hash or lockfile, as CI already did.
## v1.0.0-rc.69 — 2026-10-01 (a holder's key changes only by its own signature)

A holder key changes only with the live key's signature, and the route records its events through a routine that keeps them in order; the application's database role no longer runs the retention routines; the three verifiers read a signed status, a leaf and a document digest alike; `polaris-oid4vp` in this tree holds to RFC 7515, RFC 7516, RFC 9901 and HAIP 1.0 where it did not. 19 security changes, 4 fixes.

- **Breaking**: `polaris-oid4vp`'s `Verifier` answers 400 to a credential its resolver checked as not VALID, and to one missing a requested claim.
- **Breaking**: `polaris_oid4vp.status.decide` requires `expected_uri`.
- **Breaking**: `POST /api/v1/holder-key` answers 409 to a binding over a live key, and 401 to a rotation or revocation without `change_proof` signed by the live key.

### Security

- `polaris-oid4vp` refuses a credential its configured status resolver checked as revoked or suspended; it answered the wallet 200.
- `polaris-oid4vp` refuses a presentation that withholds a claim the request asked for.
- `polaris-oid4vp` refuses an orphan disclosure with key binding waived; only the key-binding path refused it.
- `polaris-oid4vp` judges an `x5c` leaf's validity at the verdict's `now`, not at the wall clock.
- `polaris-oid4vp` refuses a JWE response whose `crit` names any extension, as RFC 7516 requires.
- `polaris-oid4vp`'s `status.decide` binds a list to the credential's own `uri` always; with none it skipped the check.
- `polaris-oid4vp serve` stops serving a request object past its lifetime; a wallet nonce re-signed an expired one.
- `polaris-oid4vp` refuses an issuer JWT typed `vc+sd-jwt`, a W3C VC Data Model credential whose `validUntil` and `credentialStatus` it does not read; it accepted one.
- `polaris-oid4vp` refuses a credential, key binding JWT or status list token whose `crit` names an extension, as RFC 7515 requires.
- `polaris-oid4vp` refuses a key binding JWT past its `exp` or before its `nbf` (RFC 9901 7.3); both were ignored.
- `polaris-oid4vp` refuses a credential that commits to a digest twice (RFC 9901 7.1); one disclosure could stand in two places.
- `polaris-oid4vp` refuses an `x5c` leaf that is self-signed or a CA (HAIP 1.0 6.1.1); the trust anchor itself verified as an issuer.
- All three verifiers read a signed `status` that is present and not `active` as not active; the Python SDK and `polaris-verify` read `false` and `""` as active.
- `polaris-verify` calls an agent grant usable only when it understands its limits; one signed with an unknown limit or a non-finite `max_amount` was usable.
- All three verifiers refuse a revocation feed or epoch leaf set whose leaves are not 64 hex digits; a `null` leaf split Python from TypeScript.
- All three verifiers refuse a signed document whose digest is not lowercase SHA3-256, as WIRE-SPEC 3.12 requires.
- The application's database role can no longer run the retention and archive-purge routines; naming any admin, it could set retention or purge audit rows past the floor.
- A holder key changes only with the live key's signature; presenting the credential, which any relying party that took a full presentation can do, could rebind, rotate or revoke it.
- The holder key route records events through a routine that sets their instant and keeps them in order; the application role's own INSERT goes in a later release, under the expand-contract policy.

### Fixed

- The TypeScript SDK reads a presentation that names a credential and supplies none as having none; it decided the object itself.
- The TypeScript SDK reads an instant to the microsecond, as both Python verifiers do; it rounded to the millisecond.
- Both Python verifiers refuse a fractional use limit or use count, as the TypeScript SDK does; `int()` truncated it.
- The rc.68 notes list only what rc.68 released; a merge after the cut had filed the `polaris-oid4vp` 1.0.0rc12 lines there.

### Added

- Thirteen conformance cases pin the status rule for manifests, registries, holder chains, grants in use and trust edges.
- Eleven conformance cases pin WIRE-SPEC 3.3, 3.16, 3.12 and 2.2 for leaves, signed documents and instants; the suite has 243 cases.

### Changed

- `polaris-wallet holder-keygen --rotate` signs the change with the live key and keeps that key until the issuer accepts the new one.
- Published: `polaris-verify` and `polaris-sdk-python` 1.0.0rc6 on PyPI, each approved at the environment gate, and `polaris-sdk-ts` 1.0.0-rc.7 on npm under `next`, approved by the maintainer with a second factor.

## v1.0.0-rc.68 — 2026-10-01 (trust enters only where the relying party puts it)

The verifiers and SDKs trust a manifest, a tree head or a receipt's responder only through keys the relying party trusts; a login signs only a context the credential is permitted in; a verification record claims a success only when its rules allow it; every Python package the images install is hash-pinned. 19 security changes, 19 fixes.

- **Breaking**: `/api/v1/auth/authorize` answers 400 to a `required_enrollment` outside `PENDING_ENROLLMENT`, `ENROLLED` and `EXEMPT` or a `require_zk` that is not a boolean, and 403 to a `context_id` the credential is not permitted in; each was accepted before.

### Security

- All three verifiers trust a federation manifest only when a trusted key signed it; one that merely listed a trusted anchor was trusted.
- All three verifiers require a signed trust edge's key to be one of the attesting authority's anchors; any key's signature counted.
- All three verifiers require a holder proof to name the credential presented; a proof made for another credential passed.
- `polaris-verify` holds a presentation's holder proof to `--nonce` and abstains without one; `--trusted-anchor` is a trust root on every path.
- The TypeScript SDK reads a holder proof's age in UTC; an instant with no offset was read in the machine's time zone.
- `polaris-verify` refuses an agent-grant chain whose credential does not verify or whose issuer is outside `--issuer-anchor`.
- `polaris-verify` calls an agent grant usable only when all five links were supplied and checked; a bare grant was usable.
- `polaris-verify` abstains on an agent grant or a presentation with no `--issuer-anchor`, as it already did for a pack.
- `polaris-verify` binds a stapled status assertion to the credential's own key; another trusted authority's assertion was accepted.
- Both SDKs verify a credential's own signature before binding an agent grant to it.
- Every Python package the images install is hash-pinned, and liboqs builds from a checked commit; liboqs-python was unpinned and fetched it.
- A login signs only a context the credential is permitted in; `/api/v1/auth/authorize` signed any `context_id`, even one that does not exist.
- Both SDKs take a timestamp anchor's head only as a signed tree head; any artifact the log key signed was read as one.
- Both SDKs trust no federation manifest when the relying party names no trust anchor; a manifest's own signature decided.
- Both SDKs prove a holder chain only with the verifier's nonce and a credential whose signature verifies.
- All three verifiers name a receipt's responder only once `responder_key` confirms the signer; a stranger's receipt named its victim.
- Both SDKs count a holder binding only when it is checked fresh; one with no window counted as fresh.
- The conformance contract asks whether a grant in use is inside its window; an expired grant came back in scope.
- The relying-party script asks about a credential by its signed serial and verifies the answer; it asked by an id the holder could edit.

### Fixed

- All three verifiers require a timestamp's digest to be lowercase SHA3-256, as WIRE-SPEC 3.9 says; SHA-1 and uppercase were accepted.
- Both SDKs refuse a timestamp whose `issued_at` is not an instant, and a revocation feed whose `revoked_count` differs from its leaves.
- A witness threshold is a whole number of at least 1 in all three verifiers; 0.5 and -1 were met by no cosignature.
- The Python SDK reports the authority a cross-authority decision was made under; `via` was always empty.
- A NUL character in a path, query, form field or JSON string is refused as bad input; it escaped as a 500.
- Installed as a package, `polaris-id` refuses the four commands that need a clone and says which; `--version` printed `unknown`.
- Both SDKs refuse a status bundle whose signed `member_count` differs from its members, as WIRE-SPEC 3.4 requires.
- The three verifiers read an inclusion proof's index and size as JSON integers and its path as a list; each coerced differently.
- Both SDKs return a verdict for a manifest set that is not a list; the Python SDK raised on `true`, the TypeScript SDK on any.
- `polaris-verify` exits 3 on an anchor file that is not a key list; the presentation and grant paths raised.

### Changed

- **Breaking**: `polaris-verify` abstains (exit 2) on a presentation carrying a holder proof when no `--nonce` is given.
- **Breaking**: a manifest that lists a trusted anchor but is signed by another key is no longer trusted, in all three verifiers.
- **Breaking**: both SDKs' cross-authority decision trusts no manifest without `trusted_anchors`; pass the anchors you trust.
- **Breaking**: both SDKs' holder chain proves only with `expected_nonce` and a credential whose signature verifies.
- **Breaking**: an exchange receipt's `responder` is null until `responder_key` confirms the signer, in all three verifiers.
- **Breaking**: the agent-grant-use verdict carries `fresh`; a verifier implementing the contract must report it.
- **Breaking**: both SDKs bind a grant only under a holder binding checked fresh; one with no window binds nothing.
- **Breaking**: the relying-party script hands its status checker the credential, not `token_id`, and asks by possession.
- CI installs every Python dependency with `--require-hashes` from a lock; `pip-audit` and `bandit` have one of their own.
- Published: `polaris-oid4vp` 1.0.0rc11 (not certified; 1.0.0rc7 is) and the first `polaris-id-cli`, 1.0.0rc1, on PyPI, each approved at the environment gate.
- `publish.yml` can publish `polaris-id-cli`, gated on its wheel installing and behaving alone; every publish now waits for the maintainer to approve the run.
- Published: `polaris-sdk-ts` 1.0.0-rc.6 on npm under `next`, approved by the maintainer with a second factor.
- `polaris-id-cli` is packaged as 1.0.0rc1 for PyPI: metadata, README and links for a package page, built with setuptools alone.
- The project report and evidence record, in both editions, record the corrections of 2026-09-28 to 2026-09-30.

### Fixed

- `polaris-ship.py triage` names a job GitHub never gave a runner, from its annotation, instead of calling the finished run unknown.
- Two image checks read each Dockerfile's instructions, not its comments, and require a hash-checked install in every image; a comment could pass for one.
- A login's requested enrollment status applies alongside the registered one, and a malformed requirement is refused; the registered status replaced the request's.
- An operator cannot record a SUCCESS in a context the credential is not permitted in; UNAUTHORIZED records that presentation.
- An operator's SELECTIVE success names its credential; one naming none passed every success rule unchecked.
- The sample data's trust graph explains every sample verification; two cross-agency successes had no attestation.
- SECURITY-CONTROLS and the threat model say what the definer routines bound: their rules, not their caller. The threat model said none existed.
- A non-numeric acting agency on a token's status change is refused; it escaped as a 500.
- `polaris-oid4vp` accepts an issuer certificate whose extended key usage is ISO 18013-5's document signer, as EUDI issuers' are; it refused eudi-dev's PID Provider.

### Added

- `lab/interop/oid4vcgo` runs OID4VCgo v0.22.0, which checks the verifier's request-object chain after our report, with a fourth control.
- `lab/interop/eudi-dev/run.sh` with `EUDI_ISSUER=1` has eudi-dev's own issuer sign the credential; the wallet canary runs it weekly.
- Six conformance cases, each a published vector with one hostile field, pin these rules.
- Six more, three attacks and their controls, pin who signed a manifest or a trust edge and which credential a holder proof names.
- Nine more pin the timestamp, revocation-feed and manifest-signer rules of WIRE-SPEC 3.9, 3.3 and 3.1.
- Eleven more pin what a tree head, a holder chain, a receipt and a grant in use are trusted on; the suite has 219 cases.

## v1.0.0-rc.67 — 2026-09-30 (one command to a verified result)

From a clone, one command runs the production stack and has published polaris-verify verify an ML-DSA-65 credential it issued; code scanning and fuzzing, releases sealed with SBOMs and provenance; 11 security changes, 40 fixes.

### Security

- `polaris-oid4vp` refuses an x5c credential whose `iss` its certificate does not name.
- A wallet-copy offer is recorded under the operator's account before it is returned; nothing recorded who made one.
- Every GitHub Action is pinned to a full commit SHA, checkouts drop the workflow token, and Dependabot waits seven days on a new release.
- `publish.yml` builds with a hash-pinned toolchain and no build isolation, and installs one npm checked against its integrity.
- `polaris-oid4vp serve` refuses TLS below 1.2; on Python 3.9 builds that default lower, 1.0.0rc9 accepted TLS 1.0 and 1.1.
- The three verifiers refuse a grant whose `limits` is present but not an object; the Python ones read it as unlimited.
- The Python SDK refuses an `issuer_url` whose scheme is not `https` or `http` before `urlopen`. (thanks @DYNOSuprovo)
- WebAuthn registration no longer answers with an internal fault's text; the audit log keeps it.
- The app no longer makes its development state directory world-writable; the macOS launcher trusts only a secret file the user owns.
- The `pypi` and `npm` environments deploy only from `main`, and a published release's tag and assets cannot be changed.
- Workflow tokens are read-only at every workflow's top level; the jobs that write ask for it themselves.

### Fixed

- `polaris-oid4vp serve` answers `/done`, where it sends an accepted wallet, with a page instead of 404.
- `polaris-oid4vp` status checks allow a list dated up to 300 s ahead and read the clock after the fetch.
- The OpenID4VCI credential endpoint refuses a proof whose `iat` is NaN, which passed the five-minute window.
- The OpenID4VCI credential endpoint answers `400 invalid_proof`, not 500, to a proof over 16 KB or nested past the parser.
- A JSON request body nested past the parser's depth is refused as malformed, not answered with a 500.
- **Breaking**: `polaris-verify` exits 2, not 1, for a presentation or ZK decision it does not accept, as its exit table says.
- The Python SDK refuses, instead of raising on, a non-string artifact `format`, non-list `cosignatures` or a non-object revocation feed.
- `polaris-verify` refuses, instead of raising on, timestamp-anchor `cosignatures` that are not a list.
- The TypeScript SDK treats an artifact `format` that is not a string, or names a prototype member, as unknown, as the Python SDK does.
- The TypeScript SDK refuses a signature or key whose hex has a character that is not hex; it read `eg` as `0e`.
- The Python SDK and `polaris-verify` refuse hex with whitespace between bytes, which `bytes.fromhex` skipped.
- `/api/v1/verify`, the possession routes and the exchange gateway read hex that way too; whitespace is refused.
- The exchange gateway answers 502, not 500, when its upstream returns JSON nested past the parser.
- A second `polaris-ship.py run` on the same database server is refused; two runs dropped each other's databases.
- `polaris issue` signs what it issues; it stored a placeholder that verifies under nothing.
- `polaris key-register`, `key-retire` and `key-compromise` work as the schema owner; each failed reading its new row.
- `polaris bulk-enroll` signs under the issuing agency's own key and refuses another, as the issuing route does.
- `polaris-create-operator.sh`, `polaris-generate-recovery-code.sh` and `polaris-recover-admin.sh` work with `--target=docker-stack`; each handed psql a host file.
- The CLI README installs from a clone; it named a package that is not published.
- `polaris-verify --verify-dir` reports a vector that is not a JSON object instead of raising.
- `polaris-verify` no longer calls missing revocation evidence a revocation in its long-term-validation note.
- NOTICE names psycopg 3 and certifi, which are not permissive, and drops files the tree no longer ships.
- SECURITY-CONTROLS.md says Polaris is built for national-scale identity data and holds notional data; it said it stored such data.
- `polaris-oid4vp` tries every configured issuer key, not only the first that parses, so a rotated key verifies.
- `polaris-oid4vp` refuses an `x5c` header that is present but empty or not a list, instead of reading it as absent.
- **Breaking**: `polaris-oid4vp` reports the `no_authority` and `list_refused` revocation states it called `unreachable`.
- `polaris-oid4vp` refuses a JWE whose tag is not 128 bits; other splits of the same bytes decrypted.
- `polaris-oid4vp` refuses a status list whose compressed stream never ends; a truncated one was accepted.
- `polaris-oid4vp` refuses an issuer `kid` that is present but empty or not a string; `""` matched any listed key.
- The TypeScript SDK trims an issuer URL's trailing slashes in linear time; its regular expression took 30 s on 200 KB of slashes.
- `polaris-oid4vp serve` counts a body's raw bytes against Content-Length; invalid UTF-8 hid a truncated body.
- CITATION.cff says duress-aware, not duress-resistant; the vocabulary check now refuses the duress forms it missed.
- `polaris-relying-party.py` rejects, instead of crashing, when the issuer refuses its OAuth client.
- `polaris-relying-party.py` exits 3, instead of crashing, on a presentation that is not an object or an anchor it cannot read.
- The exchange gateway answers 502, not a non-JSON reply, when its upstream answers NaN, Infinity or 1e400.
- The Athena routes answer 400, not 500, to an id outside INTEGER's range; the agency facet, to a negative `limit`.
- The trust-anchors loader refuses a key of no accepted length; signature checks refuse, not raise, on a non-string.
- `polaris-create-operator.sh --target=docker-stack` hashes the password in the app container; the host needs no werkzeug.
- The eudi-dev and OID4VCgo interop records no longer say the wallet trusts the verifier's TLS listener; measured, neither validates it.
- The SBOM workflow attaches the SBOMs to a draft release, then publishes it; an immutable release refuses them afterwards.

### Added

- `check_container_psql_reads_sql_from_stdin`: no script hands a host file to a psql that runs in a container.
- 3 conformance cases (184 in all): a third party's field of the wrong type is refused, not a crash.
- 3 conformance cases (187 in all): a hex field with a character that is not hex, or a space, is refused.
- `vectors/anchors/ml-dsa-65-issuer.json`, the sample issuer's key, to try `polaris-verify` from PyPI without a clone.
- `TRADEMARKS.md`: the license covers the files, not the Polaris, owl, Khaklin Technologies or OpenID Certified marks.
- Discussions forms for questions, needs and interop results; `.github/SUPPORT.md` says where each kind of message goes.
- Coverage-guided fuzzing (atheris) of `polaris-oid4vp`'s hostile-input functions, on each change to the package and nightly.
- Code scanning: CodeQL (security-extended) over the Python, TypeScript, Rust and workflows, zizmor over the workflows, and OpenSSF Scorecard.
- `lab/strategy/006/try.sh`: from a clone, one command to a credential that PyPI's polaris-verify verifies under a key minted on the machine.
- A workflow runs `try.sh` from clean images nightly and on main; the README's Run it section names it.
- Each release carries its SBOMs' provenance bundle, so `gh attestation verify --bundle` checks them without GitHub's attestation store.

### Changed

- Polaris describes itself as pre-pilot, not a reference implementation, in MISSION.md and on every outward surface (owner's direction).
- CONTRIBUTING.md says how pull requests are handled and credited and names all six required checks; the PR template no longer asks for a version bump.
- NOTICE and the macOS launcher drop the course reference; the privacy page names no vendor.
- The three Python packages link their documentation, changelog, issues and source for PyPI.
- The site, README, citation and package summaries name the project Polaris ID, as its repository does (owner's direction).
- The review packet's drill table names the CI run behind each number, restated from the 2026-09-30 runs.
- Published: `polaris-verify` and `polaris-sdk-python` 1.0.0rc4 and `polaris-oid4vp` 1.0.0rc8 (not certified; 1.0.0rc7 is) on PyPI, `polaris-sdk-ts` 1.0.0-rc.4, then 1.0.0-rc.5 with the TypeScript format fix, on npm under `next`.
- Published: `polaris-oid4vp` 1.0.0rc9 on PyPI, with the review fixes above (not certified; 1.0.0rc7 is).
- Published: `polaris-verify` and `polaris-sdk-python` 1.0.0rc5 and `polaris-oid4vp` 1.0.0rc10 (not certified; 1.0.0rc7 is) on PyPI.
- The stranger's one-minute script runs without Docker, on the wallet's own binary checked against a pinned SHA-256.

## v1.0.0-rc.66 — 2026-09-28 (a Polaris credential in a wallet Polaris did not write)

OpenID4VCI issuance of wallet copies, received by walt.id and Credo; one security fix and three fixes.

### Security

- **Breaking**: `polaris-verify` and both SDKs refuse an unsigned trust edge past its `valid_until` or with an unreadable one.
- Until fixed packages are published, pass `require_signed_attestation=True`; [SECURITY.md](SECURITY.md) lists what each version lacks.

### Fixed

- **Breaking**: a wrong method on `/api/*` is a JSON `405` with its `Allow` header, not the HTML page.
- `polaris-oid4vp` refuses a disclosure name or `vct` that is not a string, instead of raising `TypeError`.
- `polaris-oid4vp` refuses a response JWE with a non-string `enc` or over 64 levels of nesting, instead of raising.

### Added

- OpenID4VCI 1.0 issuance of SD-JWT VC wallet copies of an ACTIVE credential; classical ES256, not ML-DSA-65 ([API](docs/reference/API.md#openid4vci-issuance-wallet-copies), [design](docs/design/oid4vci-issuer.md)).
- `CredentialCopy` record (migrations 2026-09-28-001, -002): the database copies only ACTIVE credentials and computes each status list.
- Per-agency ES256 wallet-copy keys (`POLARIS_CREDENTIAL_COPY_KEYS_DIR`), checked at load and every use; refused under the HSM-sole-signer profile.
- `polaris-oid4vp serve --issuer-trust-anchor PEM` trusts issuers that sign with an `x5c` certificate, as HAIP issuers do.
- 26 conformance cases (181 in all) for checks a verifier could skip; a case may set `require_signed_attestation`.

## v1.0.0-rc.65 — 2026-09-27 (verifiers refuse what they were never asked to accept)

Four fixes to promises the verifiers already made.

### Fixed

- **Breaking**: framework errors on `/api/*` (failure, unknown path, oversized body, rate limit) are JSON, not the HTML page.
- **Breaking**: both SDKs refuse a signed trust edge past its `valid_until` or with an unreadable one.
- **Breaking**: every verifier rejects a cross-authority decision with no presented context.
- **Breaking**: `polaris-oid4vp` refuses a `vp_token` not keyed by the DCQL query id it asked for.

## v1.0.0-rc.64 — 2026-09-27 (a credential's signature cannot be borrowed from any other artifact)

Two verifier fixes and conformance cases for exchanges.

### Security

- **Breaking**: issuance, the database and every verifier require `token_value` to be a credential serial, so no other signed artifact passes as one.

### Fixed

- `polaris-verify`: an exchange receipt that states no context no longer matches an attestation from any context.

### Added

- `exchange-use` conformance cases; both SDKs gain `verify_exchange_request`, `verify_exchange_receipt` and `verify_exchange_mint`.
- `polaris-verify`: `verify_exchange_request` takes `now`, as `verify_exchange_receipt` does.

## v1.0.0-rc.63 — 2026-09-27 (the pooler keeps each operator's scope; the application role writes less)

Security fixes from attacking the deployment as a compromised application.

### Security

- **Breaking**: the pooler runs in session mode only; in transaction mode a request could inherit another operator's scope.
- **Breaking**: `quota-set`, `discretion-set`, `user-{create,passwd,deactivate}`, `key-{register,retire,compromise}`, `rp-register` and `rp-policy` run as the schema owner.
- The application role can no longer write vouchings, proofing records, quotas, revocation bounds, operator accounts, authority keys, card personalizations, retention policies or relying parties.
- A referee's level derives from their proofing, co-signers must be proofed, and the database bounds vouching.

### Fixed

- `polaris-verify` no longer reports a grant signed under a revoked holder binding as bound.
- `polaris-id --help` examples for `revoke` and `quota-show` parse.

### Added

- `agent-grant-use` conformance cases; both SDKs gain `agent_proof_proves` and `grant_principal_bound`.

### Changed

- The trigger refusal and constitution mutation drills run on every push, the application mutation drill weekly.

## v1.0.0-rc.62 — 2026-09-26 (fifty-nine fixes, one release)

rc.4 to rc.62 were cut per fix and released together; from here a version moves only when a release is cut.

### Security

- (rc.62) The application role can no longer write `schema_version`, so it cannot mark a pending migration as applied.
- (rc.61) The application role can no longer rewrite the constitution rows the `/athena` console shows.
- (rc.59) The application role can no longer write `VerificationContext`, so it cannot lower a published proof policy.
- (rc.58) The application role can no longer revive a deprecated algorithm or grant an authority rights to one.
- (rc.57) An authority's signing key can change only to a key registered, and not retired or compromised, in `AuthorityKeyEvent`.
- (rc.56) A plain UPDATE of `IdentityToken` can change only `status`, not holder, expiry, value, issuer or duress code.
- (rc.55) The application role can no longer update or delete token permissions, device bindings or revocation-list entries.
- (rc.54) The application role can no longer record all three recovery channels itself or re-open an issued bulk batch.
- (rc.53) The application role can no longer create credentials, permissions, revocations, device bindings or recoveries outside their procedures.
- (rc.52) The application role can no longer fabricate duress events, archive checkpoints or erasure records.
- (rc.51) Anchor batches and anchors are written only by `close_anchor_batch`; the application role cannot move or rewrite them.
- (rc.50) Federation trust edges are recorded and revoked only through the admin-gated `uc10` procedures.
- (rc.49) Epochs are written only by `uc11_close_epoch`, so a direct insert cannot bypass the anonymity floor.
- (rc.46) An epoch below the minimum anonymity set (twenty by default) is refused, and CI fails on a skipped security test.
- (rc.44) Binding, moving or unbinding an operator's authority now ends their live session (`agency_changed`).
- (rc.43) Token routes refuse (403) a bound operator acting on a credential that row-level security hides from them.
- (rc.42) Seven rule-enforcing routines run as the owner, so recovery and revocation rules also hold for bound operators.
- (rc.41) Every view is `security_invoker`, so a bound operator sees no more through a view than through its tables.
- (rc.40) The application role holds only SELECT on audit-table partitions and can no longer append lifecycle events.
- (rc.39) The application role can no longer set a person's enrollment status by inserting `EnrollmentStatusEvent` rows.
- (rc.38) Change-record tables accept only rows from their recording triggers, with `db_role` set to the real session user.
- (rc.35) A zero-knowledge epoch commits only credentials that stay unexpired through the epoch's `valid_until`.
- (rc.33) `/uc8/revoke` and `/uc4/activate-reserve` check the token's issuer, not only the actor the request names.
- (rc.32) `/tokens/<id>/transition` checks the operator's binding against the token's issuer even when no actor is given.
- (rc.31) Agency edit, agency delete and token delete refuse an admin bound to another authority.
- (rc.30) Recovery decisions, device binding and algorithm migration refuse an account bound to another authority.
- (rc.24) An expired credential can no longer sign in, authorize holder signing or bind a holder key, and is attested `EXPIRED`.
- (rc.19) Only the revocation procedures can move a token to `REVOKED`, and a session cannot loosen the default revocation bound.
- (rc.18) `/sql` refuses (403) an account bound to one authority, because a query could clear its own scope.
- (rc.16) Five admin-gated procedures, including `uc_archive_purge`, now refuse a deactivated admin.
- (rc.15) Nine routes refuse (403) an operator bound to one authority acting as another.
- (rc.10) `polaris-secrets.sh unseal` refuses a store whose manifest names a path outside its destination.
- (rc.7) `polaris-oid4vp` status-list parsing bounds size, nesting depth and non-finite constants instead of raising `RecursionError`.

### Fixed

- (rc.60) Recovery channels can be recorded through the product again: new procedure, `POST /uc9/record-channel/<id>` and CLI command.
- (rc.48) The application, CLI and simulator open every database session in UTC whatever `PGTZ` says.
- (rc.47) Expiry and validity decisions in SQL use the UTC date (`polaris_utc_date()`) whatever the session timezone.
- (rc.45) `polaris retention-set` and the Atlas simulation tick now work when connected as the application role.
- (rc.37) Reporting a credential lost no longer activates a reserve past its expiration date.
- (rc.36) A device can no longer be bound to an expired credential.
- (rc.34) The per-minute rates in `/api/metrics` describe the present, not the last minute in which an event occurred.
- (rc.29) On an app host outside UTC, expired zero-knowledge epochs are refused and Atlas time windows cover their stated span.
- (rc.28) The database timezone is set to UTC, so attestation validity is judged on the UTC date.
- (rc.27) Credential expiry follows the UTC date on servers whose local timezone is not UTC.
- (rc.26) A federation attestation and its signature commit together; a failed signing records nothing.
- (rc.25) Card personalization refuses a credential past its expiration date.
- (rc.23) `/verifications/new` refuses a `SUCCESS` against an expired credential that still reads `ACTIVE`.
- (rc.22) `/verifications/new` refuses to record a `SUCCESS` against a credential that is not `ACTIVE`.
- (rc.21) Population algorithm migration re-signs and deprecates `RESERVE` credentials as well as `ACTIVE` ones.
- (rc.20) A pilot wind-down revokes the pilot's `RESERVE` credentials and counts them in the co-signer check.
- (rc.17) Visually inspected documents cap at `FAIR` evidence and physical-feature checks at `STRONG`, following NIST SP 800-63A.
- (rc.14) Three 32-bit id sequences that would run out inside the 25-year capacity horizon are widened to `BIGSERIAL`.
- (rc.13) A role change ends the operator's live session instead of raising a server error.
- (rc.12) A scoped pilot wind-down no longer pseudonymizes a person another authority still serves.
- (rc.11) Atlas `/clusters` and `/hexbin` answer 400 to a NaN or infinite `grid` or `size`.
- (rc.9) `polaris migrate-population` names the credentials it cannot re-sign instead of stopping silently.
- (rc.8) The signed status assertion reports an expired credential as `EXPIRED` and never outlives the credential.
- (rc.6) The `polaris-oid4vp` `Verifier` class now accepts `status_resolver` and passes it to verification.

### Added

- Mutation drills now delete each refusal inside trigger functions and weaken each row-level security policy; sixteen refusals and two policies that no test noticed are now covered.
- (rc.5) `polaris-oid4vp` can check a Token Status List through an opt-in `status_resolver`, reporting `unreachable` apart from `not_evaluated`.
- (rc.4) `polaris-oid4vp` verdicts carry a `revocation` field: `no_status_claim`, `not_evaluated` or `unsupported_status`.

## v1.0.0-rc.3 — 2026-09-17 (issuer trust and current-key status reported separately)

### Changed

- `polaris-verify` with no `--issuer-anchor` abstains with exit 2; `--signature-only` asks for signature validity alone.
- The `polaris-verify` verdict gains `trust_evaluated`, so abstained, trusted and untrusted runs differ in JSON and exit code.
- `issuer_authentic` in `/verify` and the relying-party API is replaced by `issuer_authorized_at_signing` and `issuer_key_current`.

### Security

- The signing instant is read from the append-only `ISSUED` lifecycle event, not the editable `IdentityToken.issued_date`.
- Not defended: `AuthorityKeyEvent.effective_at` is operator-supplied, so an authority writing its own key history can backdate it.

## v1.0.0-rc.2 — 2026-09-17 (defects found in rc.1)

### Security

- `polaris-oid4vp`: fifteen defects fixed, including accepting expired credentials, a NaN key-binding `iat`, and four denial-of-service paths.
- `polaris-verify`: sixteen defects fixed, including trust attestations that never expired and an ignored agent-grant algorithm.
- The two reference SDKs: thirteen defects fixed, including a cached bearer token that outlived the client's standing.
- Application: expired credentials stayed usable, a bound operator could make another authority sign, and eleven authentication refusals were missing.

### Changed

- NaN and Infinity are refused at one JSON provider, and a non-object JSON body no longer raises.
- `SECURITY.md` tells anyone who installed rc.1 from a registry which checks their copy lacks.
- The Flask application joined the mutation drills; 31 of its 37 refusals had survived being switched off.

## v1.0.0-rc.1 — 2026-09-15 (version scheme moves from ship counts to 1.0.0-rc.1)

### Changed

- The tree moves from 9.467 to 1.0.0-rc.1 and the four packages from 0.1.0 to 1.0.0-rc.1; PyPI classifier Beta.
- Installing the candidate needs `pip install --pre`; the npm SDK is published under the `next` tag.
- The 295 v9 tags and 294 GitHub releases were removed; [docs/history/RELEASES-v9.md](docs/history/RELEASES-v9.md) maps each to its commit.
- Document version stamps must equal the tree version exactly; the README was rewritten and its test counts re-measured.

### Fixed

- `check_roadmap_consistent` fails when it cannot parse the version, instead of skipping the comparison.
- Reloading sample data resets `RelyingPartyEvent`, so a new relying party no longer inherits an old party's history.

## v9.467 — 2026-09-15 (application-log privacy promise enforced)

### Added

- `check_logs_exclude_pii` fails if a logging call names a request body, cookie, credential or holder attribute.
- The same check fails if `docs/operator/PRIVACY.md` stops stating that promise; a repository audit found no committed secrets.

## v9.466 — 2026-09-15 (four packages published)

### Added

- Published at 0.1.0: `polaris-verify`, `polaris-oid4vp` and `polaris-sdk-python` on PyPI, `polaris-sdk-ts` on npm.
- [docs/STRANGER-PATH.md](docs/STRANGER-PATH.md) reaches an accepted external-wallet presentation from a clean machine without cloning.
- The OpenID Foundation hosted suite (`oid4vp-1final-verifier-haip-test-plan`) ran: 7 PASSED, 4 REVIEW, no failures; not a certification.

### Security

- PyPI publishing uses trusted publishing over OIDC; the single npm token was revoked within the hour.

## v9.465 — 2026-09-15 (first presentation from an unmodified external wallet)

### Added

- An unmodified walt.id Wallet API v2 presented an SD-JWT VC to `polaris-oid4vp` over OpenID4VP 1.0 and was accepted.
- Negative controls: a different trusted issuer key and a replayed `state` are both refused.
- Scope: one wallet, one credential format, one presentation path, ES256; no general interoperability claim.

### Fixed

- `polaris-oid4vp keygen` gives the request-signing certificate the `digitalSignature` key usage the wallet required.

## v9.464 — 2026-09-14 (concurrency design record corrected)

### Changed

- `docs/design/concurrency.md` corrects three passages and records which of the six locks the suite can observe.

## v9.463 — 2026-09-14 (redundant row locks measured and documented)

### Changed

- Comments beside two `FOR UPDATE` clauses record that each, or its advisory lock, suffices, and dropping both fails the suite.
- No behaviour changed.

## v9.462 — 2026-09-14 (concurrent attest and revoke tested)

### Added

- A test drives `uc10_revoke_attestation` against `uc10_attest_trust` and fails if the lock key uses the wrong agency column.
- `check_advisory_locks_have_a_contention_test` requires every procedure that takes a lock to be exercised.

## v9.461 — 2026-09-14 (local test runner collects the whole file)

### Fixed

- `scripts/polaris-test.sh app` ran 566 of 704 tests locally because the runner block sat mid-file; CI was unaffected.

### Added

- `check_test_runners_are_last_in_their_file` holds the runner block at the end of four test files.

## v9.460 — 2026-09-14 (lock-serialization tests exercise the procedures' own locks)

### Fixed

- Two serialization tests took the advisory lock themselves; `assertContends` now proves four procedures take their own lock.

### Changed

- The locks in `uc9_complete_recovery` and `close_anchor_batch` are declared unobservable from outside, with reasons.
- `check_advisory_locks_have_a_contention_test` refuses tests that take the lock by hand.

## v9.459 — 2026-09-14 (concurrency tests measure lock contention, not elapsed time)

### Fixed

- Five parallelism tests passed with lock keys that ignored their entity; they now use `lock_timeout` and assert each effect.

### Added

- `check_advisory_locks_have_a_contention_test` requires a contention test for every parameterised advisory-lock domain.

### Changed

- The `_assertRanInParallel` timing helper is removed.

## v9.458 — 2026-09-13 (Apache-2.0 license kept and pinned)

### Changed

- The license stays Apache-2.0 for its patent grant; `NOTICE` names psycopg2's LGPL 3 terms.
- `NOTICE` now describes the project as a reference implementation on notional data and is covered by the wording checks.

### Added

- `check_license_is_pinned` holds every package manifest, `LICENSE`, `NOTICE` and the README to one license identifier.

## v9.457 — 2026-09-13 (CI job installs the Node dependencies its drill runs)

### Fixed

- The `pqc-real` CI job sets up Node 24 and installs the TypeScript SDK before the SDK mutation drill.

### Added

- `check_ci_jobs_install_what_they_run` fails a job that reaches the TypeScript suite without installing it.

## v9.456 — 2026-09-13 (TypeScript SDK refusals mutation-tested)

### Fixed

- Nine of fourteen refusals in the TypeScript SDK could be inverted unnoticed, including `sameBytes`'s length guard; six tests close them.

### Changed

- The SDK mutation drill covers both SDKs (32 refusals, 4 declared survivors) with a per-SDK negative control.
- An unusable timing measurement is reported as such, and `polaris-ship.py triage` recognises it.

## v9.455 — 2026-09-13 (Python SDK refusals mutation-tested)

### Fixed

- All eighteen refusals in the Python reference verifier could be inverted with tests green; eighteen tests close them.

### Changed

- The drill inverts `return False` to `return True` rather than deleting it, and a check refuses a deleting drill.

## v9.454 — 2026-09-13 (quantum wording rule applied to the system as a whole)

### Changed

- `check_post_quantum_claims_are_agility` refuses quantum-safety wording applied to the system, engine or platform; naming algorithms stays permitted.

### Fixed

- `site/index.html` no longer opens with a quantum-safety claim about the system.

## v9.453 — 2026-09-12 (citations to a removed document replaced)

### Fixed

- 46 references in 24 files to a removed document, including one operator-facing error message, now state the rule directly.
- `01_schema.sql` no longer counts a removed table among the audit-of-record tables.

### Added

- `check_no_citations_to_deleted_apparatus` refuses new citations to the removed document.

### Changed

- `SECURITY.md` describes the development placeholder signer; `CONTRIBUTING.md` says `polaris-test.sh` runs four of CI's eighteen suites.
- The headline on every surface says the system is signed with ML-DSA-65 under an audited algorithm-migration path.
