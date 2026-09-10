# Threat model

**Reader:** an engineer or an assessor. **Job:** The adversaries, the surfaces they reach, and what is out of scope.

<!-- coherence:taxonomy-allowed, STRIDE is a standard taxonomy (S, T, R, I, D, E) + scope + deferred + coverage + how-to-use; consolidating S+T+R+I+D+E would invert the entire frame -->

STRIDE-categorized threat model for Polaris. Every threat is mapped
to a control or explicitly listed as ACCEPTED / DEFERRED with
rationale.

The STRIDE acronym (Microsoft, ~1999) covers the six classes of
threats relevant to a multi-tenant system:

- **S**poofing identity
- **T**ampering with data
- **R**epudiation
- **I**nformation disclosure
- **D**enial of service
- **E**levation of privilege

For each, threats are listed with a short identifier (T-XX), the
attack scenario, the affected component, and the control(s) that
address it.

## S: Spoofing

### T-S1: forged signing key issues fake tokens

**Scenario:** an attacker obtains an issuing agency's private key and
signs new `IdentityToken` rows that the rest of the system trusts.

**Affected:** `IdentityToken.token_value`, `Agency.agency_id`,
`CryptographicAlgorithm.key_size`

**Controls:**
- Algorithm metadata flows through `CryptographicAlgorithm` table
  (constraint C7), so a forged token's algorithm parameters are
  auditable
- Rate limit on issuance route (`security.py::rate_limiter`) caps how
  many tokens an attacker with stolen creds can mint per minute
- Append-only `TokenLifecycleEvent` (constraint C1) means the
  forgery is permanently recorded; subsequent investigation can
  enumerate every token issued under the compromised key

**Residual risk:** ACCEPTED. Key compromise is out of scope for
software controls: addressed by HSM / key-rotation procedures
documented in `docs/operator/SECURITY-CONTROLS.md`.

### T-S2: session fixation

**Scenario:** attacker plants a session ID, victim logs in to the
attacker's session, attacker hijacks.

**Affected:** Flask session cookie, `security.py::login`

**Controls:**
- `session.regenerate()` (or equivalent) called on successful login;
  test: `F01_AuthenticationTests.test_login_session_fixation_resistance`
- Session cookie attributes: `HttpOnly`, `Secure`, `SameSite=Lax`
- Session timeout: configurable (default 30 minutes idle)

**Residual risk:** LOW.

### T-S3: stolen session cookie

**Scenario:** XSS or network sniffing yields a valid session cookie.

**Affected:** Flask session cookie

**Controls:**
- CSP `script-src 'self'` (constraint C5) blocks XSS injection vectors
- HTTPS-only via `Secure` cookie attribute (production)
- `SameSite=Lax` defends against CSRF-driven leakage

**Residual risk:** LOW under HTTPS; HIGH under HTTP. Document
deployment must use TLS.

### T-S4: stolen admin password (phishing, breach disclosure, malware exfil)

**Scenario:** the admin's password is captured via phishing site,
breach disclosure of a re-used password from another service, or
malware on the admin's workstation.

**Affected:** AppUser.password_hash + Flask session

**Impact:** admin role can issue + revoke any token (UC-1 / UC-8),
trigger `uc_archive_purge`, which deletes from the hot audit tables under the
archive carve-out, create new operator accounts, and read every individual's
enrollment-status history. The highest-impact attack surface in the
system.

**Controls:**
- After the 30-day enrollment deadline, admin login REQUIRES a
  verified WebAuthn assertion in addition to a correct password
  (defense-in-depth: the password is the first factor, WebAuthn is
  the second)
- WebAuthn is **phishing-resistant by design**: assertions are bound
  to `POLARIS_DOMAIN` via the origin check inside the
  authenticator. A credential issued for `polaris.example.com` will
  not assert on `polar1s.example.com`: the look-alike domain that
  steals a password cannot replay the assertion.
- Public-key cryptography: the private key never leaves the
  authenticator. A breach disclosure of `password_hash` is
  insufficient to log in (no second factor).
- AuthAuditLog records every `WEBAUTHN_REGISTERED`,
  `WEBAUTHN_ASSERTED`, `WEBAUTHN_ASSERTION_FAILED`,
  `WEBAUTHN_DEREGISTERED`, and `EMERGENCY_PASSWORD_LOGIN_AUTHORIZED`
  event for forensic reconstruction.
- Recovery flow: a locked-out admin (lost authenticator)
  is recovered via `scripts/polaris-recover-admin.sh` (a second admin
  opens a short emergency-login window, audited as
  `EMERGENCY_PASSWORD_LOGIN_AUTHORIZED`) OR via a printed recovery
  code from `scripts/polaris-generate-recovery-code.sh` for
  solo-admin deployments.

**Residual risk:** LOW after the WebAuthn-MFA enrollment deadline
passes (T-S4 is mitigated by structural defense-in-depth). MEDIUM
during the 30-day grace period (password-only login still works
for un-enrolled admins). The emergency-login window is itself
audited and time-bounded (default 15 min).

---

## T: Tampering

### T-T1: direct DB write bypasses lifecycle invariants

**Scenario:** a DBA with write privileges on the public schema
manually `UPDATE`s `IdentityToken.status` from REVOKED back to ACTIVE.

**Affected:** `IdentityToken.status`, `TokenLifecycleEvent`

**Controls:**
- `audit_token_state_change` trigger on `IdentityToken` writes a
  `TokenLifecycleEvent` row for EVERY status change, including
  manual ones
- `TokenLifecycleEvent` is append-only (constraint C1): the manual
  unrevoke is permanently recorded
- Partial unique index `uq_one_active_per_person` (constraint C3)
  may catch the manual unrevoke if another ACTIVE token exists
- Production grants restrict DML on these tables to the
  `polaris_app` role; DBA access requires a separate audit trail

**Residual risk:** MEDIUM. A motivated DBA can falsify the
`reason_code` in the audit row but cannot delete the audit row
itself.

### T-T2: replay of a captured verification request

**Scenario:** attacker captures a signed verification request and
replays it later to gain access.

**Affected:** `VerificationEvent`, `verifications_new` route

**Controls:**
- Each `VerificationEvent` has a unique `event_id` (PK) and timestamp
- Application checks `event_timestamp` for staleness (configurable
  window)
- Server-side context binding: an event recorded for HEALTHCARE
  cannot be replayed against BANKING (constraint architecture)

**Residual risk:** LOW within freshness window. **DEFERRED:** explicit
nonce table for cross-context replay protection: currently relies on
context-side enforcement.

### T-T3: tampering with `predecessor_token_id` to disconnect succession

**Scenario:** attacker sets `predecessor_token_id = NULL` on a token
that should reference its predecessor, breaking the audit chain.

**Affected:** `IdentityToken.predecessor_token_id`

**Controls:**
- FK constraint requires the referenced token to exist
- Backlog item: constraint that `predecessor_token_id` must reference
  a token with the same `individual_id` (BACKLOG.md schema section)
- Audit trail in `TokenLifecycleEvent` records the reason_code
  (`SUCCESSION`, `LOST_REPLACEMENT`, etc.)

**Residual risk:** LOW. The cross-individual-link constraint is a
backlog item; current implementation relies on app-layer checks.

---

## R: Repudiation

### R-R1: agency denies issuing a token they actually issued

**Scenario:** an issuing agency claims a problematic token was a
forgery, when in fact they issued it.

**Affected:** `Agency.agency_id`, `IdentityToken.issuing_agency_id`

**Controls:**
- Append-only `TokenLifecycleEvent` (constraint C1) records the
  issuance with timestamp, agency, and any reason_code
- Cryptographic signature over the token-value with the agency's key
  proves issuance
- `AuthAuditLog` records every authenticated action by an agency's
  operators

**Residual risk:** LOW. The append-only audit + cryptographic
signature combination makes repudiation costly.

### R-R2: holder denies a verification event happened

**Scenario:** a holder claims they never authorized a particular
verification.

**Affected:** `VerificationEvent`

**Controls:**
- Append-only `VerificationEvent` (constraint C1) records the event
  immutably
- For `FULL` disclosure events, the holder is logged by name; for
  `SELECTIVE`, by attribute set; for `ZERO_KNOWLEDGE`, the system
  records the verification but cannot identify the holder (this is
  intentional: privacy by design)

**Residual risk:** ZK events ARE inherently repudiable for the
holder. This is the privacy/repudiability tradeoff that
`ZERO_KNOWLEDGE` exists to provide. Documented as INTENDED.

---

## I: Information Disclosure

### I-I1: unauthorized read of holder PII

**Scenario:** an unauthenticated user navigates to `/individuals/123`
and reads PII.

**Affected:** routes that render `Individual` data

**Controls:**
- `@security.login_required` on every PII route
- Role-based access: `auditor` role cannot mutate, `operator` role
  cannot delete, `admin` role full access

**Residual risk:** LOW.

### I-I2: ZK verification event leaks holder identity via timing

**Scenario:** an attacker correlates ZK event timestamps with other
data sources to deanonymize.

**Affected:** `VerificationEvent` with disclosure='ZERO_KNOWLEDGE'

**Controls:**
- ZK events have `token_id IS NULL` (constraint C2): no direct link
- Event timestamps are recorded but not co-mingled with holder
  identifiers in the ZK event row

**Residual risk:** ACCEPTED. A sufficiently-resourced attacker with
multiple data sources may deanonymize via traffic analysis. The
single-system architecture cannot fully prevent this; it limits the
ZK event itself to "valid token verified at time T" without further
specifics.

### I-I3: error messages leak schema or query detail

**Scenario:** a malformed input produces a Postgres error that the
app surfaces verbatim, leaking column names or query structure.

**Affected:** `app.py::query()`, all routes

**Controls:**
- `db_error_to_message()` in `security.py` translates psycopg2
  errors to user-friendly messages
- Test: `F08_ErrorMessageSanitizationTests`

**Residual risk:** LOW. Tests verify the sanitization layer.

### I-I4: log files accumulate sensitive data

**Scenario:** Flask logs full POST bodies including holder PII.

**Affected:** `gunicorn.conf.py`, application logs

**Controls:**
- gunicorn access log format excludes POST body
- `AuthAuditLog` records authentication metadata only (username,
  outcome, IP), never password attempts
- docs/operator/DEPLOYMENT.md backlog item: log retention policy + S3 archive

**Residual risk:** MEDIUM. **DEFERRED** to docs/operator/OPERATIONS.md (BACKLOG).

---

## D: Denial of Service

### D-D1: unbounded API result set OOMs server or browser

**Scenario:** attacker calls `/api/atlas/clusters?bbox=-90,-180,90,180&grid=0.1`
forcing 6.5M cluster bins.

**Affected:** `/api/atlas/*`, browser memory

**Controls:**
- Hard caps: `_ATLAS_MAX_CLUSTERS=5000`, `_ATLAS_MAX_POINTS=2000`,
  `_ATLAS_MAX_EVENTS=500` (constraint C8)
- Test: `AtlasAPITests.test_points_endpoint_caps_at_max`
- Server-side aggregation collapses millions of events into hundreds
  of cluster summaries

**Residual risk:** LOW.

### D-D2: brute-force authentication attempts

**Scenario:** attacker spams login attempts to lock legitimate users
out, or to crack a weak password.

**Affected:** `security.py::authenticate`

**Controls:**
- Rate limiter caps login attempts per IP per minute
- Account lockout after N failed attempts (atomic via constraint C4)
- Test: `F03_RateLimitingTests`,
  `ConcurrencyTests.test_failed_login_count_is_atomic_under_concurrent_load`

**Residual risk:** low. The limiter's Redis backend shares one bucket across
workers and hosts, and the production configuration selects it; the
per-process backend remains only for single-worker development, where its
counters are correct.

### D-D3: write-amplification via append-only triggers

**Scenario:** attacker hammers `verifications_new` causing 1M
`VerificationEvent` rows / hour.

**Affected:** `VerificationEvent` table size, audit log volume

**Controls:**
- Per-route rate limit (60/min for state-changing operations)
- Atlas scaling architecture (v6) handles 2M+ rows; not a DoS at this scale
- Backlog: storage tier policy / archival

**Residual risk:** LOW for now; revisit at 100M+ events.

### D-D4: connection-pool exhaustion

**Scenario:** attacker opens many concurrent slow requests, exhausting
the gunicorn worker pool.

**Affected:** gunicorn process

**Controls:**
- gunicorn worker timeout (default 30s)
- Per-IP rate limit
- Backlog: pgbouncer connection pooling for DB-side bottleneck

**Residual risk:** MEDIUM at internet-exposed deployment;
**DEFERRED** to docs/operator/OPERATIONS.md.

---

## E: Elevation of Privilege

### E-E1: SQL injection bypasses role enforcement

**Scenario:** attacker injects SQL through a route parameter,
escalating from `auditor` role to `admin` capability.

**Affected:** any route that takes user input → SQL

**Controls:**
- `query()` helper uses parameterized queries (psycopg2 % placeholders)
- ORM-style construction; no string concatenation into SQL
- Test class: `F08_ErrorMessageSanitizationTests` covers injection
  attempt sanitization

**Residual risk:** LOW.

### E-E2: CSRF causes authenticated user to perform privileged action

**Scenario:** attacker tricks a logged-in admin into clicking a link
that triggers `tokens_delete`.

**Affected:** state-changing routes

**Controls:**
- `@security.csrf_protect` on every state-changing route
- CSRF token tied to session
- `SameSite=Lax` cookie attribute as defense in depth

**Residual risk:** LOW.

### E-E3: privilege confusion via concurrent role change

**Scenario:** an admin's role is downgraded mid-session; their
existing session retains admin privileges until logout.

**Affected:** `AppUser.role`, session cache

**Controls:**
- Role check happens server-side on every request, against current
  `AppUser.role`, NOT against a session-cached role
- Test: implicit in role-based access control tests

**Residual risk:** LOW.

### E-E4: trigger function runs with elevated SECURITY DEFINER privileges

**Scenario:** a trigger function defined with `SECURITY DEFINER`
gets called in an attacker-controlled context, executing with the
function-owner's privileges.

**Affected:** trigger functions in `06_triggers.sql`

**Controls:**
- Triggers in Polaris are `SECURITY INVOKER` by default; no
  `SECURITY DEFINER` functions exist
- If `SECURITY DEFINER` is ever needed, it MUST be reviewed against
  this threat

**Residual risk:** LOW.

---

## P: the physical card

Added with the card profile (roadmap P4.1,
[card-profile.md](card-profile.md)). Until v0 of that profile the schema
modelled a card nobody had specified, so these threats had nowhere to attach.
They are numbered separately because the adversary here is standing in front of
the holder, not connected to anything.

### T-P1: a card is read in a pocket

**Scenario:** an attacker with a reader gets close enough to power the card and
take a response, without the holder's knowledge or consent.

**Affected:** the card's presentation path

**Controls:**
- The card carries a `credential_ref` (`SHA3-256("polaris-card-ref/1" || token_value)`),
  never the token value. A read yields nothing the relying-party API accepts.
- Key mode emits a pairwise handle scoped to the reader, so a rogue reader's
  captures cannot be correlated with any other reader's.
- The response signs the reader's challenge, so it cannot be replayed elsewhere.
- The token value, name, date of birth and biometric templates are refused BY
  NAME by the encoder, so none of them is on the card to read.

**Residual risk:** MEDIUM. A rogue reader still learns that *a* Polaris card was
present and gets a handle stable for its own scope, so it can recognise a
returning holder. Presence and return-visit linkage at one reader are inherent
to a contactless credential and are not claimed to be prevented.

### T-P2: a lost card is presented by a finder, offline

**Scenario:** a card is lost and found; the finder presents it to a verifier
with no connectivity, before the loss has propagated.

**Affected:** offline verification of a superseded card

**Controls:**
- `activation_sequence` and `predecessor_ref` let a verifier that has current
  status tell a superseded card from a current one.
- The signed status assertion's freshness window bounds how long a stale
  verifier can be fooled ([status-distribution.md](status-distribution.md)).
- The card's own `expires_at` bounds the worst case absolutely.

**Residual risk:** ACCEPTED, and stated in the profile. A card cannot prove
offline that it is the current one, because activation is an event rather than a
date. The window is exactly the freshness window the verifier chose. Putting a
validity date on the reserve card instead would fix in advance a moment the
holder cannot predict, and would leave a window where neither card verified.

### T-P3: the classical algorithm falls while the fleet is still classical

**Scenario:** P-256 is broken. Every fielded card's classical signature can be
forged, and the fleet cannot be replaced overnight.

**Affected:** every card issued before post-quantum silicon was available

**Controls:**
- The card carries two issuer signatures over the same body, and **when both are
  present both must verify**: a valid classical signature does not rescue a
  forged post-quantum one, or the reverse. Accept-if-either would hand the whole
  scheme to whoever broke the weaker algorithm first.
- `require_pq` is a verifier POLICY rather than a format version, so an
  authority flips its verifiers to post-quantum-only without reissuing the
  population first, and one population holds both while the fleet turns over.
- The database-side population migration is the same event handled at the record
  layer ([QUANTUM-EVENT.md](../operator/QUANTUM-EVENT.md)).

**Residual risk:** MEDIUM, and it is silicon, not software. A classical-only
card cannot be made post-quantum by re-signing the database record: the private
key is in the element. Those cards must be replaced, and the profile's job is to
make sure verifiers can refuse them by policy on a chosen date rather than
discovering them one at a time.

### T-P4: a coercer learns that a duress code exists

**Scenario:** an attacker compels the holder to present, and tries to determine
from the card, the reader, or the response whether a duress PIN was used or even
enrolled.

**Affected:** the anti-coercion property, which is the vocation above C1-C10

**Controls:**
- The card object carries only the normal slot's public key. Carrying both would
  make the existence of a duress key readable off the card.
- Both PINs unlock, with the same response shape, the same timing, the same
  retry counter and the same unblock procedure.
- The duress signal is raised by the authority, which holds both public keys, on
  the online path only ([duress-codes.md](duress-codes.md)).
- The drill asserts that a duress response is the same shape as a normal one and
  that the duress key appears nowhere in the object.

**Residual risk:** ACCEPTED, and stated in the profile. **An offline verifier
cannot raise a duress alarm**, because there is nobody to raise it to. The card
must therefore behave identically offline under either PIN and must not, for
instance, decline to respond: a card that behaved differently offline would tell
the coercer which PIN was entered, which is worse than having no duress feature.

### T-P5: a forged card object with a well-formed encoding

**Scenario:** an attacker constructs a card object, or edits a genuine one, so a
reader accepts it.

**Affected:** the card object encoding

**Controls:**
- Deterministic TLV: tags appear at most once and in ascending order, so one
  object has exactly one encoding and a signature cannot be moved onto content
  it did not authorise.
- An unknown tag is REFUSED rather than skipped; a reader that skipped what it
  did not recognise would verify a signature over bytes it never looked at.
- The signing body excludes the signature tags, so both signatures cover exactly
  the same bytes.
- The drill flips every field in turn, and a byte in the wire encoding, and the
  card must be refused each time.

**Residual risk:** LOW. This rests on the issuer's signing key, which is the
same assumption as T-S1.

---

## Out of scope

| Threat | Reason |
|---|---|
| Physical compromise of HSM holding signing keys | Out of software scope; docs/operator/SECURITY-CONTROLS.md addresses HSM lifecycle |
| Quantum cryptanalysis of currently-deployed RSA tokens | Polaris ships with PQ algorithms (ML-DSA primary); RSA tokens are migration-only |
| Social engineering against issuing agency staff | Out of software scope; agency policy concern |
| Side-channel attacks (timing, power analysis) on signing | Out of software scope; HSM concern |
| Supply chain attacks on dependencies | DEFERRED to docs/operator/OPERATIONS.md (backlog) |
| Invasive attack on a secure element (decapping, fault injection, power analysis) | Out of software scope; the certification level of the chosen part is the control, and which parts qualify is roadmap P4.6 |
| Coercion of the holder BEFORE presentation (a PIN taken under threat) | The duress path is the control and it is partial by construction: it signals, it does not prevent. See T-P4 |

---

## Deferred, and re-examined each pass

| Threat | Backlog item | Rationale |
|---|---|---|
| T-T2 cross-context replay | A single-use nonce store | Anti-replay currently rests on context-side enforcement and the freshness window; the nonce table would harden it |
| D-D4 connection-pool exhaustion | docs/operator/OPERATIONS.md | Production deployment concern |
| I-I4 sensitive data in logs | docs/operator/OPERATIONS.md retention policy | Operational, not architectural |

---

## Coverage check

For each MISSION.md hard constraint, this document enumerates at
least one threat where it serves as a control:

| Constraint | Threats it controls |
|---|---|
| C1 (append-only) | T-T1, R-R1, R-R2 |
| C2 (ZK→token_id NULL) | I-I2, R-R2 |
| C3 (one active per individual) | T-T1 |
| C4 (atomic increment) | D-D2 |
| C5 (CSP 'self') | T-S3, E-E1 partial |
| C6 (server-side disclosure) | I-I2, T-T2 |
| C7 (algorithm metadata) | T-S1 |
| C8 (atlas hard caps) | D-D1 |
| C9 (concurrency tests) | D-D2 (verified atomicity) |
| C10 (identity ≠ money) | architectural: would multiply blast radius of all above |

If a constraint were removed, the controls in the corresponding row
would be lost. This makes the relationship explicit for future
review.

---

## How to use this document

1. **When proposing a security-relevant change**, search this
   document for related threats. The change should either strengthen
   an existing control or add a new control for a previously-DEFERRED
   threat.

2. **When auditing**, walk the table. For each threat, find the test
   that exercises the control. If a test doesn't exist, that's a
   coverage gap.

3. **When new threat emerges** (e.g. a published CVE in a dependency,
   a novel attack pattern), add a row in the appropriate STRIDE
   section. Update the constraint coverage table if the new control
   creates a new dependency.

4. **When a DEFERRED threat is addressed**, move it from the deferred
   list into the main body and update the residual risk.
