# NIST SP 800-63 mapping: IAL, AAL, FAL

**Reader:** an assessor asking what an assurance claim rests on, or an engineer asked to close
a gap. **Job:** map what Polaris actually does onto the three assurance dimensions, cite the
artifact behind every row, and name every gap rather than rounding it away.

**Status, before anything else.** Polaris is a reference implementation running on notional
data. **This is not a conformance claim and no assessment has been performed.** A control
marked MET here means the mechanism exists in this tree and something in CI proves it still
does; it does not mean an assessor has agreed, and it does not mean a deployment inherits it.
The rows below are the evidence an assessment would start from, not its result.

**Every citation is machine-checked.**
[`scripts/polaris-assurance-mapping-drill.py`](../../scripts/polaris-assurance-mapping-drill.py)
parses this file, resolves every `check:`, `test:`, `drill:` and `schema:` citation against the
tree, and fails if one does not exist or does not pass. A row cannot claim evidence that is not
there. That is the difference between this file and a compliance spreadsheet: **when the
evidence disappears, CI goes red rather than the document going quietly stale.**

---

## Reading a row

| Verdict | Meaning |
|---|---|
| `MET` | The mechanism exists and the cited artifact proves it in CI. |
| `PARTIAL` | Some of the requirement is mechanised; what is missing is named in the row. |
| `GAP` | Not built. The reason is stated and it is counted in the totals below. |
| `WAIVED` | Deliberately out of scope, with the reason. Not a silent omission. |
| `EXTERNAL` | Depends on something an authority or a certifier provides, not on this tree. |

Citations resolve as: `check:NAME` a `polaris_checks` check that must pass; `test:PATH::CLASS` a
test class that must exist; `drill:PATH` a script CI runs; `schema:NAME` a constraint, trigger
or index that must be in `polaris_sql/`.

---

## IAL, identity assurance

What was established about the person at enrollment. The mechanism is
[identity-proofing.md](../design/identity-proofing.md).

| Requirement | Verdict | Evidence |
|---|---|---|
| Evidence is classified by strength | MET | `check:enrollment_proofing` |
| Evidence is validated (is the document genuine) and verified (is it this person's), and a piece failing either contributes nothing | MET | `drill:scripts/polaris-enrollment-proofing-drill.py` |
| The assurance level is derived from the evidence, never entered | MET | `check:enrollment_proofing` |
| A claimed level above what the evidence supports is refused | MET | `drill:scripts/polaris-enrollment-proofing-drill.py` |
| IAL2 evidence combinations | MET | `drill:scripts/polaris-enrollment-proofing-drill.py` |
| IAL3 requires in-person or supervised-remote and a live biometric | MET | `schema:ial3_needs_session_and_biometric` |
| A biometric that failed liveness does not raise the level | MET | `check:enrollment_proofing` |
| The proofing record is append-only | MET | `schema:trg_enrollment_proofing_append_only` |
| Minimisation: the record cannot reconstruct the applicant's documents | MET | `check:enrollment_proofing` |
| Address confirmation to a validated address | GAP | Not built. Polaris records no address at all, deliberately, so the notice-to-address step 800-63A describes has nowhere to send to. An authority that requires it performs it outside this tree and records the resulting evidence strength. |
| Trusted referee and enrollment-code flows for applicants who cannot present evidence themselves | GAP | `ENROLLMENT_CODE` exists as a verification method; the surrounding process, its supervision and its own evidence rules are not built. This is the accessibility half of proofing and its absence excludes exactly the people most likely to need it. |
| The kiosk itself: a locked-down browser, supervision, physical siting | GAP | Roadmap P4.4, still open. The record and the derivation shipped; the station did not. |
| Fraud, duplicate-enrollment and identity-resolution checks | PARTIAL | C3's one-active-credential-per-person partial unique index (`check:one_active_token_index`) prevents a duplicate active credential; it does not detect one person enrolling as two identities, which is a different problem needing data this tree does not hold. |

## AAL, authenticator assurance

What the holder or operator presents to authenticate, and how hard it is to steal or replay.

### The holder's credential

| Requirement | Verdict | Evidence |
|---|---|---|
| Multi-factor: something you have plus something you know | MET | `check:card_emulator` |
| The authenticator is a hardware cryptographic device whose key is generated on it and never exported | MET | `check:card_personalization` |
| Verifier-bound: a response is usable only by the verifier it was made for | MET | `check:verifier_device` |
| Replay-resistant against a different verifier | MET | `drill:scripts/polaris-card-emulator-drill.py` |
| Replay-resistant against the SAME verifier | MET | `check:verifier_device` |
| Throttled: a limited number of failed attempts, surviving a power cycle | MET | `drill:scripts/polaris-card-emulator-drill.py` |
| The authenticator is never an oracle: it signs nothing before authentication and refuses a challenge too short to be one | MET | `check:card_emulator` |
| FIPS 140 validation of the authenticator, which AAL3 requires | EXTERNAL | Roadmap P6.1 and P4.6. A validated module and certified silicon are bought, not written. Until then, **no AAL3 claim is made for the holder's credential**, whatever its design. |
| Biometric as a second factor at authentication time | GAP | The card's PIN is the knowledge factor. On-card biometric comparison needs silicon with a sensor and a template on it, which is P4.6 and is the one place a template would have to exist. |
| Reauthentication at a bounded session interval | MET | `check:session_origin_hardening` |

**Highest holder AAL claimed: AAL2**, and only for a deployment whose card meets the validation
requirement above. The design anticipates AAL3; the claim waits on certification.

### The operator's console

| Requirement | Verdict | Evidence |
|---|---|---|
| Multi-factor with a phishing-resistant second factor (WebAuthn) | MET | `test:polaris_web/test_app.py::WebAuthnCeremonyTests` |
| Hardware-only authenticators enforceable by policy | MET | `test:polaris_web/test_app.py::WebAuthnCredentialLookupTests` |
| Failed-attempt throttling that cannot be raced | MET | `check:c4_atomic_failed_login` |
| Rate limiting on the authentication endpoint | MET | `test:polaris_web/test_app.py::F03_RateLimitingTests` |
| Passwords stored one-way | MET | `test:polaris_web/test_app.py::PasswordHashingTests` |
| Session binding, idle and absolute timeouts, a server-side registry | MET | `check:session_origin_hardening` |
| Per-role network policy | MET | `test:polaris_web/test_app.py::NetworkPolicyTests` |

## FAL, federation assurance

What is passed between an identity provider and a relying party, and what a relying party can
check for itself.

| Requirement | Verdict | Evidence |
|---|---|---|
| The assertion is signed by the issuing authority | MET | `check:auth_broker` |
| The assertion is bound to a single relying party and audience | MET | `test:polaris_web/test_app.py::AuthBrokerTests` |
| The assertion has a bounded lifetime and a verifier-set ceiling on it | MET | `check:offline_verification` |
| An assertion cannot be replayed: single-use codes are consumed | MET | `check:auth_broker` |
| A relying party verifies the assertion offline, with no call back to the issuer | MET | `drill:scripts/polaris-offline-status-drill.py` |
| Pairwise subject identifiers, so two relying parties cannot correlate a holder | MET | `check:pairwise_presentation` |
| The trust list is signed and its key lifecycle is explicit | MET | `check:trust_lifecycle` |
| Federation is explicitly non-transitive | MET | `check:federation_topology` |
| Assertion encrypted to the relying party, which FAL2 requires | GAP | Assertions are signed and not encrypted. They are fetched over TLS to a registered client and carry no personal data by construction, so the confidentiality FAL2 asks of the assertion is provided by the channel rather than by the assertion. That is a different property and the row says so rather than claiming FAL2. |
| Holder-of-key assertions, which FAL3 requires | PARTIAL | The ZK presentation path (`check:scoped_nullifier`) is holder-of-key in substance: the holder proves possession of a secret, and the verifier learns a scoped nullifier rather than a bearer token. It is not an 800-63C assertion format, so the mechanism is present and the conformance is not claimed. |

**Highest FAL claimed: FAL1**, with the FAL2 confidentiality property provided by the channel
rather than the assertion, and a holder-of-key mechanism that is not in 800-63C's assertion
format.

---

## What this mapping deliberately does not do

- **It does not claim conformance.** Every "MET" is a statement about this tree, checked in CI.
  An assessment is performed by an assessor against a deployment.
- **It does not inherit.** A deployment gets these properties only if it deploys the mechanisms
  and operates them; the controls that depend on an authority's process (proofing sessions,
  referee flows, key ceremonies) are theirs.
- **It does not round a gap into a partial.** **Six** rows above are GAP or EXTERNAL. They are
  counted by the drill and printed, so the number cannot drift without the count changing.

## Proven by

`scripts/polaris-assurance-mapping-drill.py` on every push: every citation in this file is
resolved against the tree, every cited check is run, every GAP and WAIVED row is required to
carry a reason, and the totals are recomputed rather than read from here.
`check_assurance_mapping` pins the file's shape and the honesty of its front matter.
