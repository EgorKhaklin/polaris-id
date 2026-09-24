# SECURITY-DECISIONS.md: where each security decision is actually made

**Reader:** a security engineer or assessor who needs to find one decision without reading
nine thousand lines of application code. **Job:** name the file, the symbol and the line for
every security decision this system makes, say which one is authoritative when a decision is
split across layers, and name the invariant check that pins each.

This exists because `polaris_web/app.py` is large, and an outside review reasonably asked
whether a reviewer could locate anything in it. Decomposing it is not the immediate answer:
70 of the 276 invariant checks read that file's source text by path, so moving code would
leave them passing over a file the code had left. `check_no_vacuous_checks` now holds the
line that no check may report OK over a tree that contains nothing, and this document is the
other half: the map, so that finding a decision does not require finding the code first.

Line numbers drift. The **symbols** are the durable part, and every one of them is named here
so a `grep` finds it after any move.

**Before moving any of this code**, run `python3 scripts/polaris-check-inventory.py --path
<file>`. It lists every invariant check bound to that path and says which of them DISCOVER a
set of targets rather than asserting a substring. Measured on 2026-09-17: 70 checks read
`polaris_web/app.py`, 81 read the continuous-integration workflow, 44 read the schema. A check
that keeps reading a path the code has left does not fail; it passes over an empty set.

---

## The short answer

| Question | Authoritative answer |
|---|---|
| May this authority issue at all? | `uc1_issue_and_activate`, `polaris_sql/05_procedures.sql` |
| Is this credential bound to the authority that issued it? | `uc1_issue` key refusal, `polaris_web/app.py` |
| May this operator act as this authority? | `_operator_authority_permits`, `polaris_web/app.py` |
| What may this operator READ? | Row-level security policies, `polaris_sql/01_schema.sql` |
| Has this credential expired? | `_not_expired`, `polaris_web/app.py` |
| Is this credential revoked? | `trg_enforce_revocation_velocity` records it; the verification routes decide it |
| Is this signature genuine? | `verify_pack`, `packages/polaris-verify/.../verifier.py` |
| Is this credential authoritative right now? | `api_token_verify` and `api_v1_verify`, both primary-pinned |
| Is this zero-knowledge proof sound? | `verify` in `polaris_zk/src/lib.rs`, plus the second witness |
| Has this been replayed? | The nonce and nullifier ledgers below |
| Is this trust edge still open? | `_attestation_window_open`, `packages/polaris-verify/.../verifier.py` |
| Which key signs this? | `get_custody_for_agency`, `polaris_web/custody.py` |
| May this admin do this? | `require_role` plus the WebAuthn branch in the login flow |

---

## 1. Credential issuance authorization

**Authoritative: `uc1_issue_and_activate` in `polaris_sql/05_procedures.sql`.** It reads
`AgencyAlgorithmAuth.authorization_type` for the (agency, algorithm) pair and raises
`insufficient_privilege` unless it is `ISSUE` or `BOTH`. A caller cannot go around it. It
also refuses issuance under an algorithm whose `deprecation_date` has passed.

Above it, `uc1_issue` in `polaris_web/app.py` carries `@login_required`,
`@require_role('admin', 'operator')` and `@csrf_protect`: that decides who may reach the
form. Below it, `enforce_agency_quota` (`trg_quota_issue`, `polaris_sql/06_triggers.sql`)
bounds the rate, surfacing as HTTP 429.

The authorization-level filter in the agency picker query is a **user-interface filter, not a
gate**. The procedure is the gate.

Pinned by `check_procedure_refusals_are_mutation_tested`, `check_abuse_controls`.

## 2. Authority and issuer binding

Four separate mechanisms, and confusing them is how the operator-scope defect of
2026-09-17 happened.

**The credential to its issuing key.** `get_custody_for_agency` picks the agency's own key;
`uc1_issue` then **refuses** if the key that actually signed differs from the agency's
registered `signing_public_key_hex`. That refusal is what stops one installation signing as
an authority whose key it does not hold.

**The operator to their authority.** `authenticate` in `polaris_web/security.py` returns
`agency_id`; `login_user` puts it in the session; `_apply_operator_scope` binds it into the
`polaris.operator_agency_id` setting on **both** the primary and the replica connection, and
closes the connection rather than serving unscoped if that fails.

- **Reads** are bounded by the row-level security policies in `polaris_sql/01_schema.sql`:
  `token_authority_isolation`, `verification_authority_isolation`,
  `lifecycle_authority_isolation`. Authoritative for what an operator can see.
- **Acting as** is bounded by `_operator_authority_permits` in `polaris_web/app.py`.
  Authoritative, and separate, because signing is not a row and no policy can refuse it.

`_operator_authority_permits` guards the two routes that make an authority act:
`/api/v1/sign/<agency_id>` and `/api/v1/exchange-receipt/<agency_id>`. Other
agency-scoped routes are either read paths, where the policies bound them, or
possession-authenticated holder routes that carry no operator session at all.

`issuer_authentic`, reported by both verification endpoints, compares the signature's key to
the agency's registered key. It is **reported and not enforced**: it does not flip `usable`.

Pinned by `check_per_authority_isolation`, which also pins that the drill runs as a
non-superuser, because row-level security is bypassed by the owner and the check would
otherwise pass vacuously.

## 3. Credential expiry

**`_not_expired` in `polaris_web/app.py`** is the single predicate. Both verification
endpoints use it and the operator dashboard counts with the same rule, so the operator answer
and the relying-party answer cannot drift.

A credential is valid **through** its expiry date. A NULL expiry never expires. A value the
predicate cannot read counts as expired, the same rule the wallet and detached verifiers took
the same day and for the same reason: an unreadable lifetime is not an open-ended one.

Until 2026-09-17 nothing on any verification path compared this column. It is written at
issuance, `ACTIVE -> EXPIRED` is a legal transition, and the dashboard counted active
credentials past their expiry, but nothing drove the transition and no sweeper existed. Both
endpoints answered `currently_authoritative: true` for every one of them. It is enforced at
read time rather than by a background job on purpose: a sweeper that stops running silently
restores the defect, and a predicate cannot stop running.

The schema will not let an already-expired credential be issued: `chk_token_time_order`
requires the expiry to be no earlier than the issue date, so that state is reachable only by
the passage of time.

Artifact windows are elsewhere and each is its own check: `_window_within` and
`_verify_window` in the detached verifier, `exp`/`nbf` in the wallet verifier's
`verify_presentation`, `_within_window` and `_within_replay_window` in the Python software
development kit, `withinWindow` and `isoToEpoch` in the TypeScript one.

## 4. Revocation

**Recorded** by `uc8_revoke_token` under an advisory lock, bounded by a velocity policy.
**No revocation may bypass it**: `enforce_revocation_velocity_bound` refuses a direct status
update that did not set the procedure's own marker. That trigger is authoritative.

**Enforced** in three places for three audiences. Online, both verification routes read the
status from the primary. Offline, `verify_cross_authority` in the detached verifier is
fail-closed: a feed that is not authentic, fresh and bound to the issuer key rejects, and a
hit in the feed rejects. When no feed is supplied it reports `revocation_checked: false`
rather than silently accepting. Published, `api_v1_revocation_feed` serves an append-only,
therefore monotone, feed.

A fourth layer is easy to miss: `_public_artifact` derives `Cache-Control: max-age` from the
artifact's own signed `expires_at`, and refuses to cache an artifact whose expiry it cannot
read. A constant max-age is how a revoked credential keeps verifying.

## 5. Zero-knowledge proof verification

**In-circuit binding: `verify` in `polaris_zk/src/lib.rs`.** It checks the public-input
vector's length first (a short vector would have panicked the process, which is reachable
without a credential), then the epoch root, then epoch, context, nonce and scope, then the
nullifier, and runs the cryptographic verification **last**. Every binding check precedes it,
so no ordering lets an unbound proof through.

**Against the database:** `verify_proof_against_epoch` in `polaris_web/zk.py`, fed by
`_zk_verify_and_consume`, which loads the epoch's committed root and enforces the epoch's own
validity window.

**The independent second witness:** `check_claim` in `polaris_zk/witness2/verifier.py`
recomputes the root, re-derives the leaf and re-derives the nullifier itself. A witness that
did none of those would be agreeing with the prover by construction, which
`check_zk_two_witness_present` now requires it not to be.

**A separate second witness** covers signatures: `verify_both` in `polaris_web/pqc_signing.py`
runs two independent implementations and a missing witness at issuance is a refusal, not a
downgrade. A sampled fraction of the single-witness fast path is replayed through both and
pages on disagreement.

## 6. Token verification: the two questions

**Authenticity** is whether the signature is genuine over immutable material. That read is
replica-eligible, because a lagging replica cannot make a genuine signature look forged.

**Authorization** is whether the credential is usable now. That read is **pinned to the
primary**, because a replica's lag window could report a just-revoked credential as active.

Both live in `api_token_verify` in `polaris_web/app.py`, and the response publishes `as_of`
and `max_staleness_seconds` so a relying party cannot mistake one question for the other.
`api_v1_verify` is the relying-party face of the same pair, behind a bearer token, a per-party
rate limit and a possession proof, and it answers with a uniform non-verifiable verdict so it
is never an existence oracle.

## 7. Replay and nullifier protection

| Mechanism | Where | Arbiter |
|---|---|---|
| Zero-knowledge nonce | `_zk_verify_and_consume`, `app.py` | `ZkVerificationNonce` primary key; consumed only after a true verify, so a failed proof never burns a nonce |
| Scoped nullifier | `polaris_zk/src/lib.rs` | Derived from the same secret the leaf opens, so it names a person rather than some number |
| Exchange nonce | `_consume_exchange_nonce`, `app.py` | `ExchangeNonce` primary key; consumed **after** authorization, so an unauthorized caller cannot burn one |
| Authorization code | the broker's token exchange, `app.py` | `AuthCodeConsumed` insert, plus a proof-key check and a short time-to-live |
| Wallet session | `polaris_oid4vp/verifier.py` | One answer per session, popped under a lock; the decryption key is never chosen from the unauthenticated state parameter |
| Key-binding nonce | `polaris_oid4vp/sdjwt.py` | Equality against the session's nonce, plus a bounded, finite `iat` |
| Holder-proof window | all three verifiers | 300 seconds with 60 seconds of skew, the same in each |
| WebAuthn challenge | the assertion routes, `app.py` | Popped from the session before use: one shot |

The nonce tables are append-only by trigger, so a consumed nonce cannot be deleted to permit
a replay.

## 8. Trust-edge validity

**Recorded** by `uc10_attest_trust`, which checks the signer is an admin, requires a future
`valid_until`, and is bounded by four CHECK constraints (no self-attestation, a validity
floor, a revocation reason of real length, and all-or-nothing signature fields) plus a partial
unique index allowing one live edge per attesting, attested and context triple.

**Accepted** offline by `verify_attestation` and `_attestation_window_open` in the detached
verifier. An edge whose own window has closed is refused however fresh the manifest carrying
it, and an unreadable window counts as closed. A present-but-invalid signature is refused
outright, which is stricter than an absent one.

Trust is **directional and non-transitive**: `_exchange_attestation` accepts only the
responder's own attestation, so an edge drawn by another authority on the same installation
authorizes nothing.

## 9. Reads that must come from the primary

Routing lives in `query(..., primary=...)` and the `replica_reads` decorator in
`polaris_web/app.py`, with a lag bound and a failback.

The rule, stated once: **anything that decides authorization now, or becomes input to a
signature, reads the primary.** That covers the status read in both verification endpoints,
the relying party's record and rate limit, holder-key bindings, epoch state, and every row
that is about to be signed into a status assertion, a mobile document, a verifiable
credential, a registry, a trust list or a transparency head.

`_apply_operator_scope` runs on both the primary and the replica connection, so pinning a
read to the primary never widens an operator's authority scope.

Pinned by `check_read_replica_routing`.

## 10. Audit events

**Written by the application:** `_audit` and `record_audit_access` in
`polaris_web/security.py`. Both fail open by design: an audit write must not deny a
legitimate action. `record_audit_access` is the audit's audit, and it must never be called
from a route that reads the access log itself; the regress stops there by construction.

**Written by the database**, which is the stronger guarantee: `audit_token_state_change`,
`record_relying_party_change`, `record_agency_change` and `record_app_user_change` in
`polaris_sql/06_triggers.sql`. The operator's identity and reason arrive as settings on the
same transaction, so the record and the change commit together or not at all.

`record_app_user_change` is an AFTER trigger deliberately: an upsert fires BEFORE triggers
speculatively, so a BEFORE recorder would write a creation row for an account that already
existed, and would not be rolled back.

All audit-of-record tables refuse UPDATE and DELETE through `reject_audit_modification`.

## 11. Database invariants a reviewer must know

**Unique indexes.** One active credential per person. One live trust edge per triple. One
effective quota, discretion policy and retention policy, because enforcement reads a single
row and two un-superseded rows would make the bound depend on insertion order.

**Triggers.** The credential state machine. No revocation may bypass its procedure. Every
credential keeps at least one non-deprecated signature. Signature bytes, attestations and
epochs are immutable once written. Widening an operator account, or moving it between
authorities, requires a stated justification of real length.

**CHECK constraints.** The role vocabulary. The temporal ordering that makes an
already-expired credential unissuable. The four attestation constraints.

**Row-level security** for per-authority read isolation.

## 12. Which key signs

**Authoritative: `get_custody_for_agency` in `polaris_web/custody.py`.** A per-agency key
file if one exists, otherwise the installation key, which may be a file, a hardware module or
a cloud key service. A present-but-malformed key file fails loudly; an absent one falls back
deliberately and silently.

`signature_with_key_for_token` in `polaris_web/pqc_signing.py` decides real cryptography
versus the development placeholder. With the real-cryptography flag set and the library
absent it **raises** rather than downgrading, a missing second witness **raises**, and it
verifies its own output before returning. The algorithm is a signed field, chosen from the key
before the statement is canonicalised.

During an algorithm migration both parameter sets are live and an unavailable algorithm is a
refusal, never a fallback.

## 13. Administrative authorization

`require_role` in `polaris_web/security.py` decides it, denies with an audit row, and marks
the handler so the guard set is **readable off the route table** rather than maintained by
hand. A hand-written matrix had drifted to ten of twenty-seven before that was introduced.

The second factor is decided by `webauthn_status_for_user` in `polaris_web/webauthn_auth.py`
and enforced in the login flow: overdue blocks, a registered credential redirects to the
assertion, and only the not-required and grace states complete a login. The deadline itself is
guarded by the database, since pushing it out or clearing it counts as widening an account and
needs a justification.

Both ways of creating an admin give the same grace period, and
`check_admin_mfa_deadline` fails the build if they disagree. They did, and an admin created
through the command-line tool previously never had a second factor demanded at all.

**Which authority an operator may act as** is decided by `_operator_authority_permits` in
`polaris_web/app.py`: an operator bound to an authority acts only as that authority, and an
unbound operator is unaffected. Every route that takes the acting authority from the request
calls it (issuance, reserve activation, revocation, recovery, verification, the duress API, a
token transition, both federation routes, the operator exchange receipt and document signing).
`check_operator_acts_only_as_its_authority` fails a route that reads `issuing_agency_id`,
`actor_agency_id`, `requesting_agency_id` or `attesting_agency_id` without it. Before 1.0.0-rc.15
only the last two called it.

**Whether a deactivated admin may still act** is refused in the database, by every admin-gated
procedure: `uc9_complete_recovery`, `uc_pseudonymize_individual`, `uc10_attest_trust`,
`uc10_revoke_attestation`, `uc11_close_epoch`, `uc_apply_retention_template` and
`uc_archive_purge` each check `AppUser.is_active` after the role. Before 1.0.0-rc.16 the last five
checked the role alone, which the CLI and the operator scripts, passing a user id straight in,
could reach.

---

## 14. Decisions not yet made

Behaviour found on 2026-09-24 that the code does consistently and no document settles. Each is a
policy question for the maintainer rather than a defect, so none was changed. Recorded here so it
is decided rather than inherited.

- **Who may revoke.** `uc8_revoke_token` accepts any actor authority for any credential: it bounds
  the revocation rate of the ISSUING authority and requires a co-signer above the bound, but under
  the bound one authority can revoke another's credentials alone. Its own comment says the bound
  applies to the issuer, "not necessarily the actor".
- **What the revocation bound is a share of.** Every credential the authority has ever issued, of
  any status, so the base does not shrink as credentials are revoked. Against live credentials
  the share is larger (see `docs/design/issuer-discretion.md`). A live-credential base is the
  stricter bound.
- **Erasing a person who still holds a live credential.** `scripts/polaris-pseudonymize-individual.sh`
  pseudonymizes whoever it is given. The pilot wind-down refuses to leave a live credential with a
  holder nobody can name (1.0.0-rc.12); general erasure does not.
- **The sunset's newcomer question.** `polaris_web/coexistence.py` requires
  `legacy_still_issued_to_newcomers` and reports it, but no answer blocks a sunset.

---

## What this document does not do

It does not replace reading the code before changing it, and it is not a substitute for the
checks. It is a map. Where it and the code disagree, the code is what runs and the
disagreement is a defect in this file: say so in the commit that fixes it, as
`docs/CONVENTIONS.md` requires of every other document here.
