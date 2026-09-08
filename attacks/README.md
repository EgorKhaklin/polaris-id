# attacks/ — adversaries that must fail

Every file here is an **attack**: it actively tries to break a real Polaris
security property against the **real code**, not a mock. An attack *succeeds* when
the defense *fails* to stop it. The rule is simple:

> Run every release. If any attack succeeds, the build goes red.

This is the opposite of a check that greps for a string. A grep proves a line
exists; an attack proves the defense *holds* when something hostile is thrown at
it. The two suites run in CI on every push (`polaris-verify.py`'s witnesses in the
`pqc-real` job for the crypto suite, the app + Postgres in the `test` job for the
db suite), and `check_attacks_run` keeps them wired.

## Run them

```bash
python3 attacks/run_attacks.py --suite crypto   # needs liboqs (real ML-DSA-65)
python3 attacks/run_attacks.py --suite db        # needs the app + Postgres
python3 attacks/run_attacks.py                   # both
```

Exit `0` = every attack failed to break its defense (good). Exit `1` = an attack
**succeeded** (a defense is broken). Exit `3` = a suite you asked for could not run,
or an attack crashed — a hard error, never a silent green, so a `0` always means the
defenses actually held.

## The adversaries

**crypto** (`attack_crypto.py`, real ML-DSA-65 — attacks the detached verifier's
`verify_pack` and the app's two-witness `verify_stored_signature`):

| attack | what it throws | the defense that must hold |
|---|---|---|
| `forge_with_attacker_key` | a token signed with an attacker key, presented against the issuer's anchor | not-issuer: `issuer_trusted` is False even though the signature is internally valid |
| `tamper_signature` | a genuine signature with one byte flipped | the ML-DSA-65 verify rejects it |
| `alter_token` | a genuine signature against a different `token_value` | the digest no longer matches; rejected |
| `wrong_key` | a genuine signature against an unrelated public key | rejected |
| `placeholder_relabeled_as_real` | the dev SHA3 placeholder relabeled `ML-DSA-65` | a SHA3 binding is never accepted as a signature |
| `empty_signature` | an empty signature | rejected |
| `outsider_accepted_by_federation_set` | an issuer outside the federation, presented to a party trusting a 2-issuer set | the outsider's key is not in the set; `issuer_trusted` is False (the cross-issuer boundary, PE.3) |
| `witnesses_disagree_under_fuzz` | many random rounds (genuine, tampered, wrong-key, garbage) verified under liboqs and cryptography **separately** | the two witnesses return the same verdict every time — verify-at-use trusts one witness only because the two never disagree; a divergence is the break |
| `app_two_witness_verify_rejects_tamper` | a tampered signature into the app's own `verify_stored_signature(both)` | both witnesses reject it |

**db** (`attack_db.py`, the app + Postgres — attacks the verify-at-use route):

| attack | what it throws | the defense that must hold |
|---|---|---|
| `revoked_token_treated_as_authoritative` | a real signed token, revoked through the real `uc8` procedure, then presented to `/verify` | the authenticity/authorization split: the signature stays authentic, but `currently_authoritative` and `usable` are False (the replay defense) |

**controls** (`attack_controls.py`, the app + Postgres — NIST 800-53 AC + AU as
attacks, not a control-mapping document):

| attack | control | the defense that must hold |
|---|---|---|
| `ac3_unauthenticated_reaches_protected_data` | AC-3 | an unauthenticated request to login-gated data is redirected/denied, not served |
| `ac3_operator_reaches_admin_auditor_route` | AC-3 | a logged-in operator gets 403 on an admin/auditor-only route (authenticated ≠ authorized) |
| `au9_audit_row_delete_allowed` | AU-9 | an audit-of-record row (`TokenLifecycleEvent`) cannot be DELETEd — the append-only trigger refuses (attempt rolled back) |
| `au9_audit_row_update_allowed` | AU-9 | the same row cannot be UPDATEd |
| `ac7_failed_logins_do_not_lock` | AC-7 | five failed logins lock the account (the failure counter enforces; reset afterward) |

## Adding an attack

Add an `attack_*` function to the right module returning `(succeeded, note)` where
`succeeded=True` means the defense was broken, and list it in that module's
`ATTACKS`. Prefer attacks that would have *caught a real regression*: a forgery a
weaker verify would accept, an authorization a stale read would grant. Keep them
fast and hermetic (the crypto suite generates its own keys; the db suite reloads
sample data through the test harness).
