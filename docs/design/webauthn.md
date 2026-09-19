# WebAuthn for operators

**Reader:** an engineer or an assessor. **Job:** Operator credential registration, how the second factor is enforced, and what the grace period buys.

Operator accounts are the compulsion surface that matters most: a coerced or
phished operator password reaches every use case. WebAuthn puts a hardware
factor in front of that, and does it on a deadline per account rather than a
switch thrown for everybody at once.

## The four states

Every `AppUser` row carries a nullable `webauthn_required_after` timestamp.
Login reads it and lands in one of four states:

| State | Condition | Behaviour |
|---|---|---|
| No second factor | `webauthn_required_after IS NULL` | The password is sufficient |
| Grace period | now is before the deadline | The password works, and the interface asks for enrolment |
| Second factor required | the deadline has passed and a credential is registered | Password and a WebAuthn assertion, both |
| Overdue | the deadline has passed and no credential is registered | Login is refused, with the recovery path named |

The deadline is what makes the rollout tractable: enrolment is asked for
before it is demanded, and the refusal at the end is unambiguous rather than a
silent lockout. `scripts/polaris-create-operator.sh` gives a new operator
thirty days; an existing operator has no deadline until
`scripts/polaris-set-webauthn-deadline.sh` sets one. Admin accounts are the
ones the policy targets: the second factor is required for admin, optional for
operator, and not asked of the read-only auditor role.

## Where it lives

| File | Role |
|---|---|
| `polaris_web/webauthn_auth.py` | The registration and assertion ceremonies, over the `webauthn` package (pinned in `requirements.txt`) |
| `polaris_web/auth_routes.py` | Seven routes: the four ceremony endpoints, the assertion page, the settings page, and credential deletion |
| `polaris_web/templates/webauthn_assert.html`, `webauthn_settings.html` | The two operator-facing pages |
| `polaris_web/static/webauthn-register.js`, `webauthn-assert.js` | The browser half, calling `navigator.credentials.create` and `.get` |
| `polaris_sql/migrations/2026-05-14-002-operator-webauthn` | `OperatorWebauthnCredential`, the `AppUser` deadline column, and five audit event types |

## What the policy can require

All of it is environment-driven and validated at boot by `validate_policy()`,
so a malformed policy fails the process rather than silently degrading:

- `POLARIS_WEBAUTHN_ATTESTATION` sets the conveyance asked of the browser:
  none, indirect, direct or enterprise.
- `POLARIS_WEBAUTHN_REQUIRE_ATTESTATION` refuses a registration whose
  attestation format is `none`.
- `POLARIS_WEBAUTHN_ALLOWED_AAGUIDS` restricts enrolment to named
  authenticator models.
- `POLARIS_WEBAUTHN_USER_VERIFICATION` set to `required` demands a PIN or
  biometric on both ceremonies, not just at registration.
- `POLARIS_WEBAUTHN_HARDWARE_ONLY` refuses platform authenticators.

The relying party offers ML-DSA-65 (COSE algorithm -49) first, so an
authenticator that implements it enrols a post-quantum credential; every other
one falls through to ES256, EdDSA or RS256. Replay is bounded by the signature
counter, which must exceed the stored value, with the documented exception of
authenticators that report zero throughout.

## Recovering a locked-out admin

There is no bypass, by design. The recovery path needs two people or a
pre-issued secret:

1. `scripts/polaris-recover-admin.sh` requires a second admin to act. The
   locked-out admin cannot recover themselves.
2. `scripts/polaris-generate-recovery-code.sh` issues a printed mnemonic at
   account creation, which is the second factor for the recovery ceremony
   itself.

A single-admin deployment whose only admin loses their authenticator and their
recovery code is unrecoverable without a restore from backup. That is the
intended trade: an operator-side bypass would be a coercion target, and the
whole point of the surface is that it has none.

## What is tested

- `WebAuthnTests` in `polaris_web/test_app.py` drives the ceremonies end to
  end, registration through assertion, and asserts the state machine above.
- `WebAuthnAdversarialTests` covers what an attacker tries: a forged
  assertion, registration without a session, and a ceremony finished without a
  pending challenge.
- `check_session_origin_hardening` pins the policy knobs, the boot-time
  validation and the ML-DSA-first offer, so a regression fails the build
  rather than a review.

## Boundaries

- It authenticates operators, not holders. Holders do not log in; they are
  identified by their `Individual` row and their token.
- It requires a CTAP2 or FIDO2 credential. Legacy U2F is not accepted.
- It cannot solve the loss of every admin credential at once. That is a
  procedural question for the deploying organisation, and it belongs in the
  same class as the custody decisions in the readiness ledger.
- Attestation is policy-checked against an allow-list of authenticator models,
  not against a metadata service. Enforcing FIDO Metadata Service
  certification would be a further hardening step, not a correction.
