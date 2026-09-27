# 004: the operator a four-eyes rule names is the operator who acted

**Opened 2026-09-27.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md).
State: OPEN, record only.

---

## The finding that started it

The readiness ledger (docs/PRODUCTION-READINESS.md, "Authorization and operators") says it
plainly: procedures enforcing rules about people take the actor as a user id parameter, because
every operator reaches the database through one application role, so a holder of that role can
name any operator and satisfy a four-eyes rule alone.

The rule that matters most is the recovery ceremony: `uc9_initiate_recovery(p_requesting_user)`,
`uc9_record_recovery_channel(p_recording_user)` and `uc9_complete_recovery(p_deciding_user)`,
where the decider must differ from the requester. Completing a recovery issues a new active
credential. Other procedures take an actor the same way (`uc_pseudonymize_individual`, the
retention and purge procedures), and `uc4`/`uc8` take the acting authority.

## 1. What capability is being considered?

Make the database, not the application, decide which operator is acting in the rules that
separate duties, starting with the recovery ceremony.

## 2. What problem would it solve?

A compromised application could no longer complete a recovery alone by naming two operators.

## 3. Who would plausibly need it?

Any issuer that relies on the recovery ceremony's separation of duties; any reviewer, for whom
"one compromised component cannot complete a recovery" is a checkable sentence.

## 4. What already solves it?

Three known shapes, each with a different limit:

- **A. A database login per operator.** The operator's session connects as that operator's role,
  and the procedures read `session_user` instead of a parameter. Limit: the application must hold
  or derive each operator's credential, so it can act as any operator who signs in while it is
  compromised (but not as one who does not).
- **B. Decisions signed by the operator's own authenticator.** Operators already enrol WebAuthn
  keys. The decision (recovery id, verdict) becomes the WebAuthn challenge; the signed assertion
  is stored with the decision and verified by a component other than the web application.
  Limit: the browser code that shows the operator what they are approving is served by the web
  application, so a compromised application can show one decision and ask for a signature over
  another; and the credential registration itself must be anchored outside the application.
- **C. Evidence without prevention.** Store the assertion with each decision (append-only) so an
  auditor can verify offline which authenticator approved it. Limit: it detects, it does not
  prevent; it is the smallest step and the ledger's current defence made checkable.

## 5. Can Polaris interoperate instead of rebuild?

WebAuthn is the standard and is already in the tree (`polaris_web/webauthn_auth.py`); nothing
here needs a new protocol.

## 6. What unique advantage could Polaris obtain?

Closing, or honestly bounding, the one named gap a reviewer reaches first in the operator model.

## 7. What happens if Polaris does NOT build it?

The ledger's sentence stays true, and the recovery ceremony's separation of duties holds only
while the application does.

## 8. What other work would be delayed?

Strategy 002 and 003 are closed; this is the next item on the owner's adopted backlog.

## 9. Can the idea be tested cheaply in LAB first?

1. As the application role on a scratch database, complete a recovery naming two operators, and
   record the result: the executable form of the ledger's sentence.
2. Prototype C in lab: store an assertion over the decision and verify it offline with the
   detached verifier's ES256 path; measure what an auditor can and cannot conclude.
3. Only then weigh A against B for prevention, with 1 as the test each must turn into a refusal.

## 10. What evidence would prove the bet wrong?

- **Prevention is not reachable without a second trusted component** the project does not have:
  if both A and B need something outside the web application that no documented deployment
  runs, record C as the ceiling and say so in the ledger rather than claim prevention.
- **The operators cannot use it.** If B needs an authenticator ceremony per recovery decision that
  makes the ceremony impractical (measured in the lab prototype), it is not worth shipping.
- **It moves the gap without shrinking it.** If A only changes WHICH operators a compromised
  application can impersonate while the recovery still completes, it is not a fix.
