------------------------------ MODULE StatusFreshness ------------------------------
(***************************************************************************
 The epoch/status protocol — how long a revoked credential can still be
 accepted, and by what.

 v9.375 (roadmap P6.7). Checked by scripts/polaris-tla-drill.py on every push.

 WHAT THE PROTOCOL IS. An authority mints a short-lived signed status
 assertion (P3.6) carrying a credential's status at the instant of minting and
 a window [issued_at, expires_at). A verifier with no connectivity accepts iff
 the signature verifies, the status is ACTIVE, and now falls inside that
 window, with the window itself no wider than a ceiling the VERIFIER sets.

 THE PROPERTY WORTH PROVING is not that a revoked credential is refused. An
 offline verifier holding an assertion minted before the revocation cannot
 know about it, and no protocol makes it know. The property is that its
 ignorance is BOUNDED:

     a verifier never accepts a credential more than one window after it was
     revoked

 That is the whole claim offline verification makes. It is not "revocation is
 immediate", which would be false, and pretending otherwise is how an operator
 chooses a window without understanding what they are choosing. The window IS
 the exposure, stated in the units the operator sets it in.

 WHAT THE MODEL SHOWS IT RESTS ON. Two things, and the counterpart
 configurations demonstrate each. The verifier must check the window against
 its OWN clock, and it must refuse an assertion whose window is wider than its
 ceiling. Drop the second and an authority can mint a year-long assertion that
 a verifier will honour for a year, which converts a bound the verifier
 believed it controlled into one the issuer controls. That is a subtle
 difference in a document and an unbounded one in practice.

 WHAT THIS DOES NOT MODEL: the signature, the transport, clock skew between
 the authority and the verifier (real and bounded by neither), or the
 revocation feed's own propagation. It models what an accepted assertion
 implies about staleness, given a verifier that checks what it is told to.

 MODELS: status-assertion IN polaris_web/app.py
 MODELS: verify_status_assertion IN packages/polaris-verify/polaris_verify_cli/verifier.py
 MODELS: max_window_seconds IN packages/polaris-verify/polaris_verify_cli/verifier.py
 ***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxTime,          \* bounded clock
    Window,           \* the width an authority mints assertions with
    VerifierCeiling,  \* the widest window this verifier will accept
    EnforceCeiling    \* TRUE when the verifier refuses an over-wide window

ASSUME
    /\ MaxTime \in Nat
    /\ Window \in Nat /\ Window > 0
    /\ VerifierCeiling \in Nat
    /\ EnforceCeiling \in BOOLEAN

VARIABLES
    now,            \* the verifier's clock
    revokedAt,      \* the instant the credential was revoked, or MaxTime + 1 for never
    held,           \* the assertion the verifier holds, as a set of at most one.
                    \* A set rather than a record-or-"none" union: TLA+ will not
                    \* compare a record with a string, so the obvious sentinel
                    \* makes TypeOK itself fail to evaluate.
    accepted        \* instants at which the verifier accepted

vars == << now, revokedAt, held, accepted >>

NEVER == MaxTime + 1

TypeOK ==
    /\ now \in 0..MaxTime
    /\ revokedAt \in 0..NEVER
    /\ held \subseteq [issued : 0..MaxTime, status : {"ACTIVE", "REVOKED"}]
    /\ Cardinality(held) <= 1
    /\ accepted \subseteq 0..MaxTime

Init ==
    /\ now = 0
    /\ revokedAt = NEVER
    /\ held = {}
    /\ accepted = {}

Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED << revokedAt, held, accepted >>

(***************************************************************************
 The authority revokes. Once, and it stays revoked.
 ***************************************************************************)
Revoke ==
    /\ revokedAt = NEVER
    /\ revokedAt' = now
    /\ UNCHANGED << now, held, accepted >>

(***************************************************************************
 The verifier obtains an assertion minted NOW, carrying the status as of now.
 An assertion minted before the revocation says ACTIVE, truthfully, and stays
 saying it: that is the staleness the window bounds.
 ***************************************************************************)
Fetch ==
    /\ held' = {[issued |-> now,
                 status |-> IF now < revokedAt THEN "ACTIVE" ELSE "REVOKED"]}
    /\ UNCHANGED << now, revokedAt, accepted >>

(***************************************************************************
 The verifier decides, offline. Inside the window, ACTIVE, and (when the
 ceiling is enforced) the window no wider than the ceiling.
 ***************************************************************************)
WindowAcceptable == IF EnforceCeiling THEN Window <= VerifierCeiling ELSE TRUE

Accept ==
    /\ \E a \in held :
        /\ a.status = "ACTIVE"
        /\ now >= a.issued
        /\ now < a.issued + Window
    /\ WindowAcceptable
    /\ accepted' = accepted \cup {now}
    /\ UNCHANGED << now, revokedAt, held >>

Next == Tick \/ Revoke \/ Fetch \/ Accept

Spec == Init /\ [][Next]_vars

(***************************************************************************
 THE PROPERTY. Every acceptance is either before the revocation or within one
 window of it. The verifier's ignorance is bounded by the number it chose.
 ***************************************************************************)
StalenessBoundedByWindow ==
    \A t \in accepted : revokedAt = NEVER \/ t < revokedAt + Window

(***************************************************************************
 The bound the VERIFIER believes it controls. With the ceiling enforced, no
 acceptance is ever staler than the ceiling, whatever width the authority
 chose to mint. Without it, the issuer sets the verifier's exposure.
 ***************************************************************************)
StalenessBoundedByCeiling ==
    \A t \in accepted : revokedAt = NEVER \/ t < revokedAt + VerifierCeiling

============================================================================
