---------------------- MODULE C2ZeroKnowledgeUnlinkability ----------------------
(***************************************************************************
 C2 — a zero-knowledge verification does not identify the holder.

 v9.375 (roadmap P6.7). Checked by scripts/polaris-tla-drill.py on every push.

 WHAT THE EASY VERSION WOULD BE. chk_disclosure_token_consistency requires
 token_id IS NULL on every ZERO_KNOWLEDGE VerificationEvent. Modelling that
 would prove a CHECK constraint holds, which it does by construction, and
 would say nothing about whether the holder is identifiable.

 THE PROPERTY WORTH PROVING is what an observer with EVERY recorded row can
 conclude. Polaris records two things per zero-knowledge verification: the
 event (no token_id) and a consumed nonce in ZkVerificationNonce, keyed by
 (epoch_id, context_id, nonce). The scoped nullifier (P9.3) is that nonce, and
 it is derived from the holder's own secret:

     nullifier = Poseidon(secret || scope || epoch_id)

 So the recorded value DOES vary with the holder. That is deliberate: it is how
 one relying party refuses a second claim from the same person. The question is
 whether it lets two relying parties compare notes.

 THREE PROPERTIES, and the tension between them is the whole design:

   NoEventNamesAHolder — no recorded verification event carries a holder, which
   is the C2 constraint itself.

   OneVerifierRecognisesARepeat — the same holder proving twice at the same
   verifier yields the SAME nullifier, so a relying party can refuse a second
   claim. Without this the mechanism does not work at all.

   NoTwoVerifiersCanLink — no nullifier recorded by one verifier appears in
   another's records, so two relying parties who pool everything they hold
   still cannot tell they saw the same person.

 The last two pull in opposite directions and both must hold. That is why the
 scope is inside the hash, and it is exactly what the counterpart configuration
 demonstrates: with ScopedNullifier = FALSE, modelling a nullifier derived from
 the holder and the epoch but NOT the scope, NoTwoVerifiersCanLink fails while
 OneVerifierRecognisesARepeat still passes. A slip that looks like a
 simplification silently converts the mechanism into a correlation key.

 WHAT THIS ASSUMES, and it is doing real work: that the hash is
 collision-resistant, modelled here as an injective function of its inputs. The
 spec proves the PROTOCOL uses that function in a way that gives per-verifier
 unlinkability. It proves nothing about Poseidon.

 MODELS: chk_disclosure_token_consistency IN polaris_sql/01_schema.sql
 MODELS: ZkVerificationNonce IN polaris_sql/01_schema.sql
 MODELS: nullifier IN polaris_zk/src/lib.rs
 ***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    Holders,         \* the anonymity set
    Verifiers,       \* relying parties, each its own scope
    Epochs,          \* the epochs proofs are made against
    ScopedNullifier  \* TRUE when the scope is inside the nullifier

ASSUME
    /\ Holders \in SUBSET Nat
    /\ Verifiers \in SUBSET Nat
    /\ Epochs \in SUBSET Nat
    /\ ScopedNullifier \in BOOLEAN

VARIABLES
    events,     \* recorded verification events
    nonces      \* consumed nonces, as the verifier that recorded them holds them

vars == << events, nonces >>

(***************************************************************************
 The nullifier, modelled as an injective function of its inputs rather than
 as a hash. With the scope inside it, one holder presents a different value
 to each verifier; without it, the same value to all of them.
 ***************************************************************************)
Nullifier(h, v, e) ==
    IF ScopedNullifier THEN << h, v, e >> ELSE << h, 0, e >>

TypeOK ==
    /\ events \subseteq [verifier : Verifiers, epoch : Epochs]
    /\ nonces \subseteq [verifier : Verifiers, value : (Holders \X Nat \X Epochs)]

Init ==
    /\ events = {}
    /\ nonces = {}

(***************************************************************************
 A holder proves membership to a verifier. What is RECORDED is the event
 (carrying no holder) and the consumed nullifier. The holder is a parameter
 of the action and appears in no recorded field except through the
 nullifier, which is the whole question.
 ***************************************************************************)
Prove(h, v, e) ==
    /\ h \in Holders /\ v \in Verifiers /\ e \in Epochs
    \* Anti-replay: the same nullifier cannot be consumed twice by the same
    \* verifier, which is ZkVerificationNonce's primary key.
    /\ ~ \E n \in nonces : n.verifier = v /\ n.value = Nullifier(h, v, e)
    /\ events' = events \cup {[verifier |-> v, epoch |-> e]}
    /\ nonces' = nonces \cup {[verifier |-> v, value |-> Nullifier(h, v, e)]}

Next == \E h \in Holders, v \in Verifiers, e \in Epochs : Prove(h, v, e)

Spec == Init /\ [][Next]_vars

(***************************************************************************
 C2 itself: no recorded event names a holder. Structural in this model, and
 stated so the spec covers the constraint as well as the property beyond it.
 ***************************************************************************)
NoEventNamesAHolder ==
    \A ev \in events : DOMAIN ev = {"verifier", "epoch"}

(***************************************************************************
 A relying party can refuse a second claim from the same person: the
 nullifier a holder presents to ONE verifier is a function of that holder,
 so a repeat is recognisable. Modelled as: distinct holders never collide at
 one verifier, which is what makes a repeat mean what the verifier thinks.
 ***************************************************************************)
OneVerifierRecognisesARepeat ==
    \A h1, h2 \in Holders, v \in Verifiers, e \in Epochs :
        h1 /= h2 => Nullifier(h1, v, e) /= Nullifier(h2, v, e)

(***************************************************************************
 And two relying parties who pool everything they hold still cannot tell
 they saw the same person: no value recorded by one appears in another's.
 ***************************************************************************)
NoTwoVerifiersCanLink ==
    \A n1, n2 \in nonces :
        n1.verifier /= n2.verifier => n1.value /= n2.value

============================================================================
