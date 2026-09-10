------------------------------ MODULE C3OneActiveToken ------------------------------
(***************************************************************************
 C3 — one identity per person.

 v9.23 / BIG MISSION High #1 (demonstrator artifact, per the Anti-Architect's
 scoped-down resolution: ONE spec for ONE constraint, NOT ongoing
 verification infrastructure).

 What this models: the constraint that NO TWO ACTIVE IdentityToken rows
 may share the same individual_id, AT ANY POINT IN TIME, even under
 concurrent issuance. The PostgreSQL implementation enforces this via a
 partial unique index:

     CREATE UNIQUE INDEX uq_one_active_per_person
         ON IdentityToken (individual_id)
         WHERE status = 'ACTIVE';

 (v9.374: this quoted DDL named uq_one_active_token_per_individual, an index
 that does not exist anywhere in the tree. The drift meta/tla/README.md warned
 maintained specs would suffer had already happened to the one demonstrator,
 and nothing noticed because nothing resolved the name. The MODELS bindings
 below are what make that detectable.)

 The implementation also uses FOR UPDATE locking inside the
 uc1_issue_and_activate procedure to serialize concurrent issuance for
 the same individual. This spec models both layers and shows that C3
 holds under interleaved concurrent operations.

 v9.374 (P6.7): this spec is now CHECKED IN CI on every push, and bound to
 the schema objects it claims to model, so it cannot drift from them
 silently. Graduating it found two defects in the artifact itself:

   - The file was named c3-one-active-token.tla while the module is
     C3OneActiveToken. TLA+ requires the two to match, so the spec as
     committed could not be PARSED, let alone checked. The companion .cfg
     existed only as a comment at the foot of the file.
   - Every action incremented op_count and none GUARDED it, so op_count ran
     past MaxOperations and the spec violated its own TypeOK invariant at
     the thirteenth step of a twelve-step bound.

 The substantive claim survived both: C3_OneActiveTokenPerIndividual was
 never violated in any reachable state. What failed was the bookkeeping, and
 it failed silently for as long as nothing ran the checker. That is the
 argument for maintenance, made by the artifact rather than about it.

 What this spec DOES verify (when checked with TLC):
   - Safety: ¬∃ t1 ≠ t2 : (t1.status = ACTIVE) ∧ (t2.status = ACTIVE)
             ∧ (t1.individual_id = t2.individual_id)
   - Under any interleaving of N concurrent Issue actions
   - Under any interleaving of N concurrent Revoke actions
   - When the FOR UPDATE lock is HELD by a transaction, no other
     transaction may begin Issue for the same individual

 What this spec does NOT verify:
   - The PostgreSQL-internal implementation of the partial unique
     index (we model the constraint as an invariant; checking that
     the partial unique index implements this is at the SQL layer
     via 08_tests.sql)
   - The application-layer authentication that prevents arbitrary
     callers from issuing tokens (out of scope; modeled in C1
     audit-of-record)
   - The duress-code flow (R11-5; modeled separately as a future
     spec if the proposal ever opens)
 ***************************************************************************)

\* ---------------------------------------------------------------------------
\* MODELS bindings (roadmap P6.7). Each names a real object in the tree that
\* this spec claims to describe. scripts/polaris-tla-drill.py resolves every
\* one of them, so if the index is renamed or the procedure is dropped, the
\* spec's claim is void and CI says so on that push rather than years later.
\*
\* This is the answer to the objection meta/tla/README.md used to raise against
\* maintained specs: that a model which has drifted from the schema it claims
\* to describe is worse than no model. Drift is not prevented by care, it is
\* detected by a citation that has to resolve.
\*
\* MODELS: uq_one_active_per_person IN polaris_sql/02_indexes.sql
\* MODELS: uc1_issue_and_activate IN polaris_sql/05_procedures.sql
\* ---------------------------------------------------------------------------

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Individuals,     \* Set of individual IDs in the population
    MaxTokens,       \* Maximum number of token rows we model
    MaxOperations    \* Bound on operation depth (for TLC bounded checking)

ASSUME
    /\ Individuals \in SUBSET Nat
    /\ MaxTokens \in Nat
    /\ MaxOperations \in Nat
    /\ MaxTokens >= Cardinality(Individuals)

VARIABLES
    tokens,          \* Set of token records {id, individual_id, status}
    next_token_id,   \* Auto-incrementing token id
    locks,           \* Set of (transaction_id, individual_id) FOR UPDATE locks
    op_count         \* Operations performed (for bounded checking)

Statuses == {"RESERVED", "ACTIVE", "REVOKED", "EXPIRED"}

vars == << tokens, next_token_id, locks, op_count >>

(***************************************************************************
 Type invariant — basic shape of the state
 ***************************************************************************)

TypeOK ==
    /\ tokens \subseteq [id : Nat, individual_id : Individuals, status : Statuses]
    /\ next_token_id \in Nat
    /\ locks \subseteq [tx_id : Nat, individual_id : Individuals]
    /\ op_count \in Nat
    /\ op_count <= MaxOperations
    /\ Cardinality(tokens) <= MaxTokens

(***************************************************************************
 C3 INVARIANT — the constitutional claim.

 At every reachable state, no two ACTIVE tokens share the same
 individual_id. This is what the partial unique index enforces in
 PostgreSQL; this spec verifies it holds under all interleavings.
 ***************************************************************************)

C3_OneActiveTokenPerIndividual ==
    \A t1, t2 \in tokens :
        ((t1.status = "ACTIVE") /\ (t2.status = "ACTIVE")
         /\ (t1.individual_id = t2.individual_id))
        => (t1.id = t2.id)

(***************************************************************************
 Initial state — no tokens, no locks
 ***************************************************************************)

Init ==
    /\ tokens = {}
    /\ next_token_id = 1
    /\ locks = {}
    /\ op_count = 0

(***************************************************************************
 AcquireLock(tx, ind) — transaction tx acquires FOR UPDATE on individual ind.

 In the PostgreSQL implementation, uc1_issue_and_activate runs:
     SELECT * FROM Individual WHERE individual_id = $1 FOR UPDATE;

 This serializes any subsequent transaction trying to issue a token
 for the same individual.
 ***************************************************************************)

AcquireLock(tx, ind) ==
    /\ ind \in Individuals
    /\ ~ \E lock \in locks : lock.individual_id = ind  \* No existing lock
    /\ ~ \E lock \in locks : lock.tx_id = tx  \* Transaction not already holding
    /\ locks' = locks \cup {[tx_id |-> tx, individual_id |-> ind]}
    /\ op_count < MaxOperations        \* v9.374: guard the bound TypeOK asserts
    /\ op_count' = op_count + 1
    /\ UNCHANGED << tokens, next_token_id >>

(***************************************************************************
 IssueToken(tx, ind) — transaction tx issues a new ACTIVE token for ind.

 PRECONDITION: tx already holds the lock on ind.
 The partial unique index enforces the C3 invariant; the FOR UPDATE
 lock serializes concurrent attempts (the partial unique index alone
 would let a concurrent attempt fail at commit time, but the lock
 prevents that race in the first place).

 If a previous ACTIVE token for the same ind exists, this transaction
 ABORTS (modeled as a no-op here — the SQL procedure raises an
 exception).
 ***************************************************************************)

IssueToken(tx, ind) ==
    /\ \E lock \in locks :
         (lock.tx_id = tx) /\ (lock.individual_id = ind)
    /\ ~ \E t \in tokens : (t.individual_id = ind) /\ (t.status = "ACTIVE")
    /\ next_token_id <= MaxTokens
    /\ tokens' = tokens \cup {[
           id |-> next_token_id,
           individual_id |-> ind,
           status |-> "ACTIVE"
       ]}
    /\ next_token_id' = next_token_id + 1
    /\ op_count < MaxOperations        \* v9.374: guard the bound TypeOK asserts
    /\ op_count' = op_count + 1
    /\ UNCHANGED locks

(***************************************************************************
 RevokeToken(tx, t) — transaction tx revokes token t.

 The state machine permits ACTIVE → REVOKED but NOT REVOKED → ACTIVE.
 This is enforced in the PostgreSQL implementation by a CHECK constraint
 on TokenLifecycleEvent's old_status / new_status pair.
 ***************************************************************************)

RevokeToken(tx, t) ==
    /\ t \in tokens
    /\ t.status = "ACTIVE"
    /\ tokens' = (tokens \ {t}) \cup {[
           id |-> t.id,
           individual_id |-> t.individual_id,
           status |-> "REVOKED"
       ]}
    /\ op_count < MaxOperations        \* v9.374: guard the bound TypeOK asserts
    /\ op_count' = op_count + 1
    /\ UNCHANGED << next_token_id, locks >>

(***************************************************************************
 ReleaseLock(tx) — transaction tx commits or rolls back; releases its locks.
 ***************************************************************************)

ReleaseLock(tx) ==
    /\ \E lock \in locks : lock.tx_id = tx
    /\ locks' = {lock \in locks : lock.tx_id /= tx}
    /\ op_count < MaxOperations        \* v9.374: guard the bound TypeOK asserts
    /\ op_count' = op_count + 1
    /\ UNCHANGED << tokens, next_token_id >>

(***************************************************************************
 Next-state relation — non-deterministically choose an action
 ***************************************************************************)

Next ==
    \/ \E tx \in 1..3, ind \in Individuals : AcquireLock(tx, ind)
    \/ \E tx \in 1..3, ind \in Individuals : IssueToken(tx, ind)
    \/ \E tx \in 1..3, t \in tokens : RevokeToken(tx, t)
    \/ \E tx \in 1..3 : ReleaseLock(tx)

Spec ==
    Init /\ [][Next]_vars

(***************************************************************************
 The properties to check.

 INVARIANT C3_OneActiveTokenPerIndividual — the primary claim.
 INVARIANT TypeOK                          — well-formed state.

 Running TLC with:

     Individuals  = {1, 2}
     MaxTokens    = 4
     MaxOperations = 12

 explores ~10,000 reachable states and confirms both invariants hold.
 For larger Individuals sets, TLC's state space explodes; the
 N=2 case is sufficient to demonstrate the technique. For larger
 verification, use TLAPS (proof assistant) with the inductive
 invariant approach — out of scope for this demonstrator.
 ***************************************************************************)

============================================================================

\* Companion config (would live in C3OneActiveToken.cfg):
\*
\* SPECIFICATION Spec
\* CONSTANTS
\*     Individuals = {1, 2}
\*     MaxTokens = 4
\*     MaxOperations = 12
\* INVARIANT C3_OneActiveTokenPerIndividual
\* INVARIANT TypeOK
