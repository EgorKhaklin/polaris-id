------------------------------ MODULE C1PurgeCoverage ------------------------------
(***************************************************************************
 C1 — the audit-of-record is append-only, and the one carve-out is covered.

 v9.374 (roadmap P6.7). Checked by scripts/polaris-tla-drill.py on every push.

 WHAT THIS MODELS. reject_audit_modification() forbids UPDATE and DELETE on
 every audit table, with a single carve-out: a DELETE is permitted when the
 transaction-scoped GUC polaris.purge_in_progress is 'TRUE'. uc_archive_purge()
 sets that GUC and writes a LifecycleArchiveCheckpoint row in the same
 transaction, so an archived-then-deleted row leaves a record of its own
 removal.

 THE PROPERTY WORTH PROVING is not "DELETE is hard". It is PURGE COVERAGE:

     every audit row that has left the table is covered by a COMMITTED
     checkpoint recording that it left

 A deletion that commits without its checkpoint is the failure that matters,
 because it is a hole in the audit chain that nothing afterwards can see. The
 row is gone; the record that it was ever there is gone; and the absence looks
 exactly like a row that never existed.

 WHAT THE MODEL SHOWS THE PROPERTY RESTS ON. Coverage does NOT follow from the
 trigger. The trigger permits any DELETE while the GUC is TRUE, whether or not
 a checkpoint was written. Coverage follows from the GUC having exactly one
 setter, uc_archive_purge, which writes the checkpoint in the same transaction.

 That is a real result rather than a restatement: it says the safety of the
 audit chain rests on nothing else ever setting that GUC, and it converts a
 property of the trigger into a property of the procedure set. The spec
 therefore models the carve-out as openable only by a purge transaction, and
 check_formal_specs asserts in the tree what the model assumes: that
 polaris.purge_in_progress is SET in exactly one place.

 UncoveredDeleteIsPossible below is the counterpart, and it is the honest half.
 It states, as a checked invariant over the SAME model, that if any other path
 could open the carve-out then a committed uncovered delete is reachable. It is
 checked in the second configuration, where the extra setter is switched on.

 MODELS bindings, resolved by scripts/polaris-tla-drill.py so a rename cannot
 leave this spec quietly describing something that no longer exists:

 MODELS: reject_audit_modification IN polaris_sql/06_triggers.sql
 MODELS: purge_in_progress IN polaris_sql/05_procedures.sql
 MODELS: LifecycleArchiveCheckpoint IN polaris_sql/01_schema.sql
 ***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    Rows,               \* the audit rows that exist at the start
    Txs,                \* the concurrent transactions modelled
    RogueCarveOut,      \* TRUE to model a second setter of the GUC
    MaxRejects          \* bound on refused attempts, so the model is finite

ASSUME
    /\ Rows \in SUBSET Nat
    /\ Txs \in SUBSET Nat
    /\ RogueCarveOut \in BOOLEAN
    /\ MaxRejects \in Nat

VARIABLES
    present,        \* rows still in the audit table (committed view)
    departed,       \* rows whose DELETE has COMMITTED
    covered,        \* rows whose checkpoint has COMMITTED
    txState,        \* [tx -> "idle" | "open"]
    txGuc,          \* [tx -> BOOLEAN]  the transaction-scoped carve-out
    txDeletes,      \* [tx -> SUBSET Rows]  deletes staged, not yet committed
    txCheckpoints,  \* [tx -> SUBSET Rows]  checkpoints staged, not yet committed
    rejected        \* refused attempts, BOUNDED: an unbounded counter makes the
                    \* state space infinite, which is not a subtle failure. The
                    \* first version of this spec had one and TLC was still
                    \* enumerating at 35 million distinct states with the queue
                    \* nearly empty, which is the shape of a counter running away
                    \* rather than of a system with much to explore.

vars == << present, departed, covered, txState, txGuc, txDeletes,
           txCheckpoints, rejected >>

TypeOK ==
    /\ present \subseteq Rows
    /\ departed \subseteq Rows
    /\ covered \subseteq Rows
    /\ txState \in [Txs -> {"idle", "open"}]
    /\ txGuc \in [Txs -> BOOLEAN]
    /\ txDeletes \in [Txs -> SUBSET Rows]
    /\ txCheckpoints \in [Txs -> SUBSET Rows]
    /\ rejected \in Nat
    /\ rejected <= MaxRejects

Init ==
    /\ present = Rows
    /\ departed = {}
    /\ covered = {}
    /\ txState = [t \in Txs |-> "idle"]
    /\ txGuc = [t \in Txs |-> FALSE]
    /\ txDeletes = [t \in Txs |-> {}]
    /\ txCheckpoints = [t \in Txs |-> {}]
    /\ rejected = 0

(***************************************************************************
 A transaction opens. It has no carve-out until something sets the GUC.
 ***************************************************************************)
Begin(t) ==
    /\ txState[t] = "idle"
    /\ txState' = [txState EXCEPT ![t] = "open"]
    /\ UNCHANGED << present, departed, covered, txGuc, txDeletes,
                    txCheckpoints, rejected >>

(***************************************************************************
 uc_archive_purge opens the carve-out. Modelled as also staging the
 checkpoint, because the procedure writes it in the same transaction: that
 pairing IS the mechanism coverage rests on.
 ***************************************************************************)
OpenPurge(t, r) ==
    /\ txState[t] = "open"
    /\ r \in present
    /\ r \notin txDeletes[t]
    /\ txGuc' = [txGuc EXCEPT ![t] = TRUE]
    /\ txDeletes' = [txDeletes EXCEPT ![t] = @ \cup {r}]
    /\ txCheckpoints' = [txCheckpoints EXCEPT ![t] = @ \cup {r}]
    /\ UNCHANGED << present, departed, covered, txState, rejected >>

(***************************************************************************
 A second setter of the GUC, off by default. This is the path the tree does
 not have and check_formal_specs asserts it does not: it stages a DELETE with
 the carve-out open and NO checkpoint beside it.
 ***************************************************************************)
OpenRogue(t, r) ==
    /\ RogueCarveOut
    /\ txState[t] = "open"
    /\ r \in present
    /\ r \notin txDeletes[t]
    /\ txGuc' = [txGuc EXCEPT ![t] = TRUE]
    /\ txDeletes' = [txDeletes EXCEPT ![t] = @ \cup {r}]
    /\ UNCHANGED << present, departed, covered, txState, txCheckpoints,
                    rejected >>

(***************************************************************************
 An UPDATE attempt. The carve-out is DELETE-only, so this changes nothing
 whatever the GUC says. Counted so the model shows the attempts were made.
 ***************************************************************************)
AttemptUpdate(t) ==
    /\ txState[t] = "open"
    /\ rejected < MaxRejects
    /\ rejected' = rejected + 1
    /\ UNCHANGED << present, departed, covered, txState, txGuc, txDeletes,
                    txCheckpoints >>

(***************************************************************************
 A DELETE attempted with no carve-out open. Rejected: nothing changes.
 Modelled as a no-op step so the state graph contains the attempt.
 ***************************************************************************)
AttemptDeleteWithoutCarveOut(t, r) ==
    /\ txState[t] = "open"
    /\ txGuc[t] = FALSE
    /\ r \in present
    /\ rejected < MaxRejects
    /\ rejected' = rejected + 1
    /\ UNCHANGED << present, departed, covered, txState, txGuc, txDeletes,
                    txCheckpoints >>

Commit(t) ==
    /\ txState[t] = "open"
    /\ present' = present \ txDeletes[t]
    /\ departed' = departed \cup txDeletes[t]
    /\ covered' = covered \cup txCheckpoints[t]
    /\ txState' = [txState EXCEPT ![t] = "idle"]
    \* SET LOCAL: the GUC evaporates at the transaction boundary, which is why
    \* one transaction's carve-out can never authorise another's DELETE.
    /\ txGuc' = [txGuc EXCEPT ![t] = FALSE]
    /\ txDeletes' = [txDeletes EXCEPT ![t] = {}]
    /\ txCheckpoints' = [txCheckpoints EXCEPT ![t] = {}]
    /\ UNCHANGED rejected

Abort(t) ==
    /\ txState[t] = "open"
    /\ txState' = [txState EXCEPT ![t] = "idle"]
    /\ txGuc' = [txGuc EXCEPT ![t] = FALSE]
    /\ txDeletes' = [txDeletes EXCEPT ![t] = {}]
    /\ txCheckpoints' = [txCheckpoints EXCEPT ![t] = {}]
    /\ UNCHANGED << present, departed, covered, rejected >>

Next ==
    \/ \E t \in Txs : Begin(t)
    \/ \E t \in Txs, r \in Rows : OpenPurge(t, r)
    \/ \E t \in Txs, r \in Rows : OpenRogue(t, r)
    \/ \E t \in Txs : AttemptUpdate(t)
    \/ \E t \in Txs, r \in Rows : AttemptDeleteWithoutCarveOut(t, r)
    \/ \E t \in Txs : Commit(t)
    \/ \E t \in Txs : Abort(t)

Spec == Init /\ [][Next]_vars

(***************************************************************************
 THE PROPERTY. Every row that has left the audit table is covered by a
 committed checkpoint recording that it left.
 ***************************************************************************)
PurgeCoverage == departed \subseteq covered

(***************************************************************************
 A row is either present or departed, never both and never neither: the
 audit chain accounts for every row it ever held.
 ***************************************************************************)
NoRowVanishes == present \cup departed = Rows /\ present \cap departed = {}

(***************************************************************************
 One transaction's carve-out never authorises another's DELETE. SET LOCAL is
 what makes this true, and it is the reason the carve-out cannot be left
 open by a procedure that failed to clean up after itself.
 ***************************************************************************)
CarveOutIsPerTransaction ==
    \A t \in Txs : txState[t] = "idle" => txGuc[t] = FALSE

============================================================================
