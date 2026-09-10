# meta/tla/: the formal specifications

**Reader:** an assessor who found TLA+ specs and wants to know how much weight they carry.
**Job:** what is specified, what is checked, and what checking a model does not tell you.

**These are model-checked in CI on every push** by
[`scripts/polaris-tla-drill.sh`](../../scripts/polaris-tla-drill.sh). Until v9.374 they were
not, and this file said so.

---

## The specs

| Spec | Property |
|---|---|
| [`C3OneActiveToken.tla`](C3OneActiveToken.tla) | No two ACTIVE credentials share an individual, under every interleaving of concurrent issue and revoke. Models the partial unique index and the `FOR UPDATE` locking in `uc1_issue_and_activate`. |
| [`C1PurgeCoverage.tla`](C1PurgeCoverage.tla) | Every audit row that has left the table is covered by a committed checkpoint recording that it left. Models `reject_audit_modification`'s single DELETE carve-out and the transaction-scoped GUC that opens it. |

## What graduating them found

This directory used to argue against maintained specs, on the grounds that *a model which has
drifted from the schema it claims to describe is worse than no model*. That argument was
right. It was simply not an argument for leaving the spec unchecked, because the drift it
predicted had already happened to the one spec there was:

- **It could not be parsed.** The file was named `c3-one-active-token.tla` while the module
  inside was `C3OneActiveToken`. TLA+ requires the two to match, so the spec as committed could
  not be checked at all, and the companion configuration existed only as a comment at the foot
  of the file. It had never been run in the form it shipped.
- **It violated its own type invariant.** Every action incremented `op_count` and none guarded
  it, so the counter ran past `MaxOperations` and `TypeOK` failed at the thirteenth step of a
  twelve-step bound.
- **It had already drifted.** It quoted a partial unique index named
  `uq_one_active_token_per_individual`. No such index exists anywhere in the tree; the real one
  is `uq_one_active_per_person`, in `polaris_sql/02_indexes.sql`.

The substantive claim survived all three: C3 was never violated in any reachable state. What
failed was everything around it, silently, for as long as nothing ran the checker.

## How drift is caught now

A spec declares the objects it models, and the drill resolves each one against the file it
names:

```
\* MODELS: uq_one_active_per_person IN polaris_sql/02_indexes.sql
\* MODELS: uc1_issue_and_activate IN polaris_sql/05_procedures.sql
```

Rename the index and the spec's claim is void, so CI fails on the push that renamed it rather
than years later. **Drift is not prevented by care. It is detected by a citation that has to
resolve.**

## A spec that cannot fail proves nothing

The same discipline the check layer applies to itself: every `check_*` has a detection test
proving it fails on a broken fixture, and a check that cannot detect its own violation is
treated as broken.

So a spec may carry a **counterpart configuration**, `NAME.violation.cfg`, which the author
asserts *should* fail. The drill runs it and fails if the invariant holds.
`C1PurgeCoverage.violation.cfg` turns on a second setter of the carve-out GUC and requires TLC
to find a committed DELETE with no committed checkpoint.

That is what makes the C1 result a result. **Purge coverage does not follow from the trigger**,
which permits any DELETE while the GUC is `TRUE`. It follows from the GUC having exactly one
setter, inside `uc_archive_purge`, which writes the checkpoint in the same transaction. The
counterpart configuration is the proof that the assumption is load-bearing, and
`check_formal_specs` asserts in the SQL what the model assumes: that
`polaris.purge_in_progress` is `SET` in exactly one place.

## What a model check does not tell you

- **That the model matches the system.** TLC verifies the model. Whether the model describes
  PostgreSQL's actual behaviour is a human judgement, and the `MODELS` bindings narrow it
  without closing it: they prove the named objects still exist, not that the spec describes
  them correctly.
- **Anything about the unmodelled.** Neither spec models PostgreSQL's implementation of an
  index, MVCC, crash recovery, or any cryptography.
- **Anything at unbounded scale.** Both are bounded explorations: two individuals, two
  transactions, a handful of operations. The bounds are stated in each configuration. A
  property that holds at N=2 and fails at N=5 would not be caught here, and closing that needs
  a proof assistant rather than a model checker.

## Running them

```bash
scripts/polaris-tla-drill.sh            # fetches the pinned tla2tools, checks every spec
POLARIS_JAVA=/path/to/java scripts/polaris-tla-drill.sh
```

The `tla2tools` version is pinned, for the reason the axe-core pin is: an unpinned checker is
one whose semantics can change under the claim it is being used to support.
