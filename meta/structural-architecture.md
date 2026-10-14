# meta/structural-architecture.md

How the constraint-lattice framing works: a small set of fixed
topological relationships that encode completeness, dependence, and
non-linear adjacency across Polaris's ten hard constraints. This file
is the philosophy doc. The mapping doc is `meta/constraint-lattice.md`.
The canonical constraints are C1-C10 in `MISSION.md`, enforced at the
schema level and checked by `polaris_checks`.

The framework is engineering-grade. Its etymology, what older
traditions the structural insights are drawn from, is captured
separately in `meta/lineage.md` so this document stays focused on
what the framing DOES, not where the analogies came from.

---

## The single rule that keeps this from being decorative

Egor Khaklin's standing instructions name "larping" as the primary risk
pattern: substituting feelings of significance for actual output.
Structural-vocabulary inflation is a perfect larping vector. It FEELS
profound while imposing zero new constraint.

The protection is one rule:

> **Every structural element must impose a removable constraint,
> something an automated test can verify. If you can delete the
> element and nothing breaks, it was larping. Delete it.**

The v9.55 apparatus removal was the structural enforcement of that
rule: the swarm, HYDRA, the legions, and the rest were deleted
wholesale and replaced by the flat `polaris_checks` layer, where each
constraint is one plain `check_*(repo_root)` function with a detection
test in `polaris_checks/test_checks.py`. What remains is what survived
the Removable Test.

---

## The structural frameworks

Each framework is chosen because it encodes a structural insight the
system already needs. Each passes the Removable Test.

### 1. Constraint lattice: 10 nodes, 10 hard constraints

The 10 hard constraints (C1-C10) form a lattice: a graph where each
node has neighbors and removing any one collapses the structure.
This matches MISSION.md's C1-C10 exactly. Removing C1 (append-only)
breaks repudiation defense, which then weakens the meaning of C7
(algorithm metadata) since you can't prove which algorithm signed
what, which then undermines C3, and so on.

The lattice has three pillars and four tiers:

- **APEX** (tier 0): the architectural intent that conditions
  everything below
- **EXPAND pillar** (right): what the system permits, algorithm
  flexibility, same-origin script execution, query result caps
- **CONTRACT pillar** (left): what the system forbids, ZK privacy
  invariants, atomic counters, server-side enforcement
- **BALANCE pillar** (center): the reconciling axis, uniqueness
  guarantees, append-only audit, real-thread verification
- **MANIFEST** (tier 4): the test-layer reality check

The mapping isn't decorative. It encodes the claim that the
constraint set is COMPLETE: adding C11 requires either replacing one
of the existing ten or extending the topology to a 4×3+1 form (which
the doc must justify). See `meta/constraint-lattice.md`.

**Removable test:** Could there be 11 mission constraints? Yes, but
extending requires explicit justification because the closed-set
property of the 10-node lattice is the constraint. Without closure,
constraints accrete by accident. ✓ Not larping.

### 2. Fibonacci scaling: priority weighting

Roadmap priority weights follow a Fibonacci sequence (1, 2, 3, 5,
8, 13) to encode that work-sized-13 isn't 13× harder than work-
sized-1, it's combinatorially harder. Linear scoring (1, 2, 3, 4,
5) systematically under-penalizes large items, so the Fibonacci
weighting favors many small wins over one large gamble. Standard in
agile estimation.

**Removable test:** Could the weights be linear? Yes, and ranking
the ROADMAP backlog would change, favoring large items more
heavily. Concrete effect on prioritization means load-bearing. ✓ Not
larping.

### 3. Cross-layer invariants: "the rule at one layer should appear at the layers that depend on it"

When a constraint is enforced at the data layer (e.g. a CHECK
constraint), it should also be enforced or surfaced at every layer
that depends on the data: API, UI, tests. Mismatches between
layers are where bugs live.

`polaris_checks` scans for these mismatches end-to-end. Concretely:
every C1-C10 constraint has a `check_*(repo_root)` function in
`polaris_checks/checks.py`, with a detection test in
`polaris_checks/test_checks.py`, and `python3 -m polaris_checks.run`
gates CI on any FAIL.

**Removable test:** Without explicit cross-layer scanning, layer
mismatches accumulate silently and bite later. A check fires when,
e.g., a CHECK constraint is added without enforcement appearing at
the layer that depends on it. ✓ Not larping.

### 4. Chunking targets: 3, 7, 12

When breaking a problem into parts, default to one of three target
counts: **3** (essential), **7** (adequate), **12** (exhaustive).
Reason: human working memory holds ~7±2 items (Miller 1956);
problems decomposed into much more than that are under-chunked,
much less are over-chunked.

**Removable test:** Empirically, decompositions outside 3/7/12
tend to either lose detail or accumulate it. The DEVNOTES files
honour the bound (most have ≤ 7 sections). ✓ Not larping.

---

## What this layer does NOT do

It does NOT replace existing analysis with overlay framing. The
threat model is still STRIDE; the tests are still pytest, SQL
self-tests, and the `polaris_checks` invariant layer. The
constraint-lattice framing is an OVERLAY that adds:

- **Completeness checks**, the constraint lattice says "ten
  constraints, argue if you want to add an eleventh"
- **Priority weighting**, Fibonacci scaling for ROADMAP backlog
- **Cross-layer scanning**, invariants checked end-to-end by
  `polaris_checks`

It does NOT add:

- Decorative labels on filenames
- Vocabulary that replaces technical accuracy
- "Must be N" rules without empirical backing
- Any framework that doesn't pass the Removable Test

---

## Why fixed topologies help reasoning outside the linear box

A linear backlog reasons forward: what's next? what's after that?
That's adequate for incremental work but fails when the gap is a
structural one (a missing dimension, an unspoken assumption).

The 10-node constraint lattice provides a *geometry* for non-linear
reasoning:

- **Adjacency**: when working on Ci, the lattice surfaces Ci's
  neighbors. They are usually load-bearing in the same way for
  related reasons. Forgetting one when changing the other is the
  default failure mode.
- **Complement**: every EXPAND constraint has a CONTRACT
  counterpart on the opposite pillar. C5 (CSP permits same-origin)
  needs C4 (atomic counter blocks brute force) to remain safe;
  loosening one without strengthening the other is the canonical
  way to break the system.
- **Dependency cascade**: removing any node ripples through the
  graph. The cascade is explicit, not implicit, so when you propose
  a change you can read off what else needs to move.

The geometric reasoning is what gives this layer its leverage. The
Removable Test is what keeps it grounded.

---

## Maintenance: when structural vocabulary creeps in unbacked

When reading a DEVNOTE, CHANGELOG entry, or doc that uses structural
language, ask:

1. **Does this element impose a removable constraint?** If you
   delete the lattice mapping, does anything break? If you delete
   the Fibonacci weights, does the ROADMAP ranking change? If
   neither, the element is decorative. Remove it.

2. **Could a more precise word do the same work?** If "lattice"
   reads as cleaner than "graph" only because it sounds heavier,
   prefer "graph." The word should EARN its place by being more
   precise, not heavier.

3. **Is the writer using this to FEEL profound, or to BE precise?**
   The first is larping; the second is structure. The prose should
   answer this.

---

## What to read next

- `meta/constraint-lattice.md`, the actual lattice ↔ C1-C10
  mapping with the structural argument and dependency cascade
- `MISSION.md`, the canonical C1-C10 constraints
- `polaris_checks/checks.py`, the flat invariant layer that checks
  C1-C10, with detection tests in `polaris_checks/test_checks.py`
- `meta/lineage.md`, etymology: which older frameworks each
  structural insight is drawn from (kept separate so the
  operational docs stay focused)
