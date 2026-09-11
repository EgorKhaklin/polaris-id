# meta/: the structural records

**Reader:** an assessor or engineer asking why the ten constraints are
structured the way they are, rather than what they say. **Job:** hold the
records that justify the constitution's shape, including the two that are
proofs rather than prose.

[MISSION.md](../MISSION.md) states the constraints and the vocation above them;
[polaris_checks/](../polaris_checks/README.md) is where they are enforced
mechanically. The design records for individual mechanisms are in
[docs/design/](../docs/design/README.md). What is here is narrower: the
reasoning about the constraint set itself.

| File | What it holds |
|---|---|
| [structural-architecture.md](structural-architecture.md) | The Removable Test: the discipline that decides whether a thing belongs in the schema, the application or nowhere |
| [constraint-lattice.md](constraint-lattice.md) | The mapping between C1 to C10 and the lattice of what each one holds up |
| [redaction-proof.md](redaction-proof.md) | The verification-graph redaction proof and its adversary model: why a NULL column is not the whole claim |
| [trust-ladder.md](trust-ladder.md) | The anti-trust ladder: what each rung refuses, the mechanism that discharges it, where the ladder stops, and what Polaris does not claim |
| [tla/](tla/) | The TLA+ model of C3, one active token per person, checked once as a demonstrator rather than maintained |
