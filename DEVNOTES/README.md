# DEVNOTES: the working notes

**Reader:** a contributor about to change something. **Job:** the notes a
contributor working in this repository needs and nobody evaluating Polaris does.
Internal plans and assessments are kept outside the public tree.

The design records that used to live here, the threat model, the concurrency
catalogue, the substrate manifest, the ZK soundness ledger and one record per
mechanism, moved to [docs/design/](../docs/design/README.md) at v9.224. They
are assessor-facing material and were filed where an assessor would not look.

| File | What it holds |
|---|---|
| [style.md](style.md) | The house style: declarative prose, no em-dashes, no cosmic framing, and the quality bar a ship has to clear |
| [known-gotchas.md](known-gotchas.md) | Things that have already cost an hour: environment quirks, tool behaviour, and the traps in this codebase |
| [record.md](record.md) | The project record: the completed arcs and the deployment phase log, moved out of MISSION.md at v9.195 |
| [athena-ontology-assessment.md](athena-ontology-assessment.md) | The adversarial assessment of an operational ontology (Athena): model power and rules, never a graph of people; verdict, constraints, MVP, and kill criteria (roadmap P6.8) |

## Where does something new go

- A design record for a mechanism, or a cross-cutting principle an assessor
  would want: [docs/design/](../docs/design/README.md), with a row in its
  index.
- An operational procedure: [docs/operator/](../docs/operator/README.md).
- A technical reference an integrator reads: [docs/reference/](../docs/reference/README.md).
- Something only a contributor working in this repository needs: here, with a
  row in the table above.
