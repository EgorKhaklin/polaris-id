# docs/reference/: technical reference

**Reader:** an integrator shipping against Polaris, or a reviewer checking
a technical claim. **Job:** the source of truth for Polaris's interfaces
and measured characteristics, written so a third party can build against
the system without reading its source. For runbooks see
[../operator/](../operator/README.md); for the architecture narrative see
[../ARCHITECTURE-OVERVIEW.md](../ARCHITECTURE-OVERVIEW.md).

| Document | What it covers |
|---|---|
| [`SYSTEM-MAP.md`](SYSTEM-MAP.md) | The map: every directory, every package, every CI job, and who reads what |
| [`API.md`](API.md) | Every `/api/*` route, the health and metrics contracts, rate limits, error shape |
| [`DATA-MODEL.md`](DATA-MODEL.md) | Every table in the schema and its migrations, grouped, with the invariant that guards it |
| [`PQC-POSTURE.md`](PQC-POSTURE.md) | Which primitives are post-quantum and which are still classical, against the NIST 2030/2035 timeline |
| [`PERFORMANCE-BASELINE.md`](PERFORMANCE-BASELINE.md) | Issuance and verification throughput and Atlas latency, measured end to end on stated hardware and re-run by CI |
| [`SCALING.md`](SCALING.md) | The Atlas and the verification log at 10 million events: indexes, caps, rollups |
| [`BENCHMARK.md`](BENCHMARK.md) | The committed load certification: the national simulation driven at scale, with throughput, latency, Atlas query times, and invariants under load |
| [`DYNO.md`](DYNO.md) | Real numbers from a real box: single-core ML-DSA-65 sign/verify and ZK prove/verify at a stated tree depth, measured by `scripts/polaris-dyno.py` and re-measured every release |
| [`GLOSSARY.md`](GLOSSARY.md) | Defined terms |

**Reading order.** [SYSTEM-MAP.md](SYSTEM-MAP.md) first. Building against
the API: [API.md](API.md), then [DATA-MODEL.md](DATA-MODEL.md) for the
schema behind it. Sizing a deployment: [PERFORMANCE-BASELINE.md](PERFORMANCE-BASELINE.md),
then [SCALING.md](SCALING.md).

**Conventions.** One file, one surface. Tables where the structure repeats.
Every cross-reference is a Markdown link, so the link checker sees it. A
version stamp appears only beside a measured number, naming the version it
was measured at; bodies carry no ticket identifiers. Project-wide
conventions are in [../CONVENTIONS.md](../CONVENTIONS.md).
