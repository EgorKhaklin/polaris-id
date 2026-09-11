# docs/: the documentation index

**Reader:** anyone who has read the root README and needs the next document.
**Job:** one row per document in this directory and one row per
sub-directory, each delegating to its own index. `check_docs_index_coverage`
fails the build when a document under `docs/` is not listed by the index of
its own directory.

The constitution ([MISSION.md](../MISSION.md)), the build plan
([ROADMAP.md](../ROADMAP.md)), the release log ([CHANGELOG.md](../CHANGELOG.md))
and the developer runbook ([CLAUDE.md](../CLAUDE.md)) stay at the repository
root.

## Documents in this directory

| Document | Reader and job |
|---|---|
| [PRODUCTION-READINESS.md](PRODUCTION-READINESS.md) | The bound on every claim in this repository: what an operator must still decide before real identity data, and the check behind every closed engineering item. Read this first if you are deciding whether to deploy. |
| [ARCHITECTURE-OVERVIEW.md](ARCHITECTURE-OVERVIEW.md) | An engineer or auditor evaluating the system: what it is and is not, the layers, the identity flow, the cryptography, the deployment paths, and a walkthrough of the constraints refusing bad writes. |
| [REVIEW-PACKET.md](REVIEW-PACKET.md) | What each subsystem guarantees, what holds it, what does not, and the attacks the maintainers would most like attempted; every limitation carries a witness that fails the build when the limitation is fixed |
| [RED-TEAM-SCOPE.md](RED-TEAM-SCOPE.md) | The security firm to be commissioned: engagement type, threat actors, in-scope surfaces, deliverables, disclosure timeline. |
| [THESIS.md](THESIS.md) | The claim behind the project, the test that would have confirmed it, and the record that the window closed unactioned. |
| [SEED_DATA.md](SEED_DATA.md) | The notional individuals, agencies, tokens and events the sample database loads, and what each demonstrates. |
| [CONVENTIONS.md](CONVENTIONS.md) | A contributor: naming, file layout, CHANGELOG shape, cross-reference and prose rules. |

## Sub-directories

| Directory | What it holds |
|---|---|
| [design/](design/README.md) | Why it is built this way: the threat model, the concurrency catalogue, the substrate manifest, and one record per mechanism. |
| [operator/](operator/README.md) | The runbooks: install, deploy, operate, secure, back up, recover, and the drill ledgers. |
| [reference/](reference/README.md) | The technical reference: the API, the data model, the post-quantum posture, the performance baseline, scaling, the glossary, the system map. |
| [paper/](paper/README.md) | The academic report, TeX and PDF. |

Design notes that explain why things are built the way they are live in
[DEVNOTES/](../DEVNOTES/README.md); structural records (the redaction proof,
the TLA+ model) live in [meta/](../meta/README.md).

Each package and directory outside `docs/` carries its own README naming its
reader: [`polaris_sql/`](../polaris_sql/README.md),
[`polaris_web/`](../polaris_web/README.md),
[`polaris_cli/`](../polaris_cli/README.md),
[`polaris_zk/`](../polaris_zk/README.md),
[`polaris_checks/`](../polaris_checks/README.md),
[`scripts/`](../scripts/README.md),
[`deploy/`](../deploy/README.md) and
[`site/`](../site/README.md).
