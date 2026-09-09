# Version 2 author notes: what the research found in the repository

These are places where a repository document is behind its code or its own history, found while
writing Version 2 against the tree at `v9.345`. None was changed for the paper; the paper follows
the code. Each is small and each is recorded so it is not lost.

| Where | What it says | What the tree shows | Paper's choice |
|---|---|---|---|
| `docs/ARCHITECTURE-OVERVIEW.md`, Layer 1 | "Key tables (30 in `01_schema.sql`, 37 in a migrated deployment)" | `01_schema.sql` declares 36 canonical tables (40 `CREATE TABLE` statements including four partition children); DATA-MODEL.md, SYSTEM-MAP.md and the README say 36 and 43 | 36 and 43, measured |
| `docs/reference/DATA-MODEL.md`, "Migration policy" | "There are no up/down migration scripts yet"; schema reload is destructive | `polaris_sql/migrations/` holds 25 up/down pairs and `scripts/polaris-migrate.sh` applies them under lock and statement timeouts; the same document's opening paragraph counts the migration-added tables | Migrations exist and are described as such |
| `docs/design/threat-model.md` (T-T2, "Deferred") and `docs/design/zk-snark.md` ("the verification route neither issues nor consumes nonces") | A single-use nonce store is deferred | `ZkVerificationNonce` exists (migration `2026-06-04-001`), `polaris_web/app.py` inserts the consumed `(epoch_id, context_id, nonce)` on `/api/zk/verify`, and DATA-MODEL.md and PRODUCTION-READINESS.md describe single-use anti-replay as implemented | Online single-use replay protection is implemented; offline the verifier keeps no state |
| `docs/design/atlas-scaling.md`, "API contract" | "All four `/api/atlas/*` endpoints" | The application registers nineteen `/api/atlas/*` routes at HEAD | The paper describes the console by its bounded functions, not a count |
| `conformance/SPEC.md` | "sixteen artifact types at v9.331" | `cases.json` holds 48 cases at v9.345 (the frozen version-1 set holds 44); the README's compatibility line ("44/44 frozen cases") refers to the frozen set | 48 current cases, 44 frozen, sixteen artifact types |
| `ROADMAP.md`, inventory heading | "Where we are (inventory at v9.311)" | The paragraph carries v9.345 stamps | Cosmetic; noted only |
| `docs/reference/SYSTEM-MAP.md` vs `ROADMAP.md` | "seventeen documents and an index" versus "eighteen operator runbooks and ledgers" | `docs/operator/` holds eighteen Markdown files including the index | Cosmetic; noted only |
| `docs/design/threat-model.md` (T-T3, D-D3, I-I4, D-D4) | Backlog references to `BACKLOG.md` and to operator-doc backlog items | No `BACKLOG.md` exists in the tree | The paper cites the threat model's accepted and deferred items without the backlog pointers |

Two observations that are not contradictions but are worth a maintainer's eye:

- The README's stamped test counts (755 product tests, 84 of 89 crypto witnesses) date from
  v9.332 and are, per the README's own rule, restated when re-measured. The paper reports them
  with that stamp and separately reports the 1,048 test functions defined at HEAD as a
  definition count.
- The performance baseline table has not been re-run since v9.191 on the reference machine;
  the CI smoke run is a procedure check by design. The paper cites the v9.191 numbers with their
  version.
