# docs/CONVENTIONS.md: naming + structural conventions

The implicit conventions that make Polaris's structure coherent,
named explicitly so future contributors (and future agents) can
follow them without re-deriving.

If the convention isn't named here, it isn't a convention: it's
just an emergent pattern. Codify or change.

---

## 1. Top-level directory naming

**Pattern:** `polaris_<domain>/` for Python packages and the SQL bundle;
unprefixed nouns for everything else.

| Pattern | Example | Why |
|---|---|---|
| `polaris_<domain>/` | `polaris_web/`, `polaris_sql/`, `polaris_checks/`, `polaris_zk/`, `polaris_cli/` | Python package convention; namespaced; unambiguous when `pip install`'d |
| Unprefixed singular | `site/` | One thing: the published project page and the images it shares with the README |
| Unprefixed plural | `docs/`, `scripts/`, `meta/`, `deploy/` | Container of similar items |
| ALL_CAPS | `DEVNOTES/` | The one exception, kept because renaming it moves hundreds of references for no reader's benefit |

**Rule:** a top-level rename moves every cross-reference to it, so it needs a
reason a reader would recognise. The v9.224 move of the design records out of
`DEVNOTES/` had one: an assessor does not look in a directory named for
developer notes. Renaming the directory itself did not, so it kept its name.

---

## 2. Top-level file naming

**Pattern:** `ALL_CAPS.md` for constitutional docs; `Title.md` for
conventional + agent-runbook docs; `lowercase.<ext>` for everything else.

| Pattern | Example | What |
|---|---|---|
| `ALL_CAPS.md` | `MISSION.md`, `ROADMAP.md`, `CHANGELOG.md`, `LICENSE`, `NOTICE` | Constitutional / legal: the load-bearing docs |
| `Title.md` | `README.md`, `CLAUDE.md` | Conventional + agent-runbook |
| `lowercase.ext` | `polaris_mac_launch.sh`, `Polaris.command` | Executables (note: `Polaris.command` is the macOS double-click convention) |
| Hidden | `.gitignore`, `.pre-commit-config.yaml`, `.github/`, `.git/` | Tooling config |

---

## 3. Script naming

| Family | Pattern | Read by |
|---|---|---|
| Shell scripts | `scripts/polaris-<verb>.sh` | Whoever the header names: an operator, CI, or a contributor |
| Python helpers | `scripts/polaris_<name>.py` | The shell script that shells out to them |

One prefix, because the reader of a script is stated in its header rather than
encoded in its name. The `ai-` prefix the fleet carried until v9.222 said who
wrote the script, which is not information anyone running it needs.

**Rule:** every script's first comment block (after shebang) is
the doc-comment. Format:

```bash
#!/bin/bash
# =============================================================================
# scripts/<name>.sh: <one-line purpose>
#
# <multi-paragraph context>
#
# Usage:
#     <name>.sh [--flag] [--another-flag VALUE]
#
# Exit codes:
#   0  success
#   2  usage error
#   3  <specific failure>
# =============================================================================
```

Exit codes are NAMED in the script body:
```bash
EXIT_OK=0
EXIT_USAGE=2
EXIT_SHA_MISMATCH=4
```

---

## 4. Python package layout

```
polaris_<domain>/
├── README.md                # required
├── __init__.py              # may be empty; package marker
├── <module>.py              # one module per concept; lowercase + _-separated
└── <subpkg>/
    ├── README.md            # required for any subpkg
    ├── __init__.py
    └── <module>.py
```

**Rules:**
- Every top-level package has a README.md
- Every subpkg has a README.md
- `test_<module>.py` is colocated with the module under test (or
  cross-referenced in the module's docstring if not)

---

## 5. SQL files

`polaris_sql/` follows the `NN_<purpose>.sql` numeric prefix
convention so `00_load_all.sql` can `\i` them in order:

```
00_migrations_table.sql       # FIRST: the schema_version registry (v8.95)
00_load_all.sql               # entry point: \i each file in order
01_schema.sql                 # DDL (tables + constraints)
02_indexes.sql                # indexes (incl. R10-2/R11-* indexes)
03_view.sql                   # views
04_data.sql                   # sample data
05_procedures.sql             # UC-1..UC-12 + helpers
06_triggers.sql               # append-only + state-machine triggers
07_queries.sql                # analytical queries
08_tests.sql                  # SQL self-tests (sections A-R)
09_grants.sql                 # role + grants
10_auth.sql                   # AppUser + auth seed
11_atlas.sql                  # v6 atlas + filter functions
12_v7_constraints.sql         # v7 schema-hardening
13_postgis.sql                # optional-dependency PostGIS
13_substrate.sql              # SystemDependency view (M2-3)

migrations/                   # paired up/down per v8.95 framework
├── README.md
└── <YYYY-MM-DD-NNN-slug>.{up,down}.sql
```

---

## 6. Test files

| Path | Scope |
|---|---|
| `polaris_web/test_app.py` | App-level + route tests |
| `polaris_web/test_check_constraints.py` | SQL CHECK constraint regression |
| `polaris_web/test_invariants_property.py` | Hypothesis property tests (C1/C2/C3) |
| `polaris_web/test_redaction_property.py` | M2-12 redaction-proof property tests |
| `polaris_web/test_e2e_atlas.py` | End-to-end atlas route tests |
| `polaris_web/test_zk_second_witness.py` | ZK second-witness parity tests |
| `polaris_cli/test_cli.py` | CLI tests |
| `polaris_checks/test_checks.py` | C1-C10 check detection-correctness tests |

**Test class naming:** `TestPascalCaseDescriptor`. For per-ship
invariants: `Test<ShipID><ShipFeatureName>`.

**Test function naming:** `test_snake_case_descriptor`.

---

## 8. CHANGELOG entries

`CHANGELOG.md` at repo root. New entries at TOP of file (newest first). The root file
holds recent ships only; older entries live in `docs/history/CHANGELOG-v<major>.md`,
moved unchanged and never edited.

**Header format:**
```markdown
## v<N.NN>: <YYYY-MM-DD> (<one-line title with sections separated by ·>)
```

**Body sections** (when applicable):
- **Why this ship:** the directive that triggered it
- Per-item subsections describing the change
- **Constitutional preservation** verified
- **Live drill** verified
- `POLARIS_VERSION` bump line

Old CHANGELOG entries are never edited retroactively. Corrections land
as new entries cross-referencing the prior.

---

## 9. Versioning

`POLARIS_VERSION` lives in [`polaris_web/__version__.py`](../polaris_web/__version__.py)
(canonical source as of v9.06 / C5). Format: `MAJOR.MINOR` (e.g., `9.08`).

**Bump procedure** (the ship discipline in [`../CLAUDE.md`](../CLAUDE.md)):
1. Edit the `__version__` literal and `appVersion` in `deploy/helm/polaris/Chart.yaml`
2. Prepend the CHANGELOG entry
3. Run `python3 -m polaris_checks.run`, then `scripts/polaris-preflight.sh` (must report READY)

---

## 10. Documentation cross-references

**Markdown links must resolve.** `bash scripts/polaris-link-check.sh`
walks every Markdown link of shape `[text]` followed by `(path)` and
confirms target exists. CI runs this on every push.

**Cross-references prefer relative paths:**
- `[X](../meta/constraint-lattice.md)`: relative ✓
- `[X](/Users/vanta/Desktop/polaris/meta/constraint-lattice.md)`: absolute ✗
- `[X](https://github.com/.../meta/constraint-lattice.md)`, URL ✗ (would
  rot when fork count grows)

**Cross-arc references are typed:**
- "v8.95 (CHANGELOG): schema migration framework"
- "v9.04 / Wave 1 / A1": for ship + wave + item identification

---

## 11. Em-dashes

**Forbidden in prose** across every human-facing surface: the root
documents, `docs/`, `DEVNOTES/`, `meta/`, the package READMEs, `site/`,
`deploy/`, and the application's templates and messages. This is a project
standard (see [`../DEVNOTES/style.md`](../DEVNOTES/style.md)); the
`em-dash-block-new` pre-commit hook rejects a commit that adds one.

**Allowed exceptions:**
- CHANGELOG entries (the audit of record is never edited retroactively)
- Verbatim records: `DEVNOTES/record.md`, `DEVNOTES/ships/`, the
  machine-written `docs/operator/DR-DRILLS.md`, and the frozen section of
  MISSION.md
- Direct quotes from external sources

**Substitutes:** `:` (colon), `,` (comma), `(` `)` (parens),
sentence break.

---

## 12. Comments + docstrings

**Code comments default to none.** Only add a comment when the WHY
is non-obvious: a hidden constraint, a subtle invariant, a
workaround for a specific bug, behavior that would surprise a
reader.

**Don't:**
- Explain what the code does (the code does that)
- Reference the current task ("added for the X flow")
- Reference callers ("used by module Y")

**Do:**
- Reference the constitutional source ("per C2, zero-knowledge")
- Name the surprising-to-a-reader fact ("SET LOCAL evaporates at
  COMMIT; that is the intentional carve-out closure")

---

## 13. Backwards-compat removals

**When deleting code that may have callers:**

1. Add a CHANGELOG entry under the deletion ship
2. Add a `check_*` to `polaris_checks/checks.py` pinning the deletion
   if the deletion is itself load-bearing
3. Never silently delete from the CHANGELOG; it is the audit of record

---

## 14. Where these conventions live

This file (`docs/CONVENTIONS.md`) is the single source of truth.
Changes happen here, then propagate by reference. Other docs that
mention conventions cross-reference here rather than redefining.

For the project-wide architecture map, see [`reference/SYSTEM-MAP.md`](reference/SYSTEM-MAP.md);
for the constitution beneath these conventions, [`../MISSION.md`](../MISSION.md).
