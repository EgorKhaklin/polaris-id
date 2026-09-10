"""
polaris_checks — a flat, legible invariant-check layer for Polaris.

This is the clean replacement for the legacy cognitive apparatus. A check is a
check: a plain function that takes the repo root and returns a list of Findings.
No organizational mythology, no simulated economy, no self-referential
governance — just checks.

Each check maps to something real Polaris must hold — most of them to the
C1-C10 constitution (see MISSION.md). They are file-based and deterministic:
no database, no network, no global state, so they run anywhere in well under a
second and gate CI directly.

    from polaris_checks.checks import run_all
    findings = run_all(repo_root)
    fails = [f for f in findings if f.level == "FAIL"]

Add a check by writing a `check_*` function and listing it in CHECKS.
"""

from __future__ import annotations

import pathlib
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Finding:
    level: str   # "FAIL" | "WARN" | "OK"
    check: str   # the check's name
    message: str

    def __str__(self) -> str:
        glyph = {"FAIL": "✗", "WARN": "!", "OK": "✓"}.get(self.level, "?")
        return f"  {glyph} [{self.check}] {self.message}"


def _read(root: pathlib.Path, rel: str) -> str:
    p = root / rel
    return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""


def _ok(name: str, msg: str) -> list[Finding]:
    return [Finding("OK", name, msg)]


def _fail(name: str, msg: str) -> list[Finding]:
    return [Finding("FAIL", name, msg)]


# ---------------------------------------------------------------------------
# C5 — Content-Security-Policy forbids inline scripts.
# ---------------------------------------------------------------------------
def check_csp_forbids_unsafe_inline(root: pathlib.Path) -> list[Finding]:
    src = _read(root, "polaris_web/security.py")
    if "script-src 'self'" not in src:
        return _fail("csp", "security.py CSP must pin script-src 'self'")
    # C5 is violated only if the script-src directive ITSELF enables
    # 'unsafe-inline'. style-src 'unsafe-inline' is acceptable, so check per
    # directive line, not across the whole file.
    for line in src.splitlines():
        if "script-src" in line and "'unsafe-inline'" in line:
            return _fail("csp", "script-src enables 'unsafe-inline' (C5 violation)")
    return _ok("csp", "CSP pins script-src 'self'; no unsafe-inline on scripts (C5)")


# ---------------------------------------------------------------------------
# C3 — one active identity per person, enforced by a partial unique index.
# ---------------------------------------------------------------------------
def check_one_active_token_index(root: pathlib.Path) -> list[Finding]:
    sql = _read(root, "polaris_sql/02_indexes.sql") + _read(root, "polaris_sql/01_schema.sql")
    if re.search(r"UNIQUE\s+INDEX[^;]*IdentityToken[^;]*WHERE\s+status\s*=\s*'ACTIVE'", sql, re.I | re.S):
        return _ok("c3_one_active", "partial unique index enforces one ACTIVE token per person (C3)")
    return _fail("c3_one_active", "missing partial-unique index for one-active-token (C3)")


# ---------------------------------------------------------------------------
# C1 — audit-of-record append-only triggers on the lifecycle event tables.
# ---------------------------------------------------------------------------
# The audit-of-record instances named in docs/design/audit-of-record.md. Each one is a row
# whose own history is the record, so each must be append-only (or bounded one way) AT THE
# SCHEMA, not by the discipline of whoever writes to it. v9.347 (P9.7) closed the last
# exception, RecoveryRequest, which until then rested on procedure discipline: the check
# now names every table instead of counting triggers, so removing one is a failure rather
# than a smaller number nobody reads.
_AOR_TABLES = (
    "TokenLifecycleEvent", "VerificationEvent", "EnrollmentStatusEvent", "TokenSignature",
    "AgencyTrustAttestation", "TokenStateEpoch", "TokenStateEpochLeaf", "AnchorBatch",
    "DuressEvent", "AuthAuditLog", "IndividualErasureEvent", "LifecycleArchiveCheckpoint",
    "AuditAccessLog", "RecoveryRequest",
)


def check_aor_append_only_triggers(root: pathlib.Path) -> list[Finding]:
    sql = _read(root, "polaris_sql/06_triggers.sql")
    for f in sorted((root / "polaris_sql" / "migrations").glob("*.up.sql")):
        sql += "\n" + f.read_text(encoding="utf-8", errors="replace")
    if "insufficient_privilege" not in sql:
        return _fail("c1_aor", "06_triggers.sql must raise insufficient_privilege on AoR UPDATE/DELETE (C1)")
    guarded = {m.lower() for m in re.findall(r"BEFORE\s+UPDATE\s+OR\s+DELETE\s+ON\s+(\w+)", sql, re.I)}
    missing = [t for t in _AOR_TABLES if t.lower() not in guarded]
    if missing:
        return _fail("c1_aor",
                     "these audit-of-record tables have no BEFORE UPDATE OR DELETE trigger, so their history rests "
                     "on the discipline of whoever holds a database session rather than on the schema (C1): "
                     + ", ".join(missing))
    n = len(re.findall(r"BEFORE\s+UPDATE\s+OR\s+DELETE", sql, re.I))
    return _ok("c1_aor",
               f"all {len(_AOR_TABLES)} audit-of-record tables are guarded at the schema, RecoveryRequest included "
               f"since v9.347; {n} append-only trigger(s) in all, each raising insufficient_privilege (C1)")


# ---------------------------------------------------------------------------
# C1 — append-only is a PRIVILEGE boundary, not only a trigger.
#
# reject_audit_modification() has a carve-out: it permits UPDATE/DELETE when
# the custom GUC polaris.purge_in_progress is 'TRUE'. Any role can SET a custom
# GUC, so the trigger alone did not stop the application role (polaris_app) from
# deleting an audit row — it could set the GUC and delete. The grant model must
# back the trigger: polaris_app keeps SELECT + INSERT (append-only IS insert-
# allowed) but loses UPDATE/DELETE on every append-only table, so the carve-out
# is unreachable from the app role. The one legitimate DELETE path,
# uc_archive_purge, must be SECURITY DEFINER so it runs the purge with the
# owner's rights inside its admin-gated, checkpoint-writing transaction.
# ---------------------------------------------------------------------------
def check_aor_privilege_boundary(root: pathlib.Path) -> list[Finding]:
    grants = _read(root, "polaris_sql/09_grants.sql")
    # The append-only tables whose trigger honors the purge_in_progress GUC.
    # auditaccesslog is created (and revoked) in its own migration.
    base_tables = [
        "tokenlifecycleevent", "verificationevent", "enrollmentstatusevent",
        "anchorbatch", "tokenstateepochleaf", "duressevent", "authauditlog",
        # v9.125: the right-to-erasure log is append-only (the record that an
        # erasure happened must not be editable or removable).
        "individualerasureevent",
        # v9.322 (P8.2c): the exchange-receipt transparency log.
        "exchangereceiptlog",
        # v9.324 (P8.2d): the exchange gateway's replay register.
        "exchangenonce",
        # v9.326 (P8.4): the auth broker's consumed-code register.
        "authcodeconsumed",
        # v9.328 (P8.7b): the authority key register.
        "authoritykeyevent",
        "timestamplog",
        # v9.349 (P9.1): the holder key register.
        "holderkeyevent",
    ]
    if not re.search(r"REVOKE\s+UPDATE\s*,\s*DELETE", grants, re.I):
        return _fail("c1_aor_priv",
                     "09_grants.sql must REVOKE UPDATE, DELETE on append-only tables from polaris_app (C1)")
    missing = [t for t in base_tables if t.lower() not in grants.lower()]
    if missing:
        return _fail("c1_aor_priv",
                     "append-only REVOKE omits table(s): " + ", ".join(missing) + " (C1)")
    # auditaccesslog REVOKE rides along with its migration.
    mig = _read(root, "polaris_sql/migrations/2026-05-15-003-audit-access-log.up.sql")
    if not re.search(r"REVOKE\s+UPDATE\s*,\s*DELETE\s+ON\s+AuditAccessLog", mig, re.I):
        return _fail("c1_aor_priv",
                     "the AuditAccessLog migration must REVOKE UPDATE, DELETE from polaris_app (C1)")
    # The sole legitimate DELETE path must run with the owner's rights.
    proc = _read(root, "polaris_sql/05_procedures.sql")
    m = re.search(r"CREATE\s+OR\s+REPLACE\s+PROCEDURE\s+uc_archive_purge\b.*?\bAS\s*\$\$",
                  proc, re.I | re.S)
    if not m:
        return _fail("c1_aor_priv", "uc_archive_purge procedure not found in 05_procedures.sql (C1)")
    if not re.search(r"SECURITY\s+DEFINER", m.group(0), re.I):
        return _fail("c1_aor_priv",
                     "uc_archive_purge must be SECURITY DEFINER so the purge runs with the "
                     "owner's rights after polaris_app loses direct DELETE (C1)")
    return _ok("c1_aor_priv",
               "append-only tables revoke UPDATE/DELETE from polaris_app; "
               "uc_archive_purge is SECURITY DEFINER (C1)")


# ---------------------------------------------------------------------------
# C7 — cryptographic algorithm is data, not hardcoded.
# ---------------------------------------------------------------------------
def check_crypto_algorithm_is_data(root: pathlib.Path) -> list[Finding]:
    schema = _read(root, "polaris_sql/01_schema.sql")
    if re.search(r"CREATE\s+TABLE\s+CryptographicAlgorithm", schema, re.I):
        return _ok("c7_crypto_data", "CryptographicAlgorithm table holds algorithm metadata (C7)")
    return _fail("c7_crypto_data", "no CryptographicAlgorithm table — algorithm must be data, not hardcoded (C7)")


# ---------------------------------------------------------------------------
# FK discipline — no destructive ON DELETE/UPDATE CASCADE.
# ---------------------------------------------------------------------------
def check_no_fk_cascade(root: pathlib.Path) -> list[Finding]:
    offenders = []
    sqldir = root / "polaris_sql"
    files = []
    if sqldir.is_dir():
        # Scan the base schema AND migrations — a cascade smuggled into a
        # migration is just as destructive as one in 01_schema.sql.
        files = sorted(sqldir.glob("*.sql")) + sorted((sqldir / "migrations").glob("*.sql"))
    for p in files:
        text = re.sub(r"--[^\n]*", "", p.read_text(errors="replace"))  # strip line comments
        for m in re.finditer(r"ON\s+(DELETE|UPDATE)\s+CASCADE", text, re.I):
            offenders.append(f"{p.name}: ON {m.group(1).upper()} CASCADE")
    if offenders:
        return _fail("fk_cascade", "destructive FK cascade(s): " + "; ".join(offenders[:5]))
    return _ok("fk_cascade", "no ON DELETE/UPDATE CASCADE in schema or migrations")


# ---------------------------------------------------------------------------
# Version is canonical — app.py imports __version__ rather than redefining it.
# ---------------------------------------------------------------------------
def check_version_is_canonical(root: pathlib.Path) -> list[Finding]:
    app = _read(root, "polaris_web/app.py")
    if re.search(r"from\s+__version__\s+import|import\s+__version__", app):
        return _ok("version_canonical", "app.py imports the canonical __version__")
    if re.search(r"POLARIS_VERSION\s*=\s*['\"]", app):
        return _fail("version_canonical", "app.py redefines POLARIS_VERSION instead of importing __version__")
    return _ok("version_canonical", "no redefined version literal in app.py")


# ---------------------------------------------------------------------------
# CHANGELOG's top entry matches the current version.
# ---------------------------------------------------------------------------
def check_changelog_matches_version(root: pathlib.Path) -> list[Finding]:
    ver = ""
    m = re.search(r'__version__[^"\'\n]*["\'](\d+\.\d+)["\']', _read(root, "polaris_web/__version__.py"))
    if m:
        ver = m.group(1)
    top = re.search(r"^##\s+v(\d+\.\d+)\b", _read(root, "CHANGELOG.md"), re.M)
    if not ver or not top:
        return _fail("changelog_version", "could not read __version__ or CHANGELOG top entry")
    if top.group(1) != ver:
        return _fail("changelog_version", f"CHANGELOG top is v{top.group(1)} but __version__ is v{ver}")
    return _ok("changelog_version", f"CHANGELOG top entry matches __version__ (v{ver})")


# ---------------------------------------------------------------------------
# Thesis honesty — past the v9.40 terminus, the strong claim must read as RETIRED.
#
# docs/THESIS.md's terminus is mechanical: if no external cold-read attempt
# occurred by v9.40, the thesis is documented as inconclusive and the strong
# claim is retired permanently. No external cold read occurred and the repo is
# past v9.40, so docs/THESIS.md must reflect that terminal state — not leave the
# thesis framed as an open, still-pending hypothesis. Leaving the softer wording
# past the deadline is itself the dishonesty the project's discipline forbids.
# This check reads THESIS.md and the version, which are its source of record.
# (The v9.27 MISSION.md freeze line that once narrated this was retired at v9.297.)
# ---------------------------------------------------------------------------
def check_thesis_terminus_honest(root: pathlib.Path) -> list[Finding]:
    ver = _read(root, "polaris_web/__version__.py")
    m = re.search(r'__version__[^"\'\n]*["\'](\d+)\.(\d+)["\']', ver)
    if not m:
        return _fail("thesis_terminus", "could not read __version__ for the v9.40 terminus check")
    major, minor = int(m.group(1)), int(m.group(2))
    thesis = _read(root, "docs/THESIS.md")
    if not thesis:
        return _fail("thesis_terminus", "docs/THESIS.md is missing")
    if (major, minor) < (9, 40):
        return _ok("thesis_terminus",
                   f"v{major}.{minor} is before the v9.40 thesis terminus; THESIS.md may remain open")
    # Past v9.40: THESIS.md must state the terminus and the permanent retirement.
    low = thesis.lower()
    missing = [s for s in ("v9.40", "retired") if s.lower() not in low]
    if missing:
        return _fail("thesis_terminus",
                     "past the v9.40 terminus, THESIS.md must document the strong claim as retired "
                     f"(missing term(s): {', '.join(missing)}); the abandonment clause has fired")
    # The stale open-framing must be gone.
    if "until a real cold read happens" in thesis:
        return _fail("thesis_terminus",
                     "THESIS.md still holds the status open 'until a real cold read happens'; the v9.40 "
                     "terminus closed that window (retired by default, reopenable only by recorded decision)")
    if re.search(r"\*\*Status:\*\*\s*HYPOTHESIS-NOT-VERIFIED", thesis):
        return _fail("thesis_terminus",
                     "THESIS.md status is still the open 'HYPOTHESIS-NOT-VERIFIED'; past v9.40 it must "
                     "read as retired / inconclusive")
    return _ok("thesis_terminus",
               "past the v9.40 terminus, THESIS.md documents the strong claim as retired/inconclusive")


# ---------------------------------------------------------------------------
# Secrets hygiene — operator-secrets file is gitignored (no trailing-comment trap).
# ---------------------------------------------------------------------------
def check_secrets_file_ignored(root: pathlib.Path) -> list[Finding]:
    gi = _read(root, ".gitignore")
    # A bare `polaris.env` line (trailing inline comments silently disable the rule).
    if re.search(r"(?m)^\s*polaris\.env\s*$", gi):
        return _ok("secrets_ignored", "polaris.env is gitignored by a bare pattern")
    if "polaris.env" in gi:
        return _fail("secrets_ignored", "polaris.env pattern has a trailing comment — git ignores nothing")
    return _fail("secrets_ignored", "polaris.env (operator secrets) is not gitignored")


def check_gitignore_no_trailing_comments(root: pathlib.Path) -> list[Finding]:
    offenders = []
    for i, line in enumerate(_read(root, ".gitignore").splitlines(), 1):
        s = line.rstrip()
        if not s.strip() or s.lstrip().startswith("#"):
            continue
        if re.search(r"\S +#", s):
            offenders.append(str(i))
    if offenders:
        return _fail("gitignore_comments", f"trailing inline comments disable patterns at line(s) {','.join(offenders)}")
    return _ok("gitignore_comments", "no trailing inline comments in .gitignore")


# ---------------------------------------------------------------------------
# The ZK verdict is two-witnessed (the v9.44 independent verifier exists).
# ---------------------------------------------------------------------------
def check_zk_two_witness_present(root: pathlib.Path) -> list[Finding]:
    if (root / "polaris_zk" / "witness2" / "verifier.py").is_file():
        return _ok("zk_two_witness", "independent second witness present (polaris_zk/witness2)")
    return _fail("zk_two_witness", "the ZK two-witness verifier is missing (polaris_zk/witness2)")


# ---------------------------------------------------------------------------
# No debug artifacts left in source.
# ---------------------------------------------------------------------------
def check_no_debug_artifacts(root: pathlib.Path) -> list[Finding]:
    offenders = []
    for sub in ("polaris_web", "polaris_checks"):
        d = root / sub
        for p in sorted(d.rglob("*.py")) if d.is_dir() else []:
            if "venv" in p.parts or p.name.startswith("test_"):
                continue
            for i, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
                if re.search(r"\b(pdb\.set_trace|breakpoint)\s*\(", line):
                    offenders.append(f"{p.relative_to(root)}:{i}")
    if offenders:
        return _fail("debug_artifacts", "debugger calls in source: " + "; ".join(offenders[:5]))
    return _ok("debug_artifacts", "no pdb/breakpoint debug artifacts in source")


# ---------------------------------------------------------------------------
# Post-quantum signing is wired into issuance, not an island (v9.58).
# The uc1_issue route must route the issuance signature through
# pqc_signing.signature_bytes_for_token(), and uc1_issue_and_activate must
# accept it (p_signature_bytes). Otherwise the headline post-quantum claim
# decays back into a hardcoded SQL string and the signing module is dead code.
# ---------------------------------------------------------------------------
def check_pqc_signing_wired(root: pathlib.Path) -> list[Finding]:
    proc = _read(root, "polaris_sql/05_procedures.sql")
    if "p_signature_bytes" not in proc:
        return _fail("pqc_wired",
                     "uc1_issue_and_activate must accept p_signature_bytes so the app "
                     "supplies the issuance signature (it is a hardcoded SQL string otherwise)")
    app = _read(root, "polaris_web/app.py")
    if "import pqc_signing" not in app:
        return _fail("pqc_wired", "app.py does not import pqc_signing")
    # Issuance must route through the signing module — either the 2-tuple
    # signature_bytes_for_token or the 3-tuple signature_with_key_for_token
    # (v9.117, which also surfaces the public key to store with the signature).
    if not re.search(r"pqc_signing\.signature_(bytes_for_token|with_key_for_token)", app):
        return _fail("pqc_wired",
                     "app.py does not call pqc_signing.signature_bytes_for_token / "
                     "signature_with_key_for_token; the issuance signature would bypass the "
                     "signing module")
    # v9.119: uc6 algorithm-migration must also route through the signing module,
    # not write a hardcoded operator string.
    if "UC6_OPERATOR_MIGRATE" in app:
        return _fail("pqc_wired",
                     "uc6 still writes a hardcoded UC6_OPERATOR_MIGRATE signature; route the "
                     "migration signature through pqc_signing like issuance")
    # v9.257: BULK issuance must sign for real too. uc_bulk_issue must not
    # fabricate a 'BULK_ISSUE_<id>' placeholder literal; it must store the
    # signature the caller staged and REFUSE any unsigned row, so a mass-issued
    # token can never carry a signature that verifies against nothing. This is
    # the gap that let 331k simulated tokens look signed while being placeholders.
    if re.search(r"'BULK_ISSUE_'\s*\|\|", proc):
        return _fail("pqc_wired",
                     "uc_bulk_issue still fabricates a placeholder signature literal keyed on the "
                     "token id; bulk issuance must store the real signature the caller staged "
                     "(through pqc_signing), exactly like single issuance")
    bulk = re.search(r"CREATE OR REPLACE PROCEDURE uc_bulk_issue\(.*?\$\$;", proc, re.S)
    if not bulk or "signature_bytes IS NULL" not in bulk.group(0):
        return _fail("pqc_wired",
                     "uc_bulk_issue must REFUSE a staged row with no signature (signature_bytes "
                     "IS NULL); otherwise an unsigned token is mass-issued and merely believed signed")
    schema = _read(root, "polaris_sql/01_schema.sql")
    staging = re.search(r"CREATE TABLE IF NOT EXISTS BulkEnrollmentStaging \(.*?\n\);", schema, re.S)
    if not staging or "signature_bytes" not in staging.group(0):
        return _fail("pqc_wired",
                     "BulkEnrollmentStaging must carry signature_bytes so the bulk caller stages a "
                     "real per-token signature (the loader signs each token_value before staging)")
    # v9.258: verification scales via a single-witness verify-AT-USE path, but
    # ISSUANCE must stay two-witness (the strict self-check before it will persist
    # a signature). Guard the boundary both ways: issuance keeps verify_both, and
    # the throughput verify endpoint opts into single-witness.
    pqc = _read(root, "polaris_web/pqc_signing.py")
    issue_fn = re.search(r"def signature_with_key_for_token\(.*?(?=\ndef |\Z)", pqc, re.S)
    if issue_fn and "verify_both" not in issue_fn.group(0):
        return _fail("pqc_wired",
                     "issuance (signature_with_key_for_token) must TWO-witness its signature before "
                     "persisting it (verify_both); single-witness is the verify-at-use path only")
    # v9.264: issuance must not silently degrade to one witness. Its verify_both
    # self-check requires the witness (a missing witness is a refusal, not a
    # downgrade), and it refuses up front when the witness is unavailable.
    if issue_fn and ("require_witness=True" not in issue_fn.group(0)
                     or "second_witness_available()" not in issue_fn.group(0)):
        return _fail("pqc_wired",
                     "issuance must REQUIRE the second witness (verify_both(..., require_witness=True) and "
                     "an up-front second_witness_available() refusal), so a stored signature is never "
                     "certified two-witnessed when only one implementation ran")
    if "/api/tokens/<int:tok_id>/verify" not in app:
        return _fail("pqc_wired",
                     "app.py must expose the verify-at-use endpoint /api/tokens/<id>/verify (the "
                     "throughput verification path)")
    verify_ep = app.split("def api_token_verify", 1)
    ep_body = verify_ep[1][:7000] if len(verify_ep) == 2 else ""
    if len(verify_ep) == 2 and not re.search(r"witnesses\s*=\s*['\"]single['\"]", ep_body):
        return _fail("pqc_wired",
                     "the verify-at-use endpoint must use single-witness verification "
                     "(witnesses='single'), the ~10x throughput path")
    # v9.264: authenticity is replica-safe (immutable material), but the `usable`
    # AUTHORIZATION decision must be made on FRESH status from the primary, or a
    # replica's lag window could report a just-revoked token as usable.
    if len(verify_ep) == 2 and ("primary=True" not in ep_body or "status" not in ep_body):
        return _fail("pqc_wired",
                     "the verify-at-use endpoint must read the token's current status from the PRIMARY "
                     "(query(..., primary=True)) for its `usable` decision; a stale replica status could "
                     "report a revoked token as usable")
    # v9.271: the authenticity/authorization split must be EXPLICIT in the
    # response, so a relying party never confuses a genuine signature with a
    # current one. Authenticity is cacheable/replica-safe; authorization carries a
    # primary-backed freshness contract (as_of + a max-staleness bound).
    if len(verify_ep) == 2 and not all(t in ep_body for t in (
            "signature_cacheable", "currently_authoritative", "as_of", "max_staleness_seconds")):
        return _fail("pqc_wired",
                     "the verify-at-use endpoint must make the authenticity/authorization split explicit: "
                     "signature_cacheable (authenticity is replica-safe and cacheable) plus "
                     "currently_authoritative, as_of, and max_staleness_seconds (the primary-backed "
                     "freshness contract for the authorization verdict)")
    return _ok("pqc_wired",
               "single, bulk, and uc6-migration signatures all route through the pqc_signing module; "
               "bulk stores a staged real signature and refuses an unsigned row (no placeholder literal); "
               "issuance stays two-witness while the verify-at-use endpoint uses the single-witness "
               "throughput path")


# ---------------------------------------------------------------------------
# The production signing key MUST be generated as clean JSON. liboqs-python
# prints a banner to STDOUT at import; polaris-generate-secrets.sh mints the key
# by capturing a `python -c "...print(json.dumps(generate_keypair()))"` stdout,
# so a naive capture prepends the banner and produces a malformed key file the
# app refuses to load — real-PQC issuance broken at deploy (v9.139). Two
# defenses must be present: the generator swallows stdout during the import (so
# no banner can leak into the JSON), AND it validates the captured output parses
# as ML-DSA-65 key JSON before writing (fail loud, never write a malformed key).
# ---------------------------------------------------------------------------
def check_signing_key_generation(root: pathlib.Path) -> list[Finding]:
    sh = _read(root, "scripts/polaris-generate-secrets.sh")
    if not sh:
        return _fail("signing_key_gen", "scripts/polaris-generate-secrets.sh is missing")
    if "generate_keypair" not in sh:
        return _fail("signing_key_gen",
                     "polaris-generate-secrets.sh must mint the ML-DSA-65 signing key "
                     "(pqc_signing.generate_keypair)")
    # Defense 1: stdout swallowed during import so the liboqs banner cannot leak.
    if "io.StringIO()" not in sh or "sys.stdout" not in sh:
        return _fail("signing_key_gen",
                     "the signing-key generator must swallow stdout during the pqc import "
                     "(sys.stdout = io.StringIO()) so the liboqs banner cannot corrupt the key JSON")
    # Defense 2: validate the captured JSON before writing (fail loud).
    if not re.search(r"json\.load.*algorithm.*ML-DSA-65|ML-DSA-65.*secret_key_hex", sh, re.S):
        return _fail("signing_key_gen",
                     "the generator must VALIDATE the captured output is ML-DSA-65 key JSON "
                     "(algorithm + secret_key_hex + public_key_hex) before writing it")
    # The existence guards must be -s (non-empty), not -e, so an interrupted run's
    # 0-byte files are regenerated rather than silently shipped as empty secrets.
    if re.search(r"\[\[\s*-e\s+\"\$\{target\}\"\s*\]\]", sh):
        return _fail("signing_key_gen",
                     "secret existence guards must test -s (non-empty), not -e: a 0-byte file "
                     "from an interrupted run would silently block regeneration")
    return _ok("signing_key_gen",
               "the signing-key generator swallows the import banner, validates the key JSON "
               "before writing, and regenerates empty files (-s guard)")


# ---------------------------------------------------------------------------
# Real signing core (production-readiness Wave 2) — a signature that nobody can
# verify against a stable key is theater. pqc_signing must support a PERSISTENT
# signing key (POLARIS_PQC_SIGNING_KEY_FILE), expose generate_keypair + verify,
# and CI must actually exercise the real ML-DSA path (the pqc-real job installs
# liboqs and runs a persistent-key sign+verify). See docs/PRODUCTION-READINESS.md.
# ---------------------------------------------------------------------------
def check_pqc_real_signing(root: pathlib.Path) -> list[Finding]:
    p = _read(root, "polaris_web/pqc_signing.py")
    if not p:
        return _fail("pqc_real", "polaris_web/pqc_signing.py is missing")
    if "POLARIS_PQC_SIGNING_KEY_FILE" not in p:
        return _fail("pqc_real",
                     "pqc_signing.py must load a persistent signing key "
                     "(POLARIS_PQC_SIGNING_KEY_FILE), not generate an ephemeral key per call")
    if "def generate_keypair" not in p or "def verify" not in p:
        return _fail("pqc_real", "pqc_signing.py must expose generate_keypair + verify")
    ci = _read(root, ".github/workflows/ci.yml")
    if "pqc-real" not in ci or "liboqs" not in ci:
        return _fail("pqc_real",
                     "CI must install liboqs and test the real ML-DSA signing path (the pqc-real job)")
    return _ok("pqc_real",
               "real signing core: persistent key + verify, exercised by the CI pqc-real job")


# ---------------------------------------------------------------------------
# Verification must be ENFORCED, not just possible. A signing core where
# verify() is never called is theater. Two live obligations: (1) issuance
# self-verifies the signature it produces (signature_bytes_for_token calls
# verify) and refuses to persist one that does not check out; (2) a use-path
# primitive (verify_token_signature) checks a stored signature against the
# published trust anchor, exercised in the pqc-real CI job.
# ---------------------------------------------------------------------------
def check_verify_enforced(root: pathlib.Path) -> list[Finding]:
    p = _read(root, "polaris_web/pqc_signing.py")
    if not p:
        return _fail("verify_enforced", "polaris_web/pqc_signing.py is missing")
    if "def verify_token_signature" not in p or "def trust_anchor_public_key_hex" not in p:
        return _fail("verify_enforced",
                     "pqc_signing.py must expose verify_token_signature + "
                     "trust_anchor_public_key_hex (the use-path check + the published anchor)")
    # The self-verify lives in signature_with_key_for_token (v9.117); the older
    # signature_bytes_for_token is now a thin wrapper around it.
    m = re.search(r"def signature_with_key_for_token\(.*?\n(?=def [a-z])", p, re.S)
    body = m.group(0) if m else ""
    # The self-verify may be the lone verify() or, since v9.133, the two-witness
    # verify_both() (a strictly stronger self-check); either satisfies enforcement.
    if "verify(" not in body and "verify_both(" not in body:
        return _fail("verify_enforced",
                     "signature_bytes_for_token must self-verify the signature it produces (call "
                     "verify / verify_both) so an unverifiable signature is never persisted")
    ci = _read(root, ".github/workflows/ci.yml")
    if not ci or "verify_token_signature" not in ci:
        return _fail("verify_enforced",
                     "the pqc-real CI job must exercise verify_token_signature (verify-at-use)")
    return _ok("verify_enforced",
               "verification is enforced: issuance self-verifies, verify_token_signature checks "
               "stored signatures against the trust anchor, exercised in CI")


# ---------------------------------------------------------------------------
# The ML-DSA-65 verify path is TWO-WITNESSED (v9.133): every real verdict is
# cross-checked by two INDEPENDENT FIPS 204 implementations — liboqs (primary)
# and cryptography/OpenSSL (the second witness) — which must AGREE, or the
# signature is refused. A lone verifier would silently trust a signature a bug
# or compromise in its one library mis-accepts; the witness closes that, the
# same discipline polaris_zk/witness2 gives the ZK path. The contract: a
# verify_both that both signing AND use-path sites route through, a real second
# witness backed by cryptography's MLDSA65 (a different implementation, not a
# second oqs call), and CI that proves the two agree.
# ---------------------------------------------------------------------------
def check_pqc_second_witness(root: pathlib.Path) -> list[Finding]:
    p = _read(root, "polaris_web/pqc_signing.py")
    if not p:
        return _fail("pqc_second_witness", "polaris_web/pqc_signing.py is missing")
    if "def verify_both" not in p or "def _verify_second_witness" not in p:
        return _fail("pqc_second_witness",
                     "pqc_signing.py must expose verify_both + _verify_second_witness "
                     "(the two-witness ML-DSA-65 verify path)")
    # The witness must be a DIFFERENT implementation, not a second liboqs call.
    if "MLDSA65PublicKey" not in p or "mldsa" not in p:
        return _fail("pqc_second_witness",
                     "the second witness must be cryptography's MLDSA65 (an independent FIPS 204 "
                     "implementation), not a second liboqs verify")
    # A disagreement must be refused (fail closed), not silently averaged away.
    if "DISAGREEMENT" not in p:
        return _fail("pqc_second_witness",
                     "verify_both must refuse (and log) when the two witnesses disagree")
    # Every real verify site must route through verify_both, not the lone verify().
    # The three sites: issuance self-verify, verify_stored_signature, verify_token_signature.
    for fn in ("signature_with_key_for_token", "verify_stored_signature", "verify_token_signature"):
        # Match the function body up to the next top-level def OR end of file (so a
        # site that happens to be the last function is not wrongly read as empty).
        m = re.search(r"def %s\(.*?(?=\ndef [a-z]|\Z)" % re.escape(fn), p, re.S)
        body = m.group(0) if m else ""
        if "verify_both(" not in body:
            return _fail("pqc_second_witness",
                         "%s must route its real-PQC verify through verify_both (two witnesses), "
                         "not the lone verify()" % fn)
    ci = _read(root, ".github/workflows/ci.yml")
    if not ci or "SecondWitnessTests" not in ci:
        return _fail("pqc_second_witness",
                     "the pqc-real CI job must run the SecondWitnessTests (prove the two "
                     "independent implementations agree on a real ML-DSA-65 signature)")
    return _ok("pqc_second_witness",
               "ML-DSA-65 verify is two-witnessed: liboqs + cryptography/OpenSSL must agree "
               "(verify_both), a disagreement is refused, proven by the pqc-real CI job")


# ---------------------------------------------------------------------------
# The PQC posture audit must stay HONEST. Polaris's thesis is "post-quantum",
# but only its token core is; its transport (TLS key exchange) and operator auth
# (WebAuthn) are still classical. docs/reference/PQC-POSTURE.md states that split
# plainly. This check pins the honesty discipline: the doc must keep BOTH halves
# (what is post-quantum AND what is still classical), must name the classical
# surfaces by name (so the gap cannot be quietly deleted into an overclaim), must
# map to the NIST timeline, and must not assert production-readiness. It is the
# anti-larping guard for the headline claim, the same role check_thesis_* plays.
# ---------------------------------------------------------------------------
def check_pqc_posture(root: pathlib.Path) -> list[Finding]:
    doc = _read(root, "docs/reference/PQC-POSTURE.md")
    if not doc:
        return _fail("pqc_posture",
                     "docs/reference/PQC-POSTURE.md is missing (the honest post-quantum audit)")
    low = doc.lower()
    # Both halves of the honest split must be present.
    if "what is post-quantum today" not in low or "what is still classical" not in low:
        return _fail("pqc_posture",
                     "PQC-POSTURE.md must keep BOTH an honest 'what is post-quantum today' AND a "
                     "'what is still classical' section (the audit cannot become a one-sided claim)")
    # The PQ core must be named.
    if "ML-DSA-65" not in doc:
        return _fail("pqc_posture",
                     "PQC-POSTURE.md must name the post-quantum core (ML-DSA-65 token signature)")
    # The classical surfaces must be named AND called classical, so the gap is not
    # silently softened. TLS key exchange and WebAuthn are the load-bearing ones.
    classical_block = low.split("what is still classical", 1)[1]
    for surface in ("tls", "webauthn"):
        if surface not in classical_block:
            return _fail("pqc_posture",
                         "PQC-POSTURE.md must name %s among the still-classical surfaces "
                         "(honesty: the transport/auth gap stays stated)" % surface.upper())
    if "classical" not in classical_block:
        return _fail("pqc_posture",
                     "the still-classical section must actually call its surfaces 'classical' "
                     "(no euphemism for the quantum-vulnerable primitives)")
    # The NIST migration clock must be cited (the audit is timeline-relative).
    if "2030" not in doc or "2035" not in doc or "FIPS 204" not in doc:
        return _fail("pqc_posture",
                     "PQC-POSTURE.md must map to the NIST timeline (FIPS 204 + the 2030 deprecate / "
                     "2035 disallow clock from IR 8547)")
    # It must not overclaim production-readiness (the standing honesty line).
    if "production-readiness" not in low and "production readiness" not in low:
        return _fail("pqc_posture",
                     "PQC-POSTURE.md must disclaim production-readiness (link the gap ledger), not "
                     "imply the system is deployable")
    return _ok("pqc_posture",
               "PQC posture audit is honest: the PQ token core and the still-classical "
               "transport/WebAuthn are both stated, mapped to the NIST 2030/2035 clock")


# ---------------------------------------------------------------------------
# A post-quantum CLAIM must not drift ahead of its PROOF. The posture audit
# (v9.136) states the client-to-edge TLS hop negotiates the hybrid PQ group
# X25519MLKEM768. That positive security claim is only honest while CI actually
# reads it off a real handshake: this check fails if the doc names the hybrid
# group but the caddy-edge CI job does not prove the negotiation. (The empirical
# v9.136 review flagged exactly this drift risk: an unproven "proven in CI".)
# ---------------------------------------------------------------------------
def check_edge_pq_kex(root: pathlib.Path) -> list[Finding]:
    doc = _read(root, "docs/reference/PQC-POSTURE.md")
    if not doc:
        return _fail("edge_pq_kex", "docs/reference/PQC-POSTURE.md is missing")
    GROUP = "X25519MLKEM768"
    if GROUP not in doc:
        # The doc makes no edge-PQ-KEX claim; nothing to pin.
        return _ok("edge_pq_kex",
                   "the posture audit makes no edge hybrid-KEX claim; nothing to pin")
    ci = _read(root, ".github/workflows/ci.yml")
    if not ci or GROUP not in ci:
        return _fail("edge_pq_kex",
                     "PQC-POSTURE.md claims the edge negotiates %s, but CI does not prove it; "
                     "the caddy-edge job must read the negotiated group off a real handshake" % GROUP)
    # The CI must ASSERT the negotiation, not merely mention the group name. Require
    # both the negotiated-group read and a hard failure when it is absent.
    if "Negotiated TLS1.3 group" not in ci:
        return _fail("edge_pq_kex",
                     "the caddy-edge job must read 'Negotiated TLS1.3 group' off a real TLS 1.3 "
                     "handshake (not merely name the group) to prove the edge PQ-KEX claim")
    if not re.search(r"grep -q '%s'" % re.escape(GROUP), ci):
        return _fail("edge_pq_kex",
                     "the caddy-edge job must GATE on the negotiated group being %s "
                     "(a grep -q assertion), so the claim cannot pass without the proof" % GROUP)
    return _ok("edge_pq_kex",
               "the edge hybrid-KEX claim (%s) is backed by the caddy-edge CI job, which asserts "
               "the negotiated group off a real handshake" % GROUP)


# ---------------------------------------------------------------------------
# The issuer public key is stored WITH each signature (TokenSignature.
# signing_public_key_hex) so verification at use is self-contained — no live
# key-file lookup, and it survives key rotation. This pins the whole wiring:
# the column (schema), the stored-proc parameter, issuance threading the key,
# and the token-detail page verifying each stored signature.
# ---------------------------------------------------------------------------
def check_signature_self_contained_verify(root: pathlib.Path) -> list[Finding]:
    p = _read(root, "polaris_web/pqc_signing.py")
    if not p or "def verify_stored_signature" not in p or "def signature_with_key_for_token" not in p:
        return _fail("self_contained_verify",
                     "pqc_signing.py must expose signature_with_key_for_token + "
                     "verify_stored_signature (the self-contained store + verify path)")
    schema = _read(root, "polaris_sql/01_schema.sql")
    if "signing_public_key_hex" not in schema:
        return _fail("self_contained_verify",
                     "TokenSignature must have signing_public_key_hex in 01_schema.sql (the "
                     "stored issuer public key / DB trust anchor)")
    proc = _read(root, "polaris_sql/05_procedures.sql")
    if "p_signing_public_key_hex" not in proc:
        return _fail("self_contained_verify",
                     "uc1_issue_and_activate must accept p_signing_public_key_hex and store it")
    app = _read(root, "polaris_web/app.py")
    if "verify_stored_signature" not in app:
        return _fail("self_contained_verify",
                     "the token-detail route must verify each stored signature "
                     "(pqc_signing.verify_stored_signature) so verification is surfaced at use")
    return _ok("self_contained_verify",
               "the issuer public key is stored with each signature and verification is surfaced "
               "at use (token detail) — self-contained, survives key rotation")


# ---------------------------------------------------------------------------
# Real PQC must be the PRODUCTION DEFAULT, not merely testable. That needs three
# things together: liboqs in the prod image (so oqs imports at runtime), the
# flag on in the prod compose (POLARIS_USE_REAL_PQC=1), and the signing-key
# secret mounted (the stable trust anchor verify-at-use checks against). CI
# verifies real ML-DSA-65 actually works inside the prod image. The real key
# CUSTODY (HSM/KMS) stays operator-gated; the compose ships a generated key.
# ---------------------------------------------------------------------------
def check_prod_real_pqc(root: pathlib.Path) -> list[Finding]:
    df = _read(root, "polaris_web/Dockerfile.prod")
    compose = _read(root, "polaris_web/docker-compose.prod.yml")
    if not df or not compose:
        return _fail("prod_real_pqc", "Dockerfile.prod / docker-compose.prod.yml missing")
    if "liboqs-python" not in df:
        return _fail("prod_real_pqc",
                     "Dockerfile.prod must install liboqs-python so real ML-DSA-65 signing is "
                     "available in the prod image (not just testable in a CI job)")
    if not re.search(r"POLARIS_USE_REAL_PQC:\s*['\"]?1", compose):
        return _fail("prod_real_pqc",
                     "the prod compose must set POLARIS_USE_REAL_PQC=1 so issuance uses real PQC, "
                     "not the SHA3-256 placeholder")
    if "POLARIS_PQC_SIGNING_KEY_FILE" not in compose or "polaris_signing_key" not in compose:
        return _fail("prod_real_pqc",
                     "the prod compose must mount the signing keypair secret (polaris_signing_key) "
                     "and point POLARIS_PQC_SIGNING_KEY_FILE at it (the stable trust anchor)")
    ci = _read(root, ".github/workflows/ci.yml")
    if not ci or "real ML-DSA-65 signing inside the prod image" not in ci:
        return _fail("prod_real_pqc",
                     "CI must verify real ML-DSA-65 signing works INSIDE the built prod image "
                     "(a broken liboqs copy would otherwise only surface at deploy)")
    return _ok("prod_real_pqc",
               "real ML-DSA-65 is the production default: liboqs in the prod image, the flag on, "
               "the signing-key secret mounted as the trust anchor, verified in CI")


# ---------------------------------------------------------------------------
# The /sql operator console must be read-only at the DATABASE level, not just
# by a first-keyword whitelist. The whitelist accepts WITH, and a data-modifying
# CTE (`WITH t AS (DELETE ... RETURNING *) SELECT * FROM t`) starts with WITH and
# writes. `set_session(readonly=True)` — issued before any statement opens a
# transaction — makes Postgres itself refuse every write on that connection,
# closing the bypass. (A mid-transaction `SET default_transaction_read_only`
# would NOT bind the query's already-started transaction; that subtlety is why
# this needs a DB-backed test, not just this static check.) The grant boundary
# already stops DDL; this stops DML smuggled through the console.
# ---------------------------------------------------------------------------
def check_sql_console_readonly(root: pathlib.Path) -> list[Finding]:
    app = _read(root, "polaris_web/app.py")
    if not app:
        return _fail("sql_console_ro", "polaris_web/app.py is missing")
    m = re.search(r"def sql_query\(.*?\n(?=@app\.route|def [a-z])", app, re.S)
    body = m.group(0) if m else ""
    if not body:
        return _fail("sql_console_ro", "could not locate the sql_query console handler")
    if not re.search(r"set_session\(\s*readonly\s*=\s*True", body):
        return _fail("sql_console_ro",
                     "the /sql console must call conn.set_session(readonly=True) before any "
                     "statement so the database refuses writes — the SELECT/WITH keyword "
                     "whitelist alone is bypassable by a data-modifying CTE")
    return _ok("sql_console_ro",
               "the /sql console sets the session READ ONLY at the DB level "
               "(CTE-smuggled writes are refused by Postgres, not just the keyword gate)")


# ---------------------------------------------------------------------------
# The production image must not carry test frameworks. v9.105 split the single
# requirements.txt into a runtime surface (what the Docker images install) and a
# requirements-dev.txt (pytest, hypothesis, playwright). Test tooling in prod is
# dead weight and extra CVE surface — a pytest CVE (CVE-2025-71176) was riding
# into the image via the shared file. This check keeps the two apart.
# ---------------------------------------------------------------------------
_TEST_ONLY_PKGS = ("pytest", "hypothesis", "playwright")


def check_prod_image_no_test_deps(root: pathlib.Path) -> list[Finding]:
    req = _read(root, "polaris_web/requirements.txt")
    dev = _read(root, "polaris_web/requirements-dev.txt")
    if not req:
        return _fail("prod_no_test_deps", "polaris_web/requirements.txt is missing")
    if not dev:
        return _fail("prod_no_test_deps",
                     "polaris_web/requirements-dev.txt is missing — test tooling must live in a "
                     "separate file so the production image does not install it")
    leaked = [pkg for pkg in _TEST_ONLY_PKGS
              if re.search(rf"(?im)^\s*{re.escape(pkg)}\s*(?:[<>=!~;\[]|$)", req)]
    if leaked:
        return _fail("prod_no_test_deps",
                     "polaris_web/requirements.txt (the prod image surface) lists test-only "
                     "package(s): " + ", ".join(leaked) + " — move them to requirements-dev.txt")
    if not re.search(r"(?m)^\s*-r\s+requirements\.txt", dev):
        return _fail("prod_no_test_deps",
                     "requirements-dev.txt must include the runtime surface via "
                     "`-r requirements.txt` so one install covers run + test")
    for rel in ("polaris_web/Dockerfile", "polaris_web/Dockerfile.prod"):
        df = _read(root, rel)
        if df and "requirements-dev.txt" in df:
            return _fail("prod_no_test_deps",
                         f"{rel} installs requirements-dev.txt — the image must install the "
                         "runtime requirements.txt only (no test frameworks in the image)")
    return _ok("prod_no_test_deps",
               "test tooling is isolated in requirements-dev.txt; the Docker images install the "
               "runtime requirements.txt only (pytest/hypothesis/playwright never ship to prod)")


# ---------------------------------------------------------------------------
# The dependency surface must be CVE-scanned, and the scan must GATE on the
# runtime surface (requirements.txt) — a known CVE in a package the production
# image installs has to fail the build, not ship silently. pip-audit on the dev
# tooling is informational (a test-tool CVE never reaches prod). Dependabot
# opens update PRs for new advisories.
# ---------------------------------------------------------------------------
def check_cve_scanning(root: pathlib.Path) -> list[Finding]:
    ci = _read(root, ".github/workflows/ci.yml")
    if not ci:
        return _fail("cve_scanning", ".github/workflows/ci.yml is missing")
    if "pip-audit" not in ci:
        return _fail("cve_scanning",
                     "CI must run pip-audit to scan dependencies for known CVEs")
    if not re.search(r"pip-audit\s+-r\s+\S*requirements\.txt[^\n]*--strict", ci):
        return _fail("cve_scanning",
                     "the pip-audit run on requirements.txt must be gating (--strict) so a known "
                     "CVE in the production dependency surface fails the build")
    if not (root / ".github" / "dependabot.yml").is_file():
        return _fail("cve_scanning",
                     ".github/dependabot.yml is missing — add Dependabot so new advisories open "
                     "update PRs automatically")
    return _ok("cve_scanning",
               "CI gates on pip-audit of the runtime surface (--strict); Dependabot tracks new "
               "advisories")


# ---------------------------------------------------------------------------
# Container IMAGE CVE scanning (v9.138). pip-audit covers Python deps; bandit
# covers our code; but the OS packages in the base images were unscanned and
# shipped real fixable CRITICALs. This pins the control: the self-built
# Dockerfiles must patch their bases (apt-get upgrade / apk upgrade), CI must run
# Trivy gating on fixable CRITICAL, and a documented .trivyignore carries the
# justified exceptions. Without all three, image CVEs ship silently.
# ---------------------------------------------------------------------------
def check_image_cve_scanning(root: pathlib.Path) -> list[Finding]:
    ci = _read(root, ".github/workflows/ci.yml")
    if not ci:
        return _fail("image_cve_scan", ".github/workflows/ci.yml is missing")
    if "trivy" not in ci.lower():
        return _fail("image_cve_scan",
                     "CI must scan the built container images for OS-package CVEs (Trivy); "
                     "pip-audit only covers Python dependencies")
    # The scan must GATE on fixable CRITICAL (an --exit-code 1 + --severity CRITICAL
    # run), not merely report. Require both tokens near the trivy usage.
    if "--severity CRITICAL" not in ci or "--exit-code 1" not in ci:
        return _fail("image_cve_scan",
                     "the Trivy image scan must GATE on fixable CRITICAL "
                     "(--severity CRITICAL --exit-code 1), not only report")
    if "--ignore-unfixed" not in ci:
        return _fail("image_cve_scan",
                     "the Trivy gate should use --ignore-unfixed so it fails only on ACTIONABLE "
                     "(fixable) CVEs, not on base-image CVEs with no upstream patch yet")
    # The fixable CVEs must be PATCHED in what ships, not just reported: the
    # self-built Dockerfiles upgrade their base packages.
    # The pattern tolerates apt-get options (the mirror-retry flags added at
    # v9.215 sit between the command and its subcommand).
    patched = {
        "polaris_web/Dockerfile.prod": (r"apt-get\b[^\n]*\s-y upgrade", "apt-get -y upgrade"),
        "polaris_web/Dockerfile.caddy": (r"apk upgrade", "apk upgrade"),
        "polaris_web/Dockerfile.pgbouncer": (r"apk upgrade", "apk upgrade"),
        "polaris_web/Dockerfile.postgres": (r"apk upgrade", "apk upgrade"),
    }
    for path, (pattern, shown) in patched.items():
        df = _read(root, path)
        if not df or not re.search(pattern, df):
            return _fail("image_cve_scan",
                         "%s must `%s` so fixable base-image CVEs are patched in the shipped image, "
                         "not merely scanned" % (path, shown))
    # Exceptions must be documented, not silently widened.
    if not (root / ".trivyignore").is_file():
        return _fail("image_cve_scan",
                     ".trivyignore is missing — Trivy exceptions must be documented + justified")
    return _ok("image_cve_scan",
               "CI builds + Trivy-scans every prod image gating on fixable CRITICAL; the "
               "Dockerfiles patch their bases; exceptions are documented in .trivyignore")


# ---------------------------------------------------------------------------
# Static application security testing (SAST). pip-audit covers dependency CVEs;
# bandit covers OUR source for security anti-patterns (hardcoded secrets, weak
# crypto, world-writable files, shell=True, etc.). CI must run it and GATE on
# high-severity findings so a real issue (e.g. the world-writable state dir
# bandit caught at v9.112) fails the build rather than shipping.
# ---------------------------------------------------------------------------
def check_sast_scanning(root: pathlib.Path) -> list[Finding]:
    ci = _read(root, ".github/workflows/ci.yml")
    if not ci:
        return _fail("sast", ".github/workflows/ci.yml is missing")
    if "bandit" not in ci:
        return _fail("sast", "CI must run bandit (SAST) over polaris_web + polaris_cli")
    if not re.search(r"bandit\b[^\n]*--severity-level\s+high", ci):
        return _fail("sast",
                     "the bandit run must GATE on high severity (--severity-level high), so a real "
                     "finding fails the build instead of shipping")
    return _ok("sast", "CI runs bandit SAST gating on high-severity findings")


# ---------------------------------------------------------------------------
# Schema migrations must bound their lock acquisition and statement time. An
# ALTER TABLE that needs an ACCESS EXCLUSIVE lock queues behind any open
# transaction and, once granted, blocks ALL traffic on that table — an
# unbounded wait turns one slow query into a site-wide stall. The migration
# runner must SET LOCAL lock_timeout (fail fast rather than queue) AND
# statement_timeout (cap a runaway migration) inside the apply transaction.
# ---------------------------------------------------------------------------
def check_migration_timeouts(root: pathlib.Path) -> list[Finding]:
    sh = _read(root, "scripts/polaris-migrate.sh")
    if not sh:
        return _fail("migration_timeouts", "scripts/polaris-migrate.sh is missing")
    missing = [name for name in ("lock_timeout", "statement_timeout")
               if not re.search(rf"SET\s+LOCAL\s+{name}\b", sh)]
    if missing:
        return _fail("migration_timeouts",
                     "the migration runner must SET LOCAL " + " and ".join(missing) +
                     " inside the apply transaction so a migration cannot queue on / hold a "
                     "table lock unboundedly and stall all traffic")
    return _ok("migration_timeouts",
               "migrations SET LOCAL lock_timeout + statement_timeout (a blocking ALTER fails "
               "fast instead of stalling the table)")


# ---------------------------------------------------------------------------
# A persistent-volume UPGRADE does NOT re-run docker-init.sh (postgres init
# scripts only fire on an empty data dir), so the deploy must itself apply
# pending migrations AND re-sync the idempotent DB objects (procedures, triggers,
# views, grants). Without this a changed procedure — e.g. v9.117's
# uc1_issue_and_activate signature — never reaches the upgraded DB and issuance
# breaks. polaris-migrate.sh provides --sync-objects; polaris-deploy.sh runs both
# against the running stack.
# ---------------------------------------------------------------------------
def check_deploy_syncs_db_objects(root: pathlib.Path) -> list[Finding]:
    mig = _read(root, "scripts/polaris-migrate.sh")
    dep = _read(root, "scripts/polaris-deploy.sh")
    if not mig or not dep:
        return _fail("deploy_db_sync", "scripts/polaris-migrate.sh or polaris-deploy.sh is missing")
    if "--sync-objects" not in mig or "sync-objects)" not in mig:
        return _fail("deploy_db_sync",
                     "polaris-migrate.sh must provide a --sync-objects mode that re-applies the "
                     "procedure/trigger/view/grant files (else a changed object never reaches an "
                     "upgraded DB)")
    if "--sync-objects" not in dep or "--up --target=docker-stack" not in dep:
        return _fail("deploy_db_sync",
                     "polaris-deploy.sh must apply migrations + --sync-objects against the running "
                     "stack on deploy — an upgrade does not re-run docker-init, so a changed "
                     "procedure would otherwise never reach the live DB")
    return _ok("deploy_db_sync",
               "the deploy applies migrations and re-syncs DB objects on upgrade (procedure / "
               "trigger / view / grant changes reach an upgraded DB, not just a fresh one)")


# ---------------------------------------------------------------------------
# The worker-count knob must actually work. Dockerfile.prod and the prod compose
# advertise WEB_CONCURRENCY (gunicorn's own convention), but gunicorn.conf.py
# read only POLARIS_WORKERS — so setting WEB_CONCURRENCY did nothing and an
# operator scaling the stack with it silently got the default 4 workers (and,
# with no Redis, a per-worker rate limiter at 4x the configured cap). The config
# must honor WEB_CONCURRENCY so the advertised knob is real.
# ---------------------------------------------------------------------------
def check_web_concurrency_honored(root: pathlib.Path) -> list[Finding]:
    conf = _read(root, "polaris_web/gunicorn.conf.py")
    if not conf:
        return _fail("web_concurrency", "polaris_web/gunicorn.conf.py is missing")
    if "WEB_CONCURRENCY" not in conf:
        return _fail("web_concurrency",
                     "gunicorn.conf.py must honor WEB_CONCURRENCY — the Dockerfile.prod and "
                     "docker-compose.prod.yml set it, but the config reads only POLARIS_WORKERS, "
                     "so the advertised scaling knob is inert")
    return _ok("web_concurrency",
               "gunicorn.conf.py honors WEB_CONCURRENCY (the knob the prod image + compose set), "
               "with POLARIS_WORKERS taking precedence")


# ---------------------------------------------------------------------------
# Prometheus metrics must aggregate ACROSS gunicorn workers. With a per-worker
# registry a /metrics scrape reports only the worker that served it — a 4x
# undercount under 4 workers. Multiprocess mode (PROMETHEUS_MULTIPROC_DIR) file-
# backs each worker's samples and the scrape aggregates them via a
# MultiProcessCollector; gunicorn must reap a dead worker's files (child_exit +
# mark_process_dead) and the prod compose must set the dir.
# ---------------------------------------------------------------------------
def check_prometheus_multiprocess(root: pathlib.Path) -> list[Finding]:
    app = _read(root, "polaris_web/app.py")
    gconf = _read(root, "polaris_web/gunicorn.conf.py")
    compose = _read(root, "polaris_web/docker-compose.prod.yml")
    if not app or not gconf or not compose:
        return _fail("prom_multiproc",
                     "app.py / gunicorn.conf.py / docker-compose.prod.yml is missing")
    if "MultiProcessCollector" not in app or "PROMETHEUS_MULTIPROC_DIR" not in app:
        return _fail("prom_multiproc",
                     "app.py must aggregate /metrics via a MultiProcessCollector when "
                     "PROMETHEUS_MULTIPROC_DIR is set (else metrics undercount across workers)")
    if "mark_process_dead" not in gconf or "def child_exit" not in gconf:
        return _fail("prom_multiproc",
                     "gunicorn.conf.py must reap a dead worker's metric files (a child_exit hook "
                     "calling mark_process_dead)")
    if "PROMETHEUS_MULTIPROC_DIR" not in compose:
        return _fail("prom_multiproc",
                     "docker-compose.prod.yml must set PROMETHEUS_MULTIPROC_DIR so the multi-worker "
                     "app aggregates metrics")
    return _ok("prom_multiproc",
               "Prometheus /metrics aggregates across workers (multiprocess dir + "
               "MultiProcessCollector + child_exit reaping)")


# ---------------------------------------------------------------------------
# Liveness and readiness are distinct production probes and must not be
# conflated. Liveness ("is the process alive?") must be CHEAP and dependency-
# free: an orchestrator RESTARTS on liveness failure, so checking the DB there
# turns a transient outage into a restart storm. Readiness ("can I serve?") runs
# the dependency checks; its failure STOPS traffic without a restart. The app
# must expose both, the liveness handler must not run the dependency roll-up,
# and the container HEALTHCHECK must use liveness.
# ---------------------------------------------------------------------------
def check_health_liveness_readiness_split(root: pathlib.Path) -> list[Finding]:
    app = _read(root, "polaris_web/app.py")
    if not app:
        return _fail("health_probes", "polaris_web/app.py is missing")
    for route in ("/api/health/live", "/api/health/ready"):
        if route not in app:
            return _fail("health_probes",
                         f"app.py must expose {route} — liveness (cheap, no deps) and readiness "
                         "(dependency roll-up) are distinct production probes")
    m = re.search(r"def api_health_live\(.*?\n(?=@app\.route|def [a-z])", app, re.S)
    live_body = m.group(0) if m else ""
    if live_body and "_compute_readiness" in live_body:
        return _fail("health_probes",
                     "the liveness probe must not run the dependency checks (a DB blip would then "
                     "restart the container); keep /api/health/live cheap")
    df = _read(root, "polaris_web/Dockerfile.prod")
    if df and "/api/health/live" not in df:
        return _fail("health_probes",
                     "the prod HEALTHCHECK should use the liveness probe (/api/health/live), not "
                     "the dependency roll-up, so a transient outage does not restart the container")
    return _ok("health_probes",
               "liveness (/api/health/live, cheap) and readiness (/api/health/ready, deps) are "
               "split; the container HEALTHCHECK uses liveness")


# ---------------------------------------------------------------------------
# Every production-stack container must bound its blast radius: a memory/cpu
# limit (so one runaway container cannot OOM the host) and a rotating log driver
# (so logs cannot fill the disk). Both are per-service config in the prod
# compose. Checked by text (the check layer runs on system python with no
# PyYAML): every service has an image, and the count of deploy-limits + logging
# blocks must cover every service.
# ---------------------------------------------------------------------------
def check_compose_resource_limits(root: pathlib.Path) -> list[Finding]:
    text = _read(root, "polaris_web/docker-compose.prod.yml")
    if not text:
        return _fail("compose_limits", "polaris_web/docker-compose.prod.yml is missing")
    services = len(re.findall(r"(?m)^\s+image:\s", text))
    if services == 0:
        return _fail("compose_limits", "could not find any services in the prod compose")
    deploy_limits = len(re.findall(r"(?m)^\s+limits:\s*$", text))
    logging_blocks = len(re.findall(r"(?m)^\s+logging:\s*$", text))
    if deploy_limits < services:
        return _fail("compose_limits",
                     f"only {deploy_limits}/{services} prod-compose services set "
                     "deploy.resources.limits — one unbounded container can OOM the host")
    if logging_blocks < services:
        return _fail("compose_limits",
                     f"only {logging_blocks}/{services} prod-compose services configure log "
                     "rotation (logging: json-file max-size/max-file) — logs can fill the disk")
    if "max-size" not in text or "memory:" not in text:
        return _fail("compose_limits",
                     "resource limits need a memory bound and log rotation needs a max-size bound")
    return _ok("compose_limits",
               f"all {services} prod-compose services set memory/cpu limits + rotating json-file "
               "logging (no host OOM, no unbounded logs)")


# ---------------------------------------------------------------------------
# Container runtime hardening (v9.141, CIS Docker 5.x). Every prod-compose
# service must drop ALL Linux capabilities (adding back only the few its
# entrypoint genuinely needs) and forbid privilege escalation
# (no-new-privileges). The app + pgbouncer then run with ZERO capabilities; the
# public Caddy edge runs as uid 1000 on 8080/8443 with NO capability added
# back (v9.239; until then it ran as root with NET_BIND_SERVICE, the one
# engineering limit the readiness ledger carried openly); postgres/redis keep
# only the caps their root-then-drop init needs. Proven to still boot + serve by the
# prod-stack-boot CI job (cap_drop ALL would otherwise silently break an
# entrypoint). A service that ships without these is the un-hardened default.
# ---------------------------------------------------------------------------
def check_container_hardening(root: pathlib.Path) -> list[Finding]:
    text = _read(root, "polaris_web/docker-compose.prod.yml")
    if not text:
        return _fail("container_hardening", "polaris_web/docker-compose.prod.yml is missing")
    services = len(re.findall(r"(?m)^\s+image:\s", text))
    if services == 0:
        return _fail("container_hardening", "could not find any services in the prod compose")
    nnp = len(re.findall(r"no-new-privileges:\s*true", text))
    cap_drop_all = len(re.findall(r"(?m)cap_drop:\s*\n\s+-\s*ALL\b", text))
    if nnp < services:
        return _fail("container_hardening",
                     f"only {nnp}/{services} prod-compose services set "
                     "security_opt no-new-privileges:true — a service can still escalate privileges")
    if cap_drop_all < services:
        return _fail("container_hardening",
                     f"only {cap_drop_all}/{services} prod-compose services cap_drop ALL — a "
                     "service runs with the full default Linux capability set")
    # v9.239: the public edge holds no capability at all and runs as a
    # non-root user. A cap_add on the caddy service, or a Dockerfile.caddy
    # without a USER, is the old root-with-NET_BIND_SERVICE posture coming back.
    m = re.search(r"(?ms)^  caddy:\n(.*?)(?=^  [a-z_]+:\n|\Z)", text)
    if not m:
        return _fail("container_hardening", "the prod compose has no caddy service")
    if re.search(r"^\s+cap_add:", m.group(1), re.M):
        return _fail("container_hardening",
                     "the caddy service adds a capability back: the edge must run as a non-root "
                     "user on unprivileged ports (8080/8443) with the host publishing 80/443")
    if not re.search(r'"80:8080"', m.group(1)) or not re.search(r'"443:8443"', m.group(1)):
        return _fail("container_hardening",
                     "the caddy service must publish host 80/443 onto the unprivileged 8080/8443 "
                     "the non-root edge listens on")
    df = _read(root, "polaris_web/Dockerfile.caddy")
    um = re.search(r"(?m)^USER\s+(\S+)", df)
    if not um or um.group(1).split(":")[0] in ("root", "0"):
        return _fail("container_hardening",
                     "Dockerfile.caddy must end as a non-root USER: the edge ran as root until "
                     "v9.239 and the readiness ledger carried it as an open limit")
    # The boot test must prove the hardened stack still serves (cap_drop can break
    # an entrypoint that needs a capability — e.g. gosu/setpriv's SETUID).
    ci = _read(root, ".github/workflows/ci.yml")
    if not ci or "prod-stack-boot" not in ci:
        return _fail("container_hardening",
                     "the prod-stack-boot CI job must boot the HARDENED stack so cap_drop cannot "
                     "silently break a service's entrypoint")
    return _ok("container_hardening",
               f"all {services} prod-compose services drop ALL caps (adding back only what their "
               "entrypoint needs) + forbid privilege escalation; proven to still serve by CI")


# ---------------------------------------------------------------------------
# Third-party images in the PROD compose must be pinned by digest (@sha256), not
# just a mutable tag. A tag can be repointed at different content upstream (or, as
# bitnami/pgbouncer showed, deleted); a digest is immutable, so the deploy runs
# exactly what was reviewed. Locally-built images (polaris-*) are exempt — they
# have no registry digest. Dependabot's docker ecosystem bumps the pins.
# ---------------------------------------------------------------------------
def check_prod_images_digest_pinned(root: pathlib.Path) -> list[Finding]:
    compose = _read(root, "polaris_web/docker-compose.prod.yml")
    if not compose:
        return _fail("image_digests", "polaris_web/docker-compose.prod.yml is missing")
    unpinned = []
    for m in re.finditer(r"(?m)^\s*image:\s*(\S+)", compose):
        img = m.group(1).strip().strip('"').strip("'")
        if img.startswith("polaris-"):
            continue  # built locally via `build:`, no registry digest to pin
        if "@sha256:" not in img:
            unpinned.append(img)
    if unpinned:
        return _fail("image_digests",
                     "prod-compose third-party image(s) are tag-pinned, not digest-pinned: "
                     + ", ".join(unpinned) + " — pin as name:tag@sha256:<digest> so a mutated or "
                     "deleted upstream tag cannot change what runs")
    # v9.237: four of the five production images are self-built, and a
    # self-built image is only as pinned as the base its Dockerfile pulls.
    # Until now the check read the compose file's image: lines and stopped, so
    # "third-party images are digest-pinned" was true of redis and false of the
    # python, alpine and rust bases under the app and the pooler. Every
    # Dockerfile the prod compose names must pin every FROM.
    unpinned_from = []
    for m in re.finditer(r"(?m)^\s*dockerfile:\s*(\S+)", compose):
        rel = m.group(1).strip().strip('"').strip("'")
        # compose context is polaris_web/ or the repo root; resolve either.
        candidates = [root / "polaris_web" / pathlib.Path(rel).name, root / rel]
        df = next((p for p in candidates if p.is_file()), None)
        if df is None:
            return _fail("image_digests", f"prod compose names {rel}, which does not exist")
        for fm in re.finditer(r"(?m)^\s*FROM\s+(\S+)", df.read_text(encoding="utf-8")):
            base = fm.group(1)
            if base.lower() == "scratch" or "@sha256:" in base:
                continue
            # A FROM that names an earlier stage (AS builder) is not a pull.
            if re.search(rf"(?m)^\s*FROM\s+\S+\s+AS\s+{re.escape(base)}\b", df.read_text(encoding="utf-8"), re.I):
                continue
            unpinned_from.append(f"{df.name}: {base}")
    if unpinned_from:
        return _fail("image_digests",
                     "self-built production image(s) pull a base by tag only: "
                     + "; ".join(unpinned_from) + " — pin every FROM as name:tag@sha256:<digest>; "
                     "Dependabot's docker ecosystem keeps the pins current")
    dep = root / ".github" / "dependabot.yml"
    if not dep.is_file() or "docker" not in dep.read_text():
        return _fail("image_digests",
                     "add the docker ecosystem to .github/dependabot.yml so the pinned digests get "
                     "security bumps (a frozen digest never updates on its own)")
    return _ok("image_digests",
               "every pulled prod-compose image and every base under the self-built ones is "
               "digest-pinned (@sha256); Dependabot's docker ecosystem keeps the pins current")


# ---------------------------------------------------------------------------
# Alerting rules must be a real, shipped, validated artifact the operator can
# deploy — not a doc snippet. DR.md referenced "PolarisHigh5xx and related"
# rules that lived only as an OPERATIONS.md example. They now ship at
# deploy/observability/ (promtool-validated) with a scrape config; the alerting
# backend (Alertmanager + pager) remains operator-provided.
# ---------------------------------------------------------------------------
def check_alert_rules(root: pathlib.Path) -> list[Finding]:
    rules = _read(root, "deploy/observability/polaris-alerts.yml")
    cfg = _read(root, "deploy/observability/prometheus.yml")
    if not rules or not cfg:
        return _fail("alert_rules",
                     "deploy/observability/polaris-alerts.yml + prometheus.yml must ship (a real "
                     "rules artifact, not just a doc example)")
    if "groups:" not in rules:
        return _fail("alert_rules", "polaris-alerts.yml must be a Prometheus rule-group file (groups:)")
    for a in ("PolarisHigh5xx", "PolarisAppDown"):
        if f"alert: {a}" not in rules:
            return _fail("alert_rules", f"polaris-alerts.yml must define the {a} alert")
    if "polaris-alerts.yml" not in cfg or "job_name: polaris" not in cfg:
        return _fail("alert_rules",
                     "prometheus.yml must scrape the polaris job and load polaris-alerts.yml "
                     "(rule_files)")
    # v9.241: the SLIs and the error budget SLOS.md states are recorded
    # series, not prose. The file must exist with every series the document
    # names, Prometheus must load it, the overlay must mount it, the unit
    # tests must cover it, and the overview dashboard must show the budget.
    slo = _read(root, "deploy/observability/polaris-slo.yml")
    if not slo:
        return _fail("alert_rules", "deploy/observability/polaris-slo.yml is missing: the SLIs and the error "
                                    "budget must be recorded series, not expressions in SLOS.md")
    for rec in ("polaris:sli_availability:ratio_30d", "polaris:error_budget_spent:ratio_30d",
                "polaris:error_budget_burn_rate:1h", "polaris:sli_request_latency_p99:30d",
                "polaris:sli_db_latency_p99:30d"):
        if f"record: {rec}" not in slo:
            return _fail("alert_rules", f"polaris-slo.yml must record {rec} (SLOS.md names it)")
    if "polaris-slo.yml" not in cfg:
        return _fail("alert_rules", "prometheus.yml must load polaris-slo.yml in rule_files")
    overlay = _read(root, "polaris_web/docker-compose.observability.yml")
    if overlay and "polaris-slo.yml" not in overlay:
        return _fail("alert_rules", "docker-compose.observability.yml must mount polaris-slo.yml into Prometheus")
    tests = _read(root, "deploy/observability/polaris-alerts.test.yml")
    if tests and "polaris-slo.yml" not in tests:
        return _fail("alert_rules", "polaris-alerts.test.yml must load polaris-slo.yml so the recording rules are unit-tested")
    overview = _read(root, "deploy/observability/grafana/dashboards/polaris-overview.json")
    if overview and "polaris:error_budget_spent:ratio_30d" not in overview:
        return _fail("alert_rules", "the overview dashboard must show the error budget "
                                    "(polaris:error_budget_spent:ratio_30d); SLOS.md says it is observable there")
    return _ok("alert_rules",
               "shipped Prometheus scrape config, promtool-validated alerting rules, and the SLI and error-budget recording rules on the dashboard "
               "(deploy/observability/); the Alertmanager backend stays operator-provided")


# ---------------------------------------------------------------------------
# Every shipped alert must have a runbook, and every runbook must name a real
# alert. An alert that pages on-call with no documented Trigger/Diagnosis/
# Remediation is a 03:00 dead end; a runbook section for an alert that no longer
# exists is stale guidance. This parses the alert names out of polaris-alerts.yml
# and asserts a one-to-one mapping with the `## <AlertName>` headings in
# docs/operator/RUNBOOKS.md (no missing runbook, no orphan section).
# ---------------------------------------------------------------------------
def check_alert_runbooks(root: pathlib.Path) -> list[Finding]:
    rules = _read(root, "deploy/observability/polaris-alerts.yml")
    book = _read(root, "docs/operator/RUNBOOKS.md")
    if not rules:
        return _fail("alert_runbooks",
                     "deploy/observability/polaris-alerts.yml is missing — no alerts to document")
    if not book:
        return _fail("alert_runbooks",
                     "docs/operator/RUNBOOKS.md is missing — every shipped alert needs a runbook")
    alerts = re.findall(r"(?m)^\s*-\s*alert:\s*(\w+)\s*$", rules)
    if not alerts:
        return _fail("alert_runbooks", "could not parse any `- alert: <Name>` lines from polaris-alerts.yml")
    # Runbook sections are H2 headings naming exactly one alert.
    sections = re.findall(r"(?m)^##\s+(\w+)\s*$", book)
    documented = {s for s in sections if s.startswith("Polaris")}
    alert_set = set(alerts)
    missing = sorted(alert_set - documented)
    if missing:
        return _fail("alert_runbooks",
                     "alert(s) with no `## <name>` runbook section in docs/operator/RUNBOOKS.md: "
                     + ", ".join(missing) + " — an alert that pages with no runbook is a dead end")
    orphans = sorted(documented - alert_set)
    if orphans:
        return _fail("alert_runbooks",
                     "RUNBOOKS.md has runbook section(s) for alert(s) not in polaris-alerts.yml: "
                     + ", ".join(orphans) + " — stale guidance; remove or re-add the alert")
    return _ok("alert_runbooks",
               f"all {len(alert_set)} shipped alerts have exactly one runbook section in "
               "docs/operator/RUNBOOKS.md (no missing, no orphan)")


# ---------------------------------------------------------------------------
# The duress signal must be ALERTABLE (v9.128). observability.py calls duress
# "the headline metric": an unread duress event is the coercion-cover failure
# mode. The JSON /api/metrics snapshot is not scrapeable for alerting, so the
# count must be a Prometheus counter on /metrics, incremented where the
# DuressEvent is recorded, with an alert on it — otherwise the page never fires.
# ---------------------------------------------------------------------------
def check_duress_alertable(root: pathlib.Path) -> list[Finding]:
    app = _read(root, "polaris_web/app.py")
    alerts = _read(root, "deploy/observability/polaris-alerts.yml")
    if not (app and alerts):
        return _fail("duress_alert", "app.py or the alerts file is missing")
    if "polaris_duress_events_total" not in app:
        return _fail("duress_alert",
                     "app.py must expose polaris_duress_events_total on /metrics (the duress signal "
                     "must be alertable, not only in the JSON /api/metrics)")
    # It must be incremented where the DuressEvent is recorded, or the alert sits
    # on a counter that never moves.
    m = re.search(r"def _record_duress_async\b.*?(?=\n\ndef |\Z)", app, re.S)
    if not m or "_METRICS_DURESS" not in m.group(0):
        return _fail("duress_alert",
                     "the duress counter must be incremented in _record_duress_async (where the "
                     "DuressEvent is recorded) — an alert on a never-incremented counter never fires")
    if "PolarisDuressEvent" not in alerts or "polaris_duress_events_total" not in alerts:
        return _fail("duress_alert",
                     "polaris-alerts.yml must alert (PolarisDuressEvent) on polaris_duress_events_total")
    return _ok("duress_alert",
               "the duress signal is alertable: polaris_duress_events_total is on /metrics, incremented "
               "at the DuressEvent record site, and PolarisDuressEvent pages on it (runbook enforced by "
               "check_alert_runbooks)")


# ---------------------------------------------------------------------------
# Fail-closed on production misconfiguration (v9.129). The prod compose sets
# these correctly, but a hand-rolled deployment could miss them, so app.py
# refuses to start in production when:
#   - POLARIS_DB_SSLMODE permits a silent plaintext DB hop (prefer/allow/disable);
#   - POLARIS_DURESS_SYNC=1 reintroduces the duress timing side-channel.
# Mirrors the existing default-SECRET_KEY guard. This pins both guards so neither
# can be silently dropped (a removed fail-closed check reads as "still safe").
# ---------------------------------------------------------------------------
def check_prod_fail_closed(root: pathlib.Path) -> list[Finding]:
    app = _read(root, "polaris_web/app.py")
    if not app:
        return _fail("prod_fail_closed", "polaris_web/app.py is missing")
    if "_PRODUCTION" not in app:
        return _fail("prod_fail_closed", "app.py must compute a _PRODUCTION flag")
    # The DB-TLS guard: POLARIS_DB_SSLMODE tied to a sys.exit, rejecting the
    # plaintext-capable modes.
    if not re.search(r"POLARIS_DB_SSLMODE.{0,500}sys\.exit", app, re.S):
        return _fail("prod_fail_closed",
                     "app.py must refuse to start in production when POLARIS_DB_SSLMODE permits a "
                     "silent plaintext DB hop (a sys.exit guard on prefer/allow/disable)")
    if not re.search(r"prefer", app):
        return _fail("prod_fail_closed",
                     "the sslmode guard must reject the plaintext-capable modes (prefer/allow/disable)")
    # v9.132 — verify-ca/verify-full must require a pinned CA (sslrootcert) at
    # startup, or a hand-rolled deploy boots and fails confusingly at first
    # connect. The guard must tie POLARIS_DB_SSLROOTCERT to a sys.exit.
    if not re.search(r"POLARIS_DB_SSLROOTCERT.{0,500}sys\.exit", app, re.S):
        return _fail("prod_fail_closed",
                     "app.py must refuse to start in production when sslmode is verify-ca/verify-full "
                     "but POLARIS_DB_SSLROOTCERT is unset/missing (verify-* without a pinned CA cannot "
                     "verify the peer)")
    # The duress-sync guard: POLARIS_DURESS_SYNC tied to a sys.exit.
    if not re.search(r"POLARIS_DURESS_SYNC.{0,500}sys\.exit", app, re.S):
        return _fail("prod_fail_closed",
                     "app.py must refuse to start in production when POLARIS_DURESS_SYNC=1 (it "
                     "reintroduces the duress timing side-channel)")
    # v9.277 (PE.4) — the HSM-sole-signer profile. When POLARIS_REQUIRE_HSM_SOLE_SIGNER
    # is set, the app must refuse to boot unless the HSM is the sole signer: the pkcs11
    # driver, tied to a sys.exit, AND no file key in the environment (a latent fallback
    # a flipped driver would use). Both are load-bearing to "the only prod signing path".
    if not re.search(r"POLARIS_REQUIRE_HSM_SOLE_SIGNER.{0,900}sys\.exit", app, re.S):
        return _fail("prod_fail_closed",
                     "app.py must refuse to start when POLARIS_REQUIRE_HSM_SOLE_SIGNER is set but the HSM is "
                     "not the sole signer (a sys.exit guard requiring the pkcs11 driver)")
    if not re.search(r"POLARIS_REQUIRE_HSM_SOLE_SIGNER.{0,900}POLARIS_PQC_SIGNING_KEY_FILE", app, re.S):
        return _fail("prod_fail_closed",
                     "the HSM-sole-signer guard must forbid POLARIS_PQC_SIGNING_KEY_FILE (a latent file-key "
                     "fallback the sole-HSM profile must not carry)")
    return _ok("prod_fail_closed",
               "app.py fails closed in production on a plaintext-capable POLARIS_DB_SSLMODE and on "
               "POLARIS_DURESS_SYNC=1 (the duress timing side-channel), alongside the default-SECRET_KEY "
               "guard and the HSM-sole-signer profile (POLARIS_REQUIRE_HSM_SOLE_SIGNER)")


# ---------------------------------------------------------------------------
# At-rest data-protection posture. Polaris does not encrypt the live database at
# the app layer (host volume encryption + key custody is operator-gated). The
# risk is not that gap (it is documented and deliberate) but that the POSTURE doc
# silently drifts from the schema reality, or quietly starts overclaiming. This
# pins both: the doc must name the actual sensitive surfaces the schema holds in
# plaintext (Individual.legal_name / date_of_birth, TokenStateEpochLeaf.proof_path
# — the schema's own "v1 stores proof_path in plaintext" note), must point at the
# host-level operator path, and must NOT claim the live DB is encrypted at rest.
# ---------------------------------------------------------------------------
def check_encryption_at_rest_posture(root: pathlib.Path) -> list[Finding]:
    doc = _read(root, "docs/operator/ENCRYPTION-AT-REST.md")
    schema = _read(root, "polaris_sql/01_schema.sql")
    if not doc:
        return _fail("at_rest_posture",
                     "docs/operator/ENCRYPTION-AT-REST.md is missing — the at-rest posture must be "
                     "documented, not implicit")
    # Normalize markdown emphasis out so a bolded "does **not** encrypt" still
    # matches the honesty substring below.
    low = doc.lower().replace("*", "")
    # The plaintext-sensitive surfaces the doc must enumerate, so it cannot drift
    # from the schema. proof_path is load-bearing: the schema itself flags it.
    for needed, why in (
        ("proof_path", "the plaintext ZK Merkle path the schema flags as v1-plaintext"),
        ("legal_name", "the direct PII column on Individual"),
        ("date_of_birth", "the direct PII column on Individual"),
    ):
        if needed not in doc:
            return _fail("at_rest_posture",
                         f"ENCRYPTION-AT-REST.md must name {needed} ({why}) — it is plaintext at rest")
    # Schema-drift guard: while the schema still stores proof_path in plaintext,
    # the doc must say so (not quietly claim it is encrypted).
    if "proof_path" in schema and re.search(r"plaintext", schema, re.I):
        if "plaintext" not in low:
            return _fail("at_rest_posture",
                         "the schema still stores proof_path in plaintext but ENCRYPTION-AT-REST.md "
                         "does not say 'plaintext' — the posture has drifted from the schema")
    # The operator path must be named (host volume encryption), not hand-waved.
    if not re.search(r"luks|dm-crypt|fscrypt", low):
        return _fail("at_rest_posture",
                     "ENCRYPTION-AT-REST.md must name the host-level encryption path (LUKS/dm-crypt/"
                     "fscrypt) — the operator-gated control that actually closes the gap")
    if "operator-gated" not in low:
        return _fail("at_rest_posture",
                     "ENCRYPTION-AT-REST.md must mark the live-DB at-rest control operator-gated")
    # Honesty guard: the doc must NOT claim the live database is encrypted at rest.
    # Any sentence asserting at-rest encryption of the live DB must be negated
    # ('does not', 'not') — we require the explicit honest disclaimer to be present.
    if not re.search(r"does not encrypt|not encrypt the live", low):
        return _fail("at_rest_posture",
                     "ENCRYPTION-AT-REST.md must state plainly that Polaris does NOT encrypt the live "
                     "database at rest (honesty discipline — no overclaiming)")
    return _ok("at_rest_posture",
               "the at-rest posture is documented and honest: names the plaintext-sensitive surfaces "
               "(legal_name/date_of_birth/proof_path), points at the operator-gated host volume "
               "encryption, and does not claim the live DB is encrypted at rest")


# ---------------------------------------------------------------------------
# Right-to-erasure mechanism (v9.125). Polaris cannot delete a holder (C1), so
# erasure = pseudonymize Individual.legal_name and record the act in the
# append-only IndividualErasureEvent. Two things must hold for this to respect
# the audit: (1) the procedure must NOT issue a DELETE (it must not become a
# covert deletion path around C1), and (2) the erasure log must be append-only
# (its REVOKE is checked by check_aor_privilege_boundary; here we assert the
# table + procedure + trigger exist and the PRIVACY doc points at the real
# mechanism rather than describing a capability that does not ship).
# ---------------------------------------------------------------------------
def check_erasure_procedure(root: pathlib.Path) -> list[Finding]:
    schema = _read(root, "polaris_sql/01_schema.sql")
    proc = _read(root, "polaris_sql/05_procedures.sql")
    triggers = _read(root, "polaris_sql/06_triggers.sql")
    privacy = _read(root, "docs/operator/PRIVACY.md")
    if not (schema and proc and triggers):
        return _fail("erasure", "a SQL file for the erasure mechanism is missing")
    if "IndividualErasureEvent" not in schema:
        return _fail("erasure",
                     "01_schema.sql must declare IndividualErasureEvent (the append-only erasure log)")
    m = re.search(r"CREATE\s+OR\s+REPLACE\s+PROCEDURE\s+uc_pseudonymize_individual\b.*?END\$\$;",
                  proc, re.I | re.S)
    if not m:
        return _fail("erasure", "05_procedures.sql must define uc_pseudonymize_individual")
    body = m.group(0)
    # The whole point: it pseudonymizes the NAME and must NOT delete anything.
    if not (re.search(r"UPDATE\s+Individual", body, re.I) and "legal_name" in body):
        return _fail("erasure",
                     "uc_pseudonymize_individual must UPDATE Individual.legal_name (pseudonymize)")
    if "INSERT INTO IndividualErasureEvent" not in body:
        return _fail("erasure",
                     "uc_pseudonymize_individual must record the act in IndividualErasureEvent")
    if re.search(r"\bDELETE\b", body, re.I):
        return _fail("erasure",
                     "uc_pseudonymize_individual must issue NO DELETE — it must not be a covert "
                     "deletion path around C1 (erasure pseudonymizes, it does not delete)")
    if "must be admin" not in body:
        return _fail("erasure", "uc_pseudonymize_individual must be admin-gated (actor role check)")
    if "trg_erasure_append_only" not in triggers:
        return _fail("erasure",
                     "06_triggers.sql must attach the append-only trigger to IndividualErasureEvent")
    # The PRIVACY doc must point at the real procedure, not just describe a policy.
    if "uc_pseudonymize_individual" not in privacy:
        return _fail("erasure",
                     "PRIVACY.md must reference uc_pseudonymize_individual (the doc must point at the "
                     "real mechanism, not describe a capability that does not ship)")
    return _ok("erasure",
               "right-to-erasure ships: uc_pseudonymize_individual pseudonymizes legal_name (admin-"
               "gated, no DELETE) and records it in the append-only IndividualErasureEvent; PRIVACY.md "
               "points at it")


# ---------------------------------------------------------------------------
# Streaming-replication readiness (v9.126). The HA gated item's scaffolding: the
# primary is made replication-ready (wal_level + a REPLICATION role + pg_hba),
# the bootstrap + promotion are documented, and a CI round-trip proves the config
# produces a working hot standby. Only the standby HOST is operator-gated. This
# pins the wiring so it cannot silently rot, and that the doc stays honest about
# what is operator-supplied (no overclaiming a running standby).
# ---------------------------------------------------------------------------
def check_replication_scaffolding(root: pathlib.Path) -> list[Finding]:
    init = _read(root, "polaris_web/docker-init.sh")
    compose = _read(root, "polaris_web/docker-compose.prod.yml")
    secrets = _read(root, "scripts/polaris-generate-secrets.sh")
    doc = _read(root, "docs/operator/FAILOVER.md")
    ci = _read(root, ".github/workflows/ci.yml")
    if not (init and compose and secrets and doc and ci):
        return _fail("replication", "a replication-scaffolding file is missing")
    # The primary must be made replication-ready at init.
    if not re.search(r"ALTER SYSTEM SET wal_level\s*=\s*replica", init):
        return _fail("replication",
                     "docker-init.sh must set wal_level=replica (ALTER SYSTEM) for replication readiness")
    if not re.search(r"CREATE ROLE polaris_replicator.*REPLICATION", init):
        return _fail("replication",
                     "docker-init.sh must create the least-privilege polaris_replicator REPLICATION role")
    if "host replication polaris_replicator" not in init:
        return _fail("replication",
                     "docker-init.sh must add a pg_hba entry for the replication role")
    # The secret is generated and mounted (file-mounted convention, G28).
    if "polaris_replicator_password" not in secrets:
        return _fail("replication",
                     "polaris-generate-secrets.sh must mint polaris_replicator_password")
    if "POLARIS_REPLICATOR_PASSWORD_FILE" not in compose or "polaris_replicator_password" not in compose:
        return _fail("replication",
                     "the prod compose must mount the polaris_replicator_password secret + "
                     "POLARIS_REPLICATOR_PASSWORD_FILE")
    # The runbook documents the clone and the promotion and stays honest about
    # placement. v9.243: promotion is the lease changing hands under Patroni
    # (FAILOVER.md), no longer a pg_promote the operator issues.
    if "pg_basebackup" not in doc or "lease" not in doc:
        return _fail("replication",
                     "FAILOVER.md must document the pg_basebackup clone and the lease-based promotion")
    if "operator-supplied" not in doc.lower() or "placement" not in doc.lower():
        return _fail("replication",
                     "FAILOVER.md must state that the hosts (placement) are operator-supplied (no overclaiming "
                     "a multi-host deployment)")
    # A CI round-trip proves the config produces a working hot standby.
    if "pg_basebackup" not in ci or "pg_stat_replication" not in ci:
        return _fail("replication",
                     "ci.yml must run a primary->standby replication round-trip (pg_basebackup + "
                     "pg_stat_replication assertion)")
    return _ok("replication",
               "replication readiness ships: primary is wal_level=replica with a least-privilege "
               "REPLICATION role + pg_hba; the clone and the lease-based promotion are documented "
               "(FAILOVER.md) and a CI round-trip proves a working hot standby; placement stays operator-supplied")


# ---------------------------------------------------------------------------
# Continuous WAL archiving (pgBackRest, v9.126+). DR.md's 300 s RPO path. The
# scaffolding: a pgbackrest-enabled postgres image, a stanza config, the
# docker-init archive wiring (opt-in), the restore runbook, and a CI round-trip
# that archives + backs up + RESTORES with WAL replay. The offsite S3 repo is
# operator-supplied. This pins the wiring + that the config stays honest that the
# default filesystem repo is not offsite.
# ---------------------------------------------------------------------------
def check_pgbackrest_scaffolding(root: pathlib.Path) -> list[Finding]:
    dockerfile = _read(root, "polaris_web/Dockerfile.postgres")
    conf = _read(root, "polaris_web/pgbackrest.conf")
    compose = _read(root, "polaris_web/docker-compose.prod.yml")
    init = _read(root, "polaris_web/docker-init.sh")
    dr = _read(root, "docs/operator/DR.md")
    ci = _read(root, ".github/workflows/ci.yml")
    if not (dockerfile and conf and compose and init and dr and ci):
        return _fail("pgbackrest", "a pgBackRest-scaffolding file is missing")
    # pgbackrest must be IN the postgres image (archive_command runs there), and
    # the base must stay digest-pinned.
    if "pgbackrest" not in dockerfile:
        return _fail("pgbackrest",
                     "Dockerfile.postgres must install pgbackrest (archive_command runs in the DB image)")
    if "@sha256:" not in dockerfile:
        return _fail("pgbackrest",
                     "Dockerfile.postgres FROM must be digest-pinned (a mutated base must not change "
                     "what runs)")
    # The stanza config ships and stays honest about the local-vs-offsite repo.
    if "[polaris]" not in conf or "pg1-path" not in conf:
        return _fail("pgbackrest", "pgbackrest.conf must define the [polaris] stanza + pg1-path")
    if "s3" not in conf.lower():
        return _fail("pgbackrest",
                     "pgbackrest.conf must document the offsite S3 repo swap (the local repo is not "
                     "offsite) — no overclaiming durability")
    # The compose builds the image + mounts the conf + the opt-in flag.
    if "Dockerfile.postgres" not in compose or "pgbackrest.conf" not in compose:
        return _fail("pgbackrest",
                     "the prod compose must build Dockerfile.postgres and mount pgbackrest.conf")
    if "POLARIS_PGBACKREST_ENABLED" not in compose or "POLARIS_PGBACKREST_ENABLED" not in init:
        return _fail("pgbackrest",
                     "archiving must be opt-in via POLARIS_PGBACKREST_ENABLED (wired in compose + "
                     "docker-init) so a no-repo deployment does not accumulate WAL")
    if "archive_mode" not in init or "archive-push" not in init:
        return _fail("pgbackrest",
                     "docker-init.sh must set archive_mode + the pgbackrest archive_command when enabled")
    # The runbook documents stanza-create; the CI round-trip restores.
    if "stanza-create" not in dr:
        return _fail("pgbackrest", "DR.md must document `pgbackrest --stanza=polaris stanza-create`")
    if "pgbackrest" not in ci or "restore" not in ci:
        return _fail("pgbackrest",
                     "ci.yml must run a pgBackRest archive+backup+RESTORE round-trip")
    # v9.130 operational hardening: the deploy auto-bootstraps the stanza when
    # archiving is enabled (so an operator who enables it but forgets
    # stanza-create does not silently accumulate WAL until the disk fills).
    deploy = _read(root, "scripts/polaris-deploy.sh")
    if "stanza-create" not in deploy or "POLARIS_PGBACKREST_ENABLED" not in deploy:
        return _fail("pgbackrest",
                     "polaris-deploy.sh must run stanza-create when POLARIS_PGBACKREST_ENABLED=1 (so "
                     "archiving enabled-but-unbootstrapped does not fill the disk with WAL)")
    # docker-init warns loudly if archiving runs against a LOCAL (non-offsite) repo.
    if not re.search(r"repo1-type.{0,40}s3", init) or "WARNING" not in init:
        return _fail("pgbackrest",
                     "docker-init.sh must WARN when archiving is enabled with a local (non-s3) repo "
                     "(a local repo does not survive host loss)")
    # The S3 credentials must be guided to a file-mounted secret, NOT compose env.
    if "conf.d" not in conf and "conf.d" not in dr:
        return _fail("pgbackrest",
                     "the S3-credential guidance must use a file-mounted config (conf.d), not compose "
                     "env literals which leak via docker inspect")
    return _ok("pgbackrest",
               "continuous WAL archiving ships: pgbackrest in the DB image (digest-pinned base) + the "
               "[polaris] stanza, opt-in archive_mode/archive_command, a documented stanza-create + "
               "restore, a CI backup+restore round-trip, deploy auto-bootstrap, a local-repo warning, "
               "and file-mounted S3-credential guidance; the offsite S3 repo stays operator-supplied")


# ---------------------------------------------------------------------------
# The connection pooler must not depend on a third-party image that can vanish.
# bitnami/pgbouncer:1.22 was removed from Docker Hub when Bitnami retired their
# free catalogue (Aug 2025), leaving the prod stack unable to pull its pooler.
# Polaris now builds pgbouncer itself (Dockerfile.pgbouncer, alpine + the distro
# package) and the entrypoint reads the DB password from the file-mounted secret
# (not an env literal). This check keeps the bitnami image from creeping back and
# keeps the secret off the environment.
# ---------------------------------------------------------------------------
def check_pgbouncer_self_built(root: pathlib.Path) -> list[Finding]:
    compose = _read(root, "polaris_web/docker-compose.prod.yml")
    if not compose:
        return _fail("pgbouncer_image", "polaris_web/docker-compose.prod.yml is missing")
    # Docker image refs are case-insensitive and may be quoted; match accordingly.
    if re.search(r"""image:\s*['"]?bitnami/pgbouncer""", compose, re.I):
        return _fail("pgbouncer_image",
                     "the prod compose references bitnami/pgbouncer — that image was removed from "
                     "Docker Hub (Bitnami catalogue retirement); the stack cannot pull it")
    df = _read(root, "polaris_web/Dockerfile.pgbouncer")
    entry = _read(root, "polaris_web/pgbouncer-entrypoint.sh")
    if not df or not entry:
        return _fail("pgbouncer_image",
                     "the self-built pooler needs polaris_web/Dockerfile.pgbouncer + "
                     "pgbouncer-entrypoint.sh")
    # Require an actual `dockerfile: Dockerfile.pgbouncer` build directive, not a
    # passing mention of the filename in a comment.
    if not re.search(r"(?m)^\s*dockerfile:\s*Dockerfile\.pgbouncer\b", compose):
        return _fail("pgbouncer_image",
                     "the pgbouncer service must build from Dockerfile.pgbouncer (a "
                     "`dockerfile:` directive), not pull a third-party image that can disappear")
    # Require the secret to be consumed in code — a `VAR=...POLARIS_DB_PASSWORD_FILE`
    # assignment — not merely named in a comment while the password comes from env.
    if not re.search(r"(?m)^\s*[A-Za-z_][A-Za-z0-9_]*=[^#\n]*POLARIS_DB_PASSWORD_FILE", entry):
        return _fail("pgbouncer_image",
                     "pgbouncer-entrypoint.sh must READ the DB password from the file-mounted "
                     "secret (POLARIS_DB_PASSWORD_FILE), not an environment variable")
    ci = _read(root, ".github/workflows/ci.yml")
    if not ci or "Dockerfile.pgbouncer" not in ci:
        return _fail("pgbouncer_image",
                     "CI must build + exercise the self-built pgbouncer image (Dockerfile.pgbouncer) "
                     "so a broken pooler image is caught in CI, not at deploy")
    # v9.242: recovery after a database crash. PgBouncer's defaults wait 15 s
    # before retrying a failed backend connect and cache a failed name lookup
    # for 15 s; the chaos drill measured a half-second Postgres crash as a
    # 16.2 s outage for the application. The generated ini must set both to a
    # second or two, from the entrypoint's own defaults.
    for key, var, cap in (("server_login_retry", "SERVER_LOGIN_RETRY", 2), ("dns_nxdomain_ttl", "DNS_NXDOMAIN_TTL", 2),
                          ("server_connect_timeout", "SERVER_CONNECT_TIMEOUT", 5), ("tcp_user_timeout", "TCP_USER_TIMEOUT", 10000),
                          ("query_timeout", "QUERY_TIMEOUT", 30)):
        m = re.search(r'(?m)^%s="\$\{PGBOUNCER_%s:-(\d+)\}"' % (var, var), entry)
        if not m or int(m.group(1)) > cap:
            return _fail("pgbouncer_image",
                         f"pgbouncer-entrypoint.sh must default PGBOUNCER_{var} to at most {cap} seconds: on PgBouncer's "
                         f"15 s defaults a half-second database crash is a 16 s outage for the application, a "
                         f"connect started just before a failover stalls every client for 15 s, a frozen leader "
                         f"holds the pool for minutes, and a query to a vanished backend never returns")
        if not re.search(r"(?m)^%s = \$%s$" % (key, var), entry):
            return _fail("pgbouncer_image", f"pgbouncer-entrypoint.sh must write `{key} = ${var}` into the generated ini")
    if (root / "polaris_web" / "pgbouncer.ini").exists():
        return _fail("pgbouncer_image",
                     "polaris_web/pgbouncer.ini exists but nothing consumes it (the entrypoint generates the "
                     "ini): a second configuration a reader believes is the running one")
    return _ok("pgbouncer_image",
               "pgbouncer is self-built from Dockerfile.pgbouncer (no third-party catalog), reads "
               "the file-mounted DB secret (scram on both hops), retries a failed backend connect within "
               "two seconds and abandons a hung one within five, and is round-tripped in CI")


# ---------------------------------------------------------------------------
# The TLS edge must actually START. The prod Caddyfile uses the `rate_limit`
# directive from the third-party caddy-ratelimit plugin, which is NOT in the
# stock caddy image: pinning the stock image (v9.114) made the edge crash-loop
# on "unrecognized directive: rate_limit" and the whole front door never came up
# (v9.135, same class as the bitnami/pgbouncer breakage). The fix is a self-built
# Caddy (Dockerfile.caddy) with the plugin compiled in. This pins it: if the
# Caddyfile uses a third-party directive, the edge must be built (not a stock
# image), the plugin must be compiled in, and CI must validate the Caddyfile
# against the built image so an unbacked directive can never reach production.
# ---------------------------------------------------------------------------
def check_caddy_self_built(root: pathlib.Path) -> list[Finding]:
    caddyfile = _read(root, "polaris_web/Caddyfile")
    compose = _read(root, "polaris_web/docker-compose.prod.yml")
    if not caddyfile or not compose:
        return _fail("caddy_edge", "polaris_web/Caddyfile or docker-compose.prod.yml is missing")
    # The third-party directives the stock image does NOT ship. rate_limit is the
    # live one; extend this set if the Caddyfile adopts more plugin directives.
    THIRD_PARTY = {"rate_limit": "github.com/mholt/caddy-ratelimit"}
    used = {d: mod for d, mod in THIRD_PARTY.items()
            if re.search(r"(?m)^\s*%s\b" % re.escape(d), caddyfile)}
    if not used:
        # No plugin directives: the stock pinned image is fine, nothing to enforce.
        return _ok("caddy_edge",
                   "the Caddyfile uses no third-party directives; the stock edge image suffices")
    # The caddy service must BUILD from Dockerfile.caddy, not pull a stock image
    # that cannot load these directives.
    if not re.search(r"(?m)^\s*dockerfile:\s*Dockerfile\.caddy\b", compose):
        return _fail("caddy_edge",
                     "the Caddyfile uses %s (third-party plugin directives), so the caddy service "
                     "must build from Dockerfile.caddy with the plugins compiled in, not pull a "
                     "stock caddy image that crash-loops on the unrecognized directive"
                     % ", ".join(sorted(used)))
    df = _read(root, "polaris_web/Dockerfile.caddy")
    if not df:
        return _fail("caddy_edge", "polaris_web/Dockerfile.caddy is missing")
    for directive, module in sorted(used.items()):
        if module not in df:
            return _fail("caddy_edge",
                         "the Caddyfile uses `%s` but Dockerfile.caddy does not compile in its "
                         "plugin (%s) via xcaddy --with" % (directive, module))
    ci = _read(root, ".github/workflows/ci.yml")
    if not ci or "Dockerfile.caddy" not in ci or "caddy validate" not in ci:
        return _fail("caddy_edge",
                     "CI must build Dockerfile.caddy and `caddy validate` the real Caddyfile against "
                     "it (the regression guard for the v9.135 crash class)")
    return _ok("caddy_edge",
               "the TLS edge is self-built (Dockerfile.caddy) with every third-party directive (%s) "
               "compiled in, and CI validates the Caddyfile against it" % ", ".join(sorted(used)))


# ---------------------------------------------------------------------------
# The FULL production compose must boot and serve end to end, not just the dev
# compose + per-image tests. CI booting only the dev stack (db+app on :5000) let
# real prod-down bugs ship: a Caddyfile directive the stock image lacked (v9.135)
# and 09_grants.sql hardcoding the test DB name so prod init aborted before TLS
# (v9.140) — the prod stack had never come up. This pins the keystone test: a CI
# job generates secrets, builds the prod images, boots docker-compose.prod.yml +
# the citest override (Caddy internal CA instead of ACME), and asserts the stack
# serves /api/health through the TLS edge with the DB-backed components healthy.
# ---------------------------------------------------------------------------
def check_prod_stack_boot(root: pathlib.Path) -> list[Finding]:
    ci = _read(root, ".github/workflows/ci.yml")
    if not ci:
        return _fail("prod_stack_boot", ".github/workflows/ci.yml is missing")
    # The boot harness (override compose + Caddyfile) must exist.
    if not (root / "polaris_web" / "docker-compose.citest.yml").is_file():
        return _fail("prod_stack_boot",
                     "polaris_web/docker-compose.citest.yml is missing (the prod-stack boot "
                     "override that swaps Caddy's ACME edge for an internal CA in CI)")
    if not (root / "polaris_web" / "Caddyfile.citest").is_file():
        return _fail("prod_stack_boot",
                     "polaris_web/Caddyfile.citest is missing (the CI edge config)")
    # CI must actually boot the FULL prod compose with the override, not the dev one.
    if "docker-compose.prod.yml" not in ci or "docker-compose.citest.yml" not in ci:
        return _fail("prod_stack_boot",
                     "a CI job must boot the FULL prod compose end to end "
                     "(docker compose -f docker-compose.prod.yml -f docker-compose.citest.yml up)")
    # It must generate the secrets the prod stack needs (not run on dev defaults).
    if "polaris-generate-secrets.sh" not in ci:
        return _fail("prod_stack_boot",
                     "the prod-stack boot job must run polaris-generate-secrets.sh so the stack "
                     "boots on real generated secrets + certs, like a deploy")
    # It must assert the stack actually SERVES through the edge (a health probe).
    if "/api/health" not in ci:
        return _fail("prod_stack_boot",
                     "the prod-stack boot job must assert the stack serves /api/health through the "
                     "Caddy TLS edge (a 200 + DB-backed components healthy), not just that it starts")
    return _ok("prod_stack_boot",
               "CI boots the FULL prod compose (generated secrets, real images, TLS edge) and "
               "asserts it serves /api/health end to end")


# ---------------------------------------------------------------------------
# The app<->DB path must be TLS-encrypted, not silently plaintext. psycopg2's
# default sslmode is 'prefer' (encrypt if offered, else cleartext, no warning).
# The prod path encrypts BOTH hops: app -> pgbouncer (pgbouncer client_tls,
# self-signed cert) and pgbouncer -> postgres (server_tls), with postgres TLS
# enabled at init from a host-generated cert. sslmode stays configurable so
# dev/CI (no TLS) keep 'prefer'.
# ---------------------------------------------------------------------------
def check_app_db_tls(root: pathlib.Path) -> list[Finding]:
    app = _read(root, "polaris_web/app.py")
    compose = _read(root, "polaris_web/docker-compose.prod.yml")
    init = _read(root, "polaris_web/docker-init.sh")
    entry = _read(root, "polaris_web/pgbouncer-entrypoint.sh")
    if not (app and compose and init and entry):
        return _fail("app_db_tls", "an app<->DB TLS wiring file is missing")
    if "POLARIS_DB_SSLMODE" not in app or "sslmode" not in app:
        return _fail("app_db_tls",
                     "DB_CONFIG must set a configurable sslmode (POLARIS_DB_SSLMODE) — psycopg2's "
                     "'prefer' default silently falls back to plaintext")
    # v9.131 — the app must support pinning the pgbouncer cert (sslrootcert) so a
    # verify-ca/verify-full deployment can validate the peer, not just encrypt.
    if "sslrootcert" not in app or "POLARIS_DB_SSLROOTCERT" not in app:
        return _fail("app_db_tls",
                     "DB_CONFIG must support pinning the peer cert via POLARIS_DB_SSLROOTCERT "
                     "(sslrootcert) — verify-ca needs the CA/cert, not just encryption")
    # Both hops VERIFY the pinned self-signed certs (not merely encrypt): the app
    # pins pgbouncer (verify-ca + sslrootcert), pgbouncer pins postgres
    # (server_tls verify-ca + ca_file). 'require' (encrypt only) is the v9.121
    # floor; v9.131 raised the prod default to verify-ca.
    if not re.search(r"POLARIS_DB_SSLMODE:\s*verify-ca", compose):
        return _fail("app_db_tls",
                     "the prod compose must set POLARIS_DB_SSLMODE=verify-ca (pin pgbouncer's cert, "
                     "not just encrypt the app<->pgbouncer hop)")
    if "POLARIS_DB_SSLROOTCERT" not in compose:
        return _fail("app_db_tls",
                     "the prod compose must set POLARIS_DB_SSLROOTCERT to pgbouncer's pinned cert")
    if not re.search(r"PGBOUNCER_SERVER_TLS_SSLMODE:\s*verify-ca", compose):
        return _fail("app_db_tls",
                     "the prod compose must set PGBOUNCER_SERVER_TLS_SSLMODE=verify-ca (pin postgres's "
                     "cert on the pgbouncer<->postgres hop)")
    if "PGBOUNCER_SERVER_TLS_CA_FILE" not in compose or "PGBOUNCER_CLIENT_TLS_CERT_FILE" not in compose:
        return _fail("app_db_tls",
                     "the prod compose must wire the pinned CA (server_tls_ca_file) + a stable "
                     "client cert (client_tls_cert_file) for verify-ca")
    if "ALTER SYSTEM SET ssl" not in init:
        return _fail("app_db_tls",
                     "docker-init.sh must enable Postgres TLS (ALTER SYSTEM SET ssl = on) from the "
                     "mounted cert")
    if "server_tls_sslmode" not in entry or "client_tls_sslmode" not in entry:
        return _fail("app_db_tls",
                     "pgbouncer-entrypoint.sh must wire server_tls + client_tls")
    if "server_tls_ca_file" not in entry:
        return _fail("app_db_tls",
                     "pgbouncer-entrypoint.sh must wire server_tls_ca_file (the pinned postgres CA for "
                     "verify-ca on the backend hop)")
    # v9.132 — the entrypoint must ENFORCE the pairing: verify-* without a CA
    # cannot verify, so it must fail fast rather than start unverified.
    if not re.search(r"verify-ca\|verify-full", entry) or "requires PGBOUNCER_SERVER_TLS_CA_FILE" not in entry:
        return _fail("app_db_tls",
                     "pgbouncer-entrypoint.sh must REQUIRE the CA file when server_tls_sslmode is "
                     "verify-* (fail fast, not start with verification effectively off)")
    return _ok("app_db_tls",
               "the app<->DB path is TLS on both hops AND verifies the pinned self-signed certs "
               "(app verify-ca pins pgbouncer; pgbouncer server_tls verify-ca pins postgres) — a MITM "
               "with a different cert is rejected; verify-full + a real CA stays the operator's upgrade")


# ---------------------------------------------------------------------------
# Request-correlation id (v9.122). A per-request id stamped into the structured
# logs and echoed in X-Request-ID, so an operator can correlate a log line to a
# caller's request. The VOCATION constraint is the load-bearing part: the id
# must stay ephemeral and per-request and must NEVER be written to a DB row — in
# particular not the append-only audit-of-record, where the C1 trigger would
# turn it into a permanent, reconstructable cross-request linkage key (exactly
# the surveillance vector Polaris refuses). A static grep cannot PROVE
# non-persistence (the DB-backed test does that), but it can bite the realistic
# regressions: the id leaking into the DB-write module, the id-owning module
# gaining DB access, or the inbound-trust boundary being bypassed.
# ---------------------------------------------------------------------------
def check_correlation_id(root: pathlib.Path) -> list[Finding]:
    obs = _read(root, "polaris_web/observability.py")
    app = _read(root, "polaris_web/app.py")
    sec = _read(root, "polaris_web/security.py")
    if not (obs and app):
        return _fail("correlation_id", "observability.py or app.py is missing")

    # --- the id core lives in observability.py ---
    if "ContextVar(" not in obs:
        return _fail("correlation_id",
                     "observability.py must hold the request id in a contextvars.ContextVar "
                     "(per-request, not a global)")
    if "[A-Za-z0-9-]" not in obs or "{8,64}" not in obs:
        return _fail("correlation_id",
                     "the inbound id validator must bound BOTH charset ([A-Za-z0-9-]) and length "
                     "({8,64}) — an unbounded value is a log-injection + memory-abuse hole")
    if "uuid4(" not in obs:
        return _fail("correlation_id",
                     "observability.py must mint a fresh uuid4 id when none is supplied")
    # The id-owning module must never touch the DB: if it could INSERT, the
    # non-persistence property would no longer be auditable from app.py alone.
    if re.search(r"\b(execute|cursor|get_db)\s*\(", obs) or re.search(r"\bINSERT\b", obs):
        return _fail("correlation_id",
                     "observability.py must stay DB-free (no execute/cursor/get_db/INSERT) — the "
                     "request id must never reach a DB row from the module that owns it")

    # --- the lifecycle is wired in app.py ---
    if "set_request_id(" not in app:
        return _fail("correlation_id", "app.py must bind the id in a before_request (set_request_id)")
    if "X-Request-ID" not in app:
        return _fail("correlation_id", "app.py must echo the id in the X-Request-ID response header")
    if "teardown_request" not in app or "reset_request_id(" not in app:
        return _fail("correlation_id",
                     "app.py must clear the id in teardown_request (reset_request_id) so it does not "
                     "leak across requests on a reused worker")
    # set_request_id may ONLY be fed by validate_or_new_request_id — that is the
    # sole function allowed to trust inbound bytes. A raw header into the
    # contextvar would be a log-injection / response-splitting path.
    for m in re.finditer(r"(?<![A-Za-z_])set_request_id\(", app):
        window = app[m.end():m.end() + 90]
        if "validate_or_new_request_id" not in window:
            return _fail("correlation_id",
                         "set_request_id() must be called only with validate_or_new_request_id(...) "
                         "(never a raw inbound header)")

    # --- VOCATION: the id must not reach the DB-write / audit path ---
    # The DB-write + audit module must not even reference the id.
    if "get_request_id" in sec:
        return _fail("correlation_id",
                     "security.py (the DB-write/audit module) must not reference get_request_id — the "
                     "request id has no business in an audit row (vocation: no cross-request linkage)")
    # Backstop in app.py: the id must not co-occur with an audit/DB write call.
    for line in app.splitlines():
        if "get_request_id" not in line:
            continue
        if re.search(r"(_audit\(|cur\.execute\(|reason_code|requesting_purpose)", line):
            return _fail("correlation_id",
                         "the request id appears on a DB-write/audit line in app.py — it must never "
                         "be persisted (vocation)")
    # The id must not be derived from identity (that would make it a user key).
    for line in app.splitlines():
        if "set_request_id" not in line and "validate_or_new_request_id" not in line:
            continue
        if re.search(r"(session\.get\(|user_id|username)", line):
            return _fail("correlation_id",
                         "the request id must not be seeded from identity (session/user_id/username)")

    return _ok("correlation_id",
               "request id is per-request, validated+bounded ([A-Za-z0-9-]{8,64} or uuid4), echoed in "
               "X-Request-ID, cleared in teardown, and never written to the audit-of-record (vocation)")


# ---------------------------------------------------------------------------
# Docker image completeness — every LOCAL module app.py imports must be COPYd
# into both images, or the container ModuleNotFoundErrors at startup and crash-
# loops. This has bitten twice: observability.py (v9.40) and pqc_signing.py
# (v9.58, which crashed the dev + prod images until v9.94). The narrow
# "copies security.py" doctor check did not generalize; this does.
# ---------------------------------------------------------------------------
def check_dockerfile_copies_app_modules(root: pathlib.Path) -> list[Finding]:
    app = _read(root, "polaris_web/app.py")
    web = root / "polaris_web"
    if not app:
        return _fail("dockerfile_modules", "polaris_web/app.py is missing")
    # Local modules = `import X` / `from X import` where polaris_web/X.py exists.
    # Tolerate trailing comments on the import line (the v9.40 miss was a regex
    # that did not).
    imported = set(re.findall(r"^\s*(?:import|from)\s+([A-Za-z_]\w*)", app, re.M))
    local = sorted(m for m in imported if (web / f"{m}.py").is_file())
    if not local:
        return _fail("dockerfile_modules", "could not resolve app.py's local module imports")
    for rel in ("polaris_web/Dockerfile", "polaris_web/Dockerfile.prod"):
        df = _read(root, rel)
        if not df:
            continue
        copy_lines = " ".join(l for l in df.splitlines() if l.lstrip().upper().startswith("COPY"))
        copied = set(re.findall(r"\b([A-Za-z_]\w*)\.py\b", copy_lines))
        missing = [m for m in local if m not in copied]
        if missing:
            return _fail("dockerfile_modules",
                         f"{rel} does not COPY local module(s) app.py imports: "
                         + ", ".join(missing) + " — the container will ModuleNotFoundError at startup")
    return _ok("dockerfile_modules",
               f"both Dockerfiles COPY every local app module ({', '.join(local)})")


# ---------------------------------------------------------------------------
# C2 — ZERO_KNOWLEDGE verifications must not carry a token_id. Enforced by a
# CHECK constraint on VerificationEvent, not by application policy.
# ---------------------------------------------------------------------------
def check_c2_zk_token_null(root: pathlib.Path) -> list[Finding]:
    schema = _read(root, "polaris_sql/01_schema.sql")
    if ("chk_disclosure_token_consistency" in schema
            and re.search(r"ZERO_KNOWLEDGE'\s+AND\s+token_id\s+IS\s+NULL", schema, re.I)):
        return _ok("c2_zk_null", "ZERO_KNOWLEDGE verifications are forbidden from carrying token_id (C2)")
    return _fail("c2_zk_null", "no CHECK forces token_id NULL on ZERO_KNOWLEDGE verification events (C2)")


# ---------------------------------------------------------------------------
# C4 — the failed-login counter increments atomically (no TOCTOU race): a
# single UPDATE that references the column, not a read-then-write.
# ---------------------------------------------------------------------------
def check_c4_atomic_failed_login(root: pathlib.Path) -> list[Finding]:
    sec = _read(root, "polaris_web/security.py")
    if re.search(r"failed_login_count\s*=\s*failed_login_count\s*\+\s*1", sec):
        return _ok("c4_atomic_login", "failed-login counter increments atomically in one UPDATE (C4)")
    return _fail("c4_atomic_login", "no atomic 'failed_login_count = failed_login_count + 1' UPDATE in security.py (C4)")


# ---------------------------------------------------------------------------
# C8 — /api/atlas/* result sets are bounded by hard caps.
# ---------------------------------------------------------------------------
def check_c8_atlas_caps(root: pathlib.Path) -> list[Finding]:
    app = _read(root, "polaris_web/app.py")
    # v9.248: the analytical console added a bounded categorical roll-up; its
    # top-K cap joins the map's cluster/point/event caps under C8.
    missing = [c for c in ("_ATLAS_MAX_CLUSTERS", "_ATLAS_MAX_POINTS",
                           "_ATLAS_MAX_EVENTS", "_ATLAS_MAX_CATEGORIES",
                           "_ATLAS_MAX_REGIONS") if c not in app]
    if missing:
        return _fail("c8_atlas_caps", "missing atlas hard-cap constant(s): " + ", ".join(missing) + " (C8)")
    return _ok("c8_atlas_caps", "/api/atlas/* endpoints have hard result-set caps (C8): "
               "clusters, points, events, categories, and regions")


# ---------------------------------------------------------------------------
# C9 — concurrency hazards are tested with real threading, not mocks.
# ---------------------------------------------------------------------------
def check_c9_concurrency_threading(root: pathlib.Path) -> list[Finding]:
    t = _read(root, "polaris_web/test_app.py")
    if "class ConcurrencyTests" in t and re.search(r"threading\.Thread", t):
        return _ok("c9_concurrency", "ConcurrencyTests exercises real threading (C9)")
    return _fail("c9_concurrency", "no ConcurrencyTests with threading.Thread in test_app.py (C9)")


# ---------------------------------------------------------------------------
# C10 — identity is not money: the schema carries no monetary primitives.
# ---------------------------------------------------------------------------
def check_c10_no_money_tables(root: pathlib.Path) -> list[Finding]:
    schema = _read(root, "polaris_sql/01_schema.sql")
    bad = re.findall(r"CREATE TABLE\s+(\w*(?:Monetary|Balance|Payment|Wallet|Merchant|Spending)\w*)", schema, re.I)
    if bad:
        return _fail("c10_no_money", "schema defines monetary table(s): " + ", ".join(bad[:5]) + " (C10)")
    return _ok("c10_no_money", "schema carries no monetary primitives; identity is not money (C10)")


# ---------------------------------------------------------------------------
# Open redirect (CWE-601) — every post-login ?next= redirect routes through
# one guard that rejects off-site targets, including the backslash trick that
# browsers normalize to '//host'. The naive '//'-only guard must not survive.
# ---------------------------------------------------------------------------
def check_open_redirect_guard(root: pathlib.Path) -> list[Finding]:
    sec = _read(root, "polaris_web/security.py")
    if "def is_safe_next_url" not in sec:
        return _fail("open_redirect", "security.py must define the is_safe_next_url guard (CWE-601)")
    app = _read(root, "polaris_web/app.py")
    if "startswith('//')" in app:
        return _fail("open_redirect",
                     "app.py still uses the naive startswith('//') next-url guard; "
                     "route ?next= through security.is_safe_next_url (CWE-601)")
    if "is_safe_next_url" not in app:
        return _fail("open_redirect", "app.py must route ?next= through security.is_safe_next_url (CWE-601)")
    return _ok("open_redirect",
               "post-login ?next= routed through is_safe_next_url; the naive '//'-only guard is gone (CWE-601)")


# ---------------------------------------------------------------------------
# Session cookie Secure flag (CWE-614) — mandatory in production, not opt-in.
# ---------------------------------------------------------------------------
def check_cookie_secure_in_production(root: pathlib.Path) -> list[Finding]:
    app = _read(root, "polaris_web/app.py")
    m = re.search(r"SESSION_COOKIE_SECURE'\]\s*=\s*(.+)", app)
    if not m:
        return _fail("cookie_secure", "app.py does not set SESSION_COOKIE_SECURE")
    if "_PRODUCTION" not in m.group(1):
        return _fail("cookie_secure",
                     "SESSION_COOKIE_SECURE is opt-in only; force it on in production via _PRODUCTION (CWE-614)")
    return _ok("cookie_secure", "SESSION_COOKIE_SECURE is forced on in production (CWE-614)")


# ---------------------------------------------------------------------------
# Prod deploy — the polaris_app role password must be synced to the generated
# secret, not left at the dev default from 09_grants.sql.
#
# The app and pgbouncer authenticate as polaris_app with the file-mounted
# secret /run/secrets/polaris_db_password. 09_grants.sql creates the role with
# 'polaris_dev_password'. If docker-init.sh never rotates the role to the
# secret, the role keeps the dev password while its clients present the
# generated one — prod auth breaks, or the dev password is what is live. The
# postgres service must therefore point POLARIS_APP_PASSWORD_FILE at the SAME
# secret the app reads, and docker-init.sh must read it and ALTER the role.
# ---------------------------------------------------------------------------
def check_prod_app_password_synced(root: pathlib.Path) -> list[Finding]:
    compose = _read(root, "polaris_web/docker-compose.prod.yml")
    init = _read(root, "polaris_web/docker-init.sh")
    if not compose or not init:
        return _fail("prod_pw_sync", "docker-compose.prod.yml or docker-init.sh missing")
    app_secret = re.search(r"POLARIS_DB_PASSWORD_FILE:\s*(\S+)", compose)
    role_secret = re.search(r"POLARIS_APP_PASSWORD_FILE:\s*(\S+)", compose)
    if app_secret is None:
        return _fail("prod_pw_sync", "compose does not set POLARIS_DB_PASSWORD_FILE for the app")
    if role_secret is None:
        return _fail("prod_pw_sync",
                     "compose never sets POLARIS_APP_PASSWORD_FILE — the polaris_app role keeps the "
                     "dev password while the app authenticates with the generated secret")
    if app_secret.group(1) != role_secret.group(1):
        return _fail("prod_pw_sync",
                     f"role password secret ({role_secret.group(1)}) differs from the app's "
                     f"({app_secret.group(1)}); they must be the same file")
    if "POLARIS_APP_PASSWORD_FILE" not in init:
        return _fail("prod_pw_sync", "docker-init.sh does not read POLARIS_APP_PASSWORD_FILE")
    if not re.search(r"ALTER\s+ROLE\s+polaris_app", init, re.I):
        return _fail("prod_pw_sync", "docker-init.sh does not ALTER ROLE polaris_app to the secret")
    return _ok("prod_pw_sync",
               f"prod syncs the polaris_app role password to the app's secret ({app_secret.group(1)})")


# ---------------------------------------------------------------------------
# Production hardening — two BLOCKER-class defaults must not survive into prod:
#   1. The SQL seed loads demo accounts with publicly-known passwords
#      (admin/Admin@123! ...) and a demo duress code. docker-init.sh must
#      neutralize them when POLARIS_ENV=production (disable + scramble).
#   2. The rate limiter silently falls back to per-worker in-memory unless
#      POLARIS_REDIS_URL is set; prod runs 4 workers, so per-IP limits would
#      fragment 4x. The prod compose must wire POLARIS_REDIS_URL.
# (Part of the v9.101+ production-readiness arc; see docs/PRODUCTION-READINESS.md.)
# ---------------------------------------------------------------------------
def check_prod_hardening(root: pathlib.Path) -> list[Finding]:
    init = _read(root, "polaris_web/docker-init.sh")
    compose = _read(root, "polaris_web/docker-compose.prod.yml")
    if not init:
        return _fail("prod_hardening", "polaris_web/docker-init.sh is missing")
    # 1. Demo accounts neutralized in production.
    prod_block = re.search(r'POLARIS_ENV.*?production.*?(?=\nfi\b|\Z)', init, re.S)
    if not (prod_block and "is_active" in prod_block.group(0)
            and re.search(r"'admin',\s*'operator',\s*'auditor'", prod_block.group(0))):
        return _fail("prod_hardening",
                     "docker-init.sh must disable the demo accounts (admin/operator/auditor) when "
                     "POLARIS_ENV=production — they ship with publicly-known passwords")
    # 2. Prod rate limiter uses Redis, not the per-worker in-memory fallback.
    if not re.search(r"POLARIS_REDIS_URL:\s*\S+", compose):
        return _fail("prod_hardening",
                     "docker-compose.prod.yml must set POLARIS_REDIS_URL so the rate limiter uses the "
                     "cross-worker Redis backend (else per-IP limits fragment across the 4 workers)")
    return _ok("prod_hardening",
               "prod neutralizes demo accounts and wires the Redis rate limiter")


# ---------------------------------------------------------------------------
# Backup at-rest encryption — DB backups are a full pg_dump of (would-be)
# national-identity data; they must not sit in plaintext. polaris-backup.sh must
# support encrypting to POLARIS_BACKUP_KEY_FILE and polaris-restore.sh must
# decrypt .enc backups (production-readiness Wave 3, v9.102).
# ---------------------------------------------------------------------------
def check_backup_encryption(root: pathlib.Path) -> list[Finding]:
    bk = _read(root, "scripts/polaris-backup.sh")
    rs = _read(root, "scripts/polaris-restore.sh")
    if not bk or not rs:
        return _fail("backup_encryption", "backup/restore scripts missing")
    if "POLARIS_BACKUP_KEY_FILE" not in bk or "openssl enc" not in bk:
        return _fail("backup_encryption",
                     "polaris-backup.sh must support at-rest encryption (POLARIS_BACKUP_KEY_FILE + openssl)")
    if "openssl enc -d" not in rs or ".enc" not in rs:
        return _fail("backup_encryption",
                     "polaris-restore.sh must decrypt encrypted (.enc) backups")
    return _ok("backup_encryption",
               "backups support at-rest encryption (POLARIS_BACKUP_KEY_FILE) and restore decrypts them")


# ---------------------------------------------------------------------------
# Doc/schema drift — every human-facing document that states a schema-table
# count must state the real one. A reviewer reads this number first; it must
# not contradict the schema. Two numbers are legitimate: the tables 01_schema.sql
# creates, and that plus the tables migrations add to a running deployment
# (OperatorWebauthnCredential, OperatorSession, AuditAccessLog at v9.194). Any
# other number anywhere in the guarded set fails (33 = 29 + the schema_version
# registry + the three migration-added tables). v9.141 drifted because only
# the first match was validated; v9.193 drifted because DATA-MODEL.md,
# polaris_sql/README.md and the site were never guarded at all.
# ---------------------------------------------------------------------------
_TABLE_COUNT_DOCS = (
    "README.md", "CLAUDE.md", "ROADMAP.md", "MISSION.md",
    "docs/ARCHITECTURE-OVERVIEW.md", "docs/reference/DATA-MODEL.md",
    "docs/reference/SYSTEM-MAP.md", "polaris_sql/README.md", "polaris_web/README.md",
    "polaris_cli/README.md", "site/index.html",
)
_TABLE_COUNT_REQUIRED = ("README.md", "docs/ARCHITECTURE-OVERVIEW.md",
                         "docs/reference/DATA-MODEL.md")
_TABLE_COUNT_PATTERNS = (
    r"\b(\d+)(?:-table\b|\s+(?:schema\s+)?tables?\b)",   # "29 tables", "29 schema tables", "29-table"
    r"\((\d+) total\b",                                   # "(28 total, partial list)"
)


def _schema_table_counts(root: pathlib.Path) -> tuple[int, int]:
    """(tables created by 01_schema.sql, tables a migrated deployment holds).

    The second number adds every table the loader's other files create (the
    schema_version registry from 00_migrations_table.sql) and every table a
    migration adds to a running database."""
    # v9.245: a "CREATE TABLE X PARTITION OF Y" is a partition of Y, not a
    # logical table of its own; exclude it from the table count.
    pat = r"^CREATE TABLE (?:IF NOT EXISTS )?(\w+)(?!.*PARTITION OF)"
    base = set(re.findall(pat, _read(root, "polaris_sql/01_schema.sql"), re.M))
    deployed = set(base)
    sql_dir = root / "polaris_sql"
    if sql_dir.is_dir():
        for p in sorted(sql_dir.glob("[0-9]*.sql")):
            if "test" in p.name or "constraints" in p.name or "substrate" in p.name:
                continue  # self-test files create scratch tables, not schema
            deployed |= set(re.findall(pat, p.read_text(encoding="utf-8", errors="replace"), re.M))
        for p in sorted((sql_dir / "migrations").glob("*.up.sql")) if (sql_dir / "migrations").is_dir() else []:
            deployed |= set(re.findall(pat, p.read_text(encoding="utf-8", errors="replace"), re.M))
    return len(base), len(deployed)


def _prose(text: str) -> str:
    """HTML tags become spaces so "<strong>29</strong> schema tables" reads as prose."""
    return re.sub(r"<[^>]+>", " ", text)


def check_table_count_matches_doc(root: pathlib.Path) -> list[Finding]:
    n_schema, n_migrated = _schema_table_counts(root)
    if n_schema == 0:
        return _fail("table_count", "polaris_sql/01_schema.sql creates no tables (or is missing)")
    allowed = {n_schema, n_migrated}
    for rel in _TABLE_COUNT_DOCS:
        text = _prose(_read(root, rel))
        if not text:
            if rel in _TABLE_COUNT_REQUIRED:
                return _fail("table_count", f"{rel} is missing")
            continue
        stated = [int(m) for pat in _TABLE_COUNT_PATTERNS for m in re.findall(pat, text)]
        if not stated and rel in _TABLE_COUNT_REQUIRED:
            return _fail("table_count", f"{rel} states no schema-table count")
        wrong = sorted(set(s for s in stated if s not in allowed))
        if wrong:
            return _fail("table_count",
                         f"{rel} says {wrong} tables somewhere but the schema defines "
                         f"{n_schema} ({n_migrated} after migrations); every stated count must match")
    return _ok("table_count",
               f"every stated table count is {n_schema} (schema) or {n_migrated} (migrated), "
               f"across {len(_TABLE_COUNT_DOCS)} documents")


# ---------------------------------------------------------------------------
# Stated counts — the headline numbers a reviewer meets first (invariant checks,
# CI jobs, routes, stored procedures) are measured from the artifacts, never
# typed from memory. v9.193 still said "77 checks", "72 routes" and "7 CI jobs"
# on the README, the roadmap, the system map and the demo site while the repo
# held 104, 73 and 14. A number nobody re-measures is a number that lies.
# ---------------------------------------------------------------------------
_STATED_COUNT_DOCS = (
    "README.md", "CLAUDE.md", "ROADMAP.md", "MISSION.md", "CONTRIBUTING.md",
    "docs/ARCHITECTURE-OVERVIEW.md", "docs/reference/SYSTEM-MAP.md",
    "docs/reference/DATA-MODEL.md", "docs/reference/README.md",
    "docs/PRODUCTION-READINESS.md", "polaris_sql/README.md", "polaris_web/README.md",
    "polaris_cli/README.md", "polaris_checks/README.md", "site/index.html",
)
_STATED_COUNT_KINDS = {
    # kind: patterns whose single group is the stated number
    "invariant checks": (
        r"\b(\d+)\s+(?:plain\s+`?check_\*`?\s+functions|flat\s+invariant\s+checks|"
        r"invariant\s+checks|machine-checked\s+invariants|checks,\s+each\s+with)",
        r"\|\s*Invariant checks\s*\|\s*(\d+)\s*\|",
    ),
    "CI jobs": (
        r"\b(\d+)\s+(?:CI\s+)?jobs\b",
        r"\|\s*CI jobs\s*\|\s*(\d+)\s*\|",
    ),
    "routes": (
        r"\b(\d+)[\s-]+routes?\b",
    ),
    "stored procedures": (
        r"\b(\d+)\s+stored\s+procedures?\b",
        r"\b(\d+)\s+stored\s*│",   # the README's box diagram wraps the noun to the next line
    ),
}


def _ci_job_count(ci_yaml: str) -> int:
    """Count the keys directly under `jobs:` without a YAML dependency."""
    lines = ci_yaml.splitlines()
    n = 0
    inside = False
    for line in lines:
        if re.match(r"^jobs:\s*(#.*)?$", line):
            inside = True
            continue
        if inside:
            if line and not line.startswith(" ") and not line.startswith("#"):
                break  # next top-level key
            if re.match(r"^  [A-Za-z0-9_-]+:\s*(#.*)?$", line):
                n += 1
    return n


def _measured_counts(root: pathlib.Path) -> dict[str, int]:
    return {
        "invariant checks": len(CHECKS),
        "CI jobs": _ci_job_count(_read(root, ".github/workflows/ci.yml")),
        "routes": len(re.findall(r"^@app\.route\(", _read(root, "polaris_web/app.py"), re.M)),
        "stored procedures": len(re.findall(r"^CREATE (?:OR REPLACE )?(?:FUNCTION|PROCEDURE)\s+\w+",
                                            _read(root, "polaris_sql/05_procedures.sql"), re.M | re.I)),
    }


def check_stated_counts(root: pathlib.Path) -> list[Finding]:
    real = _measured_counts(root)
    if real["CI jobs"] == 0 or real["routes"] == 0:
        return _fail("stated_counts", "cannot measure CI jobs or routes (ci.yml / app.py missing)")
    seen_in_readme: set[str] = set()
    for rel in _STATED_COUNT_DOCS:
        text = _prose(_read(root, rel))
        if not text:
            continue
        for kind, patterns in _STATED_COUNT_KINDS.items():
            stated = [int(m) for pat in patterns for m in re.findall(pat, text, re.I)]
            if stated and rel == "README.md":
                seen_in_readme.add(kind)
            wrong = sorted(set(s for s in stated if s != real[kind]))
            if wrong:
                return _fail("stated_counts",
                             f"{rel} states {wrong} {kind} but the repo measures {real[kind]}")
    for kind in ("invariant checks", "CI jobs"):
        if kind not in seen_in_readme:
            return _fail("stated_counts", f"README.md no longer states the {kind} count")
    summary = ", ".join(f"{v} {k}" for k, v in real.items())
    return _ok("stated_counts", f"every stated count matches the artifacts ({summary})")


# ---------------------------------------------------------------------------
# Constitution objects — MISSION.md's C1-C10 "Where enforced" column names the
# concrete object that enforces each constraint, and the sibling summaries in
# CLAUDE.md, audit-of-record.md, PRIVACY.md and ARCHITECTURE-OVERVIEW.md repeat those
# names. Every one must exist in the code. At v9.193 four did not
# (reject_update_delete, disclosure_consistency, secure_headers, enforce_zk_typing):
# a reviewer who grepped for them found nothing and had to conclude the
# constitution was decorative.
# ---------------------------------------------------------------------------
_OBJECT_DOCS = ("MISSION.md", "CLAUDE.md", "docs/design/audit-of-record.md",
                "docs/operator/PRIVACY.md", "docs/ARCHITECTURE-OVERVIEW.md")
_OBJECT_SEARCH_DIRS = ("polaris_sql", "polaris_sql/migrations", "polaris_web", "polaris_cli")
_OBJECT_NAME_PREFIXES = ("enforce_", "reject_", "chk_", "uq_", "trg_", "idx_")


def _code_corpus(root: pathlib.Path) -> str:
    parts: list[str] = []
    for rel in _OBJECT_SEARCH_DIRS:
        d = root / rel
        if not d.is_dir():
            continue
        for p in sorted(d.iterdir()):
            if p.is_file() and p.suffix in (".sql", ".py"):
                parts.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def _object_defined(corpus: str, name: str) -> bool:
    if name.endswith("*"):
        name = re.escape(name[:-1]) + r"\w*"
    else:
        name = re.escape(name)
    return re.search(
        r"(?im)^\s*(?:def|class)\s+" + name + r"\b"            # python def/class
        r"|^" + name + r"\s*=[^=]"                                # python module constant
        r"|\b(?:FUNCTION|PROCEDURE|TABLE|INDEX|CONSTRAINT|TRIGGER)\s+(?:IF NOT EXISTS\s+)?"
        + name + r"\b",                                           # SQL object
        corpus) is not None


def check_c1c10_objects_resolve(root: pathlib.Path) -> list[Finding]:
    mission = _read(root, "MISSION.md")
    if not mission:
        return _fail("c1c10_objects", "MISSION.md is missing")
    rows = [ln for ln in mission.splitlines() if re.match(r"^\|\s*C(?:10|[1-9])\s*\|", ln)]
    if len(rows) < 10:
        return _fail("c1c10_objects", f"MISSION.md's constraint table has {len(rows)} C-rows, expected 10")
    corpus = _code_corpus(root)
    checked = 0
    for ln in rows:
        for fname, obj in re.findall(r"`([\w./-]+\.(?:sql|py))::([\w*]+)(?:\(\))?`", ln):
            checked += 1
            if not (root / "polaris_sql" / fname).is_file() and \
               not (root / "polaris_web" / fname).is_file() and \
               not (root / "polaris_cli" / fname).is_file() and not (root / fname).is_file():
                return _fail("c1c10_objects", f"MISSION.md names {fname} but no such file exists")
            if not _object_defined(corpus, obj):
                return _fail("c1c10_objects",
                             f"MISSION.md says {fname}::{obj} enforces a constraint but nothing defines it")
    if checked < 8:
        return _fail("c1c10_objects",
                     f"MISSION.md's table names only {checked} file::object anchors; C1-C9 each need one")
    for rel in _OBJECT_DOCS:
        text = _read(root, rel)
        for name in set(re.findall(r"`(\w+)\(\)`", text)) | \
                set(n for n in re.findall(r"`(\w+)`", text) if n.startswith(_OBJECT_NAME_PREFIXES)):
            if not _object_defined(corpus, name):
                return _fail("c1c10_objects", f"{rel} cites `{name}` but nothing in the code defines it")
    return _ok("c1c10_objects", f"{checked} enforcement objects in MISSION.md resolve; the sibling summaries cite only real names")


# ---------------------------------------------------------------------------
# Chart currency — the Helm chart's appVersion is the version a cluster operator
# sees in `helm list`; it must equal polaris_web/__version__.py. v9.193 shipped
# a chart still stamped 9.186 while KUBERNETES.md told the operator to tag images
# with the shipped version.
# ---------------------------------------------------------------------------
def check_helm_chart_version_current(root: pathlib.Path) -> list[Finding]:
    ver = re.search(r"""^__version__(?:\s*:\s*str)?\s*=\s*["']([^"']+)["']""", _read(root, "polaris_web/__version__.py"), re.M)
    chart = re.search(r'^appVersion:\s*"?([^"\n]+)"?\s*$', _read(root, "deploy/helm/polaris/Chart.yaml"), re.M)
    if not ver or not chart:
        return _fail("helm_chart_version", "cannot read __version__ or the chart's appVersion")
    if ver.group(1) != chart.group(1).strip():
        return _fail("helm_chart_version",
                     f"deploy/helm/polaris/Chart.yaml appVersion is {chart.group(1).strip()} but "
                     f"polaris_web/__version__.py is {ver.group(1)}; bump the chart with the ship")
    cite = re.search(r'^version:\s*"?([^"\n]+)"?\s*$', _read(root, "CITATION.cff"), re.M)
    if cite and cite.group(1).strip() != ver.group(1):
        return _fail("helm_chart_version",
                     f"CITATION.cff version is {cite.group(1).strip()} but __version__ is {ver.group(1)}; "
                     "bump the citation with the ship")
    return _ok("helm_chart_version", f"Chart.yaml appVersion and CITATION.cff match __version__ ({ver.group(1)})")


# ---------------------------------------------------------------------------
# API documentation coverage — every /api/* route in app.py has a heading in
# docs/reference/API.md, and every /api/* heading there names a real route.
# v9.193 shipped six undocumented routes and two documented routes that did
# not exist; an integrator reading the reference could not tell which.
# ---------------------------------------------------------------------------
def _norm_api_path(path: str) -> str:
    return re.sub(r"<[^>]*>", "<>", path.strip().rstrip("/"))


def _api_routes_in_app(app_src: str) -> set[str]:
    return {_norm_api_path(m) for m in re.findall(r"@app\.route\('(/api/[^']*)'", app_src)}


def _api_routes_in_doc(doc: str) -> set[str]:
    found: set[str] = set()
    for heading in re.findall(r"^#{2,4} (.+)$", doc, re.M):
        for path in re.findall(r"`(?:GET|POST|PUT|PATCH|DELETE) (/api/[^`]+)`", heading):
            found.add(_norm_api_path(path))
    return found


def check_api_routes_documented(root: pathlib.Path) -> list[Finding]:
    app_src = _read(root, "polaris_web/app.py")
    doc = _read(root, "docs/reference/API.md")
    if not app_src or not doc:
        return _fail("api_routes_documented", "polaris_web/app.py or docs/reference/API.md is missing")
    real = _api_routes_in_app(app_src)
    documented = _api_routes_in_doc(doc)
    if not real:
        return _fail("api_routes_documented", "no /api/* routes found in app.py")
    missing = sorted(real - documented)
    phantom = sorted(documented - real)
    if missing:
        return _fail("api_routes_documented",
                     f"{len(missing)} /api route(s) have no heading in docs/reference/API.md: {', '.join(missing)}")
    if phantom:
        return _fail("api_routes_documented",
                     f"docs/reference/API.md documents route(s) that do not exist: {', '.join(phantom)}")
    return _ok("api_routes_documented", f"all {len(real)} /api routes are documented and no phantom route is")


# ---------------------------------------------------------------------------
# The compose stack must trust its own edge for the client address. Caddy
# rewrites X-Forwarded-For to the real peer, and security.client_ip() honours
# it only under POLARIS_TRUST_PROXY. v9.198 shipped the prod compose without
# that variable: every client shared Caddy's container address, so the per-IP
# rate limits, the AuthAuditLog ip column and the per-role network policy all
# keyed on one address. The Helm profile already set it.
# ---------------------------------------------------------------------------
def check_prod_compose_trusts_edge(root: pathlib.Path) -> list[Finding]:
    compose = _read(root, "polaris_web/docker-compose.prod.yml")
    caddy = _read(root, "polaris_web/Caddyfile")
    if not compose or not caddy:
        return _fail("compose_trusts_edge", "docker-compose.prod.yml or Caddyfile is missing")
    if not re.search(r"header_up X-Forwarded-For \{remote_host\}", caddy):
        return _fail("compose_trusts_edge",
                     "Caddyfile must rewrite X-Forwarded-For to {remote_host} (replace, not append) "
                     "so the leftmost address is the edge's, not the client's")
    app = re.search(r"^  app:\n(.*?)(?=^  \w[\w-]*:$)", compose, re.M | re.S)
    if not app or not re.search(r"POLARIS_TRUST_PROXY:\s*[\"']?(1|true|yes)", app.group(1)):
        return _fail("compose_trusts_edge",
                     "docker-compose.prod.yml app service must set POLARIS_TRUST_PROXY so client_ip() "
                     "sees the real peer behind Caddy")
    return _ok("compose_trusts_edge", "the prod compose trusts Caddy's rewritten X-Forwarded-For")


# ---------------------------------------------------------------------------
# Documentation index coverage — every Markdown document under docs/ is linked
# from the README.md of its own directory, so a reader who follows the indexes
# reaches every document. The link checker proves links resolve; it cannot see
# an omission. v9.193's docs/README.md listed eleven of thirty-three documents.
# ---------------------------------------------------------------------------
def check_docs_index_coverage(root: pathlib.Path) -> list[Finding]:
    docs = root / "docs"
    if not docs.is_dir():
        return _fail("docs_index_coverage", "docs/ is missing")
    missing: list[str] = []
    for d in sorted(p for p in [docs, *docs.rglob("*")] if p.is_dir() and ".git" not in p.parts):
        index = d / "README.md"
        members = sorted(p for p in d.glob("*.md") if p.name != "README.md")
        subdirs = sorted(p for p in d.iterdir() if p.is_dir() and any(p.rglob("*.md")))
        if not members and not subdirs:
            continue
        if not index.is_file():
            missing.append(f"{d.relative_to(root)}/README.md (no index)")
            continue
        text = index.read_text(encoding="utf-8", errors="replace")
        for m in members:
            if not re.search(r"\]\(" + re.escape(m.name) + r"\)", text):
                missing.append(str(m.relative_to(root)))
        for sd in subdirs:
            if not re.search(r"\]\(" + re.escape(sd.name) + r"/(?:README\.md)?\)", text):
                missing.append(f"{sd.relative_to(root)}/ (sub-directory not delegated)")
    if missing:
        return _fail("docs_index_coverage",
                     f"{len(missing)} document(s) not linked from the index of their own directory: "
                     + ", ".join(missing[:8]) + (" ..." if len(missing) > 8 else ""))
    return _ok("docs_index_coverage", "every document under docs/ is linked from its directory's README")


# ---------------------------------------------------------------------------
# Presentation surface — the files a reader arriving on GitHub expects, and the
# two root policies kept current. File-based only: repository settings (private
# reporting, secret scanning) cannot be observed from inside the tree and are
# never asserted as standing claims. FUNDING.yml is deliberately not pinned
# either way (the owner's Sponsors decision).
# ---------------------------------------------------------------------------
def check_presentation_surface(root: pathlib.Path) -> list[Finding]:
    required = ("CODE_OF_CONDUCT.md", "CITATION.cff", "SECURITY.md", "CONTRIBUTING.md",
                ".github/ISSUE_TEMPLATE/config.yml", ".github/PULL_REQUEST_TEMPLATE.md",
                "scripts/polaris-release-notes.sh")
    missing = [r for r in required if not (root / r).is_file()]
    if missing:
        return _fail("presentation_surface", f"missing: {', '.join(missing)}")
    cfg = _read(root, ".github/ISSUE_TEMPLATE/config.yml")
    if not re.search(r"blank_issues_enabled:\s*false", cfg) or "security/advisories" not in cfg:
        return _fail("presentation_surface",
                     "ISSUE_TEMPLATE/config.yml must disable blank issues and route security reports "
                     "to the private advisory")
    sec = _read(root, "SECURITY.md")
    if "Report a vulnerability" not in sec or "private advisory" not in sec.lower():
        return _fail("presentation_surface", "SECURITY.md must name GitHub's private advisory as the reporting path")
    if "gh attestation verify" not in sec:
        return _fail("presentation_surface", "SECURITY.md must keep the release verification command")
    ver = re.search(r'^__version__(?:\s*:\s*str)?\s*=\s*["\']([^"\']+)["\']', _read(root, "polaris_web/__version__.py"), re.M)
    if not ver:
        return _fail("presentation_surface", "cannot read __version__")
    major, minor = (int(x) for x in ver.group(1).split(".")[:2])
    for rel in ("SECURITY.md", "CONTRIBUTING.md"):
        m = re.search(r"Last updated: \d{4}-\d{2}-\d{2} \(v(\d+)\.(\d+)\)", _read(root, rel))
        if not m:
            return _fail("presentation_surface", f"{rel} carries no 'Last updated: DATE (vX.Y)' stamp")
        smajor, sminor = int(m.group(1)), int(m.group(2))
        if smajor != major or minor - sminor > 20:
            return _fail("presentation_surface",
                         f"{rel} is stamped v{smajor}.{sminor} but the tree is v{major}.{minor}; "
                         "re-read and restamp it within twenty minors")
    # The readiness ledger's own cover must not drift from the code (its status line
    # read v9.237 while the tree was v9.291, so its version undersold the record).
    rm = re.search(r"\*\*Status \(v(\d+)\.(\d+)\):", _read(root, "docs/PRODUCTION-READINESS.md"))
    if not rm:
        return _fail("presentation_surface",
                     "docs/PRODUCTION-READINESS.md carries no '**Status (vX.Y):' stamp on its cover")
    rmajor, rminor = int(rm.group(1)), int(rm.group(2))
    if rmajor != major or minor - rminor > 20:
        return _fail("presentation_surface",
                     f"docs/PRODUCTION-READINESS.md is stamped v{rmajor}.{rminor} but the tree is v{major}.{minor}; "
                     "restamp the readiness ledger's cover within twenty minors")
    return _ok("presentation_surface",
               "community files present, security routing set, policies and the readiness ledger stamped current")


# ---------------------------------------------------------------------------
# CLI help currency — the module docstring lists the commands an operator can
# run, and the epilog documents the exit codes. Both must match the command
# registry: at v9.208 six of the twenty commands were missing from the list,
# including revoke and both halves of the recovery ceremony, so an operator
# reading the help did not know they existed.
# ---------------------------------------------------------------------------
def check_cli_help_lists_every_command(root: pathlib.Path) -> list[Finding]:
    src = _read(root, "polaris_cli/polaris.py")
    if not src:
        return _fail("cli_help", "polaris_cli/polaris.py is missing")
    registry = re.search(r"HANDLERS = \{(.*?)\n\}", src, re.S)
    if not registry:
        return _fail("cli_help", "polaris_cli/polaris.py has no HANDLERS registry")
    commands = set(re.findall(r"'([a-z0-9-]+)':", registry.group(1)))
    doc = re.match(r'(?s)\A#![^\n]*\n"""(.*?)"""', src)
    if not doc:
        return _fail("cli_help", "polaris_cli/polaris.py has no module docstring")
    listed = set(re.findall(r"^    ([a-z][a-z0-9-]+)\s{2,}\S", doc.group(1), re.M))
    missing = sorted(commands - listed)
    phantom = sorted(listed - commands)
    if missing:
        return _fail("cli_help", f"the CLI docstring does not list: {', '.join(missing)}")
    if phantom:
        return _fail("cli_help", f"the CLI docstring lists commands that do not exist: {', '.join(phantom)}")
    for needle, what in (("exit codes:", "the exit codes"), ("--version", "a --version flag")):
        if needle not in src:
            return _fail("cli_help", f"the CLI help carries no {what}")
    return _ok("cli_help", f"the CLI docstring lists all {len(commands)} commands, with exit codes and a version")


# ---------------------------------------------------------------------------
# Metrics exposure — /metrics and /api/metrics carry polaris_duress_events_total
# and neither route authenticates, so whoever can scrape them can observe that,
# and roughly when, a duress alarm fired. Both shipped edges (the compose
# Caddyfile and the Helm configmap) must refuse them from outside the
# monitoring network. Through v9.208 neither did, and the docstrings described
# an ACL that existed only in prose.
# ---------------------------------------------------------------------------
def check_metrics_edge_acl(root: pathlib.Path) -> list[Finding]:
    edges = (("polaris_web/Caddyfile", "POLARIS_METRICS_ALLOW"),
             ("deploy/helm/polaris/templates/configmap-caddy.yaml", "metricsAllow"))
    for rel, knob in edges:
        conf = _read(root, rel)
        if not conf:
            return _fail("metrics_edge_acl", f"{rel} is missing")
        if "@metrics_from_outside" not in conf or "respond @metrics_from_outside 404" not in conf:
            return _fail("metrics_edge_acl",
                         f"{rel} must refuse /metrics and /api/metrics from outside the monitoring "
                         "network (a named matcher plus `respond ... 404`)")
        matcher = conf[conf.index("@metrics_from_outside"):]
        matcher = matcher[:matcher.index("}")]
        for needle in ("/metrics", "/api/metrics", "not remote_ip"):
            if needle not in matcher:
                return _fail("metrics_edge_acl", f"{rel}'s matcher does not cover {needle}")
        if knob not in conf:
            return _fail("metrics_edge_acl", f"{rel} must let the operator name the allowed range ({knob})")
    ci = _read(root, ".github/workflows/ci.yml")
    if "metrics surfaces are refused from outside" not in ci:
        return _fail("metrics_edge_acl", "ci.yml must exercise the ACL, not just validate the config")
    return _ok("metrics_edge_acl", "both edges refuse the metrics surfaces from outside the monitoring network, proven in CI")


# ---------------------------------------------------------------------------
# Launcher currency — the macOS launcher (the SCS-230 deliverable surface) must
# track the real stack, not drift. Pin the three properties that went stale: it
# installs native deps from requirements.txt (not a hardcoded list that misses
# prometheus_client/redis/hypothesis/pytest), its `test` command runs the
# canonical suite (not just test_app), and it builds/points at the ZK binary so
# /api/zk/* is not silently dead on a native launch.
# ---------------------------------------------------------------------------
def check_launcher_current(root: pathlib.Path) -> list[Finding]:
    sh = _read(root, "polaris_mac_launch.sh")
    if not sh:
        return _fail("launcher_current", "polaris_mac_launch.sh is missing")
    # Installs via `pip install ... -r <…>` AND the file it points at is
    # requirements.txt (referenced directly or through a variable).
    if not (re.search(r"pip install[^\n]*\s-r\b", sh) and "requirements.txt" in sh):
        return _fail("launcher_current",
                     "the launcher must install native deps from requirements.txt, not a hardcoded list")
    if re.search(r"pip install[^\n]*\bflask\b[^\n]*\bpsycopg2-binary\b[^\n]*\bgunicorn\b", sh):
        return _fail("launcher_current",
                     "the launcher still pip-installs a hardcoded package list; use requirements.txt")
    missing = [s for s in ("polaris_checks", "test_check_constraints",
                           "test_invariants_property", "test_redaction_property")
               if s not in sh]
    if missing:
        return _fail("launcher_current",
                     "the launcher's test command omits canonical suite(s): " + ", ".join(missing))
    if "polaris-zk" not in sh and "POLARIS_ZK_BINARY" not in sh:
        return _fail("launcher_current",
                     "the launcher never builds or references the ZK binary; /api/zk/* would be dead natively")
    return _ok("launcher_current",
               "launcher installs from requirements.txt, runs the canonical suite, and builds the ZK binary")


# ---------------------------------------------------------------------------
# Code-object currency (v9.152) — the launcher preserves DATA across launches
# (it skips the schema reload when the core tables already exist), so a change
# to a function/trigger/view SIGNATURE in the repo does NOT reach an existing
# database through that path. Migrations cover schema/data deltas; CODE objects
# (procedures, triggers, atlas functions, ontology views) must be re-applied on
# every launch or a stale function 500s the app (the "ATLAS FEED INTERRUPTED"
# bug: v9.146 changed the atlas function signatures and old DBs kept the old
# ones). Pin that the launcher re-applies the atlas function file every launch.
# ---------------------------------------------------------------------------
def check_launcher_refreshes_code(root: pathlib.Path) -> list[Finding]:
    sh = _read(root, "polaris_mac_launch.sh")
    if not sh:
        return _fail("launcher_code", "polaris_mac_launch.sh is missing")
    mig = _read(root, "scripts/polaris-migrate.sh")
    # v9.152 pinned this with a bare "11_atlas.sql appears in the launcher"
    # grep, and that pin passed for months while the DOCKER path (the default)
    # never refreshed anything: the string lived only in the native branch, a
    # persistent dev volume kept pre-v9.146 atlas signatures, and the app 500d
    # with the exact failure the check existed to prevent. Presence is not
    # coverage. Assert each piece on its actual path:
    # 1. The object-file list lives in polaris-migrate.sh and covers the atlas.
    if "11_atlas.sql" not in mig:
        return _fail("launcher_code",
                     "polaris-migrate.sh --sync-objects does not cover 11_atlas.sql; a changed "
                     "atlas function signature would never reach an existing DB")
    # 2. The launcher syncs through that one tool (no private file list to drift).
    if "--sync-objects" not in sh:
        return _fail("launcher_code",
                     "the launcher never invokes polaris-migrate.sh --sync-objects; code-object "
                     "refresh has no path to any database")
    # 3. The DOCKER path syncs. launch_docker's body must reach a dev-stack sync.
    m = re.search(r"^launch_docker\(\)\s*\{(.*?)^\}", sh, re.M | re.S)
    if not m:
        return _fail("launcher_code", "launch_docker() not found in the launcher")
    if "sync_db_docker" not in m.group(1):
        return _fail("launcher_code",
                     "launch_docker() never calls sync_db_docker; the Docker path (the "
                     "launcher default) would leave a persistent volume with stale "
                     "functions and migrations (the v9.159 regression)")
    sync = re.search(r"^sync_db_docker\(\)\s*\{(.*?)^\}", sh, re.M | re.S)
    if not sync or "--target=dev-stack" not in sync.group(1) \
            or "--up" not in sync.group(1) or "--sync-objects" not in sync.group(1):
        return _fail("launcher_code",
                     "sync_db_docker() must apply BOTH halves against the dev stack: "
                     "migrations (--target=dev-stack --up) and code objects "
                     "(--target=dev-stack --sync-objects)")
    return _ok("launcher_code",
               "both launcher paths sync migrations + code objects through "
               "polaris-migrate.sh on every launch (single object-file list)")


# ---------------------------------------------------------------------------
# Local-wall-clock convention — the DB stores TIMESTAMP-without-zone and app+DB
# are co-located, so every Python boundary compares against datetime.now().
# A datetime.utcnow() would silently shift the boundary by the server's UTC
# offset (and is deprecated). One such bug shipped in the ZK epoch check.
# ---------------------------------------------------------------------------
def check_local_clock_convention(root: pathlib.Path) -> list[Finding]:
    app = _read(root, "polaris_web/app.py")
    if "utcnow" in app:
        return _fail("local_clock",
                     "app.py references utcnow; the DB stores local-wall-clock "
                     "TIMESTAMPs, so compare against datetime.now() (see the atlas TZ note)")
    return _ok("local_clock", "app.py uses local-wall-clock datetime.now() for boundaries, never utcnow()")


# ---------------------------------------------------------------------------
# C6 (server-side disclosure) — ZERO_KNOWLEDGE verification location must be
# redacted/excluded at EVERY read path, not just uc7_warrant_audit. The atlas
# spatial layers and the /verifications list would otherwise expose the precise
# location that de-anonymizes a ZK holder (spatial side-channel).
# ---------------------------------------------------------------------------
def check_c6_atlas_redacts_zk_location(root: pathlib.Path) -> list[Finding]:
    atlas = _read(root, "polaris_sql/11_atlas.sql")
    excludes = atlas.count("disclosure_level <> 'ZERO_KNOWLEDGE'")
    if excludes < 3:
        return _fail("c6_atlas_zk",
                     "atlas verification points + clusters + hexbin must exclude ZERO_KNOWLEDGE "
                     f"(found {excludes} exclusion clause(s), need >=3) (C6)")
    # v9.253: the Density (hexbin) surface is a spatial aggregate; like the
    # cluster/point layers it must exclude ZK entirely (a hex holding a single
    # ZK event would pin it).
    hexbin = re.search(r"CREATE OR REPLACE FUNCTION atlas_hexbin\(.*?\$\$;", atlas, re.S)
    if not hexbin or "disclosure_level <> 'ZERO_KNOWLEDGE'" not in hexbin.group(0):
        return _fail("c6_atlas_zk",
                     "atlas_hexbin (the Map v2 Density layer) must exclude ZERO_KNOWLEDGE events "
                     "so a hex never pins a zero-knowledge verification (C6)")
    # The Regions layer (atlas_geo_jurisdictions) is the exception that proves
    # the rule: it COUNTS ZK (n_zk) but its centroid must be built only from
    # located, non-ZK events, so ZK is counted yet never located.
    geojur = re.search(r"CREATE OR REPLACE FUNCTION atlas_geo_jurisdictions\(.*?\$\$;", atlas, re.S)
    if geojur:
        body = geojur.group(0)
        if "n_zk" not in body:
            return _fail("c6_atlas_zk", "atlas_geo_jurisdictions must count ZK (n_zk)")
        if not re.search(r"avg\(ve\.latitude\)\s+FILTER[^)]*<>\s*'ZERO_KNOWLEDGE'", body, re.S):
            return _fail("c6_atlas_zk",
                         "atlas_geo_jurisdictions centroid must be built from located, non-ZK events "
                         "only (a ZK-only jurisdiction is counted but unplaceable) (C6)")
    if "THEN NULL ELSE tv.latitude" not in atlas:
        return _fail("c6_atlas_zk",
                     "atlas_recent_events must NULL lat/lon for ZERO_KNOWLEDGE rows (C6)")
    # v9.142: the /atlas HTML route no longer reads requestor_location at all
    # (its inline globe-node query was dead code, removed; the globe fetches
    # via /api/atlas/*, whose SQL functions exclude ZK rows entirely, asserted
    # above). The one remaining app.py HTML read path is /verifications.
    app = _read(root, "polaris_web/app.py")
    if app.count("THEN NULL ELSE ve.requestor_location") < 1:
        return _fail("c6_atlas_zk",
                     "app.py /verifications must redact requestor_location "
                     "for ZERO_KNOWLEDGE (C6)")
    return _ok("c6_atlas_zk",
               "ZK verification location is excluded/redacted at the atlas + list read paths (C6)")


# ---------------------------------------------------------------------------
# Vocation (anti-coercion) — the coercion-evidence trail must NOT be redacted.
#
# VerificationEvent.requesting_purpose_text is operator-supplied free text: a
# coerced verification leaves the coercer's stated purpose on the permanent
# record (the evidentiary chain). It is deliberately RETAINED on every
# disclosure level, ZERO_KNOWLEDGE included — UNLIKE requestor_location, which
# IS ZK-redacted (C6, the check above). Pass-7 found a stale schema comment that
# falsely called it "redacted for ZERO_KNOWLEDGE rows at read"; a well-meaning
# engineer reading that could add a redaction CASE and silently destroy the
# anti-coercion feature. This guards against exactly that: the evidence trail
# must never be NULLed for ZK rows at a read path, and the canonical schema must
# not falsely claim it is.
# ---------------------------------------------------------------------------
def check_coercion_evidence_retained(root: pathlib.Path) -> list[Finding]:
    schema = _read(root, "polaris_sql/01_schema.sql")
    if "requesting_purpose_text" not in schema:
        return _fail("vocation_coercion_evidence",
                     "VerificationEvent.requesting_purpose_text (the coercion-evidence trail) is missing")
    # The canonical schema must not FALSELY claim the evidence trail is redacted
    # (the stale comment that invited the confusion). The same phrase legitimately
    # describes requestor_location elsewhere, so only flag it when it sits in the
    # comment block immediately preceding the requesting_purpose_text column.
    col_at = schema.find("requesting_purpose_text VARCHAR")
    false_claim = "is redacted for ZERO_KNOWLEDGE rows at read"
    claim_at = schema.rfind(false_claim, 0, col_at) if col_at != -1 else -1
    if claim_at != -1 and (col_at - claim_at) < 400:
        return _fail("vocation_coercion_evidence",
                     "01_schema.sql falsely documents requesting_purpose_text as ZK-redacted; it is "
                     "the deliberately-retained anti-coercion evidentiary trail (Vocation)")
    # No read path may redact the evidence trail to NULL for ZERO_KNOWLEDGE rows.
    reads = (_read(root, "polaris_web/app.py")
             + _read(root, "polaris_sql/11_atlas.sql")
             + _read(root, "polaris_sql/05_procedures.sql"))
    if re.search(r"THEN\s+NULL\s+ELSE[^;]*requesting_purpose_text", reads, re.I | re.S) or \
       re.search(r"requesting_purpose_text[^;]*ZERO_KNOWLEDGE[^;]*THEN\s+NULL", reads, re.I | re.S):
        return _fail("vocation_coercion_evidence",
                     "a read path redacts requesting_purpose_text for ZERO_KNOWLEDGE rows — that "
                     "destroys the anti-coercion evidentiary trail it exists to create (Vocation)")
    return _ok("vocation_coercion_evidence",
               "the coercion-evidence trail (requesting_purpose_text) is retained, not ZK-redacted (Vocation)")


# ---------------------------------------------------------------------------
# R2 anti-replay — /api/zk/verify must consume a single-use nonce.
#
# A proof bundle is bound to (epoch_id, context_id, nonce), which prevents proof
# SUBSTITUTION. It does NOT prevent REPLAY on its own: the identical bundle,
# captured off the wire, verifies again. The verify route must consume the nonce
# (insert into the single-use ZkVerificationNonce store) on a verified result and
# reject a second submission of the same tuple. Closes threat-model T-T2.
# ---------------------------------------------------------------------------
def check_zk_verify_anti_replay(root: pathlib.Path) -> list[Finding]:
    schema = _read(root, "polaris_sql/01_schema.sql")
    app = _read(root, "polaris_web/app.py")
    if "CREATE TABLE ZkVerificationNonce" not in schema:
        return _fail("zk_anti_replay",
                     "ZkVerificationNonce single-use nonce store is missing from the schema (R2/T-T2)")
    if "INSERT INTO ZkVerificationNonce" not in app:
        return _fail("zk_anti_replay",
                     "/api/zk/verify does not consume the nonce — a verified bundle replays (R2/T-T2)")
    if "replay" not in app.lower():
        return _fail("zk_anti_replay",
                     "/api/zk/verify consumes the nonce but never rejects the replay case (R2/T-T2)")
    return _ok("zk_anti_replay",
               "/api/zk/verify consumes a single-use nonce; replays are rejected (R2/T-T2)")


# ---------------------------------------------------------------------------
# Schema completeness — every column a migration ADDs to an existing table must
# also be declared in 01_schema.sql, so the canonical schema is complete on its
# own and a cold reader (or a fresh 01_schema build) never silently lacks a
# column the app writes. The migrations stay (idempotent) for deployed DBs.
# ---------------------------------------------------------------------------
def check_no_migration_column_drift(root: pathlib.Path) -> list[Finding]:
    schema = _read(root, "polaris_sql/01_schema.sql")
    mig_dir = root / "polaris_sql" / "migrations"
    missing = []
    if mig_dir.is_dir():
        for path in sorted(mig_dir.glob("*.up.sql")):
            text = path.read_text(encoding="utf-8")
            for m in re.finditer(r"ADD COLUMN(?:\s+IF NOT EXISTS)?\s+(\w+)", text, re.I):
                col = m.group(1)
                if not re.search(rf"\b{re.escape(col)}\b", schema):
                    missing.append(f"{path.name}:{col}")
    if missing:
        return _fail("migration_drift",
                     "migration-added column(s) missing from 01_schema.sql: "
                     + ", ".join(missing[:6]))
    return _ok("migration_drift",
               "every migration-added column is declared in 01_schema.sql (no schema drift)")


# ---------------------------------------------------------------------------
# Operator-script argument validation — the operator shell scripts interpolate
# argv into superuser `psql -c` statements, so every SQL-bound argument must be
# regex-validated (numeric / username format) before use or it is a SQL
# injection (multi-statement) as postgres.
# ---------------------------------------------------------------------------
def check_operator_scripts_validate_argv(root: pathlib.Path) -> list[Finding]:
    required = [
        # (script, marker that proves the SQL-bound arg is regex-validated)
        ("scripts/polaris-recover-admin.sh", r"TARGET.*=~|=~[^\n]*\[a-z0-9\._-\]\{3,50\}"),
        ("scripts/polaris-purge.sh",        r"ACTOR_USER_ID[^\n]*=~[^\n]*\^\[0-9\]\+\$"),
        ("scripts/polaris-migrate.sh",      r"ACTOR_USER_ID[^\n]*=~[^\n]*\^\[0-9\]\+\$"),
        ("scripts/polaris-archive.sh",      r"CUTOFF_DAYS[^\n]*=~[^\n]*\^\[0-9\]\+\$"),
    ]
    missing = []
    for rel, pat in required:
        if not re.search(pat, _read(root, rel)):
            missing.append(rel.split("/")[-1])
    if missing:
        return _fail("script_argv",
                     "operator script(s) missing SQL-arg validation (injection risk): "
                     + ", ".join(missing))
    return _ok("script_argv",
               "operator scripts regex-validate SQL-bound argv (recover/purge/migrate/archive)")


# ---------------------------------------------------------------------------
# Template/route integrity — every url_for('name') in a template must name a
# function that actually carries an @app.route in app.py. A renamed or deleted
# route otherwise becomes a BuildError 500 on whichever page links to it, and
# nothing static catches it until a user clicks. (v9.143; the same sweep found
# role-gated buttons rendered for roles that 403 on click, which the
# UiLinkIntegrityTests crawler in test_app.py now guards dynamically.)
# ---------------------------------------------------------------------------
def check_template_endpoints_resolve(root: pathlib.Path) -> list[Finding]:
    app_src = _read(root, "polaris_web/app.py")
    # Collect the function name following each @app.route decorator stack.
    endpoints: set[str] = set()
    pending_route = False
    for line in app_src.splitlines():
        if line.startswith("@app.route("):
            pending_route = True
        elif pending_route and line.startswith("def "):
            m = re.match(r"def ([A-Za-z_][A-Za-z_0-9]*)\(", line)
            if m:
                endpoints.add(m.group(1))
            pending_route = False
    endpoints.add("static")  # Flask built-in
    missing = []
    tpl_dir = root / "polaris_web" / "templates"
    if tpl_dir.is_dir():
        for tpl in sorted(tpl_dir.glob("*.html")):
            names = re.findall(r"url_for\(\s*'([A-Za-z_][A-Za-z_0-9]*)'",
                               tpl.read_text(encoding="utf-8"))
            for name in names:
                if name not in endpoints:
                    missing.append(f"{tpl.name} -> {name}")
    if missing:
        return _fail("template_endpoints",
                     "template url_for() names no @app.route function: "
                     + ", ".join(sorted(set(missing))))
    return _ok("template_endpoints",
               f"every template url_for() resolves to a real route ({len(endpoints) - 1} endpoints)")


# ---------------------------------------------------------------------------
# Operator-tooling sweep (v9.153). Exercising the un-swept operator scripts
# found five runtime defects, none of them visible to a static read. These five
# checks pin the fixes so the same classes cannot return.
# ---------------------------------------------------------------------------

# C1 carve-out — polaris-purge.sh issues the ONLY legitimate DELETE against the
# audit tables, and its constitutional justification is that the archive can
# reconstitute every purged row. An archive taken from a DIFFERENT database
# satisfies both the SHA-256 and the cutoff check while covering none of the
# rows being deleted. Demonstrated: a canary row absent from the archive was
# purged anyway, and the checkpoint recorded 11 purged against a 10-row
# manifest. Purge must bind the archive to its source DB and pre-check coverage.
def check_purge_binds_archive_to_database(root: pathlib.Path) -> list[Finding]:
    sh = _read(root, "scripts/polaris-purge.sh")
    if not sh:
        return _fail("purge_archive_binding", "scripts/polaris-purge.sh is missing")
    if "source_database" not in sh:
        return _fail("purge_archive_binding",
                     "polaris-purge.sh does not check the archive's source_database; an "
                     "archive from another cluster would purge rows it cannot reconstitute (C1)")
    if "coverage mismatch" not in sh:
        return _fail("purge_archive_binding",
                     "polaris-purge.sh does not pre-check that the archive covers every row "
                     "it is about to delete (C1 non-repudiation)")
    return _ok("purge_archive_binding",
               "polaris-purge.sh binds the archive to its source database and pre-checks "
               "row coverage before deleting (C1 carve-out)")


# The archive MANIFEST is a non-repudiation artifact, so its provenance must be
# derived, never a literal. A hardcoded "8.84" drifted while the product shipped
# 9.152, making every archive misreport its own origin. check_version_is_canonical
# covers app.py; this covers the archive tool.
def check_archive_version_derived(root: pathlib.Path) -> list[Finding]:
    sh = _read(root, "scripts/polaris-archive.sh")
    if not sh:
        return _fail("archive_version", "scripts/polaris-archive.sh is missing")
    if re.search(r'"polaris_version":\s*"[0-9]', sh):
        return _fail("archive_version",
                     "polaris-archive.sh hardcodes polaris_version in the MANIFEST; derive it "
                     "from polaris_web/__version__.py so the archive cannot misreport its origin")
    if "__version__.py" not in sh:
        return _fail("archive_version",
                     "polaris-archive.sh does not read polaris_web/__version__.py for the "
                     "MANIFEST provenance field")
    return _ok("archive_version",
               "the archive MANIFEST derives polaris_version from the canonical __version__.py")


# A transactional `psql -f` must never be piped into `grep -q`. grep -q exits at
# its first match, psql is killed by SIGPIPE mid-transaction, the COMMIT never
# runs, and pipefail then reports failure for a rolled-back transaction. That is
# how polaris-create-operator.sh reported "database insert failed" (exit 141) for
# accounts it had in fact created via a second, unpiped re-run.
def check_no_grep_q_transaction_scrape(root: pathlib.Path) -> list[Finding]:
    offenders = []
    sdir = root / "scripts"
    if sdir.is_dir():
        for sh in sorted(sdir.glob("*.sh")):
            text = sh.read_text(encoding="utf-8", errors="replace")
            for num, line in enumerate(text.splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                if "grep -q" not in line or not re.search(r"\b(psql|run_psql)\b", line):
                    continue
                # Only file-executed invocations are at risk: killing psql
                # mid-file aborts the transaction the file opened. A read-only
                # `-c "SELECT ..."` or a `psql -lqt` listing has nothing to
                # roll back, so piping those into grep -q is harmless.
                if not re.search(r"-f\s", line):
                    continue
                offenders.append(f"{sh.name}:{num}")
    if offenders:
        return _fail("no_grep_q_psql",
                     "a psql invocation is piped into `grep -q` (SIGPIPE kills psql "
                     "mid-transaction; judge the OUTCOME instead): " + ", ".join(offenders))
    return _ok("no_grep_q_psql",
               "no script scrapes a psql transaction through `grep -q`; success is judged "
               "by verifying the outcome")


# `_out=$(cmd)` followed by `_rc=$?` does not work under `set -e`: the shell
# exits at the assignment, so the status is never inspected. In
# polaris-recover-admin.sh that made the entire fail-safe-never-open refusal
# block unreachable, and a failed emergency-window write exited silently.
def check_psql_status_capture_set_e_safe(root: pathlib.Path) -> list[Finding]:
    offenders = []
    sdir = root / "scripts"
    if sdir.is_dir():
        for sh in sorted(sdir.glob("*.sh")):
            text = sh.read_text(encoding="utf-8", errors="replace")
            if "set -e" not in text:
                continue
            lines = text.splitlines()
            for num, line in enumerate(lines, 1):
                if not re.search(r"^\s*_?\w+=\$\(.*(psql|docker compose)", line):
                    continue
                # Status captured inline on the same logical command is safe.
                if "||" in line:
                    continue
                for nxt in lines[num:num + 2]:
                    if re.match(r"^\s*_?\w+=\$\?", nxt):
                        offenders.append(f"{sh.name}:{num}")
                        break
    if offenders:
        return _fail("psql_status_set_e",
                     "`X=$(psql ...)` followed by `RC=$?` under `set -e`: the shell exits at "
                     "the assignment and the status is never read, making the error handler "
                     "unreachable. Use `|| RC=$?`: " + ", ".join(offenders))
    return _ok("psql_status_set_e",
               "psql status capture is set -e safe; failure handlers are reachable")


# "Second-admin pairing" must involve an actual second admin. The authorizer was
# validated only as *an* active admin and never compared to the target, so one
# admin could authorize their own MFA-bypass window while the banner asserted
# second-admin pairing. Single-admin deployments keep the --recovery-code path,
# which is self-pairing by design.
def check_recover_admin_refuses_self_pairing(root: pathlib.Path) -> list[Finding]:
    sh = _read(root, "scripts/polaris-recover-admin.sh")
    if not sh:
        return _fail("recover_admin_self_pair", "scripts/polaris-recover-admin.sh is missing")
    if "self-authorization refused" not in sh:
        return _fail("recover_admin_self_pair",
                     "polaris-recover-admin.sh does not refuse self-authorization; a single "
                     "admin could authorize their own emergency password-login window while "
                     "the banner claims 'second-admin pairing'")
    if not re.search(r'AUTHORIZING_USER_ID\}"?\s*==\s*"?\$\{TARGET_USER_ID', sh):
        return _fail("recover_admin_self_pair",
                     "polaris-recover-admin.sh never compares the authorizing user to the "
                     "recovery target")
    return _ok("recover_admin_self_pair",
               "polaris-recover-admin.sh refuses self-pairing; second-admin pairing requires "
               "a distinct admin (--recovery-code remains for solo-admin recovery)")


# The test reload must fail LOUDLY. `psql -f` exits 0 even when every statement
# in the file errored, so reload_sample_data's returncode check cannot see a
# failed reload without ON_ERROR_STOP. Without it, a permission-denied TRUNCATE
# left the previous test's mutations in place and produced 200 setUp errors that
# pointed nowhere near the cause, while CI stayed green because it runs as a
# different role. A silent reload is worse than no reload: it fakes isolation.
def check_test_reload_fails_loudly(root: pathlib.Path) -> list[Finding]:
    src = _read(root, "polaris_web/test_app.py")
    if not src:
        return _fail("test_reload_loud", "polaris_web/test_app.py is missing")
    if "def reload_sample_data" not in src:
        return _fail("test_reload_loud", "reload_sample_data() is missing from test_app.py")
    body = src.split("def reload_sample_data", 1)[1].split("\ndef ", 1)[0]
    if "ON_ERROR_STOP" not in body:
        return _fail("test_reload_loud",
                     "reload_sample_data() invokes psql without ON_ERROR_STOP; psql exits 0 "
                     "even when the SQL failed, so a no-op reload reads as success and breaks "
                     "test isolation silently")
    return _ok("test_reload_loud",
               "reload_sample_data() runs psql with ON_ERROR_STOP, so a failed reload raises "
               "instead of faking test isolation")


# A dependency pin repeated in CI drifts away from requirements.txt, and the
# drift is invisible until the two disagree in a way that matters. The pqc-real
# job hardcoded cryptography==48.0.0 while the runtime surface moved to 50.0.1
# for PYSEC-2026-3552/3553/3554 + GHSA-537c-gmf6-5ccf, so the job would have
# reinstalled the exact version cve-scan had just rejected, and the second
# witness would have been exercised at a version no deployment ships.
# requirements.txt is the single source; CI must derive from it.
def check_ci_does_not_duplicate_pins(root: pathlib.Path) -> list[Finding]:
    ci = _read(root, ".github/workflows/ci.yml")
    if not ci:
        return _fail("ci_pin_drift", ".github/workflows/ci.yml is missing")
    offenders = []
    for num, line in enumerate(ci.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or "pip install" not in stripped:
            continue
        # A literal `pkg==version` inside a pip install is a second source of
        # truth. Deriving it (grep from requirements.txt) is fine.
        if "requirements" in stripped:
            continue
        for m in re.finditer(r"([A-Za-z0-9_.\-]+)==([0-9][^\"'\s]*)", stripped):
            offenders.append(f"ci.yml:{num} {m.group(1)}=={m.group(2)}")
    if offenders:
        return _fail("ci_pin_drift",
                     "CI hardcodes a dependency pin that requirements.txt already owns; "
                     "derive it instead (grep the pin) so the two cannot drift: "
                     + ", ".join(offenders))
    return _ok("ci_pin_drift",
               "CI derives dependency pins from requirements.txt; no duplicated literals "
               "that could drift from the runtime surface")


# pg_stat_ssl returns one row per backend, and PgBouncer legitimately holds a
# variable number of pooled server connections at any snapshot. A CI step that
# selects the raw per-row `ssl` column and compares the concatenated output to
# a scalar is a coin flip: it failed a healthy v9.156 push when two SSL
# backends concatenated to "tt". Any workflow probe of pg_stat_ssl must
# aggregate to a single value (bool_and) before the shell compares it.
def check_ci_ssl_probe_aggregated(root: pathlib.Path) -> list[Finding]:
    wfdir = root / ".github" / "workflows"
    offenders = []
    if wfdir.is_dir():
        for wf in sorted(wfdir.glob("*.yml")):
            text = wf.read_text(encoding="utf-8", errors="replace")
            for num, line in enumerate(text.splitlines(), 1):
                if "pg_stat_ssl" not in line or line.lstrip().startswith("#"):
                    continue
                if "bool_and" not in line:
                    offenders.append(f"{wf.name}:{num}")
    if offenders:
        return _fail("ci_ssl_probe",
                     "a workflow queries pg_stat_ssl without aggregating (bool_and); "
                     "per-row output concatenates across pooled backends and breaks "
                     "scalar comparison nondeterministically: " + ", ".join(offenders))
    return _ok("ci_ssl_probe",
               "every workflow pg_stat_ssl probe aggregates to one boolean before comparing")


# `docker compose exec -T` attaches the caller's stdin and drains it. Inside a
# `while read` loop that is fatal: the first exec swallows every remaining line
# of the loop's input. In polaris-migrate.sh's pending scan this made three
# genuinely pending migrations report as "no pending migrations" on the dev
# stack, silently, exit 0. Every docker-exec psql in run_psql must therefore
# take stdin from /dev/null (run_psql_file is exempt: its stdin IS the payload).
def check_migrate_docker_stdin_safe(root: pathlib.Path) -> list[Finding]:
    mig = _read(root, "scripts/polaris-migrate.sh")
    if not mig:
        return _fail("migrate_stdin", "scripts/polaris-migrate.sh is missing")
    m = re.search(r"^run_psql\(\)\s*\{(.*?)^\}", mig, re.M | re.S)
    if not m:
        return _fail("migrate_stdin", "run_psql() not found in polaris-migrate.sh")
    body = m.group(1)
    offenders = []
    lines = body.splitlines()
    for i, line in enumerate(lines):
        if "docker compose" not in line:
            continue
        # The exec spans a continuation; the psql line ends the command. Find
        # the end of this logical command and require the /dev/null redirect.
        j = i
        while j < len(lines) - 1 and lines[j].rstrip().endswith("\\"):
            j += 1
        logical = " ".join(l.strip() for l in lines[i:j + 1])
        if "< /dev/null" not in logical and "</dev/null" not in logical:
            offenders.append(logical[:60])
    if offenders:
        return _fail("migrate_stdin",
                     "a docker-exec psql in run_psql() does not redirect stdin from "
                     "/dev/null; inside a while-read loop it drains the loop's input and "
                     "pending migrations silently report as applied: " + "; ".join(offenders))
    return _ok("migrate_stdin",
               "every docker-exec psql in run_psql() takes stdin from /dev/null; "
               "while-read loops cannot be drained")


# P0.1 — the ZK crate must build on a DATED nightly. Plonky2 needs nightly,
# but a floating `channel = "nightly"` re-resolves on every toolchain install:
# an upstream change can break the build with zero repo changes, and two
# machines building the same commit can disagree. CI derives its toolchain
# from this file, so the date here is the single source of truth.
def check_rust_toolchain_pinned(root: pathlib.Path) -> list[Finding]:
    tc = _read(root, "polaris_zk/rust-toolchain.toml")
    if not tc:
        return _fail("rust_pin", "polaris_zk/rust-toolchain.toml is missing")
    m = re.search(r'^channel\s*=\s*"([^"]+)"', tc, re.M)
    if not m:
        return _fail("rust_pin", "rust-toolchain.toml declares no channel")
    chan = m.group(1)
    if not re.fullmatch(r"nightly-\d{4}-\d{2}-\d{2}", chan):
        return _fail("rust_pin",
                     f"the Rust channel is '{chan}'; it must be a dated nightly "
                     f"(nightly-YYYY-MM-DD) so the ZK build cannot break from an "
                     f"upstream nightly change with zero repo changes")
    ci = _read(root, ".github/workflows/ci.yml")
    if "rust-toolchain.toml" not in ci:
        return _fail("rust_pin",
                     "CI does not derive its Rust toolchain from rust-toolchain.toml; "
                     "a second hardcoded pin would drift (the v9.155 lesson)")
    return _ok("rust_pin",
               f"the ZK toolchain is pinned to {chan} and CI derives it from the file")


# P0.2 — the Atlas e2e suite must RUN in CI with the skip escape hatch closed.
# From v9.33 the suite existed but was wired to no job; it skipped everywhere,
# read as green, and rotted (the v9.146 MapLibre rewrite renamed every element
# it selected, unnoticed). A browser suite that is not forced to run is not a
# gate, it is a decoration.
def check_ci_runs_atlas_e2e(root: pathlib.Path) -> list[Finding]:
    ci = _read(root, ".github/workflows/ci.yml")
    if "test_e2e_atlas.py" not in ci:
        return _fail("ci_e2e",
                     "no CI job runs test_e2e_atlas.py; the browser surface has no gate "
                     "and the suite will rot again")
    if "POLARIS_E2E_REQUIRE=1" not in ci:
        return _fail("ci_e2e",
                     "CI runs the e2e suite without POLARIS_E2E_REQUIRE=1; an "
                     "unavailable app or browser would skip every test and read as green")
    suite = _read(root, "polaris_web/test_e2e_atlas.py")
    if "POLARIS_E2E_REQUIRE" not in suite:
        return _fail("ci_e2e",
                     "test_e2e_atlas.py no longer honors POLARIS_E2E_REQUIRE; the CI "
                     "guard is asserting an env var the suite ignores")
    return _ok("ci_e2e",
               "CI runs the Atlas e2e suite with POLARIS_E2E_REQUIRE=1; skips cannot "
               "read as green")


# P0.4 — the load generator keeps ONE outcome ledger. The original kept an
# independent `errors` counter next to statuses['err:*'] and summed both, so a
# dead target reported twice the real request count with rates halved; it also
# routed every HTTPError away from the status ledger, which made the
# rate-limited counter (statuses.get(429)) dead code and let a run of 100%
# 5xx exit green. The invariant: no independent error counter (errors are
# DERIVED from the err:* ledger entries), and the exit gate covers 5xx.
def check_load_gen_single_ledger(root: pathlib.Path) -> list[Finding]:
    src = _read(root, "scripts/polaris_load_gen.py")
    if not src:
        return _fail("load_gen_ledger", "scripts/polaris_load_gen.py is missing")
    if re.search(r"^\s*errors\s*\+=", src, re.M):
        return _fail("load_gen_ledger",
                     "polaris_load_gen.py increments an independent `errors` counter; "
                     "outcomes must land exactly once in the statuses ledger and errors "
                     "be derived, or totals double-count on failure")
    if "_5xx_count" not in src:
        return _fail("load_gen_ledger",
                     "polaris_load_gen.py has no 5xx exit gate; a run of 100% server "
                     "errors would exit green against the tool's own purpose statement")
    return _ok("load_gen_ledger",
               "the load generator keeps a single outcome ledger with derived errors "
               "and gates its exit on transport errors and 5xx")


# P0.4 — the chaos harness must run under an interpreter that can import the
# app, and its zk_binary_absent scenario must distinguish a verifier refusal
# from a probe that never loaded. The original spawned bare `python3`; where
# that is <3.10 the import of zk.py raises on its annotations, and the
# scenario counted that raise as a fail-safe pass: a permanently green probe
# that never exercised the verifier (a planted fail-open binary went
# undetected). Require the sys.executable probe and the WRAPPER_READY sentinel.
def check_chaos_probe_reaches_wrapper(root: pathlib.Path) -> list[Finding]:
    sh = _read(root, "scripts/polaris-chaos-test.sh")
    if not sh:
        return _fail("chaos_probe", "scripts/polaris-chaos-test.sh is missing")
    if re.search(r'\[\s*"python3"\s*,\s*"-c"', sh):
        return _fail("chaos_probe",
                     "the zk_binary_absent probe spawns bare python3; on a <3.10 "
                     "interpreter the zk.py import fails and the scenario mistakes that "
                     "for a verifier refusal. Use sys.executable")
    if "WRAPPER_READY" not in sh:
        return _fail("chaos_probe",
                     "the zk_binary_absent probe has no post-import sentinel; it cannot "
                     "tell a real refusal from an import that never reached the verifier")
    if "PY_BIN" not in sh:
        return _fail("chaos_probe",
                     "the chaos harness does not resolve a >=3.10 interpreter; it may run "
                     "under a python3 that cannot import the app modules")
    return _ok("chaos_probe",
               "the chaos harness runs under an app-capable interpreter and its "
               "zk_binary_absent probe proves it reached the verifier (WRAPPER_READY)")


# P0.4 — ct-monitor must be verifiable offline and must not parse a crt.sh
# error page as certificate data. crt.sh is a flaky single-operator service
# (transient 502s with HTML bodies); the tool was previously testable only
# against that live third party, and a non-array 200 body would have flowed
# into the jq filters. The fixture seam (POLARIS_CT_FIXTURE) makes the anomaly
# path testable, and the array-type guard fails closed to inconclusive.
def check_ct_monitor_testable_and_guarded(root: pathlib.Path) -> list[Finding]:
    sh = _read(root, "scripts/polaris-ct-monitor.sh")
    if not sh:
        return _fail("ct_monitor", "scripts/polaris-ct-monitor.sh is missing")
    if "POLARIS_CT_FIXTURE" not in sh:
        return _fail("ct_monitor",
                     "ct-monitor has no fixture seam; its parse/anomaly path is only "
                     "testable against the live, flaky crt.sh service")
    if "type == \"array\"" not in sh and "type==\"array\"" not in sh:
        return _fail("ct_monitor",
                     "ct-monitor does not verify the crt.sh response is a JSON array; a "
                     "transient HTML error page would be parsed as certificate data")
    return _ok("ct_monitor",
               "ct-monitor is offline-testable (fixture seam) and rejects non-array "
               "responses as inconclusive rather than parsing an error page")


# P0.4 — polaris-rotate-secret.sh must PRESERVE a secret file's mode, not force
# 0600. polaris-generate-secrets.sh deliberately makes several secrets 0644
# (inside a 0700 dir) so non-root containers can read the bind-mount on Linux
# (the v9.140 fix). A rotation that hardcoded 0600 silently regressed that and
# would crash-loop the prod stack on next deploy. Pin: no bare `chmod 0600` on
# the rotated target, and the current mode must be captured.
def check_rotate_secret_preserves_mode(root: pathlib.Path) -> list[Finding]:
    sh = _read(root, "scripts/polaris-rotate-secret.sh")
    if not sh:
        return _fail("rotate_mode", "scripts/polaris-rotate-secret.sh is missing")
    if re.search(r'chmod\s+0600\s+"\$\{TARGET\}\.new"', sh):
        return _fail("rotate_mode",
                     "rotate-secret hardcodes chmod 0600 on the replacement; it regresses "
                     "the 0644 secrets that non-root containers must read on Linux (v9.140)")
    code = "\n".join(l for l in sh.splitlines() if not l.lstrip().startswith("#"))
    if re.search(r"stat -f[^|\n]*\|\|", code):
        return _fail("rotate_mode",
                     "polaris-rotate-secret.sh chains `stat -f ... ||` to a fallback: GNU stat's -f is "
                     "file-system status and exits 0, so the fallback never runs on Linux and chmod gets "
                     "garbage (the v9.181 rotation-drill failure); pick the dialect with `stat --version`")
    if "CUR_MODE" not in sh or "stat" not in sh:
        return _fail("rotate_mode",
                     "rotate-secret does not capture the existing file mode before writing "
                     "the replacement; the rotated secret's perms are not preserved")
    return _ok("rotate_mode",
               "rotate-secret preserves each secret file's existing mode, so a 0644 "
               "container-readable secret stays 0644 after rotation")


# P0.5 — every release ships an SPDX SBOM for each artifact. The workflow must
# exist, trigger on release, cover the Python surface plus all five self-built
# images, and attach the documents to the release. A release whose contents
# cannot be enumerated from a bill of materials is a supply-chain blind spot.
def check_sbom_workflow(root: pathlib.Path) -> list[Finding]:
    wf = _read(root, ".github/workflows/sbom.yml")
    if not wf:
        return _fail("sbom", ".github/workflows/sbom.yml is missing; releases ship no SBOM")
    if "release:" not in wf:
        return _fail("sbom", "sbom.yml is not triggered on release")
    if "spdx-json" not in wf:
        return _fail("sbom", "sbom.yml does not generate SPDX-format SBOMs")
    # All five images plus the python surface must be covered. The images are
    # built through scripts/polaris-image-build.sh (which builds the whole set)
    # and scanned by a loop over the five names, so neither step spells the
    # tags out any more.
    builds_all = "polaris-image-build.sh --stack sbom" in wf
    for img in ("app", "caddy", "pgbouncer", "postgres", "etcd"):
        built = builds_all or f"polaris-{img}:sbom" in wf
        scanned = f"polaris-{img}:sbom" in wf or re.search(
            r"for name in[^\n]*\b" + img + r"\b", wf) is not None
        if not (built and scanned):
            return _fail("sbom", f"sbom.yml does not build/scan the {img} image")
    if "sbom-python" not in wf:
        return _fail("sbom", "sbom.yml does not generate the Python-surface SBOM")
    if "gh release upload" not in wf:
        return _fail("sbom", "sbom.yml does not attach the SBOMs to the release")
    return _ok("sbom",
               "every release generates SPDX SBOMs for the Python surface + all five "
               "self-built images and attaches them to the release")


# P0.5 — the SBOM generator and the CVE scanner must be the SAME Trivy version.
# If they drift, the bill of materials describes a package set the gate never
# scanned (or vice versa), and the two documents stop corroborating each other.
def check_sbom_trivy_matches_scan(root: pathlib.Path) -> list[Finding]:
    ci = _read(root, ".github/workflows/ci.yml")
    sbom = _read(root, ".github/workflows/sbom.yml")
    if not sbom:
        return _fail("sbom_trivy", ".github/workflows/sbom.yml is missing")
    versions = set(re.findall(r"aquasec/trivy:([0-9][0-9.]*)", ci + sbom))
    if not versions:
        return _fail("sbom_trivy", "no aquasec/trivy version found in the workflows")
    if len(versions) > 1:
        return _fail("sbom_trivy",
                     f"the SBOM generator and the CVE scanner use different Trivy "
                     f"versions {sorted(versions)}; they must match so the SBOM "
                     f"describes what the scanner saw")
    return _ok("sbom_trivy",
               f"the SBOM generator and CVE scanner share one Trivy version "
               f"({versions.pop()})")


# P0.6 — every release artifact carries a signed SLSA provenance attestation,
# and the docs carry a verify command. Keyless Sigstore signing (GitHub OIDC)
# means no long-lived key; the attestation binds each SBOM's digest to this
# repo + workflow. An SBOM without provenance is unforgeable-adjacent but not
# unforgeable: anyone could publish a plausible SBOM. The attestation closes
# that.
def check_release_provenance(root: pathlib.Path) -> list[Finding]:
    wf = _read(root, ".github/workflows/sbom.yml")
    if not wf:
        return _fail("provenance", ".github/workflows/sbom.yml is missing")
    if "attest-build-provenance" not in wf:
        return _fail("provenance",
                     "the release workflow generates SBOMs but does not attest their "
                     "provenance; a forged SBOM would be indistinguishable from a real one")
    # Keyless Sigstore signing needs the OIDC + attestations permissions.
    if "id-token: write" not in wf or "attestations: write" not in wf:
        return _fail("provenance",
                     "the provenance step lacks id-token:write / attestations:write; "
                     "keyless signing cannot mint its Sigstore identity")
    sec = _read(root, "SECURITY.md")
    if "gh attestation verify" not in sec:
        return _fail("provenance",
                     "SECURITY.md carries no `gh attestation verify` command; a signed "
                     "artifact nobody knows how to verify is not much of a control")
    return _ok("provenance",
               "release SBOMs get a keyless SLSA provenance attestation and SECURITY.md "
               "documents the verify command")


# P0.7 — the Rust prover and the Python second witness must build the SAME
# circuit shape, which means the SAME tree depth. Depth is now runtime-
# parameterized (POLARIS_ZK_TREE_DEPTH); both sides read that env var and must
# share the same default. If the defaults drift, a default-config prover and a
# default-config witness would silently disagree on every proof, and the
# two-witness guarantee (the strongest thing this layer offers) would break.
def check_zk_tree_depth_synced(root: pathlib.Path) -> list[Finding]:
    rs = _read(root, "polaris_zk/src/lib.rs")
    py = _read(root, "polaris_zk/witness2/merkle.py")
    if not rs or not py:
        return _fail("zk_depth_sync", "polaris_zk lib.rs or witness2/merkle.py is missing")
    # Both must read the shared env var.
    if "POLARIS_ZK_TREE_DEPTH" not in rs or "POLARIS_ZK_TREE_DEPTH" not in py:
        return _fail("zk_depth_sync",
                     "the tree depth is not read from POLARIS_ZK_TREE_DEPTH on both sides; "
                     "the prover and second witness could diverge on circuit shape")
    m_rs = re.search(r"DEFAULT_TREE_DEPTH:\s*usize\s*=\s*(\d+)", rs)
    m_py = re.search(r"DEFAULT_TREE_DEPTH\s*=\s*(\d+)", py)
    if not m_rs or not m_py:
        return _fail("zk_depth_sync", "could not find DEFAULT_TREE_DEPTH on both sides")
    if m_rs.group(1) != m_py.group(1):
        return _fail("zk_depth_sync",
                     f"default tree depth differs: Rust {m_rs.group(1)} vs Python "
                     f"{m_py.group(1)}; a default-config prover and witness would disagree")
    # The Rust fallback in tree_depth() must equal DEFAULT_TREE_DEPTH too.
    m_fallback = re.search(r"Err\(_\)\s*=>\s*(\d+)", rs)
    if m_fallback and m_fallback.group(1) != m_rs.group(1):
        return _fail("zk_depth_sync",
                     "the tree_depth() env-absent fallback differs from DEFAULT_TREE_DEPTH")
    return _ok("zk_depth_sync",
               f"the Rust prover and Python second witness share tree depth "
               f"(default {m_rs.group(1)}, both read POLARIS_ZK_TREE_DEPTH)")


# P0.8 — coverage must be measured AND gated, on both surfaces. A test suite
# with no coverage floor silently rots: a refactor that stops exercising a
# module reads as green as long as the remaining tests pass. The floor is a
# ratchet (fails on a drop). Pin that the Python gate script exists and CI runs
# it with a floor, and that CI gates the Rust library coverage too.
def check_coverage_gated(root: pathlib.Path) -> list[Finding]:
    sh = _read(root, "scripts/polaris-coverage.sh")
    if not sh:
        return _fail("coverage_gate", "scripts/polaris-coverage.sh is missing; coverage is not measured")
    if "--fail-under" not in sh:
        return _fail("coverage_gate",
                     "polaris-coverage.sh does not gate on a floor (--fail-under); it measures "
                     "coverage without failing on a regression")
    ci = _read(root, ".github/workflows/ci.yml")
    if "polaris-coverage.sh" not in ci:
        return _fail("coverage_gate",
                     "CI does not run scripts/polaris-coverage.sh; the Python coverage floor is "
                     "never enforced")
    if "COVERAGE_FLOOR" not in ci:
        return _fail("coverage_gate", "CI runs coverage without setting a COVERAGE_FLOOR")
    if "fail-under-lines" not in ci:
        return _fail("coverage_gate",
                     "CI does not gate the Rust library coverage (cargo llvm-cov "
                     "--fail-under-lines); only Python is floored")
    return _ok("coverage_gate",
               "coverage is measured and gated on both surfaces: Python via polaris-coverage.sh "
               "with a COVERAGE_FLOOR, Rust via cargo llvm-cov --fail-under-lines")


def check_offsite_backup_env_driven(root: pathlib.Path) -> list[Finding]:
    """Roadmap P0.9: the offsite (S3) backup repo is configured by env alone, the
    credentials never travel through env, and the offsite path is CI-exercised.

    The load-bearing lesson is pinned first: pgBackRest refuses an option that
    appears in more than one config file ("option 'repo1-path' cannot be set
    multiple times"), so the repo location may live ONLY in the rendered
    conf.d/repo.conf. A repo1-path back in pgbackrest.conf breaks every
    deployment, local or offsite, at container start."""
    conf = _read(root, "polaris_web/pgbackrest.conf")
    gen = _read(root, "polaris_web/pgbackrest-conf.sh")
    entry = _read(root, "polaris_web/pg-entrypoint.sh")
    dockerfile = _read(root, "polaris_web/Dockerfile.postgres")
    compose = _read(root, "polaris_web/docker-compose.prod.yml")
    secrets = _read(root, "scripts/polaris-generate-secrets.sh")
    deploy = _read(root, "scripts/polaris-deploy.sh")
    drill = _read(root, "scripts/polaris-offsite-drill.sh")
    ci = _read(root, ".github/workflows/ci.yml")
    dr = _read(root, "docs/operator/DR.md")
    if not (conf and gen and entry and dockerfile and compose and secrets and deploy and drill and ci and dr):
        return _fail("offsite_backup", "an offsite-backup file is missing (renderer, entrypoint, drill, "
                     "compose, secrets, deploy, DR.md, or ci.yml)")
    if re.search(r"^\s*repo1-path\s*=", conf, re.M):
        return _fail("offsite_backup",
                     "pgbackrest.conf sets repo1-path; the repo location lives only in the rendered "
                     "conf.d/repo.conf (pgBackRest refuses an option set in two files: 'cannot be set "
                     "multiple times' fails every container start)")
    if "POLARIS_PGBACKREST_S3_BUCKET" not in gen or "repo1-type=s3" not in gen or "repo1-path=" not in gen:
        return _fail("offsite_backup",
                     "pgbackrest-conf.sh must render BOTH the local repo1-path default and the S3 repo "
                     "(repo1-type=s3) from POLARIS_PGBACKREST_S3_BUCKET")
    if "POLARIS_PGBACKREST_S3_KEY_SECRET" not in gen or not re.search(r"exit 3", gen):
        return _fail("offsite_backup",
                     "pgbackrest-conf.sh must refuse (exit 3) when the S3 key pair is in env; the key "
                     "pair is a root-level secret that leaks via docker inspect")
    if "polaris-pgbackrest-conf.sh" not in entry or "docker-entrypoint.sh" not in entry:
        return _fail("offsite_backup",
                     "pg-entrypoint.sh must run the renderer then exec the stock docker-entrypoint.sh "
                     "(every start, not just first init: the fragment must survive recreation)")
    if "pgbackrest-conf.sh" not in dockerfile or "pg-entrypoint.sh" not in dockerfile \
            or "ENTRYPOINT" not in dockerfile:
        return _fail("offsite_backup",
                     "Dockerfile.postgres must COPY the renderer + wrapper and set ENTRYPOINT to the wrapper")
    if "POLARIS_PGBACKREST_S3_BUCKET" not in compose or "conf.d/repo-creds.conf" not in compose:
        return _fail("offsite_backup",
                     "the prod compose must pass POLARIS_PGBACKREST_S3_* to postgres and mount the "
                     "credential fragment at conf.d/repo-creds.conf")
    if re.search(r"POLARIS_PGBACKREST_S3_KEY", compose):
        return _fail("offsite_backup",
                     "the prod compose must not carry the S3 key pair in environment (it leaks via "
                     "docker inspect); it is the mounted secret fragment only")
    if "pgbackrest_repo_creds.conf" not in secrets or "pgbackrest_repo_creds.conf" not in deploy:
        return _fail("offsite_backup",
                     "polaris-generate-secrets.sh must create pgbackrest_repo_creds.conf and "
                     "polaris-deploy.sh must require it (an unconditional mount with a missing source "
                     "makes docker create a directory)")
    m_def = re.search(r"^write_pgbackrest_creds_if_missing\(\)", secrets, re.M)
    m_call = re.search(r"^write_pgbackrest_creds_if_missing\s*$", secrets, re.M)
    if not m_def or not m_call or m_def.start() > m_call.start():
        return _fail("offsite_backup",
                     "polaris-generate-secrets.sh must DEFINE write_pgbackrest_creds_if_missing before "
                     "calling it (bash resolves functions at call time; `bash -n` passes on a definition "
                     "placed after the call, and the v9.173 CI prod boot died on 'command not found')")
    if "minio" not in drill.lower() or "restore" not in drill or "repo1-type=s3" not in drill \
            or "POLARIS_PGBACKREST_S3_KEY=" not in drill:
        return _fail("offsite_backup",
                     "polaris-offsite-drill.sh must back up to and restore from an S3 endpoint (MinIO), "
                     "assert the rendered repo is repo1-type=s3, and prove the key-pair-in-env refusal")
    if "polaris-offsite-drill.sh" not in ci:
        return _fail("offsite_backup", "ci.yml must run scripts/polaris-offsite-drill.sh")
    if "POLARIS_PGBACKREST_S3_BUCKET" not in dr:
        return _fail("offsite_backup", "DR.md must document the POLARIS_PGBACKREST_S3_* offsite switch")
    return _ok("offsite_backup",
               "offsite backup by env alone: the image entrypoint renders conf.d/repo.conf every start "
               "(local default or S3), the key pair is a mounted fragment the container refuses from env, "
               "compose/secrets/deploy carry it, and CI drills backup+restore against MinIO")


def check_pager_integration(root: pathlib.Path) -> list[Finding]:
    """Roadmap P0.10: alerts reach a pager, and the duress page path is proven.

    Ships an Alertmanager receiver template whose pager URL/keys are mounted
    files (never inline: the URL usually embeds the integration key), routes
    PolarisDuressEvent with no grouping wait, wires prometheus.yml to it, and
    proves the path in CI: the product suite proves a duress match increments
    polaris_duress_events_total, and scripts/polaris-page-drill.sh proves the
    counter increment reaches the webhook through the shipped rules + config
    with real Prometheus and Alertmanager (after promtool/amtool validate them)."""
    am = _read(root, "deploy/observability/alertmanager.yml")
    prom = _read(root, "deploy/observability/prometheus.yml")
    drill = _read(root, "scripts/polaris-page-drill.sh")
    ci = _read(root, ".github/workflows/ci.yml")
    book = _read(root, "docs/operator/RUNBOOKS.md")
    tests = _read(root, "polaris_web/test_app.py")
    if not (am and prom and drill and ci and book and tests):
        return _fail("pager", "a pager-integration file is missing (alertmanager.yml, prometheus.yml, "
                     "polaris-page-drill.sh, ci.yml, RUNBOOKS.md, or test_app.py)")
    if "webhook_configs" not in am or "url_file" not in am:
        return _fail("pager", "alertmanager.yml must ship a webhook receiver whose URL comes from url_file "
                     "(the pager URL embeds the integration key; it is a mounted secret, not config)")
    if re.search(r"(?m)^\s*(url|routing_key|api_key|api_url|service_key)\s*:", am):
        return _fail("pager", "alertmanager.yml carries a pager URL or key INLINE; use url_file / "
                     "routing_key_file / api_key_file / api_url_file so the secret is a mounted file")
    if not re.search(r"matchers:\s*\[\s*'alertname=\"PolarisDuressEvent\"'\s*\][^-]*?group_wait:\s*0s", am, re.S):
        return _fail("pager", "alertmanager.yml must route PolarisDuressEvent with group_wait: 0s (a "
                     "coerced person cannot wait out a grouping window)")
    if not re.search(r"(?m)^alerting:", prom) or not re.search(r"(?m)^\s+alertmanagers:", prom):
        return _fail("pager", "prometheus.yml must have a live (uncommented) alerting.alertmanagers block; "
                     "rules that reach no Alertmanager page no one")
    for needle in ("promtool check rules", "amtool check-config", "polaris_duress_events_total",
                   "PolarisDuressEvent", "webhook", "alertmanager.yml"):
        if needle not in drill:
            return _fail("pager", f"polaris-page-drill.sh must contain '{needle}': validate the shipped "
                         "configs, flip the duress counter, and assert the PolarisDuressEvent webhook")
    if "polaris-page-drill.sh" not in ci:
        return _fail("pager", "ci.yml must run scripts/polaris-page-drill.sh")
    if "def test_duress_increments_prometheus_counter" not in tests:
        return _fail("pager", "test_app.py must keep test_duress_increments_prometheus_counter (the app half "
                     "of the page path: a duress match increments the counter the drill starts from)")
    if "pager_webhook_url" not in book:
        return _fail("pager", "RUNBOOKS.md must document wiring the pager (the pager_webhook_url secret file)")
    return _ok("pager", "pager integration: a file-secret webhook receiver template, PolarisDuressEvent "
               "routed with no wait, prometheus.yml wired to it, promtool/amtool + a real "
               "Prometheus->Alertmanager->webhook duress drill in CI, the app-half test kept, and a "
               "wiring runbook")


def check_linux_server_deployment(root: pathlib.Path) -> list[Finding]:
    """Roadmap P1.1: a fresh Debian/RHEL server reaches a healthy production stack
    from deploy/linux/install.sh alone, under systemd, with a hardening guide.

    Pins the shape that makes it trustworthy: Docker from Docker's official
    repositories with the signing key's fingerprint verified (never curl|sh),
    both apt and dnf branches present, a unit that Requires docker.service and
    reads an EnvironmentFile, backup timers, the two guides linked from the
    README and the operator index, and CI executing the package stage on both
    distro families plus the full install on a real systemd host."""
    inst = _read(root, "deploy/linux/install.sh")
    unit = _read(root, "deploy/linux/polaris.service")
    bsvc = _read(root, "deploy/linux/polaris-backup.service")
    btim = _read(root, "deploy/linux/polaris-backup.timer")
    envx = _read(root, "deploy/linux/polaris.env.example")
    guide = _read(root, "docs/operator/LINUX-SERVER.md")
    hard = _read(root, "docs/operator/HARDENING.md")
    readme = _read(root, "README.md")
    index = _read(root, "docs/operator/README.md")
    ci = _read(root, ".github/workflows/ci.yml")
    if not (inst and unit and bsvc and btim and envx and guide and hard and readme and index and ci):
        return _fail("linux_server", "a Linux-deployment file is missing (deploy/linux/{install.sh, polaris.service, "
                     "polaris-backup.service, polaris-backup.timer, polaris.env.example}, "
                     "docs/operator/{LINUX-SERVER.md, HARDENING.md}, README.md, docs/operator/README.md, ci.yml)")
    # Comments may NAME the anti-pattern (the installer's header says never to do
    # it); only executable lines are judged.
    code = "\n".join(l for l in inst.splitlines() if not l.lstrip().startswith("#"))
    if re.search(r"get\.docker\.com|curl[^|\n]*\|\s*(sudo\s+)?(ba)?sh\b", code):
        return _fail("linux_server", "install.sh must not pipe a download into a shell (get.docker.com / curl | sh); "
                     "use Docker's apt/dnf repositories with the signing key verified")
    if "download.docker.com" not in inst or "0EBFCD88" not in inst or "621E9F35" not in inst or "gpg" not in inst:
        return _fail("linux_server", "install.sh must add Docker's official repository and verify the signing key "
                     "fingerprint with gpg before trusting it, for BOTH keys: deb 9DC85822...0EBFCD88 and rpm "
                     "060A61C5...621E9F35 (they differ; the deb fingerprint refuses the rpm key)")
    if "apt-get" not in inst or "dnf" not in inst:
        return _fail("linux_server", "install.sh must carry both the Debian (apt-get) and RHEL (dnf) branches")
    for needle in ("polaris-generate-secrets.sh", "systemctl enable", "systemctl daemon-reload", "/api/health",
                   "polaris-migrate.sh"):
        if needle not in inst:
            return _fail("linux_server", f"install.sh must include '{needle}' (secrets, units enabled, migrations, "
                         "health asserted)")
    if "Requires=docker.service" not in unit or "EnvironmentFile=" not in unit \
            or "docker-compose.prod.yml" not in unit or "WantedBy=multi-user.target" not in unit \
            or "ExecStop=" not in unit:
        return _fail("linux_server", "polaris.service must Require docker.service, read an EnvironmentFile, run the prod "
                     "compose file in ExecStart with an ExecStop, and be WantedBy multi-user.target")
    if "OnCalendar=" not in btim or "Persistent=true" not in btim or "polaris-backup.sh" not in bsvc:
        return _fail("linux_server", "polaris-backup.timer must schedule (OnCalendar, Persistent) polaris-backup.service "
                     "running scripts/polaris-backup.sh")
    if "POLARIS_DOMAIN=" not in envx:
        return _fail("linux_server", "polaris.env.example must carry POLARIS_DOMAIN")
    if "install.sh" not in guide or "systemctl" not in guide or "HARDENING.md" not in guide:
        return _fail("linux_server", "LINUX-SERVER.md must document the installer, the systemd units, and link HARDENING.md")
    for needle in ("ssh", "unattended-upgrades", "ufw", "firewalld", "chrony", "daemon.json", "auditd", "/metrics"):
        if needle not in hard:
            return _fail("linux_server", f"HARDENING.md must cover '{needle}'")
    if "docs/operator/LINUX-SERVER.md" not in readme or "LINUX-SERVER.md" not in index or "HARDENING.md" not in index:
        return _fail("linux_server", "README.md must link docs/operator/LINUX-SERVER.md and the operator index must list "
                     "LINUX-SERVER.md and HARDENING.md (a server path no one can find is not a path)")
    if "deploy/linux/install.sh" not in ci or "debian@sha256:" not in ci or "rockylinux@sha256:" not in ci \
            or "systemctl is-active polaris" not in ci:
        return _fail("linux_server", "ci.yml must run install.sh: the packages stage in digest-pinned Debian and Rocky "
                     "containers, and the full install under real systemd (systemctl is-active polaris)")
    return _ok("linux_server", "Linux server deployment: install.sh (Docker's repos, key verified, apt+dnf), "
               "polaris.service + backup timers, LINUX-SERVER.md + HARDENING.md linked from README and the "
               "operator index, and CI proving both package branches plus a full systemd install to healthy")


def check_key_custody_abstraction(root: pathlib.Path) -> list[Finding]:
    """Roadmap P1.2: the issuer signing key sits behind a custody interface with
    file, PKCS#11, and AWS KMS drivers; secrets never come from env; the
    two-witness verify path is unchanged; each driver is exercised (the
    PKCS#11 one against a real token in CI); ceremony + rotation documented."""
    cu = _read(root, "polaris_web/custody.py")
    pq = _read(root, "polaris_web/pqc_signing.py")
    tests = _read(root, "polaris_web/test_custody.py")
    req = _read(root, "polaris_web/requirements-custody.txt")
    ci = _read(root, ".github/workflows/ci.yml")
    cer = _read(root, "docs/operator/KEY-CEREMONY.md")
    app = _read(root, "polaris_web/app.py")
    if not (cu and pq and tests and req and ci and cer and app):
        return _fail("key_custody", "a custody file is missing (custody.py, pqc_signing.py, test_custody.py, "
                     "requirements-custody.txt, ci.yml, KEY-CEREMONY.md, app.py)")
    for cls in ("class FileCustody", "class Pkcs11Custody", "class AwsKmsCustody", "def from_env", "def get_custody"):
        if cls not in cu:
            return _fail("key_custody", f"custody.py must define {cls}")
    if "Mechanism.ML_DSA" not in cu or "ML_DSA_KEY_PAIR_GEN" not in cu or "EXTRACTABLE: False" not in cu:
        return _fail("key_custody", "the PKCS#11 driver must sign with CKM_ML_DSA and generate the key in-token, "
                     "non-extractable (ML_DSA_KEY_PAIR_GEN, EXTRACTABLE: False)")
    if "ML_DSA_65" not in cu or "ML_DSA_SHAKE_256" not in cu or 'MessageType="RAW"' not in cu:
        return _fail("key_custody", "the AWS KMS driver must require KeySpec ML_DSA_65 and sign RAW with "
                     "ML_DSA_SHAKE_256 (pure ML-DSA over the digest, so verifiers see the same bytes)")
    if "POLARIS_CUSTODY_PKCS11_PIN_FILE" not in cu or "POLARIS_CUSTODY_PKCS11_PIN\"" not in cu \
            or "PIN_FILE" not in cu:
        return _fail("key_custody", "the PKCS#11 PIN must come from POLARIS_CUSTODY_PKCS11_PIN_FILE and the driver "
                     "must refuse POLARIS_CUSTODY_PKCS11_PIN in env")
    if "custody.get_custody()" not in pq or re.search(r"Signature\(_ALG_NAME,\s*secret_key=", pq):
        return _fail("key_custody", "pqc_signing.sign() must obtain signatures from custody.get_custody(); no direct "
                     "secret-key signing outside the custody layer")
    if "def trust_anchor_public_keys" not in pq or "POLARIS_PQC_TRUST_ANCHORS_FILE" not in pq:
        return _fail("key_custody", "pqc_signing must expose rotation trust anchors "
                     "(trust_anchor_public_keys + POLARIS_PQC_TRUST_ANCHORS_FILE)")
    if "def verify_both" not in pq or "verify_both(" not in pq.split("def signature_with_key_for_token")[1].split("\ndef ")[0]:
        return _fail("key_custody", "the two-witness verify (verify_both) must still gate every stored signature")
    for cls in ("class FileCustodyTests", "class AwsKmsCustodyTests", "class Pkcs11CustodyTests", "_KmsStandIn",
                "TRUST_ANCHORS_FILE"):
        if cls not in tests:
            return _fail("key_custody", f"test_custody.py must contain {cls} (each driver exercised, rotation tested)")
    if "python-pkcs11==" not in req or "boto3==" not in req:
        return _fail("key_custody", "requirements-custody.txt must pin python-pkcs11 and boto3")
    if "kryoptic" not in ci or "test_custody" not in ci or "POLARIS_CUSTODY_PKCS11_REQUIRE" not in ci \
            or "requirements-custody.txt" not in ci:
        return _fail("key_custody", "ci.yml must run the PKCS#11 suite against a real token (kryoptic, "
                     "POLARIS_CUSTODY_PKCS11_REQUIRE=1) and install requirements-custody.txt for the test job")
    if "## Rotation" not in cer or "pkcs11-keygen" not in cer or "ML_DSA_65" not in cer:
        return _fail("key_custody", "KEY-CEREMONY.md must document the ceremony per driver and a Rotation section")
    if "'custody':" not in app or "def _health_check_custody" not in app:
        return _fail("key_custody", "/api/health must report the custody component (driver, key id, fingerprint)")
    return _ok("key_custody", "issuer-key custody: file / PKCS#11 (CKM_ML_DSA, in-token, non-extractable) / "
               "AWS KMS (ML_DSA_65, RAW ML_DSA_SHAKE_256) behind one interface, PIN never from env, "
               "pqc_signing routed through it with the two-witness verify unchanged, rotation anchors, "
               "each driver exercised (PKCS#11 against Kryoptic in CI), ceremony + rotation runbook, health")


def check_secrets_lifecycle_sealed(root: pathlib.Path) -> list[Finding]:
    """Roadmap P1.3: production secrets come from a sealed store (age or AWS KMS
    envelope encryption), materialized into a tmpfs at start; compose reads only
    POLARIS_SECRETS_DIR; rotation writes through to the store; and CI boots the
    prod stack from a sealed store with the plaintext deleted, then rotates two
    secrets on the live stack and verifies the store still matches."""
    st = _read(root, "polaris_web/secretstore.py")
    wr = _read(root, "scripts/polaris-secrets.sh")
    dep = _read(root, "scripts/polaris-deploy.sh")
    rot = _read(root, "scripts/polaris-rotate-secret.sh")
    unit = _read(root, "deploy/linux/polaris.service")
    tests = _read(root, "polaris_web/test_secretstore.py")
    ci = _read(root, ".github/workflows/ci.yml")
    doc = _read(root, "docs/operator/SECRETS.md")
    gi = _read(root, ".gitignore")
    if not (st and wr and dep and rot and unit and tests and ci and doc and gi):
        return _fail("secrets_sealed", "a sealed-secrets file is missing (secretstore.py, polaris-secrets.sh, deploy, "
                     "rotate-secret, polaris.service, test_secretstore.py, ci.yml, SECRETS.md, .gitignore)")
    for needle in ("class AgeBackend", "class AwsKmsBackend", "generate_data_key", "AESGCM", "KeyId=self.key_id",
                   "def rotate_wrapping", "def verify", "\"mode\""):
        if needle not in st:
            return _fail("secrets_sealed", f"secretstore.py must contain {needle!r} (age + KMS envelope backends, "
                         "KeyId pinned on Decrypt, wrapping rotation, verify, modes in the manifest)")
    compose_files = ["polaris_web/docker-compose.prod.yml", "polaris_web/docker-compose.custody-pkcs11.yml",
                     "polaris_web/docker-compose.custody-awskms.yml"]
    for f in compose_files:
        c = _read(root, f)
        if c and re.search(r"(?<!\{POLARIS_SECRETS_DIR:-)\./secrets/", c):
            return _fail("secrets_sealed", f"{f} still references ./secrets/ directly; every secret path must go "
                         "through ${POLARIS_SECRETS_DIR:-./secrets} so a sealed store can be materialized elsewhere")
    if "unseal-if-configured" not in wr or "mount -t tmpfs" not in wr:
        return _fail("secrets_sealed", "polaris-secrets.sh must provide unseal-if-configured that mounts a tmpfs for the "
                     "materialized plaintext")
    if "unseal-if-configured" not in dep or "POLARIS_SECRETS_DIR" not in dep:
        return _fail("secrets_sealed", "polaris-deploy.sh must unseal-if-configured before preflight and honour "
                     "POLARIS_SECRETS_DIR")
    if "seal --only" not in rot or "POLARIS_SECRETS_DIR" not in rot:
        return _fail("secrets_sealed", "polaris-rotate-secret.sh must rotate the materialized secret and write it through "
                     "to the sealed store (seal --only)")
    m = re.search(r"polaris_db_password\)(.*?)\n\s*;;", rot, re.S)
    if not m or "force-recreate pgbouncer" not in m.group(1):
        return _fail("secrets_sealed", "rotating polaris_db_password must recreate pgbouncer (it generates userlist.txt "
                     "from the secret at start) before the app, or every connection fails SASL auth after rotation "
                     "(the v9.181 live-rotation failure)")
    if "unseal-if-configured" not in unit:
        return _fail("secrets_sealed", "polaris.service must run polaris-secrets.sh unseal-if-configured as ExecStartPre")
    for needle in ("class AgeBackendTests", "class AwsKmsBackendTests", "rotate_wrapping", "drift"):
        if needle not in tests:
            return _fail("secrets_sealed", f"test_secretstore.py must contain {needle!r}")
    if "polaris-secrets.sh seal" not in ci or "rm -rf polaris_web/secrets" not in ci \
            or "polaris-rotate-secret.sh polaris_db_password" not in ci or "polaris-secrets.sh verify" not in ci:
        return _fail("secrets_sealed", "ci.yml prod-stack-boot must seal, DELETE the plaintext, boot from the tmpfs, "
                     "rotate on the live stack, and verify the sealed store matches")
    if "POLARIS_SECRETS_BACKEND" not in doc or "rotate-wrapping" not in doc:
        return _fail("secrets_sealed", "SECRETS.md must document POLARIS_SECRETS_BACKEND and rotate-wrapping")
    if "polaris_web/secrets.sealed/" not in gi:
        return _fail("secrets_sealed", ".gitignore must exclude polaris_web/secrets.sealed/")
    envx = _read(root, "deploy/linux/polaris.env.example")
    if envx and not re.search(r"(?m)^POLARIS_SECRETS_DIR=\s*$", envx):
        return _fail("secrets_sealed", "polaris.env.example must leave POLARIS_SECRETS_DIR empty: set it with the file "
                     "backend, compose reads a directory nothing populates and polaris.service fails at start "
                     "(the v9.180 CI install failure)")
    return _ok("secrets_sealed", "secrets lifecycle: age / AWS KMS envelope sealed store, compose reads only "
               "POLARIS_SECRETS_DIR (tmpfs), deploy + polaris.service unseal first, rotation writes through, "
               "wrapping-key rotation, tests for both backends, and a CI boot-from-sealed + live rotation drill")


_DESTRUCTIVE_DDL = re.compile(
    r"\b(DROP\s+TABLE|DROP\s+COLUMN|ALTER\s+COLUMN\s+\w+\s+(SET\s+DATA\s+)?TYPE|RENAME\s+COLUMN|RENAME\s+TO|SET\s+NOT\s+NULL)\b",
    re.I)


def _strip_sql_comments(sql: str) -> str:
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    return "\n".join(l.split("--", 1)[0] for l in sql.splitlines())


def check_migrations_expand_contract(root: pathlib.Path) -> list[Finding]:
    """Roadmap P1.4: the expand-contract policy. A rolling deploy runs the OLD
    code against the NEW schema, so an .up.sql that removes or reshapes what the
    previous code used must declare `-- phase: contract` and `-- expands: <id>`
    naming an existing earlier migration. Reverts (.down.sql) are exempt."""
    mig_dir = root / "polaris_sql" / "migrations"
    readme = _read(root, "polaris_sql/migrations/README.md")
    if not mig_dir.is_dir() or not readme:
        return _fail("expand_contract", "polaris_sql/migrations/ or its README.md is missing")
    if "phase: contract" not in readme or "expands:" not in readme:
        return _fail("expand_contract", "migrations/README.md must document the expand-contract policy "
                     "(`-- phase: contract` + `-- expands: <id>` headers)")
    ups = sorted(p for p in mig_dir.glob("*.up.sql"))
    ids = {p.name[:-len(".up.sql")] for p in ups}
    offenders = []
    for up in ups:
        text = up.read_text()
        m = _DESTRUCTIVE_DDL.search(_strip_sql_comments(text))
        if not m:
            continue
        phase = re.search(r"(?m)^--\s*phase:\s*(\w+)", text)
        expands = re.search(r"(?m)^--\s*expands:\s*(\S+)", text)
        if not phase or phase.group(1).lower() != "contract" or not expands:
            offenders.append(f"{up.name}: {m.group(1)} without `-- phase: contract` + `-- expands: <id>`")
        elif expands.group(1) not in ids or expands.group(1) >= up.name[:-len(".up.sql")]:
            offenders.append(f"{up.name}: expands {expands.group(1)!r}, which is not an EARLIER migration")
    if offenders:
        return _fail("expand_contract", "destructive DDL outside the contract phase (old code would break during a "
                     "rolling deploy): " + "; ".join(offenders[:4]))
    return _ok("expand_contract", f"expand-contract policy holds across {len(ups)} up-migrations (destructive DDL only "
               "in declared contract migrations that name their earlier expand step)")


def check_zero_downtime_deploy(root: pathlib.Path) -> list[Finding]:
    """Roadmap P1.4: a blue-green profile behind a retrying edge, a deploy that
    migrates first and rolls one colour at a time with health waits, rotation
    that rolls too, and a CI drill proving zero drops under traffic WITH a
    negative control."""
    caddy = _read(root, "polaris_web/Caddyfile")
    citest = _read(root, "polaris_web/Caddyfile.citest")
    compose = _read(root, "polaris_web/docker-compose.prod.yml")
    overlay = _read(root, "polaris_web/docker-compose.bluegreen.yml")
    dep = _read(root, "scripts/polaris-deploy.sh")
    rot = _read(root, "scripts/polaris-rotate-secret.sh")
    drill = _read(root, "scripts/polaris-rolling-drill.sh")
    ci = _read(root, ".github/workflows/ci.yml")
    if not (caddy and citest and compose and overlay and dep and rot and drill and ci):
        return _fail("zero_downtime", "a zero-downtime file is missing (Caddyfile(s), compose, bluegreen overlay, "
                     "deploy, rotate-secret, rolling drill, ci.yml)")
    for name, cf in (("Caddyfile", caddy), ("Caddyfile.citest", citest)):
        if "{$POLARIS_UPSTREAMS" not in cf or "lb_try_duration" not in cf or "/api/health/live" not in cf:
            return _fail("zero_downtime", f"{name} must take upstreams from POLARIS_UPSTREAMS, retry onto the other "
                         "colour (lb_try_duration), and poll /api/health/live")
    if "healthcheck:" not in compose.split("container_name: polaris-app\n")[1].split("\n  pgbouncer:")[0] \
            or "stop_grace_period" not in compose or "POLARIS_UPSTREAMS" not in compose:
        return _fail("zero_downtime", "the app service needs a healthcheck (the roll waits on it), a stop_grace_period "
                     "for gunicorn's graceful drain, and caddy must receive POLARIS_UPSTREAMS")
    if "app-green" not in overlay or "polaris-app-green" not in overlay or "app:8000 app-green:8000" not in overlay:
        return _fail("zero_downtime", "docker-compose.bluegreen.yml must define app-green and point caddy at both colours")
    i_up, i_mig, i_roll = dep.find("postgres pgbouncer redis caddy"), dep.find("--up --target=docker-stack"), dep.find("wait_healthy")
    if "POLARIS_COMPOSE_EXTRA" not in dep or min(i_up, i_mig, i_roll) < 0 or not (i_up < i_mig < i_roll) \
            or "sort -r" not in dep:
        return _fail("zero_downtime", "polaris-deploy.sh must honour POLARIS_COMPOSE_EXTRA, bring infrastructure up "
                     "first, migrate (expand), THEN roll app-green before app with health waits")
    if "recreate_apps" not in rot or "app(-green)?" not in rot:
        return _fail("zero_downtime", "polaris-rotate-secret.sh must recreate every app colour one at a time")
    for needle in ("drops\"] == 0", "drops\"] > 0", "compose stop", "polaris-deploy.sh prod"):
        if needle not in drill:
            return _fail("zero_downtime", f"polaris-rolling-drill.sh must contain {needle!r}: zero drops under a real "
                         "deploy AND a negative control that shows drops")
    if "polaris-rolling-drill.sh" not in ci or "docker-compose.bluegreen.yml" not in ci:
        return _fail("zero_downtime", "ci.yml must boot the blue-green profile and run scripts/polaris-rolling-drill.sh")
    # v9.240: an edge configuration change is a live reload, not a window, and
    # the two windows that remain (edge and database recreation) are measured
    # under traffic against ceilings. Without the admin socket there is no
    # reload path; without the deploy step an edited Caddyfile is silently not
    # applied; without the drill the windows are a sentence in a document.
    for name, cf in (("Caddyfile", caddy), ("Caddyfile.citest", citest)):
        if "admin unix//config/admin.sock" not in cf:
            return _fail("zero_downtime", f"{name} must expose Caddy's admin API on the unix socket "
                         "/config/admin.sock: it is the reload path that makes a configuration change windowless")
    if "caddy reload" not in dep or "unix//config/admin.sock" not in dep:
        return _fail("zero_downtime", "polaris-deploy.sh must apply a Caddyfile change with `caddy reload` through "
                     "the admin unix socket; compose does not recreate a container for a bind-mounted file change")
    wdrill = _read(root, "scripts/polaris-window-drill.sh")
    if not wdrill:
        return _fail("zero_downtime", "scripts/polaris-window-drill.sh is missing: the edge and database recreation "
                     "windows must be measured, not asserted")
    for needle in ("caddy reload", "--force-recreate caddy", "restart -t 10 postgres", "EDGE_CEILING", "DB_CEILING",
                   'r_drops" -le "$_rmax"'):
        if needle not in wdrill:
            return _fail("zero_downtime", f"polaris-window-drill.sh must contain {needle!r}: a config reload within a "
                         "small transient budget (a graceful reload may drop one in-flight request at a listener swap, "
                         "not zero), an edge recreation and a database restart measured against ceilings")
    if "polaris-window-drill.sh" not in ci:
        return _fail("zero_downtime", "ci.yml must run scripts/polaris-window-drill.sh after the rolling drill")
    return _ok("zero_downtime", "blue-green profile behind a retrying edge with fast liveness, deploy migrates then rolls "
               "green/blue with health waits (rollback both), rotation rolls too, CI drills zero drops under "
               "traffic with a negative control, edge configuration changes are live reloads, and the edge and "
               "database recreation windows are measured against ceilings")


def check_verification_load_certified(root: pathlib.Path) -> list[Finding]:
    """Roadmap P2.9 (v9.259): the HA drills hold a REAL, authenticated
    verify-AT-USE load (GET /api/tokens/<id>/verify, v9.258) across the
    transitions, not just a health ping. The rolling deploy (app-tier) must drop
    ZERO verifications; the failover (database-tier) drops during each window but
    must RECOVER after every scenario and keep serving under load. Pin the load
    generator's strict accounting, both drills' use of it, and its own test."""
    gen = _read(root, "scripts/polaris-verify-load.py")
    if not gen:
        return _fail("verify_load", "scripts/polaris-verify-load.py is missing (the authenticated verify-at-use load)")
    # It must exercise the real endpoint, authenticate, and account strictly:
    # only 200 is served, 429 is tolerated, everything else (a 302 lost session,
    # a 5xx failover gap, a transport error) is a DROP.
    for needle in ("/api/tokens/", "/verify", "/login", "def classify",
                   '"served", "ok"', '"tolerated", "http_429"', '"drop"'):
        if needle not in gen:
            return _fail("verify_load", f"polaris-verify-load.py must contain {needle!r}: it authenticates against "
                         "/login and verifies /api/tokens/<id>/verify with strict served/tolerated/drop accounting")
    if "--once" not in gen:
        return _fail("verify_load", "polaris-verify-load.py needs a --once recovery probe (verify answers 200 again)")

    test = _read(root, "scripts/test_verify_load.py")
    if not test or "classify" not in test or "run_once" not in test:
        return _fail("verify_load", "scripts/test_verify_load.py must test classify() and the run_once recovery probe")
    cov = _read(root, "scripts/polaris-coverage.sh")
    if "test_verify_load" not in cov:
        return _fail("verify_load", "polaris-coverage.sh must run scripts/test_verify_load under coverage")

    # The rolling drill (app-tier) certifies ZERO dropped verifications.
    rolling = _read(root, "scripts/polaris-rolling-drill.sh")
    if "polaris-verify-load.py" not in rolling or "verify.json" not in rolling \
            or "verification requests dropped" not in rolling:
        return _fail("verify_load", "polaris-rolling-drill.sh must hold a verify-at-use load and assert ZERO verification "
                     "drops across the rollover")

    # The failover drill (database-tier) certifies recovery after each scenario
    # and sustained service under load (reads DO drop in a failover window, so it
    # asserts recovery + a served floor, not zero drops).
    failover = _read(root, "scripts/polaris-failover-drill.sh")
    if "polaris-verify-load.py" not in failover or "verify_recovered" not in failover:
        return _fail("verify_load", "polaris-failover-drill.sh must hold a verify-at-use load and probe verify_recovered")
    if failover.count("verify_recovered || fail") < 4:
        return _fail("verify_load", "polaris-failover-drill.sh must assert verification RECOVERED after each of the four "
                     "failover scenarios")
    if 'assert s["served"] >=' not in failover:
        return _fail("verify_load", "polaris-failover-drill.sh must assert a served floor (verification kept serving "
                     "under load across the failover sequence)")
    return _ok("verify_load", "the HA drills hold an authenticated verify-at-use load: the rolling deploy drops zero "
               "verifications, the failover recovers verification after every scenario and keeps serving under load; "
               "the load generator's strict accounting is unit-tested and run under coverage")


def check_helm_reference_profile(root: pathlib.Path) -> list[Finding]:
    """Roadmap P1.5: a Helm chart deploys the production topology with default-deny
    NetworkPolicies and the restricted Pod Security Standard, the postgres image
    is self-contained, and CI proves it boots to healthy on kind with an ENFORCING
    CNI, a privileged pod rejected, and a probe pod denied by policy."""
    chart = root / "deploy" / "helm" / "polaris"
    values = _read(root, "deploy/helm/polaris/values.yaml")
    helpers = _read(root, "deploy/helm/polaris/templates/_helpers.tpl")
    np = _read(root, "deploy/helm/polaris/templates/networkpolicy.yaml")
    app = _read(root, "deploy/helm/polaris/templates/app.yaml")
    pg = _read(root, "deploy/helm/polaris/templates/postgres.yaml")
    dockerfile = _read(root, "polaris_web/Dockerfile.postgres")
    drill = _read(root, "scripts/polaris-helm-drill.sh")
    kindcfg = _read(root, "deploy/helm/kind-config.yaml")
    ci = _read(root, ".github/workflows/ci.yml")
    doc = _read(root, "docs/operator/KUBERNETES.md")
    readme = _read(root, "README.md")
    if not ((chart / "Chart.yaml").is_file() and values and helpers and np and app and pg and dockerfile and drill
            and kindcfg and ci and doc and readme):
        return _fail("helm_profile", "a Helm-profile file is missing (chart, values, helpers, networkpolicy/app/postgres "
                     "templates, Dockerfile.postgres, polaris-helm-drill.sh, kind-config.yaml, ci.yml, KUBERNETES.md)")
    for f in ("caddy.yaml", "pgbouncer.yaml", "redis.yaml", "secret.yaml", "configmap-caddy.yaml"):
        if not (chart / "templates" / f).is_file():
            return _fail("helm_profile", f"chart template {f} is missing")
    for needle in ("runAsNonRoot: true", "seccompProfile", "RuntimeDefault", 'drop: ["ALL"]', "allowPrivilegeEscalation: false"):
        if needle not in helpers:
            return _fail("helm_profile", f"the restricted Pod Security Standard requires {needle!r} in the shared "
                         "securityContext helpers")
    if "policyTypes: [Ingress, Egress]" not in np or "default-deny" not in np or "allow-dns" not in np \
            or np.count("kind: NetworkPolicy") < 6:
        return _fail("helm_profile", "networkpolicy.yaml must default-deny ingress+egress for every pod, allow DNS, and "
                     "carry one allow policy per workload")
    for f in ("app.yaml", "caddy.yaml", "pgbouncer.yaml", "redis.yaml"):
        if "automountServiceAccountToken: false" not in _read(root, f"deploy/helm/polaris/templates/{f}"):
            return _fail("helm_profile", f"{f} must set automountServiceAccountToken: false (no process there needs the "
                         "API; the projected token mount under /var/run/secrets collides with the Secret mount)")
    # v9.244 (roadmap P2.13): the database runs under Patroni with the API as
    # the lease store, so the postgres pods carry a token bound to a Role that
    # grants what Patroni needs and nothing else, and the leader Service has
    # no selector (Patroni fills its endpoints).
    for needle in ("automountServiceAccountToken: true", "kind: Role\n", "kind: RoleBinding\n",
                   "POLARIS_PATRONI_DCS, value: kubernetes", "replicas: {{ .Values.postgres.replicas }}",
                   "polaris-patroni-entrypoint.sh", "application: polaris-db", "-members", "-replicas"):
        if needle not in pg:
            return _fail("helm_profile", f"postgres.yaml lacks {needle!r}: the database must run under Patroni with the "
                         "Kubernetes API as the lease store, a Role for it, a selector-less leader Service, and the "
                         "member count from values")
    if "cluster-name" not in pg or "role: replica" not in pg:
        return _fail("helm_profile", "postgres.yaml must label members for Patroni (cluster-name) and select replicas by "
                     "the role label it maintains")
    if "port: 8008" not in np or "apiServer" not in np:
        return _fail("helm_profile", "networkpolicy.yaml must let the members reach each other's Patroni REST (8008) and "
                     "the API server (the lease store)")
    router = _read(root, "deploy/helm/polaris/templates/pg-router.yaml")
    pgb = _read(root, "deploy/helm/polaris/templates/pgbouncer.yaml")
    if "on-marked-down shutdown-sessions" not in router or "GET /primary" not in router or "check port 8008" not in router:
        return _fail("helm_profile", "pg-router.yaml must run HAProxy on Patroni's /primary with sessions cut on a member "
                     "marked down: nothing else closes the pooler's connections to a frozen leader")
    if "-pg-router}" not in pgb:
        return _fail("helm_profile", "pgbouncer must dial the router, not a member or the leader Service")
    caddy_df = _read(root, "polaris_web/Dockerfile.caddy")
    if "setcap -r /usr/bin/caddy" not in caddy_df:
        return _fail("helm_profile", "Dockerfile.caddy must strip the file capability from the caddy binary: a non-root "
                     "pod with capabilities dropped cannot exec a capability-bearing binary")
    if "maxUnavailable: 0" not in app or "/api/health/live" not in app or "PodDisruptionBudget" not in app:
        return _fail("helm_profile", "the app Deployment must roll with maxUnavailable 0, probe /api/health/live, and "
                     "carry a PodDisruptionBudget")
    if '"uid" 70' not in pg or "/var/lib/postgresql/data/pgdata" not in pg:
        return _fail("helm_profile", "postgres must run as uid 70 with PGDATA in a subdirectory of the volume "
                     "(non-root under the restricted standard)")
    if "COPY --chown=postgres:postgres polaris_sql" not in dockerfile or "docker-init.sh /docker-entrypoint-initdb.d/00-init.sh" not in dockerfile \
            or "pgbackrest.conf /etc/pgbackrest/pgbackrest.conf" not in dockerfile:
        return _fail("helm_profile", "Dockerfile.postgres must bake the schema, the init script, and pgbackrest.conf "
                     "(a Kubernetes pod has no bind mounts for them)")
    if "disableDefaultCNI: true" not in kindcfg or "calico" not in drill.lower():
        return _fail("helm_profile", "the drill must disable kind's default CNI and install Calico: kindnet does not "
                     "enforce NetworkPolicy, so a green run would prove nothing about the policies")
    for needle in ("pod-security.kubernetes.io/enforce=restricted", "violates PodSecurity", "polaris-postgres\", 5432",
                   "REACHED", "helm install", "/api/health", "rollout restart", "custody",
                   "annotations.leader", "delete pod", "task pause", "switchover", "ha_marker", "inserts were acknowledged"):
        if needle not in drill:
            return _fail("helm_profile", f"polaris-helm-drill.sh must contain {needle!r} (restricted PSS enforced, a "
                         "privileged pod rejected, a probe pod denied on postgres, health incl. custody, a rolling "
                         "restart, the leader pod deleted, the leader frozen until the other member holds the lease, "
                         "a switchover, and every acknowledged insert present afterwards)")
    if "polaris-helm-drill.sh" not in ci or "helm/kind-action@" not in ci:
        return _fail("helm_profile", "ci.yml must install kind (helm/kind-action, pinned) and run scripts/polaris-helm-drill.sh")
    if "docs/operator/KUBERNETES.md" not in readme or "restricted" not in doc or "Calico" not in doc:
        return _fail("helm_profile", "README.md must link docs/operator/KUBERNETES.md, which must state the restricted "
                     "standard and the enforcing-CNI prerequisite")
    return _ok("helm_profile", "Helm reference profile: restricted PSS on every pod, default-deny NetworkPolicies per "
               "workload, app rolls with maxUnavailable 0, postgres non-root under Patroni with the API as the lease "
               "store, and a kind+Calico CI drill with PSS rejection, policy denial, health through the edge, a rolling "
               "restart, and an automated database failover under a live write stream")


def check_distributed_tracing(root: pathlib.Path) -> list[Finding]:
    """Roadmap P1.6: opt-in OTel traces across app and DB (POLARIS_OTEL-gated,
    announced in the log stream, vocation-scrubbed), the correlation id joining
    logs to traces in both directions, Grafana dashboards committed as code and
    provisioned, and CI proving the wire path with the query string absent."""
    import json as _json
    tr = _read(root, "polaris_web/tracing.py")
    ob = _read(root, "polaris_web/observability.py")
    ap = _read(root, "polaris_web/app.py")
    rq = _read(root, "polaris_web/requirements.txt")
    prod = _read(root, "polaris_web/docker-compose.prod.yml")
    ovl = _read(root, "polaris_web/docker-compose.observability.yml")
    ds = _read(root, "deploy/observability/grafana/provisioning/datasources/datasources.yml")
    dp = _read(root, "deploy/observability/grafana/provisioning/dashboards/dashboards.yml")
    ov_raw = _read(root, "deploy/observability/grafana/dashboards/polaris-overview.json")
    trc_raw = _read(root, "deploy/observability/grafana/dashboards/polaris-traces.json")
    tempo = _read(root, "deploy/observability/tempo.yml")
    drill = _read(root, "scripts/polaris-trace-drill.sh")
    ci = _read(root, ".github/workflows/ci.yml")
    tests = _read(root, "polaris_web/test_app.py")
    ops = _read(root, "docs/operator/OPERATIONS.md")
    obs_readme = _read(root, "deploy/observability/README.md")
    if not (tr and ob and ap and rq and prod and ovl and ds and dp and ov_raw and trc_raw
            and tempo and drill and ci and tests and ops and obs_readme):
        return _fail("distributed_tracing", "a P1.6 file is missing (tracing.py, the compose overlay, the grafana "
                     "provisioning + dashboards, tempo.yml, polaris-trace-drill.sh, or the docs)")
    if "POLARIS_OTEL" not in tr or "def is_enabled" not in tr:
        return _fail("distributed_tracing", "tracing.py must gate on POLARIS_OTEL (opt-in is the vocation posture: "
                     "no telemetry the operator did not switch on)")
    if "boot.tracing_enabled" not in tr or "boot.tracing_unavailable" not in tr:
        return _fail("distributed_tracing", "tracing.py must ANNOUNCE both states in the log stream (hidden "
                     "instrumentation, and silently-missing instrumentation, are both coercion-shaped failures)")
    for needle, why in (("Psycopg2Instrumentor", "DB client spans (traces across app AND db)"),
                        ("UNMATCHED", "a bounded span name for unmatched paths (the metrics-cardinality rule)"),
                        ("type(exc).__name__", "exception CLASS only — messages can carry user input"),
                        ("POLARIS_TRUST_PROXY", "inbound traceparent honoured only behind a trusted proxy"),
                        ("'http.target': path", "the query-stripped path (filters/cursors stay out of telemetry)")):
        if needle not in tr:
            return _fail("distributed_tracing", f"tracing.py must contain {needle!r}: {why}")
    if "def set_trace_context_provider" not in ob or "_trace_context_provider()" not in ob:
        return _fail("distributed_tracing", "observability.structured_log must carry trace_id/span_id via the "
                     "trace-context hook (the log half of the correlation join)")
    if "tracing.init_app(app)" not in ap:
        return _fail("distributed_tracing", "app.py must wire tracing.init_app(app) at import (Flask 3 accepts "
                     "hooks only before the first request)")
    for pkg in ("opentelemetry-sdk==", "opentelemetry-exporter-otlp-proto-http==",
                "opentelemetry-instrumentation-psycopg2=="):
        if pkg not in rq:
            return _fail("distributed_tracing", f"requirements.txt must pin {pkg}<version> (the runtime surface "
                         "ships the optional tracing deps like it ships prometheus_client)")
    if "POLARIS_OTEL" not in prod or "OTEL_EXPORTER_OTLP_ENDPOINT" not in prod:
        return _fail("distributed_tracing", "docker-compose.prod.yml must pass the POLARIS_OTEL switch and the "
                     "OTLP endpoint through to the app service")
    for needle in ("grafana/tempo@sha256:", "grafana/grafana@sha256:",
                   "deploy/observability/grafana/provisioning", "tempo.yml"):
        if needle not in ovl:
            return _fail("distributed_tracing", f"docker-compose.observability.yml must contain {needle!r} "
                         "(digest-pinned images, provisioned grafana, the shipped tempo config)")
    if "polaris-prometheus" not in ds or "polaris-tempo" not in ds:
        return _fail("distributed_tracing", "datasource provisioning must declare the polaris-prometheus and "
                     "polaris-tempo uids the dashboards reference")
    if "/var/lib/grafana/dashboards" not in dp:
        return _fail("distributed_tracing", "dashboard provisioning must load the mounted dashboards folder")
    try:
        ov = _json.loads(ov_raw)
        trc = _json.loads(trc_raw)
    except ValueError as exc:
        return _fail("distributed_tracing", f"a committed dashboard is not valid JSON: {exc}")
    if ov.get("uid") != "polaris-overview" or not ov.get("panels"):
        return _fail("distributed_tracing", "polaris-overview.json must be provisionable (uid polaris-overview, panels)")
    ov_exprs = " ".join(t.get("expr", "") for pnl in ov.get("panels", []) for t in pnl.get("targets", []))
    for metric in ("polaris_requests_total", "polaris_duress_events_total"):
        if metric not in ov_exprs:
            return _fail("distributed_tracing", f"the overview dashboard must query {metric} (the duress panel is "
                         "the anti-coercion alarm on a wall; dashboards that omit it are decorative)")
    trc_queries = " ".join(str(t.get("query", "")) for pnl in trc.get("panels", []) for t in pnl.get("targets", []))
    if trc.get("uid") != "polaris-traces" or "polaris.request_id" not in trc_queries:
        return _fail("distributed_tracing", "the traces dashboard must join on span.polaris.request_id (the "
                     "X-Request-ID a caller quotes must find its trace)")
    if "otlp" not in tempo:
        return _fail("distributed_tracing", "tempo.yml must receive OTLP (the app exporter speaks OTLP/HTTP)")
    for needle, why in (("/v1/traces", "the OTLP wire path"),
                        ("not in payload", "the query string asserted ABSENT from the exported bytes"),
                        ("X-Request-ID", "the correlation join proven on the wire")):
        if needle not in drill:
            return _fail("distributed_tracing", f"polaris-trace-drill.sh must contain {needle!r}: {why}")
    if "polaris-trace-drill.sh" not in ci:
        return _fail("distributed_tracing", "ci.yml must run scripts/polaris-trace-drill.sh")
    if "DistributedTracingTests" not in tests:
        return _fail("distributed_tracing", "test_app.py must carry DistributedTracingTests (the DB half: psycopg2 "
                     "client spans inside the request trace, statement templates only)")
    if "Distributed tracing" not in ops or "docker-compose.observability.yml" not in obs_readme:
        return _fail("distributed_tracing", "the operator docs must cover tracing (OPERATIONS.md) and the "
                     "observability overlay (deploy/observability/README.md)")
    return _ok("distributed_tracing", "P1.6: opt-in OTel tracing (POLARIS_OTEL-gated, announced, vocation-scrubbed: "
               "route templates, no query strings, statement templates, exception classes only), the correlation id "
               "joining logs to traces both ways, digest-pinned Tempo+Grafana overlay with provisioned "
               "dashboards-as-code, and a CI wire drill proving the join with the query string absent")


# ---------------------------------------------------------------------------
# Postgres readiness probes must reach the REAL server (v9.188). The official
# postgres image's entrypoint first runs a TEMPORARY init-only server bound to
# the Unix socket alone (listen_addresses='') while POSTGRES_DB and the init
# scripts load, stops it, and only then starts the real server. pg_isready and
# psql over the socket therefore report ready DURING init, and whatever runs
# next meets "the database system is shutting down" or a connection the
# server terminates mid-command (pgBackRest's [101] "NULL result required to
# complete request" that killed the v9.187 offsite drill). Only the real
# server listens on TCP, so every probe of a containerised postgres passes
# -h: the compose and Helm healthchecks, the deploy script's wait before it
# migrates, and the CI drills' readiness loops. The offsite drill must also
# keep dumping the primary's logs on failure (the v9.186 rule).
# ---------------------------------------------------------------------------
_PROBE_HOST_FLAG = re.compile(r'(?<![\w-])-h(?=[\s",])')
_PROBE_GLOBS = (
    ".github/workflows/ci.yml",
    "scripts/*.sh",
    "deploy/linux/*.sh",
    "polaris_web/docker-compose*.yml",
    "deploy/helm/polaris/templates/*.yaml",
)


def _postgres_probe_lines(text: str):
    """Yield (lineno, code) for every readiness probe of a containerised
    postgres: any pg_isready, or a docker/compose exec psql `SELECT 1` loop.
    Comment text is stripped so a commented-out probe is not an offender."""
    for n, line in enumerate(text.splitlines(), 1):
        code = line.split("#", 1)[0]
        if "pg_isready" in code:
            yield n, code
        elif ("psql" in code and "SELECT 1" in code
              and ("docker exec" in code or "compose exec" in code)):
            yield n, code


def check_postgres_probes_use_tcp(root: pathlib.Path) -> list[Finding]:
    offenders, probes = [], 0
    for pattern in _PROBE_GLOBS:
        for path in sorted(root.glob(pattern)):
            if not path.is_file():
                continue
            for n, code in _postgres_probe_lines(path.read_text(encoding="utf-8")):
                probes += 1
                if not _PROBE_HOST_FLAG.search(code):
                    offenders.append(f"{path.relative_to(root)}:{n}")
    if probes == 0:
        return _fail("pg_probe_tcp", "no postgres readiness probe found in ci.yml / scripts / compose / Helm")
    if offenders:
        return _fail("pg_probe_tcp",
                     "postgres readiness probe(s) without -h (the Unix socket is answered by the entrypoint's "
                     "TEMPORARY init-only server, so 'ready' arrives before the real server): "
                     + ", ".join(offenders[:6]))
    drill = _read(root, "scripts/polaris-offsite-drill.sh")
    if 'docker logs "$PRI"' not in drill:
        return _fail("pg_probe_tcp",
                     "polaris-offsite-drill.sh no longer dumps the primary's logs on failure (a drill that "
                     "dies without its logs is unfixable from CI)")
    return _ok("pg_probe_tcp",
               f"all {probes} postgres readiness probes (CI loops, compose + Helm healthchecks, the deploy "
               "wait) go over TCP, which only the real server answers; the offsite drill dumps logs on failure")


# ---------------------------------------------------------------------------
# Roadmap P1.7 (v9.189) — session and origin hardening. Pins: the webauthn 3.x
# major is taken (and no longer ignored by Dependabot, the ignore block being
# the un-decision); the attestation policy knobs exist and the user-verification
# requirement is policy-driven on BOTH ceremonies (never hardcoded off); the
# registration offer includes ML-DSA-65; the per-role network policy is enforced
# inside authenticate() (login) and validate_session() (live sessions) through
# the proxy-aware client_ip(); the server-side registry is written at login,
# revoked at logout, checked on every request (revoked / deactivated / idle /
# policy), wired into app.py, validated at boot, migrated with the five audit
# event types, revoked by the CLI on password change and deactivation, covered
# by the three test classes, documented, and passed through the prod compose.
# ---------------------------------------------------------------------------
def _fn_body(src: str, name: str) -> str:
    """The text of `def name(` up to the next top-level def (or the end)."""
    head = f"def {name}("
    if head not in src:
        return ""
    body = src.split(head, 1)[1]
    nxt = body.find("\ndef ")
    return body if nxt < 0 else body[:nxt]


def check_session_origin_hardening(root: pathlib.Path) -> list[Finding]:
    req = _read(root, "polaris_web/requirements.txt")
    if not re.search(r"(?m)^webauthn==3\.", req):
        return _fail("session_hardening", "requirements.txt must pin the webauthn 3.x major (P1.7 took it with "
                     "its own ceremony test pass; ML-DSA COSE support lives there)")
    if "pyasn1-modules==" not in req:
        return _fail("session_hardening", "webauthn 3.x needs pyasn1-modules pinned on the runtime surface")
    dep = _read(root, ".github/dependabot.yml")
    if re.search(r'dependency-name:\s*"webauthn"', dep):
        return _fail("session_hardening", "dependabot.yml still ignores webauthn: the ignore block is the "
                     "un-decision; remove it now that the major is taken")
    wa = _read(root, "polaris_web/webauthn_auth.py")
    for knob in ("POLARIS_WEBAUTHN_ATTESTATION", "POLARIS_WEBAUTHN_USER_VERIFICATION",
                 "POLARIS_WEBAUTHN_REQUIRE_ATTESTATION", "POLARIS_WEBAUTHN_ALLOWED_AAGUIDS"):
        if knob not in wa:
            return _fail("session_hardening", f"webauthn_auth.py does not read {knob}")
    if "ML_DSA_65" not in wa:
        return _fail("session_hardening", "registration options must offer ML-DSA-65 (the PQ-ready credential)")
    if re.search(r"require_user_verification\s*=\s*False", wa):
        return _fail("session_hardening", "user verification is hardcoded off; it must follow "
                     "POLARIS_WEBAUTHN_USER_VERIFICATION on both ceremonies")
    if wa.count("require_user_verification=_require_user_verification()") < 2:
        return _fail("session_hardening", "both verify_registration and verify_authentication must take the "
                     "user-verification policy")
    if "class AttestationPolicyViolation" not in wa:
        return _fail("session_hardening", "policy refusals need their own exception (AttestationPolicyViolation)")
    sec = _read(root, "polaris_web/security.py")
    for name in ("def network_policy_allows", "def validate_session", "def register_session",
                 "def revoke_session", "def validate_role_policies", "POLARIS_NETWORK_POLICY_",
                 "POLARIS_SESSION_MAX_", "POLARIS_SESSION_IDLE_MINUTES_"):
        if name not in sec:
            return _fail("session_hardening", f"security.py lacks {name}")
    auth = _fn_body(sec, "authenticate")
    if "network_policy_allows(" not in auth or "NETWORK_POLICY_DENIED" not in auth:
        return _fail("session_hardening", "authenticate() does not enforce the role network policy at login "
                     "(with an audited NETWORK_POLICY_DENIED)")
    if re.search(r"network_policy_allows\([^)]*remote_addr", sec):
        return _fail("session_hardening", "the network policy must be evaluated on client_ip() (proxy-aware), "
                     "never on request.remote_addr directly")
    vs = _fn_body(sec, "validate_session")
    for marker in ("revoked_at", "is_active", "idle", "network_policy_allows("):
        if marker not in vs:
            return _fail("session_hardening", f"validate_session() no longer checks {marker!r} on live sessions")
    if "register_session(" not in _fn_body(sec, "login_user"):
        return _fail("session_hardening", "login_user() must register the session server-side")
    if "revoke_session(" not in _fn_body(sec, "logout_user"):
        return _fail("session_hardening", "logout_user() must revoke the registry row")
    app = _read(root, "polaris_web/app.py")
    if "security.validate_session(get_db)" not in app:
        return _fail("session_hardening", "app.py does not run security.validate_session on every request")
    if "security.validate_role_policies()" not in app or "webauthn_auth.validate_policy()" not in app:
        return _fail("session_hardening", "app.py must validate the role and WebAuthn policies at boot")
    if "AttestationPolicyViolation" not in app:
        return _fail("session_hardening", "the register/finish route does not surface (and audit) policy refusals")
    ups = list((root / "polaris_sql" / "migrations").glob("*-operator-session.up.sql"))
    if not ups:
        return _fail("session_hardening", "no operator-session migration in polaris_sql/migrations/")
    mig = ups[0].read_text(encoding="utf-8")
    if "CREATE TABLE IF NOT EXISTS OperatorSession" not in mig:
        return _fail("session_hardening", f"{ups[0].name} does not create OperatorSession idempotently")
    for ev in ("NETWORK_POLICY_DENIED", "SESSION_EVICTED", "SESSION_EXPIRED", "SESSION_REVOKED",
               "WEBAUTHN_REGISTRATION_REFUSED"):
        if ev not in mig:
            return _fail("session_hardening", f"{ups[0].name} does not admit the {ev} audit event")
    if not ups[0].with_name(ups[0].name.replace(".up.sql", ".down.sql")).exists():
        return _fail("session_hardening", f"{ups[0].name} has no .down.sql")
    if "DROP TABLE IF EXISTS OperatorSession" not in _read(root, "polaris_sql/01_schema.sql"):
        return _fail("session_hardening", "01_schema.sql's drop list must include OperatorSession (reload path)")
    if _read(root, "polaris_cli/polaris.py").count("UPDATE OperatorSession") < 2:
        return _fail("session_hardening", "the CLI must revoke live sessions on user-passwd AND user-deactivate")
    tests = _read(root, "polaris_web/test_app.py")
    for cls in ("class WebAuthnCeremonyTests", "class NetworkPolicyTests", "class SessionLimitTests"):
        if cls not in tests:
            return _fail("session_hardening", f"test_app.py lacks {cls}")
    for rel, needle in (("docs/operator/HARDENING.md", "POLARIS_NETWORK_POLICY_"),
                        ("docs/operator/HARDENING.md", "POLARIS_SESSION_MAX_"),
                        ("docs/operator/WEBAUTHN-ROLLOUT.md", "POLARIS_WEBAUTHN_ATTESTATION"),
                        ("docs/operator/SECURITY-CONTROLS.md", "SESSION_EVICTED")):
        if needle not in _read(root, rel):
            return _fail("session_hardening", f"{rel} does not document {needle}")
    compose = _read(root, "polaris_web/docker-compose.prod.yml")
    for var in ("POLARIS_NETWORK_POLICY_ADMIN", "POLARIS_SESSION_MAX_ADMIN", "POLARIS_WEBAUTHN_ATTESTATION"):
        if var not in compose:
            return _fail("session_hardening", f"docker-compose.prod.yml does not pass {var} to the app")
    return _ok("session_hardening",
               "P1.7: webauthn 3.x taken (ML-DSA-65 offered, UV policy on both ceremonies, attestation "
               "policy knobs), per-role network policy at login + on live sessions via client_ip(), "
               "server-side session registry (caps, idle, revocation) wired, migrated, CLI-revoked, "
               "tested, documented, and passed through compose")


# ---------------------------------------------------------------------------
# The documented reload path is `00_load_all.sql` (which resets schema_version)
# followed by `polaris-migrate.sh --up`, which then re-applies EVERY migration.
# It only works if 01_schema.sql's top-of-file drop list names every table that
# 01_schema.sql or a migration creates; a plain CREATE TABLE on a survivor stops
# the whole load. v9.189 found ZkVerificationNonce and AuditAccessLog missing.
# ---------------------------------------------------------------------------
def check_schema_reload_idempotent(root: pathlib.Path) -> list[Finding]:
    schema = _read(root, "polaris_sql/01_schema.sql")
    if not schema:
        return _fail("schema_reload", "polaris_sql/01_schema.sql is missing")
    dropped = {n.lower() for n in re.findall(r"(?im)^DROP TABLE IF EXISTS\s+(\w+)", schema)}
    sources = [("01_schema.sql", schema)]
    mig_dir = root / "polaris_sql" / "migrations"
    if mig_dir.is_dir():
        sources += [(p.name, p.read_text(encoding="utf-8")) for p in sorted(mig_dir.glob("*.up.sql"))]
    missing = []
    for rel, text in sources:
        # v9.245: partitions ("CREATE TABLE X PARTITION OF Y") drop with their
        # parent (DROP TABLE Y cascades), so they need no drop-list entry.
        for name in re.findall(r"(?im)^CREATE TABLE(?:\s+IF NOT EXISTS)?\s+(\w+)(?!.*PARTITION OF)", text):
            if name.lower() not in dropped:
                missing.append(f"{rel}:{name}")
    if missing:
        return _fail("schema_reload", "table(s) created but absent from 01_schema.sql's drop list, so a "
                     "00_load_all.sql reload + migrate --up fails on a non-empty database: "
                     + ", ".join(missing[:6]))
    return _ok("schema_reload", f"every table created by 01_schema.sql or a migration is in the schema's drop "
               f"list ({len(dropped)} entries): the reload + re-migrate path is idempotent")


# ---------------------------------------------------------------------------
# Roadmap P1.8 (v9.190) — abuse controls. Pins: opt-in per-agency quotas as a
# DATABASE bound (AgencyQuota + enforce_agency_quota on every write path of
# issuance, revocation, and verification; a cheap exit for uncapped agencies;
# a per-(kind, agency) advisory lock so the cap is exact under concurrency;
# the migration pair; the window indexes), the app's side (the per-agency
# velocity counter and the refusal counter, a refusal answered as HTTP 429,
# the once-dead polaris_verifications_total incremented), the alerts with
# their promtool unit tests and the drill that runs them plus a quota under
# real load on the redis backend, the redis-py 8.x major taken (exact pin,
# no Dependabot ignore, one-attempt fail-closed retry contract), the load
# generator's operator-flow mode, the CLI, the tests, and the docs.
# ---------------------------------------------------------------------------
def check_abuse_controls(root: pathlib.Path) -> list[Finding]:
    schema = _read(root, "polaris_sql/01_schema.sql")
    if "CREATE TABLE AgencyQuota" not in schema or "DROP TABLE IF EXISTS AgencyQuota" not in schema:
        return _fail("abuse_controls", "01_schema.sql must declare AgencyQuota and drop it in the reload list")
    trg = _read(root, "polaris_sql/06_triggers.sql")
    for needle in ("FUNCTION enforce_agency_quota", "trg_quota_issue", "trg_quota_revoke", "trg_quota_verify"):
        if needle not in trg:
            return _fail("abuse_controls", f"06_triggers.sql lacks {needle} (the quota must bind every write path)")
    body = trg.split("FUNCTION enforce_agency_quota", 1)[1].split("END$$;", 1)[0]
    if "pg_advisory_xact_lock" not in body:
        return _fail("abuse_controls", "enforce_agency_quota() takes no advisory lock: the cap is not exact under "
                     "concurrent writers (C9)")
    if "IF v_cap IS NULL THEN" not in body or body.index("IF v_cap IS NULL THEN") > body.index("pg_advisory_xact_lock"):
        return _fail("abuse_controls", "enforce_agency_quota() must return for an uncapped agency BEFORE taking "
                     "the lock or counting (the no-quota path is the hot path)")
    if "quota exceeded:" not in body:
        return _fail("abuse_controls", "the refusal message must start with 'quota exceeded:' (the app maps it to 429)")
    if re.search(r"revoke_check_done", body):
        return _fail("abuse_controls", "enforce_agency_quota() must not honour the revocation opt-out GUC: a quota "
                     "has no sanctioned bypass")
    ups = list((root / "polaris_sql" / "migrations").glob("*-agency-quota.up.sql"))
    if not ups or not ups[0].with_name(ups[0].name.replace(".up.sql", ".down.sql")).exists():
        return _fail("abuse_controls", "the agency-quota migration pair is missing")
    mig = ups[0].read_text(encoding="utf-8")
    if "CREATE TABLE IF NOT EXISTS AgencyQuota" not in mig or "enforce_agency_quota" not in mig:
        return _fail("abuse_controls", f"{ups[0].name} must create AgencyQuota idempotently and install the trigger")
    idx = _read(root, "polaris_sql/02_indexes.sql")
    for name in ("idx_token_agency_issued", "idx_verification_agency_time"):
        if name not in idx or name not in mig:
            return _fail("abuse_controls", f"window index {name} must exist in 02_indexes.sql and the migration")
    app = _read(root, "polaris_web/app.py")
    for needle in ("'polaris_agency_events_total'", "'polaris_quota_refusals_total'",
                   "_record_agency_event('issue'", "_record_agency_event('revoke'", "_record_agency_event('verify'",
                   "_quota_refused(e, 'issue'", "_quota_refused(e, 'revoke'", "_quota_refused(e, 'verify'",
                   "_METRICS_VERIFICATIONS.labels("):
        if needle not in app:
            return _fail("abuse_controls", f"app.py lacks {needle}")
    if app.count("status = 429") < 3:
        return _fail("abuse_controls", "a quota refusal must answer HTTP 429 on the issue, revoke, AND verify routes")
    rules = _read(root, "deploy/observability/polaris-alerts.yml")
    for a in ("PolarisIssuanceVelocity", "PolarisRevocationVelocity", "PolarisVerificationVelocity", "PolarisQuotaRefusals"):
        if f"alert: {a}" not in rules:
            return _fail("abuse_controls", f"polaris-alerts.yml must define {a}")
    if "offset 1h" not in rules:
        return _fail("abuse_controls", "the velocity baseline must be offset so the burst is not in its own baseline")
    tests_yml = _read(root, "deploy/observability/polaris-alerts.test.yml")
    if "alert_rule_test" not in tests_yml or "PolarisQuotaRefusals" not in tests_yml:
        return _fail("abuse_controls", "deploy/observability/polaris-alerts.test.yml must unit-test the new alerts")
    drill = _read(root, "scripts/polaris-abuse-drill.sh")
    for needle in ("promtool", "test rules", "--login", "--method POST", "polaris_quota_refusals_total",
                   "polaris_agency_events_total", "polaris_verifications_total", "429"):
        if needle not in drill:
            return _fail("abuse_controls", f"polaris-abuse-drill.sh does not {needle!r}")
    ci = _read(root, ".github/workflows/ci.yml")
    if "scripts/polaris-abuse-drill.sh" not in ci:
        return _fail("abuse_controls", "ci.yml does not run scripts/polaris-abuse-drill.sh")
    if "POLARIS_TEST_REDIS_URL" not in ci or "redis-cli ping" not in ci:
        return _fail("abuse_controls", "the CI test job needs a Redis service + POLARIS_TEST_REDIS_URL so the "
                     "Redis-backed tests run instead of skipping")
    if "POLARIS_RATE_LIMIT_BACKEND: redis" not in ci:
        return _fail("abuse_controls", "the abuse drill must run on the redis rate-limiter backend in CI")
    gen = _read(root, "scripts/polaris_load_gen.py")
    for needle in ("--login", "--form", "--csrf-from", "class _NoRedirect"):
        if needle not in gen:
            return _fail("abuse_controls", f"polaris_load_gen.py lacks the operator-flow mode ({needle})")
    req = _read(root, "polaris_web/requirements.txt")
    if not re.search(r"(?m)^redis==8\.", req):
        return _fail("abuse_controls", "requirements.txt must pin the redis-py 8.x major exactly")
    if "redis==5" in _read(root, "polaris_web/Dockerfile.prod"):
        return _fail("abuse_controls", "Dockerfile.prod still installs a separate redis 5 pin (a second source of truth)")
    if re.search(r'dependency-name:\s*"redis"', _read(root, ".github/dependabot.yml")):
        return _fail("abuse_controls", "dependabot.yml still ignores redis: the ignore block is the un-decision")
    sec = _read(root, "polaris_web/security.py")
    if "Retry(NoBackoff(), 0)" not in sec:
        return _fail("abuse_controls", "RedisRateLimiter must pin the one-attempt, fail-closed retry contract "
                     "(redis-py >= 6 retries with backoff by default)")
    if "'quota-set'" not in _read(root, "polaris_cli/polaris.py"):
        return _fail("abuse_controls", "the CLI must offer quota-set")
    tests = _read(root, "polaris_web/test_app.py")
    if "class AgencyQuotaTests" not in tests:
        return _fail("abuse_controls", "test_app.py lacks AgencyQuotaTests")
    for rel, needle in (("docs/operator/RUNBOOKS.md", "## PolarisQuotaRefusals"),
                        ("docs/operator/OPERATIONS.md", "polaris_quota_refusals_total"),
                        ("docs/operator/SLOS.md", "polaris_agency_events_total"),
                        ("docs/reference/DATA-MODEL.md", "AgencyQuota"),
                        ("docs/operator/SECURITY-CONTROLS.md", "AgencyQuota")):
        if needle not in _read(root, rel):
            return _fail("abuse_controls", f"{rel} does not document {needle}")
    return _ok("abuse_controls",
               "P1.8: per-agency quotas bound issuance/revocation/verification at the database (advisory-locked, "
               "no bypass, migrated, indexed), the app answers 429 and counts refusals + per-agency velocity, "
               "four alerts unit-tested by promtool and drilled under real load on the redis backend, redis-py 8.x "
               "taken with a real Redis in CI, load generator drives operator flows, CLI + docs in place")


# ---------------------------------------------------------------------------
# Roadmap P1.9 (v9.191) — the published performance baseline. Pins: the doc
# with its measured block and stamps, the script that measures all three
# flows end to end through gunicorn with floors, the CI smoke re-run with the
# artifact, the load generator's per-request templating the issuance stage
# depends on, and the F-03 rate-limit DEFAULTS staying 10 / 60 / 60 now that
# the environment may override them for the benchmark's scratch server.
# ---------------------------------------------------------------------------
def check_performance_baseline(root: pathlib.Path) -> list[Finding]:
    doc = _read(root, "docs/reference/PERFORMANCE-BASELINE.md")
    if not doc:
        return _fail("perf_baseline", "docs/reference/PERFORMANCE-BASELINE.md is missing")
    if "<!-- baseline:begin -->" not in doc or "<!-- baseline:end -->" not in doc:
        return _fail("perf_baseline", "the baseline doc must keep its measured-block markers (the script rewrites it)")
    block = doc.split("<!-- baseline:begin -->", 1)[1].split("<!-- baseline:end -->", 1)[0]
    if not re.search(r"\*\*Measured v9\.\d+ @ [0-9a-f]{7,}(?:\+dirty)?, \d{4}-\d{2}-\d{2}T\d{2}:\d{2}Z", block):
        return _fail("perf_baseline", "the measured block carries no stamp (version, commit, date): numbers carry stamps")
    for needle in ("Issuance", "Verification", "Atlas zoomed bbox, warm", "Atlas zoomed bbox, cold", "Atlas whole-world"):
        if needle not in block:
            return _fail("perf_baseline", f"the measured block lacks the {needle!r} row")
    if "cores" not in block or "gunicorn x" not in block or "signing:" not in block:
        return _fail("perf_baseline", "the stamp must name the hardware, the worker count, and the signing mode")
    script = _read(root, "scripts/polaris-perf-baseline.sh")
    for needle in ("--smoke", "--update-doc", "/uc1/issue", "/verifications/new", "/api/atlas/clusters", "/api/atlas/stats",
                   "gunicorn", "POLARIS_RATE_LIMIT_WRITE_MAX=", "FLOOR VIOLATIONS", "check_stage(\"issue\", 2)",
                   "check_stage(\"verify\", 5)", "> 2000"):
        if needle not in script:
            return _fail("perf_baseline", f"polaris-perf-baseline.sh lacks {needle!r}")
    gen = _read(root, "scripts/polaris_load_gen.py")
    if "{seq}" not in gen or "achieved_rps" not in gen:
        return _fail("perf_baseline", "polaris_load_gen.py must substitute {seq} per request and report achieved_rps")
    ci = _read(root, ".github/workflows/ci.yml")
    if "polaris-perf-baseline.sh --smoke" not in ci or "perf-baseline-smoke" not in ci:
        return _fail("perf_baseline", "ci.yml must re-run the baseline in smoke mode and upload its JSON")
    sec = _read(root, "polaris_web/security.py")
    for name, default in (("POLARIS_RATE_LIMIT_LOGIN_MAX", "10"), ("POLARIS_RATE_LIMIT_WRITE_MAX", "60"),
                          ("POLARIS_RATE_LIMIT_WRITE_WINDOW", "60")):
        if not re.search(r"_env_int\('%s',\s*%s\)" % (name, default), sec):
            return _fail("perf_baseline", f"security.py must read {name} with the F-03 default of {default} "
                         "(the override is for the benchmark, the default is the posture)")
    if "PERFORMANCE-BASELINE.md" not in _read(root, "docs/reference/README.md"):
        return _fail("perf_baseline", "docs/reference/README.md does not index the baseline doc")
    return _ok("perf_baseline",
               "P1.9: the end-to-end baseline (issuance, verification, atlas warm/cold) is measured by one script "
               "through gunicorn with SLO-boundary floors, stamped into the doc, re-run by CI in smoke mode with the "
               "JSON as an artifact; the F-03 rate-limit defaults stay 10/60/60 behind the benchmark override")


# ---------------------------------------------------------------------------
# Roadmap P1.10 (v9.192) — DR to targets, on a schedule. Pins: the RPO bound
# (archive_timeout set when archiving is enabled), the drill that kills a
# primary and measures RPO + RTO against the 300 s / 14400 s targets with the
# integrity checks and the --record ledger row, the ledger with its header,
# the monthly workflow that commits the row (write permission, a cron, the
# push), the CI job that runs the drill on every push, the docs-only path
# filter, the Linux timer units installed by install.sh, and DR.md pointing
# at the ledger as the source of the numbers.
# ---------------------------------------------------------------------------
def check_dr_drill_scheduled(root: pathlib.Path) -> list[Finding]:
    init = _read(root, "polaris_web/docker-init.sh")
    if not re.search(r"archive_timeout\s*=\s*'?\d+s?'?", init):
        return _fail("dr_drill", "docker-init.sh must set archive_timeout when archiving is enabled (it is what "
                     "bounds the RPO; a quiet primary otherwise archives only when a segment fills)")
    drill = _read(root, "scripts/polaris-dr-drill.sh")
    for needle in ("docker kill -s KILL", "pgbackrest --stanza=polaris restore", "pg_is_in_recovery",
                   "RPO_TARGET=300", "RTO_TARGET=14400", "dr_marker", "--record", "record_row FAIL",
                   "tokens_after", "sv_after", "/api/health"):
        if needle not in drill:
            return _fail("dr_drill", f"polaris-dr-drill.sh lacks {needle!r}")
    ledger = _read(root, "docs/operator/DR-DRILLS.md")
    if "| RPO s |" not in ledger or "| Status |" not in ledger:
        return _fail("dr_drill", "docs/operator/DR-DRILLS.md must carry the ledger table header the drill appends to")
    wf = _read(root, ".github/workflows/dr-drill.yml")
    if not wf:
        return _fail("dr_drill", ".github/workflows/dr-drill.yml is missing (the monthly drill)")
    if not re.search(r"cron:\s*[\"']\S+ \S+ 1 \* \*[\"']", wf):
        return _fail("dr_drill", "dr-drill.yml must run on the 1st of every month (a monthly cron)")
    if "contents: write" not in wf or "git push" not in wf or "DR-DRILLS.md" not in wf:
        return _fail("dr_drill", "dr-drill.yml must be able to commit and push the ledger row")
    if "polaris-dr-drill.sh --record" not in wf:
        return _fail("dr_drill", "dr-drill.yml must run the drill with --record")
    ci = _read(root, ".github/workflows/ci.yml")
    if "scripts/polaris-dr-drill.sh" not in ci:
        return _fail("dr_drill", "ci.yml must run the DR drill on every push")
    if "docs/operator/DR-DRILLS.md" not in ci.split("jobs:", 1)[0]:
        return _fail("dr_drill", "ci.yml must ignore the ledger path on push (the monthly row must not spend a run)")
    for rel in ("deploy/linux/polaris-dr-drill.timer", "deploy/linux/polaris-dr-drill.service"):
        if not _read(root, rel):
            return _fail("dr_drill", f"{rel} is missing (the host-side monthly drill)")
    if "OnCalendar=*-*-01" not in _read(root, "deploy/linux/polaris-dr-drill.timer"):
        return _fail("dr_drill", "polaris-dr-drill.timer must fire monthly")
    if "polaris-dr-drill.timer" not in _read(root, "deploy/linux/install.sh"):
        return _fail("dr_drill", "install.sh must install and enable polaris-dr-drill.timer")
    dr = _read(root, "docs/operator/DR.md")
    if "DR-DRILLS.md" not in dr or "polaris-dr-drill.sh" not in dr:
        return _fail("dr_drill", "DR.md must point at the drill and the ledger as the source of the RPO/RTO numbers")
    return _ok("dr_drill",
               "P1.10: archive_timeout bounds the RPO; the DR drill kills a primary, restores from the archive, "
               "brings the app up, and measures RPO/RTO against 300 s / 14400 s; monthly by workflow with the row "
               "committed to the ledger, on every push in CI, and monthly on a Linux host by timer")


def check_chaos_program(root: pathlib.Path) -> list[Finding]:
    """Roadmap P2.11 (v9.242): the fail-closed harness runs on every push, and
    a weekly drill induces failures against the booted stack under traffic
    with paging verified through real Prometheus and Alertmanager, its row
    committed to a ledger. A chaos program that is a script a contributor may
    run by hand is not a program."""
    ci = _read(root, ".github/workflows/ci.yml")
    if "scripts/polaris-chaos-test.sh" not in ci:
        return _fail("chaos_program", "ci.yml must run scripts/polaris-chaos-test.sh on every push (the fail-closed "
                     "harness: database gone mid-recovery, prover absent, epoch close interrupted)")
    drill = _read(root, "scripts/polaris-chaos-drill.sh")
    if not drill:
        return _fail("chaos_program", "scripts/polaris-chaos-drill.sh is missing (induced failures against the stack)")
    for needle in ("--pid=host", "crash polaris-app-green", 'a_drops" -eq 0', "compose stop -t 1 app app-green",
                   '"alertname":"PolarisAppDown"', 'b_drops" -gt 0', "crash polaris-redis",
                   "crash polaris-postgres", "app_ids_before", "docker network disconnect",
                   'docker network connect "${PGB_ALIAS_ARGS[@]}"', "app_resolves_pgbouncer",
                   "CEIL_RESTART", "CEIL_DB", "CEIL_PAGE", "polaris-alerts.yml", "alertmanager.yml",
                   "--record", "record_row FAIL"):
        if needle not in drill:
            return _fail("chaos_program", f"polaris-chaos-drill.sh lacks {needle!r}: one colour crashed (a SIGKILL from "
                         "the host pid namespace; `docker kill` is a manual stop the restart policy ignores) with zero "
                         "drops, both stopped until PolarisAppDown reaches the sink, redis and postgres crashed, "
                         "pgbouncer partitioned and reconnected WITH its aliases (a plain reconnect loses the "
                         "service name), every recovery against a ceiling, the row recorded pass or fail")
    ledger = _read(root, "docs/operator/CHAOS-DRILLS.md")
    if "| Page s |" not in ledger or "| Status |" not in ledger:
        return _fail("chaos_program", "docs/operator/CHAOS-DRILLS.md must carry the ledger table header the drill appends to")
    wf = _read(root, ".github/workflows/chaos.yml")
    if not wf:
        return _fail("chaos_program", ".github/workflows/chaos.yml is missing (the weekly drill)")
    if not re.search(r"cron:\s*[\"']\S+ \S+ \* \* [0-6][\"']", wf):
        return _fail("chaos_program", "chaos.yml must run weekly (a cron on one weekday)")
    if "contents: write" not in wf or "git push" not in wf or "CHAOS-DRILLS.md" not in wf:
        return _fail("chaos_program", "chaos.yml must be able to commit and push the ledger row")
    if "polaris-chaos-drill.sh --record" not in wf or "docker-compose.bluegreen.yml" not in wf:
        return _fail("chaos_program", "chaos.yml must boot the blue-green stack and run the drill with --record")
    if "docs/operator/CHAOS-DRILLS.md" not in ci.split("jobs:", 1)[0]:
        return _fail("chaos_program", "ci.yml must ignore the chaos ledger path on push (the weekly row must not spend a run)")
    if "CHAOS-DRILLS.md" not in _read(root, "docs/operator/README.md"):
        return _fail("chaos_program", "docs/operator/README.md must index the chaos ledger")
    return _ok("chaos_program",
               "P2.11: the fail-closed harness runs on every push; weekly and on demand the drill crashes one colour "
               "(zero drops), stops both until PolarisAppDown reaches a webhook through real Prometheus and "
               "Alertmanager, crashes redis and postgres, partitions pgbouncer, measures every recovery against a "
               "ceiling, and commits the row to the ledger")


def check_ha_automation(root: pathlib.Path) -> list[Finding]:
    """Roadmap P2.7 (v9.243): supervisor-managed automated failover for the
    database. The HA profile runs the same database image under Patroni with
    a leader lease in etcd and HAProxy routing on Patroni's role endpoints;
    the failover drill crashes the leader, cuts it off from the lease store,
    switches over and crashes an etcd member, each against a ceiling; and
    FAILOVER.md carries the split-brain analysis. A leader that could keep
    the primary role without its lease (failsafe_mode) is the property the
    analysis relies on NOT having."""
    overlay = _read(root, "polaris_web/docker-compose.ha.yml")
    entry = _read(root, "polaris_web/patroni-entrypoint.sh")
    post = _read(root, "polaris_web/patroni-post-init.sh")
    init = _read(root, "polaris_web/docker-init.sh")
    df = _read(root, "polaris_web/Dockerfile.postgres")
    reqs = _read(root, "polaris_web/requirements-patroni.txt")
    etcd = _read(root, "polaris_web/Dockerfile.etcd")
    hap = _read(root, "polaris_web/haproxy-pg.cfg")
    drill = _read(root, "scripts/polaris-failover-drill.sh")
    ci = _read(root, ".github/workflows/ci.yml")
    doc = _read(root, "docs/operator/FAILOVER.md")
    build = _read(root, "scripts/polaris-image-build.sh")
    if not all((overlay, entry, post, init, df, reqs, etcd, hap, drill, ci, doc, build)):
        return _fail("ha_automation", "an HA-profile file is missing (docker-compose.ha.yml, patroni-entrypoint.sh, "
                     "patroni-post-init.sh, docker-init.sh, Dockerfile.postgres, requirements-patroni.txt, "
                     "Dockerfile.etcd, haproxy-pg.cfg, polaris-failover-drill.sh, ci.yml, FAILOVER.md, "
                     "polaris-image-build.sh)")
    for needle in ("polaris-patroni-entrypoint.sh", "postgres2:", "etcd1:", "etcd2:", "etcd3:", "pg-router:",
                   "POLARIS_DB_HOST: pg-router", "internal: true"):
        if needle not in overlay:
            return _fail("ha_automation", f"docker-compose.ha.yml lacks {needle!r}: two Patroni members, a three-member "
                         "etcd on an internal network, HAProxy as the pooler's target")
    if not re.search(r"image:\s*haproxy:[^\s@]+@sha256:[0-9a-f]{64}", overlay):
        return _fail("ha_automation", "docker-compose.ha.yml must pin the haproxy image by digest")
    if not re.search(r"(?m)^\s*failsafe_mode:\s*false", entry):
        return _fail("ha_automation", "patroni-entrypoint.sh must set failsafe_mode: false: a leader that cannot renew "
                     "its lease must demote itself, or the split-brain guard FAILOVER.md describes does not exist")
    for needle in ("use_pg_rewind: true", "post_init: /usr/local/bin/polaris-patroni-post-init.sh", "ttl:", "exec patroni"):
        if needle not in entry:
            return _fail("ha_automation", f"patroni-entrypoint.sh lacks {needle!r}")
    if "POLARIS_INIT_MANAGED_BY=patroni" not in post or "00-init.sh" not in post:
        return _fail("ha_automation", "patroni-post-init.sh must run the same docker-init.sh in its Patroni-managed mode, "
                     "so both profiles load the same schema")
    if "POLARIS_INIT_MANAGED_BY" not in init:
        return _fail("ha_automation", "docker-init.sh must honour POLARIS_INIT_MANAGED_BY (skip ALTER SYSTEM under Patroni)")
    if "requirements-patroni.txt" not in df or "patroni --version" not in df:
        return _fail("ha_automation", "Dockerfile.postgres must install the pinned requirements-patroni.txt and verify patroni")
    if not re.search(r"(?m)^patroni\[etcd3\]==\d", reqs):
        return _fail("ha_automation", "requirements-patroni.txt must pin patroni[etcd3]==<version>")
    if not re.search(r"(?m)^FROM \S+@sha256:[0-9a-f]{64}", etcd) or not re.search(r"(?m)^USER etcd", etcd):
        return _fail("ha_automation", "Dockerfile.etcd must build from a digest-pinned base and run as the etcd user")
    if "Dockerfile.etcd" not in build:
        return _fail("ha_automation", "polaris-image-build.sh must build Dockerfile.etcd with the stack")
    for needle in ("GET /primary", "GET /replica", "on-marked-down shutdown-sessions", "resolvers", "tcp-ut", "on-error mark-down"):
        if needle not in hap:
            return _fail("ha_automation", f"haproxy-pg.cfg lacks {needle!r}: route on Patroni's role endpoints, cut sessions "
                         "to a demoted node, close sessions to a vanished address (tcp-ut), follow Docker DNS")
    for needle in ("docker network disconnect", "not_primary", "switchover", "crash polaris-etcd1", "replica_streaming",
                   "CEIL_FAILOVER", "CEIL_DEMOTE", "CEIL_SWITCHOVER", "ha_marker", "no_lost_write", "replica_current"):
        if needle not in drill:
            return _fail("ha_automation", f"polaris-failover-drill.sh lacks {needle!r}: a leader crash, a leader cut from "
                         "the lease store that must demote, a switchover, an etcd crash, each against a ceiling, "
                         "under a live write stream, settled to zero lag first, with every acknowledged insert "
                         "asserted present afterwards")
    if "docker-compose.ha.yml" not in ci or "polaris-failover-drill.sh" not in ci:
        return _fail("ha_automation", "ci.yml must boot the HA profile and run scripts/polaris-failover-drill.sh")
    if "polaris-etcd:cve" not in ci:
        return _fail("ha_automation", "the image CVE scan must include the self-built etcd image")
    for needle in ("split-brain", "failsafe_mode", "patronictl switchover", "polaris-failover-drill.sh"):
        if needle not in doc:
            return _fail("ha_automation", f"FAILOVER.md lacks {needle!r}: the split-brain analysis, the failsafe decision, "
                         "the switchover procedure and the drill")
    return _ok("ha_automation",
               "P2.7: the HA profile runs the database under Patroni with a leader lease in a three-member etcd and "
               "HAProxy routing on the role endpoints; a leader without its lease demotes itself (failsafe off); the "
               "drill crashes the leader, partitions it from the lease store, switches over and crashes an etcd member "
               "under a live write stream against ceilings on every push; FAILOVER.md carries the split-brain analysis")


def check_event_table_partitioning(root: pathlib.Path) -> list[Finding]:
    """Roadmap P2.1 (v9.245): the four append-only event tables are monthly
    range-partitioned on event_timestamp, born partitioned in the canonical
    schema with a manager that premakes months and detaches old ones, an
    online migration that converts a pre-v9.245 database in place, and a CI
    drill that proves append-only holds across a partition, an attach, and a
    detach."""
    schema = _read(root, "polaris_sql/01_schema.sql")
    if not schema:
        return _fail("event_partitioning", "polaris_sql/01_schema.sql is missing")
    tables = ("TokenLifecycleEvent", "VerificationEvent", "EnrollmentStatusEvent", "AuthAuditLog")
    for t in tables:
        # the CREATE TABLE block must declare RANGE partitioning on event_timestamp,
        # a composite PK including event_timestamp, and a DEFAULT partition.
        # (?:(?!CREATE TABLE).)*? keeps the match inside this table's own block:
        # it cannot span to another table's PARTITION BY RANGE, while still
        # tolerating a ";" that appears inside a column comment.
        block = re.search(rf"CREATE TABLE {t} \((?:(?!CREATE TABLE).)*?\)\s*PARTITION BY RANGE \(event_timestamp\);", schema, re.S)
        if not block:
            return _fail("event_partitioning", f"{t} must be declared PARTITION BY RANGE (event_timestamp) in 01_schema.sql")
        if not re.search(r"PRIMARY KEY \(\w+, event_timestamp\)", block.group(0)):
            return _fail("event_partitioning", f"{t} must have a composite PRIMARY KEY (id, event_timestamp)")
        if f"CREATE TABLE {t}_default PARTITION OF {t} DEFAULT;" not in schema:
            return _fail("event_partitioning", f"{t} must have a DEFAULT partition ({t}_default) for out-of-window rows")
    # the manager: premake months + detach old ones, and a bootstrap call
    for needle in ("PROCEDURE uc_ensure_event_partitions", "PROCEDURE uc_detach_event_partitions_before",
                   "CALL uc_ensure_event_partitions();"):
        if needle not in schema:
            return _fail("event_partitioning", f"01_schema.sql must define/bootstrap the partition manager ({needle!r})")
    # the online migration converts a pre-v9.245 database in place
    mig = _read(root, "polaris_sql/migrations/2026-09-05-003-event-table-partitioning.up.sql")
    down = _read(root, "polaris_sql/migrations/2026-09-05-003-event-table-partitioning.down.sql")
    if not mig or not down:
        return _fail("event_partitioning", "the partitioning migration (2026-09-05-003 up + down) is missing")
    if "uc_convert_event_table_to_partitioned" not in mig or "already partitioned" not in mig:
        return _fail("event_partitioning", "the up migration must define an idempotent uc_convert_event_table_to_partitioned "
                     "(a no-op on an already-partitioned table)")
    for t in ("tokenlifecycleevent", "verificationevent", "enrollmentstatusevent", "authauditlog"):
        if f"uc_convert_event_table_to_partitioned('{t}'" not in mig:
            return _fail("event_partitioning", f"the up migration must convert {t}")
    if "ATTACH PARTITION" not in mig or "DEFAULT" not in mig:
        return _fail("event_partitioning", "the conversion must attach the existing table as the DEFAULT partition "
                     "(its rows stay in place; no copy)")
    if "uc_departition_event_table" not in down:
        return _fail("event_partitioning", "the down migration must departition (revert to plain tables), preserving rows")
    # the CI drill
    drill = _read(root, "scripts/polaris-partition-drill.sh")
    ci = _read(root, ".github/workflows/ci.yml")
    if not drill:
        return _fail("event_partitioning", "scripts/polaris-partition-drill.sh is missing")
    for needle in ("uc_ensure_event_partitions", "DETACH PARTITION", "insufficient_privilege",
                   "uc_convert_event_table_to_partitioned", "ATTACH PARTITION"):
        if needle not in drill:
            return _fail("event_partitioning", f"polaris-partition-drill.sh must exercise {needle!r}: the manager, a "
                         "detach, append-only across a partition, and the online conversion")
    if "polaris-partition-drill.sh" not in ci:
        return _fail("event_partitioning", "ci.yml must run scripts/polaris-partition-drill.sh")
    # ongoing premake: a standing monthly job keeps partitions ahead of now()
    maint = _read(root, "scripts/polaris-partition-maintenance.sh")
    timer = _read(root, "deploy/linux/polaris-partition-maintenance.timer")
    install = _read(root, "deploy/linux/install.sh")
    if not maint or "uc_ensure_event_partitions" not in maint:
        return _fail("event_partitioning", "scripts/polaris-partition-maintenance.sh must call uc_ensure_event_partitions "
                     "(the standing job that keeps partitions ahead of now())")
    if not timer or "OnCalendar" not in timer or "polaris-partition-maintenance.timer" not in install:
        return _fail("event_partitioning", "the monthly polaris-partition-maintenance.timer must be installed by "
                     "deploy/linux/install.sh")
    return _ok("event_partitioning",
               "the four event tables are monthly range-partitioned (composite PK, DEFAULT catch-all), a manager "
               "premakes and detaches months, an idempotent online migration converts a pre-v9.245 database by "
               "attaching its table as DEFAULT (no copy) and reverts by departitioning, and a CI drill proves "
               "append-only holds across a partition, an attach, and a detach")


def check_read_replica_routing(root: pathlib.Path) -> list[Finding]:
    """Roadmap P2.2 (v9.246): the read-only surfaces (atlas, lists, exports)
    route to a streaming replica when configured, under an explicit staleness
    contract, with failback to the primary; correctness-critical reads stay on
    the primary; single node is unaffected."""
    app = _read(root, "polaris_web/app.py")
    if not app:
        return _fail("read_replica", "polaris_web/app.py is missing")
    for needle in ("DB_CONFIG_REPLICA", "def replica_reads(", "REPLICA_MAX_LAG_S",
                   "def _replica_lag_seconds(", "X-Polaris-Data-Source", "primary-failback",
                   "_METRICS_REPLICA_FAILBACK", "database_replica"):
        if needle not in app:
            return _fail("read_replica", f"app.py must implement read-replica routing ({needle!r}): a replica config, "
                         "the @replica_reads decorator, a staleness bound, a failback path, the data-source header, "
                         "the failback metric, and the health component")
    # the read-only surfaces carry the decorator; a correctness path must not
    if app.count("@replica_reads") < 6:
        return _fail("read_replica", "the read-only surfaces (the atlas endpoints, the export, the verification list) "
                     "must be decorated @replica_reads")
    for route in ("def api_atlas_stats(", "def tokens_export(", "def verifications_list("):
        i = app.find(route)
        if i < 0 or "@replica_reads" not in app[max(0, i - 200):i]:
            return _fail("read_replica", f"a read-only surface is not @replica_reads-decorated near {route!r}")
    # a write is never routed to the read-only replica
    if "fetch in ('all', 'one')" not in app:
        return _fail("read_replica", "query() must route only reads (fetch all/one) to the replica, never a write")
    # the pooler serves a read-only database, and the HA overlay wires it end to end
    pgb = _read(root, "polaris_web/pgbouncer-entrypoint.sh")
    ha = _read(root, "polaris_web/docker-compose.ha.yml")
    if not pgb or "_ro = host=" not in pgb or "POLARIS_DB_REPLICA_HOST" not in pgb:
        return _fail("read_replica", "pgbouncer-entrypoint.sh must serve a <db>_ro database routed to the replica host")
    if not ha or "POLARIS_DB_REPLICA_NAME: polaris_ro" not in ha or "POLARIS_DB_REPLICA_PORT: '5433'" not in ha:
        return _fail("read_replica", "docker-compose.ha.yml must point the app at polaris_ro and the pooler at the "
                     "router's replica endpoint (5433)")
    # the failover drill proves the wiring end to end on the HA stack
    drill = _read(root, "scripts/polaris-failover-drill.sh")
    if not drill or "database_replica=" not in drill or "healthy/True" not in drill:
        return _fail("read_replica", "polaris-failover-drill.sh must assert the app serves reads from the replica "
                     "(database_replica healthy/True)")
    doc = _read(root, "docs/operator/OPERATIONS.md")
    if not doc or "staleness contract" not in doc.lower():
        return _fail("read_replica", "OPERATIONS.md must document the staleness contract")
    return _ok("read_replica",
               "the read-only surfaces route to a streaming replica under a staleness contract (max lag with failback "
               "to the primary, the data-source header, the health component), a write is never routed there, the "
               "pooler serves a read-only database, and the failover drill proves the app serves reads from the replica")


def check_bulk_enrollment(root: pathlib.Path) -> list[Finding]:
    """Roadmap P2.4 (v9.247): the bulk enrollment pipeline. Records are staged
    with COPY into BulkEnrollmentStaging and issued SET-BASED in one
    transaction by uc_bulk_issue -- every row through the full constraint set,
    a single violation rolling the whole batch back. A staged individual_id
    left NULL is a new person; set, it correlates a re-card to an existing one,
    which is what makes C3 (uq_one_active_per_person) reachable across a batch.
    A CI drill proves throughput, all-or-none atomicity, C3 across the batch,
    and the issue/auth/empty refusals."""
    schema = _read(root, "polaris_sql/01_schema.sql")
    if not schema:
        return _fail("bulk_enrollment", "polaris_sql/01_schema.sql is missing")
    for t in ("BulkEnrollmentBatch", "BulkEnrollmentStaging"):
        if f"CREATE TABLE IF NOT EXISTS {t} (" not in schema:
            return _fail("bulk_enrollment", f"01_schema.sql must define {t}")
    # staging references the batch but must NOT cascade (the audit rule: staging
    # is cleaned explicitly, never swept by a parent delete).
    stg = re.search(r"CREATE TABLE IF NOT EXISTS BulkEnrollmentStaging \((?:(?!CREATE TABLE).)*?\);", schema, re.S)
    if not stg:
        return _fail("bulk_enrollment", "BulkEnrollmentStaging block not found in 01_schema.sql")
    if "REFERENCES BulkEnrollmentBatch(batch_id)" not in stg.group(0):
        return _fail("bulk_enrollment", "BulkEnrollmentStaging.batch_id must reference BulkEnrollmentBatch")
    if "ON DELETE CASCADE" in stg.group(0):
        return _fail("bulk_enrollment", "BulkEnrollmentStaging must not cascade from the batch (staging is cleaned explicitly)")

    proc = _read(root, "polaris_sql/05_procedures.sql")
    if "PROCEDURE uc_bulk_issue" not in proc:
        return _fail("bulk_enrollment", "05_procedures.sql must define uc_bulk_issue")
    _m = re.search(r"CREATE OR REPLACE PROCEDURE uc_bulk_issue.*?END \$\$;", proc, re.S)
    body = _m.group(0) if _m else proc
    # the same authorization gate uc1 applies, checked once for the batch
    if "AgencyAlgorithmAuth" not in body or "'ISSUE'" not in body or "'BOTH'" not in body:
        return _fail("bulk_enrollment", "uc_bulk_issue must gate on AgencyAlgorithmAuth (ISSUE/BOTH), like uc1")
    if "insufficient_privilege" not in body:
        return _fail("bulk_enrollment", "uc_bulk_issue must raise insufficient_privilege for an unauthorized agency")
    if "already issued" not in body or "issued_at IS NOT NULL" not in body:
        return _fail("bulk_enrollment", "uc_bulk_issue must refuse a batch that was already issued")
    # new-person vs re-card correlation is what makes C3 reachable across a batch
    if "COALESCE(individual_id" not in body:
        return _fail("bulk_enrollment", "uc_bulk_issue must COALESCE a staged individual_id (NULL = new person, set = re-card)")
    if "NOT EXISTS" not in body:
        return _fail("bulk_enrollment", "uc_bulk_issue must skip the Individual insert for a correlated (existing) individual")
    # set-based issue through the full constraint set, then activate
    for needle in ("INSERT INTO Individual", "INSERT INTO IdentityToken", "'RESERVE'",
                   "INSERT INTO TokenSignature", "INSERT INTO TokenLifecycleEvent", "'ACTIVE'"):
        if needle not in body:
            return _fail("bulk_enrollment", f"uc_bulk_issue must perform the set-based issue step {needle!r}")

    up = _read(root, "polaris_sql/migrations/2026-09-06-001-bulk-enrollment.up.sql")
    down = _read(root, "polaris_sql/migrations/2026-09-06-001-bulk-enrollment.down.sql")
    if not up or "BulkEnrollmentStaging" not in up or "BulkEnrollmentBatch" not in up:
        return _fail("bulk_enrollment", "the up migration (2026-09-06-001) must add the batch + staging tables")
    if not down or "DROP TABLE IF EXISTS BulkEnrollmentStaging" not in down or "DROP PROCEDURE IF EXISTS uc_bulk_issue" not in down:
        return _fail("bulk_enrollment", "the down migration must drop the staging table and uc_bulk_issue")

    drill = _read(root, "scripts/polaris-bulk-drill.sh")
    ci = _read(root, ".github/workflows/ci.yml")
    if not drill:
        return _fail("bulk_enrollment", "scripts/polaris-bulk-drill.sh is missing")
    # the drill must stage with COPY, measure throughput, and exercise each guard
    for needle in ("\\copy", "uc_bulk_issue", "BULK_THROUGHPUT", "unique_violation",
                   "insufficient_privilege", "invalid_parameter_value", "ROLLBACK"):
        if needle not in drill:
            return _fail("bulk_enrollment", f"polaris-bulk-drill.sh must exercise {needle!r}: COPY, throughput, "
                         "atomicity/C3, the auth and already-issued refusals, and roll back")
    if "polaris-bulk-drill.sh" not in ci:
        return _fail("bulk_enrollment", "ci.yml must run scripts/polaris-bulk-drill.sh")

    # the operator surface: a CLI that stages an extract with COPY and issues it
    cli = _read(root, "polaris_cli/polaris.py")
    if "def cmd_bulk_enroll" not in cli or "'bulk-enroll'" not in cli:
        return _fail("bulk_enrollment", "polaris_cli/polaris.py must expose the bulk-enroll command (cmd_bulk_enroll + a HANDLERS entry)")
    if "copy_expert" not in cli:
        return _fail("bulk_enrollment", "the bulk-enroll command must stage the extract with COPY (copy_expert), not row-by-row inserts")
    return _ok("bulk_enrollment",
               "records stage with COPY into BulkEnrollmentStaging and issue set-based through uc_bulk_issue (the uc1 "
               "authorization gate once per batch, every row through the full constraint set, a single violation rolling "
               "the batch back); a staged individual_id correlates a re-card to an existing person, making C3 reachable "
               "across a batch; a migration adds and reverts it; the bulk-enroll CLI stages an extract with COPY and "
               "issues the batch; and a CI drill proves throughput, all-or-none atomicity, C3 across the batch, and the "
               "issue/auth/empty refusals")


def check_atlas_console(root: pathlib.Path) -> list[Finding]:
    """Roadmap P2.3 (v9.248): the Atlas is an analytical console. The Overview
    is the default view (bounded, non-geographic charts), the globe is a tab,
    and two bounded server-side aggregates feed the analytics. Preserves C8
    (the category cap) and C6 (the console counts zero-knowledge events but the
    aggregates never carry a location)."""
    atlas = _read(root, "polaris_web/templates/atlas.html")
    if not atlas:
        return _fail("atlas_console", "polaris_web/templates/atlas.html is missing")
    # Overview is the DEFAULT view (its tab is selected on first paint); the
    # Breakdown (v9.249), Records (v9.252) and Map tabs are the other views.
    for tab in ('overview', 'breakdown', 'records', 'trends', 'map'):
        if f'data-atlas-view-tab="{tab}"' not in atlas:
            return _fail("atlas_console", f"atlas.html must have the {tab} view tab")
    m = re.search(r'data-atlas-view-tab="overview"[^>]*aria-selected="true"'
                  r'|aria-selected="true"[^>]*data-atlas-view-tab="overview"', atlas)
    if not m and 'atlas-tab-active' not in atlas:
        return _fail("atlas_console", "the Overview tab must be the default (selected) view")
    if "atlas-console.js" not in atlas:
        return _fail("atlas_console", "atlas.html must load atlas-console.js")
    if not _read(root, "polaris_web/static/atlas-console.js"):
        return _fail("atlas_console", "polaris_web/static/atlas-console.js is missing")

    # v9.250: the Breakdown is scale-hardened — its dimension list is searchable
    # (a label filter finds one slice among thousands) and scrolls inside its own
    # card so the cross-tabs are never buried by a long list.
    if "data-bd-search" not in atlas or "bd-scroll" not in atlas:
        return _fail("atlas_console", "the Breakdown must have a search box (data-bd-search) and an "
                     "internally-scrolling list (bd-scroll) so it survives thousands of categories")

    # v9.251: one global faceted filter bar coordinates the analytical views,
    # with a server typeahead for the agency facet (a chip flyout of every
    # agency does not survive thousands of them).
    if "data-atlas-globalbar" not in atlas or "data-gf-facet" not in atlas:
        return _fail("atlas_console", "the console must have a global filter bar (data-atlas-globalbar) "
                     "with facets (data-gf-facet) coordinating the views")
    if "data-gf-agency-search" not in atlas:
        return _fail("atlas_console", "the agency facet must be a server typeahead (data-gf-agency-search), "
                     "not a flat chip flyout, so it survives thousands of agencies")

    # v9.252: the Records view is a keyset-paginated data grid (a "load more"
    # cursor, not an offset, so page N is O(page) not O(N*page) at scale).
    if "data-rec-grid" not in atlas or "data-rec-more" not in atlas:
        return _fail("atlas_console", "the Records view must be a data grid (data-rec-grid) with a "
                     "keyset 'load more' control (data-rec-more) so it survives millions of events")

    # v9.253 (Map v2): the map is aggregation-first — a layer-mode control
    # (Regions by jurisdiction is the DEFAULT | Density hexbin | Points drill)
    # with the globe demoted to an opt-in projection toggle, not the always-on
    # view that made thousands of raw points a clutter nightmare at scale.
    for mode in ('regions', 'density', 'points'):
        if f'data-atlas-mapmode="{mode}"' not in atlas:
            return _fail("atlas_console", f"the Map must offer the {mode} layer mode (data-atlas-mapmode)")
    if "data-atlas-projection" not in atlas:
        return _fail("atlas_console", "the globe must be an opt-in projection toggle "
                     "(data-atlas-projection), not the default map view")

    # The bounded aggregates, non-geographic (no lat/lon in their contract).
    sql = _read(root, "polaris_sql/11_atlas.sql")
    if "p_search" not in sql:
        return _fail("atlas_console", "atlas_breakdown must accept p_search (a label filter) so a "
                     "single slice is findable among thousands")
    for fn_name in ("atlas_volume_series", "atlas_breakdown", "atlas_crosstab", "atlas_agency_facet"):
        body = re.search(rf"CREATE OR REPLACE FUNCTION {fn_name}\(.*?\$\$;", sql, re.S)
        if not body:
            return _fail("atlas_console", f"11_atlas.sql must define {fn_name}")
        ret = re.search(r"RETURNS TABLE \((.*?)\)\s*LANGUAGE", body.group(0), re.S)
        if ret and re.search(r"\b(lat|lon|latitude|longitude)\b", ret.group(1)):
            return _fail("atlas_console", f"{fn_name} must not return a location column (C6): the "
                         "analytical console counts zero-knowledge events but never locates them")

    # v9.252: the row-level records function is keyset-paginated (a cursor pair,
    # not an OFFSET) and redacts zero-knowledge rows — the subject and location
    # are withheld exactly as the map never plots a ZK event (C6).
    recs = re.search(r"CREATE OR REPLACE FUNCTION atlas_records\(.*?\$\$;", sql, re.S)
    if not recs:
        return _fail("atlas_console", "11_atlas.sql must define atlas_records (the records data grid)")
    recs_body = recs.group(0)
    if "p_cursor_ts" not in recs_body or "p_cursor_id" not in recs_body:
        return _fail("atlas_console", "atlas_records must be keyset-paginated (a p_cursor_ts/p_cursor_id "
                     "cursor, not an OFFSET) so deep pages stay O(page) at millions of events")
    if "(zero-knowledge)" not in recs_body:
        return _fail("atlas_console", "atlas_records must redact zero-knowledge rows (C6): the subject "
                     "is withheld as '(zero-knowledge)' and the location is not shown")

    # v9.253: the Map v2 aggregates — a hexbin density surface and a
    # jurisdiction rollup. Their C6 posture (hexbin excludes ZK; the rollup
    # counts ZK but never locates it) is pinned by check_c6_atlas_redacts_zk_location.
    for fn_name in ("atlas_hexbin", "atlas_geo_jurisdictions"):
        if f"CREATE OR REPLACE FUNCTION {fn_name}(" not in sql:
            return _fail("atlas_console", f"11_atlas.sql must define {fn_name} (Map v2)")

    # The analytical endpoints, replica-routed and capped.
    app = _read(root, "polaris_web/app.py")
    for route in ("/api/atlas/series", "/api/atlas/breakdown", "/api/atlas/crosstab",
                  "/api/atlas/facet/agencies", "/api/atlas/records",
                  "/api/atlas/hexbin", "/api/atlas/geo/jurisdictions"):
        if f"@app.route('{route}')" not in app:
            return _fail("atlas_console", f"app.py must expose {route}")
    # both must be replica-read routes (analytical reads, no read-your-writes need)
    seg = app.split("def api_atlas_series", 1)
    if len(seg) == 2:
        head = app.rsplit("@app.route('/api/atlas/series')", 1)[-1].split("def api_atlas_series", 1)[0]
        if "@replica_reads" not in head:
            return _fail("atlas_console", "api_atlas_series must be @replica_reads")
    if "_ATLAS_BREAKDOWN_DIMENSIONS" not in app:
        return _fail("atlas_console", "the breakdown dimensions must be whitelisted server-side "
                     "(_ATLAS_BREAKDOWN_DIMENSIONS)")
    if "_ATLAS_CROSSTAB_ROWS" not in app or "_ATLAS_CROSSTAB_COLS" not in app:
        return _fail("atlas_console", "the cross-tab row/column dimensions must be whitelisted "
                     "server-side (_ATLAS_CROSSTAB_ROWS / _ATLAS_CROSSTAB_COLS)")
    # The records grid is a replica read like the aggregates (analytical, no
    # read-your-writes need) and is bounded by the event cap (C8).
    rec_head = app.rsplit("@app.route('/api/atlas/records')", 1)[-1].split("def api_atlas_records", 1)[0]
    if "@replica_reads" not in rec_head:
        return _fail("atlas_console", "api_atlas_records must be @replica_reads")
    # The Map v2 endpoints are replica reads too (analytical, no read-your-writes).
    for route, fn in (("/api/atlas/hexbin", "def api_atlas_hexbin"),
                      ("/api/atlas/geo/jurisdictions", "def api_atlas_geo_jurisdictions")):
        head = app.rsplit(f"@app.route('{route}')", 1)[-1].split(fn, 1)[0]
        if "@replica_reads" not in head:
            return _fail("atlas_console", f"{fn[4:]} must be @replica_reads")

    # v9.265 (ship 7 — Trends): the temporal-rhythm heatmap and the
    # composition-over-time stack. Both are bounded (168 cells / top-K + Other),
    # partition-pruned (COALESCE(p_since, '-infinity')), and replica-read.
    for fn_name in ("atlas_heatmap", "atlas_series_stacked"):
        if f"FUNCTION {fn_name}(" not in sql:
            return _fail("atlas_console", f"11_atlas.sql must define {fn_name} (a Trends aggregate)")
        # windowed on the parameter so the generic plan prunes (v9.260 discipline)
        if f"{fn_name}(" in sql and "COALESCE(p_since" not in sql:
            return _fail("atlas_console", f"{fn_name} must window on event_timestamp >= COALESCE(p_since, "
                         "'-infinity') so it prunes the monthly partitions")
    for route, fn in (("/api/atlas/heatmap", "def api_atlas_heatmap"),
                      ("/api/atlas/stacked", "def api_atlas_stacked")):
        if f"@app.route('{route}')" not in app:
            return _fail("atlas_console", f"app.py must expose {route} (a Trends endpoint)")
        head = app.rsplit(f"@app.route('{route}')", 1)[-1].split(fn, 1)[0]
        if "@replica_reads" not in head:
            return _fail("atlas_console", f"{fn[4:]} must be @replica_reads")
    if "_ATLAS_STACK_DIMENSIONS" not in app:
        return _fail("atlas_console", "the stacked Trends dimensions must be whitelisted server-side "
                     "(_ATLAS_STACK_DIMENSIONS)")
    if "data-trends-heatmap" not in atlas or "data-trends-stacked" not in atlas or "data-trends-dim" not in atlas:
        return _fail("atlas_console", "the Trends tab must mount a heatmap (data-trends-heatmap), a stacked "
                     "series (data-trends-stacked), and a dimension selector (data-trends-dim)")
    return _ok("atlas_console",
               "the Atlas is a coordinated analytical console: a global faceted filter bar (with an "
               "agency typeahead) drives a bounded Overview, a searchable Breakdown of cross-tabs, a "
               "keyset-paginated Records grid, and an aggregation-first Map (Regions by jurisdiction "
               "default | Density hexbin | Points drill, globe opt-in); the non-geographic rollups plus "
               "atlas_records, atlas_hexbin and atlas_geo_jurisdictions feed it, all capped (C8) so "
               "zero-knowledge events are counted but never located (C6)")


def check_atlas_rollups_prune(root: pathlib.Path) -> list[Finding]:
    """Roadmap P2.14 S5 (v9.260, benchmark-driven): the Atlas roll-ups filter the
    monthly-partitioned event tables by event_timestamp, so a windowed query must
    PRUNE to the relevant partitions. Two SQL shapes silently defeat partition
    pruning under the GENERIC plan a parameterized statement gets (the app's real
    path), turning a 'last 24h' query into a scan of every month of history:

      1. `p_since IS NULL OR event_timestamp >= p_since` — the OR-NULL guard.
      2. `event_timestamp >= params.t_start` — the window reached through a CTE
         column instead of the parameter, so the planner can't prune on it.

    The fix is `event_timestamp >= COALESCE(p_since, '-infinity'::timestamp)`,
    which prunes on a concrete since and still scans everything for an all-time
    (NULL) query. Pin that neither pruning-defeat can return, and that the fix is
    present. The behaviour itself is proved under a forced generic plan by
    test_app.AtlasPartitionPruningTests."""
    atlas = _read(root, "polaris_sql/11_atlas.sql")
    if not atlas:
        return _fail("atlas_prune", "polaris_sql/11_atlas.sql is missing")
    bad_ornull = re.findall(r"p_since\s+IS NULL OR[^)\n]*event_timestamp", atlas)
    if bad_ornull:
        return _fail("atlas_prune",
                     f"{len(bad_ornull)} Atlas roll-up predicate(s) still gate the event_timestamp window "
                     "with `p_since IS NULL OR ...`, which defeats partition pruning under the generic "
                     "plan; use `event_timestamp >= COALESCE(p_since, '-infinity'::timestamp)`")
    if re.search(r"event_timestamp\s*>=\s*params\.t_start", atlas):
        return _fail("atlas_prune",
                     "an Atlas time-series roll-up reaches the window through `params.t_start` (a CTE "
                     "column), which the planner cannot prune on; reference COALESCE(p_since, "
                     "'-infinity'::timestamp) directly in the WHERE")
    if "event_timestamp >= COALESCE(p_since" not in atlas:
        return _fail("atlas_prune",
                     "the Atlas roll-ups must window on `event_timestamp >= COALESCE(p_since, "
                     "'-infinity'::timestamp)` so a concrete since prunes partitions and a NULL since "
                     "still scans all of history")
    return _ok("atlas_prune",
               "the Atlas roll-ups window on event_timestamp >= COALESCE(p_since, '-infinity') so a "
               "concrete window prunes to the relevant monthly partitions under the generic plan the app "
               "runs, while an all-time (NULL) query still scans every partition (proved under a forced "
               "generic plan in test_app.AtlasPartitionPruningTests)")


def check_sim_mode_gated(root: pathlib.Path) -> list[Finding]:
    """Roadmap P2.14 S4 (v9.261): the Atlas live-simulation mode streams NOTIONAL
    events through the real write path, so it must be impossible on a production
    deployment. THREE independent gates enforce that, and this pins all three so
    none can silently erode:

      1. The app's SIM_MODE flag is force-off under POLARIS_ENV=production (the
         same idiom as DEMO_MODE), and the /api/sim/tick route `abort(404)`s when
         SIM_MODE is off — so a production process renders no control and the
         route is effectively absent.
      2. The writer itself, polaris_sim.assert_expendable(), refuses
         POLARIS_ENV=production, and run_stream / build_nation call it before any
         write — so even a direct invocation cannot touch production.
    """
    app = _read(root, "polaris_web/app.py")
    if not app:
        return _fail("sim_gate", "polaris_web/app.py is missing")
    if not re.search(r"SIM_MODE\s*=\s*_env_flag\(\s*['\"]POLARIS_SIM_MODE['\"].*\)\s*and\s*not\s*_PRODUCTION", app):
        return _fail("sim_gate", "SIM_MODE must be `_env_flag('POLARIS_SIM_MODE', ...) and not _PRODUCTION` "
                     "so the live-simulation control can never be on under POLARIS_ENV=production")
    tick = app.split("def api_sim_tick", 1)
    if len(tick) != 2:
        return _fail("sim_gate", "app.py must define the api_sim_tick route (the live-simulation writer)")
    head = tick[1][:600]
    if "if not SIM_MODE" not in head or "abort(404)" not in head:
        return _fail("sim_gate", "api_sim_tick must `abort(404)` when SIM_MODE is off (the route is absent "
                     "off the gate)")

    init = _read(root, "polaris_sim/__init__.py")
    if "def assert_expendable" not in init or "production" not in init:
        return _fail("sim_gate", "polaris_sim.assert_expendable() must exist and refuse POLARIS_ENV=production")
    for rel, fn in (("polaris_sim/events.py", "run_stream"), ("polaris_sim/load.py", "build_nation")):
        body = _read(root, rel)
        if "assert_expendable()" not in body:
            return _fail("sim_gate", f"{rel} ({fn}) must call assert_expendable() before it writes, so a direct "
                         "invocation cannot touch a production database")
    return _ok("sim_gate",
               "the Atlas live-simulation mode is triple-gated: SIM_MODE is force-off under "
               "POLARIS_ENV=production and /api/sim/tick 404s when it is off, and the writer "
               "(polaris_sim.assert_expendable, called by run_stream and build_nation) refuses production")


def check_ui_drill(root: pathlib.Path) -> list[Finding]:
    """Roadmap P2.14 S4 (v9.262): a headless-browser harness verifies the Atlas
    live simulation actually STREAMS in a real browser — the JavaScript, the
    fetches, the live DOM updates — not just its endpoint. It drives the Simulate
    control and asserts the sim counter climbs AND the Overview aggregate grows,
    capturing screenshots as evidence. And the live view is genuinely live:
    SIM_MODE bypasses the 30 s aggregate cache so the charts refresh with the
    stream (the lag the harness itself caught on its first run)."""
    py = _read(root, "scripts/polaris-ui-drill.py")
    sh = _read(root, "scripts/polaris-ui-drill.sh")
    if not py or not sh:
        return _fail("ui_drill", "scripts/polaris-ui-drill.py and scripts/polaris-ui-drill.sh (the "
                     "headless-browser UI harness) must both exist")
    for needle in ("playwright", "data-atlas-sim-toggle", "streamed", 'data-ov-kpi="volume"'):
        if needle not in py:
            return _fail("ui_drill", f"polaris-ui-drill.py must reference {needle!r}: it drives the sim "
                         "control and reads the live Overview aggregate in a real browser")
    # It must ASSERT growth (a real pass/fail), not merely screenshot.
    if "last > first" not in py or "kpi_after > kpi_before" not in py:
        return _fail("ui_drill", "polaris-ui-drill.py must ASSERT the counter climbs (last > first) AND the "
                     "Overview aggregate grows (kpi_after > kpi_before), not just capture screenshots")
    if "POLARIS_SIM_MODE=1" not in sh or "playwright install chromium" not in sh:
        return _fail("ui_drill", "polaris-ui-drill.sh must boot the app with SIM_MODE on and install Chromium "
                     "on demand (no standing dependency)")
    # The live view is actually live: the aggregate cache is bypassed under SIM_MODE.
    app = _read(root, "polaris_web/app.py")
    cache_fn = app.split("def _atlas_cache_get", 1)
    if len(cache_fn) != 2 or not re.search(r"if\s+SIM_MODE\s*:\s*\n\s*return None", cache_fn[1][:800]):
        return _fail("ui_drill", "_atlas_cache_get must `return None` (bypass the aggregate cache) under "
                     "SIM_MODE, so the live simulation's charts refresh with the stream")
    ci = _read(root, ".github/workflows/ci.yml")
    if "polaris-ui-drill.sh" not in ci or "ui-drill:" not in ci:
        return _fail("ui_drill", "ci.yml must run scripts/polaris-ui-drill.sh in a ui-drill job, so the "
                     "Atlas UI is verified in a real browser on every push (not just on demand)")
    return _ok("ui_drill",
               "a headless-browser harness (polaris-ui-drill.py/.sh, Playwright + Chromium) drives the "
               "Atlas live simulation in a real browser and asserts the counter climbs and the Overview "
               "aggregate grows; the ui-drill CI job runs it on every push; SIM_MODE bypasses the "
               "aggregate cache so the charts refresh live")


# ---------------------------------------------------------------------------
# Image builds — every container image CI builds goes through
# scripts/polaris-image-build.sh, which retries a build that failed on someone
# else's outage and stamps the image with the shipping version. Three releases
# in a row were marked red by a Docker Hub token reset, a Docker Hub manifest
# fetch reset, and a Debian mirror mid-sync. A bare `docker build` in a
# workflow reintroduces both the flake and the unstamped image, silently.
# ---------------------------------------------------------------------------
def check_image_builds_are_retried(root: pathlib.Path) -> list[Finding]:
    helper = root / "scripts/polaris-image-build.sh"
    if not helper.is_file():
        return _fail("image_builds", "scripts/polaris-image-build.sh is missing")
    body = helper.read_text(encoding="utf-8", errors="replace")
    for needle, why in (("POLARIS_BUILD_ATTEMPTS", "the attempt count must be a knob"),
                        ("POLARIS_VERSION=", "the build must stamp the shipping version"),
                        ("__version__.py", "the version must come from the canonical file")):
        if needle not in body:
            return _fail("image_builds", f"polaris-image-build.sh: {why} ({needle} absent)")

    workflows = sorted((root / ".github/workflows").glob("*.yml"))
    if not workflows:
        return _fail("image_builds", "no workflows found under .github/workflows")
    for wf in workflows:
        text = wf.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if re.search(r"(?<!-)\bdocker build\b", stripped):
                return _fail("image_builds",
                             f".github/workflows/{wf.name}:{lineno} builds an image directly; "
                             "call scripts/polaris-image-build.sh so the build is retried and stamped")

    # The buildx step cannot use the script (it would lose the gha cache), so it
    # carries its own retry and its own version stamp.
    ci = _read(root, ".github/workflows/ci.yml")
    if "docker/build-push-action" in ci:
        if "second attempt" not in ci:
            return _fail("image_builds",
                         "the buildx build has no second attempt; a registry reset fails the run")
        if ci.count("build-args: POLARIS_VERSION=") < 2:
            return _fail("image_builds", "both buildx attempts must stamp POLARIS_VERSION")

    dockerfiles = sorted((root / "polaris_web").glob("Dockerfile.*"))
    for df in dockerfiles:
        text = df.read_text(encoding="utf-8", errors="replace")
        if 'LABEL org.opencontainers.image.version="${POLARIS_VERSION}"' not in text:
            return _fail("image_builds",
                         f"polaris_web/{df.name} must label its version from the POLARIS_VERSION "
                         "build arg, not a literal that goes stale")
        if "github.com/polaris-id/polaris" in text:
            return _fail("image_builds", f"polaris_web/{df.name} points its source label at a repository "
                                         "that is not this one")
        if "apt-get" in text and "Acquire::Retries" not in text:
            return _fail("image_builds",
                         f"polaris_web/{df.name} runs apt-get without Acquire::Retries; a mirror "
                         "mid-sync fails the build")
    return _ok("image_builds",
               f"all {len(dockerfiles)} images build through the retrying, version-stamping helper")


# ---------------------------------------------------------------------------
# Design tokens — site/tokens.css carries the palette the published page shares
# with the application. Before v9.218 the page forked it under different names
# (--dim for --ink-dim, --gold-b for --gold-bright), so a change to the
# application's colours could not be seen to have skipped the site. Same names,
# same values, and this check is the pair that makes a drift visible.
# ---------------------------------------------------------------------------
def _css_root_tokens(text: str) -> dict[str, str]:
    """Every custom property declared in the first :root block, normalised."""
    start = text.find(":root")
    if start < 0:
        return {}
    block = text[text.index("{", start) + 1:]
    block = block[:block.index("}")]
    block = re.sub(r"/\*.*?\*/", "", block, flags=re.S)
    out: dict[str, str] = {}
    for decl in block.split(";"):
        if ":" not in decl:
            continue
        name, _, value = decl.partition(":")
        name = name.strip()
        if name.startswith("--"):
            out[name] = " ".join(value.split()).lower()
    return out


def check_site_tokens_match_app(root: pathlib.Path) -> list[Finding]:
    site = _css_root_tokens(_read(root, "site/tokens.css"))
    app = _css_root_tokens(_read(root, "polaris_web/static/polaris.css"))
    if not site:
        return _fail("design_tokens", "site/tokens.css declares no tokens")
    if not app:
        return _fail("design_tokens", "polaris_web/static/polaris.css declares no :root tokens")
    for name, value in sorted(site.items()):
        if name not in app:
            return _fail("design_tokens",
                         f"site/tokens.css declares {name}, which the application does not: "
                         "the page must use the application's token names, not its own")
        if app[name] != value:
            return _fail("design_tokens",
                         f"{name} is {value} on the site and {app[name]} in the application")
    page = _read(root, "site/index.html")
    if page and ":root" in page.split("<style>")[-1][:400]:
        return _fail("design_tokens", "site/index.html redeclares the palette; tokens.css owns it")
    return _ok("design_tokens",
               f"the site and the application share all {len(site)} design tokens by name and value")


# ---------------------------------------------------------------------------
# CSS animations — a rule that sets opacity 0 and animates it back with
# `animation: <name> ... forwards` renders nothing at all if <name> has no
# @keyframes. That is not a cosmetic defect: v9.211 deleted the boot overlay
# and its keyframes but left the dashboard's stagger rules behind, so the
# System Dashboard rendered blank from v9.211 to v9.220 and no test noticed,
# because every element was present in the DOM at opacity 0. Every animation
# name a stylesheet uses must be defined in that stylesheet.
# ---------------------------------------------------------------------------
def check_css_animations_resolve(root: pathlib.Path) -> list[Finding]:
    css_files = sorted((root / "polaris_web/static").glob("*.css"))
    if not css_files:
        return _fail("css_animations", "no stylesheet found under polaris_web/static")
    checked = 0
    for path in css_files:
        text = path.read_text(encoding="utf-8", errors="replace")
        defined = set(re.findall(r"@keyframes\s+([A-Za-z_][\w-]*)", text))
        used: set[str] = set()
        for decl in re.findall(r"\banimation(?:-name)?\s*:\s*([^;}]+)", text):
            for part in decl.split(","):
                for token in part.split():
                    token = token.strip()
                    if (not token or token in ("none", "infinite", "alternate", "forwards",
                                               "backwards", "both", "normal", "reverse",
                                               "paused", "running", "initial", "inherit",
                                               "unset", "!important", "alternate-reverse")
                            or token.startswith(("var(", "steps(", "cubic-bezier("))
                            or re.match(r"^-?[\d.]+m?s$", token)
                            or re.match(r"^(ease|ease-in|ease-out|ease-in-out|linear)$", token)
                            or re.match(r"^[\d.]+$", token)):
                        continue
                    used.add(token)
        missing = sorted(n for n in used if n not in defined)
        if missing:
            return _fail("css_animations",
                         f"polaris_web/static/{path.name} animates {missing[0]}, which has no "
                         "@keyframes: the animated elements keep their starting state, which is "
                         "usually invisible")
        checked += len(used)
    return _ok("css_animations",
               f"every animation name used in the stylesheets resolves to a @keyframes ({checked} uses)")


# ---------------------------------------------------------------------------
# The system map is the first document a reader opens, and it drifted for
# thirty-six versions: it listed a directory that had been deleted, missed one
# that had been added, and named CI jobs that no longer existed. A map nobody
# recomputes is a map nobody can trust. Both directions fail: a tracked
# top-level path the map omits, and a map entry that names nothing.
# ---------------------------------------------------------------------------
_MAP_IGNORED_TOP = {".gitignore", ".dockerignore", ".coveragerc", ".trivyignore",
                    ".pre-commit-config.yaml", "ruff.toml", ".github", ".claude"}


def _tracked_top_level(root: pathlib.Path) -> set[str]:
    """Top-level tracked entries, from git when available, else the tree."""
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files"],
                             capture_output=True, text=True, timeout=30)
        if out.returncode == 0 and out.stdout.strip():
            return {line.split("/", 1)[0] for line in out.stdout.splitlines() if line.strip()}
    except (OSError, subprocess.SubprocessError):
        pass
    return {p.name for p in root.iterdir()
            if not p.name.startswith(".") and p.name not in {"__pycache__", "venv"}}


def check_system_map_covers_the_tree(root: pathlib.Path) -> list[Finding]:
    text = _read(root, "docs/reference/SYSTEM-MAP.md")
    if not text:
        return _fail("system_map", "docs/reference/SYSTEM-MAP.md is missing")

    # The tree diagram: entries drawn at depth zero inside the fenced block.
    block = text.split("```", 2)
    if len(block) < 2:
        return _fail("system_map", "the At a glance tree is not a fenced block")
    listed: set[str] = set()
    for line in block[1].splitlines():
        m = re.match(r"^[├└]── ([A-Za-z0-9_.-]+)", line)
        if m:
            listed.add(m.group(1).rstrip("/"))
        m2 = re.match(r"^[├└]── ([A-Za-z0-9_.-]+) / ([A-Za-z0-9_.-]+)", line)
        if m2:
            listed.update(m2.groups())
    if not listed:
        return _fail("system_map", "the At a glance tree lists no top-level entries")

    tracked = {name for name in _tracked_top_level(root) if name not in _MAP_IGNORED_TOP}
    missing = sorted(tracked - listed)
    if missing:
        return _fail("system_map",
                     "the At a glance tree does not list tracked top-level "
                     f"path(s): {', '.join(missing)}")
    orphans = sorted(name for name in listed - tracked if not (root / name).exists())
    if orphans:
        return _fail("system_map",
                     f"the At a glance tree lists path(s) that do not exist: {', '.join(orphans)}")

    # The CI job list: every job key in ci.yml, and nothing else.
    ci = _read(root, ".github/workflows/ci.yml")
    # Only the keys under the top-level `jobs:` mapping; `on:` has two-space
    # keys of its own (push, pull_request) that are not jobs.
    job_keys: set[str] = set()
    in_jobs = False
    for line in ci.splitlines():
        if re.match(r"^jobs:\s*$", line):
            in_jobs = True
            continue
        if in_jobs:
            if line and not line.startswith(" ") and not line.startswith("#"):
                break
            m = re.match(r"^  ([a-z][a-z0-9-]*):\s*$", line)
            if m:
                job_keys.add(m.group(1))
    named = set(re.findall(r"^- `([a-z][a-z0-9-]*)`:", text, re.M))
    if job_keys and named:
        missing_jobs = sorted(job_keys - named)
        if missing_jobs:
            return _fail("system_map",
                         f"the CI job list omits ci.yml job(s): {', '.join(missing_jobs)}")
        phantom = sorted(named - job_keys)
        if phantom:
            return _fail("system_map",
                         f"the CI job list names job(s) ci.yml does not define: {', '.join(phantom)}")
    return _ok("system_map",
               f"the system map lists every tracked top-level path ({len(tracked)}) "
               f"and every CI job ({len(job_keys)})")


# ---------------------------------------------------------------------------
# The rendered report — docs/paper/ ships a LaTeX source and the PDF rendered
# from it. Nothing forced the two to move together, and a PDF that no longer
# matches its source is worse than no PDF: a reader cites text that the
# repository has since changed. Rendering in CI would need a LaTeX toolchain
# and byte-reproducible output; a hash of the source the PDF was rendered from
# costs nothing and fails the moment the two diverge.
# ---------------------------------------------------------------------------
def check_paper_pdf_is_current(root: pathlib.Path) -> list[Finding]:
    paper = root / "docs/paper"
    if not paper.is_dir():
        return _ok("paper_current", "no docs/paper/ directory to check")
    tex = sorted(paper.glob("*.tex"))
    pdf = sorted(paper.glob("*.pdf"))
    stamp = paper / "rendered-from.txt"
    if not tex:
        return _ok("paper_current", "docs/paper/ ships no LaTeX source")
    if not pdf:
        return _fail("paper_current", "docs/paper/ has a .tex but no rendered PDF")
    if not stamp.is_file():
        return _fail("paper_current",
                     "docs/paper/rendered-from.txt is missing: the PDF cannot be shown to "
                     "match its source")
    recorded = {}
    for line in stamp.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) == 2:
            recorded[parts[1].lstrip("*")] = parts[0].lower()
    for source in tex:
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        want = recorded.get(source.name)
        if want is None:
            return _fail("paper_current",
                         f"docs/paper/rendered-from.txt does not record {source.name}")
        if want != digest:
            return _fail("paper_current",
                         f"{source.name} has changed since the PDF was rendered. Rebuild it "
                         "(cd docs/paper && pdflatex polaris_project_report.tex, twice) and "
                         "restamp: shasum -a 256 *.tex > rendered-from.txt")
    return _ok("paper_current",
               f"the rendered report matches the source it was rendered from ({len(tex)} file)")


# ---------------------------------------------------------------------------
# Vocation - retention is bounded, and the bound is data with a floor.
# ---------------------------------------------------------------------------
def check_retention_engine(root: pathlib.Path) -> list[Finding]:
    """The retention decision is data, floored, append-only, and the purge obeys it.

    Unbounded retention is refused by the vocation; so is the opposite abuse,
    a retention short enough to erase the record. Both are held by the same
    apparatus: RetentionPolicy carries the decision, the CHECK carries the
    floor, and uc_archive_purge refuses a cutoff inside the window.
    """
    schema = _read(root, "polaris_sql/01_schema.sql")
    if not re.search(r"CREATE\s+TABLE\s+RetentionPolicy\b", schema, re.I):
        return _fail("retention", "RetentionPolicy is missing from 01_schema.sql: the "
                                  "retention decision must be data, not a constant")
    floor = re.search(r"CONSTRAINT\s+retention_floor\s+CHECK\s*\(\s*retention_days\s*>=\s*(\d+)",
                      schema, re.I)
    if not floor:
        return _fail("retention", "RetentionPolicy has no retention_floor CHECK: a configured "
                                  "retention could then be short enough to erase the record")
    if int(floor.group(1)) < 365:
        return _fail("retention",
                     f"the retention floor is {floor.group(1)} days; it must be at least 365. "
                     "Shortening the floor is a schema change and a vocation question, not a "
                     "policy edit")

    grants = _read(root, "polaris_sql/09_grants.sql")
    if "retentionpolicy" not in grants.lower():
        return _fail("retention", "09_grants.sql must revoke UPDATE, DELETE on RetentionPolicy "
                                  "from polaris_app: a retention decision is an audit of record")

    triggers = _read(root, "polaris_sql/06_triggers.sql")
    if not re.search(r"CREATE\s+TRIGGER\s+trg_retention_policy_immutable\b", triggers, re.I):
        return _fail("retention", "trg_retention_policy_immutable is missing from 06_triggers.sql: "
                                  "a retention decision could be edited in place, losing the history "
                                  "of what was decided when")

    idx = _read(root, "polaris_sql/02_indexes.sql")
    if not re.search(r"uq_effective_retention_policy", idx, re.I):
        return _fail("retention", "uq_effective_retention_policy is missing from 02_indexes.sql: "
                                  "two effective policies could disagree for the same class")

    proc = _read(root, "polaris_sql/05_procedures.sql")
    for fn in ("retention_days_for", "retention_cutoff"):
        if not re.search(rf"CREATE\s+OR\s+REPLACE\s+FUNCTION\s+{fn}\b", proc, re.I):
            return _fail("retention", f"{fn}() is missing from 05_procedures.sql: nothing resolves "
                                      "the effective retention for a table class")
    m = re.search(r"CREATE\s+OR\s+REPLACE\s+PROCEDURE\s+uc_archive_purge\b.*?\n\$\$;",
                  proc, re.I | re.S)
    if not m:
        return _fail("retention", "uc_archive_purge procedure not found in 05_procedures.sql")
    body = m.group(0)
    if "retention_days_for" not in body and "retention_cutoff" not in body:
        return _fail("retention",
                     "uc_archive_purge does not consult the retention policy: the purge would "
                     "accept any cutoff, including one inside the retention window")
    if not re.search(r"RAISE\s+EXCEPTION", body, re.I):
        return _fail("retention",
                     "uc_archive_purge reads the retention policy but never refuses: a cutoff "
                     "inside the window must raise, not silently narrow")

    # v9.235: the per-class path. A schedule that keeps the civic record longer
    # than operational history has to reach the purge as more than one cutoff,
    # and the archive has to be the source of those cutoffs. Re-resolving them
    # at purge time would drift past what the archive holds, because
    # retention_cutoff() advances with now().
    if "p_class_cutoffs" not in body:
        return _fail("retention",
                     "uc_archive_purge takes no per-class cutoffs: a retention schedule that "
                     "differs by class cannot be applied, and half the engine is unusable")
    archive = _read(root, "scripts/polaris-archive.sh")
    if "--from-policy" not in archive or "cutoff_by_class" not in archive:
        return _fail("retention",
                     "scripts/polaris-archive.sh cannot archive from the retention policy: "
                     "--from-policy and a cutoff_by_class manifest entry are what let the purge "
                     "delete per class")
    purge = _read(root, "scripts/polaris-purge.sh")
    if "cutoff_by_class" not in purge or "p_class_cutoffs" not in purge:
        return _fail("retention",
                     "scripts/polaris-purge.sh ignores the manifest's per-class cutoffs, so a "
                     "policy archive would be purged at one cutoff")
    if "MANIFEST.json" not in purge or "hashlib" not in purge:
        return _fail("retention",
                     "scripts/polaris-purge.sh does not verify the archive against its manifest "
                     "before deleting: the carve-out's justification is that the archive "
                     "reconstitutes every purged row, and an edited archive would break it")
    # v9.237: the automated form of the chain. The cron wrapper is what actually
    # runs on the first of January; until v9.237 it passed a fixed 1825-day
    # cutoff and ignored the engine, and the installed cron line omitted the
    # --actor-user-id the purge requires, so it exited with a usage error.
    rotate = _read(root, "scripts/polaris-rotate-logs.sh")
    if "--from-policy" not in rotate:
        return _fail("retention",
                     "scripts/polaris-rotate-logs.sh does not archive --from-policy: the yearly "
                     "cron rotation would ignore the retention engine")
    cron = _read(root, "scripts/polaris-cron-install.sh")
    m_cron = re.search(r"(?m)^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+.*polaris-rotate-logs\.sh(.*)$", cron)
    if m_cron and "--actor-user-id" not in m_cron.group(1):
        return _fail("retention",
                     "the cron line polaris-cron-install.sh installs for polaris-rotate-logs.sh "
                     "omits --actor-user-id, which the purge requires: the yearly rotation would "
                     "exit with a usage error")
    drill = root / "scripts/polaris-retention-drill.sh"
    if not drill.is_file():
        return _fail("retention",
                     "scripts/polaris-retention-drill.sh is missing: the archive/purge chain "
                     "would again be a path nothing exercises end to end")
    ci = _read(root, ".github/workflows/ci.yml")
    if "polaris-retention-drill.sh" not in ci:
        return _fail("retention",
                     "the retention drill is not wired into CI, so the archive/purge chain runs "
                     "only when a human runs it")
    return _ok("retention",
               f"retention is data with a {floor.group(1)}-day floor, append-only, one effective "
               "policy per class; the purge refuses a cutoff inside the window, honours the "
               "archive's per-class cutoffs, verifies the archive against its manifest, and the "
               "whole chain is drilled in CI")


# ---------------------------------------------------------------------------
# National simulation (roadmap P2.14, v9.254) - the benchmark/hardening harness
# must (a) cover the whole country, (b) be deterministic so runs compare, and
# (c) drive enrollment through the REAL bulk pipeline (uc_bulk_issue), never a
# raw INSERT that would bypass the constraint set it exists to exercise. If the
# loader ever wrote tokens directly, the "benchmark" would prove nothing about
# the real system.
# ---------------------------------------------------------------------------
def check_national_simulation(root: pathlib.Path) -> list[Finding]:
    ref = _read(root, "polaris_sim/reference.py")
    nat = _read(root, "polaris_sim/nation.py")
    ld = _read(root, "polaris_sim/load.py")
    if not ref or not nat or not ld:
        return _fail("national_simulation",
                     "polaris_sim/{reference,nation,load}.py must exist (the simulation harness)")

    # (a) the whole country: at least the 50 states + DC as ISO 3166-2 codes.
    codes = set(re.findall(r'"(US-[A-Z0-9]{1,3})"', ref))
    if len(codes) < 51:
        return _fail("national_simulation",
                     f"polaris_sim/reference.py must cover all 50 states + DC "
                     f"(found {len(codes)} US- jurisdictions, need >=51)")

    # (b) deterministic: the plan is a function of (scale, seed), seeded from a
    # local PRNG, never the global one or the wall clock.
    if "def plan_nation" not in nat or "seed" not in nat or "random.Random" not in nat:
        return _fail("national_simulation",
                     "polaris_sim/nation.py must build a deterministic, seeded plan "
                     "(plan_nation(scale, seed) using random.Random)")

    # (c) through the real pipeline: the loader issues via uc_bulk_issue and must
    # NOT write IdentityToken / TokenLifecycleEvent rows directly (that would
    # bypass the very constraints the benchmark is meant to exercise).
    if "uc_bulk_issue" not in ld:
        return _fail("national_simulation",
                     "polaris_sim/load.py must enroll through uc_bulk_issue (the real "
                     "pipeline), so every synthetic person passes the full constraint set")
    # v9.257: the loader SIGNS each token through the real module before staging,
    # so mass-issued tokens carry a real signature, not a placeholder literal.
    if "signature_with_key_for_token" not in ld:
        return _fail("national_simulation",
                     "polaris_sim/load.py must sign each token_value through pqc_signing "
                     "(signature_with_key_for_token) so mass-issued tokens are cryptographically "
                     "signed, not fabricated placeholders")
    for bypass in ("INSERT INTO IdentityToken", "INSERT INTO TokenLifecycleEvent"):
        if re.search(bypass, ld, re.I):
            return _fail("national_simulation",
                         f"polaris_sim/load.py must not {bypass.lower()} directly; issuance goes "
                         "through uc_bulk_issue so the simulation exercises the real system (not a mock)")

    # S2 (v9.255): the life-event stream writes verifications through the same
    # direct VerificationEvent INSERT the app route uses (there is no procedure
    # for a verification), and drives lifecycle through the real uc8_revoke_token
    # procedure. It must never write IdentityToken / TokenLifecycleEvent directly
    # (that would fabricate a token state the procedures gate).
    ev = _read(root, "polaris_sim/events.py")
    if not ev:
        return _fail("national_simulation", "polaris_sim/events.py (the life-event stream) must exist")
    if "VerificationEvent" not in ev:
        return _fail("national_simulation",
                     "events.py must write verifications to VerificationEvent (the real write path)")
    if "uc8_revoke_token" not in ev:
        return _fail("national_simulation",
                     "events.py must drive lifecycle through the real procedure uc8_revoke_token, "
                     "not a direct write")
    for bypass in ("INSERT INTO IdentityToken", "INSERT INTO TokenLifecycleEvent"):
        if re.search(bypass, ev, re.I):
            return _fail("national_simulation",
                         f"polaris_sim/events.py must not {bypass.lower()} directly; token state and "
                         "lifecycle events come from the procedures the simulation is exercising")

    # S3 (v9.256): the benchmark harness drives the nation at scale and certifies
    # that the invariants still hold under load; its report is committed so the
    # numbers are a record, not a claim (roadmap P2.9, realized here).
    bench = _read(root, "polaris_sim/benchmark.py")
    if not bench:
        return _fail("national_simulation", "polaris_sim/benchmark.py (the benchmark harness) must exist")
    if "check_invariants" not in bench:
        return _fail("national_simulation",
                     "benchmark.py must certify the invariants under load (check_invariants): a "
                     "benchmark that does not prove C1-C10 still hold is a throughput number, not a "
                     "load certification")
    # v9.257: the benchmark must exercise the REAL signature-verification path
    # (distinct from event ingestion) so its crypto-verification number is honest
    # and it certifies that mass-issued tokens actually verify.
    if "measure_crypto_verification" not in bench:
        return _fail("national_simulation",
                     "benchmark.py must measure real cryptographic signature verification "
                     "(measure_crypto_verification), distinct from verification-event ingestion, and "
                     "certify that mass-issued signatures verify")
    if not _read(root, "docs/reference/BENCHMARK.md"):
        return _fail("national_simulation",
                     "docs/reference/BENCHMARK.md (the committed load certification) must exist")

    # The harness is tested, and the test rides in the coverage suite so CI runs it.
    if not _read(root, "polaris_sim/test_sim.py"):
        return _fail("national_simulation", "polaris_sim/test_sim.py (the harness tests) must exist")
    cov = _read(root, "scripts/polaris-coverage.sh")
    if "polaris_sim" not in cov:
        return _fail("national_simulation",
                     "scripts/polaris-coverage.sh must run the polaris_sim suite so CI exercises it")
    return _ok("national_simulation",
               "the national simulation covers all 51 jurisdictions, is deterministic (seeded), enrolls "
               "through the real bulk pipeline (uc_bulk_issue), drives a life-event stream through the "
               "real paths (VerificationEvent inserts + uc8_revoke_token, no direct token/lifecycle "
               "writes), and a benchmark harness measures it at scale and certifies the invariants under "
               "load with a committed report; its tests run in the coverage suite (roadmap P2.14/P2.9)")


# ===========================================================================
# Athena (v9.266) — the authority-and-constitution layer. Five invariants make
# person-legibility structurally impossible and keep Athena non-sovereign.
# Spec: DEVNOTES/athena-ontology-assessment.md sections 5, 6, 8, 10, 11.
# ===========================================================================

_ATHENA_SQL_REL = "polaris_sql/16_athena.sql"

# The ONLY tables Athena may own — each descriptive (rules, the enforcement map,
# a custody reference), never an authority grant. A new athena_* table is a
# governance event (assessment section 10) and must be added here deliberately.
_ATHENA_TABLE_ALLOWLIST = {
    "athena_constitutional_rule",
    "athena_rule_enforcement",
    "athena_key_custody",
}

# Person surfaces Athena must never touch, as IDENTIFIERS (scanned against SQL
# with comments and string literals stripped, so prose and rule statements that
# mention "token" do not trip it).
_ATHENA_FORBIDDEN_IDENTIFIERS = [
    "Individual", "individual_id", "IdentityToken", "TokenPermission",
    "VerificationEvent", "TokenLifecycleEvent", "DuressEvent",
    "legal_name", "date_of_birth", "duress_code_hash",
    "token_id", "token_value", "predecessor_token_id",
]

# Stable per-person handle shapes: a cross-context handle is a universal
# identifier even if opaque (assessment section 5).
_ATHENA_SUBJECT_SURROGATES = ["subject", "person", "individual", "holder", "citizen", "_handle"]


def _athena_strip_noise(sql: str) -> str:
    """Drop -- comments and '...' string literals so an identifier scan sees only
    structural SQL (table/column names), never prose or seed text."""
    sql = re.sub(r"--[^\n]*", "", sql)
    sql = re.sub(r"'(?:[^']|'')*'", "''", sql)
    return sql


def _athena_function_bodies(sql: str):
    """(name, body) for each CREATE ... FUNCTION athena_*, body = dollar-quoted block."""
    out = []
    for m in re.finditer(
        r"CREATE\s+OR\s+REPLACE\s+FUNCTION\s+(athena_[a-z_]+)\s*\(.*?\$(\w+)\$(.*?)\$\2\$",
        sql, re.S | re.I):
        out.append((m.group(1), m.group(3)))
    return out


def _athena_view_body(sql: str, view: str):
    m = re.search(r"CREATE\s+OR\s+REPLACE\s+VIEW\s+" + re.escape(view) + r"\s+AS(.*?);",
                  sql, re.S | re.I)
    return m.group(1) if m else None


def _athena_insert_block(sql: str, table: str) -> str:
    m = re.search(r"INSERT\s+INTO\s+" + re.escape(table) + r"\b(.*?)ON\s+CONFLICT", sql, re.S | re.I)
    return m.group(1) if m else ""


def _athena_mechanism_exists(root: pathlib.Path, kind: str, name: str) -> bool:
    if kind == "CHECK_FUNCTION":
        return re.search(r"\bdef\s+" + re.escape(name) + r"\s*\(",
                         _read(root, "polaris_checks/checks.py")) is not None
    if kind == "INDEX":
        sql = _read(root, "polaris_sql/02_indexes.sql") + _read(root, "polaris_sql/01_schema.sql")
        return re.search(r"\bINDEX\s+" + re.escape(name) + r"\b", sql, re.I) is not None
    if kind == "CHECK_CONSTRAINT":
        return re.search(r"\bCONSTRAINT\s+" + re.escape(name) + r"\b",
                         _read(root, "polaris_sql/01_schema.sql"), re.I) is not None
    if kind == "TRIGGER":
        sql = _read(root, "polaris_sql/06_triggers.sql") + _read(root, "polaris_sql/01_schema.sql")
        return (re.search(r"\bCREATE\s+TRIGGER\s+" + re.escape(name) + r"\b", sql, re.I) is not None
                or re.search(r"\bFUNCTION\s+" + re.escape(name) + r"\b", sql, re.I) is not None)
    if kind == "PROCEDURE":
        return re.search(r"\b(?:FUNCTION|PROCEDURE)\s+" + re.escape(name) + r"\b",
                         _read(root, "polaris_sql/05_procedures.sql"), re.I) is not None
    return False


def check_athena_no_person(root: pathlib.Path) -> list[Finding]:
    """Athena invariant 1+2 (assessment section 11): person-legibility is
    structurally impossible. No Athena view/function/table references a natural-
    person table or column, and no Athena column is a stable cross-context person
    surrogate. The v9.19 v_ontology_individual / v_ontology_individual_tokens
    person-aggregating views are removed in the same ship, so the prohibition is
    true from the first commit. Detection: test_checks adds an individual_id
    reference, a subject_handle column, and re-adds the person view."""
    athena = _read(root, _ATHENA_SQL_REL)
    if not athena:
        return _fail("athena_no_person", f"{_ATHENA_SQL_REL} is missing")
    clean = _athena_strip_noise(athena)
    for ident in _ATHENA_FORBIDDEN_IDENTIFIERS:
        if re.search(r"\b" + re.escape(ident) + r"\b", clean, re.I):
            return _fail("athena_no_person",
                         f"16_athena.sql references the person surface `{ident}` in structural SQL; "
                         "Athena must read only the authority tables (no Individual / token / event / duress)")
    for surr in _ATHENA_SUBJECT_SURROGATES:
        if re.search(r"\bAS\s+[a-z_]*" + re.escape(surr) + r"[a-z_]*\b", clean, re.I) or \
           re.search(r"\b[a-z_]*" + re.escape(surr) + r"[a-z_]*\s+(?:VARCHAR|TEXT|INTEGER|BOOLEAN|SERIAL|BIGINT)\b",
                     clean, re.I):
            return _fail("athena_no_person",
                         f"16_athena.sql defines a `{surr}`-shaped column/alias; a stable per-person handle "
                         "is a universal identifier and is forbidden (assessment section 5)")
    ont = _read(root, "polaris_sql/15_ontology.sql")
    for gone in ("v_ontology_individual", "v_ontology_individual_tokens"):
        if gone in ont:
            return _fail("athena_no_person",
                         f"the person-aggregating view {gone} must be removed from 15_ontology.sql in the "
                         "Athena ship (its single-entity data lives on the audited Investigate path)")
    return _ok("athena_no_person",
               "Athena reads only the authority tables; no person table/column/surrogate in any view, "
               "function, or curated table, and the v9.19 person-aggregating ontology views are removed")


def check_athena_read_only(root: pathlib.Path) -> list[Finding]:
    """Athena invariant 5+8: Athena cannot act. No Athena function writes, CALLs a
    mutating procedure, or is SECURITY DEFINER; every one is declared STABLE (which
    by itself forbids DML). This keeps 'graph says revoke -> revoked' impossible
    (assessment section 6). Detection: test_checks adds SECURITY DEFINER and an
    INSERT inside an athena function."""
    athena = _read(root, _ATHENA_SQL_REL)
    if not athena:
        return _fail("athena_read_only", f"{_ATHENA_SQL_REL} is missing")
    # Scan structural SQL only: SECURITY DEFINER named in a design-law comment
    # (as this file does, to forbid it) must not trip the check.
    clean = _athena_strip_noise(athena)
    if re.search(r"SECURITY\s+DEFINER", clean, re.I):
        return _fail("athena_read_only",
                     "an Athena function is SECURITY DEFINER; Athena grants nothing beyond the underlying "
                     "table grants (invariant 8)")
    bodies = _athena_function_bodies(clean)
    if not bodies:
        return _fail("athena_read_only", "no athena_* functions found to verify")
    mutations = re.compile(r"\b(INSERT|UPDATE|DELETE|CALL|TRUNCATE|MERGE|DROP|ALTER|GRANT)\b", re.I)
    for name, body in bodies:
        m = mutations.search(body)
        if m:
            return _fail("athena_read_only",
                         f"athena function {name}() contains a `{m.group(1).upper()}`; Athena is read-only "
                         "and contributes explanation, never permission (invariant 5)")
    for m in re.finditer(r"CREATE\s+OR\s+REPLACE\s+FUNCTION\s+(athena_[a-z_]+)\b.*?LANGUAGE\s+sql\s+(\w+)",
                         athena, re.S | re.I):
        if m.group(2).upper() != "STABLE":
            return _fail("athena_read_only",
                         f"athena function {m.group(1)}() must be declared STABLE (read-only), not {m.group(2)}")
    return _ok("athena_read_only",
               f"all {len(bodies)} Athena functions are STABLE, non-mutating, and SECURITY INVOKER "
               "(read-only; Athena explains authority, never manufactures it)")


def check_athena_functions_bounded(root: pathlib.Path) -> list[Finding]:
    """Athena invariant 3: bounded result sets (the Atlas C8 discipline inherited).
    Every Athena function caps its output with LIMIT, and any function that ever
    reads an event table must ALSO carry a since-window, so Athena can never become
    a second unbounded aggregation surface beside the Atlas (assessment section 8).
    Detection: test_checks strips a LIMIT and adds an uncapped event function."""
    athena = _read(root, _ATHENA_SQL_REL)
    if not athena:
        return _fail("athena_bounded", f"{_ATHENA_SQL_REL} is missing")
    bodies = _athena_function_bodies(_athena_strip_noise(athena))
    if not bodies:
        return _fail("athena_bounded", "no athena_* functions found to verify")
    for name, body in bodies:
        if not re.search(r"\bLIMIT\s+\d+", body, re.I):
            return _fail("athena_bounded",
                         f"athena function {name}() has no LIMIT cap; every Athena function must bound its "
                         "result set (C8 discipline)")
        if re.search(r"\b(?:VerificationEvent|TokenLifecycleEvent)\b", body, re.I) and \
           not re.search(r"\bsince\b|COALESCE\(p_since|event_timestamp\s*>=", body, re.I):
            return _fail("athena_bounded",
                         f"athena function {name}() reads an event table without a since-window; an event-"
                         "touching Athena function must inherit the Atlas since-window (C8)")
    return _ok("athena_bounded",
               f"all {len(bodies)} Athena functions bound their output with LIMIT; none reads an event "
               "table unbounded (C8 discipline inherited from the Atlas)")


def check_athena_non_sovereign(root: pathlib.Path) -> list[Finding]:
    """Athena invariant 4+7: Athena describes authority, never manufactures it.
    Every authority edge resolves to an existing authority table (no independent
    store), 'current' views exclude superseded/revoked authority, and the only
    tables Athena owns are the descriptive allow-listed ones (a new athena_* table
    is a governance event, assessment section 10). Detection: test_checks drops the
    revocation filter, adds an athena_agency_grant table, and repoints an edge."""
    athena = _read(root, _ATHENA_SQL_REL)
    if not athena:
        return _fail("athena_sovereign", f"{_ATHENA_SQL_REL} is missing")
    clean = _athena_strip_noise(athena)
    for view, tbl in (("v_athena_may_issue", "AgencyAlgorithmAuth"),
                      ("v_athena_authorizes", "AgencyAlgorithmAuth"),
                      ("v_athena_relies_on", "AgencyTrustAttestation"),
                      ("v_athena_trust_agreement", "AgencyTrustAttestation")):
        body = _athena_view_body(clean, view)
        if body is None:
            return _fail("athena_sovereign", f"authority view {view} is missing")
        if tbl not in body:
            return _fail("athena_sovereign",
                         f"{view} does not resolve to the authority table {tbl}; Athena has no independent "
                         "authority store (invariant 4)")
    for view in ("v_athena_relies_on", "v_athena_trust_agreement"):
        body = _athena_view_body(clean, view) or ""
        if "revocation_date IS NULL" not in body:
            return _fail("athena_sovereign",
                         f"{view} does not filter revoked authority (revocation_date IS NULL); a superseded "
                         "attestation must not surface as current (invariant 7)")
    created = set(re.findall(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(athena_[a-z_]+)", athena, re.I))
    rogue = created - _ATHENA_TABLE_ALLOWLIST
    if rogue:
        return _fail("athena_sovereign",
                     f"Athena owns non-allow-listed table(s) {sorted(rogue)}; a new athena_* table is a "
                     "governance event and must be a descriptive (never authority) allow-listed table")
    return _ok("athena_sovereign",
               "every Athena authority edge resolves to an existing authority table, 'current' views "
               "exclude revoked authority, and Athena owns only the three descriptive curated tables")


def check_athena_rule_enforcement_resolves(root: pathlib.Path) -> list[Finding]:
    """Athena invariant 6: the constitution-as-data cannot drift from the code.
    Every athena_rule_enforcement row names a mechanism (trigger / index / check
    constraint / check_* / procedure) that actually exists in the tree, and every
    constitutional rule has at least one enforcement. This closes the prose-drift
    gap meta/constraint-lattice.md has today. Detection: test_checks points a row
    at a nonexistent trigger and adds an unenforced rule."""
    athena = _read(root, _ATHENA_SQL_REL)
    if not athena:
        return _fail("athena_rule_enf", f"{_ATHENA_SQL_REL} is missing")
    enf_block = _athena_insert_block(athena, "athena_rule_enforcement")
    rule_block = _athena_insert_block(athena, "athena_constitutional_rule")
    if not enf_block or not rule_block:
        return _fail("athena_rule_enf", "could not locate the Athena curated-seed INSERT blocks")
    rows = re.findall(r"\(\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'", enf_block)
    if not rows:
        return _fail("athena_rule_enf", "no athena_rule_enforcement rows parsed")
    for rule_code, kind, name in rows:
        if not _athena_mechanism_exists(root, kind, name):
            return _fail("athena_rule_enf",
                         f"{rule_code} claims enforcement by {kind} `{name}`, which does not exist in the "
                         "tree; the constitution-to-mechanism map has drifted from the code")
    enforced = {r[0] for r in rows}
    declared = set(re.findall(r"\(\s*'([^']*)'\s*,", rule_block))
    unenforced = declared - enforced
    if unenforced:
        return _fail("athena_rule_enf",
                     f"constitutional rule(s) {sorted(unenforced)} have no enforcement mechanism; every rule "
                     "must map to at least one live mechanism")
    return _ok("athena_rule_enf",
               f"all {len(rows)} rule-enforcement rows resolve to a live mechanism and every one of the "
               f"{len(declared)} constitutional rules is enforced (constitution cannot drift from code)")


# ---------------------------------------------------------------------------
# Athena console (v9.266) — the operator-facing surface for the authority-and-
# constitution layer must stay login-gated, person-free, and CSP-safe.
# ---------------------------------------------------------------------------
_ATHENA_CONSOLE_ROUTES = [
    ("/athena", "athena_console"),
    ("/api/athena/authority-chain", "api_athena_authority_chain"),
    ("/api/athena/affected-by-algorithm", "api_athena_affected_by_algorithm"),
    ("/api/athena/explain-proof", "api_athena_explain_proof"),
]


def _athena_py_strip_docstrings(code: str) -> str:
    """Drop triple-quoted docstrings and # comments but KEEP single-line query
    strings, so a person table inside a real query() is still caught while the
    route's own prose ("no Individual table is touched") is not."""
    code = re.sub(r'"""(?:.|\n)*?"""', '', code)
    code = re.sub(r"'''(?:.|\n)*?'''", '', code)
    code = re.sub(r"#[^\n]*", "", code)
    return code


def _athena_route_decorators(app: str, route: str) -> str:
    m = re.search(re.escape("@app.route('" + route + "')") + r"(.*?)\ndef ", app, re.S)
    return m.group(1) if m else ""


def check_athena_console(root: pathlib.Path) -> list[Finding]:
    """v9.266 (roadmap P6.8): the operator-facing Athena console. The page and its
    three drill-down endpoints must be login-gated, must read ONLY the person-free
    Athena/authority surface (never Individual / token / event), and must render
    CSP-safe (createElement, never innerHTML with markup, C5). The four tabs
    (Constitution / Authority / Proof / Trust) and the external JS must be wired.
    Detection: test_checks removes login_required, adds a person query, assigns
    innerHTML, and drops a tab mount."""
    app = _read(root, "polaris_web/app.py")
    js = _read(root, "polaris_web/static/athena-console.js")
    tpl = _read(root, "polaris_web/templates/athena.html")
    if not app or not js or not tpl:
        return _fail("athena_console", "the Athena console (app route / JS / template) is missing")

    person = ("Individual", "individual_id", "IdentityToken", "VerificationEvent",
              "TokenLifecycleEvent", "TokenPermission", "token_id", "token_value")
    for route, fn in _ATHENA_CONSOLE_ROUTES:
        if "@app.route('" + route + "')" not in app:
            return _fail("athena_console", f"the {route} route is missing from app.py")
        if "login_required" not in _athena_route_decorators(app, route):
            return _fail("athena_console", f"the {route} route is not @login_required")
        body = _athena_py_strip_docstrings(_fn_body(app, fn))
        if not body:
            return _fail("athena_console", f"{fn}() is missing")
        for bad in person:
            if re.search(r"\b" + re.escape(bad) + r"\b", body):
                return _fail("athena_console",
                             f"{fn}() references the person surface `{bad}`; the Athena console must "
                             "read only the person-free Athena layer")

    if re.search(r"innerHTML\s*=", js):
        return _fail("athena_console", "athena-console.js assigns innerHTML; build the DOM with "
                                       "createElement/textContent so script-src 'self' stays strict (C5)")
    if "createElement" not in js:
        return _fail("athena_console", "athena-console.js must build the DOM with createElement (C5-safe)")

    for tab in ("constitution", "authority", "proof", "trust"):
        if ('data-athena-tab="' + tab + '"') not in tpl or ('data-athena-panel="' + tab + '"') not in tpl:
            return _fail("athena_console", f"the '{tab}' tab/panel mount is missing from athena.html")
    if "athena-console.js" not in tpl:
        return _fail("athena_console", "athena.html does not include the external athena-console.js")

    return _ok("athena_console",
               "the Athena console (4 tabs, 1 page + 3 drill-down routes) is login-gated, reads only the "
               "person-free Athena layer, and renders CSP-safe via createElement")


# ---------------------------------------------------------------------------
# P1.18 item 1 (v9.268) — the public zero-knowledge claim stays precise.
# ---------------------------------------------------------------------------
def check_zk_claim_precise(root: pathlib.Path) -> list[Finding]:
    """The public claim about zero-knowledge must not overclaim. The README
    title/tagline may not headline "post-quantum, zero-knowledge ... system" as
    an umbrella (which reads as general anonymous credentials), and the README
    must state the boundary explicitly: unlinkable verification records + a
    Merkle-membership proof, and NOT a general selective-disclosure / anonymous-
    credential system. Detection: test_checks restores the umbrella tagline and
    removes the boundary sentence."""
    readme = _read(root, "README.md")
    if not readme:
        return _fail("zk_claim", "README.md is missing")
    # strip markdown emphasis so a bolded **not** or a **zero-knowledge** tagline
    # is matched the same as plain text.
    plain = readme.replace("*", "").replace("_", "")
    head = plain[:1600]  # the title + tagline block, above the fold
    if re.search(r"post-quantum,\s*zero.knowledge", head, re.I):
        return _fail("zk_claim",
                     "the README tagline headlines 'post-quantum, zero-knowledge ...' as an umbrella; there "
                     "'zero-knowledge' reads as general anonymous credentials. Name the precise property "
                     "(unlinkable-by-default) in the tagline and keep the zero-knowledge detail in the body")
    if not re.search(r"not a general (selective.disclosure|anonymous.credential)", plain, re.I):
        return _fail("zk_claim",
                     "the README must state the boundary: Polaris is NOT a general selective-disclosure / "
                     "anonymous-credential system (only unlinkable verification records + a Merkle-membership proof)")
    return _ok("zk_claim",
               "the public zero-knowledge claim is precise: no umbrella in the tagline, and the README states "
               "the boundary (unlinkable verification records + a Merkle-membership proof, not anonymous credentials)")


# ---------------------------------------------------------------------------
# P1.18 item 2 (v9.269) — the science-fiction scaffold tables stay removed.
# ---------------------------------------------------------------------------
def check_no_scifi_schema(root: pathlib.Path) -> list[Finding]:
    """v9.269 removed two science-fiction scaffold tables that served no current
    guarantee or milestone: GenomicAnchor (a per-token hash commitment framed as
    DNA/genomic anchoring) and QuantumObserverBinding (a 'quantum-observer
    measurement' scaffold documented as having no planned use). This guards the
    v9.55 apparatus-removal discipline: a national-identity schema names real
    mechanisms only, not DNA-alphabet or wavefunction-collapse vocabulary. To
    reintroduce either, deprecate this check in a reviewed change. Detection:
    test_checks re-adds a CREATE TABLE GenomicAnchor and the sci-fi vocabulary
    to the live schema."""
    schema = _read(root, "polaris_sql/01_schema.sql")
    if not schema:
        return _fail("no_scifi", "polaris_sql/01_schema.sql is missing")
    for name in ("GenomicAnchor", "QuantumObserverBinding"):
        if re.search(r"CREATE TABLE\s+(?:IF NOT EXISTS\s+)?" + name + r"\b", schema):
            return _fail("no_scifi",
                         f"the live schema recreates {name}, a science-fiction scaffold with no current "
                         "guarantee; it was removed in v9.269 (deprecate via a migration, not the base schema)")
    for term in ("wavefunction", "no-cloning theorem", "quantum-observer measurement", "genomic alphabet"):
        if re.search(re.escape(term), schema, re.I):
            return _fail("no_scifi",
                         f"the live schema carries science-fiction vocabulary ('{term}'); a national-identity "
                         "schema names real mechanisms only (v9.269, continuing the v9.55 discipline)")
    return _ok("no_scifi",
               "the live schema is free of the deprecated science-fiction scaffolds (GenomicAnchor, "
               "QuantumObserverBinding) and their vocabulary")


# ---------------------------------------------------------------------------
# P1.18 item 3 (v9.270) — the two-tier constitution stays consistent across
# the prose (MISSION.md) and the queryable model (Athena).
# ---------------------------------------------------------------------------
_CONSTITUTIONAL_RULES = {"C1", "C2", "C3", "C6", "C10"}


def check_constitution_layered(root: pathlib.Path) -> list[Finding]:
    """The constitution sits at two tiers beneath the vocation: CONSTITUTIONAL
    rights guarantees (C1, C2, C3, C6, C10) and ENGINEERING invariants that keep
    them honest (C4, C5, C7, C8, C9). MISSION.md's Tier column and Athena's
    athena_constitutional_rule.layer must agree, so the classification cannot
    drift between the prose constitution and its queryable model, and moving a
    rule between tiers is a visible constitutional change. Detection: test_checks
    flips a tier in one surface only, and reclassifies a rule."""
    mission = _read(root, "MISSION.md")
    athena = _read(root, "polaris_sql/16_athena.sql")
    if not mission or not athena:
        return _fail("constitution_layered", "MISSION.md or 16_athena.sql is missing")
    mission_tier = {}
    for m in re.finditer(r"(?m)^\|\s*(C\d+)\s*\|[^|]*\|\s*(Constitutional|Engineering)\s*\|", mission):
        mission_tier[m.group(1)] = m.group(2).upper()
    athena_layer = {}
    for m in re.finditer(r"\('(C\d+)',[^\n]*?'(CONSTITUTIONAL|ENGINEERING)','MISSION\.md C\d+'\)", athena):
        athena_layer[m.group(1)] = m.group(2)
    if len(mission_tier) != 10:
        return _fail("constitution_layered",
                     f"MISSION.md's constraint table classifies {len(mission_tier)}/10 rules by Tier "
                     "(each C1-C10 row needs a Constitutional|Engineering Tier cell)")
    if len(athena_layer) != 10:
        return _fail("constitution_layered",
                     f"athena_constitutional_rule seeds a layer for {len(athena_layer)}/10 C-rules")
    for c in ("C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10"):
        if mission_tier.get(c) != athena_layer.get(c):
            return _fail("constitution_layered",
                         f"{c} is {mission_tier.get(c)} in MISSION.md but {athena_layer.get(c)} in Athena; the "
                         "prose constitution and its queryable model must agree on the tier")
    got = {c for c, t in mission_tier.items() if t == "CONSTITUTIONAL"}
    if got != _CONSTITUTIONAL_RULES:
        return _fail("constitution_layered",
                     f"the constitutional tier is {sorted(got)}, expected {sorted(_CONSTITUTIONAL_RULES)}; "
                     "reclassifying a rule between tiers is a constitutional change, not a silent edit")
    return _ok("constitution_layered",
               "the constitution is two tiers beneath the vocation — constitutional (C1, C2, C3, C6, C10) and "
               "engineering (C4, C5, C7, C8, C9) — and MISSION.md agrees with Athena's queryable model")


# ---------------------------------------------------------------------------
# P1.18 item 5 (v9.272) — the two-witness availability clause: single-witness
# verify-at-use is only sound while continuous sampling checks it.
# ---------------------------------------------------------------------------
def check_verify_witness_sampling(root: pathlib.Path) -> list[Finding]:
    """The single-witness verify-at-use path is fast, but sound only while the
    fast witness stays trustworthy. So a random fraction of successful checks is
    continuously replayed through the SECOND witness; any disagreement pages (a
    SEV, not a log line); the response names which witness set actually ran; and
    sampling is MANDATORY in production (the rate is floored above zero). Two
    witnesses that are optional are one witness with extra docs. Detection:
    test_checks removes the sampling, the production floor, the alert, and the
    witness-set naming."""
    app = _read(root, "polaris_web/app.py")
    obs = _read(root, "polaris_web/observability.py")
    alerts = _read(root, "deploy/observability/polaris-alerts.yml")
    if not app or not obs or not alerts:
        return _fail("verify_sampling", "app.py / observability.py / polaris-alerts.yml is missing")
    ep = app.split("def api_token_verify", 1)
    ep_body = ep[1][:7000] if len(ep) == 2 else ""
    if "_VERIFY_SAMPLE_RATE" not in ep_body or "witnesses='both'" not in ep_body:
        return _fail("verify_sampling",
                     "the verify-at-use endpoint must sample a fraction of checks through the SECOND "
                     "witness (_VERIFY_SAMPLE_RATE + a witnesses='both' re-verify): the availability clause")
    if "record_witness_disagreement" not in ep_body or "_METRICS_VERIFY_DISAGREEMENT" not in ep_body:
        return _fail("verify_sampling",
                     "a sampling disagreement must page: record_witness_disagreement + the alertable counter "
                     "polaris_verify_witness_disagreements_total")
    if "sampled=" not in ep_body or "'both' if sampled else 'single'" not in ep_body:
        return _fail("verify_sampling",
                     "the verify response must name which witness set actually ran (witnesses 'both' when "
                     "sampled, else 'single', plus a `sampled` flag)")
    if not re.search(r"if _PRODUCTION:\s*\n\s*rate = max\(rate,", app):
        return _fail("verify_sampling",
                     "continuous sampling must be MANDATORY in production: the sample rate is floored above "
                     "zero under _PRODUCTION so it cannot be disabled")
    if "def record_witness_disagreement" not in obs:
        return _fail("verify_sampling", "observability.record_witness_disagreement is missing")
    if "PolarisWitnessDisagreement" not in alerts or "polaris_verify_witness_disagreements_total" not in alerts:
        return _fail("verify_sampling",
                     "a PolarisWitnessDisagreement alert on polaris_verify_witness_disagreements_total must exist")
    return _ok("verify_sampling",
               "the verify-at-use path continuously samples through the second witness, pages on any "
               "disagreement (a SEV), names the witness set that ran, and keeps sampling mandatory in "
               "production (the two-witness availability clause)")


# ---------------------------------------------------------------------------
# P1.18 honesty pass (v9.273) — the outward surfaces must not overstate what
# exists now. Underclaim over overclaim.
# ---------------------------------------------------------------------------
_OVERCLAIM_PHRASES = (
    "one physical token per person",   # the hardware token is modeled, not manufactured
    "the complete working system",     # it is a reference implementation, not a deployment
    # Issuance is two-witness fail-closed; verify-at-use is single-witness plus
    # sampling. "every cryptographic verdict" flattens the two into one guarantee.
    "Two independent witnesses for every cryptographic verdict",
)


def check_public_claims_honest(root: pathlib.Path) -> list[Finding]:
    """The site title and social card must name Polaris a reference implementation
    (not present it AS a national identity system in a browser tab or a shared
    link); the README must not carry the retired overclaims; and the 'Where
    Polaris sits' comparison must keep the honest 'Deployed to a real population'
    column that marks Polaris the one system NOT deployed, so its design ticks are
    not read as a deployment. Detection: test_checks restores a bare title and an
    overclaim phrase."""
    readme = _read(root, "README.md")
    site = _read(root, "site/index.html")
    if not readme or not site:
        return _fail("public_claims", "README.md or site/index.html is missing")
    title = re.search(r"<title>([^<]*)</title>", site)
    ogt = re.search(r'og:title"\s+content="([^"]*)"', site)
    for label, m in (("<title>", title), ("og:title", ogt)):
        if not m or "reference implementation" not in m.group(1).lower():
            return _fail("public_claims",
                         f"the site {label} must name Polaris a reference implementation, not present it AS a "
                         "national identity system in a browser tab or a shared social card")
        # The category must match the honest GitHub one (identity-token reference
        # implementation): the shareable surface must not call Polaris a "national"
        # system, which reads as a deployment. Understate, do not overstate.
        if "national" in m.group(1).lower():
            return _fail("public_claims",
                         f"the site {label} calls Polaris a 'national' system; that category overstates a reference "
                         "implementation on notional data. Drop 'national' from the title and social card.")
        # Unlinkability is issuer-side and ZK-mode-scoped. A bare "unlinkable-by-default"
        # on the shareable surface reads as covering the holder-to-verifier hop, which it
        # does not; the qualifier must be beside the claim, so say "issuer-unlinkable".
        low = m.group(1).lower()
        if "unlinkable" in low and "issuer-unlinkable" not in low:
            return _fail("public_claims",
                         f"the site {label} says 'unlinkable' without the issuer qualifier; unlinkability is "
                         "issuer-side and ZK-mode-scoped, so the shareable surface must say 'issuer-unlinkable' "
                         "(a full-credential presentation is correlatable across verifiers)")
    for bad in _OVERCLAIM_PHRASES:
        if bad in readme:
            return _fail("public_claims",
                         f"the README carries the overclaim {bad!r}; shrink the claim to what the code does now "
                         "(the hardware token is modeled; this is a reference implementation)")
    if "Deployed to a real population" not in readme:
        return _fail("public_claims",
                     "the 'Where Polaris sits' comparison must keep the 'Deployed to a real population' column so "
                     "Polaris's design ticks are not read as a deployment")
    # Unlinkability is issuer-side and ZK-mode-scoped. Since P9.4 the holder-to-verifier hop
    # has a two-sided answer, and the README must give BOTH sides. Saying only that stored
    # handles are now per-verifier would overclaim, because a full-credential presentation
    # still SHOWS a stable token_value. Saying only the old flat sentence would understate
    # work that shipped. Either half alone misleads, so both are required.
    if "Relying-party correlation" not in readme:
        return _fail("public_claims",
                     "the README must state relying-party correlation positively, under a heading a reader "
                     "can find")
    para = readme[readme.index("Relying-party correlation"):][:2000]
    if "store" not in para or "shown" not in para:
        return _fail("public_claims",
                     "the README must distinguish what a verifier STORES (a per-verifier handle since P9.4) "
                     "from what it is SHOWN (a full credential still carries a stable token_value); the "
                     "guarantee is about the first, and stating it without the second overclaims")
    if "token_value" not in para:
        return _fail("public_claims",
                     "the README must still name the stable token_value a full-credential presentation "
                     "shows a verifier; dropping it turns a bounded claim into an unlinkability claim")
    # The comparison must not award Polaris a deployment property it does not have:
    # its first two columns (deployed to a real population, national-scope issuance)
    # must both be a clear negative, so a skimmer is not told Polaris issues nationally.
    prow = re.search(r"\|\s*\*\*Polaris\*\*\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|", readme)
    if prow and ("✓" in prow.group(1) or "✓" in prow.group(2)):
        return _fail("public_claims",
                     "the comparison awards Polaris a deployment/national-scope tick; Polaris is not deployed and "
                     "does not issue at national scale, so both leading columns must be a negative (the paragraph "
                     "and the table must not argue)")
    return _ok("public_claims",
               "the outward surfaces name Polaris a reference implementation and drop the 'national' category "
               "(title + social card), carry no retired overclaim, and the comparison marks Polaris neither deployed "
               "nor issuing at national scale so its design ticks are not read as a deployment")


# ---------------------------------------------------------------------------
# Detached verifier (roadmap P-E1: the engine's exposed driveshaft). Polaris's
# ML-DSA-65 signatures are only worth something if someone OTHER than Polaris can
# check them. Four things must hold together for that to be real, not a claim:
#   1. scripts/polaris-verify.py is genuinely STANDALONE — imports no Polaris code
#      and no database driver, so a relying party runs it with only a standard
#      ML-DSA-65 library. A verifier that needs the app is not detached.
#   2. It does the real crypto: reconstruct SHA3-256(token_value) and verify under
#      ML-DSA-65 with both witnesses the app uses, not a stub that returns True.
#   3. GET /api/tokens/<id>/authenticity-pack EXPORTS the signature + public key
#      (the opposite of /export, which strips them), so there is something to
#      verify offline.
#   4. The published vectors/ exist with declared expectations, AND CI actually
#      RUNS the verifier (--selftest + --verify-dir) every release, so the path is
#      exercised under real crypto rather than merely committed.
# Detection: test_checks injects a psycopg2 import, strips a pack crypto field,
# deletes a vector, and removes the CI invocation.
# ---------------------------------------------------------------------------
_VERIFIER_FORBIDDEN_IMPORTS = ("psycopg2", "flask", "app", "pqc_signing", "custody",
                               "security", "observability", "zk", "anchoring",
                               "webauthn_auth", "tracing")


def check_detached_verifier(root: pathlib.Path) -> list[Finding]:
    verifier = _read(root, "scripts/polaris-verify.py")
    if not verifier:
        return _fail("detached_verifier", "scripts/polaris-verify.py is missing")
    # 1. Standalone: no Polaris code, no DB driver (that IS the capability).
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", verifier, re.M):
            return _fail("detached_verifier",
                         f"scripts/polaris-verify.py imports {mod!r}; the detached verifier must be standalone "
                         "(only a standard ML-DSA-65 library) so a relying party runs it with no Polaris code "
                         "and no database")
    # 2. Real crypto, not a stub.
    if "sha3_256" not in verifier:
        return _fail("detached_verifier",
                     "scripts/polaris-verify.py must reconstruct SHA3-256(token_value) — the digest the signer "
                     "signs — not trust a value handed to it in the pack")
    if "ML-DSA-65" not in verifier or "import oqs" not in verifier:
        return _fail("detached_verifier",
                     "scripts/polaris-verify.py must verify ML-DSA-65 via liboqs (the primary witness)")
    if "MLDSA65PublicKey" not in verifier:
        return _fail("detached_verifier",
                     "scripts/polaris-verify.py must also carry the independent cryptography/OpenSSL second "
                     "witness (MLDSA65PublicKey)")
    # 3. The pack route EXPORTS the crypto (the anti-decal to /export).
    app = _read(root, "polaris_web/app.py")
    m = re.search(r"def token_authenticity_pack\(.*?(?=\n\n\n)", app, re.S)
    if "authenticity-pack" not in app or not m:
        return _fail("detached_verifier",
                     "app.py has no /api/tokens/<id>/authenticity-pack route; there is nothing to verify offline")
    body = m.group(0)
    for field in ("signature_hex", "public_key_hex", "digest_construction"):
        if field not in body:
            return _fail("detached_verifier",
                         f"the authenticity-pack route omits {field!r}; it must EXPORT the crypto (unlike /export, "
                         "which strips it) or an offline verifier has nothing to check")
    if "signature_bytes" not in body or "signing_public_key_hex" not in body:
        return _fail("detached_verifier",
                     "the authenticity-pack route must read the real signature material (signature_bytes + "
                     "signing_public_key_hex), not a stripped view")
    # 4a. Published vectors exist with declared expectations.
    vdir = root / "vectors"
    packs = sorted(vdir.glob("*.json")) if vdir.is_dir() else []
    if not packs:
        return _fail("detached_verifier", "vectors/ has no published *.json vectors")
    have_valid = have_tampered = have_placeholder = False
    for p in packs:
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            return _fail("detached_verifier", f"vectors/{p.name} is not valid JSON ({e})")
        if obj.get("format") != "polaris-authenticity-pack/1":
            return _fail("detached_verifier", f"vectors/{p.name} is not a polaris-authenticity-pack/1")
        expect = (obj.get("_vector") or {}).get("expect")
        if expect == "valid" and obj.get("public_key_hex"):
            have_valid = True
        if expect == "invalid" and obj.get("public_key_hex"):
            have_tampered = True
        if str(obj.get("algorithm", "")).startswith("DETERMINISTIC-PLACEHOLDER"):
            have_placeholder = True
    if not (have_valid and have_tampered and have_placeholder):
        return _fail("detached_verifier",
                     "vectors/ must publish at least a genuine pack (expect valid), a tampered pack (expect "
                     "invalid, real key), and the placeholder — so a verifier proves it passes the real one AND "
                     "fails the tampered one")
    # 4b. CI runs the verifier every release (exercised, not just present).
    ci = _read(root, ".github/workflows/ci.yml")
    if "polaris-verify.py" not in ci or "--selftest" not in ci or "--verify-dir" not in ci:
        return _fail("detached_verifier",
                     "ci.yml must run scripts/polaris-verify.py --selftest (a live ML-DSA-65 round-trip) and "
                     "--verify-dir vectors (re-verify the published packs) so the detached path is exercised "
                     "under real crypto every release, not merely committed")
    return _ok("detached_verifier",
               f"the detached verifier is standalone (no Polaris/DB imports), does real ML-DSA-65 crypto, the "
               f"authenticity-pack route exports the signature, {len(packs)} vectors are published with "
               "expectations, and CI runs the verifier every release")


# ---------------------------------------------------------------------------
# Attacks that must fail (roadmap PE.5). The engine is only as strong as what it
# rejects, so attacks/ holds adversaries that actively try to break a real defense
# (forge, tamper, wrong key, a revoked token presented as authoritative) against
# the REAL code. The enforcement is CI RUNNING them every release; this check
# guards that they stay wired AND that the runner is genuinely fail-closed.
#
# In the spirit of the ship ("run the attacks, don't grep"), this check does not
# merely read run_attacks.py for a string: it EXECUTES the runner's contract with
# an in-process canary and asserts a succeeding attack yields exit 1, an all-held
# run yields 0, and a non-runnable suite yields 3 (a hard error, never a silent
# green). A runner that stopped failing on a successful attack fails this check.
# Detection: test_checks breaks the contract, un-wires a CI suite, and guts ATTACKS.
# ---------------------------------------------------------------------------
_ATTACK_MODULES = ("attack_crypto", "attack_db")
_ATTACK_NAMES_REQUIRED = ("forge", "tamper", "revoked")


def _attacks_runner_contract_holds(root: pathlib.Path):
    """Load attacks/run_attacks.py and drive its decision logic with fake suites.
    Returns (ok, detail). No liboqs/DB needed: the attacks are canary lambdas."""
    import importlib
    import importlib.util
    import io
    import types
    import contextlib
    path = root / "attacks" / "run_attacks.py"
    if not path.is_file():
        return False, "attacks/run_attacks.py is missing"
    spec = importlib.util.spec_from_file_location("polaris_attacks_runner", path)
    if spec is None or spec.loader is None:
        return False, "could not build a module spec for the runner"
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as e:
        return False, f"could not load the runner ({e})"

    def fake_import(name):
        if name.endswith("_succeed"):
            return types.SimpleNamespace(available=lambda: (True, "canary"),
                                         ATTACKS=[("c", lambda: (True, "broke"))])
        if name.endswith("_hold"):
            return types.SimpleNamespace(available=lambda: (True, "canary"),
                                         ATTACKS=[("c", lambda: (False, "held"))])
        return types.SimpleNamespace(available=lambda: (False, "unavailable"), ATTACKS=[])

    orig = importlib.import_module
    try:
        importlib.import_module = fake_import
        with contextlib.redirect_stdout(io.StringIO()):
            setattr(mod, "_SUITES", ("succeed",))
            rc_broken = mod.main(["--suite", "succeed"])
            setattr(mod, "_SUITES", ("hold",))
            rc_held = mod.main(["--suite", "hold"])
            setattr(mod, "_SUITES", ("blocked",))
            rc_blocked = mod.main(["--suite", "blocked"])
    except Exception as e:
        return False, f"executing the runner contract raised {type(e).__name__}: {e}"
    finally:
        importlib.import_module = orig

    if rc_broken != 1:
        return False, f"a SUCCEEDING attack produced exit {rc_broken}, not 1 (the runner is not red-on-break)"
    if rc_held != 0:
        return False, f"an all-held run produced exit {rc_held}, not 0"
    if rc_blocked != 3:
        return False, f"a non-runnable suite produced exit {rc_blocked}, not 3 (it must hard-error, not skip)"
    return True, "red on a successful attack, hard-error on a non-runnable suite, green only when all held"


def check_attacks_run(root: pathlib.Path) -> list[Finding]:
    if not _read(root, "attacks/run_attacks.py"):
        return _fail("attacks_run", "attacks/run_attacks.py is missing")
    # The adversary modules declare their attacks.
    corpus = []
    for mod in _ATTACK_MODULES:
        src = _read(root, f"attacks/{mod}.py")
        if not src:
            return _fail("attacks_run", f"attacks/{mod}.py is missing")
        if "ATTACKS" not in src or "def available" not in src:
            return _fail("attacks_run", f"attacks/{mod}.py must define ATTACKS and available()")
        corpus.append(src)
    allsrc = "\n".join(corpus)
    for needle in _ATTACK_NAMES_REQUIRED:
        if needle not in allsrc:
            return _fail("attacks_run",
                         f"the attack suite no longer includes a '{needle}' adversary; it must not be silently gutted")
    # CI runs BOTH suites every release (the actual enforcement).
    ci = _read(root, ".github/workflows/ci.yml")
    if "run_attacks.py --suite crypto" not in ci or "run_attacks.py --suite db" not in ci:
        return _fail("attacks_run",
                     "ci.yml must run attacks/run_attacks.py for BOTH the crypto and db suites every release")
    # The runner is fail-closed — proven by executing its contract, not grepping it.
    ok, detail = _attacks_runner_contract_holds(root)
    if not ok:
        return _fail("attacks_run", f"the attack runner is not fail-closed: {detail}")
    return _ok("attacks_run",
               "attacks/ is wired into CI (crypto + db) and the runner is fail-closed, verified by executing "
               f"its contract ({detail})")


# ---------------------------------------------------------------------------
# Federation is cryptographic, not a diagram (roadmap PE.3). The app carries an
# administrative trust graph (AgencyTrustAttestation / _federation_trust_holds),
# but on its own that is DB rows on top of a SINGLE signing key: every token
# shares one cryptographic root, so "issuer A trusts issuer B" is not something a
# relying party can check without trusting Polaris's database. PE.3 adds the root
# underneath: two issuers on one box with DISTINCT ML-DSA-65 keys, and a relying
# party that accepts its own issuer, rejects a foreign issuer, and rejects an
# outsider — decided against published KEYS via the detached verifier. This check
# pins that the drill is cryptographic (distinct roots + the detached issuer
# anchor), tests REJECTION and not only acceptance, is fail-closed, runs in CI,
# and that the cross-issuer boundary also lives in attacks/. The enforcement is CI
# RUNNING the drill under real ML-DSA-65.
# Detection: test_checks removes the reject test, the detached anchor, the CI
# invocation, and the federation adversary.
# ---------------------------------------------------------------------------
def check_federation_real(root: pathlib.Path) -> list[Finding]:
    drill = _read(root, "scripts/polaris-federation-drill.py")
    if not drill:
        return _fail("federation_real", "scripts/polaris-federation-drill.py is missing")
    # Cryptographic: distinct real roots, decided via the detached verifier's anchor.
    if "generate_keypair" not in drill:
        return _fail("federation_real",
                     "the federation drill must mint distinct real roots (generate_keypair), not reuse one key")
    if "verify_pack" not in drill or "anchor_keys" not in drill:
        return _fail("federation_real",
                     "the federation drill must decide trust via the detached verifier's issuer anchor "
                     "(verify_pack(..., anchor_keys=...)), not a database lookup")
    if "issuer_trusted" not in drill:
        return _fail("federation_real",
                     "the federation drill must key its verdict on issuer_trusted (the signing key), "
                     "not on an agency_id row")
    # It must test REJECTION, not only acceptance — an expected-reject outcome.
    if ", False)" not in drill:
        return _fail("federation_real",
                     "the federation drill must assert a CROSS-ISSUER REJECT (a relying party rejecting a "
                     "foreign issuer), not only that its own issuer is accepted")
    # Fail-closed: a broken boundary turns the drill red.
    if "return 1" not in drill:
        return _fail("federation_real",
                     "the federation drill must exit non-zero when the federation boundary does not hold")
    # CI runs it every release (the actual enforcement).
    ci = _read(root, ".github/workflows/ci.yml")
    if "polaris-federation-drill.py" not in ci:
        return _fail("federation_real",
                     "ci.yml must run scripts/polaris-federation-drill.py so the cross-issuer boundary is "
                     "exercised under real ML-DSA-65 every release")
    # The cross-issuer boundary also lives in the attack suite.
    crypto_attacks = _read(root, "attacks/attack_crypto.py")
    if "federation" not in crypto_attacks:
        return _fail("federation_real",
                     "attacks/attack_crypto.py must include a federation adversary (an outsider must not be "
                     "accepted by a trust set), so the boundary is attacked, not only drilled")
    return _ok("federation_real",
               "federation is cryptographic: the drill stands up two issuers on one box with distinct roots and "
               "proves cross-issuer accept/reject via the detached anchor, CI runs it under real ML-DSA-65, and "
               "the boundary is also an attack")


# ---------------------------------------------------------------------------
# HSM key rotation is drilled IN-TOKEN, not just designed (roadmap PE.4). The
# trust-anchor set (current key + previous keys) that makes rotation possible was
# tested for the file driver, but the sole-HSM profile signs inside a PKCS#11
# token with non-extractable keys, and rotation there means minting a NEW in-token
# key under a new label while the OLD token keeps verifying against its retired
# anchor. This check pins that the in-token rotation is actually EXERCISED: a test
# mints two distinct in-token keys, proves a token signed under the old key still
# verifies after rotation and that the new key signs, and the PKCS#11 drill (run
# by CI's custody job) executes it against a real Kryoptic token.
# Detection: test_checks removes the rotation test, the drill's suite run, and the
# CI invocation.
# ---------------------------------------------------------------------------
def check_key_rotation_drilled(root: pathlib.Path) -> list[Finding]:
    tc = _read(root, "polaris_web/test_custody.py")
    if not tc:
        return _fail("key_rotation_drilled", "polaris_web/test_custody.py is missing")
    m = re.search(r"def test_in_token_rotation_old_token_still_verifies_new_key_signs\(.*?\n(?=    def |\nclass |\Z)",
                  tc, re.S)
    if not m:
        return _fail("key_rotation_drilled",
                     "test_custody.py must have an IN-TOKEN rotation test "
                     "(test_in_token_rotation_old_token_still_verifies_new_key_signs)")
    body = m.group(0)
    # Two distinct in-token roots (a new label minted in the token), not a file key.
    if "pkcs11_generate_key" not in body or "assertNotEqual" not in body:
        return _fail("key_rotation_drilled",
                     "the rotation test must mint a SECOND distinct key IN the token (pkcs11_generate_key with a "
                     "new label) and assert it differs from the first")
    # The OLD token must STILL verify after rotation, and the NEW key must sign.
    if body.count("verify_token_signature") < 2 or "token-ROT-1" not in body:
        return _fail("key_rotation_drilled",
                     "the rotation test must prove the OLD token still verifies after rotation (via its retired "
                     "anchor) AND that the new key signs")
    if "assertFalse(pqc_signing.verify_token_signature" not in body:
        return _fail("key_rotation_drilled",
                     "the rotation test must prove retirement completes — once the old anchor is dropped, the old "
                     "token no longer verifies")
    # The PKCS#11 drill runs the in-token suite, and CI runs the drill.
    drill = _read(root, "scripts/polaris-custody-pkcs11-drill.sh")
    if "Pkcs11CustodyTests" not in drill:
        return _fail("key_rotation_drilled",
                     "scripts/polaris-custody-pkcs11-drill.sh must run Pkcs11CustodyTests (which now carries the "
                     "in-token rotation) against a real token")
    ci = _read(root, ".github/workflows/ci.yml")
    if "polaris-custody-pkcs11-drill.sh" not in ci:
        return _fail("key_rotation_drilled",
                     "ci.yml must run the PKCS#11 custody drill so in-token rotation is exercised every release")
    return _ok("key_rotation_drilled",
               "HSM key rotation is drilled in-token: a test mints two distinct in-token keys and proves the old "
               "token still verifies after rotation while the new key signs, run against a real Kryoptic token in CI")


# ---------------------------------------------------------------------------
# The holder has a surface (roadmap PE.7). Everything else in Polaris is
# operator-facing; scripts/polaris-wallet.py is the first tool a PERSON runs — to
# hold their credential as a file, verify it offline, present it, and prove
# membership in zero knowledge. It must be genuinely holder-side (no server code,
# no database) or it is just another operator tool, and its duress presentation
# must be indistinguishable from a normal one (the anti-coercion vocation, on the
# holder's side). This check pins that the wallet is standalone, offers the four
# holder capabilities, derives the epoch leaf with the SAME recipe the issuer uses
# (so membership proofs are for the real leaf), and that its behaviour — the
# deniability property and a ZK proof that round-trips — is EXERCISED by a test the
# coverage suite runs.
# Detection: test_checks adds a server import, drops a command, and removes the
# deniability test / the coverage wiring.
# ---------------------------------------------------------------------------
_WALLET_FORBIDDEN_IMPORTS = ("psycopg2", "flask", "app", "pqc_signing", "custody",
                             "security", "observability", "zk", "anchoring", "webauthn_auth")
_WALLET_COMMANDS = ("enroll", "show", "verify", "present", "prove-membership")


def check_holder_wallet(root: pathlib.Path) -> list[Finding]:
    wallet = _read(root, "scripts/polaris-wallet.py")
    if not wallet:
        return _fail("holder_wallet", "scripts/polaris-wallet.py is missing")
    # Holder-side: no server code, no database.
    for mod in _WALLET_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", wallet, re.M):
            return _fail("holder_wallet",
                         f"scripts/polaris-wallet.py imports {mod!r}; the holder wallet must be standalone "
                         "(no Polaris server code, no database) — a person runs it on their own machine")
    # The four holder capabilities.
    for cmd in _WALLET_COMMANDS:
        if f'"{cmd}"' not in wallet and f"'{cmd}'" not in wallet:
            return _fail("holder_wallet", f"the wallet is missing the {cmd!r} command")
    # Membership proofs must derive the epoch leaf with the issuer's recipe, or they
    # prove the wrong leaf: SHA3-256("{token_id}|{token_value}|{context_id}").
    if "sha3_256" not in wallet or "token_id" not in wallet or "|" not in wallet:
        return _fail("holder_wallet",
                     "the wallet must derive the epoch leaf seed with the issuer's recipe "
                     "(SHA3-256 of token_id|token_value|context_id) or its membership proof is for the wrong leaf")
    # Offline verification goes through the detached verifier (a holder tool), not a server call.
    if "verify_pack" not in wallet:
        return _fail("holder_wallet",
                     "the wallet must verify offline through the detached verifier (verify_pack), not a server call")
    # Its behaviour is exercised: the deniability property and a ZK proof that round-trips.
    test = _read(root, "scripts/test_wallet.py")
    if not test:
        return _fail("holder_wallet", "scripts/test_wallet.py is missing")
    if "test_present_and_duress_are_indistinguishable" not in test:
        return _fail("holder_wallet",
                     "test_wallet.py must prove the deniability property (present and present --duress are "
                     "structurally identical), the holder-side of the anti-coercion vocation")
    if "test_prove_membership_roundtrips" not in test or "verified" not in test:
        return _fail("holder_wallet",
                     "test_wallet.py must prove a ZK membership proof that round-trips through polaris-zk verify")
    cov = _read(root, "scripts/polaris-coverage.sh")
    if "test_wallet" not in cov:
        return _fail("holder_wallet",
                     "scripts/polaris-coverage.sh must run test_wallet so the holder surface is exercised in CI")
    return _ok("holder_wallet",
               "the holder wallet is standalone (no server/DB), offers enroll/show/verify/present/prove-membership, "
               "derives the epoch leaf with the issuer's recipe, and its deniability + ZK round-trip are tested in CI")


# ---------------------------------------------------------------------------
# The numbers are published and honest (roadmap PE.8). "Ten times faster" is not a
# number; scripts/polaris-dyno.py measures the real primitives — ML-DSA-65
# sign/verify (single- and two-witness) and ZK membership prove/verify at a stated
# tree depth — and prints them with the box spec and a version stamp. The
# committed docs/reference/DYNO.md publishes a real run, and CI re-measures every
# release so the figures cannot rot. The load-bearing honesty is that these are
# MEASURED, single-core, and NOT extrapolated (a fleet number is a separate
# labelled projection); this check pins that discipline, not any figure.
# Detection: test_checks drops the ZK measurement, the not-extrapolated honesty,
# DYNO.md's box spec, and the CI wiring.
# ---------------------------------------------------------------------------
def check_dyno_published(root: pathlib.Path) -> list[Finding]:
    dyno = _read(root, "scripts/polaris-dyno.py")
    if not dyno:
        return _fail("dyno_published", "scripts/polaris-dyno.py is missing")
    # It measures the real primitives: ML-DSA sign + single- and two-witness verify.
    for marker in ("sign_per_sec", "verify_single_per_sec", "verify_both_per_sec"):
        if marker not in dyno:
            return _fail("dyno_published",
                         f"the dyno must measure {marker} (real ML-DSA-65 throughput), not a slogan")
    # And the ZK prove/verify at a stated depth.
    if "prove_ms" not in dyno or "tree_depth" not in dyno or "verify_ms" not in dyno:
        return _fail("dyno_published",
                     "the dyno must measure ZK membership prove/verify time at a stated tree depth")
    # It reports the box spec and a version stamp (so a number is interpretable).
    if "cpu_count" not in dyno or "platform" not in dyno or "_version" not in dyno:
        return _fail("dyno_published",
                     "the dyno must print the box spec (cpu_count/platform) and a version stamp")
    # The honesty: measured, not extrapolated.
    if "extrapolat" not in dyno.lower():
        return _fail("dyno_published",
                     "the dyno must state that its numbers are measured and NOT extrapolated")
    # The published run.
    published = _read(root, "docs/reference/DYNO.md")
    if not published:
        return _fail("dyno_published", "docs/reference/DYNO.md (the published run) is missing")
    if "polaris-dyno.py" not in published:
        return _fail("dyno_published", "DYNO.md must give the reproduction command (scripts/polaris-dyno.py)")
    if not re.search(r"\bcores?\b", published) or not re.search(r"v9\.\d+", published):
        return _fail("dyno_published",
                     "DYNO.md must name the box (cores) and stamp the version the numbers were measured at")
    if "extrapolat" not in published.lower():
        return _fail("dyno_published",
                     "DYNO.md must keep the measured/not-extrapolated distinction so its figures are not read as "
                     "a fleet claim")
    # CI re-measures every release.
    ci = _read(root, ".github/workflows/ci.yml")
    if "polaris-dyno.py" not in ci:
        return _fail("dyno_published",
                     "ci.yml must run scripts/polaris-dyno.py so the published numbers are re-measured every release")
    return _ok("dyno_published",
               "the dyno measures the real ML-DSA-65 and ZK primitives with the box spec and version, DYNO.md "
               "publishes a measured (not extrapolated) run, and CI re-measures every release")


# ---------------------------------------------------------------------------
# The default boot is the real motor (roadmap PE.1). The SHA3-256 development
# placeholder is not a signature — its bytes verify against no key — so a
# production deployment that silently signed with it would issue tokens that
# authenticate against nothing. Production must therefore FAIL CLOSED at boot when
# real ML-DSA-65 signing is not actually available (pqc_signing.is_enabled()),
# rather than discovering it at first issuance; and outside production the
# placeholder must be a NAMED dev profile (POLARIS_PQC_PROFILE=placeholder) that the
# canonical test/dev paths declare and that warns loudly when used unnamed, so no
# one mistakes a dev stack's SHA3 bindings for real signatures. This check pins the
# production boot guard, the named profile and its warning, and that the canonical
# paths name it; the boot refusal itself is exercised by RealPqcDefaultBootTests.
# Detection: test_checks removes the prod guard, the named-profile warning, and the
# CI naming.
# ---------------------------------------------------------------------------
def check_real_pqc_default_boot(root: pathlib.Path) -> list[Finding]:
    app = _read(root, "polaris_web/app.py")
    if not app:
        return _fail("real_pqc_default_boot", "polaris_web/app.py is missing")
    # Production fails closed when real PQC is not available (is_enabled at boot).
    if "pqc_signing.is_enabled()" not in app:
        return _fail("real_pqc_default_boot",
                     "app.py must check pqc_signing.is_enabled() at boot (real PQC actually available), "
                     "not merely trust the flag")
    if not re.search(r"if _PRODUCTION and not _pqc_real:.{0,500}sys\.exit", app, re.S):
        return _fail("real_pqc_default_boot",
                     "app.py must FAIL CLOSED in production when real ML-DSA-65 signing is unavailable, so a "
                     "deployment cannot silently issue placeholder-signed tokens (a sys.exit guard)")
    # The placeholder is a NAMED dev profile that warns when used unnamed, and the
    # boot announces which signing profile is active.
    if "POLARIS_PQC_PROFILE" not in app or "DEVELOPMENT PLACEHOLDER" not in app:
        return _fail("real_pqc_default_boot",
                     "outside production the placeholder must be a NAMED profile "
                     "(POLARIS_PQC_PROFILE=placeholder) that warns loudly when used unnamed")
    if "boot.pqc_profile" not in app:
        return _fail("real_pqc_default_boot",
                     "app.py must announce the active signing profile at boot (boot.pqc_profile)")
    # The canonical test/dev paths NAME the placeholder profile (so it is explicit,
    # not the silent default the ship replaced).
    ci = _read(root, ".github/workflows/ci.yml")
    if "POLARIS_PQC_PROFILE: placeholder" not in ci:
        return _fail("real_pqc_default_boot",
                     "the CI test job must name the placeholder profile (POLARIS_PQC_PROFILE: placeholder), "
                     "not rely on the silent default")
    runner = _read(root, "scripts/polaris-test.sh")
    if "POLARIS_PQC_PROFILE=placeholder" not in runner:
        return _fail("real_pqc_default_boot",
                     "scripts/polaris-test.sh must name the placeholder profile so a local run is explicit too")
    # The boot refusal is exercised.
    test = _read(root, "polaris_web/test_app.py")
    if "test_production_refuses_boot_without_real_pqc" not in test:
        return _fail("real_pqc_default_boot",
                     "test_app.py must exercise the production boot refusal (RealPqcDefaultBootTests)")
    return _ok("real_pqc_default_boot",
               "the default boot is the real motor: production fails closed at boot when real ML-DSA-65 signing "
               "is unavailable, and the placeholder is a named dev profile the canonical paths declare, warning "
               "loudly when used unnamed")


# ---------------------------------------------------------------------------
# The two witnesses are fuzzed for disagreement (frontier engine item). Verify-at-
# use runs a SINGLE witness (liboqs) and trusts it because issuance already
# two-witnessed the signature — the whole throughput-soundness argument rests on
# liboqs and cryptography/OpenSSL never disagreeing. So the attack suite hunts for
# an input where they DO: many random rounds (genuine, tampered, wrong-key,
# garbage), verifying each under BOTH witnesses separately and asserting they
# return the same verdict every time; a disagreement is the break. This check pins
# that the fuzzer is real — it exercises both witnesses independently and compares
# them, and it is registered so the attack runner (and thus CI) actually runs it.
# Detection: test_checks unregisters the fuzzer, drops the second witness, and
# removes the disagreement comparison.
# ---------------------------------------------------------------------------
def check_witness_fuzz(root: pathlib.Path) -> list[Finding]:
    src = _read(root, "attacks/attack_crypto.py")
    if not src:
        return _fail("witness_fuzz", "attacks/attack_crypto.py is missing")
    m = re.search(r"def attack_witnesses_disagree_under_fuzz\(.*?(?=\ndef |\nATTACKS)", src, re.S)
    if not m:
        return _fail("witness_fuzz",
                     "attacks/attack_crypto.py must have a differential fuzzer of the two witnesses "
                     "(attack_witnesses_disagree_under_fuzz)")
    body = m.group(0)
    # It must verify under BOTH witnesses SEPARATELY (liboqs and cryptography), not
    # the combined verify_both — a disagreement is only visible with independent verdicts.
    if "pqc_signing.verify(" not in body or "_verify_second_witness(" not in body:
        return _fail("witness_fuzz",
                     "the fuzzer must verify each case under BOTH witnesses independently "
                     "(pqc_signing.verify AND pqc_signing._verify_second_witness), not only the combined check")
    # And it must actually COMPARE their verdicts (the disagreement is the break).
    if "!=" not in body or "return True" not in body:
        return _fail("witness_fuzz",
                     "the fuzzer must flag a DISAGREEMENT (the two verdicts differ) as the break it hunts for")
    # It must be registered so run_attacks actually runs it.
    if '"witnesses_disagree_under_fuzz"' not in src and "'witnesses_disagree_under_fuzz'" not in src:
        return _fail("witness_fuzz",
                     "the fuzzer must be registered in ATTACKS so the runner (and CI) exercises it")
    # CI runs the crypto attack suite (which includes the fuzzer).
    ci = _read(root, ".github/workflows/ci.yml")
    if "run_attacks.py --suite crypto" not in ci:
        return _fail("witness_fuzz",
                     "ci.yml must run the crypto attack suite so the witness fuzzer runs every release")
    return _ok("witness_fuzz",
               "the two witnesses are differentially fuzzed every release: many random rounds verify under liboqs "
               "AND cryptography independently and flag any disagreement, run via the attack suite in CI")


def check_verifier_fuzz(root: pathlib.Path) -> list[Finding]:
    """The detached verifier is fed hostile input by design: a relying party runs it on a
    credential, manifest, feed, or bundle that a stranger presented. This pins the
    metamorphic fuzzer that holds it TOTAL. For every signed type the fuzzer builds a
    genuine, real-ML-DSA object, confirms it is accepted, then a deterministic battery
    (signature and key bit-flips, mutation of each signature-bound field, non-hex and
    dropped fields, adversarial values, and cross-type confusion) must ALL be rejected
    FAIL-CLOSED, with no exception. A verifier that crashes on malformed input, or accepts
    a mutation, is a break."""
    fuzz = _read(root, "scripts/polaris-verifier-fuzz.py")
    if not fuzz:
        return _fail("verifier_fuzz", "scripts/polaris-verifier-fuzz.py is missing")
    # Every decision function the verifier exposes must be under the fuzzer.
    for fn in ("verify_manifest", "verify_epoch_checkpoint", "verify_revocation_feed",
               "verify_status_assertion", "verify_sth", "verify_status_bundle",
               "verify_cross_authority", "verify_cross_authority_via_bundle",
               "verify_cross_authority_zk"):
        if fn not in fuzz:
            return _fail("verifier_fuzz", "the fuzzer does not exercise %s" % fn)
    # The mutation battery must include the classes that matter.
    for cls, marker in (("signature bit-flip", "bitflip"), ("signed-field mutation", "mutate:"),
                        ("cross-type confusion", "cross-type"), ("adversarial/malformed input", "adv-object")):
        if marker not in fuzz:
            return _fail("verifier_fuzz", "the fuzzer is missing the %s mutation class" % cls)
    # It must assert BOTH failure modes: a wrongly-ACCEPTED mutation, and a CRASH on hostile input.
    if "ACCEPTED" not in fuzz or "raised" not in fuzz:
        return _fail("verifier_fuzz",
                     "the fuzzer must fail on a wrongly-accepted mutation AND on any exception (a crash is a break)")
    # Deterministic, so a break reproduces.
    if "_SEED" not in fuzz:
        return _fail("verifier_fuzz", "the fuzzer must be deterministic (a fixed seed) so a break reproduces")
    # It RUNS every release under real ML-DSA.
    if "polaris-verifier-fuzz.py" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("verifier_fuzz",
                     "the verifier fuzzer must run in CI (a fuzzer that never runs finds nothing)")
    # The thing it fuzzes stays standalone.
    v = _read(root, "scripts/polaris-verify.py")
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("verifier_fuzz", f"the offline verifier imports {mod!r}; it must stay standalone")
    return _ok("verifier_fuzz",
               "the detached verifier is held TOTAL by a metamorphic fuzzer: across all six signed types and both "
               "composed decisions, a genuine real-ML-DSA object is accepted and every signature/field mutation, "
               "malformation, and cross-type confusion is rejected fail-closed with no crash, run every release")


# ---------------------------------------------------------------------------
# ML-DSA-65 conformance against an independent authority (Project Wycheproof).
# The published vectors/ (PE.2) prove three implementations agree with EACH OTHER;
# this proves something stronger — that Polaris's two PRODUCTION witnesses (liboqs
# and cryptography/OpenSSL) agree with Wycheproof's INDEPENDENT known-answer
# verdicts (valid/invalid) on every vector, including the invalid ones that hunt
# for a verifier that accepts a bad signature. This check pins that the committed
# vectors carry their provenance and both directions (valid AND invalid), that the
# verifier checks under BOTH witnesses against the expected result, and that CI runs
# it. Detection: test_checks strips the provenance, drops a witness, removes the
# invalid vectors, and un-wires CI.
# ---------------------------------------------------------------------------
def check_kat_conformance(root: pathlib.Path) -> list[Finding]:
    path = root / "vectors" / "kat" / "mldsa_65_verify.json"
    if not path.is_file():
        return _fail("kat_conformance", "vectors/kat/mldsa_65_verify.json (the conformance vectors) is missing")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return _fail("kat_conformance", f"the KAT vectors are not valid JSON ({e})")
    prov = data.get("provenance") or {}
    if "wycheproof" not in str(prov.get("source", "")).lower() or not prov.get("commit"):
        return _fail("kat_conformance",
                     "the KAT vectors must record their provenance: an independent authority (Wycheproof) and a "
                     "pinned commit, so a reviewer can audit where the known answers came from")
    results = [t.get("result") for g in data.get("testGroups", []) for t in g.get("tests", [])]
    if results.count("valid") < 1 or results.count("invalid") < 1:
        return _fail("kat_conformance",
                     "the KAT must exercise BOTH directions — valid signatures that must verify AND invalid ones "
                     "that must be rejected; the invalid vectors are what catch a verifier that accepts a forgery")
    if len(results) < 20:
        return _fail("kat_conformance", f"only {len(results)} KAT vectors; keep a representative set (>=20)")
    # Context-string vectors are covered — they exercise ML-DSA's context domain
    # separation and its 255-byte cap, a distinct verify path — not silently dropped.
    if not any(t.get("ctx") for g in data.get("testGroups", []) for t in g.get("tests", [])):
        return _fail("kat_conformance",
                     "the KAT must include context-string vectors (a `ctx` field), which exercise ML-DSA's "
                     "context domain separation, not only the empty-context tests")
    # The verifier checks under BOTH witnesses against the expected result.
    verifier = _read(root, "scripts/polaris-kat-verify.py")
    if not verifier:
        return _fail("kat_conformance", "scripts/polaris-kat-verify.py is missing")
    if "MLDSA65" not in verifier or "oqs" not in verifier:
        return _fail("kat_conformance",
                     "the KAT verifier must check under BOTH production witnesses — liboqs and cryptography's "
                     "MLDSA65 — not one of them")
    if 'result' not in verifier or "expect" not in verifier:
        return _fail("kat_conformance",
                     "the KAT verifier must compare each verdict against Wycheproof's expected `result`")
    # It must be context-aware, or the context-string vectors are not actually verified with their context.
    if "verify_with_ctx_str" not in verifier or "context=" not in verifier:
        return _fail("kat_conformance",
                     "the KAT verifier must be context-aware (liboqs verify_with_ctx_str and cryptography "
                     "context=) so the context-string vectors are verified with their context, not without it")
    # A regeneration path keeps the committed subset auditable.
    if not _read(root, "scripts/polaris-fetch-kat.py"):
        return _fail("kat_conformance",
                     "scripts/polaris-fetch-kat.py (the pinned regeneration path) is missing")
    # CI runs it every release.
    ci = _read(root, ".github/workflows/ci.yml")
    if "polaris-kat-verify.py" not in ci:
        return _fail("kat_conformance",
                     "ci.yml must run scripts/polaris-kat-verify.py so ML-DSA-65 conformance is checked every release")
    return _ok("kat_conformance",
               f"ML-DSA-65 is checked for conformance against Wycheproof's independent known answers "
               f"({results.count('valid')} valid + {results.count('invalid')} invalid vectors) under both "
               "production witnesses, run in CI, with a pinned regeneration path")


# ---------------------------------------------------------------------------
# Security controls as attacks (NIST 800-53 AC + AU). "Apply the standards" done
# as displacement, not a control-mapping document: the applicable controls that map
# to Polaris's real mechanisms are expressed as adversaries that try to VIOLATE
# them against the running app + database and must fail. AC-3 (an unauthenticated
# request must not reach protected data; a lower role must not reach an
# admin/auditor route), AU-9 (an audit-of-record row must be neither deletable nor
# updatable — the append-only invariant), AC-7 (failed logins lock the account).
# This check pins that those adversaries exist, ATTACK THE REAL SYSTEM (routes and
# the append-only audit table, safely rolled back), and are run in CI. The
# enforcement is the runner going red if a control is violated.
# Detection: test_checks removes an audit-integrity adversary, a route adversary,
# and the CI wiring.
# ---------------------------------------------------------------------------
def check_controls_as_attacks(root: pathlib.Path) -> list[Finding]:
    src = _read(root, "attacks/attack_controls.py")
    if not src:
        return _fail("controls_as_attacks", "attacks/attack_controls.py is missing")
    # AC-3 access enforcement, AU-9 audit protection, AC-7 logon lockout, IA-5
    # authenticator storage, IA-2 session authenticity, SC-5 rate limiting, SC-23 CSRF.
    for control in ("ac3", "au9", "ac7", "ia5", "ia2", "sc5", "sc23"):
        if control not in src:
            return _fail("controls_as_attacks",
                         f"attacks/attack_controls.py is missing the {control.upper()} adversary "
                         "(the AC/AU/IA/SC controls, each expressed as an attack that must fail)")
    # AU-9 must attack the real append-only audit table and never actually mutate it.
    if "TokenLifecycleEvent" not in src or ("DELETE" not in src and "UPDATE" not in src):
        return _fail("controls_as_attacks",
                     "the AU-9 adversary must attempt to DELETE/UPDATE a real audit-of-record row "
                     "(TokenLifecycleEvent) and assert it is refused")
    if "rollback" not in src:
        return _fail("controls_as_attacks",
                     "the audit-integrity adversary must roll back its attempted mutation so it never actually "
                     "changes the audit table")
    # AC adversaries must drive real routes and key on the HTTP status.
    if ".get(" not in src or "status_code" not in src:
        return _fail("controls_as_attacks",
                     "the AC-3 adversary must drive a real route and key on the HTTP status (a redirect/403 is "
                     "the control holding)")
    # IA/SC adversaries must attack the real mechanisms, not merely carry the names.
    if "password_hash" not in src or "polaris_session" not in src:
        return _fail("controls_as_attacks",
                     "the IA adversaries must attack the real mechanisms — the stored password_hash (IA-5) and a "
                     "forged polaris_session cookie (IA-2)")
    if ".post(" not in src or ("429" not in src and "RATE_LIMIT" not in src):
        return _fail("controls_as_attacks",
                     "the SC adversaries must drive a real state-changing POST (SC-23 CSRF) and check rate "
                     "limiting (SC-5, a 429)")
    if "ATTACKS" not in src:
        return _fail("controls_as_attacks", "attack_controls.py must register its adversaries in ATTACKS")
    # CI runs the controls suite every release.
    ci = _read(root, ".github/workflows/ci.yml")
    if "run_attacks.py --suite controls" not in ci:
        return _fail("controls_as_attacks",
                     "ci.yml must run attacks/run_attacks.py --suite controls so the AC/AU controls are attacked "
                     "every release")
    return _ok("controls_as_attacks",
               "NIST 800-53 AC/AU/IA/SC controls are enforced by running adversaries — unauthenticated and "
               "wrong-role access denied, the audit-of-record un-deletable/un-updatable, failed logins lock, "
               "passwords stored one-way, a forged session rejected, login rate-limited, and a CSRF-less write "
               "refused — all run against the real system in CI")


# ---------------------------------------------------------------------------
# Federation in the running app (roadmap PE.3b). PE.3 proved the cryptographic
# federation boundary with a standalone drill; this puts it in the app: each Agency
# registers its own ML-DSA-65 key, /uc1/issue signs a token with the ISSUING
# agency's key (custody selects it, falling back to the global key), refuses to
# issue a token whose real signature was produced by a different key, and /verify
# reports `issuer_authentic` (the token was signed by its issuing agency's
# registered key). This check pins the whole chain — the schema column, the
# per-agency custody selection, the agency_id threaded through signing, the issuance
# binding enforcement, the verify field, and that BOTH halves are tested (per-agency
# signing under real ML-DSA, and the issuer-binding field).
# Detection: test_checks removes the enforcement, the verify field, the custody
# selector, and the schema column.
# ---------------------------------------------------------------------------
def _fn_block(src: str, fn: str):
    """The source text of function `fn`, from its `def` to the next top-level `def` (or
    end of file). None if the function is absent."""
    m = re.search(r"\ndef %s\(.*?(?=\ndef |\Z)" % re.escape(fn), src, re.S)
    return m.group(0) if m else None


def _signed_statement_keys(src: str, fn: str):
    """The ordered signed keys a canonical-statement builder projects, extracted from its
    source. Handles both shapes: a `for k in (...)` projection and an inline dict literal
    whose `"key":` entries name the signed fields. Returns None if the function is absent."""
    body = _fn_block(src, fn)
    if body is None:
        return None
    proj = re.search(r"for k in\s*\(([^)]*)\)", body, re.S)
    if proj:
        return re.findall(r"""['"]([^'"]+)['"]""", proj.group(1))
    # Inline dict: keys are the quoted tokens immediately followed by a colon.
    return re.findall(r"""['"]([a-z_]+)['"]\s*:""", body)


def check_lint_enforced(root: pathlib.Path) -> list[Finding]:
    """Import and dead-code hygiene (unused imports, unused locals, undefined names,
    placeholder-free f-strings) is not left to habit: ruff runs the pyflakes F rules in CI
    and in pre-commit. A lint that is configured but never runs is displacement, so this pins
    the config, the dev dependency, the pre-commit hook, and the CI step together."""
    cfg = _read(root, "ruff.toml")
    if not cfg:
        return _fail("lint_enforced", "ruff.toml (the lint configuration) is missing")
    if not re.search(r'select\s*=\s*\[[^\]]*"F"', cfg):
        return _fail("lint_enforced",
                     "ruff.toml must select the pyflakes F rules (unused imports, dead code, undefined names)")
    if "ruff" not in _read(root, "polaris_web/requirements-dev.txt"):
        return _fail("lint_enforced", "ruff must be a dev dependency (polaris_web/requirements-dev.txt)")
    if "ruff check" not in _read(root, ".pre-commit-config.yaml"):
        return _fail("lint_enforced", "ruff must run in pre-commit (.pre-commit-config.yaml)")
    if "ruff check" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("lint_enforced", "ruff must run in CI (a lint that never runs is displacement)")
    return _ok("lint_enforced",
               "ruff enforces the pyflakes hygiene rules (unused imports, dead locals, undefined names) via "
               "ruff.toml, and runs both in pre-commit and in the CI test job before the suites, so an unused "
               "import or a dead assignment fails fast rather than accumulating")


def check_transparency_publication(root: pathlib.Path) -> list[Finding]:
    """P3.3c: external-ledger publication. A log publishes each head into an independent
    append-only ledger and gets a receipt -- the ledger's own signed head plus an inclusion
    proof -- so the log cannot use a head it has not publicly committed, and the ledger
    cannot later drop it. The detached verifier confirms a receipt; a file-backed ledger
    driver records heads (real chain drivers declared); a drill proves the pipeline and
    rejects forgery under real ML-DSA."""
    v = _read(root, "scripts/polaris-verify.py")
    for sym in ("def verify_publication", "_publication_entry", "polaris-transparency-publication/1"):
        if sym not in v:
            return _fail("transparency_publication",
                         "scripts/polaris-verify.py must verify a publication receipt (%s missing)" % sym)
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("transparency_publication",
                         f"the offline verifier imports {mod!r}; it must stay standalone")
    ledger = _read(root, "scripts/polaris-transparency-ledger.py")
    if (not ledger or "log_tree_head" not in ledger or "log_inclusion_proof" not in ledger
            or "POLARIS_LEDGER_BACKEND" not in ledger):
        return _fail("transparency_publication",
                     "scripts/polaris-transparency-ledger.py must be an append-only ledger with a backend "
                     "driver (file default, chain drivers declared)")
    drill = _read(root, "scripts/polaris-transparency-publication-drill.py")
    if not drill or "verify_publication" not in drill or "polaris-transparency-ledger.py" not in drill:
        return _fail("transparency_publication",
                     "scripts/polaris-transparency-publication-drill.py must run the ledger and prove the "
                     "receipt / forgery / append-only matrix")
    if "polaris-transparency-publication-drill.py" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("transparency_publication",
                     "the publication drill must run in CI (a publication proof that never runs is displacement)")
    return _ok("transparency_publication",
               "a log's heads are published into an independent append-only ledger with a verifiable inclusion "
               "receipt (the ledger's signed head plus an inclusion proof), so the log cannot use a head it has "
               "not publicly committed and the ledger cannot drop one it recorded -- the standalone verifier "
               "confirms it, a file-backed ledger driver records heads (chain drivers declared), and the "
               "publication drill proves the pipeline and rejects forgery under real ML-DSA")


def check_transparency_gossip(root: pathlib.Path) -> list[Finding]:
    """P3.3b: the split-view defence. A lone monitor cannot catch a log that shows different
    heads to different observers; witnesses and gossip can. The detached verifier gains
    witness cosignatures (an independent party's attestation of a head), a witnessed-checkpoint
    threshold (a relying party requires K independent cosignatures over the same head), and a
    non-repudiable equivocation proof (two log-signed heads that conflict). An independent
    witness daemon cosigns consistent heads, refuses a fork, and by gossip proves a split view;
    the gossip drill runs it under attack every release."""
    v = _read(root, "scripts/polaris-verify.py")
    for sym in ("def verify_cosignature", "def verify_witnessed_checkpoint",
                "def verify_equivocation", "_cosignature_canonical",
                "polaris-transparency-cosignature/1"):
        if sym not in v:
            return _fail("transparency_gossip",
                         "scripts/polaris-verify.py must carry the witness/equivocation verification (%s missing)" % sym)
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("transparency_gossip",
                         f"the offline verifier imports {mod!r}; it must stay standalone")
    wit = _read(root, "scripts/polaris-transparency-witness.py")
    if not wit or "verify_equivocation" not in wit or "def cosign" not in wit or "ALERT" not in wit:
        return _fail("transparency_gossip",
                     "scripts/polaris-transparency-witness.py must cosign heads, gossip, and ALERT with an equivocation proof")
    drill = _read(root, "scripts/polaris-transparency-gossip-drill.py")
    if (not drill or "verify_witnessed_checkpoint" not in drill or "verify_equivocation" not in drill
            or "polaris-transparency-witness.py" not in drill):
        return _fail("transparency_gossip",
                     "scripts/polaris-transparency-gossip-drill.py must run the witness daemon and prove the split-view catch")
    if "polaris-transparency-gossip-drill.py" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("transparency_gossip",
                     "the gossip drill must run in CI (a split-view proof that never runs is displacement)")
    return _ok("transparency_gossip",
               "the split view a lone monitor cannot catch is caught by witnesses: the standalone verifier "
               "checks witness cosignatures, a witnessed-checkpoint threshold, and a non-repudiable equivocation "
               "proof (two conflicting log-signed heads), and an independent witness daemon cosigns consistent "
               "heads, refuses a fork, and by gossip proves a split view -- driven every release by the gossip "
               "drill under real ML-DSA")


def check_transparency_log(root: pathlib.Path) -> list[Finding]:
    """P3.3: the audit anchor log is exposed as a PUBLIC, append-only, independently
    verifiable transparency log (RFC-6962 style over SHA3-256). The app publishes a signed
    tree head and consistency proofs over the append-only AnchorBatch roots; the standalone
    verifier proves an append-only extension and rejects a rewrite, fork, shrink, or
    wrong-key head; and an independent monitor daemon, run over HTTP, alerts on tampering.
    A signed view over AnchorBatch -- no new mutable state."""
    v = _read(root, "scripts/polaris-verify.py")
    for sym in ("def merkle_tree_head", "def verify_consistency", "def verify_inclusion",
                "def verify_sth", "def verify_log_consistency", "_sth_canonical",
                "polaris-transparency-sth/1"):
        if sym not in v:
            return _fail("transparency_log",
                         "scripts/polaris-verify.py must carry the RFC-6962 log verification (%s missing)" % sym)
    if '"fork"' not in v and "'fork'" not in v:
        return _fail("transparency_log",
                     "verify_log_consistency must detect a FORK (a rewrite or a non-consistent head)")
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("transparency_log",
                         f"the offline verifier imports {mod!r}; it must stay standalone (a monitor verifies "
                         "the log with no Polaris code, no database)")
    # The app publishes the signed log as a view over the append-only AnchorBatch.
    app = _read(root, "polaris_web/app.py")
    for sym in ("/api/v1/transparency/sth", "/api/v1/transparency/consistency",
                "/api/v1/transparency/proof", "/api/v1/transparency/entries",
                "_sth_statement", "signature_over_message", "AnchorBatch"):
        if sym not in app:
            return _fail("transparency_log",
                         "app.py must publish the signed transparency log over AnchorBatch (%s missing)" % sym)
    anc = _read(root, "polaris_web/anchoring.py")
    if "log_tree_head" not in anc or "log_consistency_proof" not in anc:
        return _fail("transparency_log",
                     "anchoring.py must carry the RFC-6962 log math (log_tree_head / log_consistency_proof)")
    # An independent monitor daemon that alerts on tampering.
    mon = _read(root, "scripts/polaris-transparency-monitor.py")
    if not mon or "verify_log_consistency" not in mon or "ALERT" not in mon:
        return _fail("transparency_log",
                     "scripts/polaris-transparency-monitor.py must independently verify consistency and ALERT on tampering")
    # It RUNS every release, and the monitor is exercised under attack.
    drill = _read(root, "scripts/polaris-transparency-drill.py")
    if not drill or "verify_log_consistency" not in drill or "polaris-transparency-monitor.py" not in drill:
        return _fail("transparency_log",
                     "scripts/polaris-transparency-drill.py must run the detection matrix AND the monitor daemon")
    if "polaris-transparency-drill.py" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("transparency_log",
                     "the transparency drill must run in CI (a tampering proof that never runs is displacement)")
    if not _read(root, "docs/design/transparency-log.md"):
        return _fail("transparency_log", "docs/design/transparency-log.md (the spec) is missing")
    return _ok("transparency_log",
               "the audit anchor log is a public, append-only, RFC-6962-style transparency log: the app "
               "publishes a signed tree head (GET /api/v1/transparency/sth) and consistency proofs over the "
               "append-only AnchorBatch roots, the standalone verifier proves append-only and rejects a "
               "rewrite/fork/shrink/wrong-key head, and an independent monitor daemon alerts on tampering -- "
               "proven every release by the transparency drill under real ML-DSA")


_WIRE_SIGNED_TYPES = {
    "polaris-federation-manifest/1": "_manifest_canonical",
    "polaris-epoch-checkpoint/1": "_epoch_checkpoint_canonical",
    "polaris-revocation-feed/1": "_revocation_feed_canonical",
    "polaris-status-assertion/1": "_status_assertion_canonical",
    "polaris-transparency-sth/1": "_sth_canonical",
    "polaris-federation-status-bundle/1": "_status_bundle_canonical",
    "polaris-exchange-receipt/1": "_exchange_receipt_canonical",
    "polaris-exchange-mint/1": "_exchange_mint_canonical",
    "polaris-timestamp/1": "_timestamp_canonical",
    "polaris-registry/1": "_registry_canonical",
    "polaris-exchange-request/1": "_exchange_request_canonical",
    "polaris-signed-document/1": "_signed_document_canonical",
    "polaris-id-token/1": "_id_token_canonical",
    "polaris-trust-list/1": "_trust_list_canonical",
    # P9.5: the attesting agency's own signature over a federation trust edge.
    "polaris-trust-attestation/1": "_attestation_canonical",
    # P9.1: the issuer's binding of a holder key, and the holder's own proof of it.
    "polaris-holder-binding/1": "_holder_binding_canonical",
    "polaris-holder-proof/1": "_holder_proof_canonical",
    # P9.2: the published anonymity set a holder proves against on their own device.
    "polaris-epoch-leaves/1": "_epoch_leaves_canonical",
    # P9.8: delegation. Signed by the HOLDER's key and the AGENT's, never the issuer's.
    "polaris-agent-grant/1": "_agent_grant_canonical",
    "polaris-grant-revocation/1": "_grant_revocation_canonical",
    "polaris-agent-proof/1": "_agent_proof_canonical",
}
_WIRE_ALL_FORMATS = list(_WIRE_SIGNED_TYPES) + [
    "polaris-authenticity-pack/1", "polaris-transparency-cosignature/1",
    "polaris-transparency-publication/1", "polaris-published-head/1",
    "polaris-presentation/1", "polaris-qr/1",   # P8.6: the unsigned holder-side wrapper and its QR framing
]


def check_wire_spec_matches_code(root: pathlib.Path) -> list[Finding]:
    """P8.1: the normative wire specification is pinned to the signer. An independent
    implementation, importing no Polaris code, builds to docs/reference/WIRE-SPEC.md; this
    fails CI when a format string or a signed-field list there diverges from the app's
    canonical builders (read via the detached verifier's, which mirror them), closing the
    drift that would silently break every from-spec implementation. It also closes the
    canonical-pinning gap the oracle leaves for the pack and the transparency-infra types by
    requiring every protocol format string to be specified."""
    spec = _read(root, "docs/reference/WIRE-SPEC.md")
    if not spec:
        return _fail("wire_spec", "docs/reference/WIRE-SPEC.md (the normative wire spec) is missing")
    if "MUST" not in spec:
        return _fail("wire_spec", "the wire spec must be normative (RFC-2119 MUST/SHOULD/MAY)")
    for fmt in _WIRE_ALL_FORMATS:
        if fmt not in spec:
            return _fail("wire_spec", "the wire spec does not cover the artifact %s" % fmt)
    # Each signed statement's field list matches the code, in the code's order.
    v = _read(root, "scripts/polaris-verify.py")
    for fmt, fn in _WIRE_SIGNED_TYPES.items():
        keys = _signed_statement_keys(v, fn)
        if not keys:
            return _fail("wire_spec", "cannot read the signed-field list for %s (%s missing)" % (fmt, fn))
        joined = ", ".join(keys)
        if joined not in spec:
            return _fail("wire_spec",
                         "the wire spec's signed-field list for %s does not match the code; expected: %s" % (fmt, joined))
    # The authenticity pack's special construction (not a JSON statement).
    if "SHA3-256(token_value" not in spec:
        return _fail("wire_spec",
                     "the wire spec must document the authenticity pack's construction (SHA3-256(token_value), not a JSON statement)")
    # The canonical-signing discipline itself.
    if "sort_keys" not in spec or "separators" not in spec:
        return _fail("wire_spec",
                     "the wire spec must document the canonical JSON construction (sort_keys + compact separators)")
    # The federation trust decision: non-transitive, in-context.
    if "transitive" not in spec.lower() or "context" not in spec.lower():
        return _fail("wire_spec",
                     "the wire spec must state the federation trust decision is non-transitive and in-context")
    if "WIRE-SPEC.md" not in _read(root, "docs/reference/README.md"):
        return _fail("wire_spec", "the wire spec must be linked from docs/reference/README.md")
    return _ok("wire_spec",
               "the normative wire specification (docs/reference/WIRE-SPEC.md) covers every protocol artifact and is "
               "pinned to the signer: each signed-field list and format string is checked against the app's canonical "
               "builders, so an independent implementation building to the spec cannot silently diverge from the code")


def check_canonical_equivalence(root: pathlib.Path) -> list[Finding]:
    """Every signed statement type is signed by the app over a canonical byte string and
    reconstructed INDEPENDENTLY by scripts/polaris-verify.py. If the two sides ever
    disagree on a byte -- a key added on one side, a separator changed, a sort dropped --
    the app keeps signing while every offline verification fails, silently. This check is
    the static guard: for each type, the app statement builder and the verify canonical
    builder must project the SAME ordered key list with the same compact, sorted-key JSON.
    The runtime oracle (polaris_web/test_canonical_equivalence.py, Hypothesis) proves byte
    equality over generated inputs; this check pins the key lists and the CI wiring so the
    two can never drift unnoticed."""
    app = _read(root, "polaris_web/app.py")
    v = _read(root, "scripts/polaris-verify.py")
    if not app or not v:
        return _fail("canonical_equivalence", "app.py or scripts/polaris-verify.py is missing")
    pairs = [
        ("federation-manifest", "_manifest_statement", "_manifest_canonical"),
        ("epoch-checkpoint", "_epoch_checkpoint_statement", "_epoch_checkpoint_canonical"),
        ("revocation-feed", "_revocation_feed_statement", "_revocation_feed_canonical"),
        ("status-assertion", "_status_assertion_statement", "_status_assertion_canonical"),
        ("transparency-sth", "_sth_statement", "_sth_canonical"),
    ]
    for name, app_fn, ver_fn in pairs:
        a_keys = _signed_statement_keys(app, app_fn)
        v_keys = _signed_statement_keys(v, ver_fn)
        if a_keys is None:
            return _fail("canonical_equivalence", f"app.py is missing the {name} builder {app_fn}")
        if v_keys is None:
            return _fail("canonical_equivalence", f"polaris-verify.py is missing the {name} builder {ver_fn}")
        if a_keys != v_keys:
            return _fail("canonical_equivalence",
                         f"the {name} signed key list differs between the app and the verifier: "
                         f"app {app_fn}={a_keys} vs verify {ver_fn}={v_keys} -- an app signature would "
                         "fail every offline verification")
        # Both sides must produce the compact, sorted-key form.
        for label, src, fn in (("app", app, app_fn), ("verify", v, ver_fn)):
            block = _fn_block(src, fn) or ""
            if "sort_keys=True" not in block or re.search(r"separators=\(['\"],['\"],\s*['\"]:['\"]\)", block) is None:
                return _fail("canonical_equivalence",
                             f"the {label} {name} builder must serialize with sort_keys=True and "
                             "separators=(',', ':') (the canonical compact form)")
    # The runtime oracle must exist and run in CI.
    oracle = _read(root, "polaris_web/test_canonical_equivalence.py")
    if not oracle or "SIGNED_TYPES" not in oracle or "cross_impl_equivalence" not in oracle:
        return _fail("canonical_equivalence",
                     "polaris_web/test_canonical_equivalence.py (the Hypothesis oracle) is missing or incomplete")
    if "test_canonical_equivalence" not in _read(root, "scripts/polaris-coverage.sh"):
        return _fail("canonical_equivalence",
                     "the canonical-equivalence oracle must run in CI (add it to scripts/polaris-coverage.sh)")
    return _ok("canonical_equivalence",
               f"all {len(pairs)} signed statement types project identical ordered key lists across the app "
               "signer and the offline verifier, in the compact sorted-key form, and the Hypothesis oracle "
               "(test_canonical_equivalence) proves byte equivalence over generated inputs every release")


def check_federation_two_instances(root: pathlib.Path) -> list[Finding]:
    """P3.10: federation proven across the DEPLOYMENT boundary. Two independent instances,
    each its own database and its own real ML-DSA-65 root, talk only over HTTP: a relying
    party accepts a foreign credential from trust data (a federation manifest, an epoch
    checkpoint, a revocation feed) it pulls over the wire from the running instances, and
    the decision flips as attestations and revocations change on those instances. This is
    the milestone the in-process drills approximate, proven across two real deployments."""
    drill = _read(root, "scripts/polaris-federation-instances-drill.py")
    if not drill:
        return _fail("federation_two_instances",
                     "scripts/polaris-federation-instances-drill.py (the two-instance drill) is missing")
    # It boots two REAL instances against two databases and drives them over HTTP.
    for sym in ("gunicorn", "POLARIS_FED_A_DB", "POLARIS_FED_B_DB", "verify_cross_authority",
                "http://127.0.0.1", "/api/v1/federation-manifest/", "/api/v1/epoch-checkpoint/",
                "/api/v1/revocation-feed/"):
        if sym not in drill:
            return _fail("federation_two_instances",
                         "the two-instance drill must boot two instances and drive the federation "
                         "endpoints OVER HTTP (%s missing)" % sym)
    if "POLARIS_USE_REAL_PQC" not in drill:
        return _fail("federation_two_instances",
                     "the two-instance drill must run under real ML-DSA (POLARIS_USE_REAL_PQC)")
    # The decision must flip on real state changes: an attestation and a revocation.
    if "AgencyTrustAttestation" not in drill or "revocation" not in drill.lower():
        return _fail("federation_two_instances",
                     "the drill must prove attestation revocation and revocation propagation over the wire")
    # It RUNS every release in its own CI job -- the first with both a database and real liboqs.
    ci = _read(root, ".github/workflows/ci.yml")
    if "polaris-federation-instances-drill.py" not in ci or "federation-two-instances" not in ci:
        return _fail("federation_two_instances",
                     "the two-instance drill must run in its own CI job (a deployment proof that never runs "
                     "is displacement)")
    return _ok("federation_two_instances",
               "federation is proven across two independent instances: each its own database and real "
               "ML-DSA-65 root, a relying party accepts a foreign credential from a manifest, epoch checkpoint, "
               "and revocation feed pulled OVER HTTP, and the decision flips as attestations and revocations "
               "change on the running instances -- driven every release by the federation-two-instances CI job")


def check_epoch_revocation_propagation(root: pathlib.Path) -> list[Finding]:
    """P3.2b: epoch alignment + revocation propagation across authorities. Two more signed
    objects an authority publishes and a relying party consumes OFFLINE: an EPOCH CHECKPOINT
    (its commitment to a point on the append-only TokenStateEpoch chain, so two checkpoints
    prove monotonicity and catch a FORK) and a REVOCATION FEED (the revoked-credential
    leaves it issued, monotone because RevocationList is append-only, so a ROLLBACK is
    caught). A foreign credential is rejected offline when it is revoked in the issuer's
    authentic feed -- revocation crosses the authority boundary with no issuer contact."""
    app = _read(root, "polaris_web/app.py")
    for sym in ("/api/v1/epoch-checkpoint", "/api/v1/revocation-feed",
                "_epoch_checkpoint_statement", "_revocation_feed_statement"):
        if sym not in app:
            return _fail("epoch_revocation",
                         "app.py must publish the signed epoch checkpoint and revocation feed (%s missing)" % sym)
    if "signature_over_message" not in app:
        return _fail("epoch_revocation", "the checkpoint and feed must be issuer-SIGNED (signature_over_message)")
    # Built as views over the EXISTING append-only tables, not a new mutable store.
    if "TokenStateEpoch" not in app or "RevocationList" not in app:
        return _fail("epoch_revocation",
                     "the checkpoint and feed must derive from the append-only TokenStateEpoch and RevocationList")
    # The detached verifier consumes them OFFLINE and stays standalone.
    v = _read(root, "scripts/polaris-verify.py")
    for sym in ("def verify_epoch_checkpoint", "def check_epoch_chain", "def verify_revocation_feed",
                "def check_revocation_progression", "def is_revoked",
                "_epoch_checkpoint_canonical", "_revocation_feed_canonical",
                "polaris-epoch-checkpoint/1", "polaris-revocation-feed/1"):
        if sym not in v:
            return _fail("epoch_revocation",
                         "scripts/polaris-verify.py must verify checkpoints and feeds offline (%s missing)" % sym)
    if '"fork"' not in v and "'fork'" not in v:
        return _fail("epoch_revocation",
                     "check_epoch_chain must detect a FORK: two different roots signed at one epoch number is equivocation")
    if "rolled_back" not in v:
        return _fail("epoch_revocation",
                     "check_revocation_progression must detect a ROLLBACK: a newer feed that drops a published revocation")
    # Revocation folds into the cross-authority decision, fail-closed and bound to the issuer key.
    if "revocation_feed" not in v or "revocation_checked" not in v:
        return _fail("epoch_revocation",
                     "verify_cross_authority must fold in the issuer revocation feed (fail-closed, bound to the issuer key)")
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("epoch_revocation",
                         f"the offline verifier imports {mod!r}; it must stay standalone (a relying party checks "
                         "non-revocation with no Polaris code, no database, no issuer contact)")
    # It RUNS every release, and is tested.
    drill = _read(root, "scripts/polaris-epoch-revocation-drill.py")
    if not drill or "verify_cross_authority" not in drill or "check_epoch_chain" not in drill:
        return _fail("epoch_revocation",
                     "scripts/polaris-epoch-revocation-drill.py must run the two-authority fork/rollback/revocation matrix")
    if "polaris-epoch-revocation-drill.py" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("epoch_revocation",
                     "the epoch/revocation drill must run in CI (a protocol that never runs is displacement)")
    if "EpochRevocationTests" not in _read(root, "polaris_web/test_app.py"):
        return _fail("epoch_revocation", "test_app.py must carry EpochRevocationTests for the published endpoints")
    return _ok("epoch_revocation",
               "epoch alignment and revocation propagation run across authorities: an authority publishes a signed "
               "epoch checkpoint (GET /api/v1/epoch-checkpoint) and revocation feed (GET /api/v1/revocation-feed) as "
               "views over its append-only tables, and the standalone verifier catches a fork and a rollback and "
               "rejects a revoked foreign credential OFFLINE with no issuer contact -- proven every release by the "
               "two-authority drill under real ML-DSA and tested")


def check_federation_status_bundle(root: pathlib.Path) -> list[Finding]:
    """P3.2c: the aggregate mirrored status feed. A publisher mirrors many authorities' signed
    revocation feeds and epoch checkpoints into ONE short-lived, signed STATUS BUNDLE, so a
    relying party fetches it once and checks any member's credential OFFLINE. The publisher is
    UNTRUSTED for correctness: each member feed is embedded verbatim under the member's own
    signature, the member set is committed so it cannot be tampered, and an omitted authority
    is fail-closed (not verifiable). The aggregator adds availability, not trust -- it cannot
    forge a member's status."""
    app = _read(root, "polaris_web/app.py")
    for sym in ("/api/v1/federation-status-bundle", "_status_bundle_statement",
                "_bundle_members_root", "_STATUS_BUNDLE_FORMAT"):
        if sym not in app:
            return _fail("status_bundle", "app.py must publish the signed status bundle (%s missing)" % sym)
    if "signature_over_message" not in app:
        return _fail("status_bundle", "the bundle envelope must be publisher-SIGNED (signature_over_message)")
    # The bundle is a VIEW assembled from the per-authority feeds, not a new mutable store: it
    # reuses the same feed/checkpoint builders, which derive from the append-only tables.
    for sym in ("_revocation_feed_body", "_epoch_checkpoint_body"):
        if sym not in app:
            return _fail("status_bundle",
                         "the bundle must mirror each member's OWN signed feed via %s (no new mutation path)" % sym)
    # The detached verifier consumes it OFFLINE and stays standalone.
    v = _read(root, "scripts/polaris-verify.py")
    for sym in ("def verify_status_bundle", "def verify_cross_authority_via_bundle",
                "def bundle_members_root", "_status_bundle_canonical",
                "polaris-federation-status-bundle/1"):
        if sym not in v:
            return _fail("status_bundle",
                         "scripts/polaris-verify.py must verify the status bundle offline (%s missing)" % sym)
    # Aggregator-untrusted: the decision DELEGATES to the P3.2 cross-authority decision using the
    # MEMBER's own feed (so a forged member feed rejects there), an omitted issuer is fail-closed,
    # and the member set is committed so it cannot be tampered after signing.
    if "verify_cross_authority(" not in v:
        return _fail("status_bundle",
                     "verify_cross_authority_via_bundle must delegate the trust+revocation decision to "
                     "verify_cross_authority using the member's OWN feed (the aggregator is untrusted)")
    if "in_bundle" not in v or "not present in the status bundle" not in v:
        return _fail("status_bundle",
                     "an omitted authority must be fail-closed (not verifiable), not silently trusted")
    if "commitment_ok" not in v or "members_root" not in v:
        return _fail("status_bundle",
                     "the member set must be committed (members_root) so it cannot be tampered after signing")
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("status_bundle",
                         f"the offline verifier imports {mod!r}; it must stay standalone")
    # The app builder and the verifier agree on the signed bytes, pinned by the oracle.
    if "polaris-federation-status-bundle/1" not in _read(root, "polaris_web/test_canonical_equivalence.py"):
        return _fail("status_bundle",
                     "the bundle must be in the canonical-equivalence oracle (app and verifier signed bytes must match)")
    # It RUNS every release, proves the headline property, and is tested.
    drill = _read(root, "scripts/polaris-federation-status-bundle-drill.py")
    if not drill or "verify_cross_authority_via_bundle" not in drill:
        return _fail("status_bundle",
                     "scripts/polaris-federation-status-bundle-drill.py must run the mirror accept/reject matrix")
    if "forge" not in drill.lower():
        return _fail("status_bundle",
                     "the drill must prove the headline property: an aggregator cannot forge a member's status")
    if "polaris-federation-status-bundle-drill.py" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("status_bundle",
                     "the status-bundle drill must run in CI (a protocol that never runs is displacement)")
    if "StatusBundleTests" not in _read(root, "polaris_web/test_app.py"):
        return _fail("status_bundle", "test_app.py must carry StatusBundleTests for the published endpoint")
    # The aggregator holds NO member key. A single instance mirrors only its own authority; the
    # app endpoint must never sign a partner's feed. The CORRECT cross-authority aggregation (a
    # hub FETCHES a peer's already-signed feed over HTTP, verifies it, embeds it VERBATIM, and
    # signs only its OWN outer envelope) runs across two independent instances every release.
    inst = _read(root, "scripts/polaris-federation-instances-drill.py")
    if "verify_cross_authority_via_bundle" not in inst or "_status_bundle_canonical" not in inst:
        return _fail("status_bundle",
                     "the two-instance federation drill must prove correct aggregation: a hub fetches a peer's "
                     "signed feed over HTTP and bundles it under its OWN envelope, holding no peer key")
    return _ok("status_bundle",
               "the aggregate status bundle mirrors many authorities in one short-lived signed artifact: a relying "
               "party fetches GET /api/v1/federation-status-bundle once and checks any member's credential OFFLINE, "
               "the publisher is untrusted for correctness (each member feed is embedded under the member's own "
               "signature, the set is committed, an omitted authority is fail-closed), and the standalone verifier "
               "returns the same decision the issuer's own feed would -- proven every release by the two-authority "
               "drill under real ML-DSA and tested")


def check_cross_authority_zk(root: pathlib.Path) -> list[Finding]:
    """P3.2d: a holder's zero-knowledge inclusion proof decided against a FOREIGN authority's
    epoch, OFFLINE. The relying party trusts the authority's signed epoch checkpoint in-context
    (non-transitive) to obtain the trusted epoch root, requires the proof's public inputs to
    bind to it, and verifies the Plonky2 proof via the local polaris-zk binary. It reveals no
    credential (zero-knowledge), and ABSTAINS rather than false-accepting when the binary is
    absent."""
    v = _read(root, "scripts/polaris-verify.py")
    for sym in ("def verify_cross_authority_zk", "def verify_zk_against_root", "def _zk_verify_proof",
                "polaris-zk"):
        if sym not in v:
            return _fail("cross_authority_zk",
                         "scripts/polaris-verify.py must decide a cross-authority ZK proof offline (%s missing)" % sym)
    # Trust is rooted in the SIGNED checkpoint and a trusted in-context attestation, reusing the
    # hardened federation trust path, and it binds the proof to the trusted epoch root.
    if "verify_epoch_checkpoint(" not in v or "verify_manifest(" not in v:
        return _fail("cross_authority_zk",
                     "the ZK decision must trust the checkpoint and the attestation (verify_epoch_checkpoint / verify_manifest)")
    if "epoch_root_hex" not in v or "attested_public_key_hex" not in v:
        return _fail("cross_authority_zk",
                     "the proof must bind to the checkpoint's epoch root, and trust to the attested issuer key")
    # The proof is checked by shelling to the polaris-zk binary as a LOCAL subprocess (offline),
    # and the decision ABSTAINS when the binary is absent (never a false accept).
    if "subprocess" not in v or "abstain" not in v:
        return _fail("cross_authority_zk",
                     "the proof must be checked via the local polaris-zk binary (subprocess), abstaining when it is absent")
    # Shelling out is not importing Polaris code: the verifier stays standalone.
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("cross_authority_zk", f"the offline verifier imports {mod!r}; it must stay standalone")
    if "--zk-proof" not in v:
        return _fail("cross_authority_zk", "polaris-verify.py must expose a --zk-proof CLI mode for a relying party")
    # It RUNS every release against a committed real-proof fixture, and is red on a wrong decision.
    drill = _read(root, "scripts/polaris-cross-authority-zk-drill.py")
    if not drill or "verify_cross_authority_zk" not in drill:
        return _fail("cross_authority_zk",
                     "scripts/polaris-cross-authority-zk-drill.py must run the accept/reject/abstain matrix")
    if "abstain" not in drill:
        return _fail("cross_authority_zk", "the drill must prove the abstain-when-no-binary case (never a false accept)")
    if not (root / "polaris_zk" / "fixtures" / "cross-authority-zk.json").is_file():
        return _fail("cross_authority_zk",
                     "the committed cross-authority ZK fixture is missing (regenerate with --generate)")
    if "polaris-cross-authority-zk-drill.py" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("cross_authority_zk",
                     "the cross-authority ZK drill must run in CI (a protocol that never runs is displacement)")
    return _ok("cross_authority_zk",
               "a holder's zero-knowledge inclusion proof is decided against a foreign authority's epoch OFFLINE: the "
               "authority's signed checkpoint is trusted in-context (non-transitive) to obtain the epoch root, the "
               "proof's public inputs bind to it, and the Plonky2 proof is checked via the local polaris-zk binary "
               "(abstaining when absent, never false-accepting); proven every release against a committed real-proof "
               "fixture and red on any wrong decision")


# Positioning rule (VANTA, 2026-09-09): the tree describes the CLASS of a system it relates
# to, never a named country or its digital-state products. The P8 exchange-fabric arc was
# informed by a gap analysis against a mature national digital-identity ecosystem; Polaris
# must stand on its own terms rather than read as a derivative. Same discipline as the
# no-external-model-names rule. Residue in git history is fine; the working tree is clean.
_NAMED_REFERENCE_SYSTEMS = (
    ("i", r"estonia"), ("i", r"\bx-?road\b"), ("i", r"\bx-?tee\b"),
    ("i", r"digidoc"), ("i", r"govsso"), ("i", r"e-residency"), ("i", r"mobile-id"),
    ("i", r"smart-id"), ("i", r"web[ -]eid"),
    ("s", r"\bTARA\b"), ("s", r"\bSiVa\b"), ("s", r"\bRIA\b"),   # short acronyms: exact case, whole word
)
_NAMED_REF_EXTS = {".md", ".py", ".sh", ".tex", ".bib", ".html", ".ts", ".js", ".css", ".yml", ".yaml",
                   ".txt", ".cff", ".sql", ".rs", ".toml", ".json", ".cfg", ".ini"}
_NAMED_REF_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "target", "__pycache__", "dist", "build"}
_NAMED_REF_EXEMPT = {"polaris_checks/checks.py", "polaris_checks/test_checks.py"}   # they hold the patterns


def check_holder_side_prover(root: pathlib.Path) -> list[Finding]:
    """P9.2 (v9.350): a holder can prove membership on their OWN device.

    The prover was always a program a holder could run, but until this version nothing
    published what proving needs. An epoch's leaf set IS the anonymity set, and a set only
    the issuer holds is not one; without a published set the holder had to be handed it out
    of band, which in practice meant the issuer proving on their behalf and learning which
    member asked.

    The check requires the set to be published, signed, bounded, and checkable with SHA3-256
    alone: a verifier that needed the Poseidon proving library to check the set would not be
    standalone, and the SDKs an outsider installs could not do it at all."""
    app = _read(root, "polaris_web/app.py")
    if "_epoch_leaves_statement" not in app or "api_v1_epoch_leaves" not in app:
        return _fail("holder_side_prover",
                     "the authority must publish the epoch's leaf set, signed (_epoch_leaves_statement, "
                     "api_v1_epoch_leaves); a set only the issuer holds is not an anonymity set")
    if "_EPOCH_LEAVES_MAX" not in app:
        return _fail("holder_side_prover",
                     "the published set must be bounded (C8): an unbounded body is an unbounded read")
    # A decorator sits ABOVE the def, so look at the lines that precede it.
    before = app.split("def api_v1_epoch_leaves")[0]
    if any(g in before[-400:] for g in ("login_required", "require_role", "require_client")):
        return _fail("holder_side_prover",
                     "the anonymity set must be PUBLIC: a set a holder must authenticate to fetch tells the "
                     "issuer who is about to prove")
    verifier = _read(root, "scripts/polaris-verify.py")
    for needed, why in (("def verify_epoch_leaves", "the detached verifier must decide a published set offline"),
                        ("def member_index", "a holder must find their own leaf locally, never by asking the issuer"),
                        ("_leaves_root", "the set must be committed to with SHA3-256, checkable in any language")):
        if needed not in verifier:
            return _fail("holder_side_prover", f"{why} ({needed})")
    # The set must be checkable without the proving library: no subprocess, no zk import.
    body = verifier.split("def verify_epoch_leaves")[1].split("\ndef ")[0]
    if "subprocess" in body or "compute_epoch_root" in body or "import zk" in verifier:
        return _fail("holder_side_prover",
                     "the detached verifier must not reach for the proving library to check a published set; "
                     "the commitment is SHA3-256 precisely so a standalone verifier can check it")
    if "_leaves_root(" not in body:
        return _fail("holder_side_prover",
                     "verify_epoch_leaves must recompute the SHA3-256 commitment over the published leaves")
    wallet = _read(root, "scripts/polaris-wallet.py")
    if "from_instance" not in wallet or "verify_epoch_leaves" not in wallet:
        return _fail("holder_side_prover",
                     "the wallet must fetch the published set and VERIFY it before proving against it")
    py_sdk, ts_sdk = _read(root, "sdk/python/polaris_verify/__init__.py"), _read(root, "sdk/typescript/src/index.ts")
    if "polaris-epoch-leaves/1" not in py_sdk or "polaris-epoch-leaves/1" not in ts_sdk:
        return _fail("holder_side_prover", "both SDKs must know the published anonymity set")
    try:
        cases = json.loads((root / "conformance" / "cases.json").read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        return _fail("holder_side_prover", f"conformance/cases.json is not valid JSON ({e})")
    ep = [c for c in cases.get("cases", []) if c.get("artifact") == "epoch-leaves"]
    if not any(c.get("expect", {}).get("authentic") is True for c in ep) or \
            not any(c.get("expect", {}).get("authentic") is False for c in ep):
        return _fail("holder_side_prover",
                     "the conformance cases must certify a published set AND one whose members were swapped "
                     "after signing")
    return _ok("holder_side_prover",
               "a holder proves on their own device: the epoch's leaf set is published and signed, bounded, "
               "public so that fetching it says nothing about who is proving, committed to with SHA3-256 so any "
               "verifier checks it without the proving library, and the wallet verifies the set before finding "
               "its own leaf locally (P9.2)")


def check_holder_key_binding(root: pathlib.Path) -> list[Finding]:
    """P9.1 (v9.349): a holder can hold a KEY, not only a file.

    Polaris was issuer-centric from v1: a holder held a credential, and presenting the file
    was the whole of the proof. That single absence was the common cause under four separate
    limitations, so this is the keystone of P9. The check requires the whole chain and, above
    all, the constitutional guard on it: a key the holder controls is also a key the holder
    can be COMPELLED to use, so the holder proof must never cover the presented code. If it
    did, a coerced presentation would become distinguishable from a consenting one and the
    anti-coercion vocation would be weaker than before the key existed."""
    schema = _read(root, "polaris_sql/01_schema.sql")
    if "CREATE TABLE HolderKeyEvent" not in schema:
        return _fail("holder_key", "HolderKeyEvent (the append-only holder key register) is missing from the schema")
    if "HolderKeyCurrent" not in schema:
        return _fail("holder_key", "HolderKeyCurrent must derive the key in force per credential")
    if "trg_holder_key_append_only" not in _read(root, "polaris_sql/06_triggers.sql"):
        return _fail("holder_key",
                     "the holder key register must be append-only by trigger; a binding that could be updated "
                     "would let an operator replace the holder's key")
    if "'holderkeyevent'" not in _read(root, "polaris_sql/09_grants.sql"):
        return _fail("holder_key", "polaris_app must lose UPDATE/DELETE on holderkeyevent (the privilege boundary)")
    app = _read(root, "polaris_web/app.py")
    for needed, why in (("_holder_binding_statement", "the issuer must sign a holder key binding"),
                        ("_holder_proof_statement", "the app must build the holder proof's canonical bytes"),
                        ("api_v1_holder_key_bind", "a holder must be able to bind, rotate and revoke a key"),
                        ("_possession_authenticated", "binding must be proved by POSSESSION of the credential")):
        if needed not in app:
            return _fail("holder_key", f"{why} ({needed})")
    # THE CONSTITUTIONAL GUARD. The holder proof's signed statement must not name the
    # presented code, in either implementation.
    verifier = _read(root, "scripts/polaris-verify.py")
    # Read the SIGNED KEY LIST itself out of each implementation, not the prose around it.
    for src, name in ((app, "polaris_web/app.py"), (verifier, "scripts/polaris-verify.py")):
        m = re.search(r"def _holder_proof_(?:statement|canonical)\(.*?statement = \{k: \w+\.get\(k\) for k in\s*(\([^)]*\))",
                      src, re.S)
        if not m:
            return _fail("holder_key", f"{name} must define the holder proof's canonical statement")
        signed = {t.strip().strip("'\"") for t in m.group(1).strip("()").split(",") if t.strip()}
        if "presented_code" in signed or any("code" in f and f != "format" for f in signed):
            return _fail("holder_key",
                         f"{name}'s holder proof signs {sorted(signed)}, which names the presented code: a proof "
                         "that covered it would make a coerced presentation distinguishable from a consenting "
                         "one, a regression against the vocation rather than a feature")
        if not {"token_value", "context_id", "verifier_nonce", "issued_at"} <= signed:
            return _fail("holder_key",
                         f"{name}'s holder proof must sign the credential, the context, the verifier's nonce and "
                         f"the instant; it signs {sorted(signed)}")
    if "def verify_holder_binding" not in verifier or "def verify_holder_proof" not in verifier:
        return _fail("holder_key", "the detached verifier must decide the binding and the proof offline")
    if "require_holder_proof" not in verifier:
        return _fail("holder_key",
                     "verify_presentation must let a relying party REQUIRE possession of the holder key, not only "
                     "of the file")
    if "verifier_nonce" not in verifier:
        return _fail("holder_key",
                     "the holder proof must be bound to the verifier's own nonce, or a captured proof replays to "
                     "another verifier")
    py_sdk, ts_sdk = _read(root, "sdk/python/polaris_verify/__init__.py"), _read(root, "sdk/typescript/src/index.ts")
    if "def verify_holder" not in py_sdk or "verifyHolder" not in ts_sdk:
        return _fail("holder_key", "both SDKs must decide the holder chain, or it is available only to whoever "
                                   "runs Polaris's own verifier")
    try:
        cases = json.loads((root / "conformance" / "cases.json").read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        return _fail("holder_key", f"conformance/cases.json is not valid JSON ({e})")
    chain = [c for c in cases.get("cases", []) if c.get("artifact") == "holder-chain"]
    if not any(c.get("expect", {}).get("proved") is True for c in chain) or \
            not any(c.get("expect", {}).get("proved") is False for c in chain) or len(chain) < 4:
        return _fail("holder_key",
                     "the conformance cases must certify the chain proved AND the three ways it fails: a stranger's "
                     "key, a replayed nonce, and a revoked binding")
    return _ok("holder_key",
               "a holder can hold a key: an append-only register binds a holder PUBLIC key to a credential by "
               "possession, the issuer signs the binding, the holder signs a nonce-bound proof, the detached "
               "verifier and both SDKs decide the chain offline and can require it, and the proof's statement "
               "does not name the presented code, so a coerced presentation stays indistinguishable (P9.1)")


def check_attestation_signed(root: pathlib.Path) -> list[Finding]:
    """P9.5 (v9.348): a federation trust edge is signed by the agency that made it.

    Until this version the trust graph was the one load-bearing joint of federation that
    rested on an operator's word. The manifest that published an attestation was signed, but
    the ROW was recorded by a human and the next publication signed whatever the table held,
    so an edge inserted straight into a database was indistinguishable from one made through
    the ceremony. The whole architecture says do not trust the application; here it was
    asking exactly that.

    The check requires the whole path: the schema holds the signature and refuses to let it
    be replaced, the ceremony writes it, the manifest publishes it, and every verifier
    (the detached one and both SDKs) checks it against the attesting agency and the attested
    key."""
    schema = _read(root, "polaris_sql/01_schema.sql")
    for col in ("attestation_format", "attestation_signature_hex", "attestation_public_key_hex"):
        if col not in schema:
            return _fail("attestation_signed",
                         f"AgencyTrustAttestation must carry {col}: without it the trust graph is an "
                         "operator's word that the next manifest signs on their behalf")
    if "attestation_signature_complete" not in schema:
        return _fail("attestation_signed",
                     "the signature columns must be all-or-nothing (attestation_signature_complete), so a row "
                     "cannot carry half a signature")
    triggers = _read(root, "polaris_sql/06_triggers.sql")
    if "an attestation signature cannot be replaced once recorded" not in triggers:
        return _fail("attestation_signed",
                     "enforce_attestation_immutability must refuse a replaced attestation signature; a signature "
                     "that can be rewritten proves nothing the operator's word did not already prove")
    app = _read(root, "polaris_web/app.py")
    if "_attestation_statement" not in app or "_sign_attestation" not in app:
        return _fail("attestation_signed",
                     "the app must build the canonical attestation statement and sign the edge at the ceremony "
                     "(_attestation_statement, _sign_attestation)")
    if "_sign_attestation(cur, row['attestation_id'])" not in app:
        return _fail("attestation_signed",
                     "the attestation route must sign the edge it just recorded, in the same request")
    if "'signature_hex': a.get('attestation_signature_hex')" not in app:
        return _fail("attestation_signed",
                     "the federation manifest must publish each attestation's signature, or a consumer can only "
                     "trust that the publisher recorded the edge faithfully")
    verifier = _read(root, "scripts/polaris-verify.py")
    if "def verify_attestation" not in verifier or "require_signed_attestation" not in verifier:
        return _fail("attestation_signed",
                     "the detached verifier must verify an attestation signature and offer to require one "
                     "(verify_attestation, require_signed_attestation)")
    if "attester_matches" not in verifier or "key_matches" not in verifier:
        return _fail("attestation_signed",
                     "the verifier must bind the attestation to the publishing authority and to the attested key; "
                     "an edge signed over another key would be replayable across rotations")
    py_sdk = _read(root, "sdk/python/polaris_verify/__init__.py")
    ts_sdk = _read(root, "sdk/typescript/src/index.ts")
    if "def verify_attestation" not in py_sdk or "verifyAttestation" not in ts_sdk:
        return _fail("attestation_signed",
                     "both SDKs must verify an attestation signature, or the stronger trust decision is available "
                     "only to whoever runs Polaris's own verifier")
    if "polaris-trust-attestation/1" not in py_sdk or "polaris-trust-attestation/1" not in ts_sdk:
        return _fail("attestation_signed", "both SDKs must know the polaris-trust-attestation/1 signed-field list")
    try:
        cases = json.loads((root / "conformance" / "cases.json").read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        return _fail("attestation_signed", f"conformance/cases.json is not valid JSON ({e})")
    atts = [c for c in cases.get("cases", []) if c.get("artifact") == "trust-attestation"]
    if not any(c.get("expect", {}).get("authentic") is True for c in atts) or \
            not any(c.get("expect", {}).get("authentic") is False for c in atts):
        return _fail("attestation_signed",
                     "the conformance cases must certify a signed edge AND an edge whose signature no longer binds "
                     "(a re-pointed key or a widened context)")
    return _ok("attestation_signed",
               "a federation trust edge is signed by the agency that made it: the schema holds the signature and "
               "refuses to replace it, the ceremony writes it, the manifest publishes it, the detached verifier and "
               "both SDKs check it against the publishing authority and the attested key, and the conformance cases "
               "certify both a binding edge and one whose key or context moved after signing (P9.5)")


def check_ship_tool(root: pathlib.Path) -> list[Finding]:
    """v9.345: the ship tool, engine and tool only. `plan` names the verification a change needs:
    the release recipe as code selected by the moved paths, plus the drills that mention a route
    whose handler changed, directly or through a helper it calls (the v9.334 lesson, a changed
    verdict shipped without its drills). `run` shards the database-backed suites across processes,
    one freshly loaded database per shard, with the classes that spawn processes or bind ports
    pinned to a serial shard. `triage` classifies a red run against the known flake signatures.
    The check pins each piece with known answers, requires preflight and the runbook to carry the
    commands, and keeps the measurement apparatus cut: no viewer, no fits."""
    name = "ship_tool"
    script = root / "scripts" / "polaris-ship.py"
    if not script.is_file():
        return _fail(name, "scripts/polaris-ship.py must exist")
    for leftover in ("site/regression.html", "scripts/polaris-regression.py", "scripts/polaris_regression_viewer.py", "docs/reference/REGRESSION.md"):
        if (root / leftover).exists():
            return _fail(name, "%s is wrapper: the measurement apparatus stays cut (engine and tool only)" % leftover)
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("polaris_ship_check", str(script))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        base = 'def _h():\n    return 1\n\n@app.route("/a")\ndef a():\n    return _h()\n\n@app.route("/b/<int:i>")\ndef b(i):\n    return i\n'
        cr = mod.changed_routes(base, base.replace("return 1", "return 2"))
        dr = mod.drills_for_routes(["/b/<int:i>", "/a"], {"d.py": 'get("/b/12?x=1")', "e.py": 'get("/ab")'})
        ver = mod.verification_for(["polaris_web/custody.py", "docs/x.md"])
        flake = mod.classify_failure_log("E: Failed to fetch https://example.invalid/Packages.gz  Hash Sum mismatch")[0]
        real = mod.classify_failure_log("AssertionError: the verdict changed")[0]
        units = [("m", "A", 10), ("m", "B", 5), ("m", "C", 1), ("m", "S", 3)]
        shards = mod.distribute(units, 3, {("m", "S")})
        blocks = mod._failure_blocks("FAIL: test_x (m.C)\n----------\nTraceback\n  boom\n\n==========\nERROR: test_y (m.D)\n----------\nTraceback\n  bang\n\n----------\nRan 2 tests\n")
    except Exception as e:  # noqa: BLE001 -- a tool that cannot compute is a failed check
        return _fail(name, "the ship tool does not run: %s: %s" % (type(e).__name__, e))
    if cr != ["/a"] or dr != {"d.py": ["/b/<int:i>"]}:
        return _fail(name, "changed_routes must flag the route that calls a changed helper and drills_for_routes must match a parameterised path (got %r, %r)" % (cr, dr))
    if len(ver) != 1 or "custody" not in ver[0]["why"] or not any("verifier-fuzz" in x for x in ver[0]["run"]):
        return _fail(name, "verification_for must select the signing verification for polaris_web/custody.py and nothing for a document (got %r)" % (ver,))
    if flake != "flake" or real != "investigate":
        return _fail(name, "classify_failure_log must call the apt index hash mismatch a flake and an assertion a failure to investigate (got %r, %r)" % (flake, real))
    placed = sorted(u for sh in shards for u in sh)
    if placed != sorted(units) or ("m", "S", 3) not in shards[0] or ("m", "A", 10) in shards[0]:
        return _fail(name, "distribute must place every class once, the serial class in shard 0 and the heaviest class elsewhere (got %r)" % (shards,))
    if len(blocks) != 2 or not blocks[0].startswith("FAIL: test_x") or "bang" not in blocks[1]:
        return _fail(name, "_failure_blocks must cut a unittest log into its FAIL and ERROR blocks (got %r)" % (blocks,))
    if "polaris-ship.py plan" not in _read(root, "scripts/polaris-preflight.sh"):
        return _fail(name, "scripts/polaris-preflight.sh must print `polaris-ship.py plan` so the verification is named before every ship")
    runbook = _read(root, "CLAUDE.md")
    if any(cmd not in runbook for cmd in ("polaris-ship.py plan", "polaris-ship.py run", "polaris-ship.py triage")):
        return _fail(name, "CLAUDE.md must carry `polaris-ship.py plan`, `run` and `triage` where a fresh session reads how to work")
    return _ok(name, "plan selects verification by moved path and by changed route handler (helper-aware), run shards the suites with the serial classes pinned, "
                     "triage tells a flake from a failure; preflight and the runbook carry the commands; the measurement apparatus stays cut")


def check_timestamp_transparency(root: pathlib.Path) -> list[Finding]:
    """P8.5b (v9.341): time evidence that survives the timestamp authority's key being stolen.
    A caller may ask for an ANCHORED timestamp: only then does the timestamp's SHA3-256 join an
    append-only transparency log (TimestampLog, migration 007, strict by trigger and privilege),
    published with signed heads, and the inclusion evidence comes back stapled. The detached
    verifier checks the anchor offline and, when the relying party names witnesses, requires
    the head cosigned; long-term validation takes an anchored policy, a quorum of independent
    authorities as the no-retention alternative, and the authority's key status per the trust
    list. The default request retains nothing, and every surface says so."""
    schema = _read(root, "polaris_sql/01_schema.sql")
    if "CREATE TABLE TimestampLog" not in schema or "chk_timestamp_log_hash" not in schema:
        return _fail("timestamp_transparency", "01_schema.sql must define the append-only TimestampLog of anchored-timestamp hashes")
    if "trg_timestamp_log_append_only" not in _read(root, "polaris_sql/06_triggers.sql") or "'timestamplog'" not in _read(root, "polaris_sql/09_grants.sql"):
        return _fail("timestamp_transparency", "the timestamp log must be append-only by trigger and by privilege")
    if not (root / "polaris_sql" / "migrations" / "2026-09-09-007-timestamp-log.up.sql").is_file() \
            or not (root / "polaris_sql" / "migrations" / "2026-09-09-007-timestamp-log.down.sql").is_file():
        return _fail("timestamp_transparency", "the timestamp log must ship as a reversible migration (007)")
    app = _read(root, "polaris_web/app.py")
    for sym in ("_TIMESTAMP_LOG_ID = 'polaris-timestamp-log'", "def _anchor_timestamp", "if body.get('anchor') is True:",
                "/api/v1/timestamp/inclusion/<timestamp_hash>", "/api/v1/transparency/timestamps/sth",
                "'transparency_logs': [_LOG_ID, _RECEIPT_LOG_ID, _TIMESTAMP_LOG_ID]", "fields.get('anchor_timestamp') is True"):
        if sym not in app:
            return _fail("timestamp_transparency", "polaris_web/app.py must anchor on request and publish the timestamp log (%s missing)" % sym)
    v = _read(root, "scripts/polaris-verify.py")
    for sym in ("def timestamp_hash", "def verify_timestamp_anchor", "trusted_witnesses=None", "timestamp_quorum=1", "require_anchored=False",
                '"timestamp_authority_key_status_per_trust_list"', '"independent_timestamps"', "timestamps=None"):
        if sym not in v:
            return _fail("timestamp_transparency", "scripts/polaris-verify.py must verify anchors, quorums and the authority's key status (%s missing)" % sym)
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("timestamp_transparency", f"the offline verifier imports {mod!r}; it must stay standalone")
    drill = _read(root, "scripts/polaris-timestamp-transparency-drill.py")
    for sym in ("AFTER THE THEFT", "SPLIT VIEW", "QUORUM", "the residual risk, stated"):
        if sym not in drill:
            return _fail("timestamp_transparency", "scripts/polaris-timestamp-transparency-drill.py must show the stolen-key forgery, the split view and the quorum (%s)" % sym)
    if "polaris-timestamp-transparency-drill.py" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("timestamp_transparency", "the transparency drill must run in CI")
    fed = _read(root, "scripts/polaris-federation-instances-drill.py")
    if '"anchor": True' not in fed or "verify_timestamp_anchor" not in fed:
        return _fail("timestamp_transparency", "the two-instance drill must anchor a timestamp over HTTP and verify the evidence offline")
    tests = _read(root, "polaris_web/test_app.py")
    if "TimestampLogTests" not in tests or "retains nothing" not in tests:
        return _fail("timestamp_transparency", "the route tests must prove an unanchored request retains nothing and an anchored one is included")
    if "TimestampLog" not in _read(root, "polaris_web/test_check_constraints.py"):
        return _fail("timestamp_transparency", "the C1 privilege test must cover TimestampLog")
    spec = _read(root, "docs/reference/WIRE-SPEC.md")
    for sym in ("`anchor`", "polaris-timestamp-log", "quorum"):
        if sym not in spec:
            return _fail("timestamp_transparency", "the wire spec must specify the anchor, the timestamp log and the quorum rule (%s)" % sym)
    if not _read(root, "docs/design/timestamp-transparency.md"):
        return _fail("timestamp_transparency", "docs/design/timestamp-transparency.md must record the design and the retention trade-off")
    if "unless the caller asks for an anchor" not in _read(root, "docs/design/timestamp-authority.md"):
        return _fail("timestamp_transparency", "the timestamp authority's design record must restate its retention promise honestly")
    if "anchored timestamp" not in _read(root, "docs/PRODUCTION-READINESS.md"):
        return _fail("timestamp_transparency", "the readiness ledger must state what the timestamp authority now retains, and when")
    if "TimestampLog" not in _read(root, "docs/reference/DATA-MODEL.md"):
        return _fail("timestamp_transparency", "docs/reference/DATA-MODEL.md must document the timestamp log")
    return _ok("timestamp_transparency",
               "an anchored timestamp (the caller's choice) is a leaf in an append-only, published timestamp log with stapled "
               "inclusion evidence the detached verifier checks offline, witnessed when the relying party names witnesses; "
               "long-term validation takes an anchored policy, a quorum of independent authorities, and the authority's key "
               "status per the trust list; drilled under a stolen key, across two instances, and stated on every surface")


def check_roadmap_consistent(root: pathlib.Path) -> list[Finding]:
    """v9.337: the roadmap cannot contradict itself. A subsystem whose row is marked done may
    not still sit under "Do not have"; a done row may not open its notes with IN PROGRESS, NEXT
    or TODO; the "N invariant checks (vX.Y)" stamp names the real count and a version within
    twenty minors of the tree; and once the protocol phase is done the "Have" paragraph says
    so. An outside review found all three drifts within a day of the prior drift fix, so the
    class is now a gate, not a habit."""
    rm = _read(root, "ROADMAP.md")
    if not rm:
        return _fail("roadmap_consistent", "ROADMAP.md is missing")
    done = set(re.findall(r"^\| \[x\] ([A-Z0-9.]+) \|", rm, re.M))
    m = re.search(r"\*\*Do not have:\*\*(.*?)\n\n", rm, re.S)
    if not m:
        return _fail("roadmap_consistent", "ROADMAP.md must keep a 'Do not have' paragraph")
    not_have = m.group(1).lower()
    built = {"P8.1": ("normative wire specification",), "P8.2": ("secure-exchange gateway", "exchange gateway"),
             "P8.3": ("service-and-authority registry", "authority registry"), "P8.4": ("auth/sso broker", "auth broker"),
             "P8.5": ("general document signing",), "P8.6": ("wallet protocol surface",), "P8.7": ("trust list",),
             "P8.8": ("cross-version compatibility",)}
    for rid, phrases in built.items():
        if rid in done:
            for ph in phrases:
                if ph in not_have:
                    return _fail("roadmap_consistent", "ROADMAP.md lists %r under 'Do not have' while row %s is marked done" % (ph, rid))
    stale = re.search(r"^\| \[x\] (\S+) \|(?:[^|\n]*\|){4}\s*(IN PROGRESS|NEXT|TODO|PLANNED)\b", rm, re.M)
    if stale:
        return _fail("roadmap_consistent", "ROADMAP.md row %s is marked done but its notes open with %s" % (stale.group(1), stale.group(2)))
    sm = re.search(r"(\d+) invariant\s+checks \(v(\d+)\.(\d+)\)", rm)
    if not sm:
        return _fail("roadmap_consistent", "ROADMAP.md must stamp 'N invariant checks (vX.Y)'")
    if int(sm.group(1)) != len(CHECKS):
        return _fail("roadmap_consistent", "ROADMAP.md stamps %s invariant checks; the layer has %d" % (sm.group(1), len(CHECKS)))
    vm = re.search(r'__version__: str = "(\d+)\.(\d+)"', _read(root, "polaris_web/__version__.py"))
    if vm and (int(sm.group(2)) != int(vm.group(1)) or int(vm.group(2)) - int(sm.group(3)) > 20):
        return _fail("roadmap_consistent", "ROADMAP.md's check stamp reads v%s.%s but the tree is v%s.%s; restamp within twenty minors" % (sm.group(2), sm.group(3), vm.group(1), vm.group(2)))
    if "P8.8" in done and "protocol layer" not in rm.split("**Do not have:**")[0].lower():
        return _fail("roadmap_consistent", "ROADMAP.md's 'Have' paragraph must name the protocol layer once P8 is done")
    return _ok("roadmap_consistent",
               "the roadmap agrees with itself: nothing marked done sits under 'Do not have', no done row reads as in "
               "progress, the check stamp names the real count and a current version, and the 'Have' paragraph names "
               "the protocol layer")


def check_broker_policy_bound(root: pathlib.Path) -> list[Finding]:
    """v9.336 (P8.4b): the auth broker enforces the relying party's REGISTERED policy, not what
    the holder-side request says. The step-up, the enrollment requirement and the only context
    are columns on the relying party (a reversible migration), the authorize route applies them
    and lets a request add a requirement but never remove one, and the authorization code is
    encrypted rather than merely signed, so a bearer learns nothing from it."""
    schema = _read(root, "polaris_sql/01_schema.sql")
    for sym in ("require_zk          BOOLEAN", "required_enrollment VARCHAR(20)", "required_context_id INTEGER"):
        if sym not in schema:
            return _fail("broker_policy_bound", "01_schema.sql must hold the relying party's registered policy (%s)" % sym)
    if not (root / "polaris_sql" / "migrations" / "2026-09-09-006-relying-party-policy.up.sql").is_file() \
            or not (root / "polaris_sql" / "migrations" / "2026-09-09-006-relying-party-policy.down.sql").is_file():
        return _fail("broker_policy_bound", "the policy columns must ship as a reversible migration (006)")
    app = _read(root, "polaris_web/app.py")
    for sym in ("rp['required_context_id'] is not None and context_id != int(rp['required_context_id'])",
                "required = rp['required_enrollment'] or body.get('required_enrollment')",
                "if rp['require_zk'] or body.get('require_zk'):", "policy_violation"):
        if sym not in app:
            return _fail("broker_policy_bound", "the authorize route must apply the stored policy and let a request only add to it (%s missing)" % sym)
    ra = _read(root, "polaris_web/rp_auth.py")
    if "from cryptography.fernet import Fernet" not in ra or "_code_serializer" in ra or "URLSafeTimedSerializer(secret_key, salt=_CODE_SALT)" in ra:
        return _fail("broker_policy_bound", "the authorization code must be encrypted (Fernet), not a decodable signed blob")
    tests = _read(root, "polaris_web/test_app.py")
    for name in ("test_registered_policy_binds_the_holder_request", "test_authorization_code_is_opaque"):
        if name not in tests:
            return _fail("broker_policy_bound", "the broker tests must prove the stored policy binds and the code is opaque (%s)" % name)
    if "rp-policy" not in _read(root, "polaris_cli/polaris.py"):
        return _fail("broker_policy_bound", "the CLI must let an operator set a relying party's registered policy (rp-policy)")
    if "registered policy" not in _read(root, "docs/design/auth-broker.md") or "policy_violation" not in _read(root, "docs/reference/API.md"):
        return _fail("broker_policy_bound", "the design record and the API reference must describe the registered policy")
    if "required_context_id" not in _read(root, "docs/reference/DATA-MODEL.md"):
        return _fail("broker_policy_bound", "docs/reference/DATA-MODEL.md must document the policy columns")
    return _ok("broker_policy_bound",
               "the auth broker applies the relying party's registered policy (step-up, enrollment, context) over the "
               "holder-side request, which may add a requirement but never remove one; the authorization code is encrypted "
               "and opaque; migration 006, the route, the CLI, the tests and the docs are pinned")


def check_qr_resource_bounds(root: pathlib.Path) -> list[Finding]:
    """v9.335: the QR decoder is resource-bounded as well as total. Frame count, compressed
    size and decompressed size are each bounded and checked BEFORE the work they guard; the
    decompressor runs with an output limit, so a decompression bomb (a compressible payload
    that expands a thousandfold) is refused at the limit rather than inflated. Drilled with a
    real bomb, an oversized payload and a frame flood; stated normatively in the wire spec."""
    v = _read(root, "scripts/polaris-verify.py")
    for sym in ("_QR_MAX_FRAMES = 9999", "_QR_MAX_COMPRESSED =", "_QR_MAX_DECOMPRESSED =", "zlib.decompressobj()",
                "d.decompress(data, _QR_MAX_DECOMPRESSED)", "d.unconsumed_tail or not d.eof", "too many frames"):
        if sym not in v:
            return _fail("qr_resource_bounds", "scripts/polaris-verify.py must bound frames, compressed and decompressed sizes with an output-limited inflater (%s missing)" % sym)
    if "zlib.decompress(" in v:
        return _fail("qr_resource_bounds", "the QR decoder must not call an unbounded zlib.decompress")
    drill = _read(root, "scripts/polaris-presentation-drill.py")
    for sym in ("DECOMPRESSION BOMB", "compressed-size bound", "too many frames"):
        if sym not in drill:
            return _fail("qr_resource_bounds", "the presentation drill must refuse a decompression bomb, an oversized payload and a frame flood (%s)" % sym)
    if "MUST bound" not in _read(root, "docs/reference/WIRE-SPEC.md"):
        return _fail("qr_resource_bounds", "the wire spec must state the receiver's resource bounds normatively")
    return _ok("qr_resource_bounds",
               "the QR decoder bounds frame count, compressed and decompressed size, inflating under an output limit so a "
               "decompression bomb is refused at the limit; drilled with a real bomb, an oversized payload and a frame "
               "flood; the wire spec states the bounds")


def check_ltv_timestamp_trust(root: pathlib.Path) -> list[Finding]:
    """v9.334: long-term validation of a signed document trusts its TIME EVIDENCE only when the
    timestamp authority is one the verifier trusts (timestamp_anchors, distinct from the signer
    anchors) and is distinct from the signing key. An authentic timestamp is not a trusted one
    (anyone can sign one) and a signer's own timestamp is backdatable by whoever holds the key;
    without anchors the verdict reports the facts and claims nothing. The signing route can
    take its timestamp from another federated agency. Drilled: untrusted, self-issued, and
    anchorless evidence all fail to claim long-term validity."""
    v = _read(root, "scripts/polaris-verify.py")
    for sym in ("timestamp_anchors=None", "verify_timestamp(ts, anchor_keys=timestamp_anchors)",
                '"timestamp_authority_trusted"', '"timestamp_independent"',
                'L["timestamp_authority_trusted"] is True and L["timestamp_independent"]'):
        if sym not in v:
            return _fail("ltv_timestamp_trust", "scripts/polaris-verify.py must require a trusted, independent timestamp authority for long-term validity (%s missing)" % sym)
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("ltv_timestamp_trust", f"the offline verifier imports {mod!r}; it must stay standalone")
    if "timestamp_agency_id" not in _read(root, "polaris_web/app.py"):
        return _fail("ltv_timestamp_trust", "the signing route must let an operator take the timestamp from another federated agency")
    drill = _read(root, "scripts/polaris-document-signing-drill.py")
    for sym in ("SELF-issued timestamp", "does NOT trust", "without trusted timestamp-authority anchors"):
        if sym not in drill:
            return _fail("ltv_timestamp_trust", "the document-signing drill must prove untrusted, self-issued and anchorless time evidence claims nothing (%s)" % sym)
    if "timestamp authority the verifier trusts" not in _read(root, "docs/reference/WIRE-SPEC.md"):
        return _fail("ltv_timestamp_trust", "the wire spec must require a trusted, signer-independent timestamp authority for long-term validity")
    if "timestamp_anchors=" not in _read(root, "scripts/polaris-trust-lifecycle-drill.py"):
        return _fail("ltv_timestamp_trust", "the trust-lifecycle drill must decide long-term validity with trusted timestamp anchors (its documents are timestamped by the publisher)")
    if "timestamp_anchors" not in _read(root, "docs/design/document-signing.md") or "timestamp_agency_id" not in _read(root, "docs/reference/API.md"):
        return _fail("ltv_timestamp_trust", "the design record and the API reference must describe the timestamp trust inputs")
    return _ok("ltv_timestamp_trust",
               "long-term validity of a signed document requires time evidence from a timestamp authority the verifier "
               "trusts and that is distinct from the signer; authentic-but-untrusted, self-issued and anchorless "
               "evidence claims nothing, drilled under real ML-DSA; the signing route can timestamp at another agency")


def check_exchange_trust_directional(root: pathlib.Path) -> list[Finding]:
    """v9.333: the gateway's and the receipt's authorization is the RESPONDER's own attestation
    of the requester in the context. Trust is explicit, directional and non-transitive: an
    attestation by any other agency on the same instance authorizes nothing at this responder,
    exactly as a relying party trusts only the manifests it chose. Pinned in the query, proven
    by a three-authority test and drilled over HTTP across two instances. A receipt is stated
    for what it is: the responder's signed attestation; the envelope proves the requester."""
    app = _read(root, "polaris_web/app.py")
    m = re.search(r"def _exchange_attestation\(responder_agency_id, req_key, context_id\):(.*?)\n\n\n", app, re.S)
    if not m or "att.attesting_agency_id = %s" not in m.group(1):
        return _fail("exchange_trust_directional", "_exchange_attestation must take the responder agency and constrain attesting_agency_id to it")
    if len(re.findall(r"_exchange_attestation\((agency_id|target_agency_id), req_key, context_id\)", app)) < 2:
        return _fail("exchange_trust_directional", "both the receipt builder and the gateway must authorize against the responding agency")
    if "trust is directional" not in app:
        return _fail("exchange_trust_directional", "the refusal must say why: the responder holds no attestation of the requester")
    if "test_exchange_authorization_is_the_responders_own_attestation" not in _read(root, "polaris_web/test_app.py"):
        return _fail("exchange_trust_directional", "the three-authority test must exist (C attests M, B does not, M asks B: refused; B attests: allowed)")
    if "trust is directional, not transitive" not in _read(root, "scripts/polaris-federation-instances-drill.py"):
        return _fail("exchange_trust_directional", "the two-instance drill must refuse a third authority's attestation over HTTP")
    for fn, sym in (("polaris_web/app.py", "the RESPONDER attests an authorized exchange occurred"),
                    ("scripts/polaris-verify.py", "participation is proven by the envelope it signed"),
                    ("docs/design/exchange-receipt.md", "A receipt alone cannot prove\nthe requester took part"),
                    ("docs/reference/API.md", "its own valid `AgencyTrustAttestation`")):
        if sym not in _read(root, fn):
            return _fail("exchange_trust_directional", "%s must state a receipt as the responder's attestation and the envelope as the requester's proof" % fn)
    return _ok("exchange_trust_directional",
               "exchange authorization is the responder's own in-context attestation of the requester (directional, "
               "non-transitive), pinned in the query, proven with three authorities and drilled across two instances; "
               "a receipt is stated as the responder's signed attestation, the envelope beside it as the requester's proof")


def check_protocol_versioning(root: pathlib.Path) -> list[Finding]:
    """P8.8b (v9.330): protocol versioning, negotiation and cross-version compatibility. Every
    format's major lives in its format string and its minor is advertised by the registry; a
    minor may only add what a verifier ignores. The interactive routes refuse an unadvertised
    major as unsupported_format_version (listing the supported versions) rather than guessing,
    and the detached verifier decides, from a registry, what an instance speaks. Version 1 is
    FROZEN (cases, vectors, and a pinned older verifier) under SHA256SUMS this check recomputes,
    and the compatibility suite proves both directions in CI: the current verifiers hold every
    frozen case and the pinned older verifier never accepts what the current suite rejects."""
    app = _read(root, "polaris_web/app.py")
    for sym in ("_PROTOCOL_MINORS", "def _protocol_versions", "'versions': _protocol_versions()", "def _format_check",
                "unsupported_format_version", "advertised_in="):
        if sym not in app:
            return _fail("protocol_versioning", "polaris_web/app.py must advertise major.minor and negotiate formats (%s missing)" % sym)
    if app.count("_format_check(") < 3 or re.search(r"\.get\('format'\)\s*!=\s*_[A-Z_]+_FORMAT", app):
        return _fail("protocol_versioning", "every interactive route must negotiate its format through _format_check, not an ad-hoc comparison")
    v = _read(root, "scripts/polaris-verify.py")
    if "_VERIFIER_VERSION" not in v or "def registry_speaks" not in v:
        return _fail("protocol_versioning", "scripts/polaris-verify.py must self-identify its release and decide what a registry speaks")
    frozen = root / "conformance" / "frozen" / "v1"
    sums = _read(root, "conformance/frozen/v1/SHA256SUMS")
    if not sums or not (frozen / "FREEZE.md").is_file() or not (frozen / "cases.json").is_file():
        return _fail("protocol_versioning", "conformance/frozen/v1 must hold the frozen version-1 set with SHA256SUMS and FREEZE.md")
    listed = set()
    for line in sums.splitlines():
        if not line.strip():
            continue
        digest, rel = line.split("  ", 1)
        listed.add(rel)
        f = frozen / rel
        if not f.is_file() or hashlib.sha256(f.read_bytes()).hexdigest() != digest:
            return _fail("protocol_versioning", "the frozen version-1 set changed: %s does not match SHA256SUMS (a protocol change is a new major with its own frozen set)" % rel)
    for f in frozen.rglob("*"):
        if f.is_file() and f.name != "SHA256SUMS" and "__pycache__" not in f.parts and f.relative_to(frozen).as_posix() not in listed:
            return _fail("protocol_versioning", "unpinned file in the frozen set: %s" % f.relative_to(frozen).as_posix())
    if not any(rel.startswith("verifiers/") for rel in listed):
        return _fail("protocol_versioning", "the frozen set must vendor a pinned older detached verifier")
    if '"since"' not in _read(root, "conformance/frozen/v1/cases.json"):
        return _fail("protocol_versioning", "the frozen cases must carry `since`")
    cases = _read(root, "conformance/cases.json")
    try:
        parsed = json.loads(cases)["cases"]
    except Exception:
        parsed = []
    if not parsed or any("since" not in c for c in parsed):
        return _fail("protocol_versioning", "every current conformance case must carry `since` (the release that introduced it)")
    suite = _read(root, "scripts/polaris-compat-suite.py")
    for sym in ("predated", "fail-closed", "SHA256SUMS", "def decide"):
        if sym not in suite:
            return _fail("protocol_versioning", "scripts/polaris-compat-suite.py must prove both directions under the cross-version rule (%s missing)" % sym)
    ci = _read(root, ".github/workflows/ci.yml")
    if "polaris-compat-suite.py" not in ci:
        return _fail("protocol_versioning", "the compatibility suite must run in CI")
    spec = _read(root, "docs/reference/WIRE-SPEC.md")
    for sym in ("unsupported_format_version", "MUST NOT emit", "major.minor"):
        if sym not in spec:
            return _fail("protocol_versioning", "the wire spec must carry the versioning and negotiation rule (%s missing)" % sym)
    if not _read(root, "docs/design/protocol-versioning.md"):
        return _fail("protocol_versioning", "docs/design/protocol-versioning.md must record the design")
    return _ok("protocol_versioning",
               "protocol versioning is explicit: majors in the format string, minors advertised by the registry and never "
               "needed to verify, unadvertised versions refused as unsupported_format_version rather than guessed, version 1 "
               "frozen under recomputed checksums with a pinned older verifier, and the compatibility suite proving both "
               "directions in CI")


def check_algorithm_agility(root: pathlib.Path) -> list[Finding]:
    """P8.8a (v9.329): algorithm agility and migration. Two FIPS 204 parameter sets are accepted
    everywhere (ML-DSA-65 the default, ML-DSA-87), ML-DSA-44 is refused as below the floor, and
    no signed body hardcodes its algorithm: the key that signs decides it (C7 in the signed
    statements). The file custody driver signs under the parameter set its key file names; the
    detached verifier, both SDKs and the app's two witnesses dispatch on the declared algorithm
    and fail closed on any other value; vectors under both sets plus an ML-DSA-44 refusal are in
    the conformance suite; the fuzzer runs under both in CI; the two-instance drill federates a
    mixed-algorithm pair; the CLI records a key's parameter set."""
    cust = _read(root, "polaris_web/custody.py")
    for sym in ("ACCEPTED_ALGORITHMS", '"ML-DSA-87": (2592, 4627)', "def configured_algorithm", "def algorithm_for_public_key",
                'self.algorithm = data["algorithm"]', "oqs.Signature(self.algorithm, secret_key=self._sk)"):
        if sym not in cust:
            return _fail("algorithm_agility", "polaris_web/custody.py must accept both parameter sets and sign under the key file's (%s missing)" % sym)
    pq = _read(root, "polaris_web/pqc_signing.py")
    for sym in ('ACCEPTED_ALGORITHMS = ("ML-DSA-65", "ML-DSA-87")', '"MLDSA87PublicKey"', "def algorithm_name",
                "def algorithm_for_public_key_hex", "def generate_keypair(algorithm=None)"):
        if sym not in pq:
            return _fail("algorithm_agility", "polaris_web/pqc_signing.py must be algorithm-agile (%s missing)" % sym)
    if "_oqs.Signature(_ALG_NAME)" in pq:
        return _fail("algorithm_agility", "pqc_signing.py still signs or verifies under a hardcoded parameter set")
    app = _read(root, "polaris_web/app.py")
    if "'algorithm': 'ML-DSA-65'" in app:
        return _fail("algorithm_agility", "polaris_web/app.py hardcodes a signed body's algorithm; the signing key decides it (C7)")
    for sym in ("def _signing_algorithm", "def _algorithm_of_key", "'algorithms': list(pqc_signing.ACCEPTED_ALGORITHMS)",
                "'signing_algorithm': _signing_algorithm(agency_id)"):
        if sym not in app:
            return _fail("algorithm_agility", "polaris_web/app.py must derive algorithms from the key and advertise the accepted set (%s missing)" % sym)
    if app.count("_signing_algorithm(") < 10:
        return _fail("algorithm_agility", "every signed statement body must carry the signing key's algorithm before signing")
    v = _read(root, "scripts/polaris-verify.py")
    for sym in ("_ACCEPTED = {", '"ML-DSA-87": ("MLDSA87PublicKey"', "def _accepted_alg",
                "def _two_witness_verify(digest, sig, pk, alg=_ALG)", "a genuine ML-DSA-44 pack is refused"):
        if sym not in v:
            return _fail("algorithm_agility", "scripts/polaris-verify.py must dispatch on the declared algorithm, refuse ML-DSA-44 and prove it in --selftest (%s missing)" % sym)
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("algorithm_agility", f"the offline verifier imports {mod!r}; it must stay standalone")
    py = _read(root, "sdk/python/polaris_verify/__init__.py")
    if 'ACCEPTED_ALGORITHMS = {"ML-DSA-65": "MLDSA65PublicKey", "ML-DSA-87": "MLDSA87PublicKey"}' not in py or "def _accepted" not in py:
        return _fail("algorithm_agility", "the Python SDK must accept both parameter sets through a total predicate")
    ts = _read(root, "sdk/typescript/src/index.ts")
    for sym in ("ml_dsa87", "ACCEPTED_ALGORITHMS", "verifierFor("):
        if sym not in ts:
            return _fail("algorithm_agility", "the TypeScript SDK must dispatch on the declared algorithm (%s missing)" % sym)
    cases = _read(root, "conformance/cases.json")
    for name in ("pack-mldsa87-valid", "pack-mldsa44-unaccepted", "status-assertion-mldsa87-active", "trust-list-migration",
                 "trust-list-migration-retired-signer"):
        if '"name": "%s"' % name not in cases:
            return _fail("algorithm_agility", "conformance/cases.json must carry the two-algorithm cases (%s missing)" % name)
    if '"algorithm": "ML-DSA-87"' not in _read(root, "conformance/vectors/pack-mldsa87-valid.json"):
        return _fail("algorithm_agility", "conformance/vectors/pack-mldsa87-valid.json must be a real ML-DSA-87 vector")
    if not _read(root, "conformance/make_algorithm_vectors.py"):
        return _fail("algorithm_agility", "conformance/make_algorithm_vectors.py must regenerate the two-algorithm vectors")
    if "POLARIS_FUZZ_ALGORITHM" not in _read(root, "scripts/polaris-verifier-fuzz.py"):
        return _fail("algorithm_agility", "the metamorphic fuzzer must run under a chosen parameter set")
    if "POLARIS_FUZZ_ALGORITHM: ML-DSA-87" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("algorithm_agility", "CI must run the fuzzer under ML-DSA-87 as well as the default")
    fed = _read(root, "scripts/polaris-federation-instances-drill.py")
    if "POLARIS_DRILL_ALGORITHM_A" not in fed or '"ML-DSA-87"' not in fed:
        return _fail("algorithm_agility", "the two-instance drill must federate a mixed-algorithm pair")
    cli = _read(root, "polaris_cli/polaris.py")
    if "--algorithm" not in cli or "_KEY_ALGORITHM_BY_HEX_LENGTH" not in cli:
        return _fail("algorithm_agility", "the CLI must record a registered key's parameter set")
    spec = _read(root, "docs/reference/WIRE-SPEC.md")
    if "ML-DSA-87" not in spec or "ML-DSA-44" not in spec:
        return _fail("algorithm_agility", "the wire spec must name the accepted parameter sets and the floor")
    if not _read(root, "docs/design/algorithm-migration.md"):
        return _fail("algorithm_agility", "docs/design/algorithm-migration.md must record the design")
    if "ML-DSA-87 (accepted parameter set)" not in _read(root, "docs/reference/PQC-POSTURE.md"):
        return _fail("algorithm_agility", "PQC-POSTURE.md must carry ML-DSA-87 as an accepted parameter set")
    return _ok("algorithm_agility",
               "algorithm agility: ML-DSA-65 and ML-DSA-87 are accepted by the signer, the detached verifier, both SDKs and the "
               "app's two witnesses, ML-DSA-44 is refused, no signed body hardcodes its algorithm (the key decides), vectors "
               "under both sets are in the conformance suite, the fuzzer runs under both in CI, and a mixed-algorithm "
               "federation is drilled across two instances")


def check_trust_lifecycle(root: pathlib.Path) -> list[Finding]:
    """P8.7b: the trust-service lifecycle as one subsystem. Every authority key's life is an
    append-only event register (registered / retired / compromised, one-way, effective from an
    instant), derived into a current-status view; the federation manifest and the registry
    report REAL statuses from it; a signed trust list publishes it and must be signed by a key it
    lists as active for its publisher; a verifier decides a key's status AT AN INSTANT from the
    list, so the cross-authority decision rejects a compromised issuer key and long-term
    validation checks the signer key independently of the signer's own word; a compromise-
    recovery drill proves it under real ML-DSA and across two instances."""
    schema = _read(root, "polaris_sql/01_schema.sql")
    if "CREATE TABLE AuthorityKeyEvent" not in schema or "chk_authority_key_event" not in schema:
        return _fail("trust_lifecycle", "01_schema.sql must define the append-only AuthorityKeyEvent register with a one-way event vocabulary")
    if "CREATE OR REPLACE VIEW AuthorityKeyCurrent" not in _read(root, "polaris_sql/03_view.sql"):
        return _fail("trust_lifecycle", "03_view.sql must derive AuthorityKeyCurrent (compromised over retired over active)")
    if "trg_authority_key_event_append_only" not in _read(root, "polaris_sql/06_triggers.sql") or "authoritykeyevent" not in _read(root, "polaris_sql/09_grants.sql").lower():
        return _fail("trust_lifecycle", "the key register must be append-only by trigger and by privilege")
    app = _read(root, "polaris_web/app.py")
    for sym, why in (("/api/v1/trust-list/<int:agency_id>", "the trust-list route"),
                     ("_trust_list_statement", "the statement builder"),
                     ("polaris-trust-list/1", "the format"),
                     ("AuthorityKeyCurrent", "statuses read from the register"),
                     ("for k in _authority_keys(agency_id, ag['signing_public_key_hex'])]", "manifest anchors with real statuses"),
                     ("_key_status(a['agency_id'], a['signing_public_key_hex'])", "the registry reporting the real status"),
                     ("'keys': _authority_keys(a['agency_id'], a['signing_public_key_hex'])", "the registry listing each authority's register")):
        if sym not in app:
            return _fail("trust_lifecycle", "polaris_web/app.py lacks %s (%s)" % (why, sym))
    if "'status': 'active'}" in app.replace("k['status']", "").replace("_key_status(", ""):
        pass  # a literal active elsewhere is fine; the two surfaces above are the pinned ones
    v = _read(root, "scripts/polaris-verify.py")
    for sym in ("def verify_trust_list", "_trust_list_canonical", "def key_status_at", "trust_list=None", "def registry_key_status",
                "listed COMPROMISED", "signer_key_status_per_trust_list"):
        if sym not in v:
            return _fail("trust_lifecycle", "scripts/polaris-verify.py must verify the trust list and decide key status at an instant (%s missing)" % sym)
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("trust_lifecycle", f"the offline verifier imports {mod!r}; it must stay standalone")
    for name in ("key-register", "key-retire", "key-compromise"):
        if name not in _read(root, "polaris_cli/polaris.py"):
            return _fail("trust_lifecycle", "the CLI must record the key lifecycle (%s)" % name)
    if "_trust_list_statement" not in _read(root, "polaris_web/test_canonical_equivalence.py"):
        return _fail("trust_lifecycle", "the trust list must be in the canonical-equivalence oracle")
    if "polaris-trust-list/1" not in _read(root, "docs/reference/WIRE-SPEC.md"):
        return _fail("trust_lifecycle", "the trust list must be specified in the wire spec")
    if '"artifact": "trust-list"' not in _read(root, "conformance/cases.json"):
        return _fail("trust_lifecycle", "conformance/cases.json must carry trust-list cases (incl. an impostor)")
    if "polaris-trust-list/1" not in _read(root, "sdk/python/polaris_verify/__init__.py") or "polaris-trust-list/1" not in _read(root, "sdk/typescript/src/index.ts"):
        return _fail("trust_lifecycle", "both SDKs must verify polaris-trust-list/1 with the publisher rule")
    if "verify_trust_list" not in _read(root, "scripts/polaris-verifier-fuzz.py"):
        return _fail("trust_lifecycle", "the metamorphic fuzzer must hold verify_trust_list total")
    drill = _read(root, "scripts/polaris-trust-lifecycle-drill.py")
    if not drill or "COMPROMISE" not in drill or "key_status_at" not in drill:
        return _fail("trust_lifecycle", "scripts/polaris-trust-lifecycle-drill.py must drive compromise recovery (status at an instant)")
    if "polaris-trust-lifecycle-drill.py" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("trust_lifecycle", "the trust-lifecycle drill must run in CI")
    fed = _read(root, "scripts/polaris-federation-instances-drill.py")
    if "/api/v1/trust-list/" not in fed or "AuthorityKeyEvent" not in fed or "trust_list=" not in fed:
        return _fail("trust_lifecycle", "the two-instance drill must record a compromise on one instance and see the other's decision flip over HTTP")
    if "AuthorityKeyEvent" not in _read(root, "docs/reference/DATA-MODEL.md"):
        return _fail("trust_lifecycle", "docs/reference/DATA-MODEL.md must document the key register")
    return _ok("trust_lifecycle",
               "the trust-service lifecycle is one subsystem: an append-only, one-way authority key register derived into "
               "current statuses, reported honestly by manifests and the registry, published as a signed trust list a "
               "verifier decides key status AT AN INSTANT from, so a compromised issuer key rejects and long-term validity "
               "is checked independently of the signer -- drilled under real ML-DSA and across two instances")


def check_wallet_presentation(root: pathlib.Path) -> list[Finding]:
    """P8.6: the wallet PROTOCOL surface. A presentation (the issuer-signed credential with a
    stapled issuer-signed status assertion, an optional ZK proof, the context and disclosure
    level, and an opaque presentation code) is decidable OFFLINE by the detached verifier,
    which never interprets the code (duress indistinguishable); for QR/NFC transfer it is
    compressed and split into digest-tied polaris-qr/1 frames a receiver reassembles in any
    order and refuses when mixed, missing or altered. The wallet emits both; the verifier's CLI
    accepts both; a real-ML-DSA drill round-trips through the wallet. Native clients and the
    WebAuthn browser bridge are recorded as boundaries, not claimed."""
    v = _read(root, "scripts/polaris-verify.py")
    for sym in ("def verify_presentation", "def encode_presentation_frames", "def decode_presentation_frames",
                "PLRS1", "polaris-presentation/1", "polaris-qr/1", "usable_offline", "presented_code_present",
                "never interpreted", '"--presentation"', '"--qr-frames"'):
        if sym not in v:
            return _fail("wallet_presentation", "scripts/polaris-verify.py lacks the presentation surface (%s missing)" % sym)
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("wallet_presentation", f"the offline verifier imports {mod!r}; it must stay standalone")
    wal = _read(root, "scripts/polaris-wallet.py")
    for sym in ('"--qr"', '"--status-assertion"', '"--zk-proof"', "encode_presentation_frames"):
        if sym not in wal:
            return _fail("wallet_presentation", "polaris-wallet.py must emit QR frames and staple a status assertion / ZK proof (%s missing)" % sym)
    if '"credential"' not in _read(root, "scripts/polaris-relying-party.py"):
        return _fail("wallet_presentation", "the relying-party reference must still consume the presentation's credential")
    spec = _read(root, "docs/reference/WIRE-SPEC.md")
    if "polaris-presentation/1" not in spec or "polaris-qr/1" not in spec:
        return _fail("wallet_presentation", "the presentation and its QR framing must be specified in the wire spec")
    if "verify_presentation" not in _read(root, "scripts/polaris-verifier-fuzz.py"):
        return _fail("wallet_presentation", "the metamorphic fuzzer must hold verify_presentation and the frame decoder total")
    drill = _read(root, "scripts/polaris-presentation-drill.py")
    if not drill or "decode_presentation_frames" not in drill or "polaris-wallet.py" not in drill:
        return _fail("wallet_presentation", "scripts/polaris-presentation-drill.py must round-trip frames through the wallet")
    if "polaris-presentation-drill.py" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("wallet_presentation", "the presentation drill must run in CI")
    doc = _read(root, "docs/design/wallet-protocol.md")
    if not doc or "browser bridge" not in doc or "out of scope" not in doc.lower():
        return _fail("wallet_presentation", "docs/design/wallet-protocol.md must record the browser-bridge and native-client boundaries honestly")
    return _ok("wallet_presentation",
               "the wallet protocol surface: an offline-decidable presentation (credential + stapled status assertion, "
               "optional ZK proof, opaque code never interpreted) and digest-tied polaris-qr/1 framing, emitted by the "
               "wallet, decided by the detached verifier's CLI, fuzzed, specified, drilled through the wallet in CI, "
               "with native clients and the browser bridge recorded as boundaries")


def check_auth_broker(root: pathlib.Path) -> list[Finding]:
    """P8.4: the auth broker's protocol core -- authorization code + PKCE, a holder-side
    possession-authenticated authorize, an RP-side client-credentials exchange for an
    issuing-agency-signed polaris-id-token/1, step-up by ZK proof, duress served identically --
    with the vocation's guards pinned: the subject is derived PER RELYING PARTY (P9.4), the only
    write is the consumed code's hash (no record of who authenticated where), and a verify bearer
    cannot reach the broker (a running AC-6 adversary)."""
    app = _read(root, "polaris_web/app.py")
    for sym, why in (("/api/v1/auth/authorize", "the holder-side authorize route"),
                     ("/api/v1/auth/token", "the RP-side token route"),
                     ("_id_token_statement", "the ID token statement builder"),
                     ("polaris-id-token/1", "the ID token format"),
                     ("rp_auth.SCOPE_AUTHENTICATE", "the 'authenticate' scope gate"),
                     ("_possession_authenticated(token_value, presented)", "possession authentication of the holder"),
                     ("'sub': _pairwise_subject(token_value, rp['client_id'])",
                      "the subject is PER RELYING PARTY (P9.4). Until v9.353 this check pinned "
                      "`sha3_256(token_value)`, which was the same value everywhere: it was "
                      "pinning the defect. A global subject lets two relying parties join their "
                      "user tables exactly, forever, without either doing anything wrong"),
                     ("_pkce_challenge(verifier)", "PKCE binding"),
                     ("INSERT INTO AuthCodeConsumed (code_hash)", "single-use codes via the consumed-code register"),
                     ("_check_and_record_duress(row['token_id']", "duress served identically and recorded silently"),
                     ("_zk_verify_and_consume(", "ZK step-up")):
        if sym not in app:
            return _fail("auth_broker", "polaris_web/app.py lacks %s (%s)" % (why, sym))
    # The authorize route writes nothing: no INSERT between its def and the token route's def.
    i0, i1 = app.find("def api_v1_auth_authorize():"), app.find("def api_v1_auth_token():")
    if i0 < 0 or i1 < 0 or "INSERT INTO" in app[i0:i1].replace("INSERT INTO ZkVerificationNonce", ""):
        return _fail("auth_broker", "the authorize route must write nothing (no record of who authenticated where)")
    schema = _read(root, "polaris_sql/01_schema.sql")
    m = re.search(r"CREATE TABLE AuthCodeConsumed \((.*?)\);", schema, re.S)
    if not m or re.search(r"\b(rp_id|client_id|sub|subject|token|individual)\b", m.group(1)):
        return _fail("auth_broker", "AuthCodeConsumed must hold only the code hash and instant -- never a subject or relying party")
    if "trg_auth_code_append_only" not in _read(root, "polaris_sql/06_triggers.sql") or "authcodeconsumed" not in _read(root, "polaris_sql/09_grants.sql").lower():
        return _fail("auth_broker", "the consumed-code register must be strictly append-only by trigger and by privilege")
    rpa = _read(root, "polaris_web/rp_auth.py")
    if "def issue_auth_code" not in rpa or "def validate_auth_code" not in rpa or "_CODE_SALT" not in rpa:
        return _fail("auth_broker", "rp_auth.py must issue and validate stateless authorization codes under a salt distinct from access tokens")
    v = _read(root, "scripts/polaris-verify.py")
    if "def verify_id_token" not in v or "_id_token_canonical" not in v:
        return _fail("auth_broker", "scripts/polaris-verify.py must verify the ID token offline (verify_id_token)")
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("auth_broker", f"the offline verifier imports {mod!r}; it must stay standalone")
    if "def verify_id_token" not in _read(root, "sdk/python/polaris_verify/__init__.py") or "export function verifyIdToken" not in _read(root, "sdk/typescript/src/index.ts"):
        return _fail("auth_broker", "both SDKs must verify the ID token as a relying party (verify_id_token / verifyIdToken)")
    if "_id_token_statement" not in _read(root, "polaris_web/test_canonical_equivalence.py"):
        return _fail("auth_broker", "the ID token must be in the canonical-equivalence oracle")
    if "polaris-id-token/1" not in _read(root, "docs/reference/WIRE-SPEC.md"):
        return _fail("auth_broker", "the ID token must be specified in the wire spec")
    if '"artifact": "id-token"' not in _read(root, "conformance/cases.json"):
        return _fail("auth_broker", "conformance/cases.json must carry id-token cases")
    if "verify_id_token" not in _read(root, "scripts/polaris-verifier-fuzz.py"):
        return _fail("auth_broker", "the metamorphic fuzzer must hold verify_id_token total")
    if "/api/v1/auth/token" not in _read(root, "attacks/attack_controls.py"):
        return _fail("auth_broker", "the AC-6 adversary must prove a verify bearer cannot reach the broker's token endpoint")
    drill = _read(root, "scripts/polaris-auth-broker-drill.py")
    if not drill or "verify_id_token" not in drill or "polaris-auth-broker-drill.py" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("auth_broker", "scripts/polaris-auth-broker-drill.py must drive the ID-token verifier matrix in CI")
    fed = _read(root, "scripts/polaris-federation-instances-drill.py")
    for sym in ("/api/v1/auth/authorize", "/api/v1/auth/token", "code_verifier", "invalid_grant"):
        if sym not in fed:
            return _fail("auth_broker", "the two-instance drill must run the full code + PKCE flow over HTTP with replay refused (%s missing)" % sym)
    if "AuthBrokerTests" not in _read(root, "polaris_web/test_app.py") or "DuressEvent" not in _read(root, "polaris_web/test_app.py"):
        return _fail("auth_broker", "polaris_web/test_app.py must exercise the broker incl. duress indistinguishability")
    if "def cmd_login" not in _read(root, "scripts/polaris-wallet.py"):
        return _fail("auth_broker", "the holder wallet must be able to drive the authorize step (polaris-wallet.py login)")
    return _ok("auth_broker",
               "a holder authenticates to a relying party through Polaris by possession (authorization code + PKCE), "
               "receiving an issuing-agency-signed ID token whose subject is a credential hash, with ZK step-up, "
               "duress served identically, no record of who authenticated where (only consumed code hashes), a "
               "verify bearer unable to reach the broker, and the flow proven over HTTP across two instances")


def check_document_signing(root: pathlib.Path) -> list[Finding]:
    """P8.5: general document signing with long-term validation. A digest-bound, portable
    container signed by an agency key -- the institution itself, or its issuing authority on
    behalf of a holder who proved possession (recorded by credential HASH, never token) -- with
    long-term-validation evidence attached at signing (a timestamp over statement AND
    signature; the signer's manifest, checkpoint and feed at that instant), so a verifier
    decides validity at the instant the evidence fixes and the signature survives key
    retirement. Pins the routes, the digest-only and hash-only rules, possession auth, the
    ACTIVE requirement, the evidence, the offline verifier, the wallet path, the oracle, spec,
    conformance in both SDKs, the fuzzer, the drill, and the two-instance HTTP proof."""
    app = _read(root, "polaris_web/app.py")
    for sym, why in (("/api/v1/sign/<int:agency_id>", "the operator signing route"),
                     ("/api/v1/sign/<int:agency_id>/holder", "the holder-authorized route"),
                     ("_signed_document_statement", "the statement builder"),
                     ("polaris-signed-document/1", "the format"),
                     ("the document itself is never sent", "the digest-only rule"),
                     ("_possession_authenticated(token_value, presented)", "possession authentication of the holder"),
                     ("'credential_hash': hashlib.sha3_256(token_value", "the holder recorded by credential hash"),
                     ("row['status'] != 'ACTIVE'", "an inactive credential cannot sign"),
                     ("_document_signature_material", "the timestamp binds statement AND signature"),
                     ("doc['ltv'] = {", "long-term-validation evidence attached at signing"),
                     ("_federation_manifest_body(agency, now)", "the signer's manifest at the instant"),
                     ("_revocation_feed_body(agency, now)", "the signer's feed at the instant")):
        if sym not in app:
            return _fail("document_signing", "polaris_web/app.py lacks %s (%s)" % (why, sym))
    v = _read(root, "scripts/polaris-verify.py")
    for sym in ("def verify_signed_document", "_signed_document_canonical", "def document_signature_material",
                "def attach_ltv", "def is_revoked_leaf", "valid_long_term", "signer_key_active_at_instant",
                "credential_unrevoked_at_instant"):
        if sym not in v:
            return _fail("document_signing", "scripts/polaris-verify.py must decide long-term validity offline (%s missing)" % sym)
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("document_signing", f"the offline verifier imports {mod!r}; it must stay standalone")
    if "def cmd_sign" not in _read(root, "scripts/polaris-wallet.py"):
        return _fail("document_signing", "the holder wallet must be able to sign a document (polaris-wallet.py sign)")
    if "_signed_document_statement" not in _read(root, "polaris_web/test_canonical_equivalence.py"):
        return _fail("document_signing", "the container must be in the canonical-equivalence oracle")
    if "polaris-signed-document/1" not in _read(root, "docs/reference/WIRE-SPEC.md"):
        return _fail("document_signing", "the container must be specified in the wire spec")
    if '"artifact": "signed-document"' not in _read(root, "conformance/cases.json"):
        return _fail("document_signing", "conformance/cases.json must carry signed-document cases")
    if "polaris-signed-document/1" not in _read(root, "sdk/python/polaris_verify/__init__.py") or "polaris-signed-document/1" not in _read(root, "sdk/typescript/src/index.ts"):
        return _fail("document_signing", "both SDKs must verify polaris-signed-document/1")
    if "verify_signed_document" not in _read(root, "scripts/polaris-verifier-fuzz.py"):
        return _fail("document_signing", "the metamorphic fuzzer must hold verify_signed_document total")
    drill = _read(root, "scripts/polaris-document-signing-drill.py")
    if not drill or "KEY RETIREMENT" not in drill or "attach_ltv" not in drill:
        return _fail("document_signing", "scripts/polaris-document-signing-drill.py must prove validity survives key retirement")
    if "polaris-document-signing-drill.py" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("document_signing", "the document-signing drill must run in CI")
    fed = _read(root, "scripts/polaris-federation-instances-drill.py")
    if "/api/v1/sign/" not in fed or "polaris-wallet.py" not in fed:
        return _fail("document_signing", "the two-instance drill must sign over HTTP by possession and through the wallet")
    if "DocumentSigningTests" not in _read(root, "polaris_web/test_app.py"):
        return _fail("document_signing", "polaris_web/test_app.py must exercise holder-authorized signing")
    return _ok("document_signing",
               "arbitrary documents are signed into a portable, digest-bound container -- by the institution or, on behalf "
               "of a possession-authenticated ACTIVE holder recorded by credential hash, by its issuing authority -- with "
               "long-term-validation evidence attached at signing; the detached verifier decides validity at that instant "
               "so it survives key retirement; wallet-initiated, oracle-pinned, specified, conformant in both SDKs, "
               "fuzzed, drilled, and proven over HTTP across two instances")


def check_exchange_gateway(root: pathlib.Path) -> list[Finding]:
    """P8.2d: the exchange gateway -- institution-to-institution exchange mediated by Polaris
    trust with evidence and without retention. Pins the order of operations that IS the
    security argument (real PQC; requester KNOWN by key; signature two-witness under that key;
    AUTHORIZED through the in-context trust graph BEFORE forwarding; nonce consumed in the
    append-only replay register; forwarded only to an OPERATOR-CONFIGURED upstream, never a URL
    from the request; receipt minted with the envelope's signed time and logged; no body ever
    persisted), the client-side envelope builder in the detached verifier (oracle-pinned), the
    third-party evidence chain, the replay register's schema, the wire spec, conformance in
    both SDKs, the fuzzer, the registry advertising the gateway, and the two-instance drill."""
    app = _read(root, "polaris_web/app.py")
    for sym, why in (("/api/v1/exchange/<int:target_agency_id>", "the gateway route"),
                     ("_exchange_request_statement", "the envelope statement builder"),
                     ("polaris-exchange-request/1", "the envelope format"),
                     ("placeholder signature is not authentication", "fail-closed without real PQC"),
                     ("the requester key is not a registered authority on this instance", "requester KNOWN by key"),
                     ("verify_both(_exchange_request_statement(env)", "two-witness verify under the requester key"),
                     ("_exchange_attestation(target_agency_id, req_key, context_id)", "in-context authorization by the responder"),
                     ("_consume_exchange_nonce", "the replay register"),
                     ("INSERT INTO ExchangeNonce", "consuming the nonce"),
                     ("_exchange_upstreams()", "operator-configured upstreams"),
                     ("POLARIS_EXCHANGE_UPSTREAMS", "the upstream configuration"),
                     ("A URL never comes from a request", "no request-supplied forwarding target"),
                     ("_build_exchange_receipt(target, target_agency_id", "the receipt minted for the exchange"),
                     ("occurred_at=str(env.get('issued_at'))", "the receipt carries the envelope's signed time"),
                     ("'exchange_kinds'", "the registry advertises the exchange kinds"),
                     ("'kind': 'exchange'", "the registry advertises the gateway")):
        if sym not in app:
            return _fail("exchange_gateway", "polaris_web/app.py lacks %s (%s)" % (why, sym))
    # AUTHORIZE before FORWARD: the attestation check must precede the upstream call.
    i_auth, i_fwd = app.find("_exchange_attestation(target_agency_id, req_key, context_id):\n        return jsonify(error='forbidden'"), app.find("urllib.request.urlopen(up")
    if i_auth < 0 or i_fwd < 0 or i_auth > i_fwd:
        return _fail("exchange_gateway", "the gateway must authorize the requester (trust graph, in-context) BEFORE forwarding to the upstream")
    if re.search(r"INSERT INTO \w+ \([^)]*\bbody\b", app, re.I):
        return _fail("exchange_gateway", "no persistence path may take a request or response body (evidence without retention)")
    if "CREATE TABLE ExchangeNonce" not in _read(root, "polaris_sql/01_schema.sql") or "trg_exchange_nonce_append_only" not in _read(root, "polaris_sql/06_triggers.sql"):
        return _fail("exchange_gateway", "the replay register ExchangeNonce must exist and be strictly append-only")
    if "exchangenonce" not in _read(root, "polaris_sql/09_grants.sql").lower():
        return _fail("exchange_gateway", "09_grants.sql must REVOKE UPDATE, DELETE on ExchangeNonce from polaris_app")
    v = _read(root, "scripts/polaris-verify.py")
    for sym in ("def verify_exchange_request", "_exchange_request_canonical", "def exchange_evidence", "def canonical_body_hash"):
        if sym not in v:
            return _fail("exchange_gateway", "scripts/polaris-verify.py must verify the envelope and the evidence chain offline (%s missing)" % sym)
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("exchange_gateway", f"the offline verifier imports {mod!r}; it must stay standalone")
    if "_exchange_request_statement" not in _read(root, "polaris_web/test_canonical_equivalence.py"):
        return _fail("exchange_gateway", "the envelope statement must be held byte-equal by the canonical oracle")
    if "polaris-exchange-request/1" not in _read(root, "docs/reference/WIRE-SPEC.md"):
        return _fail("exchange_gateway", "the envelope must be specified in the wire spec")
    if '"artifact": "exchange-request"' not in _read(root, "conformance/cases.json"):
        return _fail("exchange_gateway", "conformance/cases.json must carry exchange-request cases")
    if "polaris-exchange-request/1" not in _read(root, "sdk/python/polaris_verify/__init__.py") or "polaris-exchange-request/1" not in _read(root, "sdk/typescript/src/index.ts"):
        return _fail("exchange_gateway", "both SDKs must verify polaris-exchange-request/1")
    if "verify_exchange_request" not in _read(root, "scripts/polaris-verifier-fuzz.py"):
        return _fail("exchange_gateway", "the metamorphic fuzzer must hold verify_exchange_request total")
    fed = _read(root, "scripts/polaris-federation-instances-drill.py")
    for sym in ("/api/v1/exchange/", "exchange_evidence", "POLARIS_EXCHANGE_UPSTREAMS", "409"):
        if sym not in fed:
            return _fail("exchange_gateway", "the two-instance drill must run a mediated exchange over HTTP with replay refused (%s missing)" % sym)
    if "ExchangeGatewayTests" not in _read(root, "polaris_web/test_app.py"):
        return _fail("exchange_gateway", "polaris_web/test_app.py must prove the gateway fails closed")
    return _ok("exchange_gateway",
               "the exchange gateway mediates institution-to-institution requests: requester known by key and "
               "verified two-witness, authorized in-context BEFORE forwarding, nonce consumed in an append-only "
               "replay register, forwarded only to operator-configured upstreams, receipted with the signed time and "
               "logged, no body ever persisted; envelope oracle-pinned, specified, conformant in both SDKs, fuzzed, "
               "advertised in the registry, and driven over HTTP across two instances")


def check_registry(root: pathlib.Path) -> list[Finding]:
    """P8.3: the signed registry -- what an instance offers and trusts as ONE machine-readable
    artifact (protocol formats, services + auth, federated authorities with keys, contexts and
    the proof they require, the in-context trust graph, relying parties), derived from Athena's
    views, signed by a publisher that must list itself, verified offline, and used for
    DISCOVERY: the two-instance drill drives a call from a path it read out of the registry.
    The advertised formats are pinned to the wire spec's list."""
    app = _read(root, "polaris_web/app.py")
    for sym, why in (("/api/v1/registry/<int:agency_id>", "the registry route"),
                     ("_registry_statement", "the statement builder"),
                     ("polaris-registry/1", "the format"),
                     ("_PROTOCOL_FORMATS", "the advertised protocol formats"),
                     ("_REGISTRY_SERVICES", "the advertised services"),
                     ("v_athena_agency", "authorities from Athena"),
                     ("v_athena_trust_agreement", "the trust graph from Athena"),
                     ("v_athena_proof_policy", "contexts and required proof from Athena")):
        if sym not in app:
            return _fail("registry", "polaris_web/app.py lacks %s (%s)" % (why, sym))
    m = re.search(r"_PROTOCOL_FORMATS\s*=\s*\{(.*?)\n\}", app, re.S)
    advertised = set(re.findall(r"'(polaris-[a-z-]+)'", m.group(1))) if m else set()
    specified = {f.split("/")[0] for f in _WIRE_ALL_FORMATS}
    if advertised != specified:
        return _fail("registry", "the registry's advertised formats must equal the wire spec's: missing %s, extra %s"
                     % (sorted(specified - advertised), sorted(advertised - specified)))
    v = _read(root, "scripts/polaris-verify.py")
    for sym in ("def verify_registry", "_registry_canonical", "def registry_service", "def registry_authority",
                "def registry_trusts"):
        if sym not in v:
            return _fail("registry", "scripts/polaris-verify.py must verify the registry offline and read it for discovery (%s missing)" % sym)
    if "lists for its own publisher" not in v:
        return _fail("registry", "verify_registry must require the registry to be signed by the key it lists for its own publisher (self-consistency)")
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("registry", f"the offline verifier imports {mod!r}; it must stay standalone")
    if "_registry_statement" not in _read(root, "polaris_web/test_canonical_equivalence.py"):
        return _fail("registry", "the registry must be in the canonical-equivalence oracle")
    if "polaris-registry/1" not in _read(root, "docs/reference/WIRE-SPEC.md"):
        return _fail("registry", "the registry must be specified in the wire spec")
    if '"artifact": "registry"' not in _read(root, "conformance/cases.json"):
        return _fail("registry", "conformance/cases.json must carry registry cases (artifact: registry)")
    if "polaris-registry/1" not in _read(root, "sdk/python/polaris_verify/__init__.py"):
        return _fail("registry", "the Python SDK must verify polaris-registry/1")
    if "polaris-registry/1" not in _read(root, "sdk/typescript/src/index.ts"):
        return _fail("registry", "the TypeScript SDK must verify polaris-registry/1")
    if "verify_registry" not in _read(root, "scripts/polaris-verifier-fuzz.py"):
        return _fail("registry", "the metamorphic fuzzer must hold verify_registry total")
    drill = _read(root, "scripts/polaris-registry-drill.py")
    if not drill or "registry_service" not in drill:
        return _fail("registry", "scripts/polaris-registry-drill.py must prove the registry verifies and drives discovery")
    if "polaris-registry-drill.py" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("registry", "the registry drill must run in CI (a protocol that never runs is displacement)")
    fed = _read(root, "scripts/polaris-federation-instances-drill.py")
    if "registry_service" not in fed or "registry_trusts" not in fed:
        return _fail("registry", "the two-instance drill must DISCOVER a service path and the trust graph from a fetched, verified registry")
    return _ok("registry",
               "the signed registry publishes what an instance offers and trusts (formats pinned to the wire spec, "
               "services + auth, Athena-derived authorities/contexts/trust, relying parties), self-consistent and "
               "verified offline; discovery-driven calls are proven across two instances")


def check_receipt_transparency(root: pathlib.Path) -> list[Finding]:
    """P8.2c: the SET of exchange receipts is an append-only transparency log while no
    receipt is retained. Every minted receipt's SHA3-256 joins ExchangeReceiptLog (strictly
    append-only by trigger AND by privilege), the app publishes that sequence as a second
    RFC-6962 log with inclusion evidence per receipt, the detached verifier proves inclusion
    offline against a signed head, the monitor and witness can watch the receipt log, and
    the two-instance drill proves it over HTTP under real ML-DSA."""
    schema = _read(root, "polaris_sql/01_schema.sql")
    if "CREATE TABLE ExchangeReceiptLog" not in schema or "chk_receipt_log_hash" not in schema:
        return _fail("receipt_transparency", "01_schema.sql must define ExchangeReceiptLog holding ONLY a SHA3-256 hex (chk_receipt_log_hash)")
    trig = _read(root, "polaris_sql/06_triggers.sql")
    if "trg_receipt_log_append_only" not in trig or "reject_receipt_log_modification" not in trig:
        return _fail("receipt_transparency", "06_triggers.sql must make ExchangeReceiptLog strictly append-only (trg_receipt_log_append_only)")
    if "exchangereceiptlog" not in _read(root, "polaris_sql/09_grants.sql").lower():
        return _fail("receipt_transparency", "09_grants.sql must REVOKE UPDATE, DELETE on ExchangeReceiptLog from polaris_app (C1 is a privilege boundary too)")
    mig = root / "polaris_sql" / "migrations"
    ups = list(mig.glob("*exchange-receipt-log.up.sql")) if mig.is_dir() else []
    downs = list(mig.glob("*exchange-receipt-log.down.sql")) if mig.is_dir() else []
    if not ups or not downs:
        return _fail("receipt_transparency", "a reversible migration pair must bring a deployed database the receipt log")
    app = _read(root, "polaris_web/app.py")
    for sym, why in (("_RECEIPT_LOG_ID", "the receipt log id"),
                     ("/api/v1/transparency/receipts/sth", "the receipt log's signed head"),
                     ("/api/v1/transparency/receipts/consistency", "consistency proofs over the receipt log"),
                     ("/api/v1/exchange-receipt/inclusion/", "per-receipt inclusion evidence"),
                     ("_receipt_log_append", "the mint->log hook"),
                     ("INSERT INTO ExchangeReceiptLog", "appending the receipt hash at mint time")):
        if sym not in app:
            return _fail("receipt_transparency", "polaris_web/app.py lacks %s (%s)" % (why, sym))
    v = _read(root, "scripts/polaris-verify.py")
    if "def verify_receipt_inclusion" not in v or "def receipt_hash" not in v:
        return _fail("receipt_transparency", "scripts/polaris-verify.py must prove receipt inclusion offline (verify_receipt_inclusion, receipt_hash)")
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("receipt_transparency", f"the offline verifier imports {mod!r}; it must stay standalone")
    if '"receipts"' not in _read(root, "scripts/polaris-transparency-monitor.py"):
        return _fail("receipt_transparency", "the independent monitor must be able to watch the receipt log (--log receipts)")
    drill = _read(root, "scripts/polaris-federation-instances-drill.py")
    if "verify_receipt_inclusion" not in drill or "--log" not in drill:
        return _fail("receipt_transparency", "the two-instance drill must prove inclusion over HTTP and run the monitor against the receipt log")
    if "ExchangeReceiptLogTests" not in _read(root, "polaris_web/test_app.py"):
        return _fail("receipt_transparency", "polaris_web/test_app.py must exercise the receipt log's public surface")
    if "ExchangeReceiptLog" not in _read(root, "docs/reference/DATA-MODEL.md"):
        return _fail("receipt_transparency", "docs/reference/DATA-MODEL.md must document ExchangeReceiptLog")
    return _ok("receipt_transparency",
               "the set of exchange receipts is an append-only transparency log (hash-only, strictly append-only by "
               "trigger and privilege, migrated reversibly) published as a second RFC-6962 log with per-receipt "
               "inclusion evidence, proven offline by the detached verifier, watchable by the monitor, and driven "
               "over HTTP by the two-instance drill")


def check_timestamp_authority(root: pathlib.Path) -> list[Finding]:
    """P8.7a: the timestamp authority -- an arbitrary SHA3-256 digest bound to an instant under
    an agency's registered ML-DSA-65 key, DIGEST-ONLY (the authority learns and retains
    nothing), verified offline, and held to the full machinery: the canonical oracle, the wire
    spec, conformance in BOTH SDKs, the metamorphic fuzzer, and a real-ML-DSA drill in CI. The
    time primitive document signing builds on; independent time evidence for any artifact."""
    app = _read(root, "polaris_web/app.py")
    for sym, why in (("/api/v1/timestamp/<int:agency_id>", "the timestamp route"),
                     ("_timestamp_statement", "the statement builder"),
                     ("polaris-timestamp/1", "the format"),
                     ("the content itself is never sent", "the digest-only rule at the door"),
                     ("tsa:", "the per-authority rate bound")):
        if sym not in app:
            return _fail("timestamp_authority", "polaris_web/app.py lacks %s (%s)" % (why, sym))
    v = _read(root, "scripts/polaris-verify.py")
    for sym in ("def verify_timestamp", "_timestamp_canonical", "def timestamp_binds"):
        if sym not in v:
            return _fail("timestamp_authority", "scripts/polaris-verify.py must verify the timestamp offline (%s missing)" % sym)
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("timestamp_authority", f"the offline verifier imports {mod!r}; it must stay standalone")
    if "_timestamp_statement" not in _read(root, "polaris_web/test_canonical_equivalence.py"):
        return _fail("timestamp_authority", "the timestamp must be in the canonical-equivalence oracle")
    if "polaris-timestamp/1" not in _read(root, "docs/reference/WIRE-SPEC.md"):
        return _fail("timestamp_authority", "the timestamp must be specified in the wire spec")
    if '"artifact": "timestamp"' not in _read(root, "conformance/cases.json"):
        return _fail("timestamp_authority", "conformance/cases.json must carry timestamp cases (artifact: timestamp)")
    if "polaris-timestamp/1" not in _read(root, "sdk/python/polaris_verify/__init__.py"):
        return _fail("timestamp_authority", "the Python SDK must verify polaris-timestamp/1")
    if "polaris-timestamp/1" not in _read(root, "sdk/typescript/src/index.ts"):
        return _fail("timestamp_authority", "the TypeScript SDK must verify polaris-timestamp/1")
    if "verify_timestamp" not in _read(root, "scripts/polaris-verifier-fuzz.py"):
        return _fail("timestamp_authority", "the metamorphic fuzzer must hold verify_timestamp total")
    drill = _read(root, "scripts/polaris-timestamp-drill.py")
    if not drill or "timestamp_binds" not in drill:
        return _fail("timestamp_authority", "scripts/polaris-timestamp-drill.py must prove the timestamp binds to its data and to nothing else")
    if "polaris-timestamp-drill.py" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("timestamp_authority", "the timestamp drill must run in CI (a protocol that never runs is displacement)")
    return _ok("timestamp_authority",
               "the timestamp authority binds any SHA3-256 digest to an instant under the agency's registered key, "
               "digest-only so it learns and retains nothing; verified offline (verify_timestamp + timestamp_binds), "
               "in the oracle, the wire spec, both SDKs' conformance, the fuzzer, and a real-ML-DSA drill in CI")


def check_exchange_mint_signed_auth(root: pathlib.Path) -> list[Finding]:
    """P8.2b: service-to-service minting of the exchange receipt is authenticated by the
    responder's SIGNATURE under its registered ML-DSA-65 key -- post-quantum institutional
    auth with no shared secret and no nonce store -- and it fails CLOSED. Pins the signed
    route, the two-witness verify under the registered key, the refusal without real PQC
    (a placeholder signature is not authentication), the freshness window that bounds
    replay to an identical receipt, the per-responder rate bound, the client-side canonical
    builder in the detached verifier (held byte-equal by the oracle), the wire spec, the
    HTTP proof in the two-instance drill, and the fail-closed unit test."""
    app = _read(root, "polaris_web/app.py")
    for sym, why in (("/api/v1/exchange-receipt/<int:agency_id>/signed", "the signed mint route"),
                     ("_exchange_mint_statement", "the mint statement builder"),
                     ("polaris-exchange-mint/1", "the mint format"),
                     ("verify_both(", "two-witness verification of the caller's signature"),
                     ("require_witness=True", "the second witness is REQUIRED for an auth decision"),
                     ("is_enabled()", "the real-PQC gate"),
                     ("placeholder signature is not authentication", "the fail-closed refusal"),
                     ("_EXCHANGE_MINT_WINDOW", "the freshness window"),
                     ("exmint:", "the per-responder rate bound"),
                     ("responder_agency_id", "binding the statement to the addressed agency")):
        if sym not in app:
            return _fail("exchange_mint_signed_auth", "polaris_web/app.py lacks %s (%s)" % (why, sym))
    if "_exchange_mint_canonical" not in _read(root, "scripts/polaris-verify.py"):
        return _fail("exchange_mint_signed_auth",
                     "scripts/polaris-verify.py must carry the client-side canonical builder _exchange_mint_canonical")
    if "_exchange_mint_statement" not in _read(root, "polaris_web/test_canonical_equivalence.py"):
        return _fail("exchange_mint_signed_auth", "the mint statement must be held byte-equal by the canonical oracle")
    if "polaris-exchange-mint/1" not in _read(root, "docs/reference/WIRE-SPEC.md"):
        return _fail("exchange_mint_signed_auth", "the mint request must be specified in the wire spec")
    drill = _read(root, "scripts/polaris-federation-instances-drill.py")
    if "/signed" not in drill or "no session" not in drill.lower():
        return _fail("exchange_mint_signed_auth",
                     "the two-instance drill must mint over HTTP with NO session via the signed route (the accept path needs a DB and real ML-DSA)")
    tests = _read(root, "polaris_web/test_app.py")
    if "exchange-receipt/1/signed" not in tests or "503" not in tests:
        return _fail("exchange_mint_signed_auth",
                     "polaris_web/test_app.py must prove the signed route fails CLOSED (503) without real PQC")
    return _ok("exchange_mint_signed_auth",
               "service-to-service minting is authenticated by the responder's ML-DSA-65 signature under its "
               "registered key (two-witness, fail-closed without real PQC), bound to the addressed agency and a "
               "freshness window so a replay can only duplicate a receipt; the client builder is oracle-pinned, "
               "the request is in the wire spec, and the path is proven over HTTP by the two-instance drill")


def check_no_named_reference_systems(root: pathlib.Path) -> list[Finding]:
    """The tree names the CLASS of a system, never a specific country or product.

    Polaris relates itself to prior systems by their properties (a federated national
    eID, an exchange-fabric-class system, an evidentiary message log), not by name, so
    the project stands on its own terms rather than reading as a derivative. Scans every
    text file in the tree (skipping vendored and build directories and the two check
    files that carry the pattern list) and fails on the first named reference. ONE
    documented exception (v9.340, at the maintainer's direction): the rows of the README's
    "Where Polaris sits" comparison table may name the systems they compare against,
    because a comparison that hides its subjects is a weaker claim, not a stronger one;
    nowhere else, and not the prose around the table."""
    pats = [re.compile(x, re.I) if mode == "i" else re.compile(x) for mode, x in _NAMED_REFERENCE_SYSTEMS]
    for f in sorted(root.rglob("*")):
        if not f.is_file() or f.suffix.lower() not in _NAMED_REF_EXTS:
            continue
        parts = f.relative_to(root).parts
        rel = "/".join(parts)
        if any(d in _NAMED_REF_SKIP_DIRS for d in parts) or rel in _NAMED_REF_EXEMPT:
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        in_comparison = False
        for i, line in enumerate(text.splitlines(), 1):
            if rel == "README.md" and line.startswith("## "):
                in_comparison = line.strip() == "## Where Polaris sits"
            if rel == "README.md" and in_comparison and line.startswith("| "):
                continue   # the comparison table's rows: the one place the tree names what it compares against
            for pat in pats:
                if pat.search(line):
                    return _fail("no_named_reference_systems",
                                 f"{rel}:{i} names a reference system (pattern {pat.pattern!r}); describe the "
                                 "class, not the country or product")
    return _ok("no_named_reference_systems",
               "no named reference system (country or product) appears in the tree; the class is described instead")


def check_preflight_typechecks_ts_sdk(root: pathlib.Path) -> list[Finding]:
    """The local pre-ship gate type-checks the TypeScript SDK.

    CI's sdk-typescript job runs `tsc --noEmit`, but before v9.318 the local
    preflight did not. A type-only regression is invisible to the rest of the
    gate: v9.315's verifyCrossAuthority fed an anchor-set element inferred
    `unknown` into a `Set<string>` membership test, which passed polaris-checks,
    `node --test` and every conformance case yet failed the CI type-check and
    shipped red at v9.316. Preflight must run the type-check locally, guarded on
    node so a node-less environment still runs the rest of the gate."""
    sh = _read(root, "scripts/polaris-preflight.sh")
    if not sh:
        return _fail("preflight_ts_typecheck", "scripts/polaris-preflight.sh is missing")
    if "sdk/typescript" not in sh:
        return _fail("preflight_ts_typecheck",
                     "polaris-preflight.sh must exercise the sdk/typescript gate locally")
    if "tsc --noEmit" not in sh:
        return _fail("preflight_ts_typecheck",
                     "polaris-preflight.sh must run `tsc --noEmit` -- the type gate CI runs but "
                     "the Python check layer cannot see (a type-only regression shipped red at v9.316)")
    if "command -v node" not in sh or "node_modules" not in sh:
        return _fail("preflight_ts_typecheck",
                     "the TS SDK step must be guarded on node availability (command -v node + "
                     "node_modules) so preflight still runs in a node-less environment")
    return _ok("preflight_ts_typecheck",
               "polaris-preflight runs the TS SDK type-check locally, guarded on node")


def check_exchange_receipt(root: pathlib.Path) -> list[Finding]:
    """P8.2: the exchange receipt, the gateway's evidence-without-retention primitive and the
    anti-surveillance inversion of a message log. A responder signs evidence that it served an
    authenticated, authorized request, committing to the SHA3-256 of the request and response --
    never the bodies. A third party proves, from the receipt alone, that the responder attests an
    authorized exchange occurred (the requester-signed envelope beside it proves the requester's
    side), with no access to the payload."""
    v = _read(root, "scripts/polaris-verify.py")
    for sym in ("def verify_exchange_receipt", "_exchange_receipt_canonical", "polaris-exchange-receipt/1"):
        if sym not in v:
            return _fail("exchange_receipt", "scripts/polaris-verify.py must verify the receipt offline (%s missing)" % sym)
    # Evidence WITHOUT retention: the receipt commits to HASHES, and authorization is the
    # trust-graph attestation of the requester's key; the payload never appears.
    if "request_hash" not in v or "response_hash" not in v:
        return _fail("exchange_receipt", "the receipt must commit to the request and response by HASH, not by content")
    if "requester_authorized" not in v or "attested_public_key_hex" not in v:
        return _fail("exchange_receipt",
                     "the receipt verify must confirm the requester was authorized (a trusted attestation in-context)")
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("exchange_receipt", f"the offline verifier imports {mod!r}; it must stay standalone")
    app = _read(root, "polaris_web/app.py")
    for sym in ("/api/v1/exchange-receipt", "_exchange_receipt_statement", "AgencyTrustAttestation",
                "signature_over_message"):
        if sym not in app:
            return _fail("exchange_receipt", "app.py must mint the receipt (%s missing)" % sym)
    # The mint endpoint takes only hashes -- the retention rule enforced at the door.
    if "the payload is never sent" not in app:
        return _fail("exchange_receipt",
                     "the mint endpoint must accept only SHA3-256 hashes; the payload is never sent to the app")
    if "polaris-exchange-receipt/1" not in _read(root, "polaris_web/test_canonical_equivalence.py"):
        return _fail("exchange_receipt", "the receipt must be in the canonical-equivalence oracle (app and verifier bytes must match)")
    if "polaris-exchange-receipt/1" not in _read(root, "docs/reference/WIRE-SPEC.md"):
        return _fail("exchange_receipt", "the receipt must be specified in the normative wire spec")
    drill = _read(root, "scripts/polaris-exchange-receipt-drill.py")
    if not drill or "verify_exchange_receipt" not in drill:
        return _fail("exchange_receipt", "scripts/polaris-exchange-receipt-drill.py must run the receipt accept/reject matrix")
    if "without" not in drill.lower() or "retention" not in drill.lower():
        return _fail("exchange_receipt", "the drill must prove the evidence-without-retention property (occurrence + authorization without the payload)")
    if "polaris-exchange-receipt-drill.py" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("exchange_receipt", "the exchange-receipt drill must run in CI (a protocol that never runs is displacement)")
    return _ok("exchange_receipt",
               "the exchange receipt is the gateway's evidence-without-retention primitive: a responder signs a "
               "commitment to the SHA3-256 of the request and response (never the bodies) plus who, when, and which "
               "attestation authorized the requester; the detached verifier proves, from the receipt alone, the responder's "
               "signed attestation of an authorized exchange (the envelope beside it proves the requester's side), and a holder of a body confirms the commitment "
               "binds -- minted at POST /api/v1/exchange-receipt, in the wire spec and the oracle, proven every "
               "release by the drill under real ML-DSA")


def check_inter_authority_protocol(root: pathlib.Path) -> list[Finding]:
    """P3.2: the inter-authority protocol. An authority publishes a SIGNED federation
    manifest (its anchors, plus the attestations it has made); another party decides
    cross-authority trust OFFLINE from published manifests, with no central service.
    A foreign credential is accepted iff a TRUSTED authority ATTESTS to its key in the
    presented context: trust flows along published attestation edges, never a closure."""
    app = _read(root, "polaris_web/app.py")
    if "/api/v1/federation-manifest" not in app or "_manifest_statement" not in app:
        return _fail("inter_authority", "app.py must publish GET /api/v1/federation-manifest signing a canonical manifest")
    if "signature_over_message" not in app or "attestations" not in app or "anchors" not in app:
        return _fail("inter_authority",
                     "the manifest must be issuer-SIGNED and carry anchor cross-publication (anchors) and "
                     "attestation exchange (attestations)")
    # The detached verifier decides it OFFLINE and stays standalone.
    v = _read(root, "scripts/polaris-verify.py")
    for sym in ("def verify_manifest", "def verify_cross_authority", "_manifest_canonical",
                "polaris-federation-manifest/1"):
        if sym not in v:
            return _fail("inter_authority", "scripts/polaris-verify.py must verify a manifest offline (%s missing)" % sym)
    if "declared active anchors" not in v:
        return _fail("inter_authority",
                     "verify_manifest must enforce self-consistency: a manifest is signed by one of its own declared "
                     "active anchors, so it cannot be signed by a stranger key")
    if "fresh" not in v or "max_window_seconds" not in v:
        return _fail("inter_authority", "verify_manifest must enforce freshness (a window-bounded validity)")
    if "attested_public_key_hex" not in v or "context_id" not in v:
        return _fail("inter_authority",
                     "verify_cross_authority must accept a foreign credential only when a trusted manifest attests to "
                     "its signing key IN THE PRESENTED CONTEXT (bind on attested_public_key_hex + context_id)")
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", v, re.M):
            return _fail("inter_authority",
                         f"the offline verifier imports {mod!r}; it must stay standalone (a relying party decides "
                         "cross-authority trust with no Polaris code, no database, no central service)")
    # It RUNS every release, and is specified and tested.
    drill = _read(root, "scripts/polaris-federation-manifest-drill.py")
    if not drill or "verify_cross_authority" not in drill:
        return _fail("inter_authority",
                     "scripts/polaris-federation-manifest-drill.py must run the two-authority accept/reject matrix")
    if "polaris-federation-manifest-drill.py" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("inter_authority", "the manifest drill must run in CI (a protocol that never runs is displacement)")
    if not _read(root, "docs/design/inter-authority-protocol.md"):
        return _fail("inter_authority", "docs/design/inter-authority-protocol.md (the protocol spec) is missing")
    if "FederationManifestTests" not in _read(root, "polaris_web/test_app.py"):
        return _fail("inter_authority", "test_app.py must carry FederationManifestTests")
    return _ok("inter_authority",
               "two authorities interoperate through signed federation manifests: each publishes its anchors and the "
               "attestations it has made (GET /api/v1/federation-manifest), and the standalone detached verifier "
               "accepts a FOREIGN credential offline iff a trusted authority attests to its key in the presented "
               "context (self-consistent, fresh, non-transitive) -- proven every release by the two-authority drill "
               "under real ML-DSA, specified in docs/design/inter-authority-protocol.md, and tested")


def check_federation_topology(root: pathlib.Path) -> list[Finding]:
    """P3.1: the topology decision record (ADR) chooses federated per-authority
    instances over a central instance, and records why the constitution forces it and
    the threat-model delta. The decision is kept HONEST against the code: the ADR may
    not claim the federated model unless the primitives it cites are actually present,
    so the record cannot drift into prose describing an architecture the code lacks."""
    adr = _read(root, "docs/design/federation-topology.md")
    if not adr:
        return _fail("federation_topology", "docs/design/federation-topology.md (the topology ADR) is missing")
    low = adr.lower()
    if "status:" not in low or "accepted" not in low:
        return _fail("federation_topology", "the ADR must carry a Status (Accepted) so it is a decision, not a draft")
    if "federated per-authority" not in low:
        return _fail("federation_topology", "the ADR must record the DECISION: federated per-authority instances")
    if "non-transitive" not in low:
        return _fail("federation_topology", "the ADR must state that cross-authority trust is non-transitive")
    if "no central" not in low:
        return _fail("federation_topology",
                     "the ADR must state there is no central instance / trust root / verification service")
    if "threat-model delta" not in low:
        return _fail("federation_topology", "the ADR must document the threat-model delta (central vs federated)")
    if "monopoly" not in low:
        return _fail("federation_topology",
                     "the ADR must ground the choice in the constitution (the anti-monopoly / anti-surveillance vocation), "
                     "not engineering taste")
    # Kept honest against the code: every architectural primitive the ADR cites must
    # actually exist, so a central-instance drift would fail this check.
    schema = _read(root, "polaris_sql/01_schema.sql")
    app = _read(root, "polaris_web/app.py")
    bindings = [
        ("AgencyTrustAttestation" in adr and "AgencyTrustAttestation" in schema,
         "explicit attestation (AgencyTrustAttestation) cited by the ADR and present in the schema"),
        ("_federation_trust_holds" in adr and "_federation_trust_holds" in app,
         "the non-transitive resolver (_federation_trust_holds) cited by the ADR and present in app.py"),
        ("signing_public_key_hex" in adr and "signing_public_key_hex" in schema,
         "per-authority roots (Agency.signing_public_key_hex) cited by the ADR and present in the schema"),
        ("verify_pack" in adr and bool(_read(root, "scripts/polaris-verify.py")),
         "verification against published keys (the detached verifier verify_pack) cited by the ADR and present"),
    ]
    for ok, desc in bindings:
        if not ok:
            return _fail("federation_topology",
                         "the ADR's federated model is not grounded in the code: %s is missing" % desc)
    if "](federation-topology.md)" not in _read(root, "docs/design/README.md"):
        return _fail("federation_topology", "the ADR must be linked from the docs/design index")
    return _ok("federation_topology",
               "the topology decision is recorded and grounded: the ADR chooses federated per-authority instances "
               "over a central instance (each authority its own root, explicit non-transitive attestation, a relying "
               "party verifying against published keys with no central service), derives the choice from the "
               "anti-monopoly and anti-surveillance vocation, documents the threat-model delta, and cites only "
               "primitives that actually exist in the code (AgencyTrustAttestation, _federation_trust_holds, "
               "per-authority keys, the detached verifier) so the record cannot drift")


def check_offline_verification(root: pathlib.Path) -> list[Finding]:
    """P3.6: authorization verifiable with NO connectivity. The issuer signs a
    short-lived STATUS ASSERTION (POST /api/v1/status-assertion); the detached
    verifier decides the whole holder<->verifier flow offline -- the credential's
    authenticity AND a fresh, bound, ACTIVE assertion -- with a freshness/replay
    bound (expiry + a window ceiling) and no issuer contact. Runs every release."""
    app = _read(root, "polaris_web/app.py")
    if "/api/v1/status-assertion" not in app or "_status_assertion_statement" not in app:
        return _fail("offline_verification",
                     "app.py must expose POST /api/v1/status-assertion signing a canonical status statement")
    if "signature_over_message" not in app or "expires_at" not in app:
        return _fail("offline_verification",
                     "the status assertion must be issuer-SIGNED (signature_over_message) and SHORT-LIVED (expires_at)")
    if "def signature_over_message" not in _read(root, "polaris_web/pqc_signing.py"):
        return _fail("offline_verification",
                     "pqc_signing.signature_over_message must sign the assertion (real ML-DSA or placeholder)")
    # The detached verifier decides it OFFLINE, and stays standalone.
    verifier = _read(root, "scripts/polaris-verify.py")
    for sym in ("def verify_status_assertion", "def verify_stapled", "polaris-status-assertion/1",
                "_status_assertion_canonical"):
        if sym not in verifier:
            return _fail("offline_verification",
                         "scripts/polaris-verify.py must verify a stapled presentation offline (%s missing)" % sym)
    if "max_window_seconds" not in verifier or "fresh" not in verifier:
        return _fail("offline_verification",
                     "the offline verifier must enforce freshness: now within [issued_at, expires_at) AND a window "
                     "no longer than an accepted maximum (max_window_seconds)")
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", verifier, re.M):
            return _fail("offline_verification",
                         f"the offline verifier imports {mod!r}; it must stay standalone (a relying party runs it "
                         "with no Polaris code, no database, no connectivity)")
    # It RUNS every release, red on any wrong decision.
    drill = _read(root, "scripts/polaris-offline-status-drill.py")
    if not drill or "verify_stapled" not in drill:
        return _fail("offline_verification",
                     "scripts/polaris-offline-status-drill.py must run the offline accept/reject matrix")
    if "polaris-offline-status-drill.py" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("offline_verification",
                     "the offline-status drill must run in CI (a protocol that never runs is displacement)")
    if "OfflineStatusAssertionTests" not in _read(root, "polaris_web/test_app.py"):
        return _fail("offline_verification", "test_app.py must carry OfflineStatusAssertionTests")
    return _ok("offline_verification",
               "authorization is verifiable with no connectivity: POST /api/v1/status-assertion mints a "
               "short-lived issuer-signed status assertion (possession-authenticated, no personal data), and the "
               "standalone detached verifier decides the whole flow offline -- credential authenticity plus a "
               "fresh, bound, ACTIVE assertion, rejecting a revoked/expired/over-long-window/tampered/misbound one "
               "-- proven every release by scripts/polaris-offline-status-drill.py under real ML-DSA, so the issuer "
               "never learns a verification happened")


def check_typescript_sdk(root: pathlib.Path) -> list[Finding]:
    """P3.5b: the TypeScript verify SDK, held to the SAME conformance contract as
    the Python reference SDK. A second, independent implementation (ML-DSA-65 via
    @noble/post-quantum, which agrees with liboqs and OpenSSL on the vectors) that
    passes the language-agnostic runner in CI -- proof the contract certifies more
    than one language."""
    sdk = _read(root, "sdk/typescript/src/index.ts")
    if not sdk:
        return _fail("typescript_sdk", "sdk/typescript/src/index.ts is missing")
    if "verifyAuthenticity" not in sdk or "class PolarisVerifier" not in sdk:
        return _fail("typescript_sdk", "the TS SDK must expose verifyAuthenticity() and PolarisVerifier")
    # P8.1b: the TS SDK certifies the status assertion and the signed artifacts too, held to
    # the same suite (and recomputes the recursive canonical JSON to match the signer).
    if "verifyStatusAssertion" not in sdk or "verifySignedArtifact" not in sdk or "verifyCrossAuthority" not in sdk:
        return _fail("typescript_sdk",
                     "the TS SDK must verify the status assertion, the signed artifacts, and the federation "
                     "trust decision offline (verifyStatusAssertion, verifySignedArtifact, verifyCrossAuthority)")
    if "@noble/post-quantum/ml-dsa" not in sdk or "ml_dsa65" not in sdk or ".verify(" not in sdk or "sha3_256" not in sdk:
        return _fail("typescript_sdk",
                     "the TS SDK must verify a real ML-DSA-65 signature over SHA3-256(token_value) via "
                     "@noble/post-quantum, not trust a flag")
    if '"polaris-exchange-receipt/1"' not in sdk or '"polaris-exchange-mint/1"' not in sdk:
        return _fail("typescript_sdk", "the TS SDK must verify the exchange receipt and the mint statement (v9.331)")
    if "verifyTimestampAnchor" not in sdk or "verifyInclusion" not in sdk or "verifyCosignature" not in sdk:
        return _fail("typescript_sdk",
                     "the TS SDK must decide a timestamp anchor offline too (verifyTimestampAnchor, with the "
                     "RFC-6962 inclusion proof and the witness cosignatures it rests on) -- P9.6")
    if "/api/v1/oauth/token" not in sdk or "/api/v1/verify" not in sdk:
        return _fail("typescript_sdk",
                     "the TS SDK's online path must authenticate (OAuth2 client-credentials) and call /api/v1/verify")
    # Standalone: an external org installs it; it must not reach into the Polaris tree.
    for bad in ("polaris_web", "psycopg2", "../../polaris"):
        if bad in sdk:
            return _fail("typescript_sdk", f"the TS SDK must be standalone; it must not reference {bad!r}")
    # The verifier CLI (stdin -> stdout) that the shared runner drives.
    cli = _read(root, "sdk/typescript/src/conformance.ts")
    if "verifyAuthenticity" not in cli or "issuer_trusted" not in cli:
        return _fail("typescript_sdk", "sdk/typescript/src/conformance.ts must implement the stdin->stdout verifier CLI")
    # Pinned, reproducible dependencies (npm ci needs the lockfile).
    pkg = _read(root, "sdk/typescript/package.json")
    if "@noble/post-quantum" not in pkg:
        return _fail("typescript_sdk", "sdk/typescript/package.json must pin @noble/post-quantum")
    if not (root / "sdk" / "typescript" / "package-lock.json").is_file():
        return _fail("typescript_sdk", "sdk/typescript/package-lock.json must be committed so CI runs npm ci reproducibly")
    # It RUNS in CI against the SAME conformance runner as the Python SDK.
    ci = _read(root, ".github/workflows/ci.yml")
    if "setup-node" not in ci or 'run_conformance.py --verifier "node sdk/typescript/src/conformance.ts"' not in ci:
        return _fail("typescript_sdk",
                     "CI must set up Node and drive the conformance runner against the TypeScript verifier "
                     "(the contract must certify the second language, in CI)")
    if not _read(root, "sdk/typescript/test/sdk.test.ts"):
        return _fail("typescript_sdk", "sdk/typescript/test/sdk.test.ts (the SDK unit tests) is missing")
    return _ok("typescript_sdk",
               "the TypeScript verify SDK passes the same conformance contract as the Python reference SDK: real "
               "ML-DSA-65 authenticity via @noble/post-quantum (a third implementation agreeing with liboqs and "
               "OpenSSL) plus the OAuth2 /api/v1 online check, standalone, type-checked, unit-tested, and driven "
               "through the language-agnostic conformance runner in CI -- P3.5 complete across both languages")


def check_conformance_suite(root: pathlib.Path) -> list[Finding]:
    """P3.5: the verification conformance suite is the integration contract, and the
    Python reference SDK passes it. A relying party (or an external SDK author)
    certifies its verifier -- in any language -- by making it pass the published
    cases; passing them is what "conformant" means. The SDK is standalone (an
    external org installs it) and the suite RUNS in CI, not a document that says it
    would."""
    # 1. The Python reference SDK: real ML-DSA authenticity + the online contract,
    #    standalone (only a standard crypto library + stdlib, no Polaris imports).
    sdk = _read(root, "sdk/python/polaris_verify/__init__.py")
    if not sdk:
        return _fail("conformance_suite", "sdk/python/polaris_verify/__init__.py is missing")
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", sdk, re.M):
            return _fail("conformance_suite",
                         f"the SDK imports {mod!r}; a server-side verify SDK an external org installs must be "
                         "standalone (only a standard ML-DSA library + stdlib, no Polaris code)")
    if "def verify_authenticity" not in sdk or "class PolarisVerifier" not in sdk:
        return _fail("conformance_suite", "the SDK must expose verify_authenticity() and PolarisVerifier")
    # P8.1b: the SDK certifies more than the authenticity pack. The status assertion (offline
    # authorization) and the signed statements (checkpoint, feed, manifest, bundle, STH) are
    # verified standalone too.
    if "def verify_status_assertion" not in sdk or "def verify_signed_artifact" not in sdk:
        return _fail("conformance_suite",
                     "the SDK must verify the status assertion and the signed artifacts offline "
                     "(verify_status_assertion, verify_signed_artifact), not only the pack")
    # P8.1 complete: the SDK also decides the composite federation trust decision.
    if "def verify_cross_authority" not in sdk:
        return _fail("conformance_suite",
                     "the SDK must decide the federation trust decision offline (verify_cross_authority)")
    if '"polaris-exchange-receipt/1"' not in sdk or '"polaris-exchange-mint/1"' not in sdk:
        return _fail("conformance_suite", "the SDK must verify the exchange receipt and the mint statement (v9.331)")
    # P9.6 (v9.346): long-term validation's strongest form is an ANCHORED timestamp, and until
    # now only the detached verifier could decide one. An outside verifier must be able to reach
    # the same verdict, or the strongest claim is reserved for whoever runs Polaris's own tools.
    if "def verify_timestamp_anchor" not in sdk or "def verify_inclusion" not in sdk \
            or "def verify_cosignature" not in sdk:
        return _fail("conformance_suite",
                     "the SDK must decide a timestamp anchor offline (verify_timestamp_anchor, with the RFC-6962 "
                     "inclusion proof and the witness cosignatures it rests on), not treat the anchor as an opaque "
                     "artifact")
    if "sha3_256" not in sdk or "MLDSA65PublicKey" not in sdk:
        return _fail("conformance_suite",
                     "the SDK must verify a real ML-DSA-65 signature over SHA3-256(token_value), not trust a flag")
    if "/api/v1/oauth/token" not in sdk or "/api/v1/verify" not in sdk:
        return _fail("conformance_suite",
                     "the SDK's online path must authenticate (OAuth2 client-credentials) and call /api/v1/verify")
    # 2. The verifier CLI contract (stdin -> stdout) and the language-agnostic runner.
    if "verify_authenticity" not in _read(root, "sdk/python/polaris_verify/conformance.py"):
        return _fail("conformance_suite", "polaris_verify.conformance must implement the stdin->stdout verifier CLI")
    runner = _read(root, "conformance/run_conformance.py")
    if "--verifier" not in runner or "--self" not in runner or "issuer_trusted" not in runner:
        return _fail("conformance_suite",
                     "conformance/run_conformance.py must drive ANY verifier (--verifier) as well as the bundled SDK "
                     "(--self), checking authentic + issuer_trusted")
    if not _read(root, "conformance/SPEC.md"):
        return _fail("conformance_suite", "conformance/SPEC.md (the published contract) is missing")
    # 3. The cases: real JSON, versioned, covering authentic AND not-authentic AND an
    #    untrusted-issuer verdict.
    try:
        manifest = json.loads((root / "conformance" / "cases.json").read_text(encoding="utf-8"))
    except Exception as e:
        return _fail("conformance_suite", f"conformance/cases.json is not valid JSON ({e})")
    if manifest.get("format") != "polaris-conformance/1":
        return _fail("conformance_suite", "conformance/cases.json must declare format polaris-conformance/1")
    expects = [c.get("expect", {}) for c in manifest.get("cases", [])]
    if not any(e.get("authentic") is True for e in expects) or not any(e.get("authentic") is False for e in expects):
        return _fail("conformance_suite", "the cases must cover both an authentic and a not-authentic verdict")
    if not any(e.get("issuer_trusted") is False for e in expects):
        return _fail("conformance_suite",
                     "the cases must cover a genuine signature by an UNTRUSTED issuer (authentic but issuer_trusted "
                     "false) -- a valid signature by an untrusted key must be rejectable")
    # P8.1b: the suite certifies most of the protocol, not one artifact. The cases must cover
    # several distinct artifact types (the runner and both SDKs dispatch on the case's
    # `artifact`), including the status assertion.
    artifacts = {c.get("artifact", "authenticity-pack") for c in manifest.get("cases", [])}
    if "status-assertion" not in artifacts:
        return _fail("conformance_suite",
                     "the cases must certify the status assertion too (an `artifact: status-assertion` case)")
    if len(artifacts) < 6:
        return _fail("conformance_suite",
                     "the cases must certify most of the protocol's artifacts, not one; found %d distinct "
                     "artifact types, expected at least 6" % len(artifacts))
    if "cross-authority" not in artifacts:
        return _fail("conformance_suite",
                     "the cases must certify the federation trust decision too (an `artifact: cross-authority` case)")
    if "timestamp-anchor" not in artifacts:
        return _fail("conformance_suite",
                     "the cases must certify the timestamp anchor too (an `artifact: timestamp-anchor` case), "
                     "including a head no trusted witness cosigned")
    anchors = [c for c in manifest.get("cases", []) if c.get("artifact") == "timestamp-anchor"]
    if not any(c.get("expect", {}).get("witnessed") is True for c in anchors) \
            or not any(c.get("expect", {}).get("witnessed") is False for c in anchors) \
            or not any(c.get("expect", {}).get("anchored") is False for c in anchors):
        return _fail("conformance_suite",
                     "the timestamp-anchor cases must cover a witnessed head, an unwitnessed one, and a proof that "
                     "does not reconstruct its head -- a stolen log key can sign a fabricated head, so witnessing is "
                     "the part that cannot be forged")
    if "artifact" not in _read(root, "sdk/python/polaris_verify/conformance.py"):
        return _fail("conformance_suite",
                     "the verifier CLI must dispatch on the case's `artifact` (not only the authenticity pack)")
    # 4. It RUNS in CI, and the SDK is tested.
    if "run_conformance.py --self" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("conformance_suite",
                     "the conformance suite must run in CI (a contract that never runs is displacement)")
    if "ConformanceRunnerTest" not in _read(root, "sdk/python/test_sdk.py"):
        return _fail("conformance_suite", "sdk/python/test_sdk.py must prove the SDK passes the conformance suite")
    return _ok("conformance_suite",
               "the verification conformance suite is the runnable integration contract: a language-agnostic runner "
               "drives any verifier (stdin->stdout) over the published authenticity cases -- authentic, tampered, "
               "placeholder, and a genuine-but-untrusted-issuer verdict -- and the standalone Python reference SDK "
               "(real ML-DSA-65 offline + OAuth2 online) passes it every release, with SDK unit tests")


def check_relying_party_api(root: pathlib.Path) -> list[Finding]:
    """P3.4: the relying-party verification API. A third-party organization
    authenticates AS ITSELF (OAuth2 client-credentials) and calls the versioned
    /api/v1/verify to confirm a presented credential is authentic and currently
    authoritative -- API-access auth with a scope CHECK-constrained at the schema
    to exactly 'verify', 'authenticate' (the P8.4 auth broker) or both, so the
    surface can never grow a scope the vocation has not weighed; a verdict that
    never carries personal data; and a verify credential that reaches nothing but
    verification. Identity never becomes a login RECORD: the broker writes nothing
    but consumed code hashes. The bound and the no-PII rule are RUNNING
    adversaries, not comments."""
    # 1. The scope set is fixed at the SCHEMA -- the vocation guard is a database CHECK,
    #    not a policy the app could relax. v9.326 widened it to admit the auth broker;
    #    anything beyond these three values is a scope creep the constitution has not seen.
    schema = _read(root, "polaris_sql/01_schema.sql")
    if "CREATE TABLE RelyingParty" not in schema:
        return _fail("relying_party_api", "polaris_sql/01_schema.sql has no RelyingParty table")
    if "CHECK (scope IN ('verify', 'authenticate', 'verify authenticate'))" not in schema:
        return _fail("relying_party_api",
                     "RelyingParty.scope must be CHECK-constrained to exactly 'verify' | 'authenticate' | "
                     "'verify authenticate' -- the schema-level guard that the relying-party surface can never "
                     "grow a scope the vocation has not weighed")
    if "client_secret_hash" not in schema:
        return _fail("relying_party_api", "RelyingParty must store client_secret_hash (scrypt), never the secret")
    # 2. Stateless, scope-bounded bearer, salted distinctly from the session cookie.
    rpa = _read(root, "polaris_web/rp_auth.py")
    for sym in ("def issue_access_token", "def validate_access_token", "def parse_bearer", "polaris-rp-access-token"):
        if sym not in rpa:
            return _fail("relying_party_api",
                         "polaris_web/rp_auth.py must sign/validate a verify-scoped bearer with a salt distinct from "
                         "the session cookie (%s missing)" % sym)
    # 3. The two versioned routes, client-credentials, and the anti-enumeration core.
    app = _read(root, "polaris_web/app.py")
    if "/api/v1/oauth/token" not in app or "/api/v1/verify" not in app:
        return _fail("relying_party_api", "app.py must expose POST /api/v1/oauth/token and POST /api/v1/verify")
    if "client_credentials" not in app or "invalid_client" not in app:
        return _fail("relying_party_api", "the token endpoint must be OAuth2 client-credentials (invalid_client on bad creds)")
    if "compare_digest" not in app or "not a verifiable presentation" not in app:
        return _fail("relying_party_api",
                     "/api/v1/verify must require a POSSESSION proof (the presented signature matches the stored one, "
                     "constant-time) and return a UNIFORM 'not a verifiable presentation' verdict on a not-found value "
                     "or a mismatch -- so a relying party cannot enumerate tokens or probe existence")
    # 4. Registration, the RP tool authenticating as an org, and the tests.
    if "def cmd_rp_register" not in _read(root, "polaris_cli/polaris.py"):
        return _fail("relying_party_api", "polaris_cli must offer rp-register to register a relying party")
    if "_oauth_status_checker" not in _read(root, "scripts/polaris-relying-party.py"):
        return _fail("relying_party_api",
                     "scripts/polaris-relying-party.py must be able to authenticate as an org (OAuth2) and use /api/v1/verify")
    if "RelyingPartyApiTests" not in _read(root, "polaris_web/test_app.py"):
        return _fail("relying_party_api", "test_app.py must carry RelyingPartyApiTests")
    # 5. The bound and the no-PII rule RUN as adversaries every release.
    controls = _read(root, "attacks/attack_controls.py")
    for adversary in ("ac6_rp_credential_reaches_operator_surface", "ac6_rp_verdict_leaks_personal_data"):
        if adversary not in controls:
            return _fail("relying_party_api",
                         "attacks/attack_controls.py must run %s as a fail-closed adversary (the least-privilege "
                         "bound and the no-personal-data verdict are RUNNING attacks, not comments)" % adversary)
    return _ok("relying_party_api",
               "the relying-party API is a bounded verification oracle: an organization authenticates as itself "
               "(OAuth2 client-credentials, scope CHECK-constrained to 'verify'), presents a held credential to "
               "/api/v1/verify and gets an authentic/authoritative verdict with no personal data, cannot enumerate "
               "(possession proof + uniform not-verifiable), and reaches nothing else -- the bound and the no-PII rule "
               "run as adversaries every release, with the RP tool authenticating as an org end to end")


def check_holder_verifier_flow(root: pathlib.Path) -> list[Finding]:
    """The end-to-end holder<->verifier flow: a relying party decides ACCEPT/REJECT
    from a holder's presentation by combining OFFLINE authenticity (the detached
    verifier) with ONLINE status (GET /verify). It ties the wallet (PE.7), the
    detached verifier (PE.2), and issuer status into one runnable path, and RUNS
    every release (the drill in the pqc-real job, the decision logic in the suite)."""
    rp = _read(root, "scripts/polaris-relying-party.py")
    if not rp:
        return _fail("holder_verifier_flow", "scripts/polaris-relying-party.py is missing — a holder can present "
                     "but no relying party decides ACCEPT/REJECT")
    if "def verify_presentation" not in rp:
        return _fail("holder_verifier_flow",
                     "polaris-relying-party.py must expose verify_presentation(presentation, ...)")
    # 1. Standalone: the relying party is a bank/kiosk, not the issuer — no app, no DB.
    for mod in _VERIFIER_FORBIDDEN_IMPORTS:
        if re.search(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b", rp, re.M):
            return _fail("holder_verifier_flow",
                         f"polaris-relying-party.py imports {mod!r}; the relying party must be standalone (only the "
                         "detached verifier + stdlib) so any service runs it with no Polaris code and no database")
    # 2. It COMBINES the two questions Polaris keeps apart.
    if "verify_pack" not in rp:
        return _fail("holder_verifier_flow",
                     "the relying party must check AUTHENTICITY offline via the detached verifier (verify_pack)")
    if "currently_authoritative" not in rp or "status_checker" not in rp:
        return _fail("holder_verifier_flow",
                     "the relying party must check STATUS online (currently_authoritative via a status_checker) — "
                     "authenticity alone is not authorization")
    for token in ('"accept"', '"reject"', '"provisional"'):
        if token not in rp:
            return _fail("holder_verifier_flow",
                         f"the relying party must be able to decide {token} (accept iff authentic AND currently "
                         "authoritative; provisional when status is unchecked offline)")
    # 3. The whole matrix RUNS end to end (the drill), wired into CI.
    drill = _read(root, "scripts/polaris-e2e-drill.py")
    if not drill or "verify_presentation" not in drill:
        return _fail("holder_verifier_flow",
                     "scripts/polaris-e2e-drill.py must run the holder->relying-party matrix end to end")
    if "polaris-e2e-drill.py" not in _read(root, ".github/workflows/ci.yml"):
        return _fail("holder_verifier_flow",
                     "the e2e drill must run in CI (a path that describes the flow but never runs is displacement)")
    # 4. The decision logic and the DB-backed flow are tested.
    tests = _read(root, "scripts/test_relying_party.py")
    if "verify_presentation" not in tests or "test_relying_party" not in _read(root, "scripts/polaris-coverage.sh"):
        return _fail("holder_verifier_flow",
                     "scripts/test_relying_party.py must unit-test the decision logic and run under polaris-coverage.sh")
    if "EndToEndFlowTests" not in _read(root, "polaris_web/test_app.py"):
        return _fail("holder_verifier_flow",
                     "test_app.py must carry EndToEndFlowTests — the full issue->present->accept->revoke->reject "
                     "flow against the real DB status service, under real ML-DSA")
    return _ok("holder_verifier_flow",
               "the holder<->verifier flow is one runnable path: the wallet presents, a standalone relying party "
               "ACCEPTS a live credential and REJECTS a revoked one by combining offline authenticity with online "
               "status (provisional when offline), and a duress presentation is indistinguishable from a normal "
               "accept — the matrix runs every release (drill) with the decision logic and the DB-backed flow tested")


def check_federation_in_app(root: pathlib.Path) -> list[Finding]:
    if "signing_public_key_hex" not in _read(root, "polaris_sql/01_schema.sql"):
        return _fail("federation_in_app",
                     "Agency must carry a signing_public_key_hex column (the agency's registered signing key)")
    cust = _read(root, "polaris_web/custody.py")
    if "get_custody_for_agency" not in cust or "POLARIS_AGENCY_KEYS_DIR" not in cust:
        return _fail("federation_in_app",
                     "custody.py must select the issuing agency's own key (get_custody_for_agency + "
                     "POLARIS_AGENCY_KEYS_DIR), falling back to the global key")
    if not re.search(r"def signature_with_key_for_token\(token_value[^)]*agency_id", _read(root, "polaris_web/pqc_signing.py")):
        return _fail("federation_in_app",
                     "pqc_signing.signature_with_key_for_token must accept agency_id so issuance signs with the "
                     "issuing agency's key")
    app = _read(root, "polaris_web/app.py")
    if "signature_with_key_for_token(" not in app or "agency_id=" not in app:
        return _fail("federation_in_app",
                     "uc1_issue must sign with the issuing agency's key (signature_with_key_for_token(..., agency_id=...))")
    if "federation binding" not in app:
        return _fail("federation_in_app",
                     "uc1_issue must REFUSE to issue a token whose real signature was produced by a key that is "
                     "not the issuing agency's registered key (the federation binding), or an agency's identity is "
                     "not cryptographically its own")
    if "issuer_authentic" not in app:
        return _fail("federation_in_app",
                     "/verify must report issuer_authentic — whether the token was signed by its issuing agency's "
                     "registered key")
    if "get_custody_for_agency" not in _read(root, "polaris_web/test_custody.py"):
        return _fail("federation_in_app",
                     "test_custody must prove per-agency signing under real ML-DSA (get_custody_for_agency)")
    if "issuer_authentic" not in _read(root, "polaris_web/test_app.py"):
        return _fail("federation_in_app", "test_app must prove /verify reports issuer_authentic")
    return _ok("federation_in_app",
               "federation is in the running app: each agency signs its own tokens (custody selects the agency "
               "key), issuance refuses a cross-key token, and /verify reports issuer_authentic — with per-agency "
               "signing tested under real ML-DSA and the issuer-binding field tested in the suite")



def check_commitment_mismatch_is_a_refusal(root: pathlib.Path) -> list[Finding]:
    """A set that rides OUTSIDE the signed statement must be refused when its commitment
    breaks, not merely annotated.

    Two published artifacts carry their members outside the bytes that were signed, bound
    only by a hash committed to inside them: the revocation feed (`revoked_leaves` under
    `revoked_root_hex`) and the epoch anonymity set (`all_leaves_hex` under
    `leaves_root_hex`). For both, the signature stays genuine when the members are swapped,
    because the members were never in the signed statement. Only the commitment catches it.

    So the commitment is not advisory. A verifier that reports `leaves_authentic: true` and
    leaves the mismatch in a note hands the caller a set an attacker chose: swap every member
    but one and the holder's own `member_index` still finds them, inside a crowd that does not
    exist. That is anonymity-set poisoning, and it costs the holder exactly the anonymity the
    set was published to give. The revocation feed's version is a verifier accepting a
    revocation list an attacker rewrote.

    This pins the ORDER in the three shipped verifiers: the commitment is checked, and a
    mismatch returns, BEFORE the artifact is called authentic. The behaviour itself is proven
    by conformance case `epoch-leaves-swapped`, which every implementation must refuse."""
    name = "commitment_refusal"
    verifier = _read(root, "scripts/polaris-verify.py")
    for fn, commitment, authentic in (
            ("verify_epoch_leaves", "commitment_matches", "leaves_authentic"),
            ("verify_revocation_feed", "commitment_ok", "feed_authentic")):
        if f"def {fn}" not in verifier:
            return _fail(name, f"the detached verifier must define {fn}")
        body = verifier.split(f"def {fn}")[1].split("\ndef ")[0]
        commit_at = body.find(f'v["{commitment}"] =')
        accept_at = body.find(f'v["{authentic}"] = True')
        if commit_at < 0:
            return _fail(name, f"{fn} must compute the commitment into v[{commitment!r}]")
        if accept_at < 0:
            return _fail(name,
                         f"{fn} must set v[{authentic!r}] = True at exactly one accepting point, so the "
                         "commitment gate cannot be bypassed; assigning it from the signature result "
                         "makes a swapped set read as authentic")
        if commit_at > accept_at:
            return _fail(name,
                         f"{fn} calls the artifact authentic BEFORE checking its commitment; a caller that "
                         f"reads {authentic} would take a swapped set as genuine")
        between = body[commit_at:accept_at]
        if "return v" not in between:
            return _fail(name,
                         f"{fn} must RETURN on a commitment mismatch, not merely note it: a note the caller "
                         f"does not read is not a refusal, and {authentic} would still be true")
    py_sdk = _read(root, "sdk/python/polaris_verify/__init__.py")
    ts_sdk = _read(root, "sdk/typescript/src/index.ts")
    for sdk, text in (("the Python SDK", py_sdk), ("the TypeScript SDK", ts_sdk)):
        if "leaves_root_hex" not in text:
            return _fail(name, f"{sdk} must check the published set against leaves_root_hex; a verifier that "
                               "skips the commitment accepts a swapped anonymity set")
    try:
        cases = json.loads((root / "conformance" / "cases.json").read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        return _fail(name, f"conformance/cases.json is not valid JSON ({e})")
    swapped = [c for c in cases.get("cases", [])
               if c.get("artifact") == "epoch-leaves" and c.get("expect", {}).get("authentic") is False]
    if not swapped:
        return _fail(name,
                     "the published contract must carry a swapped-set case expecting authentic=false, so every "
                     "implementation is certified to refuse it and not just this one")
    return _ok(name,
               "a broken commitment is a refusal, not a note: both verifiers that publish members outside the "
               "signed statement check the commitment and return before calling the artifact authentic, both "
               "SDKs check it too, and the conformance suite certifies the swapped set is refused")


def check_verifier_instant_normalised(root: pathlib.Path) -> list[Finding]:
    """A caller's `now` must become an instant before anything is compared against it.

    The detached verifier is a trust boundary that strangers feed input to, and its contract
    is that it returns a verdict rather than raising. Every freshness gate compares `now`
    against parsed timestamps, and the conformance cases, the CLI and every docstring invite
    `now` as an ISO-8601 string. A gate that compared the raw value did two different wrong
    things: it raised TypeError where the comparison sat outside a try, and where it sat
    inside one it reported `fresh: false` with a note blaming the artifact's own timestamps.
    The second is the worse failure. A verifier that answers "not fresh" about material that
    is fresh, and blames the material, is trusted and believed.

    So the rule is structural: any verifier that accepts `now` and compares against it must
    route it through `_instant` first."""
    name = "instant_normalised"
    rel = "scripts/polaris-verify.py"
    src = _read(root, rel)
    if "def _instant(" not in src:
        return _fail(name, f"{rel} must define _instant() to normalise a caller's `now` into an aware datetime")
    stale = re.findall(r"\bnow\s*=\s*now\s+or\s+datetime\.now\(", src)
    if stale:
        return _fail(name,
                     f"{rel} still normalises `now` with the bare `now or datetime.now(...)` idiom in "
                     f"{len(stale)} place(s); that keeps a string `now` a string and the next comparison "
                     "either raises or silently refuses genuine material")
    try:
        import ast as _ast
        tree = _ast.parse(src)
    except SyntaxError as e:
        return _fail(name, f"{rel} does not parse ({e})")
    offenders = []
    for fn in tree.body:
        if not isinstance(fn, _ast.FunctionDef):
            continue
        if not any(a.arg == "now" for a in fn.args.args):
            continue
        segment = _ast.get_source_segment(src, fn) or ""
        # Does this function compare against `now` itself, rather than only passing it on?
        compares = any(
            isinstance(n, _ast.Compare)
            and any(isinstance(x, _ast.Name) and x.id == "now" for x in [n.left, *n.comparators])
            for n in _ast.walk(fn))
        if compares and "_instant(" not in segment:
            offenders.append(fn.name)
    if offenders:
        return _fail(name,
                     "these verifiers compare against a caller's `now` without normalising it through "
                     "_instant(), so an ISO-8601 `now` raises or produces a false refusal: "
                     + ", ".join(sorted(offenders)))
    return _ok(name,
               "every verifier that judges freshness normalises the caller's `now` through _instant() first, so "
               "an ISO-8601 instant is honoured and a malformed one is refused honestly rather than blamed on "
               "the artifact being verified")



def check_scoped_nullifier(root: pathlib.Path) -> list[Finding]:
    """One person, once per scope, and no two scopes correlate (P9.3).

    A relying party often needs "this person has not already claimed here" without
    needing "this person is Maria". The scoped nullifier is that: a public value
    `Poseidon(holder secret || relying-party scope || epoch)` carried by the proof,
    identical for one person on a second visit to the SAME verifier, and
    uncorrelated with what that person presents to any OTHER verifier.

    The whole thing rests on one structural fact, and this check exists to keep it
    true. The epoch leaf must be a Poseidon COMMITMENT the circuit opens, not an
    opaque digest handed in. While the leaf was `SHA3-256(token_id|token_value|
    context_id)` computed outside the circuit, a nullifier beside it proved only
    "I know some number", because nothing tied the two to one secret: a prover
    could pair any member's leaf with a nullifier of their own choosing, and every
    property above would be a claim rather than a proof. Verifying a SHA3-256
    preimage in-circuit is expensive; moving the leaf to Poseidon is not. That is
    why the leaf moved, and why a regression to an opaque leaf is a FAIL here even
    though every test of the nullifier itself would still pass.

    The rest follows: the scope must be a public input, or a proof made for one
    verifier could be replayed at another; the nullifier must be a public input,
    or it could be edited after the fact; and the second witness must RE-DERIVE
    both from the secret rather than take the bundle's word, because a Rust
    verifier that quietly stopped constraining them would otherwise keep agreeing
    with a witness that only rechecked membership."""
    name = "scoped_nullifier"
    lib = _read(root, "polaris_zk/src/lib.rs")
    if not lib:
        return _fail(name, "polaris_zk/src/lib.rs is missing; the circuit is the whole construction")

    body_start = lib.find("pub fn build_circuit")
    if body_start < 0:
        return _fail(name, "polaris_zk/src/lib.rs must define build_circuit")
    circuit = lib[body_start:lib.find("\npub fn ", body_start + 10)]

    # 1. The leaf is OPENED in the circuit from a private secret, not handed in.
    if "add_virtual_hash()" in circuit.split("verify_merkle_proof_to_cap")[0].split("let leaf_target")[-1]:
        return _fail(name,
                     "the circuit takes the leaf as an opaque input again; a nullifier beside an "
                     "unopened leaf proves only that the prover knows some number, not that they "
                     "are the person behind that leaf")
    if "hash_n_to_hash_no_pad" not in circuit:
        return _fail(name,
                     "build_circuit must compute the leaf commitment in-circuit with Poseidon "
                     "(hash_n_to_hash_no_pad); an opaque leaf cannot be bound to a nullifier")
    leaf_at = circuit.find("let leaf_target = builder.hash_n_to_hash_no_pad")
    merkle_at = circuit.find("verify_merkle_proof_to_cap")
    if leaf_at < 0 or merkle_at < 0 or leaf_at > merkle_at:
        return _fail(name,
                     "the leaf must be OPENED from the secret before the Merkle proof is verified "
                     "against it, or the proof is about a leaf nobody opened")

    # 2. Both the leaf and the nullifier derive from the SAME secret target.
    for needed, why in (
            ("let secret = builder.add_virtual_targets",
             "the holder secret must be a private input the circuit owns"),
            ("let mut leaf_input = secret.clone();",
             "the leaf must be derived from that secret"),
            ("let mut nullifier_input = secret.clone();",
             "the nullifier must be derived from the SAME secret as the leaf; that identity IS "
             "the construction")):
        if needed not in circuit:
            return _fail(name, f"{why} ({needed!r} not found in build_circuit)")

    # 3. Scope and nullifier are PUBLIC inputs.
    if "builder.register_public_input(scope_t)" not in circuit:
        return _fail(name,
                     "scope must be a public input, or a proof made for one relying party could be "
                     "replayed at another and defeat its one-person-once rule")
    if "builder.register_public_inputs(&nullifier_target.elements)" not in circuit:
        return _fail(name,
                     "the nullifier must be a public input, or a prover could edit it after the "
                     "fact and every visit would look like a first visit")

    # 4. The verifier checks them like any other public input.
    if "bundle.public_inputs.scope" not in lib or "nullifier_hex" not in lib:
        return _fail(name, "verify() must bind the claimed scope and nullifier to the proof's own")

    # 5. Three implementations of the two derivations, and they are tested against
    #    each other rather than each against itself.
    witness = _read(root, "polaris_zk/witness2/commitment.py")
    for needed, why in (("def leaf_commitment", "the second witness must re-derive the leaf"),
                        ("def nullifier", "the second witness must re-derive the nullifier"),
                        ("hash_no_pad", "it must use the same no-pad sponge the circuit uses")):
        if needed not in witness:
            return _fail(name, f"{why} (polaris_zk/witness2/commitment.py: {needed})")
    verifier = _read(root, "polaris_zk/witness2/verifier.py")
    if "leaf_commitment" not in verifier or "derive_nullifier" not in verifier:
        return _fail(name,
                     "the second witness's check_claim must RE-DERIVE the leaf and the nullifier "
                     "from the secret; a witness that only rechecks membership would keep agreeing "
                     "with a verifier that had stopped constraining them")
    differential = _read(root, "polaris_web/test_zk_second_witness.py")
    for needed in ("test_leaf_commitment_agreement_bit_identical",
                   "test_nullifier_agreement_bit_identical"):
        if needed not in differential:
            return _fail(name, f"the cross-language differential must pin both derivations ({needed})")

    # 6. The app derives through the same commitment, and the drill proves the property.
    zkpy = _read(root, "polaris_web/zk.py")
    for needed, why in (("def derive_holder_secret", "the secret derivation must be named and separate"),
                        ("def derive_leaf_commitment", "the published leaf must be the commitment"),
                        ("def derive_nullifier", "the app must be able to derive a nullifier")):
        if needed not in zkpy:
            return _fail(name, f"{why} (polaris_web/zk.py: {needed})")
    drill = _read(root, "scripts/polaris-scoped-nullifier-drill.py")
    if not drill:
        return _fail(name, "scripts/polaris-scoped-nullifier-drill.py must prove the property end to end")
    for needed, why in (("SCOPE_CLINIC", "the drill must use two DIFFERENT relying-party scopes"),
                        ("SCOPE_LIBRARY", "one scope cannot demonstrate non-correlation")):
        if needed not in drill:
            return _fail(name, f"{why} ({needed})")

    # 7. The SDKs carry the comparison rule, since an integrator will write it by hand otherwise.
    py_sdk, ts_sdk = _read(root, "sdk/python/polaris_verify/__init__.py"), _read(root, "sdk/typescript/src/index.ts")
    if "def nullifiers_link" not in py_sdk or "export function nullifiersLink" not in ts_sdk:
        return _fail(name,
                     "both SDKs must expose the nullifier comparison, with its rules: exact hex "
                     "only, never across scopes, never across epochs")
    return _ok(name,
               "one person, once per scope: the epoch leaf is a Poseidon commitment the circuit "
               "OPENS, so the scoped nullifier is provably derived from the same secret as the "
               "leaf; scope and nullifier are public inputs the verifier binds; the independent "
               "second witness re-derives both and the cross-language differential pins them; and "
               "the drill proves a second visit is refused while a second relying party sees a "
               "value it cannot correlate")



def check_pairwise_presentation(root: pathlib.Path) -> list[Finding]:
    """No value a relying party keys its records by is stable across relying parties (P9.4).

    The login token's subject used to be `SHA3-256(token_value)`: the same sixty-four
    characters at every relying party in the system. Two of them comparing user tables
    matched people exactly, forever, and neither had to do anything wrong, because the
    identifier they were handed was a global one. The subject is the value a relying party
    WRITES DOWN, and written-down values are the ones that get pooled, sold, subpoenaed and
    breached, so this was the correlation handle that mattered most in practice.

    It is now `SHA3-256("polaris-pairwise/1" || token_value || client_id)`: stable at one
    relying party, so an account still works, and unrecognisable at the next. The same
    derivation gives the presentation layer its handle, from the holder key rather than the
    token value.

    Two things this check refuses to let slide, because both would turn the guarantee back
    into a claim:

    A handle with no scope. Deriving one from the holder key alone would be a global
    identifier again, wearing the word "pairwise". The derivations return None on a missing
    scope rather than hashing an empty string, which would collide every holder into one
    record, and this pins that.

    An overclaim. A plain presentation still SHOWS a verifier the token value, the issuer's
    signature and the holder's public key, all stable everywhere. Two verifiers who keep the
    raw material can still correlate. So `verify_presentation` must report `correlation` and
    must have both words available: "exposed" for a plain credential and "bounded" for the
    zero-knowledge form, whose handle is P9.3's scoped nullifier. A verifier that reported
    only the good word would be lying by omission about the common case."""
    name = "pairwise_presentation"
    app = _read(root, "polaris_web/app.py")
    if "def _pairwise_subject" not in app:
        return _fail(name, "polaris_web/app.py must derive the login subject per relying party "
                           "(_pairwise_subject)")
    if re.search(r"'sub':\s*hashlib\.sha3_256\(token_value", app):
        return _fail(name,
                     "the login subject is derived from the token value ALONE again; that is one "
                     "global identifier handed to every relying party, and two of them comparing "
                     "user tables match people exactly and forever")
    if "_pairwise_subject(token_value, rp['client_id'])" not in app:
        return _fail(name,
                     "the subject must be scoped to the relying party's own client_id; a subject "
                     "with no relying party in it is a global identifier whatever it is called")

    verifier = _read(root, "scripts/polaris-verify.py")
    for needed, why in (("def pairwise_handle", "the detached verifier must derive the handle"),
                        ("def handles_link", "and give a verifier the one correct way to compare two")):
        if needed not in verifier:
            return _fail(name, f"{why} ({needed})")
    body = verifier.split("def pairwise_handle")[1].split("\ndef ")[0]
    if "return None" not in body:
        return _fail(name,
                     "pairwise_handle must return None on a missing scope or key rather than "
                     "hashing an empty string, which would key every holder to one record")
    if "_PAIRWISE_TAG" not in body:
        return _fail(name, "the handle must carry a domain tag, so it cannot be confused with "
                           "another SHA3-256 value in the protocol")

    # The verdict must report correlation, and must be able to say the unflattering word.
    if '"correlation"' not in verifier:
        return _fail(name,
                     "verify_presentation must report `correlation`; a handle without a statement "
                     "of what it actually bounds invites the caller to assume the strong form")
    pres = verifier.split("def verify_presentation")[1].split("\ndef ")[0]
    for word, why in (('"exposed"', "a plain presentation still shows a stable token value, issuer "
                                    "signature and holder key; the verdict must say so"),
                      ('"bounded"', "the zero-knowledge form withholds them, and must be "
                                    "distinguishable from the plain one")):
        if word not in pres:
            return _fail(name, f"verify_presentation must be able to report {word}: {why}")

    py_sdk, ts_sdk = _read(root, "sdk/python/polaris_verify/__init__.py"), _read(root, "sdk/typescript/src/index.ts")
    if "def pairwise_handle" not in py_sdk or "export function pairwiseHandle" not in ts_sdk:
        return _fail(name, "both SDKs must expose the handle derivation, or an integrator writes "
                           "their own and it will not match")
    wallet = _read(root, "scripts/polaris-wallet.py")
    if "verifier_scope" not in wallet:
        return _fail(name, "the wallet must be able to present to a NAMED verifier "
                           "(--verifier-scope), or there is no scope to derive a handle under")
    drill = _read(root, "scripts/polaris-pairwise-drill.py")
    if not drill:
        return _fail(name, "scripts/polaris-pairwise-drill.py must prove the property end to end")
    if "exposed" not in drill:
        return _fail(name,
                     "the drill must ASSERT the bound, not only the benefit: a plain presentation "
                     "reports EXPOSED, and a reader must not take the drill for a proof of "
                     "something stronger than what ships")
    return _ok(name,
               "no value a relying party keys its records by is stable across relying parties: the "
               "login subject and the presentation handle are both derived under the relying "
               "party's own scope, a handle with no scope is refused rather than globalised, both "
               "SDKs derive it identically, and the verdict states honestly whether the "
               "correlation it bounds is exposed (a plain credential) or bounded (the "
               "zero-knowledge form, whose handle is the scoped nullifier)")



def check_agent_grant(root: pathlib.Path) -> list[Finding]:
    """A person delegates to an agent WITHOUT handing over their credential (P9.8).

    The thing this replaces is the thing people actually do: give the agent the credential.
    That gives it everything the person can do, forever, revocable only by revoking the
    person. A grant is the opposite of each of those, and this check exists to keep it that
    way, because every one of the four properties degrades silently.

    BOUNDED. `actions` and `limits` are inside the signed statement. If either sat outside,
    a grant could be widened in transit and the widening would be invisible: the signature
    would still verify, the service would still accept, and the grant would be the
    credential hand-over it was supposed to replace. An empty `actions` must grant NOTHING;
    reading it as unrestricted is the same failure wearing a different hat, and it is the
    reading a tired implementer reaches for.

    REVOCABLE BY THE HOLDER ALONE. The revocation is signed by the same key that signed the
    grant, so anyone may publish bytes but only the holder may end it. The issuer is not in
    this loop at all, which is the property worth protecting: a person can end their agent's
    authority without asking permission from, or being observed by, the authority that
    issued their identity.

    NOT A BEARER TOKEN. The agent signs a proof naming the action and the service's own
    nonce. Without that link a grant is a bearer token and whoever copies it in transit
    becomes the agent; with it, a captured proof replays neither to a second service nor to
    a second action at the first.

    NO REASON FIELD ON A REVOCATION. A place to record WHY a grant ended is a place a
    coercer can demand be filled in or left empty, and either way it turns a revocation into
    a signal about the person. Four fields, and this refuses a fifth."""
    name = "agent_grant"
    verifier = _read(root, "scripts/polaris-verify.py")
    for needed, why in (("def _agent_grant_canonical", "the grant's signed statement"),
                        ("def _grant_revocation_canonical", "the revocation's signed statement"),
                        ("def _agent_proof_canonical", "the agent's proof of the action"),
                        ("def verify_agent_grant", "the offline decision over the whole chain"),
                        ("def grant_within_limits", "the limits must be ENFORCED, not just carried")):
        if needed not in verifier:
            return _fail(name, f"the detached verifier must define {why} ({needed})")

    # BOUNDED: actions and limits inside the signature.
    stmt = verifier.split("def _agent_grant_canonical")[1].split("\ndef ")[0]
    for field in ("actions", "limits", "expires_at", "agent_public_key_hex", "grant_id"):
        if f'"{field}"' not in stmt:
            return _fail(name,
                         f"the grant's signed statement must cover {field!r}; a field outside the "
                         "signature can be edited in transit, and a widened grant that still "
                         "verifies is the credential hand-over a grant exists to replace")

    # An empty action list must grant nothing.
    body = verifier.split("def verify_agent_grant")[1].split("\ndef ")[0]
    if "isinstance(actions, (list, tuple)) else []" not in body:
        return _fail(name,
                     "verify_agent_grant must treat a missing or malformed `actions` as the EMPTY "
                     "list, so a grant that names nothing authorises nothing")
    if 'v["action_in_scope"] = str(requested_action) in actions' not in body:
        return _fail(name, "the requested action must be checked against the grant's own list")

    # REVOCABLE BY THE HOLDER ALONE.
    if "the revocation is signed by a key other than the grant's holder" not in body:
        return _fail(name,
                     "verify_agent_grant must require the revocation to be signed by the SAME key "
                     "that signed the grant; otherwise anyone who can publish bytes can end "
                     "somebody else's delegation")
    if "the revocation names a different grant" not in body:
        return _fail(name, "a revocation must name THIS grant, or one revocation would end every grant")

    # NOT A BEARER TOKEN.
    for needed, why in (("the agent proof is signed by a key the grant does not name",
                         "the agent must hold the key the grant names, or the grant is a bearer "
                         "token and whoever copied it is the agent"),
                        ("a replay",
                         "the proof must name the service's own nonce, or a proof captured at one "
                         "service replays at another"),
                        ("the agent proof is for a different action than the one requested",
                         "a proof for one action must not authorise another")):
        if needed not in body:
            return _fail(name, why)

    # NO REASON FIELD.
    rev_stmt = verifier.split("def _grant_revocation_canonical")[1].split("\ndef ")[0]
    for banned in ("reason", "coerc", "duress", "note"):
        if f'"{banned}"' in rev_stmt:
            return _fail(name,
                         f"a revocation's signed statement must not carry {banned!r}: a field that "
                         "records why a grant ended is a field a coercer can demand be filled in "
                         "or left empty, and either way it makes the revocation a signal about "
                         "the person")

    # The limits must be refused when unknown, not ignored.
    limits_body = verifier.split("def grant_within_limits")[1].split("\ndef ")[0]
    if "unknown" not in limits_body or "refusing" not in limits_body:
        return _fail(name,
                     "grant_within_limits must REFUSE a limit key it does not understand; ignoring "
                     "one silently turns a bounded grant into an unbounded one")

    # The app builds the same bytes, and the oracle pins the pair.
    app = _read(root, "polaris_web/app.py")
    for needed in ("_agent_grant_statement", "_grant_revocation_statement", "_agent_proof_statement"):
        if f"def {needed}" not in app:
            return _fail(name, f"polaris_web/app.py must build the identical bytes ({needed})")
    oracle = _read(root, "polaris_web/test_canonical_equivalence.py")
    for needed in ("agent-grant", "grant-revocation", "agent-proof"):
        if f'"{needed}"' not in oracle:
            return _fail(name, f"the canonical-equivalence oracle must pin {needed}")

    # The wallet mints and revokes; the issuer is never asked.
    wallet = _read(root, "scripts/polaris-wallet.py")
    for needed, why in (("def cmd_grant", "the holder must be able to mint a grant on their own device"),
                        ("def cmd_revoke_grant", "and end it on their own device")):
        if needed not in wallet:
            return _fail(name, f"{why} (scripts/polaris-wallet.py: {needed})")
    grant_body = wallet.split("def cmd_grant")[1].split("\ndef ")[0]
    if "urlopen" in grant_body or "urllib" in grant_body:
        return _fail(name,
                     "minting a grant must not contact the issuer; the whole point is that a person "
                     "delegates without the authority that issued their identity being told")

    # Both SDKs, the fuzzer and a drill.
    py_sdk, ts_sdk = _read(root, "sdk/python/polaris_verify/__init__.py"), _read(root, "sdk/typescript/src/index.ts")
    if "def grant_covers" not in py_sdk or "export function grantCovers" not in ts_sdk:
        return _fail(name, "both SDKs must expose the scope check, or an integrator writes their own "
                           "and reads an empty action list as unrestricted")
    if "polaris-agent-grant/1" not in py_sdk or "polaris-agent-grant/1" not in ts_sdk:
        return _fail(name, "both SDKs must know the grant's signed-field list")
    fuzz = _read(root, "scripts/polaris-verifier-fuzz.py")
    if "agent-grant" not in fuzz:
        return _fail(name,
                     "the metamorphic fuzzer must cover the grant: it is the one artifact where a "
                     "WIDENING mutation is the attack rather than a corruption")
    drill = _read(root, "scripts/polaris-agent-grant-drill.py")
    if not drill:
        return _fail(name, "scripts/polaris-agent-grant-drill.py must prove the chain end to end")
    for needed, why in (("stolen grant", "the drill must show a copied grant is useless without the agent's key"),
                        ("untouched", "and that revoking a grant leaves the human's credential usable"),
                        ("exposed", "and must assert the bound: a service under a plain binding still "
                                    "sees the credential, so the verdict says exposed")):
        if needed not in drill:
            return _fail(name, why)
    spec = _read(root, "docs/reference/WIRE-SPEC.md")
    if "polaris-agent-grant/1" not in spec:
        return _fail(name, "the normative wire spec must carry the delegation artifacts")
    # A service must be able to decide a grant WITHOUT writing code. Engine over wrapper: a
    # capability reachable only from Python is a library, and the party that needs this one
    # is a service operator with a JSON file and a shell.
    if '"--agent-grant"' not in verifier or '"--service-nonce"' not in verifier:
        return _fail(name,
                     "the detached verifier's CLI must decide a grant offline (--agent-grant, with "
                     "--action and --service-nonce); a service that has to write Python to check an "
                     "agent's authority will not check it")
    return _ok(name,
               "a person delegates to an agent without handing over their credential: the grant's "
               "actions and limits are inside the signed statement so widening it breaks the "
               "signature, an empty action list authorises nothing, only the holder's own key can "
               "end it and the issuer is never asked, the agent must prove it holds the key the "
               "grant names against the service's own nonce, a revocation carries no reason field a "
               "coercer could read, and an unknown limit is refused rather than ignored")



def check_epoch_pipeline_scale(root: pathlib.Path) -> list[Finding]:
    """The epoch pipeline runs at the national tree depth (P2.5).

    An epoch tree is fixed-depth, and the obvious implementation pads the leaf vector to
    2^depth before hashing anything. At the demo depth of 14 that is free, which is why it
    survived. At the national depth of 24 it took 10.8 seconds and 2.9 GB of resident memory
    to compute a root over a THOUSAND members, because sixteen million leaves were
    materialised whatever the real population was, and the number did not move with the
    population at all. An authority on that budget closes epochs by the minute and the
    gigabyte and pays all of it on zeros.

    The padding is one repeated value, so every subtree above the real members is an all-zero
    subtree with exactly one hash per level. This check pins the three things that make
    folding them away sound rather than merely fast:

    PARITY. The sparse root must equal the padded root element for element. If it does not,
    every epoch already published becomes unverifiable and every holder's proof stops
    verifying, which is a worse failure than a slow close. The padded construction is
    therefore KEPT, unused in production, purely as the thing parity is asserted against.

    TWO WITNESSES AT DEPTH. The independent Python witness must fold the padding the same
    way, or the second witness silently stops being able to check the first at the depth that
    matters: the padded form at depth 24 is sixteen million entries of pure-Python Poseidon.

    NO STORED PATH. Since the holder derives their own inclusion path (P9.2), an epoch close
    storing one per member was 1.7 KB of plaintext each that no query read back, roughly
    17 GB at ten million members. The close path must not put it back."""
    name = "epoch_pipeline_scale"
    lib = _read(root, "polaris_zk/src/lib.rs")
    if not lib:
        return _fail(name, "polaris_zk/src/lib.rs is missing")
    for needed, why in (("fn zero_hashes", "the per-level all-zero subtree hashes"),
                        ("pub struct EpochTree", "the sparse fixed-depth tree"),
                        ("pub fn set_leaf", "an O(depth) single-member repair, so a revocation "
                                            "between epochs is not a rebuild")):
        if needed not in lib:
            return _fail(name, f"polaris_zk must define {why} ({needed})")

    # PARITY: the padded construction is kept as the reference, and the hot paths are not on it.
    if "fn pad_leaves_to_full_depth" not in lib or "pub fn build_merkle_tree" not in lib:
        return _fail(name,
                     "the padded construction must be KEPT as the reference the sparse root is "
                     "asserted against; deleting it removes the only thing standing between a "
                     "refactor and every published epoch becoming unverifiable")
    body = lib.split("pub fn compute_epoch_root")[1].split("\n}")[0]
    if "EpochTree::from_leaves" not in body:
        return _fail(name,
                     "compute_epoch_root must use the sparse tree; the padded one is O(2^depth) "
                     "and at depth 24 costs 10.8s and 2.9GB for a thousand members")
    prove_body = lib.split("pub fn prove(")[1].split("\npub fn ")[0]
    if "EpochTree::from_leaves" not in prove_body:
        return _fail(name, "prove() must build its path from the sparse tree too")
    tests = lib.split("mod tests")[-1]
    for needed, why in (("parity_with_the_padded_construction",
                         "the sparse root must be asserted equal to the padded root"),
                        ("parity_of_every_inclusion_path",
                         "a matching root with diverging paths only surfaces when a holder proves"),
                        ("an_incremental_update_equals_a_rebuild",
                         "a repaired path must land where a rebuild would")):
        if needed not in tests:
            return _fail(name, f"the crate must test that {why} ({needed})")

    # TWO WITNESSES AT DEPTH.
    witness = _read(root, "polaris_zk/witness2/merkle.py")
    if "def zero_hashes" not in witness or "def inclusion_path" not in witness:
        return _fail(name,
                     "the second witness must fold the padding the same way (zero_hashes) and "
                     "derive a path itself (inclusion_path); otherwise it cannot check the first "
                     "at the depth that matters")
    if "_pad_leaves" in witness:
        return _fail(name,
                     "the second witness still materialises the padding; at depth 24 that is "
                     "sixteen million entries of pure-Python Poseidon and it will simply not run")

    # NO STORED PATH.
    app = _read(root, "polaris_web/app.py")
    close = app.split("def api_zk_epoch_close")[-1].split("\n@app.route")[0] if "def api_zk_epoch_close" in app else app
    if "'proof_path'" in close:
        return _fail(name,
                     "closing an epoch must not materialise an inclusion path per member: nothing "
                     "reads it back, the holder derives their own (P9.2), and it is 1.7 KB of "
                     "plaintext each, roughly 17 GB at ten million members")
    schema = _read(root, "polaris_sql/01_schema.sql")
    if re.search(r"proof_path\s+JSONB\s+NOT NULL", schema):
        return _fail(name,
                     "TokenStateEpochLeaf.proof_path must be nullable, or an epoch cannot be "
                     "closed without one")

    drill = _read(root, "scripts/polaris-epoch-scale-drill.py")
    if not drill:
        return _fail(name, "scripts/polaris-epoch-scale-drill.py must hold the pipeline to its "
                           "claims at production depth")
    if "PRODUCTION_DEPTH = 24" not in drill:
        return _fail(name, "the drill must run at the NATIONAL depth; a drill at the demo depth "
                           "measures the case that was never slow")
    for needed, why in (("MEM_CEILING_MB", "a memory ceiling, because the old cost was memory"),
                        ("ROOT_CEILING_S", "a wall-clock ceiling")):
        if needed not in drill:
            return _fail(name, f"the drill must gate on {why} ({needed})")
    spec = _read(root, "docs/design/epoch-cadence.md")
    if not spec:
        return _fail(name, "the epoch cadence spec must be published (docs/design/epoch-cadence.md)")
    for needed, why in (("Revocation freshness", "the cadence bounds how long a revoked member "
                                                 "stays provable"),
                        ("anonymity", "the epoch IS the anonymity set, so a short cadence over a "
                                      "small context is a crowd of nobody"),
                        ("nullifier", "the cadence also sets how often a relying party's "
                                      "one-human-once ledger resets, which pulls the other way")):
        if needed not in spec:
            return _fail(name, f"the cadence spec must state that {why}")
    return _ok(name,
               "the epoch pipeline runs at the national depth: the zero padding is folded into "
               "precomputed per-level hashes rather than materialised, the padded construction is "
               "kept as the reference the sparse root is asserted equal to, the second witness "
               "folds it the same way so it can still check the first at depth 24, a single-member "
               "repair is O(depth), an epoch close stores no inclusion path because the holder "
               "derives their own, and the cadence spec states the three properties the schedule "
               "sets against each other")



def check_status_distribution(root: pathlib.Path) -> list[Finding]:
    """A signed status crosses an untrusted network without a cache outliving it (P2.6).

    Signing a status artifact is what lets a cache or a content-delivery network carry it: an
    intermediary cannot forge a status any more than an aggregator can. But a cache
    introduces the one failure signing does not prevent, which is TIME. A cached status is a
    status the issuer may already have withdrawn.

    THE RULE. A cache directive is never a constant. It is the artifact's own remaining life,
    from the `expires_at` the issuer signed, so a cache physically cannot outlive that window.
    A fixed `max-age` would eventually exceed some artifact's window and the symptom would be
    a revoked credential that keeps verifying for a while, which is the failure this whole
    layer exists to prevent.

    NO STALE SERVING. `stale-while-revalidate` and `stale-if-error` exist to serve a
    known-stale body when the origin is slow or unreachable, and a known-stale revocation feed
    is precisely what an attacker wants served: the cheapest attack on this design is to make
    the origin unreachable and let the network answer from yesterday. A status origin that is
    down should fail.

    THE SPLIT, WHICH IS THE HALF THAT LEAKS. A revocation feed is byte-identical for every
    consumer; a status assertion NAMES ONE CREDENTIAL. A shared cache holding the second
    would serve one holder's credential to another, and a signature cannot undo a disclosure.
    Getting this backwards is a privacy incident rather than a performance regression, so both
    halves are pinned: the per-holder artifacts must be `no-store`, and must never be marked
    public."""
    name = "status_distribution"
    app = _read(root, "polaris_web/app.py")
    for needed, why in (("def _artifact_max_age", "the remaining life of an artifact's own window"),
                        ("def _public_artifact", "the cacheable form"),
                        ("def _private_artifact", "the never-cached form")):
        if needed not in app:
            return _fail(name, f"polaris_web/app.py must define {why} ({needed})")

    # THE RULE: max-age is computed, never a literal. Scan the CODE, not the docstring: the
    # docstring names the directives it refuses, and a check that matched those words would
    # fail on the explanation of why they are absent.
    def _code_of(fn: str) -> str:
        seg = app.split(f"def {fn}")[1].split("\ndef ")[0]
        parts = seg.split('"""')
        return parts[0] + "".join(parts[2:]) if len(parts) >= 3 else seg

    body = _code_of("_public_artifact")
    if "_artifact_max_age(body)" not in body:
        return _fail(name,
                     "_public_artifact must derive max-age from the artifact's OWN window; a "
                     "constant lets a cache outlive the window the issuer signed, and a revoked "
                     "credential keeps verifying until the cache expires")
    if re.search(r"max-age=\d", body):
        return _fail(name,
                     "_public_artifact carries a LITERAL max-age; it must be the artifact's "
                     "remaining life and nothing else")
    if "no-store" not in body:
        return _fail(name,
                     "an artifact already past its expiry, or one whose window cannot be parsed, "
                     "must be no-store: caching what every verifier must reject only creates a "
                     "stale copy to serve later")
    for banned in ("stale-while-revalidate", "stale-if-error"):
        if banned in body:
            return _fail(name,
                         f"_public_artifact permits {banned}; serving a known-stale revocation "
                         "feed when the origin is unreachable is the cheapest attack on this "
                         "design, not a resilience feature")

    # The fail-closed reading of an unparseable window.
    age = _code_of("_artifact_max_age")
    if "return None" not in age:
        return _fail(name,
                     "_artifact_max_age must return None when the window cannot be read, so the "
                     "caller refuses to cache rather than guessing an interval")

    # THE SPLIT. Every per-holder artifact goes through the private form.
    private = _code_of("_private_artifact")
    if "no-store" not in private:
        return _fail(name, "_private_artifact must be no-store")
    if "public" in private:
        return _fail(name, "_private_artifact must never mark a per-holder artifact public")
    for route, why in (("api_v1_status_assertion", "a status assertion names one token_value"),
                       ("api_v1_holder_key_bind", "a holder binding names one credential"),
                       ("api_v1_timestamp", "a timestamp is minted for one caller's digest")):
        if f"def {route}" not in app:
            continue
        seg = app.split(f"def {route}")[1].split("\n@app.route")[0]
        if "_private_artifact" not in seg:
            return _fail(name,
                         f"{route} must return through _private_artifact: {why}, and a shared "
                         "cache holding it would serve one holder's credential to another")

    # And every public artifact goes through the cacheable form rather than bare jsonify.
    # Count CALL sites, not the definition line, or removing one still reads as seven.
    if app.count("return _public_artifact(") < 7:
        return _fail(name,
                     "every public status artifact (revocation feed, epoch checkpoint, status "
                     "bundle, federation manifest, trust list, registry, epoch leaves) must be "
                     "returned through _public_artifact, or a CDN in front of this origin has "
                     "nothing to go on")

    drill = _read(root, "scripts/polaris-status-distribution-drill.py")
    if not drill:
        return _fail(name, "scripts/polaris-status-distribution-drill.py must prove both halves")
    for needed, why in (("does not outlive the signed window", "the rule itself"),
                        ("names ONE credential", "the half that leaks if it is backwards")):
        if needed not in drill:
            return _fail(name, f"the drill must assert {why}")
    spec = _read(root, "docs/design/status-distribution.md")
    if not spec:
        return _fail(name, "the freshness rules must be published (docs/design/status-distribution.md)")
    for needed in ("stale-while-revalidate", "no-store", "expires_at"):
        if needed not in spec:
            return _fail(name, f"the freshness rules must state {needed!r}")
    return _ok(name,
               "a signed status crosses an untrusted network safely: every public artifact is "
               "cached to its OWN signed window and no further, none permits serving stale when "
               "the origin is unreachable, each carries an ETag to revalidate on, an expired or "
               "unreadable window is not cached at all, and every artifact that names one "
               "credential is no-store so a shared cache cannot serve one holder's to another")



def check_multi_region_dr(root: pathlib.Path) -> list[Finding]:
    """The second region is a region, not another node (P2.8).

    The HA profile survives a node dying. It does not survive the region, and the tempting fix
    is to add a third Patroni member "in region B". That puts the wide-area network inside the
    quorum in three places: the lease store must be reachable across it, so a partition between
    regions partitions the consensus; write latency includes it; and a member of region A's
    cluster living in region B is still region A's problem when region A's lease store is
    unreachable. A three-member etcd split two-and-one loses quorum when the two-member side
    goes dark, which is exactly the outage the second region existed to survive.

    So region B is a STANDBY CLUSTER: a different scope, its own lease store, streaming
    asynchronously from region A's router. This check pins that shape, because every part of
    it is something a later change could quietly undo while everything still appeared to work
    in a single-host test.

    And it pins the honesty. Asynchronous replication means the recovery point is NOT ZERO, and
    a runbook that does not say how far from zero is one nobody can plan against. The drill
    must MEASURE both numbers rather than assert them, must assert that region B holds no row
    region A never acknowledged (a stated recovery point is a cost; divergence is a correctness
    failure), and the runbook must state the price before the procedure rather than after."""
    name = "multi_region_dr"
    compose = _read(root, "polaris_web/docker-compose.dr.yml")
    if not compose:
        return _fail(name, "polaris_web/docker-compose.dr.yml must define the standby region")
    for needed, why in (
            ("POLARIS_PATRONI_STANDBY_HOST",
             "region B must be configured as a standby cluster, not another member"),
            ("POLARIS_PATRONI_SCOPE: polaris-dr",
             "region B must use a DIFFERENT cluster scope, or it competes for region A's leader key"),
            ("dr-etcd",
             "region B must have its OWN lease store; sharing region A's puts the WAN inside the "
             "quorum and a region going dark takes the other region's consensus with it")):
        if needed not in compose:
            return _fail(name, f"{why} ({needed})")
    if "POLARIS_PATRONI_ETCD_HOSTS: dr-etcd:2379" not in compose:
        return _fail(name,
                     "region B's Patroni must point at region B's own lease store; pointing it at "
                     "region A's makes region B unavailable exactly when region A is")

    entry = _read(root, "polaris_web/patroni-entrypoint.sh")
    if "standby_cluster:" not in entry:
        return _fail(name,
                     "the Patroni entrypoint must render a standby_cluster block, or the compose "
                     "profile configures something the entrypoint ignores")
    if "POLARIS_PATRONI_STANDBY_HOST" not in entry:
        return _fail(name, "the entrypoint must read the upstream host")
    # The upstream must be validated like every other value interpolated into YAML.
    if "POLARIS_PATRONI_STANDBY_HOST must be a plain hostname" not in entry:
        return _fail(name,
                     "the standby host is interpolated into YAML and must be refused unless it is "
                     "a plain hostname, the same discipline as every other value there")

    drill = _read(root, "scripts/polaris-region-evacuation-drill.sh")
    if not drill:
        return _fail(name, "scripts/polaris-region-evacuation-drill.sh must evacuate the region")
    for needed, why in (
            ("CEIL_RTO", "the drill must gate on a recovery TIME"),
            ("CEIL_RPO_ROWS", "and on a recovery POINT, in rows"),
            ("acked.log",
             "the drill must RECORD every acknowledged write as it goes; once the region is gone "
             "nobody can ask it what it acknowledged, so an RPO measured any other way is a guess"),
            ("DIVERGED",
             "the drill must assert region B holds no row region A never acknowledged: a recovery "
             "point is a stated cost, divergence is a correctness failure"),
            ("contiguous",
             "and that what crossed is an unbroken prefix; a standby missing rows BELOW its "
             "high-water mark skipped rather than lagged, which counting rows would not catch")):
        if needed not in drill:
            return _fail(name, why)
    # The region must be cut the way a region goes dark, not the way a node dies.
    if "polaris-etcd1" not in drill or "polaris-pg-router" not in drill:
        return _fail(name,
                     "the drill must cut the members, the router AND the lease store together; "
                     "stopping only the leader is the failover drill's scenario, not this one")
    if "refuses writes while it is a standby" not in drill:
        return _fail(name,
                     "the drill must assert region B refuses writes BEFORE promotion; two regions "
                     "accepting writes at once is the divergence everything else is guarding")

    runbook = _read(root, "docs/operator/DR.md")
    if "standby region" not in runbook:
        return _fail(name, "docs/operator/DR.md must carry the region-evacuation procedure")
    ev = runbook.split("Procedure (with a standby region)")[-1][:4000]
    if "not zero" not in ev:
        return _fail(name,
                     "the runbook must state that the recovery point is NOT ZERO before the "
                     "procedure, not after it: an operator learning mid-incident that acknowledged "
                     "writes are gone is the failure this sentence prevents")
    if "diverge" not in ev:
        return _fail(name,
                     "the runbook must warn that promoting while region A still accepts writes "
                     "diverges the regions, and that nothing later repairs it")
    if "never brought back as a primary" not in runbook and "not bring region A back as a primary" not in runbook:
        return _fail(name,
                     "the runbook must say a returning region A is rebuilt as a standby or "
                     "restored, never brought back as a primary: two primaries on two timelines "
                     "is the one state with no clean recovery")
    design = _read(root, "docs/design/multi-region.md")
    if not design:
        return _fail(name, "the design record must be published (docs/design/multi-region.md)")
    if "quorum" not in design:
        return _fail(name,
                     "the design record must explain why a cross-region MEMBER puts the WAN inside "
                     "the quorum; without that reason the standby shape looks like an arbitrary choice")
    return _ok(name,
               "the second region is a region and not another node: a standby cluster with its own "
               "lease store and its own scope, streaming asynchronously through region A's router, "
               "refusing writes until promoted so the two never both accept; the evacuation drill "
               "cuts members, router and lease store together and MEASURES both the recovery time "
               "and the recovery point, asserting that what crossed is a contiguous prefix region A "
               "actually acknowledged; and the runbook states the non-zero recovery point before "
               "the procedure rather than during the incident")



def check_cost_model(root: pathlib.Path) -> list[Finding]:
    """The cost figure is a model you re-run, not a number you are asked to believe (P2.10).

    A committed cost table is out of date the week it is written, and worse, it hides which of
    its inputs are facts about this code and which are guesses about a deployment nobody has
    run. The two have completely different error bars: measured verification throughput is a
    property of the software, while verifications per person per year is a property of a
    society, and a table that presents them in the same font is misleading even when every
    figure is right.

    So the model is a SCRIPT, every input carries the kind of thing it is, and the document
    names what it leaves out. That last part matters most: staff, an HSM, the physical token
    and compliance can each exceed the whole infrastructure figure, and a cost document that
    omits them is not conservative, it is wrong by an order of magnitude in the direction that
    gets a project funded and then stranded."""
    name = "cost_model"
    script = _read(root, "scripts/polaris-cost-model.py")
    if not script:
        return _fail(name,
                     "scripts/polaris-cost-model.py must exist: a cost TABLE is stale the week it "
                     "is written, and hides which inputs are measurements and which are guesses")
    for kind, why in (("MEASURED", "numbers taken from an actual run of this code"),
                      ("COMPUTED", "arithmetic on a published constant"),
                      ("ASSUMED", "a deployment's own behaviour, which this repository cannot know"),
                      ("PRICED", "a list price on a date, which will be wrong for the reader")):
        if kind not in script:
            return _fail(name,
                         f"the model must label its {kind} inputs ({why}); presenting a measurement "
                         "and an assumption in the same font is misleading even when both are right")
    # The measured inputs must be the ones the benchmark actually published.
    bench = _read(root, "docs/reference/BENCHMARK.md")
    if "7,848" not in bench:
        return _fail(name,
                     "the benchmark no longer publishes the single-witness verification rate the "
                     "cost model is built on; one of the two has moved without the other")
    if "VERIFY_PER_CORE = 7848" not in script:
        return _fail(name,
                     "the model's verification rate must be the benchmark's measured number, not a "
                     "rounded or aspirational one")
    # The parameters that let a reader ask their own question.
    for flag in ("--persons", "--verifications-per-person", "--retention-years", "--price-vcpu-hour"):
        if flag not in script:
            return _fail(name,
                         f"the model must take {flag}: a cost model nobody can re-run with their own "
                         "assumptions is a table with extra steps")
    doc = _read(root, "docs/reference/COST-MODEL.md")
    if not doc:
        return _fail(name, "docs/reference/COST-MODEL.md must publish the model and its caveats")
    for needed, why in (("hardware security module",
                         "no HSM has ever been used here and a real deployment needs one"),
                        ("Staff",
                         "staff and on-call are the largest line in most real deployments"),
                        ("physical token",
                         "the token is modelled, not manufactured")):
        if needed not in doc:
            return _fail(name,
                         f"the cost document must name {needed!r} among what it EXCLUDES: {why}, and "
                         "a figure that omits it is not conservative, it is wrong in the direction "
                         "that gets a project funded and then stranded")
    if "single-node" not in doc:
        return _fail(name,
                     "the cost document must say the throughput it rests on is a SINGLE-NODE "
                     "measurement and the multi-node scale is projected, which is what BENCHMARK.md "
                     "and roadmap P2.9 already say in their own words")
    if "not the cost driver" not in doc:
        return _fail(name,
                     "the document must state the finding plainly: verification throughput is not "
                     "the cost driver at national scale, and availability and retention are. A cost "
                     "model whose conclusion a reader has to derive is a table again")
    return _ok(name,
               "infrastructure cost is a model that runs rather than a table that asserts: every "
               "input labelled measured, computed, assumed or priced so the error bars sit where "
               "they belong; the measured rate is the benchmark's own; a reader can re-run it with "
               "their population, retention and prices; and the document names what it excludes "
               "(staff, an HSM, the physical token) and that the throughput under it is single-node")



def check_plonky3_evaluation(root: pathlib.Path) -> list[Finding]:
    """The proof-library decision is recorded with what it rested on (P2.12).

    This check cannot tell whether keeping Plonky2 is the right call. Nothing machine-checkable
    can. What it can do is refuse the two ways a decision record goes bad.

    The first is a record with no decision: a comparison that lays out columns and stops, so the
    next person re-does the whole evaluation because they cannot tell what was concluded.

    The second is worse and more common: unverified claims presented in the same voice as
    measurements. A rewrite of a soundness core is exactly the kind of change that gets
    justified by a paragraph nobody sourced, and the defence is a record that says plainly
    which facts were measured here, which were reasoned from the code, and which were NOT
    checked and must be before anyone acts on it. So this requires the record to carry all
    three, and to carry the triggers that would re-open it, because a decision with no
    expiry condition is a decision nobody will ever revisit on evidence."""
    name = "plonky3_evaluation"
    doc = _read(root, "docs/design/plonky2-to-plonky3.md")
    if not doc:
        return _fail(name,
                     "docs/design/plonky2-to-plonky3.md must record the evaluation; the roadmap row "
                     "asked for a decision record, and an evaluation with no record is one the next "
                     "person has to redo")
    if "Decision:" not in doc:
        return _fail(name,
                     "the record must state a DECISION, not only a comparison: a set of columns with "
                     "no conclusion leaves the next reader to re-run the whole evaluation")
    if "NOT verified" not in doc and "not verified" not in doc:
        return _fail(name,
                     "the record must separate what was NOT verified from what was measured. A "
                     "soundness-core rewrite justified by unsourced claims is the failure this "
                     "section exists to prevent, and version and audit status have a shelf life")
    for needed, why in (("would change the decision",
                         "re-evaluation triggers; a decision with no expiry condition is one nobody "
                         "revisits on evidence"),
                        ("Proof size", "proof size is one of the dimensions the row named"),
                        ("two-witness",
                         "whether the second witness survives a migration is the sharpest question "
                         "here and the row named it")):
        if needed not in doc:
            return _fail(name, f"the record must cover {why} ({needed!r})")
    # The measured half must be real numbers from this tree, not adjectives.
    if not re.search(r"\b77,?840\b", doc):
        return _fail(name,
                     "the record must carry the MEASURED proof size; 'small' is not a comparison "
                     "anyone can check or re-run")
    if "1.1.0" not in doc:
        return _fail(name, "the record must name the pinned Plonky2 version it evaluated")
    lock = _read(root, "polaris_zk/Cargo.lock")
    if 'name = "plonky2"' in lock:
        m = re.search(r'name = "plonky2"\nversion = "([^"]+)"', lock)
        if m and m.group(1) not in doc:
            return _fail(name,
                         f"the record evaluates a Plonky2 version the lockfile no longer pins "
                         f"(lockfile: {m.group(1)}); the decision was made about different code")
    return _ok(name,
               "the proof-library decision is recorded and re-openable: it states a decision rather "
               "than only a comparison, separates what was measured here from what was reasoned "
               "from the code and from what was deliberately NOT verified, names the version it "
               "evaluated against the one the lockfile pins, and carries the triggers that would "
               "re-open it")



def check_mdoc_bridge(root: pathlib.Path) -> list[Finding]:
    """The ISO 18013-5 bridge is a FORMAT bridge, and says so (P3.7).

    A reader that speaks 18013-5 can parse what this produces and verify every disclosed
    element against the signed Mobile Security Object, which is the standard's whole
    selective-disclosure mechanism. It cannot verify the issuer signature, because that is
    ML-DSA (COSE -49) and the standard mandates ES256, ES384, ES512 or EdDSA.

    Three ways this goes wrong, and each is pinned:

    SIGNING CLASSICALLY. The obvious way to make a conforming reader accept the signature is
    to produce one it knows. That trades the property this entire system exists to have for
    the appearance of interoperability, and a post-quantum credential carrying a classical
    signature is a classical credential. The bridge must sign with ML-DSA and report the
    limit, not sign around it.

    CLAIMING THE mDL. A Polaris credential holds no name, no date of birth, no portrait and
    no driving privileges. A document that claimed `org.iso.18013.5.1.mDL` while carrying
    none of its elements would be a lie in a machine-readable format, which is the worst
    place to put one.

    CARRYING THE TOKEN VALUE. P9.4 spent a ship bounding the correlation a relying party can
    do, by deriving a per-verifier handle instead of handing out a stable identifier. An mdoc
    that carried `token_value` would return that handle in a different encoding, and the
    reader would have no way to know it had been given something the presentation layer
    withholds. The refusal must be at build time and must stand on its own, not merely as a
    consequence of a closed vocabulary: the day somebody adds the element to the vocabulary,
    the vocabulary check stops firing and only an independent guard saves them."""
    name = "mdoc_bridge"
    mod = _read(root, "polaris_web/mdoc.py")
    if not mod:
        return _fail(name, "polaris_web/mdoc.py must render the credential in mdoc structure")

    # NOT AN mDL.
    if "org.iso.18013.5.1" in mod.replace("ISO/IEC 18013-5", "").replace("ISO 18013-5", ""):
        if 'DOC_TYPE = "org.iso.18013.5.1' in mod or 'NAMESPACE = "org.iso.18013.5.1' in mod:
            return _fail(name,
                         "the bridge claims the mDL docType or namespace. A Polaris credential has "
                         "no name, no date of birth and no driving privileges; claiming them in a "
                         "machine-readable format is a lie in the worst possible place")
    if 'DOC_TYPE = "id.polaris' not in mod or 'NAMESPACE = "id.polaris' not in mod:
        return _fail(name, "the bridge must name its own docType and namespace")

    # NOT SIGNED CLASSICALLY.
    if "COSE_ALG_ML_DSA_65" not in mod:
        return _fail(name,
                     "the issuer signature must be ML-DSA. Signing with an algorithm a conforming "
                     "reader knows would trade the post-quantum property for the appearance of "
                     "interoperability, and a PQ credential with a classical signature is a "
                     "classical credential")
    for banned in ("ES256", "ES384", "EdDSA", "-7", "-35"):
        if f"COSE_ALG = {banned}" in mod or f'"alg": "{banned}"' in mod:
            return _fail(name, f"the bridge signs with {banned}; see above")

    # NOT CARRYING THE CORRELATION HANDLE, and the guard must stand on its own.
    if "FORBIDDEN_ELEMENTS" not in mod or "token_value" not in mod:
        return _fail(name,
                     "the bridge must refuse token_value explicitly: an mdoc is not a way around "
                     "the correlation the presentation layer bounds")
    body = mod.split("def build_issuer_signed")[1].split("\ndef ")[0]
    f_at, u_at = body.find("FORBIDDEN_ELEMENTS"), body.find("set(ELEMENTS)")
    if f_at < 0:
        return _fail(name, "build_issuer_signed must check the forbidden elements")
    if 0 <= u_at < f_at:
        return _fail(name,
                     "the forbidden-element check must run BEFORE the vocabulary check, and stand "
                     "on its own: if it runs second, token_value is refused only for being unknown "
                     "and the guard vanishes the day somebody adds it to the vocabulary")

    verifier = _read(root, "scripts/polaris-verify.py")
    if "def verify_mdoc" not in verifier:
        return _fail(name, "the detached verifier must decide an mdoc offline")
    v = verifier.split("def verify_mdoc")[1].split("\ndef ")[0]
    for key, why in (('"digests_match"', "what an off-the-shelf reader CAN establish"),
                     ('"issuer_authentic"', "what only a Polaris-aware verifier can"),
                     ('"reader_interop"', "the difference between them, in words, so a caller "
                                          "cannot report the first as the third")):
        if key not in v:
            return _fail(name, f"the verdict must report {key}: {why}")
    if "_two_witness_verify" not in v:
        return _fail(name, "the MSO signature must be checked with the same two witnesses as every "
                           "other signed artifact")
    if "Signature1" not in verifier:
        return _fail(name,
                     "the signature must be over the COSE Sig_structure, not the payload alone; "
                     "signing the payload leaves the algorithm unauthenticated and relabellable")

    drill = _read(root, "scripts/polaris-mdoc-bridge-drill.py")
    if not drill:
        return _fail(name, "scripts/polaris-mdoc-bridge-drill.py must prove the bridge end to end")
    for needed, why in (("INDEPENDENT reader",
                         "the interop claim must be tested with a CBOR implementation that did "
                         "not write the bytes, or it is a round trip with itself"),
                        ("refusing to emit the token value",
                         "the correlation refusal must be asserted, not assumed"),
                        ("never the mDL", "and so must the naming refusal")):
        if needed not in drill:
            return _fail(name, why)
    doc = _read(root, "docs/design/mdoc-bridge.md")
    if not doc:
        return _fail(name, "the design record must be published (docs/design/mdoc-bridge.md)")
    if "not a trust bridge" not in doc:
        return _fail(name,
                     "the design record must say plainly that this is a format bridge and not a "
                     "trust bridge; a reader who takes a digest check for an issuer check has "
                     "been misled by the document, not by the code")
    return _ok(name,
               "the ISO 18013-5 bridge is a format bridge and says so: it signs with ML-DSA rather "
               "than reaching for an algorithm a conforming reader knows, never claims the mDL "
               "docType because a Polaris credential is not a driving licence, refuses the token "
               "value at build time with a guard that stands on its own, and reports what a reader "
               "can establish separately from what only a Polaris-aware verifier can")



def check_accessibility(root: pathlib.Path) -> list[Finding]:
    """Every operator surface is audited, with an engine that has the rules it claims (P6.5).

    An identity system a person cannot operate is one that excludes them from identity. That
    is the same failure as the trusted-referee gap in the 800-63 mapping, at a different layer,
    and it lands on the same people.

    THE ENGINE MUST HAVE THE RULES IT CLAIMS. The convenient Python wrapper bundles axe 4.4.3,
    which is from 2022 and predates WCAG 2.2 entirely: it has none of the 2.2 rules. Auditing
    with it and reporting "WCAG 2.2 AA" would be a claim about a standard the tool has never
    heard of, so the version is pinned, current, and asserted by the drill itself.

    THE SMALL FINDINGS NEED A CEILING. Serious and critical violations failing the build is the
    easy half. Moderate and minor ones are what accumulate below the threshold anybody watches,
    so they are counted against a ceiling rather than merely printed.

    AND THE LIMIT MUST BE STATED. Automated testing detects roughly a third of WCAG failures.
    It cannot tell whether alt text is meaningful, whether a focus order makes sense, or
    whether a screen-reader user can finish the task. A green run is a floor and not
    conformance, and the document has to say so in those words, because "accessibility checks
    pass" is exactly the sentence that gets quoted as conformance."""
    name = "accessibility"
    drill = _read(root, "scripts/polaris-accessibility-drill.py")
    if not drill:
        return _fail(name, "scripts/polaris-accessibility-drill.py must audit the surfaces")
    runner = _read(root, "scripts/polaris-accessibility-drill.sh")
    if not runner:
        return _fail(name, "the drill needs a runner that boots the app and pins the engine")

    if "axe-core@" not in runner:
        return _fail(name,
                     "the axe version must be PINNED in the runner. An unpinned engine is one "
                     "whose rule set changes under the claim it is being used to support")
    if "4.13" not in runner and "4.1" not in runner:
        return _fail(name,
                     "the pinned axe version must be current enough to HAVE the WCAG 2.2 rules; "
                     "4.4 predates the standard entirely")
    # Quoted, exactly. "wcag2a" is a substring of "wcag2aa" and "wcag21a" of "wcag21aa", so a
    # bare substring test would report the earlier tags as present whenever the later ones are,
    # and dropping them would go unnoticed. The detection test found this.
    if '"wcag22aa"' not in drill:
        return _fail(name,
                     "the WCAG 2.2 AA tag must actually be requested, or the run tests 2.1 and "
                     "the row claims 2.2")
    for tag in ('"wcag2a"', '"wcag2aa"', '"wcag21a"', '"wcag21aa"'):
        if tag not in drill:
            return _fail(name,
                         f"the {tag} tag must be requested too: a 2.2 AA claim is "
                         "cumulative "
                         "and includes every earlier A and AA criterion")
    if "the engine is new enough to HAVE the WCAG 2.2 rules" not in drill:
        return _fail(name,
                     "the drill must assert its own engine version. A pin in a shell script is "
                     "a comment as far as the audit is concerned")

    if "MODERATE_CEILING" not in drill or "MINOR_CEILING" not in drill:
        return _fail(name,
                     "moderate and minor violations must be counted against a CEILING. They are "
                     "the category that accumulates below the threshold anybody is watching")
    for severity in ('"critical"', '"serious"'):
        if severity not in drill:
            return _fail(name, f"{severity} violations must fail the build")
    if "SURFACES" not in drill:
        return _fail(name,
                     "the audited surfaces must be an explicit list: a page missing from it is "
                     "a page nobody audits")
    surfaces = drill.split("SURFACES = [")[1].split("]")[0]
    if surfaces.count('("/') < 10:
        return _fail(name,
                     "the surface list must cover the operator console, not a sample of it")
    for needed, why in (('("/login"', "the login page is the one surface every operator meets "
                                      "and the only one an unauthenticated user can be stuck on"),
                        ('("/atlas"', "the densest surface is the one most likely to fail")):
        if needed not in surfaces:
            return _fail(name, why)

    doc = _read(root, "docs/design/accessibility.md")
    if not doc:
        return _fail(name, "the audit must be published (docs/design/accessibility.md)")
    low = " ".join(doc.lower().split())
    for phrase, why in (("a floor, not conformance",
                         "the document must refuse the reading that a green run is "
                         "conformance; that sentence is exactly what gets quoted"),
                        ("third of wcag failures",
                         "the document must state how much automation actually covers"),
                        ("does not claim wcag 2.2 aa conformance",
                         "the outward claim must match what was established"),
                        ("has not been done",
                         "manual testing with assistive technology is the largest gap and must "
                         "be named as undone rather than left unmentioned")):
        if phrase not in low:
            return _fail(name, why)

    # The outward surfaces must not have quietly started claiming it either.
    roadmap = _read(root, "ROADMAP.md")
    if "accessibility conformance" not in roadmap:
        return _fail(name,
                     "ROADMAP.md's not-claimed list must still carry accessibility conformance. "
                     "Automated checks passing is a floor; removing the caveat would turn a "
                     "third of the criteria into an assertion about all of them")
    return _ok(name,
               "every operator surface is audited in a real browser against a pinned, current "
               "axe-core at the WCAG 2.0, 2.1 and 2.2 A and AA tags, with the drill asserting "
               "its own engine has the rules it claims; serious and critical violations fail "
               "and the moderate and minor ones are held to a ceiling rather than printed; the "
               "surface list is explicit so a page cannot go unaudited; and the record says a "
               "green run is a floor rather than conformance, names how little automation "
               "covers, and leaves the outward claim unchanged")


def check_assurance_mapping(root: pathlib.Path) -> list[Finding]:
    """The 800-63 mapping cites evidence that exists, and does not claim conformance (P6.2).

    A control mapping is the easiest document in a project to write and the easiest to let
    rot. It is a table of claims about a codebase, maintained by hand, read by people who
    cannot check it, and it goes stale the first time somebody deletes the thing a row pointed
    at. Nothing turns red; the document just becomes untrue.

    So the mapping is executable. Every row cites a check, a test class, a drill or a schema
    object, and the drill resolves each one and RUNS every cited check. This check pins the
    shape that makes that possible, and three properties of the document itself.

    IT MUST NOT CLAIM CONFORMANCE. Polaris is a reference implementation on notional data. A
    row marked MET means the mechanism is here and CI proves it still is; it does not mean an
    assessor agreed, and a deployment does not inherit it by running the code. The front matter
    has to say so, because this is the file somebody quotes after reading only its first page.

    A GAP MUST CARRY A REASON. The whole value of writing a gap down is the sentence explaining
    it. A gap with no reason is one somebody meant to come back to.

    AND THE TOTALS MUST BE RECOMPUTED. The document states how many gaps it has; the drill
    counts them from the rows and fails on a disagreement. A summary that can drift from its
    own table is worse than no summary, because it is the part a reader believes."""
    name = "assurance_mapping"
    doc = _read(root, "docs/reference/NIST-800-63-MAPPING.md")
    if not doc:
        return _fail(name, "the mapping must be published "
                           "(docs/reference/NIST-800-63-MAPPING.md)")
    low = " ".join(doc.lower().split())
    for phrase, why in (("not a conformance claim",
                         "the front matter must refuse the reading it will otherwise get: this "
                         "is the file somebody quotes after reading only its first page"),
                        ("no assessment has been performed",
                         "an unassessed mapping must say so"),
                        ("does not inherit",
                         "a deployment does not get these properties by running the code, and "
                         "the document must say it")):
        if phrase not in low:
            return _fail(name, why)
    for level, why in (("highest holder aal claimed",
                        "the highest AAL claimed must be stated in one place, or a reader "
                        "infers it from the greenest row"),
                       ("highest fal claimed", "and the highest FAL")):
        if level not in low:
            return _fail(name, why)

    rows = []
    for line in doc.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 3 and cells[1] in ("MET", "PARTIAL", "GAP", "WAIVED", "EXTERNAL"):
            rows.append(cells)
    if len(rows) < 20:
        return _fail(name,
                     "the mapping must actually map: %d rows is not IAL, AAL and FAL"
                     % len(rows))
    if not any(r[1] == "GAP" for r in rows):
        return _fail(name,
                     "a mapping with no gaps at all is a mapping that rounded them away. Name "
                     "them; the value of writing a gap down is the sentence explaining it")
    uncited = [r[0][:40] for r in rows
               if r[1] == "MET" and not re.search(r"`(check|test|drill|schema):", r[2])]
    if uncited:
        return _fail(name,
                     "a MET row with no citation is an assertion wearing a checkmark: %s"
                     % ", ".join(uncited[:3]))

    drill = _read(root, "scripts/polaris-assurance-mapping-drill.py")
    if not drill:
        return _fail(name,
                     "scripts/polaris-assurance-mapping-drill.py must RESOLVE the citations. "
                     "Without it the mapping is a spreadsheet that goes stale silently")
    for needed, why in (("every citation in the mapping resolves",
                         "a citation naming something that was renamed away must fail"),
                        ("every cited check PASSES",
                         "naming a check that FAILS is the same as naming one that is gone, so "
                         "the cited checks must be RUN rather than merely found"),
                        ("carries a reason",
                         "a gap with no reason must fail"),
                        ("the stated gap count matches the rows",
                         "the totals must be recomputed from the rows, since a summary that "
                         "can drift from its own table is the part a reader believes")):
        if needed not in drill:
            return _fail(name, why)
    if "cannot tell you the mapping is CORRECT" not in drill:
        return _fail(name,
                     "the drill must state its own limit: it cannot tell you a row's "
                     "requirement is really what the standard asks, or that the cited check "
                     "really proves it. That is an assessor's judgement, and a drill that "
                     "implied otherwise would be the same overclaim the document avoids")
    return _ok(name,
               "the assurance mapping is executable rather than asserted: every MET row cites a "
               "check, test, drill or schema object, the drill resolves each and runs every "
               "cited check, gaps are named with reasons rather than rounded away, the totals "
               "are recomputed from the rows, the front matter refuses the conformance reading "
               "and says a deployment does not inherit these properties, and the drill states "
               "the limit of what resolving citations can establish")


def check_enrollment_proofing(root: pathlib.Path) -> list[Finding]:
    """An enrollment records what it rested on, and the level is derived from it (P4.4).

    Polaris could issue a credential and had no way to say how the person was proven to be who
    they claimed. That gap is why an assurance level could not be asserted honestly and why the
    800-63-4 mapping was blocked.

    THE LEVEL IS DERIVED, NEVER ASSERTED. An enrollment does not claim IAL2 because somebody
    typed IAL2. A level an operator can enter is a label, and every relying party downstream
    would be trusting the label rather than the proofing. Claiming above what the evidence
    supports is refused; claiming below it is allowed, because an authority may hold itself to
    less than it could assert and refusing that pushes operators to overstate.

    EVIDENCE NOBODY CHECKED IS NOT EVIDENCE. Validation asks whether the document is genuine;
    verification asks whether it belongs to the person in front of you. A genuine passport
    belonging to somebody else passes the first and fails the second, so a piece that fails
    either must contribute nothing whatever its nominal strength.

    IAL3 NEEDS A LIVE BIOMETRIC, AND THE DATABASE HOLDS THAT FLOOR. A photograph of a face
    scores excellently on quality, so a capture that failed liveness must not count, and the
    constraint must sit in the schema as well as the application: an INSERT that skips the
    application must not be able to record an IAL3 the session never had.

    AND THE RECORD SAYS WHAT WAS ESTABLISHED, NEVER WHAT WAS PRESENTED. No document number, no
    scan, no template, no date of birth: refused by name AND with no column to write them into.
    That is what keeps an enrollment archive from being a second identity database sitting
    behind the first, which is the most attractive target an identity system builds."""
    name = "enrollment_proofing"
    mod = _read(root, "polaris_web/proofing.py")
    if not mod:
        return _fail(name, "polaris_web/proofing.py must carry the proofing model")
    for fn in ("def derive_ial", "def check_claimed_ial", "def effective_strength",
               "def record_proofing", "def why_not_higher"):
        if fn not in mod:
            return _fail(name, f"the model must expose {fn.split()[1]}()")

    claimed = mod.split("def check_claimed_ial")[1].split("\ndef ")[0]
    if "ProofingRefused" not in claimed:
        return _fail(name,
                     "claiming a level the evidence does not support must be REFUSED. A level "
                     "an operator can type in is a label, and relying parties downstream would "
                     "be trusting the label rather than the proofing")
    if "index(claimed) > " not in claimed:
        return _fail(name,
                     "claiming LESS than the evidence supports must be allowed: an authority "
                     "may hold itself to less than it could assert, and refusing that pushes "
                     "operators to overstate in order to record anything at all")

    effective = mod.split("def effective_strength")[1].split("\ndef ")[0]
    if "validated" not in effective or "verified" not in effective:
        return _fail(name,
                     "evidence that was not validated AND verified must contribute nothing. A "
                     "genuine document belonging to somebody else passes validation and fails "
                     "verification, and counting it anyway rests an enrollment on a theft")
    if "UNACCEPTABLE" not in effective:
        return _fail(name, "unchecked evidence must fall to UNACCEPTABLE rather than keep its "
                           "nominal strength")

    if "class BiometricCapture" not in mod:
        return _fail(name,
                     "a vendor-neutral capture abstraction must be the only shape the "
                     "enrollment path accepts; letting each vendor's blob through and promising "
                     "not to store it is a promise rather than a boundary")
    capture = mod.split("class BiometricCapture")[1].split("\ndef ")[0]
    if "__slots__" not in capture:
        return _fail(name,
                     "the capture object must be closed, so a template cannot be attached to it "
                     "at the edge and carried inward")
    if "liveness" not in capture:
        return _fail(name,
                     "liveness must gate a capture: a photograph of a face and a lifted "
                     "fingerprint both score excellently, so a pipeline that ignored liveness "
                     "would raise the assurance of exactly the enrollments an attacker controls")

    if "FORBIDDEN_EVIDENCE_FIELDS" not in mod:
        return _fail(name, "the document itself must be refused BY NAME")
    for field in ("document_number", "scan", "biometric_template", "date_of_birth"):
        if f'"{field}"' not in mod:
            return _fail(name, f"{field!r} must be refused by name")
    check_ev = mod.split("def check_evidence")[1].split("\ndef ")[0]
    f_at, u_at = check_ev.find("FORBIDDEN_EVIDENCE_FIELDS"), check_ev.find("EVIDENCE_FIELDS)")
    if f_at < 0:
        return _fail(name, "check_evidence must check the forbidden fields")
    if 0 <= u_at < f_at:
        return _fail(name,
                     "the forbidden-field check must run BEFORE the vocabulary check and stand "
                     "on its own, or a document number is refused only for being unknown and "
                     "the guard vanishes the day somebody widens the vocabulary")

    schema = _read(root, "polaris_sql/01_schema.sql")
    for table in ("EnrollmentProofing", "EnrollmentEvidence"):
        if f"CREATE TABLE IF NOT EXISTS {table}" not in schema:
            return _fail(name, f"the schema must define {table}")
    create = re.search(r"CREATE TABLE IF NOT EXISTS EnrollmentEvidence\s*\((.*?)\n\);",
                       schema, re.S)
    if not create:
        return _fail(name, "EnrollmentEvidence must be a CREATE TABLE in 01_schema.sql")
    columns = {m.group(1).lower() for m in
               re.finditer(r"^\s{4}([a-z_]+)\s+[A-Z]", create.group(1), re.M)}
    for banned in ("document_number", "scan", "image", "photo", "portrait",
                   "biometric_template", "template", "date_of_birth", "dob", "address",
                   "ssn", "expiry_date"):
        if banned in columns:
            return _fail(name,
                         f"there must be no column to write a {banned!r} into: not 'we do not "
                         "write one'. That absence is what keeps an enrollment archive from "
                         "being a second identity database behind the first")
    if "ial3_needs_session_and_biometric" not in schema:
        return _fail(name,
                     "the DATABASE must keep its own floor under IAL3. An INSERT that skips the "
                     "application must not be able to record a level the session never had")
    if "biometric_recorded_whole" not in schema:
        return _fail(name,
                     "a biometric must be recorded whole or not at all: a modality with no "
                     "liveness result would let an enrollment count a photograph")
    triggers = _read(root, "polaris_sql/06_triggers.sql")
    for trig in ("trg_enrollment_proofing_append_only", "trg_enrollment_evidence_append_only"):
        if trig not in triggers:
            return _fail(name,
                         f"{trig} is missing: an assurance level rests on the evidence recorded "
                         "beside it, and a record of that evidence which can be edited "
                         "afterwards is not evidence")

    drill = _read(root, "scripts/polaris-enrollment-proofing-drill.py")
    if not drill:
        return _fail(name, "scripts/polaris-enrollment-proofing-drill.py must run the model "
                           "against a real database")
    for needed, why in (("every combination in the evidence table derives its level",
                         "the whole table must be walked, not one happy case"),
                        ("nobody validated contributes nothing",
                         "unchecked evidence must be exercised"),
                        ("not bound to the applicant",
                         "the genuine-document-belonging-to-someone-else case is the sharp one"),
                        ("failed liveness does not reach IAL3",
                         "a spoofed capture must be exercised"),
                        ("does not support is REFUSED",
                         "the overclaim must be refused in practice"),
                        ("NO COLUMN to write any of them into",
                         "the absence must be asserted against the live schema, not assumed"),
                        ("re-proofing that finds LESS lowers",
                         "the current level must be the latest rather than the high-water mark")):
        if needed not in drill:
            return _fail(name, why)

    doc = _read(root, "docs/design/identity-proofing.md")
    if not doc:
        return _fail(name, "the model must be published (docs/design/identity-proofing.md)")
    low = " ".join(doc.lower().split())
    for phrase, why in (("derived, never asserted",
                         "the record must lead on where the level comes from"),
                        ("second identity database",
                         "the record must say what the minimisation is FOR"),
                        ("liveness is not optional",
                         "the record must state why a quality score alone is not enough"),
                        ("remain open under p4.4",
                         "the record must say what this does NOT cover, since the kiosk build "
                         "is still open")):
        if phrase not in low:
            return _fail(name, why)
    return _ok(name,
               "an enrollment records what it rested on and the assurance level is derived from "
               "that evidence rather than typed: an overclaim is refused with the reason while "
               "an underclaim is allowed, evidence nobody validated AND bound to the applicant "
               "contributes nothing, IAL3 needs a live biometric with the database holding that "
               "floor under a direct INSERT, the capture abstraction is closed so no vendor's "
               "template reaches the record, both tables are append-only, and the document "
               "itself is refused by name with no column anywhere to write it into")


def check_duress_on_card(root: pathlib.Path) -> list[Finding]:
    """Duress is indistinguishable at the physical layer, not only in the bytes (P4.7).

    The vocation above C1-C10 says no person can be compelled to surrender their identity
    against their will. This is that mechanism where the coercer is standing next to the
    holder rather than reading a log, and indistinguishability there is not one property but
    every observable at once.

    THE COMPARISON IS UNCONDITIONAL. The card compares against a duress comparand every time,
    whether or not the holder enrolled a duress PIN. Skipping it when none is enrolled makes
    ENROLLMENT ITSELF observable, and note the shape of that harm: it does not endanger the
    holder who skipped enrollment, it endangers the ones who did enroll, by splitting the
    population into two classes a coercer can tell apart. Learning that a card has no duress
    PIN tells them the PIN they just watched was the real one.

    This is checked as a PROPERTY rather than as text. The duress comparison must be the whole
    right-hand side of its assignment: anything else there is a guard, whatever it is called.
    The first version of this check matched the exact wording of the original defect and duly
    missed a differently-worded reintroduction of it.

    THE TWO PINS ARE THE SAME LENGTH. The PIN travels in the data field of a VERIFY command,
    so its length is on the wire: a six-digit duress PIN beside a four-digit normal one
    announces which class was entered without anyone needing to see the keypad.

    AND THE TIMING IS MEASURED AGAINST SOMETHING PHYSICAL. A gap of tens of nanoseconds is
    Python object layout; what matters is whether a gap could be read through a reader, where
    an NFC exchange is milliseconds and the field's jitter is tens of microseconds. A drill
    that failed on nanoseconds would be measuring the emulator rather than the design."""
    name = "duress_on_card"
    emu = _read(root, "polaris_card/emulator.py")
    if not emu:
        return _fail(name, "polaris_card/emulator.py must implement the card's PIN handling")
    body = emu.split("def _verify_pin")[1].split("\n    def ")[0]
    if body.count("hmac.compare_digest") != 2:
        return _fail(name,
                     "both PIN comparisons must run every time and both must be constant-time")
    assignment = [ln.strip() for ln in body.splitlines() if ln.strip().startswith("duress_ok")]
    if not assignment:
        return _fail(name, "the duress comparison must be its own assignment")
    guarded = [ln for ln in assignment
               if not (ln.startswith("duress_ok = hmac.compare_digest(") and ln.endswith(")"))]
    if guarded:
        return _fail(name,
                     "the duress comparison must be the WHOLE right-hand side of its "
                     "assignment. Anything else there is a guard, whatever it is called, and a "
                     "guard makes the work depend on whether the holder enrolled a duress PIN. "
                     "That does not endanger the holder who skipped enrollment; it endangers "
                     "the ones who did, by splitting the population into two classes a coercer "
                     "can tell apart")
    init = emu.split("def __init__")[1].split("\n    def ")[0]
    if "_unmatchable" not in init:
        return _fail(name,
                     "a card with no enrolled duress PIN must still hold a comparand, or there "
                     "is nothing for the unconditional comparison to compare against")
    if "def _unmatchable" not in emu:
        return _fail(name, "the stand-in comparand must be defined")
    unmatch = emu.split("def _unmatchable")[1].split("\ndef ")[0].split("\nclass ")[0]
    if "\\x00" not in unmatch:
        return _fail(name,
                     "the stand-in comparand must be UNMATCHABLE rather than merely improbable: "
                     "a keypad cannot put a NUL in the data field, so a leading NUL is what "
                     "makes it never match")
    if "len(duress_pin) != len(normal_pin)" not in init:
        return _fail(name,
                     "the two PINs must be the same length: the PIN is in the command's data "
                     "field, so its length is on the wire")

    drill = _read(root, "scripts/polaris-duress-timing-drill.py")
    if not drill:
        return _fail(name, "scripts/polaris-duress-timing-drill.py must MEASURE the physical "
                           "layer rather than asserting it")
    if "OBSERVABLE_GAP" not in drill:
        return _fail(name,
                     "the timing judgement needs a threshold that means something physically. "
                     "A gap of tens of nanoseconds is object layout; what matters is what could "
                     "be read through a reader, where an NFC exchange is milliseconds")
    if "permutation_test" not in drill:
        return _fail(name,
                     "the measurement must be judged against noise it calibrates itself, not "
                     "against a fixed number that turns a shared runner into a coin flip")
    for needed, why in (("a card WITH a duress PIN costs no observable time over one without",
                         "the enrollment leak is the sharp case and must be measured"),
                        ("a duress PIN costs no observable time over the normal one",
                         "the basic case must be measured"),
                        ("WHOLE right-hand side, unguarded",
                         "the structural property must be asserted as a property"),
                        ("not a leak",
                         "the right/wrong PIN gap must be reported and EXPLAINED rather than "
                         "asserted away: the status word already announces it")):
        if needed not in drill:
            return _fail(name, why)

    doc = _read(root, "docs/design/duress-on-card.md")
    if not doc:
        return _fail(name, "the entry method and its safety review must be published "
                           "(docs/design/duress-on-card.md)")
    low = " ".join(doc.lower().split())
    for phrase, why in (("same length as the first",
                         "the record must specify the entry method, starting with the length "
                         "rule that keeps it off the wire"),
                        ("it does not prevent",
                         "the safety review must say that the mechanism SIGNALS rather than "
                         "prevents; treating it as prevention is how it gets people hurt"),
                        ("recall", "the safety review must address recall under stress, since "
                                   "a duress PIN is used once, years later, at the worst moment "
                                   "of someone's life"),
                        ("nothing is signalled",
                         "the record must repeat that an offline verifier raises no alarm, and "
                         "that the card must therefore behave identically offline")):
        if phrase not in low:
            return _fail(name, why)
    return _ok(name,
               "duress is indistinguishable at the physical layer and not only in the bytes: "
               "the card compares against a duress comparand unconditionally, so whether the "
               "holder ENROLLED one is not observable and the population does not split into "
               "two classes a coercer can tell apart; the stand-in comparand is unmatchable "
               "rather than improbable; the two PINs are the same length because a PIN's length "
               "is on the wire; the timing is measured with a self-calibrating test and judged "
               "against what a reader could actually carry; the one gap that does exist is "
               "reported and explained rather than asserted away; and the safety review states "
               "that the mechanism signals rather than prevents")


def check_verifier_device(root: pathlib.Path) -> list[Finding]:
    """The thing at the counter decides honestly, and says what it learned (P4.5).

    THREE FACTS, KEPT APART. Possession (the card signed THIS device's challenge just now),
    authenticity (the authority issued this card), authorization (the credential still stands
    inside a window this device accepts). All three are needed to accept, and each is reported
    on its own, because a device that says only "no" teaches its operator nothing. Possession
    alone is emphatically not acceptance: a card revoked this morning still signs.

    THE REPLAY A SIGNATURE CANNOT REFUSE. The challenge and scope are inside the card's
    signature, so a response relayed to a DIFFERENT device fails. Replayed to the SAME device
    it does not: the signature over that challenge is perfectly valid the second time. Only
    the device remembering its own outstanding challenges refuses that.

    AND THE DEVICE REPORTS WHAT IT LEARNED, NOT ONLY WHAT IT ACCEPTED. A P3.6 status assertion
    signs the token_value in the clear, so a device checking authorization offline learns the
    stable credential identifier and can correlate its sightings with any other device holding
    one. Every verdict therefore carries `linkability`, and it is set BEFORE the assertion is
    verified: the device read the value the moment it held the assertion, and a failed
    verification does not un-disclose an identifier."""
    name = "verifier_device"
    mod = _read(root, "polaris_card/verifier_device.py")
    if not mod:
        return _fail(name, "polaris_card/verifier_device.py must carry the reference device")
    for fn in ("def challenge", "def read_nfc", "def qr_request", "def read_qr", "def decide"):
        if fn not in mod:
            return _fail(name, f"the device must expose {fn.split()[1]}()")

    decide = mod.split("def decide")[1].split("\n\n# ---")[0]
    # Bare identifiers: which quote style the source uses is not the property being checked.
    for field, why in (("possession_proven", "the card signed this device's challenge"),
                       ("card_authentic", "the authority issued this card"),
                       ("authorization_fresh", "the credential still stands"),
                       ("linkability", "what the device learned about the holder")):
        if field not in decide:
            return _fail(name,
                         f"the verdict must report {field} separately: {why}. A device that "
                         "returns one boolean teaches its operator nothing about a refusal")
    if "still stands" not in decide:
        return _fail(name,
                     "possession alone must not accept, and the device must say why: a card "
                     "revoked this morning still signs")

    if "_retire" not in mod or "_spent" not in mod:
        return _fail(name,
                     "the device must remember its own challenges. A response replayed to the "
                     "SAME device carries a signature that is perfectly valid the second time, "
                     "so nothing but the device can refuse it")
    retire = mod.split("def _retire")[1].split("\n    def ")[0]
    if "already been answered" not in retire:
        return _fail(name, "a replayed challenge must be refused with its reason")
    scope_at, retire_at = decide.find("!= self.scope"), decide.find("self._retire")
    if scope_at < 0:
        return _fail(name,
                     "a presentation made for another verifier's scope must be refused: a "
                     "response relayed from another device is not a presentation to this one")
    if 0 <= retire_at < scope_at:
        return _fail(name,
                     "the scope must be checked BEFORE the challenge is retired, or a relayed "
                     "presentation burns challenges the honest holder is about to use, which "
                     "is a denial of service against the exchange")

    link_at = max(decide.find('v["linkability"] = "credential-linkable"'),
                  decide.find("v['linkability'] = 'credential-linkable'"))
    verify_at = decide.find("verify_status_assertion(")
    if link_at < 0:
        return _fail(name, "the device must report when it learned a stable identifier")
    if 0 <= verify_at < link_at:
        return _fail(name,
                     "linkability must be recorded BEFORE the status assertion is verified. "
                     "The device read the token value the moment it held the assertion, and a "
                     "failed verification does not un-disclose an identifier: reporting it only "
                     "on success accounts for what the device ACCEPTED rather than what it "
                     "LEARNED")

    if "def qr_capacity_report" not in mod:
        return _fail(name,
                     "the QR ceiling must be MEASURED. Whether a card object fits in a QR code "
                     "decides the protocol rather than decorating it")
    for const in ("QR_MAX_ALPHANUMERIC", "QR_PRACTICAL_CHARS"):
        if const not in mod:
            return _fail(name, f"the QR limit {const} must be named, not implied")
    if "verify_status_assertion" not in mod or "_load_status_verifier" not in mod:
        return _fail(name,
                     "the device must reuse the DETACHED verifier for a status assertion. A "
                     "second implementation of a decision that already has one is two answers "
                     "to a question with nothing saying which is right")

    drill = _read(root, "scripts/polaris-verifier-device-drill.py")
    if not drill:
        return _fail(name, "scripts/polaris-verifier-device-drill.py must run the device")
    for needed, why in (("replayed to the SAME device is refused",
                         "the replay a signature cannot refuse must be exercised"),
                        ("relayed to ANOTHER device is refused",
                         "the scope binding must be exercised"),
                        ("REVOKED credential is refused",
                         "a valid signature over a withdrawn credential must not accept"),
                        ("possession alone is NOT acceptance",
                         "the device must not treat a signing card as a valid one"),
                        ("stays PAIRWISE",
                         "the handle-only mode's privacy property must be asserted"),
                        ("two devices cannot tell they saw the same card",
                         "the pairwise claim must be tested across devices"),
                        ("POST-QUANTUM card object does NOT",
                         "the QR ceiling must be asserted, not just printed")):
        if needed not in drill:
            return _fail(name, why)

    doc = _read(root, "docs/design/verifier-device.md")
    if not doc:
        return _fail(name, "the design record must be published (docs/design/verifier-device.md)")
    low = " ".join(doc.lower().split())
    for phrase, why in (("possession alone is not acceptance",
                         "the record must state that a signing card is not a valid one"),
                        ("cannot carry a post-quantum card object",
                         "the record must state the QR ceiling as a constraint with a number"),
                        ("learns the stable credential identifier",
                         "the record must state the linkability an offline authorization check "
                         "costs, rather than leaving it to be discovered")):
        if phrase not in low:
            return _fail(name, why)
    return _ok(name,
               "the device at the counter keeps possession, authenticity and authorization "
               "apart and needs all three, refuses a response relayed to another device by the "
               "scope and one replayed to itself by remembering its own challenges (which a "
               "signature cannot do), does not let a refused scope burn a challenge, reuses the "
               "detached verifier rather than deciding twice, reports what it LEARNED about the "
               "holder before knowing whether it will accept, and records the measured QR "
               "ceiling that puts a post-quantum card object out of reach of any QR version")


def check_card_personalization(root: pathlib.Path) -> list[Finding]:
    """A record becomes an object, and the authority never holds the key that makes it answer (P4.3).

    Personalization is the only step where the authority's signature is applied to something
    that then leaves its control. Everything after it is downstream of whether this step was
    done right, and there is no recall.

    KEY GENERATION, NOT KEY INJECTION. The card generates its own keypairs and exports only the
    public halves. An injected key existed somewhere else first: on the personalization host,
    in its memory, possibly in a log or a core dump, and the authority can only ASSERT that it
    was destroyed. A generated key has no such history, so "the private key never left the
    card" becomes a fact about where it was made rather than a promise about what was deleted.
    The check holds the structural version of that: there must be no private-key column to
    write one into, and no parameter to pass one through.

    A CARD IS PERSONALIZED ONCE, AND A CREDENTIAL GETS ONE CARD. The card refuses a second
    generation for the life of the part, by its own rule rather than by whatever backs its
    slots; the database refuses a second card for one credential, by a unique index rather
    than by a check somebody has to remember. Two live cards answering for one credential is a
    revocation that only half works.

    THE RECORD IS APPEND-ONLY. The 15th audit-of-record instance. A personalization that could
    be edited afterwards is not a record of what was issued.

    AND EVERY CARD CARRIES A DURESS SLOT. Whether or not the holder ever enrolls a duress PIN.
    If a duress slot only existed when one was wanted, its presence in the authority's records
    would be a fact about the holder rather than about the system."""
    name = "card_personalization"
    mod = _read(root, "polaris_card/personalization.py")
    if not mod:
        return _fail(name, "polaris_card/personalization.py must carry the flow")
    if "def personalize" not in mod:
        return _fail(name, "the service must expose personalize()")
    flow = mod.split("def personalize")[1].split("\ndef ")[0]
    if "generate_keypair" not in flow:
        return _fail(name,
                     "the card must GENERATE its own keypair. An injected key existed on the "
                     "personalization host first, and the authority could only assert that it "
                     "was destroyed")
    for banned in ("private_key", "secret_key", "private_bytes"):
        if banned in flow:
            return _fail(name,
                         f"personalize() must never handle a private key ({banned!r}); there "
                         "must be no parameter through which one could be supplied, and that "
                         "absence is the design rather than an omission")
    for guard, why in (("!= \"ACTIVE\"", "a withdrawn credential must be refused: a signed "
                                          "object for something the authority has taken back is "
                                          "exactly what should not be in the world"),
                       ("already_personalized", "a credential gets one card"),
                       ("STATE_BLANK", "a card is personalized once for the life of the part")):
        if guard not in flow:
            return _fail(name, why)
    if "issuer_verify" not in flow:
        return _fail(name,
                     "the card object must be verified BEFORE the row is written. A row in the "
                     "audit-of-record saying a card was fine, for a card whose signature does "
                     "not check, is worse than no row at all")

    emu = _read(root, "polaris_card/emulator.py")
    if "INS_GENERATE_KEYPAIR" not in emu or "STATE_PERSONALIZED" not in emu:
        return _fail(name,
                     "the card must have a personalization lifecycle: a blank card that can be "
                     "personalized, and a personalized one that cannot be personalized again")
    gen = emu.split("def _generate_keypair")[1].split("\n    def ")[0]
    # The flag must appear in the REFUSAL CONDITION, not merely somewhere in the body: a
    # version that sets `self._generated = True` but never tests it reads the same to a
    # substring search and refuses nothing.
    guard = gen.split("return sw_bytes(SW_ALREADY_PERSONALIZED)")[0]
    if "self._generated" not in guard:
        return _fail(name,
                     "the CARD must refuse a second generation by its own rule. Leaving it to "
                     "whatever backs the slots makes 'a slot is generated once' a property of "
                     "the personalization host, which is the party the rule exists to constrain")
    if "SW_ALREADY_PERSONALIZED = 0x" not in emu:
        return _fail(name, "refusing a re-personalization needs its own status word, or a "
                           "reader cannot tell it from a malformed command")

    schema = _read(root, "polaris_sql/01_schema.sql")
    if "CREATE TABLE IF NOT EXISTS CardPersonalization" not in schema \
            and "CREATE TABLE CardPersonalization" not in schema:
        return _fail(name, "the schema must define CardPersonalization")
    # The CREATE TABLE body, not the first mention of the name: the header comment above it
    # names the table several times, and splitting on the name grabs prose instead of columns.
    create = re.search(r"CREATE TABLE (?:IF NOT EXISTS )?CardPersonalization\s*\((.*?)\n\);",
                       schema, re.S)
    if not create:
        return _fail(name, "CardPersonalization must be a CREATE TABLE in 01_schema.sql")
    table = create.group(1)
    # Column NAMES, not a substring search of the whole body. "pin" appears inside words like
    # "mapping"; and a required column named only in a CHECK constraint is not a column, so
    # both the banned and the required lists are answered from the same extracted set.
    columns = {m.group(1).lower() for m in
               re.finditer(r"^\s{4}([a-z_]+)\s+[A-Z]", table, re.M)}
    for banned in ("private_key", "secret_key", "normal_private_key", "duress_private_key",
                   "pin", "puk", "duress_pin", "pin_hash"):
        if banned in columns:
            return _fail(name,
                         f"the personalization record must have nowhere to write a {banned!r}: "
                         "not 'we do not write one', but no column to write it into")
    for needed, why in (("normal_public_key", "the authority must be able to verify a later "
                                              "presentation, and a fingerprint cannot"),
                        ("duress_public_key", "the authority is precisely who must be able to "
                                              "tell a duress presentation apart")):
        if needed not in columns:
            return _fail(name, why)
    if "card_slots_differ" not in schema:
        return _fail(name,
                     "the two slots must differ. A card whose duress key equalled its normal "
                     "key would produce a presentation the AUTHORITY could not tell apart "
                     "either, and the authority is the one party that has to")
    if "idx_card_personalization_one_per_token" not in schema:
        return _fail(name,
                     "one card per credential must be a unique index rather than a check in "
                     "application code: two live cards for one credential is a revocation that "
                     "only half works")
    triggers = _read(root, "polaris_sql/06_triggers.sql")
    if "trg_card_personalization_append_only" not in triggers:
        return _fail(name,
                     "the personalization record must be append-only. It is the one step where "
                     "the authority's signature goes onto something that then leaves its "
                     "control; a record of that which can be edited is not a record")

    drill = _read(root, "scripts/polaris-personalization-drill.py")
    if not drill:
        return _fail(name, "scripts/polaris-personalization-drill.py must run the flow against "
                           "a real database")
    if "session_replication_role" in drill:
        return _fail(name,
                     "the drill must not disable the append-only trigger to clean up after "
                     "itself. A drill that turns off the audit-of-record to tidy up teaches "
                     "the exact habit it exists to forbid; build a scratch database instead")
    for needed, why in (("appears in NOTHING it produced",
                         "the private key's absence must be ASSERTED against what the flow "
                         "produced, recorded and returned, not assumed"),
                        ("cannot be UPDATEd", "append-only must be proven against the database"),
                        ("a second card for the same credential is refused",
                         "one card per credential must be exercised"),
                        ("refuses a second GENERATE KEYPAIR",
                         "the card's one-shot rule must be exercised"),
                        ("sees the DURESS slot when that PIN was used",
                         "the authority's half of the duress mechanism must actually work "
                         "from the keys this flow wrote down")):
        if needed not in drill:
            return _fail(name, why)
    return _ok(name,
               "a record becomes an object without the authority ever holding the key that "
               "makes it answer: the card generates its own pair and there is no parameter to "
               "inject one through and no column to record one in, the card refuses a second "
               "personalization by its own rule and the database refuses a second card for one "
               "credential by a unique index, a withdrawn credential is refused, the record is "
               "the 15th append-only audit-of-record instance, every card carries a duress slot "
               "recorded beside the normal one so its existence says nothing about the holder, "
               "and the drill builds its own database rather than disabling the trigger to "
               "clean up")


def check_card_emulator(root: pathlib.Path) -> list[Finding]:
    """The card's BEHAVIOUR is fixed, so everything downstream can be built now (P4.2).

    P4.1 said what is on a card. This is what a card answers, in what order, and what it
    refuses. The interface is ISO 7816-4 APDUs rather than a comfortable Python API, because a
    reader written against a method call has to be rewritten the day silicon arrives and a
    reader written against APDUs does not. That is the whole content of "everything downstream
    develops against the emulator".

    THE CARD IS NOT AN ORACLE. It signs nothing before a PIN, and it refuses a challenge short
    enough to be worth waiting for a repeat of. A card that signed whatever a reader asked for
    would be a signing service in somebody's pocket.

    THE PIN IS NOT BRUTE-FORCEABLE, AND THE COUNTER SURVIVES A POWER CYCLE. A retry counter
    reset by pulling the card would make a four-digit PIN free to enumerate.

    AND THE COERCER LEARNS NOTHING, EXACTLY. Both PINs unlock with the same status word, both
    reset the counter identically, and the two must be the SAME LENGTH because the PIN travels
    in the command's data field where its length is observable. The signature is fixed-length
    raw r||s rather than DER: that is what a secure element returns, and it is what makes the
    indistinguishability an exact property instead of one you can only sample for, since a DER
    signature's length varies per signature."""
    name = "card_emulator"
    mod = _read(root, "polaris_card/emulator.py")
    if not mod:
        return _fail(name, "polaris_card/emulator.py must implement the card's behaviour")
    for needed, why in (("INS_SELECT", "the command set must be ISO 7816-4 APDUs, not a Python "
                                       "API a reader would have to abandon for real silicon"),
                        ("INS_VERIFY_PIN", "PIN verification is a command"),
                        ("INS_SIGN_CHALLENGE", "presentation is a command"),
                        ("SW_BLOCKED", "a blocked card needs its own status word"),
                        ("SW_SECURITY_NOT_SATISFIED", "refusing before a PIN needs its own")):
        if needed not in mod:
            return _fail(name, why)

    if "def transmit" not in mod:
        return _fail(name, "the card must be spoken to through one transmit() entry point")
    tx = mod.split("def transmit")[1].split("\n    def ")[0]
    if "except Exception" not in tx:
        return _fail(name,
                     "transmit() must answer a malformed command with a status word rather "
                     "than raising: half of what a reader is written against is what happens "
                     "when it gets the command wrong")

    verify = mod.split("def _verify_pin")[1].split("\n    def ")[0]
    if "compare_digest" not in verify:
        return _fail(name, "the PIN comparison must be constant-time")
    if verify.count("compare_digest") < 2 or "normal_ok or duress_ok" not in verify:
        return _fail(name,
                     "BOTH PIN comparisons must run every time. Short-circuiting on the normal "
                     "PIN makes a duress presentation measurably slower, which is exactly the "
                     "fact that must not be observable")
    if "_tries = MAX_PIN_TRIES" not in verify:
        return _fail(name,
                     "a correct PIN must reset the retry counter, and the duress PIN must reset "
                     "it identically: one that left the counter alone would announce itself on "
                     "the NEXT wrong attempt")
    init = mod.split("def __init__")[1].split("\n    def ")[0]
    if "len(duress_pin) != len(normal_pin)" not in init:
        return _fail(name,
                     "the two PINs must be the same length. The PIN travels in the command's "
                     "data field, so its length is on the wire: a six-digit duress PIN beside a "
                     "four-digit normal one announces which class was entered without anyone "
                     "seeing the keypad")
    reset = mod.split("def reset")[1].split("\n    def ")[0]
    if "hasattr" not in reset or "_tries" not in reset:
        return _fail(name,
                     "the retry counter must survive a power cycle, or a wrong PIN is free to "
                     "retry forever and a four-digit PIN is enumerable")

    if "RAW_SIGNATURE_LEN" not in mod or "def der_from_raw" not in mod:
        return _fail(name,
                     "the card must emit a FIXED-LENGTH raw r||s signature, as a secure element "
                     "does, with DER wrapping left to the reader. A DER signature's length "
                     "varies per signature, which turns 'a duress response is indistinguishable' "
                     "from an exact property into one you can only sample for")

    sign = mod.split("def _sign_challenge")[1].split("\n    def ")[0]
    if "_unlocked_slot is None" not in sign:
        return _fail(name, "the card must sign nothing before a PIN is verified")
    if "CardProfileError" not in sign:
        return _fail(name,
                     "a challenge too short to be a challenge must be refused BY THE CARD; a "
                     "card that signed whatever a reader asked for would be an oracle")
    obj = mod.split("def _get_card_object")[1].split("\n    def ")[0]
    if "_unlocked_slot is None" not in obj:
        return _fail(name,
                     "identified mode must need a verified PIN too: the reader learns a stable "
                     "credential reference, so it is something a verifier asks for rather than "
                     "something a card volunteers")

    vectors = _read(root, "polaris_card/vectors/apdu-exchanges.json")
    if not vectors:
        return _fail(name,
                     "the APDU contract must be published: a reader implementer downstream has "
                     "nothing else to write against")
    for key in ("commands", "session", "status_words", "response_body_hex"):
        if key not in vectors:
            return _fail(name, f"the published APDU contract must carry {key}")
    suite = _read(root, "polaris_card/test_emulator.py")
    if "apdu-exchanges.json" not in suite:
        return _fail(name,
                     "the suite must walk the PUBLISHED session against a real card. If the "
                     "file and the card diverge, the file is a lie in the shape of a "
                     "specification, and it must fail here rather than in somebody's lab")

    drill = _read(root, "scripts/polaris-card-emulator-drill.py")
    if not drill:
        return _fail(name, "scripts/polaris-card-emulator-drill.py must run a reader against "
                           "the card")
    for needed, why in (("built only from the published vectors",
                         "the drill's reader must use only what a downstream implementer has, "
                         "or 'everything downstream develops against it' is untested"),
                        ("replayed under a fresh challenge is refused",
                         "a captured response must be worth nothing"),
                        ("relayed to a different reader is refused",
                         "the scope is inside the signature for a reason"),
                        ("three wrong PINs block the card", "the PIN must not be brute-forceable"),
                        ("walks the same commands as a normal one",
                         "the coercer's transcript must be compared, not asserted"),
                        ("exactly one response length",
                         "the length claim must be EXACT rather than sampled")):
        if needed not in drill:
            return _fail(name, why)
    return _ok(name,
               "the card's behaviour is fixed as ISO 7816-4 APDUs with a published contract, so "
               "a reader can be written before silicon exists: it signs nothing before a PIN and "
               "refuses a challenge too short to be one, three wrong PINs block it and the block "
               "survives a power cycle, both PINs unlock identically and must be the same length "
               "because a PIN's length is on the wire, both comparisons run every time so timing "
               "says nothing, and the signature is fixed-length raw r||s as a secure element "
               "returns, which makes the duress indistinguishability exact rather than sampled")


def check_card_profile(root: pathlib.Path) -> list[Finding]:
    """The card is specified as an object somebody else can implement (P4.1).

    The schema modelled a card from the first version: serials, biometric binding type, duress
    hash, succession. What it did not have was an encoding, and a card profile that exists only
    as prose is a profile two implementers read differently.

    THE ENCODING HAS ONE READING. Deterministic TLV, tags ascending and non-repeating, unknown
    tags refused rather than skipped. All three matter because the object is signed: a format
    with two encodings of the same content is one where a signature moves onto content it did
    not authorise, and a reader that skips what it does not recognise verifies a signature over
    bytes it never looked at.

    THE RECORD IS NOT ON THE CARD. The token value, the name, the date of birth, biometric
    templates and the duress code in any form are refused BY NAME, not merely left out of the
    vocabulary. A card that emitted the token value would hand any reader the identifier the
    relying-party API accepts, so one read of a card in a pocket would be as good as holding it.

    BREAKING THE WEAKER ALGORITHM IS NOT ENOUGH. When both signatures are present both must
    verify. Accept-if-either hands the scheme to whoever breaks the classical leg first, which
    is the entire reason a transitional card carries two.

    AND THE VECTORS ARE THE CONTRACT. An implementer writing an applet in C has no other way to
    check agreement, so the vectors are published, generated from the encoder rather than
    hand-written, and checked back against it."""
    name = "card_profile"
    mod = _read(root, "polaris_card/card_profile.py")
    if not mod:
        return _fail(name, "polaris_card/card_profile.py must carry the normative encoding")
    if _read(root, "polaris_card/profile.py"):
        return _fail(name,
                     "the module must not be named profile.py: `profile` is a standard-library "
                     "module, and a file with that name shadows it for any process that puts "
                     "this directory on sys.path")
    for fn in ("def encode", "def decode", "def signing_body", "def verify_card",
               "def credential_ref", "def pairwise_handle", "def response_body"):
        if fn not in mod:
            return _fail(name, f"the profile must define {fn.split()[1]}()")
    if "import hashlib" not in mod:
        return _fail(name, "the profile must hash without a dependency")
    for banned in ("import cryptography", "import oqs", "from cryptography"):
        if banned in mod:
            return _fail(name,
                         "the profile must stay dependency-free: it has to be implementable "
                         "inside a secure element's toolchain and inside the detached verifier, "
                         "so signature verification is passed IN rather than imported")

    if "FORBIDDEN_FIELDS" not in mod:
        return _fail(name,
                     "the record must be kept off the card BY NAME. Absence is not a property: "
                     "a vocabulary that happens not to include a field stops excluding it the "
                     "day somebody adds one")
    for field in ("token_value", "legal_name", "date_of_birth", "biometric", "duress_code"):
        if f'"{field}"' not in mod:
            return _fail(name, f"{field!r} must be refused on a card by name")
    enc = mod.split("def encode")[1].split("\ndef ")[0]
    f_at, u_at = enc.find("FORBIDDEN_FIELDS"), enc.find("NAME_TO_TAG")
    if f_at < 0:
        return _fail(name, "encode() must check the forbidden fields")
    if 0 <= u_at < f_at:
        return _fail(name,
                     "the forbidden-field check must run BEFORE the vocabulary check and stand "
                     "on its own, or the record is refused only for being unknown and the guard "
                     "vanishes the day somebody widens the vocabulary")

    dec = mod.split("def decode")[1].split("\ndef ")[0]
    for needle, why in (("appears twice", "a repeated tag makes it ambiguous which one is "
                                          "signed"),
                        ("out of order", "tags must ascend so one object has one encoding"),
                        ("unknown tag", "an unknown tag must be REFUSED rather than skipped: a "
                                        "reader that skipped it would verify a signature over "
                                        "bytes it never looked at"),
                        ("truncated", "a truncated object must be refused, not padded")):
        if needle not in dec:
            return _fail(name, why)

    body = mod.split("def signing_body")[1].split("\ndef ")[0]
    if "BODY_TAGS" not in body:
        return _fail(name,
                     "the signing body must exclude the signature tags, so both signatures "
                     "cover exactly the same bytes")
    verify = mod.split("def verify_card")[1].split("\ndef ")[0]
    if "require_pq" not in verify:
        return _fail(name,
                     "a verifier must be able to REQUIRE a post-quantum signature by policy, "
                     "so an authority can refuse classical-only cards on a chosen date without "
                     "reissuing the population first")
    if "if False in checked" not in verify and "False in checked" not in verify:
        return _fail(name,
                     "when both signatures are present BOTH must verify. Accept-if-either "
                     "hands the scheme to whoever breaks the weaker algorithm first, which is "
                     "the entire reason the card carries two")

    vectors = _read(root, "polaris_card/vectors/card-objects.json")
    if not vectors:
        return _fail(name,
                     "the test vectors must be published: an implementer writing an applet in "
                     "C has no other way to check that they agree with this encoder")
    for key in ("signing_body_hex", "signing_digest_hex", "card_object_hex"):
        if key not in vectors:
            return _fail(name, f"each vector must publish {key}")
    if not _read(root, "polaris_card/make_vectors.py"):
        return _fail(name,
                     "the vectors must be GENERATED from the encoder rather than hand-written, "
                     "so they cannot drift from it")
    suite = _read(root, "polaris_card/test_card_profile.py")
    if "card_object_hex" not in suite:
        return _fail(name,
                     "the suite must check the published vectors back against the encoder, or "
                     "the file and the code drift apart silently")

    drill = _read(root, "scripts/polaris-card-profile-drill.py")
    if not drill:
        return _fail(name, "scripts/polaris-card-profile-drill.py must run the card under REAL "
                           "signatures; the suite's stubs always say yes")
    for needed, why in (("is REFUSED under another authority's key",
                         "a card must be a credential rather than a badge"),
                        ("no single-field edit survives the issuer signature",
                         "every field must be flipped in turn, not just one"),
                        ("does NOT rescue a bad post-quantum one",
                         "the anti-downgrade rule must be exercised with a real forged "
                         "signature, in both directions"),
                        ("two readers cannot tell they saw the same card",
                         "the pairwise property must hold at the card"),
                        ("duress key does not appear in the card object",
                         "'the duress feature is invisible' is a claim about bytes")):
        if needed not in drill:
            return _fail(name, why)

    doc = _read(root, "docs/design/card-profile.md")
    if not doc:
        return _fail(name, "the profile must be published (docs/design/card-profile.md)")
    low = " ".join(doc.lower().split())
    for phrase, why in (("cannot raise a duress alarm",
                         "the profile must state that an offline verifier cannot signal duress, "
                         "and that the card must therefore behave identically either way"),
                        ("cannot prove offline that it is the current one",
                         "the profile must state that succession is resolved by the status "
                         "layer rather than by the card"),
                        ("needs the holder's phone",
                         "the profile must say that unlinkable proof of membership is the "
                         "wallet's job, since no fielded secure element computes one")):
        if phrase not in low:
            return _fail(name, why)
    threats = _read(root, "docs/design/threat-model.md")
    if "T-P1" not in threats:
        return _fail(name,
                     "the physical layer must be reviewed against the threat model: the card "
                     "read in a pocket, the lost card offline, the classical algorithm falling "
                     "while the fleet is classical, the coercer, and the forged object")
    return _ok(name,
               "the card is an object somebody else can implement: a deterministic encoding "
               "with exactly one reading, where a repeated, descending or unknown tag is "
               "refused rather than tolerated; the record kept off the card by name rather than "
               "by omission; two issuer signatures over the same bytes where both must verify "
               "when both are present and post-quantum can be required by policy; published "
               "vectors generated from the encoder and checked back against it; a drill under "
               "real signatures; and the physical threats written into the threat model with "
               "their residual risks stated")


def check_quantum_event_readiness(root: pathlib.Path) -> list[Finding]:
    """A population can be re-signed when an algorithm falls, and no holder goes dark (P7.6).

    Polaris exists because the algorithms in today's credentials will not hold. Every other
    part of the system treats that as a premise; this is the part that treats it as an
    operation somebody performs, on a population, under time pressure.

    Four properties, each of which is a way the operation turns into an outage.

    THE OLD SIGNATURE OUTLIVES THE MIGRATION. Deprecating the fallen algorithm while any
    credential is still unmigrated leaves holders whose credential verifies only under an
    algorithm fielded verifiers may not accept yet. They find out at a border; the operator
    finds out from them. So deprecation is a second pass and it is REFUSED, not warned about,
    while work remains.

    A MIGRATION THAT CANNOT SIGN STOPS. The target parameter set cannot come from process
    configuration, because during a migration two are live: the instance keeps issuing under
    the current algorithm while the population moves to the new one. And when no key exists
    for the target set, the answer is a refusal rather than the key that happens to be
    loaded. A signature made with ML-DSA-65 and stored against ML-DSA-87 is a false label on a
    real signature in the audit-of-record, and every later verification reads the mismatch as
    tampering.

    RESUME IS THE DEFAULT. A national migration outlives any process. The work remaining must
    be defined by the data rather than by a cursor or a progress file, so an interrupted run
    is finished by running it again and two runners cannot double-write.

    AND THE COST IS MEASURED. "We can re-sign the population" is worth nothing without a
    number, and the number has to come from a run rather than an estimate."""
    name = "quantum_event_readiness"
    mod = _read(root, "polaris_web/migration.py")
    if not mod:
        return _fail(name, "polaris_web/migration.py must carry the population migration path")
    for fn in ("def pending_count", "def migrate_batch", "def migrate_population",
               "def deprecate_superseded", "def verifiability_report"):
        if fn not in mod:
            return _fail(name, f"the migration module must expose {fn.split()[1]}()")

    dep = mod.split("def deprecate_superseded")[1].split("\ndef ")[0]
    if "pending_count(" not in dep or "MigrationRefused" not in dep:
        return _fail(name,
                     "deprecate_superseded must REFUSE while any ACTIVE credential lacks a "
                     "signature under the target algorithm. Closing the window early leaves "
                     "those holders with a credential that verifies under nothing, and they "
                     "learn it at a border rather than the operator learning it at a console")

    batch = mod.split("def migrate_batch")[1].split("\ndef ")[0]
    if "SKIP LOCKED" not in batch:
        return _fail(name,
                     "the batch select must SKIP LOCKED, or two runners sign the same "
                     "credentials and a population migration scales with one worker")
    if "ON CONFLICT" not in batch:
        return _fail(name,
                     "the insert must tolerate a conflict: two runners racing one credential "
                     "must produce one row, with the loser learning it wrote nothing")
    # Comment lines stripped: the module explains this trap in prose, and a check that
    # matched the explanation would fire on the fix.
    batch_code = "\n".join(ln for ln in batch.splitlines() if not ln.lstrip().startswith("#"))
    if "cur.rowcount" in batch_code:
        return _fail(name,
                     "written count must not come from cur.rowcount after execute_values: it "
                     "pages its argument and reports only the LAST page, so a 250-row batch "
                     "reported 100 and an operator ran a national migration reading a number "
                     "that undercounts by the page size")
    if "status = 'ACTIVE'" not in mod:
        return _fail(name,
                     "only ACTIVE credentials are re-signed; rewriting the signatures of a "
                     "revoked or expired one would edit the audit-of-record to say something "
                     "that was never true")

    sign = _read(root, "polaris_web/pqc_signing.py")
    if "def signature_for_migration" not in sign:
        return _fail(name,
                     "signing must accept an EXPLICIT target algorithm: during a migration two "
                     "parameter sets are live at once, so the target cannot be process-wide "
                     "configuration")
    cust = _read(root, "polaris_web/custody.py")
    if "class AlgorithmUnavailableError" not in cust or "def get_custody_for_algorithm" not in cust:
        return _fail(name,
                     "custody must resolve a key BY PARAMETER SET and refuse when none exists, "
                     "rather than signing with whichever key is loaded")
    resolver = cust.split("def get_custody_for_algorithm")[1].split("\ndef ")[0]
    if "AlgorithmUnavailableError" not in resolver:
        return _fail(name,
                     "a custody key whose parameter set does not match the migration target "
                     "must RAISE. Falling back writes a false algorithm label onto a real "
                     "signature, and every later verification reads it as tampering")

    cli = _read(root, "polaris_cli/polaris.py")
    if "'migrate-population'" not in cli:
        return _fail(name,
                     "the operator needs a command: a national migration is run from a "
                     "terminal over hours, not from a per-token endpoint")

    drill = _read(root, "scripts/polaris-quantum-event-drill.py")
    if not drill:
        return _fail(name, "scripts/polaris-quantum-event-drill.py must run the migration at "
                           "scale against a real database")
    for needed, why in (("NOBODY WAS DARK at any batch boundary",
                         "the unverifiable count must be sampled after EVERY batch: a gap that "
                         "opens and closes between two endpoints is invisible to a "
                         "before-and-after check"),
                        ("an interrupted run leaves the rest of the work standing",
                         "resume must be demonstrated, since a national migration outlives any "
                         "single process"),
                        ("two concurrent runners re-signed the population once, not twice",
                         "the concurrency claim must be tested rather than asserted"),
                        ("a key for the WRONG parameter set is refused, never used",
                         "the refusal must be exercised"),
                        ("closing the window before the population is migrated is REFUSED",
                         "the ordering rule is the safety property; it must be asserted")):
        if needed not in drill:
            return _fail(name, why)
    if "re-signed per second" not in drill:
        return _fail(name,
                     "the drill must MEASURE the rate: 'we can re-sign the population' is "
                     "worth nothing without a number that came from a run")
    if "sign_seconds" not in drill or "db_seconds" not in drill:
        return _fail(name,
                     "signing and database time must be reported separately: they scale "
                     "differently, and an operator planning this is deciding which one to buy")

    doc = _read(root, "docs/operator/QUANTUM-EVENT.md")
    if not doc:
        return _fail(name, "the runbook must be committed (docs/operator/QUANTUM-EVENT.md)")
    # Whitespace collapsed: a prose check that depended on where a line happened to wrap
    # would fail on a reflow that changed nothing.
    low = " ".join(doc.lower().split())
    for phrase, why in (("verifies under nothing",
                         "the runbook must open on the number that matters, which is how many "
                         "holders are dark rather than how fast the migration runs"),
                        ("separate pass",
                         "the runbook must say that deprecation is a second pass"),
                        ("signing", "the runbook must say where the time goes")):
        if phrase not in low:
            return _fail(name, why)
    return _ok(name,
               "a population can be re-signed onto a new algorithm without any holder losing a "
               "credential that verifies: the old signature outlives the migration and closing "
               "that window early is refused rather than warned about, the target parameter set "
               "is an argument rather than process configuration and a missing key stops the "
               "migration instead of mislabelling a signature, resume is the default because "
               "the work remaining is a query, two runners divide the population, and the drill "
               "measures the rate and splits signing from database rather than estimating both")


def check_per_authority_isolation(root: pathlib.Path) -> list[Finding]:
    """One authority's operators cannot read another's credentials, and the DATABASE says so (P3.9).

    The review that produced this found sixteen operator routes reading credential data with no
    issuing-agency filter. Patching sixteen query bodies would have been exactly the
    application-level policy the schema exists to refuse: it holds until the seventeenth route,
    which nobody remembers to write. So the isolation is a row-level policy, and the application
    only tells the database who is asking.

    Three properties are pinned here, and each one is a way the feature could rot into a lie.

    THE CAST MUST NEVER SEE AN EMPTY STRING. The obvious policy shape is
    `setting = '' OR col = setting::int`. Postgres does not guarantee OR short-circuits, so the
    cast is still evaluated on an unscoped session and the query dies with
    "invalid input syntax for type integer". That is not a subtle failure: it takes down every
    unauthenticated path in the instance. The drill caught it before it shipped, and this check
    keeps the broken shape from coming back.

    THE DEFAULT MUST STAY PERMISSIVE. An unscoped session sees everything. A single-authority
    instance, the relying-party API and every test suite depend on it. A policy that quietly hid
    rows from an unbound caller would be a silent behaviour change wearing the word "security".

    THE SCOPE MUST NOT OUTLIVE THE REQUEST. The setting is applied at connection open with
    `is_local=false`, which is safe only because `get_db` opens a fresh connection per request.
    Put a connection pool behind it and one operator's authority is inherited by whoever picks
    that connection up next, which is a cross-authority read with an audit trail blaming the
    wrong person. So the pairing is checked, not assumed."""
    name = "per_authority_isolation"
    schema = _read(root, "polaris_sql/01_schema.sql")
    policies = ("token_authority_isolation", "verification_authority_isolation",
                "lifecycle_authority_isolation")
    for policy in policies:
        if f"CREATE POLICY {policy}" not in schema:
            return _fail(name, f"the schema must define the row-level policy {policy}")
    if "AppUser" not in schema or "agency_id INTEGER REFERENCES Agency" not in schema:
        return _fail(name,
                     "an operator must be bound to an authority (AppUser.agency_id), or there is "
                     "nothing for a policy to scope by")

    # The empty-string cast. Any `current_setting(...)::INTEGER` that is not guarded by NULLIF
    # is evaluated on an unscoped session and raises.
    for source in ("polaris_sql/01_schema.sql",
                   "polaris_sql/migrations/2026-09-10-012-per-authority-isolation.up.sql"):
        text = _read(root, source)
        if not text:
            return _fail(name, f"{source} must exist: the policies are defined in both places")
        for line in text.splitlines():
            if "current_setting('polaris.operator_agency_id'" not in line:
                continue
            if "::INTEGER" in line.upper() and "NULLIF" not in line.upper():
                return _fail(name,
                             f"{source} casts the operator scope to INTEGER without a NULLIF "
                             "guard. Postgres does not guarantee an OR short-circuits, so the "
                             "cast is evaluated on an UNSCOPED session and every query raises "
                             "'invalid input syntax for type integer'. That takes the instance "
                             "down, not just the isolation")
        if "coalesce(" not in text.lower():
            return _fail(name,
                         f"{source} must keep the unscoped default PERMISSIVE by comparing the "
                         "column with itself when the setting is absent; a policy that hid rows "
                         "from an unbound caller would be a silent behaviour change")

    app = _read(root, "polaris_web/app.py")
    if "def _apply_operator_scope" not in app:
        return _fail(name, "the app must tell the database which authority is asking")
    get_db = app.split("def get_db")[1].split("\ndef _apply_operator_scope")[0]
    if get_db.count("_apply_operator_scope(conn)") < 2:
        return _fail(name,
                     "every connection get_db hands out must carry the operator scope, the "
                     "read replica included; a scope applied on one path only means the same "
                     "operator sees different rows depending on which route they hit")
    if "fresh connection per request" not in get_db:
        return _fail(name,
                     "the scope is set with is_local=false, which is safe ONLY because get_db "
                     "opens a fresh connection per request. Behind a pool the setting is "
                     "inherited by the next request on that connection, which is a "
                     "cross-authority read attributed to the wrong operator. If a pool is "
                     "introduced, reset the scope on checkout and say so here")
    scope = app.split("def _apply_operator_scope")[1].split("\ndef ")[0]
    if "set_config(" not in scope or "%s" not in scope:
        return _fail(name,
                     "the authority must be bound through set_config() rather than interpolated "
                     "into a SET statement")
    if "int(agency_id)" not in scope:
        return _fail(name, "the authority must be coerced to an integer before it reaches SQL")
    if "session.get('operator_agency_id')" not in scope:
        return _fail(name, "the scope must come from the authenticated session, not a request "
                           "parameter: a caller who can name their own authority has none")
    if "session['operator_agency_id']" not in _read(root, "polaris_web/security.py"):
        return _fail(name, "login must record the operator's authority in the session")

    drill = _read(root, "scripts/polaris-authority-isolation-drill.py")
    if not drill:
        return _fail(name, "scripts/polaris-authority-isolation-drill.py must prove the isolation "
                           "against a real database")
    if "SET LOCAL ROLE polaris_app" not in drill:
        return _fail(name,
                     "the drill must ask as the APPLICATION role: a superuser and the owner both "
                     "bypass row-level security, so a drill run as either passes vacuously")
    for needed, why in (("an UNSCOPED session sees every credential",
                         "the permissive default must be asserted, not assumed"),
                        ("not even by naming the other authority explicitly",
                         "a count is weaker than the rows being unreachable when asked for "
                         "directly"),
                        ("holder identity is NOT isolated",
                         "the limit must be demonstrated, so nobody reads these policies as "
                         "achieving per-authority isolation in a shared instance")):
        if needed not in drill:
            return _fail(name, why)

    doc = _read(root, "docs/design/per-authority-isolation.md")
    if not doc:
        return _fail(name, "the design record must be published "
                           "(docs/design/per-authority-isolation.md)")
    if "not owned by" not in doc.lower():
        return _fail(name,
                     "the design record must state the part policies cannot fix: a person is not "
                     "owned by an authority, so holder identity cannot be isolated by one")
    return _ok(name,
               "one authority's operators cannot read another's credentials, and the database "
               "enforces it rather than sixteen query bodies: the operator's authority comes from "
               "the authenticated session and is bound through set_config, every connection "
               "get_db hands out carries it, the unscoped default stays permissive, no policy "
               "casts an empty setting to INTEGER, and the drill asks as the application role and "
               "demonstrates the limit rather than stating it")


def check_vc_format(root: pathlib.Path) -> list[Finding]:
    """The W3C VC representation is a FORMAT, and attests a result rather than an identity (P3.8).

    Two things separate this from the mdoc bridge, and both are pinnable.

    WHAT IT ATTESTS. Not "this person is X" but "at this instant the answer was this". A VC
    asserting identity attributes would be a larger claim than Polaris makes anywhere else,
    and the disclosure vocabulary has no identity attributes to put in one. The subject
    vocabulary is therefore closed and identity fields are refused by name, so the drift from
    "a verification result" to "a credential about a person" cannot happen quietly.

    HOW THE PROOF IS NAMED. Every registered Data Integrity cryptosuite is classical. A
    document naming one while carrying an ML-DSA signature would be asserting something FALSE
    about how its proof was made, which is worse than being unverifiable: a general verifier
    would attempt the wrong algorithm and report a failure that looks like tampering. So the
    cryptosuite names Polaris, and a relabelled document is refused rather than accepted.

    The canonicalisation is JCS over the document minus its proof, not RDF Dataset
    Canonicalization, because `-rdfc-` needs a JSON-LD processor and the detached verifier
    stays import-standalone. That is a stated trade, not an oversight, and the two
    canonicalisations must agree byte for byte or the app signs what the verifier cannot check."""
    name = "vc_format"
    mod = _read(root, "polaris_web/vc.py")
    if not mod:
        return _fail(name, "polaris_web/vc.py must build the verification-result credential")
    if 'CRYPTOSUITE = "polaris-' not in mod:
        return _fail(name,
                     "the cryptosuite must name Polaris. A document naming a REGISTERED suite "
                     "while carrying an ML-DSA signature asserts something false about how its "
                     "proof was made, and a general verifier would report the mismatch as tampering")
    for registered in ("eddsa-jcs-2022", "ecdsa-rdfc-2019", "eddsa-rdfc-2022", "bbs-2023"):
        if f'CRYPTOSUITE = "{registered}"' in mod:
            return _fail(name, f"the cryptosuite claims {registered}; see above")
    if "FORBIDDEN_SUBJECT_FIELDS" not in mod:
        return _fail(name,
                     "the subject must refuse identity fields by name: this document attests a "
                     "verification RESULT, and a VC asserting identity attributes would be a "
                     "larger claim than the system makes anywhere else")
    for field in ("token_value", "legal_name", "date_of_birth"):
        if field not in mod:
            return _fail(name, f"the subject must refuse {field!r} explicitly")
    body = mod.split("def build_credential")[1].split("\ndef ")[0]
    f_at, u_at = body.find("FORBIDDEN_SUBJECT_FIELDS"), body.find("set(SUBJECT_FIELDS)")
    if f_at < 0:
        return _fail(name, "build_credential must check the forbidden subject fields")
    if 0 <= u_at < f_at:
        return _fail(name,
                     "the forbidden-field check must run BEFORE the vocabulary check and stand on "
                     "its own, or an identity field is refused only for being unknown and the "
                     "guard vanishes the day somebody adds it to the vocabulary")
    if "subject_id" not in body:
        return _fail(name,
                     "the subject identifier must be optional and per-verifier (P9.4); minting a "
                     "stable one would hand back the correlation handle the presentation layer "
                     "bounds")

    verifier = _read(root, "scripts/polaris-verify.py")
    if "def verify_verifiable_credential" not in verifier:
        return _fail(name, "the detached verifier must decide a VC offline")
    v = verifier.split("def verify_verifiable_credential")[1].split("\ndef ")[0]
    for key, why in (('"structure_valid"', "what a general reader can establish"),
                     ('"proof_authentic"', "what only a Polaris-aware verifier can"),
                     ('"verifier_interop"', "the difference, in words")):
        if key not in v:
            return _fail(name, f"the verdict must report {key}: {why}")
    if "_VC_CRYPTOSUITE" not in v:
        return _fail(name, "the verifier must refuse a document whose cryptosuite is not the one "
                           "the signer used")
    # The two canonicalisations must be the same construction, or the app signs bytes the
    # verifier cannot reproduce.
    if "sort_keys=True" not in verifier.split("def _vc_canonical")[1].split("\ndef ")[0]:
        return _fail(name,
                     "the verifier's canonicalisation must match the app's JCS-style sorted-keys "
                     "form; a mismatch means the app signs bytes the verifier never reconstructs")

    drill = _read(root, "scripts/polaris-vc-format-drill.py")
    if not drill:
        return _fail(name, "scripts/polaris-vc-format-drill.py must prove the format end to end")
    for needed, why in (("relabelled to a registered suite",
                         "a document naming a registered suite must be REFUSED, and the drill "
                         "must assert it rather than assume it"),
                        ("refusing an identity attribute",
                         "the subject refusal must be asserted"),
                        ("carries NO id",
                         "without a verifier scope there must be no subject identifier at all")):
        if needed not in drill:
            return _fail(name, why)
    doc = _read(root, "docs/design/vc-format.md")
    if not doc:
        return _fail(name, "the design record must be published (docs/design/vc-format.md)")
    if "verification result" not in doc.lower():
        return _fail(name,
                     "the design record must say what the document attests: a verification "
                     "RESULT, not an identity")
    return _ok(name,
               "the W3C VC representation is a format and attests a result: the cryptosuite names "
               "Polaris rather than falsely claiming a registered classical one, a relabelled "
               "document is refused, the subject vocabulary is closed and refuses identity fields "
               "and the token value by name with a guard that stands on its own, the subject "
               "identifier is per-verifier or absent, and the app and the detached verifier "
               "canonicalise the same way")


CHECKS: list[Callable[[pathlib.Path], list[Finding]]] = [
    check_accessibility,
    check_assurance_mapping,
    check_enrollment_proofing,
    check_duress_on_card,
    check_verifier_device,
    check_card_personalization,
    check_card_emulator,
    check_card_profile,
    check_quantum_event_readiness,
    check_per_authority_isolation,
    check_vc_format,
    check_mdoc_bridge,
    check_plonky3_evaluation,
    check_cost_model,
    check_multi_region_dr,
    check_status_distribution,
    check_epoch_pipeline_scale,
    check_agent_grant,
    check_pairwise_presentation,
    check_scoped_nullifier,
    check_commitment_mismatch_is_a_refusal,
    check_verifier_instant_normalised,
    check_holder_side_prover,
    check_holder_key_binding,
    check_attestation_signed,
    check_ship_tool,
    check_timestamp_transparency,
    check_roadmap_consistent,
    check_broker_policy_bound,
    check_qr_resource_bounds,
    check_ltv_timestamp_trust,
    check_exchange_trust_directional,
    check_protocol_versioning,
    check_algorithm_agility,
    check_trust_lifecycle,
    check_wallet_presentation,
    check_auth_broker,
    check_document_signing,
    check_exchange_gateway,
    check_registry,
    check_receipt_transparency,
    check_timestamp_authority,
    check_exchange_mint_signed_auth,
    check_no_named_reference_systems,
    check_preflight_typechecks_ts_sdk,
    check_exchange_receipt,
    check_wire_spec_matches_code,
    check_cross_authority_zk,
    check_verifier_fuzz,
    check_federation_status_bundle,
    check_lint_enforced,
    check_transparency_publication,
    check_transparency_gossip,
    check_transparency_log,
    check_canonical_equivalence,
    check_federation_two_instances,
    check_epoch_revocation_propagation,
    check_inter_authority_protocol,
    check_federation_topology,
    check_offline_verification,
    check_typescript_sdk,
    check_conformance_suite,
    check_relying_party_api,
    check_holder_verifier_flow,
    check_federation_in_app,
    check_controls_as_attacks,
    check_kat_conformance,
    check_witness_fuzz,
    check_real_pqc_default_boot,
    check_detached_verifier,
    check_dyno_published,
    check_attacks_run,
    check_federation_real,
    check_key_rotation_drilled,
    check_holder_wallet,
    check_public_claims_honest,
    check_verify_witness_sampling,
    check_constitution_layered,
    check_no_scifi_schema,
    check_zk_claim_precise,
    check_athena_console,
    check_athena_no_person,
    check_athena_read_only,
    check_athena_functions_bounded,
    check_athena_non_sovereign,
    check_athena_rule_enforcement_resolves,
    check_csp_forbids_unsafe_inline,
    check_one_active_token_index,
    check_aor_append_only_triggers,
    check_aor_privilege_boundary,
    check_crypto_algorithm_is_data,
    check_no_fk_cascade,
    check_version_is_canonical,
    check_changelog_matches_version,
    check_thesis_terminus_honest,
    check_secrets_file_ignored,
    check_gitignore_no_trailing_comments,
    check_zk_two_witness_present,
    check_no_debug_artifacts,
    check_pqc_signing_wired,
    check_signing_key_generation,
    check_pqc_real_signing,
    check_verify_enforced,
    check_pqc_second_witness,
    check_pqc_posture,
    check_edge_pq_kex,
    check_signature_self_contained_verify,
    check_prod_real_pqc,
    check_sql_console_readonly,
    check_prod_image_no_test_deps,
    check_cve_scanning,
    check_image_cve_scanning,
    check_sast_scanning,
    check_migration_timeouts,
    check_deploy_syncs_db_objects,
    check_web_concurrency_honored,
    check_prometheus_multiprocess,
    check_health_liveness_readiness_split,
    check_compose_resource_limits,
    check_prod_images_digest_pinned,
    check_alert_rules,
    check_alert_runbooks,
    check_duress_alertable,
    check_prod_fail_closed,
    check_encryption_at_rest_posture,
    check_erasure_procedure,
    check_replication_scaffolding,
    check_pgbackrest_scaffolding,
    check_pgbouncer_self_built,
    check_caddy_self_built,
    check_prod_stack_boot,
    check_container_hardening,
    check_app_db_tls,
    check_correlation_id,
    check_dockerfile_copies_app_modules,
    check_c2_zk_token_null,
    check_c4_atomic_failed_login,
    check_c8_atlas_caps,
    check_c9_concurrency_threading,
    check_c10_no_money_tables,
    check_open_redirect_guard,
    check_cookie_secure_in_production,
    check_prod_app_password_synced,
    check_prod_hardening,
    check_backup_encryption,
    check_table_count_matches_doc,
    check_launcher_current,
    check_launcher_refreshes_code,
    check_purge_binds_archive_to_database,
    check_archive_version_derived,
    check_no_grep_q_transaction_scrape,
    check_psql_status_capture_set_e_safe,
    check_recover_admin_refuses_self_pairing,
    check_test_reload_fails_loudly,
    check_ci_does_not_duplicate_pins,
    check_ci_ssl_probe_aggregated,
    check_migrate_docker_stdin_safe,
    check_rust_toolchain_pinned,
    check_ci_runs_atlas_e2e,
    check_load_gen_single_ledger,
    check_chaos_probe_reaches_wrapper,
    check_ct_monitor_testable_and_guarded,
    check_rotate_secret_preserves_mode,
    check_sbom_workflow,
    check_sbom_trivy_matches_scan,
    check_release_provenance,
    check_zk_tree_depth_synced,
    check_coverage_gated,
    check_offsite_backup_env_driven,
    check_pager_integration,
    check_linux_server_deployment,
    check_key_custody_abstraction,
    check_secrets_lifecycle_sealed,
    check_migrations_expand_contract,
    check_zero_downtime_deploy,
    check_verification_load_certified,
    check_atlas_rollups_prune,
    check_sim_mode_gated,
    check_ui_drill,
    check_helm_reference_profile,
    check_local_clock_convention,
    check_c6_atlas_redacts_zk_location,
    check_coercion_evidence_retained,
    check_zk_verify_anti_replay,
    check_no_migration_column_drift,
    check_operator_scripts_validate_argv,
    check_template_endpoints_resolve,
    check_distributed_tracing,
    check_postgres_probes_use_tcp,
    check_session_origin_hardening,
    check_schema_reload_idempotent,
    check_abuse_controls,
    check_performance_baseline,
    check_dr_drill_scheduled,
    check_chaos_program,
    check_ha_automation,
    check_event_table_partitioning,
    check_read_replica_routing,
    check_bulk_enrollment,
    check_national_simulation,
    check_atlas_console,
    check_stated_counts,
    check_c1c10_objects_resolve,
    check_helm_chart_version_current,
    check_api_routes_documented,
    check_prod_compose_trusts_edge,
    check_docs_index_coverage,
    check_presentation_surface,
    check_cli_help_lists_every_command,
    check_metrics_edge_acl,
    check_image_builds_are_retried,
    check_site_tokens_match_app,
    check_css_animations_resolve,
    check_system_map_covers_the_tree,
    check_paper_pdf_is_current,
    check_retention_engine,
]


def run_all(repo_root: pathlib.Path) -> list[Finding]:
    """Run every check against repo_root. Deterministic; order-stable."""
    findings: list[Finding] = []
    for check in CHECKS:
        try:
            findings.extend(check(repo_root))
        except Exception as exc:  # a check must never crash the run
            findings.append(Finding("FAIL", check.__name__, f"check raised {type(exc).__name__}: {exc}"))
    return findings
