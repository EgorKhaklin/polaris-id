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
def check_aor_append_only_triggers(root: pathlib.Path) -> list[Finding]:
    triggers = _read(root, "polaris_sql/06_triggers.sql")
    if "insufficient_privilege" not in triggers:
        return _fail("c1_aor", "06_triggers.sql must raise insufficient_privilege on AoR UPDATE/DELETE (C1)")
    n = len(re.findall(r"BEFORE\s+UPDATE\s+OR\s+DELETE", triggers, re.I))
    if n < 1:
        return _fail("c1_aor", "no BEFORE UPDATE OR DELETE append-only triggers found (C1)")
    return _ok("c1_aor", f"{n} append-only audit-of-record trigger(s) present (C1)")


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
# MISSION.md's abandonment clause is mechanical: "if no cold-read attempt occurs
# by v9.40 ... the thesis is documented as inconclusive and the strong claim is
# retired permanently." No external cold read occurred and the repo is past v9.40,
# so docs/THESIS.md must reflect that terminal state — not leave the thesis framed
# as an open, still-pending hypothesis. Leaving the softer wording past the
# deadline is itself the dishonesty the project's discipline forbids. This check
# enforces the constitution's own rule against drift back to the open framing.
# (It does NOT touch MISSION.md's freeze line, which is un-amendable here.)
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
    return _ok("presentation_surface", "community files present, security routing set, policies stamped current")


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
                    ".pre-commit-config.yaml", ".github", ".claude"}


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
    for bad in _OVERCLAIM_PHRASES:
        if bad in readme:
            return _fail("public_claims",
                         f"the README carries the overclaim {bad!r}; shrink the claim to what the code does now "
                         "(the hardware token is modeled; this is a reference implementation)")
    if "Deployed to a real population" not in readme:
        return _fail("public_claims",
                     "the 'Where Polaris sits' comparison must keep the 'Deployed to a real population' column so "
                     "Polaris's design ticks are not read as a deployment")
    return _ok("public_claims",
               "the outward surfaces name Polaris a reference implementation (title + social card), carry no "
               "retired overclaim, and the comparison marks Polaris the one system not deployed")


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


CHECKS: list[Callable[[pathlib.Path], list[Finding]]] = [
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
