#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris-ci-changes.py: which parts of CI a change can skip, decided from its paths.

2026-10-15. A pull request that touched only documentation ran every job CI has, about forty
minutes of it, although most of those jobs never open a document. This says which of them a
change may skip, and it is built so that the mistake it can make is running too much:

  - The skippable set is an ALLOWLIST. A path skips only if it matches an entry in ALLOWLIST,
    and an entry is there because the jobs that skip were measured not to read it (`--audit`,
    below, repeats that measurement on every run of the invariant checks). Anything else, a
    path nobody has looked at included, means "run everything".
  - Only a pull request is classified. A push, a manual run, a merge group (unused while
    this repository is user-owned) or any other event runs everything, whatever it touched.
  - An empty diff, a base that is not in the checkout, or a git that fails, runs everything.
    "I could not tell" and "nothing changed" must not look alike.

It writes three outputs for the workflow (GITHUB_OUTPUT), each "true" or "false":

  full    every job outside the always-run set: false only when every changed path is on the
          allowlist.
  oid4vp  the OID4VP mutation drill: true when the change touches what that drill reads (it
          copies packages/polaris-oid4vp and runs the package's suites in the copy, so its
          inputs are the package, the drill, the interpreter's requirements and the workflow).
  sdk     the SDK mutation drill: true when the change touches what the drill's own --changed
          mode looks at (_SDK_PATHS, read out of the drill so the two cannot disagree).

The required gate ("Polaris product test suite", scripts/polaris-ci-gate.py) reads these
outputs back: a job it needs counts as passed when it succeeded, or when it was skipped AND
the output that governs it says it was not needed. Nothing else passes.

    python3 scripts/polaris-ci-changes.py --event pull_request --base SHA --head SHA
    python3 scripts/polaris-ci-changes.py --audit       # re-measure the allowlist (no git diff)
    python3 scripts/polaris-ci-changes.py --measure     # the measurement behind the allowlist
"""
from __future__ import annotations

import argparse
import ast
import json
import importlib.util
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CI_YML = ".github/workflows/ci.yml"

#: The events whose paths are classified. Everything else runs everything.
#: Not a merge group either, though this repository has none (GitHub offers merge queues only
#: to organization-owned repositories). A push to main runs everything, and the audit is static
#: (a glob with no literal directory, or a path built from variables, is not seen), so a missed
#: read of an allowlisted path, skipped on the pull request, shows on main, after the merge.
CLASSIFIED_EVENTS = ("pull_request",)

#: What a change may touch and still skip every job outside the always-run set. A directory
#: entry ends in "/" and covers everything under it, including a file added there later; the
#: audit then holds the new file to the same measurement on the pull request that adds it. Each
#: entry was measured on 2026-10-15 (`--measure`): no file a skippable job executes names it, by
#: its path, by a directory above it, or by a join of path segments that reaches it.
#: Deliberately absent, because a skippable job reads them: lab/strategy/006/ (the Linux install
#: job runs issue_and_pack.py), and everything outside docs/, site/, lab/ and the prose files.
ALLOWLIST = (
    # The top-level prose files.
    "CHANGELOG.md",
    "CITATION.cff",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "MISSION.md",
    "README.md",
    "ROADMAP.md",
    "SECURITY.md",
    "TRADEMARKS.md",
    # GitHub's community files: read by GitHub's pages and forms, by no job.
    ".github/CODEOWNERS",
    ".github/DISCUSSION_TEMPLATE/",
    ".github/FUNDING.yml",
    ".github/ISSUE_TEMPLATE/",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/SUPPORT.md",
    # The project site, the formal-methods notes and the contributor notes.
    "site/",
    "meta/",
    "DEVNOTES/",
    # docs/, less what a skippable job reads: docs/design/substrate.md (test_app compares it with
    # the SystemDependency view, and test_app runs in the application-role and real-PQC jobs) and
    # docs/operator/DR-DRILLS.md (the DR drill's ledger, which polaris-dr-drill.sh writes). So
    # docs/design/ and docs/operator/ are listed file by file, and a new file there runs everything
    # until it is added.
    "docs/ARCHITECTURE-OVERVIEW.md",
    "docs/ASSURANCE-CASE.md",
    "docs/CONVENTIONS.md",
    "docs/DESIGN-INTENT-REVIEW.md",
    "docs/INTEGRATION.md",
    "docs/OPERATING-CONTRACT.md",
    "docs/PRODUCTION-READINESS.md",
    "docs/README.md",
    "docs/RED-TEAM-SCOPE.md",
    "docs/RELEASING.md",
    "docs/REVIEW-PACKET.md",
    "docs/SEED_DATA.md",
    "docs/STRANGER-PATH.md",
    "docs/THESIS.md",
    "docs/assets/",
    "docs/history/",
    "docs/paper/",
    "docs/reference/",
    "docs/design/README.md",
    "docs/design/abuse-controls.md",
    "docs/design/accessibility.md",
    "docs/design/algorithm-migration.md",
    "docs/design/anchoring.md",
    "docs/design/athena.md",
    "docs/design/atlas-scaling.md",
    "docs/design/audit-of-record.md",
    "docs/design/auth-broker.md",
    "docs/design/bulk-enrollment.md",
    "docs/design/capacity-model.md",
    "docs/design/card-profile.md",
    "docs/design/coexistence.md",
    "docs/design/concurrency.md",
    "docs/design/console-design.md",
    "docs/design/cross-authority-zk.md",
    "docs/design/document-signing.md",
    "docs/design/duress-codes.md",
    "docs/design/duress-on-card.md",
    "docs/design/epoch-cadence.md",
    "docs/design/exchange-gateway.md",
    "docs/design/exchange-receipt.md",
    "docs/design/federation-status-bundle.md",
    "docs/design/federation-topology.md",
    "docs/design/federation.md",
    "docs/design/holder-side-keys.md",
    "docs/design/identity-proofing.md",
    "docs/design/inter-authority-protocol.md",
    "docs/design/issuer-discretion.md",
    "docs/design/mdoc-bridge.md",
    "docs/design/multi-region.md",
    "docs/design/multi-sig-migration.md",
    "docs/design/observability.md",
    "docs/design/offline-verification.md",
    "docs/design/oid4vci-issuer.md",
    "docs/design/partitioning.md",
    "docs/design/per-authority-isolation.md",
    "docs/design/plonky2-to-plonky3.md",
    "docs/design/protocol-versioning.md",
    "docs/design/rasp-rules.md",
    "docs/design/rate-limiter.md",
    "docs/design/recovery-ceremony.md",
    "docs/design/registry.md",
    "docs/design/restore-reconciliation.md",
    "docs/design/retention.md",
    "docs/design/status-distribution.md",
    "docs/design/synchronous-replication.md",
    "docs/design/threat-model.md",
    "docs/design/tiered-enrollment.md",
    "docs/design/timestamp-authority.md",
    "docs/design/timestamp-transparency.md",
    "docs/design/token-signature.md",
    "docs/design/transparency-log.md",
    "docs/design/transparency-program.md",
    "docs/design/trust-lifecycle.md",
    "docs/design/trusted-referee.md",
    "docs/design/two-witness-principle.md",
    "docs/design/vc-format.md",
    "docs/design/verification-scaling.md",
    "docs/design/verifier-device.md",
    "docs/design/verifier-fuzz.md",
    "docs/design/wallet-protocol.md",
    "docs/design/webauthn.md",
    "docs/design/zk-snark.md",
    "docs/design/zk-soundness.md",
    "docs/operator/CHAOS-DRILLS.md",
    "docs/operator/CONFIG.md",
    "docs/operator/DEPLOYMENT.md",
    "docs/operator/DR.md",
    "docs/operator/ENCRYPTION-AT-REST.md",
    "docs/operator/EVALUATE.md",
    "docs/operator/FAILOVER.md",
    "docs/operator/HARDENING.md",
    "docs/operator/INSTALL.md",
    "docs/operator/KEY-CEREMONY.md",
    "docs/operator/KUBERNETES.md",
    "docs/operator/LINUX-SERVER.md",
    "docs/operator/OPERATIONS.md",
    "docs/operator/PILOT.md",
    "docs/operator/PRIVACY.md",
    "docs/operator/QUANTUM-EVENT.md",
    "docs/operator/README.md",
    "docs/operator/RUNBOOKS.md",
    "docs/operator/SECRETS.md",
    "docs/operator/SECURITY-CONTROLS.md",
    "docs/operator/SECURITY-STATE-DRILLS.md",
    "docs/operator/SLOS.md",
    "docs/operator/VERIFY-RELEASE.md",
    "docs/operator/WEBAUTHN-ROLLOUT.md",
    # lab/, one entry per directory or file, less lab/strategy/006/ (the Linux install job runs
    # its issue_and_pack.py). A new directory under lab/ runs everything until it is added.
    "lab/EXTERNAL-NOUNS.md",
    "lab/README.md",
    "lab/benchmark/",
    "lab/crypto-migration/",
    "lab/duress/",
    "lab/evaluation/",
    "lab/interop/",
    "lab/linkability/",
    "lab/strategy/001-token-status-list.md",
    "lab/strategy/002-relying-party-api-compartment.md",
    "lab/strategy/002/",
    "lab/strategy/003-signing-custody-compartment.md",
    "lab/strategy/003/",
    "lab/strategy/004-operator-identity-for-four-eyes.md",
    "lab/strategy/005-oid4vci-issuer.md",
    "lab/strategy/005/",
    "lab/strategy/006-verified-result-from-one-command.md",
    "lab/strategy/007-access-gate.md",
    "lab/strategy/007/",
    "lab/strategy/008-population-scale.md",
    "lab/strategy/008/",
    "lab/strategy/009-atlas-athena-rework.md",
    "lab/strategy/010-dev-tunnel.md",
    "lab/strategy/011-slsa-build-provenance.md",
    "lab/strategy/012-issuance-tunnel.md",
    "lab/strategy/013-public-chain-anchoring.md",
    "lab/strategy/013/",
    "lab/strategy/014-precession.md",
    "lab/strategy/014/",
    "lab/strategy/015-three-signature-standards.md",
    "lab/strategy/015/",
    "lab/strategy/016-batch-wallet-copies.md",
    "lab/strategy/016/",
    "lab/strategy/017-production-operability.md",
    "lab/strategy/018-negative-vectors.md",
    "lab/strategy/025-mdoc-dc-api.md",
    "lab/strategy/README.md",
    "lab/strategy/attack_status_list.py",
)

#: What the OID4VP mutation drill reads. It copies packages/polaris-oid4vp into a temporary
#: directory and runs the package's suites there with this interpreter, so nothing else in the
#: tree reaches it: the package, the drill, the requirements its job installs, and the workflow
#: that defines the job.
OID4VP_INPUTS = (
    "packages/polaris-oid4vp/",
    "scripts/polaris-oid4vp-mutation-drill.py",
    "polaris_web/requirements.txt",
    CI_YML,
)

#: The jobs that run on every change, skippable by nothing here. The invariant checks and their
#: detection tests, the sign-off and the two dependency scans are required checks; the
#: TypeScript SDK is required; the product boundary is required; and the product suite's core
#: part and its coverage shards run polaris_checks over the whole tree (measured: the checks
#: and their detection tests open every tracked file), so no path is unread by them.
ALWAYS_RUN_JOBS = (
    "changes", "test-core", "test-coverage-shard", "test-coverage", "test-procedures", "test",
    "product-boundary", "sdk-typescript", "invariants", "dco", "osv-scan", "cve-scan",
)

#: Code outside polaris_checks/ that only always-run jobs execute, so what it reads does not
#: bound the allowlist. `--audit` verifies each entry: ci.yml names it only inside an always-run
#: job, and no file a skippable job executes names it.
ALWAYS_RUN_ONLY = {
    "scripts/polaris-coverage.sh": "the coverage shards (always run)",
    "scripts/polaris-ship.py": "run by polaris-coverage.sh; locally the ship tool",
    "scripts/polaris-link-check.sh": "the product suite's core part (always run)",
    "scripts/polaris-review-packet-drill.py": "the product suite's core part",
    "scripts/polaris-assurance-mapping-drill.py": "the product suite's core part",
    "scripts/polaris-check-mutation-drill.py": "the product suite's core part",
    "scripts/polaris-coverage-mutation-drill.py": "the product suite's core part",
    "scripts/polaris-move-mutation-drill.py": "the product suite's core part",
    "scripts/polaris-constitution-mutation-drill.py": "the product suite's core part",
    "scripts/polaris-tla-drill.sh": "the product suite's core part",
    "scripts/polaris-tla-drill.py": "run by polaris-tla-drill.sh",
    "scripts/polaris-compose-parse.py": "the invariant checks job",
    "scripts/test_compose_parse.py": "the invariant checks job and the coverage shards",
    "scripts/test_operator_env.py": "the coverage shards",
    "scripts/test_ship_tool.py": "the coverage shards",
    "scripts/test_db_reference.py": "the coverage shards",
    "scripts/test_doctor.py": "the coverage shards",
    "scripts/test_ci_changes.py": "the coverage shards",
    "scripts/polaris-product-boundary-drill.py": "the product boundary job (always run)",
    "packages/polaris-oid4vp/examples/yivi-checkin/app.py": "the product boundary job",
    "packages/polaris-oid4vp/examples/yivi-checkin/test_checkin.py": "the product boundary job",
    "scripts/polaris-ci-changes.py": "the changes job and the invariant checks",
    "scripts/polaris-perf-baseline.sh": "the product suite's core part (the smoke re-run)",
    "scripts/polaris-release-notes.sh": "test_ship_tool under the coverage shards; the release workflow",
    "polaris_web/test_capacity.py": "the coverage shards",
    "scripts/test_coverage_script.py": "the coverage shards",
    "scripts/test_ci_gate.py": "the coverage shards",
}

#: Files no job of this workflow executes: local tools, configuration other services read, and
#: the drills other workflows run. `--audit` verifies each the same way.
NOT_RUN_IN_CI = {
    "wrangler.jsonc": "the site's Cloudflare deployment, read by Cloudflare, not by a job",
    "REUSE.toml": "licensing metadata, read by the REUSE tool and by polaris_checks",
    ".pre-commit-config.yaml": "the local hooks",
    "scripts/polaris-preflight.sh": "the local pre-push gate",
    "scripts/polaris-gen-api-clients.sh": "a contributor's generator; no job runs it",
    "scripts/polaris-pg-upgrade-drill.sh": "the pg-upgrade workflow, not this one",
    "scripts/polaris-throughput-measure.sh": "the throughput workflow, not this one",
    "scripts/polaris-chaos-drill.sh": "the chaos workflow, not this one",
}

#: What the audit reads as code. Templates and stylesheets are left out: they are rendered or
#: served, and cannot open a file in the repository. Text files count only as pip requirement
#: sets, the one kind of .txt a job feeds to a tool that follows paths (`-r`, `-c`).
_CODE_SUFFIXES = (".py", ".sh", ".bash", ".yml", ".yaml", ".js", ".mjs", ".cjs", ".ts", ".rs",
                  ".sql", ".toml", ".json", ".jsonc", ".cfg", ".ini", ".conf", ".in", ".tpl",
                  ".service", ".timer", ".env", ".example", ".xml", ".go", ".mod", ".kt",
                  ".java", ".gradle", ".tf")
_TOKEN = re.compile(r"[A-Za-z0-9_.\-/*]+")
#: A Python string with whitespace in it is prose (a message, an assertion's explanation) unless
#: it starts like a command line, which a job would hand to a shell.
_COMMANDS = ("python", "python3", "bash", "sh", "node", "npx", "npm", "cat", "ls", "cd", "cp",
             "mv", "git", "psql", "docker", "find", "tar", "rsync", "head", "tail", "grep", "sed",
             "awk", "pip", "uv", "source", "sudo", "env", "exec", "install", "diff", "cmp",
             "sha256sum", "shasum", "openssl", "curl", "wget", "jq", "yq", "make", "cargo")
#: Shell lines that only talk to the reader. A path in "see docs/operator/DR.md" is not read.
_SHELL_PROSE = re.compile(r"^\s*(echo|printf|say|log|info|warn|note|die|fail|err|ok|bad|skip|step|usage)\b")

#: Mentions the audit's rules count and a reading found to name nothing in the repository,
#: (file, token): why. A new mention anywhere else is still counted.
REVIEWED_MENTIONS = {
    ("polaris_web/rp_api.py", "docs/reference/WIRE-SPEC.md"):
        "a value in the published registry document, pointing a reader at the specification",
    ("scripts/polaris-registry-drill.py", "docs/reference/WIRE-SPEC.md"):
        "the same registry value, in the drill's expected document",
    ("polaris_cli/test_cli.py", "site"):
        "os.path.join(cls.tmp, \"site\"): a directory of that name inside the test's temporary directory",
}


def _under(path: str, specs) -> bool:
    """Is `path` one of `specs` or below a directory spec (git pathspec semantics)?"""
    for spec in specs:
        bare = spec.rstrip("/")
        if path == bare or path.startswith(bare + "/"):
            return True
    return False


def allowlisted(path: str) -> bool:
    return _under(path, ALLOWLIST)


def sdk_inputs(root: pathlib.Path = ROOT) -> tuple:
    """The SDK drill's own `_SDK_PATHS`, so `sdk` and the drill's --changed cannot disagree."""
    spec = importlib.util.spec_from_file_location(
        "polaris_sdk_drill", root / "scripts" / "polaris-sdk-mutation-drill.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    paths = tuple(mod._SDK_PATHS)
    if not paths:
        raise ValueError("the SDK drill names no paths")
    return paths + (CI_YML,)


def classify(event: str, changed, sdk_paths) -> dict:
    """{"full", "oid4vp", "sdk": bool, "reason": str}. `changed` is None when unknown."""
    everything = {"full": True, "oid4vp": True, "sdk": True}
    if event not in CLASSIFIED_EVENTS:
        return dict(everything, reason="a %s run is not classified: everything runs" % (event or "nameless"))
    if changed is None:
        return dict(everything, reason="the changed paths could not be read: everything runs")
    changed = [p for p in changed if p]
    if not changed:
        return dict(everything, reason="the diff names no path, which is not the same as no change: "
                                       "everything runs")
    outside = [p for p in changed if not allowlisted(p)]
    full = bool(outside)
    oid4vp = any(_under(p, OID4VP_INPUTS) for p in changed)
    sdk = any(_under(p, sdk_paths) for p in changed)
    if full:
        reason = "%d of %d changed path(s) are not on the allowlist (first: %s)" % (
            len(outside), len(changed), outside[0])
    else:
        reason = "all %d changed path(s) are on the allowlist" % len(changed)
    return {"full": full, "oid4vp": oid4vp and full, "sdk": sdk and full, "reason": reason}


def changed_paths(root: pathlib.Path, base: str, head: str):
    """Every path the diff base..head adds, deletes or modifies, or None when that is unknown.

    --no-renames: a rename is listed as a deletion of the old path and an addition of the new
    one. With rename detection on, a file moved OUT of a code directory into docs/ would be
    listed only under its new name, and the change would read as documentation."""
    if not re.fullmatch(r"[0-9a-f]{40}", base or "") or not re.fullmatch(r"[0-9a-f]{40}|HEAD", head or ""):
        return None
    for rev in (base, head):
        r = subprocess.run(["git", "rev-parse", "--verify", "--quiet", rev + "^{commit}"],
                           cwd=str(root), capture_output=True, text=True)
        if r.returncode != 0 or not r.stdout.strip():
            return None
    r = subprocess.run(["git", "diff", "--no-renames", "--name-only", "-z", base, head],
                       cwd=str(root), capture_output=True)
    if r.returncode != 0:
        return None
    return [p for p in r.stdout.decode("utf-8", "surrogateescape").split("\0") if p]


# ---------------------------------------------------------------------------------------------
# The audit: re-measure that no skippable job's code names an allowlisted path.
# ---------------------------------------------------------------------------------------------

_NOT_SOURCE = {".git", "node_modules", "__pycache__", "venv", ".venv", "target", ".hypothesis",
               ".pytest_cache", ".ruff_cache", "dist", "build"}


def _tracked(root: pathlib.Path) -> list:
    """The files of the tree: git's list in a checkout, and in an export (`git archive`, which
    carries no .git and nothing untracked) every file, less build and cache directories."""
    if (root / ".git").exists():
        r = subprocess.run(["git", "ls-files", "-z"], cwd=str(root), capture_output=True)
        if r.returncode != 0:
            raise RuntimeError("git ls-files failed: %s" % r.stderr.decode(errors="replace").strip())
        files = [p for p in r.stdout.decode("utf-8", "surrogateescape").split("\0") if p]
    else:
        files = []
        for base, dirs, names in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in _NOT_SOURCE)
            rel = os.path.relpath(base, root)
            files += [n if rel == "." else "%s/%s" % (rel, n) for n in sorted(names)]
    if not files:
        raise RuntimeError("no file was found under %s" % root)
    return files


def _is_code(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    if name.endswith(".txt"):
        return name.startswith(("requirements", "constraints"))
    if name.endswith(".json"):
        return name == "package.json" or name.startswith("tsconfig")
    return name.endswith(_CODE_SUFFIXES) or name.startswith(("Dockerfile", "Makefile", "Caddyfile"))


def _has_shebang(root: pathlib.Path, path: str) -> bool:
    try:
        with open(root / path, "rb") as fh:
            return fh.read(2) == b"#!"
    except OSError:
        return False


def skippable_code(files: list, root: pathlib.Path = ROOT) -> list:
    """The files a skippable job may execute or read as configuration: every code-like file,
    less the always-run-only and never-run ones, polaris_checks/ (the checks run only in
    always-run jobs), the other workflows, and the allowlisted paths themselves (the audit
    separately requires that no skippable code names one of those)."""
    out = []
    for p in files:
        if allowlisted(p) or p in ALWAYS_RUN_ONLY or p in NOT_RUN_IN_CI:
            continue
        if p.startswith("polaris_checks/"):
            continue
        if p.startswith(".github/") and p != CI_YML and not p.startswith(".github/ci/"):
            continue
        if _is_code(p) or _has_shebang(root, p):
            out.append(p)
    return out


def _path_like(text: str) -> bool:
    """Could a job use this string as a path or a command? Prose cannot: a sentence that names a
    document ("the rule is in docs/operator/DR.md") is a message, not a read."""
    t = text.strip()
    if not t:
        return False
    if not re.search(r"\s", t):
        return True
    return t.split()[0].rsplit("/", 1)[-1] in _COMMANDS


def _python_view(src: str):
    """The path tokens of a Python file, or None when it does not parse. A path token is
    (text, joined): each string that could be a path or a command, and each run of constant
    segments joined by `/`, os.path.join, joinpath or Path()."""
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return None
    docstrings = {id(n.value) for n in ast.walk(tree)
                  if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)}
    tokens = []

    def runs(parts):
        run = []
        for p in parts + [None]:
            if p is None:
                if run:
                    tokens.append(("/".join(run), True))
                run = []
            else:
                run.append(p.strip("/"))

    def chain(n):
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Div):
            return chain(n.left) + chain(n.right)
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            return [n.value]
        return [None]

    # Only the outermost `/` of a chain: ROOT / "docs" / "x.md" is one path, not also ROOT / "docs".
    inner = {id(n.left) for n in ast.walk(tree) if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Div)}
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            if id(node) not in inner:
                runs(chain(node))
        elif isinstance(node, ast.Call):
            fn = node.func
            if (getattr(fn, "attr", None) or getattr(fn, "id", None)) in ("join", "joinpath", "Path", "PurePath"):
                runs([a.value if isinstance(a, ast.Constant) and isinstance(a.value, str) else None
                      for a in node.args])
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            if _path_like(node.value):
                for tok in _TOKEN.findall(node.value):
                    tokens.append((tok, False))
    return tokens


def _sql_lines(src: str):
    """The lines of SQL that can read a file: psql's include and copy meta-commands, COPY ...
    FROM a file, and pg_read_file. Everything else in a schema is statements and prose."""
    for line in src.splitlines():
        code = line.split("--", 1)[0]
        if re.match(r"^\s*\\(i|ir|include|include_relative|copy)\b", code) \
                or re.search(r"(?i)\bCOPY\b.*\bFROM\s+'", code) or re.search(r"(?i)pg_read_(binary_)?file", code):
            yield code


def _shell_lines(src: str):
    """A shell-like file's lines as they execute: comments dropped (a whole-line #, a trailing
    ` # ...`), a line that only talks to the reader (echo, printf and the scripts' own
    say/warn/die helpers) dropped with any continuation of it, and every quoted string with
    whitespace in it dropped, since "see docs/operator/DR.md" is a message."""
    prose, heredoc = False, None
    for line in src.splitlines():
        if heredoc is not None:
            if line.strip() == heredoc:
                heredoc = None
            continue
        m = re.match(r"^\s*cat(\s+>&2)?\s+<<-?\s*['\"]?(\w+)['\"]?\s*$", line)
        if m:
            # A statement `cat <<EOF` prints a usage text or a closing report to the person who
            # ran the script. `cat > file <<EOF` writes a file a job may read, and
            # `X=$(cat <<SQL` feeds a program: neither matches, and both are read as code.
            heredoc = m.group(2)
            continue
        cont = line.rstrip().endswith("\\")
        s = line.strip()
        if prose or s.startswith("#") or _SHELL_PROSE.match(re.sub(r"^\s*(-\s+)?(run:\s*)?", "", line)):
            prose = cont
            continue
        prose = False
        line = re.split(r"\s#\s", line, 1)[0]
        line = re.sub(r'"[^"]*\s[^"]*"', '""', line)
        line = re.sub(r"'[^']*\s[^']*'", "''", line)
        yield line


def _other_lines(src: str, unit: bool = False):
    """Any other file's lines, less whole-line comments (#, //, --, /* and * leaders). In a
    systemd unit, `Documentation=` is shown to a person by `systemctl status` and opened by
    nothing."""
    for line in src.splitlines():
        s = line.strip()
        if s.startswith(("#", "//", "--", "/*", "*")) or (unit and s.startswith("Documentation=")):
            continue
        yield line


def _json_view(src: str):
    """Every string in a JSON configuration (package.json, tsconfig) that could be a path."""
    try:
        doc = json.loads(re.sub(r"(?m)^\s*//.*$", "", src))
    except ValueError:
        return None
    out, stack = [], [doc]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            if _path_like(v):
                out.append(v)
        elif isinstance(v, dict):
            stack.extend(v.keys())
            stack.extend(v.values())
        elif isinstance(v, list):
            stack.extend(v)
    return out


def code_view(path: str, src: str):
    """The path tokens [(text, joined)] of one file, as the audit reads it."""
    if path.endswith(".py"):
        view = _python_view(src)
        if view is not None:
            return view
    if path.endswith((".json", ".jsonc")):
        strings = _json_view(src)
        if strings is not None:
            return [(t, False) for s in strings for t in _TOKEN.findall(s)]
    name = path.rsplit("/", 1)[-1]
    if path.endswith(".sql"):
        lines = _sql_lines(src)
    elif path.endswith((".sh", ".bash", ".yml", ".yaml", ".tpl")) or name.startswith(("Dockerfile", "Makefile")) \
            or path == CI_YML:
        lines = _shell_lines(src)
    else:
        lines = _other_lines(src, unit=path.endswith((".service", ".timer")))
    return [(t, False) for line in lines for t in _TOKEN.findall(line)]


#: Config files read their paths from their own directory (pyproject's `readme`, Cargo's).
_CONFIG_SUFFIXES = (".toml", ".cfg", ".ini", ".in", ".txt", ".json", ".jsonc")


def references(root: pathlib.Path, code: list, candidates: list, texts=None, exact=False) -> dict:
    """{candidate path: [where it is named]} over the skippable code.

    A candidate is named when a path token of a file (see code_view) is its path, or a
    directory above it, read from the repository root or from the naming file's own
    directory; or when a join of constant segments reaches it or a directory above it, a bare
    top-level directory included (ROOT / "docs" / name). A bare word ("site", "lab") outside a
    join names nothing: every such word in the code was read by hand on 2026-10-15 and each is
    prose. Globs with no literal directory, and paths assembled only from variables, are not
    seen; REVIEWED_MENTIONS records the reads of that kind found by hand. With `exact`, only a
    candidate's own path counts (whether a job runs a given script, not whether it reads a
    directory that holds it)."""
    cset = set(candidates)
    below = {}
    for c in candidates:
        p = c
        while "/" in p:
            p = p.rsplit("/", 1)[0]
            below.setdefault(p, set()).add(c)
    found = {}
    for path in code:
        if texts is not None and path in texts:
            src = texts[path]
        else:
            try:
                src = (root / path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
        here = os.path.dirname(path)
        bases = (here,) if path.endswith(_CONFIG_SUFFIXES) else (("", here) if here else ("",))
        tokens = code_view(path, src)
        for token, joined in tokens:
            t = token.strip("()[]{}'\"`").rstrip(".,;:")
            if not t or t in (".", "..") or (path, t) in REVIEWED_MENTIONS:
                continue
            # "$ROOT/docs/x.md" reaches the tokenizer as "ROOT/docs/x.md", and "/opt/app/x" may be
            # a copy of the tree: every tail after a slash is read as a path too.
            parts = t.split("/")
            tails = [t] + ["/".join(parts[k:]) for k in range(1, len(parts)) if parts[k]]
            # A run of ".." alone climbs to the repository root ($(dirname "$0")/../..); it names
            # where the script stands, not a file it reads, and what it reads there is a token
            # of its own.
            tails = [x for x in tails if not re.fullmatch(r"[./]*", x)]
            for base, tail in ((b, x) for b in bases for x in tails):
                rel = os.path.normpath(os.path.join(base, tail))
                if rel == ".." or rel.startswith("../"):
                    continue
                if "*" in rel:
                    rel = rel.split("*", 1)[0].rstrip("/")
                    if rel not in below:
                        continue
                names = {rel} & cset
                if rel in below and ("/" in rel or (joined and tail == t)) and not exact:
                    names |= below[rel]
                for n in names:
                    found.setdefault(n, set()).add(path)
    return {k: sorted(v) for k, v in found.items()}


def _ci_job_blocks(text: str) -> dict:
    jobs, cur, inside = {}, None, False
    for line in text.splitlines():
        if re.match(r"^jobs:\s*$", line):
            inside = True
            continue
        if not inside:
            continue
        if line and not line.startswith((" ", "#")):
            break
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            cur = m.group(1)
            jobs[cur] = []
        elif cur is not None:
            jobs[cur].append(line)
    return {k: "\n".join(v) for k, v in jobs.items()}


def _skippable_ci_text(root: pathlib.Path, strict: bool = True) -> str:
    """ci.yml as the skippable jobs run it: their blocks only. The always-run jobs may read
    anything, and the trigger section's paths-ignore names files without reading them."""
    path = root / CI_YML
    if not path.is_file():
        raise RuntimeError("%s is missing" % CI_YML)
    jobs = _ci_job_blocks(path.read_text(encoding="utf-8"))
    if not jobs:
        raise RuntimeError("%s has no jobs this audit can read" % CI_YML)
    missing = [j for j in ALWAYS_RUN_JOBS if j not in jobs]
    if missing and strict:
        raise RuntimeError("the always-run job(s) %s are not in %s" % (", ".join(missing), CI_YML))
    if strict:
        governed = [j for j in ALWAYS_RUN_JOBS if j in jobs
                    and re.search(r"(?m)^    if:.*needs\.changes\.outputs", jobs[j])]
        if governed:
            # An always-run job is left out of the measurement below; one that can be skipped
            # would leave its reads unmeasured.
            raise RuntimeError("the always-run job(s) %s are skipped by the changes outputs"
                               % ", ".join(governed))
    return "\n".join(b for j, b in jobs.items() if j not in ALWAYS_RUN_JOBS)


def audit(root: pathlib.Path = ROOT, out=sys.stdout) -> list:
    """Problems with the allowlist as the tree stands; [] when it holds."""
    problems = []
    files = _tracked(root)
    fset = set(files)
    candidates = [p for p in files if allowlisted(p)]
    if not candidates:
        problems.append("no tracked file is on the allowlist, so the measurement covers nothing")
    for entry in ALLOWLIST:
        if not any(_under(p, (entry,)) for p in files):
            problems.append("the allowlist entry %s matches no tracked file" % entry)
    for entry in OID4VP_INPUTS:
        if allowlisted(entry):
            problems.append("%s is both an OID4VP drill input and on the allowlist" % entry)
    code = skippable_code(files, root)
    if not code:
        problems.append("no skippable code was found to measure")
    texts = {CI_YML: _skippable_ci_text(root)}
    for path, where in sorted(references(root, code, candidates, texts).items()):
        problems.append("%s is on the allowlist but %s names it" % (path, ", ".join(where[:3])))
    # Declared always-run-only (or never-run) code: nothing a skippable job runs may name it,
    # by its path (the same reading as above) or by importing it from beside it.
    declared = [p for p in list(ALWAYS_RUN_ONLY) + list(NOT_RUN_IN_CI)]
    for path in declared:
        if path not in fset:
            problems.append("%s is declared always-run-only or not run, but is not tracked" % path)
    for (path, _token) in REVIEWED_MENTIONS:
        if path not in fset:
            problems.append("REVIEWED_MENTIONS names %s, which is not tracked" % path)
    for path, where in sorted(references(root, code, [p for p in declared if p in fset], texts,
                                         exact=True).items()):
        problems.append("%s is declared always-run-only or not run, but %s names it"
                        % (path, ", ".join(where[:3])))
    modules = {}
    for p in declared:
        if p.endswith(".py"):
            modules.setdefault((os.path.dirname(p), p.rsplit("/", 1)[-1][:-3]), p)
    for path in code:
        if not path.endswith(".py"):
            continue
        try:
            tree = ast.parse((root / path).read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError, ValueError):
            continue
        here = os.path.dirname(path)
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                names = [node.module.split(".")[0]]
            for name in names:
                if (here, name) in modules:
                    problems.append("%s is declared always-run-only or not run, but %s imports it"
                                    % (modules[(here, name)], path))
    print("audit: %d allowlisted file(s) under %d entr(ies), against %d file(s) of skippable code: %s"
          % (len(candidates), len(ALLOWLIST), len(code), "%d problem(s)" % len(problems) if problems else "clean"),
          file=out)
    return problems


def measure(root: pathlib.Path = ROOT, out=sys.stdout) -> int:
    """The measurement the allowlist was built from: which files under docs/, site/, lab/,
    DEVNOTES/ and meta/, and which top-level prose files, the skippable code names."""
    files = _tracked(root)
    pool = [p for p in files if p.startswith(("docs/", "site/", "lab/", "DEVNOTES/", "meta/"))
            or ("/" not in p and p.endswith((".md", ".cff"))) or allowlisted(p)]
    code = [p for p in files if p not in pool and p not in ALWAYS_RUN_ONLY and p not in NOT_RUN_IN_CI
            and not p.startswith("polaris_checks/") and (_is_code(p) or _has_shebang(root, p))
            and (not p.startswith(".github/") or p == CI_YML or p.startswith(".github/ci/"))]
    refs = references(root, code, pool, {CI_YML: _skippable_ci_text(root, strict=False)})
    for p in sorted(refs):
        print("named  %s  <- %s" % (p, ", ".join(refs[p][:4])), file=out)
    print("%d of %d file(s) under docs/, site/, lab/, DEVNOTES/, meta/ and the top-level prose are "
          "named by skippable code" % (len(refs), len(pool)), file=out)
    return 0


def _write_outputs(path: str, result: dict) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        for key in ("full", "oid4vp", "sdk"):
            fh.write("%s=%s\n" % (key, "true" if result[key] else "false"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--event", default=os.environ.get("GITHUB_EVENT_NAME", ""))
    ap.add_argument("--base", default="")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--output", default=os.environ.get("GITHUB_OUTPUT", ""),
                    help="append full=, oid4vp=, sdk= here (default: $GITHUB_OUTPUT)")
    ap.add_argument("--audit", action="store_true", help="re-measure the allowlist and exit")
    ap.add_argument("--measure", action="store_true", help="print the measurement and exit")
    args = ap.parse_args(argv)

    if args.audit:
        try:
            problems = audit(ROOT)
        except Exception as exc:  # noqa: BLE001  a measurement that cannot run is a failure
            print("audit: could not measure: %s" % exc, file=sys.stderr)
            return 1
        for p in problems:
            print("  " + p, file=sys.stderr)
        return 1 if problems else 0
    if args.measure:
        return measure(ROOT)

    try:
        sdk_paths = sdk_inputs(ROOT)
    except Exception as exc:  # noqa: BLE001  without the drill's paths, everything runs
        print("changes: the SDK drill's paths could not be read (%s)" % exc, file=sys.stderr)
        sdk_paths = None
    changed = None
    if args.event in CLASSIFIED_EVENTS:
        changed = changed_paths(ROOT, args.base.strip(), args.head.strip())
    result = classify(args.event, changed, sdk_paths or ())
    if sdk_paths is None:
        result.update(full=True, oid4vp=True, sdk=True,
                      reason=result["reason"] + "; the SDK drill's paths are unknown, so everything runs")
    print("changes: %s" % result["reason"])
    if changed:
        for p in changed[:40]:
            print("  %s %s" % ("allowlisted" if allowlisted(p) else "runs      ", p))
        if len(changed) > 40:
            print("  ... and %d more" % (len(changed) - 40))
    print("changes: full=%s oid4vp=%s sdk=%s" % tuple(
        "true" if result[k] else "false" for k in ("full", "oid4vp", "sdk")))
    if args.output:
        try:
            _write_outputs(args.output, result)
        except OSError as exc:
            print("changes: could not write the outputs: %s" % exc, file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
