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

It writes four outputs for the workflow (GITHUB_OUTPUT), each "true" or "false":

  full         every job outside the always-run and site-skipped sets: false only when every
               changed path is on the allowlist.
  oid4vp       the OID4VP mutation drill: true when the change touches what that drill reads (it
               copies packages/polaris-oid4vp and runs the package's suites in the copy, so its
               inputs are the package, the drill, the interpreter's requirements and the workflow).
  sdk          the SDK mutation drill: true when the change touches what the drill's own --changed
               mode looks at (_SDK_PATHS, read out of the drill so the two cannot disagree).
  beyond_site  the jobs only a change to the project site may skip (SITE_SKIPPED_JOBS), 2026-11-17:
               false only when every changed path is site-only (site_only(): a file the
               site serves, or one of the two a site change carries), which implies full=false. The same fail-closed rules: anything unknown says true.

The required gate ("Polaris product test suite", scripts/polaris-ci-gate.py) reads these
outputs back: a job it needs counts as passed when it succeeded, or when it was skipped AND
the output that governs it says it was not needed. Nothing else passes.

    python3 scripts/polaris-ci-changes.py --event pull_request --base SHA --head SHA
    python3 scripts/polaris-ci-changes.py --audit       # re-measure both lists (no git diff)
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

#: What a change may touch and still skip every job outside the always-run and site-skipped sets
#: (a site-skipped job runs on any change that is not site-only: SITE_SKIPPED_JOBS). A directory
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

#: The jobs that run on every change, skippable by nothing here: the classifier itself, the gates
#: (a gate runs `if: always()`), the invariant checks job, the sign-off, the OSV scan and the
#: product boundary, which are required checks (check_oid4vp_image also holds the image drill the
#: product boundary runs to every run, its job carrying no `if:`), and the package's 3.9 job, which
#: installs from lab/interop/requirements.txt. The invariant checks job runs polaris_checks and its
#: detection tests over the whole tree (measured: they open every tracked file) and the link check,
#: so no path is unread on any change. The coverage gate's floor steps after its gate step are
#: skipped with its shards on a site-only change; the site measurement reads them as site-skipped.
ALWAYS_RUN_JOBS = (
    "changes", "test-coverage", "test-procedures", "test", "invariants", "dco", "osv-scan",
    "product-boundary", "test-oid4vp-py39",
)

#: The jobs every change outside the site-only class runs (2026-11-17), whatever the allowlist says,
#: and only `beyond_site` may skip: the product suite's core part and its coverage shards run
#: polaris_checks over the whole tree, which the invariant checks job also does on every change;
#: the TypeScript SDK and the dependency CVE scan are required checks that read sdk/ and the
#: requirement sets; the mdoc drill reads lab/interop/, which is on the allowlist. The required
#: gate needs each, and passes its skip only on beyond_site=false.
SITE_SKIPPED_JOBS = (
    "test-core", "test-coverage-shard", "sdk-typescript", "cve-scan", "test-mdoc-drill",
)

#: The site-only class (2026-11-17): a change whose every path is one of the two files a site
#: change carries (SITE_SHIP_FILES), or under site/ and of a type the
#: site serves (SITE_ONLY_TYPES, or a host rule or key-directory file), less site/polaris_logo.webp,
#: the default emblem the Yivi check-in example serves, and any file whose name says it is a
#: dependency manifest or lockfile, which the dependency scans read. Any other file under site/
#: runs everything: code (the product suite's
#: core part lints every Python file in the tree, a walk of the whole tree this audit cannot tie to
#: a path), configuration, or a type not listed. `--audit` measures the rest as it measures the
#: allowlist: no code a site-skipped job may run names a site-only path, polaris_checks/ aside,
#: which the invariant checks job runs on every change (SITE_ONLY_RESTS_ON).
SITE_ONLY_DIR = "site/"
SITE_NOT_ONLY = ("site/polaris_logo.webp",)
#: What a site change carries beside its pages (2026-11-17): its changelog line, and the manifest
#: its sentences are held to. Without them the class missed the site changes actually sent: each
#: carried a changelog line. Measured like the rest: no code a site-skipped job may run opens the
#: tree's copy of either (SITE_REVIEWED_MENTIONS records each mention read by hand); the checks,
#: which read both, run in the invariant checks job on every change.
SITE_SHIP_FILES = ("CHANGELOG.md", "docs/reference/claims.json")
#: The types the site serves: pages, styles, images, fonts, text, Markdown and JSON. Besides
#: these, a name with no dot is site-only when it is one of the host's rule files (SITE_RULE_FILES)
#: or sits under site/.well-known/ (the OpenPGP key directory's files). A name ending otherwise, or
#: one with a leading dot, is not site-only, whatever it holds.
SITE_ONLY_TYPES = (".html", ".css", ".avif", ".webp", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                   ".woff2", ".woff", ".txt", ".md", ".json")
SITE_KEYS_DIR = "site/.well-known/"
SITE_RULE_FILES = ("_headers", "_redirects")
#: Dependency manifests and lockfiles by file name, the ones OSV-Scanner and Dependabot read for
#: the ecosystems this tree uses or could add: never site-only, under site/ or anywhere else.
_DEPENDENCY_FILE = re.compile(
    r"(?i)^(?:requirements[\w.-]*\.(?:txt|in)|constraints[\w.-]*\.txt|[\w.-]*\.lockb?|package(?:-lock)?\.json|"
    r"npm-shrinkwrap\.json|pnpm-lock\.ya?ml|pnpm-workspace\.ya?ml|go\.(?:mod|sum)|pyproject\.toml|Pipfile|"
    r"Gemfile|Cargo\.toml|composer\.json|pom\.xml|[\w.-]*\.gradle(?:\.kts)?|gradle\.lockfile|pubspec\.ya?ml|"
    r"deno\.jsonc?|[\w.-]*\.csproj|packages\.config|mix\.exs|setup\.(?:py|cfg))$")
#: And any name that says it is one, however it is spelled (dev-requirements.txt,
#: test_constraints.txt, packages.lock.json): the class errs toward running everything.
_DEPENDENCY_WORD = re.compile(r"(?i)requirement|constraint|shrinkwrap|(?:^|[._-])lock(?:b|file|ed)?(?:[._-]|$)")

#: What the site-only class rests on: the jobs a site-only change still runs, and the steps each
#: must hold, since the jobs it skips ran them too (2026-11-17: the product suite's core part ran
#: the checks and the link check; the coverage shards ran the detection tests). Each step is pinned
#: whole, as check_oid4vp_image pins the image drill: its first line is `- name:` and nothing else,
#: and its other lines, comments and blank lines aside, are exactly these, so no `if:`, `shell:`,
#: `env:`, `|| true`, folded line or extra flag fits. What they run in is held too: the job carries
#: no `if:`, `continue-on-error:`, `defaults:` or `env:`, no line of it names $GITHUB_ENV or
#: $GITHUB_PATH, and the workflow's own `env:` is WORKFLOW_ENV exactly, with no `defaults:`. A
#: change to one of these changes its pin with it.
SITE_ONLY_RESTS_ON = {
    "invariants": (
        ("        run: python3 -m polaris_checks.run",),
        ("        run: |",
         "          pip install --require-hashes -r polaris_web/requirements-test.txt",
         "          python3 -m pytest polaris_checks/test_checks.py -q -p no:cacheprovider"),
        ("        run: bash scripts/polaris-link-check.sh --ci",),
    ),
}
#: The workflow's top-level `env:`, its lines as written (comments and blank lines aside).
WORKFLOW_ENV = ('  PYTHONUNBUFFERED: "1"',)


def _pinned(step: str) -> tuple:
    """A step as SITE_ONLY_RESTS_ON pins it: the lines after its `- name:` line, comments and
    blank lines dropped; () when its first line is not a `- name:` line alone."""
    lines = step.splitlines()
    if not lines or not re.fullmatch(r"      - name:[ \t]*\S.*", lines[0]):
        return ()
    return tuple(l.rstrip() for l in lines[1:] if l.strip() and not l.lstrip().startswith("#"))

#: Code outside polaris_checks/ that only always-run and site-skipped jobs execute, so what it
#: reads does not bound the allowlist (the site measurement reads it: site_skipped_code). `--audit`
#: verifies each entry: no file a skippable job executes names it.
ALWAYS_RUN_ONLY = {
    "scripts/polaris-coverage.sh": "the coverage shards (site-skipped)",
    "scripts/polaris-ship.py": "run by polaris-coverage.sh; locally the ship tool",
    "scripts/polaris-link-check.sh": "the invariant checks job (always run)",
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
    "scripts/polaris-mdoc-mutation-drill.py": "the mdoc drill job (site-skipped)",
    "scripts/test_mdoc_drill.py": "the coverage shards",
    "packages/polaris-oid4vp/examples/yivi-checkin/app.py": "the product boundary job",
    "packages/polaris-oid4vp/examples/yivi-checkin/test_checkin.py": "the product boundary job",
    "packages/polaris-negative-vectors/stage.py": "the product boundary job (always run), through test_package.py",
    "packages/polaris-negative-vectors/test_package.py": "the product boundary job (always run)",
    "scripts/polaris-ci-changes.py": "the changes job and the invariant checks",
    "scripts/polaris-perf-baseline.sh": "the product suite's core part (the smoke re-run)",
    "scripts/polaris-release-notes.sh": "test_ship_tool under the coverage shards; the release workflow",
    "polaris_web/test_capacity.py": "the coverage shards",
    "scripts/test_coverage_script.py": "the coverage shards",
    "scripts/test_ci_gate.py": "the coverage shards",
    "scripts/polaris-tree-gate.py": "the local hooks; run by test_tree_gate under the coverage shards",
    "scripts/test_tree_gate.py": "the coverage shards",
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
    ("scripts/test_ci_changes.py", "site/index.html"):
        "a path handed to the classifier and written into a temporary repository; the test reads no site file",
    ("scripts/test_ci_changes.py", "site"):
        "(self.repo / \"site\"): a directory of that name inside the test's temporary repository",
    ("scripts/polaris-ci-changes.py", "site/index.html"):
        "the key of the reviewed mention above, in this file's own source",
    ("scripts/polaris-ci-changes.py", "site/.well-known/"):
        "SITE_KEYS_DIR, a prefix site_only() compares paths with; this file opens no site file",
    ("scripts/test_ci_changes.py", "site/film.css"):
        "a path handed to the classifier; the test reads no site file",
    ("scripts/test_ci_changes.py", "site/index.css"):
        "a path handed to the classifier; the test reads no site file",
    ("scripts/polaris-ci-changes.py", "site/film.css"):
        "the key of the reviewed mention above, in this file's own source",
    ("scripts/polaris-ci-changes.py", "site/index.css"):
        "the key of the reviewed mention above, in this file's own source",
    ("packages/polaris-oid4vp/test_cli.py", "README.md"):
        "pathlib.Path(__file__).with_name(\"README.md\"): the package's own README beside the test, "
        "which is not on the allowlist",
}
#: The same, for the site measurement alone (2026-11-17): mentions of SITE_SHIP_FILES in code a
#: site-skipped job may run, each read by hand and found to open neither file of this tree. The
#: allowlist's measurement does not read this table, so nothing here hides a read from it.
SITE_REVIEWED_MENTIONS = {
    ("scripts/polaris-ci-changes.py", "CHANGELOG.md"):
        "an entry of ALLOWLIST and of SITE_SHIP_FILES, compared with changed paths; this file opens no changelog",
    ("scripts/polaris-link-check.sh", "CHANGELOG.md"):
        "named to be left unwalked: the link check does not follow the changelog's references; and the "
        "invariant checks job runs the link check on every change",
    ("scripts/polaris-release-notes.sh", "CHANGELOG.md"):
        "read from the directory above the script's own; no job of this workflow runs the script on this tree, "
        "and test_ship_tool runs a copy in a temporary directory beside a changelog it writes there",
    ("scripts/polaris-release-notes.sh", "/CHANGELOG.md"):
        "the same read, as ${ROOT}/CHANGELOG.md",
    ("scripts/polaris-ci-changes.py", "/CHANGELOG.md"):
        "the key of the reviewed mention above, in this file's own source",
    ("scripts/polaris-ci-changes.py", "docs/reference/claims.json"):
        "an entry of SITE_SHIP_FILES, compared with changed paths; this file opens no manifest",
    ("scripts/test_ci_changes.py", "CHANGELOG.md"):
        "a path handed to the classifier, and a file written into a temporary repository",
    ("scripts/test_ci_changes.py", "docs/reference/claims.json"):
        "a path handed to the classifier, and a file written into a temporary repository",
    ("scripts/test_ship_tool.py", "CHANGELOG.md"):
        "a changelog the test writes into its own temporary directory or scratch repository",
    ("scripts/polaris-ci-changes.py", "docs/reference/"):
        "an entry of ALLOWLIST, a prefix allowlisted() compares paths with; this file opens no manifest",
    ("scripts/test_ci_changes.py", "docs/reference/"):
        "paths handed to the classifier, and files written into a temporary repository",
    ("scripts/test_ci_changes.py", "docs"):
        "the same paths, their first segment",
    ("scripts/test_compose_parse.py", "docs"):
        "(self.root / \"docs\"): a directory of that name inside the test's temporary root",
    ("docs/reference/openapi.yaml", "**Not"): "Markdown emphasis in a description; the document opens no file",
    ("docs/reference/openapi.yaml", "*as"): "Markdown emphasis in a description",
    ("docs/reference/openapi.yaml", "**Two"): "Markdown emphasis in a description",
    ("docs/reference/openapi.yaml", "*possession*"): "Markdown emphasis in a description",
    ("docs/reference/openapi.yaml", "**No"): "Markdown emphasis in a description",
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


def site_only(path: str) -> bool:
    """May a site-only change touch `path`? It must be one of the two files a site change carries
    (SITE_SHIP_FILES), or under site/, of a type the site serves, not the emblem an example
    serves, and not named as a dependency file. A strict prefix: a file named "site" is not under
    the site, and a path that climbs ("site/../x") is not either."""
    if path in SITE_SHIP_FILES:
        return True
    name = path.rsplit("/", 1)[-1]
    return bool(path.startswith(SITE_ONLY_DIR) and path not in SITE_NOT_ONLY
                and ".." not in path.split("/")
                and name and not name.startswith(".")
                and (name.lower().endswith(SITE_ONLY_TYPES)
                     or ("." not in name and (name in SITE_RULE_FILES or path.startswith(SITE_KEYS_DIR))))
                and not _DEPENDENCY_FILE.match(name) and not _DEPENDENCY_WORD.search(name))


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
    """{"full", "oid4vp", "sdk", "beyond_site": bool, "reason": str}. `changed` is None when unknown."""
    everything = {"full": True, "oid4vp": True, "sdk": True, "beyond_site": True}
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
    # Site-only implies allowlisted (the audit holds it), and beyond_site still reads full, so
    # a site-only change can never skip what an allowlisted one runs.
    beyond = [p for p in changed if not site_only(p)]
    beyond_site = full or bool(beyond)
    if full:
        reason = "%d of %d changed path(s) are not on the allowlist (first: %s)" % (
            len(outside), len(changed), outside[0])
    elif beyond_site:
        reason = "all %d changed path(s) are on the allowlist, %d of them not site-only (first: %s)" % (
            len(changed), len(beyond), beyond[0])
    else:
        reason = "all %d changed path(s) are site-only" % len(changed)
    return {"full": full, "oid4vp": oid4vp and full, "sdk": sdk and full, "beyond_site": beyond_site,
            "reason": reason}


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
    always-run jobs), the other workflows (but not one a skippable job calls, which runs as that
    job), and the allowlisted paths themselves (the audit separately requires that no skippable
    code names one of those)."""
    called = set(called_workflows(root))
    out = []
    for p in files:
        if allowlisted(p) or p in ALWAYS_RUN_ONLY or p in NOT_RUN_IN_CI:
            continue
        if p.startswith("polaris_checks/"):
            continue
        if p.startswith(".github/") and p != CI_YML and not p.startswith(".github/ci/") and p not in called:
            continue
        if _is_code(p) or _has_shebang(root, p):
            out.append(p)
    return out


def site_skipped_code(files: list, root: pathlib.Path = ROOT) -> list:
    """The files a job a site-only change skips may execute or read as configuration: every
    code-like file outside site/, less the never-run ones, polaris_checks/ (the invariant checks
    job runs the checks and their detection tests whole on every change: SITE_ONLY_RESTS_ON), and
    the other workflows but the ones a site-skipped job calls. Wider than skippable_code: the
    always-run-only scripts count, since most run in jobs a site-only change skips."""
    called = set(called_workflows(root, text=_site_skipped_ci_text(root)))
    out = []
    for p in files:
        if p.startswith(SITE_ONLY_DIR) or p in NOT_RUN_IN_CI or p.startswith("polaris_checks/"):
            continue
        if p.startswith(".github/") and p != CI_YML and not p.startswith(".github/ci/") and p not in called:
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


def references(root: pathlib.Path, code: list, candidates: list, texts=None, exact=False,
               reviewed=None) -> dict:
    """{candidate path: [where it is named]} over the skippable code.

    A candidate is named when a path token of a file (see code_view) is its path, or a
    directory above it, read from the repository root or from the naming file's own
    directory; or when a join of constant segments reaches it or a directory above it, a bare
    top-level directory included (ROOT / "docs" / name). A bare word ("site", "lab") outside a
    join names nothing: every such word in the code was read by hand on 2026-10-15 and each is
    prose. Globs with no literal directory, and paths assembled only from variables, are not
    seen; REVIEWED_MENTIONS records the reads of that kind found by hand. With `exact`, only a
    candidate's own path counts (whether a job runs a given script, not whether it reads a
    directory that holds it). `reviewed` adds one measurement's own reviewed mentions to
    REVIEWED_MENTIONS (the site measurement's: SITE_REVIEWED_MENTIONS)."""
    known = set(REVIEWED_MENTIONS) | set(reviewed or ())
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
            if not t or t in (".", "..") or (path, t) in known:
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


_SITE_COND = "needs.changes.outputs.beyond_site == 'true'"


def _steps(block: str) -> list:
    """A job block's steps, each as its text."""
    body = block.split("\n    steps:\n", 1)
    return re.split(r"(?m)^(?=      - )", body[1])[1:] if len(body) == 2 else []


#: Where a step's keys sit: on its "- " line (its first key) or below it.
_STEP_KEY = "(?:      - |        )"


def _conditions(text: str, indent: str) -> list:
    """The `if:` conditions at this indent (a pattern: _STEP_KEY for a step) that read the
    changes outputs."""
    return [c.strip() for c in re.findall(r"(?m)^%sif:(.*)$" % indent, text) if "needs.changes.outputs" in c]


_JOB_NAME = r"['\"]?([A-Za-z0-9_-]+)['\"]?"


def _needs(block: str) -> list:
    """The jobs a job block needs, read only in the plain one-line forms (`needs: [a, b]` or
    `needs: a`), the forms every non-gate job of this workflow uses. Any other spelling of the key
    (a block list, a quoted key, a flow list over two lines, a comment anywhere in it) raises: a
    need this cannot read is a need nobody measured (2026-11-17, in review)."""
    found = [l for l in block.splitlines() if re.match(r"^    ['\"]?needs['\"]?[ \t]*:", l)]
    if not found:
        return []
    m = re.fullmatch(r"    needs:[ \t]*(\[[ \t]*%s(?:[ \t]*,[ \t]*%s)*[ \t]*\]|%s)[ \t]*"
                     % (_JOB_NAME, _JOB_NAME, _JOB_NAME), found[0])
    if len(found) != 1 or not m:
        raise RuntimeError("a job's needs cannot be read: %r" % found[0].strip())
    return [v.strip().strip("'\"") for v in m.group(1).strip("[]").split(",")]


#: A gate: a job that runs whatever its needs did, and judges them (scripts/polaris-ci-gate.py).
_GATE_IF = re.compile(r"(?m)^    if:[ \t]*always\(\)[ \t]*$")
#: An expression that reads a job's needs (`needs.x`, `needs.*`, `needs['x']`, `toJSON(needs)`).
_NEEDS_READ = re.compile(r"\bneeds\s*[.\[)]")
#: The one other read: a gate's step that runs scripts/polaris-ci-gate.py hands it every result.
_GATE_RESULTS = re.compile(r"[ \t]*RESULTS: \$\{\{ toJSON\(needs\) \}\}[ \t]*")
#: A step's line that runs the gate script (`run: python3 scripts/...`, or a folded `run: >-`'s line).
_GATE_RUN = re.compile(r"[ \t]*(?:run:[ \t]*)?python3? scripts/polaris-ci-gate\.py(?:[ \t].*)?")


def _reads_needs(block: str) -> bool:
    """Whether a job reads its needs other than as the one `if:` form: every line of the job,
    comments aside, wherever it sits. A gate's (`if: always()`) RESULTS line is not such a read
    in the step that runs the gate script, and only there."""
    lines = block.splitlines()
    exempt = set()
    if _GATE_IF.search(block) and "    steps:" in lines:
        first = lines.index("    steps:")
        starts = [k for k in range(first + 1, len(lines)) if lines[k].startswith("      - ")]
        ends = starts[1:] + [len(lines)]
        for a, b in zip(starts, ends):
            b = next((k for k in range(a + 1, b) if re.match(r"    \S", lines[k])), b)
            if any(_GATE_RUN.fullmatch(l) for l in lines[a:b]):
                exempt.update(k for k in range(a, b) if _GATE_RESULTS.fullmatch(lines[k]))
    return any(_NEEDS_READ.search(l) and not _SITE_IF.fullmatch(l) and k not in exempt
               for k, l in enumerate(lines) if not l.lstrip().startswith("#"))


def _misread_layout(block: str) -> bool:
    """Whether a job is laid out other than as this audit reads it: its keys at four spaces and
    unquoted, its steps a list at six with one space after each dash (so their keys sit at eight). A compact list (`- ` at four or five spaces), a quoted key or
    a key at another indent could hold a step or a condition the rules read past."""
    lines = [l for l in block.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    if not lines or not re.match(r"    [A-Za-z][\w-]*:", lines[0]):
        return True
    if any(re.match(r" {4,5}- | {4}['\"]| {5}\S| {1,3}\S", l) for l in lines):
        return True
    if any(l.startswith("    steps:") and l != "    steps:" for l in lines):
        return True
    if any(re.match(r" {6}-(?! \S)", l) for l in lines):
        return True
    if "    steps:" in lines:
        after = lines[lines.index("    steps:") + 1:]
        return not (after and after[0].startswith("      - "))
    return False
#: The one read of the changes outputs an always-run or site-skipped job may make.
_SITE_IF = re.compile(r"\s*(?:- )?if:[ \t]*needs\.changes\.outputs\.beyond_site == 'true'[ \t]*")


def _ci_jobs(root: pathlib.Path, strict: bool) -> dict:
    path = root / CI_YML
    if not path.is_file():
        raise RuntimeError("%s is missing" % CI_YML)
    jobs = _ci_job_blocks(path.read_text(encoding="utf-8"))
    if not jobs:
        raise RuntimeError("%s has no jobs this audit can read" % CI_YML)
    missing = [j for j in ALWAYS_RUN_JOBS + SITE_SKIPPED_JOBS if j not in jobs]
    if missing and strict:
        raise RuntimeError("the always-run or site-skipped job(s) %s are not in %s" % (", ".join(missing), CI_YML))
    if strict:
        governed = [j for j in ALWAYS_RUN_JOBS if j in jobs and _conditions(jobs[j], "    ")]
        if governed:
            # An always-run job is left out of both measurements; one that can be skipped
            # would leave its reads unmeasured.
            raise RuntimeError("the always-run job(s) %s are skipped by the changes outputs"
                               % ", ".join(governed))
        waiting = ["%s (%s)" % (j, ", ".join(n for n in _needs(jobs[j]) if n not in ALWAYS_RUN_JOBS))
                   for j in ALWAYS_RUN_JOBS if j in jobs and not _GATE_IF.search(jobs[j])
                   and any(n not in ALWAYS_RUN_JOBS for n in _needs(jobs[j]))]
        if waiting:
            # GitHub skips a job whose need was skipped, unless the job runs `if: always()`, exactly
            # (a gate; `always() && ...` is skipped when the rest is false).
            raise RuntimeError("the always-run job(s) %s need a job the changes outputs can skip, so GitHub "
                               "would skip them with it" % "; ".join(waiting))
        laid = [j for j in ALWAYS_RUN_JOBS + SITE_SKIPPED_JOBS if j in jobs and _misread_layout(jobs[j])]
        if laid:
            # 2026-11-17, in review: the rules read keys at four spaces and steps at
            # six; a compact step list, a quoted key or another indent is valid YAML they read past.
            raise RuntimeError("the always-run or site-skipped job(s) %s are not laid out as this audit reads "
                               "them (keys at four spaces, unquoted; steps a list at six)" % ", ".join(laid))
        reading = [j for j in ALWAYS_RUN_JOBS + SITE_SKIPPED_JOBS if j in jobs and _reads_needs(jobs[j])]
        if reading:
            # Neither job set is in the allowlist's measurement, so a job or step skipped on full,
            # oid4vp or sdk would leave its reads unmeasured on the changes that skip it; only the
            # site measurement reads these jobs, and it reads every step skipped on beyond_site.
            # 2026-11-17, in review: a condition over two lines, a filter
            # (`needs.*`), or an output passed through env skips as surely as a one-line `if:`, so
            # every read of needs counts. Only a gate's own gate step reads its needs, and
            # scripts/polaris-ci-gate.py judges what it reads.
            raise RuntimeError("the always-run or site-skipped job(s) %s read their needs other than as "
                               "`if: %s`" % (", ".join(reading), _SITE_COND))
    return jobs


def _skippable_ci_text(root: pathlib.Path, strict: bool = True) -> str:
    """ci.yml as the skippable jobs run it: their blocks only. The always-run and site-skipped
    jobs run on every allowlisted change and may read anything on the list, and the trigger
    section's paths-ignore names files without reading them."""
    jobs = _ci_jobs(root, strict)
    return "\n".join(b for j, b in jobs.items() if j not in ALWAYS_RUN_JOBS + SITE_SKIPPED_JOBS)


def _site_skipped_ci_text(root: pathlib.Path, strict: bool = True) -> str:
    """ci.yml as a site-only change skips it: every job but the always-run ones, and each step of
    an always-run job that is skipped on beyond_site."""
    jobs = _ci_jobs(root, strict)
    parts = [b for j, b in jobs.items() if j not in ALWAYS_RUN_JOBS]
    parts += [s for j, b in jobs.items() if j in ALWAYS_RUN_JOBS for s in _steps(b)
              if _SITE_COND in _conditions(s, _STEP_KEY)]
    return "\n".join(parts)


#: A job that calls a workflow of this repository (`uses: ./.github/workflows/x.yml`).
_CALLS = re.compile(r"(?m)^\s+uses:\s*['\"]?\./(\.github/workflows/[\w.-]+\.ya?ml)['\"]?(?=\s|$)")


def called_workflows(root: pathlib.Path, strict: bool = True, text: str | None = None) -> list:
    """The workflows the skippable jobs call (or the jobs `text` holds), and the ones those call
    in turn. A called workflow's jobs run as the job that calls it, so its whole text is
    skippable code (2026-10-21: the image CVE scan's steps moved into one). One that is not there
    is listed all the same: the audit reports it rather than measuring nothing."""
    seen, todo = [], _CALLS.findall(_skippable_ci_text(root, strict) if text is None else text)
    while todo:
        rel = todo.pop(0)
        if rel in seen or rel == CI_YML:
            continue
        seen.append(rel)
        try:
            todo += _CALLS.findall((root / rel).read_text(encoding="utf-8"))
        except OSError:
            pass
    return sorted(seen)


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
    for rel in called_workflows(root):
        if rel not in fset:
            problems.append("a skippable job calls %s, which is not tracked, so what it runs is unmeasured" % rel)
    texts = {CI_YML: _skippable_ci_text(root)}
    for path, where in sorted(references(root, code, candidates, texts).items()):
        problems.append("%s is on the allowlist but %s names it" % (path, ", ".join(where[:3])))
    # Declared always-run-only (or never-run) code: nothing a skippable job runs may name it,
    # by its path (the same reading as above) or by importing it from beside it.
    declared = [p for p in list(ALWAYS_RUN_ONLY) + list(NOT_RUN_IN_CI)]
    for path in declared:
        if path not in fset:
            problems.append("%s is declared always-run-only or not run, but is not tracked" % path)
    for (path, _token) in list(REVIEWED_MENTIONS) + list(SITE_REVIEWED_MENTIONS):
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
    # The site-only class (2026-11-17). Every site-only path is on the allowlist, so a site-only
    # change skips at least what an allowlisted one does; no file a site-skipped job may run names
    # one; and the jobs a site-only change still runs do the work the skipped ones did.
    site = [p for p in files if site_only(p)]
    if not [p for p in site if p.startswith(SITE_ONLY_DIR)]:
        problems.append("no tracked file is site-only, so the site measurement covers nothing")
    problems += ["%s is site-only but not on the allowlist" % p for p in site if not allowlisted(p)]
    site_code = site_skipped_code(files, root)
    for rel in called_workflows(root, text=_site_skipped_ci_text(root)):
        if rel not in fset:
            problems.append("a site-skipped job calls %s, which is not tracked, so what it runs is unmeasured" % rel)
    site_texts = {CI_YML: _site_skipped_ci_text(root)}
    problems += ["%s is a file a site change carries, but is not tracked" % p
                 for p in SITE_SHIP_FILES if p not in fset]
    for path, where in sorted(references(root, site_code, site, site_texts,
                                         reviewed=SITE_REVIEWED_MENTIONS).items()):
        problems.append("%s is site-only but %s names it" % (path, ", ".join(where[:3])))
    jobs = _ci_job_blocks((root / CI_YML).read_text(encoding="utf-8"))
    for job, needles in SITE_ONLY_RESTS_ON.items():
        label = "invariant checks" if job == "invariants" else job
        if job not in ALWAYS_RUN_JOBS:
            problems.append("SITE_ONLY_RESTS_ON names %s, which is not an always-run job" % job)
        block = jobs.get(job, "")
        if re.search(r"(?m)^    (?:if|continue-on-error|defaults|env):", block):
            problems.append("the %s job carries an `if:`, a `continue-on-error:`, `defaults:` or `env:`, so what "
                            "a site-only change relies on may not run as pinned, or may fail without failing the "
                            "job" % label)
        if any(re.search(r"\bGITHUB_(?:ENV|PATH)\b", l) for l in block.splitlines()
               if not l.lstrip().startswith("#")):
            # 2026-11-17, in review: a step that writes either changes what every
            # later step runs in, the pinned ones included.
            problems.append("a line of the %s job names $GITHUB_ENV or $GITHUB_PATH, through which a step "
                            "changes what the steps a site-only change relies on run in" % label)
        held = {_pinned(s) for s in _steps(block)}
        for step in needles:
            if tuple(step) not in held:
                # 2026-11-17, in review: a command found by its line can still be
                # skipped, swallowed, folded into another or neutered by a flag; a step pinned whole
                # cannot.
                problems.append("the %s job does not hold the step `%s` as pinned, which a site-only change "
                                "relies on" % (label, step[-1].strip()))
    ci = "\n".join(l for l in (root / CI_YML).read_text(encoding="utf-8").splitlines()
                   if not l.lstrip().startswith("#")) + "\n"
    env = re.findall(r"(?ms)^env:[ \t]*\n(.*?)(?=^\S|\Z)", ci)
    if (len(env) != 1 or re.search(r"(?m)^defaults:", ci)
            or tuple(l.rstrip() for l in env[0].splitlines() if l.strip()) != WORKFLOW_ENV):
        problems.append("%s's top-level `env:` is not WORKFLOW_ENV, or it carries `defaults:`, so the steps a "
                        "site-only change relies on may not run as pinned" % CI_YML)
    print("audit: %d allowlisted file(s) under %d entr(ies), against %d file(s) of skippable code; "
          "site: %d site-only file(s) against %d file(s) of site-skipped code: %s"
          % (len(candidates), len(ALLOWLIST), len(code), len(site), len(site_code),
             "%d problem(s)" % len(problems) if problems else "clean"), file=out)
    return problems


def measure(root: pathlib.Path = ROOT, out=sys.stdout) -> int:
    """The measurement the allowlist was built from: which files under docs/, site/, lab/,
    DEVNOTES/ and meta/, and which top-level prose files, the skippable code names."""
    files = _tracked(root)
    pool = [p for p in files if p.startswith(("docs/", "site/", "lab/", "DEVNOTES/", "meta/"))
            or ("/" not in p and p.endswith((".md", ".cff"))) or allowlisted(p)]
    called = set(called_workflows(root, strict=False))
    code = [p for p in files if p not in pool and p not in ALWAYS_RUN_ONLY and p not in NOT_RUN_IN_CI
            and not p.startswith("polaris_checks/") and (_is_code(p) or _has_shebang(root, p))
            and (not p.startswith(".github/") or p == CI_YML or p.startswith(".github/ci/") or p in called)]
    refs = references(root, code, pool, {CI_YML: _skippable_ci_text(root, strict=False)})
    for p in sorted(refs):
        print("named  %s  <- %s" % (p, ", ".join(refs[p][:4])), file=out)
    print("%d of %d file(s) under docs/, site/, lab/, DEVNOTES/, meta/ and the top-level prose are "
          "named by skippable code" % (len(refs), len(pool)), file=out)
    return 0


#: The outputs, in the order they are written.
OUTPUTS = ("full", "oid4vp", "sdk", "beyond_site")


def _write_outputs(path: str, result: dict) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        for key in OUTPUTS:
            fh.write("%s=%s\n" % (key, "true" if result[key] else "false"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--event", default=os.environ.get("GITHUB_EVENT_NAME", ""))
    ap.add_argument("--base", default="")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--output", default=os.environ.get("GITHUB_OUTPUT", ""),
                    help="append full=, oid4vp=, sdk=, beyond_site= here (default: $GITHUB_OUTPUT)")
    ap.add_argument("--audit", action="store_true", help="re-measure the allowlist and the site class, and exit")
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
        result.update(full=True, oid4vp=True, sdk=True, beyond_site=True,
                      reason=result["reason"] + "; the SDK drill's paths are unknown, so everything runs")
    print("changes: %s" % result["reason"])
    if changed:
        for p in changed[:40]:
            print("  %s %s" % ("site-only  " if site_only(p) else "allowlisted" if allowlisted(p)
                               else "runs       ", p))
        if len(changed) > 40:
            print("  ... and %d more" % (len(changed) - 40))
    print("changes: " + " ".join("%s=%s" % (k, "true" if result[k] else "false") for k in OUTPUTS))
    if args.output:
        try:
            _write_outputs(args.output, result)
        except OSError as exc:
            print("changes: could not write the outputs: %s" % exc, file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
