#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""scripts/polaris-tree-gate.py: measure the staged tree once, and let the hook trust that.

The heavy pre-commit stages (the invariant layer, the detection tests, the link check and the
tool tests) cost five to nine minutes a commit. The usual way to work here is to measure the
staged tree on a `git archive` export minutes before committing it, and then the hook measured
the identical tree again: 36 minutes of hooks in one 65-minute stretch, all of it repeating a
result already in hand. A merge of main into a branch paid it once more.

    python3 scripts/polaris-tree-gate.py [--all]    gate the STAGED tree on an export
    python3 scripts/polaris-tree-gate.py hook ID    one pre-commit stage (what the hooks call)

The gate exports the tree `git write-tree` names, runs on the export every stage below that the
commit's hooks would run (each hook's `files:` against the diff from HEAD; `--all` runs them
all), and only when every one of them passed writes a receipt to
`<git common dir>/polaris-tree-receipts/<tree>.json`. Linked worktrees share the common dir,
so a receipt written in one is read in all of them.

The hook form runs inside pre-commit. It asks `git write-tree` for the tree being committed
(git hands the hook GIT_INDEX_FILE, so this is the index the commit records, `commit -a`
included) and skips its stage only when a receipt for THAT tree records a pass of THIS stage
measured on an export, with the same stage command (by hash) under the same interpreter,
pytest, ruff and set of installed distributions. Anything else runs the stage exactly as
before: no receipt, an unreadable or malformed one, a receipt for another tree, a recorded
failure, an entry not measured on an export, a changed command, a different interpreter, tool
version or distribution set. Only the gate makes a stage skippable. A stage the hook runs sees
the work tree, untracked files included (the link check resolves links to them, the checks
scan them), which is what the export exists to exclude, so a hook pass records nothing; a hook
failure removes that stage's entry. A receipt can only repeat a pass measured on an export of
the identical tree; it never turns a failure into one.

What is skipped is keyed by tree id, which covers every tracked byte (this script and the
stage commands included). What it cannot see is the machine: a receipt written under one
interpreter is ignored under another, and CI runs every stage regardless.

Run the gate with the `python3` the hooks run under. The receipt records the interpreter, and
a receipt from another one is ignored (the hook says so in one line).
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time

USAGE = """usage: polaris-tree-gate.py [--all] [--keep-export]   gate the staged tree, write a receipt on a pass
       polaris-tree-gate.py hook HOOK-ID         one pre-commit stage (what the hooks call)"""
FORMAT = "polaris-tree-receipt/1"
RECEIPT_DIR = "polaris-tree-receipts"
_TREE_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_MAX_RECEIPT_BYTES = 1 << 20
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

#: The heavy stages, keyed by the pre-commit hook id that runs each one. `{python}` is the
#: interpreter running this script, which is the `python3` the hook entry names. `files` is
#: the hook's own `files:` pattern (None for `always_run`), and the gate runs a stage only
#: when the staged tree differs from HEAD in a path it matches, as the hook would; `--all`
#: runs every one. The command hash covers this whole record, so editing a command, its
#: directory, its pattern or its summary retires every receipt that recorded the old one.
#:
#: polaris-script-tool-tests: the tools under scripts/ are pinned by their OWN suites, which
#: polaris_checks/test_checks.py does not contain. These need no database and no network.
#: test_verify_load is left out on purpose: it is the slowest and exercises a live verify
#: path; CI runs it. test_verify_conformance drives real ML-DSA vectors and SKIPS, naming the
#: cause, on an interpreter whose `cryptography` predates ML-DSA. `scrub_git` drops every
#: GIT_* first: git hands a hook GIT_INDEX_FILE and GIT_DIR, and a suite's scratch repository
#: would otherwise commit into the index of the commit being made (2026-10-10).
STAGES = {
    "polaris-checks": {
        "cwd": ".",
        "argv": ["{python}", "-m", "polaris_checks.run"],
        "scrub_git": False,
        "files": None,
        "summary": r"(\d+ ok \S \d+ warn \S \d+ fail)",
    },
    "polaris-detection-tests": {
        "cwd": ".",
        "argv": ["{python}", "-m", "pytest", "polaris_checks/test_checks.py", "-q"],
        "scrub_git": False,
        "files": r"^(polaris_checks/|polaris_sql/|polaris_web/|conformance/|scripts/polaris-ship\.py$|docs/REVIEW-PACKET\.md$)",
        "summary": r"^=*\s*(\d+ passed[^=\n]*?)(?: in \d[^=\n]*)?\s*=*\s*$",
    },
    "polaris-link-check": {
        "cwd": ".",
        "argv": ["bash", "scripts/polaris-link-check.sh", "--ci"],
        "scrub_git": False,
        "files": None,
        "summary": r"(\d+ references) checked, all resolved",
    },
    "polaris-script-tool-tests": {
        "cwd": "scripts",
        "argv": ["{python}", "-m", "unittest",
                 "test_ship_tool", "test_verify_conformance", "test_verify_p9",
                 "test_verify_refusals", "test_conformance_runner", "test_sbom_enrich",
                 "test_issuance_scope", "test_relying_party", "test_wallet",
                 "test_pin_chart_images", "test_chain_anchor_tool", "test_migrate_runner",
                 "test_coverage_script", "test_trigger_drill", "test_operator_env",
                 "test_key_event", "test_doctor", "test_evaluate", "test_db_init",
                 "test_tree_gate", "test_govulncheck_gate"],
        "scrub_git": True,
        "files": r"^scripts/",
        "summary": r"(Ran \d+ tests?) in [^\n]*\n+\s*(OK[^\n]*)",
    },
}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _git(cwd, *args, env=None):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, env=env)


def _scrubbed_env():
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def command_hash(stage):
    """sha256 over the stage's whole record: command, directory, environment rule, pattern."""
    spec = STAGES[stage]
    blob = json.dumps({"format": FORMAT, "stage": stage, "spec": spec}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def _dist_version(name):
    try:
        from importlib import metadata
        return metadata.version(name)
    except Exception:  # noqa: BLE001 -- absent or unreadable is a value, not an error
        return "absent"


def _ruff_version():
    exe = shutil.which("ruff")
    if not exe:
        return "absent"
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return "absent"
    return out.stdout.strip() or "absent"


def distributions_digest(dists=None):
    """sha256 over the sorted `name==version` of every installed distribution, names
    normalized (PEP 503). The tool tests also depend on cryptography, liboqs, PyYAML and more;
    any install, removal or upgrade in the interpreter changes this."""
    if dists is None:
        try:
            from importlib import metadata
            dists = [(d.metadata["Name"], d.version) for d in metadata.distributions()]
        except Exception:  # noqa: BLE001 -- unreadable is a value that matches nothing recorded
            return "unreadable"
    lines = sorted({"%s==%s" % (re.sub(r"[-_.]+", "-", str(n)).lower(), v)
                    for n, v in dists if n})
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def tool_env():
    """What a recorded pass depends on beyond the tree: compared field for field."""
    return {"python": sys.executable, "python_version": platform.python_version(),
            "pytest": _dist_version("pytest"), "ruff": _ruff_version(),
            "distributions": distributions_digest()}


def summary_of(stage, output):
    """The stage's own summary line out of its output, or "" when it printed none."""
    text = _ANSI.sub("", output or "")
    hits = list(re.finditer(STAGES[stage]["summary"], text, re.M))
    if not hits:
        return ""
    groups = [g.strip() for g in hits[-1].groups() if g and g.strip()]
    return ": ".join(groups)[:200]


def index_tree(cwd, env=None):
    """The tree the index records, via `git write-tree`, or None. Under a hook the inherited
    GIT_INDEX_FILE is what makes this the index being committed, so `env` stays as given."""
    out = _git(cwd, "write-tree", env=env)
    tree = out.stdout.strip()
    if out.returncode != 0 or not _TREE_ID.match(tree):
        return None
    return tree


def common_dir(cwd, env=None):
    out = _git(cwd, "rev-parse", "--path-format=absolute", "--git-common-dir", env=env)
    path = out.stdout.strip()
    if out.returncode != 0 or not path or not os.path.isdir(path):
        return None
    return os.path.realpath(path)


def receipt_path(common, tree):
    """Where the receipt for `tree` lives, or None when that place cannot be trusted: a tree id
    that is not one, a receipt directory that is a link, a resolved path outside it."""
    if not common or not isinstance(tree, str) or not _TREE_ID.match(tree):
        return None
    base = os.path.join(os.path.realpath(common), RECEIPT_DIR)
    if os.path.islink(base):
        return None
    path = os.path.join(base, tree + ".json")
    if os.path.islink(path):
        return None
    if os.path.dirname(os.path.realpath(path)) != os.path.realpath(base):
        return None
    return path


def load_receipt(path):
    """The parsed receipt, or None for anything that is not a readable regular JSON object."""
    if not path:
        return None
    try:
        st = os.lstat(path)
        if not os.path.isfile(path) or os.path.islink(path) or st.st_size > _MAX_RECEIPT_BYTES:
            return None
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def verdict(receipt, tree, stage, cmd_hash, env):
    """(skip, why). Skip only on a recorded pass of this stage, for this tree, by this command,
    under this interpreter and these tool versions. Every other shape runs the stage."""
    if not isinstance(receipt, dict):
        return False, "no receipt for this tree"
    if receipt.get("format") != FORMAT:
        return False, "receipt format is not %s" % FORMAT
    if receipt.get("tree") != tree:
        return False, "receipt is for another tree"
    stages = receipt.get("stages")
    if not isinstance(stages, dict):
        return False, "receipt is malformed (no stage table)"
    entry = stages.get(stage)
    if not isinstance(entry, dict):
        return False, "receipt records no run of this stage"
    if type(entry.get("exit")) is not int or entry.get("exit") != 0:
        return False, "receipt records no pass of this stage"
    if entry.get("where") != "export":
        return False, "receipt entry was not measured on an export"
    if not isinstance(entry.get("summary"), str) or not entry.get("summary").strip():
        return False, "receipt records no summary for this stage"
    if entry.get("command_sha256") != cmd_hash:
        return False, "the stage command changed since the receipt"
    recorded = entry.get("env")
    if not isinstance(recorded, dict) or recorded != env:
        diff = sorted(k for k in set(env) | set(recorded if isinstance(recorded, dict) else {})
                      if not isinstance(recorded, dict) or recorded.get(k) != env.get(k))
        return False, "receipt was recorded under a different %s" % ", ".join(diff or ["environment"])
    return True, "passed at %s (%s): %s" % (entry.get("at", "?"), entry.get("where", "?"),
                                            entry["summary"])


def _write_receipt(path, tree, entries, drop=()):
    """Merge `entries` into the receipt for `tree` and remove `drop`, atomically."""
    if not path:
        return False
    base = os.path.dirname(path)
    try:
        os.makedirs(base, mode=0o700, exist_ok=True)
    except OSError:
        return False
    if os.path.islink(base):
        return False
    old = load_receipt(path)
    stages = {}
    if isinstance(old, dict) and old.get("format") == FORMAT and old.get("tree") == tree \
            and isinstance(old.get("stages"), dict):
        stages = {k: v for k, v in old["stages"].items() if k in STAGES and isinstance(v, dict)}
    for name in drop:
        stages.pop(name, None)
    stages.update(entries)
    if not stages:
        if os.path.isfile(path) and not os.path.islink(path):
            try:
                os.unlink(path)
            except OSError:
                return False
        return True
    doc = {"format": FORMAT, "tree": tree, "updated": _now(), "stages": stages}
    try:
        fd, tmp = tempfile.mkstemp(prefix=".%s." % tree[:12], dir=base)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)
    except OSError:
        return False
    return True


def run_stage(stage, root, scrub_all=False):
    """Run one stage under `root`; (exit code, combined output, seconds). `scrub_all` drops
    every GIT_* whatever the stage says: an export is not a repository, and a GIT_DIR leaking
    in would point its git calls at the one it was exported from."""
    spec = STAGES[stage]
    argv = [sys.executable if a == "{python}" else a for a in spec["argv"]]
    env = _scrubbed_env() if (spec["scrub_git"] or scrub_all) else dict(os.environ)
    t0 = time.monotonic()
    try:
        out = subprocess.run(argv, cwd=os.path.join(root, spec["cwd"]), env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             errors="replace")
    except OSError as exc:
        return 127, "%s: %s\n" % (argv[0], exc), time.monotonic() - t0
    return out.returncode, out.stdout or "", time.monotonic() - t0


def _entry(stage, code, summary, seconds, env, where):
    return {"exit": code, "summary": summary, "seconds": round(seconds, 1), "at": _now(),
            "where": where, "command": STAGES[stage]["argv"],
            "command_sha256": command_hash(stage), "env": env}


def hook(stage):
    """One pre-commit stage: skip on a matching receipt, else run it as before."""
    if stage not in STAGES:
        print("polaris-tree-gate: unknown stage %r (known: %s)" % (stage, ", ".join(STAGES)))
        return 2
    root = os.getcwd()
    tree = index_tree(root)
    common = common_dir(root)
    path = receipt_path(common, tree)
    env = tool_env()
    cmd = command_hash(stage)
    skip, why = verdict(load_receipt(path), tree, stage, cmd, env)
    if skip:
        print("%s: skipped on a tree receipt, tree %s %s" % (stage, tree[:12], why))
        return 0
    code, output, secs = run_stage(stage, root)
    summary = summary_of(stage, output)
    if code != 0:
        sys.stdout.write(output)
        print("%s: failed (exit %d) on tree %s; its receipt entry, if any, is dropped"
              % (stage, code, (tree or "?")[:12]))
        _write_receipt(path, tree, {}, drop=[stage])
        return code
    # A pass here was measured on the work tree, untracked files and all, so it records
    # nothing: only the gate, on an export, makes a stage skippable.
    print("%s: passed in %.0f s on tree %s (%s); no receipt from a hook run, the gate writes "
          "those (ran: %s)" % (stage, secs, (tree or "?")[:12], summary or "no summary line", why))
    return 0


def changed_paths(root, tree):
    """Paths where `tree` differs from HEAD, or None when that cannot be told (no HEAD yet)."""
    out = subprocess.run(["git", "diff-tree", "-r", "-z", "--name-only", "HEAD", tree],
                         cwd=root, capture_output=True, text=True)
    if out.returncode != 0:
        return None
    return [p for p in out.stdout.split("\0") if p]


def selected(stage, changed):
    """Whether the hook would run `stage` for a commit changing `changed` (None: unknown)."""
    pattern = STAGES[stage].get("files")
    if pattern is None or changed is None:
        return True
    return any(re.search(pattern, p) for p in changed)


def gate(keep_export=False, run_all=False):
    """Export the staged tree, run the stages its commit would run, and record a receipt
    only if every one of them passed."""
    top = _git(os.getcwd(), "rev-parse", "--show-toplevel")
    root = top.stdout.strip()
    if top.returncode != 0 or not root:
        print("polaris-tree-gate: not inside a git work tree")
        return 2
    tree = index_tree(root)
    common = common_dir(root)
    path = receipt_path(common, tree)
    if not tree or not path:
        print("polaris-tree-gate: could not read the staged tree (%s) or a trusted receipt "
              "directory under the common git dir (%s)" % (tree, common))
        return 2
    env = tool_env()
    changed = None if run_all else changed_paths(root, tree)
    stages = [s for s in STAGES if selected(s, changed)]
    print("polaris-tree-gate: tree %s (the STAGED tree; unstaged edits are not in it)" % tree)
    print("  interpreter %s %s, pytest %s, %s, distributions sha256 %s"
          % (env["python"], env["python_version"], env["pytest"], env["ruff"],
             env["distributions"][:12]))
    export = tempfile.mkdtemp(prefix="polaris-tree-%s-" % tree[:12])
    try:
        archive = subprocess.Popen(["git", "archive", "--format=tar", tree], cwd=root,
                                   stdout=subprocess.PIPE, env=_scrubbed_env())
        untar = subprocess.run(["tar", "-x", "-f", "-", "-C", export], stdin=archive.stdout)
        archive.stdout.close()
        if archive.wait() != 0 or untar.returncode != 0 or not os.listdir(export):
            print("polaris-tree-gate: exporting tree %s failed" % tree)
            return 2
        results = {}
        for stage in STAGES:
            if stage not in stages:
                print("  %-26s not run: no path changed against HEAD matches %s, so the hook "
                      "will not run it either" % (stage, STAGES[stage]["files"]))
                continue
            code, output, secs = run_stage(stage, export, scrub_all=True)
            summary = summary_of(stage, output)
            results[stage] = (code, summary, secs)
            print("  %-26s exit %d in %4.0f s  %s" % (stage, code, secs,
                                                      summary or "(no summary line)"))
            if code != 0:
                sys.stdout.write(output)
    finally:
        if keep_export:
            print("  export kept at %s" % export)
        else:
            shutil.rmtree(export, ignore_errors=True)
    failed = [s for s, (c, _, _) in results.items() if c != 0]
    blank = [s for s, (c, m, _) in results.items() if c == 0 and not m]
    if not results or failed or blank:
        why = []
        if not results:
            why.append("no stage ran")
        if failed:
            why.append("failed: " + ", ".join(failed))
        if blank:
            why.append("passed with no summary line: " + ", ".join(blank))
        print("polaris-tree-gate: NO receipt (%s)" % "; ".join(why))
        _write_receipt(path, tree, {}, drop=failed)
        return 1
    entries = {s: _entry(s, c, m, t, env, "export") for s, (c, m, t) in results.items()}
    if not _write_receipt(path, tree, entries):
        print("polaris-tree-gate: every stage passed but the receipt could not be written: %s" % path)
        return 1
    print("polaris-tree-gate: receipt %s" % path)
    return 0


def main(argv):
    if argv[:1] == ["hook"] and len(argv) == 2:
        return hook(argv[1])
    flags = set(argv)
    if len(flags) == len(argv) and flags <= {"--keep-export", "--all"}:
        return gate(keep_export="--keep-export" in flags, run_all="--all" in flags)
    print(USAGE)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
