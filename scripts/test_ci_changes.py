# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""scripts/polaris-ci-changes.py: what a change may skip, and the measurement behind it.

The classifier's one permitted mistake is running too much. These cases hold it to that: a
change wholly on the allowlist skips; a path a skippable job reads, a path nobody listed, a
mixed change, an empty diff, an unreadable base and every unclassified event run everything; a
rename is two paths, not one. The audit is then held to its own question: on this tree it
finds nothing, and in a fixture it finds a skippable script that opens a document (by its
path, by a join, from its own directory, in a shell line) while reading prose as prose. No
network, no database; the git cases build their own repository.

    python3 -m unittest test_ci_changes      (from scripts/)
"""
import contextlib
import importlib.util
import io
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
_spec = importlib.util.spec_from_file_location("polaris_ci_changes", HERE / "polaris-ci-changes.py")
ch = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ch)

SDK = ch.sdk_inputs(ROOT)

# A hook's GIT_* (the pre-commit index above all) would reach every git this module runs, the
# classifier's own included; it is dropped for the module and restored after.
_HOOK_GIT_ENV = {}


def setUpModule():
    _HOOK_GIT_ENV.update({k: os.environ.pop(k) for k in list(os.environ) if k.startswith("GIT_")})


def tearDownModule():
    os.environ.update(_HOOK_GIT_ENV)


def classify(paths, event="pull_request"):
    return ch.classify(event, paths, SDK)


def _git_env():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    return env


class WhatAChangeMaySkip(unittest.TestCase):

    def test_a_docs_only_change_on_the_allowlist_skips(self):
        r = classify(["docs/operator/DR.md", "site/index.html", "lab/interop/yivi/README.md",
                      "README.md", "DEVNOTES/style.md", ".github/ISSUE_TEMPLATE/bug_report.yml"])
        self.assertEqual((r["full"], r["oid4vp"], r["sdk"]), (False, False, False), r["reason"])

    def test_a_docs_file_a_check_reads_still_reaches_the_jobs_that_read_it(self):
        # openapi.yaml is read by a check (check_openapi_covers_api_v1), and the checks run in
        # jobs no output can skip: the invariant checks, the product suite's core part and the
        # coverage shards (whose test_checks.py opens every file). Skipping is for the rest.
        self.assertIn('"docs/reference/openapi.yaml"', (ROOT / "polaris_checks" / "checks.py").read_text())
        self.assertFalse(classify(["docs/reference/openapi.yaml"])["full"])
        for job in ("invariants", "test-core", "test-coverage-shard", "test-coverage"):
            self.assertIn(job, ch.ALWAYS_RUN_JOBS)

    def test_a_docs_file_a_skippable_job_reads_runs_everything(self):
        # test_app opens docs/design/substrate.md (and test_app runs in the application-role
        # and real-PQC jobs); the DR drill writes docs/operator/DR-DRILLS.md; the Linux install
        # job runs lab/strategy/006/issue_and_pack.py, so that directory is off the allowlist,
        # its prose included.
        for p in ("docs/design/substrate.md", "docs/operator/DR-DRILLS.md",
                  "lab/strategy/006/issue_and_pack.py", "lab/strategy/006/README.md"):
            r = classify([p])
            self.assertTrue(r["full"], p)
            self.assertFalse(ch.allowlisted(p), p)

    def test_a_mixed_change_runs_everything(self):
        r = classify(["docs/operator/DR.md", "polaris_web/app.py"])
        self.assertTrue(r["full"])
        self.assertIn("polaris_web/app.py", r["reason"])

    def test_an_unknown_path_runs_everything(self):
        for p in ("somewhere/new.txt", "lab/newly-added/x.py", "lab/strategy/099/x.md", "docsx/a.md",
                  "README.md.orig", "sub/README.md", ".github/workflows/pages.yml"):
            self.assertTrue(classify([p])["full"], p)

    def test_an_empty_diff_runs_everything(self):
        for empty in ([], [""]):
            r = classify(empty)
            self.assertEqual((r["full"], r["oid4vp"], r["sdk"]), (True, True, True))

    def test_an_unreadable_diff_runs_everything(self):
        r = classify(None)
        self.assertEqual((r["full"], r["oid4vp"], r["sdk"]), (True, True, True))
        self.assertIn("could not be read", r["reason"])

    def test_unclassified_events_run_everything(self):
        for event in ("push", "workflow_dispatch", "schedule", "release", ""):
            r = ch.classify(event, ["docs/operator/DR.md"], SDK)
            self.assertEqual((r["full"], r["oid4vp"], r["sdk"]), (True, True, True), event)

    def test_a_merge_group_runs_everything_even_when_its_diff_is_on_the_allowlist(self):
        # The queue's commit is what lands on main: the last gate, where an allowlist miss (a read
        # the static audit could not see) must still be caught.
        for paths in (["docs/operator/DR.md"], ["site/index.html", "lab/interop/yivi/README.md"],
                      ["polaris_web/app.py"]):
            r = classify(paths, event="merge_group")
            self.assertEqual((r["full"], r["oid4vp"], r["sdk"]), (True, True, True), paths)
        self.assertFalse(classify(["docs/operator/DR.md"])["full"], "the pull request itself still skips")

    def test_the_oid4vp_drill_follows_what_it_reads(self):
        for p in ("packages/polaris-oid4vp/polaris_oid4vp/jwe.py", "packages/polaris-oid4vp/test_jwe.py",
                  "packages/polaris-oid4vp/testdata/verifier-info/accept-control.json",
                  "scripts/polaris-oid4vp-mutation-drill.py", "polaris_web/requirements.txt",
                  ".github/workflows/ci.yml"):
            r = classify([p])
            self.assertTrue(r["full"] and r["oid4vp"], p)
        for p in ("scripts/polaris-ship.py", "polaris_web/app.py", "sdk/python/polaris_verify/__init__.py"):
            self.assertFalse(classify([p])["oid4vp"], p)
        self.assertFalse(classify(["docs/operator/DR.md"])["oid4vp"])

    def test_the_sdk_drill_follows_its_own_paths(self):
        spec = importlib.util.spec_from_file_location("sdk_drill", HERE / "polaris-sdk-mutation-drill.py")
        drill = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(drill)
        self.assertEqual(SDK, tuple(drill._SDK_PATHS) + (".github/workflows/ci.yml",))
        for p in ("sdk/python/polaris_verify/__init__.py", "conformance/cases.json",
                  "packages/polaris-verify/polaris_verify_cli/verifier.py", "scripts/test_verify_p9.py"):
            r = classify([p])
            self.assertTrue(r["full"] and r["sdk"], p)
        self.assertFalse(classify(["polaris_web/app.py"])["sdk"])

    def test_no_drill_input_is_on_the_allowlist(self):
        for p in ch.OID4VP_INPUTS + SDK:
            self.assertFalse(ch.allowlisted(p.rstrip("/")), p)
            self.assertFalse(ch.allowlisted(p.rstrip("/") + "/x"), p)


class TheDiff(unittest.TestCase):
    """changed_paths against a real repository."""

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp(prefix="polaris-ci-changes-"))
        self.addCleanup(shutil.rmtree, self.repo, ignore_errors=True)
        self.git("init", "-q")
        (self.repo / "code").mkdir()
        (self.repo / "docs").mkdir()
        (self.repo / "code" / "a.py").write_text("print('a')\n" * 20)
        (self.repo / "docs" / "README.md").write_text("x\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "base")
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=str(self.repo), env=_git_env(), check=True,
                              capture_output=True, text=True).stdout

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "change")
        return self.git("rev-parse", "HEAD").strip()

    def test_a_rename_into_docs_is_two_paths(self):
        self.git("mv", "code/a.py", "docs/a.py")
        head = self.commit()
        changed = ch.changed_paths(self.repo, self.base, head)
        self.assertEqual(sorted(changed), ["code/a.py", "docs/a.py"])
        self.assertTrue(ch.classify("pull_request", changed, SDK)["full"])

    def test_a_docs_change_is_its_path(self):
        (self.repo / "docs" / "README.md").write_text("y\n")
        head = self.commit()
        self.assertEqual(ch.changed_paths(self.repo, self.base, head), ["docs/README.md"])

    def test_a_base_the_checkout_does_not_hold_is_unknown(self):
        self.assertIsNone(ch.changed_paths(self.repo, "f" * 40, "HEAD"))

    def test_a_base_that_is_not_a_full_commit_id_is_unknown(self):
        for base in ("", "HEAD~1", "main", self.base[:12], self.base + "\n"):
            self.assertIsNone(ch.changed_paths(self.repo, base, "HEAD"), repr(base))

    def test_no_change_is_an_empty_diff_and_runs_everything(self):
        changed = ch.changed_paths(self.repo, self.base, self.base)
        self.assertEqual(changed, [])
        self.assertTrue(ch.classify("pull_request", changed, SDK)["full"])

    def test_main_writes_the_outputs_and_runs_everything_without_the_drills_paths(self):
        # This repository has no SDK drill to read the paths from: unknown, so everything runs.
        (self.repo / "docs" / "README.md").write_text("y\n")
        head = self.commit()
        out = self.repo / "outputs"
        with mock.patch.object(ch, "ROOT", self.repo), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            code = ch.main(["--event", "pull_request", "--base", self.base, "--head", head,
                            "--output", str(out)])
        self.assertEqual(code, 0)
        self.assertEqual(out.read_text(), "full=true\noid4vp=true\nsdk=true\n")

    def test_main_skips_a_docs_only_change(self):
        (self.repo / "scripts").mkdir()
        shutil.copy(HERE / "polaris-sdk-mutation-drill.py", self.repo / "scripts")
        self.base = self.commit()
        (self.repo / "docs" / "README.md").write_text("y\n")
        head = self.commit()
        out = self.repo / "outputs"
        with mock.patch.object(ch, "ROOT", self.repo), contextlib.redirect_stdout(io.StringIO()):
            code = ch.main(["--event", "pull_request", "--base", self.base, "--head", head,
                            "--output", str(out)])
        self.assertEqual(code, 0)
        self.assertEqual(out.read_text(), "full=false\noid4vp=false\nsdk=false\n")
        with mock.patch.object(ch, "ROOT", self.repo), contextlib.redirect_stdout(io.StringIO()):
            ch.main(["--event", "pull_request", "--base", "f" * 40, "--head", head, "--output", str(out)])
        self.assertEqual(out.read_text().splitlines()[-3:], ["full=true", "oid4vp=true", "sdk=true"])

    def test_main_fails_when_it_cannot_write_its_outputs(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = ch.main(["--event", "push", "--output", str(self.repo)])    # a directory
        self.assertEqual(code, 1)


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


class TheAudit(unittest.TestCase):

    def test_this_tree_measures_clean(self):
        out = io.StringIO()
        problems = ch.audit(ROOT, out=out)
        self.assertEqual(problems, [], "\n".join(problems))
        self.assertIn("clean", out.getvalue())

    def test_the_known_readers_are_still_measured(self):
        # The three exclusions are there because skippable code reads them; the measurement must
        # still say so, or each exclusion is a belief.
        files = ch._tracked(ROOT)
        refs = ch.references(ROOT, ch.skippable_code(files, ROOT),
                             ["lab/strategy/006/issue_and_pack.py", "docs/design/substrate.md",
                              "docs/operator/DR-DRILLS.md"],
                             {ch.CI_YML: ch._skippable_ci_text(ROOT)})
        self.assertIn(ch.CI_YML, refs.get("lab/strategy/006/issue_and_pack.py", []))
        self.assertIn("polaris_web/test_app.py", refs.get("docs/design/substrate.md", []))
        self.assertIn("scripts/polaris-dr-drill.sh", refs.get("docs/operator/DR-DRILLS.md", []))

    def fixture(self, files):
        root = pathlib.Path(tempfile.mkdtemp(prefix="polaris-ci-audit-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        _write(root, dict({"docs/reference/API.md": "# API\n", "docs/design/x.md": "x\n"}, **files))
        return root

    def named(self, files, candidate="docs/reference/API.md"):
        root = self.fixture(files)
        code = [p for p in files]
        return candidate in ch.references(root, code, ["docs/reference/API.md", "docs/design/x.md"])

    def test_a_skippable_script_that_opens_a_document_is_caught(self):
        reads = {
            "a path string": {"scripts/a.py": 'open("docs/reference/API.md").read()\n'},
            "a join": {"scripts/a.py": 'ROOT / "docs" / "reference" / "API.md"\n'},
            "a join of a bare top directory": {"scripts/a.py": 'for p in (ROOT / "docs").rglob("*.md"): pass\n'},
            "os.path.join": {"scripts/a.py": 'os.path.join(ROOT, "docs", "reference", "API.md")\n'},
            "from its own directory": {"scripts/a.py": 'open("../docs/reference/API.md")\n'},
            "a command line": {"scripts/a.py": 'subprocess.run("cat docs/reference/API.md", shell=True)\n'},
            "a shell read": {"scripts/a.sh": 'grep -q route "$ROOT/docs/reference/API.md"\n'},
            "a written file read later": {"scripts/a.sh": 'cat > /tmp/x <<EOF\ndocs/reference/API.md\nEOF\n'},
            "a directory": {"scripts/a.sh": 'ls docs/reference/\n'},
            "a workflow step": {".github/workflows/ci.yml": "jobs:\n  x:\n    steps:\n      - run: wc -l docs/reference/API.md\n"},
            "a psql include": {"polaris_sql/a.sql": "\\i docs/reference/API.md\n"},
            "a package file list": {"sdk/x/package.json": '{"files": ["../..' '/docs/reference/API.md"]}'},
        }
        for why, files in reads.items():
            self.assertTrue(self.named(files), why)

    def test_prose_is_not_a_read(self):
        prose = {
            "a message": {"scripts/a.py": 'raise SystemExit("see docs/reference/API.md for the format")\n'},
            "a docstring": {"scripts/a.py": '"""The routes are in docs/reference/API.md."""\n'},
            "a comment": {"scripts/a.py": "# docs/reference/API.md\nx = 1\n"},
            "an f-string sentence": {"scripts/a.py": 'x = 1\nprint(f"{x}: read docs/reference/API.md first")\n'},
            "an echo": {"scripts/a.sh": 'echo "see docs/reference/API.md"\n'},
            "an echo continued": {"scripts/a.sh": 'echo "the format" \\\n    "(docs/reference/API.md)" >&2\n'},
            "a quoted sentence": {"scripts/a.sh": 'die "the routes are in docs/reference/API.md"\n'},
            "a usage text": {"scripts/a.sh": 'cat <<EOF\nUsage: see docs/reference/API.md\nEOF\n'},
            "a shell comment": {"scripts/a.sh": "true  # docs/reference/API.md\n"},
            "a SQL comment and string": {"polaris_sql/a.sql": "-- docs/reference/API.md\nCOMMENT ON TABLE t IS 'see docs/reference/API.md';\n"},
            "a bare word": {"scripts/a.sh": "echo docs\nx=docs\n"},
        }
        for why, files in prose.items():
            self.assertFalse(self.named(files), why)

    def test_an_always_run_job_the_outputs_skip_fails_the_audit(self):
        jobs = "".join("  %s:\n    runs-on: x\n" % j for j in ch.ALWAYS_RUN_JOBS)
        root = self.fixture({ch.CI_YML: "jobs:\n" + jobs.replace(
            "  test-core:\n    runs-on: x\n",
            "  test-core:\n    if: needs.changes.outputs.full == 'true'\n    runs-on: x\n")})
        with self.assertRaises(RuntimeError):
            ch._skippable_ci_text(root)
        root = self.fixture({ch.CI_YML: "jobs:\n" + jobs})
        self.assertEqual(ch._skippable_ci_text(root), "")

    def test_an_always_run_only_script_a_skippable_job_runs_is_caught(self):
        # The audit's second half: a script declared always-run-only that a skippable job names.
        root = self.fixture({"scripts/polaris-review-packet-drill.py": "x = 1\n",
                             "scripts/b.sh": "python3 scripts/polaris-review-packet-drill.py\n",
                             "scripts/c.sh": "true\n"})
        refs = ch.references(root, ["scripts/b.sh", "scripts/c.sh"],
                             ["scripts/polaris-review-packet-drill.py"], exact=True)
        self.assertEqual(refs, {"scripts/polaris-review-packet-drill.py": ["scripts/b.sh"]})


if __name__ == "__main__":
    unittest.main()
