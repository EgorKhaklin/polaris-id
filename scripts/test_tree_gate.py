# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""A tree receipt skips a hook stage only for the identical tree, command and tools.

scripts/polaris-tree-gate.py lets a pre-commit stage trust a pass already measured on the tree
being committed. A cache like that is only worth having if it cannot lie, so these tests drive
the real script in scratch repositories, with stub stages that log every run, and ask what it
must never do: skip on another tree, skip after a failure, skip on a receipt it cannot read,
skip under another interpreter or command, or miss a receipt a linked worktree wrote.

    python3 -m unittest test_tree_gate      (from scripts/)
"""
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent / "polaris-tree-gate.py"

# Prints its summary, logs that it ran, and exits with STUB_EXIT.
STAGE = r'''import os, sys
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write(sys.argv[1] + "\n")
if not os.environ.get("STUB_SILENT"):
    print("%s things ok" % len(sys.argv[1]))
sys.exit(int(os.environ.get("STUB_EXIT", "0")))
'''


def setUpModule():
    # Run from a hook, git hands this process GIT_INDEX_FILE and GIT_DIR, and the scratch
    # repositories below would read and write the index of the commit being made.
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        os.environ.pop(key)


def _load():
    spec = importlib.util.spec_from_file_location("polaris_tree_gate_under_test", str(SCRIPT))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _git(cwd, *args, env=None):
    out = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True, env=env)
    if out.returncode != 0:
        raise AssertionError("git %s: %s" % (" ".join(args), out.stderr))
    return out.stdout.strip()


class TreeGateTests(unittest.TestCase):

    def setUp(self):
        self.mod = _load()
        self.mod.STAGES = {
            "stub-a": {"cwd": ".", "argv": ["{python}", "stage.py", "a"], "scrub_git": False,
                       "summary": r"(\d+ things ok)"},
            "stub-b": {"cwd": ".", "argv": ["{python}", "stage.py", "bb"], "scrub_git": True,
                       "summary": r"(\d+ things ok)"},
        }
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-tree-gate-"))
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.log = self.tmp / "runs.log"
        self.log.write_text("")
        env_keys = ("STUB_LOG", "STUB_EXIT", "STUB_SILENT")
        self.saved_env = {k: os.environ.get(k) for k in env_keys}
        os.environ["STUB_LOG"] = str(self.log)
        os.environ.pop("STUB_EXIT", None)
        os.environ.pop("STUB_SILENT", None)
        _git(self.repo, "init", "-q", "-b", "main")
        _git(self.repo, "config", "user.email", "t@example.invalid")
        _git(self.repo, "config", "user.name", "t")
        _git(self.repo, "config", "commit.gpgsign", "false")
        (self.repo / "stage.py").write_text(STAGE)
        (self.repo / "a.txt").write_text("one\n")
        _git(self.repo, "add", "-A")
        self.cwd = os.getcwd()
        os.chdir(str(self.repo))

    def tearDown(self):
        os.chdir(self.cwd)
        for k, v in self.saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(str(self.tmp), ignore_errors=True)

    # helpers

    def runs(self):
        return [ln for ln in self.log.read_text().splitlines() if ln]

    def call(self, fn, *args):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = fn(*args)
        return code, buf.getvalue()

    def tree(self, cwd=None):
        return _git(cwd or self.repo, "write-tree")

    def receipt_file(self, tree, cwd=None):
        common = _git(cwd or self.repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
        return pathlib.Path(common) / "polaris-tree-receipts" / (tree + ".json")

    # the tests

    def test_a_receipt_for_tree_a_skips_on_tree_a(self):
        code, out = self.call(self.mod.gate)
        self.assertEqual(code, 0, out)
        self.assertEqual(self.runs(), ["a", "bb"], "the gate runs every stage once, on the export")
        receipt = json.loads(self.receipt_file(self.tree()).read_text())
        self.assertEqual(receipt["tree"], self.tree())
        self.assertEqual(receipt["stages"]["stub-a"]["summary"], "1 things ok")
        self.assertEqual(receipt["stages"]["stub-a"]["where"], "export")
        code, out = self.call(self.mod.hook, "stub-a")
        self.assertEqual(code, 0)
        self.assertIn("skipped on a tree receipt, tree %s" % self.tree()[:12], out)
        self.assertIn("1 things ok", out)
        self.assertEqual(self.runs(), ["a", "bb"], "a matching receipt must skip the stage")

    def test_a_receipt_for_tree_a_does_not_skip_on_tree_b(self):
        self.assertEqual(self.call(self.mod.gate)[0], 0)
        tree_a = self.tree()
        (self.repo / "a.txt").write_text("two\n")
        _git(self.repo, "add", "a.txt")
        self.assertNotEqual(self.tree(), tree_a)
        code, out = self.call(self.mod.hook, "stub-a")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.runs(), ["a", "bb", "a"], "tree B must run the stage")
        # A hook pass saw the work tree, not an export: it makes nothing skippable.
        self.assertFalse(self.receipt_file(self.tree()).exists())
        self.assertEqual(self.call(self.mod.hook, "stub-a")[0], 0)
        self.assertEqual(self.runs(), ["a", "bb", "a", "a"])

    def test_a_receipt_from_another_tree_under_this_trees_name_is_ignored(self):
        self.assertEqual(self.call(self.mod.gate)[0], 0)
        tree_a = self.tree()
        foreign = self.receipt_file(tree_a).read_text()
        (self.repo / "a.txt").write_text("two\n")
        _git(self.repo, "add", "a.txt")
        self.receipt_file(self.tree()).write_text(foreign)
        code, out = self.call(self.mod.hook, "stub-a")
        self.assertEqual(code, 0, out)
        self.assertIn("another tree", out)
        self.assertEqual(self.runs(), ["a", "bb", "a"])

    def test_a_failed_stage_writes_no_receipt(self):
        os.environ["STUB_EXIT"] = "1"
        code, out = self.call(self.mod.gate)
        self.assertEqual(code, 1, out)
        self.assertIn("NO receipt", out)
        self.assertFalse(self.receipt_file(self.tree()).exists())
        code, out = self.call(self.mod.hook, "stub-a")
        self.assertEqual(code, 1, out)
        self.assertFalse(self.receipt_file(self.tree()).exists())
        # One failing stage in the gate is enough to write nothing for the others either.
        self.mod.STAGES["stub-b"]["argv"] = ["{python}", "-c", "import sys; sys.exit(3)"]
        os.environ.pop("STUB_EXIT")
        self.assertEqual(self.call(self.mod.gate)[0], 1)
        self.assertFalse(self.receipt_file(self.tree()).exists())

    def test_a_failing_run_removes_that_stages_recorded_pass(self):
        self.assertEqual(self.call(self.mod.gate)[0], 0)
        path = self.receipt_file(self.tree())
        doc = json.loads(path.read_text())
        doc["stages"]["stub-a"]["env"]["pytest"] = "0.0"
        path.write_text(json.dumps(doc))
        os.environ["STUB_EXIT"] = "1"
        self.assertEqual(self.call(self.mod.hook, "stub-a")[0], 1)
        after = json.loads(path.read_text())
        self.assertNotIn("stub-a", after["stages"])
        self.assertIn("stub-b", after["stages"])

    def test_a_pass_with_no_summary_line_writes_no_receipt(self):
        os.environ["STUB_SILENT"] = "1"
        code, out = self.call(self.mod.gate)
        self.assertEqual(code, 1, out)
        self.assertIn("no summary line", out)
        self.assertFalse(self.receipt_file(self.tree()).exists())
        code, out = self.call(self.mod.hook, "stub-a")
        self.assertEqual(code, 0, "the stage itself passed, so the hook passes")
        self.assertFalse(self.receipt_file(self.tree()).exists())

    def test_a_hook_pass_writes_nothing_and_leaves_the_receipt_alone(self):
        self.assertEqual(self.call(self.mod.hook, "stub-a")[0], 0)
        self.assertFalse(self.receipt_file(self.tree()).exists(), "no receipt from a hook pass")
        # With a receipt in place that does not cover the stage, a hook pass leaves it byte
        # for byte as it was.
        self.assertEqual(self.call(self.mod.gate)[0], 0)
        path = self.receipt_file(self.tree())
        doc = json.loads(path.read_text())
        del doc["stages"]["stub-a"]
        path.write_text(json.dumps(doc))
        before = path.read_bytes()
        code, out = self.call(self.mod.hook, "stub-a")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.runs(), ["a", "a", "bb", "a"])
        self.assertEqual(path.read_bytes(), before)

    def test_an_entry_not_measured_on_an_export_does_not_skip(self):
        self.assertEqual(self.call(self.mod.gate)[0], 0)
        path = self.receipt_file(self.tree())
        good = json.loads(path.read_text())
        for where in ("worktree", None, "EXPORT"):
            doc = json.loads(json.dumps(good))
            if where is None:
                del doc["stages"]["stub-a"]["where"]
            else:
                doc["stages"]["stub-a"]["where"] = where
            path.write_text(json.dumps(doc))
            before = len(self.runs())
            code, out = self.call(self.mod.hook, "stub-a")
            self.assertEqual(code, 0, out)
            self.assertEqual(len(self.runs()), before + 1, "where=%r must run the stage" % where)
            self.assertIn("not measured on an export", out)

    def test_a_changed_distribution_set_does_not_skip(self):
        self.assertEqual(self.call(self.mod.gate)[0], 0)
        real = self.mod.distributions_digest
        self.mod.distributions_digest = lambda dists=None: real([("cryptography", "0.0")])
        try:
            code, out = self.call(self.mod.hook, "stub-a")
        finally:
            self.mod.distributions_digest = real
        self.assertEqual(len(self.runs()), 3, out)
        self.assertIn("distributions", out)
        self.assertIn("skipped on a tree receipt", self.call(self.mod.hook, "stub-a")[1])
        # The digest itself: an upgrade, an addition or a removal changes it; the spelling of
        # a name does not, and neither does the order distributions are found in.
        base = [("cryptography", "46.0.1"), ("PyYAML", "6.0.2"), ("liboqs-python", "0.12.0")]
        d = real(base)
        self.assertEqual(d, real(list(reversed(base))))
        self.assertEqual(d, real([("cryptography", "46.0.1"), ("pyyaml", "6.0.2"), ("liboqs_python", "0.12.0")]))
        self.assertNotEqual(d, real([("cryptography", "46.0.2")] + base[1:]))
        self.assertNotEqual(d, real(base + [("extra", "1")]))
        self.assertNotEqual(d, real(base[:2]))
        self.assertRegex(real(), r"^[0-9a-f]{64}$")

    def test_a_malformed_receipt_runs_the_stage(self):
        tree = self.tree()
        bodies = ["not json", "[]", json.dumps({"format": "polaris-tree-receipt/1", "tree": tree,
                                                "stages": []})]
        self.assertEqual(self.call(self.mod.gate)[0], 0)
        good = json.loads(self.receipt_file(tree).read_text())
        for mutate in ("exit-str", "exit-true", "no-summary", "format"):
            doc = json.loads(json.dumps(good))
            entry = doc["stages"]["stub-a"]
            if mutate == "exit-str":
                entry["exit"] = "0"
            elif mutate == "exit-true":
                entry["exit"] = True
            elif mutate == "no-summary":
                entry["summary"] = ""
            else:
                doc["format"] = "polaris-tree-receipt/0"
            bodies.append(json.dumps(doc))
        for i, body in enumerate(bodies):
            self.receipt_file(tree).write_text(body)
            before = len(self.runs())
            code, out = self.call(self.mod.hook, "stub-a")
            self.assertEqual(code, 0, out)
            self.assertEqual(len(self.runs()), before + 1, "body %d must run the stage: %s" % (i, body[:80]))

    def test_a_version_or_command_mismatch_runs_the_stage(self):
        self.assertEqual(self.call(self.mod.gate)[0], 0)
        real_env = self.mod.tool_env
        for field in ("python", "python_version", "pytest", "ruff", "distributions"):
            self.mod.tool_env = lambda f=field: dict(real_env(), **{f: "other"})
            before = len(self.runs())
            code, out = self.call(self.mod.hook, "stub-b")
            self.assertEqual(len(self.runs()), before + 1, "a different %s must run the stage" % field)
            self.assertIn(field, out)
        self.mod.tool_env = real_env
        self.mod.STAGES["stub-a"]["argv"] = ["{python}", "stage.py", "a", "--changed"]
        before = len(self.runs())
        code, out = self.call(self.mod.hook, "stub-a")
        self.assertEqual(len(self.runs()), before + 1, out)
        self.assertIn("command changed", out)

    def test_a_receipt_written_in_one_worktree_is_found_from_a_linked_one(self):
        _git(self.repo, "commit", "-q", "-m", "a")
        linked = self.tmp / "linked"
        _git(self.repo, "worktree", "add", "-q", str(linked), "-b", "side")
        self.assertEqual(self.call(self.mod.gate)[0], 0)
        os.chdir(str(linked))
        self.assertEqual(self.tree(linked), self.tree())
        self.assertEqual(os.path.realpath(self.receipt_file(self.tree(linked), cwd=linked)),
                         os.path.realpath(self.repo / ".git" / "polaris-tree-receipts" / (self.tree() + ".json")))
        self.assertTrue(self.receipt_file(self.tree(linked), cwd=linked).is_file())
        code, out = self.call(self.mod.hook, "stub-a")
        self.assertEqual(code, 0, out)
        self.assertIn("skipped on a tree receipt", out)
        self.assertEqual(self.runs(), ["a", "bb"])

    def test_the_hook_keys_on_the_index_git_hands_it(self):
        # `git commit -a` and `git commit <path>` hand the hook GIT_INDEX_FILE naming a
        # temporary index; that index, not .git/index, is the tree being committed.
        self.assertEqual(self.call(self.mod.gate)[0], 0)
        tree_a = self.tree()
        (self.repo / "a.txt").write_text("two\n")
        alt = self.tmp / "alt-index"
        env = dict(os.environ, GIT_INDEX_FILE=str(alt))
        _git(self.repo, "read-tree", tree_a, env=env)
        _git(self.repo, "add", "a.txt", env=env)
        try:
            os.environ["GIT_INDEX_FILE"] = str(alt)
            code, out = self.call(self.mod.hook, "stub-a")
        finally:
            os.environ.pop("GIT_INDEX_FILE")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.runs(), ["a", "bb", "a"], "the alternate index holds another tree")
        try:
            os.environ["GIT_INDEX_FILE"] = str(self.repo / ".git" / "index")
            code, out = self.call(self.mod.hook, "stub-a")
        finally:
            os.environ.pop("GIT_INDEX_FILE")
        self.assertIn("skipped on a tree receipt", out)

    def test_a_receipt_path_outside_the_common_dir_is_never_trusted(self):
        common = _git(self.repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
        tree = self.tree()
        self.assertIsNone(self.mod.receipt_path(common, "../../" + tree))
        self.assertIsNone(self.mod.receipt_path(common, ""))
        self.assertIsNone(self.mod.receipt_path(common, None))
        self.assertIsNone(self.mod.receipt_path(None, tree))
        self.assertEqual(self.mod.receipt_path(common, tree),
                         os.path.join(os.path.realpath(common), "polaris-tree-receipts", tree + ".json"))
        # A receipt that is a link to one elsewhere, and a receipt directory that is a link.
        self.assertEqual(self.call(self.mod.gate)[0], 0)
        path = self.receipt_file(tree)
        outside = self.tmp / "planted.json"
        outside.write_text(path.read_text())
        path.unlink()
        path.symlink_to(outside)
        self.assertIsNone(self.mod.receipt_path(common, tree))
        self.assertEqual(self.call(self.mod.hook, "stub-a")[1].count("skipped"), 0)
        path.unlink()
        rdir = path.parent
        shutil.move(str(rdir), str(self.tmp / "elsewhere"))
        rdir.symlink_to(self.tmp / "elsewhere")
        self.assertIsNone(self.mod.receipt_path(common, tree))
        before = len(self.runs())
        self.assertEqual(self.call(self.mod.hook, "stub-a")[0], 0)
        self.assertEqual(len(self.runs()), before + 1)

    def test_verdict_runs_on_every_shape_but_a_matching_pass(self):
        t, other = "a" * 40, "b" * 40
        env = {"python": "/x", "python_version": "3", "pytest": "9", "ruff": "ruff 1",
               "distributions": "d" * 64}
        h = self.mod.command_hash("stub-a")
        entry = {"exit": 0, "summary": "1 things ok", "command_sha256": h, "env": env,
                 "where": "export"}
        good = {"format": self.mod.FORMAT, "tree": t, "stages": {"stub-a": entry}}
        self.assertTrue(self.mod.verdict(good, t, "stub-a", h, env)[0], "positive control")
        for receipt, tree, stage, hh, ee in [
                (None, t, "stub-a", h, env),
                (good, other, "stub-a", h, env),
                (good, t, "stub-b", h, env),
                (good, t, "stub-a", "0" * 64, env),
                (good, t, "stub-a", h, dict(env, ruff="ruff 2")),
                (good, t, "stub-a", h, dict(env, distributions="e" * 64)),
                (dict(good, stages={"stub-a": dict(entry, where="worktree")}), t, "stub-a", h, env),
                (dict(good, stages={"stub-a": dict(entry, exit=1)}), t, "stub-a", h, env),
                (dict(good, stages={"stub-a": dict(entry, exit=False)}), t, "stub-a", h, env),
                (dict(good, stages={"stub-a": dict(entry, env=None)}), t, "stub-a", h, env),
                (dict(good, stages=None), t, "stub-a", h, env),
                (dict(good, tree=None), t, "stub-a", h, env)]:
            self.assertFalse(self.mod.verdict(receipt, tree, stage, hh, ee)[0],
                             (receipt, tree, stage, hh, ee))

    def test_the_gate_runs_what_the_commit_would_and_the_hook_runs_the_rest(self):
        _git(self.repo, "commit", "-q", "-m", "a")
        self.mod.STAGES["stub-b"]["files"] = r"^scripts/"
        (self.repo / "a.txt").write_text("two\n")
        _git(self.repo, "add", "a.txt")
        code, out = self.call(self.mod.gate)
        self.assertEqual(code, 0, out)
        self.assertIn("stub-b", out)
        self.assertIn("not run", out)
        self.assertEqual(self.runs(), ["a"], "no staged path matches stub-b's pattern")
        receipt = json.loads(self.receipt_file(self.tree()).read_text())
        self.assertEqual(sorted(receipt["stages"]), ["stub-a"])
        # A stage the gate did not run has no pass to repeat: the hook runs it.
        code, out = self.call(self.mod.hook, "stub-b")
        self.assertEqual(self.runs(), ["a", "bb"], out)
        self.assertEqual(self.call(self.mod.gate, False, True)[0], 0)
        self.assertEqual(self.runs(), ["a", "bb", "a", "bb"], "--all runs every stage")

    def test_an_unknown_stage_refuses(self):
        code, out = self.call(self.mod.hook, "nope")
        self.assertEqual(code, 2)
        self.assertEqual(self.runs(), [])

    def test_the_real_stages_are_the_four_heavy_hooks(self):
        real = _load()
        self.assertEqual(sorted(real.STAGES), ["polaris-checks", "polaris-detection-tests",
                                               "polaris-link-check", "polaris-script-tool-tests"])
        self.assertTrue(real.STAGES["polaris-script-tool-tests"]["scrub_git"])
        self.assertIn("test_tree_gate", real.STAGES["polaris-script-tool-tests"]["argv"])
        # Each summary pattern reads the line its tool really prints.
        samples = {
            "polaris-checks": ("\n  383 ok · 2 warn · 0 fail\n  READY\n", "383 ok · 2 warn · 0 fail"),
            "polaris-detection-tests": ("....\n423 passed, 1 skipped in 129.31s (0:02:09)\n", "423 passed, 1 skipped"),
            "polaris-link-check": ("\x1b[0;32mOK\x1b[0m  5120 references checked, all resolved\n", "5120 references"),
            "polaris-script-tool-tests": ("...\n------\nRan 312 tests in 4.1s\n\nOK (skipped=3)\n", "Ran 312 tests: OK (skipped=3)"),
        }
        for stage, (out, want) in samples.items():
            self.assertEqual(real.summary_of(stage, out), want, stage)
            self.assertEqual(real.summary_of(stage, ""), "", stage)
        self.assertEqual(real.summary_of("polaris-detection-tests", "2 failed, 421 passed in 3s\n"), "")


if __name__ == "__main__":
    unittest.main()
