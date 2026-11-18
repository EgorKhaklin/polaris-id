# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""scripts/polaris-ci-changes.py: what a change may skip, and the measurement behind it.

The classifier's one permitted mistake is running too much. These cases hold it to that: a
change wholly on the allowlist skips; a path a skippable job reads, a path nobody listed, a
mixed change, an empty diff, an unreadable base and every unclassified event run everything; a
rename is two paths, not one. A change wholly under site/ skips more (beyond_site=false), but
not when it touches the emblem an example serves or a dependency file, and never when the paths
are unknown. The audit is then held to its own question: on this tree it finds nothing, and in a
fixture it finds a skippable script that opens a document (by its path, by a join, from its own
directory, in a shell line) while reading prose as prose, and a site-skipped one that opens a
site file. No network, no database; the git cases build their own repository.

    python3 -m unittest test_ci_changes      (from scripts/)
"""
import contextlib
import importlib.util
import io
import os
import pathlib
import re
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
        self.assertEqual((r["full"], r["oid4vp"], r["sdk"], r["beyond_site"]), (False, False, False, True),
                         r["reason"])

    def test_a_docs_file_a_check_reads_still_reaches_the_jobs_that_read_it(self):
        # openapi.yaml is read by a check (check_openapi_covers_api_v1), and the checks run in
        # the invariant checks job, which no output can skip, and in the product suite's core part
        # and the coverage shards (whose test_checks.py opens every file), which only a site-only
        # change skips. Skipping is for the rest.
        self.assertIn('"docs/reference/openapi.yaml"', (ROOT / "polaris_checks" / "checks.py").read_text())
        r = classify(["docs/reference/openapi.yaml"])
        self.assertEqual((r["full"], r["beyond_site"]), (False, True))
        for job in ("invariants", "test-coverage"):
            self.assertIn(job, ch.ALWAYS_RUN_JOBS)
        for job in ("test-core", "test-coverage-shard"):
            self.assertIn(job, ch.SITE_SKIPPED_JOBS)

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
            self.assertEqual((r["full"], r["oid4vp"], r["sdk"], r["beyond_site"]), (True, True, True, True))

    def test_an_unreadable_diff_runs_everything(self):
        r = classify(None)
        self.assertEqual((r["full"], r["oid4vp"], r["sdk"], r["beyond_site"]), (True, True, True, True))
        self.assertIn("could not be read", r["reason"])

    def test_unclassified_events_run_everything(self):
        for event in ("push", "workflow_dispatch", "schedule", "release", ""):
            r = ch.classify(event, ["docs/operator/DR.md"], SDK)
            self.assertEqual((r["full"], r["oid4vp"], r["sdk"], r["beyond_site"]), (True, True, True, True), event)

    def test_a_merge_group_runs_everything_even_when_its_diff_is_on_the_allowlist(self):
        # The queue's commit is what lands on main: the last gate, where an allowlist miss (a read
        # the static audit could not see) must still be caught.
        for paths in (["docs/operator/DR.md"], ["site/index.html", "lab/interop/yivi/README.md"],
                      ["polaris_web/app.py"]):
            r = classify(paths, event="merge_group")
            self.assertEqual((r["full"], r["oid4vp"], r["sdk"], r["beyond_site"]), (True, True, True, True), paths)
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


class WhatOnlyASiteChangeMaySkip(unittest.TestCase):
    """2026-11-17: beyond_site is "false" only when every changed path is a site file the jobs
    it governs were measured not to read, and "true" (run them) in every other case."""

    def test_a_change_wholly_under_the_site_skips_them(self):
        for paths in (["site/index.html"], ["site/index.html", "site/a-new-style.css", "site/a-new-page.html"]):
            r = classify(paths)
            self.assertEqual((r["full"], r["oid4vp"], r["sdk"], r["beyond_site"]), (False, False, False, False),
                             paths)

    def test_what_a_site_change_carries_skips_them_too(self):
        # The path lists of the two site changes sent on 2026-11-17: each carried its changelog
        # line, and ran everything the allowlist does not skip. The manifest the site's sentences
        # are held to is the other file such a change carries.
        for paths in (["CHANGELOG.md", "site/film.css", "site/index.css"],
                      ["CHANGELOG.md", "site/film.css", "site/index.html"],
                      ["docs/reference/claims.json", "site/index.html"],
                      ["CHANGELOG.md", "docs/reference/claims.json", "site/index.html"]):
            r = classify(paths)
            self.assertEqual((r["full"], r["oid4vp"], r["sdk"], r["beyond_site"]), (False, False, False, False),
                             paths)
        self.assertEqual(ch.SITE_SHIP_FILES, ("CHANGELOG.md", "docs/reference/claims.json"))
        # The changelog beside one path of the application runs everything.
        r = classify(["CHANGELOG.md", "polaris_web/app.py"])
        self.assertEqual((r["full"], r["beyond_site"]), (True, True))
        r = classify(["CHANGELOG.md", "site/index.html", "polaris_web/app.py"])
        self.assertEqual((r["full"], r["beyond_site"]), (True, True))
        # Only those two: a neighbour of either, or a file of the same name elsewhere, runs them.
        for other in ("docs/reference/claims.md", "docs/reference/API.md", "docs/history/CHANGELOG-v9.md",
                      "changelog.md", "CHANGELOG.md.orig") + tuple("lab/" + f for f in ch.SITE_SHIP_FILES):
            self.assertFalse(ch.site_only(other), other)
            self.assertTrue(classify(["site/index.html", other])["beyond_site"], other)

    def test_a_path_that_climbs_out_of_the_site_runs_them(self):
        for p in ("site/../scripts/x.html", "site/a/../../x.css", "site/a/../b.html", "site/.."):
            self.assertFalse(ch.site_only(p), p)
            self.assertTrue(classify(["site/index.html", p])["beyond_site"], p)

    def test_the_site_with_any_other_path_runs_them(self):
        r = classify(["site/index.html", "polaris_web/app.py"])
        self.assertEqual((r["full"], r["beyond_site"]), (True, True))
        for other in ("README.md", "docs/reference/API.md", "lab/interop/yivi/README.md", "meta/README.md"):
            r = classify(["site/index.html", other])
            self.assertEqual((r["full"], r["beyond_site"]), (False, True), other)

    def test_the_emblem_an_example_serves_runs_them(self):
        # The Yivi check-in example serves site/polaris_logo.webp as its default emblem: code
        # outside the site reads it.
        app = ROOT / "packages" / "polaris-oid4vp" / "examples" / "yivi-checkin" / "app.py"
        self.assertIn("site/polaris_logo.webp", app.read_text())
        for paths in (["site/polaris_logo.webp"], ["site/index.html", "site/polaris_logo.webp"]):
            r = classify(paths)
            self.assertEqual((r["full"], r["beyond_site"]), (False, True), paths)
        self.assertFalse(classify(["site/polaris_logo_512.png"])["beyond_site"])

    def test_a_dependency_file_under_the_site_runs_them(self):
        for p in ("site/package-lock.json", "site/package.json", "site/requirements.txt",
                  "site/requirements-dev.txt", "site/constraints.txt", "site/yarn.lock", "site/pnpm-lock.yaml",
                  "site/tools/Cargo.lock", "site/tools/Cargo.toml", "site/pyproject.toml", "site/go.sum",
                  "site/Gemfile.lock", "site/poetry.lock", "site/uv.lock", "site/bun.lockb"):
            self.assertTrue(classify(["site/index.html", p])["beyond_site"], p)

    def test_code_configuration_and_unlisted_types_under_the_site_run_them(self):
        # 2026-11-17, in review: the product suite's core part runs `ruff check .`,
        # which lints a Python file under site/ as it lints any other; no job that runs on a
        # site-only change does. So the class admits only what the site serves.
        for p in ("site/tools/build.py", "site/stubs.pyi", "site/notes.ipynb", "site/app.js", "site/app.mjs",
                  "site/style.scss", "site/build.sh", "site/.eslintrc", "site/.env", "site/wrangler.toml",
                  "site/config.yaml", "site/sitemap.xml", "site/gems.locked", "site/pylock.toml",
                  "site/gradle/verification-metadata.xml", "site/page.html.py", "site/Makefile",
                  "site/Dockerfile", "site/build", "site/tools/deploy", "site/.eslintrc.json", "site/.nojekyll",
                  "site/.well-known/.hidden.txt", "site/.well-known/rotate.sh", "site/.well-known/key.py",
                  "site/", "site/_build", "site/_config"):
            self.assertFalse(ch.site_only(p), p)
            self.assertTrue(classify(["site/index.html", p])["beyond_site"], p)
        # Names of files the tree does not hold: a tracked one named here would read, to the audit,
        # as code that opens it.
        for p in ("site/_redirects", "site/.well-known/openpgpkey/a-new-key", "site/.well-known/a-new.json",
                  "site/film/a-1080.avif", "site/a.webp", "site/a.png", "site/a.jpg", "site/a.svg", "site/a.ico",
                  "site/fonts/a.woff2", "site/a-new.txt", "site/a-new-note.md", "site/a-new.css", "site/INDEX.HTML",
                  "site/lockup.svg", "site/clock.png", "site/block.css"):
            self.assertTrue(ch.site_only(p), p)
            self.assertFalse(classify(["site/index.html", p])["beyond_site"], p)

    def test_a_name_that_says_it_is_a_dependency_file_runs_them(self):
        # In review: names the manifest list does not spell.
        for p in ("site/dev-requirements.txt", "site/test_requirements.txt", "site/requirements.in",
                  "site/test_constraints.txt", "site/packages.lock.json", "site/npm-shrinkwrap.json",
                  "site/a.lockfile.json", "site/Requirements.TXT"):
            self.assertFalse(ch.site_only(p), p)
            self.assertTrue(classify(["site/index.html", p])["beyond_site"], p)

    def test_unknown_paths_and_other_events_run_them(self):
        for changed in (None, [], [""]):
            self.assertTrue(classify(changed)["beyond_site"], changed)
        for event in ("push", "workflow_dispatch", "merge_group", "schedule", ""):
            self.assertTrue(ch.classify(event, ["site/index.html"], SDK)["beyond_site"], event)

    def test_a_path_that_only_looks_like_the_site_runs_them(self):
        for p in ("site", "sitex/index.html", "docs/site/a-page.html", "lab/site/a-page.html"):
            self.assertTrue(classify([p])["beyond_site"], p)

    def test_a_site_path_off_the_allowlist_runs_them(self):
        # beyond_site reads full as well: were site/ ever taken off the allowlist, a change there
        # would run everything, not skip the site-skipped jobs while running the rest.
        off = tuple(e for e in ch.ALLOWLIST if e != "site/")
        self.assertNotEqual(off, ch.ALLOWLIST)
        with mock.patch.object(ch, "ALLOWLIST", off):
            r = classify(["site/index.html"])
        self.assertEqual((r["full"], r["beyond_site"]), (True, True))

    def test_every_site_only_path_is_on_the_allowlist(self):
        # beyond_site=false must imply full=false: a site-only change skips at least what any
        # allowlisted change does.
        site = [p for p in ch._tracked(ROOT) if ch.site_only(p)]
        self.assertTrue(site)
        self.assertEqual([p for p in site if not ch.allowlisted(p)], [])


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
        self.assertEqual(out.read_text(), "full=true\noid4vp=true\nsdk=true\nbeyond_site=true\n")

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
        self.assertEqual(out.read_text(), "full=false\noid4vp=false\nsdk=false\nbeyond_site=true\n")
        with mock.patch.object(ch, "ROOT", self.repo), contextlib.redirect_stdout(io.StringIO()):
            ch.main(["--event", "pull_request", "--base", "f" * 40, "--head", head, "--output", str(out)])
        self.assertEqual(out.read_text().splitlines()[-4:], ["full=true", "oid4vp=true", "sdk=true", "beyond_site=true"])

    def test_main_skips_more_for_a_site_only_change(self):
        (self.repo / "scripts").mkdir()
        shutil.copy(HERE / "polaris-sdk-mutation-drill.py", self.repo / "scripts")
        (self.repo / "site").mkdir()
        (self.repo / "site" / "index.html").write_text("<p>a</p>\n")
        self.base = self.commit()
        (self.repo / "site" / "index.html").write_text("<p>b</p>\n")
        head = self.commit()
        out = self.repo / "outputs"
        with mock.patch.object(ch, "ROOT", self.repo), contextlib.redirect_stdout(io.StringIO()):
            code = ch.main(["--event", "pull_request", "--base", self.base, "--head", head,
                            "--output", str(out)])
        self.assertEqual(code, 0)
        self.assertEqual(out.read_text(), "full=false\noid4vp=false\nsdk=false\nbeyond_site=false\n")

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
        jobs = "".join("  %s:\n    runs-on: x\n" % j for j in ch.ALWAYS_RUN_JOBS + ch.SITE_SKIPPED_JOBS)
        for job, cond in (("invariants", "full"), ("invariants", "beyond_site"), ("test-core", "full"),
                          ("test-core", "oid4vp")):
            root = self.fixture({ch.CI_YML: "jobs:\n" + jobs.replace(
                "  %s:\n    runs-on: x\n" % job,
                "  %s:\n    if: needs.changes.outputs.%s == 'true'\n    runs-on: x\n" % (job, cond))})
            with self.assertRaises(RuntimeError, msg=(job, cond)):
                ch._skippable_ci_text(root)
        # A site-skipped job skipped on beyond_site is what the class is for; its reads are the
        # site measurement's, not the allowlist's.
        root = self.fixture({ch.CI_YML: "jobs:\n" + jobs.replace(
            "  test-core:\n    runs-on: x\n",
            "  test-core:\n    if: needs.changes.outputs.beyond_site == 'true'\n    runs-on: x\n")})
        self.assertEqual(ch._skippable_ci_text(root), "")
        self.assertIn("beyond_site == 'true'", ch._site_skipped_ci_text(root))
        root = self.fixture({ch.CI_YML: "jobs:\n" + jobs})
        self.assertEqual(ch._skippable_ci_text(root), "")
        # A step of an always-run job may be skipped on beyond_site alone: a step skipped on full
        # would leave its reads unmeasured.
        step = ("  test-coverage:\n    runs-on: x\n    steps:\n      - name: Floor\n"
                "        if: needs.changes.outputs.%s == 'true'\n        run: cat x\n")
        for cond, raises in (("full", True), ("sdk", True), ("beyond_site", False)):
            root = self.fixture({ch.CI_YML: "jobs:\n" + jobs.replace("  test-coverage:\n    runs-on: x\n",
                                                                     step % cond)})
            if raises:
                with self.assertRaises(RuntimeError, msg=cond):
                    ch._skippable_ci_text(root)
            else:
                self.assertEqual(ch._skippable_ci_text(root), "")
                self.assertIn("run: cat x", ch._site_skipped_ci_text(root))

    def test_a_site_skipped_job_s_step_skipped_on_another_output_fails_the_audit(self):
        # In review: a site-skipped job is in neither the allowlist's measurement
        # nor (for a step skipped on full) the site's, so such a step's reads would go unmeasured.
        jobs = "".join("  %s:\n    runs-on: x\n" % j for j in ch.ALWAYS_RUN_JOBS + ch.SITE_SKIPPED_JOBS)
        core = ("  test-core:\n    runs-on: x\n    steps:\n      - name: Read\n"
                "        if: needs.changes.outputs.%s == 'true'\n        run: wc -l docs/reference/API.md\n")
        first = ("  test-core:\n    runs-on: x\n    steps:\n      - if: needs.changes.outputs.%s == 'true'\n"
                 "        run: wc -l docs/reference/API.md\n")
        for step in (core, first):
            for cond, raises in (("full", True), ("oid4vp", True), ("sdk", True), ("beyond_site", False)):
                root = self.fixture({ch.CI_YML: "jobs:\n" + jobs.replace("  test-core:\n    runs-on: x\n",
                                                                         step % cond)})
                if raises:
                    with self.assertRaises(RuntimeError, msg=(step, cond)):
                        ch._skippable_ci_text(root)
                else:
                    self.assertEqual(ch._skippable_ci_text(root), "")

    def test_an_always_run_job_that_needs_a_skippable_one_fails_the_audit(self):
        # In review: GitHub skips a job whose need was skipped, so an always-run
        # job may need only always-run jobs, unless it is a gate (`if: always()`, exactly).
        jobs = "".join("  %s:\n    runs-on: x\n" % j for j in ch.ALWAYS_RUN_JOBS + ch.SITE_SKIPPED_JOBS)
        for needs in ("    needs: [sdk-typescript]\n", "    needs: [changes, sdk-typescript]\n",
                      "    needs: sdk-typescript\n", "    needs: [docker-image]\n"):
            root = self.fixture({ch.CI_YML: "jobs:\n" + jobs.replace(
                "  product-boundary:\n    runs-on: x\n", "  product-boundary:\n" + needs + "    runs-on: x\n")})
            with self.assertRaises(RuntimeError, msg=needs):
                ch._skippable_ci_text(root)
        for needs in ("    needs: [changes]\n", "    needs: changes\n", "    needs: ['changes', \"dco\"]\n",
                      "    needs: [changes, sdk-typescript]\n    if: always()\n"):
            root = self.fixture({ch.CI_YML: "jobs:\n" + jobs.replace(
                "  product-boundary:\n    runs-on: x\n", "  product-boundary:\n" + needs + "    runs-on: x\n")})
            self.assertEqual(ch._skippable_ci_text(root), "", needs)
        self.assertEqual(ch._needs("    needs: [changes, 'test-core']\n    runs-on: x\n"), ["changes", "test-core"])
        self.assertEqual(ch._needs("    runs-on: x\n"), [])
        # In review: a need this cannot read whole raises, rather than
        # being read in part: any form but the one-line ones, a quoted key, a comment anywhere.
        for needs in ("    needs:\n      - changes\n      - sdk-typescript\n",
                      "    needs:\n      - changes\n    # after the image\n      - sdk-typescript\n",
                      "    needs:\n      - changes\n      # wait for the SDK\n      - sdk-typescript\n",
                      "    needs: [changes,\n      sdk-typescript]\n", "    needs: [changes] # x\n",
                      "    needs:\n", "    needs: ${{ fromJSON('[]') }}\n", "    needs: *anchor\n",
                      "    \"needs\": [cve-scan]\n", "    'needs': cve-scan\n",
                      "    needs: [changes]\n    needs: [cve-scan]\n"):
            with self.assertRaises(RuntimeError, msg=needs):
                ch._needs(needs + "    runs-on: x\n")
            root = self.fixture({ch.CI_YML: "jobs:\n" + jobs.replace(
                "  osv-scan:\n    runs-on: x\n", "  osv-scan:\n" + needs + "    runs-on: x\n")})
            with self.assertRaises(RuntimeError, msg=needs):
                ch._skippable_ci_text(root)
        for gate in ("    if: always() && needs.cve-scan.result == 'success'\n", "    if: ${{ always() }}\n"):
            root = self.fixture({ch.CI_YML: "jobs:\n" + jobs.replace(
                "  osv-scan:\n    runs-on: x\n", "  osv-scan:\n    needs: [cve-scan]\n" + gate + "    runs-on: x\n")})
            with self.assertRaises(RuntimeError, msg=gate):
                ch._skippable_ci_text(root)

    def test_a_job_that_reads_the_changes_outputs_otherwise_fails_the_audit(self):
        # In review: only `if: needs.changes.outputs.beyond_site == 'true'`
        # on one line; a condition over two lines, a filter, or an output passed through env skips
        # as surely. A gate reads its needs only in the step that runs the gate script.
        jobs = "".join("  %s:\n    runs-on: x\n" % j for j in ch.ALWAYS_RUN_JOBS + ch.SITE_SKIPPED_JOBS)
        for step in ("      - name: Read\n        if: >-\n          needs.changes.outputs.full == 'true'\n"
                     "        run: wc -l docs/reference/API.md\n",
                     "      - name: Read\n        env:\n          FULL: ${{ needs.changes.outputs.full }}\n"
                     "        if: env.FULL == 'true'\n        run: wc -l docs/reference/API.md\n",
                     "      - name: Read\n        env:\n          ALL: ${{ toJSON(needs) }}\n"
                     "        run: python3 read.py\n",
                     "      - name: Read\n        if: needs['changes'].outputs.full == 'true'\n"
                     "        run: wc -l docs/reference/API.md\n",
                     "      - name: Read\n        if: contains(needs.*.outputs.full, 'true')\n"
                     "        run: wc -l docs/reference/API.md\n",
                     "      - name: Read\n        if: needs.changes.outputs.beyond_site == 'true' && true\n"
                     "        run: wc -l docs/reference/API.md\n",
                     "      - name: Read\n        env:\n          RESULTS: ${{ toJSON(needs) }}\n"
                     "        run: python3 read.py\n",
                     "      - name: Read\n        env:\n          RESULTS: ${{ toJSON(needs) }}\n"
                     "        run: python3 scripts/polaris-ci-gate.py\n"):
            for job in ("test-core", "invariants", "test-coverage-shard"):
                root = self.fixture({ch.CI_YML: "jobs:\n" + jobs.replace(
                    "  %s:\n    runs-on: x\n" % job, "  %s:\n    runs-on: x\n    steps:\n" % job + step)})
                with self.assertRaises(RuntimeError, msg=(job, step)):
                    ch._skippable_ci_text(root)
            if "polaris-ci-gate.py" in step:
                continue
            # A gate's other steps are held as any job's are.
            gate = "  test-coverage:\n    needs: [changes]\n    if: always()\n    runs-on: x\n    steps:\n" + step
            root = self.fixture({ch.CI_YML: "jobs:\n" + jobs.replace("  test-coverage:\n    runs-on: x\n", gate)})
            with self.assertRaises(RuntimeError, msg=("test-coverage", step)):
                ch._skippable_ci_text(root)
        # Nor may a job read them outside its steps.
        for job in ("test-core", "osv-scan"):
            root = self.fixture({ch.CI_YML: "jobs:\n" + jobs.replace(
                "  %s:\n    runs-on: x\n" % job,
                "  %s:\n    env:\n      FULL: ${{ needs.changes.outputs.full }}\n    runs-on: x\n" % job)})
            with self.assertRaises(RuntimeError, msg=job):
                ch._skippable_ci_text(root)
        # The one form, and a gate's gate step reading its needs, pass.
        ok = ("  test-core:\n    needs: [changes]\n    if: needs.changes.outputs.beyond_site == 'true'\n"
              "    runs-on: x\n    steps:\n      - if: needs.changes.outputs.beyond_site == 'true'\n"
              "        run: cat x\n")
        gate = ("  test:\n    needs:\n      - changes\n      - test-core\n    if: always()\n    runs-on: x\n"
                "    steps:\n      - name: Gate\n        env:\n          RESULTS: ${{ toJSON(needs) }}\n"
                "        run: python3 scripts/polaris-ci-gate.py --changes changes\n")
        text = jobs.replace("  test-core:\n    runs-on: x\n", ok).replace("  test:\n    runs-on: x\n", gate)
        self.assertEqual(ch._skippable_ci_text(self.fixture({ch.CI_YML: "jobs:\n" + text})), "")

    def test_a_job_laid_out_otherwise_fails_the_audit(self):
        # In review: a compact step list, a quoted key or keys at another indent is
        # valid YAML that the rules, reading keys at four spaces and steps at six, would read past.
        jobs = "".join("  %s:\n    runs-on: x\n" % j for j in ch.ALWAYS_RUN_JOBS + ch.SITE_SKIPPED_JOBS)
        for job, block in (
                ("osv-scan", "  osv-scan:\n    needs: [changes]\n    runs-on: x\n    steps:\n    - name: The site page\n"
                             "      if: needs.changes.outputs.full == 'true'\n      run: wc -l site/index.html\n"),
                ("test-core", "  test-core:\n    runs-on: x\n    steps:\n    - run: cat x\n"),
                ("osv-scan", "  osv-scan:\n      needs: [cve-scan]\n      runs-on: x\n"),
                ("invariants", "  invariants:\n    \"if\": github.event_name == 'push'\n    runs-on: x\n"),
                ("dco", "  dco:\n    runs-on: x\n    steps:  # the sign-off\n      - run: cat x\n"),
                ("dco", "  dco:\n    runs-on: x\n    steps:\n        - run: cat x\n"),
                ("dco", "  dco:\n    runs-on: x\n     timeout-minutes: 5\n"),
                ("test-coverage", "  test-coverage:\n    runs-on: x\n    steps:\n      -   name: Read the page\n"
                                  "          if: needs.changes.outputs.beyond_site == 'true'\n"
                                  "          run: wc -l site/index.html\n"),
                ("dco", "  dco:\n    runs-on: x\n    steps:\n      -\n        run: cat x\n")):
            root = self.fixture({ch.CI_YML: "jobs:\n" + jobs.replace("  %s:\n    runs-on: x\n" % job, block)})
            with self.assertRaises(RuntimeError, msg=block):
                ch._skippable_ci_text(root)
        # The gate exemption is the RESULTS line of the step that runs the gate script, as each of
        # ci.yml's gates writes it; not a job-level env, and not a step that only names the script.
        gate = ("  test:\n    # Runs scripts/polaris-ci-gate.py\n    needs: [changes]\n    if: always()\n%s"
                "    runs-on: x\n    steps:\n      - name: Gate\n%s")
        step = "        env:\n          RESULTS: ${{ toJSON(needs) }}\n"
        for job_env, gate_step in (
                ("    env:\n      RESULTS: ${{ toJSON(needs) }}\n", "        run: python3 scripts/polaris-ci-gate.py\n"),
                ("", step + "        run: python3 scripts/polaris-ci-gate.py\n    env:\n      RESULTS: ${{ toJSON(needs) }}\n"),
                ("", step + "        run: python3 read.py  # not scripts/polaris-ci-gate.py\n"),
                ("", step + "        # python3 scripts/polaris-ci-gate.py\n        run: python3 read.py\n")):
            root = self.fixture({ch.CI_YML: "jobs:\n" + jobs.replace(
                "  test:\n    runs-on: x\n", gate % (job_env, gate_step))})
            with self.assertRaises(RuntimeError, msg=(job_env, gate_step)):
                ch._skippable_ci_text(root)
        for gate_step in (step + "        run: python3 scripts/polaris-ci-gate.py --changes changes\n",
                          step + "        run: python scripts/polaris-ci-gate.py --changes changes\n",
                          step + "        run: >-\n          python3 scripts/polaris-ci-gate.py --changes changes\n"
                                 "          --always test-coverage\n"):
            root = self.fixture({ch.CI_YML: "jobs:\n" + jobs.replace("  test:\n    runs-on: x\n", gate % ("", gate_step))})
            self.assertEqual(ch._skippable_ci_text(root), "", gate_step)

    def test_an_always_run_only_script_a_skippable_job_runs_is_caught(self):
        # The audit's second half: a script declared always-run-only that a skippable job names.
        root = self.fixture({"scripts/polaris-review-packet-drill.py": "x = 1\n",
                             "scripts/b.sh": "python3 scripts/polaris-review-packet-drill.py\n",
                             "scripts/c.sh": "true\n"})
        refs = ch.references(root, ["scripts/b.sh", "scripts/c.sh"],
                             ["scripts/polaris-review-packet-drill.py"], exact=True)
        self.assertEqual(refs, {"scripts/polaris-review-packet-drill.py": ["scripts/b.sh"]})

    def test_a_workflow_a_skippable_job_calls_is_measured(self):
        # 2026-10-21: the image CVE scan's steps moved into a workflow ci.yml's image-cve-scan job
        # calls. A called workflow runs as the job that calls it, so it is skippable code, and so is
        # one it calls; a workflow only an always-run job calls, or none, is not, as before.
        jobs = "".join("  %s:\n    runs-on: x\n" % j for j in ch.ALWAYS_RUN_JOBS + ch.SITE_SKIPPED_JOBS)
        reads = "jobs:\n  s:\n    runs-on: x\n    steps:\n      - run: wc -l docs/reference/API.md\n"
        root = self.fixture({
            ch.CI_YML: "jobs:\n" + jobs.replace("  test-core:\n    runs-on: x\n",
                                                "  test-core:\n    uses: ./.github/workflows/always.yml\n")
                       + "  scan:\n    uses: ./.github/workflows/scan.yml  # a comment\n",
            ".github/workflows/scan.yml": "on:\n  workflow_call:\njobs:\n  s:\n    uses: ./.github/workflows/inner.yml\n",
            ".github/workflows/inner.yml": reads,
            ".github/workflows/always.yml": reads,
            ".github/workflows/other.yml": reads})
        code = ch.skippable_code(ch._tracked(root), root)
        for rel in (".github/workflows/scan.yml", ".github/workflows/inner.yml"):
            self.assertIn(rel, code)
        for rel in (".github/workflows/always.yml", ".github/workflows/other.yml"):
            self.assertNotIn(rel, code)
        problems = ch.audit(root, out=io.StringIO())
        self.assertIn("docs/reference/API.md is on the allowlist but .github/workflows/inner.yml names it", problems)
        # A call to a workflow that is not there is a problem, not a file to skip.
        (root / ".github/workflows/inner.yml").unlink()
        problems = ch.audit(root, out=io.StringIO())
        self.assertIn("a skippable job calls .github/workflows/inner.yml, which is not tracked, so what it runs "
                      "is unmeasured", problems)


INVARIANTS = ("  invariants:\n    runs-on: x\n    steps:\n"
              "      - name: The invariant layer\n        run: python3 -m polaris_checks.run\n"
              "      - name: Each check fails on its broken fixture\n        run: |\n"
              "          # pytest, and PyYAML\n"
              "          pip install --require-hashes -r polaris_web/requirements-test.txt\n"
              "          python3 -m pytest polaris_checks/test_checks.py -q -p no:cacheprovider\n"
              "      - name: polaris-link-check\n        run: bash scripts/polaris-link-check.sh --ci\n")
LINK = "      - name: polaris-link-check\n        run: bash scripts/polaris-link-check.sh --ci\n"
WORKFLOW = 'on:\n  pull_request:\n\nenv:\n  PYTHONUNBUFFERED: "1"\n\njobs:\n'


class TheSiteMeasurement(unittest.TestCase):
    """2026-11-17: no file a site-skipped job may run names a site-only path, and the jobs a
    site-only change still runs do the site's checks."""

    def fixture(self, files, jobs=None, invariants=INVARIANTS, site=True, workflow=WORKFLOW, ship=True):
        root = pathlib.Path(tempfile.mkdtemp(prefix="polaris-ci-site-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        jobs = jobs or {}
        text = "".join(jobs.get(j, "  %s:\n    runs-on: x\n" % j)
                       for j in ch.ALWAYS_RUN_JOBS + ch.SITE_SKIPPED_JOBS if j != "invariants")
        base = {ch.CI_YML: workflow + text + invariants, "site/polaris_logo.webp": "x\n",
                "docs/reference/API.md": "# API\n"}
        if site:
            base["site/index.html"] = "<p>x</p>\n"
        if ship:
            base.update({p: "x\n" for p in ch.SITE_SHIP_FILES})
        _write(root, dict(base, **files))
        return ch.audit(root, out=io.StringIO())

    def test_this_tree_measures_clean(self):
        out = io.StringIO()
        self.assertEqual(ch.audit(ROOT, out=out), [])
        self.assertRegex(out.getvalue(), r"site: [1-9][0-9]* site-only file\(s\) against [1-9][0-9]* file\(s\)")

    def test_a_script_a_site_skipped_job_runs_that_opens_a_site_file_is_caught(self):
        # polaris-coverage.sh runs only in jobs the allowlist never skips, so the allowlist's
        # measurement leaves it out; the coverage shards are skipped on a site-only change.
        problems = self.fixture({"scripts/polaris-coverage.sh": "cat site/index.html\n"})
        self.assertIn("site/index.html is site-only but scripts/polaris-coverage.sh names it", problems)
        self.assertNotIn("site/index.html is site-only but scripts/polaris-coverage.sh names it",
                         self.fixture({"scripts/polaris-coverage.sh": "cat docs/reference/API.md\n"}))

    def test_a_site_skipped_job_or_step_that_opens_a_site_file_is_caught(self):
        core = ("  test-core:\n    needs: [changes]\n    if: needs.changes.outputs.beyond_site == 'true'\n"
                "    runs-on: x\n    steps:\n      - run: wc -l site/index.html\n")
        problems = self.fixture({}, jobs={"test-core": core})
        self.assertIn("site/index.html is site-only but .github/workflows/ci.yml names it", problems)
        self.assertNotIn("site/index.html is on the allowlist but .github/workflows/ci.yml names it", problems)
        floor = ("  test-coverage:\n    runs-on: x\n    steps:\n      - name: Floor\n"
                 "        if: needs.changes.outputs.beyond_site == 'true'\n        run: wc -l site/index.html\n")
        self.assertIn("site/index.html is site-only but .github/workflows/ci.yml names it",
                      self.fixture({}, jobs={"test-coverage": floor}))
        # The same step with its `if:` as its first key.
        first = ("  test-coverage:\n    runs-on: x\n    steps:\n      - if: needs.changes.outputs.beyond_site == 'true'\n"
                 "        run: wc -l site/index.html\n")
        self.assertIn("site/index.html is site-only but .github/workflows/ci.yml names it",
                      self.fixture({}, jobs={"test-coverage": first}))
        # A step of a job a site-only change still runs reads what it likes.
        kept = ("  test-coverage:\n    runs-on: x\n    steps:\n      - name: Gate\n        run: wc -l site/index.html\n")
        self.assertNotIn("site/index.html is site-only but .github/workflows/ci.yml names it",
                         self.fixture({}, jobs={"test-coverage": kept}))

    def test_a_site_skipped_script_that_opens_what_a_site_change_carries_is_caught(self):
        for target, read in (("CHANGELOG.md", "head -1 CHANGELOG.md\n"),
                             ("docs/reference/claims.json", "jq . docs/reference/claims.json\n"),
                             ("docs/reference/claims.json", "ls docs/reference/\n")):
            caught = "%s is site-only but scripts/polaris-coverage.sh names it" % target
            self.assertIn(caught, self.fixture({"scripts/polaris-coverage.sh": read}), read)
            self.assertNotIn(caught, self.fixture({"scripts/polaris-coverage.sh": "cat docs/operator/DR.md\n"}))
        # A job a site-only change skips, the same.
        core = ("  test-core:\n    needs: [changes]\n    if: needs.changes.outputs.beyond_site == 'true'\n"
                "    runs-on: x\n    steps:\n      - run: head -1 CHANGELOG.md\n")
        self.assertIn("CHANGELOG.md is site-only but .github/workflows/ci.yml names it",
                      self.fixture({}, jobs={"test-core": core}))
        # Each must be there to be measured.
        for p in ch.SITE_SHIP_FILES:
            absent = "%s is a file a site change carries, but is not tracked" % p
            self.assertNotIn(absent, self.fixture({}))
            self.assertIn(absent, self.fixture({q: "x\n" for q in ch.SITE_SHIP_FILES if q != p}, ship=False))

    def test_a_mention_reviewed_for_the_site_is_reviewed_for_the_site_alone(self):
        # SITE_REVIEWED_MENTIONS excuses a mention in the site measurement, by file and token, and
        # nowhere else: the allowlist's measurement still counts the same mention.
        script, caught = "scripts/polaris-release-notes.sh", "CHANGELOG.md is site-only but %s names it"
        self.assertIn((script, "CHANGELOG.md"), ch.SITE_REVIEWED_MENTIONS)
        self.assertNotIn((script, "CHANGELOG.md"), ch.REVIEWED_MENTIONS)
        self.assertFalse(set(ch.SITE_REVIEWED_MENTIONS) & set(ch.REVIEWED_MENTIONS))
        root = pathlib.Path(tempfile.mkdtemp(prefix="polaris-ci-site-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        _write(root, {script: "head -1 CHANGELOG.md\n", "scripts/other.sh": "head -1 CHANGELOG.md\n",
                      "CHANGELOG.md": "x\n"})
        code = [script, "scripts/other.sh"]
        self.assertEqual(ch.references(root, code, ["CHANGELOG.md"]), {"CHANGELOG.md": ["scripts/other.sh", script]})
        self.assertEqual(ch.references(root, code, ["CHANGELOG.md"], reviewed=ch.SITE_REVIEWED_MENTIONS),
                         {"CHANGELOG.md": ["scripts/other.sh"]})
        # Another token of a reviewed file is still counted.
        _write(root, {script: "head -1 docs/reference/claims.json\n", "docs/reference/claims.json": "{}\n"})
        self.assertEqual(ch.references(root, [script], ["docs/reference/claims.json"],
                                       reviewed=ch.SITE_REVIEWED_MENTIONS),
                         {"docs/reference/claims.json": [script]})
        self.assertIn(caught % "scripts/polaris-coverage.sh",
                      self.fixture({"scripts/polaris-coverage.sh": "head -1 CHANGELOG.md\n"}))
        # Every reviewed file is one the tree holds.
        gone = "REVIEWED_MENTIONS names scripts/gone.sh, which is not tracked"
        self.assertNotIn(gone, self.fixture({}))
        with unittest.mock.patch.dict(ch.SITE_REVIEWED_MENTIONS, {("scripts/gone.sh", "CHANGELOG.md"): "x"}):
            self.assertIn(gone, self.fixture({}))

    def test_the_emblem_an_example_serves_is_not_site_only(self):
        problems = self.fixture({"packages/x/app.py": 'LOGO = ROOT / "site" / "polaris_logo.webp"\n'})
        self.assertEqual([p for p in problems if "is site-only" in p], [])

    def test_the_site_only_class_rests_on_the_invariant_checks_job(self):
        self.assertEqual([p for p in self.fixture({}) if "invariant checks job" in p], [])
        # What each pin runs (test_this_tree_measures_clean finds the pins in ci.yml itself).
        self.assertEqual([s[-1].strip() for s in ch.SITE_ONLY_RESTS_ON["invariants"]],
                         ["run: python3 -m polaris_checks.run",
                          "python3 -m pytest polaris_checks/test_checks.py -q -p no:cacheprovider",
                          "run: bash scripts/polaris-link-check.sh --ci"])
        for step in ch.SITE_ONLY_RESTS_ON["invariants"]:
            lines = INVARIANTS.splitlines(keepends=True)
            gone = "".join(l for l in lines if l.rstrip("\n") != step[-1])
            commented = "".join(re.sub(r"^(\s*)", r"\1# ", l) if l.rstrip("\n") == step[-1] else l for l in lines)
            for inv in (gone, commented):
                self.assertIn("the invariant checks job does not hold the step `%s` as pinned, which a site-only "
                              "change relies on" % step[-1].strip(), self.fixture({}, invariants=inv))

    def test_what_the_class_rests_on_must_run_as_pinned(self):
        # In review: a step that may be skipped or may not fail, that does not run the
        # command as itself, or that runs it with a flag that ends it early, is not the step the
        # class rests on, however the command is spelled inside it.
        absent = ("the invariant checks job does not hold the step `run: bash scripts/polaris-link-check.sh --ci` "
                  "as pinned, which a site-only change relies on")
        for step in ("      - if: needs.changes.outputs.beyond_site == 'true'\n"
                     "        run: bash scripts/polaris-link-check.sh --ci\n",
                     "      - name: Links\n        if: needs.changes.outputs.beyond_site == 'true'\n"
                     "        run: bash scripts/polaris-link-check.sh --ci\n",
                     "      - name: Links\n        continue-on-error: true\n"
                     "        run: bash scripts/polaris-link-check.sh --ci\n",
                     "      - name: Links\n        shell: bash {0}\n        run: bash scripts/polaris-link-check.sh --ci\n",
                     "      - name: Links\n        env:\n          X: y\n        run: bash scripts/polaris-link-check.sh --ci\n",
                     "      - name: Links\n        run: bash scripts/polaris-link-check.sh --ci || true\n",
                     "      - name: Links\n        run: bash scripts/polaris-link-check.sh --ci --help\n",
                     "      - name: Links\n        run: >-\n          bash scripts/polaris-link-check.sh --ci\n"
                     "          || true\n",
                     "      - name: Links\n        run: |\n          true ||\n          bash scripts/polaris-link-check.sh --ci\n",
                     "      - name: Links\n        run: |\n          set +e\n          bash scripts/polaris-link-check.sh --ci\n",
                     "      - name: bash scripts/polaris-link-check.sh --ci\n        run: echo skipped\n",
                     "      - run: bash scripts/polaris-link-check.sh --ci\n"):
            self.assertIn(absent, self.fixture({}, invariants=INVARIANTS.replace(LINK, step)), step)
        # Its name and its comments are its own.
        for step in ("      - name: Links, renamed\n        run: bash scripts/polaris-link-check.sh --ci\n",
                     "      - name: Links\n        # why\n        run: bash scripts/polaris-link-check.sh --ci\n\n"):
            self.assertNotIn(absent, self.fixture({}, invariants=INVARIANTS.replace(LINK, step)), step)
        whole = ("the invariant checks job carries an `if:`, a `continue-on-error:`, `defaults:` or `env:`, so what "
                 "a site-only change relies on may not run as pinned, or may fail without failing the job")
        for key in ("    continue-on-error: true\n", "    if: github.event_name == 'push'\n",
                    "    defaults:\n      run:\n        shell: bash {0}\n",
                    "    env:\n      PYTEST_ADDOPTS: --collect-only\n"):
            inv = INVARIANTS.replace("  invariants:\n", "  invariants:\n" + key)
            self.assertIn(whole, self.fixture({}, invariants=inv), key)
        self.assertNotIn(whole, self.fixture({}))

    def test_what_the_pinned_steps_run_in_is_pinned_too(self):
        # In review: the steps' text pinned, an environment set around them (the
        # workflow's env, a write to $GITHUB_ENV or $GITHUB_PATH) still changes what they run.
        baseline = self.fixture({})
        workflow = ("%s's top-level `env:` is not WORKFLOW_ENV, or it carries `defaults:`, so the steps a site-only "
                    "change relies on may not run as pinned" % ch.CI_YML)
        self.assertNotIn(workflow, baseline)
        for old, new in (('  PYTHONUNBUFFERED: "1"\n', '  PYTHONUNBUFFERED: "1"\n  PYTEST_ADDOPTS: "--collect-only"\n'),
                         ('  PYTHONUNBUFFERED: "1"\n', '  PYTHONUNBUFFERED: "0"\n'),
                         ('env:\n  PYTHONUNBUFFERED: "1"\n', ""),
                         ("\njobs:\n", "\ndefaults:\n  run:\n    shell: bash {0}\n\njobs:\n"),
                         ("\njobs:\n", "\nenv:\n  BASH_ENV: x\n\njobs:\n"),
                         ('  PYTHONUNBUFFERED: "1"\n',
                          '  PYTHONUNBUFFERED: "1"\n# quieter logs\n  PYTEST_ADDOPTS: "--collect-only"\n')):
            self.assertIn(workflow, self.fixture({}, workflow=WORKFLOW.replace(old, new)), new)
        self.assertNotIn(workflow, self.fixture({}, workflow=WORKFLOW.replace('env:\n', 'env:\n  # unbuffered, for the logs\n')))
        writes = ("a line of the invariant checks job names $GITHUB_ENV or $GITHUB_PATH, through which a step "
                  "changes what the steps a site-only change relies on run in")
        self.assertNotIn(writes, baseline)
        for step in ('      - name: Quiet\n        run: echo "PYTEST_ADDOPTS=--collect-only" >> "$GITHUB_ENV"\n',
                     "      - name: Path\n        run: echo /opt/x >> $GITHUB_PATH\n",
                     "      - name: Quiet\n        run: |\n          echo PYTEST_ADDOPTS=-x >> ${GITHUB_ENV}\n"):
            self.assertIn(writes, self.fixture({}, invariants=INVARIANTS + step), step)
        self.assertNotIn(writes, self.fixture({}, invariants=INVARIANTS + "      # never write GITHUB_ENV here\n"))

    def test_the_site_measurement_covers_something_and_only_allowlisted_paths(self):
        # In review: the audit's other site lines, each made to fire.
        problems = self.fixture({}, site=False)
        self.assertIn("no tracked file is site-only, so the site measurement covers nothing", problems)
        off = tuple(e for e in ch.ALLOWLIST if e != "site/")
        with mock.patch.object(ch, "ALLOWLIST", off):
            problems = self.fixture({})
        self.assertIn("site/index.html is site-only but not on the allowlist", problems)
        self.assertNotIn("site/index.html is site-only but not on the allowlist", self.fixture({}))


if __name__ == "__main__":
    unittest.main()
