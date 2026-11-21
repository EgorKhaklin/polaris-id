# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""packages/polaris-negative-vectors: the package stages byte for byte from lab/interop/negative-vectors, npm packs
exactly its seven files, the packed tarball passes the same check, and once installed into an empty project the files
read through its exports and nothing else does. Each check that passes on a good stage is shown refusing a broken one
(one byte changed, a file added, a script added, an empty directory). Needs node and npm; no network, no database."""
import importlib.util
import json
import os
import pathlib
import subprocess
import tarfile
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
LAB = HERE.parent.parent / "lab" / "interop" / "negative-vectors"
_spec = importlib.util.spec_from_file_location("negvec_stage", HERE / "stage.py")
stage = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(stage)


class Package(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.t = pathlib.Path(os.path.realpath(tmp.name))
        self.out = self.t / "staged"
        stage.stage(str(self.out))
        rc = self.t / "npmrc"
        rc.write_text("")
        # npm reads no user config and no shared cache here: the run is the same on any machine.
        self.env = {k: v for k, v in os.environ.items() if not k.lower().startswith("npm_config_")}
        self.env.update(npm_config_userconfig=str(rc), npm_config_cache=str(self.t / "npm-cache"),
                        npm_config_update_notifier="false", npm_config_fund="false", npm_config_audit="false")

    def run_ok(self, cmd, cwd):
        r = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, env=self.env)
        self.assertEqual(r.returncode, 0, "%s: %s %s" % (" ".join(cmd), r.stdout[-400:], r.stderr[-800:]))
        return r.stdout

    def test_a_stage_passes_its_check_and_carries_the_lab_bytes(self):
        self.assertEqual(stage.check(str(self.out)), [])
        for n in stage.VECTORS:
            self.assertEqual((self.out / n).read_bytes(), (LAB / n).read_bytes())
        m = json.loads((self.out / "manifest.json").read_text())
        self.assertEqual([f["path"] for f in m["files"]], list(stage.VECTORS))
        for f in m["files"]:
            self.assertEqual(f["version"], json.loads((LAB / f["path"]).read_text())["version"])

    def test_npm_packs_exactly_the_seven_files(self):
        got = json.loads(self.run_ok(["npm", "pack", "--dry-run", "--json"], self.out))
        self.assertEqual(len(got), 1)
        self.assertEqual({f["path"] for f in got[0]["files"]}, set(stage.EXPECTED))

    def test_the_staged_manifest_names_exactly_the_files_staged(self):
        pkg = json.loads((self.out / "package.json").read_text())
        # npm always packs package.json, README.md and LICENSE; `files` names the rest, and nothing else is staged.
        self.assertEqual(set(pkg["files"]) | {"package.json", "README.md", "LICENSE"}, set(os.listdir(str(self.out))))
        self.assertEqual(set(pkg["files"]) | {"package.json", "README.md", "LICENSE"}, set(stage.EXPECTED))

    def test_the_packed_tarball_passes_the_check_and_reads_through_its_exports_once_installed(self):
        dest = self.t / "tgz"
        dest.mkdir()
        self.run_ok(["npm", "pack", "--pack-destination", str(dest)], self.out)
        tgz = list(dest.glob("*.tgz"))
        self.assertEqual(len(tgz), 1, tgz)
        with tarfile.open(str(tgz[0])) as tf:
            names = tf.getnames()
            self.assertTrue(all(n.startswith("package/") and ".." not in n for n in names), names)
            tf.extractall(str(self.t / "unpacked"), filter="data")
        self.assertEqual(stage.check(str(self.t / "unpacked" / "package")), [])
        proj = self.t / "probe"
        proj.mkdir()
        (proj / "package.json").write_text('{"name": "probe", "version": "0.0.0", "private": true}\n')
        self.run_ok(["npm", "install", "--offline", "--ignore-scripts", "--no-package-lock", str(tgz[0])], proj)
        want = {n: json.loads((LAB / n).read_text())["version"] for n in stage.VECTORS}
        cjs = self.run_ok(["node", "-e", "process.stdout.write(require('polaris-negative-vectors/vectors.json')"
                                         ".version)"], proj)
        self.assertEqual(cjs, want["vectors.json"])
        esm = self.run_ok(["node", "--input-type=module", "-e",
                           "import v from 'polaris-negative-vectors/mdoc-vectors.json' with { type: 'json' };"
                           " process.stdout.write(v.version)"], proj)
        self.assertEqual(esm, want["mdoc-vectors.json"])
        man = json.loads(self.run_ok(["node", "-e", "process.stdout.write(JSON.stringify(require("
                                                    "'polaris-negative-vectors/manifest.json')))"], proj))
        self.assertEqual(man, json.loads((self.out / "manifest.json").read_text()))
        # Every JSON file staged reads through the one pattern; nothing to run: the bare name and every other file
        # resolve to nothing.
        staged_json = sorted(n for n in os.listdir(str(self.out)) if n.endswith(".json"))
        self.assertEqual(staged_json, ["manifest.json", "mdoc-vectors.json", "package.json", "vectors.json"])
        for n in staged_json:
            got = self.run_ok(["node", "-e", "process.stdout.write(JSON.stringify(require("
                                             "'polaris-negative-vectors/%s')))" % n], proj)
            self.assertEqual(json.loads(got), json.loads((self.out / n).read_text()), n)
        for spec in ("polaris-negative-vectors", "polaris-negative-vectors/NOTICE",
                     "polaris-negative-vectors/README.md", "polaris-negative-vectors/LICENSE"):
            r = subprocess.run(["node", "-e", "require(%s)" % json.dumps(spec)], cwd=str(proj), capture_output=True,
                               text=True, env=self.env)
            self.assertNotEqual(r.returncode, 0, spec)
            self.assertIn("ERR_PACKAGE_PATH_NOT_EXPORTED", r.stderr, spec)

    def test_one_byte_changed_in_a_vector_file_is_refused(self):
        p = self.out / "vectors.json"
        data = bytearray(p.read_bytes())
        data[len(data) // 2] ^= 0x01
        p.write_bytes(bytes(data))
        problems = stage.check(str(self.out))
        self.assertTrue([x for x in problems if x.startswith("vectors.json differs from lab")], problems)
        self.assertTrue([x for x in problems if x.startswith("manifest.json is not the manifest")], problems)

    def test_one_byte_changed_in_the_manifest_is_refused(self):
        p = self.out / "manifest.json"
        text = p.read_text()
        i = text.index('"sha256": "') + len('"sha256": "')
        p.write_text(text[:i] + ("0" if text[i] != "0" else "1") + text[i + 1:])
        self.assertTrue([x for x in stage.check(str(self.out)) if x.startswith("manifest.json is not")])

    def test_a_copied_file_changed_is_refused(self):
        with open(str(self.out / "README.md"), "a") as f:
            f.write("\nInstall with a postinstall step.\n")
        self.assertEqual(stage.check(str(self.out)), ["README.md differs from packages/polaris-negative-vectors/README.md"])

    def test_a_missing_file_is_refused(self):
        (self.out / "NOTICE").unlink()
        self.assertEqual(stage.check(str(self.out)), ["a missing file: NOTICE"])

    def test_an_extra_file_is_refused(self):
        (self.out / "postinstall.js").write_text("console.log(1)\n")
        self.assertEqual(stage.check(str(self.out)), ["an extra file: postinstall.js"])

    def test_a_script_in_package_json_is_refused(self):
        p = self.out / "package.json"
        pkg = json.loads(p.read_text())
        pkg["scripts"] = {"postinstall": "node -e 1"}
        p.write_text(json.dumps(pkg))
        problems = stage.check(str(self.out))
        self.assertIn("package.json has 'scripts'", problems)

    def test_an_export_or_a_file_entry_added_is_refused(self):
        p = self.out / "package.json"
        pkg = json.loads(p.read_text())
        for key, extra, line in (("exports", {"./stage.py": "./stage.py"}, "package.json exports is"),
                                 ("files", ["stage.py"], "package.json files is")):
            changed = dict(pkg)
            changed[key] = dict(pkg[key], **extra) if isinstance(extra, dict) else pkg[key] + extra
            p.write_text(json.dumps(changed))
            problems = stage.check(str(self.out))
            self.assertTrue([x for x in problems if x.startswith(line)], (key, problems))
        p.write_text(json.dumps(pkg))

    def test_an_empty_directory_is_refused(self):
        empty = self.t / "empty"
        empty.mkdir()
        self.assertEqual(stage.check(str(empty)), ["%s holds no file" % empty])

    def test_staging_into_a_directory_that_is_not_empty_is_refused(self):
        with self.assertRaises(SystemExit):
            stage.stage(str(self.out))


if __name__ == "__main__":
    unittest.main()
