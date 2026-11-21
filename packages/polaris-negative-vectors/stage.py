#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Stage the polaris-negative-vectors npm package, or check a staged one.

  python3 packages/polaris-negative-vectors/stage.py OUT           stage into OUT (absent or empty)
  python3 packages/polaris-negative-vectors/stage.py --check DIR   check a staged directory, or the package/
                                                                   directory of an unpacked tarball

Staging copies package.json, README.md, LICENSE and NOTICE from this directory, and vectors.json and
mdoc-vectors.json from lab/interop/negative-vectors byte for byte, then writes manifest.json: the package's name
and version, and for each vector file its path, its own version, its size in bytes and its SHA-256. The vector
files are never committed here; this script is their one way in.

--check holds a directory to the same: exactly those seven files; each copied file and each vector file
byte-equal to its source; the manifest's name and version equal to package.json's and its rows equal to the bytes
beside it; package.json with no scripts, dependencies, binaries or entry points, and with the files and exports this
script expects. It prints each problem on its own line, then "done", and exits 1 on any problem.
"""
import hashlib
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.join(HERE, "..", "..", "lab", "interop", "negative-vectors")
COPIED = ("package.json", "README.md", "LICENSE", "NOTICE")
VECTORS = ("vectors.json", "mdoc-vectors.json")
MANIFEST = "manifest.json"
EXPECTED = frozenset(COPIED + VECTORS + (MANIFEST,))
FILES = ["vectors.json", "mdoc-vectors.json", "manifest.json", "NOTICE", "LICENSE"]
# Every JSON file the package ships is exported, and nothing else: NOTICE, README.md, LICENSE and the bare name resolve
# to nothing. One pattern, so the committed package.json names no file that exists only once staged.
EXPORTS = {"./*.json": "./*.json"}
# Fields that would make installing or importing the package run or fetch something.
FORBIDDEN = ("scripts", "dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
             "bundleDependencies", "bundledDependencies", "bin", "main", "module", "browser", "gypfile")


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def manifest(pkg, data):
    """The manifest for package.json's parsed dict and {vector file name: bytes}."""
    return {
        "name": pkg["name"],
        "version": pkg["version"],
        "files": [{"path": n, "version": json.loads(data[n].decode("utf-8"))["version"], "bytes": len(data[n]),
                   "sha256": hashlib.sha256(data[n]).hexdigest()} for n in VECTORS],
    }


def stage(out):
    if os.path.exists(out) and os.listdir(out):
        raise SystemExit("stage: %s is not empty" % out)
    os.makedirs(out, exist_ok=True)
    for n in COPIED:
        shutil.copyfile(os.path.join(HERE, n), os.path.join(out, n))
    data = {}
    for n in VECTORS:
        data[n] = _read(os.path.join(LAB, n))
        with open(os.path.join(out, n), "wb") as f:
            f.write(data[n])
    pkg = json.loads(_read(os.path.join(HERE, "package.json")).decode("utf-8"))
    with open(os.path.join(out, MANIFEST), "w") as f:
        json.dump(manifest(pkg, data), f, indent=1)
        f.write("\n")


def check(d):
    """Every problem with the staged directory d, as a list of lines; empty when it is the package."""
    problems = []
    present = set()
    for top, dirs, files in os.walk(d):
        for n in files + [x for x in dirs if os.path.islink(os.path.join(top, x))]:
            present.add(os.path.relpath(os.path.join(top, n), d))
    if not present:
        return ["%s holds no file" % d]
    for n in sorted(present - EXPECTED):
        problems.append("an extra file: %s" % n)
    for n in sorted(EXPECTED - present):
        problems.append("a missing file: %s" % n)
    if problems:
        return problems
    for n in COPIED:
        if _read(os.path.join(d, n)) != _read(os.path.join(HERE, n)):
            problems.append("%s differs from packages/polaris-negative-vectors/%s" % (n, n))
    data = {}
    for n in VECTORS:
        data[n] = _read(os.path.join(d, n))
        if data[n] != _read(os.path.join(LAB, n)):
            problems.append("%s differs from lab/interop/negative-vectors/%s" % (n, n))
    try:
        pkg = json.loads(_read(os.path.join(d, "package.json")).decode("utf-8"))
        got = json.loads(_read(os.path.join(d, MANIFEST)).decode("utf-8"))
        want = manifest(pkg, data)
    except (ValueError, KeyError, TypeError) as e:
        return problems + ["package.json, manifest.json or a vector file does not parse: %s" % e]
    if got != want:
        problems.append("manifest.json is not the manifest of these bytes: %s, want %s" % (
            json.dumps(got, sort_keys=True)[:300], json.dumps(want, sort_keys=True)[:300]))
    for k in FORBIDDEN:
        if k in pkg:
            problems.append("package.json has %r" % k)
    if pkg.get("files") != FILES:
        problems.append("package.json files is %r, want %r" % (pkg.get("files"), FILES))
    if pkg.get("exports") != EXPORTS:
        problems.append("package.json exports is %r, want %r" % (pkg.get("exports"), EXPORTS))
    return problems


def main(argv):
    if len(argv) == 2 and argv[0] == "--check":
        problems = check(argv[1])
        for p in problems:
            print(p)
        print("done")
        return 1 if problems else 0
    if len(argv) == 1 and not argv[0].startswith("-"):
        stage(argv[0])
        problems = check(argv[0])
        for p in problems:
            print(p)
        print("staged %s" % argv[0] if not problems else "staged with problems")
        print("done")
        return 1 if problems else 0
    print(__doc__.strip().split("\n\n")[1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
