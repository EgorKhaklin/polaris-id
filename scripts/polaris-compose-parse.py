#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris-compose-parse.py [TREE]: every documented `docker compose -f ...` file set, parsed by this
host's Docker Compose.

The calls come from polaris_checks' extractor (check_documented_compose_files_resolve): fenced code
blocks in Markdown, shell scripts and workflows, aliases and `$(cd X && ...)` seen through, and the
overlays polaris.env's POLARIS_COMPOSE_EXTRA loads. Each distinct file set, with the flags that change
how it parses (--no-interpolate, --format, --profile), runs as `docker compose ... config --quiet`
with Docker pointed at a socket that does not exist: nothing starts, nothing is pulled, and only
the files are read. A file's required `${VAR:?...}` gets a placeholder, as polaris.env gives it on a
host. On 2026-10-10 two documented commands failed only when run: `config --no-interpolate`, which
Compose 2.38 refuses on the production file, and an HA alias whose overlay extends a service only the
blue-green file defines. CI runs this under the runner's Compose; on a host it is advisory, and it
prints the version it ran.

A Markdown block preceded by `<!-- compose-parse: expect-fail <reason> -->` is a failure on purpose.
Exits 1 when a set fails, when one meant to fail parses, or when fewer sets are read than the floor;
in CI, also when Docker Compose is missing. Prints a final "done" line.
"""
import os
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from polaris_checks import checks  # noqa: E402

# Files whose parse needs what the tree does not hold, each with its reason.
SKIP = {
    "lab/interop/eudi-issuer/compose.yaml": "it mounts ./upstream, which lab/interop/eudi-issuer/run.sh clones first",
}


def required(root, files):
    names = set()
    for f in files:
        names |= set(re.findall(r"\$\{([A-Z_][A-Z0-9_]*):?\?", (root / f).read_text(errors="replace")))
    return names


def main(argv):
    root = pathlib.Path(argv[1]).resolve() if len(argv) > 1 else ROOT
    in_ci = os.environ.get("CI") == "true"
    version = ""
    if shutil.which("docker"):
        r = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True)
        version = r.stdout.strip() if r.returncode == 0 else ""
    if not version:
        print("Docker Compose is not available here" + ("; in CI that is a failure" if in_ci else ": nothing parsed"))
        print("done")
        return 1 if in_ci else 0
    print(version)
    calls = [c for c in checks._compose_calls(root) if not c.dynamic]
    sets, skipped = {}, 0
    for c in calls:
        if any(f in SKIP for f in c.files):
            skipped += 1
            continue
        sets.setdefault((c.files, c.flags), []).append(c)
    if not calls or len(sets) < checks._COMPOSE_COMBO_FLOOR:
        print(f"FAIL: {len(calls)} calls with a static file set, {len(sets)} file sets to parse "
              f"(floor {checks._COMPOSE_COMBO_FLOOR}): the extractor read less than it did")
        print("done")
        return 1
    base = {k: v for k, v in os.environ.items() if not k.startswith(("COMPOSE_", "POLARIS_"))}
    base["DOCKER_HOST"] = "unix:///nonexistent/docker.sock"
    failed = 0
    for (files, flags), cs in sorted(sets.items()):
        env = dict(base, **{v: "x" for v in required(root, files)})
        for c in cs:   # a call's own prefix; one that is itself a variable is left to the file's default
            env.update({k: v for k, v in c.env if "$" not in v})
        profiles = [x for i, x in enumerate(flags) if flags[i - 1:i] == ("--profile",) or x == "--profile"]
        config = [x for x in flags if x not in profiles]
        cmd = ["docker", "compose", *profiles, *sum((["-f", str(root / f)] for f in files), []), "config", "--quiet", *config]
        r = subprocess.run(cmd, cwd=root / pathlib.PurePosixPath(files[0]).parent, env=env,
                           capture_output=True, text=True, timeout=120)
        meant = sorted({c.expect_fail for c in cs if c.expect_fail})
        where = ", ".join(f"{c.rel}:{c.line}" for c in cs[:6]) + (f" and {len(cs) - 6} more" if len(cs) > 6 else "")
        shown = " ".join(["-f " + f for f in files] + list(flags))
        if (r.returncode != 0) != bool(meant):   # failed unmarked, or parsed though marked to fail
            failed += 1
            why = (r.stderr.strip().splitlines() or ["parsed, but it is marked to fail: " + "; ".join(meant)])[-1]
            print(f"FAIL  {shown}\n      used at {where}\n      {why}")
        else:
            print(f"ok    {shown}  ({len(cs)} call{'s' if len(cs) != 1 else ''})")
    print(f"{len(sets)} file sets from {len(calls)} documented calls ({skipped} skipped: "
          + "; ".join(f"{k}: {v}" for k, v in SKIP.items()) + f"); {failed} failed")
    print("done")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
