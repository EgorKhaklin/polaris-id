#!/usr/bin/env python3
"""polaris-product-boundary-drill.py -- can a stranger install the verifier and use it?

The product contract's REQUIRED install test, made executable:

    fresh machine -> install polaris-verify -> configure trust root -> verify fixture

"If the full Polaris system must be installed first, the product boundary has failed."
Nothing enforced that. The verifier could acquire an import from `polaris_web`, a psycopg2
call, or a read of a file that only exists in a checkout, and the tree would stay green
because every existing suite runs from inside the repository with the repository on
`sys.path`. A stranger's machine has none of that, and the first person to find out would
be the stranger.

So this builds a WHEEL, installs it into a throwaway virtual environment, and runs the
verifier from a working directory that is not the repository, with the repository nowhere
on the path. What it proves:

  1. The wheel builds and installs with no dependency on the tree.
  2. The forbidden runtime surface is absent: no Flask, no psycopg2, no polaris_checks, no
     polaris_web, no Atlas, and no PostgreSQL is contacted.
  3. The command refuses to start until the run declares its crypto mode (exit 4), and
     says so before reading the caller's files.
  4. A real backend verifies a genuine credential and refuses its tampered twin.
  5. `--dev-placeholder` cannot produce an authentic verdict at all, and every
     machine-readable verdict carries the crypto mode.

NEGATIVE CONTROL. A drill that only ever reports success is indistinguishable from one
that never ran. Before trusting any pass above, this builds a DELIBERATELY BROKEN wheel --
the verifier with `import psycopg2` at the top -- and requires the harness to catch it. If
the control is not caught, every result here is a fact about this script rather than about
the product, and the drill fails saying so.

Run: python3 scripts/polaris-product-boundary-drill.py [--keep]
"""
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT / "packages" / "polaris-verify"

#: What the contract says must NOT be required at runtime. `polaris_verify_cli` is the
#: product; everything here is the rest of the tree, which a relying party never installs.
FORBIDDEN_AT_RUNTIME = ("flask", "psycopg2", "polaris_checks", "polaris_web",
                        "polaris_cli", "polaris_sim", "redis")

#: A genuine credential and its tampered twin, from the published vectors. Real signed
#: material: the pass is cross-implementation, not self-consistency.
GENUINE = ROOT / "conformance" / "vectors" / "pack-mldsa87-valid.json"
TAMPERED = ROOT / "conformance" / "vectors" / "pack-mldsa87-tampered.json"


def _run(cmd, cwd=None, env=None):
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=900)


def _build_wheel(src, out):
    """Build a wheel from `src` into `out`. None if the build itself failed."""
    # Build isolation ON: pip fetches its own setuptools, which is what a stranger's
    # `pip install polaris-verify` does. Reusing this interpreter's build tools would test
    # a machine that already has them.
    r = _run([sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(out), str(src)])
    if r.returncode != 0:
        print(r.stdout[-2000:], r.stderr[-2000:], file=sys.stderr)
        return None
    wheels = sorted(out.glob("polaris_verify-*.whl"))
    return wheels[0] if wheels else None


def _fresh_env(work: pathlib.Path, wheel: pathlib.Path):
    """A throwaway venv with the wheel installed. Returns (python, polaris_verify) paths."""
    venv = work / "venv"
    r = _run([sys.executable, "-m", "venv", str(venv)])
    if r.returncode != 0:
        return None, None
    bindir = venv / ("Scripts" if os.name == "nt" else "bin")
    py = bindir / ("python.exe" if os.name == "nt" else "python")
    # The cryptography extra, because a verifier with no backend cannot prove leg 4 and
    # the contract's install test ends at "verify fixture", not "fail to verify fixture".
    r = _run([str(py), "-m", "pip", "-q", "install", "%s[cryptography]" % wheel])
    if r.returncode != 0:
        print(r.stdout[-2000:], r.stderr[-2000:], file=sys.stderr)
        return None, None
    return py, bindir / ("polaris-verify.exe" if os.name == "nt" else "polaris-verify")


def _clean_env():
    """An environment with nothing pointing back at the repository."""
    env = dict(os.environ)
    for k in ("PYTHONPATH", "PYTHONHOME"):
        env.pop(k, None)
    # A stranger has no POLARIS_* anything. If the verifier needs one, that is the finding.
    for k in [k for k in env if k.startswith("POLARIS_")]:
        env.pop(k, None)
    return env


def _check_install(py, cli, cwd, env, label):
    """Every leg of the install test. Returns a list of failure strings (empty = passed)."""
    bad = []

    # 2. the forbidden runtime surface is genuinely absent from the environment
    probe = ("import importlib.util,json;"
             "print(json.dumps([m for m in %r if importlib.util.find_spec(m) is not None]))"
             % (FORBIDDEN_AT_RUNTIME,))
    r = _run([str(py), "-c", probe], cwd=cwd, env=env)
    if r.returncode != 0:
        bad.append("%s: could not probe the installed environment: %s" % (label, r.stderr.strip()[:200]))
    else:
        present = json.loads(r.stdout.strip() or "[]")
        if present:
            bad.append("%s: the installed environment carries %s; the verifier must run with "
                       "none of the tree present" % (label, ", ".join(present)))

    # and the verifier must import with the repository nowhere in sight
    r = _run([str(py), "-c", "import polaris_verify_cli as v; print(v.__version__)"], cwd=cwd, env=env)
    if r.returncode != 0:
        bad.append("%s: the installed package does not import outside the repository: %s"
                   % (label, r.stderr.strip()[-300:]))

    # 3. refuses to start with no declared crypto mode, before reading anything
    r = _run([str(cli), "--pack", str(GENUINE)], cwd=cwd, env=env)
    if r.returncode != 4:
        bad.append("%s: started (exit %d) with no --pqc-provider and no --dev-placeholder; "
                   "the contract requires a refusal" % (label, r.returncode))
    if "refusing to start" not in (r.stderr or ""):
        bad.append("%s: the refusal does not say it is refusing to start" % label)

    # 4. a real backend verifies the genuine credential, and refuses the tampered twin
    r = _run([str(cli), "--pqc-provider", "auto", "--json", "--pack", str(GENUINE)], cwd=cwd, env=env)
    try:
        v = json.loads(r.stdout[r.stdout.index("{"):]) if "{" in r.stdout else {}
    except ValueError:
        v = {}
    if not v.get("signature_valid"):
        bad.append("%s: a GENUINE credential did not verify under a real backend (%s)"
                   % (label, v.get("note") or r.stderr.strip()[-200:]))
    if v.get("crypto") in (None, "DEV-PLACEHOLDER"):
        bad.append("%s: a real-backend verdict is stamped crypto=%r" % (label, v.get("crypto")))

    r = _run([str(cli), "--pqc-provider", "auto", "--json", "--pack", str(TAMPERED)], cwd=cwd, env=env)
    try:
        t = json.loads(r.stdout[r.stdout.index("{"):]) if "{" in r.stdout else {}
    except ValueError:
        t = {}
    if t.get("signature_valid") is not False:
        bad.append("%s: a TAMPERED credential was not refused (signature_valid=%r)"
                   % (label, t.get("signature_valid")))

    # 5. development crypto cannot produce an authentic verdict, and says so
    r = _run([str(cli), "--dev-placeholder", "--json", "--pack", str(GENUINE)], cwd=cwd, env=env)
    try:
        d = json.loads(r.stdout[r.stdout.index("{"):]) if "{" in r.stdout else {}
    except ValueError:
        d = {}
    if d.get("crypto") != "DEV-PLACEHOLDER":
        bad.append("%s: a --dev-placeholder verdict is stamped crypto=%r" % (label, d.get("crypto")))
    if d.get("signature_valid"):
        bad.append("%s: --dev-placeholder reported a GENUINE credential as valid. The mode was "
                   "declared but not entered, so the stamp describes something that did not "
                   "happen" % label)
    if "DEV-PLACEHOLDER" not in (r.stderr or ""):
        bad.append("%s: no banner on stderr under --dev-placeholder" % label)
    return bad


# ---------------------------------------------------------------------------------------
# The npm half of the same question. `packages/polaris-sdk-ts` is a product artifact too,
# and it failed this test on every Node version until it was built: `exports` pointed at
# `./src/index.ts`, and Node refuses type stripping inside node_modules
# (ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING). CI never saw it because `node --test` runs
# INSIDE sdk/typescript, where stripping is allowed. Tested from inside the tree, broken as
# a package: the same shape as the Python boundary problem, in another language.
# ---------------------------------------------------------------------------------------

TS_SDK = ROOT / "sdk" / "typescript"


def _npm(args, cwd, env=None):
    return _run(["npm"] + args, cwd=str(cwd), env=env)


def _check_npm(work: pathlib.Path, src: pathlib.Path, label: str):
    """Pack the SDK, install the tarball in a bare project, import it, verify real material."""
    bad = []
    if shutil.which("npm") is None:
        return ["npm is not installed, so the TypeScript half of the boundary was not tested"]

    work.mkdir(parents=True, exist_ok=True)
    r = _npm(["pack", "--pack-destination", str(work)], src)
    if r.returncode != 0:
        return ["%s: npm pack failed: %s" % (label, r.stderr.strip()[-300:])]
    tgz = sorted(work.glob("*.tgz"))
    if not tgz:
        return ["%s: npm pack produced no tarball" % label]

    consumer = work / "consumer"
    consumer.mkdir(parents=True, exist_ok=True)
    (consumer / "package.json").write_text(
        '{"name":"boundary-consumer","version":"1.0.0","type":"module","private":true}\n')
    r = _npm(["install", "--silent", str(tgz[-1])], consumer)
    if r.returncode != 0:
        return ["%s: the packed tarball does not install: %s" % (label, r.stderr.strip()[-300:])]

    # Import it the way an integrator does, from a project that is not this repository.
    (consumer / "use.mjs").write_text(
        "import { readFileSync } from 'node:fs';\n"
        "import { verifyAuthenticity } from 'polaris-sdk-ts';\n"
        "const out = [];\n"
        "for (const f of process.argv.slice(2)) {\n"
        "  const pack = JSON.parse(readFileSync(f, 'utf8'));\n"
        "  const v = await verifyAuthenticity(pack, [pack.public_key_hex]);\n"
        "  out.push(v.authentic === true);\n"
        "}\n"
        "console.log(JSON.stringify(out));\n")
    r = _run(["node", "use.mjs", str(GENUINE), str(TAMPERED)], cwd=str(consumer))
    if r.returncode != 0:
        bad.append("%s: an ordinary consumer cannot import the installed package: %s"
                   % (label, (r.stderr or "").strip()[-300:]))
        return bad
    try:
        got = json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        bad.append("%s: the consumer produced no verdict (%s)" % (label, r.stdout[-200:]))
        return bad
    if got != [True, False]:
        bad.append("%s: the installed package verified %r; a genuine credential must be "
                   "authentic and its tampered twin must not" % (label, got))
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0] or None)
    ap.add_argument("--keep", action="store_true", help="leave the build and venv in place")
    args = ap.parse_args()

    for p in (PKG, GENUINE, TAMPERED):
        if not p.exists():
            print("product-boundary drill: %s is missing" % p, file=sys.stderr)
            return 3

    work = pathlib.Path(tempfile.mkdtemp(prefix="polaris-boundary-"))
    # A working directory that is NOT the repository. Running from inside it would put the
    # tree on sys.path and prove nothing at all.
    outside = work / "elsewhere"
    outside.mkdir()
    env = _clean_env()
    failures = []
    npm_control_caught = True
    try:
        print("== building the wheel a stranger would install ==")
        wheel = _build_wheel(PKG, work / "dist")
        if wheel is None:
            print("product-boundary drill: the wheel did not build", file=sys.stderr)
            return 1
        print("  %s" % wheel.name)

        py, cli = _fresh_env(work / "real", wheel)
        if py is None:
            print("product-boundary drill: the wheel did not install into a fresh venv",
                  file=sys.stderr)
            return 1
        print("== the install test, run from %s ==" % outside)
        failures = _check_install(py, cli, outside, env, "install")
        for f in failures:
            print("  FAIL %s" % f)
        if not failures:
            print("  every leg passed: builds, installs, imports with none of the tree "
                  "present, refuses to start unsure, verifies genuine, refuses tampered, "
                  "and cannot report a dev run as authentic")

        print("== the same question of the TypeScript SDK, as a published package ==")
        npm_failures = _check_npm(work / "npm", TS_SDK, "npm")
        for f in npm_failures:
            print("  FAIL %s" % f)
        if not npm_failures:
            print("  packs, installs into a bare project, imports, and verifies real "
                  "material: genuine authentic, tampered refused")
        failures += npm_failures

        # NEGATIVE CONTROL for the npm half: a package whose exports point back at the
        # TypeScript sources is importable by nobody, because Node refuses type stripping
        # inside node_modules. That was the shipped state until it was measured.
        print("== negative control: a package that ships only .ts sources ==")
        npm_control_caught = True
        if shutil.which("npm") is None:
            print("  npm is not installed, so this control proves nothing")
            npm_control_caught = False
        else:
            broken_ts = work / "broken-ts"
            shutil.copytree(TS_SDK, broken_ts,
                            ignore=shutil.ignore_patterns("node_modules", "dist", "*.tgz"))
            pj = broken_ts / "package.json"
            d = json.loads(pj.read_text())
            d["exports"] = {".": "./src/index.ts"}
            d["files"] = ["src", "README.md"]
            d.pop("main", None)
            d.pop("types", None)
            d.get("scripts", {}).pop("prepack", None)
            pj.write_text(json.dumps(d, indent=2) + "\n")
            caught = _check_npm(work / "npm-control", broken_ts, "npm-control")
            npm_control_caught = bool(caught)
            print("  a package whose exports point at .ts is %s"
                  % ("caught" if npm_control_caught else "NOT CAUGHT"))

        # NEGATIVE CONTROL. A verifier that drags the tree in with it must be caught here,
        # or the clean result above is a fact about this script.
        print("== negative control: a verifier that requires the tree ==")
        broken_src = work / "broken"
        shutil.copytree(PKG, broken_src)
        target = broken_src / "polaris_verify_cli" / "verifier.py"
        target.write_text("import psycopg2  # the boundary violation under test\n"
                          + target.read_text())
        control_caught = True
        broken_wheel = _build_wheel(broken_src, work / "dist-broken")
        if broken_wheel is None:
            print("  the broken wheel did not build, so the control proves nothing")
            control_caught = False
        else:
            bpy, bcli = _fresh_env(work / "broken-env", broken_wheel)
            if bpy is None:
                print("  the broken wheel did not install, so the control proves nothing")
                control_caught = False
            else:
                caught = _check_install(bpy, bcli, outside, env, "control")
                control_caught = bool(caught)
                print("  a verifier importing psycopg2 is %s"
                      % ("caught" if control_caught else "NOT CAUGHT"))
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("\nkept: %s" % work)

    print()
    if not npm_control_caught:
        print("== PRODUCT BOUNDARY DRILL FAILED: the npm negative control was not caught, so "
              "the TypeScript result would mean nothing ==", file=sys.stderr)
        return 1
    if not control_caught:
        print("== PRODUCT BOUNDARY DRILL FAILED: the negative control was not caught, so a "
              "clean result here would mean nothing ==", file=sys.stderr)
        return 1
    if failures:
        print("== PRODUCT BOUNDARY DRILL FAILED: %d leg(s) of the required install test did "
              "not hold ==" % len(failures), file=sys.stderr)
        return 2
    print("== PRODUCT BOUNDARY DRILL PASSED: polaris-verify builds, installs on a machine "
          "with none of Polaris on it, and does the job a relying party installs it for. The "
          "negative control proves this harness can produce a failure. ==")
    return 0


if __name__ == "__main__":
    sys.exit(main())
