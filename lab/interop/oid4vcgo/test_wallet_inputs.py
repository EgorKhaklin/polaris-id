# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""run.sh's three wallet inputs: each one is the wallet that runs, and a wrong one stops the run.

OID4VCgo runs run.sh in its own CI and asked to test a pull request before its release
(idfoundry/oid4vcgo#312): OID4VCGO_BIN, a prebuilt binary, and OID4VCGO_SRC, a checkout built
with `go build`. OID4VCGO_VERSION stays the default.

No Docker, network or database: `docker` on PATH and PYTHON are stand-ins. The stand-in docker
records every call, "builds" a wallet that carries a token from what it was built from, and
"runs" the container by running $WORK/wallet with the container's arguments. Every wallet here
records its token and arguments, then exits 3, so the harness stops at the wallet's start.
"""
import hashlib
import os
import pathlib
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid

HERE = pathlib.Path(__file__).resolve().parent
RUN = HERE / "run.sh"
REAL_PY = sys.executable

# Records its argv (one call per line, fields split by \x1f); emulates the two builds and the
# wallet container.
FAKE_DOCKER = r'''#!%(py)s
import os, re, sys
args = sys.argv[1:]
work = os.environ["WORK"]
with open(os.path.join(work, "docker.argv"), "a") as f:
    f.write("\x1f".join(args) + "\n")
mounts = {}
for i, a in enumerate(args):
    if a == "-v":
        host, _, rest = args[i + 1].partition(":")
        mounts[rest.split(":")[0]] = host
def wallet(token):
    p = os.path.join(mounts["/out"], "conformance-wallet-vp")
    with open(p, "w") as f:
        f.write(WALLET %% token)
    os.chmod(p, 0o755)
WALLET = %(wallet)r
if args[:1] == ["run"] and "go" in args:
    assert any(a.startswith("golang:1.26@sha256:") for a in args), args  # the Go image, by digest
    go = args[args.index("go"):]
    if go[1] == "install":
        wallet("INSTALLED " + go[-1])
    elif go[1] == "build":
        wd = args[args.index("-w") + 1]
        main = os.path.join(mounts[wd], go[-1], "main.go")
        wallet("BUILT " + re.search(r"token: (\S+)", open(main).read()).group(1))
    sys.exit(0)
if args[:2] == ["run", "-d"]:
    i = next(k for k, a in enumerate(args) if a.startswith("alpine:3.20@sha256:"))  # by digest
    assert args[i + 1] == "/w/wallet", args
    os.execv(os.path.join(mounts["/w"], "wallet"), [args[i + 1]] + args[i + 2:])
sys.exit(0)
'''

# A wallet: writes its token and argv to $WORK/wallet.ran, then exits 3.
WALLET = '#!/bin/sh\nprintf "%%s\\n" "%s" "$@" > "$WORK/wallet.ran"\nexit 3\n'

# PYTHON: `-m venv venv` makes a venv whose pip, polaris-oid4vp and setup_pki.py do nothing more
# than the walk up to the wallet needs.
FAKE_PYTHON = r'''#!/bin/sh
[ "$1 $2 $3" = "-m venv venv" ] || exit 97
mkdir -p venv/bin
ln -s "%(stubs)s/vpython" venv/bin/python
ln -s "%(stubs)s/pip" venv/bin/pip
ln -s "%(stubs)s/oid4vp" venv/bin/polaris-oid4vp
'''
VPYTHON = r'''#!/bin/sh
case "$1" in */setup_pki.py) echo '{}' > config.json; exit 0;; esac
PYTHONPATH="%(stubs)s/site" exec "%(py)s" "$@"
'''
OID4VP = r'''#!/bin/sh
case "$1" in
  serve) echo "  --issuer-trust-anchor PEM";;
  keygen) mkdir -p pki && echo anchor > pki/anchor.pem;;
  *) exit 98;;
esac
'''


def setUpModule():
    # run.sh runs git on OID4VCGO_SRC, and so does this file: from a hook, a GIT_* left set
    # would point that git at the index of the commit being made.
    for k in [k for k in os.environ if k.startswith("GIT_")]:
        os.environ.pop(k)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def write_exec(path, text):
    path.write_text(text)
    path.chmod(0o755)


class WalletInputs(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        stubs = self.tmp / "stubs"
        (stubs / "site" / "polaris_oid4vp-0.0.0.dist-info").mkdir(parents=True)
        (stubs / "site" / "polaris_oid4vp-0.0.0.dist-info" / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: polaris-oid4vp\nVersion: 0.0.0\n")
        bindir = self.tmp / "bin"
        bindir.mkdir()
        write_exec(bindir / "docker", FAKE_DOCKER % {"py": REAL_PY, "wallet": WALLET})
        write_exec(bindir / "curl", "#!/bin/sh\nexit 99\n")  # no network: `latest` would fetch
        write_exec(stubs / "python", FAKE_PYTHON % {"stubs": stubs})
        write_exec(stubs / "vpython", VPYTHON % {"stubs": stubs, "py": REAL_PY})
        write_exec(stubs / "pip", "#!/bin/sh\nexit 0\n")
        write_exec(stubs / "oid4vp", OID4VP)
        self.work = self.tmp / "work"
        self.work.mkdir()
        # GIT_* are gone already (setUpModule); any OID4VCGO_* of the caller's is dropped too.
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("GIT_", "OID4VCGO_"))
               and k not in ("POLARIS_OID4VP", "PORT", "WALLET_PORT", "WORK", "PYTHON")}
        env.update(PATH="%s:/usr/bin:/bin:/usr/sbin:/sbin" % bindir, WORK=str(self.work),
                   PYTHON=str(stubs / "python"), POLARIS_OID4VP="polaris-oid4vp",
                   PORT=str(free_port()), WALLET_PORT=str(free_port()))
        self.env = env

    def run_sh(self, **extra):
        r = subprocess.run(["bash", str(RUN)], env=dict(self.env, **extra), capture_output=True,
                           text=True, timeout=120)
        self.out = r.stdout + r.stderr
        return r

    def docker_calls(self):
        p = self.work / "docker.argv"
        return [ln.split("\x1f") for ln in p.read_text().splitlines()] if p.exists() else []

    def builds(self):
        return [c for c in self.docker_calls() if "go" in c]

    def wallet_ran(self):
        p = self.work / "wallet.ran"
        self.assertTrue(p.exists(), "no wallet ran:\n" + self.out)
        lines = p.read_text().splitlines()
        self.assertEqual(lines[1:], ["-config", "/w/config.json"], self.out)
        return lines[0]

    def stopped_at_the_wallet(self, r):
        self.assertEqual(r.returncode, 3, self.out)
        self.assertNotIn("RESULT", self.out)

    def go_module(self):
        src = self.tmp / "checkout"
        (src / "cmd" / "conformance-wallet-vp").mkdir(parents=True)
        (src / "go.mod").write_text("module github.com/idfoundry/oid4vcgo\n\ngo 1.22\n")
        token = uuid.uuid4().hex
        (src / "cmd" / "conformance-wallet-vp" / "main.go").write_text(
            "package main\n\n// token: %s\nfunc main() {}\n" % token)
        return src, token

    # -- each input is the wallet that runs

    def test_default_installs_the_pinned_version(self):
        r = self.run_sh()
        self.stopped_at_the_wallet(r)
        pkg = "github.com/idfoundry/oid4vcgo/cmd/conformance-wallet-vp@v0.12.0"
        self.assertEqual([c[c.index("go"):] for c in self.builds()], [["go", "install", pkg]])
        self.assertEqual(self.wallet_ran(), "INSTALLED " + pkg)
        self.assertIn("\nwallet     github.com/idfoundry/oid4vcgo v0.12.0, "
                      "cmd/conformance-wallet-vp\n", r.stdout)

    def test_version_is_the_one_installed(self):
        r = self.run_sh(OID4VCGO_VERSION="v0.19.0")
        self.stopped_at_the_wallet(r)
        pkg = "github.com/idfoundry/oid4vcgo/cmd/conformance-wallet-vp@v0.19.0"
        self.assertEqual(self.wallet_ran(), "INSTALLED " + pkg)

    def test_bin_is_the_wallet_that_runs(self):
        token = uuid.uuid4().hex
        b = self.tmp / "dist" / "conformance-wallet-vp"
        b.parent.mkdir()
        write_exec(b, WALLET % token)
        r = self.run_sh(OID4VCGO_BIN=str(b), OID4VCGO_VERSION="latest")
        self.stopped_at_the_wallet(r)
        self.assertEqual(self.wallet_ran(), token)
        self.assertEqual(self.builds(), [], "a binary is run as is, nothing is built")
        self.assertIn("\nwallet     binary %s, sha256 %s\n"
                      % (b, hashlib.sha256(b.read_bytes()).hexdigest()), r.stdout)

    def test_src_is_built_from_that_checkout(self):
        src, token = self.go_module()
        g = ["git", "-C", str(src)]
        subprocess.run(g + ["init", "-q"], check=True, env=self.env)
        subprocess.run(g + ["add", "-A"], check=True, env=self.env)
        subprocess.run(g + ["-c", "user.name=t", "-c", "user.email=t@t", "-c",
                            "commit.gpgsign=false", "commit", "-qm", "x"], check=True, env=self.env)
        head = subprocess.run(g + ["rev-parse", "HEAD"], check=True, env=self.env,
                              capture_output=True, text=True).stdout.strip()
        self.assertRegex(head, r"^[0-9a-f]{40}$")
        r = self.run_sh(OID4VCGO_SRC=str(src))
        self.stopped_at_the_wallet(r)
        self.assertEqual(self.wallet_ran(), "BUILT " + token)
        (build,) = self.builds()
        self.assertIn("%s:/src:ro" % src, build)
        self.assertEqual(build[build.index("go"):], ["go", "build", "-buildvcs=false", "-o",
                         "/out/conformance-wallet-vp", "./cmd/conformance-wallet-vp"])
        self.assertIn("\nwallet     source %s, commit %s, cmd/conformance-wallet-vp built with "
                      "go build\n" % (src, head), r.stdout)

    # -- a wrong input stops the run, with its reason, before anything runs

    def refused(self, reason, **extra):
        r = self.run_sh(**extra)
        self.assertEqual(r.returncode, 2, self.out)
        self.assertIn(reason, r.stderr)
        self.assertEqual(self.docker_calls(), [], "it went on to build or run a wallet")
        self.assertNotIn("work dir", r.stdout)

    def test_missing_bin(self):
        b = self.tmp / "nowhere" / "conformance-wallet-vp"
        self.refused("OID4VCGO_BIN=%s: no such file" % b, OID4VCGO_BIN=str(b))

    def test_bin_not_executable(self):
        b = self.tmp / "conformance-wallet-vp"
        b.write_text(WALLET % "x")
        b.chmod(stat.S_IRUSR | stat.S_IWUSR)
        self.refused("OID4VCGO_BIN=%s: not executable" % b, OID4VCGO_BIN=str(b))

    def test_bin_and_src(self):
        src, _ = self.go_module()
        b = self.tmp / "conformance-wallet-vp"
        write_exec(b, WALLET % "x")
        self.refused("OID4VCGO_BIN and OID4VCGO_SRC are both set", OID4VCGO_BIN=str(b),
                     OID4VCGO_SRC=str(src))

    def test_src_not_a_module(self):
        src, _ = self.go_module()
        (src / "go.mod").unlink()
        self.refused("OID4VCGO_SRC=%s: not a Go module (no go.mod)" % src, OID4VCGO_SRC=str(src))

    def test_src_without_the_wallet(self):
        src, _ = self.go_module()
        shutil.rmtree(src / "cmd")
        self.refused("OID4VCGO_SRC=%s: no cmd/conformance-wallet-vp in it" % src,
                     OID4VCGO_SRC=str(src))


if __name__ == "__main__":
    unittest.main()
