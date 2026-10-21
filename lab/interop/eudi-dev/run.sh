#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# eudi-dev presents an SD-JWT VC to the PUBLISHED polaris-oid4vp, then three or four controls.
#
# Everything runs from a scratch directory: a fresh venv with polaris-oid4vp from PyPI, the
# verifier's test PKI, and the wallet's own state. The wallet generates its holder key itself;
# this script reads only the public half, to bind the credential to it. A run that passes removes
# the directory it made; a run that fails keeps it for its logs and prints where it is.
#
#   lab/interop/eudi-dev/run.sh                       # eudi-dev v2.3.7, newest polaris-oid4vp
#   EUDI_IMAGE=ghcr.io/dominikschlosser/eudi-dev:v2.4.3 lab/interop/eudi-dev/run.sh
#   EUDI_IMAGE=ghcr.io/eudi-dev/eudi-dev:v3.3.1 lab/interop/eudi-dev/run.sh
#                                                     # 3.x images are published under this name
#   EUDI_NATIVE=1 lab/interop/eudi-dev/run.sh         # the wallet's own binary, no Docker
#   EUDI_NATIVE=1 EUDI_VERSION=v3.3.1 lab/interop/eudi-dev/run.sh
#   EUDI_ISSUER=1 lab/interop/eudi-dev/run.sh         # eudi-dev's own issuer signs the credential
#   EUDI_ISSUER=1 CLAIMS=age_equal_or_over.18=true lab/interop/eudi-dev/run.sh
#                                                     # ask for one age statement of its PID
#                                                     # (each CLAIMS word is a --claim)
#   EUDI_TUNNEL=1 lab/interop/eudi-dev/run.sh         # each verifier behind its own cloudflared
#                                                     # quick tunnel: public HTTPS a wallet can verify
#   EUDI_CAPTURE=DIR lab/interop/eudi-dev/run.sh      # write the genuine exchange's bytes to DIR
#                                                     # (capture/README.md); the issuer signs under
#                                                     # an x5c certificate, trusted through its CA
#
# With Docker running, the wallet runs from its image. Without it (or with EUDI_NATIVE=1), the
# wallet's release binary for this machine (macOS or Linux, x86-64 or arm64) is downloaded and
# checked against the SHA-256 pinned below for v2.3.7, or, for another EUDI_VERSION, against the
# checksums the release publishes.
#
# Exits 0 only if the genuine presentation is accepted AND every control is refused where it
# should be. A run that only printed the success line would say nothing: a verifier that
# accepts everything prints it too. Each verdict is read from what the two sides report, not
# from their prose: the wallet's exit status and its --json output, and the verifier's record
# of its one request, taken before and after each wallet run (the responses that reached it,
# the latest one's outcome and the check that refused it, and the request object fetches it
# served and refused, from `serve --result` where the installed polaris-oid4vp has it, else
# from the lines its log prints). A control the wallet refuses also needs the wallet's own
# refusal line for the control's reason: an exit status and no response alone are what any
# wallet that stopped early leaves.
set -euo pipefail
# A run that stops before its last line fails, whatever its EXIT trap's last command returns:
# after a set -u failure, bash 3.2 (macOS /bin/bash) exits with the trap's own status, and $? in
# the trap is already 0. Every trap below hands its status to exit_trap.
finished=0
exit_trap() {  # $1 the run's exit status: kept, unless the run stopped early with 0
  local rc="$1"
  if [ "$finished" != 1 ] && [ "$rc" = 0 ]; then rc=1; fi
  exit "$rc"
}
# The last line of every run, whichever way it ends: a run that stops early is the report most worth having.
report_line() { echo "Tell us how it went, success or failure: https://github.com/EgorKhaklin/polaris-id/issues/new?template=stranger_path_report.yml"; }
# The work dir holds the test wallet's holder key and its credential. A run that made the dir
# removes it once every check passed; a run that stopped or failed keeps it for its logs and says
# where. A WORK the caller named is never removed. Nothing here may stop the trap early.
WORK_MADE=""
clean_work() {  # $1 the run's exit status
  [ -n "$WORK_MADE" ] && [ -d "$WORK" ] || return 0
  if [ "$finished" = 1 ] && [ "$1" = 0 ]; then
    cd /
    # In Docker the wallet's state belongs to the image's user, which on Docker Engine is not this
    # one, so the image empties the mount (rm cannot remove the mount point itself; that is ignored).
    if [ "${MODE:-}" = docker ] && [ -d "$WORK/home" ]; then
      docker run --rm -v "$WORK/home:/h" --entrypoint rm "$IMAGE" -rf /h >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK" 2>/dev/null || true
    [ ! -e "$WORK" ] || echo "could not remove the work dir $WORK: delete it, it holds the test wallet's key"
  elif [ -n "$(ls -A "$WORK/home" 2>/dev/null || true)" ]; then
    echo "work dir kept for its logs: $WORK (it holds the test wallet's key; delete it when done)"
  else
    echo "work dir kept for its logs: $WORK"
  fi
}

# The walk's decisions, each a function lab/interop/eudi-dev/test_walk.py runs without a wallet.
# walk_py runs them in Python ($WALK_PY, the venv's):
#   walk_py ports               a port P with P+1 beside it, both free, for the wallet's own server
#   walk_py snap LOG [RESULT]   the verifier's record of its request so far, as JSON: RESULT, the
#                               file `serve --result` keeps, or else the same read off its LOG
#   walk_py judge KIND NAME BEFORE AFTER URI [CHECK]
#                               one wallet run's verdict (KIND genuine, or control a, b, c or d),
#                               from NAME.rc, NAME.out (its --json output), the verifier's record
#                               BEFORE and AFTER it, and the launch URI it was given
walk_py() {
  "$WALK_PY" -I - "$@" <<'EOF'
import ast, errno, json, re, socket, sys, urllib.parse


def read(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def free(port):
    """Free on each address the wallet's server could bind, as eudi-dev's own check asks."""
    for family, host in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET, "127.0.0.1"),
                         (socket.AF_INET6, "::")):
        try:
            s = socket.socket(family, socket.SOCK_STREAM)
        except OSError:
            continue
        try:
            s.bind((host, port))
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                return False
        finally:
            s.close()
    return True


def ports():
    for _ in range(50):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        if port < 65535 and free(port) and free(port + 1):
            print(port)
            return
    sys.exit("found no two adjacent free ports for the wallet's server")


def snap(log_path, result_path=""):
    if result_path:
        try:
            doc = json.loads(read(result_path))
        except (OSError, ValueError) as e:
            sys.exit("the verifier's serve --result file could not be read: %s" % e)
        doc["source"] = "serve --result"
        return doc
    # A log shows no request object fetches. An acceptance closes the request, so it stays the
    # outcome, as it does in serve --result.
    log = read(log_path)
    answers = re.findall(r"^  <- (\d{3}) (.*)$", log, re.M)
    states = re.findall(r"request\.jwt\?state=([A-Za-z0-9_-]+)", log)
    doc = {"source": "its log", "state": states[-1] if states else None,
           "responses": len(answers), "request_object": None,
           "outcome": "nothing_received", "check": None, "reason": None}
    accepted = [a for a in answers if a[1].startswith("authentic")]
    if accepted:
        status, text = accepted[0]
        claims = re.search(r"claims (\[.*\])$", text)
        doc.update(outcome="accepted", claims=ast.literal_eval(claims.group(1)) if claims else [])
    elif answers:
        status, text = answers[-1]
        refused = re.match(r"refused: ([^:]+): (.*)$", text)
        if text.startswith("wallet error: "):
            doc.update(outcome="wallet_error", reason=text[len("wallet error: "):])
        elif refused:
            doc.update(outcome="refused", check=refused.group(1), reason=refused.group(2))
        else:
            doc.update(outcome="refused")
    if answers:
        doc["response"] = {"status_code": int(status)}
    return doc


def wallet_run(name):
    """One `wallet accept --json` run: its exit status, the JSON it wrote and in which shape,
    the HTTP status it says the verifier answered, and its last line on stderr. eudi-dev 3.x
    writes only one JSON document to stdout, with response.status_code, and exits non-zero when
    the verifier rejects. 2.x prints its text first, then the verifier's answer as a JSON object
    with status_code, and exits 0 on a 400, so for 2.x that object is what is read."""
    rc = int(read(name + ".rc").strip())
    out = read(name + ".out")
    doc, shape = None, None
    try:
        doc, shape = json.loads(out), "json"
    except ValueError:
        for m in reversed(list(re.finditer(r"^\{", out, re.M))):
            try:
                doc, shape = json.loads(out[m.start():]), "text, then json"
                break
            except ValueError:
                pass
    if not isinstance(doc, dict):
        doc, shape = None, None
    if shape == "json":
        response = doc.get("response")
        code = response.get("status_code") if isinstance(response, dict) else None
    else:
        code = doc.get("status_code") if doc else None
    said = [line.strip() for line in read(name + ".err").splitlines() if line.strip()]
    return rc, shape, doc, code, (said[-1] if said else "")


def record(doc):
    if doc.get("outcome") == "accepted":
        return "accepted, claims %s" % doc.get("claims")
    if doc.get("check"):
        return "%s: %s: %s" % (doc.get("outcome"), doc["check"], doc.get("reason"))
    if doc.get("reason"):
        return "%s: %s" % (doc.get("outcome"), doc["reason"])
    return str(doc.get("outcome"))


def judge(kind, name, before_path, after_path, uri, want=""):
    rc, shape, doc, code, said = wallet_run(name)
    before, after = json.loads(read(before_path)), json.loads(read(after_path))
    launched = urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query).get("request_uri", [""])[0]
    state = urllib.parse.parse_qs(urllib.parse.urlsplit(launched).query).get("state", [""])[0]
    # Tied to this walk: the record is of the request this wallet run was launched with, and
    # these are the responses and fetches that arrived while it ran.
    ours = bool(state) and after.get("state") == state
    where = ("this walk's request (state %s...)" % state[:8] if ours else
             "a request other than the one the wallet was launched with (%s, not %s)"
             % (after.get("state"), state or "none"))
    arrived = after["responses"] - before["responses"]
    served = refused = None
    if isinstance(after.get("request_object"), dict) and isinstance(before.get("request_object"), dict):
        served = after["request_object"]["served"] - before["request_object"]["served"]
        refused = after["request_object"]["refused"] - before["request_object"]["refused"]
    http = "HTTP %d" % code if isinstance(code, int) else "nothing"
    verifier = "the verifier, by %s:" % after.get("source")
    failed = []

    def check(good, text):
        print("  %s  %s" % ("ok  " if good else "FAIL", text))
        if not good:
            failed.append(text)

    if kind == "genuine":
        check(rc == 0 and code == 200 and (shape != "json" or doc.get("status") == "submitted"),
              "the wallet exited %d and reports the verifier's answer: %s" % (rc, http))
        check(ours and arrived == 1 and after.get("outcome") == "accepted"
              and (served is None or served >= 1),
              "%s %d response for %s; %s" % (verifier, arrived, where, record(after)))
    elif kind == "a":
        if shape == "json":
            good, how = rc != 0 and code == 400, "exited %d" % rc
        elif shape:
            good, how = code == 400, "exited %d (2.x exits 0 on a 400; its JSON is read)" % rc
        else:
            good, how = False, "exited %d and wrote no JSON" % rc
        check(good, "the wallet %s and reports the verifier's answer: %s" % (how, http))
        check(ours and arrived == 1 and after.get("outcome") == "refused" and after.get("check") == want
              and (served is None or served >= 1),
              "%s %d response for %s; %s" % (verifier, arrived, where, record(after)))
    elif kind in ("b", "c", "d"):
        # The wallet refuses these: it must exit non-zero AND nothing may reach the response URI.
        # A wallet that stopped for another reason (a flag it does not know, a file it could not
        # open) does both too, so each control also needs the wallet's refusal for the control's
        # own reason, in eudi-dev's words (the same in v2.3.7 and v3.3.1; (d)'s is Go's x509
        # error), naming what this walk launched it with. A wallet that words it otherwise fails
        # the control: a loud FAIL, never a pass.
        check(rc != 0, "the wallet exited %d%s" % (rc, ", having presented nothing" if rc else ""))
        text = read(name + ".err")
        outer = urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query).get("client_id", [""])[0]
        if kind == "b":
            why, own = ("at its fetch of the answered request (HTTP 404)",
                        "POST to request_uri returned HTTP 404" in text)
        elif kind == "c":
            why, own = ("the request object, whose client_id is not %s" % (outer or "given"),
                        bool(outer) and ('does not match outer client_id "%s"' % outer) in text)
        else:
            why, own = ("the verifier's certificate when fetching this walk's request",
                        bool(state) and ('request.jwt?state=%s"' % state) in text
                        and "x509: certificate signed by unknown authority" in text)
        check(own, "the wallet refused %s; it said: %s" % (why, said[:240] or "nothing"))
        if served is None:
            fetches, seen = True, ""
        elif kind == "b":
            fetches, seen = served == 0 and refused >= 1, "; it refused %d fetch(es) of the request object and served %d" % (refused, served)
        elif kind == "c":
            fetches, seen = served >= 1, "; it served the signed request object %d time(s), which the wallet read and refused" % served
        else:
            # No fetch is a zero, so the count must be shown live on this very request first:
            # control (c), run before (d) on the same verifier and request, was served it.
            live = before["request_object"]["served"]
            fetches = live >= 1 and served == 0 and refused == 0
            seen = ("; %d fetch(es) of the request object, which had counted %d before this run"
                    % (served + refused, live))
        check(ours and arrived == 0 and fetches,
              "%s %s for %s%s" % (verifier, "no response" if arrived == 0 else "%d response(s)" % arrived, where, seen))
    else:
        sys.exit("walk_py judge: no kind %r" % kind)
    sys.exit(1 if failed else 0)


command, args = sys.argv[1], sys.argv[2:]
if command == "ports":
    ports()
elif command == "snap":
    print(json.dumps(snap(*args)))
elif command == "judge":
    judge(*args)
else:
    sys.exit("walk_py: no command %r" % command)
EOF
}
# The wallet presents, its output kept apart: $1 the launch URI; $2 a name for the run's files,
# $2.out (its --json output), $2.err and $2.rc (its exit status); $3, optionally, a certificate
# the wallet trusts for the verifier's TLS in place of the listener's. --port: its own server on
# the ports the walk found free, never a wallet server already running (see WALLET_PORT).
present() {
  local rc=0
  local tls=(${TLS_CA[@]+"${TLS_CA[@]}"})
  if [ -n "${3:-}" ]; then tls=(--tls-ca "$3"); fi
  wallet accept "$1" --auto-accept --haip --mode strict --no-open --port "$WALLET_PORT" --json \
    ${tls[@]+"${tls[@]}"} > "$2.out" 2> "$2.err" || rc=$?
  echo "$rc" > "$2.rc"
}
snap() {  # $1 a verifier's log: its record so far (walk_py snap)
  walk_py snap "$1" ${RESULT_FLAG:+"${1%.log}.result.json"}
}
measure() {  # $1 genuine, a, b, c or d; $2 the verifier's log; $3 the launch URI; $4 a name for
             # the wallet run's files; $5 as present's $3. Prints the verdict; fail=1 if it fails.
  snap "$2" > "$4.before.json"
  present "$3" "$4" "${5:-}"
  snap "$2" > "$4.after.json"
  walk_py judge "$1" "$4" "$4.before.json" "$4.after.json" "$3" "$REFUSAL_A" || fail=1
}
# Sourced (test_walk.py does), the script stops here, having defined the functions above.
(return 0 2>/dev/null) && return 0
trap 'exit_rc=$?; clean_work "$exit_rc"; report_line; exit_trap "$exit_rc"' EXIT
# pip's upgrade notice is the loudest line of a run and says nothing about this walk.
export PIP_DISABLE_PIP_VERSION_CHECK=1

IMAGE="${EUDI_IMAGE:-ghcr.io/dominikschlosser/eudi-dev:v2.3.7}"
EUDI_VERSION="${EUDI_VERSION:-v2.3.7}"
# What a stranger installs: the newest release, candidates included. Pin it to repeat a run.
PKG="${POLARIS_OID4VP:-polaris-oid4vp}"
PORT="${PORT:-9443}"
HERE="$(cd "$(dirname "$0")" && pwd)"
# The issuer script: named explicitly, downloaded beside this file (docs/STRANGER-PATH.md), or
# where it sits in a clone of the repository.
ISSUER="${ISSUER:-}"
if [ -z "$ISSUER" ]; then
  for candidate in "$HERE/issue_sdjwt_vc.py" "$HERE/../waltid/issue_sdjwt_vc.py"; do
    [ -f "$candidate" ] && ISSUER="$candidate" && break
  done
fi
if [ -z "$ISSUER" ] || [ ! -f "$ISSUER" ]; then
  echo "issue_sdjwt_vc.py not found: put it beside run.sh or set ISSUER" >&2
  exit 2
fi
ISSUER="$(cd "$(dirname "$ISSUER")" && pwd)/$(basename "$ISSUER")"
# The dependencies' hashes, found the same way: downloaded beside this file, or in a clone.
REQS=""
for candidate in "$HERE/requirements.txt" "$HERE/../requirements.txt"; do
  [ -f "$candidate" ] && REQS="$candidate" && break
done
if [ -z "$REQS" ]; then
  echo "requirements.txt not found: put it beside run.sh (docs/STRANGER-PATH.md downloads it)" >&2
  exit 2
fi
if [ -z "${WORK:-}" ]; then WORK="$(mktemp -d)"; WORK_MADE=1; fi
PY="${PYTHON:-python3}"
if [ "${EUDI_NATIVE:-}" != 1 ] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  MODE=docker
  # The verifier as the container reaches it. Docker Desktop supplies host.docker.internal;
  # Docker Engine on Linux does not.
  VHOST=host.docker.internal BIND=0.0.0.0
  ADD_HOST=()
  [ "$(uname)" = Linux ] && ADD_HOST=(--add-host host.docker.internal:host-gateway)
else
  MODE=native VHOST=localhost BIND=127.0.0.1
fi
# EUDI_TUNNEL=1: every verifier this walk starts sits behind its OWN cloudflared quick tunnel (no
# account), serving plain HTTP on the loopback (--no-local-tls) and advertising the tunnel's public
# HTTPS origin (--public-base-url). The wallet then fetches the request over a certificate it can
# validate, which strict mode in eudi-dev v2.5.0 and later does. A fresh tunnel per verifier,
# because a quick tunnel does not reliably reconnect to an origin restarted under it.
TUNNEL="${EUDI_TUNNEL:-}"
# EUDI_CAPTURE=DIR: the genuine presentation's verifier runs through capture_serve.py, which runs
# the installed `polaris-oid4vp serve` in-process and writes the request object, the posted
# response and the decrypted vp_token to DIR, byte for byte, once the verifier accepts. Off by default.
CAPTURE="${EUDI_CAPTURE:-}"
if [ -n "$CAPTURE" ]; then
  [ -f "$HERE/capture_serve.py" ] || { echo "EUDI_CAPTURE needs capture_serve.py beside run.sh" >&2; exit 2; }
  mkdir -p "$CAPTURE"
  CAPTURE="$(cd "$CAPTURE" && pwd)"
  [ -z "$(ls -A "$CAPTURE")" ] || { echo "EUDI_CAPTURE=$CAPTURE is not empty; one capture per directory" >&2; exit 2; }
fi
if [ "$TUNNEL" = 1 ]; then
  command -v cloudflared >/dev/null 2>&1 || { echo "EUDI_TUNNEL=1 needs cloudflared on PATH" >&2; exit 2; }
  BIND=127.0.0.1
fi

# v2.3.7's release binaries, pinned here so a download is checked against this repository and
# not only against a file published beside it.
pinned_sha256() {
  case "$1" in
    eudi-v2.3.7-darwin-amd64) echo 983f9d51b0792bc4456458e91ec3a5906f45858bea192c48413e7704d93d9b36 ;;
    eudi-v2.3.7-darwin-arm64) echo 2cefced5cce8c25c4b1d5cf35796e8e4ce470c92067b176dd18e8c6061385fef ;;
    eudi-v2.3.7-linux-amd64) echo 075732b061128e37481d35397c16e80ff54302b9b335637a5d5164230630dd64 ;;
    eudi-v2.3.7-linux-arm64) echo ff944f0f2dac473ef22a02265b4abcd6c13407b91f3dd8c1f24a882ddefec28f ;;
  esac
}

fetch_wallet() {  # the release binary for this machine, into ./eudi, or exit 2
  local os arch name want got rel
  case "$(uname -s)" in Darwin) os=darwin ;; Linux) os=linux ;;
    *) echo "no eudi-dev binary for $(uname -s); install Docker instead" >&2; exit 2 ;; esac
  case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;;
    *) echo "no eudi-dev binary for $(uname -m); install Docker instead" >&2; exit 2 ;; esac
  name="eudi-$EUDI_VERSION-$os-$arch"
  # The project's current name, where v2.3.7's assets are too, with the SHA-256 pinned above.
  rel="https://github.com/eudi-dev/eudi-dev/releases/download/$EUDI_VERSION"
  curl -fsSL -o eudi "$rel/$name"
  want="$(pinned_sha256 "$name")"
  [ -n "$want" ] || want="$(curl -fsSL "$rel/checksums.txt" | awk -v n="$name" '$2 == n {print $1}')"
  got="$( (sha256sum eudi 2>/dev/null || shasum -a 256 eudi) | cut -d' ' -f1)"
  if [ -z "$want" ] || [ "$got" != "$want" ]; then
    echo "the $name download does not match its SHA-256; not running it" >&2
    rm -f eudi
    exit 2
  fi
  chmod +x eudi
}

if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "port $PORT is in use; set PORT (keygen writes it into the certificate)" >&2
  exit 2
fi

echo "work dir   $WORK"
if [ "$MODE" = docker ]; then echo "wallet     $IMAGE"; else echo "wallet     eudi-dev $EUDI_VERSION, its own binary (no Docker)"; fi
echo "verifier   pip install --pre $PKG"
mkdir -p "$WORK" && cd "$WORK"
"$PY" -m venv venv
# Every third-party package by hash ($REQS); then polaris-oid4vp itself, built from
# $PKG with nothing else fetched and installed as that one wheel. A release from PyPI arrives as
# its published wheel and builds nothing; a path is built here, with the build backend by hash
# (../requirements-build.txt), whose setuptools supports Python 3.10 or newer.
venv/bin/pip install -q --require-hashes -r "$REQS"
if [ -e "$PKG" ]; then
  venv/bin/python -c 'import sys; sys.exit(sys.version_info < (3, 10))' || {
    echo "building $PKG from the tree needs Python 3.10 or newer; set PYTHON to one, or set" >&2
    echo "POLARIS_OID4VP to a release on PyPI, which installs its wheel on any supported Python" >&2
    exit 2
  }
  venv/bin/pip install -q --require-hashes -r "$HERE/../requirements-build.txt"
fi
venv/bin/pip wheel -q --pre --no-deps --no-build-isolation -w wheel "$PKG"
venv/bin/pip install -q --no-deps wheel/*.whl
echo "installed  polaris-oid4vp $(venv/bin/python -c 'import importlib.metadata as m; print(m.version("polaris-oid4vp"))')"
WALK_PY="$WORK/venv/bin/python"
# The verifier's record of its request, as JSON apart from its log, where the installed
# polaris-oid4vp has `serve --result` (read off its own help); 1.0.0, the release on PyPI on
# 2026-10-21, has not, and its record is read off the lines its log prints.
RESULT_FLAG=""
if venv/bin/polaris-oid4vp serve --help 2>&1 | grep -- '--result' >/dev/null; then
  RESULT_FLAG=1
  echo "record     the verifier's, from serve --result"
else
  echo "record     the verifier's, from its log (this polaris-oid4vp has no serve --result)"
fi
# The wallet's own server, which serves its consent page and trust list while it presents, on a
# port this walk found free with the next one beside it (wallet accept --port). Without --port,
# eudi-dev 2.x hands the request to any wallet server already answering on localhost:8085, which
# presents ITS credential: the walk would judge another wallet. test_walk.py holds a listener on
# 8085 and shows that nothing reaches it.
WALLET_PORT="$(walk_py ports)"
echo "ports      the verifier on $PORT, the wallet's own server on $WALLET_PORT and $((WALLET_PORT + 1))"
venv/bin/polaris-oid4vp keygen --out pki --host "$VHOST" --port "$PORT" >/dev/null
mkdir -p home in
# In Docker the wallet runs as the image's own user and keeps its state in this directory.
# Docker Desktop maps file ownership across the mount and Docker Engine does not, so on Linux
# that user could not create its state here without this.
chmod a+rwx home
# The wallet reads its inputs from in/, mounted read-only, never from the work dir itself: mktemp
# makes that dir 0700, which on Docker Engine the image's user (uid 1000) cannot open unless the
# caller's uid is also 1000. in/ holds a readable copy of only each file the wallet reads
# (in_wallet_view): the credential and the verifier's public certificates, never a private key.
chmod a+rx in
[ "$MODE" = native ] && fetch_wallet

# No trust is configured for the verifier's TLS listener. keygen's listener certificate is
# self-signed, and eudi-dev (v2.3.7 and v2.4.3, measured 2026-09-30) presents without being given
# it, even to a host name the certificate does not carry: it does not validate it. What binds
# the exchange is the signed request object (x509_hash) and the response encrypted to its key.
#
# The wallet's keys are its own. File storage through the environment: v2.4 and later read
# EUDI_DEV_STORAGE, v2.3.7 has no --storage flag and keeps files by default. EUDI_DEV_SEED is
# cleared: the 3.x image sets a public one, from which every container of it derives the same
# holder key and CA, and an empty seed selects random keys. Without Docker the wallet's whole
# state directory is the work dir's (EUDI_DEV_HOME), not this machine's ~/.eudi-dev, where an
# installed wallet may have registered a URL handler's listener or a remote wallet to use.
wallet() {
  if [ "$MODE" = docker ]; then
    # The ${a[@]+...} form because macOS's bash 3.2 calls an empty array unbound under set -u.
    docker run --rm ${ADD_HOST[@]+"${ADD_HOST[@]}"} -v "$WORK/home:/home/app/.eudi-dev" -v "$WORK/in:/in:ro" \
      -e EUDI_DEV_STORAGE=file -e EUDI_DEV_SEED= "$IMAGE" wallet "$@"
  else
    EUDI_DEV_HOME="$WORK/home" EUDI_DEV_STORAGE=file EUDI_DEV_SEED='' ./eudi wallet "$@" --wallet-dir "$WORK/home/wallet"
  fi
}
eudi() {  # a top-level eudi-dev command (issue), on the same wallet
  if [ "$MODE" = docker ]; then
    docker run --rm -v "$WORK/home:/home/app/.eudi-dev" -e EUDI_DEV_STORAGE=file -e EUDI_DEV_SEED= "$IMAGE" "$@"
  else
    EUDI_DEV_HOME="$WORK/home" EUDI_DEV_STORAGE=file EUDI_DEV_SEED='' ./eudi "$@" --wallet-dir "$WORK/home/wallet"
  fi
}
in_wallet_view() {  # a file of the work dir, as the wallet sees it: in Docker, a copy in in/
  if [ "$MODE" = docker ]; then
    local name="${1//\//-}"
    cp "$WORK/$1" "$WORK/in/$name" && chmod a+r "$WORK/in/$name" && echo "/in/$name"
  else
    echo "$WORK/$1"
  fi
}

wallet info >/dev/null
if [ "${EUDI_ISSUER:-}" = 1 ]; then
  # EUDI_ISSUER=1: the credential comes from eudi-dev's OWN issuer, a full EUDI PID signed with
  # its PID Provider certificate in x5c (ISO 18013-5's document signer as its key usage), bound
  # to the wallet's own key. Nothing of this repository's signs it: the verifier trusts only the
  # CA the wallet exports, and control (a) trusts an unrelated CA (keygen's own) instead.
  eudi issue sdjwt --wallet --pid >/dev/null
  wallet ca-cert > issuer-ca.pem
  TRUST=--issuer-trust-anchor TRUSTED=issuer-ca.pem OTHER=pki/anchor.pem REFUSAL_A=issuer_key
  echo "credential eudi-dev's own issuer (PID Provider, x5c)"
else
# The wallet makes its own holder key on first use. In Docker it is read through the container,
# as the user that owns it: on Linux the file belongs to the image's user, mode 0600, and this
# shell cannot open it. Only the public half is kept; the copy is removed as soon as it is read.
if [ "$MODE" = docker ]; then
  docker run --rm -v "$WORK/home:/home/app/.eudi-dev" --entrypoint cat "$IMAGE" \
    /home/app/.eudi-dev/wallet/holder.pem > holder.pem
else
  cp "$WORK/home/wallet/holder.pem" holder.pem
fi
venv/bin/python - <<'EOF'
import base64, json, os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
key = serialization.load_pem_private_key(open("holder.pem", "rb").read(), None)
os.remove("holder.pem")
pub = key.public_key()
assert isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP256R1)
n = pub.public_numbers()
b = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).decode().rstrip("=")
json.dump({"kty": "EC", "crv": "P-256", "x": b(n.x), "y": b(n.y), "kid": "eudi-dev-holder"},
          open("holder-jwk.json", "w"))
EOF
# A capture signs under an x5c certificate, so the files carry the issuer's key and one CA
# certificate verifies them offline; without one, the verifier trusts a JWKS.
X5C=()
[ -n "$CAPTURE" ] && X5C=(--x5c)
venv/bin/python "$ISSUER" --holder-jwk holder-jwk.json --out issued.json ${X5C[@]+"${X5C[@]}"} >/dev/null
venv/bin/python - <<'EOF'
import base64, json
from cryptography.hazmat.primitives.asymmetric import ec
issued = json.load(open("issued.json"))
open("credential.txt", "w").write(issued["credential"])
if "issuer_ca_pem" in issued:
    open("issuer-ca.pem", "w").write(issued["issuer_ca_pem"])
json.dump(issued["issuer_jwks"], open("issuer-jwks.json", "w"))
# Control (a): a different key under the SAME kid, so only the signature can tell them apart.
n = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
b = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).decode().rstrip("=")
json.dump([{"kty": "EC", "crv": "P-256", "x": b(n.x), "y": b(n.y),
            "kid": issued["issuer_jwks"][0]["kid"]}], open("issuer-jwks-other.json", "w"))
EOF
wallet import "$(in_wallet_view credential.txt)" | tail -1
if [ -n "$CAPTURE" ]; then
  TRUST=--issuer-trust-anchor TRUSTED=issuer-ca.pem OTHER=pki/anchor.pem REFUSAL_A=issuer_key
  echo "credential this repository's issuer script, under an x5c certificate (capture)"
else
  TRUST=--issuer-jwks TRUSTED=issuer-jwks.json OTHER=issuer-jwks-other.json REFUSAL_A=issuer_signature
fi
fi

VERIFIER_PID="" TUNNEL_PID="" TUNNELS=0
stop_verifier() {  # `wait` returns the killed server's 143, which set -e would take as ours
  if [ -n "$VERIFIER_PID" ]; then
    kill "$VERIFIER_PID" 2>/dev/null || true
    wait "$VERIFIER_PID" 2>/dev/null || true
    VERIFIER_PID=""
  fi
  if [ -n "$TUNNEL_PID" ]; then
    kill "$TUNNEL_PID" 2>/dev/null || true
    wait "$TUNNEL_PID" 2>/dev/null || true
    TUNNEL_PID=""
  fi
}
trap 'exit_rc=$?; stop_verifier; clean_work "$exit_rc"; report_line; exit_trap "$exit_rc"' EXIT

start_tunnel() {  # a quick tunnel to the loopback port; sets TUNNEL_URL, or exits 2
  TUNNELS=$((TUNNELS + 1))
  cloudflared tunnel --no-autoupdate --url "http://localhost:$PORT" > "cloudflared-$TUNNELS.log" 2>&1 &
  TUNNEL_PID=$!
  TUNNEL_URL=""
  for _ in $(seq 1 60); do
    TUNNEL_URL="$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "cloudflared-$TUNNELS.log" | sed -n 1p || true)"
    [ -n "$TUNNEL_URL" ] && grep -q 'Registered tunnel connection' "cloudflared-$TUNNELS.log" && return 0
    sleep 1
  done
  echo "the tunnel did not come up; see $WORK/cloudflared-$TUNNELS.log" >&2
  exit 2
}

CLAIM_ARGS=()
for c in ${CLAIMS:-}; do CLAIM_ARGS+=(--claim "$c"); done

start_verifier() {  # $1 what the verifier trusts (a JWKS or a CA, per $TRUST), $2 log file,
                    # $3 "capture" to run it through capture_serve.py into $CAPTURE.
                    # With serve --result, the record goes beside the log (snap reads it there).
  local serve=(venv/bin/polaris-oid4vp serve)
  [ "${3:-}" = capture ] && serve=(venv/bin/python "$HERE/capture_serve.py" "$CAPTURE" serve)
  if [ "$TUNNEL" = 1 ]; then
    start_tunnel
    # The request object's certificate names the tunnel host; a fresh one per tunnel.
    venv/bin/polaris-oid4vp keygen --out "pki-$TUNNELS" --host "${TUNNEL_URL#https://}" >/dev/null
    PYTHONUNBUFFERED=1 "${serve[@]}" --pki "pki-$TUNNELS" --host "${TUNNEL_URL#https://}" \
      --bind "$BIND" --port "$PORT" --public-base-url "$TUNNEL_URL" --no-local-tls \
      "$TRUST" "$1" ${CLAIM_ARGS[@]+"${CLAIM_ARGS[@]}"} --once \
      ${RESULT_FLAG:+--result "${2%.log}.result.json"} > "$2" 2>&1 &
  else
    PYTHONUNBUFFERED=1 "${serve[@]}" --pki pki --host "$VHOST" \
      --bind "$BIND" --port "$PORT" "$TRUST" "$1" ${CLAIM_ARGS[@]+"${CLAIM_ARGS[@]}"} --once \
      ${RESULT_FLAG:+--result "${2%.log}.result.json"} > "$2" 2>&1 &
  fi
  VERIFIER_PID=$!
  local up=""
  for _ in $(seq 1 40); do grep -q 'state=' "$2" 2>/dev/null && up=1 && break; sleep 0.25; done
  [ -n "$up" ] || { echo "verifier did not start; see $WORK/$2" >&2; exit 2; }
  if [ "$TUNNEL" = 1 ]; then
    # Present only once the verifier answers THROUGH the public name; a new quick-tunnel name can
    # take some seconds to resolve.
    # The verifier's own answer at /done: its page, or, since the redirect carries a
    # response_code (OpenID4VP 1.0 section 8.2), its 404 "no such result" for a request without
    # one. A tunnel's own error page is neither.
    for _ in $(seq 1 60); do
      case "$(curl -s "$TUNNEL_URL/done" || true)" in
        *"presentation is complete"*|*"no such result"*) echo "tunnel     $TUNNEL_URL"; return 0 ;;
      esac
      sleep 2
    done
    echo "the verifier did not answer through $TUNNEL_URL; see $WORK/cloudflared-$TUNNELS.log" >&2
    exit 2
  fi
}

launch_uri() {  # $1 log file, $2 optional client_id override
  venv/bin/python - "$1" "${2:-}" <<'EOF'
import re, sys, urllib.parse
log = open(sys.argv[1]).read()
cid = sys.argv[2] or re.search(r"x509_hash:[A-Za-z0-9_-]+", log).group(0)
ruri = re.findall(r"https://\S+request\.jwt\?state=[A-Za-z0-9_-]+", log)[-1]
print("openid4vp://authorize?" + urllib.parse.urlencode(
    {"client_id": cid, "request_uri": ruri, "request_uri_method": "post"}))
EOF
}

# A wallet that checks the verifier's TLS (eudi-dev v2.5.0 and later, in strict mode) is given the
# listener's own certificate to trust, as a deployed wallet trusts its verifier's; one that does
# not check it has no such flag, so the flag is read off the wallet's own help. Behind a tunnel
# the public certificate needs nothing.
TLS_CA=() TLS_CHECKED=""
if [ "$TUNNEL" != 1 ] && wallet accept --help 2>&1 | grep -- '--tls-ca' >/dev/null; then
  TLS_CA=(--tls-ca "$(in_wallet_view pki/tls.pem)") TLS_CHECKED=1
  echo "TLS        the wallet checks the verifier's; it trusts keygen's listener certificate"
fi

fail=0
echo "== genuine presentation"
if [ -n "$CAPTURE" ]; then start_verifier "$TRUSTED" verifier.log capture
else start_verifier "$TRUSTED" verifier.log; fi
URI=$(launch_uri verifier.log)
measure genuine verifier.log "$URI" wallet
if [ -n "$CAPTURE" ]; then
  # Not a control: a run asked to capture that wrote less than all of it has not done what it
  # was asked. Every file must be there and non-empty, and the wrapper must not have said FAILED.
  # The list is taken first and judged: a substitution that fails inside a `for` list does not
  # trip set -e, and an empty list would find nothing missing.
  missing="" expected=""
  expected="$(venv/bin/python -B -c 'import sys; sys.path.insert(0, sys.argv[1]); import capture_serve; print(" ".join(capture_serve.CAPTURE_FILES))' "$HERE")" || expected=""
  [ -n "$expected" ] || missing=" (the list of expected files could not be read from capture_serve.py)"
  for f in $expected; do
    [ -s "$CAPTURE/$f" ] || missing="$missing $f"
  done
  { grep -E '^capture: ' verifier.log || true; } | sed 's/^/        /'
  if [ -n "$missing" ] || grep -q '^capture: FAILED' verifier.log; then
    echo "  FAIL  the capture in $CAPTURE is incomplete:${missing:- the wrapper reported FAILED} (see $WORK/verifier.log)"; fail=1
  else
    echo "  ok    the capture is complete in $CAPTURE"
  fi
fi

# The wallet refuses (b), (c) and (d): each passes only if it exits non-zero, nothing reaches the
# verifier's response URI while it runs, AND the wallet's refusal names the control's own reason.
# (d) runs after (c) on the same request: (c)'s counted fetch shows (d)'s count of none is live.
echo "== control (b): the same request again, after it was answered"
measure b verifier.log "$URI" wallet-replay
stop_verifier

echo "== control (c): a launch URI whose client_id is not the signed request's"
start_verifier "$OTHER" verifier-other.log
measure c verifier-other.log "$(launch_uri verifier-other.log x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)" wallet-c

if [ -n "$TLS_CHECKED" ]; then
  # Proof that the TLS check ran: the same wallet, trusting an unrelated certificate for the
  # verifier's TLS, presents nothing. It refuses before it fetches, so (a) can still use the request.
  echo "== control (d): the wallet trusts an unrelated certificate for the verifier's TLS"
  measure d verifier-other.log "$(launch_uri verifier-other.log)" wallet-d "$(in_wallet_view pki/anchor.pem)"
fi

if [ "$TRUST" = --issuer-jwks ]; then
  echo "== control (a): the verifier trusts a different issuer key under the same kid"
else
  echo "== control (a): the verifier trusts an unrelated CA"
fi
measure a verifier-other.log "$(launch_uri verifier-other.log)" wallet-a
stop_verifier

if [ "$fail" -ne 0 ]; then echo "RESULT: FAILED"
elif [ -n "$TLS_CHECKED" ]; then echo "RESULT: accepted, and all four controls refused"
else echo "RESULT: accepted, and all three controls refused"; fi
finished=1
exit "$fail"
