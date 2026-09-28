# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""scripts/polaris_bounded_run.py: a drill's suite run, inside a time bound it reports.

`run` is `subprocess.run` for the calls that run a suite, with two differences:

  - The suite starts in a session of its own, and the bound kills that whole process group,
    so what the suite started (cargo's test binaries, a server a test booted) goes with it.
    `subprocess.run(timeout=...)` kills only the direct child.
  - Hitting the bound does not raise. The run returns exit 124, as timeout(1) does, with a
    closing stderr line. Every drill reads a non-zero exit as "the suite did not pass", which
    is true: the unmutated baseline passed inside the same bound. A baseline that hits it is
    red like any other.

At exit it names every run that hit the bound, so a drill's "OK: N mutated" never hides a
mutant noticed only by hanging. It flushes the drill's stdout before each run, so progress
reaches a CI log as it happens.

POLARIS_DRILL_SUITE_TIMEOUT (seconds) replaces the 30-minute default.
"""
import atexit
import os
import signal
import subprocess
import sys

ENV = "POLARIS_DRILL_SUITE_TIMEOUT"
#: A backstop against a hang, not a budget: the longest single run a drill makes (a whole-module
#: suite in an --exhaustive sweep, or `cargo test --release` after a mutation) is well inside it.
DEFAULT_S = 1800
TIMED_OUT = 124
#: Every run that hit the bound in this process: (seconds, the command, abbreviated).
TIMEOUTS = []


def bound(default=DEFAULT_S) -> float:
    """The bound in seconds: POLARIS_DRILL_SUITE_TIMEOUT when it is a positive number, else
    `default`."""
    raw = os.environ.get(ENV, "").strip()
    try:
        value = float(raw) if raw else float(default)
    except ValueError:
        return float(default)
    return value if value > 0 else float(default)


def _kill_group(proc) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.kill()
    except ProcessLookupError:
        pass


def run(cmd, *, timeout=None, capture_output=False, **kwargs) -> subprocess.CompletedProcess:
    """`subprocess.run(cmd, ...)` inside a bound (`timeout` seconds, else `bound()`).

    Takes the keyword arguments the drills pass to subprocess.run (`cwd`, `env`, `text`,
    `capture_output`, `stdout`, `stderr`). A run that hits the bound returns returncode
    TIMED_OUT, with what it had written so far and a closing line on stderr."""
    limit = bound() if timeout is None else float(timeout)
    if capture_output:
        kwargs["stdout"] = kwargs["stderr"] = subprocess.PIPE
    kwargs["start_new_session"] = True
    sys.stdout.flush()
    sys.stderr.flush()
    proc = subprocess.Popen(cmd, **kwargs)
    try:
        out, err = proc.communicate(timeout=limit)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        try:
            out, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            # Something that left the group (a server started with its own session) still
            # holds the pipes, so they will not close. Stop reading rather than wait on it.
            empty = "" if (kwargs.get("text") or kwargs.get("universal_newlines")
                           or kwargs.get("encoding")) else b""
            for pipe in (proc.stdout, proc.stderr):
                if pipe is not None:
                    pipe.close()
            proc.wait()
            out = empty if proc.stdout is not None else None
            err = empty if proc.stderr is not None else None
        what = " ".join(str(c) for c in (cmd if isinstance(cmd, (list, tuple)) else [cmd]))
        note = ("TIMED OUT after %g s, so the run counts as not passing; the suite and "
                "everything it started were killed: %s" % (limit, what[:240]))
        print("    " + note, flush=True)
        TIMEOUTS.append((limit, what[:120]))
        if isinstance(err, bytes):
            err += ("\n" + note + "\n").encode()
        elif isinstance(err, str):
            err += "\n" + note + "\n"
        return subprocess.CompletedProcess(cmd, TIMED_OUT, out, err)
    except BaseException:
        # Interrupted (Ctrl-C) or failed while waiting: never leave the suite running behind
        # the drill, holding the database it was mutating.
        _kill_group(proc)
        proc.wait()
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


@atexit.register
def _say_timeouts() -> None:
    if TIMEOUTS:
        print("\n%d suite run(s) hit the time bound and were counted as not passing:" % len(TIMEOUTS))
        for limit, what in TIMEOUTS:
            print("   after %g s: %s" % (limit, what))
        sys.stdout.flush()
