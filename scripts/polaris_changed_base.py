"""scripts/polaris_changed_base.py: the commit a ship is measured from, one answer for every tool.

The `--changed` modes of the procedure and SDK mutation drills, and the ship tool's drill plan,
all ask "what did this ship touch?". The answer is a diff against a baseline, and the baseline
is the whole question:

  - CI names it. A push can carry several commits, and HEAD~1 sees only the last one. On
    2026-09-28 a push whose second-to-last commit changed 05_procedures.sql and added a
    migration ran the procedure drill as a no-op, in under a second, because HEAD was a
    CHANGELOG commit. The workflow now passes the commit the push started from
    (github.event.before), or a pull request's base, as POLARIS_CHANGED_BASE.
  - Locally, the upstream when HEAD is ahead of it: what the next push carries.
  - Otherwise HEAD~1.

None when the named commit cannot be reached (a shallow checkout, say). "I could not tell" and
"nothing changed" must not look alike, so every caller refuses on None rather than passing.
"""
import os
import subprocess

ENV = "POLARIS_CHANGED_BASE"
_ZERO = "0" * 40      # github.event.before on a branch's first push


def _git(root, *args):
    return subprocess.run(["git", *args], cwd=str(root), capture_output=True, text=True)


def _commit(root, rev):
    """The full id of `rev` if it names a commit this checkout holds, else None."""
    out = _git(root, "rev-parse", "--verify", "--quiet", "%s^{commit}" % rev)
    return out.stdout.strip() if out.returncode == 0 and out.stdout.strip() else None


def changed_base(root):
    named = os.environ.get(ENV, "").strip()
    if named and named != _ZERO:
        return _commit(root, named)
    upstream = _commit(root, "@{u}")
    if upstream:
        ahead = _git(root, "rev-list", "--count", "%s..HEAD" % upstream).stdout.strip()
        if ahead.isdigit() and int(ahead) > 0:
            return upstream
    return _commit(root, "HEAD~1")
