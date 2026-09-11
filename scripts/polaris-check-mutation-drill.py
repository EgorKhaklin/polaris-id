#!/usr/bin/env python3
"""polaris-check-mutation-drill.py - can a check pass on a tree where its property is gone?

Every guarantee in this repository is believed because a check says so, and the checks are
written by the same hand as the code. The review packet's last attack prompt (A-12) asks a
reviewer to break that layer, on the grounds that if a check can be made to pass on a broken
tree then everything above it is worth less than it looks.

This is that attack, run against ourselves on every push.

THE MUTATION IS THE ORDINARY FAILURE, not an adversarial one. For each check it finds the files
the check reads and the strings the check looks for, then COMMENTS OUT every line carrying one
of those strings -- leaving the words in the comment, which is exactly the shape of

    # temporarily disabled: security.record_audit_access(...)

and then re-runs the check. A check that still passes is pinned to the SPELLING of its property
rather than to the property, and would have kept passing when somebody disabled the thing during
debugging and forgot.

On 2026-09-11 this found 24 of 24 sampled checks passing on the mutated tree, because `_read`
handed checks the comments along with the code. Stripping comments there took it to 0 of 24.

WHAT IT CANNOT TEST, IT SKIPS AND SAYS SO. A check that enumerates files with `glob` or reads
them with `read_text` has inputs this harness cannot discover, so mutating only the files it can
name would leave the check reading an unmutated copy and "surviving" for no interesting reason.
Those are reported as skipped with the count, rather than counted as passes -- a drill that
inflated its own coverage would be the same error one level up.

WHAT IT IS TODAY IS A RATCHET, NOT A GATE, and the difference is stated rather than hidden.
71 of 75 fully mutated checks currently survive. The cause is one line: `_read` hands checks
the comments along with the code. Stripping there takes the number to ZERO -- measured, not
estimated -- and breaks 58 detection-test fixtures that carry their property in a comment,
which is a repair of its own size. So this drill fails when the number GROWS, and the number
comes down in the ship that fixes the fixtures.

A ratchet is the honest shape for a finding bigger than the ship that found it. Reporting 71 and
gating at 71 says what is true; gating at zero today would mean deleting the drill tomorrow.

Exits non-zero if the count of surviving checks exceeds the recorded baseline. No database.
"""
from __future__ import annotations

import ast
import pathlib
import shutil
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

MUTABLE_SUFFIXES = (".py", ".sql", ".sh", ".yml", ".yaml")

#: Checks that pass on a tree where their own property has been commented out, as of
#: v9.398. This number must not grow, and the ship that makes `_read` strip comments
#: takes it to zero. It is a measurement, not a target: see the module docstring.
SPELLING_PINNED_BASELINE = 71
IGNORE = shutil.ignore_patterns(".git", "node_modules", "target", "__pycache__",
                                ".hypothesis", "venv", ".ruff_cache")


def reads_of(fn):
    """Files the check names literally through _read / _read_raw."""
    out = []
    for node in ast.walk(fn):
        if (isinstance(node, ast.Call)
                and getattr(node.func, "id", "") in ("_read", "_read_raw")
                and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)):
            out.append(node.args[1].value)
    return out


def needles_of(fn):
    """Strings the check tests for with `in` / `not in`: what it greps."""
    out = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Compare) and isinstance(node.ops[0], (ast.In, ast.NotIn)):
            if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                value = node.left.value
                if 3 <= len(value) <= 80 and "\n" not in value:
                    out.add(value)
    return out


def opaque_inputs(fn):
    """True when the check reads files this harness cannot enumerate."""
    for node in ast.walk(fn):
        if isinstance(node, ast.Attribute) and node.attr in ("glob", "rglob", "read_text",
                                                             "iterdir", "walk"):
            return True
    return False


def main():
    from polaris_checks import checks as C

    source = (ROOT / "polaris_checks" / "checks.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    by_name = {f.__name__: f for f in C.CHECKS}
    fns = {n.name: n for n in tree.body
           if isinstance(n, ast.FunctionDef) and n.name in by_name}

    base = pathlib.Path("/tmp/polaris-mutation-base")
    shutil.rmtree(base, ignore_errors=True)
    shutil.copytree(ROOT, base, ignore=IGNORE)

    survived, mutated, skipped_opaque, skipped_nothing = [], 0, 0, 0
    work = pathlib.Path("/tmp/polaris-mutation-run")

    print("can a check pass on a tree where its property is gone?")
    print()
    for name, fn in sorted(fns.items()):
        files, needles = reads_of(fn), needles_of(fn)
        if not files or not needles:
            skipped_nothing += 1
            continue
        if not all(f.endswith(MUTABLE_SUFFIXES) for f in files):
            skipped_nothing += 1
            continue
        if opaque_inputs(fn):
            skipped_opaque += 1
            continue

        shutil.rmtree(work, ignore_errors=True)
        shutil.copytree(base, work)
        changed = False
        for rel in set(files):
            target = work / rel
            if not target.is_file():
                continue
            marker = "--" if rel.endswith(".sql") else "#"
            out = []
            for line in target.read_text(encoding="utf-8", errors="replace").split("\n"):
                if any(n in line for n in needles) and not line.lstrip().startswith(marker):
                    out.append(marker + " MUTATED-OUT: " + line.strip())
                    changed = True
                else:
                    out.append(line)
            target.write_text("\n".join(out), encoding="utf-8")
        if not changed:
            skipped_nothing += 1
            continue

        mutated += 1
        try:
            still_passes = all(f.level != "FAIL" for f in by_name[name](work))
        except Exception:                      # noqa: BLE001 - a crash is not a pass
            still_passes = False
        if still_passes:
            survived.append(name)

    shutil.rmtree(work, ignore_errors=True)
    shutil.rmtree(base, ignore_errors=True)

    print("  checks fully mutated and re-run              %4d" % mutated)
    print("  ...of those, still passing on a broken tree  %4d" % len(survived))
    print("  skipped: inputs this harness cannot enumerate %3d" % skipped_opaque)
    print("  skipped: nothing to mutate                   %4d" % skipped_nothing)
    print()

    if len(survived) > SPELLING_PINNED_BASELINE:
        print("FAIL: %d checks passed with every line carrying their own search strings "
              "commented out, up from a baseline of %d.\nA check that survives this is "
              "pinned to the SPELLING of its property, not to the property:"
              % (len(survived), SPELLING_PINNED_BASELINE), file=sys.stderr)
        for name in sorted(survived):
            print("  %s" % name, file=sys.stderr)
        return 1
    if len(survived) < SPELLING_PINNED_BASELINE:
        print("NOTE: %d survived, below the baseline of %d. Lower "
              "SPELLING_PINNED_BASELINE to %d so the ratchet holds the ground gained."
              % (len(survived), SPELLING_PINNED_BASELINE, len(survived)))
    if mutated < 50:
        print("FAIL: only %d checks were mutated; the harness has stopped reaching the "
              "layer it is supposed to attack." % mutated, file=sys.stderr)
        return 1
    print("PASS: %d of %d fully mutated checks survive, at or under the recorded baseline "
          "of %d." % (len(survived), mutated, SPELLING_PINNED_BASELINE))
    print("The mutation leaves each check's search strings present IN A COMMENT, which is "
          "what `# temporarily disabled: <the thing>` looks like -- the ordinary way a "
          "guarantee disappears without anything turning red.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
