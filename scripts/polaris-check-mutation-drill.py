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

IT GATES AT ZERO. When this drill was written, 71 of 75 fully mutated checks survived, because
`_read` handed every check the comments along with the code. Stripping there fixed all 71 at
once and broke 58 detection-test fixtures that carried their own property in a comment -- those
fixtures were repaired in the same ship, since a fixture that states its property in a comment
is testing the thing this drill exists to forbid.

THERE ARE TWO MUTATIONS, because commenting out a check's search strings only tests a check that
GREPS. The second is blunter and reaches the ones that compute: DELETE every file the check
names and require it to fail. A check that passes when its input is gone is watching nothing,
and the failure is quiet -- "the schema defines no monetary tables" is perfectly true of a
schema that does not exist. That pass found four, two of them constitutional (C10's money-table
prohibition and the canonical version), which had been vacuously true for as long as they had
existed.

A check may legitimately survive this when the deleted file is one of several it reads and the
others still carry the property; those are listed rather than failed, with the expectation that
a reader checks the list is short and understood.

Exits non-zero if any fully mutated check still passes, or if a check outside the known set
survives having its inputs deleted. No database.
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

#: Checks that legitimately survive having their NAMED inputs deleted, with the reason.
#: Both read more than the files the harness can name: athena_no_person reads its SQL
#: through a module constant the harness cannot resolve, and image_builds_are_retried
#: iterates every workflow, so deleting one leaves the others carrying the property.
DELETION_SURVIVORS_EXPECTED = {
    "check_image_builds_are_retried":
        "iterates every workflow; deleting one leaves the rest to carry the property",
}

#: Checks that pass on a tree where their own property has been commented out. It was
#: 71 of 75 at v9.398, when `_read` still handed checks the comments along with the
#: code. It is ZERO, and a zero baseline is the only one worth having: any check that
#: starts surviving this mutation fails the build on the push that makes it survive.
SPELLING_PINNED_BASELINE = 0
IGNORE = shutil.ignore_patterns(".git", "node_modules", "target", "__pycache__",
                                ".hypothesis", "venv", ".ruff_cache")


def _module_path_constants():
    """Module-level `NAME = "some/path"` bindings in checks.py, as a name -> path map.

    v9.438: a check may name its input through a constant rather than a literal --
    `_read(root, _ATHENA_SQL_REL)` -- and resolving only literals left those checks
    reported as deletion survivors for a reason that was about this harness, not about
    them. `check_athena_no_person` does fail when 16_athena.sql is deleted; the drill
    simply could not find the filename to delete. An exception declared for a harness
    limitation reads exactly like one declared for a real gap, which is why this is
    worth resolving rather than annotating.
    """
    out = {}
    try:
        tree = ast.parse((ROOT / "polaris_checks" / "checks.py").read_text(errors="replace"))
    except Exception:
        return out
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str) and "/" in node.value.value:
            out[target.id] = node.value.value
    return out


_PATH_CONSTANTS = None


def reads_of(fn):
    """Files the check names through _read / _read_raw, literally or via a constant."""
    global _PATH_CONSTANTS
    if _PATH_CONSTANTS is None:
        _PATH_CONSTANTS = _module_path_constants()
    out = []
    for node in ast.walk(fn):
        if (isinstance(node, ast.Call)
                and getattr(node.func, "id", "") in ("_read", "_read_raw")
                and len(node.args) >= 2):
            arg = node.args[1]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                out.append(arg.value)
            elif isinstance(arg, ast.Name) and arg.id in _PATH_CONSTANTS:
                out.append(_PATH_CONSTANTS[arg.id])
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


def _dir_of(node):
    """Reconstruct `root / 'a' / 'b'` into a relative path, or None if it is not that.

    Only literal joins off `root` are resolved. Anything computed stays unresolvable and
    the check that uses it is reported as skipped rather than quietly half-mutated.
    """
    parts = []
    while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        if not isinstance(node.right, ast.Constant) or not isinstance(node.right.value, str):
            return None
        parts.append(node.right.value)
        node = node.left
    if isinstance(node, ast.Name) and node.id == "root":
        return "/".join(reversed(parts))
    return None


def globs_of(fn):
    """Literal `<dir>.glob("pattern")` calls a check makes, as (dir, pattern) pairs.

    A check that enumerates migrations or workflows is testable after all: the pattern is
    a constant and the directory is a literal join off `root`. Resolving these was the
    difference between the drill skipping a C1 check and mutating it.
    """
    out = []
    for node in ast.walk(fn):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("glob", "rglob") and node.args
                and isinstance(node.args[0], ast.Constant)):
            base = _dir_of(node.func.value)
            if base is not None:
                out.append((base, node.args[0].value))
    return out


def opaque_inputs(fn):
    """True when the check reads files this harness cannot enumerate.

    A `glob` whose directory and pattern are both literal is NOT opaque: `globs_of`
    resolves it. Everything else -- a computed path, a bare `read_text`, an `iterdir` --
    leaves inputs the mutation cannot reach, and a check with those is skipped and
    counted rather than mutated halfway and called a survivor.
    """
    resolvable = {id(node) for node in ast.walk(fn)
                  if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                  and node.func.attr in ("glob", "rglob") and node.args
                  and isinstance(node.args[0], ast.Constant)
                  and _dir_of(node.func.value) is not None}
    for node in ast.walk(fn):
        if isinstance(node, ast.Attribute) and node.attr in ("read_text", "iterdir", "walk"):
            return True
        if isinstance(node, ast.Attribute) and node.attr in ("glob", "rglob"):
            parent = next((c for c in ast.walk(fn)
                           if isinstance(c, ast.Call) and c.func is node), None)
            if parent is None or id(parent) not in resolvable:
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
        # `glob_dir`, not `base`: `base` is the pristine tree copy, and shadowing it here
        # made the next copytree read from "".
        for glob_dir, pattern in globs_of(fn):
            d = ROOT / glob_dir
            if d.is_dir():
                files += [str(f.relative_to(ROOT)) for f in sorted(d.glob(pattern))
                          if f.is_file()]
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

    # SECOND MUTATION: delete what the check names and require it to notice.
    deletion_survivors, deletion_tested = [], 0
    for name, fn in sorted(fns.items()):
        named = [f for f in set(reads_of(fn)) if (base / f).is_file()]
        if not named:
            continue
        shutil.rmtree(work, ignore_errors=True)
        shutil.copytree(base, work)
        for rel in named:
            (work / rel).unlink()
        deletion_tested += 1
        try:
            still_passes = all(f.level != "FAIL" for f in by_name[name](work))
        except Exception:                      # noqa: BLE001 - a crash is not a pass
            still_passes = False
        if still_passes and name not in DELETION_SURVIVORS_EXPECTED:
            deletion_survivors.append(name)

    shutil.rmtree(work, ignore_errors=True)
    shutil.rmtree(base, ignore_errors=True)

    print("  checks fully mutated and re-run              %4d" % mutated)
    print("  ...of those, still passing on a broken tree  %4d" % len(survived))
    print("  skipped: inputs this harness cannot enumerate %3d" % skipped_opaque)
    print("  skipped: nothing to mutate                   %4d" % skipped_nothing)
    print("  checks whose named inputs were DELETED       %4d" % deletion_tested)
    print("  ...of those, still passing with them gone    %4d  (%d known and listed)"
          % (len(deletion_survivors), len(DELETION_SURVIVORS_EXPECTED)))
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
    if deletion_survivors:
        print("FAIL: these checks passed with every file they name DELETED. A check that "
              "does not notice its own input is gone is watching nothing, and the property "
              "it reports is vacuously true:", file=sys.stderr)
        for name in sorted(deletion_survivors):
            print("  %s" % name, file=sys.stderr)
        return 1
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
