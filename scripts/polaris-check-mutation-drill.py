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

THERE ARE THREE MUTATIONS, because commenting out a check's search strings only tests a check
that GREPS, and only in a file where a comment marker hides a line.

The second is blunter and reaches the ones that compute: DELETE every file the check names and
require it to fail. A check that passes when its input is gone is watching nothing, and the
failure is quiet -- "the schema defines no monetary tables" is perfectly true of a schema that
does not exist. That pass found four, two of them constitutional (C10's money-table prohibition
and the canonical version), which had been vacuously true for as long as they had existed.

The third reaches the documents. `#` in Markdown is a heading, not a comment, so the first
mutation had to skip every check reading one: 94 of them, and they are the checks that hold the
outward surfaces to what the evidence supports. There the matching lines are DELETED from the
file instead, which is what removing a sentence from a document actually looks like.

Not noticing that is not automatically a fault, and the drill distinguishes the two cases rather
than leaving a reader to guess. Many checks name a document only to require that it is
published. Deleting some lines leaves a file that still exists, so passing is correct, and the
emptied-file property those checks do carry is already pinned by check_no_vacuous_checks. So
every survivor is re-run against the same file EMPTIED: failing then means the check asserts the
document exists, and is reported as such; passing even then means it cannot tell its named input
from an empty file, and that is a failure.

Exits non-zero if any fully mutated check still passes, if a check outside the declared set
survives having its inputs deleted, if a declared exception has stopped being true, or if a
check is blind to a document it names. No database.
"""
from __future__ import annotations

import ast
import pathlib
import os
import re
import shutil
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

MUTABLE_SUFFIXES = (".py", ".sql", ".sh", ".yml", ".yaml", ".ts", ".js")

#: The marker that turns a line into something the file's own reader will not see. Per
#: language, because getting this wrong is silent: prefixing a `.ts` line with `#` leaves it
#: exactly as visible as it was, and the check would pass having proved nothing, which is the
#: failure this drill is for. Markdown and JSON have no entry and no usable marker, so they
#: are not in MUTABLE_SUFFIXES at all; the document pass deletes their lines instead.
_COMMENT_MARKER = {".sql": "--", ".ts": "//", ".js": "//"}

#: Checks that legitimately survive having their NAMED inputs deleted, with the reason.
#: Empty is the right state, and it is now enforced in both directions: an entry whose
#: check has stopped surviving fails this drill, so the list cannot quietly outlive the
#: limitation it records. check_image_builds_are_retried was the last entry. It was listed
#: because its three needles live in scripts/polaris-image-build.sh, which the check opens
#: through `_read_path(root / "...")`, a door `reads_of` did not resolve; the drill deleted
#: the workflows instead and the check went on passing. Resolving that door (2026-09-20)
#: made the entry untrue, and an untrue exception reads exactly like a load-bearing one.
DELETION_SURVIVORS_EXPECTED: dict = {}

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

    2026-09-20: requiring a separator was the same limitation one level down. A file at the
    repository root has none, so `_LAUNCHER_REL = "polaris_mac_launch.sh"` resolved to
    nothing and the four checks reading through it were reported as having nothing to
    mutate while carrying a dozen needles between them. A name is taken now if it holds a
    separator OR names a file that exists, which is the question actually being asked.
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
                and isinstance(node.value.value, str):
            value = node.value.value
            if "/" in value or (value and (ROOT / value).is_file()):
                out[target.id] = value
    return out


_PATH_CONSTANTS = None


def _package_modules(rel_dir):
    """Every non-test module of a package, as repo-relative paths."""
    d = ROOT / rel_dir
    if not d.is_dir():
        return []
    return ["%s/%s" % (rel_dir, p.name) for p in sorted(d.glob("*.py"))
            if not p.name.startswith("test_")]


_PATH_TUPLES = None


def _module_path_tuples():
    """Module-level `NAME = ("a/b", "c/d")` bindings in checks.py, as name -> [paths].

    The single-path map above resolves `_read(root, _ATHENA_SQL_REL)`. It does not resolve
    the other shape, which is a check looping over a tuple of documents:

        for rel in _OUTWARD_SURFACES:
            text = _read(root, rel)

    There the argument is a LOOP VARIABLE, so there was nothing to resolve and the files
    were invisible. Measured 2026-09-20: ten checks read files that way, 63 file-references
    between them, including check_c1c10_objects_resolve over the documents that say where
    each constitutional guarantee is enforced, and both vocabulary checks over every outward
    surface.

    The cost was not only coverage. check_schema_matches_its_migrations names its four
    inputs as literals and says in a comment that it has to, because reading them through
    _CANONICAL_OBJECT_FILES left this harness able to see one of them: it deleted that one,
    the other comparisons carried on, and the check passed with a third of its input gone.
    A check contorting its own shape to stay visible to the drill is the drill's bug.
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
        if not isinstance(target, ast.Name) or not isinstance(node.value, (ast.Tuple, ast.List)):
            continue
        paths = [e.value for e in node.value.elts
                 if isinstance(e, ast.Constant) and isinstance(e.value, str)
                 and (ROOT / e.value).is_file()]
        if paths:
            out[target.id] = paths
    return out


def _loop_bound_paths(fn):
    """Loop variable -> the paths it takes, for `for VAR in <tuple of paths>`.

    Walks the whole iterable, so `_OUTWARD_SURFACES + ("NOTICE", ...)` contributes both
    the constant's entries and the inline ones.
    """
    global _PATH_TUPLES
    if _PATH_TUPLES is None:
        _PATH_TUPLES = _module_path_tuples()
    out = {}
    for node in ast.walk(fn):
        if not isinstance(node, ast.For) or not isinstance(node.target, ast.Name):
            continue
        paths = []
        for n in ast.walk(node.iter):
            if isinstance(n, ast.Name) and n.id in _PATH_TUPLES:
                paths.extend(_PATH_TUPLES[n.id])
            elif isinstance(n, ast.Constant) and isinstance(n.value, str) \
                    and (ROOT / n.value).is_file():
                paths.append(n.value)
        if paths:
            out.setdefault(node.target.id, []).extend(paths)
    return out


def reads_of(fn):
    """Files the check names, through a path or through a PACKAGE door.

    Resolving only `_read`/`_read_raw` path arguments stopped being enough on 2026-09-18,
    when 73 checks moved from `_read(root, "polaris_web/app.py")` to `_read_app(root)` so
    that a mechanism could live in any module of the application. The path is the point of
    that change and it is also how this drill found what to mutate, so the drill saw 73
    checks with no inputs at all: it deleted nothing, mutated nothing, and reported them as
    trivially passing. `check_duress_is_indistinguishable` surfaced as a survivor for that
    reason and not for any weakness of its own.

    So the package doors resolve to the files they actually read. A check that widens its
    reach must not thereby shrink what this drill can take away from it.
    """
    global _PATH_CONSTANTS
    if _PATH_CONSTANTS is None:
        _PATH_CONSTANTS = _module_path_constants()
    _looped = _loop_bound_paths(fn)
    out = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        fname = getattr(node.func, "id", "")
        if fname in ("_read", "_read_raw") and len(node.args) >= 2:
            arg = node.args[1]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                out.append(arg.value)
            elif isinstance(arg, ast.Name) and arg.id in _PATH_CONSTANTS:
                out.append(_PATH_CONSTANTS[arg.id])
            elif isinstance(arg, ast.Name) and arg.id in _looped:
                out.extend(_looped[arg.id])
        elif fname in ("_read_app", "_app_modules"):
            out.extend(_package_modules("polaris_web"))
        elif fname == "_read_package" and len(node.args) >= 2:
            arg = node.args[1]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                out.extend(_package_modules(arg.value))
    out.extend(_read_path_targets(fn))
    return out


def needles_of(fn):
    """Strings the check tests for with `in` / `not in`: what it greps.

    Two shapes, because checks.py writes the property two ways. A single phrase goes in the
    comparison, `"phrase" in text`, and a LIST of phrases goes in a tuple the check walks:

        for phrase, why in (("...", "..."), ("...", "...")):
            if phrase not in low:

    In the second the comparison's left operand is the loop variable, so collecting only
    `ast.Constant` on the left took none of them. Measured 2026-09-20: 144 checks held
    literals only in that shape, 1,579 strings in total, and `check_athena_no_person` had
    none visible at all. Every one of those checks was still counted as fully mutated while
    being mutated against a subset of what it greps for, which is the harness making the
    same overstatement it exists to catch. Taking both shapes raised the mutated population
    from 118 to 137.
    """
    out = set()

    def take(value, cap):
        if isinstance(value, str) and 3 <= len(value) <= cap and "\n" not in value:
            out.add(value)

    for node in ast.walk(fn):
        if isinstance(node, ast.Compare) and isinstance(node.ops[0], (ast.In, ast.NotIn)):
            if isinstance(node.left, ast.Constant):
                take(node.left.value, 80)
        elif isinstance(node, (ast.For, ast.comprehension)):
            if isinstance(node.iter, (ast.Tuple, ast.List, ast.Set)):
                for el in ast.walk(node.iter):
                    if isinstance(el, ast.Constant):
                        take(el.value, 120)
    return out


#: Files whose lines cannot be commented out in a way that removes them from what a check
#: reads. Markdown's `#` is a heading and JSON has no comment syntax at all, so the
#: comment-out mutation leaves the text exactly as readable as it was. These get their
#: matching lines DELETED instead. JSON is deliberately not here: deleting a line from it
#: breaks the parse, so the check would fail for a reason that is about the file being
#: malformed rather than about the property being gone, and a mutation nobody can read a
#: result from is worse than a declared gap.
PROSE_SUFFIXES = (".md", ".txt")


def _line_carries(line, needles, patterns):
    """Does this line hold one of the strings the check looks for?"""
    if any(n in line for n in needles):
        return True
    for pat in patterns:
        try:
            if re.search(pat, line):
                return True
        except re.error:
            continue                          # a pattern this harness cannot compile alone
    return False


def _read_path_targets(fn):
    """Files reached through `_read_path`, where the path is a literal join off `root`.

    `reads_of` resolved the `_read`/`_read_raw` doors and not this one, so a check whose
    needles live in a file it opens as `helper = root / "scripts/..."` had that file left
    untouched while the drill mutated whatever else it could name.
    `check_image_builds_are_retried` surfaced as a survivor for exactly that reason: its
    three needles are in polaris-image-build.sh and the drill was commenting out workflow
    lines. A limitation of this harness reads identically to a real gap in a check, which is
    why it is resolved here rather than recorded as an expected survivor.
    """
    local = {}
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name):
            rel = _dir_of(node.value)
            if rel:
                local[node.targets[0].id] = rel
    out = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "_read_path" \
                and node.args:
            arg = node.args[0]
            rel = _dir_of(arg) if isinstance(arg, ast.BinOp) else local.get(getattr(arg, "id", ""))
            if rel:
                out.append(rel)
    return out


_COMPILED_PATTERNS = None


def _module_compiled_patterns():
    """Module-level `NAME = re.compile("pattern")` bindings in checks.py, as name -> pattern.

    `regexes_of` reads the pattern out of `re.search(...)` and friends called on the `re`
    module. A check that compiles once at import and calls `_NAME.finditer(line)` has no
    such call, so it asserted through something this harness could not see.

    Four checks are in that shape, and the cost is not hypothetical: writing a check earlier
    today I put its pattern behind `re.compile`, watched the drill report it as having
    nothing to mutate, and inlined `re.match` to get the coverage back. Contorting a check
    to suit the harness is the harness's bug, the same one _CANONICAL_OBJECT_FILES records
    one level up.
    """
    out = {}
    try:
        tree = ast.parse((ROOT / "polaris_checks" / "checks.py").read_text(errors="replace"))
    except Exception:
        return out
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target, value = node.targets[0], node.value
        if not isinstance(target, ast.Name) or not isinstance(value, ast.Call):
            continue
        if getattr(value.func, "attr", "") != "compile":
            continue
        if getattr(getattr(value.func, "value", None), "id", "") != "re":
            continue
        if value.args and isinstance(value.args[0], ast.Constant) \
                and isinstance(value.args[0].value, str):
            out[target.id] = value.args[0].value
    return out


def regexes_of(fn):
    """Patterns the check matches with `re.search` / `re.match` / `re.findall` / `re.finditer`.

    The other half of "what this check greps for". `needles_of` collects strings used in
    `in` / `not in`, which misses every check that asserts through a regex -- and measured
    on 2026-09-13, four of the six checks found to verify a proxy for their invariant were
    in exactly that group, reported as "nothing to mutate" and never tested.

    Only literal patterns are taken. A computed one cannot be mutated against a file
    without running it, and a check with only those still lands in the skipped bucket
    rather than being quietly half-mutated.
    """
    global _COMPILED_PATTERNS
    if _COMPILED_PATTERNS is None:
        _COMPILED_PATTERNS = _module_compiled_patterns()
    out = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not (isinstance(f, ast.Attribute) and f.attr in
                ("search", "match", "findall", "finditer", "fullmatch")):
            continue
        # `_NAME.finditer(...)` where _NAME was compiled at module level.
        if isinstance(f.value, ast.Name) and f.value.id in _COMPILED_PATTERNS:
            pat = _COMPILED_PATTERNS[f.value.id]
            if 3 <= len(pat) <= 400 and pat not in (".*", ".+", r"\s*"):
                out.add(pat)
            continue
        if not (isinstance(f.value, ast.Name) and f.value.id == "re"):
            continue
        if node.args and isinstance(node.args[0], ast.Constant) \
                and isinstance(node.args[0].value, str):
            pat = node.args[0].value
            # A pattern that matches everything would comment the file out wholesale and
            # prove nothing about this check.
            if 3 <= len(pat) <= 400 and pat not in (".*", ".+", r"\s*"):
                out.add(pat)
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
    nothing_to_mutate: list[str] = []
    no_named_input: list[str] = []
    unmutable_suffix: list = []
    no_line_matched: list[str] = []
    work = pathlib.Path("/tmp/polaris-mutation-run")

    print("can a check pass on a tree where its property is gone?")
    print()
    for name, fn in sorted(fns.items()):
        files, needles = reads_of(fn), needles_of(fn)
        patterns = regexes_of(fn)
        # `glob_dir`, not `base`: `base` is the pristine tree copy, and shadowing it here
        # made the next copytree read from "".
        for glob_dir, pattern in globs_of(fn):
            d = ROOT / glob_dir
            if d.is_dir():
                files += [str(f.relative_to(ROOT)) for f in sorted(d.glob(pattern))
                          if f.is_file()]
        if not files:
            # Has something to search for, and nowhere this harness can name to search it.
            # Reported apart from the no-needle case because they are different problems:
            # one is a check asserting through something unparseable, the other is a check
            # whose inputs are a glob or a computed path. check_source_path_citations_resolve
            # walks every .py file in the tree, so it is the second, and calling that "no
            # literal needle and no literal pattern" would be false of a check that has one.
            skipped_nothing += 1
            no_named_input.append(fn.name)
            continue
        if not (needles or patterns):
            skipped_nothing += 1
            nothing_to_mutate.append(fn.name)
            continue
        if not all(f.endswith(MUTABLE_SUFFIXES) for f in files):
            skipped_nothing += 1
            unmutable_suffix.append(
                (fn.name, sorted({os.path.splitext(f)[1] or "(none)" for f in files
                                  if not f.endswith(MUTABLE_SUFFIXES)})))
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
            marker = _COMMENT_MARKER.get(os.path.splitext(rel)[1], "#")
            out = []
            for line in target.read_text(encoding="utf-8", errors="replace").split("\n"):
                hit = _line_carries(line, needles, patterns)
                if hit and not line.lstrip().startswith(marker):
                    out.append(marker + " MUTATED-OUT: " + line.strip())
                    changed = True
                else:
                    out.append(line)
            target.write_text("\n".join(out), encoding="utf-8")
        if not changed:
            skipped_nothing += 1
            no_line_matched.append(fn.name)
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
    deletion_exceptions_used: set = set()
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
        if name in DELETION_SURVIVORS_EXPECTED:
            if still_passes:
                deletion_exceptions_used.add(name)
        elif still_passes:
            deletion_survivors.append(name)

    # THIRD MUTATION: DELETE the lines a check greps for, in files that cannot be commented.
    #
    # This is the one the comment-out pass could not reach. 94 of the checks it skips read a
    # .md, and those are the ones holding the outward surfaces to what the evidence supports:
    # the duress vocabulary, the readiness ledger, the posture audit, the public claims. A
    # sentence is removed here rather than hidden behind a marker that Markdown renders.
    #
    # A check that does NOT notice is not automatically at fault, and the drill says which of
    # the two it is rather than making a reader guess. Many checks name a document only to
    # require that it is published: `if not _read(root, "...md"): return _fail(...)`. Deleting
    # some lines leaves a file that still exists, so passing is the correct answer, and the
    # emptied-file property those checks DO carry is already pinned by check_no_vacuous_checks.
    # So each survivor is re-run against the same file emptied. Failing then means the check
    # asserts the document EXISTS; passing even then means it is blind to a file it names, and
    # that is the failure.
    prose_tested, prose_blind, prose_existence_only = 0, [], []
    prose_names: set = set()
    for name, fn in sorted(fns.items()):
        files = [f for f in sorted(set(reads_of(fn)))
                 if f.endswith(PROSE_SUFFIXES) and (base / f).is_file()]
        needles, patterns = needles_of(fn), regexes_of(fn)
        if not files or not (needles or patterns) or opaque_inputs(fn):
            continue

        def _rebuild(transform):
            shutil.rmtree(work, ignore_errors=True)
            shutil.copytree(base, work)
            touched = False
            for rel in files:
                t = work / rel
                if not t.is_file():
                    continue
                before = t.read_text(encoding="utf-8", errors="replace")
                after = transform(before)
                if after != before:
                    touched = True
                t.write_text(after, encoding="utf-8")
            return touched

        def _drop_matching(text):
            return "\n".join(ln for ln in text.split("\n")
                             if not _line_carries(ln, needles, patterns))

        if not _rebuild(_drop_matching):
            continue                          # nothing in those files carried a needle
        prose_tested += 1
        prose_names.add(name)
        try:
            if any(f.level == "FAIL" for f in by_name[name](work)):
                continue                      # noticed its sentences were gone
        except Exception:                      # noqa: BLE001 - a crash is not a pass
            continue
        _rebuild(lambda text: "")  # noqa: ARG005 - the point is to discard it
        try:
            notices_empty = any(f.level == "FAIL" for f in by_name[name](work))
        except Exception:                      # noqa: BLE001
            notices_empty = True
        (prose_existence_only if notices_empty else prose_blind).append(name)

    shutil.rmtree(work, ignore_errors=True)
    shutil.rmtree(base, ignore_errors=True)

    print("  checks fully mutated and re-run              %4d" % mutated)
    print("  ...of those, still passing on a broken tree  %4d" % len(survived))
    print("  skipped: inputs this harness cannot enumerate %3d" % skipped_opaque)
    print("  skipped: nothing to mutate                   %4d" % skipped_nothing)
    if skipped_nothing:
        # Naming them, not just counting them. This line used to read as a footnote, and
        # it is the drill's blind spot: the population most likely to be pinned to a
        # mechanism is the population this drill cannot reach, so "0 of N survive" is a
        # statement about the reachable N. Measured on 2026-09-13: of six checks found to
        # verify a proxy for their invariant rather than the invariant, FOUR were skipped
        # here.
        #
        # The three causes are reported apart because they are different problems and only
        # one of them is about the checks. Until 2026-09-20 one total was printed above a
        # sample drawn from the smallest of the three, under a sentence that explained only
        # that one: a reader took the names as a sample of the whole and the explanation as
        # its cause. That is the shape of defect this drill exists to find.
        covered_elsewhere = len([nm for nm, _ in unmutable_suffix if nm in prose_names])
        print("      %d of those ARE covered, by the document pass below. The remaining %d are"
              % (covered_elsewhere, skipped_nothing - covered_elsewhere))
        print("      NOT mutation-tested at all, in three groups:")
        if nothing_to_mutate:
            print("      [%d] nothing to search for: no literal needle and no literal pattern."
                  % len(nothing_to_mutate))
            for nm in sorted(nothing_to_mutate)[:6]:
                print("            %s" % nm)
        if no_named_input:
            print("      [%d] something to search for, and no file this harness can name to"
                  % len(no_named_input))
            print("            search it in: the inputs are a glob or a computed path.")
            for nm in sorted(no_named_input)[:6]:
                print("            %s" % nm)
        if unmutable_suffix:
            # Split by whether the DOCUMENT pass below reaches them. Printing one total here
            # with "this drill does not do it yet" was true when the sentence was written and
            # false one ship later, while the checks it described were being tested twenty
            # lines further down under another heading. That is the same defect this drill
            # exists to find, committed by the drill's own output.
            reached = [nm for nm, _ in unmutable_suffix if nm in prose_names]
            unreached = [(nm, sufs) for nm, sufs in unmutable_suffix if nm not in prose_names]
            print("      [%d] read a file the COMMENT mutation cannot express: hiding a line "
                  "needs a" % len(unmutable_suffix))
            print("            syntax that hides it, and `#` in Markdown is a heading, so the "
                  "sentence")
            print("            stays readable and the check would pass having proved nothing.")
            print("            %d of these ARE covered, by the document pass below, which "
                  "deletes the" % len(reached))
            print("            line instead. The remaining %d are genuinely unreached:"
                  % len(unreached))
            by_suffix: dict = {}
            for nm, sufs in unreached:
                for sfx in sufs:
                    by_suffix.setdefault(sfx, []).append(nm)
            for sfx, names in sorted(by_suffix.items(), key=lambda kv: -len(kv[1]))[:5]:
                print("            %-7s %3d check(s), e.g. %s" % (sfx, len(names), names[0]))
        if no_line_matched:
            print("      [%d] had needles, and no line in the named files carried one."
                  % len(no_line_matched))
            for nm in sorted(no_line_matched)[:6]:
                print("            %s" % nm)
    stale_exceptions = sorted(set(DELETION_SURVIVORS_EXPECTED) - deletion_exceptions_used)
    print("  checks whose named inputs were DELETED       %4d" % deletion_tested)
    print("  ...of those, still passing with them gone    %4d  (%d declared, %d still needed)"
          % (len(deletion_survivors), len(DELETION_SURVIVORS_EXPECTED),
             len(deletion_exceptions_used)))
    verified_content = prose_tested - len(prose_existence_only) - len(prose_blind)
    print("  checks whose DOC SENTENCES were deleted      %4d" % prose_tested)
    print("  ...that noticed: they verify what it SAYS    %4d" % verified_content)
    print("  ...that name a document only to require it   %4d" % len(prose_existence_only))
    print("  ...blind to a document they name             %4d" % len(prose_blind))
    if prose_existence_only:
        # Not a failure and worth seeing: these documents could be replaced with anything at
        # all and the only check naming them would still pass, because what it asserts is
        # that they are published. The emptied-file half is pinned by check_no_vacuous_checks.
        print("      deleting every sentence they grep for changed nothing; they fail only")
        print("      when the file is emptied. What each pins is that the document is")
        print("      PUBLISHED, so its wording could be replaced wholesale and hold:")
        for nm in sorted(prose_existence_only)[:8]:
            print("        %s" % nm)
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
    if prose_blind:
        print("FAIL: these checks read a document, and passed both with every sentence they "
              "grep for deleted AND with the file emptied. A check that cannot tell its own "
              "named input from an empty file is reporting a property of nothing:",
              file=sys.stderr)
        for name in sorted(prose_blind):
            print("  %s" % name, file=sys.stderr)
        return 1
    if stale_exceptions:
        # A limitations list that can only be appended to is a confession nobody
        # maintains. polaris-review-packet-drill.py fails when one of ITS limitations is
        # fixed, for the same reason: an exception that has stopped being true reads
        # exactly like one that is still load-bearing, and the next person to read it
        # believes it. check_image_builds_are_retried was listed here from the day its
        # needles lived in a file reads_of could not name, and stayed listed after that
        # was resolved.
        print("FAIL: %d declared deletion exception(s) are no longer true, so the list is "
              "describing a limitation that has been fixed. Delete the entry:"
              % len(stale_exceptions), file=sys.stderr)
        for name in stale_exceptions:
            print("  %s -- %s" % (name, DELETION_SURVIVORS_EXPECTED[name]), file=sys.stderr)
        return 1
    if mutated < 50:
        print("FAIL: only %d checks were mutated; the harness has stopped reaching the "
              "layer it is supposed to attack." % mutated, file=sys.stderr)
        return 1
    print("PASS: %d of %d fully mutated checks survive, at or under the recorded baseline "
          "of %d. %d of %d checks reading a document noticed its sentences being deleted, "
          "and the %d that did not are the ones asserting only that it is published."
          % (len(survived), mutated, SPELLING_PINNED_BASELINE,
             verified_content, prose_tested, len(prose_existence_only)))
    print("The mutation leaves each check's search strings present IN A COMMENT, which is "
          "what `# temporarily disabled: <the thing>` looks like -- the ordinary way a "
          "guarantee disappears without anything turning red.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
