#!/usr/bin/env python3
"""polaris-tla-drill.py - the formal specs, actually checked (roadmap P6.7).

meta/tla/ carried one TLA+ spec for years, described as "checked once to show the technique".
Nothing re-checked it. Graduating it to maintained found three defects in the artifact, and
every one of them is an argument for this file existing:

  IT COULD NOT BE PARSED. The file was named c3-one-active-token.tla while the module inside
  was C3OneActiveToken. TLA+ requires the two to match. The companion configuration existed
  only as a comment at the foot of the file. The spec had never been run in the form it
  shipped, and could not be.

  IT VIOLATED ITS OWN TYPE INVARIANT. Every action incremented op_count and none guarded it,
  so the counter ran past MaxOperations and TypeOK failed at the thirteenth step of a
  twelve-step bound.

  AND IT HAD ALREADY DRIFTED. The spec quoted a partial unique index named
  uq_one_active_token_per_individual. No such index exists anywhere in the tree; the real one
  is uq_one_active_per_person. The drift meta/tla/README.md warned that maintained specs would
  suffer had already happened to the single unmaintained one, and nothing noticed because
  nothing resolved the name.

The substantive claim survived all three: C3 was never violated in any reachable state. What
failed was everything around it, silently, for as long as nothing ran the checker.

SO THIS DRILL DOES TWO THINGS. It runs TLC over every spec that has a configuration, and it
resolves every `MODELS:` binding a spec declares against the file it names. The second is the
answer to the README's own objection to maintained specs: drift is not prevented by care, it
is detected by a citation that has to resolve.

Run: scripts/polaris-tla-drill.sh          (fetches the pinned tla2tools)
     POLARIS_TLA_JAR=/path/tla2tools.jar python3 scripts/polaris-tla-drill.py
Exit 0 iff every spec checks and every binding resolves, 3 to skip.
"""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TLA_DIR = os.path.join(ROOT, "meta", "tla")
JAR = os.environ.get("POLARIS_TLA_JAR", os.path.join(ROOT, ".tla", "tla2tools.jar"))
JAVA = os.environ.get("POLARIS_JAVA", "java")

_ok_all = True


#: Cases this drill actually recorded. A drill whose cases are removed or
#: short-circuited in a refactor prints its whole summary and exits 0 anyway,
#: which is a guarantee reported by something that tested nothing (v9.403).
_cases_recorded = 0


def _row(label, got, want):
    global _cases_recorded
    _cases_recorded += 1
    global _ok_all
    ok = got == want
    _ok_all &= ok
    print("  %-56s %-16s %-12s %s" % (label[:56], str(got)[:16], str(want)[:12],
                                      "OK" if ok else "FAIL"))
    return ok


def _note(label, value):
    print("  %-56s %-16s %-12s %s" % (label[:56], str(value)[:16], "", "--"))


def main():
    if not os.path.exists(JAR):
        print("tla drill needs tla2tools.jar at %s (scripts/polaris-tla-drill.sh fetches it)"
              % JAR, file=sys.stderr)
        return 3
    if subprocess.run([JAVA, "-version"], capture_output=True).returncode != 0:
        print("tla drill needs a Java runtime (POLARIS_JAVA to point at one)", file=sys.stderr)
        return 3

    specs = sorted(f for f in os.listdir(TLA_DIR) if f.endswith(".tla"))
    print("the formal specs, actually checked")
    print()
    print("  %-56s %-16s %-12s %s" % ("case", "got", "expected", "ok"))
    _row("meta/tla holds specs to check", len(specs) > 0, True)

    # THE FILENAME RULE, checked before TLC so the failure names its own cause. TLA+ requires
    # the file to be named for its module, and a mismatch is an unparseable spec rather than a
    # spec that fails: the difference matters when reading the output.
    mismatched = []
    for spec in specs:
        text = open(os.path.join(TLA_DIR, spec)).read()
        m = re.search(r"MODULE\s+(\w+)", text)
        if not m:
            mismatched.append("%s has no MODULE header" % spec)
        elif m.group(1) != spec[:-4]:
            mismatched.append("%s declares MODULE %s" % (spec, m.group(1)))
    _row("every spec's filename matches its module name", mismatched, [])

    # EVERY SPEC HAS A CONFIGURATION. One that exists only as a comment is one nobody runs.
    unconfigured = [s for s in specs
                    if not os.path.exists(os.path.join(TLA_DIR, s[:-4] + ".cfg"))]
    _row("every spec has a companion .cfg on disk", unconfigured, [])

    # THE BINDINGS RESOLVE. This is the drift answer.
    unresolved, bindings = [], 0
    for spec in specs:
        text = open(os.path.join(TLA_DIR, spec)).read()
        for obj, path in re.findall(r"MODELS:\s*(\S+)\s+IN\s+(\S+)", text):
            bindings += 1
            target = os.path.join(ROOT, path)
            if not os.path.exists(target):
                unresolved.append("%s: no such file %s" % (spec, path))
            elif obj not in open(target).read():
                unresolved.append("%s: %s not found in %s" % (spec, obj, path))
    _row("every MODELS binding resolves against the tree", unresolved, [])
    _note("bindings resolved", bindings)
    _row("...and the specs actually declare some",
         bindings >= len(specs), True)

    # AND THE CHECKER RUNS.
    def check(spec, cfg):
        # -metadir into a scratch directory. TLC otherwise writes its fingerprint and
        # state-queue files into states/ BESIDE the spec, which reached 1.5GB on one run here
        # and was duly swept into a commit by `git add -A`. The remote refused the push, which
        # is the only reason it was noticed.
        with tempfile.TemporaryDirectory(prefix="polaris-tlc-") as meta:
            proc = subprocess.run(
                [JAVA, "-XX:+UseParallelGC", "-cp", JAR, "tlc2.TLC", "-nowarning",
                 "-metadir", meta, "-config", cfg, spec],
                cwd=TLA_DIR, capture_output=True, text=True, timeout=900)
        return proc.stdout + proc.stderr, proc.returncode

    failed = []
    for spec in specs:
        cfg = spec[:-4] + ".cfg"
        if cfg in [os.path.basename(u) for u in unconfigured]:
            continue
        out, code = check(spec, cfg)
        if "Model checking completed. No error has been found." not in out:
            reason = "exit %d" % code
            for line in out.splitlines():
                if line.startswith("Error:"):
                    reason = line.strip()[:60]
                    break
            failed.append("%s: %s" % (spec, reason))
        else:
            states = re.search(r"(\d+) distinct states found", out)
            _note("  %s" % spec[:-4], "%s states" % (states.group(1) if states else "?"))
    _row("every spec model-checks with no error", failed, [])

    # AND EVERY SPEC THAT CAN FAIL, DOES, UNDER ITS COUNTERPART CONFIGURATION.
    #
    # A spec whose invariant holds no matter what proves nothing, exactly as a check that
    # cannot detect its own violation is treated as broken in this tree. A *.violation.cfg is
    # a configuration the author asserts SHOULD fail; if TLC finds no error under it, the
    # invariant was vacuous and the drill says so.
    violations = sorted(f for f in os.listdir(TLA_DIR) if f.endswith(".violation.cfg"))
    did_not_fail = []
    for cfg in violations:
        spec = cfg[:-len(".violation.cfg")] + ".tla"
        if not os.path.exists(os.path.join(TLA_DIR, spec)):
            did_not_fail.append("%s names no spec" % cfg)
            continue
        out, _code = check(spec, cfg)
        if "Model checking completed. No error has been found." in out:
            did_not_fail.append("%s: the invariant held, so it is vacuous" % cfg)
        else:
            broken = re.search(r"Error: Invariant (\w+) is violated", out)
            _note("  %s" % cfg[:-len(".cfg")],
                  "%s fails" % (broken.group(1) if broken else "invariant"))
    _row("every counterpart configuration DOES violate its invariant", did_not_fail, [])
    _note("counterpart configurations", len(violations))

    print()
    if not _cases_recorded:
        print("FAIL: this drill recorded NO cases. It tested nothing and would "
              "have printed its summary regardless.", file=sys.stderr)
        return 1
    if _ok_all:
        print("OK: every spec in meta/tla is parsed, configured, model-checked and BOUND to the "
              "objects it claims to describe. That last part is what makes maintenance possible "
              "rather than aspirational: the README used to argue against a standing set of "
              "specs on the grounds that a model which has drifted from the schema is worse "
              "than no model, and it was right, because the one unmaintained spec had already "
              "drifted to an index name that exists nowhere in the tree. Drift is not prevented "
              "by care. It is detected by a citation that has to resolve, on the push that "
              "breaks it.")
        return 0
    print("FAIL: a spec did not check, or a binding did not resolve", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
