#!/usr/bin/env python3
"""polaris-review-packet-drill.py - the review packet cannot quietly stop being true (P1.18 item 8).

A packet handed to an external reviewer is a set of claims about a codebase, written once and
read by somebody who cannot check them. It rots the way every such document rots: a check gets
renamed, a drill gets deleted, a limitation gets fixed, and the page keeps saying what it said.
Nothing turns red. The document just becomes untrue, and it is most untrue exactly where it
matters -- in the hands of the reviewer it was written for.

So the packet is executable, in both directions.

  EVERY CITATION RESOLVES, and every cited check RUNS. Naming a check that fails is the same as
  naming one that is gone. This half is the discipline the 800-63 mapping already uses.

  EVERY LIMITATION IS VERIFIED STILL TRUE. This half is the new one, and it is the reason the
  packet is worth more than a humility section. Each limitation carries a WITNESS: a file and a
  string that must still be present for the limitation to hold. Implement the external ledger
  backend and the witness string goes; the drill fails; the entry has to be removed. A list of
  limitations that can only be appended to is a confession nobody maintains. One checked in both
  directions is a record of where the system actually stands.

  THE MATRIX MUST NOT FLATTER. Every threat row has to name what does NOT stand in the way. A
  row with a mechanism and no residual is the half of the picture that reassures, and it is the
  half a reviewer can already read in the check names.

  AND THE PACKET MUST SAY NOBODY HAS REVIEWED IT. Every guarantee here is checked by machinery
  written by the same author as the guarantee. A packet that opens by listing its controls
  without saying that is the exact failure it exists to prevent.

WHAT THIS DOES NOT DO. It cannot tell you a threat row is COMPLETE, that the residual column
names the worst residual, or that a cited mechanism really holds the guarantee. Those are a
reviewer's judgement and no script substitutes for one. What it guarantees is narrower and still
worth having: nothing on the page points at something that has gone, and no limitation on it has
quietly stopped being true.

Run: python3 scripts/polaris-review-packet-drill.py
Exit 0 iff every citation resolves and every limitation still holds; 3 to skip.
"""
from __future__ import annotations

import os
import pathlib
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = pathlib.Path(os.path.dirname(HERE))
sys.path.insert(0, str(ROOT))

PACKET = ROOT / "docs" / "REVIEW-PACKET.md"

#: The packet is worthless if it omits the sentence that frames everything else.
REQUIRED_ADMISSIONS = (
    "none of it has been reviewed by anybody outside this repository",
    "a system has checked itself",
)

_ok_all = True


#: Cases this drill actually recorded. A drill whose cases are removed or
#: short-circuited in a refactor prints its whole summary and exits 0 anyway,
#: which is a guarantee reported by something that tested nothing (v9.403).
_cases_recorded = 0


def case(label, got, want):
    global _cases_recorded
    _cases_recorded += 1
    global _ok_all
    ok = got == want
    _ok_all = _ok_all and ok
    shown = str(got)
    if len(shown) > 40:
        shown = shown[:37] + "..."
    print("  %-62s %-42s %s" % (label, shown, "ok" if ok else "FAIL"))
    return ok


def rows_of(table_text):
    """Data rows of a markdown table: cells, header and separator dropped."""
    out = []
    for line in table_text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not cells or set("".join(cells)) <= set("- "):
            continue
        out.append(cells)
    return out[1:] if out else []


def section(text, heading):
    """The text between one `## heading` and the next `## `."""
    start = text.index(heading)
    rest = text[start + len(heading):]
    end = rest.find("\n## ")
    return rest if end < 0 else rest[:end]


def main():
    global _ok_all
    if not PACKET.exists():
        print("review-packet drill: docs/REVIEW-PACKET.md is missing", file=sys.stderr)
        return 3
    try:
        from polaris_checks import checks as C
    except ImportError as exc:  # noqa: BLE001
        print("review-packet drill needs polaris_checks: %s" % exc, file=sys.stderr)
        return 3
    by_name = {f.__name__.replace("check_", ""): f for f in C.CHECKS}
    text = PACKET.read_text(encoding="utf-8")

    print("the review packet cannot quietly stop being true")
    print()
    print("  %-62s %-42s %s" % ("case", "got", "ok"))

    # THE PACKET SAYS NOBODY HAS REVIEWED IT.
    missing_admission = [a for a in REQUIRED_ADMISSIONS if a not in text]
    case("the packet states that nothing here has been externally reviewed",
         missing_admission, [])

    # EVERY CITATION RESOLVES.
    unresolved = []
    cited_checks = set()
    for kind, target in re.findall(r"`(check|drill|test|witness):([^`]+)`", text):
        if kind == "check":
            if target not in by_name:
                unresolved.append("check:%s" % target)
            else:
                cited_checks.add(target)
        elif kind == "drill":
            if not (ROOT / target).exists():
                unresolved.append("drill:%s" % target)
        elif kind == "test":
            path, _, cls = target.partition("::")
            f = ROOT / path
            if not f.exists():
                unresolved.append("test file %s" % path)
            elif cls and ("class %s" % cls) not in f.read_text(encoding="utf-8"):
                unresolved.append("test class %s in %s" % (cls, path))
    case("every check, drill and test citation resolves", unresolved, [])
    case("the packet cites checks at all (a packet citing nothing proves nothing)",
         len(cited_checks) > 10, True)

    # EVERY CITED CHECK PASSES.
    failing = []
    for target in sorted(cited_checks):
        if any(f.level == "FAIL" for f in by_name[target](ROOT)):
            failing.append(target)
    case("every cited check PASSES against this tree", failing, [])
    print("    distinct checks cited and run: %d" % len(cited_checks))

    # EVERY LIMITATION IS STILL TRUE.
    #
    # The witness is the whole mechanism. A limitation whose witness string has
    # gone is a limitation that was FIXED, and leaving it on the page tells a
    # reviewer the system is weaker than it is -- which is its own kind of
    # dishonesty, and the kind nobody notices because it reads as modesty.
    lim_rows = rows_of(section(text, "## 2. Known limitations"))
    stale, unwitnessed = [], []
    for cells in lim_rows:
        ident = cells[0] if cells else "?"
        joined = " ".join(cells)
        m = re.search(r"`witness:([^:`]+(?::[^:`]+)*)::([^`]+)`", joined)
        if not m:
            unwitnessed.append(ident)
            continue
        path, needle = ROOT / m.group(1), m.group(2)
        if not path.exists() or needle not in path.read_text(encoding="utf-8"):
            stale.append("%s (%s :: %s)" % (ident, m.group(1), needle[:30]))
    case("every limitation carries a witness", unwitnessed, [])
    case("every limitation is STILL TRUE (its witness resolves)", stale, [])
    print("    limitations verified still true: %d" % len(lim_rows))

    # THE MATRIX NAMES WHAT DOES NOT STAND IN THE WAY.
    matrix = rows_of(section(text, "## 1. Threat matrix by subsystem"))
    flattering = [c[0] for c in matrix if len(c) < 4 or len(c[3]) < 40]
    case("every threat row names what does NOT stand in the way", flattering, [])
    uncited = [c[0] for c in matrix
               if not re.search(r"`(check|drill|test):", c[2] if len(c) > 2 else "")]
    case("every threat row cites a mechanism", uncited, [])
    print("    subsystems in the matrix: %d" % len(matrix))

    # THE ATTACK PROMPTS NAME A MECHANISM AND AN OUTCOME.
    attacks = rows_of(section(text, "## 3. Guarantee-attack prompts"))
    vague = [c[0] for c in attacks if len(c) < 4 or len(c[3]) < 30]
    case("every attack prompt says what a successful attack PRODUCES", vague, [])
    case("the packet offers attacks worth an engagement", len(attacks) >= 8, True)
    print("    attack prompts offered: %d" % len(attacks))

    print()
    if not _cases_recorded:
        print("FAIL: this drill recorded NO cases. It tested nothing and would "
              "have printed its summary regardless.", file=sys.stderr)
        return 1
    if _ok_all:
        print("PASS: every citation on the packet resolves and passes, and every limitation on "
              "it is still true.")
        print("The second half is the one that matters. A limitations list that can only be "
              "appended to is a confession nobody maintains; this one fails the build when a "
              "limitation is FIXED, so the page can only ever describe where the system "
              "actually stands.")
        return 0
    print("FAIL: at least one case did not hold", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
