#!/usr/bin/env python3
"""polaris-move-mutation-drill.py -- put the violation in a SIBLING module. Does anything notice?

THE THIRD QUESTION, and the one nothing in this tree asks yet.

    polaris-check-mutation-drill        delete the mechanism in place      -> 112/112 caught
    polaris-coverage-mutation-drill     add a bad member to a surface      -> 14/14 caught
    polaris-constitution-mutation-drill delete a constraint's enforcement  -> 10/10 caught

All three hold the mechanism's FILE fixed. 271 of the 282 checks read files as text, and 77
of them name `polaris_web/app.py` by path. So a mechanism that MOVES to a file the check does
not read is the one change none of them can see: the deletion drill finds nothing missing
(the code still exists), and the coverage drill finds nothing added (the surface it scans is
unchanged). The check keeps passing and the guarantee is somewhere else.

That is not hypothetical. `app.py` is 9,370 lines and the standing plan is to split it into
domain modules. On the day that happens, every check that greps a path stops looking where
the code went, and stays green while doing it.

WHAT IT FOUND, and what changed. First run, 2026-09-18, before anything was touched: 3 of 3.
Every violation caught in `app.py` went completely undetected one file over. 73 check call
sites then moved from `_read(root, "polaris_web/app.py")` to `_read_app(root)`, which reads
every non-test module of the package, and three checks that PARSE moved to walking each
module's tree; the same run is now 3 of 3 CAUGHT. That is the measurement that turns the
decomposition from a bet into a refactor, and this drill is what keeps it true.

WHAT IT DOES. It takes violations the coverage drill already proved are caught when they live
in `app.py`, and writes the same violation into a NEW module beside it instead. Nothing is
deleted and no existing file is edited except one import line, so the application still
imports. Then it asks the same question by name:

    survivor = a check that catches this violation in app.py and misses it one file over

A survivor is not a broken check. It is a check whose reach is a PATH rather than a package,
which is exactly the property the decomposition needs to remove first.

METHOD. Each case is a payload already shown to be caught in `app.py` by the coverage drill.
Writing it to `polaris_web/<module>.py` changes only where it lives. The expected check is
asserted BY NAME, for the same reason the other drills do it: a neighbour going red is not
evidence that this check followed the code.

RESTORATION. Only new files are created, and they are deleted in a `finally`. `app.py` gains
one import line and is written back byte for byte. The repair prints before anything is
touched, and the drill refuses a dirty tree.

POSITIVE CONTROL. The unmutated tree must report no failures first, or every case below looks
detected by a tree that was already red.

  python3 scripts/polaris-move-mutation-drill.py
  python3 scripts/polaris-move-mutation-drill.py --only c8_atlas_caps
"""
from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
WEB = ROOT / "polaris_web"


# --------------------------------------------------------------------------------------
# The payloads. Each is a violation the coverage drill already proved is caught when it
# lives in app.py; here it lives one file over, and nothing else changes.
# --------------------------------------------------------------------------------------

_HEADER = '''"""MUTATION: a domain module of the kind an app.py decomposition produces.

Nothing here is new behaviour. Every line below is a violation the coverage drill proves is
caught when it sits in app.py. The only thing that changed is which file it sits in."""
from flask import jsonify, request

from app import app, _query, login_required           # noqa: F401
'''

_ATLAS = '''

@app.route('/api/atlas/moved-drill')
@login_required
def api_atlas_moved_drill():
    """A caller-controlled count with no upper bound, in a sibling module."""
    limit = int(request.args.get('limit', '500'))
    return jsonify({'rows': _query("SELECT 1 FROM VerificationEvent LIMIT %s", (limit,))})
'''

_LOCATION = '''

def _moved_drill_locations():
    """A verification location read with no disclosure-level clause, in a sibling module."""
    return _query("""
        SELECT ve.event_id, ve.requestor_location, ve.latitude, ve.longitude
          FROM VerificationEvent ve
         ORDER BY ve.event_id DESC
         LIMIT 100
    """)
'''

_JSON = '''

@app.route('/api/moved-drill/json', methods=['POST'])
@login_required
def api_moved_drill_json():
    """A JSON body that does not go through _json_object(), in a sibling module."""
    body = request.get_json(silent=True) or {}
    return jsonify({'got': sorted(body)})
'''


_CLOCK = '''
import datetime


def _moved_drill_boundary():
    """A UTC clock read, in a sibling module.

    The DB stores local-wall-clock TIMESTAMPs, so comparing against utcnow() is off by the
    offset. check_local_clock_convention is an ABSENCE check, which is the opposite shape
    from the three above: widening makes an absence check STRICTER, so this is the case
    that proves the widening did not simply loosen everything."""
    return datetime.datetime.utcnow()
'''

_UNDOCUMENTED = '''

@app.route('/api/v1/moved-drill-undocumented')
@login_required
def api_moved_drill_undocumented():
    """An /api route with no heading in the API reference, in a sibling module."""
    return jsonify({'ok': True})
'''


_NETWORK = '''"""MUTATION: a module of the kind a polaris-verify split would produce.

The detached verifier's promise is that it decides OFFLINE, and it holds that property by
containing NO code that could reach a network at all -- which is stronger than not reaching
one today. That is a property of the package, and verifier.py is 4,806 lines in a two-module
package, so the same split pressure app.py is under applies here."""
import requests


def fetch_status(url):
    return requests.get(url).json()
'''


#: (expected check, what moved, module name, payload).
#: Every payload is one the coverage drill catches in app.py. If a case survives here, the
#: difference is the FILE and nothing else, which is the whole measurement.
MOVES = [
    ("c8_atlas_caps", "an unclamped Atlas count moves to a sibling module",
     "atlas_routes_moved", _ATLAS),
    ("c6_app_read_paths", "an unredacted location query moves to a sibling module",
     "event_queries_moved", _LOCATION),
    ("json_body_object", "a raw JSON body moves to a sibling module",
     "api_routes_moved", _JSON),
    # Deliberately different check SHAPES, so the drill is not three tests of one parser:
    # c8 slices route bodies by line, c6 walks parsed string constants, json_body_object
    # walks a syntax tree, local_clock is a plain substring ABSENCE, and
    # api_routes_documented discovers routes and cross-references a document.
    ("local_clock", "a utcnow() boundary moves to a sibling module",
     "clock_helpers_moved", _CLOCK),
    ("api_routes_documented", "an undocumented /api route moves to a sibling module",
     "public_api_moved", _UNDOCUMENTED),
    # A different package, and the sharpest case in the tree: the OFFLINE guarantee on the
    # primary external door. Measured before this was fixed, a sibling module importing
    # `requests` passed check_detached_verifier with an OK that still said the verifier was
    # standalone.
    ("detached_verifier", "network code moves into a sibling of the detached verifier",
     "status_client_moved", _NETWORK, "verify"),
]


VERIFY_PKG = ROOT / "packages" / "polaris-verify" / "polaris_verify_cli"

#: Modules land beside the file whose mechanism they are taking, so a case names its
#: package. polaris-verify is here for the same reason polaris_web is: one 4,806-line file
#: that 40 checks read by path, and a promise ("contains no code that could reach a
#: network") that is about the package rather than about that file.
_PKG = {"web": WEB, "verify": VERIFY_PKG}


def _target(case):
    return _PKG[case[4] if len(case) > 4 else "web"] / ("%s.py" % case[2])


#: reported check name -> the functions that report it, built once from the control run.
_BY_NAME: dict = {}


def _load_checks():
    sys.path.insert(0, str(ROOT))
    from polaris_checks import checks as _c
    return _c


def _build_name_map(mod, root) -> list:
    """The positive control AND the name->function map, from one sweep."""
    failing = []
    for fn in mod.CHECKS:
        try:
            out = fn(root)
        except Exception:
            continue
        for f in out:
            _BY_NAME.setdefault(f.check, set()).add(fn)
            if f.level == "FAIL":
                failing.append(f.check)
    return failing


def _named_check_fails(mod, root, name: str) -> bool:
    for fn in _BY_NAME.get(name) or ():
        try:
            if any(f.level == "FAIL" for f in fn(root)):
                return True
        except Exception:
            return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0] or None)
    ap.add_argument("--only", help="run one case, by the name of its check")
    args = ap.parse_args()

    created = [_target(m) for m in MOVES]
    print("REPAIR, if this run is killed:")
    print("  git checkout -- polaris_web/app.py")
    print("  rm -f " + " ".join(str(p.relative_to(ROOT)) for p in created))
    print()

    dirty = subprocess.run(["git", "status", "--porcelain", "--", "polaris_web/app.py"],
                           cwd=str(ROOT), capture_output=True).stdout.decode().strip()
    if dirty:
        print("uncommitted changes in polaris_web/app.py:\n%s\n\nIts documented repair is "
              "`git checkout --`, which would throw them away. Commit or stash first."
              % dirty, file=sys.stderr)
        return 2
    for p in created:
        if p.exists():
            print("%s already exists; refusing to overwrite it" % p, file=sys.stderr)
            return 2

    print("positive control: the unmutated tree must report no failures")
    mod = _load_checks()
    before = _build_name_map(mod, ROOT)
    if before:
        print("== VOID: %d check(s) already failing (%s). Every case below would look "
              "detected by a tree that was already red ==" % (len(before), ", ".join(before)),
              file=sys.stderr)
        return 2
    print("   clean\n")

    cases = [m for m in MOVES if not args.only or m[0] == args.only]
    if not cases:
        print("no case named %r" % args.only, file=sys.stderr)
        return 2

    app_path = WEB / "app.py"
    survivors = []
    for case in cases:
        expected, what, modname, payload = case[:4]
        new = _target(case)
        original = app_path.read_text()
        try:
            # The verifier payload is a whole module and imports nothing from the app; the
            # polaris_web ones share a header that wires them into the running application.
            new.write_text(payload if len(case) > 4 else _HEADER + payload)
            # One import, so the module is genuinely part of the application rather than a
            # file lying beside it. A check that scans the package finds the violation; a
            # check that greps app.py finds only this line.
            if len(case) <= 4:
                app_path.write_text(original + "\nimport %s  # noqa: E402,F401\n" % modname)
            caught = _named_check_fails(mod, ROOT, expected)
        finally:
            app_path.write_text(original)
            new.unlink(missing_ok=True)

        print("%-22s %-58s %s" % (expected, what, "caught" if caught else "SURVIVED"))
        if not caught:
            survivors.append((expected, what))

    print("\nviolations moved one file over  %d" % len(cases))
    print("the check followed the code     %d" % (len(cases) - len(survivors)))
    print("SURVIVED (went blind)           %d" % len(survivors))

    if survivors:
        print("\n== %d CHECK(S) CATCH THIS VIOLATION IN app.py AND MISS IT ONE FILE OVER =="
              % len(survivors))
        for expected, what in survivors:
            print("   %-22s %s" % (expected, what))
        print("\nEach reads `polaris_web/app.py` by path, so its reach is a FILE and its "
              "sentence is about the application. That difference is invisible today because "
              "the code has not moved yet. It stops being invisible the moment app.py is "
              "split, and then it is silent rather than loud: nothing goes red, the "
              "guarantee is simply somewhere the check does not look.")
        return 1

    print("\n== Every violation here is caught in a sibling module as well as in the file it "
          "was taken from, so these checks reach the PACKAGE and not one path. That is a "
          "statement about these "
          "%d payloads, not about the check layer in general: a mechanism nobody thought to "
          "move is this drill's standing limitation. ==" % len(cases))
    return 0


if __name__ == "__main__":
    sys.exit(main())
