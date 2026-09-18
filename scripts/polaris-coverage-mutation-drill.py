#!/usr/bin/env python3
"""polaris-coverage-mutation-drill.py -- grow a surface by one bad member; does anything notice?

EVERY OTHER MUTATION DRILL IN THIS TREE ASKS THE SAME QUESTION: delete the mechanism, does a
check go red? Constraints, triggers, procedures, the conformance runner, both SDKs, the ZK
witnesses, the application's refusals, the ten constitutional constraints. All of them test
ENFORCEMENT, and by 2026-09-17 all of them passed.

That is not the defect this project keeps finding. Four in one week, and every one the same
shape: a property stated over a WHOLE SURFACE, enforced and pinned only on the part somebody
was looking at.

  the word duress   was gated on four operator pages, found by grepping a column name. The
                    property is about every page an operator can open. Five more carried it.
  C6                was pinned on the Atlas SQL. MISSION states it over "every read path (the
                    Atlas functions in 11_atlas.sql, the event queries in app.py)". A fifth
                    query in the app.py half would have shipped green.
  C8                had a check reading "all 10 caller-controlled counts across 17 atlas
                    routes are clamped" whose regex accepted `limit <= 0`, a LOWER bound. The
                    real clamp could be deleted green.
  C1                named fourteen audit-of-record tables while the schema guarded
                    thirty-four, and its check asks only about the names it is handed.

None of those is an enforcement failure. In each, the mechanism was present and correct
everywhere anyone had looked, and the check's reach was narrower than its own sentence. An
enforcement drill cannot see that, because the member it would have to delete was never
there.

SO THIS DRILL RUNS THE MIRROR. It ADDS a member to a surface: a new route, a new query, a new
table, a new migration, a new document. The member is a violating one, of exactly the kind
somebody will add next year without thinking about it.

  survivor = a check whose "every" covers only what it was handed, so the surface can grow
             past it in silence

A survivor is not a broken check. It is a check whose claim is larger than its reach, which
is the thing that shipped four times this week.

METHOD. One mutation per surface, each the smallest addition that violates the property while
leaving the file valid. The expected check is asserted BY NAME: a mutation that turns some
neighbouring check red is not evidence that THIS surface is covered, and counting failures
instead of naming one is how a drill flatters itself.

RESTORATION. Every file is read before it is touched and written back in a `finally`; created
files are deleted. A killed run can still leave one behind, so the repair line prints BEFORE
anything is written, and the drill refuses to start against a dirty tree, because its repair
for a modified file is `git checkout --`.

POSITIVE CONTROL. The unmutated tree must report no failures first. Without that, a tree that
was already red makes every mutation look detected, which is how the first draft of the
application drill reported a perfect result in one second.

  python3 scripts/polaris-coverage-mutation-drill.py
  python3 scripts/polaris-coverage-mutation-drill.py --only c8_atlas_caps
"""
from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------------------
# The additions. Each returns the mutated text of an existing file, or is a (path, text)
# pair for a file that does not exist yet.
# --------------------------------------------------------------------------------------

def _append_route(app: str, block: str) -> str:
    """Add a route at the end of app.py, before any `if __name__` guard.

    Appending after the guard would put the route in dead code for anything that reads the
    file as a module, and more to the point a check that slices route bodies by the NEXT
    route start needs a following line to slice to.
    """
    i = app.find("\nif __name__ ==")
    return app + block if i < 0 else app[:i] + block + app[i:]


#: A new Atlas route that reads a caller-controlled count and never clamps it. C8 is "every
#: Atlas aggregate is bounded"; this is the aggregate somebody adds next.
_NEW_ATLAS_ROUTE = '''

@app.route('/api/atlas/coverage-drill')
@login_required
def api_atlas_coverage_drill():
    """MUTATION: a caller-controlled count with no upper bound."""
    limit = int(request.args.get('limit', '500'))
    rows = _query("SELECT 1 FROM VerificationEvent LIMIT %s", (limit,))
    return jsonify({'rows': rows})
'''

#: A new query reading a verification location with no ZERO_KNOWLEDGE clause. C6 is
#: redaction at EVERY read path, and this is a read path.
_NEW_LOCATION_QUERY = '''

def _coverage_drill_locations():
    """MUTATION: a verification location read with no disclosure-level clause."""
    return _query("""
        SELECT ve.event_id, ve.requestor_location, ve.latitude, ve.longitude
          FROM VerificationEvent ve
         ORDER BY ve.event_id DESC
         LIMIT 100
    """)
'''

#: A new JSON route taking its body the old way. The property is that EVERY JSON body goes
#: through _json_object(), which answers an empty object rather than a list or a string.
_NEW_JSON_ROUTE = '''

@app.route('/api/coverage-drill/json', methods=['POST'])
@login_required
def api_coverage_drill_json():
    """MUTATION: a JSON body that does not go through _json_object()."""
    body = request.get_json(silent=True) or {}
    return jsonify({'got': sorted(body)})
'''

#: A new state-changing route. Unlike every other addition here this one is NOT expected to
#: be flagged, and the reason is the point: rate limiting is a `before_request` hook keyed on
#: `request.method in ('POST', 'PUT', 'PATCH', 'DELETE')`, so a route that does not exist yet
#: is already covered by it. There is no list to fall off.
#:
#: The first run of this drill reported it as a survivor, which was wrong. The mutation was
#: not a violation, so "nothing noticed" was the correct answer and the drill called it a
#: finding. A mutation that does not violate the property measures nothing, and reports the
#: check as blind when the check was right: the same error as a regex that removes a comment
#: instead of a constraint. Kept, moved, and its expectation inverted.
_NEW_WRITE_ROUTE = '''

@app.route('/api/coverage-drill/write', methods=['POST'])
@login_required
def api_coverage_drill_write():
    """MUTATION: a write route, covered by the before_request hook and not by a list."""
    return jsonify({'ok': True})
'''

#: A new table under the C1 append-only mechanism that nobody classified. The property is
#: that every guarded table is an instance in the design record or a declared entity.
_NEW_GUARDED_TABLE = '''

-- MUTATION: a new append-only table nobody classified.
DROP TRIGGER IF EXISTS trg_coverage_drill_append_only ON CoverageDrillEvent;
CREATE TRIGGER trg_coverage_drill_append_only
    BEFORE UPDATE OR DELETE ON CoverageDrillEvent
    FOR EACH ROW EXECUTE FUNCTION reject_audit_modification();
'''

#: A new alert with no runbook section. The property is every shipped alert has exactly one.
_NEW_ALERT = '''
  - alert: PolarisCoverageDrillAlert
    expr: up == 0
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "MUTATION: an alert with no runbook section"
'''


#: A new Athena function that does not cap its output. Athena inherits the Atlas C8
#: discipline, and an unbounded aggregation surface beside the Atlas is the thing that
#: discipline exists to prevent.
_NEW_ATHENA_UNBOUNDED = '''

CREATE OR REPLACE FUNCTION athena_coverage_drill_unbounded()
RETURNS TABLE (agency_id INTEGER) LANGUAGE sql STABLE AS $fn$
    -- MUTATION: no LIMIT.
    SELECT agency_id FROM Agency;
$fn$;
'''

#: A new Athena function that writes. Athena contributes explanation, never permission;
#: "the graph says revoke, therefore revoked" is the thing invariant 5 forbids.
_NEW_ATHENA_WRITES = '''

CREATE OR REPLACE FUNCTION athena_coverage_drill_writes()
RETURNS TABLE (agency_id INTEGER) LANGUAGE sql STABLE AS $fn$
    -- MUTATION: Athena acting rather than explaining. The column list is REAL: this
    -- statement is scanned by the schema-drift drill like every other INSERT in the tree,
    -- and a mutation that names a column the schema lacks fails that drill instead of
    -- testing this one (it did, on 2026-09-17, and turned CI red for three commits).
    INSERT INTO AuditAccessLog (accessed_table) VALUES ('drill');
    SELECT agency_id FROM Agency LIMIT 10;
$fn$;
'''

#: A new prod-compose service with no resource limits and no log rotation. One unbounded
#: container can OOM the host; unrotated logs fill the disk.
_NEW_COMPOSE_SERVICE = '''
  coverage-drill:
    image: alpine:3.20
    command: ["sleep", "3600"]
'''

#: A new prod-compose service that IS resource-bounded and DOES rotate logs, so it clears
#: compose_limits, and drops no capabilities. The point of two nearly identical payloads is
#: that a surface can satisfy one of its checks and not the other, and the drill must catch
#: the second by name rather than be satisfied by the first going red.
_NEW_COMPOSE_UNHARDENED = '''
  coverage-drill-caps:
    image: alpine:3.20
    command: ["sleep", "3600"]
    deploy:
      resources:
        limits:
          memory: 64M
          cpus: "0.10"
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
'''


def _new_doc_example() -> list:
    """A documented polaris-verify invocation that does not say what cryptography it is doing.

    The product contract: the verifier refuses to run until the caller names its mode, and a
    fenced example in any document must name one too, or a reader copies a command that
    exits 4. A NEW document is the way that surface grows.
    """
    return [("docs/design/coverage-drill-example.md",
             "# MUTATION: a documented invocation with no crypto mode\n\n"
             "```bash\npolaris-verify --pack credential.json\n```\n")]


#: A new stylesheet rule naming an animation that no @keyframes defines.
_NEW_CSS_ANIMATION = '''
.coverage-drill-mutation {
    animation: coverage-drill-phantom 2s linear infinite;
}
'''


def _new_template() -> tuple:
    return ("polaris_web/templates/coverage_drill_phantom.html",
            "{% extends 'base.html' %}\n{% block content %}\n"
            "<a href=\"{{ url_for('coverage_drill_route_that_does_not_exist') }}\">"
            "MUTATION: a url_for to a route nobody defines</a>\n{% endblock %}\n")


def _new_migration_column() -> tuple:
    return ("polaris_sql/migrations/2099-01-01-998-coverage-drift.up.sql",
            "-- MUTATION: a column added by a migration and never declared in 01_schema.sql.\n"
            "ALTER TABLE Agency ADD COLUMN IF NOT EXISTS coverage_drill_drift TEXT;\n")


def _new_migration_down() -> tuple:
    return ("polaris_sql/migrations/2099-01-01-998-coverage-drift.down.sql",
            "-- The down half, so this mutation tests column drift and not reversibility.\n"
            "ALTER TABLE Agency DROP COLUMN IF EXISTS coverage_drill_drift;\n")


def _new_migration() -> list:
    return [("polaris_sql/migrations/2099-01-01-999-coverage-drill.up.sql",
             "-- MUTATION: an up migration with no down beside it.\n"
             "CREATE TABLE IF NOT EXISTS CoverageDrillOnly (drill_id SERIAL PRIMARY KEY);\n")]


def _new_doc() -> list:
    return [("docs/design/coverage-drill-unlinked.md",
             "# MUTATION: a design record no README links to\n\nIt should not be reachable "
             "only by knowing it is there.\n")]


def _new_drifting_migration() -> list:
    """Both halves, so this measures column drift rather than reversibility.

    Creating only the .up.sql would fail `migrations_reversible` instead, and the drill
    would credit a neighbouring check for a surface it was not testing.
    """
    return [_new_migration_column(), _new_migration_down()]


def _new_phantom_template() -> list:
    return [_new_template()]


#: (id, what is added, target -> mutation, the check whose name must appear in a FAIL).
#: `target` is a repo-relative path. A callable mutates its existing text; a tuple is a file
#: created from nothing and deleted afterwards.
MUTATIONS = [
    ("c8_atlas_caps", "an Atlas route reads a caller-controlled count and never clamps it",
     "polaris_web/app.py", lambda t: _append_route(t, _NEW_ATLAS_ROUTE)),

    ("c6_app_read_paths", "a query reads a verification location with no ZERO_KNOWLEDGE clause",
     "polaris_web/app.py", lambda t: t + _NEW_LOCATION_QUERY),

    ("json_body_object", "a JSON route takes its body without _json_object()",
     "polaris_web/app.py", lambda t: _append_route(t, _NEW_JSON_ROUTE)),

    ("api_routes_documented", "an /api route ships with no heading in the API reference",
     "polaris_web/app.py", lambda t: _append_route(t, _NEW_JSON_ROUTE)),

    ("aor_surface_derived", "a table joins the C1 append-only mechanism unclassified",
     "polaris_sql/06_triggers.sql", lambda t: t + _NEW_GUARDED_TABLE),

    ("alert_runbooks", "an alert ships with no runbook section",
     "deploy/observability/polaris-alerts.yml", lambda t: t + _NEW_ALERT),

    ("migrations_reversible", "a migration ships with no down beside it",
     None, _new_migration),

    ("docs_index_coverage", "a design record ships that no README links to",
     None, _new_doc),

    # Second wave, 2026-09-17. Surfaces where growth is security-relevant: an unbounded
    # aggregate, a reasoning layer that acts, a container with no ceiling.
    ("athena_bounded", "an Athena function ships without a LIMIT on its output",
     "polaris_sql/16_athena.sql", lambda t: t + _NEW_ATHENA_UNBOUNDED),

    ("athena_read_only", "an Athena function ships that WRITES rather than explains",
     "polaris_sql/16_athena.sql", lambda t: t + _NEW_ATHENA_WRITES),

    ("compose_limits", "a prod-compose service ships with no memory ceiling or log rotation",
     "polaris_web/docker-compose.prod.yml", lambda t: t + _NEW_COMPOSE_SERVICE),

    ("css_animations", "a stylesheet names an animation no @keyframes defines",
     "polaris_web/static/polaris.css", lambda t: t + _NEW_CSS_ANIMATION),

    ("template_endpoints", "a template links to a route nobody defines",
     None, _new_phantom_template),

    ("migration_drift", "a migration adds a column 01_schema.sql never declares",
     None, _new_drifting_migration),

    # Third wave, 2026-09-18. Surfaces where a new member is a security or honesty
    # regression rather than an untidiness.
    ("container_hardening", "a bounded, log-rotating service ships dropping no capabilities",
     "polaris_web/docker-compose.prod.yml", lambda t: t + _NEW_COMPOSE_UNHARDENED),

    ("documented_commands_run", "a documented verifier invocation names no crypto mode",
     None, _new_doc_example),
]


#: Surfaces closed BY CONSTRUCTION rather than by an enumerating check. A new member is
#: covered the moment it exists, so nothing should flag it and "nothing noticed" is the right
#: answer rather than a survivor.
#:
#: A declaration like this is the obvious way to launder a real gap, so it is not taken on
#: its word. Each entry names the construction and a pattern that must still be in the file:
#: the moment the hook becomes a per-route decorator, the construction is gone, growth CAN
#: escape, and this drill fails instead of quietly continuing to excuse the surface.
BY_CONSTRUCTION = [
    ("rate_limits", "a state-changing route arrives", "polaris_web/app.py",
     lambda t: _append_route(t, _NEW_WRITE_ROUTE),
     r"@app\.before_request[\s\S]{0,2000}?request\.method in \('POST', 'PUT', 'PATCH', 'DELETE'\)"
     r"[\s\S]{0,400}?rate_limiter\.allow",
     "a before_request hook rate-limits by METHOD, so a route that does not exist yet is "
     "already covered and there is no list to fall off"),
]


#: reported check name -> the functions that report it, built once from the control run.
_BY_NAME: dict = {}


def _load_checks():
    """Import the check layer in-process, so one check can be run without the other 281.

    A full run is about 19 seconds. This drill asks the same narrow question of every
    mutation -- "did THIS named check go red?" -- and answering it by running the whole
    layer each time cost 16 of those, which put 7.7 minutes on CI's critical path for a
    result that is 14 lines long. One check is about 0.09 seconds.
    """
    sys.path.insert(0, str(ROOT))
    from polaris_checks import checks as _c
    return _c


def _build_name_map(mod, root) -> list:
    """Run the whole layer once: the positive control AND the name->function map.

    A check's reported name is only knowable by running it (check_c8_atlas_caps reports
    `c8_atlas_caps`), so the map falls out of the control run rather than costing a
    second one.
    """
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
    """Does the one check called `name` report FAIL against the tree as it stands now?"""
    fns = _BY_NAME.get(name)
    if not fns:
        return False
    for fn in fns:
        try:
            if any(f.level == "FAIL" for f in fn(root)):
                return True
        except Exception:
            return True          # a check that crashes on the mutation noticed it
    return False


def _failing_checks(mod=None, root=None) -> list:
    """Every check reporting FAIL. The slow path, used for the control and for a survivor.

    A survivor is the one case where the drill has to say what DID fail instead, so the
    full sweep is paid only when there is a finding to explain.
    """
    if mod is not None:
        return [f.check for fn in mod.CHECKS for f in _safe(fn, root) if f.level == "FAIL"]
    r = subprocess.run([sys.executable, "-m", "polaris_checks.run"],
                       cwd=str(ROOT), capture_output=True)
    out = (r.stdout or b"").decode("utf-8", "replace")
    return re.findall(r"✗ \[(\w+)\]", out)


def _safe(fn, root) -> list:
    try:
        return fn(root)
    except Exception:
        return []


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0] or None)
    ap.add_argument("--only", help="run one surface, by the name of its check")
    args = ap.parse_args()

    modified = sorted({rel for _c, _w, rel, _m in MUTATIONS if rel})
    print("REPAIR, if this run is killed:")
    print("  git checkout -- " + " ".join(modified))
    created = [rel_ for _c, _w, r, m in MUTATIONS if r is None for rel_, _b in m()]
    print("  rm -f " + " ".join(created))
    print()

    dirty = subprocess.run(["git", "status", "--porcelain", "--"] + modified,
                           cwd=str(ROOT), capture_output=True).stdout.decode().strip()
    if dirty:
        print("uncommitted changes in a file this drill rewrites:\n%s\n\nIts documented "
              "repair is `git checkout --`, which would throw them away. Commit or stash "
              "first." % dirty, file=sys.stderr)
        return 2

    print("positive control: the unmutated tree must report no failures")
    mod = _load_checks()
    before = _build_name_map(mod, ROOT)
    if before:
        print("== VOID: %d check(s) already failing (%s). Every mutation below would look "
              "detected by a tree that was already red ==" % (len(before), ", ".join(before)),
              file=sys.stderr)
        return 2
    print("   clean\n")

    cases = [m for m in MUTATIONS if not args.only or m[0] == args.only]
    if not cases:
        print("no surface named %r" % args.only, file=sys.stderr)
        return 2

    survivors, seen = [], set()
    for expected, what, rel, mutate in cases:
        if rel:
            path = ROOT / rel
            original = path.read_text()
            try:
                path.write_text(mutate(original))
                if path.read_text() == original:
                    raise AssertionError("the mutation changed nothing")
                caught_fast = _named_check_fails(mod, ROOT, expected)
                failing = [expected] if caught_fast else _failing_checks(mod, ROOT)
            finally:
                path.write_text(original)
        else:
            created = mutate()
            paths = [ROOT / rel_ for rel_, _b in created]
            existing = [p for p in paths if p.exists()]
            if existing:
                print("%s already exists; refusing to overwrite it"
                      % ", ".join(str(p) for p in existing), file=sys.stderr)
                return 2
            try:
                for (rel_, body), p in zip(created, paths):
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(body)
                caught_fast = _named_check_fails(mod, ROOT, expected)
                failing = [expected] if caught_fast else _failing_checks(mod, ROOT)
            finally:
                for p in paths:
                    p.unlink(missing_ok=True)

        caught = expected in failing
        # Which OTHER checks noticed. Recorded rather than credited: a neighbour going red
        # is not evidence that this surface is covered, and the run below says so.
        others = sorted(set(failing) - {expected})
        seen.update(others)
        print("%-24s %-62s %s" % (expected, what, "caught" if caught else "SURVIVED"))
        if not caught:
            survivors.append((expected, what, failing))

    # The surfaces that need no check, and the evidence that they still do not.
    laundered = []
    structural = [c for c in BY_CONSTRUCTION if not args.only or c[0] == args.only]
    if structural:
        print()
    for cid, what, rel, mutate, construction, why in structural:
        path = ROOT / rel
        original = path.read_text()
        if not re.search(construction, original):
            laundered.append((cid, why, "the construction is GONE from %s" % rel))
            print("%-24s %-62s CONSTRUCTION GONE" % (cid, what))
            continue
        try:
            path.write_text(mutate(original))
            failing = [cid] if _named_check_fails(mod, ROOT, cid) else []
        finally:
            path.write_text(original)
        # A check firing here would mean the addition IS a violation after all, so the
        # entry is excusing a surface that needed a check.
        if cid in failing:
            laundered.append((cid, why, "%s flagged it, so it was a violation" % cid))
            print("%-24s %-62s WRONGLY EXCUSED" % (cid, what))
        else:
            print("%-24s %-62s covered by construction" % (cid, what))

    print("\nsurfaces grown by one bad member   %d" % len(cases))
    print("the surface's own check noticed    %d" % (len(cases) - len(survivors)))
    print("SURVIVED                           %d" % len(survivors))
    if structural:
        print("closed by construction, verified   %d" % (len(structural) - len(laundered)))

    if laundered:
        print("\n== %d SURFACE(S) DECLARED CLOSED BY CONSTRUCTION THAT ARE NOT ==" % len(laundered))
        for cid, why, how in laundered:
            print("   %-24s %s" % (cid, how))
            print("        the declaration said: %s" % why)
        print("\nA by-construction entry is an excuse from needing a check. When the "
              "construction goes, the excuse has to go with it, or it is exactly the silent "
              "coverage gap this drill exists to find.")
        return 1

    if survivors:
        print("\n== %d SURFACE(S) THAT CAN GROW PAST THEIR OWN CHECK ==" % len(survivors))
        for expected, what, failing in survivors:
            print("   %-24s %s" % (expected, what))
            print("        expected %s to fail; what failed instead: %s"
                  % (expected, ", ".join(failing) or "nothing"))
        print("\nA check whose claim quantifies over a surface it does not enumerate reports "
              "full coverage of exactly the members it was handed. That is not a broken "
              "check; it is a check with a reach smaller than its sentence, which is the "
              "defect C1, C6, C8 and the duress surface each shipped with.")
        return 1

    print("\n== Every surface here refuses a new member that lacks the property, and each is "
          "refused by its OWN named check. That is a statement about these %d additions, not "
          "about coverage in general: a surface nobody thought to grow is this drill's "
          "standing limitation, and a check that failed for a neighbouring reason would not "
          "have been credited, because the expected check is asserted by name. ==" % len(cases))
    return 0


if __name__ == "__main__":
    sys.exit(main())
