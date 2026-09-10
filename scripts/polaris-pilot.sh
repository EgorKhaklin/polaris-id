#!/usr/bin/env bash
# ============================================================================
# polaris-pilot.sh — the pilot in one command (roadmap P5.1).
#
#   scripts/polaris-pilot.sh up        # bring the pilot stack up
#   scripts/polaris-pilot.sh report    # the pack you owe your DPO and your exit report
#   scripts/polaris-pilot.sh winddown --cosigner N --agency N   # end it
#   scripts/polaris-pilot.sh down      # stop the stack (data kept)
#
# `report` is the one to run before you start, not only at the end. It prints
# what the system will hold about your participants, how long each class is
# kept, who can read it, what survives a wind-down, and the consent language
# you may truthfully use. All of it derived from the live schema, so it is not
# accurate only on the day somebody wrote it down.
#
# `winddown` needs a CO-SIGNER, and that is not a formality: a wind-down is a
# mass revocation, and the bound that makes coercive mass revocation expensive
# applies to an operator ending their own pilot. Arrange the co-signer before
# you enrol anybody. See docs/operator/PILOT.md.
# ============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CMD="${1:-}"; shift || true
PY="${POLARIS_TEST_PYTHON:-$(command -v python3.12 || command -v python3)}"

compose() {
    ( cd "$ROOT/polaris_web" && docker compose \
        -f docker-compose.prod.yml \
        -f docker-compose.observability.yml "$@" )
}

usage() {
    sed -n '3,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 2
}

case "$CMD" in
  up)
    command -v docker >/dev/null || { echo "pilot: needs docker" >&2; exit 3; }
    : "${POLARIS_DOMAIN:?set POLARIS_DOMAIN for the TLS edge}"
    : "${POLARIS_ACME_EMAIL:?set POLARIS_ACME_EMAIL for the TLS edge}"
    compose up -d
    echo
    echo "The stack is up. Before enrolling anybody, run:"
    echo "    scripts/polaris-pilot.sh report"
    echo "and read docs/operator/PILOT.md, which explains why the wind-down needs"
    echo "a second authority and why that has to be arranged now rather than later."
    ;;

  down)
    compose down
    echo "Stopped. Data kept: 'down' is not a wind-down, and stopping a pilot is not"
    echo "ending one. To end it, run: scripts/polaris-pilot.sh winddown --cosigner N"
    ;;

  report)
    "$PY" - "$@" <<'PYEOF'
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath("."))))
sys.path.insert(0, os.path.join(os.getcwd(), "polaris_web"))
import psycopg2
from psycopg2.extras import RealDictCursor
import pilot

cfg = {"host": os.environ.get("POLARIS_DB_HOST", "localhost"),
       "port": os.environ.get("POLARIS_DB_PORT", "5432"),
       "dbname": os.environ.get("POLARIS_DB_NAME", "polaris"),
       "user": os.environ.get("POLARIS_DB_USER", "polaris_app")}
if os.environ.get("POLARIS_DB_PASSWORD"):
    cfg["password"] = os.environ["POLARIS_DB_PASSWORD"]
conn = psycopg2.connect(cursor_factory=RealDictCursor, **cfg)
pack = pilot.dpia_inputs(conn)
print(json.dumps(pack, indent=2, default=str))
PYEOF
    ;;

  winddown)
    AGENCY=""; COSIGNER=""; ACTOR="${POLARIS_PILOT_ACTOR:-1}"; DRY=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --agency)   AGENCY="$2"; shift 2 ;;
            --cosigner) COSIGNER="$2"; shift 2 ;;
            --actor)    ACTOR="$2"; shift 2 ;;
            --dry-run)  DRY="1"; shift ;;
            *) usage ;;
        esac
    done
    [[ -n "$COSIGNER" ]] || {
        echo "pilot: winddown needs --cosigner AGENCY_ID." >&2
        echo "A wind-down is a mass revocation, and one authority cannot perform one." >&2
        echo "See docs/operator/PILOT.md section 2." >&2
        exit 2
    }
    AGENCY="$AGENCY" COSIGNER="$COSIGNER" ACTOR="$ACTOR" DRY="$DRY" "$PY" - <<'PYEOF'
import json, os, sys
sys.path.insert(0, os.path.join(os.getcwd(), "polaris_web"))
import psycopg2
from psycopg2.extras import RealDictCursor
import pilot

cfg = {"host": os.environ.get("POLARIS_DB_HOST", "localhost"),
       "port": os.environ.get("POLARIS_DB_PORT", "5432"),
       "dbname": os.environ.get("POLARIS_DB_NAME", "polaris"),
       "user": os.environ.get("POLARIS_DB_USER", "polaris_app")}
if os.environ.get("POLARIS_DB_PASSWORD"):
    cfg["password"] = os.environ["POLARIS_DB_PASSWORD"]
conn = psycopg2.connect(cursor_factory=RealDictCursor, **cfg)
agency = int(os.environ["AGENCY"]) if os.environ.get("AGENCY") else None
try:
    result = pilot.wind_down(conn, int(os.environ["ACTOR"]), agency_id=agency,
                             cosigner_agency_id=int(os.environ["COSIGNER"]),
                             dry_run=bool(os.environ.get("DRY")))
except pilot.WindDownRefused as exc:
    print("refused: %s" % exc, file=sys.stderr)
    raise SystemExit(1)
print(json.dumps(result, indent=2, default=str))
print("\nKeep this output. It is the factual half of your exit report, and the"
      "\nresidue list above is the honest answer to 'what is still in there?'.",
      file=sys.stderr)
PYEOF
    ;;

  *) usage ;;
esac
