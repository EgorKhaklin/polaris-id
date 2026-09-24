"""polaris_web/atlas_routes.py -- the Atlas, the operational investigation surface.

The third block lifted out of app.py (2026-09-18) and the largest: the /atlas page, the
seventeen /api/atlas aggregation endpoints, the filter parser, the bbox parser and the TTL
cache they share. 1,241 lines. app.py is presentation-free to this extent.

C8 TRAVELS WITH IT. Every Atlas aggregate is bounded, and the bound is the `_ATLAS_MAX_*`
clamp a route applies before the SQL sees a caller-controlled count: the SQL alone bounds
nothing. Those constants are in this file now, beside the routes that apply them, which is
where check_c8_atlas_caps looks because it reads the polaris_web package rather than a path.
The move mutation drill carries a c8_atlas_caps payload for exactly this, and it is the reason
the move is safe to make rather than a hope that it was.

THE CACHE IS SHARED STATE AND STAYS ONE OBJECT. `_atlas_cache`, its lock and its counters are
mutated in place and never reassigned, so app.py's readiness report reaches them as
`atlas_routes._atlas_cache`, resolved at use time, and sees the same dict this module writes.
It must not import them by name: `from` copies a binding, and while a dict would survive that,
the habit does not survive the next name that is rebound rather than mutated.
check_no_module_imports_an_unstable_name draws that line.

The `import threading` and `import time as _time` that used to sit in the middle of the cache
section stayed in app.py: other code there uses both, and an import is not owned by the section
it happens to be written next to.

Routes register by import: app.py imports this module at the END, after every name below
exists, and aliases itself into sys.modules first so `python3 app.py` does not load it twice.
"""
import os
import threading
import time as _time
from datetime import timedelta

from flask import abort, g, jsonify, render_template, request

import app as _app          # for the two values app.py owns and callers repoint; see below
import security
from app import (
    _db_now,
    app,
    atlas_basemap_origins,
    get_db,
    query,
    replica_reads,
)


# ============================================================================
# ATLAS — Operational investigation surface (Gotham-style)
# ============================================================================

@app.route('/atlas')
@security.login_required
def atlas():
    """Atlas is a live operational investigation surface, not a dashboard.
    The globe IS the page. Everything else (HUD, event feed, detail panel)
    exists to drive selection and explain a single event when the operator
    clicks one. Aggregate analytics live on the dashboard."""

    # v9.146: opt this one page into the MapLibre tile-basemap CSP relaxation
    # (apply_security_headers reads g.atlas_tiles). Every other page stays
    # strict self-only. ZERO_KNOWLEDGE events are never plotted (C6).
    g.atlas_tiles = True
    g.atlas_tile_origins = atlas_basemap_origins()

    # --- Agency roster for the operational agency filter (v9.146). ---------
    # Plotting/filtering is by issuing/acting AGENCY, an operational pivot,
    # never by any attribute of a person.
    agencies = query('SELECT agency_id, name, agency_type FROM Agency ORDER BY name')

    # --- Health snapshot for HUD chrome -----------------------------------
    table_counts = {}
    for tbl in ['Individual', 'Agency', 'IdentityToken',
                'TokenLifecycleEvent', 'VerificationEvent', 'DeviceBinding']:
        table_counts[tbl] = query(f'SELECT COUNT(*) AS n FROM {tbl}', fetch='one')['n']

    state_pop = {row['status']: row['n'] for row in query("""
        SELECT status, COUNT(*) AS n FROM IdentityToken GROUP BY status
    """)}
    for s in ['ACTIVE', 'RESERVE', 'DORMANT', 'REVOKED', 'LOST', 'EXPIRED']:
        state_pop.setdefault(s, 0)

    pq_active = query("""
        SELECT alg.quantum_resistant, COUNT(t.token_id) AS n
        FROM CryptographicAlgorithm alg
        LEFT JOIN IdentityToken t ON alg.algorithm_id = t.algorithm_id AND t.status='ACTIVE'
        GROUP BY alg.quantum_resistant
    """)
    pq_n = sum(r['n'] for r in pq_active if r['quantum_resistant'])
    cls_n = sum(r['n'] for r in pq_active if not r['quantum_resistant'])

    disc = {r['disclosure_level']: r['n'] for r in query("""
        SELECT disclosure_level, COUNT(*) AS n
        FROM VerificationEvent GROUP BY disclosure_level
    """)}
    disc_total = sum(disc.values()) or 1

    # --- Anomaly indicators visible from the globe ------------------------
    anomalies = query("""
        SELECT
          SUM(CASE WHEN outcome != 'SUCCESS' THEN 1 ELSE 0 END) AS fail_n,
          SUM(CASE WHEN disclosure_level = 'FULL' THEN 1 ELSE 0 END) AS full_n
        FROM VerificationEvent
    """, fetch='one')

    # v9.248: the Overview's 'all' window spans the actual data range; expose
    # the earliest verification timestamp so the console can label the scope.
    oldest = query("SELECT min(event_timestamp) AS t FROM VerificationEvent", fetch='one')

    health = {
        'verifications_total': table_counts['VerificationEvent'],
        'oldest_event':       (oldest['t'].isoformat() if oldest and oldest['t'] else ''),
        'tokens_total':       table_counts['IdentityToken'],
        'tokens_active':      state_pop.get('ACTIVE', 0),
        'tokens_reserve':     state_pop.get('RESERVE', 0),
        'tokens_terminal':    (state_pop.get('REVOKED', 0)
                               + state_pop.get('LOST', 0)
                               + state_pop.get('EXPIRED', 0)),
        'pq_pct': (100 * pq_n // (pq_n + cls_n)) if (pq_n + cls_n) else 0,
        'zk_pct': (100 * disc.get('ZERO_KNOWLEDGE', 0) // disc_total) if disc_total else 0,
        'agencies':           table_counts['Agency'],
        'individuals':        table_counts['Individual'],
        'verif_events':       table_counts['VerificationEvent'],
        'lifecycle_events':   table_counts['TokenLifecycleEvent'],
        'device_binds':       table_counts['DeviceBinding'],
        'failures':           int(anomalies['fail_n'] or 0),
        'full_disclosures':   int(anomalies['full_n'] or 0),
    }

    # The globe is data-driven via /api/atlas/* (clusters, points, events);
    # the page itself ships only the health snapshot for the HUD.
    return render_template(
        'atlas.html',
        # Read at USE time, not copied at import. This value has two readers, the CSP
        # builder in app.py and this page, and they must never disagree about it: an
        # operator who repoints the basemap gets a page whose tiles the policy blocks.
        # A `from app import` copy held the value from startup, and the suite that
        # repoints it found exactly that split on 2026-09-18, the CSP half passing and
        # the page half failing.
        atlas_basemap_style=_app.ATLAS_BASEMAP_STYLE_URL,
        health=health, agencies=agencies)


# ============================================================================
# ATLAS API — server-side spatial aggregation for scaling to millions of events
#
# The Atlas frontend used to receive every event inline as JSON in the
# template, which was fine for the 17-row sample but cannot scale: at 100k
# events the page is slow, at 1M it's OOM. These endpoints implement the
# proper architecture:
#
#   GET /api/atlas/clusters?bbox=...&grid=...&kind=...
#       Server-side bin aggregation. At low zoom the world resolves into
#       O(100) clusters with summary counts; at high zoom the grid shrinks
#       and each cluster is small enough that the client switches to points.
#
#   GET /api/atlas/points?bbox=...&kind=...&limit=...
#       Individual events in the bbox, hard-capped at limit. Used at high
#       zoom (city / neighborhood) when cluster count is below threshold.
#
#   GET /api/atlas/stats?bbox=...
#       The four operational ratios (Active Tokens, Anomalies, PQ%, ZK%)
#       scoped to the visible bounding box.
#
#   GET /api/atlas/events?cursor=...&limit=...
#       Paginated unified feed for the right rail.
#
# Bounding-box parameter format: "min_lat,min_lon,max_lat,max_lon" decimal
# degrees, all four required. Out-of-range or NaN values yield 400.
# ============================================================================

# Hard caps to protect the server. Even with a maximally-zoomed-out bbox
# the cluster count is bounded by the grid; here we limit the upper bound
# of any single response.
_ATLAS_MAX_CLUSTERS = 5000
_ATLAS_MAX_POINTS   = 2000
_ATLAS_MAX_EVENTS   = 500
# v9.248 (roadmap P2.3, the analytical console): the Overview/Breakdown roll-ups
# return at most this many categories per dimension (top-K by volume). Bounds
# the analytical payload the same way the cluster/point/event caps bound the
# map (C8): a dimension can only have so many rows sent to the browser.
_ATLAS_MAX_CATEGORIES = 50
# v9.253 (roadmap P2.3, Map v2): the Regions layer rolls verification volume up
# by requesting-agency jurisdiction (ISO 3166-2). The count of distinct
# jurisdictions is bounded by the standard (a few hundred at national+
# international scale), but the response is hard-capped like every other atlas
# surface (C8). The hexbin Density layer reuses the cluster cap.
_ATLAS_MAX_REGIONS = 500


# =============================================================================
# Atlas TTL cache (R8-5)
# =============================================================================
# In-process TTL cache for atlas API responses. Keys are computed from the
# request parameters (bbox, grid, kind, limit) and values are tuples of
# (timestamp, response_dict). Hot atlas queries — the same bbox/grid being
# polled by multiple operators — hit the cache instead of the SQL
# aggregation function.
#
# This is the in-memory variant. R8-2 (Redis-backed limiter) introduces
# the multi-worker dependency; once Redis is available, this cache should
# migrate to a Redis backend so cache hits work across gunicorn workers.
# Until then, each worker has its own cache (acceptable: cache hits on
# the same worker still help; the worst case is cold-start across all
# workers, which is no worse than no cache at all).
#
# Cache invalidation: pure TTL. Atlas data changes when verifications or
# lifecycle events are written, but for a 30-second TTL the staleness is
# bounded and matches the typical operator polling interval.

_ATLAS_CACHE_TTL_SECONDS = float(os.environ.get('POLARIS_ATLAS_CACHE_TTL', '30'))
_ATLAS_CACHE_MAX_ENTRIES = int(os.environ.get('POLARIS_ATLAS_CACHE_MAX', '256'))
_atlas_cache = {}                               # dict[key, tuple[float, dict]]
_atlas_cache_lock = threading.Lock()
_atlas_cache_stats = {'hits': 0, 'misses': 0, 'expired': 0, 'evicted': 0}


def _atlas_cache_get(key):
    """Return the cached payload if fresh, else None. Thread-safe."""
    if _ATLAS_CACHE_TTL_SECONDS <= 0:
        return None
    # Live simulation mode wants the console to update as events stream in, so it
    # bypasses the 30 s aggregate cache (dev/demo only; the roll-ups are bounded
    # and partition-pruned, so recomputing each refresh is cheap). Production is
    # unaffected — SIM_MODE is force-off there.
    # Read at USE time. SIM_MODE is app.py's, it is force-off under POLARIS_ENV=production,
    # and the simulation suite flips it per test because, as its own docstring says, it is read
    # at request time. A `from app import` copy froze it at startup: the flip stopped reaching
    # here, the cache stopped being bypassed, and the console would have shown 30-second-stale
    # roll-ups in the one mode whose whole point is watching events arrive. Nothing failed.
    # No test covers the bypass, and check_ui_drill reads this function's SOURCE, which still
    # said the right thing. Found by check_no_module_imports_an_unstable_name, 2026-09-18.
    if _app.SIM_MODE:
        return None
    now = _time.time()
    with _atlas_cache_lock:
        entry = _atlas_cache.get(key)
        if entry is None:
            _atlas_cache_stats['misses'] += 1
            return None
        ts, payload = entry
        if now - ts > _ATLAS_CACHE_TTL_SECONDS:
            del _atlas_cache[key]
            _atlas_cache_stats['expired'] += 1
            _atlas_cache_stats['misses'] += 1
            return None
        _atlas_cache_stats['hits'] += 1
        return payload


def _atlas_cache_set(key, payload):
    """Store payload with current timestamp. Evict oldest if at capacity."""
    if _ATLAS_CACHE_TTL_SECONDS <= 0:
        return
    now = _time.time()
    with _atlas_cache_lock:
        if len(_atlas_cache) >= _ATLAS_CACHE_MAX_ENTRIES:
            # Evict the oldest entry — simple LRU-ish behavior without ordereddict
            oldest_key = min(_atlas_cache, key=lambda k: _atlas_cache[k][0])
            del _atlas_cache[oldest_key]
            _atlas_cache_stats['evicted'] += 1
        _atlas_cache[key] = (now, payload)


def _atlas_cache_clear():
    """Used by tests and admin endpoints."""
    with _atlas_cache_lock:
        _atlas_cache.clear()
        for k in _atlas_cache_stats:
            _atlas_cache_stats[k] = 0


def _parse_bbox(s):
    """Parse 'min_lat,min_lon,max_lat,max_lon' → 4-tuple of floats.
    Validates ranges and ordering. Raises ValueError on bad input."""
    if not s:
        raise ValueError("bbox required (format: min_lat,min_lon,max_lat,max_lon)")
    parts = s.split(',')
    if len(parts) != 4:
        raise ValueError("bbox must have exactly four comma-separated values")
    try:
        min_lat, min_lon, max_lat, max_lon = (float(p) for p in parts)
    except ValueError:
        raise ValueError("bbox values must be numeric")
    if not (-90 <= min_lat <= 90 and -90 <= max_lat <= 90):
        raise ValueError("latitudes must be in [-90, 90]")
    if not (-180 <= min_lon <= 180 and -180 <= max_lon <= 180):
        raise ValueError("longitudes must be in [-180, 180]")
    if min_lat > max_lat:
        raise ValueError("min_lat must be <= max_lat")
    # Antimeridian-spanning bboxes (min_lon > max_lon) are supported as
    # of v7. The atlas SQL functions in 11_atlas.sql use a wrap-aware
    # longitude predicate: when min_lon > max_lon, the bbox covers
    # [min_lon, 180] ∪ [-180, max_lon] (i.e. wraps across the date line).
    return min_lat, min_lon, max_lat, max_lon


# Window labels → timedelta. The schema stores event_timestamp as TIMESTAMP-without-zone in
# the database session's wall clock, so the window is measured from THAT clock (_db_now).
# Until 1.0.0-rc.29 this used the app's `datetime.now()` on the premise that app and database
# share a zone; the v8.3 smoke test caught the UTC-clock version of the same mistake, and
# rc.28 (the database on UTC) made the local-clock version wrong on any host not on UTC.
_ATLAS_TIME_WINDOWS = {
    '1h':   timedelta(hours=1),
    '24h':  timedelta(hours=24),
    '7d':   timedelta(days=7),
    '30d':  timedelta(days=30),
    'all':  None,                     # no time filter
}

# Outcome alias: "anomalies" = the union the operator typically wants when
# they're investigating a security incident. Anchored here (not in JS) so
# the SQL parameter is the same set across UI versions.
_ATLAS_OUTCOME_ALIASES = {
    'anomalies': 'FAILURE,UNAUTHORIZED,EXPIRED',
}

def _parse_atlas_filters(args):
    """Pull the v8.3 / A+C filter parameters off the request and return a
    dict of the SQL-ready values: since (TIMESTAMP or None), outcomes (CSV
    or None), disclosure (CSV or None), contexts (CSV or None),
    event_types (lifecycle, CSV or None), window_label (str). Raises
    ValueError on any malformed input so the route returns 400."""
    window = (args.get('window') or '24h').strip().lower()
    if window not in _ATLAS_TIME_WINDOWS:
        raise ValueError(
            f"window must be one of {sorted(_ATLAS_TIME_WINDOWS.keys())}; got {window!r}"
        )
    delta = _ATLAS_TIME_WINDOWS[window]
    since = (_db_now() - delta) if delta is not None else None

    outcomes_raw = (args.get('outcomes') or '').strip()
    if outcomes_raw in _ATLAS_OUTCOME_ALIASES:
        outcomes_raw = _ATLAS_OUTCOME_ALIASES[outcomes_raw]
    outcomes = outcomes_raw or None
    # Whitelist outcome values to prevent SQL string-list smuggling
    if outcomes:
        valid = {'SUCCESS', 'FAILURE', 'EXPIRED', 'UNAUTHORIZED'}
        for v in outcomes.split(','):
            if v.strip() not in valid:
                raise ValueError(f"unknown outcome: {v!r}")

    disclosure_raw = (args.get('disclosure') or '').strip()
    disclosure = disclosure_raw or None
    if disclosure:
        valid = {'ZERO_KNOWLEDGE', 'SELECTIVE', 'FULL'}
        for v in disclosure.split(','):
            if v.strip() not in valid:
                raise ValueError(f"unknown disclosure level: {v!r}")

    contexts_raw = (args.get('contexts') or '').strip()
    contexts = contexts_raw or None
    if contexts:
        valid = {'BANKING', 'EMPLOYMENT', 'HEALTHCARE', 'TRAVEL',
                 'VOTING', 'MOTOR_VEHICLE', 'GOVERNMENT_BENEFITS'}
        for v in contexts.split(','):
            if v.strip() not in valid:
                raise ValueError(f"unknown context: {v!r}")

    event_types_raw = (args.get('event_types') or '').strip()
    event_types = event_types_raw or None
    if event_types:
        valid = {'ISSUED', 'ACTIVATED', 'DEACTIVATED', 'DEVICE_BOUND',
                 'DEVICE_REVOKED', 'REVOKED', 'LOST', 'EXPIRED', 'REPLACED'}
        for v in event_types.split(','):
            if v.strip() not in valid:
                raise ValueError(f"unknown event_type: {v!r}")

    # v9.146 operational agency filter — CSV of agency_id integers. Validated
    # as integers (defence in depth; the value is passed as a single bound
    # param to ANY(string_to_array(...)) so it cannot smuggle SQL). This is an
    # operational pivot (which issuer/actor), never an attribute of a person.
    agencies_raw = (args.get('agencies') or '').strip()
    agencies = None
    if agencies_raw:
        ids = [a.strip() for a in agencies_raw.split(',') if a.strip()]
        for a in ids:
            if not a.isdigit():
                raise ValueError(f"agency id must be an integer: {a!r}")
        agencies = ','.join(ids) or None

    return {
        'window': window,
        'since': since,
        'outcomes': outcomes,
        'disclosure': disclosure,
        'contexts': contexts,
        'event_types': event_types,
        'agencies': agencies,
    }


def _filter_cache_key(filters):
    """Reduce a filter dict to a hashable cache key fragment."""
    return (filters['window'], filters['outcomes'], filters['disclosure'],
            filters['contexts'], filters['event_types'], filters.get('agencies'))


@app.route('/api/atlas/clusters')
@security.login_required
@replica_reads
def api_atlas_clusters():
    """Spatial aggregation endpoint. Returns ≤ _ATLAS_MAX_CLUSTERS bins.
    R8-5: result cached for _ATLAS_CACHE_TTL_SECONDS to absorb hot polling.

    v8.3 (A+C): accepts ?window= (1h/24h/7d/30d/all), ?outcomes= (CSV
    incl. 'anomalies' alias), ?disclosure= (CSV), ?contexts= (CSV) for
    verification kind, and ?event_types= (CSV) for lifecycle kind. The
    cache key includes the filter-set so different filter combinations
    do NOT collide."""
    try:
        min_lat, min_lon, max_lat, max_lon = _parse_bbox(request.args.get('bbox'))
        grid = float(request.args.get('grid', '5'))
        # `not (0 < x <= 90)`, not `x <= 0 or x > 90`: the second is False for NaN, which
        # passed, reached the query and put NaN into the response and the cache key (2026-09-24).
        if not (0 < grid <= 90):
            raise ValueError("grid must be in (0, 90] decimal degrees")
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    cache_key = ('clusters', kind, min_lat, min_lon, max_lat, max_lon, grid,
                 _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    if kind == 'verification':
        rows = query("""
            SELECT lat, lon, n_total, n_failure, n_pq, n_zk, n_full
            FROM atlas_clusters_verifications(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            LIMIT %s
        """, (min_lat, min_lon, max_lat, max_lon, grid,
              f['since'], f['outcomes'], f['disclosure'], f['contexts'], f['agencies'],
              _ATLAS_MAX_CLUSTERS))
    else:
        rows = query("""
            SELECT lat, lon, n_total, n_revoked, n_lost, n_issued, n_activated
            FROM atlas_clusters_lifecycles(%s, %s, %s, %s, %s, %s, %s, %s)
            LIMIT %s
        """, (min_lat, min_lon, max_lat, max_lon, grid,
              f['since'], f['event_types'], f['agencies'],
              _ATLAS_MAX_CLUSTERS))

    payload = dict(
        kind=kind,
        bbox=[min_lat, min_lon, max_lat, max_lon],
        grid=grid,
        window=f['window'],
        count=len(rows),
        clusters=[dict(r) for r in rows],
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


@app.route('/api/atlas/points')
@security.login_required
@replica_reads
def api_atlas_points():
    """Individual event points in the bbox. Used at high zoom when the
    cluster count is below the cluster→point threshold. v8.3 honors the
    same filter parameter set as /clusters."""
    try:
        min_lat, min_lon, max_lat, max_lon = _parse_bbox(request.args.get('bbox'))
        limit = min(int(request.args.get('limit', '500')), _ATLAS_MAX_POINTS)
        if limit <= 0:
            raise ValueError("limit must be positive")
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    if kind == 'verification':
        rows = query("""
            SELECT event_id, lat, lon,
                   to_char(event_timestamp, 'YYYY-MM-DD HH24:MI') AS event_timestamp,
                   token_id, holder_name, agency_name, context_type,
                   outcome, disclosure_level, algorithm_name, pq, requestor_location
            FROM atlas_points_verifications(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (min_lat, min_lon, max_lat, max_lon, limit,
              f['since'], f['outcomes'], f['disclosure'], f['contexts'], f['agencies']))
    else:
        rows = query("""
            SELECT event_id, lat, lon,
                   to_char(event_timestamp, 'YYYY-MM-DD HH24:MI') AS event_timestamp,
                   token_id, event_type, reason_code, holder_name,
                   agency_name, algorithm_name, pq
            FROM atlas_points_lifecycles(%s, %s, %s, %s, %s, %s, %s, %s)
        """, (min_lat, min_lon, max_lat, max_lon, limit,
              f['since'], f['event_types'], f['agencies']))

    return jsonify(
        kind=kind,
        bbox=[min_lat, min_lon, max_lat, max_lon],
        limit=limit,
        window=f['window'],
        count=len(rows),
        points=[dict(r) for r in rows],
    )


@app.route('/api/atlas/hexbin')
@security.login_required
@replica_reads
def api_atlas_hexbin():
    """Map v2 Density layer (roadmap P2.3, v9.253): located verification events
    binned into a pointy-top hex grid of size ?size= (degrees) within the bbox,
    the top-K densest centres by count (≤ _ATLAS_MAX_CLUSTERS, C8). C6: ZK
    verifications are excluded entirely, like the cluster map. Cached like the
    other spatial aggregates."""
    try:
        min_lat, min_lon, max_lat, max_lon = _parse_bbox(request.args.get('bbox'))
        size = float(request.args.get('size', '5'))
        # `not (0 < x <= 90)`, not `x <= 0 or x > 90`: the second is False for NaN, which
        # passed, reached the query and put NaN into the response and the cache key (2026-09-24).
        if not (0 < size <= 90):
            raise ValueError("size must be in (0, 90] decimal degrees")
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    cache_key = ('hexbin', kind, min_lat, min_lon, max_lat, max_lon, size,
                 _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    # atlas_hexbin bins verification events only (located, non-ZK); a lifecycle
    # request returns an empty surface rather than an error, so the client can
    # fall back to Points for that stream.
    rows = query("""
        SELECT lat, lon, n_total, n_failure
        FROM atlas_hexbin(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (min_lat, min_lon, max_lat, max_lon, size, _ATLAS_MAX_CLUSTERS,
          f['since'], kind, f['outcomes'], f['disclosure'], f['contexts'], f['agencies']))

    payload = dict(
        kind=kind,
        bbox=[min_lat, min_lon, max_lat, max_lon],
        size=size,
        window=f['window'],
        count=len(rows),
        hexes=[dict(r) for r in rows],
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


@app.route('/api/atlas/geo/jurisdictions')
@security.login_required
@replica_reads
def api_atlas_geo_jurisdictions():
    """Map v2 Regions layer (roadmap P2.3, v9.253) — the DEFAULT map view.
    Verification (or lifecycle) volume rolled up by the requesting agency's
    jurisdiction (ISO 3166-2), top-K by volume (≤ _ATLAS_MAX_REGIONS, C8). Not
    viewport-bound: the Regions layer shows every jurisdiction, not just the
    ones on screen. C6: a jurisdiction is a regulatory grouping, not a
    coordinate, so a zero-knowledge verification is COUNTED in its jurisdiction
    (n_zk) yet never located — the centroid derives from located, non-ZK events
    only, and a ZK-only jurisdiction has a null centroid (counted, unplaceable).
    Cached like the other rollups."""
    try:
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    cache_key = ('geojur', kind, _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    rows = query("""
        SELECT jurisdiction, n_total, n_failure, n_zk, n_located, centroid_lat, centroid_lon
        FROM atlas_geo_jurisdictions(%s, %s, %s, %s, %s, %s, %s)
    """, (f['since'], _ATLAS_MAX_REGIONS, kind,
          f['outcomes'], f['disclosure'], f['contexts'], f['agencies']))

    # Split the placeable jurisdictions (a centroid) from the ZK-only /
    # unlocatable ones, which are reported as a count the legend can surface
    # without ever putting them on the map (C6).
    placeable = [dict(r) for r in rows if r['centroid_lat'] is not None]
    unplaceable = [dict(r) for r in rows if r['centroid_lat'] is None]
    payload = dict(
        kind=kind,
        window=f['window'],
        count=len(rows),
        n_unplaceable=len(unplaceable),
        n_unplaceable_events=sum(r['n_total'] for r in unplaceable),
        regions=placeable,
        unplaceable=unplaceable,
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


@app.route('/api/atlas/stats')
@security.login_required
@replica_reads
def api_atlas_stats():
    """The four HUD signals scoped to the visible bbox.
    R8-5: cached for _ATLAS_CACHE_TTL_SECONDS.

    v8.3 (A): also accepts ?window= so the HUD numbers reflect the
    operator's selected time slice, not just lifetime."""
    try:
        min_lat, min_lon, max_lat, max_lon = _parse_bbox(request.args.get('bbox'))
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    cache_key = ('stats', min_lat, min_lon, max_lat, max_lon, f['window'])
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    row = query("""
        SELECT n_active_tokens, n_anomalies, n_failures, n_full,
               pq_pct, zk_pct, n_verifs, n_lifecycles
        FROM atlas_stats(%s, %s, %s, %s, %s, %s)
    """, (min_lat, min_lon, max_lat, max_lon, f['since'], f['agencies']), fetch='one')

    payload = dict(
        bbox=[min_lat, min_lon, max_lat, max_lon],
        window=f['window'],
        n_active_tokens=int(row['n_active_tokens']),
        n_anomalies=int(row['n_anomalies']),
        n_failures=int(row['n_failures']),
        n_full=int(row['n_full']),
        pq_pct=int(row['pq_pct']),
        zk_pct=int(row['zk_pct']),
        n_verifs=int(row['n_verifs']),
        n_lifecycles=int(row['n_lifecycles']),
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


@app.route('/api/atlas/timeline')
@security.login_required
@replica_reads
def api_atlas_timeline():
    """Bucket counts for the histogram strip below the toolbar.

    Returns N points where each point is `{ts: ISO-8601, n_total, n_anomaly}`
    over the requested `?window=` time range, with `?buckets=` slices.
    Honors the same outcome / disclosure / context / event_types filters as
    the cluster endpoint so the strip reflects the operator's full filter
    state. Hard-capped at 240 buckets so a misconfigured client can't ask
    for 100k pixels of histogram. v8.3 / A."""
    try:
        min_lat, min_lon, max_lat, max_lon = _parse_bbox(request.args.get('bbox'))
        buckets = int(request.args.get('buckets', '60'))
        if buckets <= 0 or buckets > 240:
            raise ValueError("buckets must be in (0, 240]")
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    # 'all' window has no fixed start; default to 30d in that case so the
    # histogram has a meaningful x-range. The HUD reads 'all'; the
    # histogram reads '30d-strip' so both can be honest about scope.
    since = f['since'] or (_db_now() - _ATLAS_TIME_WINDOWS['30d'])

    cache_key = ('timeline', kind, min_lat, min_lon, max_lat, max_lon,
                 buckets, _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    rows = query("""
        SELECT to_char(bucket_ts, 'YYYY-MM-DD"T"HH24:MI:SS') AS ts,
               n_total, n_anomaly
        FROM atlas_timeline(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ORDER BY bucket_ts
    """, (min_lat, min_lon, max_lat, max_lon, since, buckets, kind,
          f['outcomes'], f['disclosure'], f['contexts'], f['agencies']))

    payload = dict(
        bbox=[min_lat, min_lon, max_lat, max_lon],
        window=f['window'],
        kind=kind,
        buckets=buckets,
        since=since.isoformat(),
        until=_db_now().isoformat(),
        points=[
            {'ts': r['ts'], 'n_total': int(r['n_total']),
             'n_anomaly': int(r['n_anomaly'])}
            for r in rows
        ],
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


# ----------------------------------------------------------------------------
# THE ANALYTICAL CONSOLE (v9.248, roadmap P2.3) — the Overview's non-geographic
# aggregates. Both are bounded server-side (C8) and count zero-knowledge events
# without ever locating them (C6): a ZK verification adds to volume, ZK-share
# and the disclosure/agency/context/jurisdiction tallies, but is never plotted.
# ----------------------------------------------------------------------------

@app.route('/api/atlas/series')
@security.login_required
@replica_reads
def api_atlas_series():
    """Non-geographic total-volume time series for the Overview hero chart.

    Returns `{ts, n_total, n_failure, n_zk}` per bucket over the `?window=`
    range with `?buckets=` slices, honoring the same filters as the rest of the
    Atlas. Unlike /api/atlas/timeline (located events only, for the map strip),
    this counts EVERY event, so the volume is honest and zero-knowledge
    verifications are included in n_total and n_zk without a location (C6).
    Hard-capped at 240 buckets."""
    try:
        buckets = int(request.args.get('buckets', '60'))
        if buckets <= 0 or buckets > 240:
            raise ValueError("buckets must be in (0, 240]")
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    # 'all' has no fixed start; span the actual data range so the chart is not
    # empty on old seed data. min(event_timestamp) hits the earliest partition.
    since = f['since']
    if since is None:
        col = 'VerificationEvent' if kind == 'verification' else 'TokenLifecycleEvent'
        row = query(f"SELECT min(event_timestamp) AS t FROM {col}", fetch='one')
        since = (row and row['t']) or (_db_now() - _ATLAS_TIME_WINDOWS['30d'])

    cache_key = ('series', kind, buckets, _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    rows = query("""
        SELECT to_char(bucket_ts, 'YYYY-MM-DD"T"HH24:MI:SS') AS ts,
               n_total, n_failure, n_zk
        FROM atlas_volume_series(%s, %s, %s, %s, %s, %s, %s)
        ORDER BY bucket_ts
    """, (since, buckets, kind, f['outcomes'], f['disclosure'],
          f['contexts'], f['agencies']))

    payload = dict(
        window=f['window'], kind=kind, buckets=buckets,
        since=since.isoformat(), until=_db_now().isoformat(),
        points=[
            {'ts': r['ts'], 'n_total': int(r['n_total']),
             'n_failure': int(r['n_failure']), 'n_zk': int(r['n_zk'])}
            for r in rows
        ],
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


# The dimensions the stacked Trends series can break a stream out by (whitelisted
# before the SQL CASE, same discipline as the breakdown dimensions).
_ATLAS_STACK_DIMENSIONS = {
    'verification': ('context', 'outcome', 'disclosure', 'agency', 'jurisdiction'),
    'lifecycle':    ('agency', 'event_type'),
}


@app.route('/api/atlas/heatmap')
@security.login_required
@replica_reads
def api_atlas_heatmap():
    """Trends: events by ISO weekday (1=Mon..7=Sun) x hour of day (0..23), the
    temporal-rhythm view. Returns `cells: [{dow, hour, n, n_failure}]`, at most
    7x24=168 cells (C8), counting zero-knowledge events in their cell without a
    location (C6). Honors the same filters as the rest of the Atlas."""
    try:
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    since = f['since']
    if since is None:
        col = 'VerificationEvent' if kind == 'verification' else 'TokenLifecycleEvent'
        row = query(f"SELECT min(event_timestamp) AS t FROM {col}", fetch='one')
        since = (row and row['t']) or (_db_now() - _ATLAS_TIME_WINDOWS['30d'])

    cache_key = ('heatmap', kind, _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    rows = query("""
        SELECT dow, hour, n, n_failure
        FROM atlas_heatmap(%s, %s, %s, %s, %s, %s)
        ORDER BY dow, hour
    """, (since, kind, f['outcomes'], f['disclosure'], f['contexts'], f['agencies']))

    payload = dict(
        window=f['window'], kind=kind,
        cells=[{'dow': int(r['dow']), 'hour': int(r['hour']),
                'n': int(r['n']), 'n_failure': int(r['n_failure'])} for r in rows],
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


@app.route('/api/atlas/stacked')
@security.login_required
@replica_reads
def api_atlas_stacked():
    """Trends: volume over time broken out by one dimension (top-K categories,
    the rest folded into 'Other'), for a stacked-area chart. Returns ordered
    `labels` and `points: [{ts, values: {label: n}}]`, bounded to
    buckets x (K+1) (C8); zero-knowledge events are counted, never located (C6)."""
    try:
        buckets = int(request.args.get('buckets', '48'))
        if buckets <= 0 or buckets > 240:
            raise ValueError("buckets must be in (0, 240]")
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        dimension = request.args.get('dimension', 'context')
        if dimension not in _ATLAS_STACK_DIMENSIONS.get(kind, ()):
            raise ValueError("dimension is not valid for this stream")
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    since = f['since']
    if since is None:
        col = 'VerificationEvent' if kind == 'verification' else 'TokenLifecycleEvent'
        row = query(f"SELECT min(event_timestamp) AS t FROM {col}", fetch='one')
        since = (row and row['t']) or (_db_now() - _ATLAS_TIME_WINDOWS['30d'])

    top_k = 6
    cache_key = ('stacked', kind, buckets, dimension, _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    rows = query("""
        SELECT to_char(bucket_ts, 'YYYY-MM-DD"T"HH24:MI:SS') AS ts, label, n
        FROM atlas_series_stacked(%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ORDER BY bucket_ts, label
    """, (since, buckets, dimension, kind, top_k,
          f['outcomes'], f['disclosure'], f['contexts'], f['agencies']))

    # Pivot to per-bucket {label: n}, and an ordered label list (by total volume,
    # 'Other' always last) so the client stacks the bands consistently.
    by_ts, totals = {}, {}
    for r in rows:
        by_ts.setdefault(r['ts'], {})[r['label']] = int(r['n'])
        totals[r['label']] = totals.get(r['label'], 0) + int(r['n'])
    labels = sorted((lbl for lbl in totals if lbl != 'Other'),
                    key=lambda lbl: (-totals[lbl], lbl))
    if 'Other' in totals:
        labels.append('Other')
    payload = dict(
        window=f['window'], kind=kind, dimension=dimension, buckets=buckets,
        labels=labels,
        points=[{'ts': ts, 'values': by_ts[ts]} for ts in sorted(by_ts)],
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


# The dimensions each stream can be broken down by (whitelisted here so a
# malformed ?dimension= can never reach the SQL CASE as anything but a known
# value). Jurisdiction is the REQUESTING agency's, so it covers ZK too.
_ATLAS_BREAKDOWN_DIMENSIONS = {
    'verification': ('agency', 'context', 'outcome', 'disclosure',
                     'algorithm', 'jurisdiction'),
    'lifecycle':    ('agency', 'event_type'),
}


@app.route('/api/atlas/breakdown')
@security.login_required
@replica_reads
def api_atlas_breakdown():
    """Top-K categorical roll-up for the Overview/Breakdown views.

    `?dimension=` groups the window's events by one whitelisted dimension and
    returns `{label, n_total, n_failure}` ordered by volume, capped at
    _ATLAS_MAX_CATEGORIES. Non-geographic; zero-knowledge events are counted
    like any other (C6)."""
    try:
        kind = request.args.get('kind', 'verification')
        if kind not in _ATLAS_BREAKDOWN_DIMENSIONS:
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        dimension = (request.args.get('dimension') or '').strip().lower()
        if dimension not in _ATLAS_BREAKDOWN_DIMENSIONS[kind]:
            raise ValueError(
                f"dimension must be one of {list(_ATLAS_BREAKDOWN_DIMENSIONS[kind])} for {kind}")
        limit = min(int(request.args.get('limit', str(_ATLAS_MAX_CATEGORIES))),
                    _ATLAS_MAX_CATEGORIES)
        if limit <= 0:
            raise ValueError("limit must be positive")
        # v9.250: a case-insensitive label search so one slice is findable among
        # thousands. Bounded length (defence in depth; it is a bound parameter).
        search = (request.args.get('search') or '').strip()[:60] or None
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    cache_key = ('breakdown', kind, dimension, limit, search, _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    rows = query("""
        SELECT label, n_total, n_failure
        FROM atlas_breakdown(%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ORDER BY n_total DESC, label ASC
    """, (dimension, f['since'], limit, kind, f['outcomes'],
          f['disclosure'], f['contexts'], f['agencies'], search))

    payload = dict(
        kind=kind, dimension=dimension, window=f['window'], limit=limit,
        search=search, truncated=(len(rows) == limit), count=len(rows),
        categories=[
            {'label': r['label'], 'n_total': int(r['n_total']),
             'n_failure': int(r['n_failure'])}
            for r in rows
        ],
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


# The row/column dimensions each stream's cross-tab accepts (whitelisted here so
# a malformed ?row=/?col= can never reach the SQL CASE as anything but a known
# value). The column dimension is deliberately low-cardinality so the cell count
# stays bounded (C8); the rows are capped at _ATLAS_MAX_CATEGORIES.
_ATLAS_CROSSTAB_ROWS = {
    'verification': ('agency', 'context', 'jurisdiction', 'algorithm'),
    'lifecycle':    ('agency', 'event_type'),
}
_ATLAS_CROSSTAB_COLS = {
    'verification': ('outcome', 'disclosure'),
    'lifecycle':    ('event_type',),
}
# Canonical column order per column dimension (so the matrix reads left-to-right
# in a sensible order rather than alphabetically).
_ATLAS_COL_ORDER = {
    'outcome':    ['SUCCESS', 'FAILURE', 'EXPIRED', 'UNAUTHORIZED'],
    'disclosure': ['ZERO_KNOWLEDGE', 'SELECTIVE', 'FULL'],
    'event_type': ['ISSUED', 'ACTIVATED', 'DEACTIVATED', 'DEVICE_BOUND',
                   'DEVICE_REVOKED', 'REVOKED', 'LOST', 'EXPIRED', 'REPLACED'],
}


@app.route('/api/atlas/crosstab')
@security.login_required
@replica_reads
def api_atlas_crosstab():
    """A 2-D categorical pivot for the Breakdown view: `?row=` by `?col=`.

    Returns the top-K rows of the row dimension (by volume, capped at
    _ATLAS_MAX_CATEGORIES) crossed with the column dimension, as
    `{rows:[{label,total}], cols:[label], cells:[{row,col,n}]}`. Both
    dimensions are whitelisted per stream. Non-geographic; zero-knowledge
    events are counted like any other (C6)."""
    try:
        kind = request.args.get('kind', 'verification')
        if kind not in _ATLAS_CROSSTAB_ROWS:
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        row_dim = (request.args.get('row') or '').strip().lower()
        col_dim = (request.args.get('col') or '').strip().lower()
        if row_dim not in _ATLAS_CROSSTAB_ROWS[kind]:
            raise ValueError(f"row must be one of {list(_ATLAS_CROSSTAB_ROWS[kind])} for {kind}")
        if col_dim not in _ATLAS_CROSSTAB_COLS[kind]:
            raise ValueError(f"col must be one of {list(_ATLAS_CROSSTAB_COLS[kind])} for {kind}")
        limit = min(int(request.args.get('limit', str(_ATLAS_MAX_CATEGORIES))),
                    _ATLAS_MAX_CATEGORIES)
        if limit <= 0:
            raise ValueError("limit must be positive")
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    cache_key = ('crosstab', kind, row_dim, col_dim, limit, _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    rows = query("""
        SELECT row_label, col_label, n_total
        FROM atlas_crosstab(%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (row_dim, col_dim, f['since'], limit, kind, f['outcomes'],
          f['disclosure'], f['contexts'], f['agencies']))

    # Assemble the matrix: row order by total desc, columns in canonical order
    # (falling back to sorted for any label not in the canonical list).
    row_totals, seen_cols = {}, set()
    for r in rows:
        row_totals[r['row_label']] = row_totals.get(r['row_label'], 0) + int(r['n_total'])
        seen_cols.add(r['col_label'])
    ordered_rows = sorted(row_totals.items(), key=lambda kv: (-kv[1], kv[0]))
    canon = _ATLAS_COL_ORDER.get(col_dim, [])
    ordered_cols = [c for c in canon if c in seen_cols] + sorted(seen_cols - set(canon))

    payload = dict(
        kind=kind, row=row_dim, col=col_dim, window=f['window'], limit=limit,
        rows=[{'label': lbl, 'total': tot} for lbl, tot in ordered_rows],
        cols=ordered_cols,
        cells=[{'row': r['row_label'], 'col': r['col_label'], 'n': int(r['n_total'])}
               for r in rows],
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


@app.route('/api/atlas/facet/agencies')
@security.login_required
@replica_reads
def api_atlas_facet_agencies():
    """The agency facet for the global filter (roadmap P2.3, v9.251).

    Agencies with `(agency_id, name, n_total)` matching an optional `?q=`
    search, honouring the other active facets (outcome/disclosure/context) but
    not the agency selection. A chip flyout of every agency does not survive
    thousands of them; the operator types and the server returns the matches
    with their activity counts, capped. Non-geographic (C6); operational pivot,
    never an attribute of a person."""
    try:
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        limit = min(int(request.args.get('limit', '20')), _ATLAS_MAX_CATEGORIES)
        search = (request.args.get('q') or '').strip()[:60] or None
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    cache_key = ('facet_agencies', kind, limit, search, _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    rows = query("""
        SELECT agency_id, name, n_total
        FROM atlas_agency_facet(%s, %s, %s, %s, %s, %s, %s)
    """, (f['since'], limit, kind, search, f['outcomes'], f['disclosure'], f['contexts']))
    payload = dict(kind=kind, count=len(rows), results=[
        {'agency_id': r['agency_id'], 'name': r['name'], 'n_total': int(r['n_total'])}
        for r in rows])
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


@app.route('/api/atlas/records')
@security.login_required
@replica_reads
def api_atlas_records():
    """The records grid: one stream of events matching the global filter,
    keyset-paginated (roadmap P2.3, v9.252). Cursor is `TIMESTAMP|EVENT_ID` from
    the previous page's `next_cursor`; capped at _ATLAS_MAX_EVENTS. C6: a
    zero-knowledge verification is a row but its subject and location are
    withheld (the SQL redacts them)."""
    try:
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        limit = min(int(request.args.get('limit', '50')), _ATLAS_MAX_EVENTS)
        if limit <= 0:
            raise ValueError("limit must be positive")
        cur_ts, cur_id = None, None
        cursor = request.args.get('cursor')
        if cursor:
            parts = cursor.split('|')
            if len(parts) != 2:
                raise ValueError("cursor must be TIMESTAMP|EVENT_ID")
            cur_ts, cur_id = parts[0], int(parts[1])
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    rows = query("""
        SELECT event_id,
               to_char(event_timestamp, 'YYYY-MM-DD"T"HH24:MI:SS') AS ts,
               agency_name, category, outcome, disclosure, subject, location, tone
        FROM atlas_records(%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (f['since'], cur_ts, cur_id, limit, kind,
          f['outcomes'], f['disclosure'], f['contexts'], f['agencies']))

    next_cursor = None
    if rows and len(rows) == limit:
        last = rows[-1]
        next_cursor = last['ts'] + '|' + str(last['event_id'])
    return jsonify(
        kind=kind, count=len(rows), next_cursor=next_cursor,
        records=[
            {'event_id': r['event_id'], 'ts': r['ts'], 'agency': r['agency_name'],
             'category': r['category'], 'outcome': r['outcome'],
             'disclosure': r['disclosure'], 'subject': r['subject'],
             'location': r['location'], 'tone': r['tone']}
            for r in rows
        ],
    )


# ----------------------------------------------------------------------------
# SUBJECT FOCUS (v9.148) — single-subject investigation on the map.
#
# This is the warrant-audit use case (UC-7), not population profiling. The
# distinction is hard-enforced:
#   - You reach a subject by IDENTITY (a specific individual_id), never by a
#     protected attribute. There is no "filter the population by X" path; the
#     schema carries no gender/ethnicity/religion/politics to filter on.
#   - Gated to admin/auditor (operators are denied — an operator must not be
#     able to pull a holder's movement map).
#   - Every access is written to the audit-of-record (record_audit_access).
#   - C6 HOLDS even here: ZERO_KNOWLEDGE verifications are never located. The
#     subject map shows only the events the holder already chose to disclose;
#     the ZK ones are returned as a withheld COUNT. The privacy default
#     survives the investigation, which is the whole point.
# ----------------------------------------------------------------------------

@app.route('/api/atlas/subjects/search')
@security.login_required
@security.require_role('admin', 'auditor')
@replica_reads
def api_atlas_subject_search():
    """Typeahead for the subject-focus picker. Name search only; returns the
    individual_id the caller then focuses. At national scale this wants a
    trigram index on Individual.legal_name (pg_trgm) — see docs/reference/
    SCALING.md; ILIKE is fine for the demo roster."""
    q = (request.args.get('q') or '').strip()
    if len(q) < 2:
        return jsonify(results=[])
    rows = query("""
        SELECT individual_id, legal_name, jurisdiction
        FROM Individual
        WHERE legal_name ILIKE %s
        ORDER BY legal_name
        LIMIT 20
    """, ('%' + q + '%',))
    return jsonify(results=[dict(r) for r in rows])


@app.route('/api/atlas/subject')
@security.login_required
@security.require_role('admin', 'auditor')
@replica_reads
def api_atlas_subject():
    """Return ONE subject's located events for the focused map view.

    Warrant-grade: admin/auditor only, audit-logged. C6: ZERO_KNOWLEDGE
    verifications are excluded from the plotted points and returned only as a
    withheld count — even the investigator cannot place them."""
    try:
        iid = int(request.args.get('individual_id', ''))
    except (ValueError, TypeError):
        abort(400, description='individual_id must be an integer')

    ind = query(
        "SELECT individual_id, legal_name, jurisdiction FROM Individual WHERE individual_id = %s",
        (iid,), fetch='one')
    if not ind:
        abort(404)

    # Disclosed verification events (NON-ZK) with a location — "what they did".
    verifs = query("""
        SELECT ve.event_id, ve.latitude AS lat, ve.longitude AS lon,
               to_char(ve.event_timestamp, 'YYYY-MM-DD HH24:MI') AS event_timestamp,
               ve.token_id, vc.context_type, ve.outcome::TEXT AS outcome,
               ve.disclosure_level::TEXT AS disclosure_level,
               ag.name AS agency_name, ve.requestor_location
          FROM VerificationEvent ve
          JOIN IdentityToken         t  ON ve.token_id = t.token_id
          JOIN VerificationContext   vc ON ve.context_id = vc.context_id
          LEFT JOIN Agency           ag ON ve.requesting_agency_id = ag.agency_id
         WHERE t.individual_id = %s
           AND ve.disclosure_level <> 'ZERO_KNOWLEDGE'
           AND ve.latitude IS NOT NULL AND ve.longitude IS NOT NULL
         ORDER BY ve.event_timestamp
    """, (iid,))

    # Lifecycle events for the subject's tokens (issued/activated/revoked …).
    lifecycle = query("""
        SELECT le.event_id, le.latitude AS lat, le.longitude AS lon,
               to_char(le.event_timestamp, 'YYYY-MM-DD HH24:MI') AS event_timestamp,
               le.token_id, le.event_type::TEXT AS event_type,
               le.reason_code::TEXT AS reason_code, ag.name AS agency_name
          FROM TokenLifecycleEvent le
          JOIN IdentityToken     t  ON le.token_id = t.token_id
          LEFT JOIN Agency       ag ON le.actor_agency_id = ag.agency_id
         WHERE t.individual_id = %s
           AND le.latitude IS NOT NULL AND le.longitude IS NOT NULL
         ORDER BY le.event_timestamp
    """, (iid,))

    # Audit-of-record: this access is warrant-grade and must leave a row.
    security.record_audit_access(
        get_db, 'VerificationEvent',
        filter_criteria={'route': '/api/atlas/subject', 'individual_id': iid},
        result_row_count=len(verifs),
    )

    # Note on zero-knowledge: a ZK verification carries token_id = NULL (C2), so
    # it cannot be joined to ANY individual. The subject's ZK activity is not
    # merely location-withheld; it is unattributable to them by construction.
    # The investigation can only ever see what the holder chose to disclose.
    return jsonify(
        individual=dict(ind),
        verifications=[dict(r) for r in verifs],
        lifecycle=[dict(r) for r in lifecycle],
        located=len(verifs) + len(lifecycle),
        zk_note='Zero-knowledge verifications carry no token link (C2) and cannot be attributed to any subject.',
    )


@app.route('/api/atlas/cache-stats')
@security.login_required
def api_atlas_cache_stats():
    """Cache observability — hit/miss/expired/evicted counters and current size.
    Useful for verifying R8-5 effectiveness in production."""
    with _atlas_cache_lock:
        return jsonify(
            ttl_seconds=_ATLAS_CACHE_TTL_SECONDS,
            max_entries=_ATLAS_CACHE_MAX_ENTRIES,
            current_entries=len(_atlas_cache),
            hits=_atlas_cache_stats['hits'],
            misses=_atlas_cache_stats['misses'],
            expired=_atlas_cache_stats['expired'],
            evicted=_atlas_cache_stats['evicted'],
            hit_ratio=(
                _atlas_cache_stats['hits'] /
                (_atlas_cache_stats['hits'] + _atlas_cache_stats['misses'])
                if (_atlas_cache_stats['hits'] + _atlas_cache_stats['misses']) > 0
                else 0.0
            ),
        )


@app.route('/api/atlas/events')
@security.login_required
@replica_reads
def api_atlas_events():
    """Paginated unified event feed (verifications + lifecycle), most-recent
    first. Cursor format: 'TIMESTAMP|EVENT_ID' (URL-encoded)."""
    try:
        limit = min(int(request.args.get('limit', '50')), _ATLAS_MAX_EVENTS)
        if limit <= 0:
            raise ValueError("limit must be positive")
    except ValueError as e:
        return jsonify(error=str(e)), 400

    cursor_ts, cursor_id = None, None
    cursor_param = request.args.get('cursor', '')
    if cursor_param:
        try:
            ts_str, id_str = cursor_param.split('|')
            cursor_ts = ts_str          # let Postgres parse the timestamp
            cursor_id = int(id_str)
        except (ValueError, TypeError):
            return jsonify(error="cursor must be 'TIMESTAMP|EVENT_ID'"), 400

    rows = query("""
        SELECT kind, event_id,
               to_char(event_timestamp, 'YYYY-MM-DD HH24:MI:SS') AS event_timestamp,
               -- Full-microsecond timestamp for the keyset cursor. The display
               -- column above floors to whole seconds; building the cursor from
               -- it would skip every event in the (S.0, S.f) sub-second band at
               -- a page boundary, since atlas_recent_events filters with a
               -- strict `< (cursor_ts, cursor_id)`. Cursor must be full-precision.
               to_char(event_timestamp, 'YYYY-MM-DD HH24:MI:SS.US') AS event_ts_cursor,
               token_id, holder_name, agency_name, label, detail, tone, lat, lon
        FROM atlas_recent_events(%s::timestamp, %s, %s)
    """, (cursor_ts, cursor_id, limit))

    next_cursor = None
    if rows and len(rows) == limit:
        last = rows[-1]
        next_cursor = f"{last['event_ts_cursor']}|{last['event_id']}"

    return jsonify(
        count=len(rows),
        next_cursor=next_cursor,
        # event_ts_cursor is the internal full-precision keyset value; the JSON
        # exposes only the human-readable whole-second event_timestamp.
        events=[{k: v for k, v in r.items() if k != 'event_ts_cursor'} for r in rows],
    )
