# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris_web/atlas_routes.py -- the Atlas: what the system is doing, never who.

The third block lifted out of app.py (2026-09-18) and the largest: the /atlas page, the
/api/atlas aggregation endpoints, the filter parser and the TTL cache they share. 1,241 lines
then. app.py is presentation-free to this extent.

NO PERSON, NO EVENT, NO PLACE. Every endpoint here returns counts per window, category or
region, read from the activity rollups (11_atlas.sql over 01_schema.sql), which hold no person,
credential, event or coordinate. Five endpoints that returned events, four of them naming the
holder, were withdrawn (lab/strategy/009, step A0), and the cluster, hexagon and timeline layers
with step 4: at street zoom a count of one is a point. A single event is read on the
verification log, which writes an AuditAccessLog row, and one person's history only through the
warrant audit. check_atlas_console holds this module and 11_atlas.sql to it.

SMALL CELLS ARE WITHHELD (lab/strategy/009, step 4). A count of one at a known authority,
context and hour tells someone who knows who was there what happened to them, and the Atlas,
unlike the verification log, records no read. So every count below _ATLAS_MIN_CELL comes back
null, zeros included wherever a dimension is fixed (an outcome, a disclosure level, an event
type, an hour of the week, a bucket of a series). Every count is a part of its window's scope
(the window under the request's filters), and a part is withheld when it or the rest of its
whole is below the minimum, so a category of 98 in a scope of 100 does not give the other 2
back; a share is withheld when its part is; a total is withheld when the counts withheld
beneath it sum to less than the minimum; and an open list's small categories (an authority, a
context, a jurisdiction) fold into one row, so a list does not say which of them had activity. Subtraction ACROSS responses can still recover a small
cell; the record says so, and names complementary suppression as the stronger fix it defers. A
request whose filtered window holds fewer than _ATLAS_NARROW_SCOPE events is answered, with
those counts withheld, and written to the application log with the user, the route, the window
and the filters, never a person: a narrowing question leaves a trace, as a read of the
verification log does.

THE WINDOWS ARE THE ROLLUPS'. A window starts at the top of the hour (the day, past a week) that
holds its nominal start, so '24h' read at 10:20 starts at 10:00 yesterday, and every response
says where its window starts and what grain it reads. One context and one authority at a time:
a set of either would let one question subtract another's answer (lab/strategy/009, step 4).

C8 TRAVELS WITH IT. Every Atlas aggregate is bounded, and the bound is the `_ATLAS_MAX_*`
clamp a route applies before the SQL sees a caller-controlled count: the SQL alone bounds
nothing. Those constants are in this file, beside the routes that apply them, which is where
check_c8_atlas_caps looks because it reads the polaris_web package rather than a path. The move
mutation drill carries a c8_atlas_caps payload for exactly this.

THE CACHE IS SHARED STATE AND STAYS ONE OBJECT. `_atlas_cache`, its lock and its counters are
mutated in place and never reassigned, so app.py's readiness report reaches them as
`atlas_routes._atlas_cache`, resolved at use time, and sees the same dict this module writes.
It must not import them by name: `from` copies a binding, and while a dict would survive that,
the habit does not survive the next name that is rebound rather than mutated.
check_no_module_imports_an_unstable_name draws that line. Its key holds whom an answer was
computed for (_atlas_cache_scope), since row-level security answers each scope differently.

Routes register by import: app.py imports this module at the END, after every name below
exists, and aliases itself into sys.modules first so `python3 app.py` does not load it twice.
"""
import json
import os
import threading
import time as _time
from datetime import timedelta

from flask import g, jsonify, render_template, request, session

import app as _app          # for the two values app.py owns and callers repoint; see below
import security
from app import (
    _db_now,
    app,
    atlas_basemap_origins,
    query,
    replica_reads,
)


# ============================================================================
# ATLAS: the system at scale, in counts (lab/strategy/009)
# ============================================================================

# Hard caps on what one response may carry (C8). The breakdowns, the cross-tab rows and the
# authority facet return at most _ATLAS_MAX_CATEGORIES categories, top-K by volume; the regions
# layer at most _ATLAS_MAX_REGIONS jurisdictions; a series at most _ATLAS_MAX_BUCKETS buckets.
_ATLAS_MAX_CATEGORIES = 50
_ATLAS_MAX_REGIONS = 500
_ATLAS_MAX_BUCKETS = 240

#: The minimum cell size (lab/strategy/009, step 4). See the module docstring.
_ATLAS_MIN_CELL = 5
#: A request whose filtered window holds fewer events than this is written to the application
#: log (lab/strategy/009, step 4).
_ATLAS_NARROW_SCOPE = 50
#: A compared category is marked when its failure share at least doubled against the window
#: before and it failed at least this many more times (lab/strategy/009 A4), so that a few
#: events in a small category cannot raise the mark alone.
_ATLAS_ROSE_FACTOR = 2
_ATLAS_ROSE_MIN = 10


@app.route('/atlas')
@security.login_required
def atlas():
    """The Atlas: what the system is doing, as counts over windows, categories and regions.
    It shows no event, no person and no place (lab/strategy/009). A single event is read on the
    verification log, which records the read; one person's history is reached only through the
    warrant audit."""

    # v9.146: opt this one page into the MapLibre tile-basemap CSP relaxation
    # (apply_security_headers reads g.atlas_tiles). Every other page stays strict self-only.
    g.atlas_tiles = True
    g.atlas_tile_origins = atlas_basemap_origins()

    # The authority roster for the authority filter: an operational pivot, never an attribute of
    # a person. Authorities are few; the facet typeahead (/api/atlas/facet/agencies) serves the
    # deployment that has thousands.
    agencies = query('SELECT agency_id, name, agency_type FROM Agency ORDER BY name')

    return render_template(
        'atlas.html',
        # Read at USE time, not copied at import. This value has two readers, the CSP
        # builder in app.py and this page, and they must never disagree about it: an
        # operator who repoints the basemap gets a page whose tiles the policy blocks.
        # A `from app import` copy held the value from startup, and the suite that
        # repoints it found exactly that split on 2026-09-18, the CSP half passing and
        # the page half failing.
        atlas_basemap_style=_app.ATLAS_BASEMAP_STYLE_URL,
        health=_atlas_health(), agencies=agencies, min_cell=_ATLAS_MIN_CELL,
        narrow_scope=_ATLAS_NARROW_SCOPE)


def _atlas_health():
    """The page's headline figures, each from a count kept as it changes (lab/strategy/008 and
    009, step 4), so the page costs the same at any population. Withheld below the minimum cell
    size as on every Atlas route: the figures cover everything recorded, and a deployment with a
    handful of credentials is a deployment whose figures are about a handful of people."""
    stats = query("SELECT * FROM atlas_stats(NULL, TRUE)", fetch='one')
    status = {r['item']: int(r['n']) for r in query("""
        SELECT item, sum(n) AS n
          FROM (SELECT item, n FROM PopulationCount WHERE facet = 'credential_status'
                UNION ALL
                SELECT item, n FROM PopulationCountDelta WHERE facet = 'credential_status') c
         GROUP BY item""")}
    signatures = query("""
        SELECT COALESCE(sum(c.n) FILTER (WHERE a.quantum_resistant), 0) AS pq,
               COALESCE(sum(c.n), 0) AS total
          FROM (SELECT item, n FROM PopulationCount WHERE facet = 'live_signature'
                UNION ALL
                SELECT item, n FROM PopulationCountDelta WHERE facet = 'live_signature') c
          JOIN CryptographicAlgorithm a ON a.algorithm_id::TEXT = c.item""", fetch='one')
    # Where the 'all' window starts: the first day the rollups count, not an event's time.
    first = query("""
        SELECT least((SELECT min(bucket) FROM VerificationRollupDaily),
                     (SELECT date_trunc('day', min(bucket)) FROM VerificationRollupDelta)) AS d""",
                  fetch='one')
    n_verifs = int(stats['n_verifs'])
    terminal = sum(status.get(s, 0) for s in ('REVOKED', 'LOST', 'EXPIRED'))
    return {
        'oldest_event':      first['d'].date().isoformat() if first and first['d'] else '',
        'verifications_total': _count(n_verifs),
        'tokens_active':     _count(status.get('ACTIVE', 0)),
        'tokens_reserve':    _count(status.get('RESERVE', 0)),
        'tokens_terminal':   _count(terminal),
        'pq_pct':            _share(signatures['pq'], signatures['total']),
        'zk_pct':            _share(stats['n_zk'], n_verifs),
        'failures':          _part(stats['n_failures'], n_verifs),
        'full_disclosures':  _part(stats['n_full'], n_verifs),
    }


# ============================================================================
# WITHHOLDING SMALL CELLS (lab/strategy/009, step 4)
# ============================================================================

def _count(n):
    """A count the Atlas may show, or None below the minimum cell size (zero included)."""
    n = int(n or 0)
    return n if n >= _ATLAS_MIN_CELL else None


def _part(part, whole):
    """A part of a whole the same response shows, withheld when it or the rest of the whole is
    below the minimum: a part of 98 out of 100 would give the other 2 back."""
    part, whole = int(part or 0), int(whole or 0)
    return part if min(part, whole - part) >= _ATLAS_MIN_CELL else None


def _share(part, whole):
    """A whole-number percentage of a whole, withheld as its part would be."""
    shown = _part(part, whole)
    return None if shown is None or not int(whole or 0) else round(100 * shown / int(whole))


#: The row that holds an open list's small categories (an authority, a context, a jurisdiction,
#: an algorithm): listed one by one, each would say that it had activity even with its count
#: withheld.
_ATLAS_FOLDED = 'Fewer than %d each' % _ATLAS_MIN_CELL


def _fold_small(counts):
    """Split an open list's {label: count} into the labels at or above the minimum, in order of
    volume, and the sum of the rest (zero when there is none), which the caller shows as one
    row, withheld in turn below the minimum."""
    shown = sorted((lbl for lbl, n in counts.items() if n >= _ATLAS_MIN_CELL),
                   key=lambda lbl: (-counts[lbl], lbl))
    return shown, sum(n for lbl, n in counts.items() if n < _ATLAS_MIN_CELL)


def _note_narrow(route, f, scope_total, **asked):
    """Write a narrow question to the application log: one whose filtered window holds fewer
    than _ATLAS_NARROW_SCOPE events. Who asked and what they asked, never a count below the
    threshold and never a person. Called on a cached answer too: a narrowing question is
    recorded each time it is asked, by whoever asks it."""
    if int(scope_total or 0) >= _ATLAS_NARROW_SCOPE:
        return
    detail = ' '.join('%s=%s' % kv for kv in sorted(asked.items()))
    app.logger.info(
        'atlas narrow question: user %s asked %s window=%s from=%s outcomes=%s disclosure=%s '
        'context=%s authority=%s %s (fewer than %d events in scope)',
        session.get('user_id'), route, f['window'], f['since'], f['outcomes'], f['disclosure'],
        f['contexts'], f['agencies'], detail, _ATLAS_NARROW_SCOPE)


# =============================================================================
# Atlas TTL cache (R8-5)
# =============================================================================
# In-process TTL cache for Atlas answers, keyed by the question and whom it was answered for,
# holding (timestamp, (payload, scope total)). Hot questions polled by several operators hit the
# cache instead of the SQL. Each worker has its own cache; the worst case is a cold start in
# every worker, which is no worse than no cache. Invalidation is pure TTL: the rollups change as
# events are recorded, and thirty seconds of staleness matches the polling interval.

_ATLAS_CACHE_TTL_SECONDS = float(os.environ.get('POLARIS_ATLAS_CACHE_TTL', '30'))
_ATLAS_CACHE_MAX_ENTRIES = int(os.environ.get('POLARIS_ATLAS_CACHE_MAX', '256'))
_atlas_cache = {}                               # dict[key, tuple[float, tuple[dict, int]]]
_atlas_cache_lock = threading.Lock()
_atlas_cache_stats = {'hits': 0, 'misses': 0, 'expired': 0, 'evicted': 0}


def _atlas_cache_scope():
    """Whom an answer was computed for: the authority the signed-in operator is bound to, or
    None. Row-level security answers a bound operator for that authority alone (the request
    tells the database who is asking, app._apply_operator_binding), so an answer cached for one
    scope is never served to another. Until 2026-10-02 the key held only the question, and an
    unbound administrator's breakdown of every authority reached an operator bound to one."""
    try:
        return session.get('operator_agency_id') if session.get('logged_in') else None
    except RuntimeError:     # no request: a CLI or a test outside one, unscoped as the database is
        return None


def _atlas_cache_get(key):
    """Return the cached entry if fresh, else None. Thread-safe. The key is the question and
    whom it was answered for."""
    key = (_atlas_cache_scope(), key)
    if _ATLAS_CACHE_TTL_SECONDS <= 0:
        return None
    # Live simulation mode wants the console to update as events stream in, so it bypasses the
    # aggregate cache (dev/demo only). Production is unaffected: SIM_MODE is force-off there.
    # Read at USE time. SIM_MODE is app.py's, and the simulation suite flips it per test; a
    # `from app import` copy froze it at startup and the cache stopped being bypassed, with
    # nothing failing (found by check_no_module_imports_an_unstable_name, 2026-09-18).
    if _app.SIM_MODE:
        return None
    now = _time.time()
    with _atlas_cache_lock:
        entry = _atlas_cache.get(key)
        if entry is None:
            _atlas_cache_stats['misses'] += 1
            return None
        ts, value = entry
        if now - ts > _ATLAS_CACHE_TTL_SECONDS:
            del _atlas_cache[key]
            _atlas_cache_stats['expired'] += 1
            _atlas_cache_stats['misses'] += 1
            return None
        _atlas_cache_stats['hits'] += 1
        return value


def _atlas_cache_set(key, value):
    """Store an entry with the current timestamp, for the scope it was answered for. Evict the
    oldest at capacity."""
    key = (_atlas_cache_scope(), key)
    if _ATLAS_CACHE_TTL_SECONDS <= 0:
        return
    now = _time.time()
    with _atlas_cache_lock:
        if len(_atlas_cache) >= _ATLAS_CACHE_MAX_ENTRIES:
            oldest_key = min(_atlas_cache, key=lambda k: _atlas_cache[k][0])
            del _atlas_cache[oldest_key]
            _atlas_cache_stats['evicted'] += 1
        _atlas_cache[key] = (now, value)


def _atlas_cache_clear():
    """Used by tests and admin endpoints."""
    with _atlas_cache_lock:
        _atlas_cache.clear()
        for k in _atlas_cache_stats:
            _atlas_cache_stats[k] = 0


def _answer(route, cache_key, f, compute, **asked):
    """Answer an Atlas question from the cache when it is fresh for this scope, else by
    `compute()`, which returns (payload, scope total). Either way a narrow question is noted."""
    entry = _atlas_cache_get(cache_key)
    if entry is None:
        entry = compute()
        _atlas_cache_set(cache_key, entry)
    payload, scope_total = entry
    _note_narrow(route, f, scope_total, **asked)
    return jsonify(payload)


# ============================================================================
# THE WINDOWS AND THE FILTERS
# ============================================================================

#: label -> (nominal span, the grain the window reads). The schema stores event_timestamp as
#: TIMESTAMP in the database session's wall clock (UTC since rc.28), so the window is measured
#: from THAT clock (_db_now), and starts at the top of the hour or the day holding its start.
_ATLAS_TIME_WINDOWS = {
    '1h':  (timedelta(hours=1), 'hour'),
    '24h': (timedelta(hours=24), 'hour'),
    '7d':  (timedelta(days=7), 'hour'),
    '30d': (timedelta(days=30), 'day'),
    'all': (None, 'day'),
}

# Outcome alias: "anomalies" = the union the operator typically wants when investigating an
# incident. Anchored here (not in JS) so the SQL parameter is the same set across UI versions.
_ATLAS_OUTCOME_ALIASES = {
    'anomalies': 'FAILURE,UNAUTHORIZED,EXPIRED',
}
_ATLAS_OUTCOMES = ('SUCCESS', 'FAILURE', 'EXPIRED', 'UNAUTHORIZED')
_ATLAS_DISCLOSURES = ('ZERO_KNOWLEDGE', 'SELECTIVE', 'FULL')
_ATLAS_CONTEXTS = ('BANKING', 'EMPLOYMENT', 'HEALTHCARE', 'TRAVEL', 'VOTING', 'MOTOR_VEHICLE',
                   'GOVERNMENT_BENEFITS')
_ATLAS_EVENT_TYPES = ('ISSUED', 'ACTIVATED', 'DEACTIVATED', 'DEVICE_BOUND', 'DEVICE_REVOKED',
                      'REVOKED', 'LOST', 'EXPIRED', 'REPLACED')


def _window_start(now, delta, grain):
    """The top of the hour (or day) that holds now - delta; None for the open window."""
    if delta is None:
        return None
    start = now - delta
    if grain == 'day':
        return start.replace(hour=0, minute=0, second=0, microsecond=0)
    return start.replace(minute=0, second=0, microsecond=0)


def _parse_atlas_filters(args):
    """The filters every Atlas route takes, as SQL-ready values: window, since (the start of the
    window, or None for 'all'), daily (whether it reads the daily rollup), grain, outcomes and
    disclosure (CSV or None), contexts and agencies (one value or None). Raises ValueError on
    anything malformed, which the route turns into a 400."""
    window = (args.get('window') or '24h').strip().lower()
    if window not in _ATLAS_TIME_WINDOWS:
        raise ValueError(
            f"window must be one of {sorted(_ATLAS_TIME_WINDOWS.keys())}; got {window!r}")
    delta, grain = _ATLAS_TIME_WINDOWS[window]

    outcomes = (args.get('outcomes') or '').strip()
    outcomes = _ATLAS_OUTCOME_ALIASES.get(outcomes, outcomes) or None
    for v in (outcomes or '').split(',') if outcomes else ():
        if v not in _ATLAS_OUTCOMES:
            raise ValueError(f"unknown outcome: {v!r}")

    disclosure = (args.get('disclosure') or '').strip() or None
    for v in (disclosure or '').split(',') if disclosure else ():
        if v not in _ATLAS_DISCLOSURES:
            raise ValueError(f"unknown disclosure level: {v!r}")

    # One context and one authority at a time (lab/strategy/009, step 4): with a set, the
    # answer for all but one would subtract from the answer for all.
    contexts = (args.get('contexts') or '').strip() or None
    if contexts and ',' in contexts:
        raise ValueError("one context at a time")
    if contexts and contexts not in _ATLAS_CONTEXTS:
        raise ValueError(f"unknown context: {contexts!r}")

    agencies = (args.get('agencies') or '').strip() or None
    if agencies and ',' in agencies:
        raise ValueError("one authority at a time")
    # ASCII digits only: str.isdigit() takes '\u00b2' and '\u0663' too. Normalised, so '007' is
    # authority 7, which the SQL matches as text.
    if agencies and not (agencies.isascii() and agencies.isdigit() and len(agencies) <= 10):
        raise ValueError(f"authority id must be an integer: {agencies!r}")
    if agencies:
        agencies = str(int(agencies))

    return {
        'window': window,
        'since': _window_start(_db_now(), delta, grain),
        'daily': grain == 'day',
        'grain': grain,
        'outcomes': outcomes,
        'disclosure': disclosure,
        'contexts': contexts,
        'agencies': agencies,
    }


def _filter_cache_key(f):
    """Reduce a filter dict to a hashable cache key fragment. The window's start is in it: the
    same label read in the next hour is a different window."""
    return (f['window'], f['since'], f['outcomes'], f['disclosure'], f['contexts'], f['agencies'])


def _window_fields(f):
    """What every response says about its window."""
    return {'window': f['window'], 'grain': f['grain'],
            'since': f['since'].isoformat() if f['since'] else None,
            'min_cell': _ATLAS_MIN_CELL}


def _kind(args):
    kind = args.get('kind', 'verification')
    if kind not in ('verification', 'lifecycle'):
        raise ValueError("kind must be 'verification' or 'lifecycle'")
    return kind


def _series_since(f, kind):
    """Where a series starts: the window's start, or for 'all' the first day the rollups count,
    as the caller may see them. A series needs a fixed start to cut its buckets from."""
    if f['since'] is not None:
        return f['since']
    table, delta = (('VerificationRollupDaily', 'VerificationRollupDelta') if kind == 'verification'
                    else ('LifecycleRollupDaily', 'LifecycleRollupDelta'))
    row = query(f"SELECT least((SELECT min(bucket) FROM {table}), "
                f"(SELECT date_trunc('day', min(bucket)) FROM {delta})) AS d", fetch='one')
    if row and row['d']:
        return row['d']
    return _window_start(_db_now(), timedelta(days=30), 'day')


def _first_hour(kind):
    """The first hour the hourly rollup still holds, as the caller may see it, or None."""
    table, delta = (('VerificationRollup', 'VerificationRollupDelta') if kind == 'verification'
                    else ('LifecycleRollup', 'LifecycleRollupDelta'))
    row = query(f"SELECT least((SELECT min(bucket) FROM {table}), "
                f"(SELECT min(bucket) FROM {delta})) AS h", fetch='one')
    return row['h'] if row else None


def _bucket_width(since, until, buckets, grain):
    """A series bucket: whole hours (or days), since the rollups hold nothing finer, and wider
    than the window over `buckets`, so the window cuts into at most `buckets` of them. A width of
    exactly span / buckets cuts one more, the last starting at `until` itself (C8)."""
    unit = 3600 if grain == 'hour' else 86400
    span = max((until - since).total_seconds(), unit)
    return timedelta(seconds=(int(span // (buckets * unit)) + 1) * unit)


def _buckets(since, until, width):
    """Every bucket start from `since` to `until`: a series is filled, so a quiet bucket reads
    as withheld, as a small one does, and never as a zero that says nothing happened."""
    out, t = [], since
    while t <= until:
        out.append(t)
        t += width
    return out


def _ts(t):
    return t.strftime('%Y-%m-%dT%H:%M:%S')


# ============================================================================
# THE WINDOW BEFORE (lab/strategy/009 A4)
# ============================================================================

def _parse_compare(args, f):
    """`compare=previous`: each count beside the same count for the window of the same nominal
    length immediately before. None when not asked. 'all' has nothing before it."""
    compare = (args.get('compare') or '').strip().lower() or None
    if compare is None:
        return None
    if compare != 'previous':
        raise ValueError("compare must be 'previous'")
    if f['since'] is None:
        raise ValueError("compare=previous needs a bounded window: 'all' has nothing before it")
    return compare


def _previous_window(f, kind):
    """The window before f's: [since - span, since), on f's grain. Its hours may be gone: a
    retention purge deletes the hourly rollup before its cutoff and keeps the daily one, and an
    hourly window reaching back past the first hour still held would count less than happened
    and read as a fall. When the daily rollup holds a day before that hour's, the hours were
    purged, and the window is incomplete: nothing in it is compared."""
    delta, grain = _ATLAS_TIME_WINDOWS[f['window']]
    prev = {'since': f['since'] - delta, 'until': f['since'], 'incomplete': None}
    if grain == 'hour':
        first = _first_hour(kind)
        if first is not None and prev['since'] < first:
            day = _first_day(kind)
            if day is not None and day < first.replace(hour=0):
                prev['incomplete'] = 'the hours before %s are no longer held' % _ts(first)
    return prev


def _first_day(kind):
    """The first day the daily rollup holds, or None. Only a fold writes it, and a purge folds
    before it deletes hours, so a day here before the first hour still held means a purge."""
    table = 'VerificationRollupDaily' if kind == 'verification' else 'LifecycleRollupDaily'
    row = query(f"SELECT min(bucket) AS d FROM {table}", fetch='one')
    return row['d'] if row else None


def _previous_fields(prev):
    return {'since': _ts(prev['since']), 'until': _ts(prev['until']),
            'incomplete': prev['incomplete']}


def _change(now, before):
    """The difference of two shown counts, None when either is withheld: a change computed from
    a withheld count would give it back."""
    return None if now is None or before is None else now - before


def _failure_rose(total, failure, prev_total, prev_failure):
    """Whether a category's failure share at least doubled against the window before, with at
    least _ATLAS_ROSE_MIN more failures. None unless all four counts are shown, for the reason a
    change is."""
    if None in (total, failure, prev_total, prev_failure):
        return None
    return (failure - prev_failure >= _ATLAS_ROSE_MIN
            and failure * prev_total >= _ATLAS_ROSE_FACTOR * prev_failure * total)


# ============================================================================
# THE REGIONS LAYER
# ============================================================================

# Where a jurisdiction sits on the map: reference data about the jurisdiction (static, beside
# the page), never where anyone was verified. Loaded once; an unknown code is counted and not
# placed.
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static',
                       'atlas-regions.json'), encoding='utf-8') as _fh:
    _ATLAS_REGIONS = json.load(_fh)['regions']


@app.route('/api/atlas/geo/jurisdictions')
@security.login_required
@replica_reads
def api_atlas_geo_jurisdictions():
    """The regions layer, the map's only layer: the window's counts by the requesting
    authority's jurisdiction (the acting authority's, for the lifecycle), top-K by volume
    (<= _ATLAS_MAX_REGIONS, C8), placed from reference data about each jurisdiction. A
    zero-knowledge verification is counted in its jurisdiction and located nowhere (C6): the
    rollups hold no location at all."""
    try:
        kind = _kind(request.args)
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    def compute():
        rows = query("""
            SELECT jurisdiction, n_total, n_failure, n_zk, scope_total
              FROM atlas_geo_jurisdictions(%s, %s, %s, %s, %s, %s, %s, %s)
        """, (f['since'], f['daily'], _ATLAS_MAX_REGIONS, kind,
              f['outcomes'], f['disclosure'], f['contexts'], f['agencies']))
        # A jurisdiction with fewer than the minimum is not drawn (a mark on the map would say it
        # had activity); its count joins `elsewhere`. So does one the reference data cannot place.
        scope = int(rows[0]['scope_total']) if rows else 0
        regions, unplaced, elsewhere = [], [], 0
        for r in rows:
            n = int(r['n_total'])
            if n < _ATLAS_MIN_CELL:
                elsewhere += n
                continue
            region = {'jurisdiction': r['jurisdiction'], 'n_total': _part(n, scope),
                      'n_failure': _part(r['n_failure'], n), 'n_zk': _part(r['n_zk'], n)}
            ref = _ATLAS_REGIONS.get(r['jurisdiction'])
            if ref:
                region.update(name=ref['name'], lat=ref['lat'], lon=ref['lon'])
                regions.append(region)
            else:
                unplaced.append(region)
        # At the cap, the quietest jurisdictions past it are in no row at all: counted in the
        # window's totals and drawn nowhere, which the page says rather than implying the map is
        # every jurisdiction.
        payload = dict(kind=kind, count=len(regions) + len(unplaced), regions=regions,
                       unplaced=unplaced, elsewhere=_part(elsewhere, scope),
                       truncated=len(rows) == _ATLAS_MAX_REGIONS, **_window_fields(f))
        return payload, scope

    return _answer('regions', ('geojur', kind, _filter_cache_key(f)), f, compute, kind=kind)


@app.route('/api/atlas/stats')
@security.login_required
@replica_reads
def api_atlas_stats():
    """The window's headline counts: verifications, failures, full disclosures, the
    zero-knowledge share, the share made with a credential under a quantum-resistant algorithm,
    lifecycle events, and active credentials (the population counts, not the window's)."""
    try:
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    def compute():
        row = query("SELECT * FROM atlas_stats(%s, %s, %s)",
                    (f['since'], f['daily'], f['agencies']), fetch='one')
        n = int(row['n_verifs'])
        payload = dict(
            n_active_tokens=_count(row['n_active_tokens']),
            n_verifs=_count(n),
            n_failures=_part(row['n_failures'], n),
            n_full=_part(row['n_full'], n),
            zk_pct=_share(row['n_zk'], n),
            pq_pct=_share(row['n_pq'], row['n_named']),
            n_lifecycles=_count(row['n_lifecycles']),
            **_window_fields(f))
        return payload, n + int(row['n_lifecycles'])

    return _answer('stats', ('stats', _filter_cache_key(f)), f, compute)


@app.route('/api/atlas/series')
@security.login_required
@replica_reads
def api_atlas_series():
    """Volume over the window: `{ts, n_total, n_failure, n_zk}` per bucket, every bucket from
    the window's start to now, at most `?buckets=` (<= _ATLAS_MAX_BUCKETS) of them, each whole
    hours or days wide. Counts every event, zero-knowledge ones included, located nowhere (C6)."""
    try:
        buckets = int(request.args.get('buckets', '60'))
        if not (0 < buckets <= _ATLAS_MAX_BUCKETS):
            raise ValueError(f"buckets must be in (0, {_ATLAS_MAX_BUCKETS}]")
        kind = _kind(request.args)
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    def compute():
        since, until = _series_since(f, kind), _db_now()
        width = _bucket_width(since, until, buckets, f['grain'])
        rows = query("""
            SELECT bucket_ts, n_total, n_failure, n_zk, scope_total, scope_failure, scope_zk
              FROM atlas_volume_series(%s, %s, %s, %s, %s, %s, %s, %s)
        """, (since, f['daily'], width, kind, f['outcomes'], f['disclosure'],
              f['contexts'], f['agencies']))
        scope = int(rows[0]['scope_total']) if rows else 0
        by_ts = {r['bucket_ts']: r for r in rows}
        points = []
        for t in _buckets(since, until, width):
            r = by_ts.get(t)
            n = int(r['n_total']) if r else 0
            points.append({'ts': _ts(t), 'n_total': _part(n, scope),
                           'n_failure': _part(r['n_failure'] if r else 0, n),
                           'n_zk': _part(r['n_zk'] if r else 0, n)})
        # The window's own totals, withheld as its parts are: the page shows these, never a sum of
        # the points, which would read a withheld bucket as none.
        first = rows[0] if rows else {'scope_failure': 0, 'scope_zk': 0}
        totals = {'n_total': _count(scope), 'n_failure': _part(first['scope_failure'], scope),
                  'n_zk': _part(first['scope_zk'], scope)}
        payload = dict(kind=kind, buckets=len(points), bucket_seconds=int(width.total_seconds()),
                       until=until.isoformat(), points=points, totals=totals,
                       **dict(_window_fields(f), since=since.isoformat()))
        return payload, scope

    return _answer('series', ('series', kind, buckets, _filter_cache_key(f)), f, compute,
                   kind=kind)


# The dimensions the stacked series can break a stream out by (whitelisted before the SQL CASE).
_ATLAS_STACK_DIMENSIONS = {
    'verification': ('context', 'outcome', 'disclosure', 'agency', 'jurisdiction'),
    'lifecycle':    ('agency', 'event_type'),
}


@app.route('/api/atlas/heatmap')
@security.login_required
@replica_reads
def api_atlas_heatmap():
    """The window's counts by ISO weekday (1 Monday .. 7 Sunday) and hour of day: all 168 cells,
    `{dow, hour, n, n_failure}`, each withheld below the minimum (C8, C6). Always the hourly
    rollup; for 'all' that is every hour still kept, since a purge takes the hours it empties."""
    try:
        kind = _kind(request.args)
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    def compute():
        rows = query("""
            SELECT dow, hour, n, n_failure, scope_total
              FROM atlas_heatmap(%s, %s, %s, %s, %s, %s)
        """, (f['since'], kind, f['outcomes'], f['disclosure'], f['contexts'], f['agencies']))
        scope = int(rows[0]['scope_total']) if rows else 0
        # 'all' here is every hour still kept, which a purge shortens while the daily rollup
        # keeps its days: the response says where its hours begin, not that they are all.
        since = f['since'] or _first_hour(kind)
        by_cell = {(int(r['dow']), int(r['hour'])): r for r in rows}
        cells = []
        for dow in range(1, 8):
            for hour in range(24):
                r = by_cell.get((dow, hour))
                n = int(r['n']) if r else 0
                cells.append({'dow': dow, 'hour': hour, 'n': _part(n, scope),
                              'n_failure': _part(r['n_failure'] if r else 0, n)})
        payload = dict(kind=kind, cells=cells, **dict(
            _window_fields(f), grain='hour', since=since.isoformat() if since else None))
        return payload, scope

    return _answer('heatmap', ('heatmap', kind, _filter_cache_key(f)), f, compute, kind=kind)


@app.route('/api/atlas/stacked')
@security.login_required
@replica_reads
def api_atlas_stacked():
    """Volume over the window broken out by one dimension: the top six categories by volume,
    the rest folded into 'Other', every bucket from the window's start, as ordered `labels` and
    `points: [{ts, values: {label: n}}]` (C8). Each value is withheld below the minimum."""
    try:
        buckets = int(request.args.get('buckets', '48'))
        if not (0 < buckets <= _ATLAS_MAX_BUCKETS):
            raise ValueError(f"buckets must be in (0, {_ATLAS_MAX_BUCKETS}]")
        kind = _kind(request.args)
        dimension = request.args.get('dimension', 'context')
        if dimension not in _ATLAS_STACK_DIMENSIONS[kind]:
            raise ValueError("dimension is not valid for this stream")
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    top_k = 6

    def compute():
        since, until = _series_since(f, kind), _db_now()
        width = _bucket_width(since, until, buckets, f['grain'])
        rows = query("""
            SELECT bucket_ts, label, n, scope_total
              FROM atlas_series_stacked(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (since, f['daily'], width, dimension, kind, top_k,
              f['outcomes'], f['disclosure'], f['contexts'], f['agencies']))
        scope = int(rows[0]['scope_total']) if rows else 0
        totals = {}
        for r in rows:
            totals[r['label']] = totals.get(r['label'], 0) + int(r['n'])
        # A category with fewer than the minimum over the whole window joins 'Other', so the
        # bands do not say which small categories had activity. Ordered by volume, 'Other' last.
        labels = sorted((lbl for lbl in totals if lbl != 'Other' and totals[lbl] >= _ATLAS_MIN_CELL),
                        key=lambda lbl: (-totals[lbl], lbl))
        cells = {}
        for r in rows:
            band = r['label'] if r['label'] in labels else 'Other'
            cells[(r['bucket_ts'], band)] = cells.get((r['bucket_ts'], band), 0) + int(r['n'])
        if any(lbl not in labels for lbl in totals):
            labels.append('Other')
        points = [{'ts': _ts(t), 'values': {lbl: _part(cells.get((t, lbl), 0), scope) for lbl in labels}}
                  for t in _buckets(since, until, width)]
        payload = dict(kind=kind, dimension=dimension, buckets=len(points),
                       bucket_seconds=int(width.total_seconds()), labels=labels, points=points,
                       **dict(_window_fields(f), since=since.isoformat()))
        return payload, scope

    return _answer('stacked', ('stacked', kind, buckets, dimension, _filter_cache_key(f)), f,
                   compute, kind=kind, dimension=dimension)


# The dimensions each stream can be broken down by (whitelisted here so a malformed
# ?dimension= can never reach the SQL CASE as anything but a known value). Jurisdiction is the
# REQUESTING authority's, so it covers zero-knowledge verifications too.
_ATLAS_BREAKDOWN_DIMENSIONS = {
    'verification': ('agency', 'context', 'outcome', 'disclosure', 'algorithm', 'jurisdiction'),
    'lifecycle':    ('agency', 'event_type'),
}
#: The fixed dimensions: every value is listed, so a missing row cannot say "none" where a
#: withheld count would say "fewer than five".
_ATLAS_FIXED_VALUES = {
    'context':    list(_ATLAS_CONTEXTS),
    'outcome':    list(_ATLAS_OUTCOMES),
    'disclosure': list(_ATLAS_DISCLOSURES),
    'event_type': list(_ATLAS_EVENT_TYPES),
}


@app.route('/api/atlas/breakdown')
@security.login_required
@replica_reads
def api_atlas_breakdown():
    """The window's counts by one whitelisted dimension, `{label, n_total, n_failure}` ordered
    by volume and capped at _ATLAS_MAX_CATEGORIES. An outcome, disclosure or event-type
    breakdown lists every value; the others list what is there, top-K. With compare=previous
    each listed category also carries its counts in the window before, each withheld against
    that window's own scope, the change when both counts are shown, and whether its failure
    share rose (lab/strategy/009 A4). The row of small categories is not compared: its members
    differ from one window to the next."""
    try:
        kind = _kind(request.args)
        dimension = (request.args.get('dimension') or '').strip().lower()
        if dimension not in _ATLAS_BREAKDOWN_DIMENSIONS[kind]:
            raise ValueError(
                f"dimension must be one of {list(_ATLAS_BREAKDOWN_DIMENSIONS[kind])} for {kind}")
        limit = min(int(request.args.get('limit', str(_ATLAS_MAX_CATEGORIES))),
                    _ATLAS_MAX_CATEGORIES)
        if limit <= 0:
            raise ValueError("limit must be positive")
        # A case-insensitive label search, so one slice is findable among thousands. Bounded
        # length (defence in depth; it is a bound parameter).
        search = (request.args.get('search') or '').strip()[:60] or None
        f = _parse_atlas_filters(request.args)
        compare = _parse_compare(request.args, f)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    def counts(since, until):
        """{label: (n_total, n_failure)}, the scope, and whether the top-K was full."""
        rows = query("""
            SELECT label, n_total, n_failure, scope_total
              FROM atlas_breakdown(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (dimension, since, f['daily'], limit, kind, f['outcomes'],
              f['disclosure'], f['contexts'], f['agencies'], search, until))
        return ({r['label']: (int(r['n_total']), int(r['n_failure'])) for r in rows},
                int(rows[0]['scope_total']) if rows else 0, len(rows) == limit)

    def compute():
        found, scope, full = counts(f['since'], None)
        fixed = _ATLAS_FIXED_VALUES.get(dimension)
        if fixed:
            # Every value listed, a zero withheld like a small count.
            labels = [v for v in fixed if not search or search.lower() in v.lower()]
            categories = [{'label': lbl, 'n_total': _part(found.get(lbl, (0, 0))[0], scope),
                           'n_failure': _part(found.get(lbl, (0, 0))[1], found.get(lbl, (0, 0))[0])}
                          for lbl in labels]
        else:
            labels, small = _fold_small({lbl: n for lbl, (n, _) in found.items()})
            categories = [{'label': lbl, 'n_total': _part(found[lbl][0], scope),
                           'n_failure': _part(found[lbl][1], found[lbl][0])} for lbl in labels]
            small_failures = sum(nf for lbl, (n, nf) in found.items() if n < _ATLAS_MIN_CELL)
            categories.append({'label': _ATLAS_FOLDED, 'n_total': _part(small, scope),
                               'n_failure': _part(small_failures, small), 'folded': True})
        payload = dict(kind=kind, dimension=dimension, limit=limit, search=search,
                       truncated=(not fixed and full), count=len(categories),
                       categories=categories, **_window_fields(f))
        if compare:
            prev = _previous_window(f, kind)
            payload['previous'] = _previous_fields(prev)
            before, prev_scope, prev_full = ({}, 0, False) if prev['incomplete'] else \
                counts(prev['since'], prev['until'])
            for c in categories:
                # A label missing from a full top-K is unknown there, not small.
                known = not (c.get('folded') or prev['incomplete']) and \
                    (c['label'] in before or not prev_full)
                n, nf = before.get(c['label'], (0, 0))
                pt, pf = (_part(n, prev_scope), _part(nf, n)) if known else (None, None)
                c.update(prev_total=pt, prev_failure=pf, change=_change(c['n_total'], pt),
                         failure_rose=_failure_rose(c['n_total'], c['n_failure'], pt, pf))
            if not prev['incomplete']:
                scope = min(scope, prev_scope)      # either window narrow: the question is noted
        return payload, scope

    return _answer('breakdown', ('breakdown', kind, dimension, limit, search, compare,
                                 _filter_cache_key(f)), f, compute,
                   kind=kind, dimension=dimension, **({'compare': compare} if compare else {}))


def _crosstab_row(by_col, scope):
    """A cross-tab row's cells and total as shown: a cell is withheld below the minimum or when
    the rest of its row is, and the total only when it cannot be subtracted back into a small
    count, so with no cell withheld or the withheld cells summing to the minimum or more. Zeros
    count as withheld, so a total equal to its shown cells cannot say the rest were none."""
    total = sum(by_col.values())
    shown = {col: _part(n, total) for col, n in by_col.items()}
    withheld = [n for col, n in by_col.items() if shown[col] is None]
    return shown, (_part(total, scope) if not withheld or sum(withheld) >= _ATLAS_MIN_CELL
                   else None)


# The row and column dimensions each stream's cross-tab accepts (whitelisted so a malformed
# ?row=/?col= never reaches the SQL CASE). The column dimension is fixed and low-cardinality, so
# the cells stay bounded (C8); the rows are capped at _ATLAS_MAX_CATEGORIES.
_ATLAS_CROSSTAB_ROWS = {
    'verification': ('agency', 'context', 'jurisdiction', 'algorithm'),
    'lifecycle':    ('agency', 'event_type'),
}
_ATLAS_CROSSTAB_COLS = {
    'verification': ('outcome', 'disclosure'),
    'lifecycle':    ('event_type',),
}


@app.route('/api/atlas/crosstab')
@security.login_required
@replica_reads
def api_atlas_crosstab():
    """A row dimension by a column dimension: the top-K rows by volume (capped at
    _ATLAS_MAX_CATEGORIES), every column value for each, as `{rows: [{label, total}], cols,
    cells: [{row, col, n}]}`. A cell is withheld below the minimum or when the rest of its row
    is; a row's total is withheld when the cells withheld beneath it sum to less than the
    minimum, so the row cannot be subtracted back into them. With compare=previous each listed
    row and its cells also carry the window before's, withheld by the same rules against that
    window's scope, and the change where both are shown (lab/strategy/009 A4); the folded row
    is not compared."""
    try:
        kind = _kind(request.args)
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
        compare = _parse_compare(request.args, f)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    def counts(since, until):
        """{(row, col): n}, {row: total}, the scope, and whether the top-K rows were full."""
        rows = query("""
            SELECT row_label, col_label, n_total, scope_total
              FROM atlas_crosstab(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (row_dim, col_dim, since, f['daily'], limit, kind, f['outcomes'],
              f['disclosure'], f['contexts'], f['agencies'], until))
        found, totals = {}, {}
        for r in rows:
            found[(r['row_label'], r['col_label'])] = int(r['n_total'])
            totals[r['row_label']] = totals.get(r['row_label'], 0) + int(r['n_total'])
        return found, totals, int(rows[0]['scope_total']) if rows else 0, len(totals) == limit

    def compute():
        found, row_totals, scope, full = counts(f['since'], None)
        cols = list(_ATLAS_FIXED_VALUES[col_dim])
        # Rows with fewer than the minimum fold into one, as an open list's categories do.
        labels, _ = _fold_small(row_totals)
        folded = {col: sum(found.get((lbl, col), 0) for lbl in row_totals if lbl not in labels)
                  for col in cols}
        table = [(lbl, {col: found.get((lbl, col), 0) for col in cols}) for lbl in labels]
        table.append((_ATLAS_FOLDED, folded))
        prev = _previous_window(f, kind) if compare else None
        before, prev_totals, prev_scope, prev_full = ({}, {}, 0, False) \
            if not prev or prev['incomplete'] else counts(prev['since'], prev['until'])
        out_rows, cells = [], []
        for label, by_col in table:
            shown, total_shown = _crosstab_row(by_col, scope)
            row = {'label': label, 'total': total_shown, 'folded': label == _ATLAS_FOLDED}
            prev_shown, prev_total = {}, None
            # A label missing from a full top-K is unknown in the window before, not small.
            if prev and not (row['folded'] or prev['incomplete']) and \
                    (label in prev_totals or not prev_full):
                prev_shown, prev_total = _crosstab_row(
                    {col: before.get((label, col), 0) for col in cols}, prev_scope)
            for col in cols:
                cell = {'row': label, 'col': col, 'n': shown[col]}
                if prev:
                    cell.update(prev=prev_shown.get(col), change=_change(shown[col],
                                                                         prev_shown.get(col)))
                cells.append(cell)
            if prev:
                row.update(prev_total=prev_total, change=_change(total_shown, prev_total))
            out_rows.append(row)
        payload = dict(kind=kind, row=row_dim, col=col_dim, limit=limit,
                       truncated=full, rows=out_rows, cols=cols,
                       cells=cells, **_window_fields(f))
        if prev:
            payload['previous'] = _previous_fields(prev)
            if not prev['incomplete']:
                scope = min(scope, prev_scope)      # either window narrow: the question is noted
        return payload, scope

    return _answer('crosstab', ('crosstab', kind, row_dim, col_dim, limit, compare,
                                _filter_cache_key(f)), f, compute,
                   kind=kind, row=row_dim, col=col_dim,
                   **({'compare': compare} if compare else {}))


# ============================================================================
# INTEGRITY (lab/strategy/009 A2)
# ============================================================================

@app.route('/api/atlas/integrity')
@security.login_required
def api_atlas_integrity():
    """The system's integrity beside its activity: the latest state epoch, the latest anchor
    batch, and the Athena board's verdict on the database this application is connected to.

    Header rows only, read by their keys: an epoch's leaves name credentials, and are not read;
    nor is the operator who closed the epoch. A count in them is withheld below the minimum, as
    every Atlas count is. The board reads the catalogue, so it is not routed to a replica: it
    answers for this database, as the Athena page does."""
    payload = _atlas_cache_get(('integrity',))
    if payload is None:
        import athena_board   # the board's catalogue reads; it imports nothing from app.py
        epoch = query("SELECT epoch_id, valid_from, valid_until, closed_at, committed_count "
                      "FROM TokenStateEpoch ORDER BY epoch_id DESC LIMIT 1", fetch='one')
        batch = query("SELECT batch_id, created_at, batch_size, committed_to_chain, "
                      "external_chain, external_chain_tx "
                      "FROM AnchorBatch ORDER BY batch_id DESC LIMIT 1", fetch='one')
        board = athena_board.read_board(query)
        states = [rule['state'] for rule in board['rules']]
        payload = {
            'epoch': epoch and {
                'id': epoch['epoch_id'], 'closed_at': _ts(epoch['closed_at']),
                'valid_from': _ts(epoch['valid_from']), 'valid_until': _ts(epoch['valid_until']),
                # Past it, a proof against the latest epoch fails: no current state to prove in.
                'expired': epoch['valid_until'] <= _db_now(),
                'committed': _count(epoch['committed_count'])},
            'anchor': batch and {
                'id': batch['batch_id'], 'created_at': _ts(batch['created_at']),
                'size': _count(batch['batch_size']),
                'chain': batch['external_chain'] if batch['committed_to_chain'] else None,
                'tx': batch['external_chain_tx'] if batch['committed_to_chain'] else None},
            'board': {
                'rules': len(states), 'in_force': states.count('in_force'),
                'not_in_force': states.count('not_in_force'),
                'repository': states.count('repository'),
                'verified_at': _ts(board['verified_at'])},
            'min_cell': _ATLAS_MIN_CELL,
        }
        _atlas_cache_set(('integrity',), payload)
    return jsonify(payload)


@app.route('/api/atlas/facet/agencies')
@security.login_required
@replica_reads
def api_atlas_facet_agencies():
    """The authority facet for the global filter: every authority matching an optional `?q=`, in
    name order, with `(agency_id, name, n_total)` honouring the other filters but not the
    authority selection, capped. Every match is listed, active or not, so the list does not say
    which small authorities had activity; each count is withheld below the minimum."""
    try:
        kind = _kind(request.args)
        limit = min(int(request.args.get('limit', '20')), _ATLAS_MAX_CATEGORIES)
        if limit < 0:
            raise ValueError("limit must not be negative")   # it reached SQL's LIMIT as a 500
        search = (request.args.get('q') or '').strip()[:60] or None
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    def compute():
        rows = query("""
            SELECT agency_id, name, n_total, scope_total
              FROM atlas_agency_facet(%s, %s, %s, %s, %s, %s, %s, %s)
        """, (f['since'], f['daily'], limit, kind, search, f['outcomes'], f['disclosure'],
              f['contexts']))
        scope = int(rows[0]['scope_total']) if rows else 0
        payload = dict(kind=kind, count=len(rows), results=[
            {'agency_id': r['agency_id'], 'name': r['name'], 'n_total': _part(r['n_total'], scope)}
            for r in rows], **_window_fields(f))
        return payload, scope

    return _answer('facet', ('facet_agencies', kind, limit, search, _filter_cache_key(f)), f,
                   compute, kind=kind)


@app.route('/api/atlas/cache-stats')
@security.login_required
def api_atlas_cache_stats():
    """Cache observability: hit/miss/expired/evicted counters and current size."""
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
