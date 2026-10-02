# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""population.py: figures about a population that cost the same at any size.

Decision record: lab/strategy/008-population-scale.md. A console page must not cost in proportion
to the population it describes. Every figure here is either exact at any size or bounded and says
it is an estimate, so a page can label it:

- counts(query): exact counts by authority from PopulationCount, kept by statement triggers on
  IdentityToken and TokenSignature (06_triggers.sql): credentials by status, and live signatures
  on active credentials by algorithm. A read sums the folded totals and the changes not yet
  folded, so it is exact, and it touches a few rows per authority whatever the population.
- capped(query, ...): an exact count that stops at its cap and says "or more" beyond it, for a
  rare condition (a credential past its expiry among billions) read through an index that orders
  by the condition, so stopping early is what bounds it.
- Recent(query, ...): the latest RECENT_ROWS rows of an event table through its time index:
  shares, counts and the arrival rate of that slice, exact for the slice and named as such.
- rows(query, table): the planner's row estimate, from the table's size now and the density its
  last ANALYZE saw: free, and current even when the statistics are not.

Every reader takes the application's query function first (app.query, or a test's stand-in), so
this module imports nothing from the application. A figure is an int (arithmetic, comparisons and
templates treat it as its value) carrying `exact` and `at_least`.
"""
#: How many of the latest events a window figure is read from.
RECENT_ROWS = 10_000

#: The deepest an offset page reads, in rows. The lists page by key; an old ?page=N link still
#: answers while its offset stays within this, and is refused beyond it, because OFFSET reads and
#: discards every row before the page.
MAX_OFFSET_ROWS = 10_000


class Figure(int):
    """A count that knows whether it is exact. `at_least` marks a capped count."""

    exact: bool
    at_least: bool

    def __new__(cls, value, exact=True, at_least=False):
        obj = super().__new__(cls, int(round(value)))
        obj.exact = bool(exact) and not at_least
        obj.at_least = bool(at_least)
        return obj

    def __repr__(self):
        kind = 'at least' if self.at_least else ('exact' if self.exact else 'about')
        return 'Figure(%s %d)' % (kind, int(self))


#: Rows per 8 kB block assumed for a table never analysed, only to size its sample: a block
#: sample's estimate is unbiased whatever density sized it.
DEFAULT_ROWS_PER_BLOCK = 100


def rows(query, table):
    """The planner's estimate of a table's rows, made the way the planner makes it: the
    table's size now (pg_relation_size over its leaf partitions, or the table itself) times
    the rows per block its last ANALYZE or VACUUM saw. Free, and current even when the
    statistics are stale; DEFAULT_ROWS_PER_BLOCK stands in for a table never analysed."""
    r = query("""
        WITH leaves AS (
            SELECT pt.relid FROM pg_partition_tree(%(t)s::regclass) pt WHERE pt.isleaf
            UNION
            SELECT c.oid FROM pg_class c WHERE c.oid = %(t)s::regclass AND c.relkind = 'r'
        )
        SELECT COALESCE(sum(pg_relation_size(c.oid)), 0)::bigint
                 / current_setting('block_size')::int AS blocks,
               COALESCE(sum(GREATEST(c.reltuples, 0)), 0)::float8 AS tuples,
               COALESCE(sum(GREATEST(c.relpages, 0)), 0)::bigint AS pages
          FROM leaves l JOIN pg_class c ON c.oid = l.relid
    """, {'t': table}, fetch='one', readonly=True) or {}
    blocks, tuples, pages = r.get('blocks') or 0, r.get('tuples') or 0.0, r.get('pages') or 0
    density = (tuples / pages) if pages > 0 and tuples > 0 else DEFAULT_ROWS_PER_BLOCK
    return int(blocks * density)


def counts(query):
    """{(facet, agency_id, item): Figure} exact, from PopulationCount and the changes not yet
    folded into it. Facets: 'credential_status' (item: a status) and 'live_signature' (item: an
    algorithm id, as text). Row-level security scopes both tables, so an operator bound to one
    authority reads that authority's counts. Read-only, and safe on a replica."""
    rows_ = query("""
        SELECT facet, agency_id, item, sum(n)::bigint AS n
          FROM (SELECT facet, agency_id, item, n FROM PopulationCount
                UNION ALL
                SELECT facet, agency_id, item, n FROM PopulationCountDelta) c
         GROUP BY facet, agency_id, item
    """, readonly=True)
    return {(r['facet'], r['agency_id'], r['item']): Figure(r['n']) for r in rows_ if r['n']}


def capped(query, sql, params=None, cap=10_000):
    """An exact count of the rows `sql` selects, stopping at `cap`. `sql` is a SELECT the
    caller wrote, served by an index so that stopping early is what bounds its cost."""
    n = query('SELECT count(*) AS n FROM (%s LIMIT %d) capped' % (sql, cap + 1),
                 params, fetch='one', readonly=True)['n']
    if n > cap:
        return Figure(cap, at_least=True)
    return Figure(n)


class Recent:
    """The latest RECENT_ROWS rows of an event table, newest first, through its time index.

    Everything it reports is exact for the slice it read, and says which slice: shares,
    per-key counts, and the rate at which the slice arrived (over the slice's own span, newest
    to oldest, so a quiet hour after the newest event does not dilute it). It never extrapolates
    to a window the slice does not cover: lab/strategy/008 measured that a rate times a window
    missed a 24-hour count by 57% when traffic had paused. `complete` is true when the slice
    holds every row the table has."""

    def __init__(self, query, table, columns, ts='event_timestamp', limit=None):
        limit = limit or RECENT_ROWS
        self.ts = ts
        self.rows = query('SELECT %s, %s FROM %s ORDER BY %s DESC LIMIT %d'
                          % (ts, ', '.join(columns), table, ts, limit), readonly=True)
        self.limit = limit
        self.complete = len(self.rows) < limit
        self.newest = self.rows[0][ts] if self.rows else None
        self.oldest = self.rows[-1][ts] if self.rows else None

    def __len__(self):
        return len(self.rows)

    def count(self, match=None):
        """Rows of the slice for which `match(row)` holds."""
        return sum(1 for r in self.rows if match is None or match(r))

    def mix(self, key):
        """{value: count} over the slice."""
        out = {}
        for r in self.rows:
            out[r[key]] = out.get(r[key], 0) + 1
        return out

    def per_second(self):
        """The rate the slice arrived at, over its own span; None with fewer than two rows or a
        span of no time."""
        if len(self.rows) < 2:
            return None
        span = (self.newest - self.oldest).total_seconds()
        return (len(self.rows) - 1) / span if span > 0 else None


def fmt_int(n):
    """8123456789 -> '8,123,456,789'."""
    return '{:,}'.format(int(n))


_SCALES = ((10 ** 18, 'Qi', 'quintillion'), (10 ** 15, 'Qa', 'quadrillion'),
           (10 ** 12, 'T', 'trillion'), (10 ** 9, 'B', 'billion'), (10 ** 6, 'M', 'million'))


def _scaled(n):
    """(mantissa text, short suffix, word) with three significant figures, or None below a
    million. A value that rounds up to 1000 of one scale is written in the next: 999,960,000
    is '1 billion', not '1000 million'."""
    n = int(n)
    if abs(n) < 1_000_000:
        return None
    for i, (scale, short, word) in enumerate(_SCALES):
        if abs(n) < scale:
            continue
        v = n / scale
        digits = 2 if abs(v) < 10 else (1 if abs(v) < 100 else 0)
        v = round(v, digits)
        if abs(v) >= 1000 and i > 0:
            scale, short, word = _SCALES[i - 1]
            v, digits = round(n / scale, 2), 2
        text = '%.*f' % (digits, v)
        if '.' in text:
            text = text.rstrip('0').rstrip('.')
        return text, short, word
    return None


def fmt_compact(n):
    """A count in at most about seven characters, for a tile: grouped digits below a
    million, then three significant figures and a short scale: '1.25 M', '350 M', '8.12 B'."""
    s = _scaled(n)
    return fmt_int(n) if s is None else '%s\u202f%s' % (s[0], s[1])


def fmt_words(n):
    """The same count as a reader hears it: '8.12 billion', or grouped digits below a million."""
    s = _scaled(n)
    return fmt_int(n) if s is None else '%s %s' % (s[0], s[2])


def _sig3(n):
    """Rounded to three significant figures: an estimate shown to the last digit claims a
    precision it does not have. 12,345 -> 12,300."""
    n = int(n)
    if n == 0:
        return 0
    digits = len(str(abs(n)))
    return int(round(n, -(digits - 3))) if digits > 3 else n


def fmt_estimate(n):
    """An estimate for a tile or a table cell: three significant figures, short scale."""
    return fmt_compact(_sig3(n))


def fmt_estimate_words(n):
    """The same estimate as a reader hears it."""
    return fmt_words(_sig3(n))


def fmt_figure(f, compact=False):
    """A figure as text: 'about ' before an estimate, ' or more' after a capped count."""
    if getattr(f, 'at_least', False):
        return (fmt_words(f) if compact else fmt_int(f)) + ' or more'
    if getattr(f, 'exact', True) is False:
        return 'about ' + fmt_estimate_words(f)
    return fmt_words(f) if compact else fmt_int(f)
