"""The benchmark harness: drive a synthetic nation at a chosen scale through the
real system and measure it, so the numbers that certify Polaris at scale are
produced by running it, not asserted.

It runs the S1 substrate build and the S2 event stream as timed phases, then
measures three things a load certification needs:
  - latency: the p50/p95/p99 of a single verification write,
  - the Atlas at scale: how long each bounded aggregate takes over the loaded
    data (it must stay fast, since every view is one of these),
  - the invariants under load: C3, C6, and the C1 append-only boundary must
    still hold after the load.

Everything is a report object; the CLI and the committed report render it. Point
it at an expendable database.
"""

from __future__ import annotations

import datetime
import os
import platform
import re
import socket
import time
from dataclasses import dataclass, field

from . import events as _events
from . import load as _load
from . import nation as _nation
from polaris_web import pqc_signing as _pqc


@dataclass
class Percentiles:
    p50: float
    p95: float
    p99: float
    n: int

    @staticmethod
    def of(samples_ms: list[float]) -> "Percentiles":
        if not samples_ms:
            return Percentiles(0.0, 0.0, 0.0, 0)
        s = sorted(samples_ms)

        def pct(p: float) -> float:
            i = min(len(s) - 1, int(round(p * (len(s) - 1))))
            return round(s[i], 3)
        return Percentiles(pct(0.50), pct(0.95), pct(0.99), len(s))


@dataclass
class BenchmarkReport:
    scale_divisor: int
    seed: int
    host: str
    python: str
    timestamp: str
    enrollment: dict = field(default_factory=dict)
    verification: dict = field(default_factory=dict)
    crypto_verification: dict = field(default_factory=dict)
    write_latency_ms: Percentiles = field(default_factory=lambda: Percentiles(0, 0, 0, 0))
    atlas_query_ms: dict = field(default_factory=dict)
    atlas_growth: dict = field(default_factory=dict)
    partition_pruning: dict = field(default_factory=dict)
    invariants: dict = field(default_factory=dict)
    scale_counts: dict = field(default_factory=dict)

    @property
    def all_invariants_hold(self) -> bool:
        return all(self.invariants.values()) if self.invariants else False

    def to_dict(self) -> dict:
        return {
            "scale_divisor": self.scale_divisor, "seed": self.seed, "host": self.host,
            "python": self.python, "timestamp": self.timestamp,
            "enrollment": self.enrollment, "verification": self.verification,
            "crypto_verification": self.crypto_verification,
            "write_latency_ms": vars(self.write_latency_ms),
            "atlas_query_ms": self.atlas_query_ms,
            "atlas_growth": self.atlas_growth,
            "partition_pruning": self.partition_pruning, "invariants": self.invariants,
            "scale_counts": self.scale_counts, "all_invariants_hold": self.all_invariants_hold,
        }


# The bounded Atlas aggregates, timed over the loaded data. `%s` is the window
# start; each is executed fully with SELECT count(*).
def _atlas_probes(since):
    return [
        ("atlas_volume_series", "SELECT count(*) FROM atlas_volume_series(%s, 24, 'verification')", (since,)),
        ("atlas_breakdown", "SELECT count(*) FROM atlas_breakdown('agency', %s, 50, 'verification')", (since,)),
        ("atlas_crosstab", "SELECT count(*) FROM atlas_crosstab('agency', 'outcome', %s, 50, 'verification')", (since,)),
        ("atlas_geo_jurisdictions", "SELECT count(*) FROM atlas_geo_jurisdictions(%s, 500, 'verification')", (since,)),
        ("atlas_hexbin", "SELECT count(*) FROM atlas_hexbin(-90, -180, 90, 180, 5.0, 5000, %s, 'verification')", (since,)),
        ("atlas_records", "SELECT count(*) FROM atlas_records(%s, NULL, NULL, 60, 'verification')", (since,)),
    ]


def _time_ms(fn) -> float:
    t = time.perf_counter()
    fn()
    return (time.perf_counter() - t) * 1000.0


def time_atlas_queries(conn, since) -> dict:
    out: dict = {}
    with conn.cursor() as cur:
        for name, sql, params in _atlas_probes(since):
            out[name] = round(_time_ms(lambda: cur.execute(sql, params)), 2)
    return out


#: The stream is measured after 1/GROWTH_FRACTION of it and again after all of it.
GROWTH_FRACTION = 10

#: How much faster than the data an aggregate may grow before it is a lead. A bounded
#: aggregate should track the row count or beat it; 1.5x of linear is slack for a small
#: first sample and a warm cache, not permission to be quadratic.
GROWTH_TOLERANCE = 1.5


def _event_rows(conn) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM VerificationEvent")
        return int(cur.fetchone()["n"])


def measure_growth(small_ms: dict, large_ms: dict, rows_small: int, rows_large: int) -> dict:
    """Per aggregate: how its time grew against how the data grew.

    An aggregate that costs 10x when the table holds 10x the rows is behaving. One that
    costs 40x is the lead this instrument exists to find, and a single timing at one
    scale cannot tell the two apart -- which is why the benchmark measured a point and
    called it a curve until v9.402.
    """
    rows_factor = (rows_large / rows_small) if rows_small else 0.0
    out = {"rows_small": rows_small, "rows_large": rows_large,
           "rows_factor": round(rows_factor, 2), "tolerance": GROWTH_TOLERANCE,
           "aggregates": {}, "superlinear": []}
    for name, large in sorted(large_ms.items()):
        small = small_ms.get(name)
        if not small or not rows_factor:
            continue
        factor = large / small
        # Sub-millisecond timings are dominated by noise, not by the data.
        meaningful = large >= 5.0
        entry = {"small_ms": small, "large_ms": large, "factor": round(factor, 2),
                 "vs_linear": round(factor / rows_factor, 2), "graded": meaningful}
        out["aggregates"][name] = entry
        if meaningful and factor > rows_factor * GROWTH_TOLERANCE:
            out["superlinear"].append(name)
    return out


def measure_partition_pruning(conn) -> dict:
    """P2.14 S5 (v9.260): prove the Atlas roll-ups PRUNE the monthly-partitioned
    event table under the GENERIC plan a parameterized call actually gets (the
    app's path). A far-future window matches no month partition, so a pruning
    query drops every one of them; an all-time (NULL) query must keep them all.
    The difference is the whole fix (event_timestamp >= COALESCE(p_since,
    '-infinity')): before it, both scanned every partition."""
    def _month_parts_in(plan: str) -> int:
        return len(set(re.findall(r"verificationevent_\d{4}_\d{2}", plan)))
    with conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) AS n FROM pg_inherits "
            " WHERE inhparent='verificationevent'::regclass "
            "   AND inhrelid::regclass::text ~ 'verificationevent_[0-9]'")
        month_partitions = cur.fetchone()["n"]
        cur.execute("SET plan_cache_mode = force_generic_plan")
        cur.execute("DEALLOCATE ALL")
        cur.execute("PREPARE _pp(timestamp) AS "
                    "SELECT * FROM atlas_breakdown('agency', $1, 50)")

        def scanned(arg_sql: str) -> int:
            cur.execute("EXPLAIN (COSTS OFF) EXECUTE _pp(" + arg_sql + ")")
            plan = "\n".join(next(iter(r.values())) for r in cur.fetchall())
            return _month_parts_in(plan)

        recent = scanned("(CURRENT_TIMESTAMP + INTERVAL '100 years')::timestamp")
        alltime = scanned("NULL")
        cur.execute("DEALLOCATE _pp")
        cur.execute("SET plan_cache_mode = auto")
    return {
        "month_partitions": month_partitions,
        "recent_window_scanned": recent,
        "all_time_scanned": alltime,
        # With ≥1 month partition, a recent window must scan strictly fewer than
        # all-time (it prunes them); with none, pruning is trivially satisfied.
        "prunes": bool(month_partitions == 0 or recent < alltime),
    }


_LAT_SQL = ("INSERT INTO VerificationEvent "
            "(token_id, requesting_agency_id, context_id, outcome, disclosure_level, "
            " requestor_location, latitude, longitude, requesting_purpose_text) "
            "VALUES (%s, %s, %s, 'SUCCESS', 'SELECTIVE', %s, %s, %s, 'latency probe')")


def measure_write_latency(conn, pool, agency_ids, samples: int) -> Percentiles:
    """Time `samples` individual verification writes (the operation the p95
    target names), rolled back so they do not skew the throughput counts."""
    if samples <= 0 or not pool or not agency_ids:
        return Percentiles(0, 0, 0, 0)
    import random
    rng = random.Random(20240906)
    times: list[float] = []
    with conn.cursor() as cur:
        cur.execute("SAVEPOINT lat")
        for _ in range(samples):
            ref = pool[rng.randrange(len(pool))]
            lat0, lon0 = _events.reference.STATE_CENTROIDS.get(ref.jurisdiction, (39.0, -98.0))
            args = (ref.token_id, agency_ids[rng.randrange(len(agency_ids))],
                    1, _events.reference.STATE_NAMES.get(ref.jurisdiction, "United States"),
                    round(lat0, 5), round(lon0, 5))
            times.append(_time_ms(lambda: cur.execute(_LAT_SQL, args)))
        cur.execute("ROLLBACK TO SAVEPOINT lat")
    return Percentiles.of(times)


def measure_crypto_verification(conn, samples: int) -> dict:
    """Actually verify the cryptographic signatures of a sample of issued tokens
    (pqc_signing.verify_stored_signature), timing each. This is the REAL
    cryptographic-verification rate, and it is a different number from the
    verification-EVENT ingestion rate: ingestion writes an audit row, this runs
    the ML-DSA-65 (or placeholder) verification against the stored public key.
    Also returns whether every sampled token verified, which proves mass-issued
    tokens are cryptographically valid, not placeholders a check merely believes."""
    if samples <= 0:
        return {"samples": 0, "verified": 0, "all_verified": True, "per_sec": 0.0,
                "algorithm": _pqc.PLACEHOLDER_LABEL if not _pqc.is_enabled() else "ML-DSA-65",
                "two_witness_per_sec": 0.0, "single_witness_per_sec": 0.0,
                "cores": os.cpu_count() or 1, "projected_fleet_single_witness_per_sec": 0.0,
                "single_witness_latency_ms": vars(Percentiles(0, 0, 0, 0)),
                "latency_ms": vars(Percentiles(0, 0, 0, 0))}
    with conn.cursor() as cur:
        # Scope to the MASS-ISSUED tokens the simulation created (the subject of
        # the certification: "are mass-issued identities cryptographically
        # valid?"). Pre-existing seed/demo tokens carry legacy placeholder
        # signatures and are shown as unverified elsewhere; they are not what
        # this run issued, so they are not what it certifies.
        cur.execute("""
            SELECT it.token_value, ts.signature_bytes, ts.signing_public_key_hex
            FROM IdentityToken it JOIN TokenSignature ts ON ts.token_id = it.token_id
            WHERE it.status = 'ACTIVE' AND ts.deprecation_date IS NULL
              AND it.token_value LIKE 'SIMTOK-%%'
            ORDER BY random() LIMIT %s""", (samples,))
        rows = cur.fetchall()
    tvs = [r["token_value"] for r in rows]
    sigs = [bytes(r["signature_bytes"]) for r in rows]
    pks = [r["signing_public_key_hex"] for r in rows]
    real = any(pks)

    def serial(witnesses: str):
        times: list[float] = []
        verified = 0
        for tv, sig, pk in zip(tvs, sigs, pks):
            t = time.perf_counter()
            ok = _pqc.verify_stored_signature(tv, sig, pk, witnesses=witnesses)
            times.append((time.perf_counter() - t) * 1000.0)
            if ok:
                verified += 1
        total_s = sum(times) / 1000.0
        return verified, (len(times) / total_s if total_s > 0 else 0.0), Percentiles.of(times)

    # Two-witness (issuance-grade) and single-witness (verify-at-use) per-core
    # rates. Single-witness is the throughput path a national deployment uses;
    # both must verify every sampled token. A verify-only fleet needs just the
    # public key, so the service capacity is per-core x workers x replicas.
    v_both, r_both, lat_both = serial("both")
    v_single, r_single, lat_single = serial("single")
    workers = os.cpu_count() or 1
    return {
        "samples": len(rows),
        "verified": v_both,
        "all_verified": v_both == len(rows) and v_single == len(rows),
        "algorithm": "ML-DSA-65" if real else _pqc.PLACEHOLDER_LABEL,
        "two_witness_per_sec": round(r_both, 1),
        "single_witness_per_sec": round(r_single, 1),
        "single_witness_latency_ms": vars(lat_single),
        "cores": workers,
        "projected_fleet_single_witness_per_sec": round(r_single * workers, 1),
        # backward-compat: per_sec / latency_ms are the strict two-witness serial
        "per_sec": round(r_both, 1),
        "latency_ms": vars(lat_both),
    }


def check_invariants(conn, purposes) -> dict:
    """C3, C6 and the C1 append-only boundary must hold after the load."""
    out: dict = {}
    with conn.cursor() as cur:
        # C3: one active token per person.
        cur.execute("""SELECT COALESCE(max(c), 0) m FROM (
            SELECT individual_id, count(*) c FROM IdentityToken WHERE status='ACTIVE'
            GROUP BY individual_id) t""")
        out["C3_one_active_token_per_person"] = (cur.fetchone()["m"] <= 1)

        # C6 / C2: no zero-knowledge verification carries a token (constraint), and
        # none of the simulation's ZK events carry a location.
        cur.execute("SELECT count(*) c FROM VerificationEvent "
                    "WHERE disclosure_level='ZERO_KNOWLEDGE' AND token_id IS NOT NULL")
        no_token = cur.fetchone()["c"] == 0
        cur.execute("SELECT count(*) c FROM VerificationEvent "
                    "WHERE disclosure_level='ZERO_KNOWLEDGE' AND latitude IS NOT NULL "
                    "AND requesting_purpose_text = ANY(%s)", (purposes,))
        no_location = cur.fetchone()["c"] == 0
        out["C6_zero_knowledge_never_located"] = (no_token and no_location)

        # C1: the verification audit table is append-only (an UPDATE is refused).
        cur.execute("SAVEPOINT c1")
        try:
            cur.execute("UPDATE VerificationEvent SET outcome='FAILURE' "
                        "WHERE event_id = (SELECT event_id FROM VerificationEvent LIMIT 1)")
            out["C1_verification_events_append_only"] = False   # should not reach here
            cur.execute("ROLLBACK TO SAVEPOINT c1")
        except Exception:
            out["C1_verification_events_append_only"] = True    # the trigger blocked it
            cur.execute("ROLLBACK TO SAVEPOINT c1")
    return out


def _scale_counts(conn) -> dict:
    with conn.cursor() as cur:
        cur.execute("""
            SELECT (SELECT count(*) FROM VerificationEvent) AS verification_events,
                   (SELECT count(*) FROM IdentityToken WHERE status='ACTIVE') AS active_tokens,
                   (SELECT count(*) FROM Agency) AS agencies,
                   (SELECT count(DISTINCT jurisdiction) FROM Individual) AS jurisdictions""")
        r = cur.fetchone()
    return {"verification_events": r["verification_events"], "active_tokens": r["active_tokens"],
            "agencies": r["agencies"], "jurisdictions": r["jurisdictions"]}


def run_benchmark(conn, *, scale_divisor: int, verifications: int, lifecycle: int = 0,
                  seed: int = 42, window_hours: float = 24.0, latency_samples: int = 500,
                  verify_samples: int = 1000, commit: bool = True,
                  now: datetime.datetime | None = None) -> BenchmarkReport:
    """Build, stream, then measure. With commit=False the whole run stays in one
    transaction (a test rolls it back); the committed report is produced with
    commit=True for honest, durable timings."""
    if now is None:
        now = datetime.datetime.now()
    report = BenchmarkReport(
        scale_divisor=scale_divisor, seed=seed, host=socket.gethostname(),
        python=platform.python_version(), timestamp=now.replace(microsecond=0).isoformat())

    # Phase 1: enrollment (S1).
    plan = _nation.plan_nation(scale_divisor, seed)
    t = time.perf_counter()
    ls = _load.build_nation(conn, plan, commit=commit)
    esec = time.perf_counter() - t
    report.enrollment = {"people": ls.people, "seconds": round(esec, 3),
                         "per_sec": round(ls.people / esec, 1) if esec else 0.0}

    # Phase 2: the life-event stream (S2), in two parts.
    #
    # THE SECOND PART IS WHY THERE ARE TWO. A single timing says an aggregate was fast
    # once; it cannot say whether it STAYS proportional as history grows, and that is
    # the question a capacity claim rests on. So the Atlas is timed after a tenth of the
    # stream and again after all of it, on the same database and the same hardware
    # minutes apart, and the growth factor is compared with the row-count factor.
    # Measuring at two scales in two runs would compare across machine states; measuring
    # here compares two numbers taken under the same conditions.
    first = max(1, verifications // GROWTH_FRACTION)
    ss = _events.run_stream(conn, verifications=first, lifecycle=0,
                            window_hours=window_hours, seed=seed, commit=commit, now=now)
    since_small = now - datetime.timedelta(hours=window_hours * 2)
    rows_small = _event_rows(conn)
    atlas_small = time_atlas_queries(conn, since_small)

    rest = _events.run_stream(conn, verifications=verifications - first, lifecycle=lifecycle,
                              window_hours=window_hours, seed=seed + 1, commit=commit, now=now)
    by_disclosure = dict(ss.by_disclosure)
    for k, v in rest.by_disclosure.items():
        by_disclosure[k] = by_disclosure.get(k, 0) + v
    total_events = ss.verifications + rest.verifications
    total_seconds = ss.seconds + rest.seconds
    report.verification = {"events": total_events,
                           "revocations": ss.revocations + rest.revocations,
                           "seconds": round(total_seconds, 3),
                           "per_sec": round(total_events / total_seconds, 1) if total_seconds else 0.0,
                           "by_disclosure": by_disclosure}

    # Phase 3: single-write latency.
    pool, agencies, _ = _events.load_pools(conn, 2000)
    report.write_latency_ms = measure_write_latency(conn, pool, agencies, latency_samples)

    # Phase 4: real cryptographic signature verification (distinct from the
    # verification-EVENT ingestion measured in Phase 2).
    report.crypto_verification = measure_crypto_verification(conn, verify_samples)

    # Phase 5: the Atlas at scale, and how it GREW getting there.
    since = now - datetime.timedelta(hours=window_hours * 2)
    report.atlas_query_ms = time_atlas_queries(conn, since)
    report.atlas_growth = measure_growth(atlas_small, report.atlas_query_ms,
                                         rows_small, _event_rows(conn))

    # Phase 5b: the Atlas roll-ups prune the partitioned event table (P2.14 S5).
    report.partition_pruning = measure_partition_pruning(conn)

    # Phase 6: invariants under load, including that mass-issued signatures
    # actually verify (not placeholders the schema merely accepts).
    report.invariants = check_invariants(conn, list(_events._PURPOSES))
    report.invariants["signatures_cryptographically_verify"] = \
        report.crypto_verification.get("all_verified", False)
    report.invariants["atlas_windowed_query_prunes"] = \
        report.partition_pruning.get("prunes", False)
    report.scale_counts = _scale_counts(conn)
    return report
