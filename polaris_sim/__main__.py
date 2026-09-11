"""`python3 -m polaris_sim` - build a synthetic nation and (later ships) run its
life through the real Polaris system.

    python3 -m polaris_sim build --scale 100000 --seed 42

Reads the standard POLARIS_DB_* environment (host / name / user / password),
exactly like the operator CLI, so it points at whatever database is configured.
This is a benchmark and test harness: point it at an expendable database.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import nation, reference


def _db_config() -> dict:
    return {
        "host": os.environ.get("POLARIS_DB_HOST", "localhost"),
        "dbname": os.environ.get("POLARIS_DB_NAME", "polaris_test"),
        "user": os.environ.get("POLARIS_DB_USER", "polaris_app"),
        "password": os.environ.get("POLARIS_DB_PASSWORD", "polaris_dev_password"),
    }


def _connect():
    import psycopg2
    from psycopg2.extras import RealDictCursor
    cfg = _db_config()
    try:
        return psycopg2.connect(cursor_factory=RealDictCursor, **cfg)
    except psycopg2.OperationalError as e:
        sys.stderr.write(f"cannot connect to database {cfg['dbname']} at {cfg['host']}: {e}\n")
        raise SystemExit(2)


def cmd_build(args: argparse.Namespace) -> int:
    plan = nation.plan_nation(scale_divisor=args.scale, seed=args.seed)
    if not args.json:
        print(f"Synthetic United States (scale 1:{args.scale}, seed {args.seed})")
        print(f"  jurisdictions : {plan.jurisdictions}")
        print(f"  ID bureaus    : {plan.total_bureaus}")
        print(f"  people        : {plan.total_people:,}")
        print(f"  (full-scale reference population: {reference.US_TOTAL_POPULATION:,})")
    if args.plan_only:
        if args.json:
            print(json.dumps({"scale_divisor": args.scale, "seed": args.seed,
                              "jurisdictions": plan.jurisdictions,
                              "bureaus": plan.total_bureaus, "people": plan.total_people}))
        return 0

    from . import load
    conn = _connect()
    try:
        last = [0]

        def progress(juris: str, done: int, total: int) -> None:
            pct = int(100 * done / total) if total else 100
            if pct >= last[0] + 10:
                last[0] = pct
                if not args.json:
                    sys.stderr.write(f"  ... {pct:3d}%  ({done:,}/{total:,})\n")

        stats = load.build_nation(conn, plan, batch_size=args.batch_size, progress=progress)
    finally:
        conn.close()

    summary = {
        "scale_divisor": stats.scale_divisor, "seed": stats.seed,
        "agencies": stats.agencies, "people": stats.people,
        "tokens_issued": stats.tokens_issued,
        "seconds": round(stats.seconds, 3), "rows_per_sec": round(stats.rows_per_sec, 1),
    }
    if args.json:
        print(json.dumps(summary))
    else:
        print("\nLoaded through the real bulk-enrollment pipeline:")
        print(f"  agencies      : {stats.agencies:,}")
        print(f"  tokens issued : {stats.tokens_issued:,}")
        print(f"  wall time     : {stats.seconds:.2f}s")
        print(f"  throughput    : {stats.rows_per_sec:,.0f} enrollments/s")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from . import events
    conn = _connect()
    try:
        stats = events.run_stream(
            conn, verifications=args.events, lifecycle=args.lifecycle,
            window_hours=args.window, seed=args.seed, batch_size=args.batch_size)
    except RuntimeError as e:
        sys.stderr.write(f"{e}\n")
        return 1
    finally:
        conn.close()

    summary = {
        "verifications": stats.verifications, "revocations": stats.revocations,
        "window_hours": args.window, "seed": args.seed,
        "seconds": round(stats.seconds, 3), "rows_per_sec": round(stats.rows_per_sec, 1),
        "by_disclosure": stats.by_disclosure,
    }
    if args.json:
        print(json.dumps(summary))
    else:
        print(f"Life-event stream over the last {args.window:g}h (seed {args.seed}):")
        print(f"  verifications : {stats.verifications:,}")
        for level in ("ZERO_KNOWLEDGE", "SELECTIVE", "FULL"):
            print(f"      {level:<15}: {stats.by_disclosure.get(level, 0):,}")
        print(f"  revocations   : {stats.revocations:,} (through uc8_revoke_token)")
        print(f"  wall time     : {stats.seconds:.2f}s")
        print(f"  throughput    : {stats.rows_per_sec:,.0f} verifications/s")
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    from . import benchmark
    conn = _connect()
    try:
        rep = benchmark.run_benchmark(
            conn, scale_divisor=args.scale, verifications=args.events,
            lifecycle=args.lifecycle, seed=args.seed, latency_samples=args.latency_samples,
            verify_samples=args.verify_samples)
    finally:
        conn.close()

    if args.json:
        print(json.dumps(rep.to_dict()))
    else:
        e, v, lat, cv = rep.enrollment, rep.verification, rep.write_latency_ms, rep.crypto_verification
        print(f"Polaris benchmark  scale 1:{rep.scale_divisor}  seed {rep.seed}  {rep.host}  {rep.timestamp}")
        print(f"  enrollment (issue+sign) : {e['people']:,} people @ {e['per_sec']:,.0f}/s")
        print("  verification EVENTS ingested (audit-row writes, NOT signature checks):")
        print(f"      {v['events']:,} @ {v['per_sec']:,.0f}/s  (+{v['revocations']} revocations)")
        print(f"  CRYPTOGRAPHIC signature verification ({cv.get('algorithm','?')}), "
              f"{cv.get('verified',0):,}/{cv.get('samples',0):,} verified:")
        print(f"      two-witness (issuance-grade)  : {cv.get('two_witness_per_sec',0):>8,.0f}/s per core")
        print(f"      single-witness (verify-at-use): {cv.get('single_witness_per_sec',0):>8,.0f}/s per core")
        print(f"      projected fleet ({cv.get('cores',1)} cores)      : "
              f"{cv.get('projected_fleet_single_witness_per_sec',0):>8,.0f}/s single-witness")
        print(f"  event write latency : p50 {lat.p50} ms  p95 {lat.p95} ms  p99 {lat.p99} ms  (n={lat.n})")
        print(f"  Atlas at scale ({rep.scale_counts.get('verification_events', 0):,} events):")
        for name, ms in rep.atlas_query_ms.items():
            print(f"      {name:<26}: {ms:>8.1f} ms")
        pp = rep.partition_pruning
        if pp:
            print(f"  Atlas partition pruning (generic plan, {pp.get('month_partitions', 0)} monthly partitions):")
            print(f"      recent window scans {pp.get('recent_window_scanned', 0)} vs all-time "
                  f"{pp.get('all_time_scanned', 0)}  ->  {'PRUNES' if pp.get('prunes') else 'NO PRUNING'}")
        print("  invariants under load:")
        for name, ok in rep.invariants.items():
            print(f"      {name:<40}: {'HOLD' if ok else 'VIOLATED'}")
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(rep.to_dict(), fh, indent=2)
        if not args.json:
            print(f"  report written: {args.report}")
    # A benchmark that broke an invariant under load is a failure.
    # A superlinear aggregate is a finding, not a note. The instrument exists to turn
    # one into a hardening ship (P2.14 S5), and a benchmark that printed it green while
    # a bounded roll-up went quadratic would be measuring and not watching.
    superlinear = (rep.atlas_growth or {}).get("superlinear") or []
    if superlinear:
        g = rep.atlas_growth
        print("\nSUPERLINEAR: %s grew faster than the data it reads. Rows went %.1fx "
              "(%d -> %d); these grew:" % (", ".join(superlinear), g["rows_factor"],
                                           g["rows_small"], g["rows_large"]),
              file=sys.stderr)
        for name in superlinear:
            a = g["aggregates"][name]
            print("  %-28s %.1f -> %.1f ms  (%.2fx, %.2fx of linear)"
                  % (name, a["small_ms"], a["large_ms"], a["factor"], a["vs_linear"]),
                  file=sys.stderr)
        print("A bounded aggregate tracks the row count or beats it. This is the lead.",
              file=sys.stderr)
        return 1
    return 0 if rep.all_invariants_hold else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="polaris_sim",
                                description="Polaris national simulation and benchmark harness.")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")
    b = sub.add_parser("build", help="generate a synthetic nation and enroll it")
    b.add_argument("--scale", type=int, default=100000,
                   help="downscale divisor: synthetic people ~= US population / scale (default 100000)")
    b.add_argument("--seed", type=int, default=42, help="deterministic seed (default 42)")
    b.add_argument("--batch-size", type=int, default=5000,
                   help="rows per uc_bulk_issue batch (default 5000)")
    b.add_argument("--plan-only", action="store_true",
                   help="print the plan without touching the database")
    b.add_argument("--json", action="store_true", help="emit a JSON summary")

    r = sub.add_parser("run", help="drive a life-event stream through the enrolled nation")
    r.add_argument("--events", type=int, default=100000,
                   help="verifications to generate (default 100000)")
    r.add_argument("--lifecycle", type=int, default=0,
                   help="token revocations through uc8_revoke_token (default 0)")
    r.add_argument("--window", type=float, default=24.0,
                   help="spread events over the last N hours (default 24)")
    r.add_argument("--seed", type=int, default=42, help="deterministic seed (default 42)")
    r.add_argument("--batch-size", type=int, default=10000,
                   help="rows per COPY batch (default 10000)")
    r.add_argument("--json", action="store_true", help="emit a JSON summary")

    m = sub.add_parser("benchmark", help="build + stream + measure, and certify invariants under load")
    m.add_argument("--scale", type=int, default=1000,
                   help="downscale divisor for the substrate (default 1000)")
    m.add_argument("--events", type=int, default=500000,
                   help="verifications to stream (default 500000)")
    m.add_argument("--lifecycle", type=int, default=100,
                   help="token revocations through uc8_revoke_token (default 100)")
    m.add_argument("--seed", type=int, default=42, help="deterministic seed (default 42)")
    m.add_argument("--latency-samples", type=int, default=500,
                   help="single-write latency samples (default 500)")
    m.add_argument("--verify-samples", type=int, default=1000,
                   help="token signatures to cryptographically verify (default 1000)")
    m.add_argument("--report", metavar="PATH", help="write the JSON report to PATH")
    m.add_argument("--json", action="store_true", help="emit the JSON report to stdout")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "build":
        return cmd_build(args)
    if args.command == "run":
        return cmd_run(args)
    if args.command == "benchmark":
        return cmd_benchmark(args)
    build_parser().print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
