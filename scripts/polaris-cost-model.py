#!/usr/bin/env python3
"""polaris-cost-model.py - infrastructure cost per million persons per year (P2.10).

A cost figure for a national identity system is easy to write down and hard to trust, so this
is a MODEL you re-run rather than a number you are asked to believe. Every input is labelled
with where it came from, and there are only four kinds:

  MEASURED   taken from an actual run on real code: the benchmark in
             docs/reference/BENCHMARK.md, or a storage measurement in this file's header.
  COMPUTED   arithmetic on a published constant, such as an ML-DSA-65 signature's size.
  ASSUMED    a deployment's own behaviour, which the repository cannot know: how often a
             person is verified in a year, how long events are retained.
  PRICED     a cloud list price on a stated date, in a stated region, which will be wrong
             for you.

The output separates them, because the honest error bars are entirely on the last two. The
measured throughput is a fact about this code; the annual bill is a fact about your
assumptions, and this script exists so you can change them and see the answer move.

    python3 scripts/polaris-cost-model.py
    python3 scripts/polaris-cost-model.py --persons 10000000 --verifications-per-person 12
    python3 scripts/polaris-cost-model.py --json
"""
import argparse
import json
import sys

# --- MEASURED: docs/reference/BENCHMARK.md, single node, real ML-DSA-65 ------------------
VERIFY_PER_CORE = 7848          # single-witness verify-at-use, per core per second
ISSUE_PER_SECOND = 372          # issuance is signing-bound under real ML-DSA-65
EVENT_INGEST_PER_SECOND = 25970  # audit writes; not a signature check
# MEASURED here (v9.359): 200,010 rows into the partitioned event table on PostgreSQL 16,
# pg_total_relation_size over every partition including indexes, divided by rows.
EVENT_BYTES = 228.6

# --- COMPUTED: FIPS 204 sizes, plus the row overhead they sit in ------------------------
MLDSA65_SIG_BYTES = 3309
MLDSA65_PK_BYTES = 1952
# The signature is stored as bytes and the public key as hex, which doubles it.
CREDENTIAL_BYTES = MLDSA65_SIG_BYTES + (MLDSA65_PK_BYTES * 2) + 512  # + row and index overhead

GIB = 1024 ** 3


def model(persons, verifications_per_person, retention_years, peak_factor,
          price_vcpu_hour, price_gib_month, price_gib_egress, replicas, regions):
    """Return the cost lines. Nothing here is a secret formula; it is arithmetic you can check."""
    verifications = int(persons * verifications_per_person)
    per_second = verifications / (365 * 24 * 3600)
    peak_per_second = per_second * peak_factor

    # Compute: cores to serve PEAK verification, not average. A system sized for the mean is
    # a system that fails at 09:00. Cores are whole; you cannot rent 0.4 of one.
    verify_cores = max(1, -(-int(peak_per_second) // VERIFY_PER_CORE))
    # A floor, because a deployment needs application and database processes whatever its
    # verification rate: the cheapest useful shape is not one core.
    base_cores = 8
    cores = (base_cores + verify_cores) * replicas * regions

    # Storage: credentials once, events accumulating for the retention window.
    credential_gib = (persons * CREDENTIAL_BYTES) / GIB
    event_gib = (verifications * retention_years * EVENT_BYTES) / GIB
    # Replicas and regions hold their own copy; backups are counted as one further copy.
    stored_gib = (credential_gib + event_gib) * (replicas * regions + 1)

    # Egress: a verification answer is small, but a published status artifact is fetched by
    # everyone. Sized as one revocation-feed fetch per verification, which is pessimistic for
    # a deployment that caches (P2.6) and is the point of caching.
    egress_gib = (verifications * 4096) / GIB

    compute = cores * 24 * 365 * price_vcpu_hour
    storage = stored_gib * 12 * price_gib_month
    egress = egress_gib * price_gib_egress
    total = compute + storage + egress
    return {
        "inputs": {
            "persons": persons, "verifications_per_person_year": verifications_per_person,
            "retention_years": retention_years, "peak_factor": peak_factor,
            "replicas": replicas, "regions": regions,
            "price_vcpu_hour": price_vcpu_hour, "price_gib_month": price_gib_month,
            "price_gib_egress": price_gib_egress,
        },
        "derived": {
            "verifications_per_year": verifications,
            "mean_verifications_per_second": round(per_second, 1),
            "peak_verifications_per_second": round(peak_per_second, 1),
            "verify_cores_at_peak": verify_cores,
            "total_vcpu": cores,
            "credential_gib": round(credential_gib, 1),
            "event_gib": round(event_gib, 1),
            "stored_gib_all_copies": round(stored_gib, 1),
            "egress_gib": round(egress_gib, 1),
        },
        "annual_usd": {
            "compute": round(compute), "storage": round(storage), "egress": round(egress),
            "total": round(total),
            "per_million_persons": round(total / (persons / 1_000_000)),
        },
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--persons", type=int, default=1_000_000, help="population (default 1M)")
    ap.add_argument("--verifications-per-person", type=float, default=12.0,
                    help="ASSUMED verifications per person per year (default 12: once a month)")
    ap.add_argument("--retention-years", type=float, default=1.0,
                    help="ASSUMED verification-event retention (default 1; the schema's floor is 365 days)")
    ap.add_argument("--peak-factor", type=float, default=10.0,
                    help="ASSUMED peak-to-mean ratio (default 10, the P2 planning target)")
    ap.add_argument("--replicas", type=int, default=2, help="database copies per region (default 2: HA)")
    ap.add_argument("--regions", type=int, default=2, help="regions (default 2: a standby region, P2.8)")
    ap.add_argument("--price-vcpu-hour", type=float, default=0.04,
                    help="PRICED vCPU-hour in USD (default 0.04)")
    ap.add_argument("--price-gib-month", type=float, default=0.10,
                    help="PRICED block storage per GiB-month in USD (default 0.10)")
    ap.add_argument("--price-gib-egress", type=float, default=0.09,
                    help="PRICED egress per GiB in USD (default 0.09)")
    ap.add_argument("--json", action="store_true", help="machine-readable")
    args = ap.parse_args(argv)

    r = model(args.persons, args.verifications_per_person, args.retention_years,
              args.peak_factor, args.price_vcpu_hour, args.price_gib_month,
              args.price_gib_egress, args.replicas, args.regions)
    if args.json:
        print(json.dumps(r, indent=2))
        return 0

    d, c = r["derived"], r["annual_usd"]
    print("Polaris infrastructure cost model")
    print("=" * 64)
    print("population %s, %s verifications/person/year, %s-year retention"
          % ("{:,}".format(args.persons), args.verifications_per_person, args.retention_years))
    print("%d database copies per region across %d regions, peak %sx mean"
          % (args.replicas, args.regions, args.peak_factor))
    print()
    print("DERIVED")
    print("  verifications/year          %18s" % "{:,}".format(d["verifications_per_year"]))
    print("  mean / peak per second      %9s / %6s" % (d["mean_verifications_per_second"],
                                                       d["peak_verifications_per_second"]))
    print("  cores to serve PEAK verify  %18d   (MEASURED %s/s per core)"
          % (d["verify_cores_at_peak"], "{:,}".format(VERIFY_PER_CORE)))
    print("  total vCPU (incl. base)     %18d" % d["total_vcpu"])
    print("  credentials                 %15s GiB   (COMPUTED from FIPS 204 sizes)"
          % "{:,.1f}".format(d["credential_gib"]))
    print("  events for the window       %15s GiB   (MEASURED %s bytes/row)"
          % ("{:,.1f}".format(d["event_gib"]), EVENT_BYTES))
    print("  stored, all copies + backup %15s GiB" % "{:,.1f}".format(d["stored_gib_all_copies"]))
    print()
    print("ANNUAL, USD (every price is a LIST PRICE and will be wrong for you)")
    print("  compute                     %18s" % "${:,}".format(c["compute"]))
    print("  storage                     %18s" % "${:,}".format(c["storage"]))
    print("  egress                      %18s" % "${:,}".format(c["egress"]))
    print("  " + "-" * 46)
    print("  total                       %18s" % "${:,}".format(c["total"]))
    print("  per 1M persons per year     %18s" % "${:,}".format(c["per_million_persons"]))
    print()
    print("NOT INCLUDED, and each can exceed the whole figure above: staff, on-call, the")
    print("physical token and its personalisation, enrolment stations, support, legal and")
    print("compliance, external audit, and the hardware security module a real deployment")
    print("needs and this repository has never used. This is an INFRASTRUCTURE model.")
    print("The measured throughput is single-node; the multi-node scale is projected, which")
    print("docs/reference/BENCHMARK.md and roadmap P2.9 both say in their own words.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
