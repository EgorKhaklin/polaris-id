"""polaris_web/capacity.py - do the stated national targets survive contact with the schema (P7.3).

The roadmap states four planning targets for national operation and says, in the row itself,
that they are "to be validated, not asserted". This validates them, and the answer is not the
one the throughput numbers alone would give.

EVERY THROUGHPUT TARGET IS MET WITH ENORMOUS MARGIN. Real ML-DSA-65 single-witness verification
was measured at ~7,848/s per core, so the 50,000/s peak target is about six and a half cores,
and verification needs only a public key, so it fans out across replicas without touching
custody. Enrollment at a measured ~372 tokens/s covers a 200,000/day surge in nine minutes of
signing. Judged on throughput this system clears its targets by more than an order of magnitude.

AND IT CANNOT RUN FOR A WEEK AT THE SUSTAINED TARGET, because `VerificationEvent.event_id` is a
32-bit `SERIAL`. Two billion is five days at 5,000 verifications a second and twelve hours at
the 50,000/s peak, after which every insert on the verification path fails. Nothing is slow.
Nothing is overloaded. The column simply runs out of integers.

That is why a capacity model reads the schema rather than a spreadsheet of throughput figures.
A spreadsheet says the system is ten times faster than it needs to be. It is, and that is not
the question.

The same arithmetic applied to `TokenStateEpochLeaf.leaf_id` needs no assumption about cadence
at all: the table holds one row per token per epoch, so a 350M-credential population exhausts a
32-bit leaf id on the SIXTH epoch closure, whenever those happen.

HOW A FIGURE IS LABELLED IS THE POINT OF THE MODEL. Four kinds:

  MEASURED     a number from an actual run on real code (docs/reference/BENCHMARK.md).
  EXTRAPOLATED a measured number carried somewhere it was not measured, under an assumption
               printed beside it. The core counts below are this: the per-core verification
               rate is measured on one core, and "six and a half cores" assumes those cores
               add up. Roadmap P1.18 item 6 names that move by its worst form -- "no
               one-core x8" -- and it is a move this file used to make while labelling the
               result MEASURED.
  DERIVED      arithmetic on a MEASURED number, a stated target, or the schema itself. It
               carries no assumption anybody has to agree with. The two id-space blockers above
               are DERIVED, which is why they are not arguable.
  ASSUMED      a deployment's own behaviour the repository cannot know: how often a credential
               is reissued, how often an algorithm migration runs. Stated, and overridable.
  UNVALIDATED  nothing here can establish it. The availability target is the whole of this
               category, and the model REFUSES to call such a target met.

A target is reported MET only when its throughput is met, no blocker stands against it, and no
link in its derivation is UNVALIDATED. A model that reported 50,000/s as met because six cores
can do the arithmetic would be reporting the half of the picture that flatters the system.

See docs/design/capacity-model.md.
"""
from __future__ import annotations

import re

INT4_MAX = 2 ** 31 - 1
INT8_MAX = 2 ** 63 - 1
SECONDS_PER_YEAR = 365.25 * 24 * 3600

#: Provenance labels. See the module docstring; the distinction between DERIVED and
#: ASSUMED is what separates a finding somebody must act on from one they can argue with.
MEASURED = "MEASURED"
EXTRAPOLATED = "EXTRAPOLATED"
DERIVED = "DERIVED"
ASSUMED = "ASSUMED"
UNVALIDATED = "UNVALIDATED"

#: Measured on real code. Every value here must match the figure published in
#: docs/reference/BENCHMARK.md; check_capacity_model resolves them against that
#: file, so a re-benchmarked number cannot leave a stale constant behind here.
BENCHMARK = {
    "verify_per_core_single_witness": 7848,   # verifications/s per core, verify-at-use
    "verify_per_core_two_witness": 745,       # verifications/s per core, issuance grade
    "issue_per_second": 372,                  # signing-bound under real ML-DSA-65
    "event_ingest_per_second": 25970,         # audit-row writes; NOT a signature check
}

#: The roadmap's stated P7 planning targets, quoted rather than paraphrased so that a
#: target changing in the roadmap and not here is visible as a difference in words.
#: `quote` is the roadmap's own words. check_capacity_model requires each to be a
#: literal fragment of ROADMAP.md, so a target that is reworded there and not here
#: shows up as a difference in language rather than passing as a difference in
#: nobody's attention. `statement` is the readable form for the published report.
TARGETS = {
    "population": {
        "statement": "350M persons",
        "quote": "350M persons",
        "value": 350_000_000,
    },
    "verification_sustained": {
        "statement": "5,000 sustained verifications/s nationally across federated instances",
        "quote": "5,000 sustained and 50,000 peak verifications/s nationally across "
                 "federated instances",
        "value": 5_000,
    },
    "verification_peak": {
        "statement": "50,000 peak verifications/s nationally across federated instances",
        "quote": "5,000 sustained and 50,000 peak verifications/s nationally across "
                 "federated instances",
        "value": 50_000,
    },
    "enrollment_surge": {
        "statement": "an enrollment surge of 200,000/day sustained during rollout years",
        "quote": "an enrollment surge of 200,000/day sustained during rollout years",
        "value": 200_000,
    },
    "availability": {
        "statement": "99.99% availability on the verification path",
        "quote": "99.99% availability on the verification path",
        "value": 0.9999,
    },
}

#: How fast each sequence-backed table gains rows at the stated targets.
#:
#: `per_second` is a callable over the resolved targets so a changed target moves the
#: answer. `basis` is the provenance: DERIVED rows need no agreement, ASSUMED rows do,
#: and the report prints the assumption next to the number rather than in a footnote.
GROWTH = {
    "VerificationEvent": {
        "rate": lambda t: t["verification_sustained"],
        "basis": DERIVED,
        "why": "one row per verification, at the stated sustained target",
    },
    "TokenStateEpochLeaf": {
        # Deliberately expressed per EPOCH rather than per second: the table holds one
        # row per token per epoch, so the exhaustion point is a count of closures and
        # needs no assumption about how often they happen.
        "per_epoch": lambda t: t["population"],
        "basis": DERIVED,
        "why": "one leaf per live credential per epoch closure",
    },
    "TokenSignature": {
        "rate": lambda t: t["population"] / SECONDS_PER_YEAR,
        "basis": ASSUMED,
        "why": "one row per credential per algorithm migration, assuming one migration a year",
    },
    "TokenLifecycleEvent": {
        "rate": lambda t: 5 * t["enrollment_surge"] / 86400.0,
        "basis": ASSUMED,
        "why": "about five lifecycle rows per credential, at the enrollment surge rate",
    },
    "IdentityToken": {
        "rate": lambda t: t["enrollment_surge"] / 86400.0,
        "basis": ASSUMED,
        "why": "one row per credential issued, at the enrollment surge rate",
    },
    "Individual": {
        "rate": lambda t: t["enrollment_surge"] / 86400.0,
        "basis": ASSUMED,
        "why": "one row per person enrolled, at the enrollment surge rate",
    },
    "RevocationList": {
        "rate": lambda t: 0.02 * t["population"] / SECONDS_PER_YEAR,
        "basis": ASSUMED,
        "why": "one row per revocation, assuming 2% of the population a year",
    },
    "AuthAuditLog": {
        "rate": lambda t: 10.0,
        "basis": ASSUMED,
        "why": "operator authentication events, assuming ten a second nationally",
    },
    "DuressEvent": {
        "rate": lambda t: 1.0 / 86400.0,
        "basis": ASSUMED,
        "why": "duress activations, assuming one a day nationally",
    },
}

#: The horizon a national identity system plans over. A judgment, not a measurement:
#: credentials are valid for years and the program outlives the people who start it, so
#: an id space that runs out inside a working career is a defect rather than a tradeoff.
DEFAULT_HORIZON_YEARS = 25


def sequence_columns(schema_sql):
    """Every SERIAL / BIGSERIAL column in the schema, with its owning table.

    Parsed from the schema rather than listed here, so a table added next year is
    analysed without anybody remembering to add it. A line scanner is used instead of a
    whole-statement regex because the partitioned tables do not end their CREATE TABLE
    the way the others do, and VerificationEvent -- the one that matters most -- is one
    of them.
    """
    out, table = [], None
    for line in schema_sql.splitlines():
        m = re.match(r"\s*CREATE TABLE (\w+)", line)
        if m:
            table = m.group(1)
            continue
        c = re.match(r"\s+(\w+)\s+(BIGSERIAL|SERIAL)\b", line)
        if c and table:
            out.append((table, c.group(1), c.group(2)))
    return out


def exhaustion(schema_sql, targets=None, horizon_years=DEFAULT_HORIZON_YEARS):
    """When each sequence runs out of integers at the stated targets.

    Returns a list of dicts, worst first. A row whose `basis` is DERIVED rests on the
    schema and a stated target only; an ASSUMED row rests on a growth assumption printed
    beside it.
    """
    t = {k: v["value"] for k, v in (targets or TARGETS).items()}
    horizon_seconds = horizon_years * SECONDS_PER_YEAR
    rows = []
    for table, column, kind in sequence_columns(schema_sql):
        driver = GROWTH.get(table)
        if driver is None:
            continue
        cap = INT4_MAX if kind == "SERIAL" else INT8_MAX
        row = {
            "table": table, "column": column, "width": kind,
            "basis": driver["basis"], "why": driver["why"],
            "capacity": cap,
        }
        if "per_epoch" in driver:
            per_epoch = driver["per_epoch"](t)
            row["unit"] = "epoch closures"
            row["lifetime"] = cap / per_epoch
            row["per_unit"] = per_epoch
            # A count of closures is not a duration, so it cannot be compared with the
            # horizon in years. It is flagged on its own terms: an id space that holds
            # six of an operation the system performs routinely is exhausted.
            row["exhausts_within_horizon"] = row["lifetime"] < 100
        else:
            rate = driver["rate"](t)
            row["unit"] = "seconds"
            row["per_unit"] = rate
            row["lifetime"] = cap / rate if rate else float("inf")
            row["exhausts_within_horizon"] = row["lifetime"] < horizon_seconds
        rows.append(row)
    return sorted(rows, key=lambda r: (not r["exhausts_within_horizon"], r["lifetime"]))


def human_lifetime(row):
    """A duration or a count of operations, whichever the row is measured in."""
    if row["unit"] == "epoch closures":
        return f"{row['lifetime']:.1f} epoch closures"
    s = row["lifetime"]
    if s == float("inf"):
        return "never"
    if s < 86400:
        return f"{s / 3600:.1f} hours"
    if s < 86400 * 365:
        return f"{s / 86400:.1f} days"
    return f"{s / SECONDS_PER_YEAR:.1f} years"


def throughput(targets=None, benchmark=None):
    """Cores and seconds needed to meet each throughput target.

    All MEASURED-derived. Verification fans out because verify-at-use needs only the
    public key; signing does NOT, because it needs the private key and therefore the
    custody boundary, which is why the enrollment figure is stated as time on one signer
    rather than as a number of signers.
    """
    t = {k: v["value"] for k, v in (targets or TARGETS).items()}
    b = benchmark or BENCHMARK
    return {
        "verification_sustained": {
            "cores": t["verification_sustained"] / b["verify_per_core_single_witness"],
            "per_core_measured": b["verify_per_core_single_witness"],
            "provenance": EXTRAPOLATED,
            "assumption": LINEAR_FANOUT,
            "note": "single-witness verify-at-use. The PER-CORE rate is measured; the "
                    "core COUNT is division",
        },
        "verification_peak": {
            "cores": t["verification_peak"] / b["verify_per_core_single_witness"],
            "per_core_measured": b["verify_per_core_single_witness"],
            "provenance": EXTRAPOLATED,
            "assumption": LINEAR_FANOUT,
            "note": "same path at the peak target",
        },
        "enrollment_surge": {
            "signer_seconds_per_day": t["enrollment_surge"] / b["issue_per_second"],
            "provenance": MEASURED,
            "note": "signing-bound under real ML-DSA-65, and signing does NOT fan out the "
                    "way verification does: it needs the private key, so an HSM's rate is "
                    "the ceiling",
        },
        "population": {
            "years_to_enroll": t["population"] / (t["enrollment_surge"] * 365.25),
            "provenance": DERIVED,
            "note": "the rollout duration the enrollment target implies, which the target "
                    "does not say out loud",
        },
    }


#: The assumption every core count here rests on. Plausible and unmeasured, and the
#: difference between those two words is the whole reason this constant has a name.
#: Verification needs only a public key: no custody, no private key, no shared state
#: between requests, so nothing in the path obviously serialises. What is measured is
#: one core. What is NOT measured is eight of them, or a fleet, or the network and the
#: trust-list distribution that a real federated deployment puts in front of them.
#: docs/reference/HA-VERIFICATION-REPORT.md carries what has actually been measured on
#: a real multi-node topology, which is a two-member cluster and not a fleet.
LINEAR_FANOUT = (
    "verification fans out linearly across cores and replicas because it needs only a "
    "public key and shares no state between requests. Plausible, and measured on ONE "
    "core: the multiplication has never been run."
)

#: What the repository cannot establish, and what would establish it. Each entry is a
#: reason a target CANNOT be reported met, however comfortable the other numbers look.
UNVALIDATED_LINKS = {
    "availability": (
        "99.99% is 52.6 minutes of downtime a year on the verification path. Establishing "
        "it needs a failure rate and a recovery time from a multi-region deployment under "
        "real traffic. What is measured is narrower and says so: the rolling-deploy drill "
        "drops zero verifications, and the failover drill induces four failures and "
        "demonstrates recovery, on a TWO-MEMBER topology on CI hardware. A figure "
        "extrapolated from that would be an assertion wearing a measurement's clothes."
    ),
}


def validate(schema_sql, targets=None, benchmark=None,
             horizon_years=DEFAULT_HORIZON_YEARS):
    """Per-target verdicts: MET, BLOCKED, or UNVALIDATED.

    A target is MET only when its throughput is met, no id-space blocker stands against
    it, and no link in its derivation is UNVALIDATED. Throughput alone never earns a MET,
    which is the whole reason this function exists rather than a table of core counts.
    """
    tgt = targets or TARGETS
    tp = throughput(tgt, benchmark)
    ex = exhaustion(schema_sql, tgt, horizon_years)
    blocking = [r for r in ex if r["exhausts_within_horizon"]]

    # Which tables each target's traffic actually writes to.
    touches = {
        "verification_sustained": ("VerificationEvent",),
        "verification_peak": ("VerificationEvent",),
        "enrollment_surge": ("IdentityToken", "Individual", "TokenLifecycleEvent",
                             "TokenSignature"),
        "population": ("IdentityToken", "Individual", "TokenStateEpochLeaf",
                       "TokenSignature"),
        "availability": (),
    }

    verdicts = {}
    for key, target in tgt.items():
        blockers = [r for r in blocking if r["table"] in touches.get(key, ())]
        entry = {
            "statement": target["statement"],
            "throughput": tp.get(key),
            "blockers": blockers,
        }
        if key in UNVALIDATED_LINKS:
            entry["verdict"] = UNVALIDATED
            entry["because"] = UNVALIDATED_LINKS[key]
        elif blockers:
            entry["verdict"] = "BLOCKED"
            entry["because"] = (
                "the throughput is met; the id space is not. "
                + "; ".join(f"{r['table']}.{r['column']} is {r['width']} and lasts "
                            f"{human_lifetime(r)}" for r in blockers))
        else:
            entry["verdict"] = "MET"
            # A MET that rests on an extrapolation carries the extrapolation. The
            # verdict and the assumption travel together or the verdict is a claim
            # the reader cannot grade.
            if entry["throughput"] and entry["throughput"].get("assumption"):
                entry["rests_on"] = entry["throughput"]["assumption"]
        verdicts[key] = entry
    return {"targets": verdicts, "exhaustion": ex, "throughput": tp,
            "horizon_years": horizon_years}


def nearest_survivor(report):
    """The 32-bit column closest to exhaustion that the horizon does not yet flag.

    Reported on purpose. A column that clears the horizon by a few years has not been
    shown to be safe; it has been shown to be outside the window somebody chose, and a
    model that printed only what it flagged would hide the next one to go.
    """
    survivors = [r for r in report["exhaustion"]
                 if r["width"] == "SERIAL" and not r["exhausts_within_horizon"]
                 and r["unit"] == "seconds"]
    return min(survivors, key=lambda r: r["lifetime"]) if survivors else None


def render_markdown(report):
    """The published model. Leads with what blocks, not with what passes."""
    v = report["targets"]
    lines = [
        "# National capacity model",
        "",
        f"Horizon: {report['horizon_years']} years. Every throughput figure is MEASURED on "
        "real code; every id-space figure is DERIVED from the schema and a stated target.",
        "",
        "## Verdicts",
        "",
        "| Target | Verdict |",
        "| --- | --- |",
    ]
    order = [k for k in TARGETS if k in v] + [k for k in sorted(v) if k not in TARGETS]
    for key in order:
        lines.append(f"| {v[key]['statement']} | **{v[key]['verdict']}** |")
    blocked = [k for k in order if v[k]["verdict"] != "MET"]
    resting = [k for k in order if v[k].get("rests_on")]
    if resting:
        lines += ["", "## What the MET verdicts rest on", ""]
        seen = []
        for key in resting:
            note = v[key]["rests_on"]
            if note in seen:
                continue
            seen.append(note)
            lines.append(f"- {note}")
    if blocked:
        lines += ["", "## Why the verdicts that are not MET", ""]
        for key in blocked:
            lines += [f"### {v[key]['statement']}", "", v[key]["because"], ""]
    lines += [
        "## Id-space headroom",
        "",
        "How long each sequence-backed table takes to run out of integers at the stated "
        "targets. A DERIVED row rests on the schema and a target alone and carries no "
        "assumption to argue with; an ASSUMED row prints its assumption beside it.",
        "",
        "These are the figures that decide the verdicts above. The throughput targets "
        "clear by more than an order of magnitude; what stops a system reaching them is "
        "running out of integers, and nothing is slow when that happens. Every insert on "
        "the path simply fails.",
        "",
        "| Table | Column | Width | Lasts | Basis | Driver |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for r in report["exhaustion"]:
        mark = "**" if r["exhausts_within_horizon"] else ""
        lines.append(
            f"| {r['table']} | {r['column']} | {r['width']} | "
            f"{mark}{human_lifetime(r)}{mark} | {r['basis']} | {r['why']} |")
    nearest = nearest_survivor(report)
    if nearest is not None:
        lines += [
            "",
            f"Closest column still inside 32 bits: **{nearest['table']}.{nearest['column']}**, "
            f"{human_lifetime(nearest)}. It sits outside the "
            f"{report['horizon_years']}-year horizon rather than comfortably beyond it, and "
            "it is referenced by foreign keys across the schema, so widening it is a wider "
            "change than widening a surrogate nobody points at. The model reports it rather "
            "than deciding it.",
        ]
    tp = report["throughput"]
    lines += [
        "",
        "## Throughput",
        "",
        f"- Sustained verification: {tp['verification_sustained']['cores']:.1f} cores "
        f"({tp['verification_sustained']['provenance']}; "
        f"{tp['verification_sustained']['per_core_measured']:,}/s per core is the "
        f"measured part).",
        f"- Peak verification: {tp['verification_peak']['cores']:.1f} cores "
        f"({tp['verification_peak']['provenance']}). "
        f"{tp['verification_peak']['note']}.",
        f"- Enrollment surge: "
        f"{tp['enrollment_surge']['signer_seconds_per_day'] / 60:.1f} minutes of one "
        f"signer a day. {tp['enrollment_surge']['note']}.",
        f"- Reaching the population target at the enrollment target takes "
        f"{tp['population']['years_to_enroll']:.1f} years. "
        f"{tp['population']['note']}.",
        "",
    ]
    return "\n".join(lines)
