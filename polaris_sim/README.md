# polaris_sim - national simulation and benchmark harness

A seeded, deterministic simulation of a synthetic United States, driven through
the **real** Polaris procedures and constraints, so the system can be exercised,
benchmarked, and hardened at national scale. Notional data only; point it at an
expendable database. The multi-ship plan is
[DEVNOTES/national-simulation.md](../DEVNOTES/national-simulation.md) (roadmap
P2.14).

## What ships today

**S1, the substrate:**
- `reference.py` - the real United States as data: all 50 states + DC with 2020
  Census populations, state centroids, plus deterministic name pools.
- `nation.py` - a pure, seeded generator: `plan_nation(scale_divisor, seed)`
  builds every ID bureau in the country (count per state scaled by population)
  and streams the people each bureau enrolls. Same inputs, identical plan.
- `load.py` - loads a plan through the **real** bulk-enrollment pipeline
  (`uc_bulk_issue`): agencies inserted as configuration, each granted the
  algorithm authorization the pipeline requires, then every person issued a
  token set-based so it passes exactly the constraint set a real enrollee does.
  It never writes tokens directly.

**S2, the life-event stream:**
- `events.py` - a realistic flow of verifications and token-lifecycle events
  over a time window, written through the **real** paths. Verifications use the
  same direct `INSERT INTO VerificationEvent` the application's verification
  route uses; a zero-knowledge event carries no token and no location (C6), a
  disclosing event is placed near its holder's state. Revocations go through the
  real `uc8_revoke_token` procedure (which enforces its rate bound, co-signer,
  and algorithm authorization). It never writes a token or lifecycle row
  directly. The events populate the existing Atlas with a live national picture.

## Use

```bash
# Print the plan without touching a database:
python3 -m polaris_sim build --scale 100000 --plan-only

# Build and enroll a downscaled nation through the real pipeline
# (POLARIS_DB_* select the target database; build and benchmark create authorities
# and grant them an algorithm, so POLARIS_DB_USER must be the schema owner):
python3 -m polaris_sim build --scale 1000 --seed 42

# Drive a day of national life-events over the enrolled nation:
python3 -m polaris_sim run --events 500000 --lifecycle 200 --window 24
```

`--scale` is a downscale divisor: synthetic people are approximately the US
population divided by it (1:100000 for a laptop, toward 1:1 on a benchmark host).
Every ID bureau in every state is present at any scale.

## Tested

`test_sim.py` proves the generator is deterministic, covers all 51
jurisdictions, and that a small nation loads through the real pipeline with C3
(one active token per person) holding across the batch. It runs in the coverage
suite (`scripts/polaris-coverage.sh`) and is pinned by
`polaris_checks.check_national_simulation`.
