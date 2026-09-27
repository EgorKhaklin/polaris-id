# lab/evaluation: measured, not extrapolated

**Reader:** anyone deciding what Polaris's performance numbers are worth. **Job:** report
distributions measured by a script in this directory, with the machine, the method and the
raw samples, and say what each number does not establish.

The readiness ledger says every core count is extrapolated from one one-core figure, and that
linear fan-out has never been run. This directory replaces extrapolation with measurement one
path at a time. It is lab work: it creates no guarantee and changes no behaviour.

## Offline verification latency (2026-09-27)

[`offline_verify_latency.py`](offline_verify_latency.py): one authenticity verdict over the
published ML-DSA-65 vectors ([`vectors/`](../../vectors/README.md): a valid pack, a tampered
signature, a tampered token, a wrong key), single thread, 200 warm-up calls, then 5
repetitions of 2,000 timed calls: 10,000 samples per row. Every verdict is checked against the
vector's published answer before timing, because a fast wrong answer is not a measurement.

**Machine:** Apple M3, 8 cores, macOS 26.3 (arm64), Python 3.12.13, liboqs-python 0.16.0,
cryptography 50.0.1. One laptop, not CI hardware and not a server.

Valid pack (the other three vectors are within 3 microseconds at every percentile; see the
summary file):

| Path | p50 (95% CI) | p95 | p99 (95% CI) | One core at p50 |
| --- | --- | --- | --- | --- |
| liboqs witness alone | 122.0 us (122.0 to 122.0) | 122.8 us | 124.3 us (124.1 to 124.5) | 8,194/s |
| OpenSSL witness alone (`cryptography`) | 1,210.2 us (1,210.1 to 1,210.2) | 1,216.3 us | 1,229.3 us (1,226.7 to 1,233.0) | 826/s |
| Detached verifier, both witnesses | 1,332.8 us (1,332.8 to 1,332.9) | 1,342.9 us | 1,362.3 us (1,359.5 to 1,366.7) | 750/s |
| Python SDK, both witnesses installed | 1,333.2 us (1,333.2 to 1,333.3) | 1,341.2 us | 1,356.5 us (1,351.5 to 1,365.6) | 750/s |

The intervals are bootstrap 95% (1,000 resamples); the full set is in [`results/offline_verify_latency.json`](results/offline_verify_latency.json);
every per-call sample is in `results/offline_verify_latency.csv.gz`.

What it says:

- The figure the design documents quote (about 7,848 verifications per second per core) is
  the liboqs witness alone, which is what the application's verify-at-use path runs. It
  reproduces here: 122 microseconds at p50.
- A relying party gets a tenth of that. The Python SDK verifies with `cryptography` (OpenSSL)
  and adds liboqs only when it is installed; its one declared dependency is `cryptography`, so a
  plain `pip install` has only the OpenSSL witness, about 1.21 ms per verdict, and the detached verifier runs both, about 1.33 ms.
- Refusing a tampered signature, a tampered token or a wrong key costs the same as accepting
  a valid pack, to within 3 microseconds at p50. At this layer the verdict is not a timing
  oracle. That says nothing about the HTTP verifiers, whose response timing by refusal
  reason is not measured (packages/polaris-oid4vp README).

What it does not say:

- Nothing about more than one core, more than one process, or a network: throughput is
  1/p50 on one core of this machine, not a capacity.
- Nothing about the online verification endpoint, the database, or load. Those are the next
  measurements in this directory, and until they exist the ledger's extrapolation stands.

Re-run: `python3 lab/evaluation/offline_verify_latency.py --n 2000 --reps 5` with liboqs and
cryptography installed (the application's requirements-dev set).
