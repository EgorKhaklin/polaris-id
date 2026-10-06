# Record 015, step 4: does FN-DSA signing time depend on the secret key?

**Run 2026-10-06** with [`timing/falcon_dudect.c`](timing/falcon_dudect.c) through
[`timing/run.sh`](timing/run.sh), a dudect-style test in C against the installed liboqs, on two
platforms: an Apple M3 (macOS, liboqs 0.15.0, its aarch64 Falcon) and Linux x86_64, the platform
the deployment profile names (a GitHub-hosted runner, liboqs 0.16.0 built from the release
commit and flags of `polaris_web/Dockerfile.prod`, by
[`lab-falcon-timing.yml`](../../../.github/workflows/lab-falcon-timing.yml)).

**The question (falsifier 2):** can the signing path be shown free of secret-dependent timing on
the platforms the deployment profiles name? Step 2 could not answer it: a Python timer resolves
about a microsecond, and every call crosses the interpreter.

**The method.** Each test times `OQS_SIG_falcon_padded_1024_sign` over two classes, chosen at
random per call, and reports Welch's t over the raw timings and over six percentile crops (the
dudect method). Both classes copy their key and message into the same buffers before each call,
so cache placement does not differ between them. |t| above 4.5 is a probable leak, above 10 a
leak.

| Test | Classes |
|---|---|
| key | one fixed secret key vs a key drawn from a pool of 128 fresh keys; same message |
| keypair | key A vs key B, two fixed keys; same message |
| message | one fixed key; a fixed message vs a random one |
| control | the key test with a planted leak: one class spins 100 ns after signing |

## Results

Largest |t| across the raw timings and the six crops; signing time is the median per call.

| Test | Samples | Apple M3, liboqs 0.15.0 | Linux x86_64 (AMD EPYC 7763), liboqs 0.16.0 |
|---|---|---|---|
| key (fixed vs random secret key) | 1,000,000 | 1.34 | 2.50 |
| keypair (key A vs key B) | 500,000 | 1.49 | 0.97 |
| message (fixed vs random) | 500,000 | 3.23 | 1.33 |
| control (100 ns planted) | 1,000,000 | **8.27** | **13.46** |
| signing time | | 407 µs | 474 µs |

Every real test stays below 4.5 on both platforms, and the planted 100 ns leak is found on both.
The x86_64 run is [workflow run 37454875926](https://github.com/EgorKhaklin/polaris-id/actions/runs/37454875926).
Earlier controls on the M3: a 2 µs plant read |t| 13.2 at 4,000 samples, a 500 ns plant 7.5 at
20,000. The harness first read the arm64 virtual counter directly; from user space on macOS it
reported 1 GHz and the difference wrapped, so the timer is `mach_absolute_time` (about 42 ns)
there and `CLOCK_MONOTONIC_RAW` on Linux.

## What it shows

On both platforms, no dependence of signing time on the secret key was detected, at a
sensitivity the planted control measures: a key-dependent shift in mean signing time as small as
100 ns (about 0.025% of a signing call on the M3) shows up at |t| above 4.5 in a million samples,
and the key tests stayed below 3. Falsifier 2 is not triggered on the platforms measured.

It also corrects step 2. The message dependence step 2 measured from Python (|t| 7.7 to 11.2, a
shift of about 0.4 microseconds) does not appear natively: at 500,000 samples a 0.4 microsecond
shift would read |t| near 20, and the native message test stays below 4.5. The step 2 signal came
from the Python path, not the library. The message is public in any case.

## What it does not show

- **Not a proof of constant time.** A dudect test finds first-order differences in mean timing
  between the classes it is given. A leak smaller than the control's size, or one that a random
  key pool averages away (a key crafted to hit a slow path), is not excluded. Falcon's signing is
  randomized, so each call varies by about 13 microseconds; that noise is what bounds the
  sensitivity.
- **Timing only.** Not cache sharing with a co-resident attacker, power, electromagnetic
  emanation or fault injection.
- **Two platforms.** A deployment on any other CPU or liboqs build is unmeasured; the harness and
  the workflow are here to measure it.

## The decision

The FN-DSA signer stays **experimental**, behind its opt-in and refused in production, for the
reasons that never depended on this test: FIPS 206 is a draft (falsifier 4), and no assessor or
operator outside the project has yet asked for it (falsifier 5). What this step removes is the
timing objection on the measured platforms.
