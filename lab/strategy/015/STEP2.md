# 015 step 2: FN-DSA timing, measured from Python (lab)

**2026-10-05**, Apple M3, liboqs 0.15.0, [`timing.py`](timing.py) (dudect's method: two input
classes interleaved at random, percentile crop, Welch's t; |t| > 4.5 suggests a difference and
|t| > 10 is a clear one).

**Fixed against random message, one key** (20,000 signatures each; then 40,000, three repeats):

| Algorithm | \|t\| (first run) | Repeats (t) | Median difference |
|---|---:|---|---:|
| ML-DSA-65 (reference) | 0.32 | +2.09, +2.99, +0.22 | none |
| Falcon-512 | 2.91 | | none |
| Falcon-1024 | 6.83 | **-11.19, -7.67, -8.56** | about 0.4 us of 412 us |
| Falcon-padded-512 | 4.59 | | about 0.2 us |
| Falcon-padded-1024 | 5.29 | | about 0.3 us |
| ML-DSA-65 with a planted 20 us difference (control) | **12.46** | | 33 us |

**Key against key, random messages** (two keys, 30,000 signatures, three repeats): Falcon-1024
-1.92, -2.08, -1.32; Falcon-512 +2.27, +2.09, +1.15; ML-DSA-65 -0.44, +1.42, +0.21. None reaches
4.5.

## What it shows

- **Falcon's signing time depends on the message** (stable sign, |t| 7.7 to 11.2 for Falcon-1024):
  a fixed message signs about 0.4 us faster. The message is public, so this alone reveals nothing
  secret; its cause (a cache effect on the repeated input, or the hash-to-point loop) is not
  established.
- **No dependence on the secret key was detected** at this resolution. Falcon's numbers are like
  ML-DSA's noise.
- **The setup can see a leak:** the planted 20 us difference reads |t| = 12.5.

## What it does not show, and the verdict

A Python-level timer resolves about a microsecond, with the interpreter's own noise on top. Real
side channels are often far below that. So this cannot show the signing path constant-time.
**Falsifier 2 is not cleared**, and FN-DSA stays lab-only. Clearing it needs a native harness (C,
the platform's cycle counter, dudect or its successors) on each platform the deployment profiles
name, with classes chosen over the secret key's own values, not only over which key signs.
