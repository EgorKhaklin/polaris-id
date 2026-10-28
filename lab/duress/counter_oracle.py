#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""counter_oracle.py -- what the global duress counter reveals about one forced presentation.

THE OBSERVABLE. `polaris_duress_events_total` is unlabelled, checked rather than assumed: one
global counter, no agency and no context dimension, so nothing in it breaks the population
down. Over a long period it publishes how often duress events occur across an authority,
which is what the alarm exists to publish.

THE QUESTION MEASURED. A reader of the counter who also chooses when a given holder presents
can do this:

    read polaris_duress_events_total
    make the holder present
    read it again

If the holder supplied a duress code, the counter moved by one more than the background
traffic did. Repeating the observation averages the background out. This file measures how
well that single-observation comparison identifies whether one holder signalled.

SCOPE OF THE INPUT. Reading the counter needs access to `/metrics`, which is restricted at
the edge to the monitoring network (`check_metrics_edge_acl`, enforced in both the Caddyfile
and the Helm configmap, with CI scraping from outside to prove it). The model below is of
background arrivals, not a measurement of a deployment.

THE ESTIMATOR is the simplest one that works: count the observations where the counter moved
at all, and judge the holder enrolled if it moved on most attempts.

POSITIVE CONTROL. A quiet authority, no background traffic: one observation must decide it. If
the estimator is not certain there, it is measuring noise and every number below is noise too.

Run: python3 lab/duress/counter_oracle.py [--trials K]
"""
import argparse
import random
import sys

#: Background presentations per minute at the moment the observer chooses to read.
BACKGROUND_PER_MIN = (0, 1, 10, 100)

#: How long the observation window is: read the counter, force a presentation, read it again.
WINDOW_SECONDS = 10

#: How many forced presentations are observed.
ATTEMPTS = (1, 3, 10, 30)


def _background(rate_per_min, rng):
    """Duress events from OTHER holders inside the window. A duress event is rare in the
    background: most presentations are not duress. The model uses 1 percent."""
    expected = rate_per_min * WINDOW_SECONDS / 60.0 * 0.01
    return 1 if rng.random() < expected else 0


def trial(enrolled, rate_per_min, attempts, rng):
    """One observation session. Returns the verdict: did this holder signal?

    The estimator: the holder is judged enrolled if the counter moved on MOST attempts. A
    holder who supplies their duress code moves it every time; a holder with no code
    moves it only when somebody else happens to signal in the same window.
    """
    moved = 0
    for _ in range(attempts):
        step = _background(rate_per_min, rng)
        if enrolled:
            step += 1          # the victim's own duress code
        moved += 1 if step > 0 else 0
    return moved > attempts / 2


def main():
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0] or None)
    ap.add_argument("--trials", type=int, default=4000)
    args = ap.parse_args()
    rng = random.Random(20260917)

    print("polaris_duress_events_total is UNLABELLED: one global counter, no agency or")
    print("context dimension. Below: how well a read-force-read comparison of that counter")
    print("identifies whether one holder signalled, by background volume and attempts.")
    print()

    control = all(trial(True, 0, 1, rng) for _ in range(args.trials)) and \
        not any(trial(False, 0, 1, rng) for _ in range(args.trials))
    if not control:
        print("== VOID: with no background traffic a single observation must decide it, both "
              "ways. It does not, so the estimator is measuring noise ==", file=sys.stderr)
        return 1
    print("control: no background traffic, one observation -> correct every time, both ways")
    print()

    print("%-14s %-9s %s" % ("background", "attempts", "P(verdict is right)"))
    for rate in BACKGROUND_PER_MIN:
        for n in ATTEMPTS:
            right = 0
            for _ in range(args.trials):
                truth = rng.random() < 0.5
                right += trial(truth, rate, n, rng) == truth
            print("%-14s %-9d %.4f" % ("%d/min" % rate, n, right / args.trials))
    print()
    print("Input: a model of background arrivals (1 percent of background presentations are "
          "duress), a 10 second window, and counter access on the monitoring network. "
          "Not a measurement of a deployment.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
