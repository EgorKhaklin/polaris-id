#!/usr/bin/env python3
"""counter_oracle.py -- long-run frequency analysis, taken to its actual conclusion.

THE ACCEPTED LIMITATION, from docs/design/duress-codes.md:

> **No defence against long-run frequency analysis.** Constant-time comparison covers a
> single call. An attacker measuring aggregate rates over a long period could in principle
> infer how often duress events occur, which is accepted rather than solved.

That is a population statistic, and as a population statistic it is genuinely acceptable:
how often duress events occur across an authority is close to what the alarm exists to
publish. `polaris_duress_events_total` is unlabelled, checked rather than assumed: one global
counter, no agency and no context dimension, so nothing in it breaks the population down.

THE SAME OBSERVABLE SUPPORTS A SHARPER ATTACK, and the design document does not name it. A
coercer does not have to wait for rates to accumulate. A coercer CHOOSES WHEN THE VICTIM
PRESENTS. That turns the counter into a chosen-input oracle:

    read polaris_duress_events_total
    make the holder present
    read it again

If the holder handed over a duress code, the counter moved by one more than the background
traffic did. Repeat and the background averages out. This is not "how often duress events
occur"; it is "did THIS person just signal", which is the single question the mechanism
exists to make unanswerable. README.md's conclusion is that duress codes resist a coercer who
does not know the mechanism exists; this is a coercer who does, and who can read one number.

WHAT IT COSTS THE ATTACKER, and what it needs. It needs read access to `/metrics`, which is
restricted at the edge to the monitoring network (`check_metrics_edge_acl`, enforced in both
the Caddyfile and the Helm configmap, with CI scraping from outside to prove it). So this is
not the public: it is an insider on that network, which is the operator-as-coercer this
directory already names as the adversary every safeguard assumes away.

MEASURED HERE: how many forced presentations does it take, against a given volume of
background traffic, before the coercer is confident? The estimator is deliberately the
simplest one that works, because a coercer does not need to be clever: count the observations
where the counter moved at all, and compare against how often it moves during a window where
the victim did NOT present.

POSITIVE CONTROL. A quiet authority, no background traffic: one observation must decide it. If
the estimator is not certain there, it is measuring noise and every number below is noise too.

Run: python3 lab/duress/counter_oracle.py [--trials K]
"""
import argparse
import random
import sys

#: Background presentations per minute at the moment the coercer chooses. A coercer picks the
#: moment, so the low end is the realistic one: they wait for a quiet counter.
BACKGROUND_PER_MIN = (0, 1, 10, 100)

#: How long the coercer's observation window is. They read the counter, force a presentation,
#: read it again; the window is however long that takes.
WINDOW_SECONDS = 10

#: How many forced presentations the coercer is willing to make.
ATTEMPTS = (1, 3, 10, 30)


def _background(rate_per_min, rng):
    """Duress events from OTHER holders inside the window. A duress event is rare in the
    background: most presentations are not duress. 1 percent is generous to the defender."""
    expected = rate_per_min * WINDOW_SECONDS / 60.0 * 0.01
    return 1 if rng.random() < expected else 0


def trial(enrolled, rate_per_min, attempts, rng):
    """One coercion session. Returns the coercer's verdict: did this holder signal?

    The estimator: the holder is judged enrolled if the counter moved on MOST attempts. A
    coerced holder who is using their duress code moves it every time; a holder with no code
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
    print("context dimension. The population statistic the design document accepts is all")
    print("it publishes. What follows is what the same number gives a coercer who chooses")
    print("the moment.")
    print()

    control = all(trial(True, 0, 1, rng) for _ in range(args.trials)) and \
        not any(trial(False, 0, 1, rng) for _ in range(args.trials))
    if not control:
        print("== VOID: with no background traffic a single observation must decide it, both "
              "ways. It does not, so the estimator is measuring noise ==", file=sys.stderr)
        return 1
    print("control: no background traffic, one observation -> correct every time, both ways")
    print()

    print("%-14s %-9s %s" % ("background", "attempts", "P(coercer is right)"))
    for rate in BACKGROUND_PER_MIN:
        for n in ATTEMPTS:
            right = 0
            for _ in range(args.trials):
                truth = rng.random() < 0.5
                right += trial(truth, rate, n, rng) == truth
            print("%-14s %-9d %.4f" % ("%d/min" % rate, n, right / args.trials))
    print()
    print("== A COERCER WHO CAN READ THE COUNTER DOES NOT NEED LONG-RUN RATES. They need the "
          "moment, which they already control. At every background volume in this table a "
          "handful of forced presentations answers 'did this person signal', which is the "
          "one question the mechanism exists to make unanswerable. ==")
    print()
    print("WHAT THIS DOES AND DOES NOT SAY. It needs read access to /metrics, which is "
          "restricted at the edge to the monitoring network and proven so in CI, so this is "
          "an insider on that network rather than the public. That is the operator-as-coercer "
          "this directory already names. It is a model of background arrivals, not a "
          "measurement of a deployment. And it does not weaken the case for the counter: an "
          "unread duress signal is the coercion-cover failure mode the alarm exists to "
          "prevent, so the answer is the access control, not deleting the metric. What "
          "changes is that docs/design/duress-codes.md described the accepted limitation as "
          "a population statistic, and it is also an individual test.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
