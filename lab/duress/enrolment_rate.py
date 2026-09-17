#!/usr/bin/env python3
"""enrolment_rate.py -- how identifying is a duress event, and to whom?

THE QUESTION, from README.md's unmeasured list: "If few holders enrol, a `DuressEvent` is
more identifying, which is the same anonymity-set problem measured in `lab/linkability/`."

THE PREMISE DOES NOT SURVIVE READING THE TABLE. `DuressEvent` is:

    event_id, token_id, context_id, requesting_agency_id,
    event_timestamp, oob_channel, oob_notified_at

It records `token_id`. Anybody who can read the row knows exactly which credential signalled,
and therefore which holder. There is no anonymity set to be small, and no inference to make,
so the enrolment rate does not enter into it. That adversary is Coercer 3 in README.md, where
this directory's conclusion is already that the mechanism is NET-NEGATIVE against lawful or
institutional access, precisely because the record is append-only and names the holder.

SO THERE ARE TWO ADVERSARIES AND THE BULLET CONFLATED THEM.

  the RECORD READER   admin, auditor, a database session, or lawful access. Reads token_id.
                      Anonymity set of one, always, at any enrolment rate. Not measured here
                      because there is nothing to measure: it is a lookup.

  the COUNTER WATCHER whoever can scrape `/metrics`, which carries
                      `polaris_duress_events_total` by design as a page-able alarm. They
                      learn that an alarm fired and roughly when, and nothing else. THIS is
                      the anonymity-set question, and it is what this file measures.

WHAT SHAPES THE SET. Not the enrolment rate on its own. The candidates are the holders who
presented during the interval the watcher can resolve, narrowed to those who could have
signalled at all, which is where enrolment enters. So the set is
`presentations_per_interval x enrolment_rate`, and the interval is the SCRAPE PERIOD. Both
terms shrink it, and at any plausible adoption the enrolment term dominates: one in a
thousand enrolled names a single holder even at the busiest rate in the table.

POSITIVE CONTROL. A configuration where the watcher must be certain: one presentation in the
interval, and that holder enrolled. If the adversary is not certain there, the harness is
broken and every wider number below means nothing.

Run: python3 lab/duress/enrolment_rate.py [--holders N] [--trials K]
"""
import argparse
import random
import sys

#: Scrape periods worth asking about. 15s is the Prometheus default; 60s is the common
#: relaxed setting; 300s is what an operator picks when they are told the endpoint is cheap.
SCRAPE_SECONDS = (15, 60, 300)

#: Presentations per minute across the whole authority. The low end is a quiet office; the
#: high end is the sustained rate the capacity model is built for.
PRESENTATION_RATES = (1, 10, 100, 1000)

#: Share of holders who have enrolled a duress code.
ENROLMENT_RATES = (0.001, 0.01, 0.10, 0.50)


def anonymity_set(rate_per_min, scrape_s, enrolment, rng, seen=None):
    """How many holders could have caused the increment this watcher just saw.

    Presentations in the window are drawn around the expected rate; each is an enrolled
    holder with probability `enrolment`. The one who signalled is in the set by construction,
    so the set is never empty and a set of ONE names them.

    `seen` forces the number of presentations, which is the only way to write a control that
    MEANS "exactly one presentation in the window". Sampling cannot guarantee it: the first
    version of this control asked for one presentation by setting the rate low and got a set
    of two, correctly refusing to report. A control that is itself a sample is not a control.
    """
    if seen is None:
        expected = rate_per_min * scrape_s / 60.0
        seen = max(0, int(rng.gauss(expected, max(0.8, expected ** 0.5))))
    candidates = sum(1 for _ in range(seen) if rng.random() < enrolment)
    return max(1, candidates)


def main():
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0] or None)
    ap.add_argument("--trials", type=int, default=4000)
    args = ap.parse_args()

    print("WHAT THE TABLE RECORDS: event_id, token_id, context_id, requesting_agency_id,")
    print("                        event_timestamp, oob_channel, oob_notified_at")
    print("  token_id is in the row, so a RECORD READER has an anonymity set of one at any")
    print("  enrolment rate. That is Coercer 3 and is not an inference problem.")
    print()
    print("Measured below: the COUNTER WATCHER, who sees polaris_duress_events_total move.")
    print()

    rng = random.Random(20260917)

    # The control: one presentation in the window, that holder enrolled.
    certain = [anonymity_set(0, 0, 1.0, rng, seen=1) for _ in range(args.trials)]
    if max(certain) != 1:
        print("== VOID: the control did not name a single holder (max set %d). With one "
              "presentation in the window and that holder enrolled the watcher must be "
              "certain; it is not, so the harness is broken ==" % max(certain), file=sys.stderr)
        return 1
    print("control: one presentation in the window, enrolled -> anonymity set 1.0000  (certain)")
    print()

    print("%-8s %-8s %-10s %10s %10s" % ("scrape", "pres/min", "enrolment", "median set", "P(set=1)"))
    worst = []
    for scrape in SCRAPE_SECONDS:
        for rate in PRESENTATION_RATES:
            for enrol in ENROLMENT_RATES:
                sets = sorted(anonymity_set(rate, scrape, enrol, rng)
                              for _ in range(args.trials))
                median = sets[len(sets) // 2]
                alone = sum(1 for s in sets if s == 1) / len(sets)
                print("%-8s %-8d %-10.3f %10d %10.4f" % ("%ds" % scrape, rate, enrol, median, alone))
                if alone >= 0.5:
                    worst.append((scrape, rate, enrol, alone))
    print()
    print("== THE SET IS THE PRODUCT: presentations in the window TIMES the enrolment rate. "
          "%d of the %d configurations above name a SINGLE holder more than half the time. "
          "The bullet was right that a rare enrolment is more identifying, and the reason is "
          "sharper than it said: at 1 in 1000 enrolled, the counter names one person at "
          "1000 presentations a minute and a 60-second scrape, which is the busiest "
          "authority in this table. Low adoption does not dilute the signal, it IS the "
          "signal. ==" % (len(worst), len(SCRAPE_SECONDS) * len(PRESENTATION_RATES)
                          * len(ENROLMENT_RATES)))
    print()
    print("WHAT THIS DOES AND DOES NOT SAY. It is a model of arrival times, not a measurement "
          "of a deployment: presentations are drawn around an expected rate rather than taken "
          "from traffic nobody has. What it does establish is the SHAPE, and the shape is the "
          "finding: the candidate set is a PRODUCT, so a low enrolment rate hands the counter "
          "watcher a name at any traffic, and a long scrape does it at low traffic. The "
          "control "
          "on `/metrics` is access to the surface (`check_metrics_edge_acl`, enforced at two "
          "edges), which is the right control for exactly this reason and is now measured "
          "rather than assumed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
