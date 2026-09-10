# Infrastructure cost per million persons per year

**Reader:** someone costing a deployment, or an assessor asking whether the throughput
numbers translate into money. **Job:** give a model you re-run with your own assumptions,
state which inputs are facts about this code and which are guesses about your deployment, and
name the finding that surprised the author.

`scripts/polaris-cost-model.py` computes this. It is a script rather than a table because a
cost table is out of date the week it is written, and because the interesting question is not
the number but how it moves.

## The finding

**Verification throughput is not the cost driver, at any realistic national scale.**

Single-witness verify-at-use measures about 7,848 ML-DSA-65 verifications per second per
core. A hundred million people verified twelve times a year is 38 verifications per second on
average, 381 at a ten-times peak. One core. The whole cryptographic load of a national
identity system fits inside the base capacity a deployment needs anyway for its application
and database processes.

What costs money is **availability and retention**: the copies of the database that high
availability and a standby region require, and the verification events accumulating for the
retention window. Both are policy choices, not cryptographic ones.

| Population | Peak verify/s | Cores for it | Stored, all copies | Annual | Per 1M/year |
|---|---|---|---|---|---|
| 1,000,000 | 3.8 | 1 | 49 GiB | $12,677 | $12,677 |
| 10,000,000 | 38 | 1 | 488 GiB | $13,241 | $1,324 |
| 100,000,000 | 381 | 1 | 4,875 GiB | $18,876 | $189 |

At list prices stated below, two regions and two database copies each, one-year event
retention, twelve verifications per person per year. **These are infrastructure numbers only.**

The per-million figure falls with scale because the base capacity is a floor, not a rate. A
deployment of a million people pays mostly for the shape of a highly available system; one of
a hundred million pays for the same shape plus storage.

## Where each input comes from

The model labels every input, and the honest error bars are entirely on the last two kinds.

**MEASURED**, from an actual run on this code
([BENCHMARK.md](BENCHMARK.md), single node, real ML-DSA-65):
verification 7,848/s per core single-witness and 745/s two-witness, issuance 372 tokens/s
signing-bound, event ingestion 25,970/s. Plus one measurement taken for this model: a
verification event costs **228.6 bytes** including every index, from 200,010 rows in the
partitioned table on PostgreSQL 16.

**COMPUTED**, from published constants: a credential's storage is an ML-DSA-65 signature
(3,309 bytes) plus its public key stored as hex (3,904 characters) plus row and index
overhead.

**ASSUMED**, and these are yours: verifications per person per year, retention, the
peak-to-mean ratio, how many database copies and regions. The defaults are twelve, one year,
ten, and two by two. Change them.

**PRICED**, list prices, USD, and wrong for you: $0.04 per vCPU-hour, $0.10 per GiB-month of
block storage, $0.09 per GiB of egress. No committed-use discount, no reserved capacity, no
negotiated rate, and no provider named, because naming one dates the document faster than the
prices do.

## What it does not include

Each of these can exceed the whole infrastructure figure:

- **Staff and on-call.** The largest line in most real deployments, and not a number this
  repository can estimate.
- **The physical token**, its personalisation, and the enrolment stations. Modelled here, not
  manufactured; roadmap P4.
- **A hardware security module.** The PKCS#11 driver is proven against a software token; no
  HSM has been used. A real deployment needs one and it is not a rounding error.
- **Support, legal, compliance, and external audit.** None has occurred.

## Sensitivity, which is the point of a script

Ask it the questions that matter for your deployment:

```bash
# Your population and verification rate
scripts/polaris-cost-model.py --persons 40000000 --verifications-per-person 26

# What retention actually costs: events are the growing term
scripts/polaris-cost-model.py --persons 10000000 --retention-years 7

# A single region, single copy, if availability is not your requirement
scripts/polaris-cost-model.py --regions 1 --replicas 1

# Your own prices
scripts/polaris-cost-model.py --price-vcpu-hour 0.025 --price-gib-month 0.06
```

The rate at which verification becomes the constraint is worth knowing and is far away: with
eight base cores at 7,848/s each, verification only begins to add cores past roughly 62,000
per second at peak. For a hundred million people that is about two thousand verifications per
person per year, or five a day each. If your deployment is there, the model is the least of
what needs rethinking.

## The honest caveat on all of it

The throughput numbers are **single-node measurements**. The multi-node behaviour is
projected, which [BENCHMARK.md](BENCHMARK.md) and roadmap P2.9 both say in their own words: no
production cluster has been measured, and the ten-million-record scale is extrapolated. A cost
model built on projected scaling is a planning instrument, not a quotation.

## Proven by

`check_cost_model` pins that the model is a runnable script rather than a committed table,
that it labels every input by origin, and that it names what it excludes. The measured inputs
it reads are the ones [BENCHMARK.md](BENCHMARK.md) publishes.
