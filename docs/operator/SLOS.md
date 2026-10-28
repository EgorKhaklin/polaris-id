# SLOS.md: Polaris service-level objectives (reference targets)

**Reader:** the operator or SRE writing the error-budget policy for a Polaris
deployment. **Job:** state the service-level objectives (SLOs) Polaris is
designed to meet, the service-level indicators (SLIs) that measure them, and
the error budget each implies.

These are reference targets for a notional deployment, not a measured
guarantee. Polaris ships the metrics, the alerting rules, and since v9.241 the
recording rules and dashboard panels that make these objectives observable as
series and numbers rather than as expressions in this document, but it does
not ship the measurement backend: the
Prometheus and Alertmanager stack is operator-gated (see
[`../../deploy/observability/README.md`](../../deploy/observability/README.md)).
No SLO here is enforced by Polaris at runtime. An operator who wires the stack
and runs at scale measures their own numbers; the targets below are the design
intent and a starting point for a real error-budget policy, not a claim about
an SLO Polaris itself meets.

Every SLI below is grounded in a metric Polaris **actually exposes** on
`/metrics` (Prometheus text exposition) or `/api/metrics` (JSON). Nothing here
references a metric the app does not emit.

---

## Table of contents

1. [The exposed metrics these SLOs are built on](#1-the-exposed-metrics-these-slos-are-built-on)
2. [Availability SLO](#2-availability-slo)
3. [Latency SLO](#3-latency-slo)
4. [Database-latency SLO](#4-database-latency-slo)
5. [Error budget](#5-error-budget)
6. [Design choices: what is not an SLO](#6-design-choices-what-is-not-an-slo)
7. [Cross-references](#7-cross-references)

---

## 1. The exposed metrics these SLOs are built on

| Metric | Type | Labels | Source |
|---|---|---|---|
| `polaris_requests_total` | counter | `route`, `method`, `status` | `polaris_web/app.py` (`_metrics_after_request`) |
| `polaris_request_latency_seconds` | histogram | `route` | `polaris_web/app.py` (`_metrics_after_request`) |
| `polaris_db_query_latency_seconds` | histogram | (none) | `polaris_web/app.py` (`/api/health` DB probe) |
| `polaris_app_info` | gauge (always 1) | `version` | `polaris_web/app.py` (refreshed at scrape) |
| `polaris_agency_events_total` | counter | `kind`, `agency_id` | `polaris_web/app.py` (the issue, revoke, and verify routes; v9.190). Not an SLI: the velocity alerts compare each agency against its own baseline |
| `polaris_quota_refusals_total` | counter | `kind`, `agency_id` | `polaris_web/app.py` (a quota refusal answered as 429; v9.190). Not an SLI: a refusal is the control working |
| `up{job="polaris"}` | gauge | Prometheus built-in | the scrape itself |

The JSON `/api/metrics` snapshot (`request_rate_per_minute`,
`error_rate_per_minute`, `auth_failures_per_minute`, `duress_events_total`,
`uptime_seconds`) is a human-readable rolling-window view from
`polaris_web/observability.py`. It is **not** the SLI source: it exposes rates,
not percentiles, and its windows reset on process restart. The SLOs below are
computed from the Prometheus metrics, which are the durable, aggregatable
series.

As of v9.120, `/metrics` aggregates across all gunicorn workers (Prometheus
multiprocess mode), so a ratio or quantile taken over `polaris_requests_total`
or the latency histograms reflects the whole app, not one worker.

---

## 2. Availability SLO

**Objective:** 99.9% of HTTP requests succeed (non-5xx) over a rolling 30-day
window.

**SLI (the success ratio):**

```promql
1 - (
  sum(rate(polaris_requests_total{status=~"5.."}[30d]))
  / sum(rate(polaris_requests_total[30d]))
)
```

This is the exact complement of the `PolarisHigh5xx` alert ratio
(`deploy/observability/polaris-alerts.yml`), evaluated over the SLO window
rather than the alert's 5-minute window. A request that returns 5xx (a server
error or an uncaught exception, which the after-request hook records as a 5xx)
is a failed request; everything else (including a 4xx, which is a caller error,
not a service failure) is a success.

**Target:** ≥ 99.9% success → an error budget of **0.1% of requests** per 30
days.

`PolarisHigh5xx` fires at a **1% sustained 5xx share over 10 minutes**. That is
intentionally an order of magnitude above the 0.1% SLO budget: the alert is a
"you are burning budget fast right now" page, not the SLO boundary itself. A
brief spike that clears inside 10 minutes does not page but still spends
budget, which is the point of tracking the budget separately from the alert.

---

## 3. Latency SLO

**Objective:** the p99 of per-route request latency stays under **2 seconds**
over a rolling 30-day window.

**SLI:**

```promql
histogram_quantile(0.99,
  sum(rate(polaris_request_latency_seconds_bucket[30d])) by (le))
```

`polaris_request_latency_seconds` is a real histogram with `_bucket` series, so
`histogram_quantile` is valid (this is not a synthetic percentile). The 2s
threshold is the same boundary `PolarisHighRequestLatency` alerts on
(SEV-3, `for: 10m`); the SLO is the long-window version of that alert.

**Target:** p99 < 2s. This is a degraded-experience boundary, not an outage
boundary, which is why the matching alert is SEV-3 (degraded, not down).

A secondary, gentler objective an operator may adopt: **p50 < 200ms**, computed
by substituting `0.50` for `0.99` above. Polaris does not ship an alert at p50;
it is offered here as a latency-budget reference, not a paging condition.

---

## 4. Database-latency SLO

**Objective:** the p99 of the `/api/health` database round-trip stays under
**5 seconds**.

**SLI:**

```promql
histogram_quantile(0.99,
  sum(rate(polaris_db_query_latency_seconds_bucket[30d])) by (le))
```

`polaris_db_query_latency_seconds` is recorded only from the `/api/health` DB
probe, so this SLO measures **database reachability and responsiveness as the
health check sees it**, not the latency of every application query. It is a
saturation signal: a p99 climbing toward 5s means the database is slow or
saturated before most user-facing flows have failed outright.

**Target:** p99 < 5s. This is the same boundary `PolarisHighDBLatency` alerts
on (SEV-2, `for: 5m`) and the same threshold `docs/operator/DR.md` maps to
SEV-2.

---

## 5. Error budget

For a 99.9% availability SLO over 30 days, the error budget is **0.1% of
requests**. Expressed as time-equivalent downtime (the familiar "three nines"
figure), 99.9% over 30 days allows roughly **43 minutes** of full outage per
month before the budget is exhausted.

A simple budget-tracking expression (fraction of the 30-day budget already
spent):

```promql
(
  sum(increase(polaris_requests_total{status=~"5.."}[30d]))
  / sum(increase(polaris_requests_total[30d]))
) / 0.001
```

A value ≥ 1 means the month's budget is spent.

**What ships (v9.241).** The three SLIs and the budget are recording rules in
[`polaris-slo.yml`](../../deploy/observability/polaris-slo.yml), evaluated
every five minutes, unit-tested by promtool in CI alongside the alerts, and
shown as the SLO row of the overview dashboard:

| Series | What it is |
|---|---|
| `polaris:sli_availability:ratio_30d` | the 30-day success ratio (section 2) |
| `polaris:error_budget_spent:ratio_30d` | the fraction of the month's budget spent; 1 is gone |
| `polaris:error_budget_burn_rate:1h`, `:6h` | the burn rate over short windows, in multiples of the sustainable pace |
| `polaris:sli_request_latency_p99:30d` | the 30-day request p99 (section 3) |
| `polaris:sli_db_latency_p99:30d` | the 30-day health-probe database p99 (section 4) |

Polaris still ships **no burn-rate alert**: how fast a deployment may spend
its budget before someone is paged is the operator's policy, and the alert
set is deliberately small. The series to page on are recorded, so the standard
multi-window rule is one block in the operator's own rule file:

```yaml
- alert: PolarisErrorBudgetBurn
  expr: polaris:error_budget_burn_rate:1h > 14.4 and polaris:error_budget_burn_rate:6h > 6
  for: 2m
  labels: {severity: sev2}
  annotations: {summary: "Error budget burning at 14x: the month's budget goes in about two days at this rate"}
```

The availability and DB-latency alerts route to a pager only once the operator
wires Alertmanager. Until then, the budget is a recorded series and a
dashboard panel, not an action.

---

## 6. Design choices: what is not an SLO

- **`duress_events_total`** is not an availability or latency signal. A duress
  event is a person signalling coercion, not a service failure; aggregating it
  into a reliability budget would be a category error (and a surveillance
  hazard). Treat any non-zero value as an incident to investigate per
  `docs/operator/OPERATIONS.md`, not as budget spend.
- **`auth_failures_per_minute`** is a security signal, not a reliability SLI.
  Failed logins are an expected, adversary-driven quantity; folding them into
  an availability number would let an attacker move the SLO by guessing
  passwords.
- **Per-person or per-agency availability.** Polaris does not slice these SLIs
  by identity, and it must not: an SLO computed per individual would be a
  reconstructable activity record. The SLIs above aggregate over all requests
  by design (vocation: no aggregation vector).

---

## 7. Cross-references

- [`../../deploy/observability/README.md`](../../deploy/observability/README.md): the shipped Prometheus scrape config + alert rules these SLOs are observed through (operator wires the backend).
- [`../../deploy/observability/polaris-alerts.yml`](../../deploy/observability/polaris-alerts.yml): the alert rules (ten as of v9.190: six service alerts plus the four per-agency velocity and quota alerts); the SLO thresholds match the service alert thresholds (long window vs. alert window).
- [`../../deploy/observability/polaris-slo.yml`](../../deploy/observability/polaris-slo.yml): the SLI and error-budget recording rules (v9.241), tested with the alerts.
- [`RUNBOOKS.md`](RUNBOOKS.md): what to do when an alert fires (one section per alert).
- [`DR.md`](DR.md): the SEV ladder the alert severities map to.
- [`OPERATIONS.md`](OPERATIONS.md): the day-2 metrics reference.
- [`../PRODUCTION-READINESS.md`](../PRODUCTION-READINESS.md): the readiness ledger; this doc closes the "SLOs" item.
- [`../reference/PERFORMANCE-BASELINE.md`](../reference/PERFORMANCE-BASELINE.md): the measured issuance/s, verification/s, and atlas p95 the latency SLO is judged against (v9.191).
