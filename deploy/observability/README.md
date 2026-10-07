# Polaris observability config (v9.175)

Ready-to-deploy Prometheus + Alertmanager config for scraping Polaris,
alerting on its health, and paging a human. Polaris ships the rules, the
routing, and the receiver template, and proves in CI that a duress event
reaches the pager webhook. What stays yours: the pager product and its URL.

## Files

| File | What it is |
|---|---|
| [`prometheus.yml`](prometheus.yml) | Scrape config (the `polaris` job hitting `/metrics`), `rule_files` loading the alerts, and `alerting` pointing at the Alertmanager below. |
| [`polaris-alerts.yml`](polaris-alerts.yml) | Ten alerting rules (v9.237), severity-labelled to the `docs/operator/DR.md` SEV ladder: the app down or its info series absent, the duress page, 5xx rate, request and database latency, the three velocity alerts, and quota refusals. |
| [`polaris-slo.yml`](polaris-slo.yml) | The SLI and error-budget recording rules (v9.241): the 30-day availability ratio, the budget spent, the 1h and 6h burn rates, and the two 30-day p99s, evaluated every five minutes. Loaded by `prometheus.yml`, mounted by the overlay, unit-tested with the alerts, shown on the overview dashboard's SLO row. |
| [`alertmanager.yml`](alertmanager.yml) | Routing (duress: no wait, re-page every 15m; other SEV-1: immediate; SEV-2/3: batched) and the `pager` webhook receiver, whose URL is read from a mounted secret file. |
| [`tempo.yml`](tempo.yml) | Tempo trace backend (v9.187 / P1.6): OTLP in on 4318/4317, local storage, 7-day retention. The app's opt-in exporter (`POLARIS_OTEL=1`) points here by default. |
| [`grafana/`](grafana/) | Dashboards-as-code (v9.187 / P1.6): datasource + dashboard provisioning and the committed dashboard JSONs (`polaris-overview`, `polaris-traces`). Edit the JSON, commit, redeploy: the UI copies are disposable. |

## Deploy

1. Edit `prometheus.yml`: set `scrape_configs[0].static_configs.targets` to your
   deployment's `host:port` (the app behind Caddy). If your Alertmanager is not
   reachable as `alertmanager:9093`, change the `alerting` target too.
2. Write the pager URL (one line) to a file that is NOT committed and mount it
   into Alertmanager at `/etc/alertmanager/secrets/pager_webhook_url`. Any
   webhook a pager accepts works: PagerDuty Events v2, Opsgenie, Splunk On-Call,
   a Slack/Teams incoming webhook. Prefer a native integration? Uncomment one of
   the `*_configs` blocks in `alertmanager.yml`; their keys are mounted files
   too (`routing_key_file`, `api_key_file`, `api_url_file`), never inline.
3. Validate before (re)loading:
   ```
   promtool check config prometheus.yml
   promtool check rules polaris-alerts.yml
   amtool check-config alertmanager.yml
   ```
   CI runs exactly these on every push (`scripts/polaris-page-drill.sh`).
4. Send yourself a synthetic duress page through the real receiver, before you
   need it for real:
   ```
   amtool --alertmanager.url=http://alertmanager:9093 alert add \
     alertname=PolarisDuressEvent severity=sev1 job=polaris \
     --annotation=summary="Drill: synthetic duress page"
   ```
   The `pager` receiver should notify within seconds (no grouping wait on that
   route). If it does not, the problem is between Alertmanager and your pager
   product, not in Polaris.

## The page path is proven, not asserted

`scripts/polaris-page-drill.sh` (run by the `page-drill` CI job) starts the real
Prometheus and Alertmanager binaries (digest-pinned) on the shipped rules and
config, points them at a stub `/metrics` and a webhook sink, flips
`polaris_duress_events_total` from 0 to 1, and asserts the `PolarisDuressEvent`
page arrives at the webhook (receiver `pager`, severity `sev1`, firing), with no
page beforehand. The app half, a duress-code match incrementing that counter,
is `test_duress_increments_prometheus_counter` in the product suite. Together
they cover the whole path from a holder's duress code to the pager URL.

The outage path is proven the same way, weekly, on the real application:
`scripts/polaris-chaos-drill.sh` (the `chaos` workflow) points a Prometheus at
both app colours of a booted stack, stops them, and asserts `PolarisAppDown`
reaches the webhook through this Alertmanager configuration before it starts
them again; the delivery time is recorded in
[`docs/operator/CHAOS-DRILLS.md`](../../docs/operator/CHAOS-DRILLS.md).


## Access control (required)

`/metrics` and `/api/metrics` are unauthenticated by design (Prometheus scrapes
the first; an operator curls the second), and both carry the **duress signal**
(`polaris_duress_events_total`). Whoever can scrape them can observe that, and
roughly when, a duress alarm fired. That is the same audience which needs the
signal in order to page, so the control is access to the surface, not
suppression of the metric.

**The shipped edges enforce it.** Both the compose `Caddyfile` and the Helm
chart's Caddy config answer `404` on those two paths to any client outside the
allowed range, and serve every other route normally. Unset, the range names no
client: behind an L4 load balancer, Kubernetes' default `externalTrafficPolicy`,
rootless Docker or Docker's IPv6 userland proxy every internet client reaches the
edge from a private address, so a private-ranges default would serve them all
(`scripts/polaris-metrics-edge-drill.sh` asks through such a hop). A Prometheus
on the stack's network scrapes `app:8000` directly and needs no edge route; one
elsewhere is named:

```bash
POLARIS_METRICS_ALLOW=10.20.0.0/16      # compose
```

```yaml
edge:
  metricsAllow: "10.20.0.0/16"          # Helm values
```

The `caddy-edge` CI job proves both branches on every push: an in-network client
gets `200` on both paths, a client outside the range gets `404` on both, and an
ordinary route is unaffected either way. `check_metrics_edge_acl` fails the
build if either edge stops refusing.

## The alerts

| Alert | Severity | Fires when | Route |
|---|---|---|---|
| `PolarisAppDown` | SEV-1 | the scrape target is down for 2m | immediate, re-page hourly |
| `PolarisAppInfoAbsent` | SEV-1 | `polaris_app_info` is absent for 5m | immediate (inhibited while AppDown fires) |
| `PolarisDuressEvent` | SEV-1 | a duress-code match recorded a `DuressEvent` (fires immediately) | no wait, re-page every 15m |
| `PolarisHigh5xx` | SEV-2 | the 5xx share of requests exceeds 1% for 10m | batched 30s, re-page 4h |
| `PolarisIssuanceVelocity` / `PolarisRevocationVelocity` / `PolarisVerificationVelocity` | SEV-2 | one agency's last hour exceeds an absolute floor AND 4x its own trailing 7-day hourly mean (v9.190) | batched 30s, re-page 4h |
| `PolarisQuotaRefusals` | SEV-3 | an `AgencyQuota` cap refused writes in the last 15m (v9.190) | batched 30s, re-page 4h |
| `PolarisHighDBLatency` | SEV-2 | DB round-trip p99 exceeds 5s for 5m | batched 30s, re-page 4h |
| `PolarisHighRequestLatency` | SEV-3 | request p99 exceeds 2s for 10m | batched 30s, re-page 4h |

## Metric aggregation

As of v9.120 the app's `/metrics` aggregates across all gunicorn workers
(Prometheus multiprocess mode: `PROMETHEUS_MULTIPROC_DIR` is set in the prod
compose, each worker file-backs its samples, and the scrape sums them via a
`MultiProcessCollector`). So absolute counters reflect the whole app, and
absolute-count thresholds are safe to add. The rules above remain **ratios**
(`PolarisHigh5xx`) and **quantiles** (the latency alerts) because those are the
right shapes for these conditions, not because of a per-worker limitation.

## Distributed tracing + dashboards-as-code (v9.187 / roadmap P1.6)

The whole stack runs as a compose overlay on the production file:

```bash
docker compose -f docker-compose.prod.yml -f docker-compose.observability.yml up -d
```

Prometheus, Alertmanager, Tempo, and a PROVISIONED Grafana join the stack
network. Before first up, write two more one-line secret files next to the
pager URL: `grafana_admin_password`, and point `prometheus.yml`'s scrape
target at `app:8000` (scheme `http`, inside the stack network the scrape
does not cross the TLS edge). Grafana listens on `127.0.0.1:3000` only: its
dashboards can display the duress signal, so the same access rule as
`/metrics` applies.

Tracing is the app's choice, not the stack's: set `POLARIS_OTEL=1` on the
app service (the exporter endpoint already defaults to `http://tempo:4318`).
The request span carries the v9.122 correlation id as `polaris.request_id`:
the id a caller quotes finds its trace (`{span.polaris.request_id="<id>"}`),
and every structured-log line emitted inside a traced request carries
`trace_id`/`span_id`, so logs and traces join in both directions. What spans
never carry: query strings, parameter values, identity, exception messages
(`polaris_web/tracing.py` documents the vocation constraints).

CI proves the claims on every push (`scripts/polaris-trace-drill.sh`, the
`trace-drill` job): the dashboards validate as provisionable JSON querying
the real metric names, the overlay renders against the production compose
file, and the OTLP wire path exports a span carrying the caller's exact
X-Request-ID: with the request's query string asserted ABSENT from the
payload bytes. The DB half (psycopg2 client spans inside the request trace)
is `DistributedTracingTests` in the product suite.
