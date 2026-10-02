# Observability

**Reader:** an engineer or an assessor. **Job:** What a running deployment tells its operator, and how.

An operator should be able to see what a Polaris deployment is doing with
nothing but the running stack, and above everything else they should see a
duress signal. A duress code that raises a row nobody reads makes the whole
duress mechanism decorative, so the design question here is not
what can be measured but what must be impossible to miss.

Two surfaces carry it: a log stream, and four counters.

## The counters

`polaris_web/observability.py` keeps four in-process counters, thread-safe and
free of any external dependency. They are served twice: as JSON at
`/api/metrics`, for an operator with curl and jq, and in Prometheus text
format at `/metrics`, alongside the per-route HTTP series.

| Counter | What it measures | What an anomaly means |
|---|---|---|
| `request_rate_per_minute` | trailing five-minute average throughput | a spike is a traffic shift or an attack; a drop to zero is the stack being down |
| `error_rate_per_minute` | trailing five-minute 5xx and uncaught exceptions | anything sustained is worth investigating |
| `auth_failures_per_minute` | trailing five-minute failed authentications | a spike is credential stuffing, or someone probing a coerced operator's account |
| `duress_events_total` | monotonic count since the process started | non-zero is the anti-coercion alarm, and pages immediately |

**Both surfaces are unauthenticated, and both carry the duress signal.**
Whoever can scrape them can observe that a duress alarm fired, and roughly
when. The control is access to the surface rather than suppression of the
metric, because the operator's own monitoring is exactly the audience that
needs it in order to page. Restrict `/metrics` and `/api/metrics` at the edge
to the monitoring network; the Caddy matcher that does it ships in both edges
and `deploy/observability/README.md` states the rule.

## The log stream

`structured_log(event, **fields)` writes one JSON object per line to stdout.
Every line carries `ts`, `pid`, `event` and `request_id`, and, while an
OpenTelemetry span is recording, `trace_id` and `span_id`, so a log line and a
trace join on the same request. Nothing is written to disk or to the database:
stdout goes wherever the deployment already collects logs, which on a systemd
host is the journal and in a container platform is whatever collects container
output.

Event names are namespaced by subject, so an operator can select a family:

| Event | When it is emitted | Fields |
|---|---|---|
| `auth.failure` | a password, WebAuthn or recovery-code attempt failed | `kind`, `username` |
| `duress.signal` | a holder's duress code matched during verification | `individual_id`, `agency_id` |
| `quota.refused` | an agency quota refused a write | `kind`, `agency_id` |
| `db.error` | the database refused a statement; the message is truncated and never echoed to the caller | `detail` |
| `boot.session_policy` | the per-role session and WebAuthn policy this process started with | the resolved policy |
| `boot.tracing_enabled` | tracing is on | `service`, `endpoint` |
| `boot.tracing_unavailable` | tracing was asked for and the packages are absent | |

The `boot.*` events are state announcements, emitted once at start. The others
are events, emitted as they happen. The taxonomy stays small deliberately: a
new event earns its place by being a signal an operator would act on.

## What ships for alerting

Polaris ships the rules rather than recommending that someone write them.
`deploy/observability/polaris-alerts.yml` carries ten:

- `PolarisDuressEvent`, at severity one with no delay, on any increase in
  `polaris_duress_events_total`.
- `PolarisAppDown` and `PolarisAppInfoAbsent`, on the process disappearing.
- `PolarisHigh5xx`, `PolarisHighRequestLatency` and `PolarisHighDBLatency`, on
  the service degrading.
- `PolarisIssuanceVelocity`, `PolarisRevocationVelocity` and
  `PolarisVerificationVelocity`, each comparing an agency against its own
  trailing week.
- `PolarisQuotaRefusals`, on a cap refusing writes.

Every rule names a runbook section, and `check_alert_runbooks` fails the build
if a rule exists without one or a runbook section exists without its rule.
`polaris-alerts.test.yml` is the promtool suite that proves each rule fires on
the series it claims to watch, and CI's page drill proves a duress event
reaches a webhook end to end.

`alertmanager.yml`, `prometheus.yml`, `tempo.yml` and the Grafana dashboards
ship beside them. What stays the operator's is the pager product, its URL and
the on-call rotation, which is one of the nine decisions in the readiness
ledger.

## Watching it by hand

```bash
# the four counters, as JSON
curl -fsS http://localhost:5000/api/metrics | jq .

# every duress signal in the log stream
docker compose -f polaris_web/docker-compose.prod.yml logs app -f \
  | jq -c 'select(.event == "duress.signal")'
```

## Boundaries

This is not an application-performance monitor, a log-storage layer or a
metrics database. It is a small, self-contained surface plus the rules an
operator's own Prometheus and Alertmanager consume. Tracing is a separate,
opt-in surface behind `POLARIS_OTEL`, described in the same directory.

Nothing here is auto-instrumented at import: every counter has an explicit
call site in `app.py` or `security.py`, because instrumentation an operator
cannot see is instrumentation an operator cannot switch off.
