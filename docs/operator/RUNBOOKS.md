# RUNBOOKS.md: alert response runbooks

**Reader:** the on-call operator who has just been paged. **Job:** find the
alert by its exact name and work its Trigger / Likely cause / Diagnosis /
Remediation steps. There is one runbook per shipped Prometheus alert in
[`../../deploy/observability/polaris-alerts.yml`](../../deploy/observability/polaris-alerts.yml).

Polaris ships the alert rules, the metrics they read, and the Alertmanager
routing and receiver template
([`../../deploy/observability/alertmanager.yml`](../../deploy/observability/alertmanager.yml)),
and CI proves that a duress increment reaches the pager webhook
(`scripts/polaris-page-drill.sh`). Polaris does not ship the pager itself: the
on-call product and its URL are yours, wired as described in
[Paging](#paging-wiring-the-receiver). Until that file is mounted, these are
reference procedures, not a claim that Polaris is paging anyone.

The severity labels (`sev1`/`sev2`/`sev3`) map to the SEV ladder in
[`DR.md`](DR.md) §2. The SLO thresholds these alerts
relate to are in [`SLOS.md`](SLOS.md).

`check_alert_runbooks` (in `polaris_checks`) asserts that every alert in
`polaris-alerts.yml` has exactly one section here and that no section here
names an alert that no longer exists. Keep that one-to-one mapping when you
edit either file.

---

## Table of contents

1. [PolarisAppDown](#polarisappdown)
2. [PolarisAppInfoAbsent](#polarisappinfoabsent)
3. [PolarisDuressEvent](#polarisduressevent)
4. [PolarisHigh5xx](#polarishigh5xx)
5. [PolarisHighDBLatency](#polarishighdblatency)
6. [PolarisHighRequestLatency](#polarishighrequestlatency)
7. [PolarisIssuanceVelocity](#polarisissuancevelocity)
8. [PolarisRevocationVelocity](#polarisrevocationvelocity)
9. [PolarisVerificationVelocity](#polarisverificationvelocity)
10. [PolarisQuotaRefusals](#polarisquotarefusals)
11. [Paging: wiring the receiver](#paging-wiring-the-receiver)
12. [Cross-references](#cross-references)

---

## PolarisAppDown

**Severity:** SEV-1 · **Expression:** `up{job="polaris"} == 0` · **For:** 2m

**Trigger.** Prometheus has failed to scrape the `polaris` job for 2 minutes.
The target is down: the app is unreachable or the process has crashed.

**Likely cause.**
- The app container/process exited or is crash-looping (bad deploy, OOM kill,
  an import error after an upgrade).
- The reverse proxy (Caddy) is up but the app behind it is not, so `/metrics`
  is unreachable.
- A network/firewall change broke Prometheus's path to the scrape target.
- `prometheus.yml` points at the wrong `host:port` (misconfiguration, usually
  right after a move).

**Diagnosis.**
1. Hit liveness directly, bypassing Prometheus: `curl -fsS http://<target>/api/health/live`.
   A 200 with `{"status":"alive"}` means the process is up and the scrape path,
   not the app, is the problem; no response means the process is down.
2. Check the container state: `docker compose -f polaris_web/docker-compose.prod.yml ps`
   and `docker compose ... logs --tail=200 app`. Look for a crash loop or an
   OOM kill (exit 137).
3. Confirm Prometheus is aimed correctly: in the Prometheus UI, Status →
   Targets, find the `polaris` job and read the scrape error.

**Remediation.**
- Process down / crash-looping → treat as DR §4.1 (application crash). Read the
  last log lines, fix the cause (roll back the bad image, raise the memory
  limit if OOM), and restart: `docker compose ... up -d app`.
- App up but unreachable to the scraper → fix the network path or correct the
  `targets` in `prometheus.yml` and reload Prometheus.
- Confirm recovery: the alert clears once `up{job="polaris"} == 1` and
  `/api/health/ready` returns 200.

---

**How this is verified.** Weekly, `scripts/polaris-chaos-drill.sh` (the
`chaos` workflow) stops both app colours of a booted stack under traffic and
waits for this alert to reach a webhook sink through a real Prometheus
scraping the real app on the shipped rules and the shipped Alertmanager
routing; the delivery time is a column in [CHAOS-DRILLS.md](CHAOS-DRILLS.md).
The same drill crashes one colour and shows the other carries every request.


## PolarisAppInfoAbsent

**Severity:** SEV-1 · **Expression:** `absent(polaris_app_info)` · **For:** 5m

**Trigger.** The `polaris_app_info` gauge has been missing from scrapes for 5
minutes. The scrape is succeeding (otherwise `PolarisAppDown` would fire) but
the app is not serving its metadata gauge, so it is not serving `/metrics`
normally.

**Likely cause.**
- `/metrics` is returning 503 because `prometheus_client` is not installed in
  the running image (the endpoint degrades to 503 by design when the library is
  absent).
- In a multiprocess (gunicorn) deployment, `PROMETHEUS_MULTIPROC_DIR` is unset
  or unwritable, so the `MultiProcessCollector` has no samples to aggregate and
  `polaris_app_info` never appears.
- Something is proxying `/metrics` to a different process or a stale cache.

**Diagnosis.**
1. Scrape `/metrics` by hand: `curl -fsS http://<target>/metrics | head`. A 503
   confirms the endpoint is degraded; a 200 without a `polaris_app_info` line
   confirms the gauge specifically is missing.
2. If 503: check whether `prometheus_client` is importable in the running
   container (`docker compose ... exec app python -c "import prometheus_client"`).
3. If 200 but no gauge: check `PROMETHEUS_MULTIPROC_DIR` is set and the
   directory is writable inside the container; check the gunicorn worker count
   and that `child_exit` reaping is configured (see
   [`OPERATIONS.md`](OPERATIONS.md) metrics section).

**Remediation.**
- Missing library → rebuild/redeploy the image with `requirements.txt`
  installed; `prometheus_client` is a runtime dependency.
- Multiproc dir unset/unwritable → set `PROMETHEUS_MULTIPROC_DIR` to a writable
  tmpfs path in the prod compose and restart the app.
- Confirm recovery: `curl -fsS http://<target>/metrics | grep polaris_app_info`
  returns a line with the current `version` label.

---

## PolarisDuressEvent

**Severity:** SEV-1 · **Expression:** `increase(polaris_duress_events_total[5m]) > 0` · **For:** immediate

**This is not a system fault.** A token holder entered their enrolled DURESS
code during a verification: the system silently recorded a `DuressEvent` (the
coercer did not see anything unusual, by design) and incremented
`polaris_duress_events_total`. This alert exists so a human learns of the signal,
because an unread duress event is the coercion-cover failure mode (the whole
mechanism is decorative if no one reads the row). Treat it as a person signalling
they may be acting under coercion.

**Trigger.** `polaris_duress_events_total` increased in the last 5 minutes (at
least one duress-code match). The alert pages immediately (no `for` window):
duress cannot wait out a debounce. The shipped Alertmanager route matches it
with `group_wait: 0s` and re-pages every 15 minutes until a human resolves
the situation (see [Paging](#paging-wiring-the-receiver)).

**Likely cause.**
- A genuine duress-code entry: a holder forced to authenticate under coercion
  used their duress code to raise a silent alarm.
- A drill or an accidental duress-code entry (still investigate; do not assume).

**Diagnosis (out of band, never in front of the subject).**
1. Read the event on the operator duress dashboard (`/duress`): the `token_id`,
   `context_id`, `requesting_agency_id`, and timestamp of the `DuressEvent`.
2. Correlate with the verification context (which agency/where) to understand the
   situation the holder is signalling about. The append-only audit-of-record (C1)
   holds the surrounding events.
3. Do NOT contact the subject through the channel that may be compromised, and do
   NOT take any visible action that could reveal the alarm to a coercer.

**Remediation.** The response is a HUMAN safety/legal procedure, not a system
change, and the procedure itself is **operator-defined** (who is notified, how
the subject's safety is confirmed, what law-enforcement or welfare path applies).
Polaris's job ends at recording + paging; do not script an automated action
against the holder or the token. Do NOT revoke, lock, or alter the holder's
record in reaction (that could endanger them and corrupts the evidentiary
trail). Preserve the `DuressEvent` and the surrounding audit (they are
append-only). The alert clears on its own once no new event arrives in the
window; clearing is not "resolved"; the human response is.

---


## PolarisWitnessDisagreement

**Severity: SEV-1.** Continuous second-witness sampling on `/api/tokens/<id>/verify`
replayed a single-witness verification through the second implementation and the two
disagreed. The single-witness verify-at-use path is sound only while the fast witness
agrees with the two-witness reference; a disagreement means that assumption has broken.

1. **Stop trusting single-witness verification.** Raise `POLARIS_VERIFY_SAMPLE_RATE` toward
   `1.0` (every check runs both witnesses) while you investigate; throughput drops but
   every response is now two-witnessed.
2. **Read the evidence.** Find the `verify.witness_disagreement` structured log lines
   (they carry `token_id`, `single_ok`, `both_ok`). Determine which witness is wrong by
   re-verifying the token's stored signature offline against each implementation.
3. **Identify the cause.** A witness library upgrade or downgrade, a build mismatch
   between the two implementations, or corrupted stored signature material are the usual
   causes. Pin the witness versions and re-run the crypto suites.
4. **Recover.** Once the divergence is explained and fixed, return
   `POLARIS_VERIFY_SAMPLE_RATE` to its normal value. Do not silence the alert.

## PolarisHigh5xx

**Severity:** SEV-2 · **For:** 10m
**Expression:** `sum(rate(polaris_requests_total{status=~"5.."}[5m])) / sum(rate(polaris_requests_total[5m])) > 0.01`

**Trigger.** The server-error (5xx) share of requests has exceeded 1% for 10
minutes. This is the alert-window version of the availability SLI in
[`SLOS.md`](SLOS.md) §2; sustained firing is burning the availability error
budget an order of magnitude faster than the 0.1% monthly budget allows.

**Likely cause.**
- A dependency the request path needs is failing: database unreachable/slow,
  Redis down, the ZK verifier binary missing or erroring.
- A bad deploy introduced an uncaught exception on a hot route (the
  after-request hook records uncaught exceptions as 5xx).
- Resource saturation (CPU/memory/connection-pool exhaustion) turning slow
  requests into errors.

**Diagnosis.**
1. Find which routes are erroring: in Prometheus,
   `sum by (route, status) (rate(polaris_requests_total{status=~"5.."}[5m]))`.
   A single route points at a code path; broad spread points at a shared
   dependency.
2. Check dependency health: `curl -fsS http://<target>/api/health/ready` and
   read the `checks` block (`database`, `redis`, `zk_binary`, `disk`). A
   `503` with one unhealthy check localizes the cause.
3. Correlate with `PolarisHighDBLatency`: if both are firing, the database is
   the likely root cause.
4. Pull recent error log lines by `X-Request-ID` (every response carries one;
   every `structured_log` line is tagged) to read the actual exception.

**Remediation.**
- Dependency down → follow the matching DR procedure (database → DR §4.2/§4.3,
  disk → DR §4.4, redis → restart the container; see DR §3 decision tree).
- Bad deploy → roll back to the previous image tag and confirm the 5xx share
  falls back under 1%.
- Saturation → scale workers (`WEB_CONCURRENCY`/`POLARIS_WORKERS`) or the
  database connection pool; see [`SCALING.md`](../reference/SCALING.md).
- Confirm recovery: the ratio query falls below 0.01 and the alert clears after
  the `for` window.

---

## PolarisHighDBLatency

**Severity:** SEV-2 · **For:** 5m
**Expression:** `histogram_quantile(0.99, sum(rate(polaris_db_query_latency_seconds_bucket[5m])) by (le)) > 5`

**Trigger.** The p99 of the `/api/health` database round-trip has exceeded 5
seconds for 5 minutes. The database is slow or saturated as the health probe
sees it. This matches the DB-latency SLO boundary in [`SLOS.md`](SLOS.md) §4
and the SEV-2 threshold in [`DR.md`](DR.md).

**Likely cause.**
- A long-running or blocking query/transaction holding locks (a migration
  without `lock_timeout`, a runaway analytical query).
- Connection-pool exhaustion: the probe waits for a free pgbouncer/Postgres
  connection.
- Database resource saturation (CPU, IO, memory) or a checkpoint/vacuum storm.
- The DB host is degraded (failing disk, noisy neighbour).

**Diagnosis.**
1. Confirm it is the database, not the probe: `curl -fsS http://<target>/api/health`
   and read the `database` check's latency field.
2. On the database, look for blocking:
   `SELECT pid, state, wait_event_type, query_start, query FROM pg_stat_activity
   WHERE state <> 'idle' ORDER BY query_start;` and inspect `pg_locks` for long
   waits.
3. Check pgbouncer pool saturation (`SHOW POOLS;` on the pgbouncer admin
   console); a full pool serializes the probe.
4. Check host-level IO/CPU on the database node.

**Remediation.**
- Blocking query → terminate it (`SELECT pg_terminate_backend(<pid>)`) once
  confirmed safe; if it is a migration, see DR + the migration-timeout guard
  (migrations SET LOCAL `lock_timeout`/`statement_timeout`).
- Pool exhausted → raise pool size or `WEB_CONCURRENCY` per
  [`SCALING.md`](../reference/SCALING.md); investigate connection leaks.
- Saturation → add IO/CPU or move the noisy workload; if the host is degraded,
  treat as a DR database-corruption/failover scenario (DR §4.2/§4.3).
- Confirm recovery: the p99 quantile falls back under 5s and the alert clears.

---

## PolarisHighRequestLatency

**Severity:** SEV-3 · **For:** 10m
**Expression:** `histogram_quantile(0.99, sum(rate(polaris_request_latency_seconds_bucket[5m])) by (le)) > 2`

**Trigger.** The p99 of per-route request latency has exceeded 2 seconds for 10
minutes. The service is degraded (slow), not down, which is why this is SEV-3.
This matches the latency SLO boundary in [`SLOS.md`](SLOS.md) §3.

**Likely cause.**
- Database latency bleeding into request latency (often firing alongside
  `PolarisHighDBLatency`).
- A slow downstream call or an expensive route (large `/api/atlas` viewport,
  ZK verification under load).
- Worker saturation: too few gunicorn workers for the offered load, so requests
  queue.
- A garbage-collection or cold-cache effect right after a deploy/restart.

**Diagnosis.**
1. Localize by route: `histogram_quantile(0.99, sum by (le, route)
   (rate(polaris_request_latency_seconds_bucket[5m])))`. One slow route points
   at that handler; broad slowness points at a shared resource.
2. Check whether `PolarisHighDBLatency` is also firing. If so, fix the database
   first (its runbook), and request latency usually follows.
3. Check worker saturation: request rate vs. worker count
   (`WEB_CONCURRENCY`/`POLARIS_WORKERS`) and CPU on the app node.

**Remediation.**
- Database-driven → work `PolarisHighDBLatency` first.
- Hot/expensive route → check for a missing bound or index; `/api/atlas` routes
  are hard-capped, so an uncapped expensive path is a regression worth a fix.
- Worker saturation → scale workers per [`SCALING.md`](../reference/SCALING.md).
- Post-deploy cold cache → if the p99 is trending back down on its own within
  the `for` window after a restart, monitor rather than act.
- Confirm recovery: the p99 quantile falls back under 2s and the alert clears.

---

## PolarisIssuanceVelocity

**Severity:** SEV-2 · **Expression:** last-hour issuances by one agency `> 20` AND `> 4x` that agency's trailing 7-day hourly mean (offset 1h) · **For:** 5m

An issuing agency is minting tokens far faster than it usually does. v9.190
(roadmap P1.8) keys `polaris_agency_events_total{kind="issue"}` on the issuing
agency, so the comparison is each agency against ITS OWN baseline: a large
agency's normal volume never trips a small agency's threshold, and a young or
quiet agency's first actions stay under the absolute floor of 20 per hour.

**Trigger.** More than 20 issuances in the last hour by one agency, and more
than four times what that agency averaged per hour over the previous week.

**Likely cause.**
- A legitimate enrollment drive (a campus intake week, a new office) nobody
  told operations about.
- A compromised operator account or a script running the issuance form.
- A bulk import that should have gone through a planned, announced window.

**Diagnosis.**
1. `SELECT actor_agency_id, count(*) FROM TokenLifecycleEvent WHERE event_type='ISSUED' AND event_timestamp > now() - interval '1 hour' GROUP BY 1;` confirms the agency and volume.
2. `polaris-id audit-log --since-minutes 60` shows which operator sessions were active; a single session issuing everything is the account-compromise shape.
3. Check whether the agency has an `AgencyQuota` (`polaris-id quota-show <id>`); if not, the alert is the only brake.

**Remediation.** If unexpected: set a cap with `polaris-id quota-set <agency_id>
--issue-per-day N --justification "..."` (it engages on the next write,
refusing the excess with HTTP 429 and `PolarisQuotaRefusals`), and rotate or
deactivate the operator account if it is the source (`polaris-id user-passwd` /
`user-deactivate` end its sessions). Issued tokens are not undone by the
alert; a wrongful batch is revoked through `uc8_revoke_token`, which is itself
bounded by the per-agency revocation rate limit. If expected: raise or clear the cap and note the drive in the
journal; the alert clears when the hour rolls off.

---

## PolarisRevocationVelocity

**Severity:** SEV-2 · **Expression:** last-hour revocations of one agency's tokens `> 5` AND `> 4x` its trailing 7-day hourly mean (offset 1h) · **For:** 5m

Tokens issued by one agency are being revoked far faster than that agency's
norm. Mass revocation is the denaturalization shape the constitution names;
the percentage bound in `uc8_revoke_token` may already be refusing,
and this alert is the operator's early sight of the run-up.

**Trigger.** More than 5 revocations in the last hour of one issuing agency's
tokens, and more than four times its weekly hourly mean.

**Likely cause.**
- A planned recall (a hardware batch defect) that should be co-signed and announced.
- A compromised operator working the revocation form.
- A recovery ceremony (`uc9`) or reserve swaps (`uc4`) revoking lost tokens in bulk.

**Diagnosis.**
1. `SELECT e.reason_code, count(*) FROM TokenLifecycleEvent e JOIN IdentityToken t USING (token_id) WHERE e.event_type='REVOKED' AND e.event_timestamp > now() - interval '1 hour' AND t.issuing_agency_id=<id> GROUP BY 1;` shows whether the reasons cluster (a recall) or scatter (an operator).
2. `[COSIGN:<id>]` tags in `reason_code` show whether the `uc8_revoke_token` bound already demanded a co-signer.
3. `polaris-id audit-log --since-minutes 60` for the operator sessions involved.

**Remediation.** If unexpected: `polaris-id quota-set <agency_id>
--revoke-per-day N --justification "..."` caps further revocations at the
database (no procedure bypasses it); deactivate the operator if compromised.
Revocations already recorded are append-only audit and stay; a wrongful
revocation is remedied by issuance of a successor token, never by editing
history. If expected: the co-signer path exists for exactly this; use it.

---

## PolarisVerificationVelocity

**Severity:** SEV-2 · **Expression:** last-hour verifications by one requesting agency `> 200` AND `> 4x` its trailing 7-day hourly mean (offset 1h) · **For:** 5m

A verifier is checking identities far faster than it usually does. Population-
scale verification is the dragnet shape the vocation refuses: Polaris bounds
what an agency may DO, and this alert is the signal that a verifier's behaviour
changed.

**Trigger.** More than 200 verifications recorded in the last hour by one
requesting agency, and more than four times its weekly hourly mean.

**Likely cause.**
- A legitimate surge (an event gate, a benefits deadline) at a known verifier.
- A verifier scripting the verification form, or a leaked operator session.
- A verifier sweeping the population for a purpose the attestation did not cover.

**Diagnosis.**
1. `SELECT context_id, outcome, count(*) FROM VerificationEvent WHERE requesting_agency_id=<id> AND event_timestamp > now() - interval '1 hour' GROUP BY 1,2;` shows whether one context and outcome dominate (a sweep) or the mix looks like a queue.
2. `requesting_purpose_text` on those rows is the coercion-evidence trail (kept, never redacted); read it.
3. `polaris-id audit-log --since-minutes 60` for the operator sessions.

**Remediation.** `polaris-id quota-set <agency_id> --verify-per-hour N
--justification "..."` caps the verifier at the database on its next write.
For a verifier outside its attested purpose, revoke the federation attestation
(`/api/federation/revoke`); later SUCCESS outcomes then fail the federation
trust check (`_federation_trust_holds` in `app.py`). The recorded verifications are audit-of-record and stay.

---

## PolarisQuotaRefusals

**Severity:** SEV-3 · **Expression:** `sum by (agency_id, kind) (increase(polaris_quota_refusals_total[15m])) > 0` · **For:** immediate

An `AgencyQuota` cap refused at least one write in the last 15 minutes. This
is the cap doing its job; the alert exists because both readings of it need a
human: abuse the cap is holding back, or a cap set too low for legitimate
volume that is now failing real operators with HTTP 429.

**Trigger.** Any increase of `polaris_quota_refusals_total`, labelled with the
agency and the kind (`issue`, `revoke`, `verify`).

**Diagnosis.**
1. `polaris-id quota-show <agency_id>` for the cap and its justification (the row explains why it exists).
2. The `quota.refused` structured log lines carry the request ids; the
   corresponding velocity alert above says whether the volume is anomalous.
3. Ask the agency. A legitimate surge has a name and a contact.

**Remediation.** Legitimate volume: raise the cap (`polaris-id quota-set`, with
a new justification). Abuse: leave the cap, work the matching velocity runbook,
and end the operator sessions involved. The alert clears 15 minutes after the
last refusal; refused writes were never recorded and are not replayed.

---

## Paging: wiring the receiver

Alerts page through the `pager` receiver in
[`alertmanager.yml`](../../deploy/observability/alertmanager.yml): a generic
webhook whose URL is read from a mounted file, never written into config (the
URL usually embeds the integration key).

**Wire it.**
1. Create the pager integration in your on-call product and copy its webhook
   URL (PagerDuty Events v2, Opsgenie, Splunk On-Call, or a Slack/Teams incoming
   webhook all work; a bridge of your own works too).
2. Write the URL, one line, to a file outside the repo, and mount it read-only
   at `/etc/alertmanager/secrets/pager_webhook_url` in the Alertmanager
   container. Native `pagerduty_configs` / `opsgenie_configs` / `slack_configs`
   blocks are sketched in the file; their keys are mounted files as well.
3. `amtool check-config alertmanager.yml`, then reload Alertmanager.

**Prove it, before a real page.** Send a synthetic `PolarisDuressEvent`
through the real receiver and confirm the on-call is paged within seconds:
```bash
amtool --alertmanager.url=http://alertmanager:9093 alert add \
  alertname=PolarisDuressEvent severity=sev1 job=polaris \
  --annotation=summary="Drill: synthetic duress page"
```
Tell the on-call it is a drill first. Repeat after any change to the routing or
the pager product.

**What a PolarisDuressEvent page carries.** The webhook body is Alertmanager's
standard JSON: `receiver: pager`, `status: firing`, and an `alerts[]` entry with
`labels.alertname = PolarisDuressEvent`, `labels.severity = sev1`, and the
summary "Duress code matched". It does NOT carry the token or the holder; read
those out of band on the operator duress dashboard, as the
[PolarisDuressEvent](#polarisduressevent) runbook directs.

**Routing, as shipped.** `PolarisDuressEvent`: no grouping wait, re-page every
15 minutes. Other SEV-1: immediate, re-page hourly. SEV-2/3: 30s grouping,
re-page every 4 hours. `PolarisAppInfoAbsent` is inhibited while
`PolarisAppDown` fires (one page for one fact). Everything falls through to
`pager` by default: an alert with no route is the wrong failure mode.

**How this is verified.** `scripts/polaris-page-drill.sh` (the `page-drill` CI
job) runs the real Prometheus and Alertmanager on the shipped rules and config,
flips `polaris_duress_events_total` from 0 to 1 on a stub `/metrics`, and asserts
the page arrives at a webhook sink, with none arriving before the flip. The
product suite's `test_duress_increments_prometheus_counter` proves the app
increments that counter on a duress-code match.

---

## Cross-references

- [`../../deploy/observability/polaris-alerts.yml`](../../deploy/observability/polaris-alerts.yml): the shipped alert rules these runbooks respond to.
- [`../../deploy/observability/README.md`](../../deploy/observability/README.md): the Prometheus scrape config + how to wire the operator-gated Alertmanager backend.
- [`SLOS.md`](SLOS.md): the SLO targets and error budget the alert thresholds relate to.
- [`DR.md`](DR.md): the SEV ladder and the failure-class procedures referenced above.
- [`OPERATIONS.md`](OPERATIONS.md): the day-2 metrics reference.
- [`SCALING.md`](../reference/SCALING.md): worker/pool/index scaling levers.
