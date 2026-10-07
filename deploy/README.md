# deploy/: the three substrates Polaris runs on

**Reader:** an operator choosing where to run Polaris, or reading a manifest
and wanting to know how far it is supported. **Job:** name each substrate, say
what it is for, and state its limit before it is discovered in production.

The compose stack is not here: it lives beside the application it composes, at
[`polaris_web/docker-compose.prod.yml`](../polaris_web/docker-compose.prod.yml),
and every substrate below builds on it or reproduces it.

| Directory | Substrate | Status |
|---|---|---|
| [`linux/`](linux/) | A single Linux host under systemd | Supported. One script installs it; CI runs it on Debian 12 and Rocky 9 on every push. |
| [`helm/`](helm/) | A Kubernetes cluster | Reference profile. It boots healthy on kind in CI with policies enforced and runs two PostgreSQL members under Patroni, which CI fails over and switches over. The members are not yet spread across nodes, so it is not yet tolerant of a node's loss ([operability gate](../docs/PRODUCTION-READINESS.md#operability-gate)). |
| [`observability/`](observability/) | Prometheus, Alertmanager, Grafana and Tempo | Supported configuration, not a deployment. Polaris ships the rules, the routing and the dashboards; the pager product and the on-call rotation are yours. |

## linux/

`install.sh` takes a fresh Debian, Ubuntu or RHEL-family host to a healthy
production stack: packages, Docker, the secrets, the schema, the migrations,
the compose stack behind the Caddy edge, and the systemd units that keep it
running. The units are here too: the service itself, and the timers for the
backup, the backup verification and the monthly disaster-recovery drill.
`polaris.env.example` is the operator's environment file, copied and filled in
during the install.

Read [LINUX-SERVER.md](../docs/operator/LINUX-SERVER.md) first, then
[HARDENING.md](../docs/operator/HARDENING.md), which is a separate and
deliberate step.

## helm/

`polaris/` is the chart: the Caddy edge, two application replicas, pgbouncer,
PostgreSQL and Redis, with default-deny NetworkPolicies and the restricted Pod
Security Standard enforced at the namespace. `kind-config.yaml` is the cluster
definition CI uses, with the default networking disabled so that Calico can
provide the policy enforcement a NetworkPolicy needs to mean anything.

The chart's `appVersion` tracks the application version and is checked on every
push. Read [KUBERNETES.md](../docs/operator/KUBERNETES.md), which covers the
prerequisites, the image build, and the install.

## observability/

`polaris-alerts.yml` holds the alert rules, including the duress page that
fires at severity one with no delay; `polaris-alerts.test.yml` is the promtool
suite that proves each rule fires on the series it claims to watch.
`alertmanager.yml` routes them, `prometheus.yml` scrapes the application, and
`tempo.yml` plus `grafana/` carry the trace backend and the dashboards as code.

Both metrics surfaces are unauthenticated and both carry the duress signal, so
the edge restricts them to the monitoring network. That rule, and the matcher
that enforces it, are in [observability/README.md](observability/README.md).
