# KUBERNETES.md: the Helm reference profile

**Reader:** a platform team deploying Polaris on a cluster. **Job:** the
chart, what it enforces, how CI proves it boots, and its stated limits.

The production topology on a Kubernetes cluster:
[`deploy/helm/polaris`](../../deploy/helm/polaris). Docker Compose on one Linux
host ([`LINUX-SERVER.md`](LINUX-SERVER.md)) remains the single-node path; this
profile is for an authority whose platform is a cluster. It is a reference
profile, not an operator: the database runs under Patroni with the cluster's
own API as the lease store (v9.244), on the cluster's own storage, with
backups through pgBackRest exactly as on compose.

## What the chart deploys

| Workload | Kind | Runs as | Notes |
|---|---|---|---|
| `caddy` | Deployment | uid 1000 | the TLS edge on 8080/8443 (Service 80/443); `tls: internal` or ACME; 200 req/min/IP; retries onto another app pod for 15s; polls `/api/health/live` every 2s |
| `app` | Deployment, 2 replicas | uid 1000 | `maxUnavailable: 0`, readiness on `/api/health/live`, PodDisruptionBudget `minAvailable: 1` |
| `pgbouncer` | Deployment | uid 1000 | session pooling (transaction mode is refused: it hands the operator scope to the next client), TLS to postgres (verify-ca) and from the app |
| `pg-router` | Deployment | uid 99 | HAProxy, the same as the compose HA profile: 5432 to the member answering Patroni's `/primary`, 5433 to a replica; sessions to a member marked down are cut, which is what frees the pool from a frozen leader |
| `postgres` | StatefulSet, 2 members + PVCs | uid 70 | the self-contained image under Patroni ([FAILOVER.md](FAILOVER.md)): the Kubernetes API is the lease store, the leader Service's endpoints follow the lease, a replica Service selects on the `role` label; the data directory in a subdirectory of the volume; TLS on |
| `redis` | StatefulSet + PVC | uid 999 | sessions and rate-limit state |

Every pod satisfies the **restricted** Pod Security Standard: non-root with a
numeric uid, `seccompProfile: RuntimeDefault`, all capabilities dropped, no
privilege escalation. **NetworkPolicies** default-deny both directions for
every pod, then allow only the topology: internet to caddy, caddy to app, app
to pgbouncer and redis, pgbouncer to the router, the router to the members
(5432 and Patroni's REST on 8008), the postgres members to each other
(replication and REST) and to the API server (the lease store), DNS for all, ACME egress for caddy only with `edge.tls=acme`, S3
egress for postgres only with pgBackRest enabled. The API server's addresses
are read from the `kubernetes` Endpoints at install time; set
`networkPolicy.apiServer.cidrs` when your cluster fronts its API elsewhere.

## Prerequisites

- Kubernetes 1.29+ with a CNI that **enforces** NetworkPolicy (Calico, Cilium,
  Antrea, most managed clusters). kind's default kindnet does not; the drill
  installs Calico.
- A default StorageClass (five PVCs: data and a pgBackRest repo per postgres
  member, redis).
- Permission to create a Role and RoleBinding in the namespace: Patroni
  keeps the lease in Endpoints and a ConfigMap and labels its own pod, and
  the chart grants exactly those verbs to the postgres ServiceAccount.
- The edge's certificate (`edge.tls`). Each edge replica once kept its TLS state
  in its own emptyDir, so a restart ordered a certificate again and two replicas
  served different roots; now one of:
  - `secret` (production): a `kubernetes.io/tls` Secret for the domain, named by
    `edge.tlsSecret`, which cert-manager's `Certificate` keeps (any issuer;
    DNS-01 needs no ingress). Every replica serves it and reloads it when it is
    renewed.
  - `acme`: Let's Encrypt from Caddy itself, for one edge replica
    (`edge.replicas=1`) on a volume that keeps the account and certificates
    (`edge.acmeVolume`), behind a LoadBalancer Service reachable on 80/443 with
    the domain's DNS pointing at it. The chart refuses it with more replicas:
    replicas that do not share the ACME state each order a certificate and
    answer only their own challenges.
  - `internal` (the default; evaluation, private networks): Caddy's internal CA
    under a root the chart generates once and keeps, the Secret
    `<release>-edge-ca`, whose `ca.crt` clients trust.
- The four images in a registry your nodes can pull from (`images.*` in
  values), or `kind load docker-image` for a local cluster. Polaris publishes
  no registry images yet (P0.6 deferred image signing for that reason), so
  build and push them yourself:
  ```bash
  V=$(python3 -c 'from polaris_web.__version__ import __version__; print(__version__)')   # tag images with the shipped version
  ./scripts/polaris-image-build.sh --stack "$V"        # builds all four, retried, version-stamped
  for i in app caddy pgbouncer postgres; do
    docker tag "polaris-$i:$V" "REGISTRY/polaris-$i:$V" && docker push "REGISTRY/polaris-$i:$V"
  done
  ```

## Install

```bash
kubectl create namespace polaris
kubectl label namespace polaris pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted pod-security.kubernetes.io/audit=restricted

# Secrets: the same generator as compose (it mints the ML-DSA-65 signing key
# through the built app image), then one Secret holding every file.
./scripts/polaris-generate-secrets.sh
kubectl -n polaris create secret generic polaris-secrets --from-file=polaris_web/secrets/

# The edge's certificate, kept by cert-manager (here a ClusterIssuer named letsencrypt).
kubectl -n polaris apply -f - <<'EOF'
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: polaris-edge}
spec:
  secretName: polaris-edge-tls
  dnsNames: [polaris.example.org]
  issuerRef: {name: letsencrypt, kind: ClusterIssuer}
EOF

helm install polaris deploy/helm/polaris -n polaris \
  --set domain=polaris.example.org --set edge.tls=secret --set edge.tlsSecret=polaris-edge-tls \
  --set edge.service.type=LoadBalancer \
  --set secrets.existingSecret=polaris-secrets \
  --set images.app=REGISTRY/polaris-app:$V --set images.caddy=REGISTRY/polaris-caddy:$V \
  --set images.pgbouncer=REGISTRY/polaris-pgbouncer:$V --set images.postgres=REGISTRY/polaris-postgres:$V \
  --wait --timeout 12m
```

Without `secrets.existingSecret` the chart generates random passwords and
self-signed PostgreSQL/pgbouncer certificates (kept across upgrades), but it
cannot mint a signing key, so `/api/health` reports custody degraded until you
add `polaris_signing_key` to the Secret ([`KEY-CEREMONY.md`](KEY-CEREMONY.md);
the PKCS#11 and KMS custody drivers work here too, through the same env).

The v9.189 session and origin controls (`POLARIS_NETWORK_POLICY_<ROLE>`,
`POLARIS_SESSION_MAX_<ROLE>`, `POLARIS_SESSION_IDLE_MINUTES_<ROLE>`, and the
`POLARIS_WEBAUTHN_*` attestation policy) go in `app.extraEnv` as
`{name, value}` pairs; a malformed value refuses the pod's boot, which the
startup probe surfaces. [`HARDENING.md`](HARDENING.md) section 13.

## Verify

```bash
kubectl -n polaris get pods
kubectl -n polaris port-forward svc/polaris-caddy 8443:443 &
# edge.tls=internal: trust the chart's root rather than skipping verification
kubectl -n polaris get secret polaris-edge-ca -o jsonpath='{.data.ca\.crt}' | base64 -d > edge-ca.crt
curl --cacert edge-ca.crt https://localhost:8443/api/health | python3 -m json.tool   # with domain=localhost; database, redis, zk_binary, custody: healthy
kubectl -n polaris exec polaris-postgres-0 -- patronictl -c /var/lib/postgresql/patroni.yml list   # one Leader, one streaming Replica
```

## Operate

- **Upgrade** (a new image tag or chart change): `helm upgrade polaris
  deploy/helm/polaris -n polaris --reuse-values --set images.app=...`. The app
  Deployment rolls with `maxUnavailable: 0` and readiness gating, the
  Kubernetes-native form of the P1.4 zero-downtime deploy; the edge retries
  onto the remaining pod while one is replaced.
- **Migrations** follow the expand-contract policy
  (`polaris_sql/migrations/README.md`). An install's init loads every
  migration; on `helm upgrade` a pre-upgrade Job
  (`templates/migrate-job.yaml`, `migrations.enabled`) runs the runner the
  new postgres image carries, `polaris-migrate.sh --up` then
  `--sync-objects`, before anything else is applied, so the release still
  running reads an expanded schema and the new one starts on it. A failed Job
  fails the upgrade and stays for `kubectl logs job/<release>-migrate`.
  `scripts/polaris-helm-upgrade-drill.sh` upgrades the previous release's
  chart on kind and requires nothing pending.
- **Rotate a secret**: update the Secret (`kubectl create secret ... --dry-run
  -o yaml | kubectl apply -f -`), then `kubectl rollout restart` the consumers
  (app, pgbouncer for the DB password; postgres needs the role updated first,
  as `polaris-rotate-secret.sh` does on compose).
- **Database failover** is automatic: a lost leader pod is replaced by the
  other member within the lease (`postgres.patroni.ttl`, 20 s), the
  StatefulSet brings the pod back and Patroni rejoins it as a replica. A
  planned switchover for node maintenance is
  `kubectl -n polaris exec polaris-postgres-0 -- patronictl -c /var/lib/postgresql/patroni.yml switchover`.
  The mechanics, the measured numbers and the split-brain analysis are in
  [`FAILOVER.md`](FAILOVER.md).
- **Failure domains** (lab record 017, gate row OP-7):
  - The chart spreads every replicated component across nodes and, where the
    nodes carry `topology.kubernetes.io/zone`, across zones: the two database
    members, two app pods, and two pods each of the edge, the router and
    pgbouncer. A single-node cluster still schedules them all.
  - Pods Kubernetes may move leave a node that stopped answering after
    `spread.evictAfterSeconds` (30 s, not the default 300 s).
  - Redis is a Deployment on an emptyDir, so it moves too. The rate limiter
    refuses requests while Redis is unreachable, and its windows are
    short-lived.
  - Disruption budgets keep a drain from taking the last pod of anything.
  - `scripts/polaris-zone-loss-drill.sh` kills the leader's node on a kind
    cluster of three zones and measures what comes back.
  - Upgrading from a chart with the Redis StatefulSet leaves its claim
    (`data-<release>-redis-0`) to delete.
- **Backups**: `pgbackrest.enabled=true` with the S3 values and the key pair in
  the Secret's `pgbackrest_repo_creds.conf` ([`DR.md`](DR.md)); only the
  leader archives, so the repo follows the lease.
- **Observability**: `/metrics` is served by the app pods; scrape it from
  inside the cluster (the NetworkPolicy allows ingress to the app only from
  caddy; add a rule for your Prometheus namespace). Alerting and paging:
  [`deploy/observability/`](../../deploy/observability/README.md).

## How this is tested

`scripts/polaris-helm-drill.sh`, run by the `helm-kind` CI job on every push:
a kind cluster with the default CNI disabled and Calico installed, the four
self-built images loaded (pull policy Never; redis pulled by its pinned digest),
the namespace labelled restricted and a
privileged pod rejected by the API server, the real secrets as a Secret,
`helm lint` and `helm install --wait`, `/api/health` through the edge with
database, redis, zk_binary, and custody healthy, a probe pod outside the
topology denied by policy on postgres, pgbouncer, and app, a rolling
restart that keeps the edge healthy, and (v9.244) the database failover
under a writer with the app's labels inserting through pgbouncer: the leader
pod deleted (it returns under the same name inside its lease and keeps the
role, a restart in place: 3.2 s of write outage), the leader's container
frozen through the node's runtime (a hung node: the other member held the
lease after 21 s, the pool's query cancelled at the 15 s `query_timeout` so a
15.8 s write outage, the thawed leader demoted and streaming again 6 s
later), a planned switchover (3.5 s), and every
acknowledged insert present on the leader afterwards; local reference run
at v9.244, the ceilings 60 s, 60 s and 30 s. Stated limits:
single-node kind and `tls: internal`; multi-node placement and ACME are
operator-environment concerns.
