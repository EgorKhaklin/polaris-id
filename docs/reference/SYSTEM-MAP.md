# SYSTEM-MAP: the shape of the repository

**Reader:** anyone opening the repository for the first time. **Job:** every
directory's role, every package's purpose, every CI job, and who reads what.
Naming and structural conventions are in [../CONVENTIONS.md](../CONVENTIONS.md).

The tree below and the CI job list are recomputed on every push by
`check_system_map_covers_the_tree`: a tracked top-level path this document
omits, a path it lists that no longer exists, or a job name that has drifted
from the workflow all fail the build. The prose descriptions are not
generated, so they are as current as the last reader who corrected them.

---

## At a glance

```
polaris/
│
├── README.md                     ← the front page
├── MISSION.md                    ← the constitution (C1-C10 and the vocation)
├── ROADMAP.md                    ← the build plan, P0 to P7
├── CHANGELOG.md                  ← every ship, never edited retroactively
├── CLAUDE.md                     ← the developer and agent runbook
├── CONTRIBUTING.md / SECURITY.md ← contributor guide; vulnerability disclosure
├── CODE_OF_CONDUCT.md            ← the community standard, Contributor Covenant 3.0
├── CITATION.cff                  ← how to cite this work, and the shipped version
├── LICENSE / NOTICE              ← Apache 2.0; provenance and third-party notices
│
├── Polaris.command               ← double-click launcher (macOS)
├── polaris_mac_launch.sh         ← launcher logic
│
├── polaris_web/        ← the Flask application
│   ├── app.py / security.py / webauthn_auth.py / custody.py / pqc_signing.py
│   ├── templates/ static/                         ← Jinja2 templates; external-only JS and CSS
│   ├── Dockerfile / docker-compose.yml            ← dev image and dev stack
│   ├── Dockerfile.prod / docker-compose.prod.yml  ← prod image and the five-service stack
│   ├── docker-compose.bluegreen.yml               ← the zero-downtime profile
│   ├── docker-compose.ha.yml                      ← the HA profile: Patroni, etcd, HAProxy (patroni-entrypoint.sh, Dockerfile.etcd, haproxy-pg.cfg)
│   ├── Dockerfile.caddy / Caddyfile               ← self-built TLS edge (rate_limit compiled in)
│   ├── Dockerfile.pgbouncer / pgbouncer-entrypoint.sh ← self-built connection pooler (config generated at start)
│   ├── Dockerfile.postgres / pgbackrest.conf      ← database image with WAL archiving
│   └── gunicorn.conf.py                           ← prod WSGI config
├── polaris_sql/        ← schema, procedures, triggers, atlas functions, migrations/
├── polaris_zk/         ← Plonky2 ZK-SNARK Rust crate; witness2/ is the independent second witness
├── polaris_cli/        ← the operator CLI
├── polaris_checks/     ← the flat invariant layer that gates CI (README.md indexes it)
├── polaris_sim/        ← the national simulation and benchmark harness (a synthetic USA through the real pipeline)
│
├── deploy/             ← the three substrates, with README.md naming each one's limit
│   ├── helm/polaris/   ← the Kubernetes reference profile (plus kind-config.yaml for CI)
│   ├── linux/          ← install.sh and the systemd units and timers
│   └── observability/  ← Prometheus, Alertmanager, alert rules and their tests, Grafana dashboards, Tempo
├── docs/
│   ├── ARCHITECTURE-OVERVIEW.md, PRODUCTION-READINESS.md, RED-TEAM-SCOPE.md, THESIS.md, SEED_DATA.md, CONVENTIONS.md
│   ├── operator/       ← the runbooks (seventeen documents and an index)
│   ├── reference/      ← this directory
│   ├── design/         ← why it is built this way: the threat model, the mechanisms, the substrate
│   └── paper/          ← the academic report (TeX and PDF)
├── DEVNOTES/           ← the contributor's working notes: gotchas, house style, the project record
├── meta/               ← structural records (redaction proof, structural architecture, the TLA+ model)
├── scripts/            ← every shell tool (polaris-*): deploys, drills, gates, checks; the detached verifier polaris-verify.py, its vector generator, and the holder wallet polaris-wallet.py live here too
├── vectors/            ← published authenticity packs a relying party re-verifies offline with scripts/polaris-verify.py (README.md explains the format)
├── attacks/            ← adversaries that MUST fail (forge, tamper, revoked-token); run_attacks.py runs every release and goes red if any SUCCEEDS
├── sdk/                ← server-side verify SDKs a relying party installs; sdk/python and sdk/typescript are the reference verify SDKs (offline authenticity + the OAuth2 /api/v1 online check), both held to conformance/ (P3.5)
├── conformance/        ← the verification conformance suite: the published cases + a language-agnostic runner (SPEC.md); passing it is the integration contract
├── site/               ← the published project page (GitHub Pages), its logo and the Atlas captures
│
├── .github/workflows/  ← ci.yml (18 jobs), dr-drill.yml (monthly), chaos.yml (weekly), sbom.yml (per release), pages.yml (the site)
├── .github/dependabot.yml, .pre-commit-config.yaml, .gitignore, .coveragerc, .trivyignore
```

**CI jobs** ([`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)):

- `test`: the product suite against Postgres 16 and Redis; the checks layer, the DB suites, the ZK build and prove-verify round trip, the encrypted backup and restore round trip, the abuse drill, the performance smoke.
- `docker-image`: builds and smoke-boots the dev and prod images; PgBouncer, verify-ca pinning, streaming replication and pgBackRest round trips, including the off-site S3 drill.
- `caddy-edge`: builds the self-built Caddy image, validates the real prod Caddyfile, proves the X25519MLKEM768 post-quantum hybrid KEX.
- `page-drill`: the duress page path, Prometheus rules through Alertmanager to the pager webhook.
- `trace-drill`: the tracing wire drill and dashboards-as-code validation.
- `dr-drill`: kills the primary, restores from the WAL archive, measures RPO and RTO against the targets in DR.md.
- `linux-install`: the Linux server install, systemd on the runner plus Debian 12 and Rocky 9 package stages.
- `custody-pkcs11`: key custody through PKCS#11 (Kryoptic token, ML-DSA-65 in-token, two-witness verified).
- `rolling-deploy`: a rolling deploy under traffic drops zero requests (blue-green profile and control).
- `ha-failover`: the HA profile (Patroni, etcd, HAProxy) under a leader loss, a lease partition, a switchover and an etcd crash, measured under a live write stream.
- `helm-kind`: the Kubernetes reference profile boots to healthy on kind with Calico-enforced policies and restricted PSS.
- `pqc-real`: real ML-DSA-65 sign and verify (liboqs), cross-checked by the cryptography second witness.
- `federation-two-instances`: boots two independent instances, each its own database and real ML-DSA-65 root, and drives cross-authority federation over HTTP; a relying party accepts a foreign credential from a manifest, epoch checkpoint and revocation feed pulled over the wire, and the decision flips as attestations and revocations change (P3.10). The first job with both a database and real liboqs.
- `sdk-typescript`: the TypeScript verify SDK (`sdk/typescript/`) type-checked, unit-tested, and driven through the language-agnostic conformance runner (`@noble/post-quantum` ML-DSA-65 agreeing with liboqs and OpenSSL).
- `cve-scan`: dependency CVE audit (pip-audit) plus SAST (bandit).
- `image-cve-scan`: Trivy scan of the self-built prod images; gates on fixable CRITICALs.
- `prod-stack-boot`: boots the full prod compose end to end and asserts `/api/health` serves through the TLS edge.
- `ui-drill`: drives the Atlas live-simulation mode in a headless Chromium (Playwright) and asserts the console actually streams — the sim counter climbs and the Overview aggregate grows — uploading the screenshots.

`dr-drill.yml` runs the same drill monthly and commits the measured row to
[`docs/operator/DR-DRILLS.md`](../operator/DR-DRILLS.md). `chaos.yml` boots the
blue-green stack weekly, crashes one colour, stops both until `PolarisAppDown`
reaches a webhook, crashes redis and postgres, partitions pgbouncer, and commits
every recovery time to [`docs/operator/CHAOS-DRILLS.md`](../operator/CHAOS-DRILLS.md). `sbom.yml` attaches
SPDX bills of materials with SLSA provenance to every release. `pages.yml`
publishes `site/`.

---

## The three layers

### Layer 1: the product

| Directory | What |
|---|---|
| [`polaris_sql/`](../../polaris_sql/) | The schema (31 tables, 38 in a migrated deployment), procedures, triggers, atlas functions, migrations. The security boundary. |
| [`polaris_web/`](../../polaris_web/) | The Flask application: every route, the security layer, WebAuthn, custody and signing, tracing, the Atlas. |
| [`polaris_zk/`](../../polaris_zk/) | The Plonky2 Merkle-inclusion prover and verifier in Rust, and `witness2/`, the independent Python re-derivation. |
| [`polaris_cli/`](../../polaris_cli/) | The operator CLI: the same operations without a browser. |

### Layer 2: enforcement and tooling

| Directory | What |
|---|---|
| [`polaris_checks/`](../../polaris_checks/) | The flat invariant layer: plain `check_*(repo_root)` functions with detection tests; `python3 -m polaris_checks.run` gates CI. [`polaris_checks/README.md`](../../polaris_checks/README.md) maps C1-C10 to the checks that assert them. |
| [`scripts/`](../../scripts/) | Every shell tool, all `polaris-*`: deploy, backup, restore, the drills, migrations, secrets, recovery, and the contributor gates (preflight, link check, tests, coverage). [`scripts/README.md`](../../scripts/README.md) names the reader and the caller of each. |
| [`deploy/`](../../deploy/) | The three substrates: the Linux host under systemd (supported), the Kubernetes reference profile (one PostgreSQL replica), and the observability configuration. [`deploy/README.md`](../../deploy/README.md) states each one's limit. |
| [`meta/`](../../meta/) | Structural records: the redaction proof, the structural-architecture note, the TLA+ model of C3. |

### Layer 3: documentation

| Directory | What |
|---|---|
| [`docs/operator/`](../operator/README.md) | INSTALL, DEPLOYMENT, LINUX-SERVER, KUBERNETES, HARDENING, OPERATIONS, SECRETS, KEY-CEREMONY, SECURITY, PRIVACY, DR, DR-DRILLS (ledger), CHAOS-DRILLS (ledger), FAILOVER, ENCRYPTION-AT-REST, SLOS, RUNBOOKS, WEBAUTHN-ROLLOUT |
| [`docs/reference/`](README.md) | API, DATA-MODEL, PQC-POSTURE, PERFORMANCE-BASELINE, SCALING, GLOSSARY, this map |
| [`docs/`](../README.md) | ARCHITECTURE-OVERVIEW, PRODUCTION-READINESS (the bound on every claim), RED-TEAM-SCOPE, THESIS, SEED_DATA, CONVENTIONS |
| [`docs/paper/`](../paper/) | The academic report |
| [`DEVNOTES/`](../../DEVNOTES/) | The contributor's working notes: the gotcha list, the house style, the project record, and the plan of the pass in progress. The design set moved to [`docs/design/`](../design/README.md) at v9.224. |

---

## The constitutional spine

```
MISSION.md                         the constitution: C1-C10 and the vocation
polaris_checks/checks.py           the machine-checkable enforcement, gating CI
docs/PRODUCTION-READINESS.md       the bound on every claim: what is open, and who decides it
ROADMAP.md                         what comes next, phase by phase
CHANGELOG.md                       every ship, never edited retroactively
```

---

## Where do I look for X?

| Question | Look here |
|---|---|
| What is Polaris? What is it not? | [`MISSION.md`](../../MISSION.md) |
| Can it hold real identity data yet? | [`docs/PRODUCTION-READINESS.md`](../PRODUCTION-READINESS.md) |
| What is next? | [`ROADMAP.md`](../../ROADMAP.md) |
| What just shipped? | [`CHANGELOG.md`](../../CHANGELOG.md) (top entry is the latest) |
| How do I work on it? | [`CLAUDE.md`](../../CLAUDE.md), [`CONTRIBUTING.md`](../../CONTRIBUTING.md) |
| How is it built, layer by layer? | [`docs/ARCHITECTURE-OVERVIEW.md`](../ARCHITECTURE-OVERVIEW.md) |
| A cross-cutting design question (audit of record, concurrency, threat model) | [`docs/design/`](../design/README.md) |
| How does one mechanism work (duress codes, federation, the ZK proof)? | [`docs/design/`](../design/README.md) |
| A contributor's working note (gotchas, house style, the project record) | [`DEVNOTES/`](../../DEVNOTES/README.md) |
| Naming and structural conventions | [`docs/CONVENTIONS.md`](../CONVENTIONS.md) |
| The checks | [`polaris_checks/checks.py`](../../polaris_checks/checks.py) |

---

## Who reads what

| Reader | Order |
|---|---|
| An operator deploying Polaris | [INSTALL.md](../operator/INSTALL.md) or [LINUX-SERVER.md](../operator/LINUX-SERVER.md) or [KUBERNETES.md](../operator/KUBERNETES.md), then [OPERATIONS.md](../operator/OPERATIONS.md), [SECRETS.md](../operator/SECRETS.md), [DR.md](../operator/DR.md) |
| An assessor | [PRODUCTION-READINESS.md](../PRODUCTION-READINESS.md), [SECURITY.md](../operator/SECURITY-CONTROLS.md), [PRIVACY.md](../operator/PRIVACY.md), [PQC-POSTURE.md](PQC-POSTURE.md), [RED-TEAM-SCOPE.md](../RED-TEAM-SCOPE.md) |
| An integrator | [API.md](API.md), then [DATA-MODEL.md](DATA-MODEL.md) |
| A contributor, human or agent | [CLAUDE.md](../../CLAUDE.md), [MISSION.md](../../MISSION.md), then `python3 -m polaris_checks.run` |
| An academic reviewer | [the report](../paper/README.md), then [THESIS.md](../THESIS.md) |

Last regenerated: 2026-09-02 (v9.198).
