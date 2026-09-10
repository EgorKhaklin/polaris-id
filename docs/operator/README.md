# docs/operator/: the runbooks

**Reader:** the operator who installs, runs, secures and recovers a Polaris
deployment, and the assessor checking how. **Job:** one row per runbook,
saying when you need it, and the reading order for the three situations that
bring people here. Every document in this directory is listed; the build
fails otherwise.

| Runbook | When you need it |
|---|---|
| [`DEPLOYMENT.md`](DEPLOYMENT.md) | Choosing a deployment path (laptop, single host, Linux under systemd, Kubernetes), the single-host compose procedure, and the environment-variable table |
| [`LINUX-SERVER.md`](LINUX-SERVER.md) | A fresh Linux server to a healthy production stack under systemd with one script; day-2 commands, upgrades, uninstall |
| [`KUBERNETES.md`](KUBERNETES.md) | The Helm reference profile: the production topology on a cluster with enforced network policies and the restricted Pod Security Standard |
| [`INSTALL.md`](INSTALL.md) | The laptop evaluation install (the macOS launcher) and its troubleshooting |
| [`HARDENING.md`](HARDENING.md) | The operating system around Polaris: SSH, updates, firewall and Docker, time, daemon, permissions, auditing |
| [`OPERATIONS.md`](OPERATIONS.md) | Day 2: backup and restore, the running stack, scaling, monitoring, archive and purge, certificate transparency, incidents, common errors, upgrades, decommissioning |
| [`SECRETS.md`](SECRETS.md) | Every secret the stack uses, how each is generated, read and rotated, and the sealed store |
| [`KEY-CEREMONY.md`](KEY-CEREMONY.md) | The issuer signing key: custody drivers (file, PKCS#11, AWS KMS), the witnessed ceremony, rotation with trust anchors |
| [`WEBAUTHN-ROLLOUT.md`](WEBAUTHN-ROLLOUT.md) | Rolling WebAuthn MFA out to operators in phases, the attestation policy, enrollment and recovery |
| [`SECURITY.md`](SECURITY-CONTROLS.md) | The security posture: every control, where it is enforced, which check pins it, and the dated hardening engagement |
| [`PRIVACY.md`](PRIVACY.md) | Data minimization and the operational privacy posture |
| [`ENCRYPTION-AT-REST.md`](ENCRYPTION-AT-REST.md) | What is plaintext on disk, what is already encrypted, and the host volume encryption path |
| [`DR.md`](DR.md) | Disaster recovery: the targets (RPO 300 s, RTO 4 h), the procedures by failure class, WAL archiving and the off-site repository |
| [`DR-DRILLS.md`](DR-DRILLS.md) | The drill ledger, machine-appended: every measured RPO and RTO, locally and from the monthly CI run |
| [`CHAOS-DRILLS.md`](CHAOS-DRILLS.md) | The chaos ledger, machine-appended: the standing program, its five induced failures with their recovery ceilings, and every weekly run's measured recoveries and page delivery |
| [`FAILOVER.md`](FAILOVER.md) | The HA profile: Patroni-managed automated failover with its measured drill numbers and the split-brain analysis; the high-availability complement to DR.md |
| [`SLOS.md`](SLOS.md) | The reference service objectives (availability, request latency, database latency) and the error budget, grounded in exposed metrics |
| [`QUANTUM-EVENT.md`](QUANTUM-EVENT.md) | The day an algorithm falls: re-signing the whole population onto a new parameter set without any holder losing a credential that verifies, with the measured rate and where the time goes |
| [`RUNBOOKS.md`](RUNBOOKS.md) | One response runbook per shipped alert: trigger, diagnosis, remediation; and the pager wiring |

## Reading order

**Deploying for the first time.** [DEPLOYMENT.md](DEPLOYMENT.md) to choose
the path, then the path's own page ([LINUX-SERVER.md](LINUX-SERVER.md) with
[HARDENING.md](HARDENING.md), or [KUBERNETES.md](KUBERNETES.md)), then
[SECRETS.md](SECRETS.md) and [KEY-CEREMONY.md](KEY-CEREMONY.md), then the
pre-deploy checklist in [OPERATIONS.md](OPERATIONS.md#pre-deploy-checklist).
What a deployment still needs from your organization is the decision table
in [PRODUCTION-READINESS.md](../PRODUCTION-READINESS.md).

**Assessing a deployment.** [SECURITY.md](SECURITY-CONTROLS.md), [PRIVACY.md](PRIVACY.md),
[ENCRYPTION-AT-REST.md](ENCRYPTION-AT-REST.md), [DR.md](DR.md) with the
measured rows in [DR-DRILLS.md](DR-DRILLS.md) and [CHAOS-DRILLS.md](CHAOS-DRILLS.md), and
[PQC-POSTURE.md](../reference/PQC-POSTURE.md).

**During an incident.** [OPERATIONS.md](OPERATIONS.md#incident-response) for the
first steps, [RUNBOOKS.md](RUNBOOKS.md) for the alert that fired,
[DR.md](DR.md#4-procedures-by-failure-class) for the failure class.

**Day to day.** The cron and timer rows in
[OPERATIONS.md](OPERATIONS.md#day-2-operations); `/api/health` for structured
health; `/metrics` for Prometheus.
