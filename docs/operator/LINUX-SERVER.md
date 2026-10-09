# LINUX-SERVER.md: a fresh Linux server to a healthy Polaris stack

**Reader:** the operator installing Polaris on a real Linux host. **Job:** take
a fresh Debian, Ubuntu, or RHEL-family server to the full production stack
under systemd with one script, and know everything around that script. If you
are evaluating on a laptop, use [`INSTALL.md`](INSTALL.md) instead.

## What you need

| | Requirement |
|---|---|
| OS | Debian 12+, Ubuntu 22.04+, or RHEL 9 family (Rocky, Alma, RHEL), 64-bit, with systemd |
| Size | 2 vCPU, 4 GB RAM, 40 GB disk to start ([`OPERATIONS.md`](OPERATIONS.md) "System requirements" for growth) |
| Network | TCP 80 and 443 (and UDP 443 for HTTP/3) reachable from the internet; nothing else published |
| DNS | An A/AAAA record for your `POLARIS_DOMAIN` pointing at this host, live BEFORE the first start (Caddy provisions the Let's Encrypt certificate on boot) |
| Access | root or sudo; outbound HTTPS to Docker's repositories, GitHub, and Let's Encrypt |

Time must be correct (TLS and the anchoring chain depend on it); the installer
does not manage NTP, [`HARDENING.md`](HARDENING.md) does.

## Install (three commands)

```bash
sudo apt-get install -y git      # dnf install -y git on RHEL family
git clone https://github.com/EgorKhaklin/polaris-id.git /opt/polaris
sudo POLARIS_DOMAIN=polaris.example.org /opt/polaris/deploy/linux/install.sh
```

The script is idempotent; re-running it skips what is already done. What it
does, in order:

1. **packages**: Docker Engine and the compose plugin from Docker's official
   apt or dnf repository, after verifying the signing key's fingerprint
   (deb: `9DC8 5822 9FC7 DD38 854A E2D8 8D81 803C 0EBF CD88`; rpm:
   `060A 61C5 1B55 8A7F 742B 77AA C52F EB6B 621E 9F35`; they differ, and the
   installer refuses a key that does not match its family). It never pipes a
   download into a shell. Skipped if `docker compose` already works.
2. **app**: the repository at `/opt/polaris` (it is already there if you cloned
   as above), the production images built, secrets generated into
   `polaris_web/secrets/` (a 0700 directory; see [`SECRETS.md`](SECRETS.md)),
   `/etc/polaris/polaris.env` written from
   [`deploy/linux/polaris.env.example`](../../deploy/linux/polaris.env.example),
   the systemd units installed and enabled, the stack started, migrations and
   database objects synced, and `/api/health` asserted healthy through the TLS
   edge.

Expect 5 to 10 minutes on first run (the app image builds liboqs for ML-DSA-65).
It ends with:

```
  ok   healthy through the TLS edge: https://polaris.example.org/api/health
  Polaris is running under systemd.
```

Then log in and rotate the seeded accounts immediately
([`DEPLOYMENT.md`](DEPLOYMENT.md#the-first-operator-account)), and register the signing key before
the first credential is issued ([`DEPLOYMENT.md`](DEPLOYMENT.md#the-signing-keys-registration)):
until then a relying party's verification of every credential answers "not a verifiable presentation".

## What is installed

| Unit | What it does |
|---|---|
| `polaris.service` | The production compose stack. `ExecStart` is `docker compose up -d`; enabled at boot; `Requires=docker.service`. |
| `polaris-backup.timer` and `.service` | Daily 03:00 UTC `scripts/polaris-backup.sh --dest /var/backups/polaris` (a `pg_dump` tarball with a SHA-256 manifest). |
| `polaris-backup-verify.timer` and `.service` | Sunday 04:00 UTC: the newest tarball extracted and hash-verified. |
| `polaris-restore-verify.timer` and `.service` | Sunday 06:00 UTC: `scripts/polaris-restore-verify.sh`, the newest pgBackRest backup and the archive after it restored into a scratch copy and proven against the live database, recorded for the PolarisRestoreUnverified alert ([`DR.md`](DR.md) section 6). |
| `polaris-dr-drill.timer` and `.service` | The 1st at 05:00 UTC (v9.192): the DR drill on scratch containers, RPO and RTO measured against the targets and appended to `/var/lib/polaris/dr-drills.md` ([`DR-DRILLS.md`](DR-DRILLS.md) explains the row). Never touches the production stack. |

Files: `/opt/polaris` (the checkout, root-owned), `/etc/polaris/polaris.env`
(0600; the only configuration), `/var/backups/polaris` (local backups; ship
them offsite or enable the pgBackRest S3 repo, [`DR.md`](DR.md)).

## Operate

```bash
systemctl status polaris                 # the stack
journalctl -u polaris -e                 # compose output at start/stop
cd /opt/polaris/polaris_web && docker compose -f docker-compose.prod.yml ps   # containers
docker logs polaris-app --tail 100       # per container: polaris-app, polaris-caddy, polaris-postgres, polaris-pgbouncer, polaris-redis
systemctl list-timers 'polaris-*'        # next backup / verify
systemctl start polaris-backup           # a backup now
sudo -e /etc/polaris/polaris.env && systemctl restart polaris   # change WEB_CONCURRENCY, point archiving offsite, ...
```

**The scripts read `polaris.env`.** Run the scripts under `scripts/` as root
(`sudo`). Each one reads `/etc/polaris/polaris.env`, as `polaris.service` does,
so a deploy, a rotation or a new operator account runs with the domain, overlays
and secrets the unit starts with; a variable set on the command line wins.

**Upgrade**: `cd /opt/polaris && sudo scripts/polaris-deploy.sh prod`. It
pulls, rebuilds the app image, applies migrations, smoke-tests `/api/health`,
and rolls back the app image if the smoke test fails. It operates on the same
compose project systemd started, so `systemctl status polaris` stays accurate.

**Offsite backups**: WAL archiving and the base backups are on by default, to
a local repository that does not survive the host. Set `POLARIS_PGBACKREST_S3_*`
in `polaris.env`, put the key pair in
`polaris_web/secrets/pgbackrest_repo_creds.conf`, then
`scripts/polaris-deploy.sh prod` ([`DR.md`](DR.md)).

**Zero-downtime deploys**: add `-f docker-compose.bluegreen.yml` to
`POLARIS_COMPOSE_EXTRA` in `polaris.env` and deploy once; from then on
`polaris-deploy.sh prod` rolls the two app colours behind Caddy without dropping
requests ([`OPERATIONS.md`](OPERATIONS.md), "Zero-downtime deploys").

**Automated database failover**: add `-f docker-compose.ha.yml` as well and the
database runs as two Patroni members with a leader lease in etcd behind
HAProxy; a lost leader is replaced within the lease and a returning one
rejoins as a replica ([`FAILOVER.md`](FAILOVER.md)). On one host this proves
the mechanism; the members belong on separate hosts, which is your placement.

**Sealed secrets**: until you seal them, the secrets are plaintext files in
`polaris_web/secrets/` on this disk, and `polaris-doctor.sh` and every start say
so. Set `POLARIS_SECRETS_BACKEND=age` (or `awskms`),
`POLARIS_SECRETS_DIR=/run/polaris/secrets`, and the identity/recipients (or key
id) lines in `polaris.env`; `polaris.service` unseals into a tmpfs there before
every start and the plaintext directory can be shredded
([SECRETS.md, section 5](SECRETS.md#5-the-sealed-secret-store), which also says
what a copy of the disk still holds in each setup).

**Paging**: mount your pager URL into Alertmanager per
[`RUNBOOKS.md`](RUNBOOKS.md) "Paging". The Prometheus and Alertmanager
configs are in [`deploy/observability/`](../../deploy/observability/README.md).

## Harden the host

The installer configures Polaris, not the operating system. Work through
[`HARDENING.md`](HARDENING.md) before the host carries real data: SSH, updates,
firewall (and Docker's relationship to it), time, the Docker daemon, file
permissions, auditing, and `/metrics` exposure.

## Uninstall

```bash
sudo systemctl disable --now polaris polaris-backup.timer polaris-backup-verify.timer polaris-restore-verify.timer polaris-dr-drill.timer
cd /opt/polaris/polaris_web && sudo docker compose -f docker-compose.prod.yml down -v   # -v deletes the database
sudo rm -f /etc/systemd/system/polaris*.service /etc/systemd/system/polaris*.timer && sudo systemctl daemon-reload
sudo rm -rf /opt/polaris /etc/polaris                     # keep /var/backups/polaris if you want the backups
```

## Known caveats

- **RHEL family with SELinux enforcing**: Docker bind mounts of the secrets and
  config files can be denied. Either run the stack with SELinux permissive for
  Docker, or label the checkout (`chcon -Rt svirt_sandbox_file_t /opt/polaris`).
  The installer does not change SELinux policy for you.
- **ufw/firewalld and Docker**: Docker publishes 80/443 by writing its own
  iptables rules, bypassing ufw. That is fine here because those are the only
  published ports; do not rely on ufw to hide a port you publish in compose.
  [`HARDENING.md`](HARDENING.md) covers it.
- **No public DNS yet**: Caddy will retry ACME and the site stays unreachable
  until the record resolves. For an internal-only evaluation, set
  `POLARIS_COMPOSE_EXTRA="-f docker-compose.citest.yml"` in `polaris.env` and
  the edge serves `https://localhost:8443` under Caddy's internal CA; that is
  exactly what CI does.

## How this is tested

The `linux-install` CI job runs on every push: the **packages** stage executes
for real inside Debian 12 and Rocky Linux 9 containers (both repository
branches, key verification included), and the **full installer** runs on the
Ubuntu runner with real systemd: `/opt/polaris`, secrets, units, `systemctl
start polaris`, migrations, `/api/health` healthy through the TLS edge,
`systemctl start polaris-backup` producing a tarball, and health again after
`systemctl restart polaris`. What CI cannot exercise is ACME against a public
domain; it uses the internal-CA edge (`docker-compose.citest.yml`), which
differs from production only in who signs the certificate.
