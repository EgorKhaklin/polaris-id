# scripts/: every shell tool, and who runs it

**Reader:** an operator running a deployment, a contributor before a commit, or
anyone reading a CI job and wondering what it just invoked.
**Job:** one index, with the reader and the caller of every script, so nothing
here has to be opened to find out who it is for.

One naming rule: `polaris-<verb>.sh` for shell tools, `polaris_<name>.py` for
the Python helpers a shell script shells out to. The reader is stated here and
in each script's header, not encoded in its name. Every script's first comment
block after the shebang is its documentation, and `--help` prints it.

## Operator: run against a real deployment

| Script | What it does | Called by |
|---|---|---|
| `polaris-deploy.sh` | Idempotent production deploy of the compose stack | An operator; `deploy/linux/install.sh` |
| `polaris-generate-secrets.sh` | Mints the secret material, including the ML-DSA-65 signing key | An operator, once, before the first deploy |
| `polaris-secrets.sh` | The sealed secret store: put, get, list, seal | An operator; `polaris_web/secretstore.py` documents the format |
| `polaris-rotate-secret.sh` | Rotates one secret in place, without a redeploy | An operator |
| `polaris-backup.sh` | Atomic full-system backup, encrypted, with a manifest | An operator; the cron wiring |
| `polaris-restore.sh` | Recovery from a backup, verifying the manifest first | An operator, under `DR.md` |
| `polaris-archive.sh` | Selective export of audit rows to cold storage; `--from-policy` takes a cutoff per retention class | `polaris-rotate-logs.sh` |
| `polaris-purge.sh` | Archive-then-delete for aged audit rows; verifies the archive against its manifest and honours per-class cutoffs | `polaris-rotate-logs.sh` |
| `polaris-rotate-logs.sh` | The yearly archive-and-purge wrapper | `polaris-cron-install.sh` |
| `polaris-cron-install.sh` | Installs the operator crontab wiring | An operator, once |
| `polaris-create-operator.sh` | Onboards an operator account | An operator; `polaris_web/docker-init.sh` bootstraps the first admin |
| `polaris-recover-admin.sh` | Emergency password-only login for a locked-out admin | An operator, under `RUNBOOKS.md` |
| `polaris-generate-recovery-code.sh` | Mints a printed-mnemonic recovery code | An operator, at enrolment |
| `polaris-set-webauthn-deadline.sh` | Sets `webauthn_required_after` for an account | An operator, during the MFA rollout |
| `polaris-pseudonymize-individual.sh` | The right-to-erasure wrapper over `uc_pseudonymize_individual` | An operator, under a recorded policy |
| `polaris-migrate.sh` | Applies or reverts migrations under lock and statement timeouts | An operator; `deploy/linux/install.sh` |
| `polaris-ct-monitor.sh` | Certificate Transparency monitor for the deployment domain | The cron wiring |
| `polaris-pqc-status.sh` | Reports whether real post-quantum signing is available here | An operator, diagnosing a signing failure |

## CI: run on every push, and by an operator reproducing a claim

| Script | What it proves | Called by |
|---|---|---|
| `polaris-image-build.sh` | Builds one image, or the four-image set, retried and version-stamped | Every image build in both workflows |
| `polaris-coverage.sh` | Runs the database-backed suites under coverage and gates on the floor | `ci.yml` |
| `polaris-link-check.sh` | Every cross-reference, HTML attribute and repository link resolves | `ci.yml`, `pages.yml`, `polaris-preflight.sh`, pre-commit |
| `polaris-dr-drill.sh` | Kills a primary, restores from the WAL archive, measures RPO and RTO | `ci.yml`, `dr-drill.yml`, the monthly timer |
| `polaris-offsite-drill.sh` | The S3 backup and restore path, end to end | `ci.yml` |
| `polaris-rolling-drill.sh` | A rolling deploy drops zero requests | `ci.yml` |
| `polaris-window-drill.sh` | An edge configuration reload drops nothing; edge and database recreation windows measured against ceilings | `ci.yml` |
| `polaris-failover-drill.sh` | The HA profile under induced failures: the leader crashed, cut off from the lease store, switched over, an etcd member crashed, each measured under a live write stream against a ceiling | `ci.yml` |
| `polaris-partition-drill.sh` | The event tables' partitioning: a future row lands in a monthly partition, append-only holds across a partition/attach/detach, a populated table converts in place, retention routes across partitions | `ci.yml`, on every push |
| `polaris-partition-maintenance.sh` | Premake the event tables' monthly partitions ahead of time on the running stack | `polaris-partition-maintenance.timer`, monthly |
| `polaris-helm-drill.sh` | The Kubernetes profile boots healthy with policies enforced | `ci.yml` |
| `polaris-page-drill.sh` | A duress event reaches the pager webhook | `ci.yml` |
| `polaris-chaos-drill.sh` | Induced failures against the booted stack under traffic: one colour killed, both stopped until the outage pages, redis and postgres killed, pgbouncer partitioned, every recovery measured against a ceiling | `chaos.yml`, weekly and on demand |
| `polaris-abuse-drill.sh` | The per-agency quotas refuse writes under real load | `ci.yml` |
| `polaris-retention-drill.sh` | The archive and purge chain, per retention class, end to end | `ci.yml` |
| `polaris-trace-drill.sh` | Tracing joins logs to spans, and the dashboards load | `ci.yml` |
| `polaris-perf-baseline.sh` | The published latency baseline, re-measured in smoke mode | `ci.yml` |
| `polaris-custody-pkcs11-drill.sh` | ML-DSA-65 signing inside a PKCS#11 token | `ci.yml`'s custody job |
| `polaris-verify.py` | The detached verifier: an ML-DSA-65 authenticity pack verifies offline with only a standard ML-DSA library, no Polaris code and no database. `--status-assertion` (P3.6) additionally decides AUTHORIZATION offline against a short-lived signed status assertion (fresh + bound + ACTIVE, window-bounded). `--selftest` and `--verify-dir vectors` run in pqc-real | `ci.yml`, and any relying party with no Polaris installed |
| `polaris-make-vectors.py` | Generates the published authenticity vectors (`vectors/`), preferring liboqs and falling back to an independent FIPS-204 implementation | A contributor regenerating `vectors/` |
| `polaris-federation-drill.py` | Two issuers on one box with distinct ML-DSA-65 roots plus a third outsider; proves via the detached verifier that each relying party accepts its own issuer and rejects a foreign one (PE.3), red if the boundary breaks | `ci.yml`'s pqc-real job |
| `polaris-federation-manifest-drill.py` | Inter-authority protocol (P3.2) run end to end: two authorities with distinct real ML-DSA-65 roots publish signed federation manifests, and a relying party accepts a FOREIGN credential offline iff a trusted authority attests to its key in the presented context (wrong-context/un-attested/untrusted/stranger-signed/expired/forged all reject). Red on any wrong decision | `ci.yml`'s pqc-real job |
| `polaris-epoch-revocation-drill.py` | Epoch alignment and revocation propagation (P3.2b) run end to end: two authorities publish signed epoch checkpoints and revocation feeds, and the detached verifier catches a FORK (two roots at one epoch number), catches a ROLLBACK (a feed that drops a revocation), and rejects a REVOKED foreign credential offline with no issuer contact. Red on any wrong decision; no database | `ci.yml`'s pqc-real job |
| `polaris-federation-instances-drill.py` | Federation across the DEPLOYMENT boundary (P3.10): boots two independent instances (gunicorn), each its own database and real ML-DSA-65 root, and drives the cross-authority matrix OVER HTTP -- cross-verification from a fetched manifest, attestation revocation, and anchor cross-checks (epoch checkpoint + revocation feed). Needs two loaded databases; launches and tears down the instances itself. Red on any wrong decision | `ci.yml`'s federation-two-instances job |
| `polaris-transparency-monitor.py` | The independent transparency-log monitor (P3.3): follows a Polaris log over HTTP, verifies each Signed Tree Head against a trust anchor, and proves append-only consistency from the last head it saw; ALERTs (non-zero exit) on a rewrite, fork, shrink, or wrong-key head. Standalone (stdlib + the detached verifier), read-only | Anyone auditing a log; exercised by the transparency drill |
| `polaris-transparency-drill.py` | The transparency log and its monitor under attack (P3.3): proves the detection engine (`verify_log_consistency` accepts an append-only extension, rejects rewrite/fork/shrink/wrong-key) AND runs the actual monitor daemon over HTTP against a live log that is then tampered, asserting it exits 0 while the log only appends and ALERTs the moment it is rewritten. Real ML-DSA; no database | `ci.yml`'s pqc-real job |
| `polaris-transparency-witness.py` | A transparency-log witness (P3.3b), the split-view defence: follows a log, COSIGNS a consistent head with its own key (so a relying party can require K independent cosignatures), refuses a fork, gossips the head it saw into a shared pool, and ALERTs with a written equivocation proof on a rewrite or a gossip-detected split view | Anyone witnessing a log; exercised by the gossip drill |
| `polaris-transparency-gossip-drill.py` | Witnesses and the split-view attack (P3.3b): three witnesses cosign a head to a relying party's threshold, then a fork is caught two ways -- a witness refuses a second head at a size it already cosigned, and a fresh witness catches the split view by gossip -- each producing a non-repudiable equivocation proof. Real ML-DSA; no database | `ci.yml`'s pqc-real job |
| `polaris-transparency-ledger.py` | An external publication ledger (P3.3c): a file-backed APPEND-ONLY bulletin (`POLARIS_LEDGER_BACKEND=file`; `algorand-pq`/`hyperledger-indy` declared) that records a log head (`append --sth`) and emits an inclusion RECEIPT -- its own signed tree head plus a proof the head is a leaf in it. A ledger is itself an append-only log, so it reuses the transparency Merkle machinery | A log publishing its heads to an independent pin; exercised by the publication drill |
| `polaris-transparency-publication-drill.py` | External-ledger publication under attack (P3.3c): the actual ledger records a log's heads and the verifier confirms each receipt; a forged, wrong-key, or unrecorded-head receipt is rejected; and the ledger dropping a head it recorded is caught. Real ML-DSA; no database | `ci.yml`'s pqc-real job |
| `polaris-wallet.py` | The holder's wallet (PE.7), the first non-operator surface: hold a credential as a file, verify it offline, present it (a duress presentation is indistinguishable from a normal one), and prove membership in zero knowledge. Standalone — no server code, no database | A holder; `test_wallet.py` in CI |
| `polaris-relying-party.py` | The other end of the flow: takes a holder's presentation and decides ACCEPT or REJECT by combining OFFLINE authenticity (the detached verifier, optionally against an issuer anchor) with ONLINE status. Accept needs both; offline it is only PROVISIONAL. `--oauth-client-id/--oauth-client-secret` (P3.4) authenticate to the issuer's `/api/v1` as a registered organization instead of borrowing an operator login. Standalone — only stdlib and the verifier | A relying party (a bank, a kiosk); `test_relying_party.py` under the coverage gate |
| `polaris-e2e-drill.py` | The whole holder-to-verifier flow run end to end: a real ML-DSA-65 credential is presented and the relying party is driven through the decision matrix (active accepted, revoked/tampered/foreign rejected, offline provisional, duress indistinguishable). Red if any decision is wrong | `ci.yml`'s pqc-real job |
| `polaris-offline-status-drill.py` | Offline verification (P3.6) run end to end: signs a credential and status assertions with one real ML-DSA-65 key and drives the detached verifier through the offline accept/reject matrix (active/revoked/expired/over-long-window/tampered/misbound/untrusted). Red on any wrong decision; no database | `ci.yml`'s pqc-real job |
| `polaris-dyno.py` | Real numbers from the box (PE.8): single-core ML-DSA-65 sign/verify (single- and two-witness) and ZK prove/verify at the tree depth, printed with the box spec and version; measured, not extrapolated ([DYNO.md](../docs/reference/DYNO.md)) | `ci.yml` (pqc-real: ML-DSA; test: ZK), and anyone on their own box |
| `polaris-kat-verify.py` | ML-DSA-65 conformance: verifies the committed Wycheproof known-answer vectors (`vectors/kat/`) under both production witnesses and asserts each matches Wycheproof's valid/invalid verdict | `ci.yml`'s pqc-real job |
| `polaris-fetch-kat.py` | Regenerates `vectors/kat/mldsa_65_verify.json` from Project Wycheproof at a pinned commit (empty-context subset, capped per flag-set) | A contributor refreshing the KAT set |

## Contributor: run before a commit

| Script | What it does | Called by |
|---|---|---|
| `polaris-preflight.sh` | The pre-ship gate: the invariant layer plus the link check | A contributor, before every commit |
| `polaris-test.sh` | One-shot runner for the database-backed suites, with the env set | A contributor; `polaris-coverage.sh` |
| `polaris-release-notes.sh` | Renders a release body from the CHANGELOG entry | A contributor, at release time |
| `polaris-authz-audit.sh` | The who-can-do-what report across all four authorization surfaces | A contributor or an assessor; `RED-TEAM-SCOPE.md` points here |
| `polaris-chaos-test.sh` | Fault injection, asserting the system fails safe rather than open | `ci.yml`, on every push |
| `polaris-load-test.sh` | HTTP load generation against a running instance | A contributor, by hand |
| `polaris-atlas-benchmark.sh` | The Atlas endpoints against a multi-million-event log | A contributor, reproducing `SCALING.md` |

## Python helpers

| Script | What it does | Called by |
|---|---|---|
| `polaris_authz_audit.py` | The report itself; the shell wrapper handles arguments and output | `polaris-authz-audit.sh` |
| `polaris_load_gen.py` | Async load generator, standard library only | `polaris-load-test.sh`, `polaris-abuse-drill.sh` |

Several of these are pinned by `polaris_checks`: a check asserts the script
exists and still does what a document claims it does, and its detection test
fails on a broken fixture. Renaming one means updating its check in the same
commit.
