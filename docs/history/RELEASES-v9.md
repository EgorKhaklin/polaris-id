# The v9 releases, 2026-05-16 to 2026-09-15

**Reader:** anyone holding a `v9.x` version number from the paper, the scoreboard, a CHANGELOG
entry or an old link. **Job:** map every one of those numbers to the commit it named, because the
tags and GitHub releases that carried them were removed on 16 September 2026.

Why they were removed: v9 numbered ships, not externally observable change. 295 tags and
294 releases in four months, most of them one commit apart, and the number stopped telling a
stranger anything. The tree moved to 1.0.0-rc.1 under the go-forward contract, which versions only
what an outside party can observe, and the retired series was cleared from the front door rather
than left as 294 entries under the one that matters.

What was kept: every commit is on `main`, so `git checkout <commit>` reproduces any row below; the
entry each release carried as its notes is in [CHANGELOG-v9.md](CHANGELOG-v9.md) or the root
[CHANGELOG.md](../../CHANGELOG.md), under the same version heading; and this table. What was not:
the release URLs, and the SBOM files attached to 180 of the releases by the SBOM workflow. The
author archived those files before deleting the releases; they are not published anywhere. The
workflow attaches SBOMs to every release cut from here on, starting with v1.0.0-rc.1.

| Version | Date | Commit | Subtitle |
|---|---|---|---|
| v9.30 | 2026-05-16 | `854c3ca` | (tag only; no release was cut) |
| v9.30.1 | 2026-05-16 | `85073d3` | publish-readiness polish |
| v9.41 | 2026-05-18 | `10b9c67` | AoR reclassification + v9.x release marker |
| v9.43 | 2026-05-20 | `07d97ad` | Class-shaped bash bug: grep -c double-output fix |
| v9.49 | 2026-06-03 | `0c6fafa` | Polaris v9.49 |
| v9.56 | 2026-06-04 | `57eb977` | the de-larp: the product, standing clean |
| v9.57 | 2026-06-04 | `920af2d` | documentation prune: less is more |
| v9.58 | 2026-06-04 | `5b0d1fd` | post-quantum signing wired into issuance |
| v9.59 | 2026-06-04 | `195dd75` | professional cleanup: cut the agent-governance scaffolding |
| v9.60 | 2026-06-04 | `03e7f68` | ZK anonymity set: from a 16-leaf demo to a full epoch |
| v9.61 | 2026-06-04 | `119b285` | polaris_checks: complete the C1-C10 coverage |
| v9.62 | 2026-06-04 | `ace4945` | ROADMAP: a forward roadmap, not a ship archive |
| v9.63 | 2026-06-04 | `08f00e0` | reference-clean: no source comment points at a deleted file |
| v9.64 | 2026-06-04 | `2c8e07c` | uc4 reserve activation works for every reason code |
| v9.65 | 2026-06-04 | `66998b1` | the demo ZK epoch verifies, and CI proves it |
| v9.66 | 2026-06-04 | `d168262` | harden the login redirect and the session cookie |
| v9.67 | 2026-06-04 | `b5c9c07` | test rigor: fail-loud PQC and an externally-anchored second witness |
| v9.68 | 2026-06-04 | `44bf0b8` | consistency: a true table count, a version module that points only at live things |
| v9.69 | 2026-06-04 | `447d180` | ZK verify route: local-clock epoch boundary, honest replay scope |
| v9.70 | 2026-06-04 | `3de4adb` | close the cross-site drive-by on the launcher control endpoints |
| v9.71 | 2026-06-04 | `43a138d` | recovery ceremony: works for reserve-only holders, and three channels means three actors |
| v9.72 | 2026-06-04 | `136e952` | WebAuthn second factor can actually complete |
| v9.73 | 2026-06-04 | `723d357` | uc4/uc10: validate under the lock, not before it |
| v9.74 | 2026-06-04 | `d8c31bb` | the lockout message is no longer a username oracle |
| v9.75 | 2026-06-04 | `d8c31bb` | CLI: the read-only query is actually read-only, and bad args fail cleanly |
| v9.76 | 2026-06-04 | `d8c31bb` | /api/health stops leaking infrastructure detail to anonymous callers |
| v9.77 | 2026-06-04 | `f6860e2` | C6: a ZK verification's location is redacted at every read path |
| v9.78 | 2026-06-04 | `b8bad1c` | atlas event feed: a full-precision cursor stops dropping sub-second events |
| v9.79 | 2026-06-04 | `b8bad1c` | schema completeness: 01_schema.sql declares every column the app writes |
| v9.80 | 2026-06-04 | `57c2e68` | operator scripts: validate argv to close four SQL injections |
| v9.81 | 2026-06-04 | `2b227b6` | the no-cascade invariant now covers migrations, and the one live cascade is resolved |
| v9.82 | 2026-06-04 | `2b8c235` | duress: record off the request thread so the response time reveals nothing |
| v9.83 | 2026-06-04 | `2b8c235` | bound three unbounded resources an attacker could grow |
| v9.84 | 2026-06-04 | `e23b4c2` | uc1 refuses deprecated algorithms; the ZK prover bounds-checks its index |
| v9.85 | 2026-06-04 | `3c5e28b` | C1 append-only becomes a privilege boundary, not only a trigger |
| v9.86 | 2026-06-04 | `22f96d8` | prod syncs the polaris_app role password to the generated secret |
| v9.87 | 2026-06-04 | `eba1660` | pass 6: close the two trust-boundary gaps prior passes left |
| v9.88 | 2026-06-04 | `0e79966` | pass 7 converges: a false redaction comment, and a Vocation guard for the evidence trail |
| v9.89 | 2026-06-04 | `38ec6c3` | real anti-replay: /api/zk/verify consumes a single-use nonce |
| v9.90 | 2026-06-04 | `ab7a860` | CI: bump the deprecated Node 20 actions ahead of the deadline |
| v9.91 | 2026-06-05 | `af6c4d5` | honesty: the thesis terminus passed, so the docs now say so |
| v9.92 | 2026-06-05 | `0ca2934` | un-stale the README table count, and guard it |
| v9.93 | 2026-06-05 | `c64d230` | the macOS launcher: current, faster, and pinned |
| v9.94 | 2026-06-05 | `f963b7f` | Docker image was missing pqc_signing.py: crash-loop fixed and guarded |
| v9.95 | 2026-06-05 | `ac9acd1` | CI now builds and boots the Docker image |
| v9.96 | 2026-06-05 | `a7d86b1` | the launcher tells you WHY it failed |
| v9.98 | 2026-06-05 | `07daa85` | the production image could not be built: fixed and CI-validated |
| v9.100 | 2026-06-05 | `8580121` | a successful restore looked like a failure: DR path fixed + CI-validated |
| v9.101 | 2026-06-05 | `4939a78` | production-readiness wave 1: no default credentials, real rate limiting, honest roadmap |
| v9.102 | 2026-06-05 | `a88007b` | production-readiness wave 3: encrypted backups, honest DR doc |
| v9.103 | 2026-06-05 | `3b3a162` | production-readiness wave 2: real ML-DSA-65 signing, persistent key, tested in CI |
| v9.104 | 2026-06-05 | `c3c8606` | the /sql console is read-only at the engine, not just the keyword gate |
| v9.105 | 2026-06-05 | `fb49964` | no test frameworks in the prod image; dependency CVE scanning gates the build |
| v9.106 | 2026-06-05 | `7b7b84c` | migrations bound their lock + statement time so one ALTER cannot stall the site |
| v9.107 | 2026-06-05 | `91caeba` | WEB_CONCURRENCY is no longer an inert knob |
| v9.108 | 2026-06-05 | `02191b8` | liveness and readiness are separate health probes |
| v9.109 | 2026-06-05 | `2e2a040` | every prod container bounds its memory, CPU, and logs |
| v9.110 | 2026-06-05 | `34d484e` | self-built pgbouncer (the bitnami image was removed from Docker Hub) |
| v9.111 | 2026-06-05 | `f54a5b4` | CI builds + round-trips the self-built pgbouncer image |
| v9.112 | 2026-06-05 | `a0be1c3` | SAST in CI catches a world-writable state dir |
| v9.113 | 2026-06-05 | `58ac401` | signature verification is enforced, not just possible |
| v9.114 | 2026-06-05 | `d3e2d1c` | pin prod images by digest, not a mutable tag |
| v9.115 | 2026-06-05 | `ee39231` | alerting rules are a shipped, validated artifact |
| v9.116 | 2026-06-05 | `631ca10` | real ML-DSA-65 is the production default |
| v9.117 | 2026-06-05 | `e081b0c` | issuer public key is a DB trust anchor; verification surfaced at use |
| v9.118 | 2026-06-05 | `788caa4` | procedure/trigger changes reach an UPGRADED database, not just a fresh one |
| v9.119 | 2026-06-05 | `1f83ef7` | uc6 migration routes through the signing module (Wave 2 complete) |
| v9.120 | 2026-06-05 | `2840087` | Prometheus metrics aggregate across gunicorn workers |
| v9.121 | 2026-06-05 | `b900775` | app↔DB TLS on both hops |
| v9.122 | 2026-06-05 | `29b503e` | request-correlation ids that cannot become a surveillance key |
| v9.123 | 2026-06-05 | `5af8a25` | SLOs + one runbook per alert, grounded and honest |
| v9.124 | 2026-06-05 | `60bf723` | at-rest encryption posture, documented and pinned |
| v9.125 | 2026-06-06 | `f34b70f` | right-to-erasure that respects the audit |
| v9.126 | 2026-06-06 | `e397a0d` | streaming-replication readiness + a failover runbook |
| v9.127 | 2026-06-06 | `2b841a2` | continuous WAL archiving with pgBackRest |
| v9.128 | 2026-06-06 | `b390fa3` | the duress signal is now alertable |
| v9.129 | 2026-06-06 | `f8c6d32` | fail closed on production misconfiguration |
| v9.130 | 2026-06-06 | `46b0fce` | pgBackRest operational safety |
| v9.131 | 2026-06-06 | `098f760` | both DB hops verify the pinned certs (verify-ca) |
| v9.132 | 2026-06-06 | `f6f5dc3` | enforce verify-ca at startup |
| v9.133 | 2026-06-06 | `2b98401` | two-witness the ML-DSA-65 verify path |
| v9.134 | 2026-06-06 | `ed08e2d` | honest post-quantum posture audit |
| v9.135 | 2026-06-06 | `787ee28` | the production TLS edge actually starts |
| v9.136 | 2026-06-06 | `73c9fab` | proven: the client-to-edge TLS hop does post-quantum hybrid KEX |
| v9.137 | 2026-06-06 | `59b2c72` | precision: the internal-hop PQ gate is measured, two limiters not one |
| v9.138 | 2026-06-06 | `5d35836` | scan the container images for CVEs, and patch the fixable ones |
| v9.139 | 2026-06-06 | `10a533f` | fix a real deploy-blocker: the liboqs banner corrupted the generated signing key |
| v9.140 | 2026-06-06 | `524253a` | the full production stack now boots end to end (and four prod-down bugs it found) |
| v9.141 | 2026-06-10 | `2176136` | container hardening: every prod service drops all Linux capabilities |
| v9.142 | 2026-06-12 | `d20fc1b` | full UI redesign, README rewrite, GitHub Pages site, and an 11-bug fix sweep |
| v9.143 | 2026-06-12 | `216caea` | the Atlas becomes fully operational + a role-gate/alignment sweep, proven by crawler tests and Lighthouse |
| v9.144 | 2026-06-12 | `def5daf` | Atlas console rework: full-viewport command surface |
| v9.145 | 2026-06-12 | `291debe` | Atlas futurization: fullscreen, ultra zoom to 40x, pinpoint coordinates |
| v9.146 | 2026-06-12 | `bdf3fe6` | Atlas becomes a real street-level map: MapLibre globe→street, OpenStreetMap basemap, operational agency filter |
| v9.147 | 2026-06-12 | `c3afe7e` | Atlas fixes: open over the data, no false "feed interrupted", no HUD overlap |
| v9.148 | 2026-06-12 | `630f61b` | Subject-focus: single-subject investigation on the map, and the privacy guarantee it demonstrates |
| v9.149 | 2026-06-12 | `00b533e` | Cinematic README + GitHub page: the Atlas, on the front page |
| v9.150 | 2026-06-12 | `736e681` | Scale proof: the Atlas measured at 10 million events |
| v9.151 | 2026-06-12 | `83aa3ab` | Subject-focus bug fix + activation events on the map + token data export + richer node detail |
| v9.152 | 2026-06-12 | `0ae5d09` | Fix "ATLAS FEED INTERRUPTED": the launcher now refreshes code objects on every launch |
| v9.153 | 2026-08-31 | `ac90c4c` | Operator-tooling sweep: exercising the un-swept scripts found seven runtime defects |
| v9.154 | 2026-08-31 | `982a698` | The local test runner never worked: a silent reload turned one permission error into 200 |
| v9.155 | 2026-08-31 | `dd18b00` | CVE sweep: the Python surface, the Caddy image, and the CI pin that would have undone it |
| v9.156 | 2026-08-31 | `ca984af` | Front-page redesign: the README and the site now lead with the macro |
| v9.157 | 2026-08-31 | `aaaf89d` | A nondeterministic CI assertion: the verify-ca probe lost a coin flip on a healthy stack |
| v9.158 | 2026-08-31 | `08ed813` | The deployment roadmap: a recorded decision opening the path to national scale |
| v9.159 | 2026-08-31 | `2f76f85` | ATLAS FEED INTERRUPTED, again: the v9.152 fix never covered the launcher's default path |
| v9.160 | 2026-08-31 | `f38661d` | Roadmap P0.1 + P0.2: the dated nightly, and the e2e suite that rotted because it never ran |
| v9.161 | 2026-08-31 | `c29ca95` | Roadmap P0.3: nineteen Dependabot PRs resolved, fifteen taken, four declined on the record |
| v9.162 | 2026-08-31 | `5504d5b` | P0.3 epilogue: the policy's first live test, three fresh bumps in one pass |
| v9.163 | 2026-08-31 | `23f791c` | P0.3 closed for real: the queue drains to structural zero |
| v9.164 | 2026-09-01 | `6bb60c4` | Wave four: one floor line, and the tide goes out |
| v9.165 | 2026-09-01 | `d1591e3` | Wave five: two floors taken, one minor caught narrowing its deps, one major caught sneaking past the filter |
| v9.166 | 2026-09-01 | `a229645` | Roadmap P0.4: the last four operator tools exercised, four real defects |
| v9.167 | 2026-09-01 | `a996181` | Roadmap P0.5: an SPDX bill of materials attached to every release |
| v9.168 | 2026-09-01 | `11ec6e3` | Roadmap P0.6: keyless SLSA provenance signs every release SBOM |
| v9.169 | 2026-09-01 | `2c4bc01` | Roadmap P0.7 part 1: the ZK tree is parameterized and, for the first time, benchmarked |
| v9.170 | 2026-09-01 | `87efafb` | Roadmap P0.7 part 2: the plonky2 0.2 to 1.x major, evaluated then taken |
| v9.171 | 2026-09-01 | `739d67c` | Roadmap P0.8: coverage measured, and a floor that fails CI on a regression |
| v9.172 | 2026-09-01 | `81fa7ef` | Roadmap P2.12: a Plonky2 to Plonky3 evaluation, framed honestly |
| v9.173 | 2026-09-01 | `b42022e` | Roadmap P0.9: offsite backup by env alone, drilled against S3 in CI |
| v9.174 | 2026-09-01 | `0b44d15` | P0.9 follow-through: generate-secrets defined its function after calling it |
| v9.175 | 2026-09-01 | `3064da9` | Roadmap P0.10: pager integration, and the duress page path proven end to end |
| v9.176 | 2026-09-01 | `0732d6d` | Roadmap P1.1: a fresh Linux server to a healthy production stack, under systemd |
| v9.177 | 2026-09-01 | `31bb683` | P1.1 follow-through: the CI assertion could not read the backup directory it was checking |
| v9.178 | 2026-09-01 | `740d9ad` | Roadmap P1.2: the issuer signing key behind a custody interface, HSM/PKCS#11 and AWS KMS drivers |
| v9.179 | 2026-09-01 | `b17b13e` | P1.2 follow-through: the PKCS#11 CI recipe moves out of an inline bash -c block |
| v9.180 | 2026-09-01 | `651cd09` | Roadmap P1.3: production secrets from a sealed store, materialized into a tmpfs; rotation drilled live in CI |
| v9.181 | 2026-09-01 | `cdbbab3` | P1.3 follow-through: two latent Linux defects the new drills exposed |
| v9.182 | 2026-09-01 | `501e6aa` | P1.3 follow-through: rotating the DB password never restarted pgbouncer |
| v9.183 | 2026-09-01 | `c9eedb8` | Roadmap P1.4: zero-downtime deploys; blue-green behind a retrying edge, expand-contract enforced, zero drops proven with a control |
| v9.184 | 2026-09-01 | `3008b50` | P1.4 follow-through: the installer now shows WHY polaris.service failed |
| v9.185 | 2026-09-01 | `caf0fcf` | P1.4 follow-through: a wider app healthcheck window for cold starts |
| v9.186 | 2026-09-01 | `32a2c8d` | Roadmap P1.5: the Kubernetes/Helm reference profile, boots to healthy on kind with enforced policies and the restricted standard |
| v9.187 | 2026-09-01 | `a4d4570` | Roadmap P1.6: opt-in distributed tracing and dashboards-as-code, the correlation id joining logs to traces |
| v9.188 | 2026-09-01 | `967172d` | v9.188: Postgres readiness probes go over TCP, so backups no longer start against the init-only server |
| v9.189 | 2026-09-01 | `c0f7a52` | v9.189: session and origin hardening; server-side sessions, per-role network policy, WebAuthn 3.x with ML-DSA-65 offered first |
| v9.190 | 2026-09-01 | `3b8c438` | v9.190: abuse controls; per-agency quotas enforced in the database, velocity alerts against each agency's own baseline |
| v9.191 | 2026-09-02 | `31b6946` | v9.191: the performance baseline, measured end to end and re-run by CI |
| v9.192 | 2026-09-02 | `59dc602` | v9.192: disaster recovery measured; a monthly drill kills the primary and records RPO and RTO |
| v9.193 | 2026-09-02 | `43fa714` | Roadmap amended: the national-deployment presentation pass, P1.13 to P1.17, with wholesale rework pre-authorized |
| v9.194 | 2026-09-02 | `ac53764` | v9.194: every stated count and constitution object is true, and guarded |
| v9.195 | 2026-09-02 | `0378f78` | v9.195: the constitution carries only the constitution |
| v9.196 | 2026-09-02 | `08e80b7` | v9.196: the readiness ledger opens with what is open |
| v9.197 | 2026-09-02 | `8d42975` | v9.197: the architecture document ends at the architecture |
| v9.198 | 2026-09-02 | `e71f9b9` | v9.198: the reference set describes the running code |
| v9.199 | 2026-09-03 | `9e382ae` | v9.199: the operator surface has one owner per subject |
| v9.200 | 2026-09-03 | `8de8db9` | v9.200: the indexes and the voice gate |
| v9.201 | 2026-09-03 | `c84f2d1` | v9.201: the repository's security features are on, and the policy says what is true |
| v9.202 | 2026-09-03 | `22b0ce0` | v9.202: one sentence on all four surfaces |
| v9.203 | 2026-09-03 | `edcffc2` | v9.203: the community files a reader expects |
| v9.204 | 2026-09-03 | `b994420` | v9.204: CONTRIBUTING in public voice; the README above the fold |
| v9.205 | 2026-09-03 | `62c4eea` | v9.205: the release shape, and a check on the front door |
| v9.206 | 2026-09-03 | `2ceffbd` | v9.206: the demo and the launcher beacon exist only where they belong |
| v9.207 | 2026-09-03 | `8709474` | v9.207: the application names things for the operator |
| v9.208 | 2026-09-03 | `630326b` | v9.208: one voice for every message the operator reads |
| v9.209 | 2026-09-03 | `5daddb0` | v9.209: the CLI documents itself, and it has one name |
| v9.210 | 2026-09-03 | `38dfbe1` | v9.210: the metrics surfaces are closed at the edge |
| v9.211 | 2026-09-04 | `6c68a6e` | v9.211: the chrome stops performing, and the seed stops naming its author |
| v9.212 | 2026-09-04 | `0e47083` | v9.212: the freeze line is recorded closed |
| v9.213 | 2026-09-04 | `5fc2a0f` | the Atlas captures show the Atlas that ships |
| v9.214 | 2026-09-04 | `d3aef48` | the map's colours say what they mean |
| v9.215 | 2026-09-04 | `8bdf14e` | every image is built one way |
| v9.216 | 2026-09-04 | `bdbd3f2` | the project site says only what the repository can support |
| v9.217 | 2026-09-04 | `6ec8182` | the site becomes a front door |
| v9.218 | 2026-09-04 | `82be6bf` | one copy of every image, one palette |
| v9.219 | 2026-09-04 | `e5bac8b` | the page cannot publish a claim that stopped being true |
| v9.220 | 2026-09-04 | `eb0c96e` | the System Dashboard was blank |
| v9.221 | 2026-09-04 | `d238338` | delete what nothing calls |
| v9.222 | 2026-09-04 | `3a3531c` | the scripts are named for their job |
| v9.223 | 2026-09-04 | `4ea510c` | every directory says who it is for |
| v9.224 | 2026-09-04 | `bcd1e40` | the design records move into the documentation |
| v9.225 | 2026-09-04 | `a222e48` | the map recomputes itself |
| v9.226 | 2026-09-04 | `5cd2b2a` | the presentation pass is closed |
| v9.227 | 2026-09-05 | `ad271ef` | the masthead stops showing the page through itself |
| v9.228 | 2026-09-05 | `784f644` | the README routes to the design records |
| v9.229 | 2026-09-05 | `a7e883e` | the last two indexes say what they hold |
| v9.230 | 2026-09-05 | `02966c4` | the design records, part one |
| v9.231 | 2026-09-05 | `d7c3744` | the design records, part two |
| v9.232 | 2026-09-05 | `fdf0af6` | the design records, part three |
| v9.233 | 2026-09-05 | `8ce216c` | the design index says what the pass found |
| v9.234 | 2026-09-05 | `19c09a9` | retention becomes a recorded decision with a floor |
| v9.235 | 2026-09-05 | `e530de2` | the retention schedule reaches the purge, and the chain is drilled |
| v9.236 | 2026-09-05 | `65b13b4` | the retention decision gets an operator surface; P1.11 closes |
| v9.237 | 2026-09-05 | `42dd208` | a production readiness pass over every surface, and what it found |
| v9.238 | 2026-09-05 | `d08b26b` | the dashboard is an operations page |
| v9.239 | 2026-09-05 | `95936f8` | the edge runs as a non-root user on every substrate |
| v9.240 | 2026-09-05 | `e3e6a57` | edge configuration changes are live reloads; the two remaining windows are measured |
| v9.241 | 2026-09-05 | `300f4ca` | the SLIs and the error budget are recorded series |
| v9.242 | 2026-09-05 | `928bb50` | the standing chaos program, and what its first run found |
| v9.243 | 2026-09-05 | `9f10956` | automated database failover: the HA profile |
| v9.244 | 2026-09-05 | `ca03c03` | HA on Kubernetes: the same Patroni members, the cluster's API as the lease store |
| v9.245 | 2026-09-06 | `0433764` | event-table partitioning |
| v9.246 | 2026-09-06 | `556268f` | read-replica routing |
| v9.247 | 2026-09-06 | `d03955c` | bulk enrollment |
| v9.248 | 2026-09-06 | `de082df` | the Atlas becomes an analytical console |
| v9.249 | 2026-09-06 | `4b3122b` | Atlas Breakdown: find the anomalous slice |
| v9.250 | 2026-09-06 | `9fe98df` | Atlas Breakdown, scale-hardened |
| v9.251 | 2026-09-06 | `fb843b9` | Atlas: one coordinated, faceted query |
| v9.252 | 2026-09-06 | `2877667` | Atlas: the records grid, and click to filter |
| v9.253 | 2026-09-06 | `ab9bc92` | Atlas Map v2: aggregation first, globe optional |
| v9.254 | 2026-09-07 | `561acac` | National simulation, ship 1: the synthetic nation |
| v9.255 | 2026-09-07 | `0803c8d` | National simulation, ship 2: the life-event stream |
| v9.257 | 2026-09-07 | `a850985` | Bulk signatures are real; event vs cryptographic verification |
| v9.258 | 2026-09-07 | `e015462` | Single-witness verify-at-use |
| v9.259 | 2026-09-07 | `1ce7cd7` | Verification holds through HA (closes P2.9) |
| v9.260 | 2026-09-07 | `8a45481` | Atlas roll-ups prune the partitioned event table |
| v9.261 | 2026-09-07 | `ec2e90e` | Atlas live simulation mode |
| v9.262 | 2026-09-07 | `c9d0209` | Headless-browser UI harness + live-sim cache fix |
| v9.263 | 2026-09-07 | `a497650` | The UI harness runs on every push |
| v9.264 | 2026-09-07 | `ee175c0` | Two integrity fixes in the verification path |
| v9.265 | 2026-09-07 | `b6d8bde` | Atlas Trends: temporal rhythm + composition over time |
| v9.266 | 2026-09-07 | `33a85f9` | Athena: the authority-and-constitution layer |
| v9.267 | 2026-09-08 | `88ee51f` | Athena console: the operator-facing authority-and-constitution surface |
| v9.268 | 2026-09-08 | `daca723` | Public claim pass: precise zero-knowledge, no certification |
| v9.269 | 2026-09-08 | `77cf29d` | Schema quarantine: the science-fiction scaffolds are gone |
| v9.270 | 2026-09-08 | `f9d214f` | The constitution, layered: constitutional vs engineering |
| v9.271 | 2026-09-08 | `95b2d7b` | Verify-at-use: an explicit authenticity/authorization split |
| v9.272 | 2026-09-08 | `a849f6f` | The two-witness availability clause: continuous sampling |
| v9.273 | 2026-09-08 | `9c8fabd` | Honesty pass: shrink every claim to what the code does now |
| v9.274 | 2026-09-08 | `7630c13` | The engine, not the wrap: a detached verifier a relying party runs offline |
| v9.275 | 2026-09-08 | `72dba98` | Attacks that must fail: an adversary suite run every release, not greps |
| v9.276 | 2026-09-08 | `4dad3cd` | Two issuers on one box: federation with distinct roots, proven cryptographically |
| v9.277 | 2026-09-08 | `5ab1a9b` | The HSM is the sole signer: a fail-closed profile and in-token key rotation |
| v9.278 | 2026-09-08 | `6289d02` | The holder gets a surface: a wallet that holds, presents, and proves in zero knowledge |
| v9.279 | 2026-09-08 | `759abf0` | Real numbers from the box: the engine on a dyno, measured not extrapolated |
| v9.280 | 2026-09-08 | `52c56ca` | The default boot is the real motor — Phase E complete |
| v9.281 | 2026-09-08 | `ee073d9` | Differential fuzzing of the two witnesses |
| v9.282 | 2026-09-08 | `0c4a9a9` | ML-DSA-65 conformance against Project Wycheproof |
| v9.283 | 2026-09-08 | `6d964b1` | The KAT covers context strings too |
| v9.284 | 2026-09-08 | `2d394c6` | Security controls as attacks: NIST 800-53 AC + AU |
| v9.285 | 2026-09-08 | `bcce752` | Controls as attacks: IA + SC join AC + AU |
| v9.286 | 2026-09-08 | `032873e` | Federation in the running app: each agency signs its own tokens |
| v9.287 | 2026-09-08 | `b3c399c` | The holder-to-verifier flow, run end to end |
| v9.288 | 2026-09-08 | `be95c2d` | Relying-party API v1: a bounded verification oracle |
| v9.289 | 2026-09-08 | `5424d97` | Verification conformance suite + Python SDK: the integration contract, P3.5a |
| v9.290 | 2026-09-08 | `16ebe34` | TypeScript verify SDK: P3.5 complete across two languages |
| v9.291 | 2026-09-08 | `746d023` | Offline verification: authorization with no connectivity, P3.6 |
| v9.292 | 2026-09-08 | `0a98446` | Federation topology decision record, P3.1 |
| v9.293 | 2026-09-08 | `990ec7e` | Front door: state reality, and pin it |
| v9.294 | 2026-09-08 | `91269c9` | Front door opens on the engine, with proof-of-life |
| v9.295 | 2026-09-08 | `02b8686` | Say what unlinkability does NOT cover, and split the witness claim |
| v9.296 | 2026-09-08 | `c38eb9f` | Inter-authority protocol v1: the signed federation manifest (P3.2) |
| v9.297 | 2026-09-08 | `3bc52e1` | Retire the freeze line from the constitution |
| v9.298 | 2026-09-08 | `22d356e` | Epoch alignment and revocation propagation across authorities (P3.2b) |
| v9.299 | 2026-09-08 | `66c0825` | Federation proven across two instances (P3.10) |
| v9.300 | 2026-09-08 | `b668d0e` | The canonical-signing equivalence oracle |
| v9.301 | 2026-09-08 | `fd31bfc` | The transparency log (P3.3) |
| v9.302 | 2026-09-08 | `1118bb4` | Transparency witnesses and the split-view defence (P3.3b) |
| v9.303 | 2026-09-08 | `e5741cb` | Transparency external-ledger publication (P3.3c) |
| v9.304 | 2026-09-08 | `1877a27` | Front-door honesty pass, and a flaky-benchmark fix |
| v9.305 | 2026-09-08 | `5b2eee7` | Repo hygiene: unused imports, CODEOWNERS |
| v9.306 | 2026-09-09 | `a7797a8` | Enforce import + dead-code hygiene: ruff |
| v9.307 | 2026-09-09 | `91e4aff` | Dead-code sweep |
| v9.308 | 2026-09-09 | `1f2f059` | Aggregate mirrored status feed, P3.2c |
| v9.309 | 2026-09-09 | `f2f5d9b` | Metamorphic verifier fuzzer, and the hardening it drove |
| v9.310 | 2026-09-09 | `80eda44` | Federation status bundle: the aggregator holds no member key |
| v9.311 | 2026-09-09 | `407dd4b` | ROADMAP honesty pass, and the P8 exchange-fabric arc |
| v9.312 | 2026-09-09 | `1686fab` | Offline cross-authority epoch-bound ZK, P3.2d |
| v9.313 | 2026-09-09 | `8cb9771` | Normative wire specification, P8.1 |
| v9.314 | 2026-09-09 | `cf67747` | Conformance beyond the pack, P8.1b |
| v9.315 | 2026-09-09 | `3c9dcff` | All seven signed artifacts certified, P8.1b |
| v9.316 | 2026-09-09 | `971f818` | P8.1 complete: the federation trust decision certified |
| v9.317 | 2026-09-09 | `342b636` | The exchange receipt: evidence without retention, P8.2 |
| v9.318 | 2026-09-09 | `78bb063` | The local gate type-checks the TypeScript SDK |
| v9.319 | 2026-09-09 | `ccfcb0c` | P8 on its own terms: a positioning invariant and the build plan |
| v9.320 | 2026-09-09 | `027fa4c` | Service-to-service minting: the signature is the institution, P8.2b |
| v9.321 | 2026-09-09 | `7fbe23b` | The timestamp authority: time evidence for anything, P8.7a |
| v9.322 | 2026-09-09 | `d79ab5c` | The receipt set is a transparency log, P8.2c |
| v9.323 | 2026-09-09 | `99da189` | The signed registry: discovery over the authority layer, P8.3 |
| v9.324 | 2026-09-09 | `bc70f15` | The exchange gateway: institutions exchange through Polaris trust, P8.2d |
| v9.325 | 2026-09-09 | `cb8827c` | Document signing with long-term validation, P8.5 |
| v9.326 | 2026-09-09 | `aa11078` | The auth broker: log in with a credential, no login record, P8.4 |
| v9.327 | 2026-09-09 | `89c3512` | The wallet protocol surface: offline presentation and QR framing, P8.6 |
| v9.328 | 2026-09-09 | `4974372` | The trust-service lifecycle: compromise recovery, P8.7b |
| v9.329 | 2026-09-09 | `6a9c333` | Algorithm agility and migration, P8.8a |
| v9.330 | 2026-09-09 | `7fd17be` | Protocol versioning, negotiation and cross-version compatibility, P8.8b |
| v9.331 | 2026-09-09 | `77043a9` | The P8 sweep: every protocol artifact certified, the map redrawn |
| v9.332 | 2026-09-09 | `6a9e782` | The front door restated |
| v9.333 | 2026-09-09 | `a40546b` | The gateway's trust is directional |
| v9.334 | 2026-09-09 | `61698de` | Long-term validation trusts the timestamp authority |
| v9.335 | 2026-09-09 | `2b52b95` | The QR decoder is resource-bounded |
| v9.336 | 2026-09-09 | `f4a60ed` | The auth broker binds the relying party's policy and hides the code |
| v9.337 | 2026-09-09 | `8d3a316` | The roadmap cannot contradict itself |
| v9.338 | 2026-09-09 | `90cd5fc` | The drills catch up with the stricter verifier, and the catch-up is gated |
| v9.339 | 2026-09-09 | `420136b` | The same-key timestamp guard applies to real keys |
| v9.340 | 2026-09-09 | `b69038b` | The comparison table names its subjects |
| v9.341 | 2026-09-09 | `a237c03` | Timestamp transparency: anchoring as the caller's choice, P8.5b |
| v9.342 | 2026-09-09 | `ee51f5a` | The edge image build retries a transient checksum-database failure |
| v9.343 | 2026-09-09 | `0b5493d` | Polaris as data |
| v9.344 | 2026-09-09 | `5269828` | The instrument |
| v9.345 | 2026-09-09 | `c20a3d4` | Engine and tool only |
| v9.453 | 2026-09-13 | `32e162b` | Agility, not settled security |
| v9.465 | 2026-09-15 | `95a7de3` | A wallet nobody here wrote said no, and it was right |
| v9.466 | 2026-09-15 | `0ea11b9` | You can install it now |
