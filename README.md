<div align="center">

<img src="site/polaris_logo_clean.png" alt="Polaris" width="220" height="220">

# POLARIS

**A working reference implementation of a post-quantum, issuer-unlinkable,<br>compulsion-resistant identity-token system.**

CI builds and boots the production-profile container stack on every push, proves the post-quantum handshake and the backup round trip, and runs the disaster-recovery drill. It is a reference implementation, not a deployment.

[![CI](https://img.shields.io/github/actions/workflow/status/EgorKhaklin/polaris-id/ci.yml?branch=main&label=CI&logo=githubactions&logoColor=white&style=flat-square)](https://github.com/EgorKhaklin/polaris-id/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/EgorKhaklin/polaris-id?label=release&color=2b5797&style=flat-square)](https://github.com/EgorKhaklin/polaris-id/releases/latest)
[![License](https://img.shields.io/badge/license-Apache--2.0-3b6e48?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/status-reference%20implementation%2C%20not%20production-b8860b?style=flat-square)](docs/PRODUCTION-READINESS.md)

<sub>Every release ships SBOMs with signed SLSA provenance; verify one with `gh attestation verify` ([SECURITY.md](SECURITY.md)).</sub>

[**Project site**](https://egorkhaklin.github.io/polaris-id/) · [What it is](#what-polaris-is) · [See it run](#see-it-run) · [The ten guarantees](#the-ten-guarantees) · [The hard parts](#the-hard-parts) · [Architecture](#architecture) · [Run it](#run-it) · [Documentation](#documentation)

</div>

---

## What Polaris is

Polaris is a **post-quantum credential verification engine**, on a schema backbone. An authority issues a credential signed with ML-DSA-65 (FIPS 204; ML-DSA-87 is accepted beside it); a holder holds it and presents it; and anyone can check it two ways. **Authenticity** is offline: a standalone detached verifier confirms the signature against published keys, with no Polaris code, no database, and no network. **Authorization** ("is it authoritative right now?") is answered online by a versioned relying-party API a third party calls as itself, or offline by a short-lived signed status assertion the holder staples, so a relying party never has to contact the issuer to accept a credential. Python and TypeScript verify SDKs and a language-agnostic conformance suite make "correctly verifying a Polaris credential" a contract anyone can hold their own code to, and cross-agency trust is explicit and non-transitive. Around the credential sits an institutional protocol of signed statements, each verified offline by the same detached verifier and both SDKs: a signed registry of what an authority offers and trusts, a trust list carrying each key's lifecycle, exchange receipts that prove an exchange occurred without keeping the message, a timestamp authority, document signing with long-term validation, a credential-bound login token, and offline wallet presentations. Version 1 of that protocol is frozen, and a cross-version suite proves on every push that today's verifiers still accept what version 1 published and that a pinned older verifier never accepts what the suite rejects.

The backbone is a 40-table PostgreSQL schema whose constraints are the security boundary: **the guarantees live in the database, not in application code**. A rule enforced by a trigger, a CHECK constraint, or a unique index binds every client, survives every restore from backup, and cannot be bypassed by the next caller. Around that sit a Rust ZK-SNARK prover with an independent second witness, a Flask application and an operator CLI, a hardened container stack (the production profile) behind a post-quantum TLS edge, and a flat layer of 222 machine-checked invariants (v9.382) that gates every change in CI. It runs on notional data; it has never held real identity data, and the physical token it models is not manufactured.

**The problem it models.** Americans carry six to eight credentials that do not talk to each other: driver's license, passport, Social Security card, Real ID, voter registration, insurance card. Each is a separate artifact, signed by a separate authority, secured to a separate standard, with no shared revocation path and no shared audit trail. Polaris models consolidating them into **one active credential record per person**, verified through **context-scoped events** (banking, voting, and healthcare are different events with different disclosure rules) at three disclosure levels. The default level is **zero-knowledge**: the typical verification stores no token identifier at all, so the zero-knowledge verification graph cannot be reconstructed even by someone holding the whole database (SELECTIVE and FULL events do carry a token id).

Two things here use zero knowledge, and a third deliberately does not exist. *Unlinkable verification records*: a default (zero-knowledge-mode) verification stores no token identifier, so the verification graph cannot be rebuilt from the database. A *Merkle-membership proof* (a Plonky2 SNARK) proves a token was in a published ledger and nothing else. Polaris is **not** a general selective-disclosure or anonymous-credential system, and does not claim to be.

**Relying-party correlation, bounded rather than permanent.** The unlinkability above is issuer-side and scoped to zero-knowledge mode: a ZK-mode verification stores no token identifier, so the issuer's database cannot reconstruct that graph. The holder-to-verifier hop is a separate question, and the answer has two halves. The login token's subject and the presentation handle are derived under each relying party's own scope, so they are stable where an account needs them and unrecognisable at the next verifier; since the subject is the value a relying party writes down, and written-down values are the ones pooled, sold, subpoenaed and breached, this is the half that matters most in practice. What did not change: a full-credential presentation still shows the verifier a stable `token_value`, issuer signature and holder public key, so two relying parties who deliberately keep the raw material can still correlate. The guarantee is about what a verifier should **store**, not about what it is **shown**, and the detached verifier reports which it gave: a plain presentation is `exposed`, never unlinkable, while the zero-knowledge form, whose handle is the scoped nullifier, is `bounded`. Blinded presentations, one-time presentation tokens and anonymous credentials remain unbuilt.

**Offline authorization is a tradeoff, stated plainly.** The short-lived signed status assertion lets a relying party accept a credential with no issuer contact, so the issuer never learns the verification happened. The cost is revocation latency: a revoked credential's last signed ACTIVE assertion stays valid until it expires, so there is a revoked-but-assertion-still-valid window bounded by the assertion's TTL (one hour by default, a policy number, not a law). A verifier tightens that window by imposing its own shorter `max_age`. **Authenticity and currency are separate results**: a stapled presentation can be cryptographically **authentic** and still not certainly **ACTIVE at this instant**, so the detached verifier returns them as distinct fields (`authentic` versus the `decision`/`status`), and a high-risk relying party demands online status or a `max_age` of seconds rather than the default hour. The three cannot all be maximized at once: issuer non-observation, offline availability, and revocation freshness, pick two.

---

## See it run

You do not need the stack to see the engine. Clone the repository, install a standard ML-DSA-65 library (`pip install liboqs-python cryptography`), and run the parts a relying party actually runs. None of these touch a database or a server:

```bash
python3 scripts/polaris-verify.py --selftest            # a live ML-DSA-65 sign/verify round trip
python3 scripts/polaris-verify.py --verify-dir vectors  # re-verify the published authenticity packs (a genuine one passes; every tampered one fails)
python3 conformance/run_conformance.py --self           # the reference verify SDK against the published conformance cases
python3 scripts/polaris-compat-suite.py                 # the frozen version-1 protocol under today's verifiers, and today's cases under a pinned older verifier
```

These are the detached verifier and the verification conformance suite: the same code a third party integrates, and the same code CI runs on every push.

A verdict makes the split concrete. A signature stays genuine forever; the authorization under it can change. The same credential, after it is revoked:

```jsonc
POST /api/v1/verify  ->  {
  "authentic": true,                 // the ML-DSA-65 signature is genuine
  "currently_authoritative": false,  // but this token has been revoked
  "status": "REVOKED",
  "usable": false,                   // authentic AND authoritative -> false
  "decision": "reject"
}
```

That is the whole product in one object: authenticity is permanent and cacheable; authorization is fresh and revocable; a relying party needs both. The full production stack (issuance, the operator flows, the Atlas) is under [Run it](#run-it) below.

---

## The ten guarantees

Above the ten sits the project's vocation: **no person can be compelled to renounce, transfer, or surrender their identity against their will.** Features that drift toward surveillance or population-scale aggregation are refused, and the refusal is structural: the schema carries no attribute to filter a population by. The ten sit at two tiers beneath the vocation: five **constitutional** rights guarantees (C1, C2, C3, C6, C10) that may not be relaxed without amendment, and five **engineering** invariants (C4, C5, C7, C8, C9) that keep them honest under load and attack.

| # | Guarantee | Tier | Enforced by |
|---|---|---|---|
| **C1** | The audit trail is append-only. History cannot be rewritten or deleted. | Constitutional | Database triggers reject `UPDATE`/`DELETE` on audit tables |
| **C2** | A zero-knowledge verification stores no token identifier. | Constitutional | Bidirectional `CHECK` constraint |
| **C3** | One person holds at most one ACTIVE token at any moment. | Constitutional | Partial unique index |
| **C4** | Failed-login counting is atomic. No check-then-act race. | Engineering | Single-statement `UPDATE ... RETURNING` |
| **C5** | No inline scripts. Content-Security-Policy is `script-src 'self'`. | Engineering | HTTP response header, verified per route |
| **C6** | Disclosure level is enforced server-side. A client cannot upgrade what it learns. | Constitutional | Server code paired with redaction tests |
| **C7** | No hardcoded cryptography. Algorithms are rows in a registry table. | Engineering | Foreign key to `CryptographicAlgorithm` |
| **C8** | Every map/API aggregate is bounded. No unbounded result sets. | Engineering | Hard caps in the SQL functions |
| **C9** | Concurrency claims are tested with real threads, not mocks. | Engineering | Threaded test suites against a live database |
| **C10** | Identity is not money. The schema carries no monetary claim. | Constitutional | Structural absence, pinned by a check |

Each guarantee is machine-checked by [`polaris_checks`](polaris_checks/): 222 plain `check_*` functions (v9.382), each paired with a detection test proving it fails on a broken fixture. A check that cannot detect its own violation is treated as broken. The reasoning for why these ten, and why they interlock, is in [MISSION.md](MISSION.md) and [meta/constraint-lattice.md](meta/constraint-lattice.md).

---

## The hard parts

Consolidating cards is the easy half. The hard half is what happens when an adversary shows up. Six threats are answered by construction, at the database layer, not in policy documents.

| Threat | In practice | The answer | Detail |
|---|---|---|---|
| **Cryptographic compulsion** | "Sign this or I break your fingers." | A second secret produces a verification that looks identical and silently records a `DuressEvent`. By design every operator-visible surface shows success (a tested property of the modeled flow, not an audited side-channel guarantee). | [duress-codes](docs/design/duress-codes.md) |
| **Catastrophic loss** | Token lost; the holder has nothing to prove who they are. | A two-phase recovery ceremony with independent out-of-band channels, a cooldown, and an admin-gated completion. | [recovery-ceremony](docs/design/recovery-ceremony.md) |
| **Quantum migration** | Today's signatures break when a quantum computer arrives. | Tokens carry classical and post-quantum signatures simultaneously during cutover, with a database rule that exactly one is active. The default is already post-quantum. | [multi-sig-migration](docs/design/multi-sig-migration.md) |
| **Issuer concentration** | One agency issues tokens that pass as another agency's. | Explicit-only federation, no transitive trust. Every cross-agency verification gates on an active trust attestation row. | [federation](docs/design/federation.md) |
| **Auditability vs. privacy** | "Prove this token was in the ledger" without revealing which one. | A Plonky2 ZK-SNARK over a Merkle commitment answers membership and nothing else. | [zk-snark](docs/design/zk-snark.md) |
| **Issuer overreach** | An agency revokes tokens at industrial scale, outside policy. | A per-agency revocation-rate ceiling enforced by trigger and audited under an advisory lock. | [issuer-discretion](docs/design/issuer-discretion.md) |

---

## Architecture

Four layers. The schema is the core; everything else is a client of it.

```
      ┌───────────────────────────────────────────────────────────┐
      │  CHECK LAYER          polaris_checks: flat invariant      │
      │                       checks; gates CI; reads everything, │
      │                       writes nothing                      │
      └────────────────────────────┬──────────────────────────────┘
                                   │
      ┌────────────────────────────▼──────────────────────────────┐
      │  APPLICATION          Flask routes: every use case,       │
      │                       the Atlas, WebAuthn MFA, /metrics   │
      │                       polaris_cli: the same over a shell  │
      └──────────┬──────────────────────────────┬─────────────────┘
                 │                              │ subprocess
      ┌──────────▼─────────────┐   ┌────────────▼─────────────────┐
      │  SCHEMA  PostgreSQL 16 │   │  ZK PROVER  Rust + Plonky2   │
      │  tables, procedures,   │   │  Merkle-inclusion SNARK,     │
      │  triggers, append-only │   │  re-verified bit-for-bit by  │
      │  audit (the security   │   │  an independent Python       │
      │  boundary)             │   │  second witness              │
      │                        │   └──────────────────────────────┘
      └──────────┬─────────────┘
                 │ signs under
      ┌──────────▼────────────────────────────────────────────────┐
      │  SIGNATURES           ML-DSA-65 default (FIPS 204),       │
      │                       ML-DSA-87 accepted beside it;       │
      │                       SLH-DSA registered (FIPS 205),      │
      │                       not yet a signer; algorithm         │
      │                       registry: rotation is a row, not a  │
      │                       redeploy                            │
      └───────────────────────────────────────────────────────────┘
```

| Component | What it is |
|---|---|
| [`polaris_sql/`](polaris_sql/) | The core. Schema, stored procedures implementing the use cases, append-only triggers, migrations. Business logic lives here so every client inherits it. |
| [`polaris_web/`](polaris_web/) | Flask application: dashboard, the Atlas, per-use-case flows, WebAuthn operator MFA, health and metrics. |
| [`polaris_zk/`](polaris_zk/) | Plonky2 Merkle-inclusion prover (Rust), plus [`witness2/`](polaris_zk/witness2/), an independent Python reimplementation that must agree with it. |
| [`polaris_cli/`](polaris_cli/) | Operator CLI: issuance, revocation, recovery, audit queries, without a browser. |
| [`polaris_checks/`](polaris_checks/) | The invariant layer. 222 checks (v9.382), each with a tested failure mode. `python3 -m polaris_checks.run` gates CI. |
| [`sdk/`](sdk/), [`conformance/`](conformance/) | The verify SDKs a relying party installs (Python and TypeScript, offline authenticity of the credential and of every signed protocol artifact, plus the online status check) and the language-agnostic conformance suite that certifies any verifier against the published cases. |
| [`scripts/`](scripts/), [`deploy/`](deploy/) | The holder wallet, the standalone detached verifier, and the relying-party verifier live here (`polaris-wallet.py`, `polaris-verify.py`, `polaris-relying-party.py`), alongside operator tooling (backup, restore, archive, purge, migrate, recover-admin) and observability config (Prometheus alerts, Grafana dashboards-as-code, opt-in OTel tracing). |

The production topology is five services: a self-built Caddy TLS edge, gunicorn, PgBouncer, PostgreSQL with pgBackRest WAL archiving, and Redis. Every service runs as non-root with all Linux capabilities dropped. An operator surface (the Atlas) plots verification and lifecycle events over that stack; zero-knowledge verifications are never plotted, because a zero-knowledge event carries no token id to attribute it by.

---

## Cryptography

The signing default is post-quantum **on day one**. There is no "migrate when quantum arrives" deferral; the migration target is the current default.

```
algorithm        family     PQ    NIST         sec    public key    signature
─────────────────────────────────────────────────────────────────────────────
ML-DSA-65        ML-DSA      ✓    FIPS 204     192      1,952 B      3,309 B   default
ML-DSA-87        ML-DSA      ✓    FIPS 204     256      2,592 B      4,627 B   accepted; migration is a key event
SLH-DSA-128s     SLH-DSA     ✓    FIPS 205     128         32 B      7,856 B   registered, no signer
SLH-DSA-256s     SLH-DSA     ✓    FIPS 205     256         64 B     29,792 B   registered, no signer
ECDSA-P256       ECDSA            FIPS 186-4   128         64 B         72 B   legacy, sunset 2027
```

- **Two ML-DSA implementations at issuance; sampled at use.** Issuance requires two independent ML-DSA-65 implementations (liboqs and OpenSSL via `cryptography`) and fails closed if they disagree, so no stored production signature is trusted from a single library. Verify-at-use is single-witness (liboqs) with continuous mandatory second-witness sampling; a disagreement pages a SEV. These are not the same guarantee, and the difference is deliberate: issuance is rare and must be certain, verify-at-use is hot and must be fast. The ZK epoch root computed by the Rust prover is recomputed bit-for-bit by a Python second witness.
- **SLH-DSA is a registered hedge, not a shipped signer.** ML-DSA rests on lattice assumptions, SLH-DSA on hash functions alone, so both SLH-DSA parameter sets sit in the algorithm registry and a rotation toward them is a row update. The signers wired today are ML-DSA-65 and ML-DSA-87 (the key file names its parameter set), so the seed token filed under SLH-DSA-128s can never be re-signed; the seed data's signature rows are placeholders for every algorithm, and real signatures appear at issuance. The gap is on the ledger in [PQC-POSTURE.md](docs/reference/PQC-POSTURE.md).
- **The TLS edge negotiates post-quantum key exchange.** The public edge speaks X25519MLKEM768 hybrid KEX with capable clients, and CI proves the handshake on every push. What remains classical (internal TLS hops, certificates, WebAuthn credentials on today's authenticators; the relying party already offers ML-DSA-65 first) is mapped honestly in [PQC-POSTURE.md](docs/reference/PQC-POSTURE.md).
- **The ZK proof is transparent.** Plonky2 is FRI-based: no trusted setup. The proof answers "was this token in the ledger at epoch N" and nothing else. Source: [`polaris_zk/src/lib.rs`](polaris_zk/src/lib.rs).

---

## Verified, not asserted

Every claim above is backed by a gate that fails if the claim stops being true. The table, check, route and CI-job counts are re-measured by `polaris_checks` on every run and are current; the two test counts are a point-in-time measurement (v9.332) and are restated when re-measured, never extrapolated. 15 product tests skip without optional backends; 5 crypto witnesses need a PKCS#11 token or a real KMS key.

| Layer | Scale | What it proves |
|---|---|---|
| Product tests (live database) | 755 | Every CHECK constraint, every use case, every route, redaction at every read path, concurrency with real threads, the secret store; `test_app`, `test_cli`, `test_check_constraints`, the two property suites, `test_secretstore` |
| Crypto witnesses | 84 passing of 89 collected | ML-DSA sign/verify under both accepted parameter sets against both witnesses, in-file and in a software PKCS#11 module (Kryoptic) custody; the Rust and Python epoch roots agree; `test_pqc_signing`, `test_custody`, `test_zk_second_witness`, `witness2`. Both rows count tests passing on the reference machine at v9.332 (`pytest -q` per suite); the five crypto tests and fifteen product tests skipped there need an optional backend (AWS KMS, a PKCS#11 module, a browser) and run in CI |
| Invariant checks | 222 | C1-C10 plus production posture, each check paired with a detection test |
| CI jobs | 19 | See below |

The CI jobs do not just run tests; they exercise the artifacts. On every push, CI **builds and boots the dev and prod images**, **boots the five-service production-profile stack end to end** and asserts health through the TLS edge, **round-trips an encrypted backup and restore** with a fail-closed negative check and an off-site S3 drill, **kills the primary and restores it from the WAL archive** while measuring RPO and RTO, **rolls a deploy under traffic** and counts dropped requests, **installs the Linux server profile** on Debian and Rocky, **boots the Kubernetes reference profile** on kind, **pages a duress alert** through Prometheus and Alertmanager to a webhook, **proves the post-quantum TLS handshake** against a real certificate, **signs and verifies with real ML-DSA-65** both in the production image and inside a software PKCS#11 module (Kryoptic; not a hardware HSM), **runs the protocol drills** (two instances federating under different ML-DSA parameter sets, the trust-list compromise recovery, the frozen version-1 compatibility suite in both directions), and **fails the HA profile's leader, lease store and etcd member** under a live write stream, and **gates on CVE scans** of both the Python dependency surface and all five self-built container images.

Most of those jobs carry a comment naming the specific past failure they exist to prevent. The pattern behind them: every defect class found by running the system, rather than reading it, gets a permanent gate.

```bash
python3 -m polaris_checks.run      # the invariant layer, no database needed
./scripts/polaris-test.sh               # the full product suite against local Postgres
./polaris_mac_launch.sh test       # the same, via the launcher
```

---

## Run it

**Local (macOS).** The only prerequisite is [Docker Desktop](https://www.docker.com/products/docker-desktop).

```bash
git clone https://github.com/EgorKhaklin/polaris-id.git polaris
cd polaris
./Polaris.command
```

The first run pulls PostgreSQL, builds the app image, loads the schema, runs the SQL self-tests, and opens `http://localhost:2222`. Closing the browser tab tears the stack down. Three seeded roles (notional data, development credentials only):

```
admin     Admin@123!      full access, SQL console
operator  Operator@123!   issue, activate, bind tokens
auditor   Auditor@123!    read-only, warrant audits, duress dashboard
```

**Single-host compose profile (any Docker host).**

```bash
./scripts/polaris-generate-secrets.sh
export POLARIS_DOMAIN=polaris.example.com
./scripts/polaris-deploy.sh prod
curl -fsS https://$POLARIS_DOMAIN/api/health
```

On a fresh Debian, Ubuntu, or RHEL-family server, one script does all of the above under systemd: `sudo POLARIS_DOMAIN=polaris.example.com deploy/linux/install.sh` ([LINUX-SERVER](docs/operator/LINUX-SERVER.md), then [HARDENING](docs/operator/HARDENING.md)). On a Kubernetes cluster, the Helm reference profile deploys the same topology with enforced network policies and the restricted pod security standard ([KUBERNETES](docs/operator/KUBERNETES.md)). Caddy provisions TLS automatically; `/api/health` reports structured per-component status. Runbooks: [INSTALL](docs/operator/INSTALL.md) · [OPERATIONS](docs/operator/OPERATIONS.md) · [SECRETS](docs/operator/SECRETS.md) · [DR](docs/operator/DR.md) · [FAILOVER](docs/operator/FAILOVER.md). Diagnostics: `./polaris_mac_launch.sh doctor`; full launcher reference: `./polaris_mac_launch.sh --help`.

---

## Where Polaris sits

| System | Deployed to a real population | National-scope issuance | Post-quantum default | Unlinkable verification default | Compulsion-resistant primitive | Append-only audit at schema |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Real ID (US) | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| mDL / ISO 18013-5 | ✓ | ✓ | ✗ | partial | ✗ | ✗ |
| Aadhaar (India) | ✓ | ✓ | ✗ | ✗ | ✗ | partial |
| e-Estonia | ✓ | ✓ | ✗ | ✗ | ✗ | partial |
| W3C DIDs / VCs | partial | ✗ | method-dependent | method-dependent | ✗ | n/a |
| **Polaris** | **✗** | **✗** | ✓ | ✓ | ✓ | ✓ |

The first two columns are the honest ones: every other row is deployed to real people at national scale, and Polaris is neither deployed nor issuing at that scale. Its remaining ticks mark design properties genuinely present in the codebase (post-quantum by default, unlinkable verification, a compulsion-resistant primitive, append-only audit at the schema), not a deployment. This compares designs, then, not deployments; Polaris runs on notional data. No single row is novel; the point is the assembly — all five properties in one working codebase, every one enforced at the schema level and machine-checked rather than asserted in prose. The closest deployed system is mDL, which has selective disclosure and real signatures but no post-quantum default, no duress primitive, and no constitutional layer governing the issuer itself.

---

## Documentation

| If you are | Start with |
|---|---|
| Deciding whether this is worth your time | [MISSION.md](MISSION.md), the constitution: what the system refuses to do and why |
| Reviewing the architecture | [ARCHITECTURE-OVERVIEW](docs/ARCHITECTURE-OVERVIEW.md) · [SYSTEM-MAP](docs/reference/SYSTEM-MAP.md) |
| Reading the security posture | [SECURITY.md](SECURITY.md) · [PQC-POSTURE](docs/reference/PQC-POSTURE.md) · [RED-TEAM-SCOPE](docs/RED-TEAM-SCOPE.md) · [threat model](docs/design/threat-model.md) |
| Integrating against it | [API](docs/reference/API.md) · [DATA-MODEL](docs/reference/DATA-MODEL.md) · [GLOSSARY](docs/reference/GLOSSARY.md) |
| Running an instance | [docs/operator/](docs/operator/README.md), the operator runbooks and ledgers, from install to disaster recovery |
| Asking why a mechanism is built this way | [docs/design/](docs/design/README.md), one record per mechanism plus the cross-cutting notes |
| Reading it as an academic artifact | [The project report](docs/paper/polaris_project_report.pdf) (PDF, same license) · [CITATION.cff](CITATION.cff) |
| Working on the code, human or AI agent | [CONTRIBUTING.md](CONTRIBUTING.md) · [CLAUDE.md](CLAUDE.md) · [CHANGELOG.md](CHANGELOG.md) |

---

## Scope, honestly

- **Educational reference implementation.** Built as a portfolio project for Seton Hill University, Spring 2026. Notional data only; not a deployed identity system, and the seeded credentials above are deliberately public.
- **Not production-ready, and says so.** The remaining gaps are operator decisions (the production key-custody choice: HSM, KMS, or software module, since no production HSM is chosen here; offsite backup target; alerting backend; legal review; external penetration test), not missing code. The honest ledger is [PRODUCTION-READINESS.md](docs/PRODUCTION-READINESS.md).
- **Security disclosures** go through [SECURITY.md](SECURITY.md); `/.well-known/security.txt` ships with the stack.

---

## License

[Apache License 2.0](LICENSE). Copyright 2026 Egor Khaklin.

The license carries an explicit patent grant and attribution preservation. If you build on the code, the schema, or the patterns (audit-of-record discipline, the constraint lattice, the flat invariant-check layer), retain [LICENSE](LICENSE) and [NOTICE](NOTICE). Third-party attributions (Plonky2, MapLibre, Flask, and others) are in [NOTICE](NOTICE).

If you read one document after this one, read [MISSION.md](MISSION.md).
