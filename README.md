<div align="center">

<img src="site/polaris_logo_clean.png" alt="Polaris" width="220" height="220">

# POLARIS

**A working reference implementation of an issuer-unlinkable, duress-aware<br>identity-token system, signed with ML-DSA-65 under an audited algorithm-migration path.**

CI builds and boots the production-profile container stack on every push, proves the post-quantum handshake and the backup round trip, and runs the disaster-recovery drill. It is a reference implementation, not a deployment.

[![CI](https://img.shields.io/github/actions/workflow/status/EgorKhaklin/polaris-id/ci.yml?branch=main&label=CI&logo=githubactions&logoColor=white&style=flat-square)](https://github.com/EgorKhaklin/polaris-id/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/EgorKhaklin/polaris-id?include_prereleases&label=release&color=2b5797&style=flat-square)](https://github.com/EgorKhaklin/polaris-id/releases/latest)
[![License](https://img.shields.io/badge/license-Apache--2.0-3b6e48?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/status-reference%20implementation%2C%20not%20production-b8860b?style=flat-square)](docs/PRODUCTION-READINESS.md)

<sub>Every release ships SBOMs with signed SLSA provenance; verify one with `gh attestation verify` ([SECURITY.md](SECURITY.md)).</sub>

[**Project site**](https://egorkhaklin.github.io/polaris-id/) · [What it is](#what-it-is) · [Status](#status) · [Try it](#try-it) · [The ten guarantees](#the-ten-guarantees) · [Architecture](#architecture) · [Verified](#verified-not-asserted) · [Run it](#run-it) · [Documentation](#documentation)

</div>

---

## What it is

Polaris issues, holds, presents and verifies one credential per person, and it answers the two questions a relying party has about a presented credential separately, because they have different lifetimes:

- **Authenticity, offline.** Is the ML-DSA-65 signature genuine? A standalone detached verifier answers against published keys, with no Polaris code, no database and no network. The answer never changes.
- **Authorization, fresh.** Is the credential authoritative right now? A versioned relying-party API answers online, or a short-lived signed status assertion the holder staples answers offline. The answer can change tomorrow.

A relying party needs both, and the verdict keeps them apart ([Try it](#try-it)). Python and TypeScript verify SDKs and a language-agnostic conformance suite of 118 published cases make "correctly verifying a Polaris credential" a contract anyone can hold their own code to. Around the credential sits a protocol of signed statements (an authority's registry and trust list, exchange receipts, timestamps, signed documents, a credential-bound login token, offline wallet presentations), each verified offline by the same verifier and both SDKs. Version 1 of that protocol is frozen, and a cross-version suite proves on every push that today's verifiers still accept what version 1 published. Trust between agencies is explicit and non-transitive.

The backbone is a 45-table PostgreSQL schema whose constraints are the security boundary: **the guarantees live in the database, not in application code.** A rule enforced by a trigger, a CHECK constraint or a unique index binds every client, survives every restore from backup and cannot be bypassed by the next caller. Around it sit a Rust ZK-SNARK prover with an independent second witness, a Flask application and an operator CLI, a hardened five-service container stack behind a post-quantum TLS edge, and a flat layer of 319 machine-checked invariants (v1.0.0-rc.7) that gates every change in CI.

**The problem it models.** Americans carry six to eight credentials that do not talk to each other: driver's license, passport, Social Security card, Real ID, voter registration, insurance card. Each is a separate artifact, signed by a separate authority, secured to a separate standard, with no shared revocation path and no shared audit trail. Polaris models consolidating them into **one active credential record per person**, verified through **context-scoped events** (banking, voting and healthcare are different events with different disclosure rules) at three disclosure levels. The default level is **zero-knowledge**: the typical verification stores no token identifier at all, so the verification graph cannot be reconstructed even by someone holding the whole database.

**Three limits, stated before the rest of the page.**

- *Zero knowledge here means two specific things.* A zero-knowledge-mode verification stores no token identifier, and a Plonky2 SNARK proves that a token was in a published ledger and nothing else. Polaris is **not** a general selective-disclosure or anonymous-credential system, and does not claim to be.
- *Relying-party correlation is bounded, not eliminated.* Unlinkability is issuer-side: a zero-knowledge-mode verification stores no token identifier, so the issuer's database cannot rebuild the graph. What a verifier is **shown** is a separate question from what it has to **store**. A full presentation still shows a stable `token_value`, issuer signature and holder public key, so two relying parties who keep the raw material can correlate; the login subject and the presentation handle are derived per relying party, so the value a verifier writes down is unrecognisable at the next one. The detached verifier reports a plain presentation as `exposed` and the zero-knowledge form as `bounded`. Blinded presentations, one-time presentation tokens and anonymous credentials are unbuilt. The findings are in [lab/linkability](lab/linkability/README.md).
- *Offline authorization trades revocation latency for issuer non-observation.* A revoked credential's last signed ACTIVE assertion stays valid until it expires, one hour by default, a policy number and not a law. A verifier tightens the window with its own `max_age`; a high-risk one demands online status. Issuer non-observation, offline availability and revocation freshness cannot all be maximized at once.

---

## Status

**1.0.0-rc.3, a release candidate.** The tree and all four published packages are the same version as of 2026-09-18.

| | version | where |
|---|---|---|
| this tree | 1.0.0-rc.3 | the source you are reading |
| `polaris-verify`, `polaris-sdk-python`, `polaris-oid4vp` | 1.0.0rc3 | PyPI |
| `polaris-sdk-ts` | 1.0.0-rc.3 | npm, under `next`; `latest` stays 0.1.0, so a plain install resolves the stable release |

Each candidate exists because a defect was found in the one before it, which is the only thing that moves the number. rc.2 collected twenty-two, measured inside the downloaded wheels rather than inferred, under [**What a stranger installing rc.1 has**](CHANGELOG.md#v100-rc2--2026-09-17-a-defect-found-in-the-candidate). rc.3 resolved two published-contract ambiguities found by an outside design-intent review: a genuine signature no longer implies a trusted issuer at the detached verifier's exit code, and `issuer_authentic` became two fields because one boolean was reporting every credential issued before a key rotation as inauthentic.

Publishing to a registry is irreversible and is the owner's call, recorded run by run in [docs/RELEASING.md](docs/RELEASING.md).

The four standalone products are `polaris-verify`, `polaris-oid4vp` and `polaris-sdk-python` on PyPI and `polaris-sdk-ts` on npm, every run recorded in [docs/RELEASING.md](docs/RELEASING.md); `--pre` because pip skips a candidate unless told, and on npm the candidate is `polaris-sdk-ts@next`, so 0.1.0 remains what a plain install resolves. The PyPI packages are published by GitHub Actions trusted publishing over OIDC, with no API token created at any point, and each is verified by installing from the live registry into a clean environment and running it there. Being installable is not being validated: see [scope](#scope-honestly).

Two things here were checked by someone other than the author:

- **An unmodified wallet spoke to the verifier.** On 15 September 2026 a stock [walt.id](https://walt.id) Wallet API v2 (`waltid/wallet-api2:1.0.0`) presented an SD-JWT VC to `polaris-oid4vp` over OpenID4VP 1.0 and was accepted, the key binding signed by a P-256 key that never left the wallet. It refused Polaris first, correctly: `keygen` was emitting a request-signing certificate with no `digitalSignature` key usage, which eleven conformance modules, 142 package tests and every check in the invariant layer had passed over. You can repeat the exchange in about ten minutes from a clean machine: [STRANGER-PATH.md](docs/STRANGER-PATH.md).
- **The OpenID Foundation's hosted suite ran the profile.** Eleven modules of `oid4vp-1final-verifier-haip-test-plan` across the open internet, zero failures and zero warnings. Seven negative modules carry the service's own `result: PASSED`; four positive modules sit in REVIEW, awaiting a Foundation reviewer. **REVIEW is not PASSED, and Polaris is not yet certified.**

Everything else on this page is this project checking itself. The counterweight: this is one unpaid author's reference implementation on notional data. It has never held real identity data, no independent security review of it exists, no operator other than the author has run it, and there has been no pilot. That operator is what separates the candidate from 1.0.0. The row-by-row ledger of what has and has not happened outside the project is [the scoreboard](lab/EXTERNAL-NOUNS.md).

---

## Try it

The verifier installs from PyPI and runs with no database, no server and none of the rest of this repository:

```bash
pip install --pre "polaris-verify[cryptography]"
# does the signature verify? issuer trust NOT evaluated
polaris-verify --pqc-provider auto --signature-only --pack your-credential.json

# the real question: and does that key belong to an issuer you trust?
polaris-verify --pqc-provider auto --issuer-anchor trusted-keys.json --pack your-credential.json
```

It refuses to start until the run says what cryptography it is doing. There is no default and no environment variable for that choice, because a verifier that quietly stopped verifying still answers every question.

**A genuine signature is not a trusted issuer**, and the second flag is how you say which question you asked. Without `--issuer-anchor` the tool can tell you the signature is mathematically valid and nothing about whose key made it, so it abstains (exit 2) rather than returning a success anyone could read as trust. `--signature-only` says that cryptographic validity alone is genuinely what you wanted.

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

That is the whole product in one object: authenticity is permanent and cacheable, authorization is fresh and revocable, and a relying party needs both.

From a clone, with a standard ML-DSA-65 library (`pip install liboqs-python cryptography`), the parts a relying party actually runs:

```bash
python3 scripts/polaris-verify.py --pqc-provider oqs --selftest
python3 scripts/polaris-verify.py --pqc-provider oqs --verify-dir vectors
python3 conformance/run_conformance.py --self
python3 scripts/polaris-compat-suite.py
```

In order: a live ML-DSA-65 sign/verify round trip; the published authenticity packs, where the genuine one passes and every tampered one fails; the reference verify SDK against the 118 published cases; and the frozen version-1 protocol under today's verifiers, with today's cases under a pinned older verifier. These are the detached verifier and the conformance suite: the same code a third party integrates, and the same code CI runs on every push. The full stack, with issuance, the operator flows and the Atlas, is under [Run it](#run-it).

---

## The ten guarantees

Above the ten sits the project's vocation: **no person can be compelled to renounce, transfer, or surrender their identity against their will.** Features that drift toward surveillance or population-scale aggregation are refused, and the refusal is structural: the schema carries no attribute to filter a population by. Five **constitutional** guarantees (C1, C2, C3, C6, C10) may not be relaxed without amendment; five **engineering** invariants (C4, C5, C7, C8, C9) keep them honest under load and attack.

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

Each guarantee is machine-checked by [`polaris_checks`](polaris_checks/): 319 plain `check_*` functions (v1.0.0-rc.13), each paired with a detection test proving it fails on a broken fixture. A check that cannot detect its own violation is treated as broken. Why these ten, and why they interlock: [MISSION.md](MISSION.md) and [meta/constraint-lattice.md](meta/constraint-lattice.md).

---

## Threats answered by construction

Consolidating cards is the easy half. The hard half is the adversary. Six threats are answered at the database layer, not in policy documents.

| Threat | In practice | The answer | Detail |
|---|---|---|---|
| **Cryptographic compulsion** | "Sign this or I break your fingers." | A second secret produces a verification that looks identical and silently records a `DuressEvent`. Every operator-visible surface shows success, tested across every operator-reachable page. **Bounded:** this resists a coercer who does not know the mechanism exists. It does not resist one watching the holder type, and against lawful or institutional access it is net-negative, because the `DuressEvent` is append-only and cannot be erased. | [duress-codes](docs/design/duress-codes.md) · [the assessment](lab/duress/README.md) |
| **Catastrophic loss** | Token lost; the holder has nothing to prove who they are. | A two-phase recovery ceremony with independent out-of-band channels, a cooldown, and an admin-gated completion. | [recovery-ceremony](docs/design/recovery-ceremony.md) |
| **Algorithm agility** | A signature algorithm can fall to cryptanalysis or to an implementation flaw, and a credential outlives the assumption it was signed under. | The algorithm is a row in `CryptographicAlgorithm`, not a constant (C7), authorized per authority and migrated through `uc6_migrate` on a path CI runs. Tokens carry classical and post-quantum signatures during cutover, with a database rule that exactly one is active. | [multi-sig-migration](docs/design/multi-sig-migration.md) |
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
| [`polaris_checks/`](polaris_checks/) | The invariant layer. 319 checks (v1.0.0-rc.13), each with a tested failure mode. `python3 -m polaris_checks.run` gates CI. |
| [`packages/`](packages/), [`sdk/`](sdk/), [`conformance/`](conformance/) | The standalone products: the detached verifier, the OpenID4VP verifier, the Python and TypeScript verify SDKs, and the conformance suite that holds any verifier to the published cases. |
| [`scripts/`](scripts/), [`deploy/`](deploy/) | The holder wallet and relying-party verifier (`polaris-wallet.py`, `polaris-relying-party.py`), operator tooling (backup, restore, archive, purge, migrate, recover-admin) and observability config (Prometheus alerts, Grafana dashboards-as-code, opt-in OTel tracing). |

The production topology is five services: a self-built Caddy TLS edge, gunicorn, PgBouncer, PostgreSQL with pgBackRest WAL archiving, and Redis, every one non-root with all Linux capabilities dropped. The Atlas plots verification and lifecycle events over that stack; zero-knowledge verifications are never plotted, because a zero-knowledge event carries no token id to attribute it by.

---

## Cryptography

The claim is **algorithm agility under an audited migration path**, not settled security against a quantum adversary. ML-DSA-65 rests on the hardness of Module-LWE against the best known classical and quantum algorithms, and whether that holds is mathematics, not a property of this repository. What is a property of this repository: the algorithm is a row in `CryptographicAlgorithm` rather than a constant (C7), so registering a replacement, authorizing it per authority and migrating credentials through `uc6_migrate` is a path CI exercises on every push. There is no "migrate when quantum arrives" deferral; the registered default is already ML-DSA-65.

| Algorithm | Family | PQ | Standard | Security (bits) | Public key | Signature | Role |
|---|---|:---:|---|:---:|---:|---:|---|
| ML-DSA-65 | ML-DSA | ✓ | FIPS 204 | 192 | 1,952 B | 3,309 B | default |
| ML-DSA-87 | ML-DSA | ✓ | FIPS 204 | 256 | 2,592 B | 4,627 B | accepted; migration is a key event |
| SLH-DSA-128s | SLH-DSA | ✓ | FIPS 205 | 128 | 32 B | 7,856 B | registered, no signer |
| SLH-DSA-256s | SLH-DSA | ✓ | FIPS 205 | 256 | 64 B | 29,792 B | registered, no signer |
| ECDSA-P256 | ECDSA | | FIPS 186-4 | 128 | 64 B | 72 B | legacy, sunset 2027 |

- **Two ML-DSA implementations at issuance, sampled at use.** Issuance requires liboqs and OpenSSL (via `cryptography`) to agree and fails closed if they do not, so no stored production signature is trusted from a single library. Verify-at-use is single-witness with continuous second-witness sampling, and a disagreement pages a SEV. The Rust prover's ZK epoch root is recomputed bit-for-bit by a Python second witness.
- **SLH-DSA is a registered hedge, not a shipped signer.** ML-DSA rests on lattice assumptions and SLH-DSA on hash functions alone, so both SLH-DSA parameter sets sit in the registry and a rotation toward them is a row update; the signers wired today are ML-DSA-65 and ML-DSA-87. The gap is on the ledger in [PQC-POSTURE.md](docs/reference/PQC-POSTURE.md).
- **The TLS edge negotiates post-quantum key exchange.** X25519MLKEM768 hybrid KEX with capable clients, proven in CI on every push. What remains classical (internal TLS hops, certificates, WebAuthn credentials on today's authenticators) is mapped in the same ledger.
- **The ZK proof is transparent.** Plonky2 is FRI-based: no trusted setup. The proof answers "was this token in the ledger at epoch N" and nothing else. Source: [`polaris_zk/src/lib.rs`](polaris_zk/src/lib.rs).

**Two limits a reader should have before believing the word.** Without `POLARIS_USE_REAL_PQC=1` and liboqs, the default signing path writes a 32-byte deterministic SHA3-256 placeholder that verifies against no key, and that is the default in CI; production fails closed without real signing, and the placeholder is a named development profile. And a credential carries a classical signature alongside the post-quantum one during cutover, which nothing here protects: anything harvested today is readable the day that half falls, whatever is migrated to afterwards. Both, and what a break in Module-LWE would and would not cost, are in [PRODUCTION-READINESS.md](docs/PRODUCTION-READINESS.md).

---

## Verified, not asserted

Every claim above is backed by a gate that fails if the claim stops being true. The table, check, route and CI-job counts are re-measured by `polaris_checks` on every run and are current; the two test counts are a point-in-time measurement (v1.0.0-rc.3) and are restated when re-measured, never extrapolated.

| Layer | Scale | What it proves |
|---|---|---|
| Product tests (live database) | 1030 | Every CHECK constraint, every use case, every route, redaction at every read path, concurrency with real threads, the secret store; `test_app`, `test_cli`, `test_check_constraints`, the two property suites, `test_secretstore` |
| Crypto witnesses | 107 passing of 112 collected | ML-DSA sign/verify under both accepted parameter sets against both witnesses, in-file and in a software PKCS#11 module (Kryoptic) custody; the Rust and Python epoch roots agree; `test_pqc_signing`, `test_custody`, `test_zk_second_witness`, `witness2` |
| Invariant checks | 319 | C1-C10 plus production posture, each check paired with a detection test |
| CI jobs | 20 | Below |

Both test rows count tests passing on the reference machine at v1.0.0-rc.3 (`pytest -q` per suite). The three product tests skipped there need real ML-DSA and four of the crypto tests a PKCS#11 module, and CI runs both; the fifth needs a real KMS key and is opt-in, so it runs nowhere in this repository.

CI does not just run tests; it exercises the artifacts. On every push it:

- builds and boots the dev and prod images, then the five-service production-profile stack end to end, and asserts health through the TLS edge;
- round-trips an encrypted backup and restore with a fail-closed negative check and an off-site S3 drill, then kills the primary and restores it from the WAL archive while measuring RPO and RTO;
- rolls a deploy under traffic and counts dropped requests, and fails the HA profile's leader, lease store and etcd member under a live write stream;
- installs the Linux server profile on Debian and Rocky, and boots the Kubernetes reference profile on kind;
- pages a duress alert through Prometheus and Alertmanager to a webhook;
- proves the post-quantum TLS handshake against a real certificate, and signs and verifies with real ML-DSA-65 both in the production image and inside a software PKCS#11 module (Kryoptic; not a hardware HSM);
- runs the protocol drills: two instances federating under different ML-DSA parameter sets, the trust-list compromise recovery, the frozen version-1 compatibility suite in both directions;
- gates on CVE scans of both the Python dependency surface and all five self-built container images.

Most of those jobs carry a comment naming the specific past failure they exist to prevent. The pattern behind them: every defect class found by running the system, rather than reading it, gets a permanent gate.

```bash
python3 -m polaris_checks.run      # the invariant layer, no database needed
python3 scripts/polaris-ship.py run  # the full local gate: 912 sharded + 627 unsharded tests
./scripts/polaris-test.sh          # the four DB-heavy modules only (912), for an inner loop
./polaris_mac_launch.sh test       # the same four, via the launcher
```

`polaris-ship.py run` is the one that matches CI. `polaris-test.sh` runs the four modules CI
shards and none of the suites it does not, which is a real gap rather than a detail: twice in
one day a commit passed the narrower command and went red in CI on a file none of those four
modules imports.

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

On a fresh Debian, Ubuntu or RHEL-family server, one script does all of the above under systemd: `sudo POLARIS_DOMAIN=polaris.example.com deploy/linux/install.sh` ([LINUX-SERVER](docs/operator/LINUX-SERVER.md), then [HARDENING](docs/operator/HARDENING.md)). On a Kubernetes cluster, the Helm reference profile deploys the same topology with enforced network policies and the restricted pod security standard ([KUBERNETES](docs/operator/KUBERNETES.md)). Caddy provisions TLS automatically; `/api/health` reports structured per-component status. Runbooks: [INSTALL](docs/operator/INSTALL.md) · [OPERATIONS](docs/operator/OPERATIONS.md) · [SECRETS](docs/operator/SECRETS.md) · [DR](docs/operator/DR.md) · [FAILOVER](docs/operator/FAILOVER.md). Diagnostics: `./polaris_mac_launch.sh doctor`; the full launcher reference: `./polaris_mac_launch.sh --help`.

---

## Where Polaris sits

| System | Deployed to a real population | National-scope issuance | Post-quantum default | Unlinkable verification default | Duress-aware primitive | Append-only audit at schema |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Real ID (US) | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| mDL / ISO 18013-5 | ✓ | ✓ | ✗ | partial | ✗ | ✗ |
| Aadhaar (India) | ✓ | ✓ | ✗ | ✗ | ✗ | partial |
| e-Estonia | ✓ | ✓ | ✗ | ✗ | ✗ | partial |
| W3C DIDs / VCs | partial | ✗ | method-dependent | method-dependent | ✗ | n/a |
| **Polaris** | **✗** | **✗** | ✓ | ✓ | ✓ | ✓ |

The first two columns are the honest ones: every other row is deployed to real people at national scale, and Polaris is neither deployed nor issuing at that scale. Its remaining ticks mark design properties present in the codebase, not a deployment; this compares designs, and Polaris runs on notional data. No single row is novel. The point is the assembly: all five properties in one working codebase, each enforced at the schema level and machine-checked rather than asserted in prose. The closest deployed system is mDL, which has selective disclosure and real signatures but no post-quantum default, no duress primitive, and no constitutional layer governing the issuer itself.

---

## Documentation

| If you are | Start with |
|---|---|
| Wanting to prove it works, yourself, in ten minutes | [STRANGER-PATH.md](docs/STRANGER-PATH.md): clean machine to one accepted presentation from an external wallet. If it fails for you, that is the most useful bug this project can receive |
| Deciding whether this is worth your time | [MISSION.md](MISSION.md), the constitution: what the system refuses to do and why |
| Reviewing the architecture | [ARCHITECTURE-OVERVIEW](docs/ARCHITECTURE-OVERVIEW.md) · [SYSTEM-MAP](docs/reference/SYSTEM-MAP.md) |
| Reading the security posture | [SECURITY.md](SECURITY.md) · [PQC-POSTURE](docs/reference/PQC-POSTURE.md) · [RED-TEAM-SCOPE](docs/RED-TEAM-SCOPE.md) · [threat model](docs/design/threat-model.md) |
| Integrating against it | [API](docs/reference/API.md) · [DATA-MODEL](docs/reference/DATA-MODEL.md) · [GLOSSARY](docs/reference/GLOSSARY.md) |
| Running an instance | [docs/operator/](docs/operator/README.md), the operator runbooks and ledgers, from install to disaster recovery |
| Asking why a mechanism is built this way | [docs/design/](docs/design/README.md), one record per mechanism plus the cross-cutting notes |
| Reading it as an academic artifact | [The project report, Version 3](docs/paper/polaris_project_report_v3.pdf) (PDF, same license; the system at 1.0.0-rc.7) · [the same in Russian](docs/paper/polaris_project_report_v3_ru.pdf) · [CITATION.cff](CITATION.cff) |
| Working on the code, human or AI agent | [CONTRIBUTING.md](CONTRIBUTING.md) · [CLAUDE.md](CLAUDE.md) · [CHANGELOG.md](CHANGELOG.md) |

---

## Scope, honestly

- **Educational reference implementation.** Built as a portfolio project for Seton Hill University, Spring 2026. Notional data only; not a deployed identity system, and the seeded credentials above are deliberately public.
- **Not production-ready, and says so.** The remaining gaps are operator decisions (the production key-custody choice: HSM, KMS, or software module, since no production HSM is chosen here; offsite backup target; alerting backend; legal review; external penetration test), not missing code. The honest ledger is [PRODUCTION-READINESS.md](docs/PRODUCTION-READINESS.md).
- **Security disclosures** go through [SECURITY.md](SECURITY.md); `/.well-known/security.txt` ships with the stack.

---

## License

[Apache License 2.0](LICENSE). Copyright 2026 Egor Khaklin. Apache 2.0 rather than MIT or BSD for its section 3, an express and irrevocable patent grant from every contributor, which is what a reference implementation of a lattice signature scheme needs while the patent landscape around post-quantum cryptography is younger than the algorithms; copyleft would defeat the purpose, which is to be built on.

If you build on the code, the schema or the patterns, retain [LICENSE](LICENSE) and [NOTICE](NOTICE) per section 4. [NOTICE](NOTICE) names every dependency license: all permissive except psycopg2 (LGPL 3 with an OpenSSL exception, used unmodified through its public API). `check_license_is_pinned` holds LICENSE, NOTICE, all five package manifests and this section to the same identifier, so a package added later cannot ship without one.

If you read one document after this one, read [MISSION.md](MISSION.md).
