<div align="center">

<img src="docs/assets/hero.svg" width="100%" alt="Polaris ID">

**Polaris ID is identity infrastructure built to be checked, not trusted.**

[![CI](https://img.shields.io/github/actions/workflow/status/EgorKhaklin/polaris-id/ci.yml?branch=main&label=CI&logo=githubactions&logoColor=white&labelColor=0a1421&style=flat-square)](https://github.com/EgorKhaklin/polaris-id/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/EgorKhaklin/polaris-id?include_prereleases&label=release&color=c9a352&labelColor=0a1421&style=flat-square)](https://github.com/EgorKhaklin/polaris-id/releases/latest)
[![Status: pre-pilot, notional data](https://img.shields.io/badge/status-pre--pilot_%C2%B7_notional_data-9a6b2f?labelColor=0a1421&style=flat-square)](#status)
[![License](https://img.shields.io/badge/license-Apache--2.0-2b5797?labelColor=0a1421&style=flat-square)](LICENSE)
[![Discord](https://img.shields.io/badge/Discord-join_the_server-5865F2?logo=discord&logoColor=white&labelColor=0a1421&style=flat-square)](https://discord.gg/ragewuCKj)
[![OpenSSF Best Practices](https://img.shields.io/cii/level/15004?label=OpenSSF%20best%20practices&labelColor=0a1421&style=flat-square)](https://www.bestpractices.dev/projects/15004)
[![OpenSSF Baseline](https://www.bestpractices.dev/projects/15004/baseline)](https://www.bestpractices.dev/projects/15004)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/EgorKhaklin/polaris-id/badge)](https://scorecard.dev/viewer/?uri=github.com/EgorKhaklin/polaris-id)

[![OpenID Certified: polaris-oid4vp verifier](https://img.shields.io/badge/OpenID_Certified-polaris--oid4vp_verifier-c9a352?labelColor=0a1421&style=flat-square)](docs/reference/SPEC-COMPLIANCE.md#openid-certified)
[![OpenID4VP 1.0](https://img.shields.io/badge/OpenID4VP-1.0-2b5797?labelColor=0a1421&style=flat-square)](docs/reference/SPEC-COMPLIANCE.md#openid4vp-10)
[![HAIP 1.0](https://img.shields.io/badge/HAIP-1.0-2b5797?labelColor=0a1421&style=flat-square)](docs/reference/SPEC-COMPLIANCE.md#haip-10)
[![SD-JWT VC](https://img.shields.io/badge/SD--JWT_VC-supported-2b5797?labelColor=0a1421&style=flat-square)](docs/reference/SPEC-COMPLIANCE.md#sd-jwt-vc)
[![OpenID4VCI 1.0](https://img.shields.io/badge/OpenID4VCI-1.0-2b5797?labelColor=0a1421&style=flat-square)](docs/reference/SPEC-COMPLIANCE.md#openid4vci-10)
[![Token Status List](https://img.shields.io/badge/Token_Status_List-IETF_draft-2b5797?labelColor=0a1421&style=flat-square)](docs/reference/SPEC-COMPLIANCE.md#token-status-list)

[![ML-DSA-65](https://img.shields.io/badge/ML--DSA--65-FIPS_204-5b4b8a?labelColor=0a1421&style=flat-square)](docs/reference/SPEC-COMPLIANCE.md#ml-dsa-65)
[![PyPI](https://img.shields.io/badge/PyPI-polaris--verify-3775a9?labelColor=0a1421&style=flat-square)](https://pypi.org/project/polaris-verify/)
[![npm](https://img.shields.io/badge/npm-polaris--sdk--ts-cb3837?labelColor=0a1421&style=flat-square)](https://www.npmjs.com/package/polaris-sdk-ts)

<a href="https://polaris-id.e-khaklin.workers.dev/"><img src="docs/assets/nav/project-site.svg" alt="Project site"></a>
<a href="#what-it-is"><img src="docs/assets/nav/what-it-is.svg" alt="What it is"></a>
<a href="#status"><img src="docs/assets/nav/status.svg" alt="Status"></a>
<a href="#try-it"><img src="docs/assets/nav/try-it.svg" alt="Try it"></a>
<a href="#the-ten-guarantees"><img src="docs/assets/nav/the-ten-guarantees.svg" alt="The ten guarantees"></a>
<a href="#architecture"><img src="docs/assets/nav/architecture.svg" alt="Architecture"></a>
<a href="#verified-not-asserted"><img src="docs/assets/nav/verified.svg" alt="Verified"></a>
<a href="#run-it"><img src="docs/assets/nav/run-it.svg" alt="Run it"></a>
<a href="#documentation"><img src="docs/assets/nav/documentation.svg" alt="Documentation"></a>

</div>

<img src="docs/assets/rule.svg" width="100%" alt="">

## What it is

Polaris issues, holds, presents and verifies one credential per person, and answers a relying party's two questions separately:

- **Authenticity, offline.** Is the ML-DSA-65 signature genuine? A standalone verifier answers against published keys, with no database and no network.
- **Authorization, fresh.** Is the credential authoritative right now? A relying-party API answers online, or a short-lived signed status assertion answers offline.

Around the credential:

- **The schema is the security boundary.** A 57-table PostgreSQL schema whose triggers, CHECK constraints and unique indexes bind every client: **the guarantees live in the database, not in application code.**
- **Verifiers anyone can hold to a contract.** Python and TypeScript SDKs and a conformance suite of 281 published cases; version 1 of the signed-statement protocol is frozen and re-verified on every push.
- **Explicit federation.** Trust between agencies is explicit and non-transitive.
- **Zero-knowledge by default.** A zero-knowledge verification stores no token identifier; a Plonky2 SNARK, re-checked by an independent second witness, proves ledger membership and nothing else.
- **Gated by invariants.** 344 machine-checked invariants (v1.0.0-rc.70) gate every change in CI.

**The problem it models.** Americans carry six to eight credentials (driver's license, passport, Social Security card and more) with no shared revocation path or audit trail. Polaris models one active credential record per person, verified through context-scoped events (banking, voting, healthcare) at three disclosure levels.

**Three limits.**

- *Zero knowledge means two specific things:* no token identifier stored, and a membership proof. Polaris is **not** a general selective-disclosure or anonymous-credential system.
- *Relying-party correlation is bounded, not eliminated.* What a verifier is **shown** differs from what it has to **store**: a full presentation still shows a stable `token_value`, so two relying parties keeping raw material can correlate. Per-relying-party identifiers mean the value a verifier writes down is unrecognisable at the next one. Findings: [lab/linkability](lab/linkability/README.md).
- *Offline authorization trades revocation latency for issuer non-observation.* A revoked credential's last ACTIVE assertion stays valid until it expires (one hour by default); a high-risk verifier demands online status.

<img src="docs/assets/rule.svg" width="100%" alt="">

## Status

<a href="https://openid.net/certification/certified-oid4vp-haip-final/"><img src="docs/assets/openid-certified-mark-on-white.png" alt="OpenID Certified" width="150"></a>

**`polaris-oid4vp 1.0.0rc7` is OpenID® Certified™ by Egor Khaklin to the OpenID4VP 1.0 + HAIP 1.0 Verifier profile** (`sd_jwt_vc`, `direct_post.jwt`; [listing](https://openid.net/certification/certified-oid4vp-haip-final/), 24 September 2026). A self-certification the Foundation reviewed and published, for that package version in that role: not an endorsement, not an audit, and not a certification of the rest of Polaris. OpenID® and OpenID® Certified™ are trademarks of the OpenID Foundation, used under its [certification terms](https://openid.net/certification/mark/).

| | version | where |
|---|---|---|
| this tree | 1.0.0-rc.70 | the source you are reading |
| `polaris-oid4vp` | 1.0.0rc14 | PyPI; 1.0.0rc7 is the certified version |
| `polaris-verify`, `polaris-sdk-python` | 1.0.0rc7 | PyPI |
| `polaris-id-cli` | 1.0.0rc1 | PyPI; the operator CLI, for a running Polaris PostgreSQL |
| `polaris-sdk-ts` | 1.0.0-rc.9 | npm, under `next` (`latest` stays 0.1.0) |

- **A release candidate.** A new candidate is cut as a release that collects the defects fixed since the last: see [releases](https://github.com/EgorKhaklin/polaris-id/releases) and the [CHANGELOG](CHANGELOG.md). What separates it from 1.0.0 is an operator who is not the author.
- **Installing:** `pip install --pre` (pip skips candidates otherwise); npm `polaris-sdk-ts@next`. PyPI packages use trusted publishing over OIDC. Every publish is recorded in [RELEASING.md](docs/RELEASING.md).

### Tested against

Outside OpenID4VP implementations present to the verifier, each unmodified unless its row says
otherwise: configuration only (trust anchors, TLS roots). Every walk also sends controls that must be refused, because a verifier
that accepts everything prints the same success line; among them a wrong issuer key under the same
`kid`, the answered request again, a mismatched `client_id`, a key the wallet does not hold and an
untrusted CA.
The [wallet canary](.github/workflows/wallet-canary.yml) re-runs the walks every week against the
newest `polaris-oid4vp` on PyPI.

| Implementation | Maintained by | Language | Last walk | Re-run weekly |
|---|---|---|---|---|
| [walt.id Wallet API v2](lab/interop/waltid/README.md) | walt.id | Kotlin | 1.1.1, against 1.0.0rc16 (2026-10-04) | 1.1.1 by digest, and the latest |
| [Credo](lab/interop/credo/README.md) | OpenWallet Foundation | TypeScript | 0.7.2, against 1.0.0rc14 (2026-10-03) | the lock file's release, and the latest |
| [`eudi-lib-jvm-openid4vp-kt`](lab/interop/eudi-kt/README.md), the EUDI Wallet's OpenID4VP library, under a wallet built here | European Commission | Kotlin | 0.16.2, against 1.0.0rc16 (2026-10-04) | 0.16.2 |
| [vck](lab/interop/vck/README.md) (`vck-openid-ktor`), under a wallet built here; vck also issued the credential | A-SIT Plus | Kotlin | 8.0.0, against 1.0.0rc16 (2026-10-04) | 8.0.0 |
| [`eudi-lib-ios-openid4vp-swift`](lab/interop/eudi-ios/README.md), the EUDI Wallet's iOS OpenID4VP library, under a wallet built here | European Commission | Swift | 0.43.2, against 1.0.0rc16 (2026-10-04) | 0.43.2, on macOS |
| [irmago](lab/interop/irmago/README.md), the library under the Yivi wallet, under a wallet built here | Privacy by Design Foundation (Yivi) | Go | v1.4.0, against 1.0.0rc16 (2026-10-04) | v1.4.0 |
| [SpruceID `openid4vp`](lab/interop/spruceid/README.md), its conformance adapter with the test issuer replaced | SpruceID | Rust | e5f29b85, against 1.0.0rc16 (2026-10-04) | e5f29b85 |
| [Procivis One Core](lab/interop/procivis/README.md) (`core-server`), which also issued the credential | Procivis | Rust | v1.87.2, against 1.0.0rc16 (2026-10-04) | v1.87.2 |
| [ProtocolSoup](lab/interop/protocolsoup/README.md), its wallet harness | ParleSec | Go | v4.0.0, against 1.0.0rc16 (2026-10-04) | v4.0.0 (listed by the OpenID Foundation as certified) |
| [The EU reference PID issuer](lab/interop/eudi-issuer/README.md) (`eudi-srv-pid-issuer`), issuing to a wallet built here on the EU's OpenID4VCI and OpenID4VP libraries | European Commission | Kotlin | v0.11.1, against 1.0.0rc16 (2026-10-04) | v0.11.1 |
| [Credo on a cheqd ledger](lab/interop/cheqd/README.md), the issuer a `did:cheqd` with its status list on the ledger | cheqd, OpenWallet Foundation | TypeScript, Go | cheqd-node 4.2.1 and Credo 0.7.2, against 1.0.0rc15 (2026-10-04) | cheqd-node 4.2.1 |
| [Multipaz](lab/interop/multipaz/README.md), under a wallet built here | OpenWallet Foundation | Kotlin | 0.101.0, against 1.0.0rc16 (2026-10-04) | 0.101.0 |
| [ERICA](lab/interop/erica/README.md), the German EUDI Wallet programme's verifier testing tool, with its negative modes | the German EUDI Wallet programme (opencode.de) | TypeScript | 2c27dc92, against this repository (2026-10-04; the German PID type needs `--vct`, not in 1.0.0rc15) | |
| [eudi-dev](lab/interop/eudi-dev/README.md), HAIP strict mode with its TLS check on | dominikschlosser | Go | v2.5.1, against 1.0.0rc15 (2026-10-04) | v2.3.7 (listed by the OpenID Foundation as certified), the latest, its own binary, its own issuer's PID |
| [OID4VCgo](lab/interop/oid4vcgo/README.md) | IDFoundry | Go | 0.25.0, against 1.0.0rc14 (2026-10-03) | 0.12.0 (listed as certified), and the latest |
| [The OpenID Foundation's conformance suite](docs/reference/SPEC-COMPLIANCE.md#openid-certified) | OpenID Foundation | Java | all eleven modules of the HAIP verifier plan, 1.0.0rc7 (2026-09-24): the certification; eleven of eleven clean against 1.0.0rc15 on a GitHub runner, both controls noticed (2026-10-04) | the suite's newest prebuilt images |

The author drove every walk: this is interoperability with those implementations, not use by their
maintainers. Each row's controls, and what it does not establish, are in
[the scoreboard](lab/EXTERNAL-NOUNS.md#wallets). Repeat one yourself in ten minutes with
[STRANGER-PATH.md](docs/STRANGER-PATH.md).

Everything else here is the project checking itself: one author's pre-pilot system on notional data. It has never held real identity data, and there has been no independent security review, no other operator and no pilot. The ledger of outside results is [the scoreboard](lab/EXTERNAL-NOUNS.md).

<img src="docs/assets/rule.svg" width="100%" alt="">

## Try it

The verifier installs from PyPI and needs nothing else from this repository:

```bash
pip install --pre "polaris-verify[cryptography]"
# signature only; issuer trust NOT evaluated
polaris-verify --pqc-provider auto --signature-only --pack your-credential.json
# signature AND a key that belongs to an issuer you trust
polaris-verify --pqc-provider auto --issuer-anchor trusted-keys.json --pack your-credential.json
```

- It refuses to start until you name the cryptography it uses; there is no default.
- **A genuine signature is not a trusted issuer:** without `--issuer-anchor` it abstains (exit 2) rather than report success.

No credential yet? A published sample and its issuer's key, with no clone:

```bash
curl -fsSLO https://raw.githubusercontent.com/EgorKhaklin/polaris-id/main/vectors/ml-dsa-65-valid.json
curl -fsSLO https://raw.githubusercontent.com/EgorKhaklin/polaris-id/main/vectors/anchors/ml-dsa-65-issuer.json
polaris-verify --pqc-provider auto --issuer-anchor ml-dsa-65-issuer.json --pack ml-dsa-65-valid.json
# signature_valid: True, issuer_trusted: True, exit 0
```

The same two files verify from npm — same bytes, same verdict, which is why there are two independent SDKs (Node 20.19+; also Deno, Bun, browsers and workers):

```bash
npm install polaris-sdk-ts@next   # candidates ship under `next`; a plain install is 0.1.0 until 1.0.0
node --input-type=module -e '
import { readFileSync } from "node:fs";
import { verifyAuthenticity } from "polaris-sdk-ts";
const pack = JSON.parse(readFileSync("ml-dsa-65-valid.json", "utf8"));
const anchors = JSON.parse(readFileSync("ml-dsa-65-issuer.json", "utf8")).public_keys_hex;
const { authentic, issuerTrusted, algorithm } = await verifyAuthenticity(pack, anchors);
console.log({ authentic, issuerTrusted, algorithm });
'
# { authentic: true, issuerTrusted: true, algorithm: 'ML-DSA-65' }
```

`ml-dsa-65-tampered-signature.json` beside it is rejected by both — the verifier exits 2, the SDK returns `authentic: false` — as is the genuine sample under any other issuer's key. The sample issuer is a demo: in real use an issuer's key comes from the issuer or a trust list you already trust, never from beside the credential.

Authenticity is permanent; authorization can change. The same credential after revocation:

```jsonc
POST /api/v1/verify  ->  {
  "authentic": true,                 // the ML-DSA-65 signature is genuine
  "currently_authoritative": false,  // but this token has been revoked
  "status": "REVOKED",
  "usable": false,
  "decision": "reject"
}
```

From a clone (`pip install liboqs-python cryptography`):

```bash
python3 scripts/polaris-verify.py --pqc-provider oqs --selftest        # live ML-DSA-65 round trip
python3 scripts/polaris-verify.py --pqc-provider oqs --verify-dir vectors   # published packs
python3 conformance/run_conformance.py --self                          # 281 published cases
python3 scripts/polaris-compat-suite.py                                # frozen v1 protocol
```

<img src="docs/assets/rule.svg" width="100%" alt="">

## The ten guarantees

The vocation above them: **no person can be compelled to renounce, transfer, or surrender their identity against their will.** Constitutional guarantees (C1, C2, C3, C6, C10) change only by amendment; engineering invariants (C4, C5, C7, C8, C9) keep them honest.

| # | Guarantee | Tier | Enforced by |
|---|---|---|---|
| **C1** | The audit trail is append-only. | Constitutional | Triggers reject `UPDATE`/`DELETE` on audit tables |
| **C2** | A zero-knowledge verification stores no token identifier. | Constitutional | Bidirectional `CHECK` constraint |
| **C3** | One person holds at most one ACTIVE token. | Constitutional | Partial unique index |
| **C4** | Failed-login counting is atomic. | Engineering | Single-statement `UPDATE ... RETURNING` |
| **C5** | No inline scripts (`script-src 'self'`). | Engineering | HTTP response header, verified per route |
| **C6** | Disclosure level is enforced server-side. | Constitutional | Server code paired with redaction tests |
| **C7** | No hardcoded cryptography. | Engineering | Foreign key to `CryptographicAlgorithm` |
| **C8** | Every map/API aggregate is bounded. | Engineering | Hard caps in the SQL functions |
| **C9** | Concurrency is tested with real threads. | Engineering | Threaded suites against a live database |
| **C10** | Identity is not money. | Constitutional | Structural absence, pinned by a check |

Each is machine-checked by [`polaris_checks`](polaris_checks/): 344 plain `check_*` functions (v1.0.0-rc.70), each with a detection test proving it fails on a broken fixture. Why these ten: [MISSION.md](MISSION.md).

<img src="docs/assets/rule.svg" width="100%" alt="">

## Threats answered by construction

| Threat | The answer | Detail |
|---|---|---|
| **Cryptographic compulsion** | A second secret yields a normal-looking verification and records a `DuressEvent`. **Bounded:** resists a coercer who does not know the mechanism exists; not one watching the holder, and net-negative against lawful access (the record is append-only). | [design](docs/design/duress-codes.md) · [assessment](lab/duress/README.md) |
| **Catastrophic loss** | Two-phase recovery with independent out-of-band channels, a cooldown and admin-gated completion. | [recovery-ceremony](docs/design/recovery-ceremony.md) |
| **Algorithm agility** | The algorithm is a row, not a constant (C7); migration through `uc6_migrate` runs in CI, with exactly one active signature per token. | [multi-sig-migration](docs/design/multi-sig-migration.md) |
| **Issuer concentration** | Explicit-only, non-transitive federation gated on an active trust attestation. | [federation](docs/design/federation.md) |
| **Auditability vs. privacy** | A Plonky2 SNARK proves ledger membership and nothing else. | [zk-snark](docs/design/zk-snark.md) |
| **Issuer overreach** | A per-agency revocation-rate ceiling enforced by trigger. | [issuer-discretion](docs/design/issuer-discretion.md) |

<img src="docs/assets/rule.svg" width="100%" alt="">

## Architecture

The schema is the core and the security boundary. The application, the CLI and the Rust prover
(re-checked by an independent Python witness) are its clients; the check layer reads everything
and writes nothing; the signer is ML-DSA-65, the algorithm a registry row ([overview](docs/ARCHITECTURE-OVERVIEW.md)).

| Component | What it is |
|---|---|
| [`polaris_sql/`](polaris_sql/) | Schema, use-case procedures, append-only triggers, migrations. |
| [`polaris_web/`](polaris_web/) | Flask application: use-case flows, the Atlas, WebAuthn operator MFA, health and metrics. |
| [`polaris_zk/`](polaris_zk/) | Plonky2 prover (Rust) and [`witness2/`](polaris_zk/witness2/), an independent Python reimplementation. |
| [`polaris_cli/`](polaris_cli/) | Operator CLI for issuance, revocation, recovery and audit. |
| [`polaris_checks/`](polaris_checks/) | The invariant layer: 344 checks (v1.0.0-rc.70). |
| [`packages/`](packages/), [`sdk/`](sdk/), [`conformance/`](conformance/) | The detached verifier, the OpenID4VP verifier, the verify SDKs and the conformance suite. |
| [`scripts/`](scripts/), [`deploy/`](deploy/) | Wallet and relying-party tools, operator tooling, observability config. |

Reference deployment profile: a Caddy TLS edge, gunicorn, PgBouncer, PostgreSQL with pgBackRest, and Redis; all non-root with capabilities dropped.

<img src="docs/assets/rule.svg" width="100%" alt="">

## Cryptography

The claim is **algorithm agility under an audited migration path**, not settled security against a quantum adversary: whether Module-LWE holds is mathematics, not a property of this repository.

| Algorithm | Family | PQ | Standard | Security (bits) | Public key | Signature | Role |
|---|---|:---:|---|:---:|---:|---:|---|
| ML-DSA-65 | ML-DSA | ✓ | FIPS 204 | 192 | 1,952 B | 3,309 B | default |
| ML-DSA-87 | ML-DSA | ✓ | FIPS 204 | 256 | 2,592 B | 4,627 B | accepted; migration is a key event |
| SLH-DSA-128s | SLH-DSA | ✓ | FIPS 205 | 128 | 32 B | 7,856 B | registered, no signer |
| SLH-DSA-256s | SLH-DSA | ✓ | FIPS 205 | 256 | 64 B | 29,792 B | registered, no signer |
| ECDSA-P256 | ECDSA | | FIPS 186-4 | 128 | 64 B | 72 B | legacy, sunset 2027 |

- **Two ML-DSA implementations at issuance** (liboqs and OpenSSL) must agree, or issuance fails closed.
- **The TLS edge negotiates X25519MLKEM768** hybrid key exchange, proven in CI; what stays classical is in [PQC-POSTURE.md](docs/reference/PQC-POSTURE.md).
- **The ZK proof needs no trusted setup** (Plonky2, FRI-based).
- **Limits:** without real PQC enabled, development signing writes a named placeholder that verifies against no key; and the classical half of a credential in migration is protected by nothing here. See [PRODUCTION-READINESS.md](docs/PRODUCTION-READINESS.md).

<img src="docs/assets/rule.svg" width="100%" alt="">

## Verified, not asserted

Counts of checks, tables, routes and CI jobs are re-measured by `polaris_checks` on every run; test counts are measured per release.

| Layer | Scale | What it proves |
|---|---|---|
| Product tests (live database) | 1245 | Constraints, use cases, routes, redaction, real-thread concurrency, the secret store |
| Crypto witnesses | 126 passing of 131 collected | ML-DSA across both witnesses and a software PKCS#11 module; Rust and Python epoch roots agree |
| Invariant checks | 344 | C1-C10 plus production posture, each with a detection test |
| CI jobs | 23 | Below |

Test counts: reference machine, v1.0.0-rc.62 (`pytest -q` per suite, 2026-09-26). The five skipped crypto tests need a PKCS#11 module or a real KMS key.

On every push, CI also boots the five-service production-profile stack, round-trips backups,
fails over the HA profile under writes, proves the post-quantum TLS handshake and real ML-DSA-65
signing, runs the federation and compatibility drills and the mutation drills, and gates on CVE
scans ([ci.yml](.github/workflows/ci.yml)). What the mutation drills broke, what noticed and which run each number
is from: [the review packet](docs/REVIEW-PACKET.md#4-broken-on-purpose).

```bash
python3 -m polaris_checks.run        # the invariant layer, no database needed
python3 scripts/polaris-ship.py run  # the full local gate, matching CI
```

<img src="docs/assets/rule.svg" width="100%" alt="">

## Run it

**Local (macOS),** with [Docker Desktop](https://www.docker.com/products/docker-desktop):

```bash
git clone https://github.com/EgorKhaklin/polaris-id.git polaris
cd polaris
./Polaris.command
```

Opens `http://localhost:2222` with three seeded roles (notional data, development credentials only):

```
admin     Admin@123!      full access, SQL console
operator  Operator@123!   issue, activate, bind tokens
auditor   Auditor@123!    read-only, warrant audits, duress dashboard
```

The laptop stack signs with a named development placeholder, not ML-DSA-65, so `polaris-verify`
reports what it issues as not authenticatable. Real signing is the production image (liboqs).

**Real signing, on your machine:** `bash lab/strategy/006/try.sh` builds the production images,
generates an ML-DSA-65 key on your machine, and runs the production stack on
`https://localhost:8443` beside anything else running. It then issues one credential and verifies
it with `polaris-verify` from PyPI against that key. It needs Docker and Python 3.9 or later, and
takes about seven minutes, most of them the image build. `--down` removes the stack.

**Single host:**

```bash
./scripts/polaris-generate-secrets.sh
export POLARIS_DOMAIN=polaris.example.com
./scripts/polaris-deploy.sh prod
curl -fsS https://$POLARIS_DOMAIN/api/health
```

- **Linux server:** `sudo POLARIS_DOMAIN=polaris.example.com deploy/linux/install.sh` ([docs/operator/LINUX-SERVER.md](docs/operator/LINUX-SERVER.md), [HARDENING](docs/operator/HARDENING.md)).
- **Kubernetes:** the Helm reference profile ([docs/operator/KUBERNETES.md](docs/operator/KUBERNETES.md)).
- **Runbooks:** [INSTALL](docs/operator/INSTALL.md) · [OPERATIONS](docs/operator/OPERATIONS.md) · [SECRETS](docs/operator/SECRETS.md) · [DR](docs/operator/DR.md) · [FAILOVER](docs/operator/FAILOVER.md).

<img src="docs/assets/rule.svg" width="100%" alt="">

## Where Polaris sits

| System | Deployed to a real population | National-scope issuance | Post-quantum default | Unlinkable verification default | Duress-aware primitive | Append-only audit at schema |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Real ID (US) | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| mDL / ISO 18013-5 | ✓ | ✓ | ✗ | partial | ✗ | ✗ |
| Aadhaar (India) | ✓ | ✓ | ✗ | ✗ | ✗ | partial |
| e-Estonia | ✓ | ✓ | ✗ | ✗ | ✗ | partial |
| W3C DIDs / VCs | partial | ✗ | method-dependent | method-dependent | ✗ | n/a |
| **Polaris** | **✗** | **✗** | ✓ | ✓ | ✓ | ✓ |

The first two columns matter most: every other row is deployed at national scale; Polaris is neither. Its other ticks are design properties in the codebase, on notional data. None is novel alone; the point is all five in one codebase, enforced at the schema and machine-checked.

<img src="docs/assets/rule.svg" width="100%" alt="">

## Documentation

| If you are | Start with |
|---|---|
| Proving it works yourself | [STRANGER-PATH.md](docs/STRANGER-PATH.md): clean machine to an accepted external-wallet presentation |
| Deciding if it is worth your time | [MISSION.md](MISSION.md) |
| Reviewing the architecture | [ARCHITECTURE-OVERVIEW](docs/ARCHITECTURE-OVERVIEW.md) · [SYSTEM-MAP](docs/reference/SYSTEM-MAP.md) |
| Reviewing security | [SECURITY.md](SECURITY.md) · [PQC-POSTURE](docs/reference/PQC-POSTURE.md) · [RED-TEAM-SCOPE](docs/RED-TEAM-SCOPE.md) · [threat model](docs/design/threat-model.md) |
| Integrating | [API](docs/reference/API.md) · [DATA-MODEL](docs/reference/DATA-MODEL.md) · [GLOSSARY](docs/reference/GLOSSARY.md) |
| Operating an instance | [docs/operator/](docs/operator/README.md) |
| Asking why a mechanism is built this way | [docs/design/](docs/design/README.md) |
| Reading it as research | [Project report, Version 3](docs/paper/polaris_project_report_v3.pdf) (the system at 1.0.0-rc.7) · [Russian edition](docs/paper/polaris_project_report_v3_ru.pdf) · [CITATION.cff](CITATION.cff) |
| Asking a question | [Discussions](https://github.com/EgorKhaklin/polaris-id/discussions) · [Discord](https://discord.gg/ragewuCKj) · [where each kind of message goes](.github/SUPPORT.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) · [CHANGELOG.md](CHANGELOG.md) |

<img src="docs/assets/rule.svg" width="100%" alt="">

## Scope, honestly

- **Not production-ready, and says so.** Remaining gaps are operator decisions (key custody, offsite backup, alerting, legal review, penetration test): [PRODUCTION-READINESS.md](docs/PRODUCTION-READINESS.md).
- **Security disclosures:** [SECURITY.md](SECURITY.md).

<img src="docs/assets/rule.svg" width="100%" alt="">

## License

[Apache License 2.0](LICENSE), for its express patent grant. Copyright 2026 Egor Khaklin. If you build on it, retain [LICENSE](LICENSE) and [NOTICE](NOTICE). NOTICE names every dependency license: all are permissive except psycopg2 and psycopg 3 (LGPL 3) and certifi (MPL 2.0), each used unmodified. The license covers the files, not the names and logos: see [TRADEMARKS.md](TRADEMARKS.md).

<br>

<div align="center">

<img src="docs/assets/band.svg" width="100%" alt="">

<br>

<img src="docs/assets/seal.svg" width="76" alt="The Khaklin Technologies owl">

<sub><i>Fixus inter mutabilia</i> · fixed amid the mutable</sub>

</div>
