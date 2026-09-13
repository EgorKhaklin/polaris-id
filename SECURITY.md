# Security Policy

**Reader:** a security researcher who has found something, or a reviewer
checking how findings are handled. **Job:** how to report a vulnerability
privately, what is in scope, what response to expect, how a release is
verified, and how dependencies are kept current.

Polaris is a reference implementation of a national identity-token system.
Its guarantees are enforced in the database schema and machine-checked by
`polaris_checks`; the operator-facing security posture, control by control,
is [docs/operator/SECURITY-CONTROLS.md](docs/operator/SECURITY-CONTROLS.md), the threat model is
[docs/design/threat-model.md](docs/design/threat-model.md), and the scope prepared
for an external engagement is [docs/RED-TEAM-SCOPE.md](docs/RED-TEAM-SCOPE.md).

---

## Reporting a vulnerability

**Do not** file a public GitHub issue for a security vulnerability.

**Report privately** through GitHub: open the repository's Security tab and
use **Report a vulnerability**, which creates a private advisory only the
maintainer can see. If you cannot use GitHub, email
PolarisID@protonmail.com.

Include:

- The affected component (web app, SQL schema, migration, script, launcher,
  container image, dependency)
- The affected version (`/api/health` returns the running version; the
  canonical version is `polaris_web/__version__.py`)
- Reproduction steps
- Impact: which of C1 to C10 is at risk, if any, and which anti-coercion
  surface is affected
- Suggested remediation, if you have one
- Whether you have published anywhere; coordinated disclosure is preferred

**Response:** initial acknowledgement within 5 business days, severity
assessment within 10 business days.

**Before you start, read [docs/REVIEW-PACKET.md](docs/REVIEW-PACKET.md).** It says
what each subsystem is supposed to guarantee, what mechanism holds it, and -- in the
column that matters -- what does NOT stand in the way. It also lists the known
limitations, each with a witness in the tree, so you can tell an accepted limitation
from a defect before spending a day on it, and twelve guarantee-attack prompts that
name the attacks the maintainers would most like attempted. Nothing on that page has
been reviewed by anybody outside this repository, which is the reason it is written
down at all.

Worth knowing before you start, because it says what has already been tried: the
verification layer is itself mutation-tested. `scripts/polaris-check-mutation-drill.py`
comments out each invariant's subject and requires the check to notice;
`scripts/polaris-constraint-mutation-drill.py` drops each CHECK constraint the database
suite names and requires the naming tests to go red (46 of 46 are load-bearing). The
same treatment of the triggers is in progress and the current count is in the CHANGELOG;
where a trigger is not yet covered by a test, that is stated rather than implied.

**Fix, by severity:**

- **Critical** (breaks C1 to C10 in a deployable configuration): patch
  within 14 days, coordinated disclosure
- **High** (authentication bypass, data exposure not covered by C2, denial
  of service against the live stack): patch within 30 days
- **Medium** (an information leak that does not violate C2, an insecure
  default, weakened but unbroken cryptography): patch within 90 days
- **Low** (a defence-in-depth gap, a documentation error that could lead to
  an insecure deployment): patch within 180 days

**Coordinated disclosure:** the default disclosure date is 90 days from the
initial report, extended for Critical findings as the patch warrants.

---

## Scope

### In scope

- The Flask application (`polaris_web/`)
- The SQL schema, procedures, triggers and indexes (`polaris_sql/`)
- The Rust ZK prover and verifier (`polaris_zk/`) and the Python second witness
- The invariant-check layer (`polaris_checks/`)
- Every script under `scripts/` (all now `polaris-*`: operator tools, the CI drills and the contributor gates)
- The Dockerfiles, the compose files (the HA profile's Patroni, etcd and HAProxy
  configuration included), the Helm chart and the Linux installer
- The macOS launcher
- The migration framework
- The exchange fabric (P8): the exchange gateway and its replay register, the auth
  broker and its consumed-code register, document signing with long-term validation,
  the signed registry, the timestamp authority, the receipt transparency log, and the
  wallet's presentation and QR framing
- The verify SDKs (`sdk/python`, `sdk/typescript`) and the conformance suite
  (`conformance/`), which independent implementations build to. **What passing the
  conformance suite does and does not prove** is itself worth reading before you rely
  on it: `scripts/polaris-conformance-mutation-drill.py` measures which verdict fields
  the published cases actually constrain, and 43 of them are not constrained at all. An
  implementation can pass all 118 cases while never performing those checks. None of the
  43 can be closed by writing a case: each needs a conforming verifier to compute
  something it does not, so the contract constrains what its WEAKEST conforming
  implementation computes. The drill
  declares the list exactly and CI fails if it grows. A divergence between the shipped
  verifiers that the suite fails to catch is a finding we want: v9.430 and v9.431 each
  found one that way (no replay bound on holder proofs in either SDK; no way for either
  SDK to report whether an artifact's issuer is trusted)
- The physical layer (`polaris_card/`, P4): the card profile and its encoding, the
  software token emulator and its APDU contract, the personalization flow, and the
  reference verifier device. A finding that an emulator does not model a property of
  real silicon (constant time, fault-injection resistance, key non-extractability) is
  in scope as a documentation error only: those are properties of a certified part,
  and the profile says so
- The documentation, where an error would lead to an insecure deployment

### Out of scope

- **The seed accounts and notional data.** The sample database ships three
  demonstration accounts whose passwords are printed in the README's
  quickstart; production initialization disables and scrambles them. Their
  existence is not a vulnerability.
- **Self-inflicted denial of service** through misconfiguration of your own
  deployment.
- **Banking, payments and merchant codes.** Excluded by C10; a finding that
  Polaris lacks a transaction primitive is by design.
- **Hosted infrastructure you do not control.** Reports against a
  deployment you operate are in scope; reports against example domains are
  not.
- **Upstream vulnerabilities in third-party dependencies** not yet pinned in
  the `polaris_web/requirements*.txt` files. Report those upstream; they are
  picked up by the dependency policy below.
- **The placeholder signing default.** Without `POLARIS_USE_REAL_PQC=1` and liboqs,
  `TokenSignature.signature_bytes` holds a 32-byte value labelled
  `DETERMINISTIC-PLACEHOLDER-SHA3-256` that verifies against no key, where real
  ML-DSA-65 produces 3,309. That is the default, including in CI, and it is a named
  development profile rather than a defect: production fails closed at boot without
  real signing (`check_real_pqc_default_boot`), and the profile warns loudly when used
  unnamed. A report that credential signatures do not verify on a default checkout is
  this, and is already known. What IS in scope is the guard failing -- a production
  boot that does not fail closed, a placeholder that is not labelled, or a verifier
  that accepts a placeholder as though it were a signature.

  Related, and worth reading before relying on the word: the cryptographic claim is
  **algorithm agility under an audited migration path**, not settled security against a
  quantum adversary. ML-DSA-65 rests on Module-LWE hardness, which this repository
  cannot establish. What a break would and would not cost -- including that a
  credential's classical half during cutover is protected by nothing here -- is stated
  in [docs/PRODUCTION-READINESS.md](docs/PRODUCTION-READINESS.md).

---

## Verifying a release (supply chain)

Every published release carries an SPDX 2.3 SBOM for each artifact (the
Python runtime surface and the five self-built images), and each SBOM carries
a signed SLSA build-provenance attestation. The attestation is keyless: it is
signed through GitHub's OIDC identity via Sigstore (Fulcio certificate, Rekor
transparency log), so there is no long-lived signing key to leak.

To confirm an SBOM you downloaded from a release was produced by this
repository's release workflow and not tampered with or forged:

```bash
gh attestation verify sbom-python.spdx.json --repo EgorKhaklin/polaris-id
```

A passing check binds the file's SHA-256 to this repository and the workflow
that built it; the SBOM then enumerates the exact package set of that
release. Image signing at a registry digest waits until the container images
are published to a registry; today they are built and scanned in CI but not
published, so there is no registry reference to sign.

---

## Dependencies

Dependabot alerts and security updates are enabled on the repository, and
Dependabot opens weekly version-update PRs for the Python, Rust, GitHub
Actions and Docker surfaces (`.github/dependabot.yml`). Patch and minor bumps
are batch-applied to `main` and validated by one full CI run, after which
Dependabot closes its own PRs on its next scan; that is why the closed PRs
outnumber the merged ones. Majors of foundation dependencies (PostgreSQL, the
Python base image, the plonky2 proving system) are deliberate roadmap work
with their own test passes, never a blind bump. Independently of Dependabot,
the `cve-scan` and `image-cve-scan` CI jobs fail the build on a known CVE in
the runtime surface or a fixable critical in a self-built image.

---

## Reporting under duress

Vulnerability disclosure is itself an anti-coercion surface. This policy
commits to coordinated disclosure with no retaliation against good-faith
researchers, a documented response timeline, and embargo coordination before
publication. If you are reporting under duress, say so in the initial
message; the report is handled as a duress-channel event. The application's
duress-code mechanism is for holders authenticating into Polaris, not for
this channel, but the same commitment applies: a coerced report must not
lead to retaliation against the researcher.

---

## Credit

Researchers who report Critical or High findings and coordinate disclosure
are credited, with consent, in the CHANGELOG entry of the patch that ships;
anonymity is honoured on request. There is no bug-bounty payout: Polaris is
a reference implementation, not a deployed service. Operators of deployed
instances may run their own programs against their deployments, citing this
policy.

---

*Maintainer: Egor Khaklin (VANTA)*
*Last updated: 2026-09-12 (v9.453)*
*Machine-readable: the live `/.well-known/security.txt` route (RFC 9116)*
