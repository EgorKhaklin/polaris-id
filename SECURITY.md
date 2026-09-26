# Security Policy

How to report a vulnerability, what is in scope, what to expect, and how to verify a release.
Polaris is a reference implementation on notional data; it has never held real identity data.
Related: [security controls](docs/operator/SECURITY-CONTROLS.md) · [threat model](docs/design/threat-model.md) · [red-team scope](docs/RED-TEAM-SCOPE.md) · [review packet](docs/REVIEW-PACKET.md).

---

## Reporting a vulnerability

**Do not** open a public issue. Report privately through the repository's **Security** tab
(**Report a vulnerability**), which opens a private advisory only the maintainer can see, or
email PolarisID@protonmail.com.

Include: the component, the version (`/api/health` or `polaris_web/__version__.py`),
reproduction steps, the impact (which of C1 to C10, if any), a suggested fix if you have one,
and whether you have published anywhere.

| | |
|---|---|
| Acknowledgement | within 5 business days |
| Severity assessment | within 10 business days |
| **Critical** (breaks C1 to C10 in a deployable configuration) | patch within 14 days |
| **High** (authentication bypass, data exposure, denial of service against the live stack) | patch within 30 days |
| **Medium** (a leak that does not violate C2, an insecure default, weakened cryptography) | patch within 90 days |
| **Low** (a defence-in-depth gap, a documentation error that could mislead a deployment) | patch within 180 days |
| Coordinated disclosure | 90 days from the report by default |

**Before you start,** read [docs/REVIEW-PACKET.md](docs/REVIEW-PACKET.md): what each subsystem
guarantees, what does not stand in the way, and the known limitations, so you can tell an
accepted limitation from a defect. Constraints, triggers, procedures, row-level security, the
checks and the conformance suite are all mutation-tested; the conformance drill lists the 43
verdict fields the published cases do not constrain.

---

## Published packages

| Package | Current | Older versions still carrying known defects |
|---|---|---|
| `polaris-oid4vp` | `1.0.0rc7` | `1.0.0rc3`: no Token Status List support. `1.0.0rc1`, `0.1.0`: **never reads `exp`**, plus missing input bounds and disclosure-name guards. |
| `polaris-verify` | `1.0.0rc3` | `1.0.0rc1`, `0.1.0`: **never reads a trust attestation's `valid_until`**; no finite-number guards. |
| `polaris-sdk-python` | `1.0.0rc3` | `1.0.0rc1`, `0.1.0`: no finite-number guards on grant limits; cached tokens outlive a revoked client. |
| `polaris-sdk-ts` (npm) | `1.0.0-rc.3` under `next` | `0.1.0` (what `latest` resolves by design): canonicalisation and parsing divergences from the wire specification. |

If you installed or pinned an older version, upgrade. The Current column is checked against
[docs/RELEASING.md](docs/RELEASING.md) on every run. The packages are for evaluation and
interoperability work, not for protecting anything.

---

## Scope

**In scope:** the application (`polaris_web/`), the SQL schema, procedures and triggers
(`polaris_sql/`), the ZK prover and its second witness (`polaris_zk/`), the invariant checks
(`polaris_checks/`), every script under `scripts/`, the container images, compose files, Helm
chart and Linux installer, the macOS launcher, the migration framework, the exchange fabric,
the verify SDKs and conformance suite, the card profile and emulator (`polaris_card/`; a
missing silicon property is a documentation finding only), and documentation errors that could
lead to an insecure deployment.

**Out of scope:**

- The seed accounts and notional data (their passwords are public by design; production
  initialization disables them).
- Denial of service caused by misconfiguring your own deployment.
- Payments and transactions (excluded by C10).
- Hosted infrastructure you do not control.
- Upstream vulnerabilities in dependencies (report upstream; the dependency policy picks them up).
- **The placeholder signing default.** Without `POLARIS_USE_REAL_PQC=1` and liboqs, development
  signing writes a labelled placeholder that verifies against no key; production fails closed
  without real signing (`check_real_pqc_default_boot`). In scope: that guard failing. The
  cryptographic claim is algorithm agility under an audited migration path, not settled security
  against a quantum adversary; see [docs/PRODUCTION-READINESS.md](docs/PRODUCTION-READINESS.md).

---

## Verifying a release

Every release carries SPDX SBOMs (the Python surface and the five images) with signed, keyless
SLSA build provenance (Sigstore via GitHub OIDC):

```bash
gh attestation verify sbom-python.spdx.json --repo EgorKhaklin/polaris-id
```

Container images are built and scanned in CI but not published to a registry, so there is no
image digest to sign yet.

---

## Dependencies

Dependabot alerts and weekly updates cover Python, Rust, GitHub Actions and Docker. Patch and
minor bumps are applied in batches and validated by a full CI run; majors of foundation
dependencies are planned work. The `cve-scan` and `image-cve-scan` CI jobs fail the build on a
known CVE in the runtime surface or a fixable critical in an image.

---

## Reporting under duress

No retaliation against good-faith researchers. If you are reporting under duress, say so in
your first message and it will be handled accordingly.

## Credit

Researchers who report Critical or High findings and coordinate disclosure are credited, with
consent, in the release that ships the fix; anonymity is honoured on request. There is no bug
bounty: Polaris is a reference implementation, not a deployed service.

---

*Maintainer: Egor Khaklin (VANTA)*
*Last updated: 2026-09-26 (v1.0.0-rc.62)*
*Machine-readable: the live `/.well-known/security.txt` route (RFC 9116)*
