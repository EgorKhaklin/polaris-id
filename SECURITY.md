# Security Policy

How to report a vulnerability, what is in scope, what to expect, and how to verify a release.
Polaris is pre-pilot software on notional data; it has never held real identity data.
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

The current versions carry none of the defects below except the one stated after the table; each row
lists what older versions still carry.

| Package | Current | Older versions still carrying known defects |
|---|---|---|
| `polaris-oid4vp` | `1.0.0rc9` | `1.0.0rc8` and earlier: decrypt a JWE whose tag is not 128 bits (other splits of the same bytes); read an `x5c` header that is present but empty, or not a list, as absent; verify under only the first issuer key that parses, so a rotated key fails; report the `no_authority` and `list_refused` revocation answers as `unreachable`; in `serve`, miss a truncated body that is not valid UTF-8. `1.0.0rc7` (the certified version) and earlier: with an x5c issuer, **accept an `iss` its certificate does not name** and pass it to the status resolver; accept a `vp_token` under a key the DCQL query did not use. `1.0.0rc7` (measured): **raises instead of refusing** a non-string disclosure name, `vct` or JWE `enc`, or JSON nested about 20,000 deep (`serve` answers 400; a library caller gets `TypeError` or `RecursionError`). `1.0.0rc3`: no Token Status List support. `1.0.0rc1`, `0.1.0`: **never read `exp`**; missing input bounds. |
| `polaris-verify` | `1.0.0rc4` | `1.0.0rc3` and earlier: **report any authority-signed artifact re-wrapped as an authenticity pack as an authentic credential**; with **no context presented**, accept a trust edge from any context; accept an **unsigned** trust edge past, or without a readable, `valid_until`. `1.0.0rc3` also: a grant under a **revoked** holder binding reads as bound, a receipt stating no context reads as requester-authorized, and timestamp-anchor `cosignatures` that are not a list **raise** instead of refusing (measured). `1.0.0rc1`, `0.1.0`: **never read a trust attestation's `valid_until`**; no finite-number guards. |
| `polaris-sdk-python` | `1.0.0rc4` | `1.0.0rc3` and earlier: `verify_authenticity` **accepts any authority-signed artifact re-wrapped as a pack**; `verify_cross_authority` accepts a signed or **unsigned** trust edge past, or without a readable, `valid_until`, and with **no context presented** an edge from any context. `1.0.0rc3` (measured): an artifact `format` that is not a string, `cosignatures` that are not a list, or a revocation feed that is not an object **raise** instead of refusing. `1.0.0rc1`, `0.1.0`: no finite-number guards on grant limits; cached tokens outlive a revoked client. |
| `polaris-sdk-ts` (npm) | `1.0.0-rc.5` under `next` | `1.0.0-rc.4` and earlier: read an artifact `format` that is a list as the string it coerces to. `1.0.0-rc.3` and earlier: `verifyAuthenticity` **accepts any authority-signed artifact re-wrapped as a pack**; `verifyCrossAuthority` accepts a signed or **unsigned** trust edge past, or without a readable, `valid_until`, and with **no context presented** an edge from any context. `0.1.0` (what `latest` resolves): canonicalisation and parsing divergences from the wire specification. |

Exception until the next publish: `polaris-verify` and `polaris-sdk-python` 1.0.0rc4 accept a signature or
key whose hex has whitespace between bytes, and `polaris-sdk-ts` 1.0.0-rc.5 accepts one with a character
that is not hex; each verifier accepted spellings the others refused. The tree carries the fix and three
conformance cases that hold all three to it. `polaris-verify` 1.0.0rc4 also raises in `--verify-dir` on a
vector that is not a JSON object, and its long-term-validation note calls missing revocation evidence a
revocation; both are fixed in the tree. `polaris-oid4vp` 1.0.0rc9's `serve` accepts TLS 1.0 and 1.1
where the Python build's default allows them, as the macOS system Python 3.9 does; the tree sets
the floor at TLS 1.2. `polaris-verify` and `polaris-sdk-python` 1.0.0rc4 read a signed grant whose
`limits` is not an object as unlimited, and `polaris-sdk-ts` 1.0.0-rc.5 does so when it is a string
or a number; the tree refuses it in all three.

If you installed or pinned an older version, upgrade. The Current column is checked against
[docs/RELEASING.md](docs/RELEASING.md) on every run. The packages are for evaluation and
interoperability work, not for protecting anything.

---

## Supported versions

Security fixes go to the newest release of each package and to the newest release candidate of
the tree. Until 1.0.0, an older version stops receiving security updates the day a newer one is
published: the fix ships as a new version, and the table above lists what older versions still
carry. `polaris-oid4vp` 1.0.0rc7 stays the certified version and is listed with its known defects;
it is not patched in place.

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

The attestation names the repository and the workflow run that built the artifact, so a passing
check also confirms who produced it. The packages on PyPI and npm carry the same kind of provenance
from trusted publishing, shown on each registry page.

Container images are built and scanned in CI but not published to a registry, so there is no
image digest to sign yet.

---

## Dependencies

A dependency is added only when the standard library or an existing dependency cannot do the
job; each published package declares a dependency budget that a check holds on every push
(`polaris-verify` has none). Dependencies come from PyPI, npm and crates.io through their package
managers. npm and Rust dependencies are fully locked (package-lock.json, Cargo.lock); Python's
direct dependencies are pinned in the requirements files, but their own dependencies resolve at
build time, which a hash-pinned lock will close. Container base images are pinned by digest. Dependabot alerts and weekly updates cover Python, Rust, GitHub Actions and Docker. Patch and
minor bumps are applied in batches and validated by a full CI run; majors of foundation
dependencies are planned work. The `cve-scan` and `image-cve-scan` CI jobs fail the build on a
known CVE in the runtime surface or a fixable critical in an image.

Thresholds. Dependency findings (SCA): a known vulnerability in a runtime dependency, or a fixable
critical in an image, fails the build and is fixed before anything merges; a high finding in an
image is reviewed before each release and fixed once a fixed version exists. A dependency whose
license does not allow its use in an Apache-2.0 project is not added (NOTICE lists every license). Code findings (SAST): bandit fails the build on a high-severity
finding; medium findings are reviewed before each release. CodeQL and zizmor report every push and
pull request to the Security tab, and a high or critical alert is fixed, or dismissed with its
reason written on the alert, before the next release. Every change is also scanned by OSV-Scanner for malicious packages (the OpenSSF Malicious Packages
data) and known vulnerabilities, in the Python sets the images install and in the npm and Rust
lockfiles; any finding blocks the merge unless it is declared, with its reason, in
`osv-scanner.toml`. No release is cut while any of these jobs fails. A finding that does not affect Polaris is declared, with the reason, in
[vex.openvex.json](vex.openvex.json) and, for the image scan, in `.trivyignore`.

---

## Repository controls

These are settings rather than files, so they are listed here; each can be read back through
the API (`gh api repos/EgorKhaklin/polaris-id/rulesets`, `.../environments`,
`.../immutable-releases`):

- `main` takes changes only through pull requests: merge commits only, the six required checks
  [CONTRIBUTING.md](CONTRIBUTING.md) names, review conversations resolved, no force push, no
  deletion, and no bypass for anyone, the owner included.
- Version tags (`v*`) cannot be moved or deleted, and a published release's tag and assets
  cannot be changed.
- The `pypi` and `npm` environments deploy only from `main`, so only reviewed, merged workflow
  code can publish; an npm publish also waits for a maintainer's second factor.
- Secret scanning with push protection, private vulnerability reporting, and Dependabot alerts,
  malware alerts and security updates are on. Workflow tokens default to read-only, and a
  first-time contributor's workflow run waits for approval.
- Code scanning ([code-scanning.yml](.github/workflows/code-scanning.yml)): CodeQL with the
  security-extended queries over the Python, the TypeScript SDK, the Rust prover and the
  workflows, and zizmor over the workflows. OpenSSF Scorecard
  ([scorecard.yml](.github/workflows/scorecard.yml)) publishes its results.

---

## Reporting under duress

No retaliation against good-faith researchers. If you are reporting under duress, say so in
your first message and it will be handled accordingly.

## Credit

Researchers who report Critical or High findings and coordinate disclosure are credited, with
consent, in the release that ships the fix; anonymity is honoured on request. There is no bug
bounty: Polaris is pre-pilot software, not a deployed service.

---

*Maintainer: Egor Khaklin (VANTA)*
*Last updated: 2026-09-28 (v1.0.0-rc.66)*
*Machine-readable: the live `/.well-known/security.txt` route (RFC 9116)*
