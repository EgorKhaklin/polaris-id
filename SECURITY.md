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

The current versions carry none of the defects below except those stated after the table; each row
lists what older versions still carry.

| Package | Current | Older versions still carrying known defects |
|---|---|---|
| `polaris-oid4vp` | `1.0.0rc11` | `1.0.0rc10` and earlier: refuse an issuer certificate whose extended key usage is ISO 18013-5's document signer, as EUDI issuers' are. `1.0.0rc9` and earlier: `serve` accepts TLS 1.0 and 1.1 where the Python build's default allows them, as the macOS system Python 3.9 does; accept a Token Status List whose compressed data is truncated; read an issuer `kid` of `""` as no `kid`, so it matches any listed key. `1.0.0rc8` and earlier: decrypt a JWE whose tag is not 128 bits (other splits of the same bytes); read an `x5c` header that is present but empty, or not a list, as absent; verify under only the first issuer key that parses, so a rotated key fails; report the `no_authority` and `list_refused` revocation answers as `unreachable`; in `serve`, miss a truncated body that is not valid UTF-8. `1.0.0rc7` (the certified version) and earlier: with an x5c issuer, **accept an `iss` its certificate does not name** and pass it to the status resolver; accept a `vp_token` under a key the DCQL query did not use. `1.0.0rc7` (measured): **raises instead of refusing** a non-string disclosure name, `vct` or JWE `enc`, or JSON nested about 20,000 deep (`serve` answers 400; a library caller gets `TypeError` or `RecursionError`). `1.0.0rc3`: no Token Status List support. `1.0.0rc1`, `0.1.0`: **never read `exp`**; missing input bounds. |
| `polaris-verify` | `1.0.0rc6` | `1.0.0rc5` and earlier: **accept an agent-grant chain whose credential does not verify, or whose issuer is outside `--issuer-anchor`**; call a grant with a link missing usable; decide an agent grant or a presentation with no `--issuer-anchor` instead of abstaining; **accept a stapled status assertion signed by another trusted key than the credential's**; ignore `--nonce` and `--trusted-anchor` on a presentation; **trust a federation manifest that merely lists a trusted anchor**; count any key's signature on a trust edge as the attesting authority's; accept a holder proof made for another credential; name a receipt's responder that nothing confirmed; accept a timestamp over a SHA-1 or uppercase digest; coerce an inclusion proof's index, size and path; accept a witness threshold of 0.5 or -1 as met by no cosignature; on the presentation and grant paths, raise on an anchor file that is not a key list. `1.0.0rc4` and earlier: accept a signature or key whose hex has whitespace between bytes, which the TypeScript SDK refused; raise in `--verify-dir` on a vector that is not a JSON object; call missing revocation evidence a revocation in the long-term-validation note; read a signed grant whose `limits` is not an object as unlimited. `1.0.0rc3` and earlier: **report any authority-signed artifact re-wrapped as an authenticity pack as an authentic credential**; with **no context presented**, accept a trust edge from any context; accept an **unsigned** trust edge past, or without a readable, `valid_until`. `1.0.0rc3` also: a grant under a **revoked** holder binding reads as bound, a receipt stating no context reads as requester-authorized, and timestamp-anchor `cosignatures` that are not a list **raise** instead of refusing (measured). `1.0.0rc1`, `0.1.0`: **never read a trust attestation's `valid_until`**; no finite-number guards. |
| `polaris-sdk-python` | `1.0.0rc6` | `1.0.0rc5` and earlier: `grant_principal_bound` **binds a grant to a credential whose signature does not verify**; **read any artifact the timestamp log's key signed as its tree head**; **trust a federation manifest when no trust anchor is named, or one that merely lists a trusted anchor**; **prove a holder chain checked against no nonce, or with a credential whose signature does not verify**; count any key's signature on a trust edge as the attesting authority's; accept a holder proof made for another credential; count a holder binding with no window as fresh; name a receipt's responder that nothing confirmed; accept a timestamp over a SHA-1 or uppercase digest, or whose `issued_at` is not an instant; accept a revocation feed or status bundle whose signed count differs from its members; coerce an inclusion proof's index, size and path; accept a witness threshold of 0.5 or -1 as met by no cosignature; `verify_cross_authority` **raises** on a manifest set of `true` and reports no `via`. `1.0.0rc4` and earlier: pass an `issuer_url` whose scheme is not `https` or `http` to `urlopen`; accept a signature or key whose hex has whitespace between bytes; read a signed grant whose `limits` is not an object as unlimited. `1.0.0rc3` and earlier: `verify_authenticity` **accepts any authority-signed artifact re-wrapped as a pack**; `verify_cross_authority` accepts a signed or **unsigned** trust edge past, or without a readable, `valid_until`, and with **no context presented** an edge from any context. `1.0.0rc3` (measured): an artifact `format` that is not a string, `cosignatures` that are not a list, or a revocation feed that is not an object **raise** instead of refusing. `1.0.0rc1`, `0.1.0`: no finite-number guards on grant limits; cached tokens outlive a revoked client. |
| `polaris-id-cli` | `1.0.0rc1` | None: the first release. |
| `polaris-sdk-ts` (npm) | `1.0.0-rc.7` under `next` | `1.0.0-rc.6` and earlier: `grantPrincipalBound` **binds a grant to a credential whose signature does not verify**; **read any artifact the timestamp log's key signed as its tree head**; **trust a federation manifest when no trust anchor is named, or one that merely lists a trusted anchor**; **prove a holder chain checked against no nonce, or with a credential whose signature does not verify**; count any key's signature on a trust edge as the attesting authority's; accept a holder proof made for another credential; count a holder binding with no window as fresh; name a receipt's responder that nothing confirmed; accept a timestamp over a SHA-1 or uppercase digest, or whose `issued_at` is not an instant; accept a revocation feed or status bundle whose signed count differs from its members; coerce an inclusion proof's index, size and path; accept a witness threshold of 0.5 or -1 as met by no cosignature; read a holder proof's instant with no offset in the machine's time zone; `verifyCrossAuthority` **raises** on any manifest set that is not a list. `1.0.0-rc.5` and earlier: accept a signature or key whose hex has a character that is not hex, which the other verifiers refuse; read a signed grant whose `limits` is a string or a number as unlimited. `1.0.0-rc.4` and earlier: read an artifact `format` that is a list as the string it coerces to. `1.0.0-rc.3` and earlier: `verifyAuthenticity` **accepts any authority-signed artifact re-wrapped as a pack**; `verifyCrossAuthority` accepts a signed or **unsigned** trust edge past, or without a readable, `valid_until`, and with **no context presented** an edge from any context. `0.1.0` (what `latest` resolves): canonicalisation and parsing divergences from the wire specification. |

Exception until the next publish: `polaris-oid4vp` 1.0.0rc11 **answers a wallet 200 for a credential
its configured status resolver found revoked**, accepts a presentation that withholds a requested claim,
an orphan disclosure with key binding waived, an `x5c` leaf expired at the verdict's `now` and a JWE
marked `crit`, and a W3C VC Data Model credential typed `vc+sd-jwt` as an SD-JWT VC, ignoring its
`validUntil` and `credentialStatus`; it also ignores a `crit` on the credential, its key binding JWT
and a status list token, and the key binding JWT's `exp` and `nbf`, accepts a digest committed twice
and the trust anchor or a CA certificate as the issuer's `x5c` leaf; and it serves an expired request
object. `polaris-verify` 1.0.0rc6 and `polaris-sdk-python` 1.0.0rc6 read a signed anchor, registry
authority or holder binding whose `status` is `false` or `""` as active; `polaris-verify` 1.0.0rc6 calls a
grant usable whose limits it does not understand; all three read a revocation feed's non-hex leaf by
its spelling, so a `null` leaf passes one language and not the other, accept an agent grant with no
`grant_id`, which no revocation can name, and accept a signed document whose digest is not lowercase
SHA3-256; both Python packages read a use limit of 2.5 as 2, an instant in non-ASCII digits as valid, a
missing agency id as matching a null one, and `true` as context or agency 1 and as the credential or
grant `"True"`; both SDKs read a status answer of `currently_authoritative: "false"` as current; and
`polaris-sdk-ts` 1.0.0-rc.7 rounds instants to the millisecond, reads an offset of 24 hours, refuses a
genuine artifact signed with a number like 1.5e-05 or a key outside the Basic Multilingual Plane,
decides a presentation naming `credential: null` as the object itself, proves a holder chain whose
signed nonce is `true` against the nonce "true", and binds a grant through a binding naming `true` to
the credential "true". The tree carries the fixes; releases follow the maintainer's approval.

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
SLSA build provenance (Sigstore via GitHub OIDC), attached before the release is published, so
the immutable release holds them:

```bash
gh attestation verify sbom-python.spdx.json --repo EgorKhaklin/polaris-id
```

The provenance bundle is attached beside the SBOMs, so the same check also runs without
GitHub's attestation store:

```bash
gh attestation verify sbom-python.spdx.json --repo EgorKhaklin/polaris-id \
  --bundle sbom-provenance.intoto.jsonl --signer-workflow EgorKhaklin/polaris-id/.github/workflows/sbom.yml
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
managers. npm and Rust dependencies are fully locked (package-lock.json, Cargo.lock), and so is
every Python package the images install: each `requirements*.in` is compiled into a hash-pinned
lock that the Dockerfiles install with `--require-hashes`, and liboqs is built from its release
commit, checked, never fetched by liboqs-python at import. Container base images are pinned by digest. Dependabot alerts and weekly updates cover Python, Rust, GitHub Actions and Docker. Patch and
minor bumps are applied in batches and validated by a full CI run; majors of foundation
dependencies are planned work. The `cve-scan` and `image-cve-scan` CI jobs fail the build on a
known CVE in the runtime surface or a fixable critical in an image.

Thresholds. Dependency findings (SCA): a known vulnerability in a runtime dependency, or a fixable
critical in an image, fails the build and is fixed before anything merges; a high finding in an
image is reviewed before each release and fixed once a fixed version exists. A dependency whose
license does not allow its use in an Apache-2.0 project is not added (NOTICE lists every license). Code findings (SAST): bandit fails the build on a high-severity
finding; medium findings are reviewed before each release. CodeQL and zizmor report every push and
pull request to the Security tab, and a high or critical alert is fixed, or dismissed with its
reason written on the alert, before the next release. The functions in `polaris-oid4vp` that read what a wallet or a
status list server sends are fuzzed, coverage-guided, on every change to that package and
nightly; an input that breaks a function's documented promise fails the job. Every change is also scanned by OSV-Scanner for malicious packages (the OpenSSF Malicious Packages
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
  code can publish, and every publish waits for the maintainer to approve that run; an npm
  publish also waits for a maintainer's second factor.
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
*Last updated: 2026-10-01 (v1.0.0-rc.68)*
*Machine-readable: the live `/.well-known/security.txt` route (RFC 9116)*
