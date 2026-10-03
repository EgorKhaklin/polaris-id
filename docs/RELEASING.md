# RELEASING.md: publishing the product artifacts

**Reader:** whoever decides that a version of a Polaris product artifact should exist
outside this repository. **Job:** say exactly what has to be true first, what the one-time
setup is, and what the command is.

This covers the four artifacts a stranger installs, and the operator CLI, `polaris-id-cli`
(`polaris_cli/`), for someone already running a Polaris instance: its commands need a running
Polaris PostgreSQL, and the few that need the application tree refuse from a package install and
name the clone to run them from. It does not cover the tree version in
`polaris_web/__version__.py`, which is published nowhere and moves only when something
externally observable changes.

| Artifact | Registry | Name | On the registry | Before it |
|---|---|---|---|---|
| `packages/polaris-verify/` | PyPI | `polaris-verify` | 1.0.0rc7, 2026-10-01 | 1.0.0rc6, 2026-10-01 |
| `packages/polaris-oid4vp/` | PyPI | `polaris-oid4vp` | 1.0.0rc13, 2026-10-02 | 1.0.0rc12, 2026-10-01 |
| `sdk/python/` | PyPI | `polaris-sdk-python` | 1.0.0rc7, 2026-10-01 | 1.0.0rc6, 2026-10-01 |
| `polaris_cli/` | PyPI | `polaris-id-cli` | 1.0.0rc1, 2026-09-30 | none, the first |
| `sdk/typescript/` | npm | `polaris-sdk-ts` | 1.0.0-rc.9, 2026-10-03 | 1.0.0-rc.8, 2026-10-01 |

> **2026-10-03:** `polaris-sdk-ts` 1.0.0-rc.9, staged under `next` and approved by the maintainer with a
> second factor (shasum `8ad830518a2dd4877da956b233cd986eb6681971`), read back from the live registry: its
> `engines` now require Node >= 20.19.0, the floor its dependencies require (1.0.0-rc.8 declared >= 18 and
> did not load there).
>
> **2026-10-02:** `polaris-oid4vp` 1.0.0rc13, approved at the environment gate and read back from the
> live registry: a clean virtual environment installed it from PyPI and ran the package's 359 tests, all
> passing. It carries the RFC 7515, RFC 9901 and HAIP 1.0 checks (#157) and the JWK `use`/`key_ops`/`alg`
> rule (#168) that the 04:56 build behind 1.0.0rc12 lacked. Not certified; 1.0.0rc7 is.
>
> **2026-10-01, later still:** `polaris-verify` and `polaris-sdk-python` 1.0.0rc7, each approved
> at the environment gate, and `polaris-sdk-ts` 1.0.0-rc.8, staged under `next` and approved by
> the maintainer with a second factor (shasum `00555b86875e58f6ee07ec1d89f7226424bdcc41`), each
> read back from the live registry. Installed from the registries, both SDKs pass all 281
> conformance cases. They carry the value rules all three verifiers now share and the command
> line's exit codes (SECURITY.md lists what 1.0.0rc6 and 1.0.0-rc.7 got wrong).
>
> **2026-10-01, later:** `polaris-oid4vp` 1.0.0rc12, approved at the environment gate and read
> back from the live registry, with STRANGER-PATH walked against it. It refuses a credential its
> status resolver checked as revoked, a presentation withholding a requested claim, a W3C
> `vc+sd-jwt` credential, and an expired request object. The run that published it was dispatched
> at 04:56 and built at 7bfd26ed, before the RFC 7515, RFC 9901 and HAIP checks and the JWK `use`
> rule merged, so it carries neither; 1.0.0rc13 does. Not certified; 1.0.0rc7 is.
>
> **2026-10-01:** `polaris-verify` and `polaris-sdk-python` 1.0.0rc6, each approved at the environment
> gate, and `polaris-sdk-ts` 1.0.0-rc.7, staged under `next` and approved by the maintainer with a
> second factor (shasum `e86011abae989848bcaa6ecc7041804ae50ab605`), each read back from the live
> registry. Installed from the registries, both SDKs pass all 219 conformance cases (1.0.0rc5 and
> 1.0.0-rc.6 fail 20 each), and the `polaris-verify` wheel's verifier is byte-identical to the
> tree's and passes its contract run.
>
> **2026-09-30, evening:** `polaris-oid4vp` 1.0.0rc11, which takes ISO 18013-5's document
> signer as an issuer certificate usage (not certified; 1.0.0rc7 is), and the first
> `polaris-id-cli`, 1.0.0rc1, each held at the environment gate until the maintainer approved
> the run, then read back from the live registry.
>
> **2026-09-30, later:** `polaris-verify` and `polaris-sdk-python` 1.0.0rc5 and `polaris-oid4vp`
> 1.0.0rc10 went out the same way, each read back from the live registry, carrying the fixes
> SECURITY.md lists against their predecessors. 1.0.0rc10 is not certified; 1.0.0rc7 is.
>
> **2026-09-30:** `polaris-oid4vp` 1.0.0rc9 went out through trusted publishing over OIDC and was
> read back from the live registry. It carries the fixes a review found in 1.0.0rc8 and is not
> certified; the certified version is 1.0.0rc7.
>
> **2026-09-28:** `polaris-verify` and `polaris-sdk-python` 1.0.0rc4 and `polaris-oid4vp`
> 1.0.0rc8 went out through trusted publishing over OIDC, each read back from the live
> registry. `polaris-sdk-ts` 1.0.0-rc.4 was staged under `next`, approved by the maintainer and
> read back (shasum `09964827b3aedb66c23a19bb89aed0c0156ab42a`). It predated the TypeScript format fix,
> so `polaris-sdk-ts` 1.0.0-rc.5 followed the same day, staged, approved and read back the same way
> (shasum `c77a33fe0014e0ab7a0cf20bae7b99964cbe9d34`; the installed package passes all 184 conformance
> cases). `polaris-oid4vp` 1.0.0rc8 is not certified; the certified version is 1.0.0rc7.
>
> **npm now takes two people-steps, and the first one lies.** `npm stage publish` uploads the
> tarball and stops; the job exits 0 while nothing is installable. A maintainer then approves
> it from their own machine with a second factor. Three things cost time here and are worth
> knowing before the next release:
>
> - The workflow's own `npm stage list` step returns `401 Unauthorized`: the OIDC token can
>   publish that package but cannot list stages. Cosmetic, but it reads like a failure.
> - `npm stage` needs npm >= 11.15.0, and `npm install -g npm@latest` fetches npm 12, which
>   requires node `^22.22.2 || ^24.15.0 || >=26.0.0`. On an older node that install fails and
>   the command stays missing. `npm install -g npm@11.19.1` has `stage` and runs on
>   node >= 22.9.0, so it is the smaller change.
> - Several auth attempts in quick succession trip `E429 ... rate limited otp`. The passkey is
>   fine; the rate is not. Wait, then retry ONCE.
>
> The approval is what makes it real, and the tarball's shasum is the thing to check before
> approving: `npm stage view <id>` must match what the build published. For rc.3 that was
> `7bc35e6dbaf0e505b9bb7a4f6c90f5e79e3ffcad`, and the registry serves the same digest; for
> rc.4 it is `09964827b3aedb66c23a19bb89aed0c0156ab42a`.
> Verify from the registry rather than the exit code, always: a green workflow and an
> unpublished package look identical from outside.

All four names were unclaimed when checked (the first three on 2026-09-13, `polaris-oid4vp`
on 2026-09-14, each against a calibration that tells an absent name from a present one) and
are held by this project now. The npm package was `@polaris/verify` until then and had to
change: `@polaris` resolves to an existing npm organisation that this project could never
have published under.

---

## Installing

From the registries. Nothing here needs this repository:

```bash
pip install --pre "polaris-verify[cryptography]"
pip install --pre polaris-oid4vp
pip install --pre polaris-sdk-python
npm install polaris-sdk-ts@next
```

`--pre` because the current version is a release candidate and pip skips pre-releases unless
told; without it pip installs 0.1.0, the previous release, which also works. npm refuses to
publish a prerelease without a dist-tag, so a candidate goes out under `next`: `latest` stays
on the last full release, and the candidate is `polaris-sdk-ts@next`.

Every publish is verified the same way, and recorded only after that: install from the live
registry into an environment with none of Polaris present, then run the thing. For
`polaris-oid4vp` that is `keygen` producing a working HAIP certificate set, which is the
package an outside verifier operator reaches for. The rows are in
[`lab/EXTERNAL-NOUNS.md`](../lab/EXTERNAL-NOUNS.md).

A branch install exists for someone evaluating a change before it is released. Both forms
were run from the public URL on 2026-09-14 in an empty environment:

```bash
pip install "polaris-verify[cryptography] @ git+https://github.com/EgorKhaklin/polaris-id#subdirectory=packages/polaris-verify"
pip install "polaris-oid4vp @ git+https://github.com/EgorKhaklin/polaris-id#subdirectory=packages/polaris-oid4vp"
```

The `#subdirectory=` fragment is not optional: the repository root has no `pyproject.toml`,
so `pip install git+https://github.com/EgorKhaklin/polaris-id` fails with *"does not appear
to be a Python project"*. This installs whatever is on the default branch, not a fixed
version. npm has no `#subdirectory=` and no one-line form, so for the TypeScript SDK a branch
install is a clone: `cd sdk/typescript && npm ci`, then `npm install
/path/to/polaris-id/sdk/typescript` from your project.

---

## What the version number says

The four packages are at 1.0.0-rc.1 (`1.0.0rc1` in the Python metadata, which is how PEP 440
spells the same thing). The go-forward contract names five conditions for calling anything
1.0.0, and all five hold:

1. A clean-machine install works: the product boundary drill, on every push and before every
   publish, and the registry installs above.
2. The cryptographic mode is explicit and safe: `polaris-verify` refuses to start without
   `--pqc-provider`; there is no default and no environment variable for it.
3. A named external client completed a presentation: walt.id `wallet-api2:1.0.0`, unmodified,
   on 2026-09-15.
4. A named external conformance suite has been run: the OpenID Foundation's hosted suite,
   `oid4vp-1final-verifier-haip-test-plan`, across the open internet.
5. That result is published where it is not green: 7 PASSED, 4 REVIEW, in the README, on the
   site and in the scoreboard. REVIEW is not PASSED.

Why a candidate and not 1.0.0: the contract's 90-day objective also asks for an operator who
is not the author to have used the verifier, and that row of the scoreboard is blank. A release
candidate is the number that says both things at once. That operator makes 1.0.0; a defect
found in the candidate makes the next candidate, which is what rc.2 was. Nothing else does.
The next candidate is cut as a release, one tag and one GitHub Release that collect every defect
fixed since the last one, and not per fix (2026-09-26; rc.4 to rc.62 moved per fix, untagged, and
v1.0.0-rc.62 was released as one candidate covering all of them).

The PyPI maturity classifier is `4 - Beta`. There is no classifier for a candidate, and
`5 - Production/Stable` would say more than has happened.

What must hold for any publish:

1. `python scripts/polaris-product-boundary-drill.py` passes. The workflow runs it and will
   not publish past a failure. It builds each wheel, installs it into a throwaway environment
   with none of Polaris present, verifies real signed material, packs and installs the npm
   tarball into a bare project, and opens a conformance-suite response with `polaris-oid4vp`
   from outside the repository. It carries three negative controls.
2. `python -m twine check` passes on every distribution. The distributions are built by the
   toolchain pinned with hashes in `.github/publish/requirements.txt` (build, setuptools,
   twine), without build isolation, so no unpinned setuptools is fetched into the build.
3. The version was bumped. **A version number on a registry can never be reused**, even
   after a yank, so a mistake costs a number rather than being undone.

---

## One-time setup, per registry

Done for all four, and written down so that a fifth artifact gets the same shape. No
long-lived token exists for any of them, and the workflow contains no `secrets.` reference.

### PyPI (Trusted Publishing)

Each of the three projects has a trusted publisher: owner `EgorKhaklin`, repository
`polaris-id`, workflow `publish.yml`, environment `pypi`. The `pypi` environment exists in
this repository's settings. Whether it requires a reviewer is a setting too, and on 2026-09-30
it did not: typing `PUBLISH` into `confirm` was the deliberate step.

For a new project name, add a *pending* publisher at
<https://pypi.org/manage/account/publishing/> before the first publish, with exactly those
four values. Two things cost time on 2026-09-15 and are worth knowing:

- The environment must match the workflow's `environment: pypi` exactly. `polaris-oid4vp` was
  first registered with environment *(Any)*, and PyPI refused the publish as an invalid
  publisher (run 34938539770) until it was re-registered with `pypi`.
- PyPI holds one pending publisher per (owner, repository, workflow, environment) at a time
  (pypi/warehouse#16920), so register a name, publish it, then register the next.

### npm (Trusted Publishing)

`polaris-sdk-ts` has a trusted publisher, created on the package's access page on 2026-09-16
(this file had claimed one existed since 0.1.0; the registry's identity exchange answered
`package not found` until it was actually created, two refused runs later). Its fields, which
npm does not let you edit afterwards: publisher GitHub Actions, organization or user
`EgorKhaklin`, repository `polaris-id`, workflow filename `publish.yml`, environment name
`npm`, direct `npm publish` allowed (switched off 2026-09-28, below). npm cannot do any of this for a package's *first* publish: the
publisher is configured on a package page that does not exist until something has been
published (npm/cli#8544). 0.1.0 therefore went out under a granular token scoped to the one
package, held as a repository secret for that one run and revoked within the hour. The secret
is gone and the workflow no longer reads one; 1.0.0-rc.1 went out through the trusted
publisher on 2026-09-16, the first token-free npm publish, under the `next` dist-tag.

The npm job also learned three things the hard way that day, each recorded below: a
prerelease is refused without a dist-tag; `setup-node` with a `registry-url` writes a
placeholder token into the npm config, which the CLI then uses instead of the identity
exchange; and the exchange needs npm 11.5.1 or later, so the job upgrades the CLI first and
publishes verbose so the exchange's answer is in the log.

#### The npm job stages; it does not publish (2026-09-16)

**A green npm job means STAGED, not published.** The step runs `npm stage publish`, which
uploads the tarball and stops. The version is not on the registry, `npm install` cannot
reach it, and it becomes available only when a maintainer approves it with a 2FA code that
no workflow can produce. So the workflow, compromised or merely run by mistake with
`confirm: PUBLISH`, cannot put code in front of an installer by itself. `npm stage publish`
needs npm 11.15.0 and Node 22.14.0. The job installs one exact npm (12.1.0), checked against
its registry sha512 integrity before it runs, and asserts both floors: a silent fall back to a
direct publish is the one outcome staging exists to prevent.

Finish it from your own machine, where the 2FA code lives:

```bash
npm stage list polaris-sdk-ts       # the stage-id of what the run uploaded
npm stage view <stage-id>           # what is in it, before approving anything
npm stage download <stage-id>       # or unpack the tarball and read it
npm stage approve <stage-id> --otp <code>
npm stage reject <stage-id>         # to abandon it instead
```

Then verify from the live registry as below. Until `approve` runs, the verification will
correctly find nothing, and that is the staging working rather than a failed publish.

**Direct `npm publish` is off (2026-09-28).** The trusted publisher was created with it
allowed, which left that path open beside staging and made the approval optional. "Allow `npm
publish`" is now unchecked on the package's access page, so a staged publish approved with a
second factor is the only path. Nothing in the tree can enforce this: the staging in
`publish.yml` is half of the control, and that setting is the other half. Keep it unchecked.

---

## Publishing

Actions → **Publish product artifacts** → Run workflow.

- **Dry run** (the default): leave `target` at `dry-run-everything` and `confirm` empty.
  Everything is built, gated and validated, and the distributions are attached to the run as
  an artifact. Nothing leaves the runner. Do this first, every time.
- **Real publish**: set `target` to the one artifact, and type `PUBLISH` into `confirm`.
  Anything other than that exact string stays a dry run. The publish job then waits for the
  maintainer to approve the run (the `pypi` and `npm` environments require it since
  2026-09-30), so a dispatch alone publishes nothing.

One artifact per run, on purpose. A publish that half-succeeded across three registries is a
worse state to be in than three runs.

**The record** (all from this workflow):

| Run | Date | Target | Result |
|---|---|---|---|
| 34761304289 | 2026-09-13 | dry run | built five files; predates `polaris-oid4vp` |
| 34859291906 | 2026-09-14 | dry run | built all seven; every wheel `twine check PASSED` |
| 34936298068 | 2026-09-15 | dry run | built and gated; nothing published |
| 34938127694 | 2026-09-15 | `polaris-sdk-python` 0.1.0 | published to PyPI |
| 34938379181 | 2026-09-15 | `polaris-verify` 0.1.0 | published to PyPI |
| 34938539770 | 2026-09-15 | `polaris-oid4vp` 0.1.0 | refused by PyPI, publisher environment mismatch |
| 34939353013 | 2026-09-15 | `polaris-oid4vp` 0.1.0 | published to PyPI |
| 34940499289 | 2026-09-15 | `polaris-sdk-ts` 0.1.0 | published to npm, under the bootstrap token |
| 35052310852 | 2026-09-16 | dry run | built and gated all seven rc.1 files; nothing published |
| 35147578684 | 2026-09-16 | `polaris-sdk-python` 1.0.0rc1 | published to PyPI |
| 35147739226 | 2026-09-16 | `polaris-verify` 1.0.0rc1 | published to PyPI |
| 35147945583 | 2026-09-16 | `polaris-oid4vp` 1.0.0rc1 | published to PyPI |
| 35148098228 | 2026-09-16 | `polaris-sdk-ts` 1.0.0-rc.1 | refused by npm: a prerelease needs a dist-tag; nothing uploaded |
| 35148829860 | 2026-09-16 | `polaris-sdk-ts` 1.0.0-rc.1 | refused by npm on the upload (404): the CLI used a placeholder token instead of the identity exchange; nothing uploaded |
| 35149358665 | 2026-09-16 | `polaris-sdk-ts` 1.0.0-rc.1 | refused by npm at the identity exchange (`package not found`): no trusted publisher matched the workflow; nothing uploaded |
| 35150720818 | 2026-09-16 | `polaris-sdk-ts` 1.0.0-rc.1 | refused again at the identity exchange, same answer; nothing uploaded |
| 35151803855 | 2026-09-16 | `polaris-sdk-ts` 1.0.0-rc.1 | published to npm under `next` by trusted publishing, no token |
| 35296615756 | 2026-09-18 | dry run | built and gated all seven rc.3 files; nothing published |
| 35298509935 | 2026-09-18 | `polaris-verify` 1.0.0rc3 | published to PyPI by trusted publishing over OIDC; version read back from the live registry |
| 35298624742 | 2026-09-18 | `polaris-sdk-python` 1.0.0rc3 | published to PyPI the same way; version read back from the live registry |
| 35298734112 | 2026-09-18 | `polaris-oid4vp` 1.0.0rc3 | published to PyPI the same way; read back, and STRANGER-PATH walked end to end against it |
| 35298838076 | 2026-09-18 | `polaris-sdk-ts` 1.0.0-rc.3 | staged (id b399d351), not published by the job; npm requires a maintainer's second factor to finish |
| (by hand) | 2026-09-18 | `polaris-sdk-ts` 1.0.0-rc.3 | approved with a passkey via `npm stage approve` and published under `next`; shasum 7bc35e6d matches the staged tarball, and `npm install polaris-sdk-ts@next` into a clean directory runs |
| 35946054368 | 2026-09-24 | dry run | built and gated; nothing published |
| 35946206199 | 2026-09-24 | dry run | the PyPI job skipped: target or confirm did not match exactly; nothing published |
| 35946434707 | 2026-09-24 | dry run | the same; nothing published |
| 35946558589 | 2026-09-24 | `polaris-oid4vp` 1.0.0rc7 | published to PyPI by trusted publishing; read back from the live registry and installed into a clean environment outside the tree. Published so the OpenID Foundation certification run tests the version a stranger installs, not 0.1.0 |
| 36448334875 | 2026-09-28 | dry run | built and gated all four at the new versions; nothing published |
| 36448595804 | 2026-09-28 | `polaris-verify` 1.0.0rc4 | published to PyPI by trusted publishing; read back from the live registry |
| 36448937187 | 2026-09-28 | `polaris-sdk-python` 1.0.0rc4 | published to PyPI the same way; read back from the live registry |
| 36449355751 | 2026-09-28 | `polaris-oid4vp` 1.0.0rc8 | published to PyPI the same way; read back from the live registry. Not certified: 1.0.0rc7 stays the certified version |
| 36449564786 | 2026-09-28 | `polaris-sdk-ts` 1.0.0-rc.4 | staged (id 24f2675d); approved by the maintainer with a second factor, then read back from the live registry under `next` |
| 36467934686 | 2026-09-28 | `polaris-sdk-ts` 1.0.0-rc.5 | staged (id 0af1ec71); approved by the maintainer with a second factor, then read back from the live registry under `next`; the installed package passes all 184 conformance cases |
| 36673380963 | 2026-09-30 | dry run | built and gated all four; nothing published |
| 36673624400 | 2026-09-30 | `polaris-oid4vp` 1.0.0rc9 | published to PyPI by trusted publishing; read back from the live registry and installed into a clean environment outside the tree. Not certified: 1.0.0rc7 stays the certified version |
| 36700255631 | 2026-09-30 | dry run | built and gated all four at the new versions; nothing published |
| 36702201606 | 2026-09-30 | `polaris-verify` 1.0.0rc5 | published to PyPI by trusted publishing; read back from the live registry |
| 36702209438 | 2026-09-30 | `polaris-sdk-python` 1.0.0rc5 | published to PyPI the same way; read back from the live registry |
| 36702217173 | 2026-09-30 | `polaris-oid4vp` 1.0.0rc10 | published to PyPI the same way; read back, and STRANGER-PATH walked against it. Not certified: 1.0.0rc7 stays the certified version |
| 36743013280 | 2026-09-30 | dry run | built and gated the four Python packages, polaris-id-cli among them, and the npm tarball; nothing published |
| 36743023024 | 2026-09-30 | `polaris-oid4vp` 1.0.0rc11 | approved by the maintainer at the environment gate, published by trusted publishing; read back, and STRANGER-PATH walked against it. Not certified: 1.0.0rc7 stays the certified version |
| 36743032972 | 2026-09-30 | `polaris-id-cli` 1.0.0rc1 | the first: approved at the gate, published the same way; read back, installed alone, `--version` and the clone-only refusals checked |
| 36712332414 | 2026-09-30 | `polaris-sdk-ts` 1.0.0-rc.6 | staged (id d1d7abd7-f1ed-47ab-adb6-5f62497f3f0c); not published by the job; npm requires a maintainer's second factor |
| (by hand) | 2026-09-30 | `polaris-sdk-ts` 1.0.0-rc.6 | approved by the maintainer with a second factor and read back from the live registry under `next`; shasum e57ef6929e7bf809efccd51c325a0592ca53b88d |
| 36807822852 | 2026-10-01 | dry run | built and gated the four Python packages and the npm tarball at the new versions; nothing published |
| 36807850646 | 2026-10-01 | `polaris-verify` 1.0.0rc6 | approved by the maintainer at the environment gate, published by trusted publishing; read back: the wheel's verifier is byte-identical to the tree's, passes its contract run, and refuses the forged agent-grant chain 1.0.0rc5 accepts |
| 36807880510 | 2026-10-01 | `polaris-sdk-python` 1.0.0rc6 | approved at the gate, published the same way; read back, and the installed package passes all 219 conformance cases (1.0.0rc5 fails 20) |
| 36807922993 | 2026-10-01 | `polaris-sdk-ts` 1.0.0-rc.7 | staged (id 86ef20ea-2998-42c0-aaa6-681207109235); not published by the job; npm requires a maintainer's second factor |
| (by hand) | 2026-10-01 | `polaris-sdk-ts` 1.0.0-rc.7 | approved by the maintainer with a second factor and read back from the live registry under `next`; shasum e86011abae989848bcaa6ecc7041804ae50ab605; the installed package passes all 219 conformance cases (1.0.0-rc.6 fails 20) |
| 36817451155 | 2026-10-01 | `polaris-oid4vp` 1.0.0rc12 | dispatched 04:56, approved by the maintainer at the environment gate 12:56, published by trusted publishing from 7bfd26ed (before #157 and #168); read back, and STRANGER-PATH walked against it. Not certified: 1.0.0rc7 stays the certified version |
| 36865073345 | 2026-10-01 | `polaris-oid4vp` 1.0.0rc12 | dispatched again from df252fef; PyPI refused the upload, the version already existed, and nothing changed |
| 36865574554 | 2026-10-01 | `polaris-verify` 1.0.0rc7 | approved by the maintainer at the environment gate, published by trusted publishing; read back: the wheel's verifier is byte-identical to the tree's and passes its contract run |
| 36865603134 | 2026-10-01 | `polaris-sdk-python` 1.0.0rc7 | approved at the gate, published the same way; read back, and the installed package passes all 281 conformance cases |
| 36865643449 | 2026-10-01 | `polaris-sdk-ts` 1.0.0-rc.8 | staged (id 970e5352-5353-4765-a995-ec90f0462198); not published by the job; npm requires a maintainer's second factor |
| 36949202765 | 2026-10-02 | `polaris-oid4vp` 1.0.0rc13 | approved by the maintainer at the environment gate, published by trusted publishing from main; read back: a clean venv install passes all 359 package tests. Carries #157 and #168, which 1.0.0rc12 lacked. Not certified: 1.0.0rc7 stays the certified version |
| (by hand) | 2026-10-01 | `polaris-sdk-ts` 1.0.0-rc.8 | approved by the maintainer with a second factor and read back from the live registry under `next`; shasum 00555b86875e58f6ee07ec1d89f7226424bdcc41; the installed package passes all 281 conformance cases |
| 37139232183 | 2026-10-03 | `polaris-sdk-ts` 1.0.0-rc.9 | staged (id 14d906c5-a442-46be-8da0-e658069057c6); not published by the job; npm requires a maintainer's second factor |
| (by hand) | 2026-10-03 | `polaris-sdk-ts` 1.0.0-rc.9 | approved by the maintainer with a second factor and read back from the live registry under `next`; shasum 8ad830518a2dd4877da956b233cd986eb6681971; its `engines` require Node >= 20.19.0, which 1.0.0-rc.8 declared as >= 18 and did not satisfy |

The first dry run was once cited as cover for all four artifacts, and it had not built one of
them. A dry run that did not build the thing being published is a rehearsal of a different
performance; the table names what each run built so that cannot happen by reading.

---

## After publishing

Record it in [`lab/EXTERNAL-NOUNS.md`](../lab/EXTERNAL-NOUNS.md). Being installable is not
external use and does not fill in a scoreboard row on its own: a registry download count is
not a person. The rows that count are a named wallet, a named conformance profile with a
score, a named relying party, and a defect filed by somebody who is not the author.
