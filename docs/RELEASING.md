# RELEASING.md: publishing the product artifacts

**Reader:** whoever decides that a version of a Polaris product artifact should exist
outside this repository. **Job:** say exactly what has to be true first, what the one-time
setup is, and what the command is.

This covers the four artifacts a stranger installs. It does not cover the tree version in
`polaris_web/__version__.py`, which is published nowhere and moves only when something
externally observable changes.

| Artifact | Registry | Name | On the registry | Before it |
|---|---|---|---|---|
| `packages/polaris-verify/` | PyPI | `polaris-verify` | 1.0.0rc3, 2026-09-18 | 1.0.0rc1, 2026-09-16 |
| `packages/polaris-oid4vp/` | PyPI | `polaris-oid4vp` | 1.0.0rc3, 2026-09-18 | 1.0.0rc1, 2026-09-16 |
| `sdk/python/` | PyPI | `polaris-sdk-python` | 1.0.0rc3, 2026-09-18 | 1.0.0rc1, 2026-09-16 |
| `sdk/typescript/` | npm | `polaris-sdk-ts` | 1.0.0-rc.1, 2026-09-16 (rc.3 STAGED, not published) | 0.1.0, 2026-09-15 |

> **rc.3 IS PUBLISHED ON PyPI. npm IS STAGED AND NEEDS A MAINTAINER.** On 2026-09-18 the
> three PyPI packages went out at 1.0.0rc3 through trusted publishing over OIDC, verified by
> reading the versions back from the live registry and by walking
> [STRANGER-PATH.md](STRANGER-PATH.md) end to end against the published `polaris-oid4vp`
> 1.0.0rc3: a walt.id wallet presented a credential and the verifier answered
> `200 authentic`.
>
> `polaris-sdk-ts` did not publish. npm now requires a maintainer's 2FA approval as the final
> step of a staged publish, so the workflow uploads the tarball and stops, which is the
> behaviour it is meant to have. The run also reports `401 Unauthorized` on
> `GET /-/stage`, so the token cannot even list what it staged. Finishing it is a person with
> the account's second factor, from their own machine:
>
>     npm stage list polaris-sdk-ts
>     npm stage view <stage-id>          # inspect before approving
>     npm stage approve <stage-id> --otp <code>
>
> Then read the version back from the registry rather than trusting the workflow's exit code,
> which is what caught this: the job reported success while nothing had become installable.

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

The PyPI maturity classifier is `4 - Beta`. There is no classifier for a candidate, and
`5 - Production/Stable` would say more than has happened.

What must hold for any publish:

1. `python scripts/polaris-product-boundary-drill.py` passes. The workflow runs it and will
   not publish past a failure. It builds each wheel, installs it into a throwaway environment
   with none of Polaris present, verifies real signed material, packs and installs the npm
   tarball into a bare project, and opens a conformance-suite response with `polaris-oid4vp`
   from outside the repository. It carries three negative controls.
2. `python -m twine check` passes on every distribution.
3. The version was bumped. **A version number on a registry can never be reused**, even
   after a yank, so a mistake costs a number rather than being undone.

---

## One-time setup, per registry

Done for all four, and written down so that a fifth artifact gets the same shape. No
long-lived token exists for any of them, and the workflow contains no `secrets.` reference.

### PyPI (Trusted Publishing)

Each of the three projects has a trusted publisher: owner `EgorKhaklin`, repository
`polaris-id`, workflow `publish.yml`, environment `pypi`. The `pypi` environment exists in
this repository's settings; a required reviewer there makes the irreversible step a second,
deliberate click.

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
`npm`, direct `npm publish` allowed. npm cannot do any of this for a package's *first* publish: the
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
needs npm 11.15.0 and Node 22.14.0, and the job asserts both rather than trusting
`npm@latest` to be new enough: a silent fall back to a direct publish is the one outcome
staging exists to prevent.

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

**One setting still has to change on npmjs.com, and it is not in this repository.** The
trusted publisher was created with direct `npm publish` allowed, which leaves that path open
beside this one and makes the approval optional rather than required. On the package's
access page, under the trusted publisher, leave "allow `npm publish`" **unchecked**. npm's
own wording calls the checked state not recommended. Nothing in the tree can enforce this,
which is why it is written here: the staging in `publish.yml` is half of the control, and
this checkbox is the other half.

---

## Publishing

Actions → **Publish product artifacts** → Run workflow.

- **Dry run** (the default): leave `target` at `dry-run-everything` and `confirm` empty.
  Everything is built, gated and validated, and the distributions are attached to the run as
  an artifact. Nothing leaves the runner. Do this first, every time.
- **Real publish**: set `target` to the one artifact, and type `PUBLISH` into `confirm`.
  Anything other than that exact string stays a dry run.

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
| 35298838076 | 2026-09-18 | `polaris-sdk-ts` 1.0.0-rc.3 | STAGED, not published. npm requires a maintainer's 2FA approval to finish; the job exited 0 and the registry still shows rc.1 |

The first dry run was once cited as cover for all four artifacts, and it had not built one of
them. A dry run that did not build the thing being published is a rehearsal of a different
performance; the table names what each run built so that cannot happen by reading.

---

## After publishing

Record it in [`lab/EXTERNAL-NOUNS.md`](../lab/EXTERNAL-NOUNS.md). Being installable is not
external use and does not fill in a scoreboard row on its own: a registry download count is
not a person. The rows that count are a named wallet, a named conformance profile with a
score, a named relying party, and a defect filed by somebody who is not the author.
