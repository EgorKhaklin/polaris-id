# RELEASING.md: publishing the product artifacts

**Reader:** whoever decides that a version of a Polaris product artifact should exist
outside this repository. **Job:** say exactly what has to be true first, what the one-time
setup is, and what the command is.

This covers the three artifacts a stranger installs. It does not cover the `v9.x` tree
version, which is not a product version and is not published anywhere.

| Artifact | Registry | Name | Current |
|---|---|---|---|
| `packages/polaris-verify/` | PyPI | `polaris-verify` | 0.1.0, unpublished |
| `sdk/python/` | PyPI | `polaris-sdk-python` | 0.1.0, unpublished |
| `sdk/typescript/` | npm | `polaris-sdk-ts` | 0.1.0, unpublished |

All three names were confirmed unclaimed on 2026-09-13. The npm package was `@polaris/verify`
until that date and had to change: `@polaris` resolves to an existing npm organisation, so
that scope could never have been published to. Checked, not assumed, against a calibration
that distinguishes a real org from an absent one.

---

## Installing before any of that

Nothing is blocked on publishing. An external party can install and run the verifier today,
from a public URL, and this is measured on a clean machine rather than assumed:

```bash
pip install "polaris-verify[cryptography] @ git+https://github.com/EgorKhaklin/polaris-id#subdirectory=packages/polaris-verify"
polaris-verify --pqc-provider auto --pack credential.json
```

The `#subdirectory=` fragment is not optional. The repository root has no `pyproject.toml`,
so the form a newcomer tries first, `pip install git+https://github.com/EgorKhaklin/polaris-id`,
fails with *"does not appear to be a Python project"*.

This installs whatever is on the default branch, not a fixed version, so it is the right tool
for someone evaluating and the wrong one for anyone depending on it.

**The TypeScript SDK has no equivalent.** npm has no `#subdirectory=`, so
`npm install github:EgorKhaklin/polaris-id` fails (`Could not read package.json`, exit 254) and
there is no one-line form that works. A clone is the path:

```bash
cd sdk/typescript && npm ci
cd /your/project && npm install /path/to/polaris-id/sdk/typescript
```

So publishing means two different things for the two packages: for `polaris-verify` it buys a
fixed version over a moving branch, and for `polaris-sdk-ts` it buys the first one-command
install there has ever been. That is the argument for
publishing, and it is a different argument from "otherwise nobody can use it".

---

## Before anything is published

`0.1.0` is deliberate. The go-forward contract gives `1.0.0` five conditions, and a version
number that claims more than has happened is the thing the front-door rule exists to stop.
Publishing `0.x` is fine and says what it is: a thing that works and that nobody outside has
used yet.

What must hold for any publish:

1. `python scripts/polaris-product-boundary-drill.py` passes. The workflow runs it and will
   not publish past a failure. It builds a wheel, installs it into a throwaway environment
   with none of Polaris present, verifies real signed material, and packs and installs the
   npm tarball into a bare project. It carries two negative controls.
2. `python -m twine check` passes on every distribution.
3. The version was bumped. **A version number on a registry can never be reused**, even
   after a yank, so a mistake costs a number rather than being undone.

---

## One-time setup, per registry

Neither of these puts a long-lived token in the repository.

### PyPI (Trusted Publishing)

Do this once per project name, before the first publish. Because neither project exists yet,
use the *pending* publisher form.

1. Go to <https://pypi.org/manage/account/publishing/>.
2. Add a pending publisher:
   - PyPI project name: `polaris-verify` (then repeat for `polaris-sdk-python`)
   - Owner: `EgorKhaklin`
   - Repository name: `polaris-id`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`
3. In this repository's settings, create an environment named `pypi`. Adding a required
   reviewer there is worth it: it makes the irreversible step a second, deliberate click.

### npm (Trusted Publishing)

1. Create the package's first version through the workflow, or reserve the name by
   publishing `0.1.0` from it.
2. In this repository's settings, create an environment named `npm`.
3. If npm Trusted Publishing is configured for the package, no token is needed. Otherwise
   add an `NPM_TOKEN` secret with a granular access token scoped to `polaris-sdk-ts` only.

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

---

## After publishing

Record it in [`lab/EXTERNAL-NOUNS.md`](../lab/EXTERNAL-NOUNS.md). Being installable is not
external use and does not fill in a scoreboard row on its own: a registry download count is
not a person. The rows that count are a named wallet, a named conformance profile with a
score, a named relying party, and a defect filed by somebody who is not the author.
