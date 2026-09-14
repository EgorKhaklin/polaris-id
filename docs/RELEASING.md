# RELEASING.md: publishing the product artifacts

**Reader:** whoever decides that a version of a Polaris product artifact should exist
outside this repository. **Job:** say exactly what has to be true first, what the one-time
setup is, and what the command is.

This covers the three artifacts a stranger installs. It does not cover the `v9.x` tree
version, which is not a product version and is not published anywhere.

| Artifact | Registry | Name | Current |
|---|---|---|---|
| `packages/polaris-verify/` | PyPI | `polaris-verify` | 0.1.0, unpublished |
| `packages/polaris-oid4vp/` | PyPI | `polaris-oid4vp` | 0.1.0, unpublished |
| `sdk/python/` | PyPI | `polaris-sdk-python` | 0.1.0, unpublished |
| `sdk/typescript/` | npm | `polaris-sdk-ts` | 0.1.0, unpublished |

All four names were confirmed unclaimed: the first three on 2026-09-13, `polaris-oid4vp` on
2026-09-14, each against a calibration that tells an absent name from a present one
(`cryptography` and `requests` answer 200; the candidate and a nonsense name answer 404). The npm package was `@polaris/verify`
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

```bash
pip install "polaris-oid4vp @ git+https://github.com/EgorKhaklin/polaris-id#subdirectory=packages/polaris-oid4vp"
```

**Both were run from the public URL on 2026-09-14, in an empty environment, and are what
the output below actually was.** The product boundary drill builds its wheels from the
working tree, which answers a different question: whether the code in front of you installs.
This answers whether what GitHub is serving does.

    polaris-verify --pqc-provider auto --pack pack-mldsa87-valid.json
        crypto: cryptography · algorithm: ML-DSA-87 · signature_valid: True     exit 0
    polaris-verify --pack pack-mldsa87-valid.json        (no declared crypto mode)
        "There is no default and no environment variable for this."            exit 4

    polaris-oid4vp, on the conformance suite's own captured response
        authentic: True, claims given_name / family_name / vct                 exit 0
        the same response under a nonce we did not send                      refused, code `nonce`

    polaris_web, polaris_checks, flask, psycopg2                    all absent from the venv

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
   not publish past a failure. It builds each wheel, installs it into a throwaway environment
   with none of Polaris present, verifies real signed material, packs and installs the npm
   tarball into a bare project, and opens a conformance-suite response with `polaris-oid4vp`
   from outside the repository. It carries three negative controls.
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
   - PyPI project name: `polaris-verify` (then repeat for `polaris-sdk-python` and
     `polaris-oid4vp`)
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

**The dry run has been executed, and re-executed since a fourth artifact appeared.**
2026-09-14, run 34859291906: `build-and-gate` green, both publish jobs correctly skipped,
`target: dry-run-everything`, `confirm: (not PUBLISH) -- DRY RUN, nothing leaves this
runner`, and it produced

```
dist/polaris-verify/polaris_verify-0.1.0-py3-none-any.whl            twine check PASSED
dist/polaris-verify/polaris_verify-0.1.0.tar.gz                      twine check PASSED
dist/polaris-sdk-python/polaris_sdk_python-0.1.0-py3-none-any.whl    twine check PASSED
dist/polaris-sdk-python/polaris_sdk_python-0.1.0.tar.gz              twine check PASSED
dist/polaris-oid4vp/polaris_oid4vp-0.1.0-py3-none-any.whl            twine check PASSED
dist/polaris-oid4vp/polaris_oid4vp-0.1.0.tar.gz                      twine check PASSED
dist/polaris-sdk-ts-0.1.0.tgz
```

**The earlier record was stale and would have been trusted.** Run 34761304289 on 2026-09-13
is the one this section used to name, and it predates `polaris-oid4vp` entirely: it built
five files, not seven, and never exercised the artifact that now carries a conformance
result. A dry run that did not build one of the things being published is a rehearsal of a
different performance, and reading it as cover for all four would have been exactly the
failure this section exists to prevent.

So the mechanism is exercised, not merely written: a workflow nobody has ever run is a plan.
The remaining untested step is the authenticated publish itself, which cannot be rehearsed.

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
