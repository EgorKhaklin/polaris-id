# 011: Build provenance for the packages a stranger installs

**Opened 2026-10-02.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md),
on the owner's direction of 2026-10-02 (work toward the badges Polaris can earn; SLSA was on the
owner's list). State: APPROVED by the owner 2026-10-02 (decision D14): build the SLSA Build L3
provenance after 1.0.0-rc.71 ships, with publish.yml publishing the attested files so the bytes on
PyPI and npm are the bytes the provenance names. The falsifiers in section 10 were written before the build.

---

## The finding that started it

[SECURITY.md](../../SECURITY.md) said the packages on PyPI and npm "carry the same kind of
provenance" as the release SBOMs. Measured on 2026-10-02, they do not all:

- The SBOMs carry SLSA build provenance (`actions/attest-build-provenance` in
  `.github/workflows/sbom.yml`), made in the same job that generates them.
- `polaris-oid4vp 1.0.0rc13` on PyPI carries a **publish** attestation (predicate
  `https://docs.pypi.org/attestations/publish/v1`, publisher `publish.yml`): it binds the file to
  the workflow that uploaded it, not to a source commit and the build that produced it.
- `polaris-sdk-ts` on npm carries SLSA provenance from `npm stage publish --provenance`, made in
  the job that also installs and packs it.

So no package a stranger installs has build provenance made apart from the steps that built it.

- **Kept:** the SBOM provenance, PyPI's publish attestations and npm's provenance, which each say
  something true; trusted publishing and the staged npm publish.
- **Dropped:** that a publish attestation is "the same kind of provenance" as build provenance.
  SECURITY.md now says what each one is.
- **New position:** each release builds its distributions once, attests them from a job that holds
  the signing identity and runs none of the build steps, attaches them to the release with their
  SBOMs, and the registries receive those same bytes.

## 1. What capability is being considered?

SLSA v1.0 Build L3 provenance over every release's distributions (the wheels and sdists of
`polaris-verify`, `polaris-oid4vp`, `polaris-sdk-python` and `polaris-id-cli`, and the
`polaris-sdk-ts` tarball):

- a reusable workflow with two jobs: one builds the distributions with the pinned toolchain and no
  `id-token` permission; the other, which runs no build step, downloads them, checks their digests
  against the build job's, and attests them with `actions/attest-build-provenance`;
- `sbom.yml` calls it and attaches the distributions and their provenance bundle to the draft
  release before publishing it, as it already does for the SBOMs;
- a consumer verifies with
  `gh attestation verify <file> --repo EgorKhaklin/polaris-id --signer-workflow
  EgorKhaklin/polaris-id/.github/workflows/<the reusable workflow>`;
- then, the owner's call: `publish.yml` publishes the attested files from the release instead of
  building its own, so the bytes on PyPI and npm are the bytes the provenance names.

## 2. What problem would it solve?

A relying party trusts `polaris-verify` to say whether a credential is authentic. Today it can check
that a file was uploaded by this repository's workflow, not that the file was built from a given
commit by steps that could not also forge the attestation.

## 3. Who would plausibly need it?

Relying parties and integrators who install the verifier; an independent security review; funders
and evaluators who read a project's supply-chain posture. No one has asked for it by name: this is a
bet, which is why it is recorded here.

## 4. What existing systems already solve it?

The SLSA framework's generic generator (Build L3; referenced by tag, which OpenSSF Scorecard counts
as an unpinned dependency); GitHub artifact attestations made from a reusable workflow, which GitHub
documents as a route to Build L3; PyPI's publish attestations and npm provenance, which Polaris
already has.

## 5. Can Polaris interoperate instead of rebuild?

Yes: the action already in the tree, run from a reusable workflow, with every reference pinned by
digest. Nothing is written that a standard verifier (`gh attestation`, Sigstore) cannot check.

## 6. What unique advantage could Polaris obtain?

An identity verifier whose own build is verifiable apart from the repository's word, which is the
claim the project makes about credentials ("built to be checked, not trusted") applied to itself.

## 7. What happens if Polaris does NOT build it?

The SBOMs stay attested, the packages keep their publish attestations, and SECURITY.md says so
accurately. Nothing breaks; a reviewer finds the gap.

## 8. What other work would be delayed?

The database refusal of a signature row whose key no authority registered (the next THREAT-MODEL
change) and the posture's count of placeholder signatures, by about a day if this goes first. This
record does not go first: it is written now, built after them.

## 9. Can the idea be tested cheaply in LAB first?

Yes: the reusable workflow runs on the next release's draft, and the release is not published unless
every distribution verifies with `--signer-workflow`, exactly as the SBOMs are checked today. A
failure leaves a draft, not a broken release.

## 10. What evidence would prove the bet was wrong?

Any one of these, written before the build:

- `gh attestation verify --signer-workflow` cannot tell the reusable workflow's signature from one
  made by the calling workflow, so the separation buys nothing a verifier can see;
- the build job can obtain the signing identity after all (an `id-token` request from a build step
  succeeds), so the separation is nominal;
- the published packages cannot be made the attested bytes (the owner keeps `publish.yml` building
  its own, and the files differ), so the provenance covers copies nobody installs;
- ninety days after the first release that carries it, no one outside the repository (a relying
  party, a reviewer, an auditor) has verified it or asked about it, as
  [EXTERNAL-NOUNS.md](../EXTERNAL-NOUNS.md) would record.
