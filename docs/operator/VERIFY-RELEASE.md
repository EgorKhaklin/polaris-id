# Verifying a released image or chart

**Reader:** an operator about to pull Polaris from a registry. **Job:** check that an image or
the chart was built by this repository's release workflow, from a release tag, before running it.

The release workflow is [`release-images.yml`](../../.github/workflows/release-images.yml) (lab
record 017, phase 3). Run on a release tag and approved by the maintainer, it builds the five
self-built images from the tagged commit on amd64 and arm64, pushes each to
`ghcr.io/egorkhaklin/polaris-<name>` (app, caddy, pgbouncer, postgres, etcd), joins the two
architectures into one index, signs the index keyless with cosign, and attaches SLSA build
provenance to the index and an SPDX SBOM to each architecture's image, at the registry. The Helm
chart, its images pinned to those signed digests, is pushed to
`oci://ghcr.io/egorkhaklin/charts/polaris` and signed the same way.

**Status:** the workflow exists; no release has been published with it yet. Until one is, there
is nothing at these references to verify, and the [deployment guide](DEPLOYMENT.md) builds the
images from source.

## What a signature proves, and what it does not

A valid signature and provenance prove that the digest was produced by `release-images.yml` in
`EgorKhaklin/polaris-id`, run on the release tag the certificate names, from the commit the
provenance names. They do not prove the code is free of defects, that anyone outside the project
reviewed it, or that it is fit to hold real identity data
([PRODUCTION-READINESS.md](../PRODUCTION-READINESS.md)).

## Verify an image

Pull by digest, never by tag alone: a tag can move, a digest cannot. Pin the identity to the
exact release you are installing.

```bash
TAG=v1.0.0-rc.71        # the release you are installing
IMAGE=ghcr.io/egorkhaklin/polaris-app
DIGEST=$(docker buildx imagetools inspect "$IMAGE:$TAG" --format '{{json .Manifest}}' | jq -r .digest)

# The signature: made by this repository's release workflow on that tag, logged in Rekor.
cosign verify "$IMAGE@$DIGEST" \
  --certificate-identity "https://github.com/EgorKhaklin/polaris-id/.github/workflows/release-images.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# The build provenance, attested by the same workflow from the same tag.
gh attestation verify "oci://$IMAGE@$DIGEST" --repo EgorKhaklin/polaris-id \
  --signer-workflow EgorKhaklin/polaris-id/.github/workflows/release-images.yml \
  --source-ref "refs/tags/$TAG"

# The SBOM is attached to each architecture's image: verify the one you will run.
ARCH=amd64              # or arm64
PLATFORM=$(docker buildx imagetools inspect "$IMAGE@$DIGEST" --format '{{json .Manifest}}' \
  | jq -r --arg a "$ARCH" '.manifests[] | select(.platform.architecture == $a) | .digest')
gh attestation verify "oci://$IMAGE@$PLATFORM" --repo EgorKhaklin/polaris-id \
  --signer-workflow EgorKhaklin/polaris-id/.github/workflows/release-images.yml \
  --source-ref "refs/tags/$TAG" --predicate-type https://spdx.dev/Document/v2.3
```

Each attestation is also stored at the registry beside the image it describes; add
`--bundle-from-oci` to read it from there instead of from GitHub.

## Verify the chart

```bash
helm pull oci://ghcr.io/egorkhaklin/charts/polaris --version "${TAG#v}"   # prints the chart's digest
cosign verify "ghcr.io/egorkhaklin/charts/polaris@sha256:<the digest helm printed>" \
  --certificate-identity "https://github.com/EgorKhaklin/polaris-id/.github/workflows/release-images.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The published chart's `values.yaml` names each self-built image by the signed digest, so
installing that chart version pulls exactly the images verified above.
