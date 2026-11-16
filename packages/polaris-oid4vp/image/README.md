# The polaris-oid4vp image

**Reader:** someone who wants the verifier as a container, for a test stack or a CI job.
**What it is:** the released `polaris-oid4vp` package from PyPI, installed by hash on a base
pinned by digest. Nothing in the image is built from this repository. Its entrypoint is the
package's command, and it runs as a user that is not root (uid 10001).

The version is the one line of [`requirements.in`](requirements.in); an image's tag is that
version with a `v` in front. A rebuild of the same package release, on a newer base or
dependency, is a new tag with a revision after it (`v1.1.0-2`); a published tag never moves.

## Run it

Two commands, as with the package: `keygen` once, then `serve`. `/data` is the working directory
and belongs to the image's user, so mount a volume there.

```bash
docker build -t polaris-oid4vp packages/polaris-oid4vp/image
IMAGE=polaris-oid4vp

docker volume create verifier
docker run --rm -v verifier:/data "$IMAGE" keygen --out /data/pki --host localhost --port 9443

docker run --rm -p 9443:9443 -v verifier:/data -v "$PWD/issuers.json:/issuers.json:ro" "$IMAGE" \
  serve --pki /data/pki --host localhost --bind 0.0.0.0 --port 9443 \
  --issuer-jwks /issuers.json --once --result /data/result.json
```

- `--host` and `--port` are the name and port a wallet reaches the verifier by; `keygen` and
  `serve` take the same pair. `--bind 0.0.0.0` listens on the container's interfaces.
- `--issuer-jwks` names the issuers' public keys: a JWK Set, a list of JWKs or one JWK.
  `--issuer-trust-anchor` takes a CA certificate, for issuers that send an `x5c` chain.
- `--once` starts one request and prints the parameters and links a wallet is launched with.
  The request lives five minutes.
- `--result` keeps what became of that request as one JSON object: `nothing_received` until a
  response arrives, then `accepted` with the names of the claims, `refused` with the check that
  refused, or `wallet_error` when the wallet answered with an error.

The listener speaks TLS under the certificate `keygen` made (`/data/pki/tls.pem`). Behind a proxy
that provides HTTPS, add `--no-local-tls --public-base-url https://verifier.example`. The
[package README](../README.md) has every flag.

[`scripts/polaris-oid4vp-image-drill.py`](../../../scripts/polaris-oid4vp-image-drill.py) builds
the image and presents to it: a valid presentation is accepted, and one bound to the wrong nonce
is refused. CI runs it on every pull request.

## Verify a published image

[`release-oid4vp-image.yml`](../../../.github/workflows/release-oid4vp-image.yml) publishes the
image as `ghcr.io/egorkhaklin/polaris-oid4vp`, for amd64 and arm64, after the drill and a
vulnerability scan passed on each. It signs the index keyless with cosign and attaches SLSA build
provenance to the index and an SPDX SBOM to each architecture's image, at the registry. A valid
signature shows that workflow, run on `main` in `EgorKhaklin/polaris-id`, signed the digest; the
provenance states that it built it.

Pull by digest, never by tag alone. Use cosign 3 or later.

```bash
IMAGE=ghcr.io/egorkhaklin/polaris-oid4vp
TAG=v1.1.0
DIGEST=$(docker buildx imagetools inspect "$IMAGE:$TAG" --format '{{json .Manifest}}' | jq -r .digest)

# The signature: made by this repository's workflow on main, logged in Rekor.
cosign verify "$IMAGE@$DIGEST" \
  --certificate-identity "https://github.com/EgorKhaklin/polaris-id/.github/workflows/release-oid4vp-image.yml@refs/heads/main" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# The build provenance, attested by the same workflow.
gh attestation verify "oci://$IMAGE@$DIGEST" --repo EgorKhaklin/polaris-id \
  --signer-workflow EgorKhaklin/polaris-id/.github/workflows/release-oid4vp-image.yml \
  --source-ref refs/heads/main

# The SBOM is attached to each architecture's image: verify the one you will run.
ARCH=amd64              # or arm64
PLATFORM=$(docker buildx imagetools inspect "$IMAGE@$DIGEST" --format '{{json .Manifest}}' \
  | jq -r --arg a "$ARCH" '.manifests[] | select(.platform.architecture == $a) | .digest')
gh attestation verify "oci://$IMAGE@$PLATFORM" --repo EgorKhaklin/polaris-id \
  --signer-workflow EgorKhaklin/polaris-id/.github/workflows/release-oid4vp-image.yml \
  --source-ref refs/heads/main --predicate-type https://spdx.dev/Document/v2.3
```
