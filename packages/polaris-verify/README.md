# polaris-verify

A detached verifier for Polaris credentials and signed artifacts. It decides authenticity
on its own: no Polaris server, no database, no operator console, no network unless you ask
it to fetch status.

```bash
pip install "polaris-verify[cryptography]"
polaris-verify --pqc-provider auto --pack credential.json
```

## It refuses to start until you say what cryptography it is doing

There is no default and no environment variable for this choice.

```
--pqc-provider oqs           real ML-DSA via liboqs
--pqc-provider cryptography  real ML-DSA via cryptography>=48
--pqc-provider auto          whichever real backend is installed
--dev-placeholder            NO real cryptography; development only
```

Run it with none of them and it exits 4 without reading your files. Name a backend that is
not usable on the machine and it exits 4 rather than starting and reporting a verification
failure for every credential, which reads as the credentials being bad instead of the
verifier being unable.

Under `--dev-placeholder` every verdict carries `"crypto": "DEV-PLACEHOLDER"` and a banner
goes to stderr. Development crypto is never mistaken for production crypto.

## What it verifies

Authenticity packs, presentations and QR frames, status assertions (offline, with a
freshness window), ID tokens, epoch checkpoints and leaves, revocation feeds, federation
manifests and status bundles, trust lists and attestations, registries, timestamps and
their transparency anchors, signed documents, exchange requests, receipts and mints, holder
bindings and proofs, agent grants with their revocations and proofs, and cross-authority
decisions. `--verify-dir` re-verifies a directory of published vectors; `--selftest` checks
the verifier against material it generates.

## Trust

`--issuer-anchor` takes a JSON file of the issuer's published verification keys, and
`--trusted-anchor` takes one key hex. Without either, the verifier reports whether a
signature is genuine but leaves `issuer_trusted` unanswered, which is the honest verdict:
a genuine signature by a key you do not trust is authentic and worthless.

## Status

`0.1.0`. Unreleased on any registry as of this writing, and not yet exercised by a named
external implementation. See `lab/EXTERNAL-NOUNS.md` in the repository for what has and has
not happened outside the project.

Apache 2.0. Part of the Polaris reference implementation, which runs on notional data.
