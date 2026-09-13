# polaris-verify

A detached verifier for Polaris credentials and signed artifacts. It decides authenticity
on its own: no Polaris server, no database, no operator console, no network unless you ask
it to fetch status.

```bash
# Not on PyPI yet. This works today, from a clean machine, and is measured:
pip install "polaris-verify[cryptography] @ git+https://github.com/EgorKhaklin/polaris-id#subdirectory=packages/polaris-verify"

polaris-verify --pqc-provider auto --pack credential.json
```

The `#subdirectory=` fragment is required and is easy to miss: this repository holds several
packages, so its root has no `pyproject.toml`, and `pip install git+…` without the fragment
fails with *"does not appear to be a Python project"*, which reads as "this is not
installable" rather than "look one directory down".

Once it is published the command becomes `pip install "polaris-verify[cryptography]"`. See
[RELEASING.md](../../docs/RELEASING.md) for why nothing is published yet.

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

### Configuring a trust root

The anchor file is a JSON list of hex keys, or an object carrying one under
`public_keys_hex`, `anchors`, `public_key_hex` or `keys`. All four are accepted:

```json
["90bece7e1902ccce...the issuer's ML-DSA public key, in hex..."]
```

```bash
polaris-verify --pqc-provider auto --issuer-anchor anchors.json --pack credential.json
```

**Where the key comes from is your decision, and it is the decision that matters.** The
issuer publishes its keys in a signed registry (`GET /api/v1/registry/<agency_id>`, verified
with `verify_registry`) and in a signed federation manifest; both are themselves signed, so
each moves the question one step rather than answering it. Somewhere a key is pinned out of
band, by you. This tool does not pretend otherwise and will not fetch one for you.

What it does guarantee, and what you can script on:

| | `signature_valid` | `issuer_trusted` | exit |
|---|---|---|---|
| correct anchor | `true` | `true` | 0 |
| a different, well-formed key | `true` | **`false`** | **2** |
| empty anchor list | `true` | **`false`** | **2** |
| no anchor given | `true` | `null` | 0 |

A genuine signature by a key you did not anchor is reported authentic and untrusted, and
exits non-zero. The two questions stay separate because collapsing them is how a format
check gets read as a trust decision.

## Status

`0.1.0`. Unreleased on any registry as of this writing, and not yet exercised by a named
external implementation. See `lab/EXTERNAL-NOUNS.md` in the repository for what has and has
not happened outside the project.

Apache 2.0. Part of the Polaris reference implementation, which runs on notional data.
