# polaris-verify

A detached verifier for Polaris credentials and signed artifacts. It decides authenticity
on its own: no Polaris server, no database, no operator console, no network unless you ask
it to fetch status.

> **Project name and import name differ, and the obvious guess lands elsewhere.** This
> project, `polaris-verify`, installs the `polaris-verify` COMMAND and the module
> `polaris_verify_cli`. The module `polaris_verify` belongs to a different project,
> `polaris-sdk-python`, which is the library. They install side by side without colliding,
> and `pip install polaris-verify` followed by `import polaris_verify` is the mistake this
> paragraph exists to prevent. The names were fixed before either was published and are not
> worth changing after: `conformance/SPEC.md` publishes `python -m polaris_verify.conformance`
> as the reference verifier command, so the module name is part of a contract.

```bash
pip install --pre "polaris-verify[cryptography]"

# cryptographic validity alone; issuer trust NOT evaluated
polaris-verify --pqc-provider auto --signature-only --pack credential.json

# validity AND whether that key is one you trust
polaris-verify --pqc-provider auto --issuer-anchor trusted-keys.json --pack credential.json
```

No credential of your own yet? The repository publishes test vectors, and a first run needs
nothing but the install above and `curl`:

```bash
base=https://raw.githubusercontent.com/EgorKhaklin/polaris-id/main/vectors
curl -sO $base/ml-dsa-65-valid.json
curl -sO $base/ml-dsa-65-tampered-signature.json
polaris-verify --pqc-provider auto --signature-only --pack ml-dsa-65-valid.json               # exit 0
polaris-verify --pqc-provider auto --signature-only --pack ml-dsa-65-tampered-signature.json  # exit 2
```

The first reports `signature_valid: True`, the second `False`. Walked on 2026-09-23 from a clean
virtualenv against the package on PyPI, with the `cryptography` backend only. What each vector
is: [vectors/README.md](https://github.com/EgorKhaklin/polaris-id/blob/main/vectors/README.md).

A genuine signature is not a trusted issuer. Without `--issuer-anchor` there is no trust root
to judge against, so the run abstains (exit 2) instead of exiting 0 on a credential that could
have been signed by anyone; `--signature-only` is how a caller says that is the question they
meant to ask.

This is 1.0.0-rc.4. The artifact on PyPI is 1.0.0-rc.3, put there by GitHub Actions
trusted publishing over OIDC; rc.4 refuses a signed transparency head whose `tree_size`
is a bool, refuses a zero-knowledge proof against a foreign epoch with fewer members than
`--min-anonymity-set` (20 unless named, the issuing authority's own default) as "privacy
unavailable", and goes out when the owner publishes it. Both are release candidates:
`--pre` tells pip to consider them, and 0.1.0 remains as the prior release. What separates a candidate from 1.0.0 is one thing, an operator who is not the
author reaching a verified result without help. Verified by installing from the live
registry into a clean virtualenv and running the command there, not by a build that exited
zero.

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

## Exit codes

What a script built on this command can rely on, measured on 2026-09-23 against the package on
PyPI:

| exit | meaning |
|---|---|
| 0 | accepted: the signature is genuine, and with `--issuer-anchor` the key is one you trust |
| 2 | not accepted: a signature that does not verify, a JSON file that is not an authenticity pack, or an abstention because no trust anchor was given |
| 3 | the check could not run: the input could not be read or is not JSON, or `--selftest` without liboqs |
| 4 | refused to start: no cryptography declared, or the declared backend is not usable here; your files are not read |
| 1 | `--qr-frames` that do not decode into a presentation |

The last row is the one inconsistency: every other unreadable input exits 3. It is recorded
rather than changed, because a script may already depend on it.

## Offline means it cannot reach a network

Not "does not today". The verifier contains no networking code at all: zero references to
`urllib`, `http.client`, `socket` or `requests`, and `check_detached_verifier` fails the build
if one appears. An air-gapped relying party is running the same code path as a connected one.

The online status path is a different thing and lives elsewhere, in the SDK and the relying
party, both of which are allowed `urllib` on purpose.

## What it verifies

Authenticity packs, presentations and QR frames, status assertions (offline, with a
freshness window), ID tokens, epoch checkpoints and leaves, revocation feeds, federation
manifests and status bundles, trust lists and attestations, registries, timestamps and
their transparency anchors, signed documents, exchange requests, receipts and mints, holder
bindings and proofs, agent grants with their revocations and proofs, and cross-authority
decisions. `--verify-dir` re-verifies a directory of published vectors; `--selftest` checks
the verifier against material it generates. It signs that material, so it needs liboqs
(`pip install liboqs-python`, which also needs the liboqs C library) and exits 3 without it,
deliberately, so a runner meant to exercise real cryptography cannot skip in silence; with the
`cryptography` extra alone, verify the published vectors above instead.

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
| no anchor given | `true` | `null` | **2** (abstains; 0 only with `--signature-only`) |

A genuine signature by a key you did not anchor is reported authentic and untrusted, and
exits non-zero. The two questions stay separate because collapsing them is how a format
check gets read as a trust decision.

## Status

1.0.0-rc.4, a release candidate. No named external implementation has exercised this
command, and the scoreboard's row for an operator who is not the author is blank; that
operator is what turns the candidate into 1.0.0. See
[the scoreboard](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/EXTERNAL-NOUNS.md)
for what has and has not happened outside the project.

Apache 2.0. Part of the Polaris reference implementation, which runs on notional data.
