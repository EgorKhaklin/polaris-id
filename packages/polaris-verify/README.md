# polaris-verify

A detached verifier for Polaris credentials and signed artifacts. It decides authenticity
on its own: no Polaris server, no database, no operator console, no network unless you ask
it to fetch status.

> **Naming:** this project installs the `polaris-verify` command (module `polaris_verify_cli`).
> The module `polaris_verify` is the library, from `polaris-sdk-python`. They install side by side.

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

Release candidate: PyPI serves 1.0.0rc3 (`pip install --pre`); the tree is at 1.0.0-rc.4, which
adds two refusals and goes out at the next publish.

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
decisions. `--verify-dir` re-verifies a directory of published vectors. `--selftest` signs its own material,
so it needs liboqs and exits 3 without it; with the `cryptography` extra alone, verify the published
vectors instead.

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

A release candidate. No named external implementation has exercised this command, and no operator
other than the author has run it; see
[the scoreboard](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/EXTERNAL-NOUNS.md).

Apache 2.0. Part of the Polaris reference implementation, which runs on notional data.
