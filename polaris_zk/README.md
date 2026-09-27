# polaris_zk

The Plonky2 prover and verifier behind Polaris's `ZERO_KNOWLEDGE` disclosure level. Given the
leaves of an epoch's Merkle tree, it proves that a leaf is in the tree with root R without saying
which leaf; the verifier checks the proof against R alone. A zero-knowledge verification stores no
token identifier (C2), and this proof is what the verifier gets instead.

Plonky2 is FRI-based, so there is no trusted setup. [`witness2/`](witness2/) is an independent
Python implementation of the same Poseidon Merkle computation, and the two must agree bit for bit.

## Build

Optional: only the zero-knowledge path needs it; `SELECTIVE` and `FULL` disclosure work without it.

```bash
cd polaris_zk
cargo +nightly build --release          # rust-toolchain.toml pins nightly
export POLARIS_ZK_BINARY=$PWD/target/release/polaris-zk   # the default path, if unset
```

Without the binary, the `/api/zk/*` routes return an error saying how to build it.

## The binary

`polaris-zk <subcommand>` reads JSON on stdin and writes JSON on stdout
([`src/main.rs`](src/main.rs) documents each shape):

| Subcommand | Does |
|---|---|
| `compute-root` | Poseidon Merkle root over a leaf set |
| `compute-leaves` | the inclusion path for every leaf |
| `leaf` | a holder's leaf commitment |
| `nullifier` | the per-relying-party nullifier for a leaf |
| `prove` | a SNARK that a leaf is in the tree, bound to an epoch, a context and a nonce |
| `verify` | checks a proof bundle |

The application calls it as a subprocess ([`polaris_web/zk.py`](../polaris_web/zk.py)).

## In the application

- `TokenStateEpoch` and `TokenStateEpochLeaf` hold each epoch and its leaves; `uc11_close_epoch`
  closes an epoch and is the only writer.
- `POST /api/zk/epoch/close` (admin), `GET /api/zk/epoch/<id>`, `POST /api/zk/verify` (single-use
  nonces).

## Limits

- The claim is membership and nothing else; it does not hide a holder from the issuer, which
  builds every leaf ([docs/PRODUCTION-READINESS.md](../docs/PRODUCTION-READINESS.md)).
- The proof system rests on hash-based assumptions; its security level is Plonky2's, not
  established here.

Design record: [docs/design/zk-snark.md](../docs/design/zk-snark.md).
