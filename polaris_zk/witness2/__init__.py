# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""
witness2 - the second witness for Polaris's zero-knowledge verdict.

An independent, from-scratch re-implementation of the Goldilocks + Poseidon +
Merkle semantics that Polaris's Rust ZK crate (polaris_zk) proves, written in a
different language and number representation and sharing no code with the crate
or with Glass. It exists to two-witness the verifier's verdict: a proof you
cannot independently check is just a promise.

Provenance: this is the bounded, additive outcome of the 2026-06-03 Glass fit
analysis (a recorded decision). The Glass language's
Pentecost discipline ("the verdict itself must be two-witnessed") and its
soundness-ledger honesty are the transferable assets; the production substrate
stays Postgres + Flask + the audited Plonky2 Rust crate.

Public API (import explicitly, e.g. `from witness2 import verifier`):
    poseidon.permute / two_to_one / hash_or_noop / self_test
    merkle.build_root / root_from_path / membership_holds / {hex<->elements}
    verifier.recompute_root / check_claim

Submodules are not eagerly imported here so that `python3 -m witness2.verifier`
executes cleanly (eager import would re-import the __main__ module).
"""
