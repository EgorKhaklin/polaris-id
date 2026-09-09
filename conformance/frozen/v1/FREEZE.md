# Frozen protocol-version-1 set (P8.8b, v9.330)

A snapshot of the version-1 conformance cases and vectors as published at v9.330 (44 cases;
the conformance vectors under `vectors/`, the original authenticity packs under `packs/`),
plus one pinned OLDER detached verifier: the v9.317 `scripts/polaris-verify.py` (byte-identical to
the release except one comment line, edited to describe a class of system rather than name a
product; no code changed), the release that closed P8.1, before the timestamp, registry, gateway, document, broker, wallet,
trust-list and algorithm-agility artifacts existed.

`scripts/polaris-compat-suite.py` proves cross-version compatibility in both directions on
every CI run:

- **current verifiers, frozen vectors:** the detached verifier and both SDKs of the tree must
  reach every frozen expectation; a verifier that stops accepting what version 1 published
  has broken the protocol;
- **pinned older verifier, current vectors:** the v9.317 verifier must agree on every case at
  or before its release (`since`), MUST NOT accept anything a later case expects rejected
  (fail-closed across versions), and may only decline what it predates.

`SHA256SUMS` pins every file here; the suite and `check_protocol_versioning` recompute it,
so a changed frozen file fails CI. A protocol change that would require changing this set
is a new major (`/2`) with its own frozen set beside this one.
