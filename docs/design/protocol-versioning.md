# Protocol versioning, negotiation and cross-version compatibility (P8.8b, v9.330)

**Status:** shipped in v9.330. **Invariant:** `check_protocol_versioning` (#184).

## The problem

Every artifact carried a major (`name/1`) and the wire spec said a breaking change bumps it,
but nothing said what a non-breaking change was, nothing advertised it, the interactive
routes answered a wrong version with a generic "invalid request", and nothing proved that a
verifier built last month still accepts what the protocol published, or that today's
verifier still accepts last month's vectors. Compatibility was a belief.

## The design

- **Major in the format string, minor in the registry.** A minor may add fields nested inside
  an existing signed structure or unsigned top-level fields a verifier ignores; it may never
  touch a top-level signed field or canonicalization. `_PROTOCOL_MINORS` records minors per
  format (the registry is at 1.3: `keys` under authorities in v9.328, `signing_algorithm` in
  v9.329, `versions` in v9.330) and the registry advertises `instance.protocol.versions`.
  A verifier never needs a minor: the current verifier holds every frozen 1.0 vector and the
  frozen v9.317 verifier holds every current 1.x artifact it implements.
- **Negotiation is a rule, not a handshake.** A consumer rejects an unknown major and accepts
  any minor; a producer never emits an unadvertised version and never sends an instance a
  format it does not advertise (`registry_speaks` decides from the registry). The interactive
  routes (`POST /api/v1/exchange/<id>`, the mint) answer a known name at another major with
  `400 unsupported_format_version`, the `supported` list and where versions are advertised,
  through one `_format_check`; a wrong or missing format is an invalid request. The check
  precedes nonce consumption and signature verification: a version mismatch spends nothing.
- **Version 1 is frozen and the freeze is enforced.** `conformance/frozen/v1` holds the 44
  cases, the 41 vectors and the vendored v9.317 detached verifier under `SHA256SUMS`;
  `check_protocol_versioning` and the suite recompute the sums, so a changed frozen file
  fails CI. Every case carries `since`.
- **Both directions on every push.** `scripts/polaris-compat-suite.py`: the current detached
  verifier and both SDKs must hold every frozen case; the pinned older verifier must agree on
  every current case at or before its release, must never accept what a later case expects
  rejected (fail-closed across versions), and may only decline what it predates (reported as
  "predated", never as a pass). At v9.330: 44/44 frozen cases under all three current
  verifiers; the v9.317 verifier agrees on 26 current cases, predates 16 artifact types,
  declines 2 newer ML-DSA-87 cases fail-closed, 0 violations.

## Limits

- One pinned older verifier (v9.317, the P8.1 close) is vendored, byte-identical to the release
  except one comment line (a named product replaced by its class; no code changed). Older SDK releases are not
  pinned: the SDKs are published from this tree, and the frozen vectors are the contract an
  external SDK certifies against.
- Minors are advertised, not signed separately: they ride inside the signed registry.
- A `/2` of any format does not exist yet; the rule for introducing one (a new frozen set
  beside version 1, decisions per artifact by `format`) is specified but not exercised.
