# Verifying post-quantum signatures at national scale

The benchmark (`polaris_sim`, [BENCHMARK.md](../reference/BENCHMARK.md)) measured
real ML-DSA-65 signature verification at ~745/s on one core. A national
deployment needs thousands per second, sustained through failover and rolling
deploys. This is how Polaris gets there without weakening the guarantee that
matters.

## The two-witness cost, and where it belongs

Every real signature check ran through `verify_both`: two independent
implementations, liboqs AND the OpenSSL/`cryptography` ML-DSA-65 verifier, both
of which must agree. That cross-check is a defense against a bug in one
implementation silently accepting a bad signature. It costs two verifies plus a
digest, ~1.35 ms, so ~745/s per core.

The critical moment for that defense is **issuance**. `signature_with_key_for_token`
two-witnesses the signature it just produced and **refuses to persist it** unless
both implementations accept it. So a stored real signature is, by construction,
known to verify under both liboqs and OpenSSL.

That guarantee only holds if the second witness actually ran, so issuance must
not silently degrade to one (v9.264). By default `verify_both` falls back to the
lone primary when the witness library is unavailable — fine for the
re-verification and display paths, where the signature was already two-witnessed
at issuance. But issuance passes `require_witness=True`: a missing witness there
is a **refusal**, and `signature_with_key_for_token` additionally refuses up front
when `second_witness_available()` is false. A real ML-DSA-65 signature is only
persisted when the second witness genuinely participated — never certified
two-witnessed on the strength of one implementation.

## Single-witness verify-at-use

Because issuance already established two-witness validity, **verification at use**
does not need to re-run both. One witness (liboqs) re-confirms authenticity and
detects any tampering or substitution, at about ten times the rate:

| Path | per core | when used |
|---|---|---|
| Two-witness (`verify_stored_signature(..., witnesses="both")`) | ~745/s | issuance self-check; the strict display path; anywhere maximum rigor is wanted |
| **Single-witness (`witnesses="single"`)** | **~7,800/s** | the verify-AT-USE throughput path |

A tampered or forged signature still fails single-witness verification (liboqs
rejects it); the only thing dropped at use is the redundant second
implementation of the same check. The two-witness path remains available and is
still the default, so nothing silently weakens: a caller opts into `"single"` on
the throughput path.

## Why it scales cleanly

Verification needs **only the public key** stored with the signature. No private
key, no custody driver, no HSM, no KMS is touched (those are issuance-only). Each
verify opens its own liboqs context and holds no shared mutable state. So
verification is embarrassingly parallel:

- **Across gunicorn workers.** Sync workers each verify in their own process; W
  workers deliver ~W x the per-core rate. Use long-lived (preloaded) workers,
  not spawn-per-request, or process start-up dominates.
- **Across HA replicas.** The verify route is replica-routed (a read); add app
  containers/hosts behind the edge and the capacity adds up, with no shared
  secret to coordinate.

Projected fleet capacity on an 8-core node: ~62,000/s single-witness (measured
per-core rate x cores), before adding replicas. Thousands per second is reached
on a single core; tens of thousands per node.

## The verify endpoint

`GET /api/tokens/<id>/verify` (login-gated, replica-routed) cryptographically
verifies a token's active signature at use, single-witness, and returns whether
the signature is authentic, whether the token is currently usable (signature
valid AND status ACTIVE), and the per-signature result. This is the
throughput-oriented verification capability (a seed of the roadmap's P3.4
relying-party verification API); the login-gated `/tokens/<id>` display page
keeps the strict two-witness check since it verifies one signature per view.

**Authenticity is replica-safe; authorization is not (v9.264).** The endpoint
answers two different questions with two different freshness needs.
*Authenticity* — does this signature verify against its stored public key — is a
property of IMMUTABLE material: the signed `token_value`, the signature bytes and
the stored key never change once issued, so a lagging replica can neither forge
authenticity nor deny it. That read stays replica-eligible. But *is this token
usable NOW* is a CURRENT-AUTHORIZATION question, and a revocation flips `status`
to REVOKED on the primary; a replica inside its staleness window could still show
ACTIVE for a token revoked seconds ago. So the endpoint splits the reads: the
signature material comes from the replica, but the `status` that decides `usable`
is pinned to the PRIMARY (`query(..., primary=True)`) and the response carries
`status_source: primary`. The primary read is a tiny indexed point-lookup, and
the expensive ML-DSA verify touches no database, so throughput is preserved while
`usable` is never decided on stale state.

**The freshness contract is explicit (v9.271).** So a relying party never
confuses a genuine signature with a current one, the response separates the two
verdicts by name. Authenticity is `signature_valid` with `signature_cacheable:
true` — immutable, replica-safe, cacheable. Authorization is
`currently_authoritative` (status is ACTIVE) carrying `as_of` (the primary clock
at the read) and `max_staleness_seconds: 0` (primary-backed, no lag). A caller
may cache `signature_valid`; it must re-read authorization, and the `as_of` /
`max_staleness_seconds` pair tells it exactly how fresh the verdict it holds is.
If a deployment ever routes the authorization read to a replica for scale, that
is the single field it raises (to the replica's lag bound); the API shape does
not change.

**The single-witness path earns its speed by being continuously checked
(v9.272).** Single-witness verify-at-use is sound only while the fast witness
stays trustworthy, so the endpoint does not take that on faith: a random
fraction of successful checks (`POLARIS_VERIFY_SAMPLE_RATE`) is replayed through
the SECOND witness, and any disagreement increments
`polaris_verify_witness_disagreements_total` and pages
(`PolarisWitnessDisagreement`, a SEV-1, not a log line). Every response names
which witness set actually ran — `witnesses: single` on the fast path, `both`
when this request was sampled, plus a `sampled` flag — so an operator can see
the coverage. Sampling is MANDATORY in production: the rate is floored above
zero there, so two-witness verification can never be silently turned off. The
sampling read is read-only; it re-reads the same immutable material and never
touches authorization. Two witnesses that are optional would be one witness with
extra docs; the sampling is what keeps the second witness real. Pinned by
`check_verify_witness_sampling` and `test_app.VerifyWitnessSamplingTests`.

## Under HA, failover, and rolling deploys

Verification is stateless and read-only, so it inherits the HA properties the
failover and rolling-deploy drills prove. Both drills now hold a REAL,
authenticated verification load on `/api/tokens/<id>/verify` across the
transition (`scripts/polaris-verify-load.py`, driven by the CI drills), so the
claim is measured, not asserted:

- **Rolling deploy (app-tier).** A rolling deploy replaces app containers one
  colour at a time behind the retrying edge, so a verify request is always
  served by a live colour. The drill certifies **zero dropped verifications**
  across the rollover, the same bar its health traffic already meets.
- **Failover (database-tier).** A verify request is a read; during a database
  failover's window there is a gap where reads (verification included) fail,
  exactly as writes do, because a promoted replica or a healed partition takes a
  bounded time. The honest claim is therefore not zero-drop but **recovery**:
  the drill induces four failures (a leader crash, a lease partition, a
  switchover, an etcd crash) and, under a continuous verification load, asserts
  that verification is **served again after every one of them** and kept serving
  at rate throughout. The recovery rides the same replica-routing failback the
  read path uses.

Because the demo operator accounts are disabled in production, each drill first
bootstraps a real admin (the scrypt hash is computed inside the app container,
which carries werkzeug), then authenticates the load against it. This is the
verification half of the roadmap's P2.9: real ML-DSA-65 verification holds
through a rolling deploy and recovers through a failover, under load.
