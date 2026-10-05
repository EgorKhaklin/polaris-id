# Token signatures

**Reader:** an engineer or an assessor. **Job:** How a signature is produced, stored and verified across a rotation.

A token is worth nothing without proof that the issuing agency authorised it.
`TokenSignature` is where that proof lives, and it is shaped by the one
requirement that outlasts any algorithm: a token issued today must still verify
after the signing algorithm has been rotated and the signing key replaced.

## The table

```
IdentityToken ── 1:N ── TokenSignature ── N:1 ── CryptographicAlgorithm
```

The relation is many to one in both directions on purpose. A token carries one
signature per algorithm, so during a migration window it holds both the
outgoing and the incoming signature, and `UNIQUE (token_id, algorithm_id)`
keeps that to one each. Which algorithm signed a given row is data, not code,
which is C7 in the schema.

Each row records:

- `token_id` and `algorithm_id`, the foreign keys above. The algorithm is the
  one active at the moment of signing, which is what makes a rotation
  reconstructable afterwards.
- `signature_bytes`, the signature itself.
- `signing_public_key_hex`, the issuer public key that produced those bytes,
  stored beside them. This is what makes verification self-contained: it needs
  no live key-file lookup and it survives key rotation. A NULL here means the
  row holds a deterministic placeholder rather than a real signature.
- `signed_at`, and `deprecation_date`, which is NULL while the signature is
  accepted and a timestamp once it is not.

Two triggers hold the invariants. `enforce_token_has_active_signature` refuses
any write that would leave a token with no non-deprecated signature.
`enforce_token_signature_immutability` makes the row write-once: no deletes, no
updates except to `deprecation_date`, and that field moves only from NULL to a
timestamp, never back and never earlier. `idx_token_signature_active`, a
partial index over the rows where `deprecation_date IS NULL`, keeps the
invariant's count reading the small active set rather than the whole history.
Verification reads a credential's signatures in force, a deprecated one included
until its date passes, through the unique `(token_id, algorithm_id)` index.

## Two modes, and which one production runs

`POLARIS_USE_REAL_PQC` selects between them:

- **Set.** `pqc_signing.py` signs through liboqs with ML-DSA-65 (FIPS 204),
  and `verify_both` checks the result against an independent implementation
  before accepting it. Both shipped production paths set it: the production
  compose file and the Helm chart's `app.realPqc`. CI's `pqc-real` job signs
  and verifies inside the production image on every push.
- **Unset.** `sign_token` returns a deterministic SHA3-256 value derived from
  the token, recorded under the label `DETERMINISTIC-PLACEHOLDER-SHA3-256` so
  it cannot be mistaken for a signature, and `signing_public_key_hex` stays
  NULL. This is the development default, and it exists so a developer without
  liboqs still exercises the schema's structural invariants: every token has a
  signature row, the triggers fire, the migration path works.

The placeholder is safe because it labels itself. What would not be safe is a
placeholder that looked like a signature, which is why the label is checked
rather than assumed.

## What is tested, and where

| Surface | Tests |
|---|---|
| Table shape, the unique constraint, the immutability and active-signature triggers | `polaris_sql/08_tests.sql` |
| The placeholder path: determinism, distinctness, and its label | `polaris_web/test_pqc_signing.py` |
| The real signing path and `verify_both` against the second witness | `polaris_web/test_pqc_signing.py`, and CI's `pqc-real` job inside the production image |
| Verification surviving key rotation, using the stored public key | `polaris_web/test_app.py` |
| That the wiring exists at all | `check_pqc_signing_wired`, `check_verify_enforced`, `check_signature_self_contained_verify` |

## Boundaries

- It binds a token to its issuer's signature, not to a holder's biometric or
  device. `DeviceBinding` is the separate table for that.
- It records the signing event, not the token's current standing. Revocation
  lives in `TokenLifecycleEvent` and the revocation list.
- It stores no key material. An agency holds its own signing key; Polaris
  records the resulting signature and the public half needed to check it.
- Multi-algorithm coexistence is the migration window, not a threshold scheme.
  [multi-sig-migration.md](multi-sig-migration.md) covers what that window
  does and does not promise.

## Where change would land

- **Algorithm rotation** adds a row to `CryptographicAlgorithm` and routes new
  signatures to it. Existing tokens keep the algorithm that signed them and
  gain a second row during the window.
- **A larger signature** changes nothing in the schema: `signature_bytes` is a
  `BYTEA` with no length ceiling, so ML-DSA-87 or a hash-based scheme needs no
  migration on this table.
- **A second witness for a new algorithm** is required before it can render a
  production verdict, under [two-witness-principle.md](two-witness-principle.md).

## Reading the code

- `polaris_web/pqc_signing.py`: signing, verification, and the second witness.
- `polaris_sql/01_schema.sql`: the `TokenSignature` definition.
- `polaris_sql/06_triggers.sql`: `enforce_token_has_active_signature` and
  `enforce_token_signature_immutability`.
- `scripts/polaris-pqc-status.sh`: the operator's readiness probe for real
  post-quantum signing on a given host.
