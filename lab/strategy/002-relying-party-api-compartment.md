# 002: the relying-party API in its own compartment

**Opened 2026-09-27.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md).
State: MEASURED 2026-09-27, NOT BUILT as a process split alone. Results: [002/RESULTS.md](002/RESULTS.md).

---

## The finding that started it

The web application is one process with one database login. Measured by reading every route
module for the statements it runs (2026-09-27):

| Surface | Writes | Reads |
| --- | --- | --- |
| relying-party API (`rp_api.py`, the internet-facing `/api/v1`) | 6 tables: consumed auth codes, exchange nonces, exchange receipts, holder key events, relying-party `last_used_at`, timestamps | 17 |
| operator routes, use cases, federation, verification, transparency | identities, tokens, agencies, recoveries, attestations, verification events, epochs (mostly through procedures) | the rest |
| Atlas, SQL console | nothing | 7 each |

So the surface that parses the most untrusted input, from any relying party on the internet,
runs with the same database rights as the operator console. A parser bug that yields code
execution anywhere in `/api/v1` holds the login that can issue, revoke and re-point identities.
Earlier work (rc.56 to rc.63) narrowed what that one login can do; it did not separate who holds
it.

## 1. What capability is being considered?

Run the relying-party API as its own service, with its own database login (`polaris_rp`)
granted only the six writes and seventeen reads it needs, so a compromise of the public surface
cannot write anything the operator surfaces own.

## 2. What problem would it solve?

The blast radius of the most exposed code path. Today it is the whole database the application
role can write; after, it is six append-mostly registers and one timestamp column.

## 3. Who would plausibly need it?

Any operator who exposes `/api/v1` to relying parties while keeping the operator console on an
internal network, which is the deployment the documentation already recommends; and any
reviewer, for whom "the public API cannot write identities" is a checkable sentence.

## 4. What already solves it?

Nothing new is invented: separate services with least-privileged database users is ordinary
practice. What is missing is Polaris doing it and proving it.

## 5. Can Polaris interoperate instead of rebuild?

Not applicable: this is how Polaris is deployed, not a protocol.

## 6. What unique advantage could Polaris obtain?

A compartment demonstrated by exploit rather than asserted: the same method as the rc.56 to
rc.63 fixes (act as the role, try the write, require the refusal), now applied to a deployment
boundary.

## 7. What happens if Polaris does NOT build it?

One remote-code-execution bug in any relying-party parser (JSON, CBOR for mdoc, JOSE, the
exchange envelope) is a full compromise of the issuer's writable state.

## 8. What other work would be delayed?

Per-operator database identity (the readiness ledger's named four-eyes gap), which touches the
same connection code; doing this first makes that change smaller, not larger.

## 9. Can the idea be tested cheaply in LAB first?

Yes, and it must be before any product change:

1. Create `polaris_rp` in a lab database with exactly the grants the table above names.
2. Run every relying-party test class (the `/api/v1` classes in `polaris_web/test_app.py`) with
   the application connected as `polaris_rp`, the way `scripts/polaris-app-role-suite.py` runs
   the whole suite as `polaris_app`.
3. Record every failure: each is a right the surface uses that the static map missed.
4. As `polaris_rp`, attempt the operator writes (issue, revoke, re-point a signing key, create
   an account) and require every one refused.

## 10. What evidence would prove the bet wrong?

Written before the work starts:

- **The surface is not separable.** If the relying-party routes need writes to identity, token,
  agency or account tables (directly or through helpers they share with operator routes), the
  compartment would hold nothing that matters. Kill if step 3 finds any such write that cannot
  be removed without changing a published behaviour.
- **It costs more than it protects.** If running two services breaks the stranger's path or the
  single-host deployment (docs/STRANGER-PATH.md, the Linux profile), and the split cannot be
  optional, it is not worth a surface nobody outside has asked to have hardened.
- **Nobody runs it split.** If, by the next release after it ships, no documented deployment
  (compose, Helm, Linux) runs the relying-party API separately by default, it was a diagram,
  not a compartment.

---

## Measured (2026-09-27)

Section 9 was run in a scratch database: a login `polaris_rp` with exactly the rights the
relying-party routes need ([002/polaris_rp_grants.sql](002/polaris_rp_grants.sql)), the 22
test classes that call `/api/v1` run with the application connected as it
([002/run_rp_as_polaris_rp.py](002/run_rp_as_polaris_rp.py)), and every operator write
attempted as it ([002/attempt_operator_writes.py](002/attempt_operator_writes.py)).

- **The surface is separable** (the first kill criterion does not fire): 163 tests, 160 pass
  and 3 skip in split mode, with 26 relations read, 7 tables written (the six the map named plus
  `ZkVerificationNonce`), and one definer procedure (`uc12_record_duress`). Every operator write
  was refused: issuing, revoking, re-pointing a signing key, trust edges, accounts, sessions,
  verification events, audit deletion, epochs, recoveries, erasure, purge, DDL.
- **Section 2 overstated what the split buys.** Its sentence, that the blast radius would be
  six append-mostly registers and one timestamp column, is false. As `polaris_rp` the public
  surface still: binds any holder key to any credential (the insert is not tied to possession in
  the database), reads every credential pack in one query (token value plus stored signature,
  which is what possession authentication checks, so it can present as any holder), reads the
  enrolled duress hashes and holder legal names, and records duress events through
  `uc12_record_duress`. And outside the database it signs with the SAME custody key as issuance,
  so code execution there acts as the issuer whatever login it holds.

## Decision

Not built as a process split alone: separating the login while the signing key and the bulk
pack read stay shared would put a boundary on a diagram that an attacker walks around. The
compartment that decides the blast radius is signing custody, a key the public surface can use
for what it signs and cannot use for issuance, together with a possession lookup that does not
expose packs in bulk. That is its own bet with its own record (003), before any of this ships.

Recorded here because a strategy that only records its successes is a list of preferences.
