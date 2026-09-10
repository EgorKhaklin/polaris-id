# QUANTUM-EVENT.md: re-signing the population when an algorithm falls

**Reader:** the operator on the day FIPS 204's ML-DSA-65 is withdrawn, weakened,
or superseded, and every credential the authority has issued needs a signature
under a different parameter set. **Job:** get the whole population onto the new
algorithm without any holder ever carrying a credential that verifies under
nothing.

This is the operation Polaris was built for. The database has expressed it since
the beginning: `TokenSignature` is a set of signatures per credential rather than
one column, `CryptographicAlgorithm` carries a `deprecation_date` rather than a
boolean, and UC-6 adds a signature instead of replacing one. This runbook is the
procedure that uses that shape, and
[`scripts/polaris-quantum-event-drill.py`](../../scripts/polaris-quantum-event-drill.py)
runs it end to end on every push so the procedure below is executed, not merely
written down.

---

## 1. The one number that matters

Not throughput. **How many holders have a credential that verifies under
nothing.** It must be zero at every instant: before you start, after every batch,
and after you close the window.

```bash
polaris migrate-population --to ML-DSA-87 --dry-run
```

The `unverifiable` count in that output is the number. If it is not zero before
you begin, **stop**: a migration assumes it is adding an algorithm to a working
population, not repairing a broken one, and the command refuses to run rather
than burying the finding under a successful-looking migration.

## 2. Why there is no downtime, and what would create some

A credential's old signature keeps verifying until its `deprecation_date`. That
interval is the migration window, and during it a credential carries signatures
under both algorithms: an old verifier accepts the old one, a new verifier the
new one, and neither needs to know about the other.

The way to break this is to deprecate the old algorithm as you go. Then a
partially migrated population contains credentials that verify only under an
algorithm fielded verifiers may not accept yet, and the holder discovers it at a
border while the operator's console reports progress. So deprecation is a
**separate pass**, and `polaris migrate-population --deprecate-old` refuses to
run while any ACTIVE credential is still unmigrated. That refusal is not advice.

## 3. Provision the key first

The migration signs under a parameter set the running instance is not configured
for: it keeps issuing under the current algorithm while the population moves to
the new one, so both are live at once. Provision a key for the target set per
[KEY-CEREMONY.md](KEY-CEREMONY.md) and point the runner at it:

```bash
export POLARIS_MIGRATION_SIGNING_KEY_FILE=/etc/polaris/mldsa87.json
```

If that key is absent or holds the wrong parameter set, the migration **stops**.
It does not fall back to the key it has. Signing with ML-DSA-65 and recording the
row as ML-DSA-87 would put a false algorithm label on a real signature in the
audit-of-record: every later verification would attempt the wrong parameter set,
fail, and be indistinguishable from tampering.

## 4. Run it

```bash
polaris migrate-population --to ML-DSA-87 --batch 500
```

Name the algorithm, not its id. An off-by-one in a numeric id re-signs a
population under the wrong parameter set with no error anywhere.

**Interruption is expected and costs nothing.** The work remaining is a query
("ACTIVE credentials with no active signature under the target algorithm"), not a
cursor or a progress file. Kill the runner, lose the machine, run it again next
week: it finishes what is left. There is no state to corrupt because there is no
state.

**Run as many as the signing capacity supports.** Runners divide the population
with `FOR UPDATE ... SKIP LOCKED` and write disjoint rows; two of them re-sign a
population once, not twice. They need no coordination with each other.

**Inside a maintenance window,** cap the run:

```bash
polaris migrate-population --to ML-DSA-87 --limit 2000000
```

## 5. What it costs

Measured by the drill, 2,000 credentials, real ML-DSA-87 with one custodied key,
one runner on a development laptop:

| | |
|---|---|
| Re-signed per second | ~345 |
| Signing's share of the work | **91%** |
| Database's share | 9% |
| 350M on one runner | ~11.7 days |
| 350M on 64 runners | ~4.4 hours |

**The migration is bounded by signing, not by the database.** Nine tenths of the
time is spent producing ML-DSA-87 signatures. Buying database capacity for this
operation buys almost nothing; the lever is signing parallelism, and if the key
lives in an HSM, that HSM's signing throughput is the migration's speed limit.
Plan against its rate, not the database's.

That number is linear in the population and assumes runners do not contend, which
holds while they divide the work by `SKIP LOCKED` and write disjoint rows. It
does not model the write amplification of a larger signature, replication lag
under sustained bulk insert, or an issuance load running alongside. Those belong
to the capacity model (roadmap P7.3), not to this procedure.

## 6. Close the window

Only after the population is fully migrated, and only once fielded verifiers
accept the new algorithm. Those are two separate conditions and the second is not
in the database's view:

```bash
polaris migrate-population --to ML-DSA-87 --deprecate-old --grace-seconds 3600
```

The grace period is the interval before the superseded signatures stop verifying.
Set it long enough for caches to turn over: the revocation feeds, epoch
checkpoints and status assertions in flight were signed before you ran this, and
their own windows are what
[status distribution](../design/status-distribution.md) bounds.

Verify:

```bash
polaris migrate-population --to ML-DSA-87 --dry-run     # unverifiable must be 0
```

## 7. What this procedure does not cover

- **Credentials that are not ACTIVE.** A REVOKED or EXPIRED credential keeps its
  historical signatures exactly as they were. Re-signing one would edit the
  audit-of-record to say something that was never true.
- **The physical token.** A card holding a private key under the fallen algorithm
  is not fixed by re-signing the database record. That is the UC-6 dual-signature
  migration on silicon (roadmap P4), and it is the reason the card profile
  carries two signature slots.
- **Other authorities.** Each instance migrates its own population. The
  federation trust list is where a relying party learns which algorithms an
  authority's keys now use.
- **Deciding when.** The algorithm falling is an external event. This runbook
  starts the moment that decision has been made.
